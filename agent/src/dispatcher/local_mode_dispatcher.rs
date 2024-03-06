/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::collections::{HashMap, HashSet};
use std::mem::drop;
use std::process::Command;
use std::str;
use std::sync::atomic::Ordering;
#[cfg(target_os = "linux")]
use std::sync::Arc;
use std::time::Duration;

use arc_swap::access::Access;
use log::{debug, info, log_enabled, warn};
use regex::Regex;

use super::base_dispatcher::{BaseDispatcher, BaseDispatcherListener};
use super::error::Result;

#[cfg(target_os = "linux")]
use crate::platform::{GenericPoller, LibvirtXmlExtractor, Poller};
use crate::{
    common::{
        decapsulate::TunnelType,
        enums::{EthernetType, TapType},
        MetaPacket, TapPort, FIELD_OFFSET_ETH_TYPE, MAC_ADDR_LEN, VLAN_HEADER_SIZE,
    },
    config::DispatcherConfig,
    flow_generator::{flow_map::Config, FlowMap},
    handler::MiniPacket,
    rpc::get_timestamp,
    utils::bytes::read_u16_be,
};
use public::{
    proto::{common::TridentType, trident::IfMacSource},
    utils::net::{Link, MacAddr},
};

pub(super) struct LocalModeDispatcher {
    pub(super) base: BaseDispatcher,
    #[cfg(target_os = "linux")]
    pub(super) extractor: Arc<LibvirtXmlExtractor>,
}

impl LocalModeDispatcher {
    const VALID_MAC_INDEX: usize = 3;

    pub(super) fn run(&mut self) {
        let base = &mut self.base;
        info!("Start dispatcher {}", base.log_id);
        let time_diff = base.ntp_diff.load(Ordering::Relaxed);
        let mut prev_timestamp = get_timestamp(time_diff);

        let mut flow_map = FlowMap::new(
            base.id as u32,
            base.flow_output_queue.clone(),
            base.l7_stats_output_queue.clone(),
            base.policy_getter,
            base.log_output_queue.clone(),
            base.ntp_diff.clone(),
            &base.flow_map_config.load(),
            Some(base.packet_sequence_output_queue.clone()), // Enterprise Edition Feature: packet-sequence
            base.stats.clone(),
            false, // !from_ebpf
        );

        while !base.terminated.load(Ordering::Relaxed) {
            let config = Config {
                flow: &base.flow_map_config.load(),
                log_parser: &base.log_parse_config.load(),
                collector: &base.collector_config.load(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                ebpf: None,
            };

            if base.reset_whitelist.swap(false, Ordering::Relaxed) {
                base.tap_interface_whitelist.reset();
            }
            // The lifecycle of the recved will end before the next call to recv.
            let recved = unsafe {
                BaseDispatcher::recv(
                    &mut base.engine,
                    &base.leaky_bucket,
                    &base.exception_handler,
                    &mut prev_timestamp,
                    &base.counter,
                    &base.ntp_diff,
                )
            };
            if recved.is_none() {
                flow_map.inject_flush_ticker(&config, Duration::ZERO);
                if base.tap_interface_whitelist.next_sync(Duration::ZERO) {
                    base.need_update_bpf.store(true, Ordering::Relaxed);
                }
                drop(recved);
                base.check_and_update_bpf();
                continue;
            }
            if base.pause.load(Ordering::Relaxed) {
                continue;
            }
            #[cfg(target_os = "windows")]
            let (mut packet, mut timestamp) = recved.unwrap();
            #[cfg(any(target_os = "linux", target_os = "android"))]
            let (packet, mut timestamp) = recved.unwrap();

            let pipeline = {
                let pipelines = base.pipelines.lock().unwrap();
                if let Some(p) = pipelines.get(&(packet.if_index as u32)) {
                    p.clone()
                } else if pipelines.is_empty() {
                    continue;
                } else {
                    // send to one of the pipelines if packet is LLDP
                    let mut eth_type: EthernetType =
                        read_u16_be(&packet.data[FIELD_OFFSET_ETH_TYPE..]).into();
                    if eth_type == EthernetType::DOT1Q {
                        eth_type =
                            read_u16_be(&packet.data[FIELD_OFFSET_ETH_TYPE + VLAN_HEADER_SIZE..])
                                .into();
                    }
                    if eth_type != EthernetType::LINK_LAYER_DISCOVERY {
                        continue;
                    }
                    pipelines.iter().next().unwrap().1.clone()
                }
            };
            let mut pipeline = pipeline.lock().unwrap();

            if timestamp + Duration::from_millis(1) < pipeline.timestamp {
                // FIXME: just in case
                base.counter.retired.fetch_add(1, Ordering::Relaxed);
                continue;
            } else if timestamp < pipeline.timestamp {
                timestamp = pipeline.timestamp;
            }

            pipeline.timestamp = timestamp;

            // compare 3 low bytes
            let mac_low = &pipeline.vm_mac.octets()[Self::VALID_MAC_INDEX..];
            // src mac
            let src_local = mac_low
                == &packet.data[MAC_ADDR_LEN + Self::VALID_MAC_INDEX..MAC_ADDR_LEN + MAC_ADDR_LEN];
            // dst mac
            let dst_local = !src_local
                && (mac_low == &packet.data[Self::VALID_MAC_INDEX..MAC_ADDR_LEN]
                    || MacAddr::is_multicast(&packet.data));

            // LOCAL模式L2END使用underlay网络的MAC地址，实际流量解析使用overlay

            let tunnel_type_bitmap = base.tunnel_type_bitmap.lock().unwrap().clone();

            #[cfg(any(target_os = "linux", target_os = "android"))]
            let decap_length = match BaseDispatcher::decap_tunnel(
                packet.data,
                &base.tap_type_handler,
                &mut base.tunnel_info,
                tunnel_type_bitmap,
            ) {
                Ok((l, _)) => l,
                Err(e) => {
                    base.counter.invalid_packets.fetch_add(1, Ordering::Relaxed);
                    warn!("decap_tunnel failed: {:?}", e);
                    continue;
                }
            };

            #[cfg(target_os = "windows")]
            let decap_length = match BaseDispatcher::decap_tunnel(
                &mut packet.data,
                &base.tap_type_handler,
                &mut base.tunnel_info,
                tunnel_type_bitmap,
            ) {
                Ok((l, _)) => l,
                Err(e) => {
                    base.counter.invalid_packets.fetch_add(1, Ordering::Relaxed);
                    warn!("decap_tunnel failed: {:?}", e);
                    continue;
                }
            };
            let overlay_packet = &packet.data[decap_length..];
            let mut meta_packet = MetaPacket::empty();
            let offset = Duration::ZERO;
            if let Err(e) = meta_packet.update(
                overlay_packet,
                src_local,
                dst_local,
                timestamp + offset,
                packet.data.len() - decap_length,
            ) {
                base.counter.invalid_packets.fetch_add(1, Ordering::Relaxed);
                warn!("meta_packet update failed: {:?}", e);
                continue;
            }

            base.counter.rx.fetch_add(1, Ordering::Relaxed);
            base.counter
                .rx_bytes
                .fetch_add(packet.data.len() as u64, Ordering::Relaxed);

            if base.tunnel_info.tunnel_type != TunnelType::None {
                meta_packet.tunnel = Some(base.tunnel_info);
                if base.tunnel_info.tunnel_type == TunnelType::TencentGre
                    || base.tunnel_info.tunnel_type == TunnelType::Vxlan
                {
                    // 腾讯TCE、青云私有云需要通过TunnelID查询云平台信息
                    // 这里只需要考虑单层隧道封装的情况
                    // 双层封装的场景下认为内层MAC存在且有效（VXLAN-VXLAN）或者需要通过IP来判断（VXLAN-IPIP）
                    meta_packet.lookup_key.tunnel_id = base.tunnel_info.id;
                }
            } else {
                // 无隧道并且MAC地址都是0一定是loopback流量
                if meta_packet.lookup_key.src_mac == MacAddr::ZERO
                    && meta_packet.lookup_key.dst_mac == MacAddr::ZERO
                {
                    meta_packet.lookup_key.src_mac = base.ctrl_mac;
                    meta_packet.lookup_key.dst_mac = base.ctrl_mac;
                    meta_packet.lookup_key.l2_end_0 = true;
                    meta_packet.lookup_key.l2_end_1 = true;
                }
            }

            meta_packet.tap_port = TapPort::from_local_mac(
                meta_packet.lookup_key.get_nat_source(),
                base.tunnel_info.tunnel_type,
                u64::from(pipeline.vm_mac) as u32,
            );
            BaseDispatcher::prepare_flow(
                &mut meta_packet,
                TapType::Cloud,
                false,
                base.id as u8,
                base.npb_dedup_enabled.load(Ordering::Relaxed),
            );
            flow_map.inject_meta_packet(&config, &mut meta_packet);
            let mini_packet = MiniPacket::new(overlay_packet, &meta_packet, 0);
            for h in pipeline.handlers.iter_mut() {
                h.handle(&mini_packet);
            }

            if let Some(policy) = meta_packet.policy_data.as_ref() {
                if policy.acl_id > 0 && !base.tap_interface_whitelist.has(packet.if_index as usize)
                {
                    // 如果匹配策略则认为需要拷贝整个包
                    base.tap_interface_whitelist.add(packet.if_index as usize);
                }
            }
            if base
                .tap_interface_whitelist
                .next_sync(meta_packet.lookup_key.timestamp.into())
            {
                base.need_update_bpf.store(true, Ordering::Relaxed);
            }
            drop(packet);
            base.check_and_update_bpf();
        }

        base.terminate_handler();
        info!("Stopped dispatcher {}", base.log_id);
    }

    pub(super) fn listener(&self) -> LocalModeDispatcherListener {
        #[cfg(target_os = "linux")]
        return LocalModeDispatcherListener::new(self.base.listener(), self.extractor.clone());

        #[cfg(any(target_os = "windows", target_os = "android"))]
        return LocalModeDispatcherListener::new(self.base.listener());
    }
}

impl LocalModeDispatcher {
    pub(super) fn switch_recv_engine(&mut self, config: &DispatcherConfig) -> Result<()> {
        self.base.switch_recv_engine(config)
    }
}

#[derive(Clone)]
pub struct LocalModeDispatcherListener {
    base: BaseDispatcherListener,
    #[cfg(target_os = "linux")]
    extractor: Arc<LibvirtXmlExtractor>,
    rewriter: MacRewriter,
}

impl LocalModeDispatcherListener {
    pub(super) fn new(
        base: BaseDispatcherListener,
        #[cfg(target_os = "linux")] extractor: Arc<LibvirtXmlExtractor>,
    ) -> Self {
        Self {
            base,
            #[cfg(target_os = "linux")]
            extractor,
            rewriter: MacRewriter::new(),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn netns(&self) -> &public::netns::NsFile {
        &self.base.netns
    }

    pub(super) fn on_config_change(&mut self, config: &DispatcherConfig) {
        self.base.on_config_change(config)
    }

    pub fn on_vm_change(&self, _: &[MacAddr]) {}

    pub fn id(&self) -> usize {
        return self.base.id;
    }

    pub fn local_dispatcher_count(&self) -> usize {
        return self.base.local_dispatcher_count;
    }

    pub fn flow_acl_change(&self) {
        // Start capturing traffic after resource information is distributed
        self.base.pause.store(false, Ordering::Relaxed);
        self.base.reset_whitelist.store(true, Ordering::Relaxed);
    }

    pub fn on_tap_interface_change(
        &self,
        interfaces: &[Link],
        if_mac_source: IfMacSource,
        trident_type: TridentType,
        blacklist: &Vec<u64>,
    ) {
        let mut interfaces = interfaces.to_vec();
        if !blacklist.is_empty() {
            // 当虚拟机内的容器节点已部署采集器时，宿主机采集器需要排除容器节点的接口，避免采集双份重复流量
            let mut blackset = HashSet::with_capacity(blacklist.len());
            for mac in blacklist {
                blackset.insert(*mac & 0xffffffff);
            }
            let mut rejected = vec![];
            interfaces.retain(|iface| {
                if blackset.contains(&(u64::from(iface.mac_addr) & 0xffffffff)) {
                    rejected.push(iface.mac_addr);
                    false
                } else {
                    true
                }
            });
            if !rejected.is_empty() {
                debug!(
                    "Dispatcher{} Tap interfaces {:?} rejected by blacklist",
                    self.base.log_id, rejected
                );
            }
        }
        // interfaces为实际TAP口的集合，macs为TAP口对应主机的MAC地址集合
        interfaces.sort_by_key(|link| link.if_index);
        let keys = interfaces
            .iter()
            .map(|link| link.if_index)
            .collect::<Vec<_>>();
        let macs = self.get_mapped_macs(
            &interfaces,
            if_mac_source,
            trident_type,
            #[cfg(target_os = "linux")]
            &self.base.options.lock().unwrap().tap_mac_script,
        );
        self.base.on_vm_change(&keys, &macs);
        self.base.on_tap_interface_change(interfaces, if_mac_source);
    }

    fn get_mapped_macs(
        &self,
        interfaces: &Vec<Link>,
        if_mac_source: IfMacSource,
        trident_type: TridentType,
        #[cfg(target_os = "linux")] tap_mac_script: &str,
    ) -> Vec<MacAddr> {
        let mut macs = vec![];

        #[cfg(any(target_os = "windows", target_os = "android"))]
        let index_to_mac_map = Self::get_if_index_to_inner_mac_map();
        #[cfg(target_os = "linux")]
        let index_to_mac_map =
            Self::get_if_index_to_inner_mac_map(&self.base.platform_poller, &self.base.netns);

        #[cfg(target_os = "linux")]
        let name_to_mac_map = self.get_if_name_to_mac_map(tap_mac_script);

        for iface in interfaces.iter() {
            if !index_to_mac_map.is_empty() {
                // kubernetes环境POD场景，需要根据平台数据来获取TAP口对应的主机MAC
                if let Some(mac) = index_to_mac_map.get(&iface.if_index) {
                    macs.push(*mac);
                    continue;
                }
            }
            macs.push(match if_mac_source {
                IfMacSource::IfMac => {
                    let mut mac = iface.mac_addr;
                    if trident_type == TridentType::TtProcess {
                        let mut octets = mac.octets().to_owned();
                        octets[0] = 0;
                        mac = octets.into();
                    }
                    mac
                }
                IfMacSource::IfName => {
                    let new_mac = self.rewriter.regenerate_mac(iface);
                    if log_enabled!(log::Level::Debug) && new_mac != iface.mac_addr {
                        debug!(
                            "Dispatcher{} interface {} rewrite mac {} -> {}",
                            self.base.log_id, iface.name, iface.mac_addr, new_mac
                        );
                    }
                    new_mac
                }
                #[cfg(target_os = "linux")]
                IfMacSource::IfLibvirtXml => {
                    *name_to_mac_map.get(&iface.name).unwrap_or(&iface.mac_addr)
                }
                #[cfg(any(target_os = "windows", target_os = "android"))]
                IfMacSource::IfLibvirtXml => MacAddr::ZERO,
            });
        }
        macs
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn get_if_name_to_mac_map(&self, tap_mac_script: &str) -> HashMap<String, MacAddr> {
        let mut result = HashMap::new();
        #[cfg(target_os = "linux")]
        if let Some(entries) = self.extractor.get_entries() {
            debug!("Xml Mac:");
            for entry in entries {
                debug!("\tif_name: {}, mac: {}", entry.name, entry.mac);
                result.insert(entry.name, entry.mac);
            }
        }
        if tap_mac_script != "" {
            match Command::new(&tap_mac_script).output() {
                Ok(output) => Self::parse_tap_mac_script_output(&mut result, &output.stdout),
                Err(e) => warn!("Exec {} failed: {:?}", tap_mac_script, e),
            }
        }
        result
    }

    pub fn parse_tap_mac_script_output(result: &mut HashMap<String, MacAddr>, bytes: &[u8]) {
        let mut iter = bytes.split(|x| *x == b'\n');
        while let Some(line) = iter.next() {
            let mut kvs = line.split(|x| *x == b',');
            let name = kvs.next();
            let mac = kvs.next();
            if name.is_none() || mac.is_none() || kvs.next().is_some() {
                warn!(
                    "Static-config tap-mac-map has invalid item: {}",
                    str::from_utf8(line).unwrap()
                );
            }
            let name = str::from_utf8(name.unwrap()).unwrap();
            if result.contains_key(name) {
                debug!(
                    "Ignore static-config tap-mac-map: {}",
                    str::from_utf8(line).unwrap()
                );
            } else if let Ok(mac) = str::from_utf8(mac.unwrap()).unwrap().parse() {
                result.insert(name.to_owned(), mac);
            }
        }
    }
}

#[cfg(any(target_os = "windows", target_os = "android"))]
impl LocalModeDispatcherListener {
    pub fn get_if_index_to_inner_mac_map() -> HashMap<u32, MacAddr> {
        let mut result = HashMap::new();

        match public::utils::net::link_list() {
            Ok(links) => {
                if result.len() == 0 {
                    debug!("Poller Mac:");
                }
                for link in links {
                    if link.mac_addr != MacAddr::ZERO && !result.contains_key(&link.if_index) {
                        debug!("\tif_index: {}, mac: {}", link.if_index, link.mac_addr);
                        result.insert(link.if_index, link.mac_addr);
                    }
                }
            }
            Err(e) => warn!("failed getting link list: {:?}", e),
        }

        result
    }
}

#[cfg(target_os = "linux")]
impl LocalModeDispatcherListener {
    pub fn get_if_index_to_inner_mac_map(
        poller: &GenericPoller,
        ns: &public::netns::NsFile,
    ) -> HashMap<u32, MacAddr> {
        let mut result = HashMap::new();

        match poller.get_interface_info_in(ns) {
            Some(entries) if !entries.is_empty() => {
                debug!("Poller Mac:");
                for entry in entries {
                    debug!("\tif_index: {}, mac: {}, mapped", entry.tap_idx, entry.mac);
                    result.insert(entry.tap_idx, entry.mac);
                }
            }
            _ => return result,
        }

        match public::netns::link_list_in_netns(ns) {
            Ok(links) => {
                if result.len() == 0 {
                    debug!("Poller Mac:");
                }
                for link in links {
                    if link.mac_addr != MacAddr::ZERO && !result.contains_key(&link.if_index) {
                        debug!(
                            "\tif_index: {}, mac: {}, not mapped",
                            link.if_index, link.mac_addr
                        );
                        result.insert(link.if_index, link.mac_addr);
                    }
                }
            }
            Err(e) => warn!("failed getting link list: {:?}", e),
        }

        result
    }
}

#[derive(Clone)]
pub struct MacRewriter {
    contrail_regex: Regex,
    qing_cloud_vm_regex: Regex,
    qing_cloud_sriov_regex: Regex,
    qing_cloud_sriov_mac_regex: Regex,
    tce_cloud_dpdk_regex: Regex,
}

impl MacRewriter {
    const CONTRAIL_REGEX: &'static str = "^tap[0-9a-f]{8}-[0-9a-f]{2}$";
    const QING_CLOUD_VM_REGEX: &'static str = "^[0-9a-f]{8}";
    const QING_CLOUD_SRIOV_REGEX: &'static str = "^[0-9a-zA-Z]+_[0-9]{1,3}$";
    const QING_CLOUD_SRIOV_MAC_REGEX: &'static str = "^52:54:9b";
    const TCE_CLOUD_DPDK_REGEX: &'static str = "^veth_[0-9a-fA-F]{8}$";

    pub fn new() -> Self {
        Self {
            // Contrail中，tap口的MAC与虚拟机内部MAC无关，但其名字后缀是虚拟机MAC后缀
            contrail_regex: Regex::new(Self::CONTRAIL_REGEX).unwrap(),
            qing_cloud_vm_regex: Regex::new(Self::QING_CLOUD_VM_REGEX).unwrap(),
            qing_cloud_sriov_regex: Regex::new(Self::QING_CLOUD_SRIOV_REGEX).unwrap(),
            qing_cloud_sriov_mac_regex: Regex::new(Self::QING_CLOUD_SRIOV_MAC_REGEX).unwrap(),
            tce_cloud_dpdk_regex: Regex::new(Self::TCE_CLOUD_DPDK_REGEX).unwrap(),
        }
    }

    pub fn regenerate_mac(&self, interface: &Link) -> MacAddr {
        let ifname = &interface.name;
        if self.contrail_regex.is_match(ifname) {
            // safe unwrap because string matched
            let mac_4b = u64::from_str_radix(&ifname[3..11], 16).unwrap();
            let mac_1b = u64::from_str_radix(&ifname[12..14], 16).unwrap();
            MacAddr::try_from(mac_4b << 8 | mac_1b).unwrap()
        } else if self.qing_cloud_vm_regex.is_match(ifname) {
            // safe unwrap because string matched
            MacAddr::try_from(u64::from_str_radix(&ifname[..8], 16).unwrap()).unwrap()
        } else if self.qing_cloud_sriov_regex.is_match(ifname) {
            self.get_mac_by_bridge_fdb(interface)
                .unwrap_or(interface.mac_addr)
        } else if self.tce_cloud_dpdk_regex.is_match(ifname) {
            let first = u8::from_str_radix(&ifname[5..7], 16).unwrap();
            let second = u8::from_str_radix(&ifname[7..9], 16).unwrap();
            let thired = u8::from_str_radix(&ifname[9..11], 16).unwrap();
            MacAddr::from([0, 0, 0, first, second, thired])
        } else {
            interface.mac_addr
        }
    }

    fn get_mac_by_bridge_fdb(&self, interface: &Link) -> Option<MacAddr> {
        let output = match Command::new("bridge")
            .args(["fdb", "show", "dev", &interface.name])
            .output()
        {
            Ok(output) => output.stdout,
            Err(e) => {
                warn!("bridge command failed: {}", e);
                return None;
            }
        };
        for line in output.split(|x| *x == b'\n') {
            let mut iter = line.split(|x| *x == b' ');
            if let Some(part) = iter.next() {
                let s = str::from_utf8(part).unwrap();
                if self.qing_cloud_sriov_mac_regex.is_match(s) {
                    return match s.parse::<MacAddr>() {
                        Ok(mac) => Some(mac),
                        Err(e) => {
                            warn!("{:?}", e);
                            None
                        }
                    };
                }
            }
        }
        warn!("interface mac not found in bridge fdb");
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_rewrite() {
        let rewriter = MacRewriter::new();
        for case in vec![
            (
                "qingcloud2",
                Link {
                    name: "aabbccdd".into(),
                    mac_addr: "a1:01:02:03:04:05".parse().unwrap(),
                    ..Default::default()
                },
                "00:00:aa:bb:cc:dd",
            ),
            (
                "qingcloud",
                Link {
                    name: "aabbccdd@if252".into(),
                    mac_addr: "a1:01:02:03:04:05".parse().unwrap(),
                    ..Default::default()
                },
                "00:00:aa:bb:cc:dd",
            ),
            (
                "tap",
                Link {
                    name: "tap01234567-89".into(),
                    mac_addr: "a1:01:02:03:04:05".parse().unwrap(),
                    ..Default::default()
                },
                "00:01:23:45:67:89",
            ),
            (
                "lo",
                Link {
                    name: "lo".into(),
                    mac_addr: "00:00:00:00:00:01".parse().unwrap(),
                    ..Default::default()
                },
                "00:00:00:00:00:01",
            ),
        ] {
            assert_eq!(
                &rewriter.regenerate_mac(&case.1).to_string(),
                case.2,
                "case {} failed",
                case.0
            );
        }
    }

    #[test]
    fn parse_mac_script_output() {
        let bs = "abcdefg,11:22:33:44:55:66";
        let mut m = HashMap::new();
        LocalModeDispatcherListener::parse_tap_mac_script_output(&mut m, bs.as_bytes());
        assert_eq!(
            m.get("abcdefg"),
            Some(&"11:22:33:44:55:66".parse().unwrap())
        );
    }
}
