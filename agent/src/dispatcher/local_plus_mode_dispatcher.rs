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

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::collections::HashMap;
use std::collections::HashSet;
use std::mem::drop;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::process::Command;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::str;
use std::sync::{atomic::Ordering, Arc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use arc_swap::access::Access;
use log::{debug, info, log_enabled, warn};

use super::base_dispatcher::{BaseDispatcher, BaseDispatcherListener};
use super::error::Result;
use super::local_mode_dispatcher::{LocalModeDispatcherListener, MacRewriter};

#[cfg(target_os = "linux")]
use crate::platform::LibvirtXmlExtractor;
use crate::{
    common::{
        decapsulate::{TunnelInfo, TunnelType},
        enums::{EthernetType, TapType},
        MetaPacket, TapPort, FIELD_OFFSET_ETH_TYPE, MAC_ADDR_LEN, VLAN_HEADER_SIZE,
    },
    config::DispatcherConfig,
    flow_generator::{flow_map::Config, FlowMap},
    handler::MiniPacket,
    rpc::get_timestamp,
    utils::{
        bytes::read_u16_be,
        stats::{self, Countable, QueueStats},
    },
};
use public::{
    buffer::{Allocator, BatchedBuffer},
    debug::QueueDebugger,
    proto::{common::TridentType, trident::IfMacSource},
    queue::{self, bounded_with_debug, DebugSender, Receiver},
    utils::net::{Link, MacAddr},
};

#[derive(Debug)]
struct Packet {
    timestamp: Duration,
    raw: BatchedBuffer<u8>,
    original_length: u32,
    raw_length: u32,
    if_index: isize,
}

const HANDLER_BATCH_SIZE: usize = 64;

pub(super) struct LocalPlusModeDispatcher {
    pub(super) base: BaseDispatcher,
    #[cfg(target_os = "linux")]
    pub(super) extractor: Arc<LibvirtXmlExtractor>,
    pub(super) queue_debugger: Arc<QueueDebugger>,
    pub(super) stats_collector: Arc<stats::Collector>,
    pub(super) flow_generator_thread_handler: Option<JoinHandle<()>>,
    pub(super) pipeline_thread_handler: Option<JoinHandle<()>>,
    pub(super) inner_queue_size: usize,
    pub(super) raw_packet_block_size: usize,
    pub(super) pool_raw_size: usize,
}

impl LocalPlusModeDispatcher {
    const VALID_MAC_INDEX: usize = 3;

    // This thread implements the following functions:
    // 1. Decap tunnel
    // 2. Lookup l2end
    // 3. Generate MetaPacket
    // 4. Generate tagged flow
    fn run_flow_generator(
        &mut self,
        receiver: Receiver<Packet>,
        sender: DebugSender<MiniPacket<'static>>,
    ) {
        let base = &self.base;

        let terminated = base.terminated.clone();
        let counter = base.counter.clone();
        let id = base.id;
        let flow_output_queue = base.flow_output_queue.clone();
        let l7_stats_output_queue = base.l7_stats_output_queue.clone();
        let policy_getter = base.policy_getter;
        let log_output_queue = base.log_output_queue.clone();
        let ntp_diff = base.ntp_diff.clone();
        let flow_map_config = base.flow_map_config.clone();
        let log_parse_config = base.log_parse_config.clone();
        let collector_config = base.collector_config.clone();
        let packet_sequence_output_queue = base.packet_sequence_output_queue.clone(); // Enterprise Edition Feature: packet-sequence
        let stats = base.stats.clone();
        let pipelines = base.pipelines.clone();
        let tunnel_type_bitmap = base.tunnel_type_bitmap.clone();
        let tap_type_handler = base.tap_type_handler.clone();
        let mut tunnel_info = TunnelInfo::default();
        let npb_dedup_enabled = base.npb_dedup_enabled.clone();
        let ctrl_mac = base.ctrl_mac;
        let pool_raw_size = self.pool_raw_size;

        self.flow_generator_thread_handler.replace(
            thread::Builder::new()
                .name("dispatcher-packet-to-flow-generator".to_owned())
                .spawn(move || {
                    let mut batch = Vec::with_capacity(HANDLER_BATCH_SIZE);
                    let mut output_batch = Vec::with_capacity(HANDLER_BATCH_SIZE);
                    let mut flow_map = FlowMap::new(
                        id as u32,
                        flow_output_queue,
                        l7_stats_output_queue,
                        policy_getter,
                        log_output_queue,
                        ntp_diff,
                        &flow_map_config.load(),
                        Some(packet_sequence_output_queue), // Enterprise Edition Feature: packet-sequence
                        stats,
                        false, // !from_ebpf
                    );

                    while !terminated.load(Ordering::Relaxed) {
                        let config = Config {
                            flow: &flow_map_config.load(),
                            log_parser: &log_parse_config.load(),
                            collector: &collector_config.load(),
                            #[cfg(any(target_os = "linux", target_os = "android"))]
                            ebpf: None,
                        };

                        match receiver.recv_all(&mut batch, Some(Duration::from_secs(1))) {
                            Ok(_) => {}
                            Err(queue::Error::Timeout) => {
                                flow_map.inject_flush_ticker(&config, Duration::ZERO);
                                continue;
                            }
                            Err(queue::Error::Terminated(..)) => break,
                            Err(queue::Error::BatchTooLarge(_)) => unreachable!(),
                        }

                        for mut packet in batch.drain(..) {
                            let pipeline = {
                                let pipelines = pipelines.lock().unwrap();
                                if let Some(p) = pipelines.get(&(packet.if_index as u32)) {
                                    p.clone()
                                } else if pipelines.is_empty() {
                                    continue;
                                } else {
                                    // send to one of the pipelines if packet is LLDP
                                    let mut eth_type: EthernetType =
                                        read_u16_be(&packet.raw[FIELD_OFFSET_ETH_TYPE..]).into();
                                    if eth_type == EthernetType::DOT1Q {
                                        eth_type = read_u16_be(
                                            &packet.raw[FIELD_OFFSET_ETH_TYPE + VLAN_HEADER_SIZE..],
                                        )
                                        .into();
                                    }
                                    if eth_type != EthernetType::LINK_LAYER_DISCOVERY {
                                        continue;
                                    }
                                    pipelines.iter().next().unwrap().1.clone()
                                }
                            };
                            let pipeline = pipeline.lock().unwrap();
                            let mut timestamp = packet.timestamp;

                            if timestamp + Duration::from_millis(1) < pipeline.timestamp {
                                // FIXME: just in case
                                counter.retired.fetch_add(1, Ordering::Relaxed);
                                continue;
                            } else if timestamp < pipeline.timestamp {
                                timestamp = pipeline.timestamp;
                            }

                            // compare 3 low bytes
                            let mac_low = &pipeline.vm_mac.octets()[Self::VALID_MAC_INDEX..];
                            // src mac
                            let src_local = mac_low
                                == &packet.raw[MAC_ADDR_LEN + Self::VALID_MAC_INDEX
                                    ..MAC_ADDR_LEN + MAC_ADDR_LEN];
                            // dst mac
                            let dst_local = !src_local
                                && (mac_low == &packet.raw[Self::VALID_MAC_INDEX..MAC_ADDR_LEN]
                                    || MacAddr::is_multicast(&packet.raw));

                            // LOCAL模式L2END使用underlay网络的MAC地址，实际流量解析使用overlay
                            let cur_tunnel_type_bitmap = tunnel_type_bitmap.lock().unwrap().clone();
                            let decap_length = match BaseDispatcher::decap_tunnel(
                                &mut packet.raw,
                                &tap_type_handler,
                                &mut tunnel_info,
                                cur_tunnel_type_bitmap,
                            ) {
                                Ok((l, _)) => l,
                                Err(e) => {
                                    counter.invalid_packets.fetch_add(1, Ordering::Relaxed);
                                    warn!("decap_tunnel failed: {:?}", e);
                                    continue;
                                }
                            };
                            let original_length = packet.raw.len() - decap_length;
                            let raw_length = (packet.raw_length as usize)
                                .min(packet.raw.len())
                                .min(pool_raw_size);
                            let mut overlay_packet = packet.raw;
                            overlay_packet.truncate(decap_length..raw_length);
                            let mut meta_packet = MetaPacket::empty();
                            let offset = Duration::ZERO;
                            if let Err(e) = meta_packet.update(
                                overlay_packet,
                                src_local,
                                dst_local,
                                timestamp + offset,
                                original_length,
                            ) {
                                counter.invalid_packets.fetch_add(1, Ordering::Relaxed);
                                warn!("meta_packet update failed: {:?}", e);
                                continue;
                            }

                            if tunnel_info.tunnel_type != TunnelType::None {
                                meta_packet.tunnel = Some(tunnel_info);
                                if tunnel_info.tunnel_type == TunnelType::TencentGre
                                    || tunnel_info.tunnel_type == TunnelType::Vxlan
                                {
                                    // 腾讯TCE、青云私有云需要通过TunnelID查询云平台信息
                                    // 这里只需要考虑单层隧道封装的情况
                                    // 双层封装的场景下认为内层MAC存在且有效（VXLAN-VXLAN）或者需要通过IP来判断（VXLAN-IPIP）
                                    meta_packet.lookup_key.tunnel_id = tunnel_info.id;
                                }
                            } else {
                                // 无隧道并且MAC地址都是0一定是loopback流量
                                if meta_packet.lookup_key.src_mac == MacAddr::ZERO
                                    && meta_packet.lookup_key.dst_mac == MacAddr::ZERO
                                {
                                    meta_packet.lookup_key.src_mac = ctrl_mac;
                                    meta_packet.lookup_key.dst_mac = ctrl_mac;
                                    meta_packet.lookup_key.l2_end_0 = true;
                                    meta_packet.lookup_key.l2_end_1 = true;
                                }
                            }

                            meta_packet.tap_port = TapPort::from_local_mac(
                                meta_packet.lookup_key.get_nat_source(),
                                tunnel_info.tunnel_type,
                                u64::from(pipeline.vm_mac) as u32,
                            );
                            BaseDispatcher::prepare_flow(
                                &mut meta_packet,
                                TapType::Cloud,
                                false,
                                id as u8,
                                npb_dedup_enabled.load(Ordering::Relaxed),
                            );

                            flow_map.inject_meta_packet(&config, &mut meta_packet);
                            let mini_packet = MiniPacket::new(
                                meta_packet.raw.take().unwrap(),
                                &meta_packet,
                                packet.if_index,
                            );
                            drop(meta_packet);
                            output_batch.push(mini_packet);
                        }
                        if let Err(e) = sender.send_all(&mut output_batch) {
                            debug!(
                                "dispatcher-meta-packet-flow-generator {} sender failed: {:?}",
                                id, e
                            );
                            output_batch.clear();
                        }
                    }
                })
                .unwrap(),
        );
    }

    // This thread implements the following functions:
    // 1. Lookup pipeline
    // 2. NPB/PCAP/...
    fn run_additional_packet_pipeline(&mut self, receiver: Receiver<MiniPacket<'static>>) {
        let base = &self.base;
        let terminated = base.terminated.clone();
        let pipelines = base.pipelines.clone();

        self.pipeline_thread_handler.replace(
            thread::Builder::new()
                .name("dispatcher-additional-packet-pipeline".to_owned())
                .spawn(move || {
                    let mut batch = Vec::with_capacity(HANDLER_BATCH_SIZE);
                    while !terminated.load(Ordering::Relaxed) {
                        match receiver.recv_all(&mut batch, Some(Duration::from_secs(1))) {
                            Ok(_) => {}
                            Err(queue::Error::Timeout) => continue,
                            Err(queue::Error::Terminated(..)) => break,
                            Err(queue::Error::BatchTooLarge(_)) => unreachable!(),
                        }

                        for mini_packet in batch.drain(..) {
                            let pipeline = {
                                let pipelines = pipelines.lock().unwrap();
                                if let Some(p) = pipelines.get(&(mini_packet.if_index() as u32)) {
                                    p.clone()
                                } else if pipelines.is_empty() {
                                    continue;
                                } else {
                                    // send to one of the pipelines if packet is LLDP
                                    let raw = mini_packet.raw();
                                    let mut eth_type: EthernetType =
                                        read_u16_be(&raw[FIELD_OFFSET_ETH_TYPE..]).into();
                                    if eth_type == EthernetType::DOT1Q {
                                        eth_type = read_u16_be(
                                            &raw[FIELD_OFFSET_ETH_TYPE + VLAN_HEADER_SIZE..],
                                        )
                                        .into();
                                    }
                                    if eth_type != EthernetType::LINK_LAYER_DISCOVERY {
                                        continue;
                                    }
                                    pipelines.iter().next().unwrap().1.clone()
                                }
                            };
                            let mut pipeline = pipeline.lock().unwrap();

                            for i in pipeline.handlers.iter_mut() {
                                i.handle(&mini_packet);
                            }
                        }
                    }
                })
                .unwrap(),
        );
    }

    fn setup_inner_thread_and_queue(&mut self) -> DebugSender<Packet> {
        let id = self.base.id;
        let name = "0.1-raw-packet-to-flow-generator";
        let (sender_to_parser, receiver_from_dispatcher, counter) =
            bounded_with_debug(self.inner_queue_size, name, &self.queue_debugger);
        self.stats_collector.register_countable(
            &QueueStats { id, module: name },
            Countable::Owned(Box::new(counter)),
        );

        let name = "0.2-packet-to-additional-pipeline";
        let (sender_to_pipeline, receiver_from_flow, counter) =
            bounded_with_debug(self.inner_queue_size, name, &self.queue_debugger);
        self.stats_collector.register_countable(
            &QueueStats { id, module: name },
            Countable::Owned(Box::new(counter)),
        );

        self.run_flow_generator(receiver_from_dispatcher, sender_to_pipeline);
        self.run_additional_packet_pipeline(receiver_from_flow);
        return sender_to_parser;
    }

    pub(super) fn run(&mut self) {
        let sender_to_parser = self.setup_inner_thread_and_queue();
        let base = &mut self.base;
        info!("Start local plus dispatcher {}", base.log_id);
        let time_diff = base.ntp_diff.load(Ordering::Relaxed);
        let mut prev_timestamp = get_timestamp(time_diff);
        let id = base.id;
        let mut batch = Vec::with_capacity(HANDLER_BATCH_SIZE);
        let mut allocator = Allocator::new(self.raw_packet_block_size);

        while !base.terminated.load(Ordering::Relaxed) {
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
            if recved.is_none() || batch.len() >= HANDLER_BATCH_SIZE {
                if let Err(e) = sender_to_parser.send_all(&mut batch) {
                    debug!("dispatcher {} sender failed: {:?}", id, e);
                    batch.clear();
                }
            }
            if recved.is_none() {
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

            let (packet, timestamp) = recved.unwrap();

            base.counter.rx.fetch_add(1, Ordering::Relaxed);
            base.counter
                .rx_bytes
                .fetch_add(packet.capture_length as u64, Ordering::Relaxed);
            if base.tap_interface_whitelist.next_sync(timestamp.into()) {
                base.need_update_bpf.store(true, Ordering::Relaxed);
            }

            let buffer = allocator.allocate_with(&packet.data);
            let info = Packet {
                timestamp,
                raw: buffer,
                original_length: packet.capture_length as u32,
                raw_length: packet.data.len() as u32,
                if_index: packet.if_index,
            };
            batch.push(info);

            drop(packet);
            base.check_and_update_bpf();
        }
        if let Some(handler) = self.flow_generator_thread_handler.take() {
            let _ = handler.join();
        }
        if let Some(handler) = self.pipeline_thread_handler.take() {
            let _ = handler.join();
        }

        base.terminate_handler();
        info!("Stopped dispatcher {}", base.log_id);
    }

    pub(super) fn listener(&self) -> LocalPlusModeDispatcherListener {
        #[cfg(target_os = "linux")]
        return LocalPlusModeDispatcherListener::new(self.base.listener(), self.extractor.clone());

        #[cfg(any(target_os = "windows", target_os = "android"))]
        return LocalPlusModeDispatcherListener::new(self.base.listener());
    }
}

impl LocalPlusModeDispatcher {
    pub(super) fn switch_recv_engine(&mut self, config: &DispatcherConfig) -> Result<()> {
        self.base.switch_recv_engine(config)
    }
}

#[derive(Clone)]
pub struct LocalPlusModeDispatcherListener {
    base: BaseDispatcherListener,
    #[cfg(target_os = "linux")]
    extractor: Arc<LibvirtXmlExtractor>,
    rewriter: MacRewriter,
}

impl LocalPlusModeDispatcherListener {
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
        let index_to_mac_map = LocalModeDispatcherListener::get_if_index_to_inner_mac_map();
        #[cfg(target_os = "linux")]
        let index_to_mac_map = LocalModeDispatcherListener::get_if_index_to_inner_mac_map(
            &self.base.platform_poller,
            &self.base.netns,
        );

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
                Ok(output) => LocalModeDispatcherListener::parse_tap_mac_script_output(
                    &mut result,
                    &output.stdout,
                ),
                Err(e) => warn!("Exec {} failed: {:?}", tap_mac_script, e),
            }
        }
        result
    }
}
