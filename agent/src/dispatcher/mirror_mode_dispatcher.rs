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

use std::{
    collections::HashMap,
    mem::drop,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use arc_swap::access::Access;
#[cfg(any(target_os = "linux", target_os = "android"))]
use log::debug;
use log::{info, warn};

#[cfg(windows)]
use super::TapTypeHandler;

#[cfg(windows)]
use crate::common::decapsulate::TunnelTypeBitmap;
#[cfg(target_os = "linux")]
use crate::platform::{GenericPoller, Poller};
use crate::{
    common::{
        decapsulate::{TunnelInfo, TunnelType},
        enums::TapType,
        MetaPacket, TapPort,
    },
    config::DispatcherConfig,
    dispatcher::{
        base_dispatcher::{BaseDispatcher, BaseDispatcherListener},
        error::{Error, Result},
        PacketCounter,
    },
    flow_generator::{flow_map::Config, FlowMap},
    handler::PacketHandlerBuilder,
    handler::{MiniPacket, PacketHandler},
    rpc::get_timestamp,
    utils::environment::is_tt_hyper_v_compute,
};
use packet_dedup::PacketDedupMap;
#[cfg(windows)]
use public::packet::Packet;
use public::{
    proto::{common::TridentType, trident::IfMacSource},
    utils::net::{Link, MacAddr},
};

const IF_INDEX_MAX_SIZE: usize = 1000;

#[derive(Clone)]
pub struct MirrorModeDispatcherListener {
    local_vm_mac_set: Arc<Mutex<HashMap<u32, bool>>>,
    updated: Arc<AtomicBool>,
    #[cfg(target_os = "linux")]
    poller: Option<Arc<GenericPoller>>,
    trident_type: Arc<Mutex<TridentType>>,
    base: BaseDispatcherListener,
}

impl MirrorModeDispatcherListener {
    #[cfg(target_os = "linux")]
    pub fn netns(&self) -> &public::netns::NsFile {
        &self.base.netns
    }

    pub fn on_tap_interface_change(&self, _: &[Link], _: IfMacSource, trident_type: TridentType) {
        let mut old_trident_type = self.trident_type.lock().unwrap();
        *old_trident_type = trident_type;
        self.base
            .on_tap_interface_change(vec![], IfMacSource::IfMac);
    }

    pub fn on_vm_change_with_bridge_macs(
        &self,
        vm_mac_addrs: &[MacAddr],
        tap_bridge_macs: &Vec<MacAddr>,
    ) {
        let mut new_vm_mac_set = HashMap::new();

        vm_mac_addrs.iter().for_each(|e| {
            let key = e.to_lower_32b();
            new_vm_mac_set.insert(key, true);
        });
        tap_bridge_macs.iter().for_each(|e| {
            let key = e.to_lower_32b();
            new_vm_mac_set.insert(key, true);
        });
        let mut old_vm_mac_set = self.local_vm_mac_set.lock().unwrap();
        let mut new_macs = vec![];
        let mut delete_macs = vec![];
        new_vm_mac_set.iter().for_each(|e| {
            if old_vm_mac_set.get(e.0).is_none() {
                new_macs.push(MacAddr::try_from(*e.0 as u64).unwrap());
            }
        });
        old_vm_mac_set.iter().for_each(|e| {
            if new_vm_mac_set.get(e.0).is_none() {
                delete_macs.push(MacAddr::try_from(*e.0 as u64).unwrap());
            }
        });
        if new_macs.len() == 0 && delete_macs.len() == 0 {
            return;
        }
        if new_macs.len() > 0 {
            info!("Dispatcher{} Add vm macs: {:?}", self.base.log_id, new_macs);
        }
        if delete_macs.len() > 0 {
            info!(
                "Dispatcher{} Delete vm macs: {:?}",
                self.base.log_id, delete_macs
            );
        }
        *old_vm_mac_set = new_vm_mac_set;
        self.updated.store(true, Ordering::Relaxed);
    }

    pub fn on_vm_change(&self, vm_mac_addrs: &[MacAddr]) {
        #[cfg(target_os = "linux")]
        self.on_vm_change_with_bridge_macs(
            vm_mac_addrs,
            &self.tap_bridge_inner_macs(self.base.src_interface_index),
        );
        #[cfg(any(target_os = "windows", target_os = "android"))]
        self.on_vm_change_with_bridge_macs(vm_mac_addrs, &vec![]);
    }

    pub(super) fn on_config_change(&mut self, config: &DispatcherConfig) {
        self.base.on_config_change(config)
    }

    pub fn id(&self) -> usize {
        return self.base.id;
    }

    pub fn flow_acl_change(&self) {
        // Start capturing traffic after resource information is distributed
        self.base.pause.store(false, Ordering::Relaxed);
        self.base.reset_whitelist.store(true, Ordering::Relaxed);
    }
}

#[cfg(target_os = "linux")]
impl MirrorModeDispatcherListener {
    fn tap_bridge_inner_macs(&self, if_index: usize) -> Vec<MacAddr> {
        if self.poller.is_none() {
            debug!("Dispatcher{} Poller is none.", self.base.log_id);
            return vec![];
        }
        if if_index == 0 {
            debug!(
                "Dispatcher{} Mirror mode tap-bridge src-interface ifindex == 0",
                self.base.log_id
            );
            return vec![];
        }
        let mut macs = vec![];
        let ifaces = self.poller.as_ref().unwrap().get_interface_info();
        if ifaces.len() == 0 {
            debug!(
                "Dispatcher{} Mirror mode tap-bridge macs is nill.",
                self.base.log_id
            );
            return macs;
        }
        for iface in ifaces {
            if iface.tap_idx as usize == if_index {
                macs.push(iface.mac);
            }
        }
        debug!(
            "Dispatcher{} TapBridge: Src-IfIndex {} MAC {:?}",
            self.base.log_id, if_index, macs
        );
        return macs;
    }
}

pub(super) struct MirrorPipeline {
    handlers: Vec<PacketHandler>,
}

pub(super) struct LastTimestamps {
    if_index: isize,
    last_timestamp: Duration,
}

pub(super) struct MirrorModeDispatcher {
    pub(super) base: BaseDispatcher,
    pub(super) dedup: PacketDedupMap,
    pub(super) local_vm_mac_set: Arc<Mutex<HashMap<u32, bool>>>,
    pub(super) local_segment_macs: Vec<MacAddr>,
    pub(super) tap_bridge_macs: Vec<MacAddr>,
    #[cfg(target_os = "linux")]
    pub(super) poller: Option<Arc<GenericPoller>>,
    pub(super) pipelines: HashMap<u32, MirrorPipeline>,
    pub(super) updated: Arc<AtomicBool>,
    pub(super) trident_type: Arc<Mutex<TridentType>>,
    pub(super) mac: u32,
    pub(super) last_timestamp_array: Vec<LastTimestamps>,
}

impl MirrorModeDispatcher {
    pub(super) fn init(&mut self) -> Result<()> {
        info!(
            "Mirror mode dispatcher {} init with 0x{:x}.",
            self.base.id, self.mac
        );
        self.base.init()
    }

    pub(super) fn listener(&self) -> MirrorModeDispatcherListener {
        MirrorModeDispatcherListener {
            local_vm_mac_set: self.local_vm_mac_set.clone(),
            updated: self.updated.clone(),
            base: self.base.listener(),
            trident_type: self.trident_type.clone(),
            #[cfg(target_os = "linux")]
            poller: self.poller.clone(),
        }
    }

    fn get_key(
        vm_mac_set: &Arc<Mutex<HashMap<u32, bool>>>,
        overlay_packet: &[u8],
        tunnel_info: TunnelInfo,
    ) -> (u32, u32, bool, bool) {
        let (da_key, sa_key) =
            if tunnel_info.tier == 0 && overlay_packet.len() >= super::L2_MAC_ADDR_OFFSET {
                let mut da_mac: [u8; 6] = [0; 6];
                let mut sa_mac: [u8; 6] = [0; 6];
                da_mac.copy_from_slice(&overlay_packet[..6]);
                sa_mac.copy_from_slice(&overlay_packet[6..12]);
                (
                    MacAddr::from(da_mac).to_lower_32b(),
                    MacAddr::from(sa_mac).to_lower_32b(),
                )
            } else {
                (tunnel_info.mac_dst, tunnel_info.mac_src)
            };

        let vm_mac_set = vm_mac_set.lock().unwrap();
        return (
            da_key,
            sa_key,
            vm_mac_set.contains_key(&da_key),
            vm_mac_set.contains_key(&sa_key),
        );
    }

    fn get_pipeline<'a>(
        updated: &'a Arc<AtomicBool>,
        pipelines: &'a mut HashMap<u32, MirrorPipeline>,
        key: u32,
        id: usize,
        handler_builder: &Arc<Mutex<Vec<PacketHandlerBuilder>>>,
    ) -> &'a mut MirrorPipeline {
        if updated.load(Ordering::Relaxed) {
            pipelines.clear();
            pipelines.shrink_to_fit();
            updated.store(false, Ordering::Relaxed);
        }

        match pipelines.contains_key(&key) {
            true => pipelines.get_mut(&key).unwrap(),
            false => {
                let handlers = handler_builder
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|b| b.build_with(id, 0, MacAddr::try_from(key as u64).unwrap()))
                    .collect();
                let value = MirrorPipeline { handlers };
                pipelines.insert(key, value);

                pipelines.get_mut(&key).unwrap()
            }
        }
    }

    fn get_meta_packet<'a>(
        timestamp: Duration,
        overlay_packet: &'a [u8],
        counter: &Arc<PacketCounter>,
        tunnel_info: &'a TunnelInfo,
        src_local: bool,
        dst_local: bool,
        original_length: usize,
    ) -> Result<MetaPacket<'a>> {
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
            return Err(Error::PacketInvalid(format!("with {:?}", e)));
        }

        if tunnel_info.tunnel_type != TunnelType::None {
            meta_packet.tunnel = Some(*tunnel_info);
        }

        Ok(meta_packet)
    }

    fn handler(
        id: usize,
        key: u32,
        src_local: bool,
        dst_local: bool,
        overlay_packet: &[u8],
        timestamp: Duration,
        original_length: usize,
        updated: &Arc<AtomicBool>,
        pipelines: &mut HashMap<u32, MirrorPipeline>,
        handler_builder: &Arc<Mutex<Vec<PacketHandlerBuilder>>>,
        tunnel_info: &TunnelInfo,
        config: &Config,
        flow_map: &mut FlowMap,
        counter: &Arc<PacketCounter>,
        trident_type: TridentType,
        mac: u32,
        npb_dedup: bool,
    ) -> Result<()> {
        let pipeline = Self::get_pipeline(updated, pipelines, key, id, handler_builder);

        let mut meta_packet = Self::get_meta_packet(
            timestamp,
            &overlay_packet,
            counter,
            tunnel_info,
            src_local,
            dst_local,
            original_length,
        )?;

        Self::prepare_flow(
            &mut meta_packet,
            tunnel_info.tunnel_type,
            key,
            id as u8,
            trident_type,
            mac,
            npb_dedup,
        );
        // flowProcesser
        flow_map.inject_meta_packet(&config, &mut meta_packet);
        let mini_packet = MiniPacket::new(overlay_packet, &meta_packet, 0);
        for i in pipeline.handlers.iter_mut() {
            i.handle(&mini_packet);
        }

        Ok(())
    }

    pub(super) fn run(&mut self) {
        info!("Start mirror dispatcher {}", self.base.log_id);
        let time_diff = self.base.ntp_diff.load(Ordering::Relaxed);
        let mut prev_timestamp = get_timestamp(time_diff);

        let mut flow_map = FlowMap::new(
            self.base.id as u32,
            self.base.flow_output_queue.clone(),
            self.base.l7_stats_output_queue.clone(),
            self.base.policy_getter,
            self.base.log_output_queue.clone(),
            self.base.ntp_diff.clone(),
            &self.base.flow_map_config.load(),
            Some(self.base.packet_sequence_output_queue.clone()), // Enterprise Edition Feature: packet-sequence
            self.base.stats.clone(),
            false, // !from_ebpf
        );

        while !self.base.terminated.load(Ordering::Relaxed) {
            let config = Config {
                flow: &self.base.flow_map_config.load(),
                log_parser: &self.base.log_parse_config.load(),
                collector: &self.base.collector_config.load(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                ebpf: None,
            };
            if self.base.reset_whitelist.swap(false, Ordering::Relaxed) {
                self.base.tap_interface_whitelist.reset();
            }
            // The lifecycle of the recved will end before the next call to recv.
            let recved = unsafe {
                BaseDispatcher::recv(
                    &mut self.base.engine,
                    &self.base.leaky_bucket,
                    &self.base.exception_handler,
                    &mut prev_timestamp,
                    &self.base.counter,
                    &self.base.ntp_diff,
                )
            };
            if recved.is_none() {
                flow_map.inject_flush_ticker(&config, Duration::ZERO);
                if self.base.tap_interface_whitelist.next_sync(Duration::ZERO) {
                    self.base.need_update_bpf.store(true, Ordering::Relaxed);
                }
                drop(recved);
                self.base.check_and_update_bpf();
                continue;
            }
            if self.base.pause.load(Ordering::Relaxed) {
                continue;
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            let (packet, mut timestamp) = recved.unwrap();
            #[cfg(target_os = "windows")]
            let (mut packet, mut timestamp) = recved.unwrap();

            match Self::swap_last_timestamp(
                &mut self.last_timestamp_array,
                &self.base.counter,
                packet.if_index,
                timestamp,
            ) {
                Ok(last_timestamp) => timestamp = last_timestamp,
                Err(_) => continue,
            }

            self.base.counter.rx.fetch_add(1, Ordering::Relaxed);
            self.base
                .counter
                .rx_bytes
                .fetch_add(packet.capture_length as u64, Ordering::Relaxed);

            #[cfg(any(target_os = "linux", target_os = "android"))]
            let decap_length = 0;
            #[cfg(target_os = "windows")]
            let decap_length = {
                // Mirror Mode运行于Windows环境下时目前只有Hyper-V一个场景，由于Hyper-V加了VXLAN隧道，
                // 这里需要decap并将tunnel信息保存在flow中，目前仅保存最外层的tunnel
                let len = Self::decap_tunnel(
                    &mut packet,
                    &self.base.tap_type_handler,
                    &mut self.base.tunnel_info,
                    &self.base.tunnel_type_bitmap,
                    &self.base.counter,
                ) as usize;
                if len > packet.capture_length as usize {
                    warn!("Decap tunnel error.");
                    continue;
                }
                len
            };

            let original_length = packet.data.len() - decap_length;
            let overlay_packet = &mut packet.data[decap_length..decap_length + original_length];

            // Only virtual network traffic goes to remove duplicates
            #[cfg(any(target_os = "linux", target_os = "android"))]
            if self.dedup.duplicate(overlay_packet, timestamp) {
                debug!("Packet is duplicate");
                continue;
            }

            let (da_key, sa_key, dst_local, src_local) = Self::get_key(
                &self.local_vm_mac_set,
                overlay_packet,
                self.base.tunnel_info,
            );
            let trident_type = self.trident_type.lock().unwrap().clone();
            if !src_local && !dst_local {
                let _ = Self::handler(
                    self.base.id,
                    self.mac, // In order for two-way traffic to be handled by the same pipeline, self.mac is used as the key here
                    src_local,
                    dst_local,
                    overlay_packet,
                    timestamp,
                    original_length,
                    &self.updated,
                    &mut self.pipelines,
                    &self.base.handler_builder,
                    &self.base.tunnel_info,
                    &config,
                    &mut flow_map,
                    &self.base.counter,
                    trident_type,
                    self.mac,
                    self.base.npb_dedup_enabled.load(Ordering::Relaxed),
                );
                continue;
            }

            if src_local {
                let _ = Self::handler(
                    self.base.id,
                    sa_key,
                    true,
                    false,
                    overlay_packet,
                    timestamp,
                    original_length,
                    &self.updated,
                    &mut self.pipelines,
                    &self.base.handler_builder,
                    &self.base.tunnel_info,
                    &config,
                    &mut flow_map,
                    &self.base.counter,
                    trident_type,
                    self.mac,
                    self.base.npb_dedup_enabled.load(Ordering::Relaxed),
                );
            }
            if dst_local {
                let _ = Self::handler(
                    self.base.id,
                    da_key,
                    false,
                    true,
                    overlay_packet,
                    timestamp,
                    original_length,
                    &self.updated,
                    &mut self.pipelines,
                    &self.base.handler_builder,
                    &self.base.tunnel_info,
                    &config,
                    &mut flow_map,
                    &self.base.counter,
                    trident_type,
                    self.mac,
                    self.base.npb_dedup_enabled.load(Ordering::Relaxed),
                );
            }
        }

        self.pipelines.clear();
        self.base.terminate_handler();
        self.last_timestamp_array.clear();
        info!("Stopped dispatcher {}", self.base.log_id);
    }

    pub(super) fn prepare_flow(
        meta_packet: &mut MetaPacket,
        tunnel_type: TunnelType,
        key: u32,
        queue_hash: u8,
        trident_type: TridentType,
        mac: u32,
        npb_dedup: bool,
    ) {
        let nat_source = meta_packet.lookup_key.get_nat_source();
        if is_tt_hyper_v_compute(trident_type) {
            meta_packet.tap_port = TapPort::from_local_mac(nat_source, tunnel_type, mac);
        } else {
            meta_packet.tap_port = TapPort::from_local_mac(nat_source, tunnel_type, key);
        }

        BaseDispatcher::prepare_flow(meta_packet, TapType::Cloud, false, queue_hash, npb_dedup)
    }

    // Ensure that the packets' timestamp obtained by each if_index are incremented in chronological order, otherwise correct them
    fn swap_last_timestamp(
        last_timestamp_array: &mut Vec<LastTimestamps>,
        counter: &Arc<PacketCounter>,
        if_index: isize,
        timestamp: Duration,
    ) -> Result<Duration> {
        for i in last_timestamp_array.iter_mut() {
            if if_index == i.if_index {
                if timestamp + Duration::from_millis(1) < i.last_timestamp {
                    // FIXME: just in case
                    counter.retired.fetch_add(1, Ordering::Relaxed);
                    return Err(Error::PacketInvalid("invalid timestamp".to_string()));
                } else if i.last_timestamp < timestamp {
                    i.last_timestamp = timestamp;
                }
                return Ok(i.last_timestamp);
            }
        }
        if last_timestamp_array.len() > IF_INDEX_MAX_SIZE {
            last_timestamp_array.clear();
            warn!("too many if_indexes");
        }
        last_timestamp_array.push(LastTimestamps {
            if_index,
            last_timestamp: timestamp,
        });
        Ok(timestamp)
    }
}

#[cfg(target_os = "windows")]
impl MirrorModeDispatcher {
    fn decap_tunnel(
        packet: &mut Packet,
        tap_type_handler: &TapTypeHandler,
        tunnel_info: &mut TunnelInfo,
        tunnel_type_bitmap: &Arc<Mutex<TunnelTypeBitmap>>,
        counter: &Arc<PacketCounter>,
    ) -> usize {
        let (decap_length, _) = match BaseDispatcher::decap_tunnel(
            &mut packet.data,
            tap_type_handler,
            tunnel_info,
            tunnel_type_bitmap.lock().unwrap().clone(),
        ) {
            Ok(d) => d,
            Err(e) => {
                counter.invalid_packets.fetch_add(1, Ordering::Relaxed);
                warn!("decap_tunnel failed: {:?}", e);
                return 0;
            }
        };

        return decap_length;
    }
}
