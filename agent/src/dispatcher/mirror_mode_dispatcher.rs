/*
 * Copyright (c) 2022 Yunshan Networks
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
    ops::Add,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, Weak,
    },
    time::Duration,
};

#[cfg(windows)]
use log::warn;
use log::{debug, info};

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
    flow_generator::FlowMap,
    handler::PacketHandlerBuilder,
    handler::{MiniPacket, PacketHandler},
    proto::{common::TridentType, trident::IfMacSource},
    rpc::get_timestamp,
    utils::{
        environment::is_tt_hyper_v_compute,
        stats::{Countable, RefCountable, StatsOption},
    },
};
use packet_dedup::PacketDedupMap;
#[cfg(windows)]
use public::packet::Packet;
use public::utils::net::{Link, MacAddr};

#[derive(Clone)]
pub struct MirrorModeDispatcherListener {
    local_vm_mac_set: Arc<Mutex<HashMap<u32, bool>>>,
    updated: Arc<AtomicBool>,
    #[cfg(target_os = "linux")]
    poller: Option<Arc<GenericPoller>>,

    base: BaseDispatcherListener,
}

impl MirrorModeDispatcherListener {
    pub fn on_tap_interface_change(&self, _: &Vec<Link>, _: IfMacSource) {
        self.base
            .on_tap_interface_change(vec![], IfMacSource::IfMac);
    }

    #[cfg(target_os = "linux")]
    fn tap_bridge_inner_macs(&self, if_index: usize) -> Vec<MacAddr> {
        if self.poller.is_none() {
            debug!("Poller is none.");
            return vec![];
        }
        if if_index == 0 {
            debug!("Mirror mode tap-bridge src-interface ifindex == 0");
            return vec![];
        }
        let mut macs = vec![];
        let ifaces = self.poller.as_ref().unwrap().get_interface_info();
        if ifaces.len() == 0 {
            debug!("Mirror mode tap-bridge macs is nill.");
            return macs;
        }
        for iface in ifaces {
            if iface.tap_idx as usize == if_index {
                macs.push(iface.mac);
            }
        }
        debug!("TapBridge: Src-IfIndex {} MAC {:?}", if_index, macs);
        return macs;
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
            info!("Add vm macs: {:?}", new_macs);
        }
        if delete_macs.len() > 0 {
            info!("Delete vm macs: {:?}", delete_macs);
        }
        *old_vm_mac_set = new_vm_mac_set;
        self.updated.store(true, Ordering::Relaxed);
    }

    pub fn on_vm_change(&self, vm_mac_addrs: &[MacAddr]) {
        #[cfg(target_os = "linux")]
        let tap_bridge_macs = self.tap_bridge_inner_macs(self.base.src_interface_index);
        #[cfg(target_os = "linux")]
        self.on_vm_change_with_bridge_macs(vm_mac_addrs, &tap_bridge_macs);
        #[cfg(target_os = "windows")]
        self.on_vm_change_with_bridge_macs(vm_mac_addrs, &vec![]);
    }

    pub(super) fn on_config_change(&mut self, config: &DispatcherConfig) {
        self.base.on_config_change(config)
    }
}

pub(super) struct MirrorPipeline {
    handlers: Vec<PacketHandler>,
    timestamp: Duration,
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
    pub(super) trident_type: TridentType,
    pub(super) mac: u32,
}

impl MirrorModeDispatcher {
    pub(super) fn init(&mut self) {
        self.base.init();
    }

    pub(super) fn listener(&self) -> MirrorModeDispatcherListener {
        MirrorModeDispatcherListener {
            local_vm_mac_set: self.local_vm_mac_set.clone(),
            updated: self.updated.clone(),
            base: self.base.listener(),
            #[cfg(target_os = "linux")]
            poller: self.poller.clone(),
        }
    }

    #[cfg(target_os = "windows")]
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
        timestamp: Duration,
    ) -> &'a mut MirrorPipeline {
        if updated.load(Ordering::Relaxed) {
            pipelines.clear();
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
                let value = MirrorPipeline {
                    handlers,
                    timestamp,
                };
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
            &overlay_packet,
            src_local,
            dst_local,
            timestamp + offset,
            original_length,
        ) {
            counter.invalid_packets.fetch_add(1, Ordering::Relaxed);
            return Err(Error::PacketInvalid(format!("with {:?}", e)));
        }

        if tunnel_info.tunnel_type != TunnelType::None {
            meta_packet.tunnel = Some(tunnel_info);
        }

        Ok(meta_packet)
    }

    fn handler(
        id: usize,
        key: u32,
        src_local: bool,
        dst_local: bool,
        overlay_packet: &[u8],
        mut timestamp: Duration,
        original_length: usize,
        updated: &Arc<AtomicBool>,
        pipelines: &mut HashMap<u32, MirrorPipeline>,
        handler_builder: &Arc<Mutex<Vec<PacketHandlerBuilder>>>,
        tunnel_info: &TunnelInfo,
        flow_map: &mut FlowMap,
        counter: &Arc<PacketCounter>,
        trident_type: TridentType,
        mac: u32,
    ) -> Result<()> {
        let pipeline = Self::get_pipeline(updated, pipelines, key, id, handler_builder, timestamp);
        if timestamp
            .add(Duration::from_millis(1))
            .lt(&pipeline.timestamp)
        {
            // FIXME: just in case
            counter.retired.fetch_add(1, Ordering::Relaxed);
            return Err(Error::PacketInvalid(
                "packet timestamp lt pipeline timestamp".to_string(),
            ));
        } else if timestamp.lt(&pipeline.timestamp) {
            timestamp = pipeline.timestamp;
        }
        pipeline.timestamp = timestamp;

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
        );
        // flowProcesser
        flow_map.inject_meta_packet(&mut meta_packet);
        let mini_packet = MiniPacket::new(overlay_packet, &meta_packet);
        for i in pipeline.handlers.iter_mut() {
            i.handle(&mini_packet);
        }

        Ok(())
    }

    pub(super) fn run(&mut self) {
        info!("Start mirror dispatcher {}", self.base.id);
        let time_diff = self.base.ntp_diff.load(Ordering::Relaxed);
        let mut prev_timestamp = get_timestamp(time_diff);

        let (mut flow_map, flow_counter) = FlowMap::new(
            self.base.id as u32,
            self.base.flow_output_queue.clone(),
            self.base.policy_getter,
            self.base.log_output_queue.clone(),
            self.base.ntp_diff.clone(),
            self.base.flow_map_config.clone(),
            self.base.log_parse_config.clone(),
            self.base.packet_sequence_output_queue.clone(), // Enterprise Edition Feature: packet-sequence
        );

        self.base.stats.register_countable(
            "flow-perf",
            Countable::Ref(Arc::downgrade(&flow_counter) as Weak<dyn RefCountable>),
            vec![StatsOption::Tag("id", format!("{}", self.base.id))],
        );

        while !self.base.terminated.load(Ordering::Relaxed) {
            if self.base.reset_whitelist.swap(false, Ordering::Relaxed) {
                self.base.tap_interface_whitelist.reset();
            }
            let recved = BaseDispatcher::recv(
                &mut self.base.engine,
                &self.base.leaky_bucket,
                &self.base.exception_handler,
                &mut prev_timestamp,
                &self.base.counter,
                &self.base.ntp_diff,
            );
            if recved.is_none() {
                flow_map.inject_flush_ticker(Duration::ZERO);
                if self.base.tap_interface_whitelist.next_sync(Duration::ZERO) {
                    self.base.need_update_bpf.store(true, Ordering::Relaxed);
                }
                self.base.check_and_update_bpf();
                continue;
            }
            #[cfg(target_os = "linux")]
            let (packet, timestamp) = recved.unwrap();
            #[cfg(target_os = "windows")]
            let (mut packet, timestamp) = recved.unwrap();

            self.base.counter.rx.fetch_add(1, Ordering::Relaxed);
            self.base
                .counter
                .rx_bytes
                .fetch_add(packet.capture_length as u64, Ordering::Relaxed);

            #[cfg(windows)]
            let mut decap_length = 0;
            #[cfg(unix)]
            let decap_length = 0;

            #[cfg(target_os = "windows")]
            {
                // Mirror Mode运行于Windows环境下时目前只有Hyper-V一个场景，由于Hyper-V加了VXLAN隧道，
                // 这里需要decap并将tunnel信息保存在flow中，目前仅保存最外层的tunnel
                decap_length = Self::decap_tunnel(
                    &mut packet,
                    &self.base.tap_type_handler,
                    &mut self.base.tunnel_info,
                    &self.base.tunnel_type_bitmap,
                    &self.base.counter,
                ) as usize;
                if decap_length > packet.capture_length as usize {
                    warn!("Decap tunnel error.");
                    continue;
                }
            }

            let original_length = packet.data.len() - decap_length;
            let overlay_packet = &mut packet.data[decap_length..packet.capture_length as usize];

            // Only virtual network traffic goes to remove duplicates
            #[cfg(target_os = "linux")]
            if self.dedup.duplicate(overlay_packet, timestamp) {
                debug!("Packet is duplicate");
                continue;
            }

            let (da_key, sa_key, dst_local, src_local) = Self::get_key(
                &self.local_vm_mac_set,
                overlay_packet,
                self.base.tunnel_info,
            );
            if !src_local && !dst_local {
                let _ = Self::handler(
                    self.base.id,
                    da_key,
                    src_local,
                    dst_local,
                    overlay_packet,
                    timestamp,
                    original_length,
                    &self.updated,
                    &mut self.pipelines,
                    &self.base.handler_builder,
                    &self.base.tunnel_info,
                    &mut flow_map,
                    &self.base.counter,
                    self.trident_type,
                    self.mac,
                );
                continue;
            }

            if src_local {
                let _ = Self::handler(
                    self.base.id,
                    sa_key,
                    src_local,
                    dst_local,
                    overlay_packet,
                    timestamp,
                    original_length,
                    &self.updated,
                    &mut self.pipelines,
                    &self.base.handler_builder,
                    &self.base.tunnel_info,
                    &mut flow_map,
                    &self.base.counter,
                    self.trident_type,
                    self.mac,
                );
            }
            if dst_local {
                let _ = Self::handler(
                    self.base.id,
                    da_key,
                    src_local,
                    dst_local,
                    overlay_packet,
                    timestamp,
                    original_length,
                    &self.updated,
                    &mut self.pipelines,
                    &self.base.handler_builder,
                    &self.base.tunnel_info,
                    &mut flow_map,
                    &self.base.counter,
                    self.trident_type,
                    self.mac,
                );
            }
        }

        self.base.terminate_handler();
        info!("Stopped dispatcher {}", self.base.id);
    }

    pub(super) fn prepare_flow(
        meta_packet: &mut MetaPacket,
        tunnel_type: TunnelType,
        key: u32,
        queue_hash: u8,
        trident_type: TridentType,
        mac: u32,
    ) {
        if is_tt_hyper_v_compute(trident_type) {
            meta_packet.tap_port = TapPort::from_local_mac(tunnel_type, mac);
        } else {
            meta_packet.tap_port = TapPort::from_local_mac(tunnel_type, key);
        }

        BaseDispatcher::prepare_flow(meta_packet, TapType::Tor, false, queue_hash)
    }
}
