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
    sync::{atomic::Ordering, Arc, Mutex},
    time::Duration,
};

use arc_swap::access::Access;
use log::{debug, info, warn};
use packet_dedup::PacketDedupMap;

use super::base_dispatcher::BaseDispatcher;
use crate::{
    common::{
        decapsulate::{TunnelInfo, TunnelType, TunnelTypeBitmap},
        enums::TapType,
        MetaPacket, TapPort,
    },
    config::DispatcherConfig,
    dispatcher::{
        base_dispatcher::{BaseDispatcherListener, TapTypeHandler},
        error::Result,
    },
    flow_generator::FlowMap,
    handler::{MiniPacket, PacketHandler},
    rpc::get_timestamp,
};
use public::proto::trident::IfMacSource;
use public::utils::net::{Link, MacAddr};

// BILD to reduce the processing flow of Trident tunnel traffic, the tunnel traffic will be marked
// Use the first byte of the source MAC to mark the ERSPAN traffic, which is 0xff
// Use the second byte of the source MAC to mark the offset of the overlay traffic
const BILD_FLAGS: usize = 0xff;
const BILD_FLAGS_OFFSET: usize = 6;
const BILD_OVERLAY_OFFSET: usize = 7;

#[derive(Clone)]
pub struct AnalyzerModeDispatcherListener {
    vm_mac_addrs: Arc<Mutex<HashMap<u32, MacAddr>>>,
    base: BaseDispatcherListener,
}

impl AnalyzerModeDispatcherListener {
    pub fn on_tap_interface_change(&self, _: &Vec<Link>, _: IfMacSource) {
        self.base
            .on_tap_interface_change(vec![], IfMacSource::IfMac);
    }

    pub fn on_vm_change(&self, vm_mac_addrs: &[MacAddr]) {
        let mut old_vm_mac_addrs = self.vm_mac_addrs.lock().unwrap();
        if old_vm_mac_addrs.len() <= vm_mac_addrs.len()
            && vm_mac_addrs
                .iter()
                .all(|addr| old_vm_mac_addrs.contains_key(&addr.to_lower_32b()))
        {
            return;
        }
        old_vm_mac_addrs.clear();
        vm_mac_addrs.iter().for_each(|addr| {
            old_vm_mac_addrs.insert(addr.to_lower_32b(), *addr);
        });
    }

    pub(super) fn on_config_change(&mut self, config: &DispatcherConfig) {
        self.base.on_config_change(config)
    }
}

pub(super) struct AnalyzerPipeline {
    tap_type: TapType,
    handlers: Vec<PacketHandler>,
    timestamp: Duration,
}

pub(super) struct AnalyzerModeDispatcher {
    pub(super) base: BaseDispatcher,
    pub(super) vm_mac_addrs: Arc<Mutex<HashMap<u32, MacAddr>>>,
    pub(super) dedup: PacketDedupMap,
    pub(super) tap_pipelines: HashMap<TapType, Arc<Mutex<AnalyzerPipeline>>>,
    pub(super) pool_raw_size: usize,
}

impl AnalyzerModeDispatcher {
    pub(super) fn listener(&self) -> AnalyzerModeDispatcherListener {
        AnalyzerModeDispatcherListener {
            vm_mac_addrs: self.vm_mac_addrs.clone(),
            base: self.base.listener(),
        }
    }

    pub(super) fn run(&mut self) {
        let base = &mut self.base;
        info!("Start analyzer dispatcher {}", base.log_id);
        let time_diff = base.ntp_diff.load(Ordering::Relaxed);
        let mut prev_timestamp = get_timestamp(time_diff);

        let mut flow_map = FlowMap::new(
            base.id as u32,
            base.flow_output_queue.clone(),
            base.policy_getter,
            base.log_output_queue.clone(),
            base.ntp_diff.clone(),
            base.flow_map_config.clone(),
            base.log_parse_config.clone(),
            Some(base.packet_sequence_output_queue.clone()), // Enterprise Edition Feature: packet-sequence
            &base.stats,
            false, // !from_ebpf
        );

        while !base.terminated.load(Ordering::Relaxed) {
            if base.reset_whitelist.swap(false, Ordering::Relaxed) {
                base.tap_interface_whitelist.reset();
            }
            let recved = BaseDispatcher::recv(
                &mut base.engine,
                &base.leaky_bucket,
                &base.exception_handler,
                &mut prev_timestamp,
                &base.counter,
                &base.ntp_diff,
            );
            if recved.is_none() {
                flow_map.inject_flush_ticker(Duration::ZERO);
                if base.tap_interface_whitelist.next_sync(Duration::ZERO) {
                    base.need_update_bpf.store(true, Ordering::Relaxed);
                }
                base.check_and_update_bpf();
                continue;
            }

            #[cfg(target_os = "linux")]
            let (packet, mut timestamp) = recved.unwrap();
            #[cfg(target_os = "windows")]
            let (mut packet, mut timestamp) = recved.unwrap();

            // From here on, ANALYZER mode is different from LOCAL mode
            base.counter.rx.fetch_add(1, Ordering::Relaxed);
            base.counter
                .rx_bytes
                .fetch_add(packet.capture_length as u64, Ordering::Relaxed);

            // parseProcesser
            let raw_length = if packet.capture_length as usize > self.pool_raw_size {
                self.pool_raw_size
            } else {
                packet.data.len()
            };

            let tunnel_type_bitmap = base.tunnel_type_bitmap.lock().unwrap().clone();
            #[cfg(target_os = "windows")]
            let (decap_length, tap_type) = match Self::decap_tunnel(
                packet.data[..raw_length].as_mut(),
                &base.tap_type_handler,
                &mut base.tunnel_info,
                tunnel_type_bitmap,
            ) {
                Ok(d) => d,
                Err(e) => {
                    base.counter.invalid_packets.fetch_add(1, Ordering::Relaxed);
                    warn!("decap_tunnel failed: {:?}", e);
                    continue;
                }
            };
            #[cfg(target_os = "linux")]
            let (decap_length, tap_type) = match Self::decap_tunnel(
                &mut packet.data[..raw_length],
                &base.tap_type_handler,
                &mut base.tunnel_info,
                tunnel_type_bitmap,
            ) {
                Ok(d) => d,
                Err(e) => {
                    base.counter.invalid_packets.fetch_add(1, Ordering::Relaxed);
                    warn!("decap_tunnel failed: {:?}", e);
                    continue;
                }
            };

            if decap_length >= raw_length {
                base.counter.invalid_packets.fetch_add(1, Ordering::Relaxed);
                warn!(
                    "decap_tunnel wrong, decap_length: {}, raw_length: {}",
                    decap_length, raw_length
                );
                continue;
            }

            let original_length = packet.data.len() - decap_length;

            let overlay_packet = &mut packet.data[decap_length..raw_length];
            // Only cloud traffic goes to de-duplication
            if tap_type == TapType::Cloud
                && !base.analyzer_dedup_disabled
                && self.dedup.duplicate(overlay_packet, timestamp)
            {
                debug!("packet is duplicate");
                continue;
            }

            let (da_key, sa_key) = if base.tunnel_info.tier == 0
                && overlay_packet.len() >= super::L2_MAC_ADDR_OFFSET
            {
                let mut da_mac: [u8; 6] = [0; 6];
                let mut sa_mac: [u8; 6] = [0; 6];
                da_mac.copy_from_slice(&overlay_packet[..6]);
                sa_mac.copy_from_slice(&overlay_packet[6..12]);
                (
                    MacAddr::from(da_mac).to_lower_32b(),
                    MacAddr::from(sa_mac).to_lower_32b(),
                )
            } else {
                (base.tunnel_info.mac_dst, base.tunnel_info.mac_src)
            };
            let vm_mac_addrs = self.vm_mac_addrs.lock().unwrap().clone();
            let (dst_remote, src_remote) = (
                vm_mac_addrs.contains_key(&da_key),
                vm_mac_addrs.contains_key(&sa_key),
            );
            let mut tap_port = TapPort::from_id(base.tunnel_info.tunnel_type, base.id as u32);
            let is_unicast =
                base.tunnel_info.tier > 0 || MacAddr::is_multicast(&overlay_packet[..].to_vec()); // Consider unicast when there is a tunnel
            let (src_local, dst_local) = if src_remote && dst_remote && is_unicast {
                (true, true)
            } else if src_remote {
                if base.flow_map_config.load().cloud_gateway_traffic {
                    tap_port = TapPort::from_gateway_mac(base.tunnel_info.tunnel_type, sa_key);
                }
                (true, false)
            } else if dst_remote && is_unicast {
                if base.flow_map_config.load().cloud_gateway_traffic {
                    tap_port = TapPort::from_gateway_mac(base.tunnel_info.tunnel_type, da_key);
                }
                (false, true)
            } else {
                (false, false)
            };

            // pipelineProcesser
            let mut pipeline = match self.tap_pipelines.get(&tap_type) {
                None => {
                    // ff : ff : ff : ff : DispatcherID : TapType(1-255)
                    let mac = ((0xffffffff as u64) << 16)
                        | ((base.id as u64) << 8)
                        | (u16::from(tap_type) as u64);
                    let handlers = base
                        .handler_builder
                        .lock()
                        .unwrap()
                        .iter()
                        .map(|b| b.build_with(base.id, 0, MacAddr::try_from(mac).unwrap()))
                        .collect();
                    let pipeline = AnalyzerPipeline {
                        tap_type,
                        handlers,
                        timestamp: Duration::ZERO,
                    };
                    self.tap_pipelines
                        .insert(tap_type, Arc::new(Mutex::new(pipeline)));
                    self.tap_pipelines.get(&tap_type).unwrap().lock().unwrap()
                }
                Some(p) => p.lock().unwrap(),
            };

            if timestamp
                .add(Duration::from_millis(1))
                .lt(&pipeline.timestamp)
            {
                // FIXME: just in case
                base.counter.retired.fetch_add(1, Ordering::Relaxed);
                continue;
            } else if timestamp.lt(&pipeline.timestamp) {
                timestamp = pipeline.timestamp;
            }

            pipeline.timestamp = timestamp;

            let mut meta_packet = MetaPacket::empty();
            meta_packet.tap_port = tap_port;
            let offset = Duration::ZERO;
            if let Err(e) = meta_packet.update(
                &overlay_packet,
                src_local,
                dst_local,
                timestamp + offset,
                original_length,
            ) {
                base.counter.invalid_packets.fetch_add(1, Ordering::Relaxed);
                debug!("meta_packet update failed: {:?}", e);
                continue;
            }

            if base.tunnel_info.tunnel_type != TunnelType::None {
                meta_packet.tunnel = Some(&base.tunnel_info);
                if base.tunnel_info.tunnel_type == TunnelType::TencentGre
                    || base.tunnel_info.tunnel_type == TunnelType::Vxlan
                {
                    // Tencent TCE and Qingyun Private Cloud need to query cloud platform information through TunnelID
                    // Only the case of single-layer tunnel encapsulation needs to be considered here
                    // In the double-layer encapsulation scenario, consider that the inner MAC exists and is valid (VXLAN-VXLAN) or needs to be judged by IP (VXLAN-IPIP)
                    meta_packet.lookup_key.tunnel_id = base.tunnel_info.id;
                }
            }

            Self::prepare_flow(
                &mut meta_packet,
                tap_type,
                base.id as u8,
                base.npb_dedup_enabled.load(Ordering::Relaxed),
            );
            // flowProcesser
            flow_map.inject_meta_packet(&mut meta_packet);
            let mini_packet = MiniPacket::new(overlay_packet, &meta_packet);
            for i in pipeline.handlers.iter_mut() {
                i.handle(&mini_packet);
            }
        }

        self.tap_pipelines.clear();
        base.terminate_handler();
        info!("Stopped dispatcher {}", base.log_id);
    }

    pub(super) fn decap_tunnel(
        packet: &mut [u8],
        tap_type_handler: &TapTypeHandler,
        tunnel_info: &mut TunnelInfo,
        bitmap: TunnelTypeBitmap,
    ) -> Result<(usize, TapType)> {
        if packet[BILD_FLAGS_OFFSET] == BILD_FLAGS as u8 {
            // bild will mark ERSPAN traffic and reduce the Trident process
            // XXX: In the current implementation mode, when using bild to mark the ERSPAN offset, it does not support the scenario that there are other tunnel encapsulation in the inner layer
            let overlay_offset = packet[BILD_OVERLAY_OFFSET] as usize;
            let tap_type = match tap_type_handler.get_l2_info(packet) {
                Ok(l2_info) => l2_info.0,
                Err(e) => {
                    return Err(e);
                }
            };
            *tunnel_info = TunnelInfo::default();
            return Ok((overlay_offset, tap_type));
        }

        BaseDispatcher::decap_tunnel(&mut packet.to_vec(), tap_type_handler, tunnel_info, bitmap)
    }

    pub(super) fn prepare_flow(
        meta_packet: &mut MetaPacket,
        tap_type: TapType,
        queue_hash: u8,
        npb_dedup: bool,
    ) {
        let mut reset_ttl = false;
        if tap_type == TapType::Cloud {
            reset_ttl = true;
        }
        BaseDispatcher::prepare_flow(meta_packet, tap_type, reset_ttl, queue_hash, npb_dedup)
    }
}
