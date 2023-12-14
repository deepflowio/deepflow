/*
 * Copyright (c) 2023 Yunshan Networks
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
    ops::Add,
    sync::{atomic::Ordering, Arc, RwLock},
    thread::{self, JoinHandle},
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
        MetaPacket, TapPort, ETH_HEADER_SIZE, VLAN_HEADER_SIZE,
    },
    config::DispatcherConfig,
    dispatcher::{
        base_dispatcher::{BaseDispatcherListener, TapTypeHandler},
        error::Result,
    },
    flow_generator::{flow_map::Config, FlowMap},
    handler::{MiniPacket, PacketHandler},
    rpc::get_timestamp,
    utils::{
        bytes::read_u32_be,
        stats::{self, Countable, StatsOption},
    },
};
use public::{
    buffer::{Allocator, BatchedBuffer},
    debug::QueueDebugger,
    proto::trident::IfMacSource,
    queue::{self, bounded_with_debug, DebugSender, Receiver},
    utils::net::{Link, MacAddr},
};

// BILD to reduce the processing flow of Trident tunnel traffic, the tunnel traffic will be marked
// Use the first byte of the source MAC to mark the ERSPAN traffic, which is 0xff
// Use the second byte of the source MAC to mark the offset of the overlay traffic
const BILD_FLAGS: usize = 0xff;
const BILD_FLAGS_OFFSET: usize = 6;
const BILD_OVERLAY_OFFSET: usize = 7;

const HANDLER_BATCH_SIZE: usize = 64;

#[derive(Clone)]
pub struct AnalyzerModeDispatcherListener {
    vm_mac_addrs: Arc<RwLock<HashMap<u32, MacAddr>>>,
    gateway_vmac_addrs: Arc<RwLock<Vec<MacAddr>>>,
    base: BaseDispatcherListener,
}

impl AnalyzerModeDispatcherListener {
    #[cfg(target_os = "linux")]
    pub fn netns(&self) -> &public::netns::NsFile {
        &self.base.netns
    }

    pub fn on_tap_interface_change(&self, _: &[Link], _: IfMacSource) {
        self.base
            .on_tap_interface_change(vec![], IfMacSource::IfMac);
    }

    pub fn on_vm_change(&self, vm_mac_addrs: &[MacAddr], gateway_vmac_addrs: &[MacAddr]) {
        let old_vm_mac_addrs = self.vm_mac_addrs.read().unwrap();
        let old_gateway_vmac_addrs = self.gateway_vmac_addrs.read().unwrap();
        if old_gateway_vmac_addrs.as_slice() == gateway_vmac_addrs
            && old_vm_mac_addrs.len() <= vm_mac_addrs.len()
            && vm_mac_addrs
                .iter()
                .all(|addr| old_vm_mac_addrs.contains_key(&addr.to_lower_32b()))
        {
            return;
        }
        drop(old_vm_mac_addrs);
        drop(old_gateway_vmac_addrs);

        if vm_mac_addrs.len() <= 100 {
            info!(
                "Update {} remote VMs: {:?}",
                vm_mac_addrs.len(),
                &vm_mac_addrs
            );
        } else {
            info!(
                "Update {} remote VMs: {:?} ...",
                vm_mac_addrs.len(),
                &vm_mac_addrs[..100]
            );
        }
        let mut new_vm_mac_addrs = HashMap::with_capacity(vm_mac_addrs.len());
        vm_mac_addrs
            .iter()
            .zip(gateway_vmac_addrs)
            .for_each(|(vm_mac, gw_vmac)| {
                new_vm_mac_addrs.insert(vm_mac.to_lower_32b(), gw_vmac.clone());
            });
        *self.vm_mac_addrs.write().unwrap() = new_vm_mac_addrs;
        *self.gateway_vmac_addrs.write().unwrap() = gateway_vmac_addrs.to_vec();
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

pub(super) struct AnalyzerPipeline {
    tap_type: TapType,
    handlers: Vec<PacketHandler>,
    timestamp: Duration,
}

#[derive(Debug)]
struct Packet {
    timestamp: Duration,
    raw: BatchedBuffer<u8>,
    original_length: u32,
    raw_length: u32,
}

pub(super) struct AnalyzerModeDispatcher {
    pub(super) base: BaseDispatcher,
    pub(super) vm_mac_addrs: Arc<RwLock<HashMap<u32, MacAddr>>>,
    pub(super) pool_raw_size: usize,
    pub(super) flow_generator_thread_handler: Option<JoinHandle<()>>,
    pub(super) pipeline_thread_handler: Option<JoinHandle<()>>,
    pub(super) queue_debugger: Arc<QueueDebugger>,
    pub(super) stats_collector: Arc<stats::Collector>,
    pub(super) inner_queue_size: usize,
    pub(super) raw_packet_block_size: usize,
}

impl AnalyzerModeDispatcher {
    pub(super) fn listener(&self) -> AnalyzerModeDispatcherListener {
        AnalyzerModeDispatcherListener {
            vm_mac_addrs: self.vm_mac_addrs.clone(),
            gateway_vmac_addrs: Arc::new(RwLock::new(vec![])),
            base: self.base.listener(),
        }
    }

    fn timestamp(
        timestamp_map: &mut HashMap<TapType, Duration>,
        tap_type: TapType,
        mut timestamp: Duration,
    ) -> (Duration, bool) {
        let last_timestamp = timestamp_map.entry(tap_type).or_insert(Duration::ZERO);

        if timestamp.add(Duration::from_millis(1)).lt(last_timestamp) {
            return (Duration::ZERO, false);
        } else if timestamp.lt(last_timestamp) {
            timestamp = *last_timestamp;
        }

        *last_timestamp = timestamp;
        return (timestamp, true);
    }

    fn lookup_l2end(
        id: usize,
        vm_mac_addrs: &Arc<RwLock<HashMap<u32, MacAddr>>>,
        tunnel_info: &TunnelInfo,
        overlay_packet: &[u8],
        cloud_gateway_traffic: bool,
    ) -> (TapPort, bool, bool) {
        let (da_key, sa_key) =
            if tunnel_info.tier == 0 && overlay_packet.len() >= super::L2_MAC_ADDR_OFFSET {
                (
                    read_u32_be(&overlay_packet[2..6]),
                    read_u32_be(&overlay_packet[8..12]),
                )
            } else {
                (tunnel_info.mac_dst, tunnel_info.mac_src)
            };
        let vm_mac_addrs = vm_mac_addrs.read().unwrap();
        let (dst_remote, dst_gateway_vmac_addr) = match vm_mac_addrs.get(&da_key) {
            Some(vmac) => (true, u64::from(*vmac) as u32),
            None => (false, 0),
        };
        let (src_remote, src_gateway_vmac_addr) = match vm_mac_addrs.get(&sa_key) {
            Some(vmac) => (true, u64::from(*vmac) as u32),
            None => (false, 0),
        };
        let mut tap_port = TapPort::from_id(tunnel_info.tunnel_type, id as u32);
        let is_unicast = tunnel_info.tier > 0 || !MacAddr::is_multicast(overlay_packet); // Consider unicast when there is a tunnel

        if src_remote && dst_remote && is_unicast {
            if cloud_gateway_traffic {
                let gateway_vmac_addr = src_gateway_vmac_addr.max(dst_gateway_vmac_addr);
                tap_port = TapPort::from_gateway_mac(tunnel_info.tunnel_type, gateway_vmac_addr);
            }
            (tap_port, true, true)
        } else if src_remote {
            if cloud_gateway_traffic {
                tap_port =
                    TapPort::from_gateway_mac(tunnel_info.tunnel_type, src_gateway_vmac_addr);
            }
            (tap_port, true, false)
        } else if dst_remote && is_unicast {
            if cloud_gateway_traffic {
                tap_port =
                    TapPort::from_gateway_mac(tunnel_info.tunnel_type, dst_gateway_vmac_addr);
            }
            (tap_port, false, true)
        } else {
            (tap_port, false, false)
        }
    }

    // This thread implements the following functions:
    // 1. Decap tunnel
    // 2. Lookup l2end
    // 3. Generate MetaPacket
    // 4. Generate tagged flow
    fn run_flow_generator(
        &mut self,
        receiver: Receiver<Packet>,
        sender: DebugSender<(TapType, MiniPacket<'static>)>,
    ) {
        let base = &self.base;

        let terminated = base.terminated.clone();
        let tunnel_type_bitmap = base.tunnel_type_bitmap.clone();
        let tap_type_handler = base.tap_type_handler.clone();
        let counter = base.counter.clone();
        let analyzer_dedup_disabled = base.analyzer_dedup_disabled;
        let vm_mac_addrs = self.vm_mac_addrs.clone();
        let mut dedup = PacketDedupMap::new();
        let id = base.id;
        let pool_raw_size = self.pool_raw_size;

        let npb_dedup_enabled = base.npb_dedup_enabled.clone();
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

        self.flow_generator_thread_handler.replace(
            thread::Builder::new()
                .name("dispatcher-packet-to-flow-generator".to_owned())
                .spawn(move || {
                    let mut timestamp_map: HashMap<TapType, Duration> = HashMap::new();
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
                            // Truncate package according to configuration
                            let raw_length = (packet.raw_length as usize)
                                .min(packet.raw.len())
                                .min(pool_raw_size);
                            let tunnel_type_bitmap = tunnel_type_bitmap.lock().unwrap().clone();
                            let mut tunnel_info = TunnelInfo::default();

                            let (decap_length, tap_type) = match Self::decap_tunnel(
                                &mut packet.raw[..raw_length],
                                &tap_type_handler,
                                &mut tunnel_info,
                                tunnel_type_bitmap,
                            ) {
                                Ok(d) => d,
                                Err(e) => {
                                    counter.invalid_packets.fetch_add(1, Ordering::Relaxed);
                                    warn!("decap_tunnel failed: {:?}", e);
                                    continue;
                                }
                            };

                            if decap_length >= raw_length {
                                counter.invalid_packets.fetch_add(1, Ordering::Relaxed);
                                warn!(
                                    "decap_tunnel wrong, decap_length: {}, raw_length: {}",
                                    decap_length, raw_length
                                );
                                continue;
                            }

                            let decap_length = if packet.raw.len() - decap_length
                                > ETH_HEADER_SIZE + VLAN_HEADER_SIZE
                            {
                                decap_length
                            } else {
                                tunnel_info = TunnelInfo::default();
                                0
                            };
                            let original_length = packet.raw.len() - decap_length;
                            let timestamp = packet.timestamp;

                            let mut overlay_packet = packet.raw;
                            overlay_packet.truncate(decap_length..raw_length);
                            // Only cloud traffic goes to de-duplication
                            if tap_type == TapType::Cloud
                                && !analyzer_dedup_disabled
                                && dedup.duplicate(overlay_packet.as_mut(), timestamp)
                            {
                                debug!("packet is duplicate");
                                continue;
                            }

                            let (tap_port, src_local, dst_local) = Self::lookup_l2end(
                                id,
                                &vm_mac_addrs,
                                &tunnel_info,
                                overlay_packet.as_mut(),
                                flow_map_config.load().cloud_gateway_traffic,
                            );
                            let (timestamp, ok) =
                                Self::timestamp(&mut timestamp_map, tap_type, timestamp);
                            if !ok {
                                // FIXME: just in case
                                counter.retired.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }

                            let mut meta_packet = MetaPacket::empty();
                            meta_packet.tap_port = tap_port;
                            let offset = Duration::ZERO;
                            if let Err(e) = meta_packet.update(
                                overlay_packet,
                                src_local,
                                dst_local,
                                timestamp + offset,
                                original_length,
                            ) {
                                counter.invalid_packets.fetch_add(1, Ordering::Relaxed);
                                debug!("meta_packet update failed: {:?}", e);
                                continue;
                            }

                            if tunnel_info.tunnel_type != TunnelType::None {
                                meta_packet.tunnel = Some(tunnel_info);
                                if tunnel_info.tunnel_type == TunnelType::TencentGre
                                    || tunnel_info.tunnel_type == TunnelType::Vxlan
                                {
                                    // Tencent TCE and Qingyun Private Cloud need to query cloud platform information through TunnelID
                                    // Only the case of single-layer tunnel encapsulation needs to be considered here
                                    // In the double-layer encapsulation scenario, consider that the inner MAC exists and is valid (VXLAN-VXLAN) or needs to be judged by IP (VXLAN-IPIP)
                                    meta_packet.lookup_key.tunnel_id = tunnel_info.id;
                                }
                            }

                            Self::prepare_flow(
                                &mut meta_packet,
                                tap_type,
                                id as u8,
                                npb_dedup_enabled.load(Ordering::Relaxed),
                            );
                            flow_map.inject_meta_packet(&config, &mut meta_packet);
                            let mini_packet =
                                MiniPacket::new(meta_packet.raw.take().unwrap(), &meta_packet);
                            output_batch.push((tap_type, mini_packet));
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
    fn run_additional_packet_pipeline(
        &mut self,
        receiver: Receiver<(TapType, MiniPacket<'static>)>,
    ) {
        let base = &self.base;
        let terminated = base.terminated.clone();
        let handler_builder = self.base.handler_builder.clone();
        let id = base.id;

        self.pipeline_thread_handler.replace(
            thread::Builder::new()
                .name("dispatcher-additional-packet-pipeline".to_owned())
                .spawn(move || {
                    let mut tap_pipelines: HashMap<TapType, AnalyzerPipeline> = HashMap::new();
                    let mut batch = Vec::with_capacity(HANDLER_BATCH_SIZE);
                    while !terminated.load(Ordering::Relaxed) {
                        match receiver.recv_all(&mut batch, Some(Duration::from_secs(1))) {
                            Ok(_) => {}
                            Err(queue::Error::Timeout) => continue,
                            Err(queue::Error::Terminated(..)) => break,
                            Err(queue::Error::BatchTooLarge(_)) => unreachable!(),
                        }

                        for (tap_type, mini_packet) in batch.drain(..) {
                            let pipeline = match tap_pipelines.get_mut(&tap_type) {
                                None => {
                                    // ff : ff : ff : ff : DispatcherID : TapType(1-255)
                                    let mac = ((0xffffffff as u64) << 16)
                                        | ((id as u64) << 8)
                                        | (u16::from(tap_type) as u64);
                                    let handlers = handler_builder
                                        .lock()
                                        .unwrap()
                                        .iter()
                                        .map(|b| {
                                            b.build_with(id, 0, MacAddr::try_from(mac).unwrap())
                                        })
                                        .collect();
                                    let pipeline = AnalyzerPipeline {
                                        tap_type,
                                        handlers,
                                        timestamp: Duration::ZERO,
                                    };
                                    tap_pipelines.insert(tap_type, pipeline);
                                    tap_pipelines.get_mut(&tap_type).unwrap()
                                }
                                Some(p) => p,
                            };

                            for i in pipeline.handlers.iter_mut() {
                                i.handle(&mini_packet);
                            }
                        }
                    }
                    tap_pipelines.clear();
                })
                .unwrap(),
        );
    }

    fn setup_inner_thread_and_queue(&mut self) -> DebugSender<Packet> {
        let id = self.base.id.to_string();
        let name = "0.1-raw-packet-to-flow-generator";
        let (sender_to_parser, receiver_from_dispatcher, counter) =
            bounded_with_debug(self.inner_queue_size, name, &self.queue_debugger);
        self.stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag("module", name.to_string()),
                StatsOption::Tag("index", id.clone()),
            ],
        );

        let name = "0.2-packet-to-additional-pipeline";
        let (sender_to_pipeline, receiver_from_flow, counter) =
            bounded_with_debug(self.inner_queue_size, name, &self.queue_debugger);
        self.stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag("module", name.to_string()),
                StatsOption::Tag("index", id),
            ],
        );

        self.run_flow_generator(receiver_from_dispatcher, sender_to_pipeline);
        self.run_additional_packet_pipeline(receiver_from_flow);
        return sender_to_parser;
    }

    pub(super) fn run(&mut self) {
        let sender_to_parser = self.setup_inner_thread_and_queue();
        let base = &mut self.base;
        info!("Start analyzer dispatcher {}", base.log_id);
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

            // From here on, ANALYZER mode is different from LOCAL mode
            base.counter.rx.fetch_add(1, Ordering::Relaxed);
            base.counter
                .rx_bytes
                .fetch_add(packet.capture_length as u64, Ordering::Relaxed);

            let buffer = allocator.allocate_with(&packet.data);
            let info = Packet {
                timestamp,
                raw: buffer,
                original_length: packet.capture_length as u32,
                raw_length: packet.data.len() as u32,
            };
            batch.push(info);
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

    pub(super) fn decap_tunnel<T: AsMut<[u8]>>(
        mut packet: T,
        tap_type_handler: &TapTypeHandler,
        tunnel_info: &mut TunnelInfo,
        bitmap: TunnelTypeBitmap,
    ) -> Result<(usize, TapType)> {
        let packet = packet.as_mut();
        if packet[BILD_FLAGS_OFFSET] == BILD_FLAGS as u8 && packet.len() > ETH_HEADER_SIZE {
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

        BaseDispatcher::decap_tunnel(packet, tap_type_handler, tunnel_info, bitmap)
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
