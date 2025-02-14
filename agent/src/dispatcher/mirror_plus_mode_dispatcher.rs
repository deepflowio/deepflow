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
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use arc_swap::access::Access;
use log::{debug, info, warn};
#[cfg(any(target_os = "linux", target_os = "android"))]
use nix::{
    sched::{sched_setaffinity, CpuSet},
    unistd::Pid,
};

use super::mirror_mode_dispatcher::{
    get_key as mirror_get_key, handler as mirror_handler, swap_last_timestamp,
};
use super::{Packet, TapTypeHandler};
#[cfg(target_os = "linux")]
use crate::platform::{GenericPoller, Poller};
use crate::{
    common::decapsulate::{TunnelInfo, TunnelTypeBitmap},
    config::DispatcherConfig,
    dispatcher::{
        base_dispatcher::{BaseDispatcher, BaseDispatcherListener},
        error::Result,
        PacketCounter,
    },
    flow_generator::{flow_map::Config, FlowMap},
    rpc::get_timestamp,
    utils::stats::{self, Countable, QueueStats},
};
use public::{
    buffer::Allocator,
    debug::QueueDebugger,
    proto::{common::TridentType, trident::IfMacSource},
    queue::{self, bounded_with_debug, DebugSender, Receiver},
    utils::net::{Link, MacAddr},
};

const IF_INDEX_MAX_SIZE: usize = 1000;
const HANDLER_BATCH_SIZE: usize = 64;

#[derive(Clone)]
pub struct MirrorPlusModeDispatcherListener {
    local_vm_mac_set: Arc<RwLock<HashMap<u32, MacAddr>>>,
    updated: Arc<AtomicBool>,
    #[cfg(target_os = "linux")]
    poller: Option<Arc<GenericPoller>>,
    trident_type: Arc<RwLock<TridentType>>,
    base: BaseDispatcherListener,
}

impl MirrorPlusModeDispatcherListener {
    #[cfg(target_os = "linux")]
    pub fn netns(&self) -> &public::netns::NsFile {
        &self.base.netns
    }

    pub fn on_tap_interface_change(
        &self,
        links: &[Link],
        _: IfMacSource,
        trident_type: TridentType,
    ) {
        let mut old_trident_type = self.trident_type.write().unwrap();
        *old_trident_type = trident_type;
        self.base
            .on_tap_interface_change(links.to_vec(), IfMacSource::IfMac);
    }

    pub fn on_vm_change_with_bridge_macs(
        &self,
        vm_mac_addrs: &[MacAddr],
        gateway_vmac_addrs: &[MacAddr],
        tap_bridge_macs: &Vec<MacAddr>,
    ) {
        let mut new_vm_mac_set = HashMap::new();

        vm_mac_addrs
            .iter()
            .zip(gateway_vmac_addrs)
            .for_each(|(vm_mac, gw_vmac)| {
                new_vm_mac_set.insert(vm_mac.to_lower_32b(), gw_vmac.clone());
            });
        tap_bridge_macs.iter().for_each(|e| {
            let key = e.to_lower_32b();
            new_vm_mac_set.insert(key, *e);
        });
        let mut old_vm_mac_set = self.local_vm_mac_set.write().unwrap();
        let mut new_macs = vec![];
        let mut delete_macs = vec![];
        new_vm_mac_set.iter().for_each(|e| {
            if let Some(v) = old_vm_mac_set.get(e.0) {
                if e.1 != v {
                    new_macs.push(MacAddr::try_from(*e.0 as u64).unwrap());
                }
            } else {
                new_macs.push(MacAddr::try_from(*e.0 as u64).unwrap());
            }
        });
        old_vm_mac_set.iter().for_each(|e| {
            if let Some(v) = new_vm_mac_set.get(e.0) {
                if e.1 != v {
                    delete_macs.push(MacAddr::try_from(*e.0 as u64).unwrap());
                }
            } else {
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

    pub fn on_vm_change(
        &self,
        vm_mac_addrs: &[MacAddr],
        #[allow(unused)] gateway_vmac_addrs: &[MacAddr],
    ) {
        #[cfg(target_os = "linux")]
        self.on_vm_change_with_bridge_macs(
            vm_mac_addrs,
            gateway_vmac_addrs,
            &self.tap_bridge_inner_macs(self.base.src_interface_index),
        );
        #[cfg(any(target_os = "windows", target_os = "android"))]
        self.on_vm_change_with_bridge_macs(vm_mac_addrs, &vec![], &vec![]);
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
impl MirrorPlusModeDispatcherListener {
    fn tap_bridge_inner_macs(&self, if_index: usize) -> Vec<MacAddr> {
        if self.poller.is_none() {
            debug!("Dispatcher{} Poller is none.", self.base.log_id);
            return vec![];
        }
        if if_index == 0 {
            debug!(
                "Dispatcher{} Mirror plus mode tap-bridge src-interface ifindex == 0",
                self.base.log_id
            );
            return vec![];
        }
        let mut macs = vec![];
        let ifaces = self.poller.as_ref().unwrap().get_interface_info();
        if ifaces.len() == 0 {
            debug!(
                "Dispatcher{} Mirror plus mode tap-bridge macs is nill.",
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

pub(super) struct MirrorPlusModeDispatcher {
    pub(super) base: BaseDispatcher,
    pub(super) local_vm_mac_set: Arc<RwLock<HashMap<u32, MacAddr>>>,
    pub(super) local_segment_macs: Vec<MacAddr>,
    pub(super) tap_bridge_macs: Vec<MacAddr>,
    #[cfg(target_os = "linux")]
    pub(super) poller: Option<Arc<GenericPoller>>,
    pub(super) updated: Arc<AtomicBool>,
    pub(super) trident_type: Arc<RwLock<TridentType>>,
    pub(super) mac: u32,
    pub(super) flow_generator_thread_handler: Option<JoinHandle<()>>,
    pub(super) queue_debugger: Arc<QueueDebugger>,
    pub(super) inner_queue_size: usize,
    pub(super) stats_collector: Arc<stats::Collector>,
    pub(super) raw_packet_block_size: usize,
}

impl MirrorPlusModeDispatcher {
    pub(super) fn init(&mut self) -> Result<()> {
        info!(
            "Mirror plus mode dispatcher {} init with 0x{:x}.",
            self.base.is.id, self.mac
        );
        self.base.init()
    }

    pub(super) fn listener(&self) -> MirrorPlusModeDispatcherListener {
        MirrorPlusModeDispatcherListener {
            local_vm_mac_set: self.local_vm_mac_set.clone(),
            updated: self.updated.clone(),
            base: self.base.listener(),
            trident_type: self.trident_type.clone(),
            #[cfg(target_os = "linux")]
            poller: self.poller.clone(),
        }
    }

    fn setup_inner_thread_and_queue(&mut self) -> DebugSender<Packet> {
        let id = self.base.is.id;
        let name = "0.1-raw-packet-to-flow-generator-and-pipeline";
        let (sender_to_parser, receiver_from_dispatcher, counter) =
            bounded_with_debug(self.inner_queue_size, name, &self.queue_debugger);
        self.stats_collector.register_countable(
            &QueueStats { id, module: name },
            Countable::Owned(Box::new(counter)),
        );

        self.run_flow_generator_and_pipeline(receiver_from_dispatcher);
        return sender_to_parser;
    }

    // This thread implements the following functions:
    // 1. Decap tunnel
    // 2. Dedup packet
    // 3. Lookup l2end
    // 4. Generate MetaPacket
    // 5. Generate tagged flow
    // 6. Pipeline (NPB AND PCAP)
    fn run_flow_generator_and_pipeline(&mut self, receiver: Receiver<Packet>) {
        let base = &self.base.is;
        let updated = self.updated.clone();
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
        let tap_type_handler = base.tap_type_handler.clone();
        let tunnel_type_bitmap = base.tunnel_type_bitmap.clone();
        let tunnel_type_trim_bitmap = base.tunnel_type_trim_bitmap.clone();
        let mut tunnel_info = TunnelInfo::default();
        let handler_builder = base.handler_builder.clone();
        let npb_dedup_enabled = base.npb_dedup_enabled.clone();
        let mac = self.mac;
        let trident_type = self.trident_type.clone();
        let local_vm_mac_set = self.local_vm_mac_set.clone();
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let cpu_set = base.options.lock().unwrap().cpu_set;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let mut dedup = packet_dedup::PacketDedupMap::new();

        self.flow_generator_thread_handler.replace(
            thread::Builder::new()
                .name("dispatcher-packet-to-flow-generator".to_owned())
                .spawn(move || {
                    let mut batch = Vec::with_capacity(HANDLER_BATCH_SIZE);
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
                    let mut pipelines = HashMap::new();
                    let mut last_timestamp_array = vec![];
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    if cpu_set != CpuSet::new() {
                        if let Err(e) = sched_setaffinity(Pid::from_raw(0), &cpu_set) {
                            warn!("CPU Affinity({:?}) bind error: {:?}.", &cpu_set, e);
                        }
                    }

                    while !terminated.load(Ordering::Relaxed) {
                        let config = Config {
                            flow: &flow_map_config.load(),
                            log_parser: &log_parse_config.load(),
                            collector: &collector_config.load(),
                            #[cfg(any(target_os = "linux", target_os = "android"))]
                            ebpf: None,
                        };
                        let cloud_gateway_traffic = config.flow.cloud_gateway_traffic;

                        match receiver.recv_all(&mut batch, Some(Duration::from_secs(1))) {
                            Ok(_) => {}
                            Err(queue::Error::Timeout) => {
                                flow_map.inject_flush_ticker(&config, Duration::ZERO);
                                continue;
                            }
                            Err(queue::Error::Terminated(..)) => break,
                            Err(queue::Error::BatchTooLarge(_)) => unreachable!(),
                        }

                        let trident_type = trident_type.read().unwrap().clone();
                        for mut packet in batch.drain(..) {
                            let mut timestamp = packet.timestamp;
                            match swap_last_timestamp(
                                &mut last_timestamp_array,
                                &counter,
                                packet.if_index,
                                timestamp,
                                cloud_gateway_traffic,
                            ) {
                                Ok(last_timestamp) => timestamp = last_timestamp,
                                Err(_) => continue,
                            }

                            let decap_length = {
                                // Mirror Mode运行于Windows环境下时目前只有Hyper-V一个场景，由于Hyper-V加了VXLAN隧道，
                                // 这里需要decap并将tunnel信息保存在flow中，目前仅保存最外层的tunnel
                                let len = Self::decap_tunnel(
                                    &mut packet,
                                    &tap_type_handler,
                                    &mut tunnel_info,
                                    &tunnel_type_bitmap,
                                    tunnel_type_trim_bitmap,
                                    &counter,
                                ) as usize;
                                if len > packet.raw_length as usize {
                                    warn!("Decap tunnel error.");
                                    continue;
                                }
                                len
                            };

                            let original_length = packet.raw_length as usize - decap_length;
                            let overlay_packet =
                                &mut packet.raw[decap_length..decap_length + original_length];

                            // Only virtual network traffic goes to remove duplicates
                            #[cfg(any(target_os = "linux", target_os = "android"))]
                            if dedup.duplicate(overlay_packet, timestamp) {
                                debug!("Packet is duplicate");
                                continue;
                            }
                            let (da_key, sa_key, da_gateway_vmac, sa_gateway_vmac) =
                                mirror_get_key(&local_vm_mac_set, overlay_packet, tunnel_info);
                            if sa_gateway_vmac == 0 && da_gateway_vmac == 0 {
                                let _ = mirror_handler(
                                    id,
                                    mac, // In order for two-way traffic to be handled by the same pipeline, self.mac is used as the key here
                                    false,
                                    false,
                                    overlay_packet,
                                    timestamp,
                                    original_length,
                                    &updated,
                                    &mut pipelines,
                                    &handler_builder,
                                    &tunnel_info,
                                    &config,
                                    &mut flow_map,
                                    &counter,
                                    trident_type,
                                    mac,
                                    npb_dedup_enabled.load(Ordering::Relaxed),
                                );
                                continue;
                            }

                            if sa_gateway_vmac > 0 {
                                let _ = mirror_handler(
                                    id,
                                    sa_key,
                                    true,
                                    false,
                                    overlay_packet,
                                    timestamp,
                                    original_length,
                                    &updated,
                                    &mut pipelines,
                                    &handler_builder,
                                    &tunnel_info,
                                    &config,
                                    &mut flow_map,
                                    &counter,
                                    trident_type,
                                    if cloud_gateway_traffic {
                                        sa_gateway_vmac
                                    } else {
                                        mac
                                    },
                                    npb_dedup_enabled.load(Ordering::Relaxed),
                                );
                            }
                            if da_gateway_vmac > 0 {
                                let _ = mirror_handler(
                                    id,
                                    da_key,
                                    false,
                                    true,
                                    overlay_packet,
                                    timestamp,
                                    original_length,
                                    &updated,
                                    &mut pipelines,
                                    &handler_builder,
                                    &tunnel_info,
                                    &config,
                                    &mut flow_map,
                                    &counter,
                                    trident_type,
                                    if cloud_gateway_traffic {
                                        da_gateway_vmac
                                    } else {
                                        mac
                                    },
                                    npb_dedup_enabled.load(Ordering::Relaxed),
                                );
                            }
                        }
                    }
                    pipelines.clear();
                    last_timestamp_array.clear();
                })
                .unwrap(),
        );
    }

    pub(super) fn run(&mut self) {
        info!("Start mirror plus dispatcher {}", self.base.is.log_id);
        let sender_to_parser = self.setup_inner_thread_and_queue();
        let base = &mut self.base.is;
        let time_diff = base.ntp_diff.load(Ordering::Relaxed);
        let mut prev_timestamp = get_timestamp(time_diff);
        let mut batch = Vec::with_capacity(HANDLER_BATCH_SIZE);
        let id = base.id;
        let mut allocator = Allocator::new(self.raw_packet_block_size);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let cpu_set = base.options.lock().unwrap().cpu_set;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Err(e) = sched_setaffinity(Pid::from_raw(0), &cpu_set) {
            warn!("CPU Affinity({:?}) bind error: {:?}.", &cpu_set, e);
        }
        while !base.terminated.load(Ordering::Relaxed) {
            if base.reset_whitelist.swap(false, Ordering::Relaxed) {
                base.tap_interface_whitelist.reset();
            }
            // The lifecycle of the recved will end before the next call to recv.
            let recved = unsafe {
                BaseDispatcher::recv(
                    &mut self.base.engine,
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
                base.check_and_update_bpf(&mut self.base.engine);
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
                ns_ino: 0,
            };
            batch.push(info);

            drop(packet);
            base.check_and_update_bpf(&mut self.base.engine);
        }
        if let Some(handler) = self.flow_generator_thread_handler.take() {
            let _ = handler.join();
        }
        self.base.terminate_handler();
        info!("Stopped dispatcher {}", self.base.is.log_id);
    }

    fn decap_tunnel(
        packet: &mut Packet,
        tap_type_handler: &TapTypeHandler,
        tunnel_info: &mut TunnelInfo,
        tunnel_type_bitmap: &Arc<RwLock<TunnelTypeBitmap>>,
        tunnel_type_trim_bitmap: TunnelTypeBitmap,
        counter: &Arc<PacketCounter>,
    ) -> usize {
        let (decap_length, _) = match BaseDispatcher::decap_tunnel(
            &mut packet.raw,
            tap_type_handler,
            tunnel_info,
            tunnel_type_bitmap.read().unwrap().clone(),
            tunnel_type_trim_bitmap,
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
