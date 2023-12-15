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
    boxed::Box,
    cell::RefCell,
    collections::{HashMap, HashSet},
    mem,
    net::Ipv4Addr,
    rc::Rc,
    str::FromStr,
    sync::{
        atomic::{AtomicI64, AtomicU64, Ordering},
        Arc, Weak,
    },
    time::{Duration, SystemTime},
};

use arc_swap::{
    access::{Access, Map},
    ArcSwap,
};
use log::{debug, warn};

use super::{
    app_table::AppTable,
    error::Error,
    flow_state::{StateMachine, StateValue},
    perf::{l7_rrt::RrtCache, FlowPerf, FlowPerfCounter, L7ProtocolChecker},
    protocol_logs::MetaAppProto,
    service_table::{ServiceKey, ServiceTable},
    FlowMapKey, FlowNode, FlowState, FlowTimeout, COUNTER_FLOW_ID_MASK, FLOW_METRICS_PEER_DST,
    FLOW_METRICS_PEER_SRC, L7_PROTOCOL_UNKNOWN_LIMIT, QUEUE_BATCH_SIZE,
    SERVICE_TABLE_IPV4_CAPACITY, SERVICE_TABLE_IPV6_CAPACITY, STATISTICAL_INTERVAL,
    THREAD_FLOW_ID_MASK, TIMER_FLOW_ID_MASK, TIME_UNIT,
};

#[cfg(target_os = "linux")]
use crate::config::handler::EbpfAccess;
use crate::{
    common::{
        endpoint::{EndpointData, EndpointInfo, EPC_FROM_DEEPFLOW, EPC_FROM_INTERNET},
        enums::{EthernetType, HeaderType, IpProtocol, TapType, TcpFlags},
        flow::{
            CloseType, Flow, FlowKey, FlowMetricsPeer, L4Protocol, L7Protocol, PacketDirection,
            SignalSource, TunnelField,
        },
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ProtocolParser, L7ProtocolParserInterface},
        lookup_key::LookupKey,
        meta_packet::{MetaPacket, MetaPacketTcpHeader},
        tagged_flow::TaggedFlow,
        tap_port::TapPort,
        Timestamp,
    },
    config::{
        handler::{L7LogDynamicConfig, LogParserAccess, LogParserConfig},
        FlowAccess, FlowConfig, ModuleConfig, RuntimeConfig,
    },
    metric::document::TapSide,
    policy::{Policy, PolicyGetter},
    rpc::get_timestamp,
    utils::stats::{self, Countable, StatsOption},
};
use public::{
    counter::{Counter, CounterType, CounterValue, RefCountable},
    debug::QueueDebugger,
    l7_protocol::L7ProtocolEnum,
    proto::common::TridentType,
    queue::{self, DebugSender, Receiver},
    utils::net::MacAddr,
};

use packet_sequence_block::PacketSequenceBlock;

// not thread-safe
pub struct FlowMap {
    node_map: Option<HashMap<FlowMapKey, Vec<Box<FlowNode>>>>,
    time_set: Option<Vec<HashSet<FlowMapKey>>>,
    id: u32,
    state_machine_master: StateMachine,
    state_machine_slave: StateMachine,
    service_table: ServiceTable,
    app_table: AppTable,
    policy_getter: PolicyGetter,
    start_time: Duration,    // 时间桶中的最早时间
    start_time_in_unit: u64, // 时间桶中的最早时间，以TIME_SLOT_UNIT为单位
    hash_slots: usize,
    time_window_size: usize,
    total_flow: usize,
    time_set_slot_size: usize,

    output_queue: DebugSender<Box<TaggedFlow>>,
    out_log_queue: DebugSender<Box<MetaAppProto>>,
    output_buffer: Vec<Box<TaggedFlow>>,
    protolog_buffer: Vec<Box<MetaAppProto>>,
    last_queue_flush: Duration,
    config: FlowAccess,
    parse_config: LogParserAccess,
    #[cfg(target_os = "linux")]
    ebpf_config: Option<EbpfAccess>, // TODO: We only need its epc_id，epc_id is not only useful for ebpf, consider moving it to FlowConfig
    rrt_cache: Rc<RefCell<RrtCache>>,
    flow_perf_counter: Arc<FlowPerfCounter>,
    ntp_diff: Arc<AtomicI64>,
    packet_sequence_queue: Option<DebugSender<Box<PacketSequenceBlock>>>, // Enterprise Edition Feature: packet-sequence
    packet_sequence_enabled: bool,
    stats_counter: Arc<FlowMapCounter>,

    l7_protocol_checker: L7ProtocolChecker,

    time_key_buffer: Option<Vec<(u64, FlowMapKey)>>,
}

impl FlowMap {
    pub fn new(
        id: u32,
        output_queue: DebugSender<Box<TaggedFlow>>,
        policy_getter: PolicyGetter,
        app_proto_log_queue: DebugSender<Box<MetaAppProto>>,
        ntp_diff: Arc<AtomicI64>,
        config: FlowAccess,
        parse_config: LogParserAccess,
        #[cfg(target_os = "linux")] ebpf_config: Option<EbpfAccess>,
        packet_sequence_queue: Option<DebugSender<Box<PacketSequenceBlock>>>, // Enterprise Edition Feature: packet-sequence
        stats_collector: &stats::Collector,
        from_ebpf: bool,
    ) -> Self {
        let flow_perf_counter = Arc::new(FlowPerfCounter::default());
        let stats_counter = Arc::new(FlowMapCounter::default());
        let config_guard = config.load();
        let packet_sequence_enabled = config_guard.packet_sequence_flag > 0 && !from_ebpf;
        let time_window_size = {
            let max_timeout = config_guard.flow_timeout.max;
            let size = (config_guard.packet_delay + max_timeout + Duration::from_secs(1)).as_secs();
            size.next_power_of_two() as usize
        };
        stats_collector.register_countable(
            "flow-map",
            Countable::Ref(Arc::downgrade(&stats_counter) as Weak<dyn RefCountable>),
            vec![StatsOption::Tag("id", id.to_string())],
        );

        stats_collector.register_countable(
            "flow-perf",
            Countable::Ref(Arc::downgrade(&flow_perf_counter) as Weak<dyn RefCountable>),
            vec![StatsOption::Tag("id", format!("{}", id))],
        );
        let start_time = get_timestamp(ntp_diff.load(Ordering::Relaxed))
            - config_guard.packet_delay
            - Duration::from_secs(1);
        let time_set_slot_size = config_guard.hash_slots as usize / time_window_size;
        Self {
            node_map: Some(HashMap::with_capacity(config_guard.hash_slots as usize)),
            time_set: Some(vec![
                HashSet::with_capacity(time_set_slot_size);
                time_window_size
            ]),
            id,
            state_machine_master: StateMachine::new_master(&config_guard.flow_timeout),
            state_machine_slave: StateMachine::new_slave(&config_guard.flow_timeout),
            service_table: ServiceTable::new(
                SERVICE_TABLE_IPV4_CAPACITY,
                SERVICE_TABLE_IPV6_CAPACITY,
            ),
            app_table: AppTable::new(
                config_guard.l7_protocol_inference_max_fail_count,
                config_guard.l7_protocol_inference_ttl,
            ),
            policy_getter,
            start_time,
            start_time_in_unit: start_time.as_secs(),
            hash_slots: config_guard.hash_slots as usize,
            time_window_size,
            total_flow: 0,
            time_set_slot_size,
            output_queue,
            out_log_queue: app_proto_log_queue,
            output_buffer: Vec::with_capacity(QUEUE_BATCH_SIZE),
            protolog_buffer: Vec::with_capacity(QUEUE_BATCH_SIZE),
            last_queue_flush: Duration::ZERO,
            config,
            parse_config,
            #[cfg(target_os = "linux")]
            ebpf_config,
            rrt_cache: Rc::new(RefCell::new(RrtCache::new(
                (config_guard.capacity >> 2) as usize,
            ))),
            flow_perf_counter,
            ntp_diff,
            packet_sequence_queue, // Enterprise Edition Feature: packet-sequence
            packet_sequence_enabled,
            stats_counter,
            l7_protocol_checker: L7ProtocolChecker::new(
                &config_guard.l7_protocol_enabled_bitmap,
                &config_guard
                    .l7_protocol_parse_port_bitmap
                    .iter()
                    .filter_map(|(name, bitmap)| {
                        L7ProtocolParser::try_from(name.as_ref())
                            .ok()
                            .map(|p| (p.protocol(), bitmap.clone()))
                    })
                    .collect(),
            ),
            time_key_buffer: None,
        }
    }

    // sort nodes by swapping timed out nodes to right
    // the result will be like:
    //     nodes: [A1, A4, A3, A2, A5, B4, B1, B2, B3]
    //     A refers to nodes after time_in_unit or not timed out
    //     B refers to nodes timed out
    // returned index will be the first timed out node in nodes
    fn sort_nodes_by_timeout(
        nodes: &mut Vec<Box<FlowNode>>,
        timestamp: Duration,
        time_in_unit: u64,
    ) -> usize {
        let mut left = 0 as isize;
        let mut right = nodes.len() as isize - 1;

        while left <= right {
            let node = &nodes[left as usize];

            // find first timeout node from left
            let timeout = node.recent_time + node.timeout;
            if node.timestamp_key > time_in_unit || timestamp < timeout {
                // not timeout
                left += 1;
                continue;
            }

            // find first not timeout node from right
            while left <= right {
                let node = &nodes[right as usize];
                let timeout = node.recent_time + node.timeout;
                if node.timestamp_key > time_in_unit || timestamp < timeout {
                    break;
                }
                right -= 1;
            }

            // swap nodes
            if left < right {
                nodes.swap(left as usize, right as usize);
                left += 1;
                right -= 1;
            }
        }
        left as usize
    }

    pub fn inject_flush_ticker(&mut self, mut timestamp: Duration) -> bool {
        if timestamp.is_zero() {
            timestamp = get_timestamp(self.ntp_diff.load(Ordering::Relaxed));
        } else if timestamp < self.start_time {
            self.stats_counter
                .drop_by_window
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let config = self.config.load();

        // FlowMap 时间窗口无法推动
        if timestamp - config.packet_delay - TIME_UNIT < self.start_time {
            return true;
        }

        // 根据包到达时间的容差调整
        let next_start_time_in_unit =
            ((timestamp - config.packet_delay).as_nanos() / TIME_UNIT.as_nanos()) as u64;
        self.start_time =
            Duration::from_nanos(next_start_time_in_unit * TIME_UNIT.as_nanos() as u64);
        timestamp = self.start_time - Duration::from_nanos(1);

        let (mut node_map, mut time_set) = match self.node_map.take().zip(self.time_set.take()) {
            Some(pair) => pair,
            None => {
                warn!("cannot get node map or time set");
                return false;
            }
        };

        let mut moved_key = self
            .time_key_buffer
            .take()
            .unwrap_or(Vec::with_capacity(self.hash_slots / self.time_window_size));
        moved_key.clear();
        // at most self.time_windows_size slots in time_set
        for time_in_unit in self.start_time_in_unit
            ..next_start_time_in_unit.min(self.start_time_in_unit + self.time_window_size as u64)
        {
            let time_hashset = &mut time_set[time_in_unit as usize & (self.time_window_size - 1)];
            for flow_key in time_hashset.drain() {
                let Some(nodes) = node_map.get_mut(&flow_key) else {
                    continue;
                };
                self.stats_counter
                    .total_scan
                    .fetch_add(nodes.len() as u64, Ordering::Relaxed);
                self.stats_counter
                    .slot_max_depth
                    .fetch_max(nodes.len() as u64, Ordering::Relaxed);

                // nodes are partitioned by timed out or not
                // nodes not in this time_set or not timed out are moved to front
                // timed out nodes are move to back
                // the returned index refers to the first node that is timed out
                let index = Self::sort_nodes_by_timeout(nodes, timestamp, time_in_unit);
                // handle and remove timeout nodes
                for node in nodes.drain(index..) {
                    let timeout = node.recent_time + node.timeout;
                    self.node_removed_aftercare(&config, *node, timeout, None);
                }
                if nodes.is_empty() {
                    node_map.remove(&flow_key);
                    continue;
                }

                // handle rest nodes
                for node in nodes.iter_mut() {
                    if node.timestamp_key > time_in_unit {
                        continue;
                    }
                    // 未超时Flow的统计信息发送到队列下游
                    self.node_updated_aftercare(&config, node, timestamp, None);
                    // Enterprise Edition Feature: packet-sequence
                    if self.packet_sequence_enabled {
                        if let Some(block) = node.packet_sequence_block.take() {
                            // flush the packet_sequence_block at the regular time
                            if let Err(_) = self.packet_sequence_queue.as_ref().unwrap().send(block)
                            {
                                warn!(
                                    "packet sequence block to queue failed maybe queue have terminated"
                                );
                            }
                        }
                    }

                    // 若流统计信息已输出，将节点移动至最终超时的时间
                    let timeout = node.recent_time + node.timeout;
                    if node.timestamp_key != timeout.as_secs() {
                        node.timestamp_key = timeout.as_secs();
                        moved_key.push((node.timestamp_key, flow_key));
                    }
                }
            }
            if time_hashset.capacity() > 2 * self.time_set_slot_size {
                self.stats_counter
                    .time_set_shrinks
                    .fetch_add(1, Ordering::Relaxed);
                time_hashset.shrink_to(self.time_set_slot_size);
            }
            for key in moved_key.drain(..) {
                time_set[key.0 as usize & (self.time_window_size - 1)].insert(key.1);
            }
        }
        Self::update_stats_counter(&self.stats_counter, node_map.len() as u64, 0);

        self.time_key_buffer.replace(moved_key);
        self.node_map.replace(node_map);
        self.time_set.replace(time_set);

        self.start_time_in_unit = next_start_time_in_unit;
        self.flush_queue(&config, timestamp);

        self.flush_app_protolog();

        true
    }

    pub fn inject_meta_packet(&mut self, meta_packet: &mut MetaPacket) {
        if !self.inject_flush_ticker(meta_packet.lookup_key.timestamp) {
            // 补充由于超时导致未查询策略，用于其它流程（如PCAP存储）
            #[cfg(target_os = "linux")]
            let local_epc_id = if self.ebpf_config.is_some() {
                self.ebpf_config.as_ref().unwrap().load().epc_id as i32
            } else {
                0
            };
            #[cfg(target_os = "windows")]
            let local_epc_id = 0;
            (self.policy_getter).lookup(meta_packet, self.id as usize, local_epc_id);
            return;
        }

        let flow_config = self.config.load();
        let log_parser_config = self.parse_config.load();

        let pkt_key = FlowMapKey::new(&meta_packet.lookup_key, meta_packet.tap_port);

        let (mut node_map, mut time_set) = match self.node_map.take().zip(self.time_set.take()) {
            Some(pair) => pair,
            None => {
                warn!("cannot get node map or time set");
                return;
            }
        };

        let pkt_timestamp = meta_packet.lookup_key.timestamp;
        let mut max_depth = 1;
        match node_map.get_mut(&pkt_key) {
            // 找到一组可能的 FlowNode
            Some(nodes) => {
                max_depth = nodes.len();
                let ignore_l2_end = flow_config.ignore_l2_end;
                let ignore_tor_mac = flow_config.ignore_tor_mac;
                let ignore_idc_vlan = flow_config.ignore_idc_vlan;
                let trident_type = flow_config.trident_type;
                let index = nodes.iter().position(|node| {
                    node.match_node(
                        meta_packet,
                        ignore_l2_end,
                        ignore_tor_mac,
                        ignore_idc_vlan,
                        trident_type,
                    )
                });
                let Some(index) = index else {
                    // 没有找到严格匹配的 FlowNode，插入新 Node
                    let node = self.new_flow_node(&flow_config, &log_parser_config, meta_packet);
                    if node.is_some() {
                        let node = Box::new(node.unwrap());
                        time_set[node.timestamp_key as usize & (self.time_window_size - 1)].insert(pkt_key);
                        nodes.push(node);
                        max_depth += 1;
                    }
                    Self::update_stats_counter(
                        &self.stats_counter,
                        node_map.len() as u64,
                        max_depth as u64,
                    );
                    self.stats_counter
                        .total_scan
                        .fetch_add(max_depth as u64, Ordering::Relaxed);
                    self.node_map.replace(node_map);
                    self.time_set.replace(time_set);
                    return;
                };
                self.stats_counter
                    .total_scan
                    .fetch_add(1 + index as u64, Ordering::Relaxed);

                let node = &mut nodes[index];
                // 1. 输出上一个统计周期的统计信息
                self.node_updated_aftercare(&flow_config, node, pkt_timestamp, Some(meta_packet));

                // 2. 更新Flow状态，判断是否已结束
                // 设置timestamp_key为流的相同，time_set根据key来删除
                meta_packet.flow_id = node.tagged_flow.flow.flow_id;
                let flow_closed = match meta_packet.lookup_key.proto {
                    IpProtocol::Tcp => {
                        self.update_tcp_node(&flow_config, &log_parser_config, node, meta_packet)
                    }
                    IpProtocol::Udp => {
                        self.update_udp_node(&flow_config, &log_parser_config, node, meta_packet)
                    }
                    _ => self.update_other_node(&flow_config, node, meta_packet),
                };

                if flow_closed {
                    let node = *nodes.swap_remove(index);
                    self.node_removed_aftercare(
                        &flow_config,
                        node,
                        meta_packet.lookup_key.timestamp,
                        Some(meta_packet),
                    );

                    if nodes.is_empty() {
                        node_map.remove(&pkt_key);
                    }
                } else {
                    if node.timestamp_key != pkt_timestamp.as_secs() {
                        // Because pkt_key is shared by multiple nodes, we have no low-cost way to
                        // delete it from time_set. In fact, we can invalidate the flow_key in the
                        // old slot in time_set by updating node.timestamp_key.
                        //
                        // Therefore, it is only necessary to insert the node into the new slot of
                        // time_set, so that the statistical data can be output in time. However,
                        // the following operations are only required when the slot needs to be
                        // changed.
                        node.timestamp_key = pkt_timestamp.as_secs();
                        time_set[node.timestamp_key as usize & (self.time_window_size - 1)]
                            .insert(pkt_key);
                    }
                }
            }
            // 未找到匹配的 FlowNode，需要插入新的节点
            None => {
                let node = self.new_flow_node(&flow_config, &log_parser_config, meta_packet);
                if node.is_some() {
                    let node = Box::new(node.unwrap());
                    time_set[node.timestamp_key as usize & (self.time_window_size - 1)]
                        .insert(pkt_key);
                    node_map.insert(pkt_key, vec![node]);
                }
            }
        }
        Self::update_stats_counter(&self.stats_counter, node_map.len() as u64, max_depth as u64);
        self.node_map.replace(node_map);
        self.time_set.replace(time_set);
        // go实现只有插入node的时候，插入的节点数目大于ring buffer 的capacity 才会执行policy_getter,
        // rust 版本用了std的hashmap自动处理扩容，所以无需执行policy_gettelr
    }

    fn append_to_block(&self, config: &FlowConfig, node: &mut FlowNode, meta_packet: &MetaPacket) {
        const MINUTE: u64 = 60;
        if node.packet_sequence_block.is_some() {
            if !node.packet_sequence_block.as_ref().unwrap().is_available(
                config.packet_sequence_block_size,
                (meta_packet.lookup_key.timestamp.as_secs() / MINUTE) as u32,
            ) {
                // if the packet_sequence_block is no enough to push one more packet, then send it to the queue
                if let Err(_) = self
                    .packet_sequence_queue
                    .as_ref()
                    .unwrap()
                    .send(node.packet_sequence_block.take().unwrap())
                {
                    warn!("packet sequence block to queue failed maybe queue have terminated");
                }
                node.packet_sequence_block = Some(Box::new(PacketSequenceBlock::new(
                    (meta_packet.lookup_key.timestamp.as_secs() / MINUTE) as u32,
                )));
            }
        } else {
            node.packet_sequence_block = Some(Box::new(PacketSequenceBlock::new(
                (meta_packet.lookup_key.timestamp.as_secs() / MINUTE) as u32,
            )));
        }

        let mini_meta_packet = packet_sequence_block::MiniMetaPacket::new(
            node.tagged_flow.flow.flow_id,
            meta_packet.direction as u8,
            meta_packet.lookup_key.timestamp,
            meta_packet.payload_len,
            meta_packet.tcp_data.seq,
            meta_packet.tcp_data.ack,
            meta_packet.tcp_data.win_size,
            meta_packet.tcp_data.mss,
            meta_packet.tcp_data.flags.bits(),
            meta_packet.tcp_data.win_scale,
            meta_packet.tcp_data.sack_permitted,
            &meta_packet.tcp_data.sack,
        );
        node.packet_sequence_block
            .as_mut()
            .unwrap()
            .append_packet(mini_meta_packet, config.packet_sequence_flag);
    }

    fn update_tcp_node(
        &mut self,
        flow_config: &FlowConfig,
        log_parser_config: &LogParserConfig,
        node: &mut FlowNode,
        meta_packet: &mut MetaPacket,
    ) -> bool {
        let flow_closed = self.update_tcp_flow(flow_config, meta_packet, node);
        if flow_config.collector_enabled {
            let direction = meta_packet.direction == PacketDirection::ClientToServer;
            self.collect_metric(
                flow_config,
                log_parser_config,
                node,
                meta_packet,
                direction,
                false,
            );
        }

        // After collect_metric() is called for eBPF MetaPacket, its direction is determined.
        if node.tagged_flow.flow.signal_source == SignalSource::EBPF {
            if meta_packet.direction == PacketDirection::ClientToServer {
                node.residual_request += 1;
            } else {
                node.residual_request -= 1;
            }
            // For eBPF data, timeout as soon as possible when there are no unaggregated requests.
            // Considering that eBPF data may be out of order, wait for an additional 5s(default) timeout.
            if node.residual_request == 0 {
                node.timeout = flow_config.flow_timeout.opening;
            } else {
                node.timeout = log_parser_config.l7_log_session_aggr_timeout;
            }
        }

        // Enterprise Edition Feature: packet-sequence
        if self.packet_sequence_enabled {
            self.append_to_block(flow_config, node, meta_packet);
        }

        flow_closed
    }

    fn update_udp_node(
        &mut self,
        flow_config: &FlowConfig,
        log_parser_config: &LogParserConfig,
        node: &mut FlowNode,
        meta_packet: &mut MetaPacket,
    ) -> bool {
        self.update_flow(node, meta_packet);
        let peers = &node.tagged_flow.flow.flow_metrics_peers;
        if peers[FLOW_METRICS_PEER_SRC].packet_count > 0
            && peers[FLOW_METRICS_PEER_DST].packet_count > 0
        {
            // For udp, eBPF and Packet data use the same timeout
            node.timeout = flow_config.flow_timeout.closing;
        }
        meta_packet.is_active_service = node.tagged_flow.flow.is_active_service;
        if flow_config.collector_enabled {
            self.collect_metric(
                flow_config,
                log_parser_config,
                node,
                meta_packet,
                meta_packet.direction == PacketDirection::ClientToServer,
                false,
            );
        }

        if node.tagged_flow.flow.signal_source == SignalSource::EBPF {
            self.update_udp_is_active(node, meta_packet.direction);
        }

        false
    }

    fn update_other_node(
        &mut self,
        config: &FlowConfig,
        node: &mut FlowNode,
        meta_packet: &mut MetaPacket,
    ) -> bool {
        self.update_flow(node, meta_packet);
        let peers = &node.tagged_flow.flow.flow_metrics_peers;
        if peers[FLOW_METRICS_PEER_SRC].packet_count > 0
            && peers[FLOW_METRICS_PEER_DST].packet_count > 0
        {
            node.timeout = config.flow_timeout.established_rst;
        }

        false
    }

    fn generate_flow_id(&mut self, timestamp: Duration, thread_id: u32) -> u64 {
        self.total_flow += 1;
        (timestamp.as_nanos() as u64 >> 30 & TIMER_FLOW_ID_MASK) << 32
            | thread_id as u64 & THREAD_FLOW_ID_MASK << 24
            | self.total_flow as u64 & COUNTER_FLOW_ID_MASK
    }

    fn update_tcp_flow(
        &mut self,
        config: &FlowConfig,
        meta_packet: &mut MetaPacket,
        node: &mut FlowNode,
    ) -> bool {
        let direction = meta_packet.direction;
        let pkt_tcp_flags = meta_packet.tcp_data.flags;
        node.tagged_flow.flow.flow_metrics_peers[direction as usize].tcp_flags |= pkt_tcp_flags;
        node.tagged_flow.flow.flow_metrics_peers[direction as usize].total_tcp_flags |=
            pkt_tcp_flags;
        self.update_flow(node, meta_packet);
        if node.tagged_flow.flow.signal_source == SignalSource::EBPF {
            // Because eBPF data does not have L4 information, the remaining steps of direction
            // correction, state machine maintenance, SEQ acquisition, etc., do not need to be
            // performed.
            return false;
        }

        // 有特殊包时更新ServiceTable并矫正流方向：SYN+ACK或SYN
        if pkt_tcp_flags.bits() & TcpFlags::SYN.bits() != 0 {
            self.update_l4_direction(meta_packet, node, false);
            self.update_syn_or_syn_ack_seq(node, meta_packet);
        }

        self.update_tcp_keepalive_seq(node, meta_packet);
        meta_packet.is_active_service = node.tagged_flow.flow.is_active_service;

        if pkt_tcp_flags.is_invalid() {
            // exception timeout
            node.timeout = config.flow_timeout.exception;
            node.flow_state = FlowState::Exception;
            return false;
        }

        self.update_flow_state_machine(config, node, pkt_tcp_flags, direction)
    }

    // 协议参考：https://datatracker.ietf.org/doc/html/rfc1122#section-4.2.3.6
    // TCP Keepalive报文特征：
    //		1.payloadLen为0/1
    //		2.非FIN、SYN、RST
    //		3.TCP保活探测报文序列号(Seq)为前一个TCP报文序列号(Seq)减一
    fn update_tcp_keepalive_seq(&mut self, node: &mut FlowNode, meta_packet: &MetaPacket) {
        // 保存TCP Seq用于TCP Keepalive报文判断

        let (next_tcp_seq0, next_tcp_seq1) = (node.next_tcp_seq0, node.next_tcp_seq1);

        // 记录下一次TCP Seq
        match meta_packet.direction {
            PacketDirection::ClientToServer => node.next_tcp_seq1 = meta_packet.tcp_data.ack,
            PacketDirection::ServerToClient => node.next_tcp_seq0 = meta_packet.tcp_data.ack,
        }
        // TCP Keepalive报文判断，并记录其TCP Seq
        if meta_packet.payload_len > 1 {
            return;
        }

        if meta_packet.tcp_data.flags & (TcpFlags::SYN | TcpFlags::FIN | TcpFlags::RST)
            != TcpFlags::empty()
        {
            return;
        }

        let (seq, ack) = (meta_packet.tcp_data.seq, meta_packet.tcp_data.ack);

        if meta_packet.direction == PacketDirection::ClientToServer
            && seq.wrapping_add(1) == next_tcp_seq0
            || meta_packet.direction == PacketDirection::ServerToClient
                && seq.wrapping_add(1) == next_tcp_seq1
        {
            let flow = &mut node.tagged_flow.flow;
            flow.last_keepalive_seq = seq;
            flow.last_keepalive_ack = ack;
        }
    }

    fn update_syn_or_syn_ack_seq(&mut self, node: &mut FlowNode, meta_packet: &mut MetaPacket) {
        let tcp_flag = meta_packet.tcp_data.flags;
        let flow = &mut node.tagged_flow.flow;
        if tcp_flag == TcpFlags::SYN {
            flow.syn_seq = meta_packet.tcp_data.seq;
        } else if tcp_flag == TcpFlags::SYN_ACK && meta_packet.payload_len == 0 {
            flow.synack_seq = meta_packet.tcp_data.seq;
        }
    }

    //flow_state.rs 有个state_machine的测试用到该方法, 要用super
    pub(super) fn update_flow_state_machine(
        &mut self,
        config: &FlowConfig,
        node: &mut FlowNode,
        flags: TcpFlags,
        direction: PacketDirection,
    ) -> bool {
        let &StateValue {
            mut timeout,
            mut state,
            mut closed,
        } = self
            .state_machine_master
            .get(node.flow_state, flags)
            .unwrap_or(&StateValue::new(
                // exception timeout,
                config.flow_timeout.exception,
                FlowState::Exception,
                false,
            ));

        if direction == PacketDirection::ServerToClient {
            if let Some(v) = self.state_machine_slave.get(node.flow_state, flags) {
                timeout = v.timeout;
                state = v.state;
                closed = v.closed;
            }
        }

        node.flow_state = state;
        let flow = &node.tagged_flow.flow;
        let peer_src = &flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC];
        let peer_dst = &flow.flow_metrics_peers[FLOW_METRICS_PEER_DST];
        if peer_src.total_packet_count == 0 || peer_dst.total_packet_count == 0 {
            //single direction timeout
            node.timeout = config.flow_timeout.single_direction;
        } else {
            node.timeout = timeout;
        }

        closed
    }

    fn l7_metrics_enabled(config: &FlowConfig) -> bool {
        config.l7_metrics_enabled
    }

    fn l7_log_parse_enabled(config: &FlowConfig, lookup_key: &LookupKey) -> bool {
        // parse tap_type any or tap_type in config
        config.app_proto_log_enabled
            && (lookup_key.proto == IpProtocol::Tcp || lookup_key.proto == IpProtocol::Udp)
            && (config.l7_log_tap_types[u16::from(TapType::Any) as usize]
                || lookup_key.tap_type <= TapType::Max
                    && config.l7_log_tap_types[u16::from(lookup_key.tap_type) as usize])
    }

    fn l4_metrics_enabled(config: &FlowConfig) -> bool {
        config.l4_performance_enabled
    }

    fn init_flow(&mut self, config: &FlowConfig, meta_packet: &mut MetaPacket) -> FlowNode {
        meta_packet.direction = PacketDirection::ClientToServer;

        let mut tagged_flow = TaggedFlow::default();
        let lookup_key = &meta_packet.lookup_key;
        let is_active_service = if meta_packet.signal_source == SignalSource::EBPF {
            match lookup_key.proto {
                IpProtocol::Tcp => true, // Tcp data coming from eBPF means it must be an active service
                _ => false,
            }
        } else {
            false
        };
        let flow = Flow {
            flow_key: FlowKey {
                vtap_id: config.vtap_id,
                mac_src: lookup_key.src_mac,
                mac_dst: lookup_key.dst_mac,
                ip_src: lookup_key.src_ip,
                ip_dst: lookup_key.dst_ip,
                port_src: lookup_key.src_port,
                port_dst: lookup_key.dst_port,
                proto: lookup_key.proto,
                tap_type: lookup_key.tap_type,
                tap_port: meta_packet.tap_port,
            },
            tunnel: if let Some(tunnel) = meta_packet.tunnel {
                TunnelField {
                    tx_ip0: tunnel.src,
                    tx_ip1: tunnel.dst,
                    tx_mac0: tunnel.mac_src,
                    tx_mac1: tunnel.mac_dst,
                    tx_id: tunnel.id,
                    tier: tunnel.tier,
                    tunnel_type: tunnel.tunnel_type,
                    is_ipv6: tunnel.is_ipv6,
                    ..Default::default()
                }
            } else {
                TunnelField::default()
            },
            flow_id: if meta_packet.signal_source == SignalSource::EBPF {
                meta_packet.socket_id
            } else {
                self.generate_flow_id(lookup_key.timestamp, self.id)
            },
            start_time: lookup_key.timestamp.into(),
            flow_stat_time: Timestamp::from_nanos(
                (lookup_key.timestamp.as_nanos() / TIME_UNIT.as_nanos() * TIME_UNIT.as_nanos())
                    as u64,
            ),
            vlan: meta_packet.vlan,
            eth_type: lookup_key.eth_type,
            queue_hash: meta_packet.queue_hash,
            is_new_flow: true,
            // 统计量
            flow_metrics_peers: [
                FlowMetricsPeer {
                    total_packet_count: 1,
                    packet_count: 1,
                    total_byte_count: meta_packet.packet_len as u64,
                    byte_count: meta_packet.packet_len as u64,
                    l3_byte_count: meta_packet.l3_payload_len() as u64,
                    l4_byte_count: meta_packet.l4_payload_len() as u64,
                    first: lookup_key.timestamp.into(),
                    last: lookup_key.timestamp.into(),
                    tcp_flags: meta_packet.tcp_data.flags,
                    total_tcp_flags: meta_packet.tcp_data.flags,
                    ..Default::default()
                },
                FlowMetricsPeer::default(),
            ],
            signal_source: meta_packet.signal_source,
            is_active_service,
            ..Default::default()
        };
        tagged_flow.flow = flow;

        // FlowMap信息
        let mut policy_in_tick = [false; 2];
        policy_in_tick[meta_packet.direction as usize] = true;

        let mut node = FlowNode {
            timestamp_key: lookup_key.timestamp.as_secs(),

            tagged_flow,
            min_arrived_time: lookup_key.timestamp,
            recent_time: lookup_key.timestamp,
            timeout: Duration::ZERO,
            packet_in_tick: true,
            policy_in_tick,
            flow_state: FlowState::Raw,
            meta_flow_perf: None,
            next_tcp_seq0: 0,
            next_tcp_seq1: 0,
            policy_data_cache: Default::default(),
            endpoint_data_cache: Default::default(),
            packet_sequence_block: None, // Enterprise Edition Feature: packet-sequence
            residual_request: 0,
        };
        #[cfg(target_os = "linux")]
        let local_epc_id = if self.ebpf_config.is_some() {
            self.ebpf_config.as_ref().unwrap().load().epc_id as i32
        } else {
            0
        };
        #[cfg(target_os = "windows")]
        let local_epc_id = 0;

        // 标签
        (self.policy_getter).lookup(meta_packet, self.id as usize, local_epc_id);
        self.update_endpoint_and_policy_data(&mut node, meta_packet);

        /*
            ebpf will pass the server port to FlowPerf use for adjuest packet direction.
            non ebpf not need this field, FlowPerf::server_port always 0.
        */
        let (l7_proto_enum, port, from_app_tab) = if let Some((proto, port)) =
            match meta_packet.signal_source {
                SignalSource::EBPF => {
                    let (local_epc, remote_epc) = if meta_packet.lookup_key.l2_end_0 {
                        (local_epc_id, 0)
                    } else {
                        (0, local_epc_id)
                    };
                    self.app_table
                        .get_protocol_from_ebpf(meta_packet, local_epc, remote_epc)
                }
                _ => self.app_table.get_protocol(meta_packet).map(|p| (p, 0u16)),
            } {
            (proto, port, true)
        } else {
            (L7ProtocolEnum::default(), 0, false)
        };

        if config.collector_enabled {
            node.meta_flow_perf = FlowPerf::new(
                self.rrt_cache.clone(),
                L4Protocol::from(meta_packet.lookup_key.proto),
                l7_proto_enum,
                from_app_tab,
                self.flow_perf_counter.clone(),
                port,
                match meta_packet.lookup_key.proto {
                    IpProtocol::Tcp => config.rrt_tcp_timeout,
                    IpProtocol::Udp => config.rrt_tcp_timeout,
                    _ => 0,
                },
            )
            .map(|o| Box::new(o));
        }
        node
    }

    fn update_flow(&mut self, node: &mut FlowNode, meta_packet: &mut MetaPacket) {
        let pkt_timestamp = meta_packet.lookup_key.timestamp;
        let flow = &mut node.tagged_flow.flow;
        if pkt_timestamp > node.recent_time {
            node.recent_time = pkt_timestamp;
            flow.duration = (node.recent_time - node.min_arrived_time).into();
            // Duration仅使用包的时间计算，不包括超时时间
        }

        if !node.packet_in_tick {
            // FlowStatTime取整至统计时间的开始，只需要赋值一次，且使用包的时间戳
            node.packet_in_tick = true;
            flow.flow_stat_time = Timestamp::from_nanos(
                (pkt_timestamp.as_nanos() / STATISTICAL_INTERVAL.as_nanos()
                    * STATISTICAL_INTERVAL.as_nanos()) as u64,
            );
        }

        if !node.policy_in_tick[meta_packet.direction as usize] {
            node.policy_in_tick[meta_packet.direction as usize] = true;
            #[cfg(target_os = "linux")]
            let local_epc_id = if self.ebpf_config.is_some() {
                self.ebpf_config.as_ref().unwrap().load().epc_id as i32
            } else {
                0
            };
            #[cfg(target_os = "windows")]
            let local_epc_id = 0;
            (self.policy_getter).lookup(meta_packet, self.id as usize, local_epc_id);
            self.update_endpoint_and_policy_data(node, meta_packet);
        } else {
            // copy endpoint and policy data
            meta_packet
                .policy_data
                .replace(node.policy_data_cache[meta_packet.direction as usize].clone());
            match meta_packet.direction {
                PacketDirection::ClientToServer => {
                    meta_packet
                        .endpoint_data
                        .replace(node.endpoint_data_cache[0].clone());
                }
                PacketDirection::ServerToClient => {
                    meta_packet
                        .endpoint_data
                        .replace(node.endpoint_data_cache[1].clone());
                }
            }
            if let Some(endpoint_data) = meta_packet.endpoint_data.as_ref() {
                meta_packet.lookup_key.l3_end_0 = endpoint_data.src_info.l3_end;
                meta_packet.lookup_key.l3_end_1 = endpoint_data.dst_info.l3_end;
            }
        }

        // The ebpf data has no l3 and l4 information, so it can be returned directly
        if node.tagged_flow.flow.signal_source == SignalSource::EBPF {
            return;
        }

        let flow = &mut node.tagged_flow.flow;
        let flow_metrics_peer = &mut flow.flow_metrics_peers[meta_packet.direction as usize];
        flow_metrics_peer.packet_count += 1;
        flow_metrics_peer.total_packet_count += 1;
        flow_metrics_peer.byte_count += meta_packet.packet_len as u64;
        flow_metrics_peer.l3_byte_count += meta_packet.l3_payload_len() as u64;
        flow_metrics_peer.l4_byte_count += meta_packet.l4_payload_len() as u64;
        flow_metrics_peer.total_byte_count += meta_packet.packet_len as u64;
        flow_metrics_peer.last = pkt_timestamp.into();
        if flow_metrics_peer.first.is_zero() {
            flow_metrics_peer.first = pkt_timestamp.into();
        }

        if meta_packet.vlan > 0 {
            flow.vlan = meta_packet.vlan;
        }
        if let Some(tunnel) = meta_packet.tunnel {
            match meta_packet.direction {
                PacketDirection::ClientToServer => {
                    flow.tunnel.tx_ip0 = tunnel.src;
                    flow.tunnel.tx_ip1 = tunnel.dst;
                    flow.tunnel.tx_mac0 = tunnel.mac_src;
                    flow.tunnel.tx_mac1 = tunnel.mac_dst;
                    flow.tunnel.tx_id = tunnel.id;
                }
                PacketDirection::ServerToClient => {
                    flow.tunnel.rx_ip0 = tunnel.src;
                    flow.tunnel.rx_ip1 = tunnel.dst;
                    flow.tunnel.rx_mac0 = tunnel.mac_src;
                    flow.tunnel.rx_mac1 = tunnel.mac_dst;
                    flow.tunnel.rx_id = tunnel.id;
                }
            }
            flow.tunnel.tier = tunnel.tier;
            flow.tunnel.tunnel_type = tunnel.tunnel_type;
            flow.tunnel.is_ipv6 = tunnel.is_ipv6;
        }
        // 这里需要查询策略，建立ARP表
        if meta_packet.is_ndp_response() {
            #[cfg(target_os = "linux")]
            let local_epc_id = if self.ebpf_config.is_some() {
                self.ebpf_config.as_ref().unwrap().load().epc_id as i32
            } else {
                0
            };
            #[cfg(target_os = "windows")]
            let local_epc_id = 0;

            (self.policy_getter).lookup(meta_packet, self.id as usize, local_epc_id);
        }
    }

    fn collect_metric(
        &mut self,
        flow_config: &FlowConfig,
        log_parser_config: &LogParserConfig,
        node: &mut FlowNode,
        meta_packet: &mut MetaPacket,
        is_first_packet_direction: bool,
        is_first_packet: bool,
    ) {
        let mut info = None;
        if let Some(perf) = node.meta_flow_perf.as_mut() {
            let flow_id = node.tagged_flow.flow.flow_id;
            #[cfg(target_os = "linux")]
            let local_epc_id = if self.ebpf_config.is_some() {
                self.ebpf_config.as_ref().unwrap().load().epc_id as i32
            } else {
                0
            };
            #[cfg(target_os = "windows")]
            let local_epc_id = 0; // just for ebpf, Windows does not need this value
            let (local_epc, remote_epc) = if meta_packet.lookup_key.l2_end_0 {
                (local_epc_id, 0)
            } else {
                (0, local_epc_id)
            };
            match perf.parse(
                flow_config,
                log_parser_config,
                meta_packet,
                is_first_packet_direction,
                flow_id,
                node.tagged_flow.flow.signal_source == SignalSource::Packet
                    && Self::l4_metrics_enabled(flow_config),
                Self::l7_metrics_enabled(flow_config),
                Self::l7_log_parse_enabled(flow_config, &meta_packet.lookup_key),
                &mut self.app_table,
                local_epc,
                remote_epc,
                &self.l7_protocol_checker,
            ) {
                Ok(i) => {
                    info = Some(i);
                }
                Err(Error::L7ReqNotFound(c)) => {
                    self.flow_perf_counter
                        .mismatched_response
                        .fetch_add(c, Ordering::Relaxed);
                }
                Err(e) => debug!("{}", e),
            }
        }
        if let Some((info, rrt)) = info {
            if node.tagged_flow.flow.signal_source == SignalSource::EBPF {
                // For ebpf data, after perf.parse() success, meta_packet's direction
                // is determined. Here we determine whether to reverse flow.
                Self::rectify_ebpf_flow_direction(node, meta_packet, is_first_packet);
            }
            for i in info.into_iter() {
                self.write_to_app_proto_log(flow_config, node, &meta_packet, i, rrt);
            }
        }
    }

    fn new_tcp_node(
        &mut self,
        flow_config: &FlowConfig,
        log_parser_config: &LogParserConfig,
        meta_packet: &mut MetaPacket,
    ) -> FlowNode {
        let mut node = self.init_flow(flow_config, meta_packet);
        meta_packet.is_active_service = node.tagged_flow.flow.is_active_service;
        let mut reverse = false;
        if node.tagged_flow.flow.signal_source == SignalSource::EBPF {
            // Initialize a timeout long enough for eBPF Flow to enable successful session aggregation.
            node.timeout = log_parser_config.l7_log_session_aggr_timeout;
        } else {
            reverse = self.update_l4_direction(meta_packet, &mut node, true);

            let pkt_tcp_flags = meta_packet.tcp_data.flags;
            if pkt_tcp_flags.is_invalid() {
                // exception timeout
                node.timeout = flow_config.flow_timeout.exception;
                node.flow_state = FlowState::Exception;
            }
            self.update_flow_state_machine(
                flow_config,
                &mut node,
                pkt_tcp_flags,
                meta_packet.direction,
            );
            self.update_syn_or_syn_ack_seq(&mut node, meta_packet);
        }

        if flow_config.collector_enabled {
            self.collect_metric(
                flow_config,
                log_parser_config,
                &mut node,
                meta_packet,
                !reverse,
                true,
            );
        }

        // After collect_metric() is called for eBPF MetaPacket, its direction is determined.
        if node.tagged_flow.flow.signal_source == SignalSource::EBPF {
            if meta_packet.direction == PacketDirection::ClientToServer {
                node.residual_request += 1;
            } else {
                node.residual_request -= 1;
            }
        }

        // Enterprise Edition Feature: packet-sequence
        if self.packet_sequence_enabled {
            self.append_to_block(flow_config, &mut node, meta_packet);
        }
        node
    }

    fn new_udp_node(
        &mut self,
        flow_config: &FlowConfig,
        log_parser_config: &LogParserConfig,
        meta_packet: &mut MetaPacket,
    ) -> FlowNode {
        let mut node = self.init_flow(flow_config, meta_packet);
        meta_packet.is_active_service = node.tagged_flow.flow.is_active_service;
        node.flow_state = FlowState::Established;
        // For eBPF UDP Flow, there is no special treatment for timeout.
        node.timeout = flow_config.flow_timeout.opening; // use opening timeout
        let mut reverse = false;
        if node.tagged_flow.flow.signal_source != SignalSource::EBPF {
            // eBPF Flow only use server_port to correct the direction.
            reverse = self.update_l4_direction(meta_packet, &mut node, true);
        }
        if flow_config.collector_enabled {
            self.collect_metric(
                flow_config,
                log_parser_config,
                &mut node,
                meta_packet,
                !reverse,
                true,
            );
        }
        node
    }

    fn new_other_node(&mut self, config: &FlowConfig, meta_packet: &mut MetaPacket) -> FlowNode {
        let mut node = self.init_flow(config, meta_packet);
        node.flow_state = FlowState::Established;
        // opening timeout
        node.timeout = config.flow_timeout.opening;
        node
    }

    fn new_flow_node(
        &mut self,
        flow_config: &FlowConfig,
        log_parser_config: &LogParserConfig,
        meta_packet: &mut MetaPacket,
    ) -> Option<FlowNode> {
        // To avoid using each package to query policies that may lead to CPU increase and performance decrease,
        // there will not be use config.capacity to limit the addition of FlowNode
        self.stats_counter.new.fetch_add(1, Ordering::Relaxed);
        let node = match meta_packet.lookup_key.proto {
            IpProtocol::Tcp => self.new_tcp_node(flow_config, log_parser_config, meta_packet),
            IpProtocol::Udp => self.new_udp_node(flow_config, log_parser_config, meta_packet),
            _ => self.new_other_node(flow_config, meta_packet),
        };
        meta_packet.flow_id = node.tagged_flow.flow.flow_id;
        if meta_packet.signal_source == SignalSource::EBPF
            && node.meta_flow_perf.is_some()
            && node.meta_flow_perf.as_ref().unwrap().server_port == 0
        {
            // For ebpf data, if server_port is 0, it means that parsed data failed,
            // the info in node maybe wrong, we should not create this node.
            None
        } else {
            self.stats_counter
                .concurrent
                .fetch_add(1, Ordering::Relaxed);
            Some(node)
        }
    }

    fn flush_queue(&mut self, config: &FlowConfig, now: Duration) {
        if now - self.last_queue_flush > config.flush_interval {
            if self.output_buffer.len() > 0 {
                if let Err(_) = self.output_queue.send_all(&mut self.output_buffer) {
                    warn!(
                        "flow-map push tagged flows to queue failed because queue have terminated"
                    );
                    self.output_buffer.clear();
                }
            }
            self.last_queue_flush = now;
        }
    }

    fn push_to_flow_stats_queue(&mut self, config: &FlowConfig, mut tagged_flow: TaggedFlow) {
        // This field is required for logging when the flow is not finished. To avoid
        // double counting, it is assigned when the flow statistics are finished output
        //
        // Currently, only virtual traffic's tap_side is counted
        tagged_flow
            .flow
            .set_tap_side(config.trident_type, config.cloud_gateway_traffic);

        // Unknown application only counts metrics, and the judgment condition needs to consider
        // the flow's duration, so the value is assigned when the flow is finished
        //
        // The L7Protocol::Unknown data's flow_perf_stats are collected only when all of the following conditions are met:
        // 1. TCP protocol
        // 2. l4_metrics_enabled = true
        // 3. l7_metrics_enabled = true
        // 4. The application protocol cannot be identified
        // 5. The flow ends or the flow lasts more than 60 seconds
        // 6. The L7PerfStats is valuable

        let flow = &mut tagged_flow.flow;
        if flow.flow_key.proto == IpProtocol::Tcp
            && flow.flow_perf_stats.is_some()
            && Self::l7_metrics_enabled(config)
        {
            let stats = flow.flow_perf_stats.as_mut().unwrap();
            if stats.l7_protocol == L7Protocol::Unknown
                && (flow.close_type != CloseType::ForcedReport
                    || flow.duration >= L7_PROTOCOL_UNKNOWN_LIMIT)
                && (stats.l7.request_count > 0 || stats.l7.response_count > 0)
            {
                stats.l7_protocol = L7Protocol::Other; // In order to the L7PerfStats to be counted, change it's l7_protocol to Other, the Unknown will not be counted
            }
        }
        self.output_buffer.push(Box::new(tagged_flow));
        if self.output_buffer.len() >= QUEUE_BATCH_SIZE {
            if let Err(_) = self.output_queue.send_all(&mut self.output_buffer) {
                warn!("flow-map push tagged flows to queue failed because queue have terminated");
                self.output_buffer.clear();
            }
        }
    }

    // go 版本的removeAndOutput
    fn node_removed_aftercare(
        &mut self,
        config: &FlowConfig,
        mut node: FlowNode,
        timeout: Duration,
        meta_packet: Option<&mut MetaPacket>,
    ) {
        // 统计数据输出前矫正流方向
        self.update_flow_direction(&mut node, meta_packet);

        let flow = &mut node.tagged_flow.flow;
        if flow.signal_source == SignalSource::EBPF {
            // the flow which from eBPF, it's close_type always be CloseType::Timeout
            flow.close_type = CloseType::Timeout;
        } else {
            flow.update_close_type(node.flow_state);
        }
        flow.end_time = timeout.into();
        flow.flow_stat_time = Timestamp::from_nanos(
            (timeout.as_nanos() / STATISTICAL_INTERVAL.as_nanos() * STATISTICAL_INTERVAL.as_nanos())
                as u64,
        );

        if config.collector_enabled
            && (flow.flow_key.proto == IpProtocol::Tcp || flow.flow_key.proto == IpProtocol::Udp)
        {
            let l7_timeout_count = self.rrt_cache.borrow_mut().get_timeout_count(flow.flow_id);
            // 如果返回None，就清空掉flow_perf_stats
            flow.flow_perf_stats = node.meta_flow_perf.as_mut().and_then(|perf| {
                perf.copy_and_reset_perf_data(
                    flow.reversed,
                    l7_timeout_count as u32,
                    flow.signal_source == SignalSource::Packet && Self::l4_metrics_enabled(config),
                    Self::l7_metrics_enabled(config),
                )
                .map(|o| Box::new(o))
            });
        }

        // Enterprise Edition Feature: packet-sequence
        if self.packet_sequence_enabled && flow.flow_key.proto == IpProtocol::Tcp {
            if let Some(block) = node.packet_sequence_block.take() {
                if let Err(_) = self.packet_sequence_queue.as_ref().unwrap().send(block) {
                    warn!("packet sequence block to queue failed maybe queue have terminated");
                }
            }
        }

        self.stats_counter
            .concurrent
            .fetch_sub(1, Ordering::Relaxed);
        self.stats_counter.closed.fetch_add(1, Ordering::Relaxed);

        self.push_to_flow_stats_queue(config, node.tagged_flow);
    }

    // go 版本的copyAndOutput
    fn node_updated_aftercare(
        &mut self,
        config: &FlowConfig,
        node: &mut FlowNode,
        timestamp: Duration,
        meta_packet: Option<&mut MetaPacket>,
    ) {
        let flow = &node.tagged_flow.flow;
        // if this function is called by inject_flush_ticker (no meta_packet),
        // skip statistical interval check because timestamp will be equal to
        // flow_stat_time
        if node.packet_in_tick
            && (meta_packet.is_none()
                || timestamp >= flow.flow_stat_time + STATISTICAL_INTERVAL
                || timestamp < flow.flow_stat_time)
        {
            self.update_flow_direction(node, meta_packet); // 每个流统计数据输出前矫正流方向
            node.tagged_flow.flow.close_type = CloseType::ForcedReport;
            let flow = &mut node.tagged_flow.flow;
            if !config.collector_enabled {
                return;
            }
            if flow.flow_key.proto == IpProtocol::Tcp || flow.flow_key.proto == IpProtocol::Udp {
                flow.flow_perf_stats = node.meta_flow_perf.as_mut().and_then(|perf| {
                    perf.copy_and_reset_perf_data(
                        flow.reversed,
                        0,
                        flow.signal_source == SignalSource::Packet
                            && Self::l4_metrics_enabled(config),
                        Self::l7_metrics_enabled(config),
                    )
                    .map(|o| Box::new(o))
                });
            }
            self.push_to_flow_stats_queue(config, node.tagged_flow.clone());
            node.reset_flow_stat_info();
        }
    }

    fn write_to_app_proto_log(
        &mut self,
        config: &FlowConfig,
        node: &mut FlowNode,
        meta_packet: &MetaPacket,
        l7_info: L7ProtocolInfo,
        rrt: u64,
    ) {
        if self.protolog_buffer.len() >= QUEUE_BATCH_SIZE {
            self.flush_app_protolog();
        }
        // 考虑性能，最好是l7 perf解析后，满足需要的包生成log
        if let Some(mut head) = l7_info.app_proto_head() {
            head.rrt = rrt;
            node.tagged_flow
                .flow
                .set_tap_side(config.trident_type, config.cloud_gateway_traffic);

            if let Some(app_proto) =
                MetaAppProto::new(&node.tagged_flow, meta_packet, l7_info, head)
            {
                self.protolog_buffer.push(Box::new(app_proto));
            }
        }
    }

    fn flush_app_protolog(&mut self) {
        if self.protolog_buffer.len() > 0 {
            if let Err(_) = self.out_log_queue.send_all(&mut self.protolog_buffer) {
                warn!("flow-map push MetaAppProto to queue failed because queue have terminated");
                self.protolog_buffer.clear();
            }
        }
    }

    fn update_l4_direction(
        &mut self,
        meta_packet: &mut MetaPacket,
        node: &mut FlowNode,
        is_first_packet: bool,
    ) -> bool {
        let lookup_key = &meta_packet.lookup_key;
        let src_key = ServiceKey::new(
            lookup_key.src_ip,
            node.endpoint_data_cache[0].src_info.l3_epc_id as i16,
            lookup_key.src_port,
        );
        let dst_key = ServiceKey::new(
            lookup_key.dst_ip,
            node.endpoint_data_cache[0].dst_info.l3_epc_id as i16,
            lookup_key.dst_port,
        );
        let (mut src_score, mut dst_score) = match lookup_key.proto {
            // TCP/UDP
            IpProtocol::Tcp => {
                let flags = meta_packet.tcp_data.flags;
                self.service_table
                    .get_tcp_score(is_first_packet, flags, src_key, dst_key)
            }
            IpProtocol::Udp => self
                .service_table
                .get_udp_score(is_first_packet, src_key, dst_key),
            _ => unimplemented!(),
        };

        if PacketDirection::ServerToClient == meta_packet.direction {
            mem::swap(&mut src_score, &mut dst_score);
        }

        let mut reverse = false;
        if !ServiceTable::is_client_to_server(src_score, dst_score) {
            mem::swap(&mut src_score, &mut dst_score);

            Self::reverse_flow(node, is_first_packet);
            meta_packet.direction = meta_packet.direction.reversed();
            reverse = true;
        }

        node.tagged_flow.flow.is_active_service = ServiceTable::is_active_service(dst_score);
        return reverse;
    }

    // just for ebpf, tcp flow.is_active_service is always true,
    // but udp flow.is_active_service still needs to continue to judge.
    fn update_udp_is_active(&mut self, node: &mut FlowNode, direction: PacketDirection) {
        // If it is already an active service, we do not need to continue to query.
        if !node.tagged_flow.flow.is_active_service {
            let flow_key = &node.tagged_flow.flow.flow_key;
            // Because the flow direction is already correct, we can use flow_key's
            // ip_src, port_src and ip_dst, port_dst directly without swapping them.
            let src_key = ServiceKey::new(
                flow_key.ip_src,
                node.endpoint_data_cache[0].src_info.l3_epc_id as i16,
                flow_key.port_src,
            );
            let dst_key = ServiceKey::new(
                flow_key.ip_dst,
                node.endpoint_data_cache[0].dst_info.l3_epc_id as i16,
                flow_key.port_dst,
            );

            node.tagged_flow.flow.is_active_service = self
                .service_table
                .is_ebpf_active_udp_service(src_key, dst_key, direction);
        }
    }

    fn update_flow_direction(&mut self, node: &mut FlowNode, meta_packet: Option<&mut MetaPacket>) {
        if node.tagged_flow.flow.signal_source == SignalSource::EBPF {
            // The direction of eBPF Flow is determined when FlowPerf::l7_parse is called for the
            // first time, and no further correction is required.
            return;
        }
        let flow_key = &node.tagged_flow.flow.flow_key;
        let src_epc_id = node.tagged_flow.flow.flow_metrics_peers[0].l3_epc_id as i16;
        let dst_epc_id = node.tagged_flow.flow.flow_metrics_peers[1].l3_epc_id as i16;

        let src_key = ServiceKey::new(flow_key.ip_src, src_epc_id, flow_key.port_src);
        let dst_key = ServiceKey::new(flow_key.ip_dst, dst_epc_id, flow_key.port_dst);
        let (mut src_score, mut dst_score) = match flow_key.proto {
            IpProtocol::Tcp => {
                self.service_table
                    .get_tcp_score(false, TcpFlags::empty(), src_key, dst_key)
            }
            IpProtocol::Udp => self.service_table.get_udp_score(false, src_key, dst_key),
            _ => return,
        };

        if !ServiceTable::is_client_to_server(src_score, dst_score) {
            mem::swap(&mut src_score, &mut dst_score);
            Self::reverse_flow(node, false);
            if let Some(pkt) = meta_packet {
                pkt.direction = pkt.direction.reversed();
            }
        }

        node.tagged_flow.flow.is_active_service = ServiceTable::is_active_service(dst_score);
    }

    fn reverse_flow(node: &mut FlowNode, is_first_packet: bool) {
        node.policy_in_tick.swap(0, 1);
        node.policy_data_cache.swap(0, 1);
        node.endpoint_data_cache.swap(0, 1);
        node.tagged_flow.flow.reverse(is_first_packet);
        node.tagged_flow.tag.reverse();

        // Enterprise Edition Feature: packet-sequence
        if node.packet_sequence_block.is_some() {
            node.packet_sequence_block
                .as_mut()
                .unwrap()
                .reverse_needed_for_new_packet();
        }
    }

    fn rectify_ebpf_flow_direction(
        node: &mut FlowNode,
        meta_packet: &mut MetaPacket,
        is_first_packet: bool,
    ) {
        if node.tagged_flow.flow.flow_key.ip_src == meta_packet.lookup_key.src_ip
            && node.tagged_flow.flow.flow_key.port_src == meta_packet.lookup_key.src_port
        {
            // If flow_key.ip_src and flow_key.port_src of node.tagged_flow.flow are the same as
            // that of meta_packet, but the direction of meta_packet is S2C, reverse flow
            if meta_packet.direction == PacketDirection::ServerToClient {
                Self::reverse_flow(node, is_first_packet);
            }
        } else {
            // If flow_key.ip_src or flow_key.port_src of node.tagged_flow.flow is different
            // from that of meta_packet, and the direction of meta_packet is C2S, reverse flow
            if meta_packet.direction == PacketDirection::ClientToServer {
                Self::reverse_flow(node, is_first_packet);
            }
        }
    }

    fn update_endpoint_and_policy_data(
        &mut self,
        node: &mut FlowNode,
        meta_packet: &mut MetaPacket,
    ) {
        // update endpoint
        if let Some(data) = meta_packet.endpoint_data.as_ref() {
            match meta_packet.direction {
                PacketDirection::ClientToServer => {
                    node.endpoint_data_cache[0] = data.clone();
                    node.endpoint_data_cache[1] = Arc::new(data.reversed());
                }
                PacketDirection::ServerToClient => {
                    node.endpoint_data_cache[1] = data.clone();
                    node.endpoint_data_cache[0] = Arc::new(data.reversed());
                }
            }
        }

        let mut reset_tap_side;
        {
            let src_info = node.endpoint_data_cache[0].src_info;
            let peer_src = &mut node.tagged_flow.flow.flow_metrics_peers[0];
            reset_tap_side =
                peer_src.is_l2_end != src_info.l2_end || peer_src.is_l3_end != src_info.l3_end;
            peer_src.is_device = src_info.is_device;
            peer_src.is_vip_interface = src_info.is_vip_interface;
            peer_src.is_l2_end = src_info.l2_end;
            peer_src.is_l3_end = src_info.l3_end;
            peer_src.l3_epc_id = src_info.l3_epc_id;
            peer_src.is_vip = src_info.is_vip;
            if src_info.real_ip.is_unspecified() {
                peer_src.nat_real_ip = src_info.real_ip;
            }
            peer_src.is_local_mac = src_info.is_local_mac;
            peer_src.is_local_ip = src_info.is_local_ip;
        }
        {
            let dst_info = node.endpoint_data_cache[0].dst_info;
            let peer_dst = &mut node.tagged_flow.flow.flow_metrics_peers[1];
            reset_tap_side = reset_tap_side
                || peer_dst.is_l2_end != dst_info.l2_end
                || peer_dst.is_l3_end != dst_info.l3_end;
            peer_dst.is_device = dst_info.is_device;
            peer_dst.is_vip_interface = dst_info.is_vip_interface;
            peer_dst.is_l2_end = dst_info.l2_end;
            peer_dst.is_l3_end = dst_info.l3_end;
            peer_dst.l3_epc_id = dst_info.l3_epc_id;
            peer_dst.is_vip = dst_info.is_vip;
            if dst_info.real_ip.is_unspecified() {
                peer_dst.nat_real_ip = dst_info.real_ip;
            }
            peer_dst.is_local_mac = dst_info.is_local_mac;
            peer_dst.is_local_ip = dst_info.is_local_ip;
        }
        // When there is a change in l2end or l3end, the tap side needs to be recalculated
        if reset_tap_side {
            node.tagged_flow.flow.tap_side = TapSide::Rest;
        }

        // update policy data
        if let Some(policy_data) = meta_packet.policy_data.as_ref() {
            node.policy_data_cache[meta_packet.direction as usize] = policy_data.clone();
        }
        node.tagged_flow.tag.policy_data = node.policy_data_cache.clone();
    }

    fn update_stats_counter(c: &FlowMapCounter, slots: u64, max_depth: u64) {
        c.slots.swap(slots, Ordering::Relaxed);
        c.slot_max_depth.fetch_max(max_depth, Ordering::Relaxed);
    }
}

#[derive(Default)]
pub struct FlowMapCounter {
    new: AtomicU64,              // the number of  created flow
    closed: AtomicU64,           // the number of closed flow
    drop_by_window: AtomicU64,   // times of flush wihich drop by window
    concurrent: AtomicU64,       // current the number of FlowNode
    slots: AtomicU64,            // current the length of HashMap
    slot_max_depth: AtomicU64,   // the max length of Vec<FlowNode>
    total_scan: AtomicU64,       // the total number of iteration to scan over Vec<FlowNode>
    time_set_shrinks: AtomicU64, // the total number of time_set HashSet shrinks
}

impl RefCountable for FlowMapCounter {
    fn get_counters(&self) -> Vec<Counter> {
        let concurrent = self.concurrent.load(Ordering::Relaxed);
        let slots = self.slots.swap(0, Ordering::Relaxed);

        vec![
            (
                "new",
                CounterType::Gauged,
                CounterValue::Unsigned(self.new.swap(0, Ordering::Relaxed)),
            ),
            (
                "closed",
                CounterType::Gauged,
                CounterValue::Unsigned(self.closed.swap(0, Ordering::Relaxed)),
            ),
            (
                "drop_by_window",
                CounterType::Gauged,
                CounterValue::Unsigned(self.drop_by_window.swap(0, Ordering::Relaxed)),
            ),
            (
                "concurrent",
                CounterType::Gauged,
                CounterValue::Unsigned(concurrent),
            ),
            (
                "slot_max_depth",
                CounterType::Gauged,
                CounterValue::Unsigned(self.slot_max_depth.swap(0, Ordering::Relaxed)),
            ),
            (
                "total_scan",
                CounterType::Gauged,
                CounterValue::Unsigned(self.total_scan.swap(0, Ordering::Relaxed)),
            ),
            ("slots", CounterType::Gauged, CounterValue::Unsigned(slots)),
            (
                "time_set_shrinks",
                CounterType::Gauged,
                CounterValue::Unsigned(self.time_set_shrinks.swap(0, Ordering::Relaxed)),
            ),
        ]
    }
}

pub fn _reverse_meta_packet(packet: &mut MetaPacket) {
    let lookup_key = &mut packet.lookup_key;
    mem::swap(&mut lookup_key.src_ip, &mut lookup_key.dst_ip);
    mem::swap(&mut lookup_key.src_port, &mut lookup_key.dst_port);
    mem::swap(&mut lookup_key.src_mac, &mut lookup_key.dst_mac);
    mem::swap(&mut lookup_key.l2_end_0, &mut lookup_key.l2_end_1);
    if packet.endpoint_data.is_some() {
        let endpoint_data = packet.endpoint_data.as_ref().unwrap();
        packet.endpoint_data = Some(Arc::new(EndpointData {
            src_info: endpoint_data.dst_info.clone(),
            dst_info: endpoint_data.src_info.clone(),
        }));
    }
}

pub fn _new_flow_map_and_receiver(
    trident_type: TridentType,
    flow_timeout: Option<FlowTimeout>,
    ignore_idc_vlan: bool,
) -> (FlowMap, Receiver<Box<TaggedFlow>>) {
    let (_, mut policy_getter) = Policy::new(1, 0, 1 << 10, 1 << 14, false);
    policy_getter.disable();
    let queue_debugger = QueueDebugger::new();
    let (output_queue_sender, output_queue_receiver, _) =
        queue::bounded_with_debug(256, "", &queue_debugger);
    let (app_proto_log_queue, _, _) = queue::bounded_with_debug(256, "", &queue_debugger);
    let (packet_sequence_queue, _, _) = queue::bounded_with_debug(256, "", &queue_debugger); // Enterprise Edition Feature: packet-sequence
    let mut config = ModuleConfig {
        flow: FlowConfig {
            trident_type,
            collector_enabled: true,
            l4_performance_enabled: true,
            l7_metrics_enabled: true,
            app_proto_log_enabled: true,
            ignore_idc_vlan: ignore_idc_vlan,
            flow_timeout: flow_timeout.unwrap_or(super::TcpTimeout::default().into()),
            ..(&RuntimeConfig::default()).into()
        },
        log_parser: LogParserConfig {
            l7_log_collect_nps_threshold: 0,
            l7_log_session_aggr_timeout: Duration::new(0, 0),
            l7_log_dynamic: L7LogDynamicConfig::default(),
        },
        ..Default::default()
    };
    // Any
    config.flow.l7_log_tap_types[0] = true;
    config.flow.trident_type = trident_type;
    let current_config = Arc::new(ArcSwap::from_pointee(config));
    #[cfg(target_os = "linux")]
    let flow_map = FlowMap::new(
        0,
        output_queue_sender,
        policy_getter,
        app_proto_log_queue,
        Arc::new(AtomicI64::new(0)),
        Map::new(current_config.clone(), |config| -> &FlowConfig {
            &config.flow
        }),
        Map::new(current_config.clone(), |config| -> &LogParserConfig {
            &config.log_parser
        }),
        None,
        Some(packet_sequence_queue), // Enterprise Edition Feature: packet-sequence
        &stats::Collector::new("127.0.0.1".to_string(), 30033),
        false,
    );
    #[cfg(target_os = "windows")]
    let flow_map = FlowMap::new(
        0,
        output_queue_sender,
        policy_getter,
        app_proto_log_queue,
        Arc::new(AtomicI64::new(0)),
        Map::new(current_config.clone(), |config| -> &FlowConfig {
            &config.flow
        }),
        Map::new(current_config.clone(), |config| -> &LogParserConfig {
            &config.log_parser
        }),
        Some(packet_sequence_queue), // Enterprise Edition Feature: packet-sequence
        &stats::Collector::new("127.0.0.1".to_string(), 30033),
        false,
    );

    (flow_map, output_queue_receiver)
}

pub fn _new_meta_packet<'a>() -> MetaPacket<'a> {
    let mut packet = MetaPacket::default();
    packet.lookup_key = LookupKey {
        timestamp: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap(),
        src_mac: MacAddr::from_str("12:34:56:78:9A:BC").unwrap(),
        dst_mac: MacAddr::from_str("21:43:65:87:A9:CB").unwrap(),
        eth_type: EthernetType::Ipv4,
        proto: IpProtocol::Tcp,
        src_ip: Ipv4Addr::new(8, 8, 8, 8).into(),
        dst_ip: Ipv4Addr::new(114, 114, 114, 114).into(),
        src_port: 12345,
        dst_port: 22,
        tap_type: TapType::Idc(1),
        ..Default::default()
    };
    packet.header_type = HeaderType::Ipv4Tcp;
    packet.tap_port = TapPort(65533);
    packet.packet_len = 128;
    packet.tcp_data = MetaPacketTcpHeader {
        data_offset: 5,
        flags: TcpFlags::SYN,
        ack: 0,
        seq: 0,
        ..Default::default()
    };
    packet.endpoint_data = Some(Arc::new(EndpointData {
        src_info: EndpointInfo {
            real_ip: Ipv4Addr::UNSPECIFIED.into(),
            l2_end: false,
            l3_end: false,
            is_device: false,
            is_vip_interface: false,
            is_vip: false,
            is_local_mac: false,
            is_local_ip: false,

            l2_epc_id: EPC_FROM_DEEPFLOW,
            l3_epc_id: 1,
        },
        dst_info: EndpointInfo {
            real_ip: Ipv4Addr::UNSPECIFIED.into(),
            l2_end: false,
            l3_end: false,
            is_device: false,
            is_vip_interface: false,
            is_vip: false,
            is_local_mac: false,
            is_local_ip: false,

            l2_epc_id: EPC_FROM_DEEPFLOW,
            l3_epc_id: EPC_FROM_INTERNET,
        },
    }));
    packet
}

// 对应 flow_generator_test.go
#[cfg(test)]
mod tests {
    use std::{net::IpAddr, ops::Add, time};

    use super::*;

    use crate::{
        common::{enums::EthernetType, flow::CloseType, tap_port::TapPort},
        utils::test::Capture,
    };
    use npb_pcap_policy::{DirectionType, NpbAction, NpbTunnelType, PolicyData, TapSide};
    use public::utils::net::MacAddr;

    const DEFAULT_DURATION: Duration = Duration::from_millis(10);

    impl FlowMap {
        fn reset_start_time(&mut self, d: Duration) {
            self.start_time = d;
            self.start_time_in_unit = (d.as_nanos() / TIME_UNIT.as_nanos()) as u64;
        }
    }

    #[test]
    fn syn_rst() {
        let (mut flow_map, output_queue_receiver) =
            _new_flow_map_and_receiver(TridentType::TtProcess, None, false);
        let mut packet0 = _new_meta_packet();
        flow_map.inject_meta_packet(&mut packet0);
        let mut packet1 = _new_meta_packet();
        packet1.tcp_data.flags = TcpFlags::RST;
        _reverse_meta_packet(&mut packet1);
        packet1.lookup_key.timestamp += DEFAULT_DURATION;
        let flush_timestamp = packet1.lookup_key.timestamp;
        flow_map.inject_meta_packet(&mut packet1);

        // 没到期删除，所以下游queue等不到flow
        flow_map.inject_flush_ticker(flush_timestamp);

        flow_map.inject_flush_ticker(flush_timestamp + Duration::from_secs(10));

        if let Ok(tagged_flow) = output_queue_receiver.recv(Some(TIME_UNIT)) {
            assert_eq!(tagged_flow.flow.close_type, CloseType::ServerReset);
            // 生成包需要时间，因为 pkt0 - pk1 的duration = DEFAULT_DURATION 加上生成包的时间.
            //  assert!(tagged_flow.flow().duration <= DEFAULT_DURATION);

            let peer_src = &tagged_flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC];
            let peer_dst = &tagged_flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_DST];
            assert!(peer_src.tcp_flags == TcpFlags::SYN && peer_dst.tcp_flags == TcpFlags::RST);
        }
    }

    #[test]
    fn syn_fin() {
        let (mut flow_map, output_queue_receiver) =
            _new_flow_map_and_receiver(TridentType::TtProcess, None, false);
        let mut packet0 = _new_meta_packet();
        flow_map.inject_meta_packet(&mut packet0);

        let mut packet1 = _new_meta_packet();
        packet1.tcp_data.flags = TcpFlags::PSH_ACK;
        flow_map.inject_meta_packet(&mut packet1);

        let mut packet2 = _new_meta_packet();
        packet2.tcp_data.flags = TcpFlags::FIN_ACK;
        packet2.lookup_key.timestamp += Duration::from_millis(10);
        _reverse_meta_packet(&mut packet2);
        let flush_timestamp = packet2.lookup_key.timestamp;
        flow_map.inject_meta_packet(&mut packet2);

        flow_map.inject_flush_ticker(flush_timestamp);
        flow_map.inject_flush_ticker(flush_timestamp + Duration::from_secs(10));

        if let Ok(tagged_flow) = output_queue_receiver.recv(Some(TIME_UNIT)) {
            assert_eq!(tagged_flow.flow.close_type, CloseType::ClientHalfClose);

            let peer_src = &tagged_flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC];
            let peer_dst = &tagged_flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_DST];
            assert!(
                peer_src.tcp_flags == TcpFlags::SYN_ACK | TcpFlags::PSH
                    || peer_dst.tcp_flags == TcpFlags::FIN_ACK
            );
        }
    }

    #[test]
    fn platform_data() {
        let (mut flow_map, output_queue_receiver) =
            _new_flow_map_and_receiver(TridentType::TtProcess, None, false);
        let mut packet1 = _new_meta_packet();
        packet1.tcp_data.seq = 1111;
        packet1.tcp_data.ack = 112;
        packet1.lookup_key.timestamp = Duration::from_nanos(
            (packet1.lookup_key.timestamp.as_nanos() / TIME_UNIT.as_nanos() * TIME_UNIT.as_nanos())
                as u64,
        );
        let flush_timestamp = packet1.lookup_key.timestamp;
        flow_map.inject_meta_packet(&mut packet1);

        flow_map.inject_flush_ticker(flush_timestamp);
        flow_map.inject_flush_ticker(flush_timestamp + Duration::from_secs(10));
        if let Ok(tagged_flow) = output_queue_receiver.recv(Some(TIME_UNIT)) {
            assert_eq!(tagged_flow.flow.close_type, CloseType::ClientSynRepeat);
            let peer_src = &tagged_flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC];
            assert_eq!(peer_src.l3_epc_id, 1);
        }
    }

    #[test]
    fn handshake_perf() {
        let (mut flow_map, output_queue_receiver) =
            _new_flow_map_and_receiver(TridentType::TtProcess, None, false);
        let mut packet0 = _new_meta_packet();
        packet0.tcp_data.flags = TcpFlags::SYN;
        packet0.tcp_data.seq = 111;
        packet0.tcp_data.ack = 0;
        flow_map.inject_meta_packet(&mut packet0);

        let mut packet1 = _new_meta_packet();
        packet1.tcp_data.flags = TcpFlags::SYN_ACK;
        packet1.lookup_key.timestamp += Duration::from_millis(10);
        _reverse_meta_packet(&mut packet1);
        packet1.tcp_data.seq = 1111;
        packet1.tcp_data.ack = 112;
        flow_map.inject_meta_packet(&mut packet1);

        let mut packet2 = _new_meta_packet();
        packet2.tcp_data.flags = TcpFlags::ACK;
        packet2.lookup_key.timestamp += 2 * Duration::from_millis(10);
        packet2.tcp_data.seq = 112;
        packet2.tcp_data.ack = 1112;
        let flush_timestamp = packet2.lookup_key.timestamp;
        flow_map.inject_meta_packet(&mut packet2);

        flow_map.inject_flush_ticker(flush_timestamp);
        flow_map.inject_flush_ticker(flush_timestamp + Duration::from_secs(10));

        if let Ok(tagged_flow) = output_queue_receiver.recv(Some(TIME_UNIT)) {
            assert_eq!(tagged_flow.flow.close_type, CloseType::ForcedReport);
        }
    }

    #[test]
    fn reverse_new_cycle() {
        let (mut flow_map, _) = _new_flow_map_and_receiver(TridentType::TtProcess, None, false);
        let npb_action = NpbAction::new(
            0,
            10,
            IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)),
            1,
            NpbTunnelType::VxLan,
            TapSide::SRC,
            DirectionType::ALL,
            123,
        );
        let mut policy_data0 = PolicyData::default();
        policy_data0.merge_npb_actions(&vec![npb_action], 10, DirectionType::FORWARD);
        let mut packet0 = _new_meta_packet();
        packet0.policy_data.replace(Arc::new(policy_data0));

        let npb_action = NpbAction::new(
            0,
            11,
            IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)),
            1,
            NpbTunnelType::VxLan,
            TapSide::SRC,
            DirectionType::ALL,
            123,
        );
        let mut policy_data1 = PolicyData::default();
        policy_data1.merge_npb_actions(&vec![npb_action], 11, DirectionType::FORWARD);
        let mut packet1 = _new_meta_packet();
        packet1.tcp_data.flags = TcpFlags::SYN_ACK;
        _reverse_meta_packet(&mut packet1);
        packet1.direction = PacketDirection::ServerToClient;
        packet1.policy_data.replace(Arc::new(policy_data1));

        let config = (&RuntimeConfig::default()).into();
        let mut node = flow_map.init_flow(&config, &mut packet0);
        node.policy_in_tick.fill(false);
        flow_map.update_flow(&mut node, &mut packet1);

        let tap_side = node.tagged_flow.tag.policy_data[0].npb_actions[0].tap_side();
        let acl_id = node.tagged_flow.tag.policy_data[1].acl_id;
        assert_eq!(tap_side, TapSide::SRC);
        assert_eq!(acl_id, 11);
    }

    #[test]
    fn force_report() {
        let (mut flow_map, output_queue_receiver) =
            _new_flow_map_and_receiver(TridentType::TtProcess, None, false);
        let mut packet0 = _new_meta_packet();
        flow_map.inject_meta_packet(&mut packet0);

        let mut packet1 = _new_meta_packet();
        packet1.tcp_data.flags = TcpFlags::SYN_ACK;
        packet1.lookup_key.timestamp += Duration::from_millis(10);
        _reverse_meta_packet(&mut packet1);
        flow_map.inject_meta_packet(&mut packet1);

        let mut packet2 = _new_meta_packet();
        packet2.tcp_data.flags = TcpFlags::ACK;
        packet2.lookup_key.timestamp += Duration::from_millis(10);
        let flush_timestamp = packet2.lookup_key.timestamp;
        flow_map.inject_meta_packet(&mut packet2);

        flow_map.inject_flush_ticker(flush_timestamp);
        flow_map.inject_flush_ticker(flush_timestamp + Duration::from_secs(10));

        if let Ok(tagged_flow) = output_queue_receiver.recv(Some(TIME_UNIT)) {
            assert_eq!(tagged_flow.flow.close_type, CloseType::ForcedReport);
            let total_flow = flow_map
                .node_map
                .as_ref()
                .map(|map| map.len())
                .unwrap_or_default();
            assert_eq!(total_flow, 1);
        }
    }

    #[test]
    fn udp_arp_short_flow() {
        let (mut flow_map, output_queue_receiver) =
            _new_flow_map_and_receiver(TridentType::TtProcess, None, false);
        let mut packet0 = _new_meta_packet();
        packet0.lookup_key.proto = IpProtocol::Udp;
        let flush_timestamp = packet0.lookup_key.timestamp;
        flow_map.inject_meta_packet(&mut packet0);

        flow_map.inject_flush_ticker(flush_timestamp);
        flow_map.inject_flush_ticker(flush_timestamp + Duration::from_secs(10));

        if let Ok(tagged_flow) = output_queue_receiver.recv(Some(TIME_UNIT)) {
            assert_eq!(tagged_flow.flow.close_type, CloseType::Timeout);
        }

        let mut packet1 = _new_meta_packet();
        packet1.lookup_key.eth_type = EthernetType::Arp;
        let flush_timestamp = packet1.lookup_key.timestamp;
        flow_map.inject_meta_packet(&mut packet1);

        flow_map.inject_flush_ticker(flush_timestamp);
        flow_map.inject_flush_ticker(flush_timestamp + Duration::from_secs(10));

        if let Ok(tagged_flow) = output_queue_receiver.recv(Some(TIME_UNIT)) {
            assert_eq!(tagged_flow.flow.close_type, CloseType::Timeout);
        }
    }

    #[test]
    fn port_equal_tor() {
        let (mut flow_map, output_queue_receiver) =
            _new_flow_map_and_receiver(TridentType::TtHyperVCompute, None, false);
        let mut packet0 = _new_meta_packet();
        packet0.lookup_key.tap_type = TapType::Cloud;
        flow_map.inject_meta_packet(&mut packet0);

        let mut packet1 = _new_meta_packet();
        packet1.lookup_key.tap_type = TapType::Cloud;
        packet1.tcp_data.flags = TcpFlags::RST;
        _reverse_meta_packet(&mut packet1);
        let flush_timestamp = packet1.lookup_key.timestamp;
        flow_map.inject_meta_packet(&mut packet1);

        flow_map.inject_flush_ticker(flush_timestamp);
        flow_map.inject_flush_ticker(flush_timestamp + Duration::from_secs(10));

        if let Ok(tagged_flow) = output_queue_receiver.recv(Some(TIME_UNIT)) {
            assert_eq!(
                tagged_flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_DST].packet_count,
                1
            );
        }

        let mut packet2 = _new_meta_packet();
        packet2.lookup_key.src_ip = Ipv4Addr::new(192, 168, 1, 2).into();
        packet2.lookup_key.tap_type = TapType::Cloud;
        packet2.tap_port = TapPort(0x1234);
        flow_map.inject_meta_packet(&mut packet2);

        let mut packet3 = _new_meta_packet();
        packet3.lookup_key.src_ip = Ipv4Addr::new(192, 168, 1, 3).into();
        packet3.lookup_key.dst_mac = MacAddr::from([0x21, 0x43, 0x65, 0xaa, 0xaa, 0xaa]);
        packet3.lookup_key.tap_type = TapType::Cloud;
        packet3.tap_port = TapPort(0x1234);
        packet3.lookup_key.l2_end_0 = true;
        packet3.lookup_key.l2_end_1 = false;
        packet3.tcp_data.flags = TcpFlags::RST;
        _reverse_meta_packet(&mut packet3);
        let flush_timestamp = packet3.lookup_key.timestamp;
        flow_map.inject_meta_packet(&mut packet3);

        flow_map.inject_flush_ticker(flush_timestamp);
        flow_map.inject_flush_ticker(flush_timestamp + Duration::from_secs(10));

        if let Ok(tagged_flow) = output_queue_receiver.recv(Some(TIME_UNIT)) {
            assert_eq!(
                tagged_flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_DST].packet_count,
                1
            );
        }
    }

    #[test]
    fn flow_state_machine() {
        let (mut flow_map, _) = _new_flow_map_and_receiver(TridentType::TtProcess, None, false);

        let config = (&RuntimeConfig::default()).into();

        let mut packet0 = _new_meta_packet();
        // test handshake
        let mut node = flow_map.init_flow(&config, &mut packet0);
        let peer_src = &mut node.tagged_flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC];
        peer_src.tcp_flags = TcpFlags::SYN;
        flow_map.update_flow_state_machine(
            &config,
            &mut node,
            TcpFlags::SYN_ACK,
            PacketDirection::ServerToClient,
        );
        assert_eq!(node.flow_state, FlowState::Opening2);
        node.flow_state = FlowState::Opening1;
        let peer_src = &mut node.tagged_flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC];
        peer_src.tcp_flags = TcpFlags::SYN;
        flow_map.update_flow_state_machine(
            &config,
            &mut node,
            TcpFlags::SYN_ACK,
            PacketDirection::ServerToClient,
        );
        assert_eq!(node.flow_state, FlowState::Opening2);
        flow_map.update_flow_state_machine(
            &config,
            &mut node,
            TcpFlags::ACK,
            PacketDirection::ClientToServer,
        );
        assert_eq!(node.flow_state, FlowState::Established);
        // test fin
        let peer_src = &mut node.tagged_flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC];
        peer_src.tcp_flags = TcpFlags::FIN;
        node.flow_state = FlowState::ClosingTx1;
        flow_map.update_flow_state_machine(
            &config,
            &mut node,
            TcpFlags::ACK,
            PacketDirection::ServerToClient,
        );
        assert_eq!(node.flow_state, FlowState::ClosingTx1);
        flow_map.update_flow_state_machine(
            &config,
            &mut node,
            TcpFlags::FIN_ACK,
            PacketDirection::ServerToClient,
        );
        assert_eq!(node.flow_state, FlowState::ClosingTx2);
        flow_map.update_flow_state_machine(
            &config,
            &mut node,
            TcpFlags::ACK,
            PacketDirection::ClientToServer,
        );
        assert_eq!(node.flow_state, FlowState::Closed);
    }

    #[test]
    fn double_fin_from_server() {
        let (mut flow_map, output_queue_receiver) =
            _new_flow_map_and_receiver(TridentType::TtProcess, None, false);
        // SYN
        let mut packet0 = _new_meta_packet();
        packet0.lookup_key.timestamp = Duration::from_nanos(
            (packet0.lookup_key.timestamp.as_nanos() / STATISTICAL_INTERVAL.as_nanos()
                * STATISTICAL_INTERVAL.as_nanos()) as u64,
        );
        let flush_timestamp = packet0.lookup_key.timestamp;
        flow_map.inject_meta_packet(&mut packet0);

        // SYN|ACK
        let mut packet1 = _new_meta_packet();
        packet1.lookup_key.timestamp = flush_timestamp;
        packet1.tcp_data.flags = TcpFlags::SYN_ACK;
        _reverse_meta_packet(&mut packet1);
        flow_map.inject_meta_packet(&mut packet1);

        // ACK
        let mut packet1 = _new_meta_packet();
        packet1.lookup_key.timestamp = flush_timestamp;
        packet1.tcp_data.flags = TcpFlags::ACK;
        flow_map.inject_meta_packet(&mut packet1);

        // FIN
        let mut packet1 = _new_meta_packet();
        packet1.lookup_key.timestamp = flush_timestamp;
        packet1.tcp_data.flags = TcpFlags::FIN;
        _reverse_meta_packet(&mut packet1);
        flow_map.inject_meta_packet(&mut packet1);
        // FIN
        let mut packet1 = _new_meta_packet();
        packet1.lookup_key.timestamp = flush_timestamp;
        packet1.tcp_data.flags = TcpFlags::FIN;
        _reverse_meta_packet(&mut packet1);
        flow_map.inject_meta_packet(&mut packet1);

        flow_map.inject_flush_ticker(flush_timestamp);
        flow_map.inject_flush_ticker(flush_timestamp + Duration::from_secs(10));

        if let Ok(tagged_flow) = output_queue_receiver.recv(Some(TIME_UNIT)) {
            assert_eq!(tagged_flow.flow.close_type, CloseType::ClientHalfClose);
        }
    }

    #[test]
    fn l3_l4_payload() {
        let (mut flow_map, output_queue_receiver) = _new_flow_map_and_receiver(
            TridentType::TtProcess,
            Some(FlowTimeout {
                opening: Duration::ZERO,
                established: Duration::from_secs(300),
                closing: Duration::ZERO,
                established_rst: Duration::from_secs(30),
                opening_rst: Duration::from_secs(1),
                exception: Duration::from_secs(5),
                closed_fin: Duration::ZERO,
                single_direction: Duration::from_millis(10),
                max: Duration::from_secs(300),
                min: Duration::ZERO,
            }),
            false,
        );

        let capture = Capture::load_pcap("resources/test/flow_generator/ip-fragment.pcap", None);
        let packets = capture.as_meta_packets();

        let dst_mac = packets[0].lookup_key.dst_mac;
        let timestamp = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap();
        for mut packet in packets {
            packet.lookup_key.timestamp = timestamp;
            packet.direction = if packet.lookup_key.dst_mac == dst_mac {
                PacketDirection::ClientToServer
            } else {
                PacketDirection::ServerToClient
            };
            flow_map.inject_meta_packet(&mut packet);
        }

        flow_map.inject_flush_ticker(timestamp.add(Duration::from_secs(2)));
        let flow_1 = output_queue_receiver.recv(Some(TIME_UNIT)).unwrap();

        flow_map.inject_flush_ticker(timestamp.add(Duration::from_secs(10)));
        let flow_2 = output_queue_receiver.recv(Some(TIME_UNIT)).unwrap();

        let l3_payload = flow_1.flow.flow_metrics_peers[0].l3_byte_count
            + flow_2.flow.flow_metrics_peers[0].l3_byte_count;
        let l4_payload = flow_1.flow.flow_metrics_peers[0].l4_byte_count
            + flow_2.flow.flow_metrics_peers[0].l4_byte_count;

        assert_eq!(l3_payload, 3008 * 6);
        assert_eq!(l4_payload, 3000 * 6);
    }

    #[test]
    fn ignore_vlan() {
        let (mut flow_map, output_queue_receiver) =
            _new_flow_map_and_receiver(TridentType::TtProcess, None, false);
        let mut packet_0 = _new_meta_packet();
        let mut packet_1 = _new_meta_packet();
        packet_1.vlan = 100;
        flow_map.inject_meta_packet(&mut packet_0);
        flow_map.inject_meta_packet(&mut packet_1);
        flow_map.inject_flush_ticker(packet_0.lookup_key.timestamp.add(Duration::from_secs(120)));
        let tagged_flow = output_queue_receiver.recv(Some(TIME_UNIT)).unwrap();
        assert_eq!(tagged_flow.flow.flow_metrics_peers[0].packet_count, 1);
        let tagged_flow = output_queue_receiver.recv(Some(TIME_UNIT)).unwrap();
        assert_eq!(tagged_flow.flow.flow_metrics_peers[0].packet_count, 1);

        let (mut flow_map, output_queue_receiver) =
            _new_flow_map_and_receiver(TridentType::TtProcess, None, true);
        let mut packet_0 = _new_meta_packet();
        let mut packet_1 = _new_meta_packet();
        packet_1.vlan = 100;
        flow_map.inject_meta_packet(&mut packet_0);
        flow_map.inject_meta_packet(&mut packet_1);
        flow_map.inject_flush_ticker(packet_0.lookup_key.timestamp.add(Duration::from_secs(120)));
        let tagged_flow = output_queue_receiver.recv(Some(TIME_UNIT)).unwrap();
        assert_eq!(tagged_flow.flow.flow_metrics_peers[0].packet_count, 2);
    }

    #[test]
    fn tcp_perf() {
        let (mut flow_map, output_queue_receiver) =
            _new_flow_map_and_receiver(TridentType::TtProcess, None, false);

        let capture = Capture::load_pcap("resources/test/flow_generator/http.pcap", None);
        let packets = capture.as_meta_packets();

        flow_map.reset_start_time(packets[0].lookup_key.timestamp);
        let dst_mac = packets[0].lookup_key.dst_mac;
        let timestamp = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap();
        for mut packet in packets {
            packet.direction = if packet.lookup_key.dst_mac == dst_mac {
                PacketDirection::ClientToServer
            } else {
                PacketDirection::ServerToClient
            };
            flow_map.inject_meta_packet(&mut packet);
        }

        flow_map.inject_flush_ticker(timestamp.add(Duration::from_secs(120)));

        let tagged_flow = output_queue_receiver.recv(Some(TIME_UNIT)).unwrap();
        let perf_stats = &tagged_flow.flow.flow_perf_stats.unwrap().tcp;
        assert_eq!(perf_stats.rtt_client_max, 114);
        assert_eq!(perf_stats.rtt_server_max, 44);
        assert_eq!(perf_stats.srt_max, 12);
    }

    #[test]
    fn tcp_syn_ack_zerowin() {
        let (mut flow_map, output_queue_receiver) =
            _new_flow_map_and_receiver(TridentType::TtProcess, None, false);

        let capture = Capture::load_pcap(
            "resources/test/flow_generator/tcp-syn-ack-zerowin.pcap",
            None,
        );
        let packets = capture.as_meta_packets();

        flow_map.reset_start_time(packets[0].lookup_key.timestamp);
        let timestamp = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap();
        for mut packet in packets {
            flow_map.inject_meta_packet(&mut packet);
        }

        flow_map.inject_flush_ticker(timestamp.add(Duration::from_secs(120)));

        let tagged_flow = output_queue_receiver.recv(Some(TIME_UNIT)).unwrap();
        let perf_stats = &tagged_flow.flow.flow_perf_stats.unwrap().tcp;
        assert_eq!(perf_stats.counts_peers[0].zero_win_count, 0);
        assert_eq!(perf_stats.counts_peers[1].zero_win_count, 1);
    }

    #[test]
    fn sort_nodes_by_timeout() {
        let mut nodes = vec![
            Box::new(FlowNode {
                timestamp_key: 120,
                ..Default::default()
            }),
            Box::new(FlowNode {
                timestamp_key: 60,
                recent_time: Duration::from_secs(40),
                ..Default::default()
            }),
            Box::new(FlowNode {
                timestamp_key: 60,
                recent_time: Duration::from_secs(10),
                ..Default::default()
            }),
            Box::new(FlowNode {
                timestamp_key: 60,
                recent_time: Duration::from_secs(60),
                ..Default::default()
            }),
            Box::new(FlowNode {
                timestamp_key: 180,
                ..Default::default()
            }),
            Box::new(FlowNode {
                timestamp_key: 60,
                recent_time: Duration::from_secs(60),
                ..Default::default()
            }),
            Box::new(FlowNode {
                timestamp_key: 120,
                ..Default::default()
            }),
            Box::new(FlowNode {
                timestamp_key: 60,
                recent_time: Duration::from_secs(20),
                ..Default::default()
            }),
            Box::new(FlowNode {
                timestamp_key: 60,
                recent_time: Duration::from_secs(60),
                ..Default::default()
            }),
        ];
        let index = FlowMap::sort_nodes_by_timeout(&mut nodes, Duration::from_secs(50), 70);
        assert_eq!(
            6,
            index,
            "{}\n{:?}",
            index,
            nodes
                .iter()
                .map(|n| (n.timestamp_key, n.recent_time))
                .collect::<Vec<_>>()
        );
    }
}
