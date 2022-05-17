use std::{
    cell::RefCell,
    collections::{BTreeSet, HashMap},
    mem,
    net::Ipv4Addr,
    rc::Rc,
    str::FromStr,
    sync::{atomic::Ordering, Arc},
    time::{Duration, SystemTime},
};

use arc_swap::{
    access::{Access, Map},
    ArcSwap,
};
use log::{debug, warn};

use super::{
    error::Error,
    flow_state::{StateMachine, StateValue},
    perf::{get_l7_protocol, FlowPerf, FlowPerfCounter, L7RrtCache},
    protocol_logs::MetaAppProto,
    service_table::{ServiceKey, ServiceTable},
    FlowMapKey, FlowNode, FlowState, COUNTER_FLOW_ID_MASK, FLOW_METRICS_PEER_DST,
    FLOW_METRICS_PEER_SRC, L7_PROTOCOL_UNKNOWN_LIMIT, L7_RRT_CACHE_CAPACITY, QUEUE_BATCH_SIZE,
    SERVICE_TABLE_IPV4_CAPACITY, SERVICE_TABLE_IPV6_CAPACITY, STATISTICAL_INTERVAL,
    THREAD_FLOW_ID_MASK, TIMER_FLOW_ID_MASK, TIME_MAX_INTERVAL, TIME_UNIT,
};
use crate::{
    common::{
        endpoint::{EndpointData, EndpointInfo, EPC_FROM_DEEPFLOW, EPC_FROM_INTERNET},
        enums::{EthernetType, HeaderType, IpProtocol, PacketDirection, TapType, TcpFlags},
        flow::{CloseType, Flow, FlowKey, FlowMetricsPeer, L4Protocol, L7Protocol, TunnelField},
        lookup_key::LookupKey,
        meta_packet::{MetaPacket, MetaPacketTcpHeader},
        policy::PolicyData,
        tagged_flow::TaggedFlow,
        tap_port::TapPort,
    },
    config::handler::{FlowAccess, FlowConfig, NewRuntimeConfig},
    debug::QueueDebugger,
    policy::{Policy, PolicyGetter},
    proto::common::TridentType,
    rpc::get_timestamp,
    utils::hasher::Jenkins64Hasher,
    utils::net::MacAddr,
    utils::queue::{self, DebugSender, Receiver},
};

// not thread-safe
pub struct FlowMap {
    node_map: Option<HashMap<Rc<FlowMapKey>, FlowNode, Jenkins64Hasher>>,
    time_set: Option<BTreeSet<Rc<FlowMapKey>>>,
    id: u32,
    state_machine_master: StateMachine,
    state_machine_slave: StateMachine,
    service_table: ServiceTable,
    policy_getter: PolicyGetter,
    start_time: Duration,    // 时间桶中的最早时间
    start_time_in_unit: u64, // 时间桶中的最早时间，以TIME_SLOT_UNIT为单位

    output_queue: DebugSender<TaggedFlow>,
    out_log_queue: DebugSender<MetaAppProto>,
    output_buffer: Vec<TaggedFlow>,
    last_queue_flush: Duration,
    config: FlowAccess,
    rrt_cache: Rc<RefCell<L7RrtCache>>,
    counter: Arc<FlowPerfCounter>,
}

impl FlowMap {
    pub fn new(
        id: u32,
        output_queue: DebugSender<TaggedFlow>,
        policy_getter: PolicyGetter,
        app_proto_log_queue: DebugSender<MetaAppProto>,
        config: FlowAccess,
    ) -> (Self, Arc<FlowPerfCounter>) {
        let counter = Arc::new(FlowPerfCounter::default());

        (
            Self {
                node_map: Some(HashMap::with_hasher(Jenkins64Hasher::default())),
                time_set: Some(BTreeSet::new()),
                id,
                state_machine_master: StateMachine::new_master(&config.load().flow_timeout),
                state_machine_slave: StateMachine::new_slave(&config.load().flow_timeout),
                service_table: ServiceTable::new(
                    SERVICE_TABLE_IPV4_CAPACITY,
                    SERVICE_TABLE_IPV6_CAPACITY,
                ),
                policy_getter,
                start_time: Duration::ZERO,
                start_time_in_unit: 0,
                output_queue,
                out_log_queue: app_proto_log_queue,
                output_buffer: vec![],
                last_queue_flush: Duration::ZERO,
                config,
                rrt_cache: Rc::new(RefCell::new(L7RrtCache::new(L7_RRT_CACHE_CAPACITY))),
                counter: counter.clone(),
            },
            counter,
        )
    }

    pub fn inject_flush_ticker(&mut self, mut timestamp: Duration) -> bool {
        if timestamp.is_zero() {
            timestamp = get_timestamp();
        } else if timestamp < self.start_time {
            return false;
        }

        // FlowMap 时间窗口无法推动
        if timestamp - self.config.load().packet_delay - TIME_UNIT < self.start_time {
            return true;
        }

        // 根据包到达时间的容差调整
        let next_start_time_in_unit = ((timestamp - self.config.load().packet_delay).as_nanos()
            / TIME_UNIT.as_nanos()) as u64;
        self.start_time =
            Duration::from_nanos(next_start_time_in_unit * TIME_UNIT.as_nanos() as u64);

        let (mut node_map, mut time_set) = match self.node_map.take().zip(self.time_set.take()) {
            Some(pair) => pair,
            None => {
                warn!("cannot get node map or time set");
                return false;
            }
        };

        let start_time_key = Rc::new(FlowMapKey {
            current_time_in_unit: self.start_time_in_unit,
            ..Default::default()
        });
        let next_time_key = Rc::new(FlowMapKey {
            current_time_in_unit: next_start_time_in_unit,
            ..Default::default()
        });
        let need_solve_keys = time_set
            .range(start_time_key..next_time_key)
            .map(|k| k.clone())
            .collect::<Vec<_>>();

        for time_key in need_solve_keys {
            let mut node = node_map.remove(&time_key).unwrap();
            let timeout = node.recent_time + node.timeout;
            if timestamp >= timeout {
                // 超时Flow将被删除然后把统计信息发送队列下游
                time_set.remove(&time_key);
                self.node_removed_aftercare(node, timeout, None);
                continue;
            }
            // 未超时Flow的统计信息发送到队列下游
            self.node_updated_aftercare(&mut node, timeout, None);
            // 若流统计信息已输出，将节点移动至最终超时的时间
            let updated_time_in_unit = if timeout > timestamp + TIME_MAX_INTERVAL {
                ((timestamp + TIME_MAX_INTERVAL).as_nanos() / TIME_UNIT.as_nanos()) as u64
            } else {
                (timeout.as_nanos() / TIME_UNIT.as_nanos()) as u64
            };
            time_set.remove(&time_key);
            let mut new_key = Rc::try_unwrap(time_key).unwrap();
            new_key.current_time_in_unit = updated_time_in_unit;
            let rc_new_key = Rc::new(new_key);
            time_set.insert(rc_new_key.clone());
            node_map.insert(rc_new_key, node);
        }

        self.node_map.replace(node_map);
        self.time_set.replace(time_set);

        self.start_time_in_unit = next_start_time_in_unit;
        self.flush_queue(timestamp);

        true
    }

    pub fn inject_meta_packet(&mut self, mut meta_packet: MetaPacket) {
        if !self.inject_flush_ticker(meta_packet.lookup_key.timestamp) {
            // 补充由于超时导致未查询策略，用于其它流程（如PCAP存储）
            (self.policy_getter).lookup(&mut meta_packet, self.id as usize);
            return;
        }

        let config_ignore = (
            self.config.load().ignore_l2_end,
            self.config.load().ignore_tor_mac,
        );
        let time_in_unit =
            (meta_packet.lookup_key.timestamp.as_nanos() / TIME_UNIT.as_nanos()) as u64;
        let pkt_key = Rc::new(FlowMapKey::new(
            time_in_unit,
            &meta_packet,
            config_ignore,
            self.config.load().trident_type,
        ));

        let (mut node_map, mut time_set) = match self.node_map.take().zip(self.time_set.take()) {
            Some(pair) => pair,
            None => {
                warn!("cannot get node map or time set");
                return;
            }
        };
        let total_flow = node_map.len();

        match node_map.remove_entry(&pkt_key) {
            // 找到Flow,更新
            Some((key, mut node)) => {
                let pkt_timestamp = meta_packet.lookup_key.timestamp;

                // 1. 输出上一个统计周期的统计信息
                self.node_updated_aftercare(&mut node, pkt_timestamp, Some(&mut meta_packet));

                // 2. 更新Flow状态，判断是否已结束
                match meta_packet.lookup_key.proto {
                    IpProtocol::Tcp => {
                        self.update_tcp_node(node, meta_packet, key, &mut time_set, &mut node_map)
                    }
                    IpProtocol::Udp => self.update_udp_node(node, meta_packet, key, &mut node_map),

                    _ => self.update_other_node(node, meta_packet, key, &mut node_map),
                };
            }
            // 未找到Flow，需要插入新的节点
            None => {
                let node = self.new_flow_node(meta_packet, total_flow);
                time_set.insert(pkt_key.clone());
                node_map.insert(pkt_key, node);
            }
        }

        self.node_map.replace(node_map);
        self.time_set.replace(time_set);
        // go实现只有插入node的时候，插入的节点数目大于ring buffer 的capacity 返回false,
        // rust 版本用了std的hashmap自动处理扩容,也就没有返回false, 然后执行policy_getter
    }

    fn update_tcp_node(
        &mut self,
        mut node: FlowNode,
        mut meta_packet: MetaPacket,
        pkt_key: Rc<FlowMapKey>,
        time_set: &mut BTreeSet<Rc<FlowMapKey>>,
        node_map: &mut HashMap<Rc<FlowMapKey>, FlowNode, Jenkins64Hasher>,
    ) {
        let lookup_key = &meta_packet.lookup_key;
        let node_flow_key = &node.tagged_flow.flow.flow_key;
        let timestamp = lookup_key.timestamp;
        // update flow meta_packet direction for flow
        if lookup_key.src_ip == node_flow_key.ip_src
            && lookup_key.dst_ip == node_flow_key.ip_dst
            && lookup_key.src_port == node_flow_key.port_src
            && lookup_key.dst_port == node_flow_key.port_dst
        {
            meta_packet.direction = PacketDirection::ClientToServer;
        } else if lookup_key.src_ip == node_flow_key.ip_dst
            && lookup_key.dst_ip == node_flow_key.ip_src
            && lookup_key.src_port == node_flow_key.port_dst
            && lookup_key.dst_port == node_flow_key.port_src
        {
            meta_packet.direction = PacketDirection::ServerToClient;
        }

        let flow_closed = self.update_tcp_flow(&mut meta_packet, &mut node);
        if self.config.load().collector_enabled {
            let direction = node.tagged_flow.flow.reversed
                == (meta_packet.direction == PacketDirection::ServerToClient);
            self.collect_metric(&mut node, &meta_packet, direction);
        }
        if flow_closed {
            time_set.remove(&pkt_key);
            self.node_removed_aftercare(node, timestamp, Some(&mut meta_packet));
        } else {
            node_map.insert(pkt_key, node);
        }
    }

    fn update_udp_node(
        &mut self,
        mut node: FlowNode,
        mut meta_packet: MetaPacket,
        pkt_key: Rc<FlowMapKey>,
        node_map: &mut HashMap<Rc<FlowMapKey>, FlowNode, Jenkins64Hasher>,
    ) {
        let lookup_key = &meta_packet.lookup_key;
        let node_flow_key = &node.tagged_flow.flow.flow_key;

        // update flow meta_packet direction for flow
        if lookup_key.src_ip == node_flow_key.ip_src
            && lookup_key.dst_ip == node_flow_key.ip_dst
            && lookup_key.src_port == node_flow_key.port_src
            && lookup_key.dst_port == node_flow_key.port_dst
        {
            meta_packet.direction = PacketDirection::ClientToServer;
        } else if lookup_key.src_ip == node_flow_key.ip_dst
            && lookup_key.dst_ip == node_flow_key.ip_src
            && lookup_key.src_port == node_flow_key.port_dst
            && lookup_key.dst_port == node_flow_key.port_src
        {
            meta_packet.direction = PacketDirection::ServerToClient;
        }
        self.update_flow(&mut node, &mut meta_packet);
        let peers = &node.tagged_flow.flow.flow_metrics_peers;
        if peers[FLOW_METRICS_PEER_SRC].packet_count > 0
            && peers[FLOW_METRICS_PEER_DST].packet_count > 0
        {
            node.timeout = self.config.load().flow_timeout.closing;
        }
        meta_packet.is_active_service = node.tagged_flow.flow.is_active_service;
        if self.config.load().collector_enabled {
            self.collect_metric(&mut node, &meta_packet, false);
        }

        node_map.insert(pkt_key, node);
    }

    fn update_other_node(
        &mut self,
        mut node: FlowNode,
        mut meta_packet: MetaPacket,
        pkt_key: Rc<FlowMapKey>,
        node_map: &mut HashMap<Rc<FlowMapKey>, FlowNode, Jenkins64Hasher>,
    ) {
        let lookup_key = &meta_packet.lookup_key;
        let node_flow_key = &node.tagged_flow.flow.flow_key;
        // update flow meta_packet direction for flow
        if lookup_key.src_mac.eq(&node_flow_key.mac_src)
            && lookup_key.dst_mac.eq(&node_flow_key.mac_dst)
            && lookup_key.src_ip.eq(&node_flow_key.ip_src)
            && lookup_key.dst_ip.eq(&node_flow_key.ip_dst)
        {
            meta_packet.direction = PacketDirection::ClientToServer;
        } else if lookup_key.src_mac.eq(&node_flow_key.mac_dst)
            && lookup_key.dst_mac.eq(&node_flow_key.mac_src)
            && lookup_key.src_ip.eq(&node_flow_key.ip_dst)
            && lookup_key.dst_ip.eq(&node_flow_key.ip_src)
        {
            meta_packet.direction = PacketDirection::ServerToClient;
        }

        self.update_flow(&mut node, &mut meta_packet);
        let peers = &node.tagged_flow.flow.flow_metrics_peers;
        if peers[FLOW_METRICS_PEER_SRC].packet_count > 0
            && peers[FLOW_METRICS_PEER_DST].packet_count > 0
        {
            node.timeout = self.config.load().flow_timeout.established_rst;
        }

        node_map.insert(pkt_key, node);
    }

    fn generate_flow_id(timestamp: Duration, thread_id: u32, total_flow: usize) -> u64 {
        (timestamp.as_nanos() as u64 >> 30 & TIMER_FLOW_ID_MASK) << 32
            | thread_id as u64 & THREAD_FLOW_ID_MASK << 24
            | total_flow as u64 & COUNTER_FLOW_ID_MASK
    }

    fn update_tcp_flow(&mut self, meta_packet: &mut MetaPacket, node: &mut FlowNode) -> bool {
        let direction = meta_packet.direction;
        let pkt_tcp_flags = meta_packet.tcp_data.flags;
        node.tagged_flow.flow.flow_metrics_peers[direction as usize].tcp_flags |= pkt_tcp_flags;
        self.update_flow(node, meta_packet);

        // 有特殊包时更新ServiceTable并矫正流方向：SYN+ACK或SYN
        if pkt_tcp_flags.bits() & TcpFlags::SYN.bits() != 0 {
            self.update_l4_direction(meta_packet, node, false);
            self.update_syn_or_syn_ack_seq(node, meta_packet);
        }

        self.update_tcp_keepalive_seq(node, meta_packet);
        meta_packet.is_active_service = node.tagged_flow.flow.is_active_service;

        if pkt_tcp_flags.is_invalid() {
            // exception timeout
            node.timeout = self.config.load().flow_timeout.exception;
            node.flow_state = FlowState::Exception;
            return false;
        }

        self.update_flow_state_machine(node, pkt_tcp_flags, direction)
    }

    // 协议参考：https://datatracker.ietf.org/doc/html/rfc1122#section-4.2.3.6
    // TCP Keepalive报文特征：
    //		1.payloadLen为0/1
    //		2.非FIN、SYN、RST
    //		3.TCP保活探测报文序列号(Seq)为前一个TCP报文序列号(Seq)减一
    fn update_tcp_keepalive_seq(&mut self, node: &mut FlowNode, meta_packet: &mut MetaPacket) {
        // 保存TCP Seq用于TCP Keepalive报文判断
        let (next_tcp_seq0, next_tcp_seq1) = (node.next_tcp_seq0, node.next_tcp_seq1);

        // 记录下一次TCP Seq
        match meta_packet.direction {
            PacketDirection::ClientToServer => node.next_tcp_seq1 = meta_packet.tcp_data.ack,
            PacketDirection::ServerToClient => node.next_tcp_seq0 = meta_packet.tcp_data.ack,
        }
        // TCP Keepalive报文判断，并记录其TCP Seq
        let payload_len = meta_packet.payload_len;
        if payload_len > 1 {
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
        } else if tcp_flag == TcpFlags::SYN_ACK && meta_packet.packet_len == 0 {
            flow.synack_seq = meta_packet.tcp_data.seq;
        }
    }

    //flow_state.rs 有个state_machine的测试用到该方法, 要用super
    pub(super) fn update_flow_state_machine(
        &mut self,
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
                self.config.load().flow_timeout.exception,
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
            node.timeout = self.config.load().flow_timeout.single_direction;
        } else {
            node.timeout = timeout;
        }

        closed
    }

    fn l7_metrics_enabled(&self) -> bool {
        let guard = self.config.load();
        guard.l7_metrics_enabled || guard.app_proto_log_enabled
    }

    fn l4_metrics_enabled(&self) -> bool {
        self.config.load().l4_performance_enabled
    }

    fn init_flow(&mut self, meta_packet: &mut MetaPacket, total_flow: usize) -> FlowNode {
        meta_packet.direction = PacketDirection::ClientToServer;

        let mut tagged_flow = TaggedFlow::default();
        let lookup_key = &meta_packet.lookup_key;
        let flow = Flow {
            flow_key: FlowKey {
                vtap_id: self.config.load().vtap_id,
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
            flow_id: Self::generate_flow_id(lookup_key.timestamp, self.id, total_flow),
            start_time: lookup_key.timestamp,
            flow_stat_time: Duration::from_nanos(
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
                    first: lookup_key.timestamp,
                    last: lookup_key.timestamp,
                    tcp_flags: meta_packet.tcp_data.flags,
                    ..Default::default()
                },
                FlowMetricsPeer::default(),
            ],
            ..Default::default()
        };
        tagged_flow.flow = flow;

        // FlowMap信息
        let mut policy_in_tick = [false; 2];
        policy_in_tick[meta_packet.direction as usize] = true;

        let mut node = FlowNode {
            tagged_flow,
            min_arrived_time: lookup_key.timestamp,
            recent_time: lookup_key.timestamp,
            timeout: Duration::ZERO,
            packet_in_tick: true,
            policy_in_tick,
            flow_state: FlowState::Raw,
            meta_flow_perf: if self.config.load().collector_enabled {
                FlowPerf::new(
                    self.rrt_cache.clone(),
                    L4Protocol::from(lookup_key.proto),
                    get_l7_protocol(
                        lookup_key.src_port,
                        lookup_key.dst_port,
                        self.l7_metrics_enabled(),
                    ),
                    self.counter.clone(),
                )
            } else {
                None
            },
            next_tcp_seq0: 0,
            next_tcp_seq1: 0,
            policy_data_cache: Default::default(),
            endpoint_data_cache: EndpointData {
                src_info: EndpointInfo {
                    real_ip: Ipv4Addr::UNSPECIFIED.into(),
                    l2_epc_id: 0,
                    l3_epc_id: 0,
                    l2_end: false,
                    l3_end: false,
                    is_device: false,
                    is_vip_interface: false,
                    is_vip: false,
                    is_local_mac: false,
                    is_local_ip: false,
                },

                dst_info: EndpointInfo {
                    real_ip: Ipv4Addr::UNSPECIFIED.into(),
                    l2_epc_id: 0,
                    l3_epc_id: 0,
                    l2_end: false,
                    l3_end: false,
                    is_device: false,
                    is_vip_interface: false,
                    is_vip: false,
                    is_local_mac: false,
                    is_local_ip: false,
                },
            },
        };
        // 标签
        (self.policy_getter).lookup(meta_packet, self.id as usize);
        self.update_endpoint_and_policy_data(&mut node, meta_packet);
        node
    }

    fn update_flow(&mut self, node: &mut FlowNode, meta_packet: &mut MetaPacket) {
        let pkt_timestamp = meta_packet.lookup_key.timestamp;
        let flow = &mut node.tagged_flow.flow;
        if pkt_timestamp > node.recent_time {
            node.recent_time = pkt_timestamp;
            flow.duration = node.recent_time - node.min_arrived_time
            // Duration仅使用包的时间计算，不包括超时时间
        }

        if !node.packet_in_tick {
            // FlowStatTime取整至统计时间的开始，只需要赋值一次，且使用包的时间戳
            node.packet_in_tick = true;
            flow.flow_stat_time = Duration::from_nanos(
                (pkt_timestamp.as_nanos() / STATISTICAL_INTERVAL.as_nanos()
                    * STATISTICAL_INTERVAL.as_nanos()) as u64,
            );
        }

        if !node.policy_in_tick[meta_packet.direction as usize] {
            node.policy_in_tick[meta_packet.direction as usize] = true;
            (self.policy_getter).lookup(meta_packet, self.id as usize);
            self.update_endpoint_and_policy_data(node, meta_packet);
        } else {
            // copy endpoint and policy data
            meta_packet.policy_data.replace(Arc::new(
                node.policy_data_cache[meta_packet.direction as usize].clone(),
            ));
            match meta_packet.direction {
                PacketDirection::ClientToServer => {
                    meta_packet
                        .endpoint_data
                        .replace(Arc::new(node.endpoint_data_cache.clone()));
                }
                PacketDirection::ServerToClient => {
                    meta_packet
                        .endpoint_data
                        .replace(Arc::new(node.endpoint_data_cache.reversed()));
                }
            }
            if let Some(endpoint_data) = meta_packet.endpoint_data.as_ref() {
                meta_packet.lookup_key.l3_end_0 = endpoint_data.src_info.l3_end;
                meta_packet.lookup_key.l3_end_1 = endpoint_data.dst_info.l3_end;
            }
        }

        let flow = &mut node.tagged_flow.flow;
        let flow_metrics_peer = &mut flow.flow_metrics_peers[meta_packet.direction as usize];
        flow_metrics_peer.packet_count += 1;
        flow_metrics_peer.total_packet_count += 1;
        flow_metrics_peer.byte_count += meta_packet.packet_len as u64;
        flow_metrics_peer.l3_byte_count += meta_packet.l3_payload_len() as u64;
        flow_metrics_peer.l4_byte_count += meta_packet.l4_payload_len() as u64;
        flow_metrics_peer.total_byte_count += meta_packet.packet_len as u64;
        flow_metrics_peer.last = pkt_timestamp;
        if flow_metrics_peer.first.is_zero() {
            flow_metrics_peer.first = pkt_timestamp;
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
            (self.policy_getter).lookup(meta_packet, self.id as usize);
        }
    }

    fn new_tcp_node(&mut self, mut meta_packet: MetaPacket, total_flow: usize) -> FlowNode {
        let mut node = self.init_flow(&mut meta_packet, total_flow);
        self.update_l4_direction(&mut meta_packet, &mut node, true);
        meta_packet.is_active_service = node.tagged_flow.flow.is_active_service;

        let pkt_tcp_flags = meta_packet.tcp_data.flags;
        if pkt_tcp_flags.is_invalid() {
            // exception timeout
            node.timeout = self.config.load().flow_timeout.exception;
            node.flow_state = FlowState::Exception;
        }
        self.update_flow_state_machine(&mut node, pkt_tcp_flags, meta_packet.direction);
        self.update_syn_or_syn_ack_seq(&mut node, &mut meta_packet);

        if self.config.load().collector_enabled {
            let direction = node.tagged_flow.flow.reversed
                == (meta_packet.direction == PacketDirection::ServerToClient);
            self.collect_metric(&mut node, &meta_packet, direction);
        }
        node
    }

    fn collect_metric(
        &mut self,
        node: &mut FlowNode,
        meta_packet: &MetaPacket,
        is_first_packet_direction: bool,
    ) {
        if let Some(perf) = node.meta_flow_perf.as_mut() {
            let flow_id = node.tagged_flow.flow.flow_id;
            match perf.parse(
                &meta_packet,
                is_first_packet_direction,
                flow_id,
                self.l4_metrics_enabled(),
                self.l7_metrics_enabled(),
            ) {
                Err(Error::L7ReqNotFound(c)) => {
                    self.counter
                        .mismatched_response
                        .fetch_add(c, Ordering::Relaxed);
                }
                Err(e) => debug!("{}", e),
                _ => (),
            }
        }
        if self.config.load().app_proto_log_enabled && meta_packet.packet_len > 0 {
            self.write_to_app_proto_log(
                node,
                &meta_packet,
                self.config.load().l7_log_packet_size as u16,
            );
        }
    }

    fn new_udp_node(&mut self, mut meta_packet: MetaPacket, total_flow: usize) -> FlowNode {
        let mut node = self.init_flow(&mut meta_packet, total_flow);
        node.flow_state = FlowState::Established;
        // opening timeout
        node.timeout = self.config.load().flow_timeout.opening;
        self.update_l4_direction(&mut meta_packet, &mut node, true);
        meta_packet.is_active_service = node.tagged_flow.flow.is_active_service;
        if self.config.load().collector_enabled {
            self.collect_metric(&mut node, &meta_packet, false);
        }
        node
    }

    fn new_other_node(&mut self, mut meta_packet: MetaPacket, total_flow: usize) -> FlowNode {
        let mut node = self.init_flow(&mut meta_packet, total_flow);
        node.flow_state = FlowState::Established;
        // opening timeout
        node.timeout = self.config.load().flow_timeout.opening;
        node
    }

    fn new_flow_node(&mut self, meta_packet: MetaPacket, total_flow: usize) -> FlowNode {
        match meta_packet.lookup_key.proto {
            IpProtocol::Tcp => self.new_tcp_node(meta_packet, total_flow),
            IpProtocol::Udp => self.new_udp_node(meta_packet, total_flow),
            _ => self.new_other_node(meta_packet, total_flow),
        }
    }

    fn flush_queue(&mut self, now: Duration) {
        if now - self.last_queue_flush > self.config.load().flush_interval {
            if self.output_buffer.len() > 0 {
                let flows = self.output_buffer.drain(..).collect::<Vec<_>>();
                if let Err(_) = self.output_queue.send_all(flows) {
                    warn!(
                        "flow-map push tagged flows to queue failed because queue have terminated"
                    );
                }
            }
            self.last_queue_flush = now;
        }
    }

    fn push_to_flow_stats_queue(&mut self, mut tagged_flow: TaggedFlow) {
        // 流在未结束时应用日志会需要这个字段，为了避免重复计算，所以在流统计完成输出时赋值
        //
        // 目前仅虚拟流量会计算该统计位置
        tagged_flow.flow.set_tap_side(
            self.config.load().trident_type,
            self.config.load().cloud_gateway_traffic,
        );

        // 未知应用仅统计指标量数据，并且判断条件需要考虑流持续时间等，所以在流统计完成输出时赋值
        //
        // 满足如下全部条件才会统计未知应用协议指标量：
        // 1. TCP协议
        // 2. 开启4层性能统计
        // 3. 开启7层性能统计
        // 4. 应用协议未能识别
        // 5. 流结束或流持续60秒以上

        let flow = &mut tagged_flow.flow;
        if flow.flow_key.proto == IpProtocol::Tcp
            && flow.flow_perf_stats.is_some()
            && self.l7_metrics_enabled()
        {
            let stats = flow.flow_perf_stats.as_mut().unwrap();
            if stats.l7_protocol == L7Protocol::Unknown
                && (flow.close_type != CloseType::ForcedReport
                    || flow.duration >= L7_PROTOCOL_UNKNOWN_LIMIT)
            {
                stats.l7_protocol = L7Protocol::Other;
            }
        }
        self.output_buffer.push(tagged_flow);
        if self.output_buffer.len() >= QUEUE_BATCH_SIZE {
            let flows = self.output_buffer.drain(..).collect::<Vec<_>>();
            if let Err(_) = self.output_queue.send_all(flows) {
                warn!("flow-map push tagged flows to queue failed because queue have terminated");
            }
        }
    }

    // go 版本的removeAndOutput
    fn node_removed_aftercare(
        &mut self,
        mut node: FlowNode,
        timeout: Duration,
        meta_packet: Option<&mut MetaPacket>,
    ) {
        // 统计数据输出前矫正流方向
        self.update_flow_direction(&mut node, meta_packet);

        let flow = &mut node.tagged_flow.flow;
        flow.update_close_type(node.flow_state);
        flow.end_time = timeout;
        flow.flow_stat_time = Duration::from_nanos(
            (timeout.as_nanos() / STATISTICAL_INTERVAL.as_nanos() * STATISTICAL_INTERVAL.as_nanos())
                as u64,
        );

        if self.config.load().collector_enabled
            && (flow.flow_key.proto == IpProtocol::Tcp || flow.flow_key.proto == IpProtocol::Udp)
        {
            let l7_timeout_count = self
                .rrt_cache
                .borrow_mut()
                .get_and_remove_l7_req_timeout(flow.flow_id);
            // 如果返回None，就清空掉flow_perf_stats
            flow.flow_perf_stats = node.meta_flow_perf.as_mut().and_then(|perf| {
                perf.copy_and_reset_perf_data(
                    flow.reversed,
                    l7_timeout_count as u32,
                    self.l4_metrics_enabled(),
                    self.l7_metrics_enabled(),
                )
            });
        }

        self.push_to_flow_stats_queue(node.tagged_flow);
    }

    // go 版本的copyAndOutput
    fn node_updated_aftercare(
        &mut self,
        node: &mut FlowNode,
        timeout: Duration,
        meta_packet: Option<&mut MetaPacket>,
    ) {
        let flow = &node.tagged_flow.flow;
        if node.packet_in_tick
            && (timeout >= flow.flow_stat_time + STATISTICAL_INTERVAL
                || timeout < flow.flow_stat_time)
        {
            self.update_flow_direction(node, meta_packet); // 每个流统计数据输出前矫正流方向
            node.tagged_flow.flow.close_type = CloseType::ForcedReport;
            let flow = &mut node.tagged_flow.flow;
            if !self.config.load().collector_enabled {
                return;
            }
            if flow.flow_key.proto == IpProtocol::Tcp || flow.flow_key.proto == IpProtocol::Udp {
                flow.flow_perf_stats = node.meta_flow_perf.as_mut().and_then(|perf| {
                    perf.copy_and_reset_perf_data(
                        flow.reversed,
                        0,
                        self.l4_metrics_enabled(),
                        self.l7_metrics_enabled(),
                    )
                });
            }
            self.push_to_flow_stats_queue(node.tagged_flow.clone());
            node.reset_flow_stat_info();
        }
    }

    fn write_to_app_proto_log(
        &mut self,
        node: &mut FlowNode,
        meta_packet: &MetaPacket,
        pkt_size: u16,
    ) {
        let lookup_key = &meta_packet.lookup_key; //  trisolaris接口定义: 0(TAP_ANY)表示所有都需要
        if !self.config.load().l7_log_tap_types[u16::from(TapType::Any) as usize]
            && (lookup_key.tap_type > TapType::Max
                || !self.config.load().l7_log_tap_types[u16::from(lookup_key.tap_type) as usize])
        {
            return;
        }

        if lookup_key.proto != IpProtocol::Tcp && lookup_key.proto != IpProtocol::Udp {
            return;
        }
        // 考虑性能，最好是l7 perf解析后，满足需要的包生成log
        let (head, offset) = match node
            .meta_flow_perf
            .as_mut()
            .and_then(|perf| perf.app_proto_head(self.l7_metrics_enabled()))
        {
            Some(v) => v,
            None => return,
        };

        node.tagged_flow.flow.set_tap_side(
            self.config.load().trident_type,
            self.config.load().cloud_gateway_traffic,
        );

        if let Some(app_proto) =
            MetaAppProto::new(&node.tagged_flow, meta_packet, head, offset, pkt_size)
        {
            if let Err(_) = self.out_log_queue.send(app_proto) {
                warn!("flow-map push MetaAppProto to queue failed because queue have terminated");
            }
        }
    }

    fn update_l4_direction(
        &mut self,
        meta_packet: &mut MetaPacket,
        node: &mut FlowNode,
        is_first_packet: bool,
    ) {
        let lookup_key = &meta_packet.lookup_key;
        let src_key = ServiceKey::new(
            lookup_key.src_ip,
            node.endpoint_data_cache.src_info.l3_epc_id as i16,
            lookup_key.src_port,
        );
        let dst_key = ServiceKey::new(
            lookup_key.dst_ip,
            node.endpoint_data_cache.dst_info.l3_epc_id as i16,
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

        if let PacketDirection::ServerToClient = meta_packet.direction {
            mem::swap(&mut src_score, &mut dst_score);
        }

        if !ServiceTable::is_client_to_server(src_score, dst_score) {
            mem::swap(&mut src_score, &mut dst_score);

            Self::reverse_flow(node);
            meta_packet.direction = meta_packet.direction.reversed();
        }

        node.tagged_flow.flow.is_active_service = ServiceTable::is_active_service(dst_score);
    }

    fn update_flow_direction(&mut self, node: &mut FlowNode, meta_packet: Option<&mut MetaPacket>) {
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
            Self::reverse_flow(node);
            if let Some(pkt) = meta_packet {
                pkt.direction = pkt.direction.reversed();
            }
        }

        node.tagged_flow.flow.is_active_service = ServiceTable::is_active_service(dst_score);
    }

    fn reverse_flow(node: &mut FlowNode) {
        node.policy_in_tick.swap(0, 1);
        node.policy_data_cache.swap(0, 1);
        node.endpoint_data_cache = node.endpoint_data_cache.reversed();
        node.tagged_flow.flow.reverse();
        node.tagged_flow.tag.reverse();
    }

    fn update_endpoint_and_policy_data(
        &mut self,
        node: &mut FlowNode,
        meta_packet: &mut MetaPacket,
    ) {
        // update endpoint
        match meta_packet.direction {
            PacketDirection::ClientToServer => {
                if meta_packet.endpoint_data.is_some() {
                    node.endpoint_data_cache = **(meta_packet.endpoint_data.as_ref().unwrap());
                }
            }
            PacketDirection::ServerToClient => {
                if let Some(endpoint_data) =
                    meta_packet.endpoint_data.as_ref().map(|e| e.reversed())
                {
                    node.endpoint_data_cache = endpoint_data;
                }
            }
        }

        {
            let src_info = node.endpoint_data_cache.src_info;
            let peer_src = &mut node.tagged_flow.flow.flow_metrics_peers[0];
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
            let dst_info = node.endpoint_data_cache.dst_info;
            let peer_dst = &mut node.tagged_flow.flow.flow_metrics_peers[1];
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

        // update policy data
        if meta_packet.policy_data.is_some() {
            node.policy_data_cache[meta_packet.direction as usize] = PolicyData {
                acl_id: meta_packet.policy_data.as_ref().unwrap().acl_id,
                npb_actions: meta_packet
                    .policy_data
                    .as_ref()
                    .unwrap()
                    .npb_actions
                    .clone(),
                action_flags: meta_packet.policy_data.as_ref().unwrap().action_flags,
            };
        }
        node.tagged_flow.tag.policy_data = node.policy_data_cache.clone();
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

pub fn _new_flow_map_and_receiver() -> (FlowMap, Receiver<TaggedFlow>) {
    let (_, mut policy_getter) = Policy::new(1, 0, 1 << 10, false);
    policy_getter.disable();
    let queue_debugger = QueueDebugger::new();
    let (output_queue_sender, output_queue_receiver, _) =
        queue::bounded_with_debug(256, "", &queue_debugger);
    let (app_proto_log_queue, _, _) = queue::bounded_with_debug(256, "", &queue_debugger);
    let mut config = NewRuntimeConfig::default();
    // Any
    config.flow.l7_log_tap_types[0] = true;
    config.flow.trident_type = TridentType::TtProcess;
    let current_config = Arc::new(ArcSwap::from_pointee(config));
    let (flow_map, _counter) = FlowMap::new(
        0,
        output_queue_sender,
        policy_getter,
        app_proto_log_queue,
        Map::new(current_config.clone(), |config| -> &FlowConfig {
            &config.flow
        }),
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
        tap_type: TapType::Isp(1),
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

    use crate::{
        common::{
            enums::EthernetType,
            flow::CloseType,
            policy::{NpbAction, NpbTunnelType, PolicyData, TapSide},
            tap_port::TapPort,
        },
        utils::net::MacAddr,
    };

    use super::*;

    const DEFAULT_DURATION: Duration = Duration::from_millis(10);

    #[test]
    fn syn_rst() {
        let (mut flow_map, output_queue_receiver) = _new_flow_map_and_receiver();
        let packet0 = _new_meta_packet();
        flow_map.inject_meta_packet(packet0);
        let mut packet1 = _new_meta_packet();
        packet1.tcp_data.flags = TcpFlags::RST;
        _reverse_meta_packet(&mut packet1);
        packet1.lookup_key.timestamp += DEFAULT_DURATION;
        let flush_timestamp = packet1.lookup_key.timestamp;
        flow_map.inject_meta_packet(packet1);

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
        let (mut flow_map, output_queue_receiver) = _new_flow_map_and_receiver();
        let packet0 = _new_meta_packet();
        flow_map.inject_meta_packet(packet0);

        let mut packet1 = _new_meta_packet();
        packet1.tcp_data.flags = TcpFlags::PSH_ACK;
        flow_map.inject_meta_packet(packet1);

        let mut packet2 = _new_meta_packet();
        packet2.tcp_data.flags = TcpFlags::FIN_ACK;
        packet2.lookup_key.timestamp += Duration::from_millis(10);
        _reverse_meta_packet(&mut packet2);
        let flush_timestamp = packet2.lookup_key.timestamp;
        flow_map.inject_meta_packet(packet2);

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
        let (mut flow_map, output_queue_receiver) = _new_flow_map_and_receiver();
        let mut packet1 = _new_meta_packet();
        packet1.tcp_data.seq = 1111;
        packet1.tcp_data.ack = 112;
        packet1.lookup_key.timestamp = Duration::from_nanos(
            (packet1.lookup_key.timestamp.as_nanos() / TIME_UNIT.as_nanos() * TIME_UNIT.as_nanos())
                as u64,
        );
        let flush_timestamp = packet1.lookup_key.timestamp;
        flow_map.inject_meta_packet(packet1);

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
        let (mut flow_map, output_queue_receiver) = _new_flow_map_and_receiver();
        let mut packet0 = _new_meta_packet();
        packet0.tcp_data.flags = TcpFlags::SYN;
        packet0.tcp_data.seq = 111;
        packet0.tcp_data.ack = 0;
        flow_map.inject_meta_packet(packet0);

        let mut packet1 = _new_meta_packet();
        packet1.tcp_data.flags = TcpFlags::SYN_ACK;
        packet1.lookup_key.timestamp += Duration::from_millis(10);
        _reverse_meta_packet(&mut packet1);
        packet1.tcp_data.seq = 1111;
        packet1.tcp_data.ack = 112;
        flow_map.inject_meta_packet(packet1);

        let mut packet2 = _new_meta_packet();
        packet2.tcp_data.flags = TcpFlags::ACK;
        packet2.lookup_key.timestamp += 2 * Duration::from_millis(10);
        packet2.tcp_data.seq = 112;
        packet2.tcp_data.ack = 1112;
        let flush_timestamp = packet2.lookup_key.timestamp;
        flow_map.inject_meta_packet(packet2);

        flow_map.inject_flush_ticker(flush_timestamp);
        flow_map.inject_flush_ticker(flush_timestamp + Duration::from_secs(10));

        if let Ok(tagged_flow) = output_queue_receiver.recv(Some(TIME_UNIT)) {
            assert_eq!(tagged_flow.flow.close_type, CloseType::ForcedReport);
        }
    }

    #[test]
    fn reverse_new_cycle() {
        let (mut flow_map, _) = _new_flow_map_and_receiver();
        let npb_action = NpbAction::new(0, 10, NpbTunnelType::VxLan, TapSide::SRC, 123);
        let mut policy_data0 = PolicyData::default();
        policy_data0.merge_npb_action(vec![npb_action], 10, vec![]);
        let mut packet0 = _new_meta_packet();
        packet0.policy_data.replace(Arc::new(policy_data0));

        let npb_action = NpbAction::new(0, 11, NpbTunnelType::VxLan, TapSide::SRC, 123);
        let mut policy_data1 = PolicyData::default();
        policy_data1.merge_npb_action(vec![npb_action], 11, vec![]);
        let mut packet1 = _new_meta_packet();
        packet1.tcp_data.flags = TcpFlags::SYN_ACK;
        _reverse_meta_packet(&mut packet1);
        packet1.direction = PacketDirection::ServerToClient;
        packet1.policy_data.replace(Arc::new(policy_data1));

        let total_flow = flow_map
            .node_map
            .as_ref()
            .map(|map| map.len())
            .unwrap_or_default();
        let mut node = flow_map.init_flow(&mut packet0, total_flow);
        node.policy_in_tick.fill(false);
        flow_map.update_flow(&mut node, &mut packet1);

        let tap_side = node.tagged_flow.tag.policy_data[0].npb_actions[0].tap_side();
        let acl_id = node.tagged_flow.tag.policy_data[1].acl_id;
        assert_eq!(tap_side, TapSide::SRC);
        assert_eq!(acl_id, 11);
    }

    #[test]
    fn force_report() {
        let (mut flow_map, output_queue_receiver) = _new_flow_map_and_receiver();
        let packet0 = _new_meta_packet();
        flow_map.inject_meta_packet(packet0);

        let mut packet1 = _new_meta_packet();
        packet1.tcp_data.flags = TcpFlags::SYN_ACK;
        packet1.lookup_key.timestamp += Duration::from_millis(10);
        _reverse_meta_packet(&mut packet1);
        flow_map.inject_meta_packet(packet1);

        let mut packet2 = _new_meta_packet();
        packet2.tcp_data.flags = TcpFlags::ACK;
        packet2.lookup_key.timestamp += Duration::from_millis(10);
        let flush_timestamp = packet2.lookup_key.timestamp;
        flow_map.inject_meta_packet(packet2);

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
        let (mut flow_map, output_queue_receiver) = _new_flow_map_and_receiver();
        let mut packet0 = _new_meta_packet();
        packet0.lookup_key.proto = IpProtocol::Udp;
        let flush_timestamp = packet0.lookup_key.timestamp;
        flow_map.inject_meta_packet(packet0);

        flow_map.inject_flush_ticker(flush_timestamp);
        flow_map.inject_flush_ticker(flush_timestamp + Duration::from_secs(10));

        if let Ok(tagged_flow) = output_queue_receiver.recv(Some(TIME_UNIT)) {
            assert_eq!(tagged_flow.flow.close_type, CloseType::Timeout);
        }

        let mut packet1 = _new_meta_packet();
        packet1.lookup_key.eth_type = EthernetType::Arp;
        let flush_timestamp = packet1.lookup_key.timestamp;
        flow_map.inject_meta_packet(packet1);

        flow_map.inject_flush_ticker(flush_timestamp);
        flow_map.inject_flush_ticker(flush_timestamp + Duration::from_secs(10));

        if let Ok(tagged_flow) = output_queue_receiver.recv(Some(TIME_UNIT)) {
            assert_eq!(tagged_flow.flow.close_type, CloseType::Timeout);
        }
    }

    #[test]
    fn port_equal_tor() {
        let (mut flow_map, output_queue_receiver) = _new_flow_map_and_receiver();
        let mut packet0 = _new_meta_packet();
        packet0.lookup_key.tap_type = TapType::Tor;
        flow_map.inject_meta_packet(packet0);

        let mut packet1 = _new_meta_packet();
        packet1.lookup_key.dst_mac = MacAddr::from([0x21, 0x43, 0x65, 0xaa, 0xaa, 0xaa]);
        packet1.lookup_key.tap_type = TapType::Tor;
        packet1.tcp_data.flags = TcpFlags::RST;
        _reverse_meta_packet(&mut packet1);
        let flush_timestamp = packet1.lookup_key.timestamp;
        flow_map.inject_meta_packet(packet1);

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
        packet2.lookup_key.tap_type = TapType::Tor;
        packet2.tap_port = TapPort(0x1234);
        flow_map.inject_meta_packet(packet2);

        let mut packet3 = _new_meta_packet();
        packet3.lookup_key.src_ip = Ipv4Addr::new(192, 168, 1, 3).into();
        packet3.lookup_key.dst_mac = MacAddr::from([0x21, 0x43, 0x65, 0xaa, 0xaa, 0xaa]);
        packet3.lookup_key.tap_type = TapType::Tor;
        packet3.tap_port = TapPort(0x1234);
        packet3.lookup_key.l2_end_0 = true;
        packet3.lookup_key.l2_end_1 = false;
        packet3.tcp_data.flags = TcpFlags::RST;
        _reverse_meta_packet(&mut packet3);
        let flush_timestamp = packet3.lookup_key.timestamp;
        flow_map.inject_meta_packet(packet3);

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
        let (mut flow_map, _) = _new_flow_map_and_receiver();

        let mut packet0 = _new_meta_packet();
        // test handshake
        let total_flow = flow_map
            .node_map
            .as_ref()
            .map(|map| map.len())
            .unwrap_or_default();
        let mut node = flow_map.init_flow(&mut packet0, total_flow);
        let peer_src = &mut node.tagged_flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC];
        peer_src.tcp_flags = TcpFlags::SYN;
        flow_map.update_flow_state_machine(
            &mut node,
            TcpFlags::SYN_ACK,
            PacketDirection::ServerToClient,
        );
        assert_eq!(node.flow_state, FlowState::Opening2);
        node.flow_state = FlowState::Opening1;
        let peer_src = &mut node.tagged_flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC];
        peer_src.tcp_flags = TcpFlags::SYN;
        flow_map.update_flow_state_machine(
            &mut node,
            TcpFlags::SYN_ACK,
            PacketDirection::ServerToClient,
        );
        assert_eq!(node.flow_state, FlowState::Opening2);
        flow_map.update_flow_state_machine(
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
            &mut node,
            TcpFlags::ACK,
            PacketDirection::ServerToClient,
        );
        assert_eq!(node.flow_state, FlowState::ClosingTx1);
        flow_map.update_flow_state_machine(
            &mut node,
            TcpFlags::FIN_ACK,
            PacketDirection::ServerToClient,
        );
        assert_eq!(node.flow_state, FlowState::ClosingTx2);
        flow_map.update_flow_state_machine(
            &mut node,
            TcpFlags::ACK,
            PacketDirection::ClientToServer,
        );
        assert_eq!(node.flow_state, FlowState::Closed);
    }

    #[test]
    fn double_fin_from_server() {
        let (mut flow_map, output_queue_receiver) = _new_flow_map_and_receiver();
        // SYN
        let mut packet0 = _new_meta_packet();
        packet0.lookup_key.timestamp = Duration::from_nanos(
            (packet0.lookup_key.timestamp.as_nanos() / STATISTICAL_INTERVAL.as_nanos()
                * STATISTICAL_INTERVAL.as_nanos()) as u64,
        );
        let flush_timestamp = packet0.lookup_key.timestamp;
        flow_map.inject_meta_packet(packet0);

        // SYN|ACK
        let mut packet1 = _new_meta_packet();
        packet1.lookup_key.timestamp = flush_timestamp;
        packet1.tcp_data.flags = TcpFlags::SYN_ACK;
        _reverse_meta_packet(&mut packet1);
        flow_map.inject_meta_packet(packet1);

        // ACK
        let mut packet1 = _new_meta_packet();
        packet1.lookup_key.timestamp = flush_timestamp;
        packet1.tcp_data.flags = TcpFlags::ACK;
        flow_map.inject_meta_packet(packet1);

        // FIN
        let mut packet1 = _new_meta_packet();
        packet1.lookup_key.timestamp = flush_timestamp;
        packet1.tcp_data.flags = TcpFlags::FIN;
        _reverse_meta_packet(&mut packet1);
        flow_map.inject_meta_packet(packet1);
        // FIN
        let mut packet1 = _new_meta_packet();
        packet1.lookup_key.timestamp = flush_timestamp;
        packet1.tcp_data.flags = TcpFlags::FIN;
        _reverse_meta_packet(&mut packet1);
        flow_map.inject_meta_packet(packet1);

        flow_map.inject_flush_ticker(flush_timestamp);
        flow_map.inject_flush_ticker(flush_timestamp + Duration::from_secs(10));

        if let Ok(tagged_flow) = output_queue_receiver.recv(Some(TIME_UNIT)) {
            assert_eq!(tagged_flow.flow.close_type, CloseType::ClientHalfClose);
        }
    }
}
