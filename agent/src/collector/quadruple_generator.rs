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

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{
    atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    Arc, Weak,
};
use std::thread;
use std::time::Duration;

use arc_swap::access::Access;
#[cfg(target_os = "linux")]
use log::error;
use log::{debug, info, warn};
use thread::JoinHandle;

use super::{acc_flow::AccumulatedFlow, consts::*, MetricsType};

use crate::common::{
    endpoint::EPC_FROM_INTERNET,
    enums::{EthernetType, IpProtocol, TapType},
    flow::{CloseType, FlowMetricsPeer, L7Protocol, SignalSource},
    tagged_flow::TaggedFlow,
};
use crate::config::handler::CollectorAccess;
use crate::metric::meter::{
    AppAnomaly, AppLatency, AppMeter, AppTraffic, FlowMeter, Latency, Performance, Traffic,
};
use crate::platform::process_info_enabled;
use crate::rpc::get_timestamp;
use crate::utils::{
    lru::Lru,
    possible_host::PossibleHost,
    stats::{Collector, Countable, Counter, CounterType, CounterValue, RefCountable, StatsOption},
};
use public::queue::{DebugSender, Error, Receiver};

#[derive(Debug, Default)]
pub struct QgCounter {
    pub window_delay: AtomicI64,
    pub flow_delay: AtomicI64,

    pub no_endpoint: AtomicU64,
    pub drop_before_window: AtomicU64,
}

struct QuadrupleStash {
    v4_flows: HashMap<[u8; IPV4_LRU_KEY_SIZE], AccumulatedFlow>,
    v6_flows: HashMap<[u8; IPV6_LRU_KEY_SIZE], AccumulatedFlow>,
}

#[derive(Clone)]
pub enum QgKey {
    V4([u8; IPV4_LRU_KEY_SIZE]),
    V6([u8; IPV6_LRU_KEY_SIZE]),
}

impl QuadrupleStash {
    pub fn new() -> Self {
        Self {
            v4_flows: HashMap::new(),
            v6_flows: HashMap::new(),
        }
    }
    pub fn clear(&mut self) {
        self.v4_flows.clear();
        self.v6_flows.clear();
    }
}

// 并发连接算法逻辑：
// 依赖组件；
//     1. flowgenerator生成的流统计数据来计算并发连接数
//     2. 使用qg的key来计算统计对应四元组的并发连接，并发连接统计不需要其中的closeType，统计流程中会忽略
// 并发连接误差原因：
//     1. 队列出现丢包
//     2. flowgenerator中流计算的超时时间和并发连接的超时时间不一致
// 并发连接计算：
//     1. 新增的流，流未结束，sum和living同时加1，并更新时间戳
//     2. 新增的流，已经结束，sum加1，并更新时间戳
//     3. 非新增的流，已经结束，living减1，并更新时间戳
//     4. 当前时间点的并发连接统计完毕后，将living数据统计到下一个时间点的sum和living
//     5. 四元组查询对应的并发连接时会更新时间戳
struct QuadrupleConnections {
    sum: i64,    // 当前时间点的并发连接数
    living: i64, // 当前时间点依然存活的连接，时间点结束后会统计到下一个时间点
    time_in_second: Duration,
}

impl QuadrupleConnections {
    pub fn new(sum: i64, living: i64, time_in_second: Duration) -> Self {
        Self {
            sum,
            living,
            time_in_second,
        }
    }
}

struct ConcurrentConnection {
    v4_connections: Lru<[u8; IPV4_LRU_KEY_SIZE], QuadrupleConnections>,
    v6_connections: Lru<[u8; IPV6_LRU_KEY_SIZE], QuadrupleConnections>,
}

impl ConcurrentConnection {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            v4_connections: Lru::with_capacity(capacity >> 5, capacity),
            v6_connections: Lru::with_capacity(capacity >> 5, capacity),
        }
    }

    fn merge(&mut self, time_in_second: Duration, other: &ConcurrentConnection) {
        for (k, v) in other.v4_connections.iter() {
            // 四元组数据一直没有更新，数据超时直接删除
            if time_in_second > v.time_in_second + CONCURRENT_TIMEOUT {
                continue;
            }
            // 若发生丢包，可能会统计为负数直接丢弃
            if v.living <= 0 {
                continue;
            }
            if let Some(d) = self.v4_connections.get_mut(k) {
                d.living += v.living;
                d.sum += v.living;
            } else {
                self.v4_connections.put(
                    *k,
                    QuadrupleConnections::new(v.living, v.living, v.time_in_second),
                );
            }
        }
        for (k, v) in other.v6_connections.iter() {
            // 四元组数据一直没有更新，数据超时直接删除
            if time_in_second > v.time_in_second + CONCURRENT_TIMEOUT {
                continue;
            }
            // 若发生丢包，可能会统计为负数直接丢弃
            if v.living <= 0 {
                continue;
            }
            if let Some(d) = self.v6_connections.get_mut(k) {
                d.living += v.living;
                d.sum += v.living;
            } else {
                self.v6_connections.put(
                    *k,
                    QuadrupleConnections::new(v.living, v.living, v.time_in_second),
                );
            }
        }
    }

    fn connections_put(
        &mut self,
        key: &mut QgKey,
        time_in_second: Duration,
        living: i64,
        sum: i64,
    ) {
        match key {
            QgKey::V6(k) => self
                .v6_connections
                .put(*k, QuadrupleConnections::new(sum, living, time_in_second)),
            QgKey::V4(k) => self
                .v4_connections
                .put(*k, QuadrupleConnections::new(sum, living, time_in_second)),
        };
    }

    fn connections_mut(&mut self, key: &mut QgKey) -> Option<&mut QuadrupleConnections> {
        let ret = match key {
            QgKey::V6(k) => self.v6_connections.get_mut(k),
            QgKey::V4(k) => self.v4_connections.get_mut(k),
        };
        ret
    }

    fn get_concurrent(&mut self, time_in_second: Duration, key: &mut QgKey) -> u64 {
        let result = self.connections_mut(key);
        if let Some(v) = result {
            v.time_in_second = time_in_second;
            if v.sum <= 0 {
                // 如果数据超时或队列有丢包，merge时会丢弃数据，这里返回1
                1
            } else {
                v.sum as u64
            }
        } else {
            // 如果数据超时或队列有丢包，merge时会丢弃数据，这里返回1
            1
        }
    }

    pub fn add_connection(&mut self, time_in_second: Duration, key: &mut QgKey) {
        let result = self.connections_mut(key);
        if let Some(v) = result {
            v.living += 1;
            v.sum += 1;
            v.time_in_second = time_in_second;
        } else {
            self.connections_put(key, time_in_second, 1, 1);
        }
    }

    pub fn delete_connection(
        &mut self,
        time_in_second: Duration,
        key: &mut QgKey,
        is_new_flow: bool,
    ) {
        if let Some(v) = self.connections_mut(key) {
            v.time_in_second = time_in_second;
            if is_new_flow {
                v.sum += 1;
            } else {
                v.living -= 1;
            }
        } else {
            let mut living = 0i64;
            let mut sum = 0i64;
            if is_new_flow {
                sum += 1;
            } else {
                living -= 1;
            }
            self.connections_put(key, time_in_second, living, sum);
        }
    }

    fn clear(&mut self) {
        self.v4_connections.clear();
        self.v6_connections.clear();
    }
}

fn round_to_minute(t: Duration) -> Duration {
    Duration::from_secs(t.as_secs() / SECONDS_IN_MINUTE * SECONDS_IN_MINUTE)
}

struct SubQuadGen {
    id: usize,

    output: DebugSender<Box<AccumulatedFlow>>,

    counter: Arc<QgCounter>,
    metrics_type: MetricsType,

    // time in seconds
    window_start: Duration,
    // 1 or 60
    slot_interval: u64,
    number_of_slots: u64,

    delay_seconds: u64,

    stashs: VecDeque<QuadrupleStash>, // flow_generator 不会有超过2分钟的延时

    connections: VecDeque<ConcurrentConnection>,
    ntp_diff: Arc<AtomicI64>,
    // TODO: 策略统计处理
    // traffic_setter: TrafficSetter,
}

impl RefCountable for QgCounter {
    fn get_counters(&self) -> Vec<Counter> {
        vec![
            (
                "window-delay",
                CounterType::Counted,
                CounterValue::Signed(self.window_delay.swap(0, Ordering::Relaxed)),
            ),
            (
                "flow-delay",
                CounterType::Counted,
                CounterValue::Signed(self.flow_delay.swap(0, Ordering::Relaxed)),
            ),
            (
                "no-endpoint",
                CounterType::Counted,
                CounterValue::Unsigned(self.no_endpoint.swap(0, Ordering::Relaxed)),
            ),
            (
                "drop-before-window",
                CounterType::Counted,
                CounterValue::Unsigned(self.drop_before_window.swap(0, Ordering::Relaxed)),
            ),
        ]
    }
}

impl SubQuadGen {
    // return false if flow out of window
    fn move_window(&mut self, time_in_second: Duration, possible_host: &mut PossibleHost) -> bool {
        if time_in_second < self.window_start {
            self.counter
                .drop_before_window
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let ts = get_timestamp(self.ntp_diff.load(Ordering::Relaxed));
        while time_in_second.as_secs() >= self.window_start.as_secs() + self.delay_seconds {
            let delay = ts.as_nanos() as i64 - self.window_start.as_nanos() as i64;
            self.counter
                .window_delay
                .fetch_max(delay, Ordering::Relaxed);

            let slots_to_shift =
                (time_in_second.as_secs() - self.window_start.as_secs() - self.delay_seconds)
                    / self.slot_interval
                    + 1;
            if slots_to_shift >= self.number_of_slots {
                for i in 0..self.stashs.len() {
                    // 计算并发连接数，发送该秒/分钟的flow后, 将该秒/分钟的连接数，需并入下一秒/分钟中计算
                    let mut front = self.connections.pop_front().unwrap();
                    self.flush_flow(i, &mut front, possible_host);
                    self.connections[0].merge(time_in_second, &front);
                    front.clear();
                    self.connections.push_back(front);
                }
            } else {
                let slots_to_shift = slots_to_shift as usize;
                for i in 0..slots_to_shift {
                    let mut front = self.connections.pop_front().unwrap();
                    self.flush_flow(i, &mut front, possible_host);
                    self.connections[0].merge(time_in_second, &front);
                    front.clear();
                    self.connections.push_back(front);
                }
                self.stashs.rotate_left(slots_to_shift);
            }
            self.window_start += Duration::from_secs(self.slot_interval * slots_to_shift as u64);
            debug!(
                "qg window moved interval={} sys_ts={} flow_ts={:?} window={:?}",
                self.slot_interval,
                ts.as_secs(),
                time_in_second,
                self.window_start
            );
        }
        let delay = ts.as_nanos() as i64 - time_in_second.as_nanos() as i64;
        self.counter.flow_delay.fetch_max(delay, Ordering::Relaxed);

        true
    }

    fn set_connection(
        flows: &mut Vec<Box<AccumulatedFlow>>,
        connection: &mut ConcurrentConnection,
        possible_host: &mut PossibleHost,
    ) {
        if flows.len() == 0 || flows[0].tagged_flow.flow.signal_source == SignalSource::EBPF {
            // eBPF data has no L4 info
            // A SubQuadGen only process one type of data, so here we can return.
            return;
        }
        for acc_flow in flows.iter_mut() {
            acc_flow.is_active_host0 = Self::check_active_host(
                possible_host,
                &acc_flow.tagged_flow.flow.flow_metrics_peers[0],
                &acc_flow.tagged_flow.flow.flow_key.ip_src,
            );
            acc_flow.is_active_host1 = Self::check_active_host(
                possible_host,
                &acc_flow.tagged_flow.flow.flow_metrics_peers[1],
                &acc_flow.tagged_flow.flow.flow_key.ip_dst,
            );

            if acc_flow.tagged_flow.flow.flow_key.proto == IpProtocol::Tcp
                || acc_flow.tagged_flow.flow.flow_key.proto == IpProtocol::Udp
            {
                acc_flow.flow_meter.flow_load.load =
                    connection.get_concurrent(acc_flow.time_in_second, &mut acc_flow.key);
                acc_flow.flow_meter.flow_load.flow_count = if acc_flow.flow_meter.flow_load.load
                    > acc_flow.flow_meter.traffic.closed_flow
                {
                    acc_flow.flow_meter.flow_load.load - acc_flow.flow_meter.traffic.closed_flow
                } else {
                    0
                };
            }
        }
    }

    fn flush_flow(
        &mut self,
        stash_index: usize,
        connection: &mut ConcurrentConnection,
        possible_host: &mut PossibleHost,
    ) {
        self.stashs.push_back(QuadrupleStash::new());
        let stash = self.stashs.swap_remove_back(stash_index).unwrap();
        if !stash.v4_flows.is_empty() {
            let mut v4_flows: Vec<Box<AccumulatedFlow>> =
                stash.v4_flows.into_values().map(Box::new).collect();
            Self::set_connection(&mut v4_flows, connection, possible_host);
            if let Err(_) = self.output.send_large(v4_flows) {
                debug!("qg push v4 flows to queue failed maybe queue have terminated");
            }
        }

        if !stash.v6_flows.is_empty() {
            let mut v6_flows: Vec<Box<AccumulatedFlow>> =
                stash.v6_flows.into_values().map(Box::new).collect();
            Self::set_connection(&mut v6_flows, connection, possible_host);
            if let Err(_) = self.output.send_large(v6_flows) {
                debug!("qg push v6 flows to queue failed maybe queue have terminated");
            }
        }
    }

    fn flush_all_flow(&mut self, possible_host: &mut PossibleHost) {
        let mut tmp = ConcurrentConnection::with_capacity(1 << 13);
        for i in 0..self.stashs.len() {
            tmp.merge(Duration::ZERO, &self.connections[i]);
            self.flush_flow(i, &mut tmp, possible_host);
        }
    }

    fn check_active(
        possible_host: &mut PossibleHost,
        tagged_flow: &Arc<TaggedFlow>,
    ) -> (bool, bool) {
        (
            Self::check_active_host(
                possible_host,
                &tagged_flow.flow.flow_metrics_peers[0],
                &tagged_flow.flow.flow_key.ip_src,
            ),
            Self::check_active_host(
                possible_host,
                &tagged_flow.flow.flow_metrics_peers[1],
                &tagged_flow.flow.flow_key.ip_dst,
            ),
        )
    }

    fn check_active_host(
        possible_host: &mut PossibleHost,
        flow_metric: &FlowMetricsPeer,
        ip: &IpAddr,
    ) -> bool {
        if flow_metric.is_active_host || flow_metric.l3_epc_id == EPC_FROM_INTERNET {
            // 有EPC并且是Device, L3Epc是过平台数据获取的，无需添加到PossibleHost中
            return flow_metric.is_active_host;
        }
        if flow_metric.is_device {
            return true;
        }
        if flow_metric.total_packet_count > 0 {
            // 有EPC无Device的场景是通过CIDR获取的，这里需要加入的PossibleHost中
            possible_host.add(ip, flow_metric.l3_epc_id);
            true
        } else {
            possible_host.check(ip, flow_metric.l3_epc_id)
        }
    }

    // TODO 策略统计
    // fn sync_traffic(&self, flow: Arc<TaggedFlow>, meter: &FlowMeter) {}

    pub fn inject_flow(
        &mut self,
        tagged_flow: Arc<TaggedFlow>,
        flow_meter: &FlowMeter,
        app_meter: &AppMeter,
        id_maps: &[HashMap<u16, u16>; 2],
        time_in_second: Duration,
        key: &mut QgKey,
    ) {
        let slot = ((time_in_second - self.window_start).as_secs() / self.slot_interval) as usize;
        let stash = &mut self.stashs[slot];
        let connection = &mut self.connections[slot];

        // Only count the number of concurrent connections between TCP and UDP with the signal_source of packet
        if (tagged_flow.flow.flow_key.proto == IpProtocol::Tcp
            || tagged_flow.flow.flow_key.proto == IpProtocol::Udp)
            && tagged_flow.flow.signal_source == SignalSource::Packet
        {
            if tagged_flow.flow.is_new_flow
                && tagged_flow.flow.close_type == CloseType::ForcedReport
            {
                connection.add_connection(time_in_second, key);
            } else if tagged_flow.flow.close_type != CloseType::ForcedReport {
                connection.delete_connection(time_in_second, key, tagged_flow.flow.is_new_flow);
            }
        }

        let value = match key {
            QgKey::V6(k) => stash.v6_flows.get_mut(k),
            QgKey::V4(k) => stash.v4_flows.get_mut(k),
        };
        if let Some(acc_flow) = value {
            acc_flow.merge(time_in_second, flow_meter, app_meter, id_maps, &tagged_flow);
        } else {
            let nat_real_ip_0 = tagged_flow.flow.flow_metrics_peers[0].nat_real_ip;
            let nat_real_port_0 = tagged_flow.flow.flow_metrics_peers[0].nat_real_port;
            let nat_real_ip_1 = tagged_flow.flow.flow_metrics_peers[1].nat_real_ip;
            let nat_real_port_1 = tagged_flow.flow.flow_metrics_peers[1].nat_real_port;
            let l7_protocol = if let Some(p) = tagged_flow.flow.flow_perf_stats.as_ref() {
                p.l7_protocol
            } else {
                L7Protocol::Unknown
            };
            let acc_flow = AccumulatedFlow {
                tagged_flow,
                l7_protocol,
                is_active_host0: true,
                is_active_host1: true,
                id_maps: id_maps.clone(),
                flow_meter: *flow_meter,
                time_in_second,
                nat_real_ip_0,
                nat_real_ip_1,
                nat_real_port_0,
                nat_real_port_1,
                key: key.clone(),
                app_meter: *app_meter,
            };
            match key {
                QgKey::V6(k) => stash.v6_flows.insert(*k, acc_flow),
                QgKey::V4(k) => stash.v4_flows.insert(*k, acc_flow),
            };
        }
    }
}

pub struct QuadrupleGeneratorThread {
    id: usize,
    input: Arc<Receiver<Box<TaggedFlow>>>,
    second_output: DebugSender<Box<AccumulatedFlow>>,
    minute_output: DebugSender<Box<AccumulatedFlow>>,
    toa_info_output: DebugSender<Box<(SocketAddr, SocketAddr)>>,
    flow_output: Option<DebugSender<Arc<TaggedFlow>>>, // Send TaggedFlows to FlowAggr, equal to None when processing eBPF data.
    connection_lru_capacity: usize,
    metrics_type: MetricsType,
    second_delay_seconds: u64,
    minute_delay_seconds: u64,
    possible_host_size: usize,
    l7_metrics_enabled: Arc<AtomicBool>,
    vtap_flow_1s_enabled: Arc<AtomicBool>,
    collector_enabled: Arc<AtomicBool>,

    thread_handle: Option<JoinHandle<()>>,

    running: Arc<AtomicBool>,
    config: CollectorAccess,
    ntp_diff: Arc<AtomicI64>,

    stats: Arc<Collector>,
}

impl QuadrupleGeneratorThread {
    pub fn new(
        id: usize,
        input: Receiver<Box<TaggedFlow>>,
        second_output: DebugSender<Box<AccumulatedFlow>>,
        minute_output: DebugSender<Box<AccumulatedFlow>>,
        toa_info_output: DebugSender<Box<(SocketAddr, SocketAddr)>>,
        flow_output: Option<DebugSender<Arc<TaggedFlow>>>,
        connection_lru_capacity: usize,
        metrics_type: MetricsType,
        second_delay_seconds: u64,
        minute_delay_seconds: u64,
        possible_host_size: usize,
        config: CollectorAccess,
        ntp_diff: Arc<AtomicI64>,
        stats: Arc<Collector>,
    ) -> Self {
        let running = Arc::new(AtomicBool::new(false));
        Self {
            id,
            input: Arc::new(input),
            second_output: second_output.clone(),
            minute_output: minute_output.clone(),
            toa_info_output,
            flow_output,
            connection_lru_capacity,
            metrics_type,
            second_delay_seconds,
            minute_delay_seconds,
            possible_host_size,
            l7_metrics_enabled: Arc::new(AtomicBool::new(config.load().l7_metrics_enabled)),
            vtap_flow_1s_enabled: Arc::new(AtomicBool::new(config.load().vtap_flow_1s_enabled)),
            collector_enabled: Arc::new(AtomicBool::new(config.load().enabled)),
            thread_handle: None,
            running,
            config,
            ntp_diff,
            stats,
        }
    }

    pub fn update_config(&self) {
        let l7_metrics_enabled = self.config.load().l7_metrics_enabled;
        let vtap_flow_1s_enabled = self.config.load().vtap_flow_1s_enabled;
        let collector_enabled = self.config.load().enabled;
        if self.l7_metrics_enabled.load(Ordering::Relaxed) != l7_metrics_enabled {
            info!(
                "quadruple generator update l7_metrics_enabled to {}",
                l7_metrics_enabled
            );
            self.l7_metrics_enabled
                .store(l7_metrics_enabled, Ordering::Relaxed);
        }
        if self.vtap_flow_1s_enabled.load(Ordering::Relaxed) != vtap_flow_1s_enabled {
            info!(
                "quadruple generator update vtap_flow_1s_enabled to {}",
                vtap_flow_1s_enabled
            );
            self.vtap_flow_1s_enabled
                .store(vtap_flow_1s_enabled, Ordering::Relaxed);
        }
        if self.collector_enabled.load(Ordering::Relaxed) != collector_enabled {
            info!(
                "quadruple generator update collector_enabled to {}",
                collector_enabled
            );
            self.collector_enabled
                .store(collector_enabled, Ordering::Relaxed);
        }
    }

    pub fn start(&mut self) {
        if self.running.swap(true, Ordering::Relaxed) {
            warn!(
                "quadruple generator id: {} already started, do nothing.",
                self.id
            );
            return;
        }

        let mut quadruple_generator = QuadrupleGenerator::new(
            self.id,
            self.input.clone(),
            self.second_output.clone(),
            self.minute_output.clone(),
            self.toa_info_output.clone(),
            process_info_enabled(self.config.load().trident_type),
            self.flow_output.clone(),
            self.connection_lru_capacity,
            self.metrics_type,
            self.second_delay_seconds,
            self.minute_delay_seconds,
            self.possible_host_size,
            self.l7_metrics_enabled.clone(),
            self.vtap_flow_1s_enabled.clone(),
            self.collector_enabled.clone(),
            self.running.clone(),
            self.ntp_diff.clone(),
            self.stats.clone(),
        );
        self.thread_handle = Some(
            thread::Builder::new()
                .name("quadruple-generator".to_owned())
                .spawn(move || quadruple_generator.handler_routine())
                .unwrap(),
        );
        info!("quadruple generator id: {} started", self.id);
    }

    pub fn stop(&mut self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            warn!(
                "quadruple generator id: {} already stopped, do nothing.",
                self.id
            );
            return;
        }
        info!("stoping quadruple generator: {}", self.id);
        let _ = self.thread_handle.take().unwrap().join();
        info!("stopped quadruple generator: {}", self.id);
    }
}

pub struct QuadrupleGenerator {
    id: usize,
    input: Arc<Receiver<Box<TaggedFlow>>>,
    name: String,

    second_quad_gen: Option<SubQuadGen>,
    minute_quad_gen: Option<SubQuadGen>,
    possible_host: PossibleHost,

    key: QgKey,
    id_maps: [HashMap<u16, u16>; 2],
    output_flow: Option<DebugSender<Arc<TaggedFlow>>>, // Send TaggedFlows to FlowAggr, equal to None when processing eBPF data.

    l7_metrics_enabled: Arc<AtomicBool>,
    vtap_flow_1s_enabled: Arc<AtomicBool>,
    collector_enabled: Arc<AtomicBool>,

    running: Arc<AtomicBool>,
    ntp_diff: Arc<AtomicI64>,

    stats: Arc<Collector>,

    // DebugSender<Box<LocalAddr, RealAddr>>
    // send to SocketSynchronizer
    toa_info_output: DebugSender<Box<(SocketAddr, SocketAddr)>>,
    // use to determine whether should send the toa info
    proc_sync_enable: bool,
}

impl QuadrupleGenerator {
    pub fn new(
        id: usize,
        input: Arc<Receiver<Box<TaggedFlow>>>,
        second_output: DebugSender<Box<AccumulatedFlow>>,
        minute_output: DebugSender<Box<AccumulatedFlow>>,
        toa_info_output: DebugSender<Box<(SocketAddr, SocketAddr)>>,
        proc_sync_enable: bool,
        flow_output: Option<DebugSender<Arc<TaggedFlow>>>,
        connection_lru_capacity: usize,
        metrics_type: MetricsType,
        second_delay_seconds: u64,
        minute_delay_seconds: u64,
        possible_host_size: usize,
        // traffic_setter: TrafficSetter,
        l7_metrics_enabled: Arc<AtomicBool>,
        vtap_flow_1s_enabled: Arc<AtomicBool>,
        collector_enabled: Arc<AtomicBool>,
        running: Arc<AtomicBool>,
        ntp_diff: Arc<AtomicI64>,
        stats: Arc<Collector>,
    ) -> Self {
        info!("new quadruple_generator id: {}, second_delay: {}, minute_delay: {}, l7_metrics_enabled: {}, vtap_flow_1s_enabled: {} collector_enabled: {}", id, second_delay_seconds, minute_delay_seconds, l7_metrics_enabled.load(Ordering::Relaxed), vtap_flow_1s_enabled.load(Ordering::Relaxed), collector_enabled.load(Ordering::Relaxed));
        if minute_delay_seconds < SECONDS_IN_MINUTE || minute_delay_seconds >= SECONDS_IN_MINUTE * 2
        {
            panic!("minute_delay_seconds须在[60, 120)秒内")
        }

        let second_slots = second_delay_seconds as usize;
        let minute_slots = 2 as usize;
        let mut second_quad_gen = None;
        let mut minute_quad_gen = None;
        let window_start = round_to_minute(get_timestamp(ntp_diff.load(Ordering::Relaxed)))
            - Duration::from_secs(2 * SECONDS_IN_MINUTE);

        if metrics_type.contains(MetricsType::SECOND) {
            second_quad_gen = Some(SubQuadGen {
                id,
                output: second_output,
                metrics_type: MetricsType::SECOND,
                window_start,
                slot_interval: 1,
                number_of_slots: second_slots as u64,
                delay_seconds: second_delay_seconds,
                stashs: VecDeque::with_capacity(second_slots),
                connections: VecDeque::with_capacity(second_slots),
                counter: Arc::new(QgCounter::default()),
                ntp_diff: ntp_diff.clone(),
                // traffic_setter: traffic_setter,
            });

            for _ in 0..second_slots {
                second_quad_gen
                    .as_mut()
                    .unwrap()
                    .stashs
                    .push_back(QuadrupleStash::new());
                second_quad_gen
                    .as_mut()
                    .unwrap()
                    .connections
                    .push_back(ConcurrentConnection::with_capacity(connection_lru_capacity));
            }
            stats.register_countable(
                "second_quadruple_generator",
                Countable::Ref(Arc::downgrade(&second_quad_gen.as_ref().unwrap().counter)
                    as Weak<dyn RefCountable>),
                vec![StatsOption::Tag("index", id.to_string())],
            );
        }

        if metrics_type.contains(MetricsType::MINUTE) {
            minute_quad_gen = Some(SubQuadGen {
                id,
                output: minute_output,
                metrics_type: MetricsType::MINUTE,
                window_start,
                slot_interval: 60,
                number_of_slots: minute_slots as u64,
                delay_seconds: minute_delay_seconds,
                stashs: VecDeque::with_capacity(minute_slots),
                connections: VecDeque::with_capacity(minute_slots),
                counter: Arc::new(QgCounter::default()),
                ntp_diff: ntp_diff.clone(),
                // traffic_setter: traffic_setter,
            });

            for _ in 0..minute_slots {
                minute_quad_gen
                    .as_mut()
                    .unwrap()
                    .stashs
                    .push_back(QuadrupleStash::new());
                minute_quad_gen
                    .as_mut()
                    .unwrap()
                    .connections
                    .push_back(ConcurrentConnection::with_capacity(connection_lru_capacity));
            }
            stats.register_countable(
                "minute_quadruple_generator",
                Countable::Ref(Arc::downgrade(&minute_quad_gen.as_ref().unwrap().counter)
                    as Weak<dyn RefCountable>),
                vec![StatsOption::Tag("index", id.to_string())],
            );
        }

        QuadrupleGenerator {
            id,
            input,
            name: "quadruple_generator".to_string(),

            second_quad_gen,
            minute_quad_gen,
            possible_host: PossibleHost::new(possible_host_size),

            key: QgKey::V6([0; IPV6_LRU_KEY_SIZE]),
            id_maps: [HashMap::new(), HashMap::new()],
            output_flow: flow_output,

            l7_metrics_enabled,
            vtap_flow_1s_enabled,
            collector_enabled,
            running,
            ntp_diff,
            stats,

            toa_info_output,
            proc_sync_enable,
        }
    }

    fn handle(&mut self, tagged_flow: Option<Arc<TaggedFlow>>, time_in_second: Duration) {
        let mut second_inject = false;
        let mut minute_inject = false;
        if let Some(s) = self.second_quad_gen.as_mut() {
            if self.vtap_flow_1s_enabled.load(Ordering::Relaxed) {
                second_inject = s.move_window(time_in_second, &mut self.possible_host);
            }
        }
        if let Some(s) = self.minute_quad_gen.as_mut() {
            minute_inject = s.move_window(time_in_second, &mut self.possible_host);
        }

        if tagged_flow.is_none() || !(second_inject || minute_inject) {
            return;
        }
        let tagged_flow = tagged_flow.unwrap();

        let mut no_endpoint_flag = true;
        for i in 0..2 {
            let side = &tagged_flow.flow.flow_metrics_peers[i];
            let is_l2_and_l3_end = side.is_l3_end && side.is_l2_end;
            if (tagged_flow.flow.flow_key.tap_type == TapType::Cloud && is_l2_and_l3_end)
                || (tagged_flow.flow.flow_key.tap_type != TapType::Cloud
                    && side.l3_epc_id != EPC_FROM_INTERNET)
            {
                no_endpoint_flag = false;
                break;
            }
        }

        if no_endpoint_flag {
            if let Some(s) = self.second_quad_gen.as_mut() {
                s.counter.no_endpoint.fetch_add(1, Ordering::Relaxed);
            }
            if let Some(s) = self.minute_quad_gen.as_mut() {
                s.counter.no_endpoint.fetch_add(1, Ordering::Relaxed);
            }
        }

        let key = Self::get_key(&tagged_flow);
        self.key = key;
        self.id_maps[0].clear();
        self.id_maps[1].clear();

        let (flow_meter, app_meter) =
            Self::generate_meter(&tagged_flow, self.l7_metrics_enabled.clone());

        if second_inject {
            self.second_quad_gen.as_mut().unwrap().inject_flow(
                tagged_flow.clone(),
                &flow_meter,
                &app_meter,
                &self.id_maps,
                time_in_second,
                &mut self.key,
            );
        }

        if minute_inject {
            for i in 0..2 {
                // policy_ids are only used for the calculation of vtap_acl metrics
                for action in tagged_flow.tag.policy_data[i].npb_actions.iter() {
                    for (&gid, &ip_id) in action.acl_gids().iter().zip(action.tunnel_ip_ids()) {
                        self.id_maps[i].insert(gid, ip_id);
                    }
                }
            }
            self.minute_quad_gen.as_mut().unwrap().inject_flow(
                tagged_flow,
                &flow_meter,
                &app_meter,
                &self.id_maps,
                time_in_second,
                &mut self.key,
            );
        }
    }

    fn generate_meter(
        tagged_flow: &TaggedFlow,
        l7_metrics_enabled: Arc<AtomicBool>,
    ) -> (FlowMeter, AppMeter) {
        let (mut flow_meter, mut app_meter) = (FlowMeter::default(), AppMeter::default());

        let src = &tagged_flow.flow.flow_metrics_peers[0];
        let dst = &tagged_flow.flow.flow_metrics_peers[1];

        let perf_stats = tagged_flow.flow.flow_perf_stats.as_ref();
        let stats = match tagged_flow.flow.flow_perf_stats.as_ref() {
            Some(s) => s,
            None => return (flow_meter, app_meter),
        };
        // Only count the flow_meter whose signal_source of flow is SignalSource::Packet or SignalSource::XFlow
        if tagged_flow.flow.signal_source == SignalSource::Packet
            || tagged_flow.flow.signal_source == SignalSource::XFlow
        {
            flow_meter.traffic = Traffic {
                packet_tx: src.packet_count,
                packet_rx: dst.packet_count,
                byte_tx: src.byte_count,
                byte_rx: dst.byte_count,
                l3_byte_tx: src.l3_byte_count,
                l3_byte_rx: dst.l3_byte_count,
                l4_byte_tx: src.l4_byte_count,
                l4_byte_rx: dst.l4_byte_count,
                new_flow: tagged_flow.flow.is_new_flow as u64,
                closed_flow: (tagged_flow.flow.close_type != CloseType::ForcedReport) as u64,
                l7_request: 0,
                l7_response: 0,
                syn: perf_stats.map(|s| s.tcp.syn_count).unwrap_or_default(),
                synack: perf_stats.map(|s| s.tcp.synack_count).unwrap_or_default(),
            };
            if tagged_flow.flow.flow_key.proto == IpProtocol::Tcp {
                match tagged_flow.flow.close_type {
                    CloseType::TcpServerRst => flow_meter.anomaly.server_rst_flow = 1,
                    CloseType::Timeout => flow_meter.anomaly.tcp_timeout = 1,
                    CloseType::ClientSynRepeat => flow_meter.anomaly.client_syn_repeat = 1,
                    CloseType::ServerHalfClose => flow_meter.anomaly.server_half_close_flow = 1,
                    CloseType::TcpClientRst => flow_meter.anomaly.client_rst_flow = 1,
                    CloseType::ServerSynAckRepeat => flow_meter.anomaly.server_synack_repeat = 1,
                    CloseType::ClientHalfClose => flow_meter.anomaly.client_half_close_flow = 1,
                    CloseType::ClientSourcePortReuse => {
                        flow_meter.anomaly.client_source_port_reuse = 1
                    }
                    CloseType::ServerReset => flow_meter.anomaly.server_reset = 1,
                    CloseType::ServerQueueLack => flow_meter.anomaly.server_queue_lack = 1,
                    CloseType::ClientEstablishReset => {
                        flow_meter.anomaly.client_establish_reset = 1
                    }
                    CloseType::ServerEstablishReset => {
                        flow_meter.anomaly.server_establish_reset = 1
                    }
                    CloseType::ForcedReport
                    | CloseType::TcpFin
                    | CloseType::Unknown
                    | CloseType::Max => (),
                }
            }

            if tagged_flow.flow.flow_key.proto == IpProtocol::Tcp {
                flow_meter.latency = Latency {
                    rtt_max: stats.tcp.rtt,
                    rtt_client_max: stats.tcp.rtt_client_max,
                    rtt_server_max: stats.tcp.rtt_server_max,
                    srt_max: stats.tcp.srt_max,
                    art_max: stats.tcp.art_max,
                    rrt_max: 0,
                    cit_max: stats.tcp.cit_max,

                    rtt_sum: stats.tcp.rtt as u64,
                    rtt_client_sum: stats.tcp.rtt_client_sum as u64,
                    rtt_server_sum: stats.tcp.rtt_server_sum as u64,
                    srt_sum: stats.tcp.srt_sum as u64,
                    art_sum: stats.tcp.art_sum as u64,
                    rrt_sum: 0,
                    cit_sum: stats.tcp.cit_sum as u64,

                    rtt_count: (stats.tcp.rtt > 0) as u32,
                    rtt_client_count: stats.tcp.rtt_client_count,
                    rtt_server_count: stats.tcp.rtt_server_count,
                    srt_count: stats.tcp.srt_count,
                    art_count: stats.tcp.art_count,
                    rrt_count: 0,
                    cit_count: stats.tcp.cit_count,
                };

                let src_perf = &stats.tcp.counts_peers[0];
                let dst_perf = &stats.tcp.counts_peers[1];
                flow_meter.performance = Performance {
                    retrans_tx: src_perf.retrans_count as u64,
                    retrans_rx: dst_perf.retrans_count as u64,
                    zero_win_tx: src_perf.zero_win_count as u64,
                    zero_win_rx: dst_perf.zero_win_count as u64,
                    retrans_syn: stats.tcp.retrans_syn_count,
                    retrans_synack: stats.tcp.retrans_synack_count,
                };
            } else {
                flow_meter.latency.art_max = stats.tcp.art_max;
                flow_meter.latency.art_sum = stats.tcp.art_sum as u64;
                flow_meter.latency.art_count = stats.tcp.art_max;
            }

            if !l7_metrics_enabled.load(Ordering::Relaxed) {
                return (flow_meter, app_meter);
            }
        }

        match stats.l7_protocol {
            L7Protocol::Unknown | L7Protocol::Other => {
                app_meter = AppMeter {
                    traffic: AppTraffic {
                        request: (tagged_flow.flow.close_type != CloseType::ForcedReport) as u32,
                        response: (tagged_flow.flow.close_type != CloseType::ForcedReport) as u32,
                    },
                    ..Default::default()
                }
            }
            _ => {
                app_meter = AppMeter {
                    traffic: AppTraffic {
                        request: stats.l7.request_count,
                        response: stats.l7.response_count,
                    },
                    latency: AppLatency {
                        rrt_max: stats.l7.rrt_max,
                        rrt_sum: stats.l7.rrt_sum as u64,
                        rrt_count: stats.l7.rrt_count,
                    },
                    anomaly: AppAnomaly {
                        client_error: stats.l7.err_client_count,
                        server_error: stats.l7.err_server_count,
                        timeout: stats.l7.err_timeout,
                    },
                };
                flow_meter.traffic.l7_request = stats.l7.request_count;
                flow_meter.traffic.l7_response = stats.l7.response_count;
                flow_meter.latency.rrt_max = stats.l7.rrt_max;
                flow_meter.latency.rrt_sum = stats.l7.rrt_sum;
                flow_meter.latency.rrt_count = stats.l7.rrt_count;
                flow_meter.anomaly.l7_client_error = stats.l7.err_client_count;
                flow_meter.anomaly.l7_server_error = stats.l7.err_server_count;
                flow_meter.anomaly.l7_timeout = stats.l7.err_timeout;
            }
        }

        (flow_meter, app_meter)
    }

    fn set_key(key: &mut [u8], tagged_flow: &Arc<TaggedFlow>) {
        let src = &tagged_flow.flow.flow_metrics_peers[0];
        let dst = &tagged_flow.flow.flow_metrics_peers[1];
        let (tap_port, tap_port_type, tunnel_type) =
            tagged_flow.flow.flow_key.tap_port.split_fields();
        key[OFFSET_L3_EPC_ID_0] = (src.l3_epc_id >> 8) as u8;
        key[OFFSET_L3_EPC_ID_0 + 1] = src.l3_epc_id as u8;
        key[OFFSET_L3_EPC_ID_1] = (dst.l3_epc_id >> 8) as u8;
        key[OFFSET_L3_EPC_ID_1 + 1] = dst.l3_epc_id as u8;
        key[OFFSET_GPID_0] = (src.gpid >> 24) as u8;
        key[OFFSET_GPID_0 + 1] = (src.gpid >> 16) as u8;
        key[OFFSET_GPID_0 + 2] = (src.gpid >> 8) as u8;
        key[OFFSET_GPID_0 + 3] = src.gpid as u8;
        key[OFFSET_GPID_1] = (dst.gpid >> 24) as u8;
        key[OFFSET_GPID_1 + 1] = (dst.gpid >> 16) as u8;
        key[OFFSET_GPID_1 + 2] = (dst.gpid >> 8) as u8;
        key[OFFSET_GPID_1 + 3] = dst.gpid as u8;
        // TAP_PORT_SIZE: tap_port(4B), tap_port_type(1B), tap_type(1B), tunnel_type(1B), tap_side(1B)
        key[OFFSET_TAP_PORT] = ((tap_port as u32) >> 24) as u8;
        key[OFFSET_TAP_PORT + 1] = ((tap_port as u32) >> 16) as u8;
        key[OFFSET_TAP_PORT + 2] = ((tap_port as u32) >> 8) as u8;
        key[OFFSET_TAP_PORT + 3] = tap_port as u8;
        key[OFFSET_TAP_PORT + 4] = tap_port_type as u8;
        key[OFFSET_TAP_PORT + 5] = u16::from(tagged_flow.flow.flow_key.tap_type) as u8;
        key[OFFSET_TAP_PORT + 6] = tunnel_type as u8;
        key[OFFSET_TAP_PORT + 7] = tagged_flow.flow.tap_side as u8;
        key[OFFSET_PROTOCOL] = u8::from(tagged_flow.flow.flow_key.proto);
        // 对于sflow, netflow流量，仅当确定目的IP是服务端时，将目的端口作为查询key
        if tagged_flow.flow.signal_source == SignalSource::Packet
            || tagged_flow.flow.is_active_service
        {
            key[OFFSET_PORT] = (tagged_flow.flow.flow_key.port_dst >> 8) as u8;
            key[OFFSET_PORT + 1] = tagged_flow.flow.flow_key.port_dst as u8;
        }
    }

    pub fn get_key(tagged_flow: &Arc<TaggedFlow>) -> QgKey {
        if tagged_flow.flow.eth_type == EthernetType::Ipv6 {
            let mut key: [u8; IPV6_LRU_KEY_SIZE] = [0; IPV6_LRU_KEY_SIZE];
            Self::set_key(&mut key, tagged_flow);
            match (
                tagged_flow.flow.flow_key.ip_src,
                tagged_flow.flow.flow_key.ip_dst,
            ) {
                (IpAddr::V6(src), IpAddr::V6(dst)) => {
                    key[OFFSET_IP..OFFSET_IP + 16].copy_from_slice(src.octets().as_slice());
                    key[OFFSET_IP + 16..OFFSET_IP + 32].copy_from_slice(dst.octets().as_slice())
                }
                _ => (),
            }
            QgKey::V6(key)
        } else {
            let mut key: [u8; IPV4_LRU_KEY_SIZE] = [0; IPV4_LRU_KEY_SIZE];
            Self::set_key(&mut key, tagged_flow);
            match (
                tagged_flow.flow.flow_key.ip_src,
                tagged_flow.flow.flow_key.ip_dst,
            ) {
                (IpAddr::V4(src), IpAddr::V4(dst)) => {
                    key[OFFSET_IP..OFFSET_IP + 4].copy_from_slice(src.octets().as_slice());
                    key[OFFSET_IP + 4..OFFSET_IP + 8].copy_from_slice(dst.octets().as_slice());
                }
                _ => (),
            }
            QgKey::V4(key)
        }
    }

    fn handler_routine(&mut self) {
        let mut recv_batch = Vec::with_capacity(QUEUE_BATCH_SIZE);
        let mut send_batch = Vec::with_capacity(QUEUE_BATCH_SIZE);
        while self.running.load(Ordering::Relaxed) {
            match self.input.recv_all(&mut recv_batch, Some(RCV_TIMEOUT)) {
                Ok(_) => {
                    for tagged_flow in recv_batch.drain(..) {
                        let tagged_flow = Arc::from(tagged_flow);
                        if self.output_flow.is_some() {
                            send_batch.push(Arc::clone(&tagged_flow));
                        }
                        if self.collector_enabled.load(Ordering::Relaxed) {
                            self.handle(
                                Some(Arc::clone(&tagged_flow)),
                                tagged_flow.flow.flow_stat_time.into(),
                            );
                        }

                        #[cfg(target_os = "linux")]
                        if let Some(toa) = tagged_flow.get_toa_info() {
                            if self.proc_sync_enable {
                                if let Err(_) = self.toa_info_output.send(Box::new(toa)) {
                                    error!("send toa info fail");
                                }
                            }
                        }
                    }
                    if send_batch.len() > 0 {
                        if let Err(_) = self.output_flow.as_mut().unwrap().send_all(&mut send_batch)
                        {
                            debug!("qg push TaggedFlow to l4_flow queue failed, maybe queue have terminated");
                            send_batch.clear();
                        }
                    }
                }
                Err(Error::Timeout) => {
                    self.handle(None, get_timestamp(self.ntp_diff.load(Ordering::Relaxed)));
                }
                Err(Error::Terminated(_, _)) => {
                    if let Some(g) = self.second_quad_gen.as_mut() {
                        g.flush_all_flow(&mut self.possible_host);
                    }
                    if let Some(g) = self.minute_quad_gen.as_mut() {
                        g.flush_all_flow(&mut self.possible_host);
                    }
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use super::*;

    use public::{debug::QueueDebugger, queue};

    fn new_acc_flow(tagged_flow: Arc<TaggedFlow>) -> AccumulatedFlow {
        AccumulatedFlow {
            tagged_flow: tagged_flow.clone(),
            l7_protocol: L7Protocol::Unknown,
            is_active_host0: true,
            is_active_host1: true,
            id_maps: [HashMap::new(), HashMap::new()],
            flow_meter: FlowMeter::default(),
            app_meter: AppMeter::default(),
            key: QuadrupleGenerator::get_key(&tagged_flow),
            time_in_second: Duration::from_secs(0),
            nat_real_ip_0: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            nat_real_port_0: 0,
            nat_real_ip_1: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            nat_real_port_1: 0,
        }
    }

    #[test]
    fn second_inject_flow() {
        let ntp_diff = Arc::new(AtomicI64::new(0));
        let window_start = round_to_minute(get_timestamp(ntp_diff.load(Ordering::Relaxed)))
            - Duration::from_secs(2 * SECONDS_IN_MINUTE);
        let queue_debugger = QueueDebugger::new();
        let (s, r, _) = queue::bounded_with_debug(100, "", &queue_debugger);
        let slots = 30u64;
        let mut quad_gen = SubQuadGen {
            id: 0,
            output: s,
            metrics_type: MetricsType::SECOND,
            window_start,
            slot_interval: 1,
            number_of_slots: slots,
            delay_seconds: slots,
            stashs: VecDeque::with_capacity(slots as usize),
            connections: VecDeque::with_capacity(slots as usize),
            counter: Arc::new(QgCounter::default()),
            ntp_diff,
        };
        for _ in 0..slots as usize {
            quad_gen.stashs.push_back(QuadrupleStash::new());
            quad_gen
                .connections
                .push_back(ConcurrentConnection::with_capacity((slots as usize) << 8));
        }

        let mut tagged_flow = TaggedFlow::default();
        tagged_flow.flow.close_type = CloseType::ForcedReport;
        tagged_flow.flow.is_new_flow = true;
        tagged_flow.flow.flow_key.proto = IpProtocol::Tcp;
        let tagged_flow_arc = Arc::new(tagged_flow);
        let flow_meter = FlowMeter::default();
        let app_meter = AppMeter::default();
        let id_maps = [HashMap::new(), HashMap::new()];
        let mut key = QuadrupleGenerator::get_key(&tagged_flow_arc);
        quad_gen.inject_flow(
            tagged_flow_arc.clone(),
            &flow_meter,
            &app_meter,
            &id_maps,
            window_start + Duration::from_secs(10),
            &mut key,
        );

        let mut tagged_flow = TaggedFlow::default();
        tagged_flow.flow.close_type = CloseType::ForcedReport;
        tagged_flow.flow.is_new_flow = true;
        tagged_flow.flow.flow_key.proto = IpProtocol::Tcp;
        quad_gen.inject_flow(
            tagged_flow_arc.clone(),
            &flow_meter,
            &app_meter,
            &id_maps,
            window_start + Duration::from_secs(15),
            &mut key,
        );

        let k = if let QgKey::V4(k) = key {
            k
        } else {
            return;
        };
        assert_eq!(
            quad_gen.stashs[10].v4_flows.get(&k).unwrap().flow_meter,
            new_acc_flow(tagged_flow_arc.clone()).flow_meter
        );
        let mut poss_host = PossibleHost::new(100);
        quad_gen.flush_all_flow(&mut poss_host);
        if let Ok(ret) = r.recv(None) {
            assert_eq!(ret.flow_meter.flow_load.load, 1);
        }
        if let Ok(ret) = r.recv(None) {
            assert_eq!(ret.flow_meter.flow_load.load, 2);
        }
    }
}
