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

use std::collections::{HashMap, VecDeque};
use std::sync::{
    atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    Arc, Weak,
};
use std::thread;
use std::time::Duration;

use arc_swap::access::Access;
use log::{debug, info, warn};
use thread::JoinHandle;

use super::{
    check_active,
    consts::*,
    round_to_minute,
    types::{AppMeterWithFlow, MiniFlow},
    MetricsType,
};

use crate::common::flow::{CloseType, L7Protocol, L7Stats, SignalSource};
use crate::config::handler::{CollectorAccess, CollectorConfig};
use crate::metric::meter::{AppAnomaly, AppLatency, AppMeter, AppTraffic};
use crate::rpc::get_timestamp;
use crate::utils::{
    possible_host::PossibleHost,
    stats::{Collector, Countable, Counter, CounterType, CounterValue, RefCountable, StatsOption},
};
use public::{
    buffer::BatchedBox,
    queue::{DebugSender, Error, Receiver},
    utils::hash::hash_to_u64,
};

const FLOW_ID_LEN: usize = 8;

#[derive(Debug, Default)]
pub struct QgCounter {
    pub window_delay: AtomicI64,
    pub flow_delay: AtomicI64,

    pub drop_before_window: AtomicU64,

    pub stash_total_len: AtomicU64,
    pub stash_total_capacity: AtomicU64,
}

struct AppMeterWithL7Protocol {
    app_meter: AppMeter,
    endpoint: Option<String>,
    endpoint_hash: u32,
    l7_protocol: L7Protocol,
}

struct QuadrupleStash {
    l7_stats: HashMap<u64, Vec<AppMeterWithL7Protocol>>,
    meters: Vec<Box<AppMeterWithFlow>>,
}

impl QuadrupleStash {
    pub fn new() -> Self {
        Self {
            l7_stats: HashMap::new(),
            meters: vec![],
        }
    }
    pub fn clear(&mut self) {
        self.l7_stats.clear();
        self.meters.clear();
    }
}

struct SubQuadGen {
    id: usize,

    l7_output: DebugSender<Box<AppMeterWithFlow>>,

    counter: Arc<QgCounter>,
    metrics_type: MetricsType,

    // time in seconds
    window_start: Duration,
    // 1 or 60
    slot_interval: u64,
    number_of_slots: u64,

    delay_seconds: u64,

    stashs: VecDeque<QuadrupleStash>, // flow_generator will not have a delay of more than 2 minutes
    ntp_diff: Arc<AtomicI64>,
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
                "drop-before-window",
                CounterType::Counted,
                CounterValue::Unsigned(self.drop_before_window.swap(0, Ordering::Relaxed)),
            ),
            (
                "stash-total-len",
                CounterType::Counted,
                CounterValue::Unsigned(self.stash_total_len.load(Ordering::Relaxed)),
            ),
            (
                "stash-total-capacity",
                CounterType::Counted,
                CounterValue::Unsigned(self.stash_total_capacity.load(Ordering::Relaxed)),
            ),
        ]
    }
}

impl SubQuadGen {
    // return false if flow out of window
    fn move_window(&mut self, time_in_second: Duration) -> bool {
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
                    self.flush_stats(i);
                }
            } else {
                let slots_to_shift = slots_to_shift as usize;
                for i in 0..slots_to_shift {
                    self.flush_stats(i);
                }
                self.stashs.rotate_left(slots_to_shift);
            }
            self.window_start += Duration::from_secs(self.slot_interval * slots_to_shift as u64);
            debug!(
                "l7 qg window moved interval={} sys_ts={} flow_ts={:?} window={:?}",
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

    fn flush_stats(&mut self, stash_index: usize) {
        self.stashs.push_back(QuadrupleStash::new());
        let mut stash = self.stashs.swap_remove_back(stash_index).unwrap();
        stash.l7_stats.clear();
        if !stash.meters.is_empty() {
            if let Err(_) = self.l7_output.send_large(stash.meters) {
                debug!("l7 qg push l7 stats to queue failed maybe queue have terminated");
            }
        }
    }

    fn flush_all_stats(&mut self) {
        for i in 0..self.stashs.len() {
            self.flush_stats(i);
        }
    }

    fn calc_stash_counters(&self) {
        let mut len = 0;
        let mut cap = 0;
        for s in self.stashs.iter() {
            len += s.l7_stats.len();
            cap += s.l7_stats.capacity();
        }
        self.counter
            .stash_total_len
            .store(len as u64, Ordering::Relaxed);
        self.counter
            .stash_total_capacity
            .store(cap as u64, Ordering::Relaxed);
    }

    pub fn inject_app_meter(
        &mut self,
        l7_stats: &L7Stats,
        app_meter: &AppMeter,
        endpoint_hash: u32,
        time_in_second: Duration,
        possible_host: &mut PossibleHost,
    ) {
        if time_in_second < self.window_start {
            self.counter
                .drop_before_window
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        let slot = (((time_in_second - self.window_start).as_secs() / self.slot_interval) as usize)
            .min(self.stashs.len() - 1);
        let stash = &mut self.stashs[slot];
        let value = stash.l7_stats.get_mut(&l7_stats.flow_id);
        if let Some(meters) = value {
            if let Some(meter) = meters.iter_mut().find(|m| m.endpoint == l7_stats.endpoint) {
                // flow L7Protocol of different client ports on the same server port may be inconsistent.
                // unknown l7_protocol needs to be judged by the close_type and duration of the flow,
                // so the L7Protocol of the same flow may be different. The principles are as follows:
                // 1. Unknown l7_protocol can be overwritten by any protocol.
                if l7_stats.l7_protocol == meter.l7_protocol {
                    meter.app_meter.sequential_merge(app_meter);
                } else if meter.l7_protocol == L7Protocol::Unknown {
                    meter.l7_protocol = l7_stats.l7_protocol;
                    meter.app_meter = *app_meter;
                }
            } else {
                let meter = AppMeterWithL7Protocol {
                    app_meter: *app_meter,
                    l7_protocol: l7_stats.l7_protocol,
                    endpoint: l7_stats.endpoint.clone(),
                    endpoint_hash,
                };
                meters.push(meter);
            }

            // If l7_stats.flow.is_some(), set the flow of all meter belonging to this flow
            if let Some(tagged_flow) = &l7_stats.flow {
                let flow = MiniFlow::from(&tagged_flow.flow);
                let (is_active_host0, is_active_host1) =
                    check_active(time_in_second.as_secs(), possible_host, &flow);
                for meter in meters.drain(..) {
                    let app_meter = Box::new(AppMeterWithFlow {
                        app_meter: meter.app_meter,
                        flow: flow.clone(),
                        l7_protocol: meter.l7_protocol,
                        endpoint_hash: meter.endpoint_hash,
                        endpoint: meter.endpoint,
                        is_active_host0,
                        is_active_host1,
                        time_in_second: tagged_flow.flow.flow_stat_time,
                    });
                    stash.meters.push(app_meter);
                }
            }
        } else {
            // app_meter.traffic.request and app_meter.traffic.response are 0, there is no need to save
            if app_meter.traffic.request == 0 && app_meter.traffic.response == 0 {
                return;
            }
            // If l7_stats.flow.is_some(), set the flow of all meter belonging to this flow
            if let Some(tagged_flow) = &l7_stats.flow {
                let flow = MiniFlow::from(&tagged_flow.flow);
                let (is_active_host0, is_active_host1) =
                    check_active(time_in_second.as_secs(), possible_host, &flow);
                let boxed_app_meter = Box::new(AppMeterWithFlow {
                    app_meter: *app_meter,
                    flow,
                    l7_protocol: l7_stats.l7_protocol,
                    endpoint_hash,
                    endpoint: l7_stats.endpoint.clone(),
                    is_active_host0,
                    is_active_host1,
                    time_in_second: tagged_flow.flow.flow_stat_time,
                });
                stash.meters.push(boxed_app_meter);
            } else {
                let meter = AppMeterWithL7Protocol {
                    app_meter: *app_meter,
                    l7_protocol: l7_stats.l7_protocol,
                    endpoint: l7_stats.endpoint.clone(),
                    endpoint_hash,
                };
                let _ = stash.l7_stats.insert(l7_stats.flow_id, vec![meter]);
            }
        }
    }
}

pub struct L7QuadrupleGeneratorThread {
    id: usize,
    l7_stats_input: Arc<Receiver<BatchedBox<L7Stats>>>,
    l7_second_output: DebugSender<Box<AppMeterWithFlow>>,
    l7_minute_output: DebugSender<Box<AppMeterWithFlow>>,
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

impl L7QuadrupleGeneratorThread {
    pub fn new(
        id: usize,
        l7_stats_input: Receiver<BatchedBox<L7Stats>>,
        l7_second_output: DebugSender<Box<AppMeterWithFlow>>,
        l7_minute_output: DebugSender<Box<AppMeterWithFlow>>,
        metrics_type: MetricsType,
        second_delay_seconds: u64,
        minute_delay_seconds: u64,
        possible_host_size: usize,
        config: CollectorAccess,
        ntp_diff: Arc<AtomicI64>,
        stats: Arc<Collector>,
    ) -> Self {
        let running = Arc::new(AtomicBool::new(false));
        let conf = config.load();
        Self {
            id,
            l7_stats_input: Arc::new(l7_stats_input),
            l7_second_output: l7_second_output.clone(),
            l7_minute_output: l7_minute_output.clone(),
            metrics_type,
            second_delay_seconds,
            minute_delay_seconds,
            possible_host_size,
            l7_metrics_enabled: Arc::new(AtomicBool::new(conf.l7_metrics_enabled)),
            vtap_flow_1s_enabled: Arc::new(AtomicBool::new(conf.vtap_flow_1s_enabled)),
            collector_enabled: Arc::new(AtomicBool::new(conf.enabled)),
            thread_handle: None,
            running,
            config,
            ntp_diff,
            stats,
        }
    }

    pub fn start(&mut self) {
        if self.running.swap(true, Ordering::Relaxed) {
            warn!(
                "l7 quadruple generator id: {} already started, do nothing.",
                self.id
            );
            return;
        }

        let mut l7_quadruple_generator = L7QuadrupleGenerator::new(
            self.id,
            self.l7_stats_input.clone(),
            self.l7_second_output.clone(),
            self.l7_minute_output.clone(),
            self.metrics_type,
            self.second_delay_seconds,
            self.minute_delay_seconds,
            self.possible_host_size,
            self.config.clone(),
            self.running.clone(),
            self.ntp_diff.clone(),
            self.stats.clone(),
        );
        self.thread_handle = Some(
            thread::Builder::new()
                .name("l7-quadruple-generator".to_owned())
                .spawn(move || l7_quadruple_generator.handler_routine())
                .unwrap(),
        );
        info!("l7 quadruple generator id: {} started", self.id);
    }

    pub fn notify_stop(&mut self) -> Option<JoinHandle<()>> {
        if !self.running.swap(false, Ordering::Relaxed) {
            warn!(
                "l7 quadruple generator id: {} already stopped, do nothing.",
                self.id
            );
            return None;
        }
        info!("notified stopping l7 quadruple generator: {}", self.id);
        self.thread_handle.take()
    }

    pub fn stop(&mut self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            warn!(
                "l7 quadruple generator id: {} already stopped, do nothing.",
                self.id
            );
            return;
        }
        info!("stopping l7 quadruple generator: {}", self.id);
        let _ = self.thread_handle.take().unwrap().join();
        info!("stopped l7 quadruple generator: {}", self.id);
    }
}

pub struct L7QuadrupleGenerator {
    id: usize,
    l7_stats_input: Arc<Receiver<BatchedBox<L7Stats>>>,
    name: String,
    second_quad_gen: Option<SubQuadGen>,
    minute_quad_gen: Option<SubQuadGen>,
    possible_host: PossibleHost,
    config: CollectorAccess,
    running: Arc<AtomicBool>,
    ntp_diff: Arc<AtomicI64>,
    stats: Arc<Collector>,
}

impl L7QuadrupleGenerator {
    pub fn new(
        id: usize,
        l7_stats_input: Arc<Receiver<BatchedBox<L7Stats>>>,
        l7_second_output: DebugSender<Box<AppMeterWithFlow>>,
        l7_minute_output: DebugSender<Box<AppMeterWithFlow>>,
        metrics_type: MetricsType,
        second_delay_seconds: u64,
        minute_delay_seconds: u64,
        possible_host_size: usize,
        config: CollectorAccess,
        running: Arc<AtomicBool>,
        ntp_diff: Arc<AtomicI64>,
        stats: Arc<Collector>,
    ) -> Self {
        let collector_config = config.load();
        info!("new l7 quadruple_generator id: {}, second_delay: {}, minute_delay: {}, l7_metrics_enabled: {}, vtap_flow_1s_enabled: {} collector_enabled: {}", id, second_delay_seconds, minute_delay_seconds, collector_config.l7_metrics_enabled, collector_config.vtap_flow_1s_enabled, collector_config.enabled);
        if minute_delay_seconds < SECONDS_IN_MINUTE || minute_delay_seconds >= SECONDS_IN_MINUTE * 2
        {
            panic!("minute_delay_seconds must be in [60, 120)s")
        }

        let second_slots = second_delay_seconds as usize;
        let minute_slots = 2 as usize;
        let mut second_quad_gen = None;
        let mut minute_quad_gen = None;
        let window_start = round_to_minute(get_timestamp(ntp_diff.load(Ordering::Relaxed)))
            - Duration::from_secs(2 * SECONDS_IN_MINUTE);

        if metrics_type.contains(MetricsType::SECOND) {
            let mut quad_gen = SubQuadGen {
                id,
                l7_output: l7_second_output,
                metrics_type: MetricsType::SECOND,
                window_start,
                slot_interval: 1,
                number_of_slots: second_slots as u64,
                delay_seconds: second_delay_seconds,
                stashs: VecDeque::with_capacity(second_slots),
                counter: Arc::new(QgCounter::default()),
                ntp_diff: ntp_diff.clone(),
                // traffic_setter: traffic_setter,
            };

            for _ in 0..second_slots {
                quad_gen.stashs.push_back(QuadrupleStash::new());
            }
            stats.register_countable(
                "quadruple_generator",
                Countable::Ref(Arc::downgrade(&quad_gen.counter) as Weak<dyn RefCountable>),
                vec![
                    StatsOption::Tag("kind", "l7_second".to_owned()),
                    StatsOption::Tag("index", id.to_string()),
                ],
            );
            second_quad_gen = Some(quad_gen);
        }

        if metrics_type.contains(MetricsType::MINUTE) {
            let mut quad_gen = SubQuadGen {
                id,
                l7_output: l7_minute_output,
                metrics_type: MetricsType::MINUTE,
                window_start,
                slot_interval: 60,
                number_of_slots: minute_slots as u64,
                delay_seconds: minute_delay_seconds,
                stashs: VecDeque::with_capacity(minute_slots),
                counter: Arc::new(QgCounter::default()),
                ntp_diff: ntp_diff.clone(),
                // traffic_setter: traffic_setter,
            };

            for _ in 0..minute_slots {
                quad_gen.stashs.push_back(QuadrupleStash::new());
            }
            stats.register_countable(
                "quadruple_generator",
                Countable::Ref(Arc::downgrade(&quad_gen.counter) as Weak<dyn RefCountable>),
                vec![
                    StatsOption::Tag("kind", "l7_minute".to_owned()),
                    StatsOption::Tag("index", id.to_string()),
                ],
            );
            minute_quad_gen = Some(quad_gen);
        }

        L7QuadrupleGenerator {
            id,
            l7_stats_input,
            name: "quadruple_generator".to_string(),
            second_quad_gen,
            minute_quad_gen,
            possible_host: PossibleHost::new(possible_host_size),
            config,
            running,
            ntp_diff,
            stats,
        }
    }

    fn handle(
        &mut self,
        config: &CollectorConfig,
        l7_stats: Option<BatchedBox<L7Stats>>,
        time_in_second: Duration,
    ) {
        let mut second_inject = false;
        let mut minute_inject = false;
        if config.vtap_flow_1s_enabled {
            if let Some(s) = self.second_quad_gen.as_mut() {
                second_inject = s.move_window(time_in_second);
            }
        }
        if let Some(s) = self.minute_quad_gen.as_mut() {
            minute_inject = s.move_window(time_in_second);
        }

        if l7_stats.is_none() || !(second_inject || minute_inject) {
            return;
        }
        let l7_stats = l7_stats.unwrap();

        let endpoint_hash = match &l7_stats.endpoint {
            Some(e) => hash_to_u64(e) as u32,
            None => 0,
        };

        let app_meter = if config.l7_metrics_enabled {
            Self::generate_app_meter(&l7_stats)
        } else {
            AppMeter::default()
        };

        if second_inject {
            self.second_quad_gen.as_mut().unwrap().inject_app_meter(
                &l7_stats,
                &app_meter,
                endpoint_hash,
                time_in_second,
                &mut self.possible_host,
            );
        }

        if minute_inject {
            self.minute_quad_gen.as_mut().unwrap().inject_app_meter(
                &l7_stats,
                &app_meter,
                endpoint_hash,
                time_in_second,
                &mut self.possible_host,
            );
        }
    }

    fn generate_app_meter(l7_stats: &L7Stats) -> AppMeter {
        let (close_type, direction_score) = if let Some(tagged_flow) = &l7_stats.flow {
            (
                tagged_flow.flow.close_type,
                tagged_flow.flow.direction_score,
            )
        } else {
            (CloseType::ForcedReport, 0)
        };
        let stats = &l7_stats.stats;
        match (l7_stats.l7_protocol, l7_stats.signal_source) {
            (
                L7Protocol::Unknown,
                SignalSource::Packet | SignalSource::EBPF | SignalSource::XFlow,
            ) => {
                // only L7Protocol is Unknown or Other and SignalSource != Otel will execute the following logic
                AppMeter {
                    traffic: AppTraffic {
                        request: (close_type != CloseType::ForcedReport) as u32,
                        response: (close_type != CloseType::ForcedReport) as u32,
                        direction_score,
                    },
                    ..Default::default()
                }
            }
            (_, _) => AppMeter {
                traffic: AppTraffic {
                    request: stats.request_count,
                    response: stats.response_count,
                    direction_score: direction_score,
                },
                latency: AppLatency {
                    rrt_max: stats.rrt_max,
                    rrt_sum: stats.rrt_sum as u64,
                    rrt_count: stats.rrt_count,
                },
                anomaly: AppAnomaly {
                    client_error: stats.err_client_count,
                    server_error: stats.err_server_count,
                    timeout: stats.err_timeout,
                },
            },
        }
    }

    fn handler_routine(&mut self) {
        let mut l7_recv_batch = Vec::with_capacity(QUEUE_BATCH_SIZE);
        while self.running.load(Ordering::Relaxed) {
            let config = self.config.load();
            match self
                .l7_stats_input
                .recv_all(&mut l7_recv_batch, Some(RCV_TIMEOUT))
            {
                Ok(_) => {
                    if config.enabled {
                        for l7_stat in l7_recv_batch.drain(..) {
                            let time_in_second = l7_stat.time_in_second;
                            self.handle(&config, Some(l7_stat), time_in_second);
                        }
                    } else {
                        l7_recv_batch.clear();
                    }
                    if let Some(g) = self.second_quad_gen.as_ref() {
                        g.calc_stash_counters();
                    }
                    if let Some(g) = self.minute_quad_gen.as_mut() {
                        g.calc_stash_counters();
                    }
                }
                Err(Error::Timeout) => {
                    self.handle(
                        &config,
                        None,
                        get_timestamp(self.ntp_diff.load(Ordering::Relaxed)),
                    );
                }
                Err(Error::Terminated(_, _)) => {
                    if let Some(g) = self.second_quad_gen.as_mut() {
                        g.flush_all_stats();
                    }
                    if let Some(g) = self.minute_quad_gen.as_mut() {
                        g.flush_all_stats();
                    }
                    break;
                }
                Err(Error::BatchTooLarge(_)) => unreachable!(),
            }
        }
    }
}
