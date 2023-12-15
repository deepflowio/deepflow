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

use std::collections::{HashMap, VecDeque};
use std::sync::{
    atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;
use thread::JoinHandle;

use arc_swap::access::Access;
use log::{debug, info, warn};
use npb_pcap_policy::NpbTunnelType;
use rand::prelude::{Rng, SeedableRng, SmallRng};

use super::consts::*;

use crate::collector::types::U16Set;
use crate::common::Timestamp;
use crate::common::{
    enums::TapType,
    flow::CloseType,
    tagged_flow::{BoxedTaggedFlow, TaggedFlow},
};
use crate::config::handler::CollectorAccess;
use crate::rpc::get_timestamp;
use crate::utils::stats::{Counter, CounterType, CounterValue, RefCountable};
use public::{
    buffer::BatchedBox,
    queue::{DebugSender, Error, Receiver},
};

const TIMESTAMP_SLOT_COUNT: usize = SECONDS_IN_MINUTE as usize;
const QUEUE_READ_TIMEOUT: Duration = Duration::from_secs(1); // Must be less than or equal to FLUSH_TIMEOUT
const FLUSH_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Default)]
pub struct FlowAggrCounter {
    drop_before_window: AtomicU64,
    out: AtomicU64,
    drop_in_throttle: AtomicU64,
    stash_total_len: AtomicU64,
    stash_total_capacity: AtomicU64,
    stash_shrinks: AtomicU64,
}

pub struct FlowAggrThread {
    id: usize,
    input: Arc<Receiver<Arc<BatchedBox<TaggedFlow>>>>,
    output: DebugSender<BoxedTaggedFlow>,
    config: CollectorAccess,

    thread_handle: Option<JoinHandle<()>>,

    running: Arc<AtomicBool>,
    ntp_diff: Arc<AtomicI64>,

    metrics: Arc<FlowAggrCounter>,
}

impl FlowAggrThread {
    pub fn new(
        id: usize,
        input: Receiver<Arc<BatchedBox<TaggedFlow>>>,
        output: DebugSender<BoxedTaggedFlow>,
        config: CollectorAccess,
        ntp_diff: Arc<AtomicI64>,
    ) -> (Self, Arc<FlowAggrCounter>) {
        let running = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(FlowAggrCounter::default());
        (
            Self {
                id,
                input: Arc::new(input),
                output: output.clone(),
                thread_handle: None,
                config,
                running,
                ntp_diff,
                metrics: metrics.clone(),
            },
            metrics,
        )
    }

    pub fn start(&mut self) {
        if self.running.swap(true, Ordering::Relaxed) {
            warn!("l4 flow aggr id: {} already started, do nothing.", self.id);
            return;
        }

        let mut flow_aggr = FlowAggr::new(
            self.input.clone(),
            self.output.clone(),
            self.running.clone(),
            self.config.clone(),
            self.ntp_diff.clone(),
            self.metrics.clone(),
        );
        self.thread_handle = Some(
            thread::Builder::new()
                .name("flow-aggr".to_owned())
                .spawn(move || flow_aggr.run())
                .unwrap(),
        );
        info!("l4 flow aggr id: {} started", self.id);
    }

    pub fn notify_stop(&mut self) -> Option<JoinHandle<()>> {
        if !self.running.swap(false, Ordering::Relaxed) {
            warn!("l4 flow aggr id: {} already stopped, do nothing.", self.id);
            return None;
        }
        info!("notify stopping l4 flow aggr: {}", self.id);
        self.thread_handle.take()
    }

    pub fn stop(&mut self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            warn!("l4 flow aggr id: {} already stopped, do nothing.", self.id);
            return;
        }
        info!("stopping l4 flow aggr: {}", self.id);
        let _ = self.thread_handle.take().unwrap().join();
        info!("stopped l4 flow aggr: {}", self.id);
    }
}

pub struct FlowAggr {
    input: Arc<Receiver<Arc<BatchedBox<TaggedFlow>>>>,
    output: ThrottlingQueue,
    slot_start_time: Duration,
    flow_stashs: VecDeque<HashMap<u64, Box<TaggedFlow>>>,
    stash_init_capacity: usize,
    slot_count: usize,

    flush_timeout: Duration,
    last_flush_time: Duration,
    config: CollectorAccess,

    running: Arc<AtomicBool>,

    ntp_diff: Arc<AtomicI64>,
    metrics: Arc<FlowAggrCounter>,
}

impl FlowAggr {
    // record stash size in last N flushes to determine shrinking size
    const HISTORY_RECORD_COUNT: usize = 10;
    const MIN_STASH_CAPACITY_SECOND: usize = 1024;

    pub fn new(
        input: Arc<Receiver<Arc<BatchedBox<TaggedFlow>>>>,
        output: DebugSender<BoxedTaggedFlow>,
        running: Arc<AtomicBool>,
        config: CollectorAccess,
        ntp_diff: Arc<AtomicI64>,
        metrics: Arc<FlowAggrCounter>,
    ) -> Self {
        let slot_count = TIMESTAMP_SLOT_COUNT + config.load().packet_delay.as_secs() as usize + 1;
        let mut flow_stashs = VecDeque::with_capacity(slot_count);
        for _ in 0..slot_count {
            flow_stashs.push_back(HashMap::with_capacity(Self::MIN_STASH_CAPACITY_SECOND));
        }
        Self {
            input,
            output: ThrottlingQueue::new(output, config.clone()),
            flow_stashs,
            stash_init_capacity: Self::MIN_STASH_CAPACITY_SECOND,
            slot_start_time: Duration::ZERO,
            flush_timeout: Duration::from_secs(slot_count as u64),
            last_flush_time: Duration::ZERO,
            config,
            running,
            metrics,
            ntp_diff,
            slot_count,
        }
    }

    fn minute_merge(&mut self, f: Arc<BatchedBox<TaggedFlow>>) {
        let f = f.as_ref();
        let flow_time = Timestamp::from_secs(f.flow.start_time_in_minute());
        if flow_time < self.slot_start_time {
            debug!("flow drop before slot start time. flow stat time: {:?}, slot start time is {:?}, delay is {:?}", flow_time, self.slot_start_time, self.slot_start_time - flow_time);
            self.metrics
                .drop_before_window
                .fetch_add(1, Ordering::Relaxed);
            return;
        }

        let mut time_slot = (flow_time - self.slot_start_time).as_secs() as usize;
        if time_slot >= self.slot_count {
            let flush_count = time_slot - self.slot_count + 1;
            self.flush_slots(flush_count);
            time_slot = self.slot_count - 1;
        }

        let flow_stash = &mut self.flow_stashs[time_slot];
        let flow_id = f.flow.flow_id;
        if let Some(flow) = flow_stash.get_mut(&flow_id) {
            if flow.flow.reversed != f.flow.reversed {
                flow.reverse();
                if let Some(stats) = flow.flow.flow_perf_stats.as_mut() {
                    stats.reverse();
                }
            }
            flow.sequential_merge(&f);
            if flow.flow.close_type != CloseType::ForcedReport {
                if let Some(closed_flow) = flow_stash.remove(&flow_id) {
                    self.send_flow(closed_flow);
                }
            }
        } else {
            if f.flow.close_type != CloseType::ForcedReport {
                self.send_flow(Box::new(f.as_ref().clone()));
            } else {
                flow_stash.insert(f.flow.flow_id, Box::new(f.as_ref().clone()));
            }
        }
    }

    fn send_flow(&mut self, mut f: Box<TaggedFlow>) {
        // We use acl_gid to mark which flows are configured with PCAP storage policies.
        // Since acl_gid is used for both PCAP and NPB functions, only the acl_gid used by PCAP is sent here.
        let mut acl_gids = U16Set::new();
        for policy_data in f.tag.policy_data.iter() {
            let Some(policy_data) = policy_data else {
                continue;
            };
            if !policy_data.contain_pcap() {
                continue;
            }
            for action in policy_data.npb_actions.iter() {
                if action.tunnel_type() != NpbTunnelType::Pcap {
                    continue;
                }
                for gid in action.acl_gids().iter() {
                    acl_gids.add(*gid);
                }
            }
        }
        f.flow.acl_gids = Vec::from(acl_gids.list());

        if !f.flow.is_new_flow {
            f.flow.start_time = Timestamp::from_secs(f.flow.start_time_in_minute());
        }

        if f.flow.close_type == CloseType::ForcedReport {
            // Align time to seconds
            f.flow.end_time = Timestamp::from_secs(f.flow.start_time.as_secs() + SECONDS_IN_MINUTE);
        }

        self.metrics.out.fetch_add(1, Ordering::Relaxed);

        let now = get_timestamp(self.ntp_diff.load(Ordering::Relaxed));
        self.output.flush_cache_with_throttling(&now);
        self.output.flush_cache_without_throttling(&now);
        if f.flow.hit_pcap_policy() {
            self.output.send_without_throttling(f);
        } else {
            if !self.output.send_with_throttling(f) {
                self.metrics
                    .drop_in_throttle
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn flush_front_slot_and_rotate(&mut self) {
        let mut flow_stash = self.flow_stashs.pop_front().unwrap();

        for (_, flow) in flow_stash.drain() {
            self.send_flow(flow);
        }

        let stash_cap = self.flow_stashs.capacity();
        if stash_cap > self.stash_init_capacity {
            let stash_len = self.flow_stashs.len();
            if stash_cap > 2 * stash_len {
                // shrink stash if its capacity is larger than 2 times of the max stash length in the past HISTORY_RECORD_COUNT flushes
                self.metrics.stash_shrinks.fetch_add(1, Ordering::Relaxed);
                flow_stash.shrink_to(self.stash_init_capacity.max(2 * stash_len));
            }
        }

        self.flow_stashs.push_back(flow_stash);
        self.last_flush_time = get_timestamp(self.ntp_diff.load(Ordering::Relaxed));
        self.slot_start_time += Duration::from_secs(1);
    }

    fn flush_slots(&mut self, slot_count: usize) {
        for _ in 0..slot_count.min(self.slot_count) {
            self.flush_front_slot_and_rotate();
        }

        // 若移动数超过slot的数量后, 只需设置slot开始时间
        if slot_count > self.slot_count {
            self.slot_start_time += Duration::from_secs((slot_count - self.slot_count) as u64);
            info!(
                "now slot start time is {:?} have flushed minute slot count is {:?}",
                self.slot_start_time, slot_count
            );
        }
    }

    fn calc_stash_counters(&self) {
        self.metrics
            .stash_total_len
            .store(self.flow_stashs.len() as u64, Ordering::Relaxed);
        self.metrics
            .stash_total_capacity
            .store(self.flow_stashs.capacity() as u64, Ordering::Relaxed);
    }

    fn run(&mut self) {
        let mut batch = Vec::with_capacity(QUEUE_BATCH_SIZE);
        while self.running.load(Ordering::Relaxed) {
            match self.input.recv_all(&mut batch, Some(QUEUE_READ_TIMEOUT)) {
                Ok(_) => {
                    let config = self.config.load();
                    for tagged_flow in batch.drain(..) {
                        if config.l4_log_ignore_tap_sides[tagged_flow.flow.tap_side as usize] {
                            continue;
                        }
                        if config.l4_log_store_tap_types[u16::from(TapType::Any) as usize]
                            || config.l4_log_store_tap_types
                                [u16::from(tagged_flow.flow.flow_key.tap_type) as usize]
                        {
                            self.minute_merge(tagged_flow);
                        }
                    }
                    self.calc_stash_counters();
                }
                Err(Error::Timeout) => {
                    let now = get_timestamp(self.ntp_diff.load(Ordering::Relaxed));
                    self.output.flush_cache_with_throttling(&now);
                    self.output.flush_cache_without_throttling(&now);
                    if now > self.last_flush_time + self.flush_timeout {
                        self.flush_front_slot_and_rotate();
                    }
                }
                Err(Error::Terminated(..)) => {
                    break;
                }
                Err(Error::BatchTooLarge(_)) => unreachable!(),
            }
        }
    }
}

impl RefCountable for FlowAggrCounter {
    fn get_counters(&self) -> Vec<Counter> {
        vec![
            (
                "drop-before-window",
                CounterType::Counted,
                CounterValue::Unsigned(self.drop_before_window.swap(0, Ordering::Relaxed)),
            ),
            (
                "out",
                CounterType::Counted,
                CounterValue::Unsigned(self.out.swap(0, Ordering::Relaxed)),
            ),
            (
                "drop-in-throttle",
                CounterType::Counted,
                CounterValue::Unsigned(self.drop_in_throttle.swap(0, Ordering::Relaxed)),
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
            (
                "stash-shrinks",
                CounterType::Counted,
                CounterValue::Unsigned(self.stash_shrinks.swap(0, Ordering::Relaxed)),
            ),
        ]
    }
}

struct ThrottlingQueue {
    config: CollectorAccess,
    throttle: u64,

    small_rng: SmallRng,

    last_flush_cache_with_throttling_time: Duration,
    last_flush_cache_without_throttling_time: Duration,
    period_count: usize,
    output: DebugSender<BoxedTaggedFlow>,

    cache_with_throttling: Vec<BoxedTaggedFlow>,
    cache_without_throttling: Vec<BoxedTaggedFlow>,
}

impl ThrottlingQueue {
    const THROTTLE_BUCKET_BITS: u64 = 2;
    const THROTTLE_BUCKET: u64 = 1 << Self::THROTTLE_BUCKET_BITS; // 2^N。由于发送方是有突发的，需要累积一定时间做采样
    const MIN_L4_LOG_COLLECT_NPS_THRESHOLD: u64 = 100;
    const MAX_L4_LOG_COLLECT_NPS_THRESHOLD: u64 = 1000000;
    const CACHE_WITHOUT_THROTTLING_SIZE: usize = 1024;

    pub fn new(output: DebugSender<BoxedTaggedFlow>, config: CollectorAccess) -> Self {
        let t: u64 = config.load().l4_log_collect_nps_threshold * Self::THROTTLE_BUCKET;
        Self {
            config,
            throttle: t,

            small_rng: SmallRng::from_entropy(),

            last_flush_cache_with_throttling_time: Duration::ZERO,
            last_flush_cache_without_throttling_time: Duration::ZERO,
            period_count: 0,

            output,
            cache_with_throttling: Vec::with_capacity(t as usize),
            cache_without_throttling: Vec::with_capacity(Self::CACHE_WITHOUT_THROTTLING_SIZE),
        }
    }

    fn flush_cache_with_throttling(&mut self, now: &Duration) {
        if now.as_secs() >> Self::THROTTLE_BUCKET_BITS
            != self.last_flush_cache_with_throttling_time.as_secs() >> Self::THROTTLE_BUCKET_BITS
        {
            self.update_throttle();
            if let Err(_) = self.output.send_all(&mut self.cache_with_throttling) {
                debug!("l4 flow throttle push aggred flow to sender queue failed, maybe queue have terminated");
                self.cache_with_throttling.clear();
            }

            self.last_flush_cache_with_throttling_time = *now;
            self.period_count = 0;
        }
    }

    pub fn send_with_throttling(&mut self, f: Box<TaggedFlow>) -> bool {
        self.period_count += 1;
        if self.cache_with_throttling.len() < self.throttle as usize {
            self.cache_with_throttling.push(BoxedTaggedFlow(f));
            true
        } else {
            let r = self.small_rng.gen_range(0..self.period_count);
            if r < self.throttle as usize {
                self.cache_with_throttling[r] = BoxedTaggedFlow(f);
            }
            false
        }
    }

    fn flush_cache_without_throttling(&mut self, now: &Duration) {
        if self.cache_without_throttling.len() >= Self::CACHE_WITHOUT_THROTTLING_SIZE
            || now.as_secs() >> Self::THROTTLE_BUCKET_BITS
                != self.last_flush_cache_without_throttling_time.as_secs()
                    >> Self::THROTTLE_BUCKET_BITS
        {
            if let Err(_) = self.output.send_all(&mut self.cache_without_throttling) {
                debug!(
                    "l4 flow push aggred flow to sender queue failed, maybe queue have terminated"
                );
                self.cache_without_throttling.clear();
            }

            self.last_flush_cache_without_throttling_time = *now;
        }
    }

    pub fn send_without_throttling(&mut self, f: Box<TaggedFlow>) {
        self.cache_without_throttling.push(BoxedTaggedFlow(f));
    }

    pub fn update_throttle(&mut self) {
        let new = self.config.load().l4_log_collect_nps_threshold;
        if new < Self::MIN_L4_LOG_COLLECT_NPS_THRESHOLD
            || new > Self::MAX_L4_LOG_COLLECT_NPS_THRESHOLD
        {
            debug!(
                "l4 flow throttle {} is invalid, must in range[{}, {}]",
                new,
                Self::MIN_L4_LOG_COLLECT_NPS_THRESHOLD,
                Self::MAX_L4_LOG_COLLECT_NPS_THRESHOLD
            );
            return;
        }
        if self.throttle == new * Self::THROTTLE_BUCKET {
            return;
        }

        info!(
            "l4_log_collect_nps_threshold update from {} to  {}",
            self.throttle / Self::THROTTLE_BUCKET,
            new
        );
        self.throttle = new * Self::THROTTLE_BUCKET;
        self.cache_with_throttling.truncate(self.throttle as usize);
    }
}
