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

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::Arc;

use public::packet::Downcast;
use public::{
    counter,
    l7_protocol::{L7Protocol, L7ProtocolChecker},
};

pub trait CacheItem: Downcast {
    // Distinguish different flows
    fn get_id(&self) -> u64;
    // Used for sorting
    fn get_seq(&self) -> u64;
    // Time in millis seconds
    fn get_timestmap(&self) -> u64;
    fn get_l7_protocol(&self) -> L7Protocol;
    fn is_segment_start(&self) -> bool;
}

#[derive(Default)]
pub struct ReorderCounter {
    drop_before_window: AtomicU64,
    drop_out_of_order: AtomicU64,
    flow_counter: AtomicU64,
    packet_counter: AtomicU64,
    max_seq_gap: AtomicU64,
    closed: AtomicBool,
}

pub struct StatsReorderCounter(Arc<ReorderCounter>);

impl StatsReorderCounter {
    pub fn new(count: Arc<ReorderCounter>) -> Self {
        Self(count)
    }
}

impl counter::OwnedCountable for StatsReorderCounter {
    fn closed(&self) -> bool {
        self.0.closed.load(Relaxed)
    }

    fn get_counters(&self) -> Vec<counter::Counter> {
        vec![
            (
                "drop-before-window",
                counter::CounterType::Counted,
                counter::CounterValue::Unsigned(self.0.drop_before_window.swap(0, Relaxed)),
            ),
            (
                "drop-out-of-order",
                counter::CounterType::Counted,
                counter::CounterValue::Unsigned(self.0.drop_out_of_order.swap(0, Relaxed)),
            ),
            (
                "flow-counter",
                counter::CounterType::Counted,
                counter::CounterValue::Unsigned(self.0.flow_counter.load(Relaxed)),
            ),
            (
                "packet-counter",
                counter::CounterType::Counted,
                counter::CounterValue::Unsigned(self.0.packet_counter.load(Relaxed)),
            ),
            (
                "max-seq-gap",
                counter::CounterType::Counted,
                counter::CounterValue::Unsigned(self.0.max_seq_gap.swap(0, Relaxed)),
            ),
        ]
    }
}

pub struct Reorder {
    counter: Arc<ReorderCounter>,
}

impl Reorder {
    pub fn new(_: Box<dyn L7ProtocolChecker>, counter: Arc<ReorderCounter>, _: usize) -> Self {
        Self { counter }
    }

    pub fn flush(&mut self, _: u64) -> Vec<Box<dyn CacheItem>> {
        vec![]
    }

    pub fn inject_item(&mut self, item: Box<dyn CacheItem>) -> Vec<Box<dyn CacheItem>> {
        vec![item]
    }
}

impl Drop for Reorder {
    fn drop(&mut self) {
        self.counter.closed.store(true, Relaxed);
    }
}
