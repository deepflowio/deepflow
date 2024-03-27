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

use std::any::Any;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::Arc;

use public::{
    counter,
    l7_protocol::{L7Protocol, L7ProtocolChecker},
};

pub trait Downcast {
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

pub trait CacheItem: Downcast {
    // Distinguish different flows
    fn get_id(&self) -> u64;
    // Used for sorting
    fn get_seq(&self) -> u64;
    // Time in seconds
    fn get_timestmap(&self) -> u64;
    fn get_l7_protocol(&self) -> L7Protocol;
}

struct CacheNode {
    cache: VecDeque<Option<Box<dyn CacheItem>>>,
    start: u64,
    last_timestamp: u64,

    counter: Arc<ReorderCounter>,
    cache_size: usize,
    enabled: bool,
}

impl CacheNode {
    fn new(
        item: Box<dyn CacheItem>,
        enabled: bool,
        cache_size: usize,
        counter: Arc<ReorderCounter>,
    ) -> Self {
        let mut cache = VecDeque::with_capacity(cache_size);
        for _ in 0..cache_size {
            cache.push_back(None);
        }
        counter.packet_couter.fetch_add(1, Relaxed);
        let mut start = item.get_seq();
        if start < cache_size as u64 {
            start = 0;
        } else {
            start -= cache_size as u64 + 1;
        }
        let offset = item.get_seq() - start;
        let mut node = Self {
            cache,
            start,
            last_timestamp: item.get_timestmap(),
            counter,
            cache_size,
            enabled,
        };
        node.cache[offset as usize] = Some(item);
        node
    }

    fn flush(&mut self, count: usize) -> Vec<Box<dyn CacheItem>> {
        self.start += count as u64;

        let count = count.min(self.cache_size);
        let mut items = vec![];
        for _ in 0..count {
            if let Some(i) = self.cache.pop_front().unwrap() {
                items.push(i);
                self.counter.packet_couter.fetch_sub(1, Relaxed);
            }
            self.cache.push_back(None);
        }

        items
    }

    fn add(&mut self, item: Box<dyn CacheItem>, enabled: bool) -> (u64, Vec<Box<dyn CacheItem>>) {
        let seq = item.get_seq();
        if seq < self.start {
            self.counter.drop_out_of_order.fetch_add(1, Relaxed);
            return (self.last_timestamp, vec![]);
        }
        let mut offset = seq - self.start;
        let mut out = vec![];
        if offset >= self.cache_size as u64 {
            out = self.flush(offset as usize - self.cache_size + 1);
            offset = item.get_seq() - self.start;
        }
        let last_timestmap = self.last_timestamp;
        self.last_timestamp = item.get_timestmap();
        self.cache[offset as usize] = Some(item);
        self.enabled = self.enabled || enabled;

        self.counter.packet_couter.fetch_add(1, Relaxed);

        if out.len() == 0 && !self.enabled {
            out = self.flush(self.cache_size);
        }

        (last_timestmap, out)
    }
}

#[derive(Default)]
pub struct ReorderCounter {
    drop_before_window: AtomicU64,
    drop_out_of_order: AtomicU64,
    flow_counter: AtomicU64,
    packet_couter: AtomicU64,
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
                counter::CounterValue::Unsigned(self.0.packet_couter.load(Relaxed)),
            ),
        ]
    }
}

pub struct Reorder {
    cache: HashMap<u64, CacheNode>,
    windows: VecDeque<HashSet<u64>>, // time in seconds
    window_start: u64,
    last_flush_timestamp: u64, // time in seconds

    counter: Arc<ReorderCounter>,
    checker: Box<dyn L7ProtocolChecker>,
    cache_size: usize,
}

impl Reorder {
    const TIMEOUT: u64 = 5;
    const WINDOW_SIZE: u64 = Self::TIMEOUT;

    pub fn new(
        checker: Box<dyn L7ProtocolChecker>,
        counter: Arc<ReorderCounter>,
        cache_size: usize,
    ) -> Self {
        let mut windows = VecDeque::with_capacity(Self::WINDOW_SIZE as usize);
        for _ in 0..Self::TIMEOUT as usize {
            windows.push_back(HashSet::new());
        }
        Self {
            cache: HashMap::new(),
            windows,
            window_start: 0,
            last_flush_timestamp: 0,
            counter,
            checker,
            cache_size,
        }
    }

    fn window_change(&mut self, last: u64, now: u64, id: u64) {
        self.window_delete(last, id);
        self.window_add(now, id);
    }

    fn window_delete(&mut self, timestamp: u64, id: u64) {
        let offset = timestamp - self.window_start;
        self.windows[offset as usize].remove(&id);
    }

    fn window_add(&mut self, timestamp: u64, id: u64) {
        let mut offset = timestamp - self.window_start;
        if offset >= Self::WINDOW_SIZE {
            self.flush(timestamp);
            offset = timestamp - self.window_start;
        }
        self.windows[offset as usize].insert(id);
    }

    pub fn flush(&mut self, now: u64) -> Vec<Box<dyn CacheItem>> {
        if now < self.window_start {
            self.counter.drop_before_window.fetch_add(1, Relaxed);
            return vec![];
        }
        self.last_flush_timestamp = now;
        let offset = now - self.window_start;
        let mut items = vec![];
        if offset >= Self::WINDOW_SIZE {
            let count = offset - Self::WINDOW_SIZE + 1;
            self.window_start += count;
            for _ in 0..count.min(Self::WINDOW_SIZE) {
                let Some(mut window) = self.windows.pop_front() else {
                    break;
                };
                self.counter
                    .flow_counter
                    .fetch_sub(window.len() as u64, Relaxed);
                for id in window.drain() {
                    if let Some(mut node) = self.cache.remove(&id) {
                        items.append(&mut node.flush(self.cache_size));
                    }
                }
                self.windows.push_back(window);
            }
        }

        items
    }

    pub fn inject_item(&mut self, item: Box<dyn CacheItem>) -> Vec<Box<dyn CacheItem>> {
        let id = item.get_id();
        let timestamp = item.get_timestmap();
        if timestamp < self.window_start {
            self.counter.drop_before_window.fetch_add(1, Relaxed);
            return vec![];
        }

        let enabled = self.checker.is_enabled(item.get_l7_protocol());
        if let Some(node) = self.cache.get_mut(&id) {
            let (last_timestamp, out) = node.add(item, enabled);
            self.window_change(last_timestamp, timestamp, id);
            return out;
        } else {
            let node = CacheNode::new(item, enabled, self.cache_size, self.counter.clone());
            self.cache.insert(id, node);
            self.window_add(timestamp, id);
            self.counter.flow_counter.fetch_add(1, Relaxed);
        }
        vec![]
    }
}

impl Drop for Reorder {
    fn drop(&mut self) {
        self.counter.closed.store(true, Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering::Relaxed;
    use std::sync::Arc;

    use super::{CacheItem, Downcast, Reorder, ReorderCounter};

    #[derive(PartialEq)]
    struct A {
        seq: u64,
        timestamp: u64,
    }

    impl A {
        fn new(seq: u64, timestamp: u64) -> Self {
            Self { seq, timestamp }
        }
    }

    impl Downcast for A {
        fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
            self
        }

        fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
            self
        }
    }

    impl CacheItem for A {
        fn get_id(&self) -> u64 {
            10
        }

        fn get_seq(&self) -> u64 {
            self.seq
        }

        fn get_timestmap(&self) -> u64 {
            self.timestamp
        }
    }

    #[test]
    fn test_normal() {
        let counter = Arc::new(ReorderCounter::default());
        let mut reorder = Reorder::new(counter.clone(), 16);
        let node1 = Box::new(A::new(0, 1000));
        let node2 = Box::new(A::new(2, 1000));
        reorder.inject_item(node1);
        reorder.inject_item(node2);

        assert_eq!(counter.flow_counter.load(Relaxed), 1);
        assert_eq!(counter.packet_couter.load(Relaxed), 2);

        let mut nodes = reorder.flush(2000);
        let nodes = nodes
            .iter_mut()
            .map(|x| x.as_any_mut().downcast_mut::<A>().unwrap())
            .collect::<Vec<&mut A>>();
        assert_eq!(nodes[0].as_ref().unwrap().seq, 0);
        assert_eq!(nodes[1].as_ref().unwrap().seq, 2);
        assert_eq!(reorder.window_start, 1996);
        assert_eq!(reorder.cache.len(), 0);
        assert_eq!(counter.flow_counter.load(Relaxed), 0);
        assert_eq!(counter.packet_couter.load(Relaxed), 0);
    }

    #[test]
    fn test_cache() {
        let counter = Arc::new(ReorderCounter::default());
        let mut reorder = Reorder::new(counter.clone(), 16);
        let node1 = Box::new(A::new(0, 1000));
        let node2 = Box::new(A::new(2, 1000));
        let node3 = Box::new(A::new(20, 1000));
        reorder.inject_item(node1);
        reorder.inject_item(node2);
        let mut nodes = reorder.inject_item(node3);
        assert_eq!(counter.flow_counter.load(Relaxed), 1);
        assert_eq!(counter.packet_couter.load(Relaxed), 1);

        let nodes = nodes
            .iter_mut()
            .map(|x| x.as_any_mut().downcast_mut::<A>().unwrap())
            .collect::<Vec<&mut A>>();
        assert_eq!(nodes[0].as_ref().unwrap().seq, 0);
        assert_eq!(nodes[1].as_ref().unwrap().seq, 2);
        assert_eq!(reorder.cache.iter().all(|f| f.1.start == 5), true);
        assert_eq!(counter.flow_counter.load(Relaxed), 1);
        assert_eq!(counter.packet_couter.load(Relaxed), 1);
    }
}
