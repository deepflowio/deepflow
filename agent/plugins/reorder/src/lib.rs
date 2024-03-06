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

use std::collections::{HashMap, VecDeque, HashSet};
use std::time::Duration;
use std::any::Any;

const CACHE_SIZE: usize = 16;

pub trait Downcast {
    fn as_any_mut(&mut self) -> &mut dny Any;
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

pub trait CacheItem: Downcast {
    fn get_id(&self) -> u64;
    fn get_seq(&self) -> u64;
    fn get_timestmap(&self) -> Duration;
}

struct CacheNode {
   cache: [Option<Box<dyn CacheItem>>; CACHE_SIZE],
   start: u64,
   last_timestamp: u64,
}

impl CacheNode {
    fn new(item: Box<dyn CacheItem>) -> Self {
        let mut node = Self {
            cache: [None; CACHE_SIZE],
            start: item.get_seq(),
            last_timestamp: item.get_timestmap(),
        };
        node.cache[0] = Some(item);
        node
    }

    fn flush(&mut self, count: usize) -> Vec<Option<Box<dyn CacheItem>>> {
        self.start += count;

        let count = count.min(CACHE_SIZE);
        let out = self.cache[0..count].to_vec();
        self.cache[0..count].iter_mut().for_each(|x| *x = None);
        if count < CACHE_SIZE {
            let remain = CACHE_SIZE - count;
            self.cache[0..reamin].copy_from_slice(&self.cache[count..]);
            self.cache[count..].iter_mut().for_each(|x| *x = None);
        }

        out
    }

    fn add(&mut self, item: Box<dyn CacheItem>) -> (u64, Vec<Option<Box<dyn CacheItem>>>) {
        let seq = item.get_seq();
        if seq < self.start {
            // TODO
            return (self.last_timestamp, vec![]);
        }
        let mut offset = seq - self.start;
        let mut out = vec![];
        if offset >= CACHE_SIZE {
            out = self.flush(offset as usize - CACHE_SIZE + 1);
            offset = item.get_seq() - self.start;
        }
        let last_timestmap = self.last_timestamp;
        self.cache[offset] = item;
        self.last_timestamp = item.get_timestmap().as_secs();
        (last_timestmap, out)
    }
}

struct Reorder {
   cache: HashMap<u64, CacheNode>,
   windows: VecDeque<HashSet<u64>>, // time in seconds
   window_start: u64,
}

impl Reorder {
    const TIMEOUT: u64 = 5;
    const WINDOW_SIZE: u64 = Self::TIMEOUT;

    fn new() ->Self {
        let mut windows = VecDeque::with_capacity(Self::WINDOW_SIZE as usize);
        for _ in 0..Self::TIMEOUT as usize {
            windows.push_back(HashSet::new());
        }
        Self {
            cache: HashMap::new(),
            windows,
            window_start: 0,
        }
    }

    fn window_change(&mut self, last: u64, now: u64, id: u64) {
        self.window_delete(last, id);
        self.window_delete(now, id);
    }

    fn window_delete(&mut self, timestamp: u64, id: u64) {
        let offset = timestamp - self.window_start;
        self.windows[offset].remove(id);
    }

    fn window_add(&mut self, timestamp: u64, id: u64) {
        let offset = timestamp - self.window_start;
        self.windows[offset].insert(id);
    }

    fn flush(&mut self, timestamp: Duration) -> Vec<Option<Box<dyn CacheItem>>> {


    }

    fn flush(&mut self, timestamp: Duration) -> Vec<Option<Box<dyn CacheItem>>> {
        let now = timestamp.as_secs();
        if now < self.window_start {
            // TODO
            return vec![];
        }
        let offset = now - self.window_start;
        let mut items = vec![];
        if offset >= Self::WINDOW_SIZE {
            let count = offset - Self::WINDOW_SIZE + 1;
            for i in 0..count.min(Self::WINDOW_SIZE) {
                let ids = self.windows[i]
            }
        }
    }

    fn inject_item(&mut self, item: Box<dyn CacheItem>) -> Vec<Option<Box<dyn CacheItem>>> {
        let id = item.get_id();
        if let Some(node) = self.cache.get_mut(&id) {
            let (last_timestamp, out) = node.add(item);
            self.window_change(last_timestamp, item.get_timestmap().as_secs(), id);
            return out;
        } else {
            let node = CacheNode::new(item);
            let mut timestmap = item.get_timestmap();
            self.cache.insert(id, node);
            self.window_add(item.get_timestmap().as_secs(), id);
        }
        vec![]
    }
}

