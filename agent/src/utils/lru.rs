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

use std::borrow::Borrow;
use std::hash::Hash;

use lru::LruCache;

pub struct Lru<K, V> {
    cache: LruCache<K, V>,
    init_cap: usize,
    max_cap: usize,

    cap: usize,
}

impl<K: Hash + Eq, V> Lru<K, V> {
    pub fn with_capacity(init_cap: usize, max_cap: usize) -> Self {
        let init_cap = init_cap.next_power_of_two();
        let max_cap = max_cap.next_power_of_two().max(init_cap);
        Self {
            cache: LruCache::new(init_cap.try_into().unwrap()),
            init_cap,
            max_cap,
            cap: init_cap,
        }
    }

    pub fn iter(&self) -> lru::Iter<K, V> {
        self.cache.iter()
    }

    pub fn put(&mut self, k: K, v: V) -> Option<V> {
        let r = self.cache.put(k, v);
        if r.is_none() && self.cache.len() >= self.cap && self.cap < self.max_cap {
            // new entry, check capacity
            self.cap <<= 1;
            self.cache.resize(self.cap.try_into().unwrap());
        }
        r
    }

    pub fn get_mut<'a, Q>(&'a mut self, k: &Q) -> Option<&'a mut V>
    where
        lru::KeyRef<K>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.cache.get_mut(k)
    }

    pub fn clear(&mut self) {
        self.cache.resize(self.init_cap.try_into().unwrap());
        self.cap = self.init_cap;
        self.cache.clear();
    }

    pub fn cap(&self) -> (usize, usize) {
        (self.init_cap, self.max_cap)
    }

    pub fn is_full(&self) -> bool {
        self.cache.len() >= self.max_cap
    }
}
