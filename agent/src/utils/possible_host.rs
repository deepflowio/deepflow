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

use std::net::{IpAddr, Ipv6Addr};

use log::error;
use lru::LruCache;

pub struct PossibleHost {
    cache: LruCache<u64, bool>,
    last_log_time: u64, // time in second
}

impl PossibleHost {
    const LOG_INTERVLAN: u64 = 60;
    pub fn new(capacity: usize) -> Self {
        PossibleHost {
            cache: LruCache::new(capacity.try_into().unwrap()),
            last_log_time: 0,
        }
    }

    fn get_ip6_hash(ip6: &Ipv6Addr) -> u32 {
        let mut hash1 = 0 as u16;
        let mut hash2 = 0 as u16;
        let segs = ip6.segments();
        for i in (0..8).step_by(2) {
            hash1 ^= segs[i];
            hash2 ^= segs[i + 1];
        }
        (hash1 as u32) << 16 | hash2 as u32
    }

    fn gen_key(host: &IpAddr, epc_id: i32) -> u64 {
        match host {
            IpAddr::V4(ip4) => {
                u32::from_le_bytes(ip4.octets()) as u64 | ((epc_id & 0xffff) as u64) << 32
            }
            IpAddr::V6(ip6) => {
                1u64 << 48 | ((epc_id & 0xffff) as u64) << 32 | Self::get_ip6_hash(ip6) as u64
            }
        }
    }

    pub fn add(&mut self, now: u64, host: &IpAddr, epc_id: i32) {
        if usize::from(self.cache.cap()) <= self.cache.len()
            && now > self.last_log_time + Self::LOG_INTERVLAN
        {
            self.last_log_time = now;
            error!("The capacity({}) of the possible-host table will be exceeded. please adjust the configuration", self.cache.cap())
        }
        self.cache.put(Self::gen_key(host, epc_id), true);
    }

    pub fn check(&mut self, host: &IpAddr, epc_id: i32) -> bool {
        self.cache.get(&Self::gen_key(host, epc_id)).is_some()
    }

    pub fn clear(&mut self) {
        self.cache.clear();
    }
}
