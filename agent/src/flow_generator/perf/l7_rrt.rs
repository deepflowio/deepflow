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

use std::time::Duration;

use log::debug;
use lru::LruCache;

use crate::{common::flow::PacketDirection, flow_generator::LogMessageType};

pub struct RrtCache {
    rrt_cache: LruCache<u128, (LogMessageType, Duration)>,
    // LruCache<flow_id, count>
    timeout_count: LruCache<u64, usize>,
}

impl RrtCache {
    pub fn new(cap: usize) -> Self {
        RrtCache {
            rrt_cache: LruCache::new(cap.try_into().unwrap()),
            timeout_count: LruCache::new(cap.try_into().unwrap()),
        }
    }

    pub fn cal_rrt(
        &mut self,
        flow_id: u64,
        session_id: Option<u32>,
        direction: PacketDirection,
        cur_time: Duration,
        cap_seq: u64,
        from_ebpf: bool,
    ) -> Duration {
        let key = Self::cal_cache_key(
            flow_id,
            session_id,
            if from_ebpf {
                if direction == PacketDirection::ClientToServer {
                    cap_seq + 1
                } else {
                    cap_seq
                }
            } else {
                0
            },
        );
        let c = &mut self.rrt_cache;
        let cur_type: LogMessageType = direction.into();
        let Some((prev_type, prev_time)) = c.pop(&key) else {
            let count = self.timeout_count.get_or_insert_mut(flow_id, ||0);
            *count += 1;
            c.push(key, (cur_type, cur_time));
            return Duration::ZERO;
        };
        let timeout_count = self.timeout_count.get_mut(&flow_id);

        if prev_type == LogMessageType::Request
            && cur_type == LogMessageType::Response
            && cur_time > prev_time
        {
            // if previous is req and current is resp and resp time gt req time, calculate the round trip time.
            timeout_count.map(|c| *c -= 1);
            return cur_time - prev_time;
        } else if prev_type == LogMessageType::Response
            && cur_type == LogMessageType::Request
            && cur_time < prev_time
        {
            // if previous is resp and current is req and resp time gt req time, likely ebpf disorder,
            // calculate the round trip time.
            timeout_count.map(|c| *c -= 1);
            return prev_time - cur_time;
        } else {
            debug!(
                "can not calculate rrt, flow_id: {}, previous log type:{:?}, previous time: {:?}, current log type: {:?}, current time: {:?}",
                flow_id, prev_type, prev_time, cur_type, cur_time
            );
            timeout_count.map(|c| *c += 1);
            c.push(key, (cur_type, cur_time));
            return Duration::ZERO;
        }
    }

    pub fn get_timeout_count(&mut self, flow_id: u64) -> usize {
        *(self.timeout_count.get(&flow_id).unwrap_or(&0))
    }

    pub fn get(
        &mut self,
        flow_id: u64,
        session_id: Option<u32>,
        direction: PacketDirection,
        cap_seq: u64,
        from_ebpf: bool,
    ) -> Option<&(LogMessageType, Duration)> {
        let key = Self::cal_cache_key(
            flow_id,
            session_id,
            if from_ebpf {
                if direction == PacketDirection::ClientToServer {
                    cap_seq + 1
                } else {
                    cap_seq
                }
            } else {
                0
            },
        );
        self.rrt_cache.get(&key)
    }

    pub fn set(
        &mut self,
        flow_id: u64,
        session_id: Option<u32>,
        direction: PacketDirection,
        cap_seq: u64,
        from_ebpf: bool,
        time: Duration,
    ) -> Option<(LogMessageType, Duration)> {
        let key = Self::cal_cache_key(
            flow_id,
            session_id,
            if from_ebpf {
                if direction == PacketDirection::ClientToServer {
                    cap_seq + 1
                } else {
                    cap_seq
                }
            } else {
                0
            },
        );
        let old_val = self.rrt_cache.push(key, (direction.into(), time));

        if let Some((_, val)) = old_val {
            if let Some(v) = self.timeout_count.get_mut(&flow_id) {
                *v += 1;
            } else {
                self.timeout_count.push(flow_id, 1);
            }
            Some(val)
        } else {
            None
        }
    }

    fn cal_cache_key(flow_id: u64, session_id: Option<u32>, packet_seq: u64) -> u128 {
        match session_id {
            Some(id) => ((flow_id as u128) << 64) | id as u128,
            None => ((flow_id as u128) << 64) | packet_seq as u128,
        }
    }
}
