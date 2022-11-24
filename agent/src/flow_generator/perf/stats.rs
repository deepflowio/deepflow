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

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use serde::Serialize;

use crate::utils::stats::{Counter, CounterType, CounterValue, RefCountable};

// 每次获取统计数据后此结构体都会被清零，不能在其中保存Flow级别的信息避免被清空
#[derive(Debug, Default, PartialEq, Clone, Serialize)]
pub struct PerfStats {
    pub req_count: u32,
    pub resp_count: u32,
    pub req_err_count: u32,
    pub resp_err_count: u32,
    pub rrt_count: u32,
    pub rrt_max: Duration,
    pub rrt_last: Duration,
    pub rrt_sum: Duration,
}

impl PerfStats {
    // TODO use for perf parse, will move to log parser when perf parse abstruct to log parse.
    pub fn update_perf(
        &mut self,
        req_count: u32,
        resp_count: u32,
        req_err: u32,
        resp_err: u32,
        rrt: u64,
    ) {
        self.req_count += req_count;
        self.resp_count += resp_count;
        self.req_err_count += req_err;
        self.resp_err_count += resp_err;

        if rrt != 0 {
            let d = Duration::from_micros(rrt);
            self.rrt_max = self.rrt_max.max(d);
            self.rrt_last = d;
            self.rrt_sum += d;
            self.rrt_count += 1;
        }
    }
}

#[derive(Default)]
pub struct FlowPerfCounter {
    closed: AtomicBool,

    // tcp stats
    pub ignored_packet_count: AtomicU64,
    pub invalid_packet_count: AtomicU64,

    // L7 stats
    pub mismatched_response: AtomicU64,
    pub unknown_l7_protocol: AtomicU64,
}

impl RefCountable for FlowPerfCounter {
    fn get_counters(&self) -> Vec<Counter> {
        let ignored = self.ignored_packet_count.swap(0, Ordering::Relaxed);
        let invalid = self.invalid_packet_count.swap(0, Ordering::Relaxed);
        let mismatched = self.mismatched_response.swap(0, Ordering::Relaxed);
        let unknown_l7_protocol = self.unknown_l7_protocol.swap(0, Ordering::Relaxed);

        vec![
            (
                "ignore_packet_count",
                CounterType::Counted,
                CounterValue::Unsigned(ignored),
            ),
            (
                "invalid_packet_count",
                CounterType::Counted,
                CounterValue::Unsigned(invalid),
            ),
            (
                "l7_mismatch_response",
                CounterType::Counted,
                CounterValue::Unsigned(mismatched),
            ),
            (
                "unknown_l7_protocol",
                CounterType::Counted,
                CounterValue::Unsigned(unknown_l7_protocol),
            ),
        ]
    }
}
