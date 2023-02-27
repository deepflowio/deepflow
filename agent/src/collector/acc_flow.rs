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

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use super::quadruple_generator::QgKey;

use crate::common::flow::{L7Protocol, SignalSource};
use crate::common::tagged_flow::TaggedFlow;
use crate::metric::meter::{AppMeter, FlowMeter};

pub struct AccumulatedFlow {
    pub tagged_flow: Arc<TaggedFlow>,
    pub l7_protocol: L7Protocol,
    pub is_active_host0: bool,
    pub is_active_host1: bool,

    pub id_maps: [HashMap<u16, u16>; 2],
    pub flow_meter: FlowMeter,
    pub app_meter: AppMeter,
    pub key: QgKey,
    pub time_in_second: Duration,
    pub nat_real_ip_0: IpAddr,
    pub nat_real_ip_1: IpAddr,
    pub nat_real_port_0: u16,
    pub nat_real_port_1: u16,
}

impl fmt::Display for AccumulatedFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AccumulatedFlow: time: {:?}, flow_meter: {:?}, app_meter: {:?}, nat_real_ip_0: {:?}, nat_real_ip_1: {:?}, nat_real_port_0: {}, nat_real_port_1: {}", 
            self.time_in_second, &self.flow_meter, &self.app_meter, &self.nat_real_ip_0, &self.nat_real_ip_1,  &self.nat_real_port_0, &self.nat_real_port_1,
        )
    }
}

impl fmt::Debug for AccumulatedFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl AccumulatedFlow {
    pub fn merge(
        &mut self,
        time_in_second: Duration,
        flow_meter: &FlowMeter,
        app_meter: &AppMeter,
        id_maps: &[HashMap<u16, u16>; 2],
        tagged_flow: &Arc<TaggedFlow>,
    ) {
        self.time_in_second = time_in_second;
        // Only flow whose signal_source is Packet or XFlow has flow_meter
        if tagged_flow.flow.signal_source == SignalSource::Packet
            || tagged_flow.flow.signal_source == SignalSource::XFlow
        {
            self.flow_meter.sequential_merge(flow_meter);
            for i in 0..2 {
                for (k, v) in id_maps[i].iter() {
                    self.id_maps[i].insert(*k, *v);
                }
            }
        }
        // 相同服务端端口不同客户端端口的流L7Protocol可能不一致
        // 未知应用的判断需要通过流结束原因和持续时间，所以同一个流的L7Protocol可能不同这里需要更新，原则如下：
        // 1. unknown协议可以被任何协议覆盖
        // 2. other可以被其他非unknown协议覆盖
        if let Some(other_stats) = tagged_flow.flow.flow_perf_stats.as_ref() {
            if self.l7_protocol == L7Protocol::Unknown
                || (self.l7_protocol == L7Protocol::Other
                    && other_stats.l7_protocol != L7Protocol::Unknown)
            {
                self.l7_protocol = other_stats.l7_protocol;
                self.app_meter = *app_meter;
            } else if other_stats.l7_protocol == self.l7_protocol {
                self.app_meter.sequential_merge(app_meter);
            }
        }
    }
}

#[derive(Clone)]
pub struct U16Set(Vec<u16>);

impl U16Set {
    pub fn new() -> Self {
        U16Set(Vec::new())
    }

    pub fn add(&mut self, v: u16) {
        if let Err(i) = self.0.binary_search(&v) {
            self.0.insert(i, v);
        }
    }

    pub fn merge(&mut self, other: &U16Set) {
        if other.0.is_empty() {
            return;
        }
        if self.0.is_empty() {
            self.0.extend_from_slice(other.0.as_slice());
            return;
        }
        let self_len = self.0.len();
        let other_len = other.0.len();
        let total_len = self_len + other_len;
        self.0.resize(total_len, 0);
        self.0.copy_within(0..self_len, other_len);
        let mut i = other_len;
        let mut j = 0;
        let mut k = 0;
        while i < total_len && j < other_len {
            if self.0[i] > other.0[j] {
                self.0[k] = other.0[j];
                j += 1;
            } else if self.0[i] < other.0[j] {
                self.0[k] = self.0[i];
                i += 1;
            } else {
                self.0[k] = self.0[i];
                i += 1;
                j += 1;
            }
            k += 1;
        }

        if i < total_len {
            self.0.copy_within(i..total_len, k);
            k += total_len - i;
        }

        if j < other_len {
            let left = other_len - j;
            self.0[k..k + left].copy_from_slice(&other.0[j..j + left]);
            k += left;
        }
        self.0.truncate(k);
    }

    pub fn list(&self) -> &[u16] {
        &self.0
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn add() {
        let mut set = U16Set::new();
        set.add(128);
        set.add(128);
        set.add(1280);
        set.add(1);
        set.add(1100);
        set.add(65535);
        assert_eq!(set.list(), [1, 128, 1100, 1280, 65535]);
    }

    #[test]
    fn merge() {
        let tests = vec![
            (
                vec![1u16, 2, 3, 4, 5],
                vec![11u16, 12, 13, 14, 15],
                vec![1u16, 2, 3, 4, 5, 11, 12, 13, 14, 15],
            ),
            (
                vec![11u16, 12, 13, 14, 15],
                vec![1u16, 2, 3, 4, 5],
                vec![1u16, 2, 3, 4, 5, 11, 12, 13, 14, 15],
            ),
            (
                vec![11u16, 12, 13, 14, 15],
                vec![],
                vec![11u16, 12, 13, 14, 15],
            ),
            (vec![], vec![1u16, 2, 3, 4, 5], vec![1u16, 2, 3, 4, 5]),
            (
                vec![1u16, 3, 5, 7, 9],
                vec![2u16, 4, 6, 8, 10],
                vec![1u16, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            ),
            (
                vec![1u16, 3, 5, 7, 9],
                vec![1u16, 3, 5, 7, 9],
                vec![1u16, 3, 5, 7, 9],
            ),
            (
                vec![1u16, 3, 5, 7, 9],
                vec![1u16, 2, 3, 5],
                vec![1u16, 2, 3, 5, 7, 9],
            ),
            (
                vec![1u16, 3, 5, 7, 9],
                vec![1u16, 2, 3, 5, 8, 10, 11, 12],
                vec![1u16, 2, 3, 5, 7, 8, 9, 10, 11, 12],
            ),
        ];
        for i in tests.iter() {
            let mut merged = U16Set::new();
            merged.merge(&U16Set { 0: i.0.clone() });
            merged.merge(&U16Set { 0: i.1.clone() });
            assert_eq!(merged.list(), i.2)
        }
    }
}
