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

pub(crate) mod acc_flow;
mod collector;
mod consts;
pub(crate) mod flow_aggr;
pub(crate) mod quadruple_generator;

pub use collector::Collector;

use bitflags::bitflags;
use std::time::Duration;

use self::{flow_aggr::FlowAggrThread, quadruple_generator::QuadrupleGeneratorThread};

const SECONDS_IN_MINUTE: u64 = 60;

bitflags! {
    pub struct MetricsType: u32 {
        const SECOND = 1;
        const MINUTE = 1<<1;
   }
}

pub fn round_to_minute(t: Duration) -> Duration {
    Duration::from_secs(t.as_secs() / SECONDS_IN_MINUTE * SECONDS_IN_MINUTE)
}

pub struct CollectorThread {
    pub quadruple_generator: QuadrupleGeneratorThread,
    l4_flow_aggr: Option<FlowAggrThread>,
    second_collector: Option<Collector>,
    minute_collector: Option<Collector>,
}

impl CollectorThread {
    pub fn new(
        quadruple_generator: QuadrupleGeneratorThread,
        l4_flow_aggr: Option<FlowAggrThread>,
        second_collector: Option<Collector>,
        minute_collector: Option<Collector>,
    ) -> Self {
        Self {
            quadruple_generator,
            l4_flow_aggr,
            second_collector,
            minute_collector,
        }
    }

    pub fn start(&mut self) {
        self.quadruple_generator.start();
        if let Some(l4_flow_aggr) = self.l4_flow_aggr.as_mut() {
            l4_flow_aggr.start();
        }
        if let Some(second_collector) = self.second_collector.as_mut() {
            second_collector.start();
        }
        if let Some(minute_collector) = self.minute_collector.as_mut() {
            minute_collector.start();
        }
    }

    pub fn stop(&mut self) {
        self.quadruple_generator.stop();
        if let Some(l4_flow_aggr) = self.l4_flow_aggr.as_mut() {
            l4_flow_aggr.stop();
        }
        if let Some(second_collector) = self.second_collector.as_mut() {
            second_collector.stop();
        }
        if let Some(minute_collector) = self.minute_collector.as_mut() {
            minute_collector.stop();
        }
    }
}

const FLOW_METRICS_PEER_SRC: usize = 0;
const FLOW_METRICS_PEER_DST: usize = 1;
