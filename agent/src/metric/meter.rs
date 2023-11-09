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

use std::{mem::swap, sync::Arc};

use public::{buffer::BatchedBox, l7_protocol::L7Protocol, proto::metric};

use crate::common::TaggedFlow;

const FLOW_ID: u32 = 1;
const USAGE_ID: u32 = 4;
const APP_ID: u32 = 5;

#[derive(Debug, Clone, Copy)]
pub enum Meter {
    Flow(FlowMeter),
    App(AppMeter),
    Usage(UsageMeter),
}

impl Meter {
    pub fn new_flow() -> Self {
        Meter::Flow(FlowMeter::default())
    }
    pub fn new_app() -> Self {
        Meter::App(AppMeter::default())
    }
    pub fn new_usage() -> Self {
        Meter::Usage(UsageMeter::default())
    }

    pub fn sequential_merge(&mut self, other: &Meter) {
        match (self, other) {
            (Meter::Flow(m), Meter::Flow(n)) => m.sequential_merge(n),
            (Meter::App(m), Meter::App(n)) => m.sequential_merge(n),
            (Meter::Usage(m), Meter::Usage(n)) => m.sequential_merge(n),
            (m, n) => panic!("Meter merge {:?} and {:?} mismatch type.", m, n),
        }
    }
    pub fn reverse(&mut self) {
        match self {
            Meter::Flow(m) => m.reverse(),
            Meter::App(m) => m.reverse(),
            Meter::Usage(m) => m.reverse(),
        }
    }
}

impl From<Meter> for metric::Meter {
    fn from(m: Meter) -> Self {
        match m {
            Meter::Flow(f) => metric::Meter {
                meter_id: FLOW_ID,
                flow: Some(f.into()),
                app: None,
                usage: None,
            },
            Meter::App(f) => metric::Meter {
                meter_id: APP_ID,
                flow: None,
                app: Some(f.into()),
                usage: None,
            },
            Meter::Usage(f) => metric::Meter {
                meter_id: USAGE_ID,
                flow: None,
                app: None,
                usage: Some(f.into()),
            },
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct FlowMeter {
    pub traffic: Traffic,
    pub latency: Latency,
    pub performance: Performance,
    pub anomaly: Anomaly,
    pub flow_load: FlowLoad,
}

impl FlowMeter {
    pub fn sequential_merge(&mut self, other: &FlowMeter) {
        self.traffic.sequential_merge(&other.traffic);
        self.latency.sequential_merge(&other.latency);
        self.performance.sequential_merge(&other.performance);
        self.anomaly.sequential_merge(&other.anomaly);
        self.flow_load.sequential_merge(&other.traffic);
    }

    pub fn reverse(&mut self) {
        self.traffic.reverse();

        // 时延, 性能, 异常, 负载统计量以客户端、服务端为视角，无需Reverse
    }

    pub fn to_reversed(&self) -> Self {
        let mut reversed = self.clone();
        reversed.traffic.reverse();
        reversed
    }
}

impl From<FlowMeter> for metric::FlowMeter {
    fn from(m: FlowMeter) -> Self {
        metric::FlowMeter {
            traffic: Some(m.traffic.into()),
            latency: Some(m.latency.into()),
            performance: Some(m.performance.into()),
            anomaly: Some(m.anomaly.into()),
            flow_load: Some(m.flow_load.into()),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Traffic {
    pub packet_tx: u64,
    pub packet_rx: u64,
    pub byte_tx: u64,
    pub byte_rx: u64,
    pub l3_byte_tx: u64,
    pub l3_byte_rx: u64,
    pub l4_byte_tx: u64,
    pub l4_byte_rx: u64,
    pub new_flow: u64,
    pub closed_flow: u64,
    pub l7_request: u32,
    pub l7_response: u32,
    pub syn: u32,
    pub synack: u32,
    pub direction_score: u8,
}

impl Traffic {
    pub fn sequential_merge(&mut self, other: &Traffic) {
        self.packet_tx += other.packet_tx;
        self.packet_rx += other.packet_rx;
        self.byte_tx += other.byte_tx;
        self.byte_rx += other.byte_rx;
        self.l3_byte_tx += other.l3_byte_tx;
        self.l3_byte_rx += other.l3_byte_rx;
        self.l4_byte_tx += other.l4_byte_tx;
        self.l4_byte_rx += other.l4_byte_rx;
        self.new_flow += other.new_flow;
        self.closed_flow += other.closed_flow;
        self.l7_request += other.l7_request;
        self.l7_response += other.l7_response;
        self.syn += other.syn;
        self.synack += other.synack;
        self.direction_score = self.direction_score.max(other.direction_score);
    }

    pub fn reverse(&mut self) {
        swap(&mut self.packet_tx, &mut self.packet_rx);
        swap(&mut self.byte_tx, &mut self.byte_rx);
        swap(&mut self.l3_byte_tx, &mut self.l3_byte_rx);
        swap(&mut self.l4_byte_tx, &mut self.l4_byte_rx);

        self.direction_score = 0
        // flow, L7等其他统计,以客户端、服务端为视角，无需Reverse
    }
}

impl From<Traffic> for metric::Traffic {
    fn from(m: Traffic) -> Self {
        metric::Traffic {
            packet_tx: m.packet_tx,
            packet_rx: m.packet_rx,
            byte_tx: m.byte_tx,
            byte_rx: m.byte_rx,
            l3_byte_tx: m.l3_byte_tx,
            l3_byte_rx: m.l3_byte_rx,
            l4_byte_tx: m.l4_byte_tx,
            l4_byte_rx: m.l4_byte_rx,
            new_flow: m.new_flow,
            closed_flow: m.closed_flow,
            l7_request: m.l7_request,
            l7_response: m.l7_response,
            syn: m.syn,
            synack: m.synack,
            direction_score: m.direction_score as u32,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Latency {
    pub rtt_max: u32,
    pub rtt_client_max: u32,
    pub rtt_server_max: u32,
    pub srt_max: u32,
    pub art_max: u32,
    pub rrt_max: u32,
    pub cit_max: u32, // us, the max time between the client request and the last server response (Payload > 1)

    pub rtt_sum: u64,
    pub rtt_client_sum: u64,
    pub rtt_server_sum: u64,
    pub srt_sum: u64,
    pub art_sum: u64,
    pub rrt_sum: u64,
    pub cit_sum: u64,

    pub rtt_count: u32,
    pub rtt_client_count: u32,
    pub rtt_server_count: u32,
    pub srt_count: u32,
    pub art_count: u32,
    pub rrt_count: u32,
    pub cit_count: u32,
}

impl Latency {
    pub fn sequential_merge(&mut self, other: &Latency) {
        if self.rtt_max < other.rtt_max {
            self.rtt_max = other.rtt_max;
        }
        if self.rtt_client_max < other.rtt_client_max {
            self.rtt_client_max = other.rtt_client_max;
        }
        if self.rtt_server_max < other.rtt_server_max {
            self.rtt_server_max = other.rtt_server_max;
        }
        if self.srt_max < other.srt_max {
            self.srt_max = other.srt_max;
        }
        if self.art_max < other.art_max {
            self.art_max = other.art_max;
        }
        if self.rrt_max < other.rrt_max {
            self.rrt_max = other.rrt_max;
        }
        if self.cit_max < other.cit_max {
            self.cit_max = other.cit_max;
        }

        self.rtt_sum += other.rtt_sum;
        self.rtt_client_sum += other.rtt_client_sum;
        self.rtt_server_sum += other.rtt_server_sum;
        self.srt_sum += other.srt_sum;
        self.art_sum += other.art_sum;
        self.rrt_sum += other.rrt_sum;
        self.cit_sum += other.cit_sum;

        self.rtt_count += other.rtt_count;
        self.rtt_client_count += other.rtt_client_count;
        self.rtt_server_count += other.rtt_server_count;
        self.srt_count += other.srt_count;
        self.art_count += other.art_count;
        self.rrt_count += other.rrt_count;
        self.cit_count += other.cit_count;
    }
}

impl From<Latency> for metric::Latency {
    fn from(m: Latency) -> Self {
        metric::Latency {
            rtt_max: m.rtt_max,
            rtt_client_max: m.rtt_client_max,
            rtt_server_max: m.rtt_server_max,
            srt_max: m.srt_max,
            art_max: m.art_max,
            rrt_max: m.rrt_max,
            cit_max: m.cit_max,

            rtt_sum: m.rtt_sum,
            rtt_client_sum: m.rtt_client_sum,
            rtt_server_sum: m.rtt_server_sum,
            srt_sum: m.srt_sum,
            art_sum: m.art_sum,
            rrt_sum: m.rrt_sum,
            cit_sum: m.cit_sum,

            rtt_count: m.rtt_count,
            rtt_client_count: m.rtt_client_count,
            rtt_server_count: m.rtt_server_count,
            srt_count: m.srt_count,
            art_count: m.art_count,
            rrt_count: m.rrt_count,
            cit_count: m.cit_count,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Performance {
    pub retrans_tx: u64,
    pub retrans_rx: u64,
    pub zero_win_tx: u64,
    pub zero_win_rx: u64,
    pub retrans_syn: u32,
    pub retrans_synack: u32,
}

impl Performance {
    pub fn sequential_merge(&mut self, other: &Performance) {
        self.retrans_tx += other.retrans_tx;
        self.retrans_rx += other.retrans_rx;
        self.zero_win_tx += other.zero_win_tx;
        self.zero_win_rx += other.zero_win_rx;
        self.retrans_syn += other.retrans_syn;
        self.retrans_synack += other.retrans_synack;
    }
}

impl From<Performance> for metric::Performance {
    fn from(m: Performance) -> Self {
        metric::Performance {
            retrans_tx: m.retrans_tx,
            retrans_rx: m.retrans_rx,
            zero_win_tx: m.zero_win_tx,
            zero_win_rx: m.zero_win_rx,
            retrans_syn: m.retrans_syn,
            retrans_synack: m.retrans_synack,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Anomaly {
    pub client_rst_flow: u64,
    pub server_rst_flow: u64,
    pub client_syn_repeat: u64,
    pub server_synack_repeat: u64,
    pub client_half_close_flow: u64,
    pub server_half_close_flow: u64,

    pub client_source_port_reuse: u64,
    pub client_establish_reset: u64,
    pub server_reset: u64,
    pub server_queue_lack: u64,
    pub server_establish_reset: u64,
    pub tcp_timeout: u64,

    pub l7_client_error: u32,
    pub l7_server_error: u32,
    pub l7_timeout: u32,
}

impl Anomaly {
    pub fn sequential_merge(&mut self, other: &Anomaly) {
        self.client_rst_flow += other.client_rst_flow;
        self.server_rst_flow += other.server_rst_flow;
        self.client_syn_repeat += other.client_syn_repeat;
        self.server_synack_repeat += other.server_synack_repeat;
        self.client_half_close_flow += other.client_half_close_flow;
        self.server_half_close_flow += other.server_half_close_flow;

        self.client_source_port_reuse += other.client_source_port_reuse;
        self.client_establish_reset += other.client_establish_reset;
        self.server_reset += other.server_reset;
        self.server_queue_lack += other.server_queue_lack;
        self.server_establish_reset += other.server_establish_reset;
        self.tcp_timeout += other.tcp_timeout;

        self.l7_client_error += other.l7_client_error;
        self.l7_server_error += other.l7_server_error;
        self.l7_timeout += other.l7_timeout;
    }
}

impl From<Anomaly> for metric::Anomaly {
    fn from(m: Anomaly) -> Self {
        metric::Anomaly {
            client_rst_flow: m.client_rst_flow,
            server_rst_flow: m.server_rst_flow,
            client_syn_repeat: m.client_syn_repeat,
            server_synack_repeat: m.server_synack_repeat,
            client_half_close_flow: m.client_half_close_flow,
            server_half_close_flow: m.server_half_close_flow,

            client_source_port_reuse: m.client_source_port_reuse,
            client_establish_reset: m.client_establish_reset,
            server_reset: m.server_reset,
            server_queue_lack: m.server_queue_lack,
            server_establish_reset: m.server_establish_reset,
            tcp_timeout: m.tcp_timeout,

            l7_client_error: m.l7_client_error,
            l7_server_error: m.l7_server_error,
            l7_timeout: m.l7_timeout,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct FlowLoad {
    pub load: u64,
    pub flow_count: u64,
}

impl FlowLoad {
    pub fn sequential_merge(&mut self, other: &Traffic) {
        self.load = self.flow_count + other.new_flow;
        self.flow_count = if self.load > other.closed_flow {
            self.load - other.closed_flow
        } else {
            0
        };
    }
}

impl From<FlowLoad> for metric::FlowLoad {
    fn from(m: FlowLoad) -> Self {
        metric::FlowLoad { load: m.load }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AppMeter {
    pub traffic: AppTraffic,
    pub latency: AppLatency,
    pub anomaly: AppAnomaly,
}

impl AppMeter {
    pub fn sequential_merge(&mut self, other: &AppMeter) {
        self.traffic.sequential_merge(&other.traffic);
        self.latency.sequential_merge(&other.latency);
        self.anomaly.sequential_merge(&other.anomaly);
    }
    pub fn reverse(&mut self) {
        self.traffic.reverse()
    }
}

impl From<AppMeter> for metric::AppMeter {
    fn from(m: AppMeter) -> Self {
        metric::AppMeter {
            traffic: Some(m.traffic.into()),
            latency: Some(m.latency.into()),
            anomaly: Some(m.anomaly.into()),
        }
    }
}

#[derive(Debug)]
pub struct AppMeterWithFlow {
    pub app_meter: AppMeter,
    pub flow: Arc<BatchedBox<TaggedFlow>>,
    pub l7_protocol: L7Protocol,
    pub endpoint_hash: u32,
    pub endpoint: Option<String>,
    pub is_active_host0: bool,
    pub is_active_host1: bool,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AppTraffic {
    pub request: u32,
    pub response: u32,
    pub direction_score: u8,
}

impl AppTraffic {
    pub fn sequential_merge(&mut self, other: &AppTraffic) {
        self.request += other.request;
        self.response += other.response;
        self.direction_score = self.direction_score.max(other.direction_score)
    }
    pub fn reverse(&mut self) {
        swap(&mut self.request, &mut self.response);
        self.direction_score = 0;
    }
}

impl From<AppTraffic> for metric::AppTraffic {
    fn from(m: AppTraffic) -> Self {
        metric::AppTraffic {
            request: m.request,
            response: m.response,
            direction_score: m.direction_score as u32,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AppLatency {
    pub rrt_max: u32,
    pub rrt_sum: u64,
    pub rrt_count: u32,
}

impl AppLatency {
    pub fn sequential_merge(&mut self, other: &AppLatency) {
        if self.rrt_max < other.rrt_max {
            self.rrt_max = other.rrt_max;
        }
        self.rrt_sum += other.rrt_sum;
        self.rrt_count += other.rrt_count;
    }
}

impl From<AppLatency> for metric::AppLatency {
    fn from(m: AppLatency) -> Self {
        metric::AppLatency {
            rrt_max: m.rrt_max,
            rrt_sum: m.rrt_sum,
            rrt_count: m.rrt_count,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AppAnomaly {
    pub client_error: u32,
    pub server_error: u32,
    pub timeout: u32,
}

impl AppAnomaly {
    pub fn sequential_merge(&mut self, other: &AppAnomaly) {
        self.client_error += other.client_error;
        self.server_error += other.server_error;
        self.timeout += other.timeout;
    }
}

impl From<AppAnomaly> for metric::AppAnomaly {
    fn from(m: AppAnomaly) -> Self {
        metric::AppAnomaly {
            client_error: m.client_error,
            server_error: m.server_error,
            timeout: m.timeout,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct UsageMeter {
    pub packet_tx: u64,
    pub packet_rx: u64,
    pub byte_tx: u64,
    pub byte_rx: u64,
    pub l3_byte_tx: u64,
    pub l3_byte_rx: u64,
    pub l4_byte_tx: u64,
    pub l4_byte_rx: u64,
}

impl UsageMeter {
    pub fn sequential_merge(&mut self, other: &UsageMeter) {
        self.packet_tx += other.packet_tx;
        self.packet_rx += other.packet_rx;
        self.byte_tx += other.byte_tx;
        self.byte_rx += other.byte_rx;
        self.l3_byte_rx += other.l3_byte_rx;
        self.l3_byte_tx += other.l3_byte_tx;
        self.l4_byte_rx += other.l4_byte_rx;
        self.l4_byte_tx += other.l4_byte_tx;
    }

    pub fn reverse(&mut self) {
        swap(&mut self.packet_tx, &mut self.packet_rx);
        swap(&mut self.byte_tx, &mut self.byte_rx);
        swap(&mut self.l3_byte_tx, &mut self.l3_byte_rx);
        swap(&mut self.l4_byte_tx, &mut self.l4_byte_rx);
    }
}

impl From<UsageMeter> for metric::UsageMeter {
    fn from(m: UsageMeter) -> Self {
        metric::UsageMeter {
            packet_tx: m.packet_tx,
            packet_rx: m.packet_rx,
            byte_tx: m.byte_tx,
            byte_rx: m.byte_rx,
            l3_byte_tx: m.l3_byte_tx,
            l3_byte_rx: m.l3_byte_rx,
            l4_byte_tx: m.l4_byte_tx,
            l4_byte_rx: m.l4_byte_rx,
        }
    }
}
