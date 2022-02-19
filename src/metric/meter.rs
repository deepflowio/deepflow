use std::mem::swap;

#[derive(Debug)]
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

    pub fn sequential_merge(&mut self, other: Meter) {
        match (self, other) {
            (Meter::Flow(m), Meter::Flow(n)) => m.sequential_merge(n),
            (Meter::App(m), Meter::App(n)) => m.sequential_merge(n),
            (Meter::Usage(m), Meter::Usage(n)) => m.sequential_merge(n),
            _ => panic!("Meter merge mismatch type."),
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

#[derive(Debug, Default)]
pub struct FlowMeter {
    pub traffic: Traffic,
    pub latency: Latency,
    pub performance: Performance,
    pub anomaly: Anomaly,
    pub flow_load: FlowLoad,
}

impl FlowMeter {
    pub fn sequential_merge(&mut self, other: FlowMeter) {
        self.traffic.sequential_merge(other.traffic);
        self.latency.sequential_merge(other.latency);
        self.performance.sequential_merge(other.performance);
        self.anomaly.sequential_merge(other.anomaly);
        self.flow_load.sequential_merge(other.flow_load);
    }

    pub fn reverse(&mut self) {
        self.traffic.reverse();

        // 时延, 性能, 异常, 负载统计量以客户端、服务端为视角，无需Reverse
    }
}

#[derive(Debug, Default)]
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
    pub close_flow: u64,
    pub l7_request: u32,
    pub l7_response: u32,
}

impl Traffic {
    pub fn sequential_merge(&mut self, other: Traffic) {
        self.packet_tx += other.packet_tx;
        self.packet_rx += other.packet_rx;
        self.byte_tx += other.byte_tx;
        self.byte_rx += other.byte_rx;
        self.l3_byte_tx += other.l3_byte_tx;
        self.l3_byte_rx += other.l3_byte_rx;
        self.l4_byte_tx += other.l4_byte_tx;
        self.l4_byte_rx += other.l4_byte_rx;
        self.new_flow += other.new_flow;
        self.close_flow += other.close_flow;
        self.l7_request += other.l7_request;
        self.l7_response += other.l7_response;
    }

    pub fn reverse(&mut self) {
        swap(&mut self.packet_tx, &mut self.packet_rx);
        swap(&mut self.byte_tx, &mut self.byte_rx);
        swap(&mut self.l3_byte_tx, &mut self.l3_byte_rx);
        swap(&mut self.l4_byte_tx, &mut self.l4_byte_rx);

        // flow, L7等其他统计,以客户端、服务端为视角，无需Reverse
    }
}

#[derive(Debug, Default)]
pub struct Latency {
    pub rtt_max: u32,
    pub rtt_client_max: u32,
    pub rtt_server_max: u32,
    pub srt_max: u32,
    pub art_max: u32,
    pub rrt_max: u32,

    pub rtt_sum: u64,
    pub rtt_client_sum: u64,
    pub rtt_server_sum: u64,
    pub srt_sum: u64,
    pub art_sum: u64,
    pub rrt_sum: u64,

    pub rtt_count: u32,
    pub rtt_client_count: u32,
    pub rtt_server_count: u32,
    pub srt_count: u32,
    pub art_count: u32,
    pub rrt_count: u32,
}

impl Latency {
    pub fn sequential_merge(&mut self, other: Latency) {
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

        self.rtt_sum += other.rtt_sum;
        self.rtt_client_sum += other.rtt_client_sum;
        self.rtt_server_sum += other.rtt_server_sum;
        self.srt_sum += other.srt_sum;
        self.art_sum += other.art_sum;
        self.rrt_sum += other.rrt_sum;

        self.rtt_count = other.rtt_count;
        self.rtt_client_count += other.rtt_client_count;
        self.rtt_server_count += other.rtt_server_count;
        self.srt_count += other.srt_count;
        self.art_count += other.art_count;
        self.rrt_count = other.rrt_count;
    }
}

#[derive(Debug, Default)]
pub struct Performance {
    pub retrans_tx: u64,
    pub retrans_rx: u64,
    pub zero_win_tx: u64,
    pub zero_win_rx: u64,
}

impl Performance {
    pub fn sequential_merge(&mut self, other: Performance) {
        self.retrans_tx += other.retrans_tx;
        self.retrans_rx += other.retrans_rx;
        self.zero_win_tx += other.zero_win_tx;
        self.zero_win_rx += other.zero_win_rx;
    }
}

#[derive(Debug, Default)]
pub struct Anomaly {
    pub client_rst_flow: u64,
    pub server_rst_flow: u64,
    pub client_syn_repeat: u64,
    pub server_syn_ack_repeat: u64,
    pub client_half_close_flow: u64,
    pub server_half_close_flow: u64,

    pub client_source_port_reuse: u64,
    pub client_establish_other_rst: u64,
    pub server_reset: u64,
    pub server_queue_lack: u64,
    pub server_establish_other_rst: u64,
    pub tcp_timeout: u64,

    pub l7_client_error: u64,
    pub l7_server_error: u64,
    pub l7_timeout: u64,
}

impl Anomaly {
    pub fn sequential_merge(&mut self, other: Anomaly) {
        self.client_rst_flow += other.client_rst_flow;
        self.server_rst_flow += other.server_rst_flow;
        self.client_syn_repeat += other.client_syn_repeat;
        self.server_syn_ack_repeat += other.server_syn_ack_repeat;
        self.client_half_close_flow += other.client_half_close_flow;
        self.server_half_close_flow += other.server_half_close_flow;

        self.client_source_port_reuse += other.client_source_port_reuse;
        self.client_establish_other_rst += other.client_establish_other_rst;
        self.server_reset += other.server_reset;
        self.server_queue_lack += other.server_queue_lack;
        self.server_establish_other_rst += other.server_establish_other_rst;
        self.tcp_timeout += other.tcp_timeout;

        self.l7_client_error += other.l7_client_error;
        self.l7_server_error += other.l7_server_error;
        self.l7_timeout += other.l7_timeout;
    }
}

#[derive(Debug, Default)]
pub struct FlowLoad {
    pub load: u64,
}

impl FlowLoad {
    pub fn sequential_merge(&mut self, other: FlowLoad) {
        self.load += other.load;
    }
}

#[derive(Debug, Default)]
pub struct AppMeter {
    pub traffic: AppTraffic,
    pub latency: AppLatency,
    pub anomaly: AppAnomaly,
}

impl AppMeter {
    pub fn sequential_merge(&mut self, other: AppMeter) {
        self.traffic.sequential_merge(other.traffic);
        self.latency.sequential_merge(other.latency);
        self.anomaly.sequential_merge(other.anomaly);
    }
    pub fn reverse(&mut self) {
        self.traffic.reverse()
    }
}

#[derive(Debug, Default)]
pub struct AppTraffic {
    pub request: u32,
    pub response: u32,
}

impl AppTraffic {
    pub fn sequential_merge(&mut self, other: AppTraffic) {
        self.request += other.request;
        self.response += other.response;
    }
    pub fn reverse(&mut self) {
        swap(&mut self.request, &mut self.response);
    }
}

#[derive(Debug, Default)]
pub struct AppLatency {
    pub rrt_max: u32,
    pub rrt_sum: u64,
    pub rrt_count: u32,
}

impl AppLatency {
    pub fn sequential_merge(&mut self, other: AppLatency) {
        if self.rrt_max < other.rrt_max {
            self.rrt_max = other.rrt_max;
        }
        self.rrt_sum += other.rrt_sum;
        self.rrt_count += other.rrt_count;
    }
}

#[derive(Debug, Default)]
pub struct AppAnomaly {
    pub client_error: u32,
    pub server_error: u32,
    pub timeout: u32,
}

impl AppAnomaly {
    pub fn sequential_merge(&mut self, other: AppAnomaly) {
        self.client_error += other.client_error;
        self.server_error += other.server_error;
        self.timeout += other.timeout;
    }
}

#[derive(Debug, Default)]
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
    pub fn sequential_merge(&mut self, other: UsageMeter) {
        self.packet_tx += other.packet_tx;
        self.packet_rx += other.packet_rx;
        self.byte_tx += other.byte_tx;
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
