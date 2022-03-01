#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MiniField {
    #[prost(bytes = "vec", tag = "1")]
    pub ip: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub ip1: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub global_thread_id: u32,
    #[prost(uint32, tag = "4")]
    pub is_ipv6: u32,
    #[prost(int32, tag = "5")]
    pub l3_epc_id: i32,
    #[prost(int32, tag = "6")]
    pub l3_epc_id1: i32,
    #[prost(uint64, tag = "7")]
    pub mac: u64,
    #[prost(uint64, tag = "8")]
    pub mac1: u64,
    #[prost(uint32, tag = "9")]
    pub direction: u32,
    #[prost(uint32, tag = "10")]
    pub tap_side: u32,
    #[prost(uint32, tag = "11")]
    pub protocol: u32,
    #[prost(uint32, tag = "12")]
    pub acl_gid: u32,
    #[prost(uint32, tag = "13")]
    pub server_port: u32,
    #[prost(uint32, tag = "14")]
    pub vtap_id: u32,
    #[prost(uint64, tag = "15")]
    pub tap_port: u64,
    #[prost(uint32, tag = "16")]
    pub tap_type: u32,
    #[prost(uint32, tag = "17")]
    pub l7_protocol: u32,
    #[prost(uint32, tag = "18")]
    pub tag_type: u32,
    #[prost(uint32, tag = "19")]
    pub tag_value: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MiniTag {
    #[prost(message, optional, tag = "1")]
    pub field: ::core::option::Option<MiniField>,
    #[prost(uint64, tag = "2")]
    pub code: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Meter {
    #[prost(uint32, tag = "1")]
    pub meter_id: u32,
    #[prost(message, optional, tag = "2")]
    pub flow: ::core::option::Option<FlowMeter>,
    #[prost(message, optional, tag = "3")]
    pub usage: ::core::option::Option<UsageMeter>,
    #[prost(message, optional, tag = "4")]
    pub app: ::core::option::Option<AppMeter>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Document {
    #[prost(uint32, tag = "1")]
    pub timestamp: u32,
    #[prost(message, optional, tag = "2")]
    pub tag: ::core::option::Option<MiniTag>,
    #[prost(message, optional, tag = "3")]
    pub meter: ::core::option::Option<Meter>,
    #[prost(uint32, tag = "4")]
    pub flags: u32,
}
/// flow meter
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FlowMeter {
    #[prost(message, optional, tag = "1")]
    pub traffic: ::core::option::Option<Traffic>,
    #[prost(message, optional, tag = "2")]
    pub latency: ::core::option::Option<Latency>,
    #[prost(message, optional, tag = "3")]
    pub performance: ::core::option::Option<Performance>,
    #[prost(message, optional, tag = "4")]
    pub anomaly: ::core::option::Option<Anomaly>,
    #[prost(message, optional, tag = "5")]
    pub flow_load: ::core::option::Option<FlowLoad>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Traffic {
    #[prost(uint64, tag = "1")]
    pub packet_tx: u64,
    #[prost(uint64, tag = "2")]
    pub packet_rx: u64,
    #[prost(uint64, tag = "3")]
    pub byte_tx: u64,
    #[prost(uint64, tag = "4")]
    pub byte_rx: u64,
    #[prost(uint64, tag = "5")]
    pub l3_byte_tx: u64,
    #[prost(uint64, tag = "6")]
    pub l3_byte_rx: u64,
    #[prost(uint64, tag = "7")]
    pub l4_byte_tx: u64,
    #[prost(uint64, tag = "8")]
    pub l4_byte_rx: u64,
    #[prost(uint64, tag = "9")]
    pub new_flow: u64,
    #[prost(uint64, tag = "10")]
    pub closed_flow: u64,
    #[prost(uint32, tag = "11")]
    pub l7_request: u32,
    #[prost(uint32, tag = "12")]
    pub l7_response: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Latency {
    #[prost(uint32, tag = "1")]
    pub rtt_max: u32,
    #[prost(uint32, tag = "2")]
    pub rtt_client_max: u32,
    #[prost(uint32, tag = "3")]
    pub rtt_server_max: u32,
    #[prost(uint32, tag = "4")]
    pub srt_max: u32,
    #[prost(uint32, tag = "5")]
    pub art_max: u32,
    #[prost(uint32, tag = "6")]
    pub rrt_max: u32,
    #[prost(uint64, tag = "7")]
    pub rtt_sum: u64,
    #[prost(uint64, tag = "8")]
    pub rtt_client_sum: u64,
    #[prost(uint64, tag = "9")]
    pub rtt_server_sum: u64,
    #[prost(uint64, tag = "10")]
    pub srt_sum: u64,
    #[prost(uint64, tag = "11")]
    pub art_sum: u64,
    #[prost(uint64, tag = "12")]
    pub rrt_sum: u64,
    #[prost(uint32, tag = "13")]
    pub rtt_count: u32,
    #[prost(uint32, tag = "14")]
    pub rtt_client_count: u32,
    #[prost(uint32, tag = "15")]
    pub rtt_server_count: u32,
    #[prost(uint32, tag = "16")]
    pub srt_count: u32,
    #[prost(uint32, tag = "17")]
    pub art_count: u32,
    #[prost(uint32, tag = "18")]
    pub rrt_count: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Performance {
    #[prost(uint64, tag = "1")]
    pub retrans_tx: u64,
    #[prost(uint64, tag = "2")]
    pub retrans_rx: u64,
    #[prost(uint64, tag = "3")]
    pub zero_win_tx: u64,
    #[prost(uint64, tag = "4")]
    pub zero_win_rx: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Anomaly {
    #[prost(uint64, tag = "1")]
    pub client_rst_flow: u64,
    #[prost(uint64, tag = "2")]
    pub server_rst_flow: u64,
    #[prost(uint64, tag = "3")]
    pub client_syn_repeat: u64,
    #[prost(uint64, tag = "4")]
    pub server_synack_repeat: u64,
    #[prost(uint64, tag = "5")]
    pub client_half_close_flow: u64,
    #[prost(uint64, tag = "6")]
    pub server_half_close_flow: u64,
    #[prost(uint64, tag = "7")]
    pub client_source_port_reuse: u64,
    #[prost(uint64, tag = "8")]
    pub client_establish_reset: u64,
    #[prost(uint64, tag = "9")]
    pub server_reset: u64,
    #[prost(uint64, tag = "10")]
    pub server_queue_lack: u64,
    #[prost(uint64, tag = "11")]
    pub server_establish_reset: u64,
    #[prost(uint64, tag = "12")]
    pub tcp_timeout: u64,
    #[prost(uint32, tag = "13")]
    pub l7_client_error: u32,
    #[prost(uint32, tag = "14")]
    pub l7_server_error: u32,
    #[prost(uint32, tag = "15")]
    pub l7_timeout: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FlowLoad {
    #[prost(uint64, tag = "1")]
    pub load: u64,
}
/// usage meter
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UsageMeter {
    #[prost(uint64, tag = "1")]
    pub packet_tx: u64,
    #[prost(uint64, tag = "2")]
    pub packet_rx: u64,
    #[prost(uint64, tag = "3")]
    pub byte_tx: u64,
    #[prost(uint64, tag = "4")]
    pub byte_rx: u64,
    #[prost(uint64, tag = "5")]
    pub l3_byte_tx: u64,
    #[prost(uint64, tag = "6")]
    pub l3_byte_rx: u64,
    #[prost(uint64, tag = "7")]
    pub l4_byte_tx: u64,
    #[prost(uint64, tag = "8")]
    pub l4_byte_rx: u64,
}
/// app meter
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppMeter {
    #[prost(message, optional, tag = "1")]
    pub traffic: ::core::option::Option<AppTraffic>,
    #[prost(message, optional, tag = "2")]
    pub latency: ::core::option::Option<AppLatency>,
    #[prost(message, optional, tag = "3")]
    pub anomaly: ::core::option::Option<AppAnomaly>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppTraffic {
    #[prost(uint32, tag = "1")]
    pub request: u32,
    #[prost(uint32, tag = "2")]
    pub response: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppLatency {
    #[prost(uint32, tag = "1")]
    pub rrt_max: u32,
    #[prost(uint64, tag = "2")]
    pub rrt_sum: u64,
    #[prost(uint32, tag = "3")]
    pub rrt_count: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppAnomaly {
    #[prost(uint32, tag = "1")]
    pub client_error: u32,
    #[prost(uint32, tag = "2")]
    pub server_error: u32,
    #[prost(uint32, tag = "3")]
    pub timeout: u32,
}
