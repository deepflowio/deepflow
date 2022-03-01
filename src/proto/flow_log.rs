#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TaggedFlow {
    #[prost(message, optional, tag = "1")]
    pub flow: ::core::option::Option<Flow>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Flow {
    #[prost(message, optional, tag = "1")]
    pub flow_key: ::core::option::Option<FlowKey>,
    #[prost(message, optional, tag = "2")]
    pub metrics_peer_src: ::core::option::Option<FlowMetricsPeer>,
    #[prost(message, optional, tag = "3")]
    pub metrics_peer_dst: ::core::option::Option<FlowMetricsPeer>,
    #[prost(message, optional, tag = "4")]
    pub tunnel: ::core::option::Option<TunnelField>,
    #[prost(uint64, tag = "5")]
    pub flow_id: u64,
    #[prost(uint64, tag = "6")]
    pub start_time: u64,
    #[prost(uint64, tag = "7")]
    pub end_time: u64,
    /// uint64 flow_start_time = 9;  // 目前无需发送
    #[prost(uint64, tag = "8")]
    pub duration: u64,
    /// uint32 vlan = 10;  // 目前无需发送
    #[prost(uint32, tag = "11")]
    pub eth_type: u32,
    #[prost(message, optional, tag = "13")]
    pub perf_stats: ::core::option::Option<FlowPerfStats>,
    #[prost(uint32, tag = "14")]
    pub close_type: u32,
    #[prost(uint32, tag = "15")]
    pub flow_source: u32,
    #[prost(uint32, tag = "16")]
    pub is_active_service: u32,
    #[prost(uint32, tag = "17")]
    pub queue_hash: u32,
    #[prost(uint32, tag = "18")]
    pub is_new_flow: u32,
    #[prost(uint32, tag = "19")]
    pub tap_side: u32,
    /// TCP Seq
    #[prost(uint32, tag = "20")]
    pub syn_seq: u32,
    #[prost(uint32, tag = "21")]
    pub synack_seq: u32,
    #[prost(uint32, tag = "22")]
    pub last_keepalive_seq: u32,
    #[prost(uint32, tag = "23")]
    pub last_keepalive_ack: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FlowKey {
    #[prost(uint32, tag = "1")]
    pub vtap_id: u32,
    #[prost(uint32, tag = "2")]
    pub tap_type: u32,
    #[prost(uint64, tag = "3")]
    pub tap_port: u64,
    #[prost(uint64, tag = "4")]
    pub mac_src: u64,
    #[prost(uint64, tag = "5")]
    pub mac_dst: u64,
    #[prost(uint32, tag = "6")]
    pub ip_src: u32,
    #[prost(uint32, tag = "7")]
    pub ip_dst: u32,
    #[prost(bytes = "vec", tag = "8")]
    pub ip6_src: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub ip6_dst: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag = "10")]
    pub port_src: u32,
    #[prost(uint32, tag = "11")]
    pub port_dst: u32,
    #[prost(uint32, tag = "12")]
    pub proto: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FlowMetricsPeer {
    #[prost(uint64, tag = "1")]
    pub byte_count: u64,
    #[prost(uint64, tag = "2")]
    pub l3_byte_count: u64,
    #[prost(uint64, tag = "3")]
    pub l4_byte_count: u64,
    #[prost(uint64, tag = "4")]
    pub packet_count: u64,
    #[prost(uint64, tag = "5")]
    pub total_byte_count: u64,
    #[prost(uint64, tag = "6")]
    pub total_packet_count: u64,
    #[prost(uint64, tag = "7")]
    pub first: u64,
    #[prost(uint64, tag = "8")]
    pub last: u64,
    #[prost(uint32, tag = "9")]
    pub tcp_flags: u32,
    #[prost(int32, tag = "10")]
    pub l3_epc_id: i32,
    #[prost(uint32, tag = "11")]
    pub is_l2_end: u32,
    #[prost(uint32, tag = "12")]
    pub is_l3_end: u32,
    #[prost(uint32, tag = "13")]
    pub is_active_host: u32,
    #[prost(uint32, tag = "14")]
    pub is_device: u32,
    #[prost(uint32, tag = "15")]
    pub is_vip_interface: u32,
    #[prost(uint32, tag = "16")]
    pub is_vip: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TunnelField {
    #[prost(uint32, tag = "1")]
    pub tx_ip0: u32,
    #[prost(uint32, tag = "2")]
    pub tx_ip1: u32,
    #[prost(uint32, tag = "3")]
    pub rx_ip0: u32,
    #[prost(uint32, tag = "4")]
    pub rx_ip1: u32,
    #[prost(uint32, tag = "5")]
    pub tx_mac0: u32,
    #[prost(uint32, tag = "6")]
    pub tx_mac1: u32,
    #[prost(uint32, tag = "7")]
    pub rx_mac0: u32,
    #[prost(uint32, tag = "8")]
    pub rx_mac1: u32,
    #[prost(uint32, tag = "9")]
    pub tx_id: u32,
    #[prost(uint32, tag = "10")]
    pub rx_id: u32,
    #[prost(uint32, tag = "11")]
    pub tunnel_type: u32,
    #[prost(uint32, tag = "12")]
    pub tier: u32,
    #[prost(uint32, tag = "13")]
    pub is_ipv6: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FlowPerfStats {
    #[prost(message, optional, tag = "1")]
    pub tcp: ::core::option::Option<TcpPerfStats>,
    #[prost(message, optional, tag = "2")]
    pub l7: ::core::option::Option<L7PerfStats>,
    #[prost(uint32, tag = "3")]
    pub l4_protocol: u32,
    #[prost(uint32, tag = "4")]
    pub l7_protocol: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TcpPerfStats {
    #[prost(uint32, tag = "1")]
    pub rtt_client_max: u32,
    #[prost(uint32, tag = "2")]
    pub rtt_server_max: u32,
    #[prost(uint32, tag = "3")]
    pub srt_max: u32,
    #[prost(uint32, tag = "4")]
    pub art_max: u32,
    #[prost(uint32, tag = "5")]
    pub rtt: u32,
    #[prost(uint32, tag = "6")]
    pub rtt_client_sum: u32,
    #[prost(uint32, tag = "7")]
    pub rtt_server_sum: u32,
    #[prost(uint32, tag = "8")]
    pub srt_sum: u32,
    #[prost(uint32, tag = "9")]
    pub art_sum: u32,
    #[prost(uint32, tag = "10")]
    pub rtt_client_count: u32,
    #[prost(uint32, tag = "11")]
    pub rtt_server_count: u32,
    #[prost(uint32, tag = "12")]
    pub srt_count: u32,
    #[prost(uint32, tag = "13")]
    pub art_count: u32,
    #[prost(message, optional, tag = "14")]
    pub counts_peer_tx: ::core::option::Option<TcpPerfCountsPeer>,
    #[prost(message, optional, tag = "15")]
    pub counts_peer_rx: ::core::option::Option<TcpPerfCountsPeer>,
    #[prost(uint32, tag = "16")]
    pub total_retrans_count: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TcpPerfCountsPeer {
    #[prost(uint32, tag = "1")]
    pub retrans_count: u32,
    #[prost(uint32, tag = "2")]
    pub zero_win_count: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct L7PerfStats {
    #[prost(uint32, tag = "1")]
    pub request_count: u32,
    #[prost(uint32, tag = "2")]
    pub response_count: u32,
    #[prost(uint32, tag = "3")]
    pub err_client_count: u32,
    #[prost(uint32, tag = "4")]
    pub err_server_count: u32,
    #[prost(uint32, tag = "5")]
    pub err_timeout: u32,
    #[prost(uint32, tag = "6")]
    pub rrt_count: u32,
    #[prost(uint64, tag = "7")]
    pub rrt_sum: u64,
    #[prost(uint32, tag = "8")]
    pub rrt_max: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppProtoLogsData {
    #[prost(message, optional, tag = "1")]
    pub base: ::core::option::Option<AppProtoLogsBaseInfo>,
    #[prost(message, optional, tag = "2")]
    pub http: ::core::option::Option<HttpInfo>,
    #[prost(message, optional, tag = "3")]
    pub dns: ::core::option::Option<DnsInfo>,
    #[prost(message, optional, tag = "4")]
    pub dubbo: ::core::option::Option<DubboInfo>,
    #[prost(message, optional, tag = "5")]
    pub kafka: ::core::option::Option<KafkaInfo>,
    #[prost(message, optional, tag = "6")]
    pub mysql: ::core::option::Option<MysqlInfo>,
    #[prost(message, optional, tag = "7")]
    pub redis: ::core::option::Option<RedisInfo>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppProtoLogsBaseInfo {
    #[prost(uint64, tag = "1")]
    pub start_time: u64,
    #[prost(uint64, tag = "2")]
    pub end_time: u64,
    #[prost(uint64, tag = "3")]
    pub flow_id: u64,
    #[prost(uint64, tag = "4")]
    pub tap_port: u64,
    #[prost(uint32, tag = "5")]
    pub vtap_id: u32,
    #[prost(uint32, tag = "6")]
    pub tap_type: u32,
    #[prost(uint32, tag = "7")]
    pub is_ipv6: u32,
    #[prost(uint32, tag = "8")]
    pub tap_side: u32,
    #[prost(message, optional, tag = "9")]
    pub head: ::core::option::Option<AppProtoHead>,
    #[prost(uint64, tag = "10")]
    pub mac_src: u64,
    #[prost(uint64, tag = "11")]
    pub mac_dst: u64,
    #[prost(uint32, tag = "12")]
    pub ip_src: u32,
    #[prost(uint32, tag = "13")]
    pub ip_dst: u32,
    #[prost(bytes = "vec", tag = "14")]
    pub ip6_src: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "15")]
    pub ip6_dst: ::prost::alloc::vec::Vec<u8>,
    #[prost(int32, tag = "16")]
    pub l3_epc_id_src: i32,
    #[prost(int32, tag = "17")]
    pub l3_epc_id_dst: i32,
    #[prost(uint32, tag = "18")]
    pub port_src: u32,
    #[prost(uint32, tag = "19")]
    pub port_dst: u32,
    #[prost(uint32, tag = "20")]
    pub protocol: u32,
    #[prost(uint32, tag = "21")]
    pub is_vip_interface_src: u32,
    #[prost(uint32, tag = "22")]
    pub is_vip_interface_dst: u32,
    #[prost(uint32, tag = "23")]
    pub req_tcp_seq: u32,
    #[prost(uint32, tag = "24")]
    pub resp_tcp_seq: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AppProtoHead {
    #[prost(uint32, tag = "1")]
    pub proto: u32,
    #[prost(uint32, tag = "2")]
    pub msg_type: u32,
    #[prost(uint32, tag = "3")]
    pub status: u32,
    #[prost(uint32, tag = "4")]
    pub code: u32,
    #[prost(uint64, tag = "5")]
    pub rrt: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HttpInfo {
    #[prost(uint32, tag = "1")]
    pub stream_id: u32,
    #[prost(string, tag = "3")]
    pub version: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub method: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub path: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub host: ::prost::alloc::string::String,
    #[prost(string, tag = "7")]
    pub client_ip: ::prost::alloc::string::String,
    #[prost(string, tag = "8")]
    pub trace_id: ::prost::alloc::string::String,
    #[prost(string, tag = "9")]
    pub span_id: ::prost::alloc::string::String,
    #[prost(int64, tag = "10")]
    pub req_content_length: i64,
    #[prost(int64, tag = "11")]
    pub resp_content_length: i64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DnsInfo {
    #[prost(uint32, tag = "1")]
    pub trans_id: u32,
    #[prost(uint32, tag = "2")]
    pub query_type: u32,
    #[prost(string, tag = "3")]
    pub query_name: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub answers: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DubboInfo {
    #[prost(uint32, tag = "1")]
    pub serial_id: u32,
    #[prost(uint32, tag = "2")]
    pub r#type: u32,
    #[prost(uint32, tag = "4")]
    pub id: u32,
    #[prost(string, tag = "5")]
    pub version: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub service_name: ::prost::alloc::string::String,
    #[prost(string, tag = "7")]
    pub service_version: ::prost::alloc::string::String,
    #[prost(string, tag = "8")]
    pub method_name: ::prost::alloc::string::String,
    #[prost(int32, tag = "9")]
    pub req_body_len: i32,
    #[prost(int32, tag = "10")]
    pub resp_body_len: i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KafkaInfo {
    #[prost(uint32, tag = "1")]
    pub correlation_id: u32,
    #[prost(int32, tag = "2")]
    pub req_msg_size: i32,
    #[prost(uint32, tag = "3")]
    pub api_version: u32,
    #[prost(uint32, tag = "4")]
    pub api_key: u32,
    #[prost(string, tag = "5")]
    pub client_id: ::prost::alloc::string::String,
    #[prost(int32, tag = "6")]
    pub resp_msg_size: i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MysqlInfo {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    #[prost(string, tag = "2")]
    pub server_version: ::prost::alloc::string::String,
    #[prost(uint32, tag = "3")]
    pub server_thread_id: u32,
    #[prost(uint32, tag = "4")]
    pub command: u32,
    #[prost(string, tag = "5")]
    pub context: ::prost::alloc::string::String,
    #[prost(uint32, tag = "6")]
    pub response_code: u32,
    #[prost(uint64, tag = "7")]
    pub affected_rows: u64,
    #[prost(uint32, tag = "8")]
    pub error_code: u32,
    #[prost(string, tag = "9")]
    pub error_message: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RedisInfo {
    #[prost(string, tag = "1")]
    pub request: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub request_type: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub response: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub status: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub error: ::prost::alloc::string::String,
}
