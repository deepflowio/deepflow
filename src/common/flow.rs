use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use super::{Ethernet, IpProtocol, TapType};

use crate::utils::net::MacAddr;

type TapPort = u64;
type TunnelType = u8;
type CloseType = u8;

pub struct FlowKey {
    vtap_id: u16,
    tap_type: TapType,
    tap_port: TapPort,
    /* L2 */
    mac_src: MacAddr,
    mac_dst: MacAddr,
    /* L3 ipv4 or ipv6 */
    ip_src: IpAddr,
    ip_dst: IpAddr,

    port_src: u16,
    proto: IpProtocol,
}

#[repr(u8)]
pub enum FlowSource {
    Normal,
    Sflow,
    NetFlow,
}

pub struct TunnelField {
    tx_ip_0: Ipv4Addr,
    tx_ip_1: Ipv4Addr, // 对应发送方向的源目的隧道IP
    rx_ip_0: Ipv4Addr,
    rx_ip_1: Ipv4Addr, // 对应接收方向的源目的隧道IP
    tx_mac_0: u32,
    tx_mac_1: u32, // 对应发送方向的源目的隧道MAC，低4字节
    rx_mac_0: u32,
    rx_mac_1: u32, // 对应接收方向的源目的隧道MAC，低4字节
    tx_id: u32,
    rx_id: u32,
    tunnel_type: TunnelType,
    tier: u8,
    is_ipv6: bool,
}

pub struct TcpPerfCountsPeer {
    retrans_count: u32,
    zero_win_count: u32,
    first_seq_id: u32,
}

// UDPPerfStats仅有2个字段，复用art_max, art_sum, art_count
pub struct TcpPerfStats {
    // 除特殊说明外，均为每个流统计周期（目前是自然分）清零
    rtt_client_max: u32, // us, agent保证时延最大值不会超过3600s，能容纳在u32内
    rtt_server_max: u32, // us
    srt_max: u32,        // us
    art_max: u32,        // us, UDP复用

    rtt: u32,            // us, TCP建连过程, 只会计算出一个RTT
    rtt_client_sum: u32, // us, 假定一条流在一分钟内的时延加和不会超过u32
    rtt_server_sum: u32, // us
    srt_sum: u32,        // us
    art_sum: u32,        // us

    rtt_client_count: u32,
    rtt_server_count: u32,
    srt_count: u32,
    art_count: u32, // UDP复用

    counts_peers: [TcpPerfCountsPeer; 2],
    total_retrans_count: u32,
}

pub struct FlowPerfStats {
    tcp: TcpPerfStats,
    l7: L7PerfStats,
    l4_protocol: L4Protocol,
    l7_protocol: L7Protocol,
}

impl FlowPerfStats {
    pub fn sequential_merge(&mut self, s: &FlowPerfStats) {}
}

pub struct L7PerfStats {
    request_count: u32,
    response_count: u32,
    err_client_count: u32, // client端原因导致的响应异常数量
    err_server_count: u32, // server端原因导致的响应异常数量
    err_timeout: u32,      // request请求timeout数量
    rrt_count: u32,        // u32可记录40000M时延, 一条流在一分钟内的请求数远无法达到此数值
    rrt_sum: u64,          // us RRT(Request Response Time)
    rrt_max: u32,          // us agent保证在3600s以内
}

#[repr(u8)]
pub enum L4Protocol {
    Unknown = 0,
    Tcp = 1,
    Udp = 2,
    Max = 3,
}

#[repr(u8)]
pub enum L7Protocol {
    Unknown = 0,
    Http = 1,
    Dns = 2,
    Mysql = 3,
    Redis = 4,
    Dubbo = 5,
    Kafka = 6,
    other = 7,
    Max = 8,
}

pub struct FlowMetricsPeer {
    nat_real_ip: IpAddr, // IsVIP为true，通过MAC查询对应的IP

    byte_count: u64,         // 每个流统计周期（目前是自然秒）清零
    l3_byte_count: u64,      // 每个流统计周期的L3载荷量
    l4_byte_count: u64,      // 每个流统计周期的L4载荷量
    packet_count: u64,       // 每个流统计周期（目前是自然秒）清零
    total_byte_count: u64,   // 整个Flow生命周期的统计量
    total_packet_count: u64, // 整个Flow生命周期的统计量
    first: Duration,         // 整个Flow生命周期首包的时间戳
    last: Duration,          // 整个Flow生命周期尾包的时间戳

    l3_epc_id: i32,
    is_l2_end: bool,
    is_l3_end: bool,
    is_active_host: bool,
    is_device: bool,        // ture表明是从平台数据获取的
    tcp_flags: u8,          // 所有TCP的Flags的或运算结果
    is_vip_interface: bool, // 目前仅支持微软Mux设备，从grpc Interface中获取
    is_vip: bool,           // 从grpc cidr中获取
    is_local_mac: bool,     // 同EndpointInfo中的IsLocalMac, 流日志中不需要存储
    is_local_ip: bool,      // 同EndpointInfo中的IsLocalIp, 流日志中不需要存储
}

impl FlowMetricsPeer {
    pub fn sequential_merge(&mut self, other: &FlowMetricsPeer) {}
}

pub struct Flow {
    flow_key: FlowKey,
    flow_metrics_peers: [FlowMetricsPeer; 2],

    tunnel: TunnelField,

    flow_id: u64,

    start_time: Duration,
    end_time: Duration,
    duration: Duration,
    flow_start_time: Duration,

    vlan: u16,
    eth_type: Ethernet,

    /* TCP Perf Data*/
    flow_perf_stats: Option<FlowPerfStats>,
    close_type: CloseType,
    flow_source: FlowSource,
    is_active_service: bool,
    queue_hash: u8,
    is_new_flow: bool,
    tap_side: u8,
}
