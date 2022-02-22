use std::{
    fmt,
    mem::swap,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use log::warn;

use super::{
    decapsulate::TunnelType,
    enums::{EthernetType, IpProtocol, TapType, TcpFlags},
    tap_port::TapPort,
};

use crate::flow_generator::FlowState;
use crate::utils::net::MacAddr;

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum CloseType {
    Unknown = 0,
    TcpFin = 1,                 //  1: 正常结束
    TcpServerRst = 2,           //  2: 传输-服务端重置
    Timeout = 3,                //  3: 连接超时
    ForcedReport = 5,           //  5: 周期性上报
    ClientSynRepeat = 7,        //  7: 建连-客户端SYN结束
    ServerHalfClose = 8,        //  8: 断连-服务端半关
    TcpClientRst = 9,           //  9: 传输-客户端重置
    ServerSynAckRepeat = 10,    // 10: 建连-服务端SYN结束
    ClientHalfClose = 11,       // 11: 断连-客户端半关
    ClientSourcePortReuse = 13, // 13: 建连-客户端端口复用
    ServerReset = 15,           // 15: 建连-服务端直接重置
    ServerQueueLack = 17,       // 17: 传输-服务端队列溢出
    ClientEstablishReset = 18,  // 18: 建连-客户端其他重置
    ServerEstablishReset = 19,  // 19: 建连-服务端其他重置
    Max = 20,
}

impl CloseType {
    pub fn is_client_error(self) -> bool {
        self == CloseType::ClientSynRepeat
            || self == CloseType::TcpClientRst
            || self == CloseType::ClientHalfClose
            || self == CloseType::ClientSourcePortReuse
            || self == CloseType::ClientEstablishReset
    }

    pub fn is_server_error(self) -> bool {
        self == CloseType::TcpServerRst
            || self == CloseType::Timeout
            || self == CloseType::ServerHalfClose
            || self == CloseType::ServerSynAckRepeat
            || self == CloseType::ServerReset
            || self == CloseType::ServerQueueLack
            || self == CloseType::ServerEstablishReset
    }
}

impl Default for CloseType {
    fn default() -> Self {
        CloseType::Unknown
    }
}

pub struct FlowKey {
    pub vtap_id: u16,
    pub tap_type: TapType,
    pub tap_port: TapPort,
    /* L2 */
    pub mac_src: MacAddr,
    pub mac_dst: MacAddr,
    /* L3 ipv4 or ipv6 */
    pub ip_src: IpAddr,
    pub ip_dst: IpAddr,
    /* L4 */
    pub port_src: u16,
    pub port_dst: u16,
    pub proto: IpProtocol,
}

impl FlowKey {
    pub fn reverse(&mut self) {
        swap(&mut self.mac_src, &mut self.mac_dst);
        swap(&mut self.ip_src, &mut self.ip_dst);
        swap(&mut self.port_src, &mut self.port_dst);
    }
}

impl Default for FlowKey {
    fn default() -> Self {
        FlowKey {
            ip_src: Ipv4Addr::UNSPECIFIED.into(),
            ip_dst: Ipv4Addr::UNSPECIFIED.into(),
            vtap_id: 0,
            tap_type: TapType::default(),
            tap_port: TapPort::default(),
            mac_src: MacAddr::default(),
            mac_dst: MacAddr::default(),
            port_src: 0,
            port_dst: 0,
            proto: IpProtocol::default(),
        }
    }
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "vtap_id:{} tap_type:{} tap_port:{} mac_src:{} mac_dst:{} ip_src:{} ip_dst:{} proto:{:?} port_src:{} port_dst:{}",
            self.vtap_id,
            self.tap_type,
            self.tap_port,
            self.mac_src,
            self.mac_dst,
            self.ip_src,
            self.ip_dst,
            self.proto,
            self.port_src,
            self.port_dst
        )
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum FlowSource {
    Normal = 0,
    Sflow = 1,
    NetFlow = 2,
}

impl Default for FlowSource {
    fn default() -> Self {
        FlowSource::Normal
    }
}

#[derive(Debug)]
pub struct TunnelField {
    pub tx_ip0: Ipv4Addr, // 对应发送方向的源隧道IP
    pub tx_ip1: Ipv4Addr, // 对应发送方向的目的隧道IP
    pub rx_ip0: Ipv4Addr, // 对应接收方向的源隧道IP
    pub rx_ip1: Ipv4Addr, // 对应接收方向的目的隧道IP
    pub tx_mac0: u32,     // 对应发送方向的源隧道MAC，低4字节
    pub tx_mac1: u32,     // 对应发送方向的目的隧道MAC，低4字节
    pub rx_mac0: u32,     // 对应接收方向的源隧道MAC，低4字节
    pub rx_mac1: u32,     // 对应接收方向的目的隧道MAC，低4字节
    pub tx_id: u32,
    pub rx_id: u32,
    pub tunnel_type: TunnelType,
    pub tier: u8,
    pub is_ipv6: bool,
}

impl Default for TunnelField {
    fn default() -> Self {
        TunnelField {
            tx_ip0: Ipv4Addr::UNSPECIFIED,
            tx_ip1: Ipv4Addr::UNSPECIFIED,
            rx_ip0: Ipv4Addr::UNSPECIFIED,
            rx_ip1: Ipv4Addr::UNSPECIFIED,
            tx_mac0: 0,
            tx_mac1: 0,
            rx_mac0: 0,
            rx_mac1: 0,
            tx_id: 0,
            rx_id: 0,
            tunnel_type: TunnelType::default(),
            tier: 0,
            is_ipv6: false,
        }
    }
}

impl TunnelField {
    pub fn reverse(&mut self) {
        swap(&mut self.tx_ip0, &mut self.rx_ip0);
        swap(&mut self.tx_ip1, &mut self.rx_ip1);
        swap(&mut self.tx_mac0, &mut self.rx_mac0);
        swap(&mut self.tx_mac1, &mut self.rx_mac1);
        swap(&mut self.tx_id, &mut self.rx_id);
    }
}

impl fmt::Display for TunnelField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.tunnel_type == TunnelType::None {
            write!(f, "none")
        } else {
            write!(
            f,
            "{}, tx_id:{}, rx_id:{}, tier:{}, tx_0:{} {:08x}, tx_1:{} {:08x}, rx_0:{} {:08x}, rx_1:{} {:08x}",
            self.tunnel_type, self.tx_id, self.rx_id, self.tier,
            self.tx_ip0, self.tx_mac0,
            self.tx_ip1, self.tx_mac1,
            self.rx_ip0, self.rx_mac0,
            self.rx_ip1, self.rx_mac1,
            )
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct TcpPerfCountsPeer {
    pub retrans_count: u32,
    pub zero_win_count: u32,
}

impl TcpPerfCountsPeer {
    pub fn sequential_merge(&mut self, other: &TcpPerfCountsPeer) {
        self.retrans_count += other.retrans_count;
        self.zero_win_count += other.zero_win_count;
    }
}

#[derive(Debug, Default, Clone)]
// UDPPerfStats仅有2个字段，复用art_max, art_sum, art_count
pub struct TcpPerfStats {
    // 除特殊说明外，均为每个流统计周期（目前是自然分）清零
    pub rtt_client_max: u32, // us, agent保证时延最大值不会超过3600s，能容纳在u32内
    pub rtt_server_max: u32, // us
    pub srt_max: u32,        // us
    pub art_max: u32,        // us, UDP复用

    pub rtt: u32,            // us, TCP建连过程, 只会计算出一个RTT
    pub rtt_client_sum: u32, // us, 假定一条流在一分钟内的时延加和不会超过u32
    pub rtt_server_sum: u32, // us
    pub srt_sum: u32,        // us
    pub art_sum: u32,        // us

    pub rtt_client_count: u32,
    pub rtt_server_count: u32,
    pub srt_count: u32,
    pub art_count: u32, // UDP复用

    pub counts_peers: [TcpPerfCountsPeer; 2],
    pub total_retrans_count: u32,
}

impl TcpPerfStats {
    pub fn sequential_merge(&mut self, other: &TcpPerfStats) {
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
        if self.rtt < other.rtt {
            self.rtt = other.rtt;
        }
        self.rtt_client_sum += other.rtt_client_sum;
        self.rtt_server_sum += other.rtt_server_sum;
        self.srt_sum += other.srt_sum;
        self.art_sum += other.art_sum;

        self.rtt_client_count += other.rtt_client_count;
        self.rtt_server_count += other.rtt_server_count;
        self.srt_count += other.srt_count;
        self.art_count += other.art_count;
        self.counts_peers[0].sequential_merge(&other.counts_peers[0]);
        self.counts_peers[1].sequential_merge(&other.counts_peers[1]);
        self.total_retrans_count += other.total_retrans_count;
    }

    pub fn reverse(&mut self) {
        swap(&mut self.rtt_client_sum, &mut self.rtt_server_sum);
        swap(&mut self.rtt_client_count, &mut self.rtt_server_count);
        self.counts_peers.swap(0, 1);
    }
}

#[derive(Debug, Default, Clone)]
pub struct FlowPerfStats {
    pub tcp: TcpPerfStats,
    pub l7: L7PerfStats,
    pub l4_protocol: L4Protocol,
    pub l7_protocol: L7Protocol,
}

impl FlowPerfStats {
    pub fn sequential_merge(&mut self, other: &FlowPerfStats) {
        if self.l4_protocol == L4Protocol::Unknown {
            self.l4_protocol = other.l4_protocol;
        }

        if self.l7_protocol == L7Protocol::Unknown
            || (self.l7_protocol == L7Protocol::Other && other.l7_protocol != L7Protocol::Unknown)
        {
            self.l7_protocol = other.l7_protocol;
        }
        self.tcp.sequential_merge(&other.tcp);
        self.l7.sequential_merge(&other.l7);
    }

    pub fn reverse(&mut self) {
        self.tcp.reverse()
    }
}

impl fmt::Display for FlowPerfStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "l4_protocol:{:?} tcp_perf_stats:{:?} \n\t l7_protocol:{:?} l7_perf_stats:{:?}",
            self.l4_protocol, self.tcp, self.l7_protocol, self.l7
        )
    }
}

#[derive(Debug, Default, Clone)]
pub struct L7PerfStats {
    pub request_count: u32,
    pub response_count: u32,
    pub err_client_count: u32, // client端原因导致的响应异常数量
    pub err_server_count: u32, // server端原因导致的响应异常数量
    pub err_timeout: u32,      // request请求timeout数量
    pub rrt_count: u32,        // u32可记录40000M时延, 一条流在一分钟内的请求数远无法达到此数值
    pub rrt_sum: u64,          // us RRT(Request Response Time)
    pub rrt_max: u32,          // us agent保证在3600s以内
}

impl L7PerfStats {
    pub fn sequential_merge(&mut self, other: &L7PerfStats) {
        self.request_count += other.request_count;
        self.response_count += other.response_count;
        self.err_client_count += other.err_client_count;
        self.err_server_count += other.err_server_count;
        self.err_timeout += other.err_timeout;
        self.rrt_count += other.rrt_count;
        self.rrt_sum += other.rrt_sum;
        if self.rrt_max < other.rrt_max {
            self.rrt_max = other.rrt_max
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum L4Protocol {
    Unknown = 0,
    Tcp = 1,
    Udp = 2,
}

impl Default for L4Protocol {
    fn default() -> Self {
        L4Protocol::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum L7Protocol {
    Unknown = 0,
    Http = 1,
    Dns = 2,
    Mysql = 3,
    Redis = 4,
    Dubbo = 5,
    Kafka = 6,
    Other = 7,
    Max = 8,
}

impl Default for L7Protocol {
    fn default() -> Self {
        L7Protocol::Unknown
    }
}

#[derive(Debug)]
pub struct FlowMetricsPeer {
    pub nat_real_ip: IpAddr, // IsVIP为true，通过MAC查询对应的IP

    pub byte_count: u64,         // 每个流统计周期（目前是自然秒）清零
    pub l3_byte_count: u64,      // 每个流统计周期的L3载荷量
    pub l4_byte_count: u64,      // 每个流统计周期的L4载荷量
    pub packet_count: u64,       // 每个流统计周期（目前是自然秒）清零
    pub total_byte_count: u64,   // 整个Flow生命周期的统计量
    pub total_packet_count: u64, // 整个Flow生命周期的统计量
    pub first: Duration,         // 整个Flow生命周期首包的时间戳
    pub last: Duration,          // 整个Flow生命周期尾包的时间戳

    pub l3_epc_id: i32,
    pub is_l2_end: bool,
    pub is_l3_end: bool,
    pub is_active_host: bool,
    pub is_device: bool,        // ture表明是从平台数据获取的
    pub tcp_flags: TcpFlags,    // 所有TCP的Flags的或运算结果
    pub is_vip_interface: bool, // 目前仅支持微软Mux设备，从grpc Interface中获取
    pub is_vip: bool,           // 从grpc cidr中获取
    pub is_local_mac: bool,     // 同EndpointInfo中的IsLocalMac, 流日志中不需要存储
    pub is_local_ip: bool,      // 同EndpointInfo中的IsLocalIp, 流日志中不需要存储
}

impl Default for FlowMetricsPeer {
    fn default() -> Self {
        FlowMetricsPeer {
            nat_real_ip: Ipv4Addr::UNSPECIFIED.into(),
            byte_count: 0,
            l3_byte_count: 0,
            l4_byte_count: 0,
            packet_count: 0,
            total_byte_count: 0,
            total_packet_count: 0,
            first: Duration::default(),
            last: Duration::default(),

            l3_epc_id: 0,
            is_l2_end: false,
            is_l3_end: false,
            is_active_host: false,
            is_device: false,
            tcp_flags: TcpFlags::empty(),
            is_vip_interface: false,
            is_vip: false,
            is_local_mac: false,
            is_local_ip: false,
        }
    }
}

impl FlowMetricsPeer {
    pub const SRC: u8 = 0;
    pub const DST: u8 = 1;
    pub fn sequential_merge(&mut self, other: &FlowMetricsPeer) {
        self.byte_count += other.byte_count;
        self.l3_byte_count += other.l3_byte_count;
        self.l4_byte_count += other.l4_byte_count;
        self.packet_count += other.packet_count;
        self.total_byte_count += other.total_byte_count;
        self.total_packet_count += other.total_packet_count;
        self.first = other.first;
        self.last = other.last;

        self.l3_epc_id = other.l3_epc_id;
        self.is_l2_end = other.is_l2_end;
        self.is_l3_end = other.is_l3_end;
        self.is_active_host = other.is_active_host;
        self.is_device = other.is_device;
        self.tcp_flags |= other.tcp_flags;
        self.is_vip_interface = other.is_vip_interface;
        self.is_vip = other.is_vip;
        self.is_local_mac = other.is_local_mac;
        self.is_local_ip = other.is_local_ip;
    }
}

#[derive(Default)]
pub struct Flow {
    pub flow_key: FlowKey,
    pub flow_metrics_peers: [FlowMetricsPeer; 2],

    pub tunnel: TunnelField,

    pub flow_id: u64,

    /* TCP Seq */
    pub syn_seq: u32,
    pub syn_ack_seq: u32,
    pub last_keepalive_seq: u32,
    pub last_keepalive_ack: u32,

    pub start_time: Duration,
    pub end_time: Duration,
    pub duration: Duration,
    pub flow_start_time: Duration,

    /* L2 */
    pub vlan: u16,
    pub eth_type: EthernetType,

    /* TCP Perf Data*/
    pub flow_perf_stats: Option<FlowPerfStats>,

    pub close_type: CloseType,
    pub flow_source: FlowSource,
    pub is_active_service: bool,
    pub queue_hash: u8,
    pub is_new_flow: bool,
    pub reversed: bool,
    pub tap_side: u8,
}

impl Flow {
    pub fn sequential_merge(&mut self, other: &Flow) {
        self.flow_metrics_peers[0].sequential_merge(&other.flow_metrics_peers[0]);
        self.flow_metrics_peers[1].sequential_merge(&other.flow_metrics_peers[1]);

        self.end_time = other.end_time;
        self.duration = other.duration;

        if other.flow_perf_stats.is_some() {
            let x = other.flow_perf_stats.as_ref().unwrap();
            if self.flow_perf_stats.is_none() {
                self.flow_perf_stats = Some(x.clone());
            } else {
                self.flow_perf_stats.as_mut().unwrap().sequential_merge(&x)
            }
        }

        self.close_type = other.close_type;
        self.is_active_service = other.is_active_service;
        self.reversed = other.reversed;

        if other.last_keepalive_seq != 0 {
            self.last_keepalive_seq = other.last_keepalive_seq;
        }
        if other.last_keepalive_ack != 0 {
            self.last_keepalive_ack = other.last_keepalive_ack;
        }
    }

    // FIXME 注意：由于FlowGenerator中TcpPerfStats在Flow方向调整之后才获取到，
    // 因此这里不包含对TcpPerfStats的反向。
    pub fn reverse(&mut self) {
        self.reversed = !self.reversed;
        self.tap_side = 0;
        self.tunnel.reverse();
        self.flow_key.reverse();
        self.flow_metrics_peers.swap(0, 1);
    }

    pub fn update_close_type(&mut self, flow_state: FlowState) {
        self.close_type = match flow_state {
            FlowState::Exception => CloseType::Unknown,
            FlowState::Opening1 => CloseType::ClientSynRepeat,
            FlowState::Opening2 => CloseType::ServerSynAckRepeat,
            FlowState::Established => CloseType::Timeout,
            FlowState::ClosingTx1 => CloseType::ServerHalfClose,
            FlowState::ClosingRx1 => CloseType::ClientHalfClose,
            FlowState::ClosingTx2 | FlowState::ClosingRx2 | FlowState::Closed => CloseType::TcpFin,
            FlowState::Reset => {
                if self.flow_metrics_peers[FlowMetricsPeer::DST as usize]
                    .tcp_flags
                    .contains(TcpFlags::RST)
                {
                    CloseType::TcpServerRst
                } else {
                    CloseType::TcpClientRst
                }
            }
            FlowState::Syn1 | FlowState::ClientL4PortReuse => CloseType::ClientSourcePortReuse,
            FlowState::ServerReset => CloseType::ServerReset,
            FlowState::SynAck1 => CloseType::ServerQueueLack,
            FlowState::ServerCandidateQueueLack => {
                const TCP_SYN_RETRANSE_MIN_TIMES: u64 = 3;
                if self.flow_metrics_peers[FlowMetricsPeer::DST as usize].total_packet_count
                    > TCP_SYN_RETRANSE_MIN_TIMES
                {
                    CloseType::ServerQueueLack
                } else {
                    CloseType::TcpClientRst
                }
            }
            FlowState::EstablishReset => {
                if self.flow_metrics_peers[FlowMetricsPeer::DST as usize]
                    .tcp_flags
                    .contains(TcpFlags::RST)
                {
                    CloseType::ServerEstablishReset
                } else {
                    CloseType::ClientEstablishReset
                }
            }
            _ => {
                warn!(
                    "unexpected 'unknown' close type, flow id is {}",
                    self.flow_id
                );
                CloseType::Unknown
            }
        }
    }
}

impl fmt::Display for Flow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "flow_id:{} flow_source:{:?} tunnel:{} close_type:{:?} is_active_service:{} is_new_flow:{} queue_hash:{} \
        syn_seq:{} syn_ack_seq:{} last_keepalive_seq:{} last_keepalive_ack:{} flow_start_time:{:?} \
        \t start_time:{:?} end_time:{:?} duration:{:?} \
        \t vlan:{} eth_type:{:?} reversed:{} flow_key:{} \
        \n\t flow_metrics_peers_src:{:?} \
        \n\t flow_metrics_peers_dst:{:?} \
        \n\t flow_perf_stats:{:?}",
            self.flow_id, self.flow_source, self.tunnel, self.close_type, self.is_active_service, self.is_new_flow, self.queue_hash,
            self.syn_seq, self.syn_ack_seq, self.last_keepalive_seq, self.last_keepalive_ack, self.flow_start_time,
            self.start_time, self.end_time, self.duration,
            self.vlan, self.eth_type, self.reversed, self.flow_key,
            self.flow_metrics_peers[0],
            self.flow_metrics_peers[1],
            self.flow_perf_stats
        )
    }
}
