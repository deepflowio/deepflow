/*
 * Copyright (c) 2024 Yunshan Networks
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

use std::{
    fmt::{self, Display},
    mem::swap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process,
    sync::Arc,
    thread,
    time::Duration,
};

use log::{error, warn};
use serde::{Serialize, Serializer};

#[cfg(any(target_os = "linux", target_os = "android"))]
use super::super::ebpf::{MSG_REQUEST, MSG_REQUEST_END, MSG_RESPONSE, MSG_RESPONSE_END};
use super::{
    decapsulate::TunnelType,
    enums::{EthernetType, IpProtocol, TapType, TcpFlags},
    tap_port::TapPort,
    TaggedFlow,
};

use crate::{
    common::{endpoint::EPC_INTERNET, timestamp_to_micros, Timestamp},
    metric::document::Direction,
};
use crate::{
    flow_generator::protocol_logs::to_string_format,
    flow_generator::FlowState,
    metric::document::TapSide,
    utils::environment::{is_tt_pod, is_tt_workload},
};
use public::utils::net::MacAddr;
use public::{
    buffer::BatchedBox,
    packet::SECONDS_IN_MINUTE,
    proto::{common::TridentType, flow_log},
};

pub use public::enums::L4Protocol;
pub use public::l7_protocol::*;

const COUNTER_FLOW_ID_MASK: u64 = 0x00FFFFFF;

#[derive(Serialize, Debug, PartialEq, Clone, Copy)]
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
    TcpFinClientRst = 20,       // 20: 正常结束-客户端重置
    Max = 21,
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

#[derive(Serialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct FlowKey {
    pub vtap_id: u16,
    pub tap_type: TapType,
    #[serde(serialize_with = "to_string_format")]
    pub tap_port: TapPort,
    /* L2 */
    #[serde(serialize_with = "to_string_format")]
    pub mac_src: MacAddr,
    #[serde(serialize_with = "to_string_format")]
    pub mac_dst: MacAddr,
    /* L3 ipv4 or ipv6 */
    pub ip_src: IpAddr,
    pub ip_dst: IpAddr,
    /* L4 */
    pub port_src: u16,
    pub port_dst: u16,
    #[serde(rename = "protocol")]
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

impl From<FlowKey> for flow_log::FlowKey {
    fn from(f: FlowKey) -> Self {
        let (ip4_src, ip4_dst, ip6_src, ip6_dst) = match (f.ip_src, f.ip_dst) {
            (IpAddr::V4(ip4), IpAddr::V4(ip4_1)) => {
                (ip4, ip4_1, Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED)
            }
            (IpAddr::V6(ip6), IpAddr::V6(ip6_1)) => {
                (Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, ip6, ip6_1)
            }
            _ => panic!("FlowKey({:?}) ip_src,ip_dst type mismatch", &f),
        };
        flow_log::FlowKey {
            vtap_id: f.vtap_id as u32,
            tap_type: u16::from(f.tap_type) as u32,
            tap_port: f.tap_port.0,
            mac_src: f.mac_src.into(),
            mac_dst: f.mac_dst.into(),
            ip_src: u32::from_be_bytes(ip4_src.octets()),
            ip_dst: u32::from_be_bytes(ip4_dst.octets()),
            ip6_src: ip6_src.octets().to_vec(),
            ip6_dst: ip6_dst.octets().to_vec(),
            port_src: f.port_src as u32,
            port_dst: f.port_dst as u32,
            proto: u8::from(f.proto) as u32,
        }
    }
}

#[derive(Serialize, Debug, Clone, Copy, PartialOrd, PartialEq, Eq, Ord)]
#[repr(u8)]
pub enum SignalSource {
    Packet = 0, // Packet data from AF_PACKET/Winpcap
    XFlow = 1,  // Flow data from NetFlow/sFlow/NetStream
    // 2 reserved
    EBPF = 3, // Function call data from eBPF
    OTel = 4, // Tracing data received using the OTLP protocol, such as otel-collector data
}

impl Default for SignalSource {
    fn default() -> Self {
        SignalSource::Packet
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct TunnelField {
    #[serde(rename = "tunnel_tx_ip_0")]
    pub tx_ip0: Ipv4Addr, // 对应发送方向的源隧道IP
    #[serde(rename = "tunnel_tx_ip_1")]
    pub tx_ip1: Ipv4Addr, // 对应发送方向的目的隧道IP
    #[serde(rename = "tunnel_rx_ip_0")]
    pub rx_ip0: Ipv4Addr, // 对应接收方向的源隧道IP
    #[serde(rename = "tunnel_rx_ip_1")]
    pub rx_ip1: Ipv4Addr, // 对应接收方向的目的隧道IP
    #[serde(rename = "tunnel_tx_mac_0", serialize_with = "mac_low32_to_string")]
    pub tx_mac0: u32, // 对应发送方向的源隧道MAC，低4字节
    #[serde(rename = "tunnel_tx_mac_1", serialize_with = "mac_low32_to_string")]
    pub tx_mac1: u32, // 对应发送方向的目的隧道MAC，低4字节
    #[serde(rename = "tunnel_rx_mac_0", serialize_with = "mac_low32_to_string")]
    pub rx_mac0: u32, // 对应接收方向的源隧道MAC，低4字节
    #[serde(rename = "tunnel_rx_mac_1", serialize_with = "mac_low32_to_string")]
    pub rx_mac1: u32, // 对应接收方向的目的隧道MAC，低4字节
    #[serde(rename = "tunnel_tx_id")]
    pub tx_id: u32,
    #[serde(rename = "tunnel_rx_id")]
    pub rx_id: u32,
    pub tunnel_type: TunnelType,
    #[serde(rename = "tunnel_tier")]
    pub tier: u8,
    #[serde(skip)]
    pub is_ipv6: bool,
}

pub fn mac_low32_to_string<S>(d: &u32, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("{:08x}", d))
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

impl From<TunnelField> for flow_log::TunnelField {
    fn from(f: TunnelField) -> Self {
        flow_log::TunnelField {
            tx_ip0: u32::from_be_bytes(f.tx_ip0.octets()),
            tx_ip1: u32::from_be_bytes(f.tx_ip1.octets()),
            rx_ip0: u32::from_be_bytes(f.rx_ip0.octets()),
            rx_ip1: u32::from_be_bytes(f.rx_ip1.octets()),
            tx_mac0: f.tx_mac0.into(),
            tx_mac1: f.tx_mac1.into(),
            rx_mac0: f.rx_mac0.into(),
            rx_mac1: f.rx_mac1.into(),
            tx_id: f.tx_id,
            rx_id: f.rx_id,
            tunnel_type: f.tunnel_type as u32,
            tier: f.tier as u32,
            is_ipv6: 0,
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

impl From<TcpPerfCountsPeer> for flow_log::TcpPerfCountsPeer {
    fn from(p: TcpPerfCountsPeer) -> Self {
        flow_log::TcpPerfCountsPeer {
            retrans_count: p.retrans_count,
            zero_win_count: p.zero_win_count,
        }
    }
}

#[derive(Serialize, Debug, Default, Clone)]
// UDPPerfStats仅有2个字段，复用art_max, art_sum, art_count
pub struct TcpPerfStats {
    // 除特殊说明外，均为每个流统计周期（目前是自然分）清零
    pub rtt_client_max: u32, // us, agent保证时延最大值不会超过3600s，能容纳在u32内
    pub rtt_server_max: u32, // us
    pub srt_max: u32,        // us
    pub art_max: u32,        // us, UDP复用
    pub cit_max: u32, // us, the max time between the client request and the last server response (Payload > 1)

    pub rtt: u32,            // us, TCP建连过程, 只会计算出一个RTT
    pub rtt_client_sum: u32, // us, 假定一条流在一分钟内的时延加和不会超过u32
    pub rtt_server_sum: u32, // us
    pub srt_sum: u32,        // us
    pub art_sum: u32,        // us
    pub cit_sum: u32,        // us

    pub rtt_client_count: u32,
    pub rtt_server_count: u32,
    pub srt_count: u32,
    pub art_count: u32, // UDP复用
    pub cit_count: u32,

    pub syn_count: u32,
    pub synack_count: u32,

    #[serde(rename = "retrans_syn")]
    pub retrans_syn_count: u32,
    #[serde(rename = "retrans_synack")]
    pub retrans_synack_count: u32,

    #[serde(flatten, serialize_with = "serialize_tcp_perf_counts")]
    pub counts_peers: [TcpPerfCountsPeer; 2],
    #[serde(skip)]
    pub total_retrans_count: u32,
}

pub fn serialize_tcp_perf_counts<S>(
    v: &[TcpPerfCountsPeer; 2],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    #[derive(Serialize)]
    struct Ser {
        pub retrans_tx: u32,
        pub retrans_rx: u32,
        pub zero_win_tx: u32,
        pub zero_win_rx: u32,
    }
    let s = Ser {
        retrans_tx: v[0].retrans_count,
        retrans_rx: v[1].retrans_count,
        zero_win_tx: v[0].zero_win_count,
        zero_win_rx: v[1].zero_win_count,
    };
    serializer.serialize_newtype_struct("tcp_perf_counts", &s)
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
        if self.cit_max < other.cit_max {
            self.cit_max = other.cit_max;
        }

        self.rtt_client_sum += other.rtt_client_sum;
        self.rtt_server_sum += other.rtt_server_sum;
        self.srt_sum += other.srt_sum;
        self.art_sum += other.art_sum;
        self.cit_sum += other.cit_sum;

        self.rtt_client_count += other.rtt_client_count;
        self.rtt_server_count += other.rtt_server_count;
        self.srt_count += other.srt_count;
        self.art_count += other.art_count;
        self.syn_count += other.syn_count;
        self.cit_count += other.cit_count;
        self.synack_count += other.synack_count;
        self.retrans_syn_count += other.retrans_syn_count;
        self.retrans_synack_count += other.retrans_synack_count;
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

impl From<TcpPerfStats> for flow_log::TcpPerfStats {
    fn from(p: TcpPerfStats) -> Self {
        flow_log::TcpPerfStats {
            rtt_client_max: p.rtt_client_max,
            rtt_server_max: p.rtt_server_max,
            srt_max: p.srt_max,
            art_max: p.art_max,
            rtt: p.rtt,
            srt_sum: p.srt_sum,
            art_sum: p.art_sum,
            srt_count: p.srt_count,
            art_count: p.art_count,
            counts_peer_tx: Some(p.counts_peers[0].into()),
            counts_peer_rx: Some(p.counts_peers[1].into()),
            total_retrans_count: p.total_retrans_count,
            cit_count: p.cit_count,
            cit_sum: p.cit_sum,
            cit_max: p.cit_max,
            syn_count: p.syn_count,
            synack_count: p.synack_count,
            ..Default::default()
        }
    }
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct FlowPerfStats {
    #[serde(flatten)]
    pub tcp: TcpPerfStats,
    #[serde(flatten)]
    pub l7: L7PerfStats,
    pub l4_protocol: L4Protocol,
    pub l7_protocol: L7Protocol,
    pub l7_failed_count: u32,
}

impl FlowPerfStats {
    pub fn sequential_merge(&mut self, other: &FlowPerfStats) {
        if self.l4_protocol == L4Protocol::Unknown {
            self.l4_protocol = other.l4_protocol;
        }

        if self.l7_protocol == L7Protocol::Unknown && other.l7_protocol != L7Protocol::Unknown {
            self.l7_protocol = other.l7_protocol;
        }

        self.l7_failed_count = self.l7_failed_count.max(other.l7_failed_count);

        self.tcp.sequential_merge(&other.tcp);
        self.l7.sequential_merge(&other.l7);
    }

    pub fn reverse(&mut self) {
        self.tcp.reverse()
    }

    pub fn reset_on_plugin_reload(&mut self) {
        if matches!(self.l7_protocol, L7Protocol::Custom) {
            self.l7 = Default::default();
            self.l7_protocol = Default::default();
            self.l7_failed_count = Default::default();
        }
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

impl From<FlowPerfStats> for flow_log::FlowPerfStats {
    fn from(p: FlowPerfStats) -> Self {
        flow_log::FlowPerfStats {
            tcp: Some(p.tcp.into()),
            l7: Some(p.l7.into()),
            l4_protocol: p.l4_protocol as u32,
            l7_protocol: p.l7_protocol as u32,
            l7_failed_count: p.l7_failed_count,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct L7Stats {
    pub stats: L7PerfStats,
    pub flow: Option<Arc<BatchedBox<TaggedFlow>>>,
    pub endpoint: Option<String>,
    pub flow_id: u64,
    pub l7_protocol: L7Protocol,
    pub signal_source: SignalSource,
    pub time_in_second: Duration,
    pub biz_type: u8,
}

#[derive(Serialize, Debug, Default, Clone, PartialEq, Eq)]
pub struct L7PerfStats {
    #[serde(rename = "l7_request")]
    pub request_count: u32,
    #[serde(rename = "l7_response")]
    pub response_count: u32,
    #[serde(rename = "l7_client_error")]
    pub err_client_count: u32, // client端原因导致的响应异常数量
    #[serde(rename = "l7_server_error")]
    pub err_server_count: u32, // server端原因导致的响应异常数量
    #[serde(rename = "l7_server_timeout")]
    pub err_timeout: u32, // request请求timeout数量
    pub rrt_count: u32, // u32可记录40000M时延, 一条流在一分钟内的请求数远无法达到此数值
    pub rrt_sum: u64,   // us RRT(Request Response Time)
    pub rrt_max: u32,   // us agent保证在3600s以内
    pub tls_rtt: u32,
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
        self.tls_rtt += other.tls_rtt;
    }

    pub fn merge_perf(
        &mut self,
        req_count: u32,
        resp_count: u32,
        req_err: u32,
        resp_err: u32,
        rrt: u64,
        tls_rtt: u64,
    ) {
        self.request_count += req_count;
        self.response_count += resp_count;
        self.err_client_count += req_err;
        self.err_server_count += resp_err;

        if rrt != 0 {
            self.rrt_max = self.rrt_max.max(rrt as u32);
            self.rrt_sum += rrt;
            self.rrt_count += 1;
        }
        if tls_rtt != 0 {
            self.tls_rtt += tls_rtt as u32;
        }
    }

    pub fn inc_req(&mut self) {
        self.merge_perf(1, 0, 0, 0, 0, 0);
    }

    pub fn inc_resp(&mut self) {
        self.merge_perf(0, 1, 0, 0, 0, 0);
    }

    pub fn inc_req_err(&mut self) {
        self.merge_perf(0, 0, 1, 0, 0, 0);
    }

    pub fn inc_resp_err(&mut self) {
        self.merge_perf(0, 0, 0, 1, 0, 0);
    }

    pub fn update_rrt(&mut self, rrt: u64) {
        self.merge_perf(0, 0, 0, 0, rrt, 0);
    }

    pub fn update_tls_rtt(&mut self, tls_rtt: u64) {
        self.merge_perf(0, 0, 0, 0, 0, tls_rtt);
    }
}

impl From<L7PerfStats> for flow_log::L7PerfStats {
    fn from(p: L7PerfStats) -> Self {
        flow_log::L7PerfStats {
            request_count: p.request_count,
            response_count: p.response_count,
            err_client_count: p.err_client_count,
            err_server_count: p.err_server_count,
            err_timeout: p.err_timeout,
            rrt_count: p.rrt_count,
            rrt_sum: p.rrt_sum,
            rrt_max: p.rrt_max,
            tls_rtt: p.tls_rtt,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FlowMetricsPeer {
    pub byte_count: u64,         // 每个流统计周期（目前是自然秒）清零
    pub l3_byte_count: u64,      // 每个流统计周期的L3载荷量
    pub l4_byte_count: u64,      // 每个流统计周期的L4载荷量
    pub packet_count: u64,       // 每个流统计周期（目前是自然秒）清零
    pub total_byte_count: u64,   // 整个Flow生命周期的统计量
    pub total_packet_count: u64, // 整个Flow生命周期的统计量
    pub first: Timestamp,        // 整个Flow生命周期首包的时间戳
    pub last: Timestamp,         // 整个Flow生命周期尾包的时间戳

    pub l3_epc_id: i32,
    pub is_l2_end: bool,
    pub is_l3_end: bool,
    pub is_active_host: bool,
    pub is_device: bool,           // ture表明是从平台数据获取的
    pub tcp_flags: TcpFlags,       // 每个流统计周期的TCP的Flags的或运算结果
    pub total_tcp_flags: TcpFlags, // 整个Flow生命周期的TCP的Flags的或运算结果
    pub is_vip_interface: bool,    // 目前仅支持微软Mux设备，从grpc Interface中获取
    pub is_vip: bool,              // 从grpc cidr中获取
    pub is_local_mac: bool,        // 同EndpointInfo中的IsLocalMac, 流日志中不需要存储
    pub is_local_ip: bool,         // 同EndpointInfo中的IsLocalIp, 流日志中不需要存储

    // This field is valid for the following two scenarios:
    // VIP: Mac query acquisition
    // TOA: Parsing tcp options
    pub nat_source: u8,
    pub nat_real_port: u16,
    pub gpid: u32,
    pub nat_real_ip: IpAddr,
}

pub fn serialize_flow_metrics<S>(v: &[FlowMetricsPeer; 2], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let real_ip_0 = match v[0].nat_real_ip {
        IpAddr::V4(ip) => u32::from(ip),
        IpAddr::V6(ip) if ip.to_ipv4().is_some() => {
            let ip = ip.to_ipv4().unwrap();
            u32::from(ip)
        }
        _ => 0,
    };
    let real_ip_1 = match v[1].nat_real_ip {
        IpAddr::V4(ip) => u32::from(ip),
        IpAddr::V6(ip) if ip.to_ipv4().is_some() => {
            let ip = ip.to_ipv4().unwrap();
            u32::from(ip)
        }
        _ => 0,
    };

    #[derive(Serialize)]
    struct Ser {
        byte_tx: u64,
        byte_rx: u64,
        l3_byte_tx: u64,
        l3_byte_rx: u64,
        l4_byte_tx: u64,
        l4_byte_rx: u64,
        packet_tx: u64,
        packet_rx: u64,
        total_byte_tx: u64,
        total_byte_rx: u64,
        total_packet_tx: u64,
        total_packet_rx: u64,
        l3_epc_id_0: i32,
        l3_epc_id_1: i32,
        l2_end_0: bool,
        l2_end_1: bool,
        l3_end_0: bool,
        l3_end_1: bool,
        real_ip_0: u32,
        real_ip_1: u32,
        real_port_src: u16,
        real_port_dst: u16,
        gpid_0: u32,
        gpid_1: u32,

        #[serde(serialize_with = "to_string_format")]
        tcp_flags_bit_0: TcpFlags,
        #[serde(serialize_with = "to_string_format")]
        tcp_flags_bit_1: TcpFlags,
    }
    let s = Ser {
        byte_tx: v[0].byte_count,
        byte_rx: v[1].byte_count,
        l3_byte_tx: v[0].l3_byte_count,
        l3_byte_rx: v[1].l3_byte_count,
        l4_byte_tx: v[0].l4_byte_count,
        l4_byte_rx: v[1].l4_byte_count,
        packet_tx: v[0].packet_count,
        packet_rx: v[1].packet_count,
        total_byte_tx: v[0].total_byte_count,
        total_byte_rx: v[1].total_byte_count,
        total_packet_tx: v[0].total_packet_count,
        total_packet_rx: v[1].total_packet_count,
        l3_epc_id_0: v[0].l3_epc_id,
        l3_epc_id_1: v[1].l3_epc_id,
        l2_end_0: v[0].is_l2_end,
        l2_end_1: v[1].is_l2_end,
        l3_end_0: v[0].is_l3_end,
        l3_end_1: v[1].is_l3_end,
        tcp_flags_bit_0: v[0].tcp_flags,
        tcp_flags_bit_1: v[1].tcp_flags,
        real_ip_0,
        real_ip_1,
        real_port_src: v[0].nat_real_port,
        real_port_dst: v[1].nat_real_port,
        gpid_0: v[0].gpid,
        gpid_1: v[1].gpid,
    };
    serializer.serialize_newtype_struct("flow_metrics", &s)
}

impl Default for FlowMetricsPeer {
    fn default() -> Self {
        FlowMetricsPeer {
            nat_source: TapPort::NAT_SOURCE_NONE,
            nat_real_ip: Ipv4Addr::UNSPECIFIED.into(),
            nat_real_port: 0,
            byte_count: 0,
            l3_byte_count: 0,
            l4_byte_count: 0,
            packet_count: 0,
            total_byte_count: 0,
            total_packet_count: 0,
            first: Default::default(),
            last: Default::default(),

            l3_epc_id: 0,
            is_l2_end: false,
            is_l3_end: false,
            is_active_host: false,
            is_device: false,
            tcp_flags: TcpFlags::empty(),
            total_tcp_flags: TcpFlags::empty(),
            is_vip_interface: false,
            is_vip: false,
            is_local_mac: false,
            is_local_ip: false,

            gpid: 0,
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

        self.total_byte_count = other.total_byte_count;
        self.total_packet_count = other.total_packet_count;
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
        self.nat_real_ip = other.nat_real_ip;
        self.nat_real_port = other.nat_real_port;
        if other.gpid > 0 {
            self.gpid = other.gpid;
        }
    }
}

impl From<FlowMetricsPeer> for flow_log::FlowMetricsPeer {
    fn from(m: FlowMetricsPeer) -> Self {
        let real_ip = match m.nat_real_ip {
            IpAddr::V4(i) => u32::from(i),
            IpAddr::V6(i) if i.to_ipv4().is_some() => u32::from(i.to_ipv4().unwrap()),
            _ => 0,
        };
        flow_log::FlowMetricsPeer {
            byte_count: m.byte_count,
            l3_byte_count: m.l3_byte_count,
            l4_byte_count: m.l4_byte_count,
            packet_count: m.packet_count,
            total_byte_count: m.total_byte_count,
            total_packet_count: m.total_packet_count,
            first: m.first.as_nanos(),
            last: m.last.as_nanos(),

            l3_epc_id: m.l3_epc_id,
            is_l2_end: m.is_l2_end as u32,
            is_l3_end: m.is_l3_end as u32,
            is_active_host: m.is_active_host as u32,
            is_device: m.is_device as u32,
            tcp_flags: m.tcp_flags.bits() as u32,
            is_vip_interface: m.is_vip_interface as u32,
            is_vip: m.is_vip as u32,
            real_ip,
            real_port: m.nat_real_port as u32,
            gpid: m.gpid,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketDirection {
    ClientToServer = FlowMetricsPeer::SRC,
    ServerToClient = FlowMetricsPeer::DST,
}

impl PacketDirection {
    pub fn reversed(&self) -> Self {
        match self {
            PacketDirection::ClientToServer => PacketDirection::ServerToClient,
            PacketDirection::ServerToClient => PacketDirection::ClientToServer,
        }
    }
}

impl Default for PacketDirection {
    fn default() -> PacketDirection {
        PacketDirection::ClientToServer
    }
}

impl Display for PacketDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClientToServer => write!(f, "c2s"),
            Self::ServerToClient => write!(f, "s2c"),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl From<u8> for PacketDirection {
    fn from(msg_type: u8) -> Self {
        match msg_type {
            MSG_REQUEST | MSG_REQUEST_END => Self::ClientToServer,
            MSG_RESPONSE | MSG_RESPONSE_END => Self::ServerToClient,
            _ => panic!("ebpf direction({}) unknown.", msg_type),
        }
    }
}

#[derive(Serialize, Default, Clone, Debug)]
pub struct Flow {
    #[serde(flatten)]
    pub flow_key: FlowKey,
    #[serde(flatten, serialize_with = "serialize_flow_metrics")]
    pub flow_metrics_peers: [FlowMetricsPeer; 2],

    #[serde(flatten, skip_serializing_if = "tunnel_is_none")]
    pub tunnel: TunnelField,

    pub flow_id: u64,

    /* TCP Seq */
    pub syn_seq: u32,
    #[serde(rename = "syn_ack_seq")]
    pub synack_seq: u32,
    pub last_keepalive_seq: u32,
    pub last_keepalive_ack: u32,

    #[serde(serialize_with = "timestamp_to_micros")]
    pub start_time: Timestamp,
    #[serde(serialize_with = "timestamp_to_micros")]
    pub end_time: Timestamp,
    #[serde(serialize_with = "timestamp_to_micros")]
    pub duration: Timestamp,

    #[serde(skip)]
    pub flow_stat_time: Timestamp,

    /* L2 */
    pub vlan: u16,
    pub eth_type: EthernetType,

    /* TCP Perf Data*/
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub flow_perf_stats: Option<FlowPerfStats>,

    pub close_type: CloseType,
    pub signal_source: SignalSource,
    #[serde(skip)]
    pub is_active_service: bool,
    #[serde(skip)]
    pub queue_hash: u8,
    pub is_new_flow: bool,
    #[serde(skip)]
    pub reversed: bool,
    pub tap_side: TapSide,
    #[serde(skip)]
    pub directions: [Direction; 2],
    #[serde(skip)]
    pub acl_gids: Vec<u16>,
    #[serde(skip)]
    pub otel_service: Option<String>,
    #[serde(skip)]
    pub otel_instance: Option<String>,
    #[serde(skip)]
    pub last_endpoint: Option<String>,
    #[serde(skip)]
    pub last_biz_type: u8,
    pub direction_score: u8,
    pub pod_id: u32,
    pub request_domain: String,
}

fn tunnel_is_none(t: &TunnelField) -> bool {
    t.tunnel_type == TunnelType::None
}

impl Flow {
    pub fn start_time_in_minute(&self) -> u64 {
        let second_in_minute = self.start_time.as_secs() % SECONDS_IN_MINUTE;
        (self.flow_stat_time.as_secs() - second_in_minute) / SECONDS_IN_MINUTE * SECONDS_IN_MINUTE
            + second_in_minute
    }

    fn swap_flow_ip_and_real_ip(&mut self) {
        let metric = &mut self.flow_metrics_peers[PacketDirection::ClientToServer as usize];
        swap(&mut self.flow_key.port_src, &mut metric.nat_real_port);
        swap(&mut self.flow_key.ip_src, &mut metric.nat_real_ip);

        let metric = &mut self.flow_metrics_peers[PacketDirection::ServerToClient as usize];
        swap(&mut self.flow_key.port_dst, &mut metric.nat_real_port);
        swap(&mut self.flow_key.ip_dst, &mut metric.nat_real_ip);
    }

    pub fn sequential_merge(&mut self, other: &Flow) {
        self.flow_metrics_peers[0].sequential_merge(&other.flow_metrics_peers[0]);
        self.flow_metrics_peers[1].sequential_merge(&other.flow_metrics_peers[1]);

        self.end_time = other.end_time;
        self.duration = other.duration;
        self.tap_side = other.tap_side;

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
        if other.vlan > 0 {
            self.vlan = other.vlan
        }

        if other.last_keepalive_seq != 0 {
            self.last_keepalive_seq = other.last_keepalive_seq;
        }
        if other.last_keepalive_ack != 0 {
            self.last_keepalive_ack = other.last_keepalive_ack;
        }

        for new_acl_gid in other.acl_gids.iter() {
            let mut has = false;
            for old_acl_gid in self.acl_gids.iter() {
                if *new_acl_gid == *old_acl_gid {
                    has = true;
                    break;
                }
            }
            if !has {
                self.acl_gids.push(*new_acl_gid);
            }
        }
        let nat_source = other.flow_key.tap_port.get_nat_source();
        if nat_source > self.flow_key.tap_port.get_nat_source() {
            self.flow_key.tap_port.set_nat_source(nat_source);
        }

        if !other.request_domain.is_empty() {
            self.request_domain = other.request_domain.clone();
        }
    }

    // FIXME 注意：由于FlowGenerator中TcpPerfStats在Flow方向调整之后才获取到，
    // 因此这里不包含对TcpPerfStats的反向。
    pub fn reverse(&mut self, is_first_packet: bool) {
        // 如果没有统计数据不需要标记reversed来反向数据
        self.reversed = !self.reversed && !is_first_packet;
        self.tap_side = TapSide::Rest;
        self.tunnel.reverse();
        self.flow_key.reverse();
        self.flow_metrics_peers.swap(0, 1);
        self.direction_score = 0;
    }

    fn is_heartbeat(&self) -> bool {
        let src_tcp_flags = &self.flow_metrics_peers[FlowMetricsPeer::SRC as usize].total_tcp_flags;
        let dst_tcp_flags = &self.flow_metrics_peers[FlowMetricsPeer::DST as usize].total_tcp_flags;

        if src_tcp_flags.contains(TcpFlags::PSH) || dst_tcp_flags.contains(TcpFlags::PSH) {
            return false;
        }

        // Sender:    Client                   Server
        // TCP Flags: SYN
        //                                     SYN-ACK
        //            [ACK]
        //            RST|RST-ACK
        src_tcp_flags.contains(TcpFlags::SYN | TcpFlags::RST)
            && dst_tcp_flags.contains(TcpFlags::SYN_ACK)
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
                if self.is_heartbeat() {
                    CloseType::TcpFinClientRst
                } else {
                    if self.flow_metrics_peers[FlowMetricsPeer::DST as usize]
                        .total_tcp_flags
                        .contains(TcpFlags::RST)
                    {
                        CloseType::TcpServerRst
                    } else {
                        CloseType::TcpClientRst
                    }
                }
            }
            FlowState::Syn1 | FlowState::ClientL4PortReuse => {
                if self.is_heartbeat() {
                    CloseType::TcpFinClientRst
                } else {
                    CloseType::ClientSourcePortReuse
                }
            }
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
            FlowState::EstablishReset | FlowState::OpeningRst => {
                if self.is_heartbeat() {
                    CloseType::TcpFinClientRst
                } else {
                    if self.flow_metrics_peers[FlowMetricsPeer::DST as usize]
                        .total_tcp_flags
                        .contains(TcpFlags::RST)
                    {
                        CloseType::ServerEstablishReset
                    } else {
                        CloseType::ClientEstablishReset
                    }
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

    pub fn set_tap_side(
        &mut self,
        trident_type: TridentType,
        cloud_gateway_traffic: bool, // 从static config 获取
    ) {
        if self.tap_side != TapSide::Rest {
            return;
        }
        // 链路追踪统计位置
        self.directions = get_direction(&*self, trident_type, cloud_gateway_traffic);

        if self.directions[0] != Direction::None && self.directions[1] == Direction::None {
            self.tap_side = self.directions[0].into();
        } else if self.directions[0] == Direction::None && self.directions[1] != Direction::None {
            self.tap_side = self.directions[1].into();
        }
    }

    // Currently acl_gids only saves the policy ID of pcap, but does not save the policy ID of NPB
    pub fn hit_pcap_policy(&self) -> bool {
        self.acl_gids.len() > 0
    }
}

impl fmt::Display for Flow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "flow_id:{} signal_source:{:?} tunnel:{} close_type:{:?} is_active_service:{} is_new_flow:{} queue_hash:{} \
        syn_seq:{} synack_seq:{} last_keepalive_seq:{} last_keepalive_ack:{} flow_stat_time:{:?} \
        \t start_time:{:?} end_time:{:?} duration:{:?} \
        \t vlan:{} eth_type:{:?} reversed:{} otel_service:{:?} otel_instance:{:?} request_domain:{:?} flow_key:{} \
        \n\t flow_metrics_peers_src:{:?} \
        \n\t flow_metrics_peers_dst:{:?} \
        \n\t flow_perf_stats:{:?}",
            self.flow_id, self.signal_source, self.tunnel, self.close_type, self.is_active_service, self.is_new_flow, self.queue_hash,
            self.syn_seq, self.synack_seq, self.last_keepalive_seq, self.last_keepalive_ack, self.flow_stat_time,
            self.start_time, self.end_time, self.duration,
            self.vlan, self.eth_type, self.reversed, self.otel_service, self.otel_instance, self.request_domain, self.flow_key,
            self.flow_metrics_peers[0],
            self.flow_metrics_peers[1],
            self.flow_perf_stats
        )
    }
}

impl From<Flow> for flow_log::Flow {
    // When sending l4_flow_log, exchange the IP/Port in the traffic with the real IP/Port before and after NAT.
    // That is, the client and server in Flow are stored as the real (farthest) client and server first
    fn from(mut f: Flow) -> Self {
        f.swap_flow_ip_and_real_ip();
        flow_log::Flow {
            flow_key: Some(f.flow_key.into()),
            metrics_peer_src: Some(f.flow_metrics_peers[0].into()),
            metrics_peer_dst: Some(f.flow_metrics_peers[1].into()),
            tunnel: {
                if f.tunnel.tunnel_type == TunnelType::None {
                    None
                } else {
                    Some(f.tunnel.into())
                }
            },
            flow_id: f.flow_id,
            start_time: f.start_time.as_nanos() as u64,
            end_time: f.end_time.as_nanos() as u64,
            duration: f.duration.as_nanos() as u64,
            eth_type: u16::from(f.eth_type) as u32,
            vlan: f.vlan as u32,
            has_perf_stats: f.flow_perf_stats.is_some() as u32,
            perf_stats: f.flow_perf_stats.map(|stats| stats.into()),
            close_type: f.close_type as u32,
            signal_source: f.signal_source as u32,
            is_active_service: f.is_active_service as u32,
            queue_hash: f.queue_hash as u32,
            is_new_flow: f.is_new_flow as u32,
            tap_side: f.tap_side as u32,
            syn_seq: f.syn_seq,
            synack_seq: f.synack_seq,
            last_keepalive_seq: f.last_keepalive_seq,
            last_keepalive_ack: f.last_keepalive_ack,
            acl_gids: f.acl_gids.into_iter().map(|g| g as u32).collect(),
            direction_score: f.direction_score as u32,
            request_domain: f.request_domain,
        }
    }
}

pub fn get_direction(
    flow: &Flow,
    trident_type: TridentType,
    cloud_gateway_traffic: bool, // 从static config 获取
) -> [Direction; 2] {
    let src_ep = &flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC];
    let dst_ep = &flow.flow_metrics_peers[FLOW_METRICS_PEER_DST];

    match flow.signal_source {
        SignalSource::EBPF => {
            // For eBPF data, the direction can be calculated directly through l2_end,
            // and its l2_end has been set in MetaPacket::from_ebpf().
            let (mut src_direct, mut dst_direct) = (
                Direction::ClientProcessToServer,
                Direction::ServerProcessToClient,
            );
            // FIXME: tap_side should be determined based on which side of the process_id
            if src_ep.is_l2_end {
                dst_direct = Direction::None
            } else if dst_ep.is_l2_end {
                src_direct = Direction::None
            }
            return [src_direct, dst_direct];
        }
        SignalSource::XFlow => {
            return [Direction::None, Direction::None];
        }
        _ => {
            // workload and container collector need to collect loopback port flow
            if flow.flow_key.mac_src == flow.flow_key.mac_dst
                && (is_tt_pod(trident_type) || is_tt_workload(trident_type))
            {
                return [Direction::None, Direction::LocalToLocal];
            }
        }
    }

    // 返回值分别为统计点对应的zerodoc.DirectionEnum以及及是否添加追踪数据的开关，在微软
    // 云MUX场景中，云内和云外通过VIP通信，在MUX和宿主机中采集到的流量IP地址为VIP，添加追
    // 踪数据后会将VIP替换为实际虚拟机的IP。
    fn inner(
        tap_type: TapType,
        tunnel: &TunnelField,
        l2_end: bool,
        l3_end: bool,
        is_unicast: bool,
        is_local_mac: bool,
        is_local_ip: bool,
        l3_epc_id: i32,
        cloud_gateway_traffic: bool, // 从static config 获取
        trident_type: TridentType,
    ) -> (Direction, Direction) {
        let is_ep = l2_end && l3_end;
        let tunnel_tier = tunnel.tier;

        match trident_type {
            TridentType::TtDedicatedPhysicalMachine => {
                //  接入网络
                if tap_type != TapType::Cloud {
                    if l3_epc_id != EPC_INTERNET {
                        return (Direction::ClientToServer, Direction::ServerToClient);
                    }
                } else {
                    // 虚拟网络
                    // 腾讯TCE场景，NFV区域的镜像流量规律如下（---表示无隧道路径，===表示有隧道路径）：
                    //   WAN ---> NFV1 ===> NFV2 ===> CVM
                    //         ^       ^ ^       ^
                    //         |       | |       `镜像流量有隧道（GRE）、左侧L2End=True
                    //         |       | `镜像流量有隧道（VXLAN/IPIP）、右侧L2End=True
                    //         |       |   <不同类NFV串联时，中间必过路由，MAC会变化>
                    //         |       `镜像流量有隧道（VXLAN/IPIP）、左侧L2End=True
                    //         `镜像流量无隧道、右侧L2End=True
                    //
                    //   CVM ===> NFV1 ===> NFV2 ===> CVM
                    //         ^
                    //         `镜像流量有隧道（GRE）、右侧L2End=True
                    //
                    //   当从WAN访问CVM时，必定有一侧是Internet IP；当云内资源经由NFV互访时，两端都不是Internet IP。
                    //   另外，穿越NFV的过程中内层IP不会变，直到目的端CVM宿主机上才会从GRE Key中提取出RSIP进行替换。
                    //
                    // 腾讯TCE场景下，通过手动录入Type=Gateway类型的宿主机，控制器下发的RemoteSegment等于Gateway的MAC。
                    // 其他场景下不会有此类宿主机，控制器下发的RemoteSegment等于**没有**KVM/K8s等本地采集器覆盖的资源MAC。
                    if l2_end {
                        if cloud_gateway_traffic {
                            // 云网关镜像（腾讯TCE等）
                            // 注意c/s方向与0/1相反
                            return (
                                Direction::ServerGatewayToClient,
                                Direction::ClientGatewayToServer,
                            );
                        } else {
                            return (Direction::ClientToServer, Direction::ServerToClient);
                        }
                    }
                }
            }
            TridentType::TtHyperVCompute => {
                // 仅采集宿主机物理口
                if l2_end {
                    // SNAT、LB Backend
                    // IP地址为VIP: 将双端(若不是vip_iface)的VIP替换为其MAC对对应的RIP,生成另一份doc
                    return (
                        Direction::ClientHypervisorToServer,
                        Direction::ServerHypervisorToClient,
                    );
                }
            }
            TridentType::TtHyperVNetwork => {
                // 仅采集宿主机物理口
                if is_ep {
                    return (
                        Direction::ClientHypervisorToServer,
                        Direction::ServerHypervisorToClient,
                    );
                }

                if l2_end && is_unicast {
                    // Router&MUX
                    // windows hyper-v场景采集到的流量ttl还未减1，这里需要屏蔽ttl避免l3end为true
                    // 注意c/s方向与0/1相反
                    return (
                        Direction::ServerGatewayHypervisorToClient,
                        Direction::ClientGatewayHypervisorToServer,
                    );
                }
            }
            TridentType::TtPublicCloud | TridentType::TtPhysicalMachine => {
                // 该采集器类型中统计位置为客户端网关/服务端网关或存在VIP时，会使用VIP创建Doc和Log.
                // VIP：
                //     微软ACS云内SLB通信场景，在VM内采集的流量无隧道IP地址使用VIP,
                if is_ep {
                    return (Direction::ClientToServer, Direction::ServerToClient);
                } else if l2_end {
                    if is_unicast {
                        // 注意c/s方向与0/1相反
                        return (
                            Direction::ServerGatewayToClient,
                            Direction::ClientGatewayToServer,
                        );
                    }
                }
            }
            TridentType::TtHostPod | TridentType::TtVmPod | TridentType::TtK8sSidecar => {
                if is_ep {
                    if tunnel_tier == 0 {
                        return (Direction::ClientToServer, Direction::ServerToClient);
                    } else {
                        // tunnelTier > 0：容器节点的出口做隧道封装
                        return (Direction::ClientNodeToServer, Direction::ServerNodeToClient);
                    }
                } else if l2_end {
                    if is_local_ip {
                        // 本机IP：容器节点的出口做路由转发
                        return (Direction::ClientNodeToServer, Direction::ServerNodeToClient);
                    } else if tunnel_tier > 0 {
                        // tunnelTier > 0：容器节点的出口做隧道封装
                        // 例如：两个容器节点之间打隧道，隧道内层IP为tunl0接口的/32隧道专用IP
                        // 但由于tunl0接口有时候没有MAC，不会被控制器记录，因此不会匹配isLocalIp的条件
                        return (Direction::ClientNodeToServer, Direction::ServerNodeToClient);
                    }
                    // 其他情况
                    // 举例：在tun0接收到的、本地POD发送到容器节点外部的流量
                    //       其目的MAC为tun0且l2End为真，但目的IP不是本机的IP
                } else if l3_end {
                    if is_local_mac {
                        // 本机MAC：容器节点的出口做交换转发
                        // 平安Serverless容器集群中，容器POD访问的流量特征为：
                        //   POD -> 外部：源MAC=Node MAC（Node路由转发）
                        //   POD <- 外部：目MAC=POD MAC（Node交换转发）
                        return (Direction::ClientNodeToServer, Direction::ServerNodeToClient);
                    }
                } else {
                    if is_local_mac {
                        if is_local_ip {
                            return (Direction::ClientNodeToServer, Direction::ServerNodeToClient);
                        } else if tunnel_tier > 0 {
                            return (Direction::ClientNodeToServer, Direction::ServerNodeToClient);
                        } else {
                            //其他情况: BUM流量
                        }
                    } else {
                        //其他情况: BUM流量
                    }
                }
            }
            TridentType::TtProcess => {
                if is_ep {
                    if tunnel_tier == 0 {
                        return (Direction::ClientToServer, Direction::ServerToClient);
                    } else {
                        // 宿主机隧道转发
                        if is_local_ip {
                            // 端点VTEP
                            return (
                                Direction::ClientHypervisorToServer,
                                Direction::ServerHypervisorToClient,
                            );
                        }
                        // 其他情况
                        // 中间VTEP：VXLAN网关（二层网关）
                    }
                } else if l2_end {
                    if is_local_ip {
                        if tunnel_tier > 0 {
                            // 容器节点作为路由器时，在宿主机出口上抓到隧道封装流量
                            return (
                                Direction::ClientHypervisorToServer,
                                Direction::ServerHypervisorToClient,
                            );
                        } else {
                            // 虚拟机或容器作为路由器时，在虚接口上抓到路由转发流量
                            // 额外追踪数据：新增的追踪数据添加MAC地址，后端通过MAC地址获取设备信息
                            return (
                                Direction::ServerGatewayToClient,
                                Direction::ClientGatewayToServer,
                            );
                        }
                    } else if is_local_mac {
                        // 本地MAC、已知单播
                        if tunnel_tier > 0 {
                            // 虚拟机作为路由器时，在宿主机出口上抓到隧道封装流量
                            if tunnel.tunnel_type == TunnelType::Ipip {
                                // 腾讯TCE的Underlay母机使用IPIP封装，外层IP为本机Underlay CVM的IP，内层IP为CLB的VIP
                                // FIXME: 目前还没有看到其他KVM使用IPIP封装的场景，这里用IPIP判断是否为TCE Underlay隧道
                                return (
                                    Direction::ClientHypervisorToServer,
                                    Direction::ServerHypervisorToClient,
                                );
                            } else {
                                return (
                                    Direction::ServerGatewayHypervisorToClient,
                                    Direction::ClientGatewayHypervisorToServer,
                                );
                            }
                        } else {
                            // 虚拟机或容器作为路由器时，在虚接口上抓到路由转发流量
                            // 额外追踪数据：新增的追踪数据添加MAC地址，后端通过MAC地址获取设备信息
                            return (
                                Direction::ServerGatewayToClient,
                                Direction::ClientGatewayToServer,
                            );
                        }
                    } else {
                        if tunnel_tier > 0 && tunnel.tunnel_type == TunnelType::TencentGre {
                            // 腾讯TCE场景，TCE-GRE隧道解封装后我们伪造了MAC地址（因此不是LocalMac）
                            // 在JNSGW场景中，Underlay CVM直接封装了GRE协议且内层IP为VIP（因此不是LocalIP）、外层IP为实IP
                            return (
                                Direction::ClientHypervisorToServer,
                                Direction::ServerHypervisorToClient,
                            );
                        }
                        //其他情况:  由隧道封装的BUM包
                    }
                } else if l3_end {
                    if is_local_mac {
                        // 交换转发：被宿主机的虚拟交换机转发的（和客户端/服务端完全一样）流量，记录为客户端宿主机、服务端宿主机
                        return (
                            Direction::ClientHypervisorToServer,
                            Direction::ServerHypervisorToClient,
                        );
                        //其他情况: BUM流量
                    }
                } else {
                    if is_local_mac {
                        if is_local_ip {
                            // 容器节点作为路由器时，路由流量在宿主机出接口上直接做交换转发
                            // 举例：青云环境中，如果网卡做VXLAN Offload，流量会从vfXXX口经过，此时没有做隧道封装
                            //       POD与外部通信时在vfXXX口看到的MAC是容器节点的，因此l2End和l3End同时为假
                            //       此时只能通过isLocalIp来判断统计数据的direction
                            return (
                                Direction::ClientHypervisorToServer,
                                Direction::ServerHypervisorToClient,
                            );
                        } else if tunnel_tier > 0 {
                            // 腾讯TCE的Underlay母机使用IPIP封装，外层IP为本机Underlay CVM的IP和MAC，内层IP为CLB的VIP
                            // 宽泛来讲，如果隧道内层是本机MAC、且L2End=false（即隧道外层不是本机MAC），也认为是到达了端点
                            return (
                                Direction::ClientHypervisorToServer,
                                Direction::ServerHypervisorToClient,
                            );
                        } else {
                            return (
                                Direction::ServerGatewayHypervisorToClient,
                                Direction::ClientGatewayHypervisorToServer,
                            );
                        }
                    }
                    //其他情况: BUM流量
                }
            }
            TridentType::TtVm => {
                if tunnel_tier == 0 && is_ep {
                    return (Direction::ClientToServer, Direction::ServerToClient);
                }
            }
            _ => {
                // 采集器类型不正确，不应该发生
                error!("invalid trident type, deepflow-agent restart...");
                thread::sleep(Duration::from_secs(1));
                process::exit(1)
            }
        }
        (Direction::None, Direction::None)
    }

    const FLOW_METRICS_PEER_SRC: usize = 0;
    const FLOW_METRICS_PEER_DST: usize = 1;

    let flow_key = &flow.flow_key;

    // 全景图统计
    let tunnel = &flow.tunnel;
    let (mut src_direct, _) = inner(
        flow_key.tap_type,
        tunnel,
        src_ep.is_l2_end,
        src_ep.is_l3_end,
        true,
        src_ep.is_local_mac,
        src_ep.is_local_ip,
        src_ep.l3_epc_id,
        cloud_gateway_traffic,
        trident_type,
    );
    let (_, mut dst_direct) = inner(
        flow_key.tap_type,
        tunnel,
        dst_ep.is_l2_end,
        dst_ep.is_l3_end,
        MacAddr::is_unicast(flow_key.mac_dst),
        dst_ep.is_local_mac,
        dst_ep.is_local_ip,
        dst_ep.l3_epc_id,
        cloud_gateway_traffic,
        trident_type,
    );
    // 双方向都有统计位置优先级为：client/server侧 > L2End侧 > IsLocalMac侧 > 其他
    if src_direct != Direction::None && dst_direct != Direction::None {
        if let TapType::Idc(_) = flow_key.tap_type {
            // When the IDC traffic collected by the dedicated deepflow-agent cannot distinguish between Directions,
            // the Direction is set to None and Doc data to count a Rest record.
            // ======================================================================================================
            // 当专属采集器采集的 IDC 流量无法区分 Direction 时，Direction设置为None Doc数据中统计一份 Rest 记录。
            return [Direction::None, Direction::None];
        } else if (src_direct == Direction::ClientToServer || src_ep.is_l2_end)
            && dst_direct != Direction::ServerToClient
        {
            dst_direct = Direction::None;
        } else if (dst_direct == Direction::ServerToClient || dst_ep.is_l2_end)
            && src_direct != Direction::ClientToServer
        {
            src_direct = Direction::None;
        } else if src_ep.is_local_mac {
            dst_direct = Direction::None;
        } else if dst_ep.is_local_mac {
            src_direct = Direction::None;
        }
    }

    [src_direct, dst_direct]
}

// 生成32位flowID,确保在1分钟内1个thread的flowID不重复
pub fn get_uniq_flow_id_in_one_minute(flow_id: u64) -> u64 {
    // flowID中时间低8位可保证1分钟内时间的唯一，counter可保证一秒内流的唯一性（假设fps < 2^24）
    (flow_id >> 32 & 0xff << 24) | (flow_id & COUNTER_FLOW_ID_MASK)
}
