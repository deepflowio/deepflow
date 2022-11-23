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

mod consts;
pub mod error;
pub mod l7_protocol_info;
pub mod pb_adapter;

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use prost::Message;
use serde::{Serialize, Serializer};

use crate::common::{
    ebpf::EbpfType,
    enums::{IpProtocol, TapSide, TapType},
    flow::{PacketDirection, SignalSource},
    l7_protocol::L7Protocol,
    tap_port::TapPort,
};
use crate::proto::{flow_log, protobuf_rpc::KrpcMeta};
use crate::utils::net::MacAddr;
use error::Result;
pub use l7_protocol_info::L7ProtocolInfo;
pub use pb_adapter::L7ProtocolSendLog;

const NANOS_PER_MICRO: u64 = 1000;

#[derive(Serialize, Debug, PartialEq, Copy, Clone, Eq)]
#[repr(u8)]
pub enum L7ResponseStatus {
    Ok,
    Error, // deprecate
    NotExist,
    ServerError,
    ClientError,
}

impl Default for L7ResponseStatus {
    fn default() -> Self {
        L7ResponseStatus::Ok
    }
}

#[derive(Serialize, Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum LogMessageType {
    Request,
    Response,
    Session,
    Other,
    Max,
}

impl Default for LogMessageType {
    fn default() -> Self {
        LogMessageType::Other
    }
}

impl From<PacketDirection> for LogMessageType {
    fn from(d: PacketDirection) -> LogMessageType {
        match d {
            PacketDirection::ClientToServer => LogMessageType::Request,
            PacketDirection::ServerToClient => LogMessageType::Response,
        }
    }
}

// 应用层协议原始数据类型
#[derive(Debug, PartialEq, Copy, Clone, Serialize)]
#[repr(u8)]
pub enum L7ProtoRawDataType {
    // 标准协议类型, 从af_packet, ebpf 的 tracepoint 或者 部分 uprobe(read/write等获取原始数据的hook点) 上报的数据都属于这个类型
    RawProtocol,
    // ebpf hook 在 go readHeader/writeHeader 获取http2原始未压缩的 header
    GoHttp2Uprobe,
}

impl L7ProtoRawDataType {
    pub fn from_ebpf_type(t: EbpfType) -> Self {
        match t {
            EbpfType::TracePoint | EbpfType::TlsUprobe | EbpfType::None => Self::RawProtocol,
            EbpfType::GoHttp2Uprobe => Self::GoHttp2Uprobe,
        }
    }
}

impl Default for L7ProtoRawDataType {
    fn default() -> Self {
        return Self::RawProtocol;
    }
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct AppProtoHead {
    #[serde(rename = "l7_protocol")]
    pub proto: L7Protocol,
    pub msg_type: LogMessageType, // HTTP，DNS: request/response
    #[serde(rename = "response_duration")]
    pub rrt: u64, // HTTP，DNS时延: response-request
}

impl From<AppProtoHead> for flow_log::AppProtoHead {
    fn from(f: AppProtoHead) -> Self {
        flow_log::AppProtoHead {
            proto: f.proto as u32,
            msg_type: f.msg_type as u32,
            rrt: f.rrt * NANOS_PER_MICRO,
            ..Default::default()
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct AppProtoLogsBaseInfo {
    #[serde(serialize_with = "duration_to_micros")]
    pub start_time: Duration,
    #[serde(serialize_with = "duration_to_micros")]
    pub end_time: Duration,
    pub signal_source: SignalSource,
    pub flow_id: u64,
    #[serde(serialize_with = "to_string_format")]
    pub tap_port: TapPort,
    pub vtap_id: u16,
    pub tap_type: TapType,
    #[serde(skip)]
    pub is_ipv6: bool,
    pub tap_side: TapSide,
    #[serde(flatten)]
    pub head: AppProtoHead,

    /* L2 */
    #[serde(
        skip_serializing_if = "value_is_default",
        serialize_with = "to_string_format"
    )]
    pub mac_src: MacAddr,
    #[serde(
        skip_serializing_if = "value_is_default",
        serialize_with = "to_string_format"
    )]
    pub mac_dst: MacAddr,
    /* L3 ipv4 or ipv6 */
    pub ip_src: IpAddr,
    pub ip_dst: IpAddr,
    /* L3EpcID */
    pub l3_epc_id_src: i32,
    pub l3_epc_id_dst: i32,
    /* L4 */
    pub port_src: u16,
    pub port_dst: u16,
    /* First L7 TCP Seq */
    pub req_tcp_seq: u32,
    pub resp_tcp_seq: u32,

    /* EBPF Info */
    pub ebpf_type: EbpfType,
    #[serde(skip_serializing_if = "value_is_default")]
    pub process_id_0: u32,
    #[serde(skip_serializing_if = "value_is_default")]
    pub process_id_1: u32,
    #[serde(skip_serializing_if = "value_is_default")]
    pub process_kname_0: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub process_kname_1: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub syscall_trace_id_request: u64,
    #[serde(skip_serializing_if = "value_is_default")]
    pub syscall_trace_id_response: u64,
    #[serde(rename = "syscall_thread_0", skip_serializing_if = "value_is_default")]
    pub syscall_trace_id_thread_0: u32,
    #[serde(rename = "syscall_thread_1", skip_serializing_if = "value_is_default")]
    pub syscall_trace_id_thread_1: u32,
    #[serde(skip_serializing_if = "value_is_default")]
    pub syscall_cap_seq_0: u64,
    #[serde(skip_serializing_if = "value_is_default")]
    pub syscall_cap_seq_1: u64,

    pub protocol: IpProtocol,
    #[serde(skip)]
    pub is_vip_interface_src: bool,
    #[serde(skip)]
    pub is_vip_interface_dst: bool,
}

pub fn duration_to_micros<S>(d: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u64(d.as_micros() as u64)
}

pub fn to_string_format<D, S>(d: &D, serializer: S) -> Result<S::Ok, S::Error>
where
    D: fmt::Display,
    S: Serializer,
{
    serializer.serialize_str(&d.to_string())
}

pub fn value_is_default<T>(t: &T) -> bool
where
    T: Default + std::cmp::PartialEq,
{
    t == &T::default()
}

pub fn value_is_negative<T>(t: &T) -> bool
where
    T: Default + std::cmp::PartialEq + std::cmp::PartialOrd,
{
    t < &T::default()
}

impl From<AppProtoLogsBaseInfo> for flow_log::AppProtoLogsBaseInfo {
    fn from(f: AppProtoLogsBaseInfo) -> Self {
        let (ip4_src, ip4_dst, ip6_src, ip6_dst) = match (f.ip_src, f.ip_dst) {
            (IpAddr::V4(ip4), IpAddr::V4(ip4_1)) => {
                (ip4, ip4_1, Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED)
            }
            (IpAddr::V6(ip6), IpAddr::V6(ip6_1)) => {
                (Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, ip6, ip6_1)
            }
            _ => panic!("ip_src,ip_dst type mismatch"),
        };
        flow_log::AppProtoLogsBaseInfo {
            start_time: f.start_time.as_nanos() as u64,
            end_time: f.end_time.as_nanos() as u64,
            flow_id: f.flow_id,
            tap_port: f.tap_port.0,
            vtap_id: f.vtap_id as u32,
            tap_type: u16::from(f.tap_type) as u32,
            is_ipv6: f.is_ipv6 as u32,
            tap_side: f.tap_side as u32,
            head: Some(f.head.into()),
            mac_src: f.mac_src.into(),
            mac_dst: f.mac_dst.into(),
            ip_src: u32::from_be_bytes(ip4_src.octets()),
            ip_dst: u32::from_be_bytes(ip4_dst.octets()),
            ip6_src: ip6_src.octets().to_vec(),
            ip6_dst: ip6_dst.octets().to_vec(),
            l3_epc_id_src: f.l3_epc_id_src,
            l3_epc_id_dst: f.l3_epc_id_dst,
            port_src: f.port_src as u32,
            port_dst: f.port_dst as u32,
            protocol: f.protocol as u32,
            is_vip_interface_src: f.is_vip_interface_src as u32,
            is_vip_interface_dst: f.is_vip_interface_dst as u32,
            req_tcp_seq: f.req_tcp_seq,
            resp_tcp_seq: f.resp_tcp_seq,
            process_id_0: f.process_id_0,
            process_id_1: f.process_id_1,
            process_kname_0: f.process_kname_0,
            process_kname_1: f.process_kname_1,
            syscall_trace_id_request: f.syscall_trace_id_request,
            syscall_trace_id_response: f.syscall_trace_id_response,
            syscall_trace_id_thread_0: f.syscall_trace_id_thread_0,
            syscall_trace_id_thread_1: f.syscall_trace_id_thread_1,
            syscall_cap_seq_0: f.syscall_cap_seq_0 as u32,
            syscall_cap_seq_1: f.syscall_cap_seq_1 as u32,
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct AppProtoLogsData {
    #[serde(flatten)]
    pub base_info: AppProtoLogsBaseInfo,
    #[serde(flatten)]
    pub special_info: L7ProtocolInfo,
}

impl fmt::Display for AppProtoLogsData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\n", self.base_info)?;
        write!(f, "\t{:?}", self.special_info)
    }
}

impl AppProtoLogsData {
    pub fn new(base_info: AppProtoLogsBaseInfo, special_info: L7ProtocolInfo) -> Self {
        Self {
            base_info,
            special_info,
        }
    }

    pub fn is_request(&self) -> bool {
        self.base_info.head.msg_type == LogMessageType::Request
    }

    pub fn is_response(&self) -> bool {
        return self.base_info.head.msg_type == LogMessageType::Response;
    }

    pub fn encode(self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        let mut pb_proto_logs_data = flow_log::AppProtoLogsData {
            base: Some(self.base_info.into()),
            ..Default::default()
        };

        let log: L7ProtocolSendLog = self.special_info.into();
        log.fill_app_proto_log(&mut pb_proto_logs_data);
        pb_proto_logs_data
            .encode(buf)
            .map(|_| pb_proto_logs_data.encoded_len())
    }

    pub fn to_kv_string(&self, dst: &mut String) {
        let json = serde_json::to_string(&self).unwrap();
        dst.push_str(&json);
        dst.push('\n');
    }
}

impl fmt::Display for AppProtoLogsBaseInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Timestamp: {:?} Vtap_id: {} Flow_id: {} TapType: {} TapPort: {} TapSide: {:?}\n \
                \t{}_{}_{} -> {}_{}_{} Proto: {:?} Seq: {} -> {} VIP: {} -> {} EPC: {} -> {}\n \
                \tProcess: {}:{} -> {}:{} Trace-id: {} -> {} Thread: {} -> {} cap_seq: {} -> {}\n \
                \tL7Protocol: {:?} MsgType: {:?} Rrt: {}",
            self.start_time,
            self.vtap_id,
            self.flow_id,
            self.tap_type,
            self.tap_port,
            self.tap_side,
            self.mac_src,
            self.ip_src,
            self.port_src,
            self.mac_dst,
            self.ip_dst,
            self.port_dst,
            self.protocol,
            self.req_tcp_seq,
            self.resp_tcp_seq,
            self.is_vip_interface_src,
            self.is_vip_interface_dst,
            self.l3_epc_id_src,
            self.l3_epc_id_dst,
            self.process_kname_0,
            self.process_id_0,
            self.process_kname_1,
            self.process_id_1,
            self.syscall_trace_id_request,
            self.syscall_trace_id_response,
            self.syscall_trace_id_thread_0,
            self.syscall_trace_id_thread_1,
            self.syscall_cap_seq_0,
            self.syscall_cap_seq_1,
            self.head.proto,
            self.head.msg_type,
            self.head.rrt
        )
    }
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct KafkaInfo {
    pub msg_type: LogMessageType,
    #[serde(skip)]
    pub start_time: u64,
    #[serde(skip)]
    pub end_time: u64,
    #[serde(skip)]
    pub is_tls: bool,

    #[serde(rename = "request_id", skip_serializing_if = "value_is_default")]
    pub correlation_id: u32,

    // request
    #[serde(rename = "request_length", skip_serializing_if = "value_is_negative")]
    pub req_msg_size: Option<u32>,
    #[serde(skip)]
    pub api_version: u16,
    #[serde(rename = "request_type")]
    pub api_key: u16,
    #[serde(skip)]
    pub client_id: String,

    // reponse
    #[serde(rename = "response_length", skip_serializing_if = "value_is_negative")]
    pub resp_msg_size: Option<u32>,
    #[serde(rename = "response_status")]
    pub status: L7ResponseStatus,
    #[serde(rename = "response_code", skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i32>,

    // the first 14 byte of resp_data, use to parse error code
    // only fetch and api version > 7 can get the correct err code
    #[serde(skip)]
    pub resp_data: Option<[u8; 14]>,
}

#[derive(Serialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct DnsInfo {
    #[serde(rename = "request_id", skip_serializing_if = "value_is_default")]
    pub trans_id: u16,
    #[serde(rename = "request_type", skip_serializing_if = "value_is_default")]
    pub query_type: u8,
    #[serde(skip)]
    pub domain_type: u16,

    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub query_name: String,
    // 根据查询类型的不同而不同，如：
    // A: ipv4/ipv6地址
    // NS: name server
    // SOA: primary name server
    #[serde(rename = "response_result", skip_serializing_if = "value_is_default")]
    pub answers: String,

    #[serde(rename = "response_status")]
    pub status: L7ResponseStatus,
    #[serde(rename = "response_code", skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i32>,

    #[serde(skip)]
    pub start_time: u64,
    #[serde(skip)]
    pub end_time: u64,
    pub msg_type: LogMessageType,
    #[serde(skip)]
    pub is_tls: bool,
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct DubboInfo {
    #[serde(skip)]
    pub start_time: u64,
    #[serde(skip)]
    pub end_time: u64,
    pub msg_type: LogMessageType,
    #[serde(skip)]
    pub is_tls: bool,

    // header
    #[serde(skip)]
    pub serial_id: u8,
    #[serde(skip)]
    pub data_type: u8,
    #[serde(rename = "request_id", skip_serializing_if = "value_is_default")]
    pub request_id: i64,

    // req
    #[serde(rename = "request_length", skip_serializing_if = "value_is_negative")]
    pub req_msg_size: Option<u32>,
    #[serde(rename = "version", skip_serializing_if = "value_is_default")]
    pub dubbo_version: String,
    #[serde(rename = "request_domain", skip_serializing_if = "value_is_default")]
    pub service_name: String,
    #[serde(skip)]
    pub service_version: String,
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub method_name: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub trace_id: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub span_id: String,

    // resp
    #[serde(rename = "response_length", skip_serializing_if = "Option::is_none")]
    pub resp_msg_size: Option<u32>,
    #[serde(rename = "response_status")]
    pub resp_status: L7ResponseStatus,
    #[serde(rename = "response_code", skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i32>,
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct HttpInfo {
    // 流是否结束，用于 http2 ebpf uprobe 处理.
    // 由于ebpf有可能响应会比请求先到，所以需要 is_req_end 和 is_resp_end 同时为true才认为结束
    #[serde(skip)]
    pub is_req_end: bool,
    #[serde(skip)]
    pub is_resp_end: bool,
    // from MetaPacket::cap_seq
    pub cap_seq: Option<u64>,

    #[serde(skip)]
    pub proto: L7Protocol,
    #[serde(skip)]
    pub start_time: u64,
    #[serde(skip)]
    pub end_time: u64,
    #[serde(skip)]
    pub is_tls: bool,
    pub msg_type: LogMessageType,
    // 数据原始类型，标准的协议格式或者是ebpf上报的自定义格式
    #[serde(skip)]
    pub raw_data_type: L7ProtoRawDataType,

    #[serde(rename = "request_id", skip_serializing_if = "value_is_default")]
    pub stream_id: Option<u32>,
    #[serde(skip_serializing_if = "value_is_default")]
    pub version: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub trace_id: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub span_id: String,

    #[serde(rename = "request_type", skip_serializing_if = "value_is_default")]
    pub method: String,
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub path: String,
    #[serde(rename = "request_domain", skip_serializing_if = "value_is_default")]
    pub host: String,
    #[serde(rename = "user_agent", skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(rename = "referer", skip_serializing_if = "Option::is_none")]
    pub referer: Option<String>,
    #[serde(rename = "http_proxy_client", skip_serializing_if = "value_is_default")]
    pub client_ip: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub x_request_id: String,

    #[serde(rename = "request_length", skip_serializing_if = "Option::is_none")]
    pub req_content_length: Option<u32>,
    #[serde(rename = "response_length", skip_serializing_if = "Option::is_none")]
    pub resp_content_length: Option<u32>,

    #[serde(rename = "response_code", skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i32>,
    #[serde(rename = "response_status")]
    pub status: L7ResponseStatus,
}

#[derive(Serialize, Clone, Debug)]
pub struct MqttInfo {
    #[serde(skip)]
    pub start_time: u64,
    #[serde(skip)]
    pub end_time: u64,
    pub msg_type: LogMessageType,

    #[serde(rename = "request_domain", skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "value_is_default")]
    pub version: u8,
    #[serde(rename = "request_type")]
    pub pkt_type: PacketKind,
    #[serde(rename = "request_length", skip_serializing_if = "value_is_negative")]
    pub req_msg_size: Option<u32>,
    #[serde(rename = "response_length", skip_serializing_if = "value_is_negative")]
    pub res_msg_size: Option<u32>,
    #[serde(
        rename = "request_resource",
        skip_serializing_if = "Option::is_none",
        serialize_with = "topics_format"
    )]
    pub subscribe_topics: Option<Vec<flow_log::MqttTopic>>,
    #[serde(skip)]
    pub publish_topic: Option<String>,
    #[serde(rename = "response_code", skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>, // connect_ack packet return code
    pub status: L7ResponseStatus,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    Connect,
    Connack,
    Publish {
        dup: bool,
        qos: QualityOfService,
        retain: bool,
    },
    Puback,
    Pubrec,
    Pubrel,
    Pubcomp,
    Subscribe,
    Suback,
    Unsubscribe,
    Unsuback,
    Pingreq,
    Pingresp,
    Disconnect,
}

impl fmt::Display for PacketKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Connect => write!(f, "CONNECT"),
            Self::Connack => write!(f, "CONNACK"),
            Self::Publish { .. } => write!(f, "PUBLISH"),
            Self::Puback => write!(f, "PUBACK"),
            Self::Pubrec => write!(f, "PUBREC"),
            Self::Pubrel => write!(f, "PUBREL"),
            Self::Pubcomp => write!(f, "PUBCOMP"),
            Self::Subscribe => write!(f, "SUBSCRIBE"),
            Self::Suback => write!(f, "SUBACK"),
            Self::Unsubscribe => write!(f, "UNSUBSCRIBE"),
            Self::Unsuback => write!(f, "UNSUBACK"),
            Self::Pingreq => write!(f, "PINGREQ"),
            Self::Pingresp => write!(f, "PINGRESP"),
            Self::Disconnect => write!(f, "DISCONNECT"),
        }
    }
}

impl Default for PacketKind {
    fn default() -> Self {
        Self::Disconnect
    }
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum QualityOfService {
    AtMostOnce = 0,
    AtLeastOnce = 1,
    ExactlyOnce = 2,
}

impl Default for QualityOfService {
    fn default() -> Self {
        Self::AtMostOnce
    }
}

pub fn topics_format<S>(
    t: &Option<Vec<flow_log::MqttTopic>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let ts = t.as_ref().unwrap();
    let names = ts.iter().map(|c| c.name.clone()).collect::<Vec<_>>();
    serializer.serialize_str(&names.join(","))
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct MysqlInfo {
    pub msg_type: LogMessageType,
    #[serde(skip)]
    pub start_time: u64,
    #[serde(skip)]
    pub end_time: u64,
    #[serde(skip)]
    pub is_tls: bool,

    // Server Greeting
    #[serde(rename = "version", skip_serializing_if = "value_is_default")]
    pub protocol_version: u8,
    #[serde(skip)]
    pub server_version: String,
    #[serde(skip)]
    pub server_thread_id: u32,
    // request
    #[serde(rename = "request_type")]
    pub command: u8,
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub context: String,
    // response
    pub response_code: u8,
    #[serde(skip)]
    pub error_code: Option<i32>,
    #[serde(rename = "sql_affected_rows", skip_serializing_if = "value_is_default")]
    pub affected_rows: u64,
    #[serde(
        rename = "response_execption",
        skip_serializing_if = "value_is_default"
    )]
    pub error_message: String,
    #[serde(rename = "response_status")]
    pub status: L7ResponseStatus,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct PostgreInfo {
    pub msg_type: LogMessageType,
    #[serde(skip)]
    pub start_time: u64,
    #[serde(skip)]
    pub end_time: u64,
    #[serde(skip)]
    pub is_tls: bool,
    /*
        ignore return this info, default is true.

        with request, parse:
            simple query ('Q')
            prepare statment ('P')

        with response parse
            command complete('C')
            error return ('E')

        when frame not all of these block, it will ignore.

        it use for skip some prepare statement execute and param bind, let the session aggregate match the query and result.

    */
    #[serde(skip)]
    pub ignore: bool,

    // request
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub context: String,
    #[serde(rename = "request_type", skip_serializing_if = "value_is_default")]
    pub req_type: char,

    // response
    #[serde(skip)]
    pub resp_type: char,

    #[serde(rename = "response_result", skip_serializing_if = "value_is_default")]
    pub result: String,
    #[serde(rename = "sql_affected_rows", skip_serializing_if = "value_is_default")]
    pub affected_rows: u64,
    #[serde(
        rename = "response_execption",
        skip_serializing_if = "value_is_default"
    )]
    pub error_message: String,
    pub status: L7ResponseStatus,
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct RedisInfo {
    pub msg_type: LogMessageType,
    #[serde(skip)]
    pub start_time: u64,
    #[serde(skip)]
    pub end_time: u64,
    #[serde(skip)]
    pub is_tls: bool,

    #[serde(
        rename = "request_resource",
        skip_serializing_if = "value_is_default",
        serialize_with = "vec_u8_to_string"
    )]
    pub request: Vec<u8>, // 命令字段包括参数例如："set key value"
    #[serde(
        skip_serializing_if = "value_is_default",
        serialize_with = "vec_u8_to_string"
    )]
    pub request_type: Vec<u8>, // 命令类型不包括参数例如：命令为"set key value"，命令类型为："set"
    #[serde(
        rename = "response_result",
        skip_serializing_if = "value_is_default",
        serialize_with = "vec_u8_to_string"
    )]
    pub response: Vec<u8>, // 整数回复 + 批量回复 + 多条批量回复
    #[serde(skip)]
    pub status: Vec<u8>, // '+'
    #[serde(
        rename = "response_expection",
        skip_serializing_if = "value_is_default",
        serialize_with = "vec_u8_to_string"
    )]
    pub error: Vec<u8>, // '-'
    #[serde(rename = "response_status")]
    pub resp_status: L7ResponseStatus,

    pub cap_seq: Option<u64>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct KrpcInfo {
    #[serde(skip)]
    pub start_time: u64,
    #[serde(skip)]
    pub end_time: u64,

    pub msg_type: LogMessageType,
    pub msg_id: i32,
    pub serv_id: i32,
    pub sequence: i32,
    // 0 success, negative indicate error, no positive number.
    pub ret_code: i32,

    //trace info
    pub trace_id: String,
    pub span_id: String,

    pub status: L7ResponseStatus,
}

impl KrpcInfo {
    const KRPC_DIR_REQ: i32 = 1;
    const KRPC_DIR_RESP: i32 = 2;
    pub fn fill_from_pb(&mut self, k: KrpcMeta) -> error::Result<()> {
        self.msg_type = match k.direction {
            Self::KRPC_DIR_REQ => LogMessageType::Request,
            Self::KRPC_DIR_RESP => LogMessageType::Response,
            _ => return Err(error::Error::L7ProtocolUnknown),
        };
        self.msg_id = k.msg_id;
        self.serv_id = k.service_id;
        self.sequence = k.sequence;
        self.ret_code = k.ret_code;

        if let Some(t) = k.trace {
            self.trace_id = t.trace_id;
            self.span_id = t.span_id;
        }

        if self.ret_code == 0 {
            self.status = L7ResponseStatus::Ok;
        } else {
            self.status = L7ResponseStatus::ServerError;
        }

        Ok(())
    }
}

// all protobuf rpc info
#[derive(Serialize, Clone, Debug)]
pub enum ProtobufRpcInfo {
    KrpcInfo(KrpcInfo),
}

impl Into<L7ProtocolSendLog> for ProtobufRpcInfo {
    fn into(self) -> L7ProtocolSendLog {
        match self {
            ProtobufRpcInfo::KrpcInfo(k) => k.into(),
        }
    }
}

pub fn vec_u8_to_string<S>(v: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&String::from_utf8_lossy(v))
}
