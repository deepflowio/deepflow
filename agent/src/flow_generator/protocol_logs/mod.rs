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

pub mod consts;
pub(crate) mod dns;
pub(crate) mod fastcgi;
pub(crate) mod http;
pub(crate) mod mq;
mod parser;
pub mod pb_adapter;
pub(crate) mod plugin;
pub(crate) mod rpc;
pub(crate) mod sql;
pub(crate) mod tls;
pub use self::http::{
    check_http_method, get_http_request_info, get_http_request_version, get_http_resp_info,
    is_http_v1_payload, parse_v1_headers, HttpInfo, HttpLog, Httpv2Headers,
};
use self::pb_adapter::L7ProtocolSendLog;
pub use self::plugin::custom_wrap::CustomWrapLog;
pub use self::plugin::wasm::{get_wasm_parser, WasmLog};
pub use dns::{DnsInfo, DnsLog};
pub use mq::{mqtt, KafkaInfo, KafkaLog, MqttInfo, MqttLog};
use num_enum::TryFromPrimitive;
pub use parser::{MetaAppProto, SessionAggregator, SLOT_WIDTH};
pub use rpc::{
    decode_new_rpc_trace_context, decode_new_rpc_trace_context_with_type, DubboHeader, DubboInfo,
    DubboLog, SofaRpcInfo, SofaRpcLog, SOFA_NEW_RPC_TRACE_CTX_KEY,
};
pub use sql::{
    decode, MongoDBInfo, MongoDBLog, MysqlHeader, MysqlInfo, MysqlLog, OracleInfo, OracleLog,
    PostgreInfo, PostgresqlLog, RedisInfo, RedisLog,
};
pub use tls::{TlsInfo, TlsLog};

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str,
    time::Duration,
};

use prost::Message;
use serde::{Serialize, Serializer};

use crate::common::l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface};
use crate::{
    common::{
        ebpf::EbpfType,
        enums::{IpProtocol, TapType},
        flow::{L7Protocol, PacketDirection, SignalSource},
        tap_port::TapPort,
    },
    flow_generator::error::Error,
    flow_generator::error::Result,
    metric::document::TapSide,
};
use public::proto::flow_log;
use public::sender::{SendMessageType, Sendable};
use public::utils::net::MacAddr;

const NANOS_PER_MICRO: u64 = 1000;
const FLOW_LOG_VERSION: u32 = 20220128;

#[derive(Serialize, Debug, PartialEq, Copy, Clone, Eq, TryFromPrimitive)]
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

#[derive(Serialize, Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive)]
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
    pub flow_id: u64,
    #[serde(serialize_with = "to_string_format")]
    pub tap_port: TapPort,
    pub signal_source: SignalSource,
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

    /* GPID */
    pub gpid_0: u32,
    pub gpid_1: u32,

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
    pub syscall_coroutine_0: u64,
    #[serde(skip_serializing_if = "value_is_default")]
    pub syscall_coroutine_1: u64,
    #[serde(skip_serializing_if = "value_is_default")]
    pub syscall_cap_seq_0: u64,
    #[serde(skip_serializing_if = "value_is_default")]
    pub syscall_cap_seq_1: u64,

    pub protocol: IpProtocol,
    #[serde(skip)]
    pub is_vip_interface_src: bool,
    #[serde(skip)]
    pub is_vip_interface_dst: bool,
    #[serde(skip)]
    pub netns_id_0: u32,
    #[serde(skip)]
    pub netns_id_1: u32,
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
            _ => panic!("{:?} ip_src,ip_dst type mismatch", &f),
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
            protocol: u8::from(f.protocol) as u32,
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
            syscall_coroutine_0: f.syscall_coroutine_0,
            syscall_coroutine_1: f.syscall_coroutine_1,
            gpid_0: f.gpid_0,
            gpid_1: f.gpid_1,
            netns_id_0: f.netns_id_0,
            netns_id_1: f.netns_id_1,
        }
    }
}

impl AppProtoLogsBaseInfo {
    // 请求调用回应来合并
    fn merge(&mut self, log: AppProtoLogsBaseInfo) {
        // adjust protocol when change, now only use for http2 change to grpc.
        if self.head.proto != log.head.proto {
            self.head.proto = log.head.proto;
        }
        if log.process_id_0 > 0 {
            self.process_id_0 = log.process_id_0;
            self.process_kname_0 = log.process_kname_0;
        }
        if log.process_id_1 > 0 {
            self.process_id_1 = log.process_id_1;
            self.process_kname_1 = log.process_kname_1;
        }
        self.syscall_trace_id_thread_1 = log.syscall_trace_id_thread_1;
        self.syscall_cap_seq_1 = log.syscall_cap_seq_1;

        self.start_time = log.start_time.min(self.start_time);
        self.end_time = log.end_time.max(self.end_time);
        match log.head.msg_type {
            LogMessageType::Request if self.req_tcp_seq == 0 && log.req_tcp_seq != 0 => {
                self.req_tcp_seq = log.req_tcp_seq;
            }
            LogMessageType::Response if self.resp_tcp_seq == 0 && log.resp_tcp_seq != 0 => {
                self.resp_tcp_seq = log.resp_tcp_seq;
            }
            _ => {}
        }

        self.syscall_trace_id_response = log.syscall_trace_id_response;
        // go http2 uprobe  may merge multi times, if not req and resp merge can not set to session
        if self.head.msg_type != log.head.msg_type {
            self.head.msg_type = LogMessageType::Session;
        }

        self.head.rrt = if self.end_time > self.start_time {
            (self.end_time.as_micros() - self.start_time.as_micros()) as u64
        } else {
            0
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct AppProtoLogsData {
    #[serde(flatten)]
    pub base_info: AppProtoLogsBaseInfo,
    #[serde(flatten)]
    pub special_info: L7ProtocolInfo,
    pub direction_score: u8,
}

impl fmt::Display for AppProtoLogsData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} direction_score: {}\n",
            self.base_info, self.direction_score
        )?;
        write!(f, "\t{:?}", self.special_info)
    }
}

impl AppProtoLogsData {
    pub fn new(
        base_info: AppProtoLogsBaseInfo,
        special_info: L7ProtocolInfo,
        direction_score: u8,
    ) -> Self {
        Self {
            base_info,
            special_info,
            direction_score,
        }
    }

    pub fn is_request(&self) -> bool {
        self.base_info.head.msg_type == LogMessageType::Request
    }

    pub fn is_response(&self) -> bool {
        return self.base_info.head.msg_type == LogMessageType::Response;
    }

    pub fn ebpf_flow_session_id(&self) -> u64 {
        // 取flow_id(即ebpf底层的socket id)的高8位(cpu id)+低24位(socket id的变化增量), 作为聚合id的高32位
        // |flow_id 高8位| flow_id 低24位|proto 8 位|session 低24位|

        // due to grpc is init by http2 and modify during parse, it must reset to http2 when the protocol is grpc.
        let proto = if self.base_info.head.proto == L7Protocol::Grpc {
            if let L7ProtocolInfo::HttpInfo(_) = &self.special_info {
                L7Protocol::Http2
            } else {
                unreachable!()
            }
        } else {
            self.base_info.head.proto
        };

        let flow_id_part =
            (self.base_info.flow_id >> 56 << 56) | (self.base_info.flow_id << 40 >> 8);
        if let Some(session_id) = self.special_info.session_id() {
            flow_id_part | (proto as u64) << 24 | ((session_id as u64) & 0xffffff)
        } else {
            let mut cap_seq = self
                .base_info
                .syscall_cap_seq_0
                .max(self.base_info.syscall_cap_seq_1);
            if self.base_info.head.msg_type == LogMessageType::Request {
                cap_seq += 1;
            };
            flow_id_part | ((proto as u64) << 24) | (cap_seq & 0xffffff)
        }
    }

    pub fn session_merge(&mut self, log: Self) -> Result<()> {
        if let Err(err) = self.protocol_merge(log.special_info) {
            /*
                if can not merge, return log which can not merge to self.
                the follow circumstance can not merge:
                    when ebpf disorder, http1 can not match req/resp.
            */
            if let Error::L7ProtocolCanNotMerge(special_info) = err {
                return Err(Error::L7LogCanNotMerge(Self {
                    special_info,
                    ..log
                }));
            }
            return Err(err);
        };
        self.base_info.merge(log.base_info);
        Ok(())
    }

    fn protocol_merge(&mut self, log: L7ProtocolInfo) -> Result<()> {
        self.special_info.merge_log(log)
    }

    // 是否需要进一步聚合
    // 目前仅http2 uprobe 需要聚合多个请求
    pub fn need_protocol_merge(&self) -> bool {
        self.special_info.need_merge()
    }
}

#[derive(Debug)]
pub struct BoxAppProtoLogsData(pub Box<AppProtoLogsData>);

impl Sendable for BoxAppProtoLogsData {
    fn encode(self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        let mut pb_proto_logs_data = flow_log::AppProtoLogsData {
            base: Some(self.0.base_info.into()),
            direction_score: self.0.direction_score as u32,
            ..Default::default()
        };

        let log: L7ProtocolSendLog = self.0.special_info.into();
        log.fill_app_proto_log(&mut pb_proto_logs_data);
        pb_proto_logs_data
            .encode(buf)
            .map(|_| pb_proto_logs_data.encoded_len())
    }

    fn file_name(&self) -> &str {
        "l7_flow_log"
    }

    fn message_type(&self) -> SendMessageType {
        SendMessageType::ProtocolLog
    }

    fn to_kv_string(&self, kv_string: &mut String) {
        let json = serde_json::to_string(&(*self.0)).unwrap();
        kv_string.push_str(&json);
        kv_string.push('\n');
    }

    fn version(&self) -> u32 {
        FLOW_LOG_VERSION
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

fn decode_base64_to_string(value: &str) -> String {
    let bytes = match base64::decode(value) {
        Ok(v) => v,
        Err(_) => return value.to_string(),
    };
    match str::from_utf8(&bytes) {
        Ok(s) => s.to_string(),
        Err(_) => value.to_string(),
    }
}
