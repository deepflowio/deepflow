pub mod consts;
mod dns;
mod http;
mod mq;
mod parser;
mod rpc;
mod sql;

pub use self::http::{
    check_http_method, get_http_request_version, get_http_resp_info, HttpInfo, HttpLog,
    Httpv2Headers,
};
pub use dns::{DnsInfo, DnsLog};
pub use mq::{KafkaInfo, KafkaLog};
pub use parser::{AppProtoLogsParser, MetaAppProto};
pub use rpc::{DubboHeader, DubboInfo, DubboLog};
pub use sql::{decode, MysqlHeader, MysqlInfo, MysqlLog, RedisInfo, RedisLog};

use std::{
    fmt,
    mem::swap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use prost::Message;

use crate::{
    common::{
        enums::{IpProtocol, PacketDirection, TapType},
        flow::L7Protocol,
        meta_packet::MetaPacket,
        tap_port::TapPort,
    },
    flow_generator::error::Result,
    metric::document::TapSide,
    proto::flow_log,
    utils::net::MacAddr,
};

#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum L7ResponseStatus {
    Ok,
    Error,
    NotExist,
    ServerError,
    ClientError,
}

impl Default for L7ResponseStatus {
    fn default() -> Self {
        L7ResponseStatus::Ok
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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

#[derive(Debug, Default, Clone)]
pub struct AppProtoHead {
    pub proto: L7Protocol,
    pub msg_type: LogMessageType, // HTTP，DNS: request/response
    pub status: L7ResponseStatus, // 状态描述：0：正常，1：已废弃使用(先前用于表示异常)，2：不存在，3：服务端异常，4：客户端异常
    pub code: u16,                // HTTP状态码: 1xx-5xx, DNS状态码: 0-7
    pub rrt: u64,                 // HTTP，DNS时延: response-request
}

impl From<AppProtoHead> for flow_log::AppProtoHead {
    fn from(f: AppProtoHead) -> Self {
        flow_log::AppProtoHead {
            proto: f.proto as u32,
            msg_type: f.msg_type as u32,
            status: f.status as u32,
            code: f.code as u32,
            rrt: f.rrt,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppProtoLogsBaseInfo {
    pub start_time: Duration,
    pub end_time: Duration,
    pub flow_id: u64,
    pub tap_port: TapPort,
    pub vtap_id: u16,
    pub tap_type: TapType,
    pub is_ipv6: bool,
    pub tap_side: TapSide,
    pub head: AppProtoHead,

    /* L2 */
    pub mac_src: MacAddr,
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
    pub cap_seq: u64,
    pub process_id_0: u32,
    pub process_id_1: u32,
    pub process_kname_0: String,
    pub process_kname_1: String,
    pub syscall_trace_id_request: u64,
    pub syscall_trace_id_response: u64,
    pub syscall_trace_id_thread: u32,

    pub protocol: IpProtocol,
    pub is_vip_interface_src: bool,
    pub is_vip_interface_dst: bool,
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
            syscall_trace_id_thread: f.syscall_trace_id_thread,
        }
    }
}

impl AppProtoLogsBaseInfo {
    pub fn from_ebpf(
        packet: &MetaPacket,
        head: AppProtoHead,
        vtap_id: u16,
        local_epc: i32,
        remote_epc: i32,
    ) -> Self {
        let is_src = packet.lookup_key.l2_end_0;
        let mut info = Self {
            start_time: packet.lookup_key.timestamp,
            end_time: packet.lookup_key.timestamp,
            flow_id: packet.socket_id,
            tap_port: packet.tap_port,
            tap_type: TapType::Tor,
            is_ipv6: packet.lookup_key.dst_ip.is_ipv6(),
            tap_side: if is_src {
                TapSide::ClientProcess
            } else {
                TapSide::ServerProcess
            },

            mac_src: packet.lookup_key.src_mac,
            mac_dst: packet.lookup_key.dst_mac,
            ip_src: packet.lookup_key.src_ip,
            ip_dst: packet.lookup_key.dst_ip,
            port_src: packet.lookup_key.src_port,
            port_dst: packet.lookup_key.dst_port,
            protocol: packet.lookup_key.proto,

            cap_seq: packet.cap_seq,
            process_id_0: if is_src { packet.process_id } else { 0 },
            process_id_1: if !is_src { packet.process_id } else { 0 },
            process_kname_0: if is_src {
                packet.process_name.clone()
            } else {
                "".to_string()
            },
            process_kname_1: if !is_src {
                packet.process_name.clone()
            } else {
                "".to_string()
            },

            syscall_trace_id_request: if packet.direction == PacketDirection::ClientToServer {
                packet.syscall_trace_id
            } else {
                0
            },
            syscall_trace_id_response: if packet.direction == PacketDirection::ServerToClient {
                packet.syscall_trace_id
            } else {
                0
            },
            req_tcp_seq: if packet.direction == PacketDirection::ClientToServer {
                packet.tcp_data.seq
            } else {
                0
            },
            resp_tcp_seq: if packet.direction == PacketDirection::ServerToClient {
                packet.tcp_data.seq
            } else {
                0
            },
            syscall_trace_id_thread: packet.thread_id,

            vtap_id,
            head,
            l3_epc_id_src: if is_src { local_epc } else { remote_epc },
            l3_epc_id_dst: if is_src { remote_epc } else { local_epc },
            is_vip_interface_src: false,
            is_vip_interface_dst: false,
        };
        if packet.direction == PacketDirection::ServerToClient {
            swap(&mut info.mac_src, &mut info.mac_dst);
            swap(&mut info.ip_src, &mut info.ip_dst);
            swap(&mut info.l3_epc_id_src, &mut info.l3_epc_id_dst);
            swap(&mut info.port_src, &mut info.port_dst);
            swap(&mut info.process_id_0, &mut info.process_id_1);
            swap(&mut info.process_kname_0, &mut info.process_kname_1);
            info.tap_side = if info.tap_side == TapSide::ClientProcess {
                TapSide::ServerProcess
            } else {
                TapSide::ClientProcess
            };
        }

        info
    }
    // 请求调用回应来合并
    fn merge(&mut self, log: AppProtoLogsBaseInfo) {
        if log.process_id_0 > 0 {
            self.process_id_0 = log.process_id_0;
            self.process_kname_0 = log.process_kname_0;
        }
        if log.process_id_1 > 0 {
            self.process_id_1 = log.process_id_1;
            self.process_kname_1 = log.process_kname_1;
        }

        self.end_time = log.end_time;
        self.resp_tcp_seq = log.resp_tcp_seq;
        self.syscall_trace_id_response = log.syscall_trace_id_response;
        self.head.msg_type = LogMessageType::Session;
        self.head.code = log.head.code;
    }
}

#[derive(Debug, Clone)]
pub enum AppProtoLogsInfo {
    Dns(DnsInfo),
    Mysql(MysqlInfo),
    Redis(RedisInfo),
    Kafka(KafkaInfo),
    Dubbo(DubboInfo),
    HttpV1(HttpInfo),
    HttpV2(HttpInfo),
}

impl AppProtoLogsInfo {
    fn session_id(&self) -> u32 {
        match self {
            AppProtoLogsInfo::Dns(t) => t.trans_id as u32,
            AppProtoLogsInfo::Mysql(_t) => 0,
            AppProtoLogsInfo::Redis(_t) => 0,
            AppProtoLogsInfo::Kafka(t) => t.correlation_id,
            AppProtoLogsInfo::Dubbo(t) => t.serial_id as u32,
            AppProtoLogsInfo::HttpV1(t) => t.stream_id,
            AppProtoLogsInfo::HttpV2(t) => t.stream_id,
        }
    }

    fn merge(&mut self, other: Self) {
        match (self, other) {
            (Self::Dns(m), Self::Dns(o)) => m.merge(o),
            (Self::Mysql(m), Self::Mysql(o)) => m.merge(o),
            (Self::Redis(m), Self::Redis(o)) => m.merge(o),
            (Self::Kafka(m), Self::Kafka(o)) => m.merge(o),
            (Self::Dubbo(m), Self::Dubbo(o)) => m.merge(o),
            (Self::HttpV1(m), Self::HttpV1(o)) => m.merge(o),
            (Self::HttpV2(m), Self::HttpV2(o)) => m.merge(o),
            _ => unreachable!(),
        }
    }
}

impl fmt::Display for AppProtoLogsInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(l) => write!(f, "{:?}", l),
            Self::Mysql(l) => write!(f, "{:?}", l),
            Self::Redis(l) => write!(f, "{}", l),
            Self::Dubbo(l) => write!(f, "{:?}", l),
            Self::Kafka(l) => write!(f, "{:?}", l),
            Self::HttpV1(l) => write!(f, "{:?}", l),
            Self::HttpV2(l) => write!(f, "{:?}", l),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppProtoLogsData {
    pub base_info: AppProtoLogsBaseInfo,
    pub special_info: AppProtoLogsInfo,
}

impl fmt::Display for AppProtoLogsData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\n", self.base_info)?;
        write!(f, "\t{}", self.special_info)
    }
}

impl AppProtoLogsData {
    pub fn new(base_info: AppProtoLogsBaseInfo, special_info: AppProtoLogsInfo) -> Self {
        Self {
            base_info,
            special_info,
        }
    }

    pub fn encode(self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        let mut pb_proto_logs_data = flow_log::AppProtoLogsData {
            base: Some(self.base_info.into()),
            http: None,
            dns: None,
            mysql: None,
            redis: None,
            dubbo: None,
            kafka: None,
        };
        match self.special_info {
            AppProtoLogsInfo::Dns(t) => pb_proto_logs_data.dns = Some(t.into()),
            AppProtoLogsInfo::Mysql(t) => pb_proto_logs_data.mysql = Some(t.into()),
            AppProtoLogsInfo::Redis(t) => pb_proto_logs_data.redis = Some(t.into()),
            AppProtoLogsInfo::Kafka(t) => pb_proto_logs_data.kafka = Some(t.into()),
            AppProtoLogsInfo::Dubbo(t) => pb_proto_logs_data.dubbo = Some(t.into()),
            AppProtoLogsInfo::HttpV1(t) => pb_proto_logs_data.http = Some(t.into()),
            AppProtoLogsInfo::HttpV2(t) => pb_proto_logs_data.http = Some(t.into()),
        };

        pb_proto_logs_data
            .encode(buf)
            .map(|_| pb_proto_logs_data.encoded_len())
    }

    pub fn flow_session_id(&self) -> u64 {
        self.base_info.flow_id << 32
            | (self.base_info.head.proto as u64) << 24
            | self.special_info.session_id() as u64
    }

    pub fn session_merge(&mut self, log: AppProtoLogsData) {
        self.base_info.merge(log.base_info);
        self.special_info.merge(log.special_info);
    }
}

impl fmt::Display for AppProtoLogsBaseInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Timestamp: {:?} Vtap_id: {} Flow_id: {} TapType: {} TapPort: {} TapSide: {:?}\n \
                \t{}_{}_{} -> {}_{}_{} Proto: {:?} Seq: {} -> {} VIP: {} -> {} EPC: {} -> {}\n \
                \tProcess: {}:{} -> {}:{} Trace-id: {} -> {} Thread: {}\n \
                \tL7Protocol: {:?} MsgType: {:?} Status: {:?} Code: {} Rrt: {}",
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
            self.syscall_trace_id_thread,
            self.head.proto,
            self.head.msg_type,
            self.head.status,
            self.head.code,
            self.head.rrt
        )
    }
}

pub trait L7LogParse: Send + Sync {
    fn parse(
        &mut self,
        payload: &[u8],
        proto: IpProtocol,
        direction: PacketDirection,
    ) -> Result<AppProtoHead>;
    fn info(&self) -> AppProtoLogsInfo;
}
