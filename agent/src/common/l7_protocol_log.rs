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

use std::fmt::Debug;
use std::net::IpAddr;

use enum_dispatch::enum_dispatch;

use super::ebpf::EbpfType;
use super::flow::PacketDirection;
use super::l7_protocol_info::L7ProtocolInfo;
use super::MetaPacket;

use crate::config::handler::LogParserConfig;
use crate::flow_generator::protocol_logs::{
    get_protobuf_rpc_parser, DnsLog, DubboLog, HttpLog, KafkaLog, MqttLog, MysqlLog, PostgresqlLog,
    ProtobufRpcWrapLog, RedisLog, SofaRpcLog,
};
use crate::flow_generator::Result;

use public::enums::IpProtocol;
use public::l7_protocol::{L7Protocol, L7ProtocolEnum, ProtobufRpcProtocol};

/*
 所有协议都需要实现L7ProtocolLogInterface这个接口.
 其中，check_payload 用于MetaPacket判断应用层协议，parse_payload 用于解析具体协议.
 更具体就是遍历ALL_PROTOCOL的协议，用check判断协议，再用parse解析整个payload，得到L7ProtocolInfo.
 最后发送到server之前，调用into() 转成通用结构L7ProtocolSendLog.

 all protocol need implement L7ProtocolLogInterface trait.
 check_payload use to determine what protocol the payload is.
 parse_payload use to parse whole payload.
 more specifically, traversal all protocol from get_all_protocol,check the payload and then parse it,
 get the L7ProtocolInfo enum, finally convert to L7ProtocolSendLog struct and send to server.

 the parser flow:

    check_payload -> parse_payload -> reset --
                        /|\                  |
                         |                   |
                         |_____next packet___|
*/

#[macro_export]
macro_rules! parse_common {
    ($self:ident,$parse_param:ident) => {
        $self.info.start_time = $parse_param.time;
        $self.info.end_time = $parse_param.time;
        if let Some(param) = $parse_param.ebpf_param {
            $self.info.is_tls = param.is_tls;
        }
    };
}

/*
    common log perf update macro. if must define the log and info struct like:

    struct xxxInfo{
        // .. some field

        // the current msg type
        msg_type: LogMessageType,

        // the msg time
        start_time: u64,
        end_time: u64,

    }

    struct xxxLog{
        // ... some field

        // the log info
        info: xxxInfo,

        // (log_type, timestamp), record the previous log info,
        previous_log_info: LruCache<u32, (LogMessageType, u64)>,
        perf_stats: Option<PerfStats>,
    }

    also need to add the code like:

    impl L7ProtocolParserInterface for xxxLog {
        // ... other fn

         fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<Vec<L7ProtocolInfo>> {
            // set the info time
            self.info.start_time = param.time;
            self.info.end_time = param.time;

            // ...parse payload

            // revert the info time before return Ok().
            self.revert_info_time(param.direction, param.time);
            Ok(...)

         }

        fn reset(&mut self) {
            // save the current log info before reset log
            self.save_info_rrt();

            // ... reset log
        }
    }
*/
#[macro_export]
macro_rules! perf_impl {
    ($log_struct:ident) => {
        impl $log_struct {
            fn save_info_time(&mut self){
                let time = match self.info.msg_type{
                    LogMessageType::Response =>self.info.end_time,
                    LogMessageType::Request =>self.info.start_time,
                    _=>return,
                };

                self.previous_log_info.put(
                    self.info.session_id().unwrap_or_default(),
                    (self.info.msg_type, time),
                );
            }

            // revert the rrt from previous_log_info
            fn revert_info_time(&mut self, direction: PacketDirection, cur_time: u64) {
                let Some((ref prev_typ,ref prev_time)) = self.previous_log_info.get(&self.info.session_id().unwrap_or_default()) else{
                    return ;
                };
                match direction {
                    // current is req and previous is resp and previous time gt current time,
                    // likely ebpf disorder, revert the info end time
                    PacketDirection::ClientToServer
                        if *prev_typ == LogMessageType::Response && *prev_time > cur_time =>
                    {
                        self.info.end_time = *prev_time;
                    }

                    // current is resp and previous is req and current info time gt previous info time, revert the info start.
                    PacketDirection::ServerToClient
                        if *prev_typ == LogMessageType::Request && cur_time > *prev_time =>
                    {
                        self.info.start_time = *prev_time;
                    }
                    _ => {}
                }
            }

            fn update_perf(
                &mut self,
                req_count: u32,
                resp_count: u32,
                req_err: u32,
                resp_err: u32,
                time: u64,
            ) {
                if self.perf_stats.is_none() {
                    self.perf_stats = Some(PerfStats::default());
                }
                let perf = self.perf_stats.as_mut().unwrap();
                perf.update_perf(req_count, resp_count, req_err, resp_err, {
                    let previous_log_info = self
                        .previous_log_info
                        .get(&self.info.session_id().unwrap_or_default());

                    if time != 0 && previous_log_info.is_some() {
                        let previous_log_info = previous_log_info.unwrap();
                        // if previous is req and current is resp, calculate the round trip time.
                        if previous_log_info.0 == LogMessageType::Request
                            && self.info.msg_type == LogMessageType::Response
                            && time > previous_log_info.1
                        {
                            time - previous_log_info.1

                        // if previous is resp and current is req and previous time gt current time, likely ebpf disorder,
                        // calculate the round trip time.
                        } else if previous_log_info.0 == LogMessageType::Response
                            && self.info.msg_type == LogMessageType::Request
                            && previous_log_info.1 > time
                        {
                            previous_log_info.1 - time
                        } else {
                            0
                        }
                    } else {
                        0
                    }
                });
            }

            fn perf_inc_req(&mut self, time: u64) {
                self.update_perf(1, 0, 0, 0, time);
            }

            fn perf_inc_resp(&mut self, time: u64) {
                self.update_perf(0, 1, 0, 0, time);
            }

            fn perf_inc_req_err(&mut self) {
                self.update_perf(0, 0, 1, 0, 0);
            }

            fn perf_inc_resp_err(&mut self) {
                self.update_perf(0, 0, 0, 1, 0);
            }
        }
    };
}

macro_rules! impl_protocol_parser {
    (pub enum $name:ident { $($proto:ident($log_type:ty)),* $(,)? }) => {
        pub enum $name {
            Http(Box<HttpLog>),
            $($proto($log_type)),*
        }

        impl L7ProtocolParserInterface for $name {
            fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
                match self {
                    Self::Http(p) => p.check_payload(payload, param),
                    $(Self::$proto(p) => p.check_payload(payload, param)),*
                }
            }

            fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<Vec<L7ProtocolInfo>> {
                match self {
                    Self::Http(p) => p.parse_payload(payload, param),
                    $(Self::$proto(p) => p.parse_payload(payload, param)),*
                }
            }

            fn protocol(&self) -> L7Protocol {
                match self {
                    Self::Http(p) => p.protocol(),
                    $(Self::$proto(p) => p.protocol()),*
                }
            }

            fn protobuf_rpc_protocol(&self) -> Option<ProtobufRpcProtocol> {
                match self {
                    Self::Http(p) => p.protobuf_rpc_protocol(),
                    $(Self::$proto(p) => p.protobuf_rpc_protocol()),*
                }
            }

            fn l7_protocl_enum(&self) -> L7ProtocolEnum {
                match self {
                    Self::Http(p) => p.l7_protocl_enum(),
                    $(Self::$proto(p) => p.l7_protocl_enum()),*
                }
            }

            fn parsable_on_tcp(&self) -> bool {
                match self {
                    Self::Http(p) => p.parsable_on_tcp(),
                    $(Self::$proto(p) => p.parsable_on_tcp()),*
                }
            }

            fn parsable_on_udp(&self) -> bool {
                match self {
                    Self::Http(p) => p.parsable_on_udp(),
                    $(Self::$proto(p) => p.parsable_on_udp()),*
                }
            }

            fn parse_default(&self) -> bool {
                match self {
                    Self::Http(p) => p.parse_default(),
                    $(Self::$proto(p) => p.parse_default()),*
                }
            }

            fn reset(&mut self) {
                match self {
                    Self::Http(p) => p.reset(),
                    $(Self::$proto(p) => p.reset()),*
                }
            }
        }

        impl L7ProtocolParser {
            pub fn as_str(&self) -> &'static str {
                match self {
                    Self::Http(p) => {
                        match p.protocol() {
                            L7Protocol::Http1 => return "HTTP",
                            L7Protocol::Http2 => return "HTTP2",
                            _ => unreachable!()
                        }
                    },
                    $(
                        Self::$proto(_) => stringify!($proto),
                    )*
                }
            }
        }

        impl TryFrom<&str> for L7ProtocolParser {
            type Error = String;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                match value {
                    "HTTP" => Ok(Self::Http(Box::new(HttpLog::new_v1()))),
                    "HTTP2" => Ok(Self::Http(Box::new(HttpLog::new_v2(false)))),
                    $(
                        stringify!($proto) => Ok(Self::$proto(Default::default())),
                    )*
                    _ => Err(String::from(format!("unknown protocol {}",value))),
                }
            }
        }

        pub fn get_parser(p: L7ProtocolEnum) -> Option<L7ProtocolParser> {
            match p {
                L7ProtocolEnum::L7Protocol(p) => match p {
                    L7Protocol::Http1 | L7Protocol::Http1TLS => Some(L7ProtocolParser::Http(Box::new(HttpLog::new_v1()))),
                    L7Protocol::Http2 | L7Protocol::Http2TLS => Some(L7ProtocolParser::Http(Box::new(HttpLog::new_v2(false)))),
                    L7Protocol::Grpc => Some(L7ProtocolParser::Http(Box::new(HttpLog::new_v2(true)))),

                    $(
                        L7Protocol::$proto => Some(L7ProtocolParser::$proto(Default::default())),
                    )+
                    _ => None,
                },
                L7ProtocolEnum::ProtobufRpc(p) => Some(get_protobuf_rpc_parser(p)),
            }
        }

        pub fn get_all_protocol() -> Vec<L7ProtocolParser> {
            Vec::from([
                L7ProtocolParser::Http(Box::new(HttpLog::new_v1())),
                L7ProtocolParser::Http(Box::new(HttpLog::new_v2(false))),
                $(
                    L7ProtocolParser::$proto(Default::default()),
                )+
            ])
        }
    }
}

/*
macro expand result like:

#[enum_dispatch]
pub enum L7ProtocolParser {
    HttpParser(HttpLog),
    DnsParser(DnsLog),
    MysqlParser(MysqlLog),
    ...
}

pub fn get_parser(p: L7Protocol) -> Option<L7ProtocolParser> {
    match p {
        L7Protocol::Http1 => Some(L7ProtocolParser::HttpParser(HttpLog::new_v1())),
        L7Protocol::Http2 => Some(L7ProtocolParser::HttpParser(HttpLog::new_v2())),
        L7Protocol::Dns => Some(L7ProtocolParser::DnsParser(DnsLog::default())),
        L7Protocol::Mysql => Some(L7ProtocolParser::MysqlParser(MysqlLog::default())),
        ...

    }
}

pub fn get_all_protocol() -> Vec<L7ProtocolParser> {
    Vec::from([
        L7ProtocolParser::HttpParser(HttpLog::new_v1()),
        L7ProtocolParser::HttpParser(HttpLog::new_v2()),
        L7ProtocolParser::DnsParser(DnsLog::default()),
        L7ProtocolParser::MysqlParser(MysqlLog::default()),
        ...
    ])
}
*/

// 内部实现的协议
// log的具体结构和实现在 src/flow_generator/protocol_logs/** 下
// 注意枚举名大小写，因为会用于字符串解析
// 大结构体（128B以上）注意加Box，减少内存使用
// =========================================================
// the inner implement protocol source code in src/flow_generator/protocol_logs/**
// enum name will be used to parse strings so case matters
// large structs (>128B) should be boxed to reduce memory consumption
//
impl_protocol_parser! {
    pub enum L7ProtocolParser {
        // http have two version but one parser, can not place in macro param.
        DNS(DnsLog),
        ProtobufRPC(Box<ProtobufRpcWrapLog>),
        SofaRPC(Box<SofaRpcLog>),
        MySQL(MysqlLog),
        Kafka(KafkaLog),
        Redis(Box<RedisLog>),
        PostgreSQL(Box<PostgresqlLog>),
        Dubbo(Box<DubboLog>),
        MQTT(MqttLog),
        // add protocol below
    }
}

#[enum_dispatch]
pub trait L7ProtocolParserInterface {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool;
    // 协议解析
    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<Vec<L7ProtocolInfo>>;
    // 返回协议号和协议名称，由于的bitmap使用u128，所以协议号不能超过128.
    // 其中 crates/public/src/l7_protocol.rs 里面的 pub const L7_PROTOCOL_xxx 是已实现的协议号.
    // ===========================================================================================
    // return protocol number and protocol string. because of bitmap use u128, so the max protocol number can not exceed 128
    // crates/public/src/l7_protocol.rs, pub const L7_PROTOCOL_xxx is the implemented protocol.
    fn protocol(&self) -> L7Protocol;
    // return protobuf protocol, only when L7Protocol is ProtobufRPC will not None
    fn protobuf_rpc_protocol(&self) -> Option<ProtobufRpcProtocol> {
        None
    }

    fn l7_protocl_enum(&self) -> L7ProtocolEnum {
        let proto = self.protocol();
        match proto {
            L7Protocol::ProtobufRPC => {
                L7ProtocolEnum::ProtobufRpc(self.protobuf_rpc_protocol().unwrap())
            }
            _ => L7ProtocolEnum::L7Protocol(proto),
        }
    }
    // l4是tcp时是否解析，用于快速过滤协议
    // ==============================
    // whether l4 is parsed when tcp, use for quickly protocol filter
    fn parsable_on_tcp(&self) -> bool {
        true
    }
    // l4是udp是是否解析，用于快速过滤协议
    // ==============================
    // whether l4 is parsed when udp, use for quickly protocol filter
    fn parsable_on_udp(&self) -> bool {
        true
    }

    // is parse default? use for config init.
    fn parse_default(&self) -> bool {
        true
    }

    fn reset(&mut self);
}

#[derive(Clone, Copy)]
pub struct EbpfParam {
    pub is_tls: bool,
    // 目前仅 http2 uprobe 有意义
    // ==========================
    // now only http2 uprobe uses
    pub is_req_end: bool,
    pub is_resp_end: bool,

    /*
        eBPF 程序为每一个 socket 维护一个 cap_seq 序列号，每次 read/write syscall 调用会自增 1。
        目前仅用于处理ebpf乱序问题，并且仅能用于没有 request_id 并且是请求响应串行的模型。
        当响应的 cap_seq 减去请求的 cap_seq 不等于1，就认为乱序无法聚合，直接发送请求和响应。
        其中，mysql 和 postgresql 由于 预编译请求 和 执行结果之间有数个报文的间隔，所以不能通过序号差判断是否乱序。
        所以现在只有 http1，redis 能使用这个方法处理乱序。
        FIXME: http1 在 pipeline 模型下依然会有乱序的情况，目前不解决。
        ====================================================================
        The eBPF program maintains a cap_seq sequence number for each socket, which is incremented by 1 for each read/write syscall call.
        Currently only used to deal with ebpf out-of-order problems, and can only be used for protocol without request_id and request-response serialization.
        When the cap_seq of the response subtract the cap_seq of the request is not equal to 1, it is considered that the out-of-order cannot be aggregated, and the request and response are sent directly without merge.
        MySQL and postgreSQL cannot judge whether the order is out of order due to the interval of several messages between the precompiled request and the execution result.
        So now only http1, redis can use this method to deal with out-of-order.
        FIXME: http1 will still be out of order under the pipeline model, which is not resolved at present.
    */
    pub cap_seq: u64,
}

#[derive(Clone, Copy)]
pub struct ParseParam<'a> {
    // l3/l4 info
    pub l4_protocol: IpProtocol,
    pub ip_src: IpAddr,
    pub ip_dst: IpAddr,
    pub port_src: u16,
    pub port_dst: u16,

    pub direction: PacketDirection,
    pub ebpf_type: EbpfType,
    // ebpf_type 不为 EBPF_TYPE_NONE 会有值
    // ===================================
    // not None when payload from ebpf
    pub ebpf_param: Option<EbpfParam>,
    pub time: u64,

    pub parse_config: Option<&'a LogParserConfig>,
}

impl From<&MetaPacket<'_>> for ParseParam<'_> {
    fn from(packet: &MetaPacket<'_>) -> Self {
        let mut param = Self {
            l4_protocol: packet.lookup_key.proto,
            ip_src: packet.lookup_key.src_ip,
            ip_dst: packet.lookup_key.dst_ip,
            port_src: packet.lookup_key.src_port,
            port_dst: packet.lookup_key.dst_port,

            direction: packet.lookup_key.direction,
            ebpf_type: packet.ebpf_type,
            ebpf_param: None,
            time: packet.lookup_key.timestamp.as_micros() as u64,
            parse_config: None,
        };
        if packet.ebpf_type != EbpfType::None {
            let is_tls = match packet.ebpf_type {
                EbpfType::TlsUprobe => true,
                _ => match packet.l7_protocol_from_ebpf {
                    L7Protocol::Http1TLS | L7Protocol::Http2TLS => true,
                    _ => false,
                },
            };
            param.ebpf_param = Some(EbpfParam {
                is_tls,
                is_req_end: packet.is_request_end,
                is_resp_end: packet.is_response_end,
                cap_seq: packet.cap_seq,
            });
        }

        param
    }
}

impl<'a> From<(&MetaPacket<'_>, &'a LogParserConfig)> for ParseParam<'a> {
    fn from(f: (&MetaPacket<'_>, &'a LogParserConfig)) -> Self {
        let mut p = Self::from(f.0);
        p.parse_config = Some(f.1);
        p
    }
}

impl ParseParam<'_> {
    pub fn is_tls(&self) -> bool {
        if let Some(ebpf_param) = self.ebpf_param {
            return ebpf_param.is_tls;
        }
        false
    }
}

/*
    param:
        protocol: the protocol which should check

        l7_enabled: the protocol from static config indicate which protocol should check or skip

    it will merge the bitmap from config and l4 protocol filter.

    return the protocol bitmap indicate which protocol should check and parse.
*/
pub fn get_parse_bitmap(protocol: IpProtocol, l7_enabled: L7ProtocolBitmap) -> L7ProtocolBitmap {
    let mut bitmap = L7ProtocolBitmap(0);
    for i in get_all_protocol().iter() {
        if l7_enabled.is_enabled(i.protocol()) {
            match protocol {
                IpProtocol::Tcp if i.parsable_on_tcp() => {
                    bitmap.set_enabled(i.protocol());
                }
                IpProtocol::Udp if i.parsable_on_udp() => {
                    bitmap.set_enabled(i.protocol());
                }
                _ => {}
            }
        }
    }

    bitmap
}

/*
    protocol is u128 bitmap indicate which protocol should check or skip.
    when bit set 0 should skip the protocol check.
    so the protocol number can not exceed 127.
*/
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct L7ProtocolBitmap(u128);

impl L7ProtocolBitmap {
    pub fn set_enabled(&mut self, p: L7Protocol) {
        self.0 |= 1 << (p as u128);
    }

    pub fn set_disabled(&mut self, p: L7Protocol) {
        self.0 &= !(1 << (p as u128));
    }

    pub fn is_disabled(&self, p: L7Protocol) -> bool {
        self.0 & (1 << (p as u128)) == 0
    }

    pub fn is_enabled(&self, p: L7Protocol) -> bool {
        !self.is_disabled(p)
    }
}

impl From<&Vec<String>> for L7ProtocolBitmap {
    fn from(vs: &Vec<String>) -> Self {
        let mut bitmap = L7ProtocolBitmap(0);
        for v in vs.iter() {
            if let Ok(p) = L7ProtocolParser::try_from(v.as_str()) {
                bitmap.set_enabled(p.protocol());
            }
        }
        bitmap
    }
}

impl Debug for L7ProtocolBitmap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut p = vec![];
        for i in get_all_protocol() {
            if self.is_enabled(i.protocol()) {
                p.push(i.protocol());
            }
        }
        f.write_str(format!("{:#?}", p).as_str())
    }
}
