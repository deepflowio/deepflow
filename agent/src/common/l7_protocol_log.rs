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

use std::cell::RefCell;
use std::fmt::Debug;
use std::net::IpAddr;
use std::rc::Rc;

use enum_dispatch::enum_dispatch;

use lru::LruCache;

use super::ebpf::EbpfType;
use super::flow::{L7PerfStats, PacketDirection};
use super::l7_protocol_info::L7ProtocolInfo;
use super::MetaPacket;

use crate::config::handler::LogParserConfig;
use crate::flow_generator::protocol_logs::plugin::custom_wrap::CustomWrapLog;
use crate::flow_generator::protocol_logs::plugin::get_custom_log_parser;
use crate::flow_generator::protocol_logs::{
    get_protobuf_rpc_parser, DnsLog, DubboLog, HttpLog, KafkaLog, MqttLog, MysqlLog, PostgresqlLog,
    ProtobufRpcWrapLog, RedisLog, SofaRpcLog,
};
use crate::flow_generator::{LogMessageType, Result};
use crate::plugin::wasm::WasmVm;

use public::enums::IpProtocol;
use public::l7_protocol::{CustomProtocol, L7Protocol, L7ProtocolEnum, ProtobufRpcProtocol};

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
                    Self::Http(_) => None,
                    $(Self::$proto(p) => p.protobuf_rpc_protocol()),*
                }
            }

            fn custom_protocol(&self) -> Option<CustomProtocol> {
                match self {
                    Self::Http(_) => None,
                    $(Self::$proto(p) => p.custom_protocol()),*
                }
            }

            fn l7_protocol_enum(&self) -> L7ProtocolEnum {
                match self {
                    Self::Http(p) => p.l7_protocol_enum(),
                    $(Self::$proto(p) => p.l7_protocol_enum()),*
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

            fn perf_stats(&mut self) -> Option<L7PerfStats> {
                match self {
                    Self::Http(p) => p.perf_stats(),
                    $(Self::$proto(p) => p.perf_stats()),*
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
                L7ProtocolEnum::Custom(p) => Some(get_custom_log_parser(p)),
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
        Custom(CustomWrapLog),
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

    // return inner proto of Custom, only when L7Protocol is Custom will not None
    fn custom_protocol(&self) -> Option<CustomProtocol> {
        None
    }

    // this func must call after log success check_payload, otherwise maybe panic
    fn l7_protocol_enum(&self) -> L7ProtocolEnum {
        let proto = self.protocol();
        match proto {
            L7Protocol::ProtobufRPC => {
                L7ProtocolEnum::ProtobufRpc(self.protobuf_rpc_protocol().unwrap())
            }
            L7Protocol::Custom => L7ProtocolEnum::Custom(self.custom_protocol().unwrap()),
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

    fn reset(&mut self) {}

    // return perf data
    fn perf_stats(&mut self) -> Option<L7PerfStats>;
}

#[derive(Clone)]
pub struct EbpfParam {
    pub is_tls: bool,
    // 目前仅 http2 uprobe 有意义
    // ==========================
    // now only http2 uprobe uses
    pub is_req_end: bool,
    pub is_resp_end: bool,
    pub process_kname: String,
}

pub struct L7PerfCache {
    // lru cache previous rrt
    pub rrt_cache: LruCache<u128, (LogMessageType, u64)>,
    // LruCache<flow_id, count>
    pub timeout_cache: LruCache<u64, usize>,
}

impl L7PerfCache {
    pub fn new(cap: usize) -> Self {
        L7PerfCache {
            rrt_cache: LruCache::new(cap.try_into().unwrap()),
            timeout_cache: LruCache::new(cap.try_into().unwrap()),
        }
    }

    pub fn get_timeout_count(&mut self, flow_id: &u64) -> usize {
        *(self.timeout_cache.get(flow_id).unwrap_or(&0))
    }
}

pub struct ParseParam<'a> {
    // l3/l4 info
    pub l4_protocol: IpProtocol,
    pub ip_src: IpAddr,
    pub ip_dst: IpAddr,
    pub port_src: u16,
    pub port_dst: u16,
    pub flow_id: u64,

    // parse info
    pub direction: PacketDirection,
    pub ebpf_type: EbpfType,
    // ebpf_type 不为 EBPF_TYPE_NONE 会有值
    // ===================================
    // not None when payload from ebpf
    pub ebpf_param: Option<EbpfParam>,
    // calculate from cap_seq, req and correspond resp may have same packet seq, non ebpf always 0
    pub packet_seq: u64,
    pub time: u64, // micro second
    pub perf_only: bool,

    pub parse_config: Option<&'a LogParserConfig>,

    pub l7_perf_cache: Rc<RefCell<L7PerfCache>>,

    pub wasm_vm: Option<Rc<RefCell<WasmVm>>>,
}

// from packet, previous_log_info_cache, perf_only
impl From<(&MetaPacket<'_>, Rc<RefCell<L7PerfCache>>, bool)> for ParseParam<'_> {
    fn from(f: (&MetaPacket<'_>, Rc<RefCell<L7PerfCache>>, bool)) -> Self {
        let (packet, cache, perf_only) = f;

        let mut param = Self {
            l4_protocol: packet.lookup_key.proto,
            ip_src: packet.lookup_key.src_ip,
            ip_dst: packet.lookup_key.dst_ip,
            port_src: packet.lookup_key.src_port,
            port_dst: packet.lookup_key.dst_port,
            flow_id: packet.flow_id,

            direction: packet.lookup_key.direction,
            ebpf_type: packet.ebpf_type,
            packet_seq: packet.cap_seq,
            ebpf_param: None,
            time: packet.lookup_key.timestamp.as_micros() as u64,
            perf_only,
            parse_config: None,

            l7_perf_cache: cache,

            wasm_vm: None,
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
                process_kname: String::from_utf8_lossy(&packet.process_kname[..]).to_string(),
            });
        }

        param
    }
}

// from packet, previous_log_info_cache, perf_only, parse_config
impl<'a>
    From<(
        &MetaPacket<'_>,
        Rc<RefCell<L7PerfCache>>,
        bool,
        &'a LogParserConfig,
    )> for ParseParam<'a>
{
    fn from(
        f: (
            &MetaPacket<'_>,
            Rc<RefCell<L7PerfCache>>,
            bool,
            &'a LogParserConfig,
        ),
    ) -> Self {
        let mut p = Self::from((f.0, f.1, f.2));
        p.parse_config = Some(f.3);
        p
    }
}

impl ParseParam<'_> {
    pub fn is_tls(&self) -> bool {
        if let Some(ebpf_param) = self.ebpf_param.as_ref() {
            return ebpf_param.is_tls;
        }
        false
    }

    pub fn set_wasm_vm(&mut self, vm: Rc<RefCell<WasmVm>>) {
        self.wasm_vm = Some(vm);
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
