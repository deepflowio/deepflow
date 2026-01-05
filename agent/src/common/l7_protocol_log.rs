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

use std::cell::RefCell;
use std::fmt;
use std::net::IpAddr;
use std::rc::Rc;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

use enum_dispatch::enum_dispatch;
use log::debug;
use lru::LruCache;

use super::ebpf::EbpfType;
use super::flow::{L7PerfStats, PacketDirection};
use super::l7_protocol_info::L7ProtocolInfo;
use super::MetaPacket;

use crate::common::meta_packet::{IcmpData, ProtocolData};
use crate::config::config::Iso8583ParseConfig;
use crate::config::handler::LogParserConfig;
use crate::config::OracleConfig;
use crate::flow_generator::flow_map::FlowMapCounter;
use crate::flow_generator::protocol_logs::{
    fastcgi::FastCGILog,
    plugin::{custom_wrap::CustomWrapLog, get_custom_log_parser},
    sql::ObfuscateCache,
    AmqpLog, BrpcLog, DnsLog, DubboLog, HttpLog, KafkaLog, L7ResponseStatus, MemcachedLog,
    MongoDBLog, MqttLog, MysqlLog, NatsLog, OpenWireLog, PingLog, PostgresqlLog, PulsarLog,
    RedisLog, RocketmqLog, SofaRpcLog, TarsLog, ZmtpLog,
};

use crate::flow_generator::Result;
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::plugin::c_ffi::SoPluginFunc;
use crate::plugin::wasm::WasmVm;

use public::enums::IpProtocol;
use public::l7_protocol::{
    CustomProtocol, L7Protocol, L7ProtocolChecker, L7ProtocolEnum, LogMessageType,
};

macro_rules! count {
    () => (0);
    ($x:tt $($xs: tt)* ) => (1usize + count!($($xs)*));
}

macro_rules! impl_protocol_parser {
    (pub enum $name:ident { $($proto:ident($log_type:ty)),* $(,)? }) => {
        #[enum_dispatch(L7ProtocolParserInterface)]
        pub enum $name {
            Custom(CustomWrapLog),
            Http(HttpLog),
            $($proto($log_type)),*
        }

        impl L7ProtocolParser {
            pub fn as_str(&self) -> &'static str {
                match self {
                    Self::Http(p) => {
                        match p.protocol() {
                            L7Protocol::Http1 => return "HTTP",
                            L7Protocol::Http2 => return "HTTP2",
                            L7Protocol::Triple => return "Triple",
                            _ => unreachable!()
                        }
                    },
                    Self::Custom(_) => return "Custom",
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
                    "HTTP" => Ok(Self::Http(HttpLog::new_v1())),
                    "HTTP2" => Ok(Self::Http(HttpLog::new_v2(false))),
                    "gRPC" => Ok(Self::Http(HttpLog::new_v2(true))),
                    "Triple" => Ok(Self::Http(HttpLog::new_triple())),
                    "Custom"=>Ok(Self::Custom(Default::default())),
                    #[cfg(feature = "enterprise")]
                    "ISO-8583"=>Ok(Self::Iso8583(Default::default())),
                    #[cfg(feature = "enterprise")]
                    "WebSphereMQ"=>Ok(Self::WebSphereMq(Default::default())),
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
                    L7Protocol::Http1 => Some(L7ProtocolParser::Http(HttpLog::new_v1())),
                    L7Protocol::Http2 => Some(L7ProtocolParser::Http(HttpLog::new_v2(false))),
                    L7Protocol::Grpc => Some(L7ProtocolParser::Http(HttpLog::new_v2(true))),
                    L7Protocol::Triple => Some(L7ProtocolParser::Http(HttpLog::new_triple())),

                    // in check_payload, need to get the default Custom by L7Protocol.
                    // due to Custom not in macro, need to define explicit
                    L7Protocol::Custom => Some(L7ProtocolParser::Custom(CustomWrapLog::default())),
                    $(
                        L7Protocol::$proto => Some(L7ProtocolParser::$proto(Default::default())),
                    )+
                    _ => None,
                },
                L7ProtocolEnum::Custom(p) => Some(get_custom_log_parser(p)),
            }
        }

        pub fn get_all_protocol() -> [L7ProtocolParser; 3 + count!($($proto)*)] {
            [
                L7ProtocolParser::Custom(Default::default()),
                L7ProtocolParser::Http(HttpLog::new_v1()),
                L7ProtocolParser::Http(HttpLog::new_v2(false)),
                $(
                    L7ProtocolParser::$proto(Default::default()),
                )+
            ]
        }
    }
}

// 内部实现的协议
// log的具体结构和实现在 src/flow_generator/protocol_logs/** 下
// 注意枚举名大小写，因为会用于字符串解析
// 大结构体（128B以上）注意加Box，减少内存使用
// =========================================================
// the inner implement protocol source code in src/flow_generator/protocol_logs/**
// enum name will be used to parse strings so case matters
// large structs (>128B) should be boxed to reduce memory consumption
//
cfg_if::cfg_if! {
    if #[cfg(not(feature = "enterprise"))] {
        impl_protocol_parser! {
            pub enum L7ProtocolParser {
                // http have two version but one parser, can not place in macro param.
                // custom must in first so can not place in macro
                DNS(DnsLog),
                SofaRPC(SofaRpcLog),
                MySQL(MysqlLog),
                Kafka(KafkaLog),
                Redis(RedisLog),
                MongoDB(MongoDBLog),
                Memcached(MemcachedLog),
                PostgreSQL(PostgresqlLog),
                Dubbo(DubboLog),
                FastCGI(FastCGILog),
                Brpc(BrpcLog),
                Tars(TarsLog),
                MQTT(MqttLog),
                AMQP(AmqpLog),
                NATS(NatsLog),
                Pulsar(PulsarLog),
                ZMTP(ZmtpLog),
                RocketMQ(RocketmqLog),
                OpenWire(OpenWireLog),
                Ping(PingLog),
                // add protocol below
            }
        }
    } else {
        impl_protocol_parser! {
            pub enum L7ProtocolParser {
                // http have two version but one parser, can not place in macro param.
                // custom must in first so can not place in macro
                DNS(DnsLog),
                SofaRPC(SofaRpcLog),
                MySQL(MysqlLog),
                Kafka(KafkaLog),
                Redis(RedisLog),
                MongoDB(MongoDBLog),
                Memcached(MemcachedLog),
                PostgreSQL(PostgresqlLog),
                Dubbo(DubboLog),
                FastCGI(FastCGILog),
                Brpc(BrpcLog),
                Tars(TarsLog),
                Oracle(crate::flow_generator::protocol_logs::OracleLog),
                Iso8583(crate::flow_generator::protocol_logs::Iso8583Log),
                MQTT(MqttLog),
                AMQP(AmqpLog),
                NATS(NatsLog),
                Pulsar(PulsarLog),
                ZMTP(ZmtpLog),
                RocketMQ(RocketmqLog),
                WebSphereMq(crate::flow_generator::protocol_logs::WebSphereMqLog),
                OpenWire(OpenWireLog),
                TLS(crate::flow_generator::protocol_logs::TlsLog),
                SomeIp(crate::flow_generator::protocol_logs::SomeIpLog),
                Ping(PingLog),
                // add protocol below
            }
        }
    }
}

pub enum L7ParseResult {
    Single(L7ProtocolInfo),
    Multi(Vec<L7ProtocolInfo>),
    None,
}

impl L7ParseResult {
    pub fn is_none(&self) -> bool {
        match self {
            L7ParseResult::None => true,
            _ => false,
        }
    }

    pub fn unwrap_single(self) -> L7ProtocolInfo {
        match self {
            L7ParseResult::Single(s) => s,
            L7ParseResult::Multi(_) => panic!("parse result is multi but unwrap single"),
            L7ParseResult::None => panic!("parse result is none but unwrap single"),
        }
    }

    pub fn unwrap_multi(self) -> Vec<L7ProtocolInfo> {
        match self {
            L7ParseResult::Multi(m) => m,
            L7ParseResult::Single(_) => panic!("parse result is single but unwrap multi"),
            L7ParseResult::None => panic!("parse result is none but unwrap multi"),
        }
    }
}

#[enum_dispatch]
pub trait L7ProtocolParserInterface {
    // Determine whether the current payload belongs to this protocol, with the return values meaning as follows:
    // - None: Does not belong to this protocol
    // - LogMessageType::Request: It is a request that belongs to this protocol
    // - LogMessageType::Response: It is a response that belongs to this protocol
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> Option<LogMessageType>;
    // 协议解析
    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult>;
    // 返回协议号和协议名称，由于的bitmap使用u128，所以协议号不能超过128.
    // 其中 crates/public/src/l7_protocol.rs 里面的 pub const L7_PROTOCOL_xxx 是已实现的协议号.
    // ===========================================================================================
    // return protocol number and protocol string. because of bitmap use u128, so the max protocol number can not exceed 128
    // crates/public/src/l7_protocol.rs, pub const L7_PROTOCOL_xxx is the implemented protocol.
    fn protocol(&self) -> L7Protocol;

    // return inner proto of Custom, only when L7Protocol is Custom will not None
    fn custom_protocol(&self) -> Option<CustomProtocol> {
        None
    }

    // this func must call after log success check_payload, otherwise maybe panic
    fn l7_protocol_enum(&self) -> L7ProtocolEnum {
        let proto = self.protocol();
        match proto {
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

    // l4即不是udp也不是tcp，用于快速过滤协议
    // ==============================
    // L4 is neither UDP nor TCP and is used to quickly filter protocols
    fn parsable_on_other(&self) -> bool {
        false
    }

    // is parse default? use for config init.
    fn parse_default(&self) -> bool {
        true
    }

    fn reset(&mut self) {}

    // return perf data
    fn perf_stats(&mut self) -> Option<L7PerfStats>;

    fn set_obfuscate_cache(&mut self, _: Option<ObfuscateCache>) {}
}

#[derive(Clone, Debug)]
pub struct EbpfParam<'a> {
    pub is_tls: bool,
    // 目前仅 http2 uprobe 有意义
    // ==========================
    // now only http2 uprobe uses
    pub is_req_end: bool,
    pub is_resp_end: bool,
    pub process_kname: &'a str,
}

#[derive(Default)]
pub struct MultiMergeInfo {
    pub req_end: bool,
    pub resp_end: bool,
    pub merged: bool,
}

#[derive(Default)]
pub struct LogCache {
    pub msg_type: LogMessageType,
    pub time: u64,
    pub resp_status: L7ResponseStatus,

    pub on_blacklist: bool,

    // set merged to true when req and resp merge once
    pub multi_merge_info: Option<MultiMergeInfo>,
    // used to update response endpoint from request
    // leave it to None when not needed to reduce memory allocation (not calling `load_endpoint_from_cache`)
    pub endpoint: Option<String>,
}

impl LogCache {
    pub fn is_request_of(&self, other: &Self) -> bool {
        self.msg_type == LogMessageType::Request
            && other.msg_type == LogMessageType::Response
            && self.time < other.time
    }

    pub fn is_response_of(&self, other: &Self) -> bool {
        self.msg_type == LogMessageType::Response
            && other.msg_type == LogMessageType::Request
            && self.time > other.time
    }
}

impl From<&LogCache> for L7PerfStats {
    fn from(cache: &LogCache) -> Self {
        let (request_count, response_count) = match cache.multi_merge_info.as_ref() {
            Some(info) => (
                if info.req_end { 1 } else { 0 },
                if info.resp_end { 1 } else { 0 },
            ),
            None => match cache.msg_type {
                LogMessageType::Request => (1, 0),
                LogMessageType::Response => (0, 1),
                _ => (0, 0),
            },
        };
        let (err_client_count, err_server_count) = match cache.resp_status {
            L7ResponseStatus::ClientError => (1, 0),
            L7ResponseStatus::ServerError => (0, 1),
            _ => (0, 0),
        };
        L7PerfStats {
            request_count,
            response_count,
            err_client_count,
            err_server_count,
            ..Default::default()
        }
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct LogCacheKey(pub u128);

impl LogCacheKey {
    pub fn is_reversed(&self) -> bool {
        self.0 & (1 << 63) == 1
    }

    pub fn new(param: &ParseParam, session_id: Option<u32>, is_reversed: bool) -> Self {
        /*
            if session id is some: flow id 64bit | is_reversed 1 bit | 0 31bit | session id 32bit
            if session id is none: flow id 64bit | is_reversed 1 bit | packet_seq 63bit
        */
        let key = match session_id {
            Some(sid) => {
                if is_reversed {
                    ((param.flow_id as u128) << 64) | 1 << 63 | sid as u128
                } else {
                    ((param.flow_id as u128) << 64) | sid as u128
                }
            }
            None => {
                ((param.flow_id as u128) << 64)
                    | (if param.ebpf_type != EbpfType::None {
                        // NOTE:
                        //   In the request-log session aggregation process, for eBPF data, we require that requests and
                        // responses have consecutive cap_seq to ensure the correctness of session aggregation. However,
                        // when SR (Segmentation-Reassembly) is enabled, we combine multiple eBPF socket event events
                        // before parsing the protocol. Therefore, in order to ensure that session aggregation can still
                        // be performed correctly, we need to retain the cap_seq of the last request and the cap_seq of
                        // the first response, so that the cap_seq of the request and response can still be consecutive.
                        let seq = if param.direction == PacketDirection::ClientToServer {
                            param.packet_end_seq + 1
                        } else {
                            param.packet_start_seq
                        };

                        if is_reversed {
                            1 << 63 | seq & 0x7fffffff_ffffffff
                        } else {
                            seq & 0x7fffffff_ffffffff
                        }
                    } else {
                        0
                    }) as u128
            }
        };

        Self(key)
    }

    fn flow_id(&self) -> u64 {
        (self.0 >> 64) as u64
    }
}

#[derive(Clone)]
pub struct L7PerfCacheCounter {
    pub rrt_cache_len: Arc<AtomicU64>,
    pub timeout_cache_len: Arc<AtomicU64>,
}

pub struct RrtCache {
    // lru cache previous rrt
    logs: LruCache<LogCacheKey, LogCache>,
    // LruCache<flow_id, LruCache<LogCacheKey, bool>>
    flows: LruCache<u64, LruCache<LogCacheKey, ()>>,

    cache_len: Arc<AtomicU64>,

    // time in microseconds
    last_log_time: u64,
}

impl RrtCache {
    // 60 seconds
    const LOG_INTERVAL: u64 = 60_000_000;

    // When the number of concurrent transactions exceeds this value, the RRT calculation error will occur.
    const MAX_RRT_CACHE_PER_FLOW: usize = 16;

    pub fn get(&mut self, key: &LogCacheKey) -> Option<&LogCache> {
        self.logs.get(key)
    }

    pub fn get_mut(&mut self, key: &LogCacheKey) -> Option<&mut LogCache> {
        self.logs.get_mut(key)
    }

    pub fn put(&mut self, key: LogCacheKey, value: LogCache) -> Option<LogCache> {
        let now = value.time;
        if self.logs.len() >= usize::from(self.logs.cap())
            && self.last_log_time + Self::LOG_INTERVAL < now
        {
            self.last_log_time = now;
            debug!("The capacity({}) of the rrt table will be exceeded. please adjust the configuration", self.logs.cap());
        }

        let keys = self.flows.get_or_insert_mut(key.flow_id(), || {
            LruCache::new(Self::MAX_RRT_CACHE_PER_FLOW.try_into().unwrap())
        });
        match keys.push(key, ()) {
            // Another cache entry is removed due to the lru's capacity.
            Some((old, _)) if key != old => {
                self.logs.pop(&old);
                if self.last_log_time + Self::LOG_INTERVAL < now {
                    self.last_log_time = now;
                    debug!(
                        "LogCache removed from flow id {} cache because capacity({}) exceeded",
                        old.flow_id(),
                        Self::MAX_RRT_CACHE_PER_FLOW,
                    );
                }
            }
            _ => (),
        }

        let ret = self.logs.put(key, value);
        self.cache_len
            .store(self.logs.len() as u64, Ordering::Relaxed);
        ret
    }

    pub fn pop(&mut self, key: &LogCacheKey) -> Option<LogCache> {
        if let Some(cache) = self.flows.get_mut(&key.flow_id()) {
            cache.pop(key);

            if cache.is_empty() {
                self.flows.pop(&key.flow_id());
            }
        }
        let ret = self.logs.pop(key);
        self.cache_len
            .store(self.logs.len() as u64, Ordering::Relaxed);
        ret
    }

    pub fn collect_flow_perf_stats(&mut self, flow_id: u64) -> Option<(L7PerfStats, L7PerfStats)> {
        let Some(keys) = self.flows.pop(&flow_id) else {
            return None;
        };

        let mut forward = L7PerfStats::default();
        let mut backward = L7PerfStats::default();
        for (key, _) in keys {
            if let Some(cache) = self.logs.pop(&key) {
                if key.is_reversed() {
                    backward.sequential_merge(&L7PerfStats::from(&cache));
                } else {
                    forward.sequential_merge(&L7PerfStats::from(&cache));
                }
            }
        }

        if forward == L7PerfStats::default() && backward == L7PerfStats::default() {
            None
        } else {
            Some((forward, backward))
        }
    }

    pub fn remove_flow(&mut self, flow_id: u64) {
        if let Some(keys) = self.flows.pop(&flow_id) {
            for (key, _) in keys {
                self.logs.pop(&key);
            }
        }
        self.cache_len
            .store(self.logs.len() as u64, Ordering::Relaxed);
    }
}

#[derive(Default)]
pub struct TimeoutCacheEntry {
    pub in_cache: [u64; 2],
    pub timeout: [u64; 2],
}

pub struct TimeoutCache {
    flows: LruCache<u64, TimeoutCacheEntry>,
    cache_len: Arc<AtomicU64>,
}

impl TimeoutCache {
    pub fn pop_timeout_count(&mut self, flow_id: u64, flow_end: bool, is_reversed: bool) -> u64 {
        let entry = self.get_or_insert_mut(flow_id);
        let index = if is_reversed { 1 } else { 0 };
        if flow_end {
            let v = entry.in_cache[index] + entry.timeout[index];
            self.flows.pop(&flow_id);
            self.cache_len
                .store(self.flows.len() as u64, Ordering::Relaxed);

            v
        } else {
            let v = entry.timeout[index];
            entry.timeout[index] = 0;

            v
        }
    }

    pub fn get_or_insert_mut(&mut self, flow_id: u64) -> &mut TimeoutCacheEntry {
        self.flows
            .get_or_insert_mut(flow_id, || TimeoutCacheEntry::default());
        self.cache_len
            .store(self.flows.len() as u64, Ordering::Relaxed);
        self.flows.get_mut(&flow_id).unwrap()
    }

    pub fn remove_flow(&mut self, flow_id: u64) {
        self.flows.pop(&flow_id);
        self.cache_len
            .store(self.flows.len() as u64, Ordering::Relaxed);
    }
}

pub struct L7PerfCache {
    pub rrt_cache: RrtCache,
    pub timeout_cache: TimeoutCache,
}

impl L7PerfCache {
    pub fn new(cap: usize) -> Self {
        L7PerfCache {
            rrt_cache: RrtCache {
                logs: LruCache::new(cap.try_into().unwrap()),
                flows: LruCache::new(cap.try_into().unwrap()),
                cache_len: Arc::new(AtomicU64::new(0)),
                last_log_time: 0,
            },
            timeout_cache: TimeoutCache {
                flows: LruCache::new(cap.try_into().unwrap()),
                cache_len: Arc::new(AtomicU64::new(0)),
            },
        }
    }

    pub fn counters(&self) -> L7PerfCacheCounter {
        L7PerfCacheCounter {
            rrt_cache_len: self.rrt_cache.cache_len.clone(),
            timeout_cache_len: self.timeout_cache.cache_len.clone(),
        }
    }

    pub fn remove_flow(&mut self, flow_id: u64) {
        self.rrt_cache.remove_flow(flow_id);
        self.timeout_cache.remove_flow(flow_id);
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
    pub icmp_data: Option<&'a IcmpData>,

    // parse info
    pub direction: PacketDirection,
    pub ebpf_type: EbpfType,
    // ebpf_type 不为 EBPF_TYPE_NONE 会有值
    // ===================================
    // not None when payload from ebpf
    pub ebpf_param: Option<EbpfParam<'a>>,
    // calculate from cap_seq, req and correspond resp may have same packet seq, non ebpf always 0
    pub packet_start_seq: u64,
    pub packet_end_seq: u64,
    pub time: u64, // micro second
    pub parse_perf: bool,
    pub parse_log: bool,

    pub parse_config: Option<&'a LogParserConfig>,

    pub l7_perf_cache: Rc<RefCell<L7PerfCache>>,

    // plugins
    pub wasm_vm: Rc<RefCell<Option<WasmVm>>>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub so_func: Rc<RefCell<Option<Vec<SoPluginFunc>>>>,

    pub stats_counter: Option<Arc<FlowMapCounter>>,

    // rrt cal timeout
    pub rrt_timeout: usize, // micro second

    // the config of `l7_log_packet_size`, must set in parse_payload and check_payload
    pub buf_size: u16,
    pub captured_byte: u16,

    pub oracle_parse_conf: OracleConfig,
    pub iso8583_parse_conf: Iso8583ParseConfig,
}

impl<'a> fmt::Debug for ParseParam<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ds = f.debug_struct("ParseParam");
        ds.field("l4_protocol", &self.l4_protocol)
            .field("ip_src", &self.ip_src)
            .field("ip_dst", &self.ip_dst)
            .field("port_src", &self.port_src)
            .field("port_dst", &self.port_dst)
            .field("flow_id", &self.flow_id)
            .field("icmp_data", &self.icmp_data)
            .field("direction", &self.direction)
            .field("ebpf_type", &self.ebpf_type)
            .field("ebpf_param", &self.ebpf_param)
            .field("packet_start_seq", &self.packet_start_seq)
            .field("packet_end_seq", &self.packet_end_seq)
            .field("time", &self.time)
            .field("parse_perf", &self.parse_perf)
            .field("parse_log", &self.parse_log)
            .field("parse_config", &self.parse_config)
            .field("wasm_vm", &self.wasm_vm.borrow().is_some());
        #[cfg(any(target_os = "linux", target_os = "android"))]
        ds.field("so_func", &self.so_func.borrow().is_some());
        ds.field("rrt_timeout", &self.rrt_timeout)
            .field("buf_size", &self.buf_size)
            .field("captured_byte", &self.captured_byte)
            .field("oracle_parse_conf", &self.oracle_parse_conf)
            .field("iso8583_parse_conf", &self.iso8583_parse_conf)
            .finish()
    }
}

impl<'a> ParseParam<'a> {
    pub fn is_from_ebpf(&self) -> bool {
        self.ebpf_type != EbpfType::None
    }

    pub fn new(
        packet: &'a MetaPacket<'a>,
        cache: Rc<RefCell<L7PerfCache>>,
        wasm_vm: Rc<RefCell<Option<WasmVm>>>,
        #[cfg(any(target_os = "linux", target_os = "android"))] so_func: Rc<
            RefCell<Option<Vec<SoPluginFunc>>>,
        >,
        parse_perf: bool,
        parse_log: bool,
    ) -> Self {
        let mut param = Self {
            l4_protocol: packet.lookup_key.proto,
            ip_src: packet.lookup_key.src_ip,
            ip_dst: packet.lookup_key.dst_ip,
            port_src: packet.lookup_key.src_port,
            port_dst: packet.lookup_key.dst_port,
            icmp_data: if let ProtocolData::IcmpData(icmp_data) = &packet.protocol_data {
                Some(icmp_data)
            } else {
                None
            },
            flow_id: packet.flow_id,

            direction: packet.lookup_key.direction,
            ebpf_type: packet.ebpf_type,
            packet_start_seq: packet.cap_start_seq,
            packet_end_seq: packet.cap_end_seq,
            ebpf_param: None,
            time: packet.lookup_key.timestamp.as_micros() as u64,
            parse_perf,
            parse_log,
            parse_config: None,

            l7_perf_cache: cache,

            wasm_vm,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            so_func,

            stats_counter: None,

            // the timeout will overwrite by set_rrt_timeout(), 10s set in here only use for test.
            rrt_timeout: Duration::from_secs(10).as_micros() as usize,

            buf_size: 0,
            captured_byte: 0,

            oracle_parse_conf: OracleConfig::default(),
            iso8583_parse_conf: Iso8583ParseConfig::default(),
        };
        if packet.ebpf_type != EbpfType::None {
            param.ebpf_param = Some(EbpfParam {
                is_tls: packet.is_tls(),
                is_req_end: packet.is_request_end,
                is_resp_end: packet.is_response_end,
                #[cfg(any(target_os = "linux", target_os = "android"))]
                process_kname: std::str::from_utf8(&packet.process_kname[..]).unwrap_or(""),
                #[cfg(target_os = "windows")]
                process_kname: "",
            });
        }

        param
    }
}

impl<'a> ParseParam<'a> {
    pub fn is_tls(&self) -> bool {
        if let Some(ebpf_param) = self.ebpf_param.as_ref() {
            return ebpf_param.is_tls;
        }
        false
    }

    pub fn set_counter(&mut self, stat: Arc<FlowMapCounter>) {
        self.stats_counter = Some(stat);
    }

    pub fn set_buf_size(&mut self, buf_size: usize) {
        self.buf_size = buf_size as u16;
    }

    pub fn set_captured_byte(&mut self, captured_byte: usize) {
        self.captured_byte = captured_byte as u16;
    }

    pub fn set_rrt_timeout(&mut self, t: usize) {
        self.rrt_timeout = t;
    }

    pub fn set_log_parser_config(&mut self, conf: &'a LogParserConfig) {
        self.parse_config = Some(conf);
    }

    pub fn set_oracle_conf(&mut self, conf: OracleConfig) {
        self.oracle_parse_conf = conf;
    }

    pub fn set_iso8583_conf(&mut self, conf: &Iso8583ParseConfig) {
        self.iso8583_parse_conf = conf.clone();
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
                IpProtocol::TCP if i.parsable_on_tcp() => {
                    bitmap.set_enabled(i.protocol());
                }
                IpProtocol::UDP if i.parsable_on_udp() => {
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
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct L7ProtocolBitmap(u128);

impl L7ProtocolBitmap {
    pub fn set_enabled(&mut self, p: L7Protocol) {
        self.0 |= 1 << (p as u128);
    }

    pub fn set_disabled(&mut self, p: L7Protocol) {
        self.0 &= !(1 << (p as u128));
    }
}

impl L7ProtocolChecker for L7ProtocolBitmap {
    fn is_disabled(&self, p: L7Protocol) -> bool {
        self.0 & (1 << (p as u128)) == 0
    }

    fn is_enabled(&self, p: L7Protocol) -> bool {
        !self.is_disabled(p)
    }
}

impl From<&[String]> for L7ProtocolBitmap {
    fn from(vs: &[String]) -> Self {
        let mut bitmap = L7ProtocolBitmap(0);
        for v in vs.iter() {
            if let Ok(p) = L7ProtocolParser::try_from(v.as_str()) {
                bitmap.set_enabled(p.protocol());
            }
        }
        bitmap
    }
}

impl fmt::Debug for L7ProtocolBitmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut p = vec![];
        for i in get_all_protocol() {
            if self.is_enabled(i.protocol()) {
                p.push(i.protocol());
            }
        }
        f.write_str(format!("{:#?}", p).as_str())
    }
}
