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

pub(crate) mod icmp;
mod stats;
pub mod tcp;
pub(crate) mod udp;

use std::cell::{RefCell, RefMut};
use std::collections::HashMap;
use std::net::IpAddr;
use std::rc::Rc;
use std::slice;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use enum_dispatch::enum_dispatch;
use public::bitmap::Bitmap;
use public::enums::IpProtocol;
use public::l7_protocol::L7ProtocolEnum;
use tcp_reassemble::payload::{Payload, PayloadReader, TcpPayload};
use tcp_reassemble::tcp_reassemble::{TcpFlowReassembleBuf, DIRECTION_0, DIRECTION_1};

use super::{
    app_table::AppTable,
    error::{Error, Result},
    flow_map::FlowMapCounter,
    pool::MemoryPool,
    protocol_logs::AppProtoHead,
};

use crate::common::ebpf::EbpfType;
use crate::common::l7_protocol_log::{CheckResult, L7PerfCache, EbpfParam};
use crate::common::lookup_key::LookupKey;
use crate::common::meta_packet::ProtocolData;
use crate::common::{
    flow::{Flow, L7PerfStats},
    l7_protocol_log::L7ParseResult,
};
use crate::config::OracleParseConfig;
use crate::plugin::wasm::WasmVm;
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::plugin::{c_ffi::SoPluginFunc, shared_obj::SoPluginCounterMap};
use crate::rpc::get_timestamp;
use crate::{
    common::{
        flow::{FlowPerfStats, L4Protocol, L7Protocol, PacketDirection, SignalSource},
        l7_protocol_log::{
            get_all_protocol, get_parser, L7ProtocolBitmap, L7ProtocolParser,
            L7ProtocolParserInterface, ParseParam,
        },
        meta_packet::MetaPacket,
        Timestamp,
    },
    config::{handler::LogParserConfig, FlowConfig},
};

use {icmp::IcmpPerf, tcp::TcpPerf, udp::UdpPerf};

pub use stats::FlowPerfCounter;
pub use stats::PerfStats;

const ART_MAX: Timestamp = Timestamp::from_secs(30);

pub trait L4FlowPerf {
    fn parse(&mut self, packet: &MetaPacket, direction: bool) -> Result<()>;
    fn data_updated(&self) -> bool;
    fn copy_and_reset_data(&mut self, flow_reversed: bool) -> FlowPerfStats;
}

#[enum_dispatch]
pub trait L7FlowPerf {
    fn parse(
        &mut self,
        config: Option<&LogParserConfig>,
        packet: &MetaPacket,
        flow_id: u64,
    ) -> Result<()>;
    fn data_updated(&self) -> bool;
    fn copy_and_reset_data(&mut self, l7_timeout_count: u32) -> FlowPerfStats;
    fn app_proto_head(&mut self) -> Option<(AppProtoHead, u16)>;
}

pub enum L4FlowPerfTable {
    Tcp(Box<TcpPerf>),
    Udp(UdpPerf),
    Icmp(IcmpPerf),
}

impl L4FlowPerf for L4FlowPerfTable {
    fn parse(&mut self, packet: &MetaPacket, direction: bool) -> Result<()> {
        match self {
            Self::Tcp(p) => p.parse(packet, direction),
            Self::Udp(p) => p.parse(packet, direction),
            Self::Icmp(p) => p.parse(packet, direction),
        }
    }

    fn data_updated(&self) -> bool {
        match self {
            Self::Tcp(p) => p.data_updated(),
            Self::Udp(p) => p.data_updated(),
            Self::Icmp(p) => p.data_updated(),
        }
    }

    fn copy_and_reset_data(&mut self, flow_reversed: bool) -> FlowPerfStats {
        match self {
            Self::Tcp(p) => p.copy_and_reset_data(flow_reversed),
            Self::Udp(p) => p.copy_and_reset_data(flow_reversed),
            Self::Icmp(p) => p.copy_and_reset_data(flow_reversed),
        }
    }
}

pub type L7ProtocolTuple = (L7Protocol, Option<Bitmap>);

// None in Vec means all ports
pub struct L7ProtocolChecker {
    tcp: Vec<L7ProtocolTuple>,
    udp: Vec<L7ProtocolTuple>,
}

impl L7ProtocolChecker {
    pub fn new(
        protocol_bitmap: &L7ProtocolBitmap,
        port_bitmap: &HashMap<L7Protocol, Bitmap>,
    ) -> Self {
        let mut tcp = vec![];
        let mut udp = vec![];
        for parser in get_all_protocol() {
            let protocol = parser.protocol();
            if !protocol_bitmap.is_enabled(protocol) {
                continue;
            }
            if parser.parsable_on_tcp() {
                tcp.push((protocol, port_bitmap.get(&protocol).map(|m| m.clone())));
            }
            if parser.parsable_on_udp() {
                udp.push((protocol, port_bitmap.get(&protocol).map(|m| m.clone())));
            }
        }

        L7ProtocolChecker { tcp, udp }
    }

    pub fn possible_protocols(
        &self,
        l4_protocol: L4Protocol,
        port: u16,
    ) -> L7ProtocolCheckerIterator {
        L7ProtocolCheckerIterator {
            iter: match l4_protocol {
                L4Protocol::Tcp => self.tcp.iter(),
                L4Protocol::Udp => self.udp.iter(),
                _ => [].iter(),
            },
            port,
        }
    }
}

pub struct L7ProtocolCheckerIterator<'a> {
    iter: slice::Iter<'a, L7ProtocolTuple>,
    port: u16,
}

impl<'a> Iterator for L7ProtocolCheckerIterator<'a> {
    type Item = &'a L7Protocol;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((proto, bitmap)) = self.iter.next() {
            match bitmap {
                // if bitmap is not None and does not has port in it, check next protocol
                Some(b) if !b.get(self.port as usize).unwrap_or_default() => continue,
                _ => return Some(proto),
            }
        }
        None
    }
}

pub struct FlowLogLookupKey {
    pub ip: IpAddr,
    pub port: u16,
    pub l2_end_0: bool,
    pub direction: PacketDirection,
}

pub struct FlowLog {
    l4: Option<Box<L4FlowPerfTable>>,
    l7_protocol_log_parser: Option<Box<L7ProtocolParser>>,
    // use for cache previous log info, use for calculate rrt
    perf_cache: Rc<RefCell<L7PerfCache>>,
    l7_protocol_enum: L7ProtocolEnum,

    // Only for eBPF data, the server_port will be set in l7_check() method, it checks the first
    // request packet's payload, and then set self.server_port = packet.lookup_key.dst_port,
    // we use the server_port to judge packet's direction.
    pub server_port: u16,

    is_success: bool,
    is_skip: bool,

    wasm_vm: Option<Rc<RefCell<WasmVm>>>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    so_plugin: Option<Rc<Vec<SoPluginFunc>>>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    so_plugin_counter: Option<Rc<SoPluginCounterMap>>,
    stats_counter: Arc<FlowMapCounter>,
    rrt_timeout: usize,

    // the timestamp sec of accumulate fail exceed l7_protocol_inference_max_fail_count
    last_fail: Option<u64>,
    l7_protocol_inference_ttl: u64,

    ntp_diff: Arc<AtomicI64>,

    tcp_reassemble: Option<Rc<RefCell<TcpFlowReassembleBuf>>>,

    // reassemble direction key, (ip, port, l2_end_0)
    lookup_key_0: FlowLogLookupKey,
    lookup_key_1: FlowLogLookupKey,

    flow_id: u64,

    ebpf_type: EbpfType,

    ebpf_param:EbpfParam,
}

impl FlowLog {
    const PROTOCOL_CHECK_LIMIT: usize = 5;

    // if flow parse fail exceed l7_protocol_inference_max_fail_count and time exceed l7_protocol_inference_ttl,
    // recover the flow check and parse
    fn check_fail_recover(&mut self) {
        if self.is_skip {
            let now = get_timestamp(self.ntp_diff.load(Ordering::Relaxed));
            if now.as_secs() > self.last_fail.unwrap() + self.l7_protocol_inference_ttl {
                self.last_fail = None;
                self.is_skip = false;
            }
        }
    }

    // 重组可能要解析多次数据,只要成功一次就认为成功
    fn l7_parse_log(
        &mut self,
        lookup_key: &mut LookupKey,
        app_table: &mut AppTable,
        parse_param: &mut ParseParam,
        local_epc: i32,
        remote_epc: i32,
        payload_reader: &mut PayloadReader,
    ) -> Result<L7ParseResult> {
        let parser = self.l7_protocol_log_parser.as_mut().unwrap();
        let mut latest_err = None;
        let mut logs = None;
        while let Some(payload) = payload_reader.get() {
            parse_param.update_by_tcp_payload(&payload);
            match parser.parse_payload(payload.payload, parse_param) {
                Ok(res) => {
                    if logs.is_none() {
                        let _ = logs.insert(res);
                    } else {
                        let l = logs.as_mut().unwrap();
                        l.extend(res);
                    }
                    payload_reader.move_next();
                    payload_reader.skip_to_read_end();
                    continue;
                }
                Err(e) => match e {
                    Error::NeedMoreData => {
                        latest_err = Some(Err(e));
                        payload_reader.move_next();
                        continue;
                    }
                    _ => {
                        latest_err = Some(Err(e));
                        payload_reader.move_next();
                        payload_reader.skip_to_read_end();
                        continue;
                    }
                },
            }
        }

        let ret = if let Some(l) = logs {
            Ok(l)
        } else {
            latest_err.unwrap()
        };

        let mut cache_proto = |proto: L7ProtocolEnum| match parse_param.ebpf_type {
            EbpfType::None => {
                app_table.set_protocol(parse_param.endpoint.clone(), &*lookup_key, proto)
            }
            _ => app_table.set_protocol_from_ebpf(
                &*lookup_key,
                parse_param
                    .ebpf_param
                    .as_ref()
                    .map_or(&[], |p| p.process_kname.as_bytes()),
                parse_param.ebpf_param.as_ref().map_or(0, |p| p.pid),
                parse_param.endpoint.clone(),
                proto,
                local_epc,
                remote_epc,
            ),
        };

        let cached = if ret.is_ok() && self.l7_protocol_enum != parser.l7_protocol_enum() {
            // due to http2 may be upgrade grpc, need to reset the flow node protocol
            self.l7_protocol_enum = parser.l7_protocol_enum();
            cache_proto(self.l7_protocol_enum.clone());
            true
        } else {
            false
        };
        parser.reset();

        if !self.is_success {
            self.is_success = ret.is_ok();
            if self.is_success && !cached {
                cache_proto(self.l7_protocol_enum.clone());
            }
            if !self.is_success {
                self.is_skip = cache_proto(L7ProtocolEnum::default());
                if self.is_skip {
                    self.last_fail = Some(lookup_key.timestamp.as_secs())
                }
            }
        }
        ret
    }

    fn l7_check(
        &mut self,
        param: &mut ParseParam,
        lookup_key: &mut LookupKey,
        app_table: &mut AppTable,
        local_epc: i32,
        remote_epc: i32,
        checker: &L7ProtocolChecker,
        payload_reader: &mut PayloadReader,
    ) -> Result<L7ParseResult> {
        /*
            | f1 | f2 | f3 |...
            假设刚开始只有 f1
            case 1. 全体失败, head 移动最少连续解析帧(例如协议1 peek 了2帧,协议2 peek 了 3 帧,这里就直接跳过2帧, 这里假设都是1帧就失败), 这里就变成 | f2 | f3 |
            case 2. 遇到 need more frame:
                一直 peek 直到失败

            一直到全部解析失败
        */
        while let Some(payload) = payload_reader.get() {
            param.update_by_tcp_payload(&payload);
            'check: for protocol in checker.possible_protocols(
                lookup_key.proto.into(),
                match lookup_key.direction {
                    PacketDirection::ClientToServer => lookup_key.dst_port,
                    PacketDirection::ServerToClient => lookup_key.src_port,
                },
            ) {
                let Some(mut parser) = get_parser(L7ProtocolEnum::L7Protocol(*protocol)) else {
                    continue;
                };

                match parser.check_payload(payload.payload, &param) {
                    CheckResult::Ok => {
                        return self.on_check_success(
                            parser,
                            lookup_key,
                            param,
                            app_table,
                            local_epc,
                            remote_epc,
                            payload_reader,
                        );
                    }
                    // TODO 这里有相同数据重复 check 的情况,因为只要返回 NeedMoreData 就会等待后续数据,再次 check 实际上只是数据变长但是还是会失败.
                    CheckResult::Fail => {
                        continue;
                    }
                    CheckResult::NeedMoreData => {
                        let mut idx = 1;
                        while let Some(payload) = payload_reader.peek(idx) {
                            param.update_by_tcp_payload(&payload);
                            match parser.check_payload(payload.payload, &param) {
                                CheckResult::Ok => {
                                    return self.on_check_success(
                                        parser,
                                        lookup_key,
                                        param,
                                        app_table,
                                        local_epc,
                                        remote_epc,
                                        payload_reader,
                                    );
                                }

                                CheckResult::Fail => break 'check,

                                CheckResult::NeedMoreData => idx += 1,
                            }
                        }
                        return Err(Error::NeedMoreData);
                    }
                }
            }

            // 全体 fail, 移动一帧
            payload_reader.move_next();
            payload_reader.skip_head();
        }

        if param.is_from_ebpf() {
            app_table.set_protocol_from_ebpf(
                &*lookup_key,
                param.ebpf_param.as_ref().unwrap().process_kname.as_bytes(),
                param.ebpf_param.as_ref().unwrap().pid,
                param.endpoint.clone(),
                L7ProtocolEnum::default(),
                local_epc,
                remote_epc,
            );
        } else {
            app_table.set_protocol(
                param.endpoint.clone(),
                &*&lookup_key,
                L7ProtocolEnum::default(),
            );
        }

        if self.is_skip {
            self.last_fail = Some(lookup_key.timestamp.as_secs())
        }

        return Err(Error::L7ProtocolUnknown);
    }

    fn on_check_success(
        &mut self,
        parser: L7ProtocolParser,
        lookup_key: &mut LookupKey,
        param: &mut ParseParam,
        app_table: &mut AppTable,
        local_epc: i32,
        remote_epc: i32,
        payload_reader: &mut PayloadReader,
    ) -> Result<L7ParseResult> {
        self.l7_protocol_enum = parser.l7_protocol_enum();
        // redis can not determine dirction by RESP protocol when pakcet is from ebpf, special treatment
        if self.l7_protocol_enum.get_l7_protocol() == L7Protocol::Redis {
            let host = lookup_key.get_redis_server_addr(
                param.is_from_ebpf(),
                param
                    .ebpf_param
                    .as_ref()
                    .map_or(&[], |e| e.process_kname.as_bytes()),
                param.direction,
            );
            let server_ip = host.0;
            self.server_port = host.1;
            if lookup_key.dst_port != self.server_port || lookup_key.dst_ip != server_ip {
                lookup_key.direction = PacketDirection::ServerToClient;
            } else {
                lookup_key.direction = PacketDirection::ClientToServer;
            }
        } else {
            self.server_port = lookup_key.dst_port;
            lookup_key.direction = PacketDirection::ClientToServer;
        }
        param.direction = lookup_key.direction;

        self.l7_protocol_log_parser = Some(Box::new(parser));
        self.l7_parse_log(
            lookup_key,
            app_table,
            param,
            local_epc,
            remote_epc,
            payload_reader,
        )
    }

    fn update_lookup_key(&mut self, meta_packet: &MetaPacket) {
        match meta_packet
            .lookup_key
            .get_reassemble_direction(&self.lookup_key_0)
        {
            DIRECTION_0 => {
                self.lookup_key_0.l2_end_0 = meta_packet.lookup_key.l2_end_0;
                self.lookup_key_0.direction = meta_packet.lookup_key.direction;
            }
            DIRECTION_1 => {
                self.lookup_key_1.l2_end_0 = meta_packet.lookup_key.l2_end_0;
                self.lookup_key_1.direction = meta_packet.lookup_key.direction;
            }
            _ => unreachable!(),
        }
    }

    // return (result, drain_frame)
    fn l7_parse(
        &mut self,
        mut payload_reader: PayloadReader,
        param: &mut ParseParam,
        lookup_key: &mut LookupKey,
        app_table: &mut AppTable,
        local_epc: i32,
        remote_epc: i32,
        checker: &L7ProtocolChecker,
    ) -> (Result<L7ParseResult>, usize) {
        if self.l7_protocol_log_parser.is_some() {
            return (
                self.l7_parse_log(
                    lookup_key,
                    app_table,
                    param,
                    local_epc,
                    remote_epc,
                    &mut payload_reader,
                ),
                payload_reader.get_skip_frame_len().unwrap_or_default(),
            );
        }

        (
            self.l7_check(
                param,
                lookup_key,
                app_table,
                local_epc,
                remote_epc,
                checker,
                &mut payload_reader,
            ),
            payload_reader.get_skip_frame_len().unwrap_or_default(),
        )
    }

    fn get_payload_reader<'a>(
        tcp_reassemble: &'a mut RefMut<'_, TcpFlowReassembleBuf>,
        meta_packet: &'a MetaPacket,
        log_size: usize,
        param: &mut ParseParam,
        lk_0: &FlowLogLookupKey,
    ) -> Option<PayloadReader<'a>> {
        let cut_payload = meta_packet.get_l4_payload_cut(log_size)?;
        let ProtocolData::TcpHeader(t) = &meta_packet.protocol_data else {
            unreachable!()
        };

        let direction = meta_packet.lookup_key.get_reassemble_direction(lk_0);
        if tcp_reassemble.buf_is_empty(direction) {
            // 这里 的 payload in buffer 是 false, 表示然可以重组, 但是当 cut_payload.len() == log_size 的时候, 丢进重组实际上并不会重组, 只会更新 base seq
            param.set_payload_in_buffer(false);
            return Some(PayloadReader::new(Payload::MetaPacket(
                // when cut_payload.len() == log_size can not reassemble
                TcpPayload {
                    payload: cut_payload,
                    seq: t.seq,
                    cap_seq:meta_packet.cap_seq,
                    can_reassemble: cut_payload.len() != log_size,
                    timestamp: meta_packet.lookup_key.timestamp.as_micros(),
                },
            )));
        } else {
            let ProtocolData::TcpHeader(ref tcp_data) = meta_packet.protocol_data else {
                return None;
            };
            let consequent_frame_size =
                tcp_reassemble.get_consequent_frame_size(direction).unwrap();

            match tcp_reassemble.reassemble_non_serial(tcp_data.seq, cut_payload, direction,meta_packet.lookup_key.timestamp.as_micros() as u64,meta_packet.cap_seq)
            {
                Ok(_) => {
                    if tcp_reassemble
                        .get_waitting_buf_len_before_first_frame(direction)
                        .unwrap_or_default()
                        == 0
                    {
                        // 只有 buffer 里第一帧和 base_seq 之间没有预留空间并且第一段连续的帧数据有变化,才会出发解析
                        // 由于已经重组,所以不需要再重组, can_reassemble 是 false
                        if tcp_reassemble.get_consequent_frame_size(direction).unwrap()
                            != consequent_frame_size
                        {
                            let (tcp_framse, buffer) =
                                tcp_reassemble.get_consequent_buffer(direction).unwrap();
                                param.set_payload_in_buffer(true);
                                Some(PayloadReader::new(Payload::InFlightBuffer(buffer, tcp_framse)))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                Err(e) => match e{
                    tcp_reassemble::tcp_reassemble::TcpReassembleError::FrameBeforeBase => {
                        param.set_payload_in_buffer(true);
                        Some(PayloadReader::new(Payload::MetaPacket( TcpPayload{
                            payload: cut_payload,
                            seq: t.seq,
                            cap_seq: meta_packet.cap_seq,
                            can_reassemble:  cut_payload.len() != log_size,
                            timestamp: meta_packet.lookup_key.timestamp.as_micros(),
                        })))
                    },
                    tcp_reassemble::tcp_reassemble::TcpReassembleError::PayloadExceedMaxBufferSize => unreachable!(),
                    tcp_reassemble::tcp_reassemble::TcpReassembleError::FrameExist => None,
                    tcp_reassemble::tcp_reassemble::TcpReassembleError::BufferFlush(buffer) => {
                        param.set_payload_in_buffer(true);
                        Some(PayloadReader::new(Payload::FlushedBuffer(buffer)))
                    }
                },
            }
        }
    }

    pub fn new(
        l4_enabled: bool,
        tcp_perf_pool: &mut MemoryPool<TcpPerf>,
        l7_enabled: bool,
        perf_cache: Rc<RefCell<L7PerfCache>>,
        l4_proto: L4Protocol,
        l7_protocol_enum: L7ProtocolEnum,
        is_skip: bool,
        counter: Arc<FlowPerfCounter>,
        server_port: u16,
        wasm_vm: Option<Rc<RefCell<WasmVm>>>,
        #[cfg(any(target_os = "linux", target_os = "android"))] so_plugin: Option<
            Rc<Vec<SoPluginFunc>>,
        >,
        #[cfg(any(target_os = "linux", target_os = "android"))] so_plugin_counter: Option<
            Rc<SoPluginCounterMap>,
        >,
        stats_counter: Arc<FlowMapCounter>,
        rrt_timeout: usize,
        l7_protocol_inference_ttl: u64,
        last_time: Option<u64>,
        ntp_diff: Arc<AtomicI64>,
        buffer_size: usize,
        max_tcp_frame: usize,
        flow_id: u64,
        lookup_key_0: FlowLogLookupKey,
        lookup_key_1: FlowLogLookupKey,
        ebpf_type:EbpfType,
        ebpf_param:EbpfParam,
    ) -> Option<Self> {
        if !l4_enabled && !l7_enabled {
            return None;
        }
        let l4 = if l4_enabled {
            match l4_proto {
                L4Protocol::Tcp => Some(L4FlowPerfTable::Tcp(
                    tcp_perf_pool
                        .get()
                        .unwrap_or_else(|| Box::new(TcpPerf::new(counter))),
                )),
                L4Protocol::Udp => Some(L4FlowPerfTable::Udp(UdpPerf::new())),
                L4Protocol::Icmp => Some(L4FlowPerfTable::Icmp(IcmpPerf::new())),
                _ => None,
            }
        } else {
            None
        };

        Some(Self {
            l4: l4.map(|o| Box::new(o)),
            l7_protocol_log_parser: get_parser(l7_protocol_enum.clone()).map(|o| Box::new(o)),
            perf_cache,
            l7_protocol_enum,
            server_port: server_port,
            is_success: false,
            is_skip,
            wasm_vm,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            so_plugin,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            so_plugin_counter,
            stats_counter: stats_counter,
            rrt_timeout: rrt_timeout,
            last_fail: last_time,
            l7_protocol_inference_ttl,
            ntp_diff,
            lookup_key_0,
            lookup_key_1,
            tcp_reassemble: if l4_proto == L4Protocol::Tcp && max_tcp_frame > 1 && ebpf_type!=EbpfType::GoHttp2Uprobe && ebpf_type!=EbpfType::GoHttp2UprobeData{
                Some(Rc::new(RefCell::new(TcpFlowReassembleBuf::new(
                    buffer_size,
                    max_tcp_frame,
                    flow_id,
                ))))
            } else {
                None
            },
            flow_id,
            ebpf_type,
            ebpf_param,
        })
    }

    pub fn recycle(tcp_perf_pool: &mut MemoryPool<TcpPerf>, log: FlowLog) {
        if let Some(p) = log.l4 {
            if let L4FlowPerfTable::Tcp(t) = *p {
                tcp_perf_pool.put(t);
            }
        }
    }

    pub fn parse(
        &mut self,
        flow_config: &FlowConfig,
        log_parser_config: &LogParserConfig,
        packet: &mut MetaPacket,
        is_first_packet_direction: bool,
        l7_performance_enabled: bool,
        l7_log_parse_enabled: bool,
        app_table: &mut AppTable,
        local_epc: i32,
        remote_epc: i32,
        checker: &L7ProtocolChecker,
    ) -> Result<L7ParseResult> {
        if let Some(l4) = self.l4.as_mut() {
            l4.parse(packet, is_first_packet_direction)?;
        }

        if l7_performance_enabled || l7_log_parse_enabled {
            // 抛出错误由flowMap.FlowPerfCounter处理
            self.check_fail_recover();
            if self.is_skip {
                return Err(Error::L7ProtocolParseLimit);
            }

            if packet.l4_payload_len() == 0 {
                return Err(Error::ZeroPayloadLen);
            }

            if packet.signal_source == SignalSource::EBPF && self.server_port != 0 {
                // if the packet from eBPF and it's server_port is not equal to 0, We can get the packet's
                // direction by comparing self.server_port with packet.lookup_key.dst_port When check_payload()
                // fails, the server_port value is still 0, and the flow direction cannot be corrected.
                packet.lookup_key.direction = if self.server_port == packet.lookup_key.dst_port {
                    PacketDirection::ClientToServer
                } else {
                    PacketDirection::ServerToClient
                };
            }
            self.update_lookup_key(&*packet);

            let mut lookup_key = packet.lookup_key.clone();
            let param = &mut ParseParam::new(
                &*packet,
                self.perf_cache.clone(),
                l7_performance_enabled,
                l7_log_parse_enabled,
            );
            param.set_log_parse_config(log_parser_config);
            #[cfg(any(target_os = "linux", target_os = "android"))]
            param.set_counter(self.stats_counter.clone(), self.so_plugin_counter.clone());
            param.set_rrt_timeout(self.rrt_timeout);
            param.set_buf_size(flow_config.l7_log_packet_size as usize);
            param.set_oracle_conf(flow_config.oracle_parse_conf);
            #[cfg(any(target_os = "linux", target_os = "android"))]
            if let Some(p) = self.so_plugin.as_ref() {
                param.set_so_func(p.clone());
            }
            if let Some(vm) = self.wasm_vm.as_ref() {
                param.set_wasm_vm(vm.clone());
            }

            let log_size = flow_config.l7_log_packet_size as usize;

            let res = if let Some(tcp_reassemble) = self.tcp_reassemble.clone() {
                let tt = tcp_reassemble.clone();
                let mut t = tt.borrow_mut();

                let Some(payload_reader) =
                    Self::get_payload_reader(&mut t, packet, log_size, param, &self.lookup_key_0)
                else {
                    return Err(Error::L7ProtocolParseLimit);
                };
                let (res, drain_frame) = self.l7_parse(
                    payload_reader,
                    param,
                    &mut lookup_key,
                    app_table,
                    local_epc,
                    remote_epc,
                    checker,
                );
                if drain_frame != 0 {
                    t.drain_frames(
                        lookup_key.get_reassemble_direction(&self.lookup_key_0),
                        drain_frame,
                    );
                }

                if let Err(Error::NeedMoreData) = res {
                    /*
                        res 如果是从 parse 返回,由于 parse 可能不止解析一段数据,这里需要分几种情况
                        1. buffer 是空, 说明 payload 是 metapacket 原始 payload,这时候 payload_in_buffer = false, 并且只有一段数据, parse 只解析一次,所以要么成功要么失败.
                            1.1 如果 metapacket 的 payload 长度 < buffer最大长度, 只有这种情况需要重组, 直接把 payload 放入 buffer
                            1.2 如果 metapacket 的 payload 长度 >= buffer最大长度,这时候不能再重组, parse 要么返回 info 要么返回错误,如果
                                返回 NeedMoreData 则会丢数据(因为这里应该尽可能返回 log info),但是还是会调用 reassemble, 目的只是更新 base seq
                        2. 如果 buffer 不为空, 那么说明 payload 已经经过重组, 这时候 payload_in_buffer = true, payload 的数据是 buffer 里的数据, 这时候 parse 可能需要解析多段数据
                            2.1 存在成功解析的数据, 那么就认为解析成功,即使最后返回 NeedMoreData, 由于 payload 已经经过重组,不影响.
                            2.2 全部失败, res 就是 Err


                        重组的设计请参考 tcp_reassemble::BufferData::reassemble()
                    */
                    if !param.payload_in_buffer {
                        // 如果 payload_in_buffer 目前的逻辑重组 buffer 必定是空, drop_frame 必定是0,并且这里的 param.tcp_seq 必定等于 metapacket 的 tcp seq
                        match t.reassemble_non_serial(param.tcp_seq,packet.get_l4_payload().unwrap(), lookup_key.get_reassemble_direction(&self.lookup_key_0),packet.lookup_key.timestamp.as_micros(),packet.cap_seq
                            ){
                        Ok(_) => {},
                        Err(e) => match e{
                            // tcp_reassemble_after_parse 必定在 get_payload 之后调用,目前的逻辑这里只可能返回 PayloadExceedMaxBufferSize
                            tcp_reassemble::tcp_reassemble::TcpReassembleError::PayloadExceedMaxBufferSize => {},
                            _=>unreachable!()
                        } ,
                    }
                    }
                }
                res
            } else {
                let (res, _) = self.l7_parse(
                    PayloadReader::new(Payload::MetaPacket(TcpPayload {
                        payload: packet.get_l4_payload_cut(log_size).unwrap(),
                        seq: match &packet.protocol_data {
                            ProtocolData::TcpHeader(t) => t.seq,
                            ProtocolData::IcmpData(_) => 0,
                        },
                        cap_seq:packet.cap_seq,
                        can_reassemble: false,
                        timestamp: packet.lookup_key.timestamp.as_micros(),
                    })),
                    param,
                    &mut lookup_key,
                    app_table,
                    local_epc,
                    remote_epc,
                    checker,
                );
                res
            };

            packet.lookup_key = lookup_key;
            return res;
        }
        Ok(L7ParseResult::None)
    }

    // TODO flush all buffer when flow close
    pub fn flush_all_buffer(
        &mut self,
        l7_performance_enabled: bool,
        l7_log_parse_enabled: bool,
        flow_config: &FlowConfig,
        log_parser_config: &LogParserConfig,
        app_table: &mut AppTable,
        local_epc: i32,
        remote_epc: i32,
    ) -> Option<Result<L7ParseResult>> {
        let Some(tcp_reassemble) = self.tcp_reassemble.clone() else {
            return None;
        };

        let mut tcp_reassemble = tcp_reassemble.borrow_mut();
        let (buf_0, buf_1) = tcp_reassemble.flush_all_buf();
        let payload = PayloadReader::new(Payload::FlushedBuffer(buf_0));
        let mut param_0 = ParseParam {
            l4_protocol: IpProtocol::TCP,
            ip_src: self.lookup_key_0.ip,
            ip_dst: self.lookup_key_1.ip,
            port_src: self.lookup_key_0.port,
            port_dst: self.lookup_key_0.port,
            flow_id: self.flow_id,
            direction: self.lookup_key_0.direction,
            ebpf_type: self.ebpf_type,
            ebpf_param: if self.ebpf_type==EbpfType::None{
                None
            }else{
                Some(self.ebpf_param.clone())
            },
            // the follow 4 field will update by tcp frame
            packet_seq: 0,
            time: 0,
            tcp_seq: 0,
            payload_can_reassemble: false,

            parse_perf: l7_performance_enabled,
            parse_log: l7_log_parse_enabled,
            endpoint: todo!(),
            parse_config: None,
            l7_perf_cache: todo!(),
            wasm_vm: None,
            so_func: None,
            so_plugin_counter_map: None,
            stats_counter: None,
            rrt_timeout: 0,
            buf_size: 0,
            oracle_parse_conf: OracleParseConfig::default(),
            payload_in_buffer: true,
        };
        
        todo!()
    }

    pub fn parse_l3(&mut self, packet: &mut MetaPacket) -> Result<()> {
        if let Some(l4) = self.l4.as_mut() {
            l4.parse(packet, false)?;
        }
        Ok(())
    }

    pub fn copy_and_reset_l4_perf_data(&mut self, flow_reversed: bool, flow: &mut Flow) {
        if let Some(l4) = self.l4.as_mut() {
            if l4.data_updated() {
                let flow_perf_stats = l4.copy_and_reset_data(flow_reversed);
                flow.flow_perf_stats.as_mut().unwrap().l4_protocol = flow_perf_stats.l4_protocol;
                flow.flow_perf_stats.as_mut().unwrap().tcp = flow_perf_stats.tcp;
            }
        }
    }

    pub fn copy_and_reset_l7_perf_data(
        &mut self,
        l7_timeout_count: u32,
    ) -> (L7PerfStats, L7Protocol) {
        let default_l7_perf = L7PerfStats {
            err_timeout: l7_timeout_count,
            ..Default::default()
        };

        let l7_perf = self
            .l7_protocol_log_parser
            .as_mut()
            .map_or(default_l7_perf.clone(), |l| {
                l.perf_stats().map_or(default_l7_perf, |mut p| {
                    p.err_timeout = l7_timeout_count;
                    p
                })
            });

        (l7_perf, self.l7_protocol_enum.get_l7_protocol())
    }
}
