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

mod stats;
pub mod tcp;
pub(crate) mod udp;

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::slice;
use std::sync::Arc;

use enum_dispatch::enum_dispatch;
use public::bitmap::Bitmap;
use public::l7_protocol::L7ProtocolEnum;

use super::{
    app_table::AppTable,
    error::{Error, Result},
    flow_map::FlowMapCounter,
    pool::MemoryPool,
    protocol_logs::AppProtoHead,
};

use crate::common::flow::L7PerfStats;
use crate::common::l7_protocol_log::L7PerfCache;
use crate::plugin::wasm::WasmVm;
use crate::{
    common::{
        flow::{FlowPerfStats, L4Protocol, L7Protocol, PacketDirection, SignalSource},
        l7_protocol_info::L7ProtocolInfo,
        l7_protocol_log::{
            get_all_protocol, get_parser, L7ProtocolBitmap, L7ProtocolParser,
            L7ProtocolParserInterface, ParseParam,
        },
        meta_packet::MetaPacket,
        Timestamp,
    },
    config::{handler::LogParserConfig, FlowConfig},
};

use {tcp::TcpPerf, udp::UdpPerf};

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
}

impl L4FlowPerf for L4FlowPerfTable {
    fn parse(&mut self, packet: &MetaPacket, direction: bool) -> Result<()> {
        match self {
            Self::Tcp(p) => p.parse(packet, direction),
            Self::Udp(p) => p.parse(packet, direction),
        }
    }

    fn data_updated(&self) -> bool {
        match self {
            Self::Tcp(p) => p.data_updated(),
            Self::Udp(p) => p.data_updated(),
        }
    }

    fn copy_and_reset_data(&mut self, flow_reversed: bool) -> FlowPerfStats {
        match self {
            Self::Tcp(p) => p.copy_and_reset_data(flow_reversed),
            Self::Udp(p) => p.copy_and_reset_data(flow_reversed),
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
                L4Protocol::Unknown => [].iter(),
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

    is_from_app: bool,
    is_success: bool,
    is_skip: bool,

    wasm_vm: Option<Rc<RefCell<WasmVm>>>,
    stats_counter: Arc<FlowMapCounter>,
}

impl FlowLog {
    const PROTOCOL_CHECK_LIMIT: usize = 5;

    fn l7_parse_log(
        &mut self,
        flow_config: &FlowConfig,
        packet: &mut MetaPacket,
        app_table: &mut AppTable,
        parse_param: &ParseParam,
        local_epc: i32,
        remote_epc: i32,
    ) -> Result<Vec<L7ProtocolInfo>> {
        if self.is_skip {
            return Err(Error::L7ProtocolParseLimit);
        }

        if let Some(payload) = packet.get_l4_payload() {
            let parser = self.l7_protocol_log_parser.as_mut().unwrap();

            let ret = parser.parse_payload(
                {
                    let pkt_size = flow_config.l7_log_packet_size as usize;
                    if pkt_size > payload.len() {
                        payload
                    } else {
                        &payload[..pkt_size]
                    }
                },
                parse_param,
            );

            let mut cache_proto = |proto: L7ProtocolEnum| match packet.signal_source {
                SignalSource::EBPF => {
                    app_table.set_protocol_from_ebpf(packet, proto, local_epc, remote_epc)
                }
                _ => app_table.set_protocol(packet, proto),
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
                }
            }
            return ret;
        }

        Err(Error::ZeroPayloadLen)
    }

    fn l7_check(
        &mut self,
        flow_config: &FlowConfig,
        log_parser_config: &LogParserConfig,
        packet: &mut MetaPacket,
        app_table: &mut AppTable,
        is_parse_log: bool,
        local_epc: i32,
        remote_epc: i32,
        checker: &L7ProtocolChecker,
    ) -> Result<Vec<L7ProtocolInfo>> {
        if self.is_skip {
            return Err(Error::L7ProtocolCheckLimit);
        }

        if let Some(payload) = packet.get_l4_payload() {
            let mut param = ParseParam::from((
                &*packet,
                self.perf_cache.clone(),
                !is_parse_log,
                log_parser_config,
            ));
            param.set_counter(self.stats_counter.clone());
            if let Some(vm) = self.wasm_vm.as_ref() {
                param.set_wasm_vm(vm.clone());
            }

            for protocol in checker.possible_protocols(
                packet.lookup_key.proto.into(),
                match packet.lookup_key.direction {
                    PacketDirection::ClientToServer => packet.lookup_key.dst_port,
                    PacketDirection::ServerToClient => packet.lookup_key.src_port,
                },
            ) {
                let Some(mut parser) = get_parser(L7ProtocolEnum::L7Protocol(*protocol)) else {
                    continue;
                };
                if parser.check_payload(payload, &param) {
                    self.l7_protocol_enum = parser.l7_protocol_enum();

                    // redis can not determine dirction by RESP protocol when pakcet is from ebpf, special treatment
                    if self.l7_protocol_enum.get_l7_protocol() == L7Protocol::Redis {
                        let host = packet.get_redis_server_addr();
                        let server_ip = host.0;
                        self.server_port = host.1;
                        if packet.lookup_key.dst_port != self.server_port
                            || packet.lookup_key.dst_ip != server_ip
                        {
                            packet.lookup_key.direction = PacketDirection::ServerToClient;
                        } else {
                            packet.lookup_key.direction = PacketDirection::ClientToServer;
                        }
                    } else {
                        self.server_port = packet.lookup_key.dst_port;
                        packet.lookup_key.direction = PacketDirection::ClientToServer;
                    }
                    param.direction = packet.lookup_key.direction;

                    self.l7_protocol_log_parser = Some(Box::new(parser));
                    let ret = self.l7_parse_log(
                        flow_config,
                        packet,
                        app_table,
                        &param,
                        local_epc,
                        remote_epc,
                    )?;
                    return Ok(ret);
                }
            }

            self.is_skip = match packet.signal_source {
                SignalSource::EBPF => app_table.set_protocol_from_ebpf(
                    packet,
                    L7ProtocolEnum::default(),
                    local_epc,
                    remote_epc,
                ),
                _ => app_table.set_protocol(packet, L7ProtocolEnum::default()),
            };
        }

        return Err(Error::L7ProtocolUnknown);
    }

    fn l7_parse(
        &mut self,
        flow_config: &FlowConfig,
        log_parser_config: &LogParserConfig,
        packet: &mut MetaPacket,
        app_table: &mut AppTable,
        is_parse_log: bool,
        local_epc: i32,
        remote_epc: i32,
        checker: &L7ProtocolChecker,
    ) -> Result<Vec<L7ProtocolInfo>> {
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

        if self.l7_protocol_log_parser.is_some() {
            let param = &mut ParseParam::from((
                &*packet,
                self.perf_cache.clone(),
                !is_parse_log,
                log_parser_config,
            ));
            param.set_counter(self.stats_counter.clone());
            if let Some(vm) = self.wasm_vm.as_ref() {
                param.set_wasm_vm(vm.clone());
            }
            return self.l7_parse_log(flow_config, packet, app_table, param, local_epc, remote_epc);
        }

        if self.is_from_app {
            return Err(Error::L7ProtocolUnknown);
        }

        if packet.l4_payload_len() < 2 {
            return Err(Error::L7ProtocolUnknown);
        }

        self.l7_check(
            flow_config,
            log_parser_config,
            packet,
            app_table,
            is_parse_log,
            local_epc,
            remote_epc,
            checker,
        )
    }

    pub fn new(
        l4_enabled: bool,
        tcp_perf_pool: &mut MemoryPool<TcpPerf>,
        l7_enabled: bool,
        perf_cache: Rc<RefCell<L7PerfCache>>,
        l4_proto: L4Protocol,
        l7_protocol_enum: L7ProtocolEnum,
        is_from_app_tab: bool,
        counter: Arc<FlowPerfCounter>,
        server_port: u16,
        wasm_vm: Option<Rc<RefCell<WasmVm>>>,
        stats_counter: Arc<FlowMapCounter>,
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
            is_from_app: is_from_app_tab,
            is_success: false,
            is_skip: false,
            server_port: server_port,
            wasm_vm: wasm_vm,
            stats_counter: stats_counter,
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
    ) -> Result<Vec<L7ProtocolInfo>> {
        if let Some(l4) = self.l4.as_mut() {
            l4.parse(packet, is_first_packet_direction)?;
        }

        if l7_performance_enabled || l7_log_parse_enabled {
            // 抛出错误由flowMap.FlowPerfCounter处理
            return self.l7_parse(
                flow_config,
                log_parser_config,
                packet,
                app_table,
                l7_log_parse_enabled,
                local_epc,
                remote_epc,
                checker,
            );
        }
        Ok(vec![])
    }

    pub fn copy_and_reset_perf_data(
        &mut self,
        flow_reversed: bool,
        l7_timeout_count: u32,
        _: bool,
        l7_performance_enabled: bool,
    ) -> Option<FlowPerfStats> {
        let mut stats = None;
        if let Some(l4) = self.l4.as_mut() {
            if l4.data_updated() {
                stats.replace(l4.copy_and_reset_data(flow_reversed));
            }
        }

        if l7_performance_enabled {
            let default_l7_perf = L7PerfStats {
                err_timeout: l7_timeout_count,
                ..Default::default()
            };

            let l7_perf =
                self.l7_protocol_log_parser
                    .as_mut()
                    .map_or(default_l7_perf.clone(), |l| {
                        l.perf_stats().map_or(default_l7_perf, |mut p| {
                            p.err_timeout = l7_timeout_count;
                            p
                        })
                    });

            if let Some(stats) = stats.as_mut() {
                stats.l7 = l7_perf;
                stats.l7_protocol = self.l7_protocol_enum.get_l7_protocol();
            } else {
                stats.replace(FlowPerfStats {
                    l7: l7_perf,
                    l7_protocol: self.l7_protocol_enum.get_l7_protocol(),
                    ..Default::default()
                });
            }
        }
        stats
    }
}
