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

pub(crate) mod dns;
pub mod l7_rrt;
pub(crate) mod mq;
pub(crate) mod rpc;
pub(crate) mod sql;
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

use super::app_table::AppTable;
use super::error::{Error, Result};
use super::protocol_logs::AppProtoHead;

use crate::common::flow::L7PerfStats;
use crate::common::l7_protocol_log::L7PerfCache;
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

use {
    dns::DnsPerfData,
    mq::{KafkaPerfData, MqttPerfData},
    rpc::DubboPerfData,
    sql::{MysqlPerfData, RedisPerfData},
    tcp::TcpPerf,
    udp::UdpPerf,
};

pub use l7_rrt::L7RrtCache;
pub use stats::FlowPerfCounter;
pub use stats::PerfStats;

pub use dns::DNS_PORT;

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

macro_rules! impl_l7_flow_perf {
    (pub enum $name:ident { $($enum_name:ident($enum_type:ty)),* $(,)? }) => {
        pub enum $name {
            $($enum_name($enum_type)),*
        }

        impl L7FlowPerf for $name {
            fn parse(
                &mut self,
                config: Option<&LogParserConfig>,
                packet: &MetaPacket,
                flow_id: u64,
            ) -> Result<()> {
                match self {
                    $(Self::$enum_name(p) => p.parse(config, packet, flow_id)),*
                }
            }

            fn data_updated(&self) -> bool {
                match self {
                    $(Self::$enum_name(p) => p.data_updated()),*
                }
            }

            fn copy_and_reset_data(&mut self, l7_timeout_count: u32) -> FlowPerfStats {
                match self {
                    $(Self::$enum_name(p) => p.copy_and_reset_data(l7_timeout_count)),*
                }
            }

            fn app_proto_head(&mut self) -> Option<(AppProtoHead, u16)> {
                match self {
                    $(Self::$enum_name(p) => p.app_proto_head()),*
                }
            }
        }
    };
}

// impl L7FlowPerf for L7FlowPerfTable
// TODO will remove after perf remake
impl_l7_flow_perf! {
    pub enum L7FlowPerfTable {
        Dns(DnsPerfData),
        Kafka(KafkaPerfData),
        Mqtt(MqttPerfData),
        Redis(RedisPerfData),
        Dubbo(DubboPerfData),
        Mysql(MysqlPerfData),
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

    // TODO perf 重构完成后会去掉
    // TODO after finish perf remake  will remove
    l7: Option<Box<L7FlowPerfTable>>,

    // perf 目前还没有抽象出来,自定义协议需要添加字段区分,以后抽出来后 l7可以去掉.
    l7_protocol_log_parser: Option<Box<L7ProtocolParser>>,
    // TODO perf 重构完成后会去掉
    // TODO after finish perf remake  will remove
    rrt_cache: Rc<RefCell<L7RrtCache>>,

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
}

impl FlowLog {
    const PROTOCOL_CHECK_LIMIT: usize = 5;
    // TODO will remove after perf remake
    fn l7_new(protocol: L7Protocol, rrt_cache: Rc<RefCell<L7RrtCache>>) -> Option<L7FlowPerfTable> {
        match protocol {
            L7Protocol::DNS => Some(L7FlowPerfTable::Dns(DnsPerfData::new(rrt_cache.clone()))),
            L7Protocol::Dubbo => Some(L7FlowPerfTable::Dubbo(DubboPerfData::new(
                rrt_cache.clone(),
            ))),
            L7Protocol::Kafka => Some(L7FlowPerfTable::Kafka(KafkaPerfData::new(
                rrt_cache.clone(),
            ))),
            L7Protocol::MQTT => Some(L7FlowPerfTable::Mqtt(MqttPerfData::new(rrt_cache.clone()))),
            L7Protocol::MySQL => Some(L7FlowPerfTable::Mysql(MysqlPerfData::new(
                rrt_cache.clone(),
            ))),
            L7Protocol::Redis => Some(L7FlowPerfTable::Redis(RedisPerfData::new(
                rrt_cache.clone(),
            ))),
            _ => None,
        }
    }

    // return rrt
    // TODO will remove after perf remake
    fn l7_parse_perf(
        &mut self,
        log_parser_config: &LogParserConfig,
        packet: &MetaPacket,
        flow_id: u64,
        app_table: &mut AppTable,
        local_epc: i32,
        remote_epc: i32,
    ) -> Result<u64> {
        if self.is_skip {
            return Err(Error::L7ProtocolParseLimit);
        }
        if packet.get_l4_payload().is_none() {
            return Err(Error::ZeroPayloadLen);
        }
        let perf_parser = self.l7.as_mut().unwrap();
        let ret = perf_parser.parse(Some(log_parser_config), packet, flow_id);

        // TODO 目前rrt由perf计算， 用于聚合时计算slot，后面perf 抽象出来后，将去掉perf，rrt由log parser计算
        // =======================================================================================
        // TODO now rrt is calculate by perf parse, use for calculate slot index on session merge.
        // when log parse implement perf parse, rrt will calculate from log parse.
        let rrt = if ret.is_ok() {
            let rrt = if let Some((head, _)) = perf_parser.app_proto_head() {
                head.rrt
            } else {
                0
            };
            rrt
        } else {
            0
        };

        if !self.is_success {
            if ret.is_ok() {
                match packet.signal_source {
                    SignalSource::EBPF => {
                        app_table.set_protocol_from_ebpf(
                            packet,
                            self.l7_protocol_enum,
                            local_epc,
                            remote_epc,
                        );
                    }
                    _ => {
                        app_table.set_protocol(packet, self.l7_protocol_enum);
                    }
                }
                self.is_success = true;
            } else {
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
        }
        ret?;
        Ok(rrt)
    }

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
            parser.reset();

            if !self.is_success {
                if ret.is_ok() {
                    match packet.signal_source {
                        SignalSource::EBPF => {
                            app_table.set_protocol_from_ebpf(
                                packet,
                                self.l7_protocol_enum,
                                local_epc,
                                remote_epc,
                            );
                        }
                        _ => {
                            app_table.set_protocol(packet, self.l7_protocol_enum);
                        }
                    }
                    self.is_success = true;
                } else {
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
            }
            return ret;
        }

        return Err(Error::ZeroPayloadLen);
    }

    fn l7_check(
        &mut self,
        flow_config: &FlowConfig,
        log_parser_config: &LogParserConfig,
        packet: &mut MetaPacket,
        flow_id: u64,
        app_table: &mut AppTable,
        is_parse_perf: bool,
        is_parse_log: bool,
        local_epc: i32,
        remote_epc: i32,
        checker: &L7ProtocolChecker,
    ) -> Result<(Vec<L7ProtocolInfo>, u64)> {
        if self.is_skip {
            return Err(Error::L7ProtocolCheckLimit);
        }

        if let Some(payload) = packet.get_l4_payload() {
            let param = ParseParam::from((
                &*packet,
                self.perf_cache.clone(),
                !is_parse_log,
                log_parser_config,
            ));
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
                    self.l7_protocol_enum = parser.l7_protocl_enum();

                    // redis can not determine dirction by RESP protocol when pakcet is from ebpf, special treatment
                    if self.l7_protocol_enum.get_l7_protocol() == L7Protocol::Redis
                        && packet.signal_source == SignalSource::EBPF
                    {
                        (_, self.server_port) = packet.get_redis_server_addr();
                    } else {
                        self.server_port = packet.lookup_key.dst_port;
                    }

                    packet.lookup_key.direction = PacketDirection::ClientToServer;

                    // 重构后rrt直接由log获取，对于已完成重构的协议 这里的rrt都是0
                    let mut rrt = 0;
                    // 完成重构的协议， 只会解析一次
                    if protocol.remaked() {
                        self.l7_protocol_log_parser = Some(Box::new(parser));
                        let ret = self.l7_parse_log(
                            flow_config,
                            packet,
                            app_table,
                            &param,
                            local_epc,
                            remote_epc,
                        )?;
                        return Ok((ret, rrt));
                    }

                    // TODO 没完成重构的协议依然走旧逻辑，完成重构后这部分会去掉
                    if is_parse_perf {
                        // perf 没有抽象出来,这里可能返回None，对于返回None即不解析perf，只解析log
                        self.l7 =
                            Self::l7_new(*protocol, self.rrt_cache.clone()).map(|o| Box::new(o));
                        if self.l7.is_some() {
                            rrt = self.l7_parse_perf(
                                log_parser_config,
                                packet,
                                flow_id,
                                app_table,
                                local_epc,
                                remote_epc,
                            )?;
                        }
                    }

                    if is_parse_log {
                        self.l7_protocol_log_parser = Some(Box::new(parser));
                        let ret = self.l7_parse_log(
                            flow_config,
                            packet,
                            app_table,
                            &param,
                            local_epc,
                            remote_epc,
                        )?;
                        return Ok((ret, rrt));
                    }
                    return Ok((vec![], 0));
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

    // TODO 目前rrt由perf计算， 用于聚合时计算slot，后面perf 抽象出来后，将去掉perf，rrt由log parser计算
    // =======================================================================================
    // TODO now rrt is calculate by perf parse, use for calculate slot index on session merge.
    // when log parse implement perf parse, rrt will calculate from log parse.
    fn l7_parse(
        &mut self,
        flow_config: &FlowConfig,
        log_parser_config: &LogParserConfig,
        packet: &mut MetaPacket,
        flow_id: u64,
        app_table: &mut AppTable,
        is_parse_perf: bool,
        is_parse_log: bool,
        local_epc: i32,
        remote_epc: i32,
        checker: &L7ProtocolChecker,
    ) -> Result<(Vec<L7ProtocolInfo>, u64)> {
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

        // 已重构完成的协议，只解析一次
        if self.l7_protocol_enum.get_l7_protocol().remaked()
            && self.l7_protocol_log_parser.is_some()
        {
            let ret = self.l7_parse_log(
                flow_config,
                packet,
                app_table,
                &ParseParam::from((
                    &*packet,
                    self.perf_cache.clone(),
                    !is_parse_log,
                    log_parser_config,
                )),
                local_epc,
                remote_epc,
            )?;
            // 完成重构的协议，rrt可以直接从log获取，这里兼容旧逻辑先返回0
            return Ok((ret, 0));
        }

        // TODO 未完成重构的协议走旧逻辑，所有协议重构后下面两个解析会去掉
        let mut rrt = 0;
        if self.l7.is_some() && is_parse_perf {
            rrt = self.l7_parse_perf(
                log_parser_config,
                packet,
                flow_id,
                app_table,
                local_epc,
                remote_epc,
            )?;
            if !is_parse_log {
                return Ok((vec![], rrt));
            }
        }

        if self.l7_protocol_log_parser.is_some() && is_parse_log {
            let ret = self.l7_parse_log(
                flow_config,
                packet,
                app_table,
                &ParseParam::from((&*packet, self.perf_cache.clone(), false, log_parser_config)),
                local_epc,
                remote_epc,
            )?;
            return Ok((ret, rrt));
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
            flow_id,
            app_table,
            is_parse_perf,
            is_parse_log,
            local_epc,
            remote_epc,
            checker,
        )
    }

    pub fn new(
        l4_enabled: bool,
        l7_enabled: bool,
        // TODO rrt cache 重构完成后会去掉
        rrt_cache: Rc<RefCell<L7RrtCache>>,
        perf_cache: Rc<RefCell<L7PerfCache>>,
        l4_proto: L4Protocol,
        l7_protocol_enum: L7ProtocolEnum,
        is_from_app_tab: bool,
        counter: Arc<FlowPerfCounter>,
        server_port: u16,
    ) -> Option<Self> {
        let l4 = if l4_enabled {
            match l4_proto {
                L4Protocol::Tcp => Some(L4FlowPerfTable::Tcp(Box::new(TcpPerf::new(counter)))),
                L4Protocol::Udp => Some(L4FlowPerfTable::Udp(UdpPerf::new())),
                _ => None,
            }
        } else {
            None
        };
        let l7 = if l7_enabled {
            Self::l7_new(l7_protocol_enum.get_l7_protocol(), rrt_cache.clone())
        } else {
            None
        };
        if l4.is_none() && l7.is_none() {
            return None;
        }

        Some(Self {
            l4: l4.map(|o| Box::new(o)),
            l7: l7.map(|o| Box::new(o)),
            l7_protocol_log_parser: get_parser(l7_protocol_enum).map(|o| Box::new(o)),
            rrt_cache,
            perf_cache,
            l7_protocol_enum,
            is_from_app: is_from_app_tab,
            is_success: false,
            is_skip: false,
            server_port: server_port,
        })
    }

    pub fn parse(
        &mut self,
        flow_config: &FlowConfig,
        log_parser_config: &LogParserConfig,
        packet: &mut MetaPacket,
        is_first_packet_direction: bool,
        flow_id: u64,
        _: bool,
        l7_performance_enabled: bool,
        l7_log_parse_enabled: bool,
        app_table: &mut AppTable,
        local_epc: i32,
        remote_epc: i32,
        checker: &L7ProtocolChecker,
    ) -> Result<(Vec<L7ProtocolInfo>, u64)> {
        if let Some(l4) = self.l4.as_mut() {
            l4.parse(packet, is_first_packet_direction)?;
        }

        if l7_performance_enabled || l7_log_parse_enabled {
            // 抛出错误由flowMap.FlowPerfCounter处理
            return self.l7_parse(
                flow_config,
                log_parser_config,
                packet,
                flow_id,
                app_table,
                l7_performance_enabled,
                l7_log_parse_enabled,
                local_epc,
                remote_epc,
                checker,
            );
        }
        Ok((vec![], 0))
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
            self.get_l7_perf_stat(l7_timeout_count).map_or(
                {
                    if l7_timeout_count > 0 {
                        stats.replace(FlowPerfStats {
                            l7_protocol: self.l7_protocol_enum.get_l7_protocol(),
                            l7: L7PerfStats {
                                err_timeout: l7_timeout_count,
                                ..Default::default()
                            },
                            ..Default::default()
                        });
                    }
                },
                |mut perf| {
                    if let Some(stats) = stats.as_mut() {
                        perf.err_timeout = l7_timeout_count;
                        stats.l7 = perf;
                        stats.l7_protocol = self.l7_protocol_enum.get_l7_protocol();
                    } else {
                        stats.replace(FlowPerfStats {
                            l7: perf,
                            l7_protocol: self.l7_protocol_enum.get_l7_protocol(),
                            ..Default::default()
                        });
                    }
                },
            );
        }
        stats
    }

    // TODO 这个用于根据协议判断从perf/log 获取perf数据， perf重构完成后会去掉
    fn get_l7_perf_stat(&mut self, l7_timeout_count: u32) -> Option<L7PerfStats> {
        if self.l7_perf_remake() {
            self.l7_protocol_log_parser
                .as_mut()
                .map_or(None, |l| l.perf_stats())
        } else {
            if let Some(p) = self.l7.as_mut() {
                if p.data_updated() {
                    return Some(p.copy_and_reset_data(l7_timeout_count).l7);
                }
            }
            return None;
        }
    }

    // TODO perf重构完成后会去掉
    pub fn l7_perf_remake(&self) -> bool {
        self.l7_protocol_enum.get_l7_protocol().remaked()
    }
}
