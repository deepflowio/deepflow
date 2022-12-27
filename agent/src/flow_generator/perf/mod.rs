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

mod dns;
pub mod http;
pub mod l7_rrt;
mod mq;
mod rpc;
mod sql;
mod stats;
pub mod tcp;
mod udp;

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::access::Access;
use enum_dispatch::enum_dispatch;
use public::bitmap::Bitmap;
use public::l7_protocol::L7ProtocolEnum;

use super::app_table::AppTable;
use super::error::{Error, Result};
use super::protocol_logs::{AppProtoHead, PostgresqlLog, ProtobufRpcWrapLog, SofaRpcLog};

use crate::common::flow::{PacketDirection, SignalSource};
use crate::common::l7_protocol_info::L7ProtocolInfo;
use crate::common::l7_protocol_log::{
    get_all_protocol, get_parse_bitmap, L7ProtocolBitmap, L7ProtocolParser,
    L7ProtocolParserInterface, ParseParam,
};
use crate::common::{
    enums::IpProtocol,
    flow::{FlowPerfStats, L4Protocol, L7Protocol},
    meta_packet::MetaPacket,
};
use crate::config::handler::LogParserAccess;
use crate::config::FlowAccess;

use {
    self::http::HttpPerfData,
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

const ART_MAX: Duration = Duration::from_secs(30);

#[enum_dispatch(L4FlowPerfTable)]
pub trait L4FlowPerf {
    fn parse(&mut self, packet: &MetaPacket, direction: bool) -> Result<()>;
    fn data_updated(&self) -> bool;
    fn copy_and_reset_data(&mut self, flow_reversed: bool) -> FlowPerfStats;
}

#[enum_dispatch(L7FlowPerfTable)]
pub trait L7FlowPerf {
    fn parse(&mut self, packet: &MetaPacket, flow_id: u64) -> Result<()>;
    fn data_updated(&self) -> bool;
    fn copy_and_reset_data(&mut self, l7_timeout_count: u32) -> FlowPerfStats;
    fn app_proto_head(&mut self) -> Option<(AppProtoHead, u16)>;
}

#[enum_dispatch]
pub enum L4FlowPerfTable {
    TcpPerf,
    UdpPerf,
}

#[enum_dispatch]
pub enum L7FlowPerfTable {
    DnsPerfData,
    KafkaPerfData,
    MqttPerfData,
    RedisPerfData,
    DubboPerfData,
    MysqlPerfData,
    HttpPerfData,
    PostgresqlLog,
    ProtobufRpcWrapLog,
    SofaRpcLog,
}

impl L7FlowPerfTable {
    // TODO will remove when perf abstruct to log parse
    pub fn reset(&mut self) {
        match self {
            L7FlowPerfTable::ProtobufRpcWrapLog(p) => p.reset(),
            L7FlowPerfTable::PostgresqlLog(p) => p.reset(),
            L7FlowPerfTable::SofaRpcLog(p) => p.reset(),
            _ => {}
        }
    }
}

pub struct FlowPerf {
    l4: L4FlowPerfTable,
    l7: Option<L7FlowPerfTable>,

    // perf 目前还没有抽象出来,自定义协议需要添加字段区分,以后抽出来后 l7可以去掉.
    l7_protocol_log_parser: Option<L7ProtocolParser>,

    rrt_cache: Rc<RefCell<L7RrtCache>>,

    protocol_bitmap: L7ProtocolBitmap,
    l7_protocol_enum: L7ProtocolEnum,

    // Only for eBPF data, the server_port will be set in l7_check() method, it checks the first
    // request packet's payload, and then set self.server_port = packet.lookup_key.dst_port,
    // we use the server_port to judge packet's direction.
    pub server_port: u16,

    is_from_app: bool,
    is_success: bool,
    is_skip: bool,

    parse_config: LogParserAccess,
    flow_config: FlowAccess,

    // port bitmap max = 65535, indicate the l7 protocol in this port whether to parse
    l7_protocol_parse_port_bitmap: Arc<Vec<(String, Bitmap)>>,
}

impl FlowPerf {
    const PROTOCOL_CHECK_LIMIT: usize = 5;

    fn l7_new(protocol: L7Protocol, rrt_cache: Rc<RefCell<L7RrtCache>>) -> Option<L7FlowPerfTable> {
        match protocol {
            L7Protocol::DNS => Some(L7FlowPerfTable::from(DnsPerfData::new(rrt_cache.clone()))),
            L7Protocol::ProtobufRPC => Some(L7FlowPerfTable::from(ProtobufRpcWrapLog::new())),
            L7Protocol::SofaRPC => Some(L7FlowPerfTable::from(SofaRpcLog::new())),
            L7Protocol::Dubbo => Some(L7FlowPerfTable::from(DubboPerfData::new(rrt_cache.clone()))),
            L7Protocol::Kafka => Some(L7FlowPerfTable::from(KafkaPerfData::new(rrt_cache.clone()))),
            L7Protocol::MQTT => Some(L7FlowPerfTable::from(MqttPerfData::new(rrt_cache.clone()))),
            L7Protocol::MySQL => Some(L7FlowPerfTable::from(MysqlPerfData::new(rrt_cache.clone()))),
            L7Protocol::PostgreSQL => Some(L7FlowPerfTable::from(PostgresqlLog::new())),
            L7Protocol::Redis => Some(L7FlowPerfTable::from(RedisPerfData::new(rrt_cache.clone()))),
            L7Protocol::Http1
            | L7Protocol::Http1TLS
            | L7Protocol::Http2
            | L7Protocol::Http2TLS
            | L7Protocol::Grpc => Some(L7FlowPerfTable::from(HttpPerfData::new(rrt_cache.clone()))),
            _ => None,
        }
    }

    fn is_skip_l7_protocol_parse(&self, proto: &L7ProtocolParser, port: u16) -> bool {
        if self.protocol_bitmap.is_disabled(proto.protocol()) {
            return true;
        }
        proto.is_skip_parse_by_port_bitmap(&self.l7_protocol_parse_port_bitmap, port)
    }

    // return rrt
    fn l7_parse_perf(
        &mut self,
        packet: &MetaPacket,
        flow_id: u64,
        app_table: &mut AppTable,
    ) -> Result<u64> {
        if self.is_skip {
            return Err(Error::L7ProtocolParseLimit);
        }
        if packet.get_l4_payload().is_none() {
            return Err(Error::ZeroPayloadLen);
        }
        let perf_parser = self.l7.as_mut().unwrap();
        let ret = perf_parser.parse(packet, flow_id);

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

        if ret.is_ok() {
            perf_parser.reset();
        }

        if !self.is_success {
            if ret.is_ok() {
                app_table.set_protocol(packet, self.l7_protocol_enum);
                self.is_success = true;
            } else {
                self.is_skip = app_table.set_protocol(packet, L7ProtocolEnum::default());
            }
        }
        ret?;
        Ok(rrt)
    }

    fn l7_parse_log(
        &mut self,
        packet: &mut MetaPacket,
        app_table: &mut AppTable,
        parse_param: &ParseParam,
    ) -> Result<Vec<L7ProtocolInfo>> {
        if self.is_skip {
            return Err(Error::L7ProtocolParseLimit);
        }

        if let Some(payload) = packet.get_l4_payload() {
            let parser = self.l7_protocol_log_parser.as_mut().unwrap();
            parser.set_parse_config(&self.parse_config);

            let ret = parser.parse_payload(
                {
                    let pkt_size = self.flow_config.load().l7_log_packet_size as usize;
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
                    app_table.set_protocol(packet, self.l7_protocol_enum);
                    self.is_success = true;
                } else {
                    self.is_skip = app_table.set_protocol(packet, L7ProtocolEnum::default());
                }
            }
            return ret;
        }

        return Err(Error::ZeroPayloadLen);
    }

    fn l7_check(
        &mut self,
        packet: &mut MetaPacket,
        flow_id: u64,
        app_table: &mut AppTable,
        is_parse_perf: bool,
        is_parse_log: bool,
    ) -> Result<(Vec<L7ProtocolInfo>, u64)> {
        if self.is_skip {
            return Err(Error::L7ProtocolCheckLimit);
        }

        if let Some(payload) = packet.get_l4_payload() {
            let param = ParseParam::from(&*packet);
            for mut i in get_all_protocol() {
                if self.is_skip_l7_protocol_parse(
                    &i,
                    match packet.direction {
                        PacketDirection::ClientToServer => packet.lookup_key.dst_port,
                        PacketDirection::ServerToClient => packet.lookup_key.src_port,
                    },
                ) {
                    continue;
                }
                i.set_parse_config(&self.parse_config);
                if i.check_payload(payload, &param) {
                    self.l7_protocol_enum = i.l7_protocl_enum();
                    self.server_port = packet.lookup_key.dst_port;
                    packet.direction = PacketDirection::ClientToServer;

                    let mut rrt = 0;
                    if is_parse_perf {
                        // perf 没有抽象出来,这里可能返回None，对于返回None即不解析perf，只解析log
                        self.l7 = Self::l7_new(i.protocol(), self.rrt_cache.clone());
                        if self.l7.is_some() {
                            rrt = self.l7_parse_perf(packet, flow_id, app_table)?;
                        }
                    }

                    if is_parse_log {
                        self.l7_protocol_log_parser = Some(i);
                        let ret = self.l7_parse_log(packet, app_table, &param)?;
                        return Ok((ret, rrt));
                    }
                    return Ok((vec![], 0));
                }
            }

            self.is_skip = app_table.set_protocol(packet, L7ProtocolEnum::default());
        }

        return Err(Error::L7ProtocolUnknown);
    }

    // TODO 目前rrt由perf计算， 用于聚合时计算slot，后面perf 抽象出来后，将去掉perf，rrt由log parser计算
    // =======================================================================================
    // TODO now rrt is calculate by perf parse, use for calculate slot index on session merge.
    // when log parse implement perf parse, rrt will calculate from log parse.
    fn l7_parse(
        &mut self,
        packet: &mut MetaPacket,
        flow_id: u64,
        app_table: &mut AppTable,
        is_parse_perf: bool,
        is_parse_log: bool,
    ) -> Result<(Vec<L7ProtocolInfo>, u64)> {
        if packet.signal_source == SignalSource::EBPF && self.server_port != 0 {
            // if the packet from eBPF and it's server_port is not equal to 0, We can get the packet's
            // direction by comparing self.server_port with packet.lookup_key.dst_port When check_payload()
            // fails, the server_port value is still 0, and the flow direction cannot be corrected.
            packet.direction = if self.server_port == packet.lookup_key.dst_port {
                PacketDirection::ClientToServer
            } else {
                PacketDirection::ServerToClient
            };
        }

        let mut rrt = 0;
        if self.l7.is_some() && is_parse_perf {
            rrt = self.l7_parse_perf(packet, flow_id, app_table)?;
            if !is_parse_log {
                return Ok((vec![], rrt));
            }
        }

        if self.l7_protocol_log_parser.is_some() && is_parse_log {
            let ret = self.l7_parse_log(packet, app_table, &ParseParam::from(&*packet))?;
            return Ok((ret, rrt));
        }

        if self.is_from_app {
            return Err(Error::L7ProtocolUnknown);
        }

        if packet.l4_payload_len() < 2 {
            return Err(Error::L7ProtocolUnknown);
        }

        self.l7_check(packet, flow_id, app_table, is_parse_perf, is_parse_log)
    }

    pub fn new(
        rrt_cache: Rc<RefCell<L7RrtCache>>,
        l4_proto: L4Protocol,
        l7_proto: Option<L7ProtocolEnum>,
        l7_parser: Option<L7ProtocolParser>,
        counter: Arc<FlowPerfCounter>,
        l7_prorocol_enable_bitmap: L7ProtocolBitmap,
        parse_config: LogParserAccess,
        flow_config: FlowAccess,
        l7_protocol_parse_port_bitmap: Arc<Vec<(String, Bitmap)>>,
    ) -> Option<Self> {
        let l4 = match l4_proto {
            L4Protocol::Tcp => L4FlowPerfTable::from(TcpPerf::new(counter)),
            L4Protocol::Udp => L4FlowPerfTable::from(UdpPerf::new()),
            _ => {
                return None;
            }
        };

        let l7_protocol_enum = l7_proto.unwrap_or(L7ProtocolEnum::default());

        Some(Self {
            l4,
            l7: Self::l7_new(l7_protocol_enum.get_l7_protocol(), rrt_cache.clone()),
            protocol_bitmap: {
                match l4_proto {
                    L4Protocol::Tcp => get_parse_bitmap(IpProtocol::Tcp, l7_prorocol_enable_bitmap),
                    _ => get_parse_bitmap(IpProtocol::Udp, l7_prorocol_enable_bitmap),
                }
            },
            l7_protocol_log_parser: l7_parser,
            rrt_cache,
            l7_protocol_enum,
            is_from_app: l7_proto.is_some(),
            is_success: false,
            is_skip: false,
            parse_config,
            flow_config,
            l7_protocol_parse_port_bitmap,
            server_port: 0,
        })
    }

    pub fn reverse(&mut self, l7_proto: Option<L7Protocol>) {
        let l7_protocol = l7_proto.unwrap_or(L7Protocol::Unknown);
        self.is_from_app = l7_proto.is_some();
        self.is_skip = false;
        self.is_success = false;
        self.l7 = Self::l7_new(l7_protocol, self.rrt_cache.clone());
    }

    pub fn parse(
        &mut self,
        packet: &mut MetaPacket,
        is_first_packet_direction: bool,
        flow_id: u64,
        l4_performance_enabled: bool,
        l7_performance_enabled: bool,
        l7_log_parse_enabled: bool,
        app_table: &mut AppTable,
    ) -> Result<(Vec<L7ProtocolInfo>, u64)> {
        if l4_performance_enabled {
            self.l4.parse(packet, is_first_packet_direction)?;
        }

        if l7_performance_enabled || l7_log_parse_enabled {
            // 抛出错误由flowMap.FlowPerfCounter处理
            return self.l7_parse(
                packet,
                flow_id,
                app_table,
                l7_performance_enabled,
                l7_log_parse_enabled,
            );
        }
        Ok((vec![], 0))
    }

    pub fn copy_and_reset_perf_data(
        &mut self,
        flow_reversed: bool,
        l7_timeout_count: u32,
        l4_performance_enabled: bool,
        l7_performance_enabled: bool,
    ) -> Option<FlowPerfStats> {
        let mut stats = None;
        if l4_performance_enabled && self.l4.data_updated() {
            stats.replace(self.l4.copy_and_reset_data(flow_reversed));
        }

        if l7_performance_enabled && self.l7.is_some() {
            let self_l7 = self.l7.as_mut().unwrap();
            if self_l7.data_updated() || l7_timeout_count > 0 {
                if let Some(stats) = stats.as_mut() {
                    let FlowPerfStats {
                        l7, l7_protocol, ..
                    } = self_l7.copy_and_reset_data(l7_timeout_count);
                    stats.l7 = l7;
                    stats.l7_protocol = l7_protocol;
                } else {
                    stats.replace(self_l7.copy_and_reset_data(l7_timeout_count));
                }
            }
        }

        stats
    }
}
