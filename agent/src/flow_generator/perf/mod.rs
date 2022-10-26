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
mod http;
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

use enum_dispatch::enum_dispatch;

use super::app_table::AppTable;
use super::error::{Error, Result};
use super::protocol_logs::{AppProtoHead, PostgresqlLog};

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
}

pub struct FlowPerf {
    l4: L4FlowPerfTable,
    l7: Option<L7FlowPerfTable>,

    // perf 目前还没有抽象出来,自定义协议需要添加字段区分,以后抽出来后 l7可以去掉.
    l7_protocol_log_parser: Option<L7ProtocolParser>,

    rrt_cache: Rc<RefCell<L7RrtCache>>,

    protocol_bitmap: L7ProtocolBitmap,
    l7_protocol: L7Protocol,

    is_from_app: bool,
    is_success: bool,
    is_skip: bool,

    parse_config: LogParserAccess,
}

impl FlowPerf {
    const PROTOCOL_CHECK_LIMIT: usize = 5;

    fn l7_new(protocol: L7Protocol, rrt_cache: Rc<RefCell<L7RrtCache>>) -> Option<L7FlowPerfTable> {
        match protocol {
            L7Protocol::DNS => Some(L7FlowPerfTable::from(DnsPerfData::new(rrt_cache.clone()))),
            L7Protocol::Dubbo => Some(L7FlowPerfTable::from(DubboPerfData::new(rrt_cache.clone()))),
            L7Protocol::Kafka => Some(L7FlowPerfTable::from(KafkaPerfData::new(rrt_cache.clone()))),
            L7Protocol::MQTT => Some(L7FlowPerfTable::from(MqttPerfData::new(rrt_cache.clone()))),
            L7Protocol::MySQL => Some(L7FlowPerfTable::from(MysqlPerfData::new(rrt_cache.clone()))),
            L7Protocol::PostgreSQL => Some(L7FlowPerfTable::from(PostgresqlLog::new())),
            L7Protocol::Redis => Some(L7FlowPerfTable::from(RedisPerfData::new(rrt_cache.clone()))),
            L7Protocol::Http1 | L7Protocol::Http2 => {
                Some(L7FlowPerfTable::from(HttpPerfData::new(rrt_cache.clone())))
            }
            _ => None,
        }
    }

    fn l7_parse_perf(
        &mut self,
        packet: &MetaPacket,
        flow_id: u64,
        app_table: &mut AppTable,
    ) -> Result<()> {
        if self.is_skip {
            return Err(Error::L7ProtocolParseLimit);
        }

        let ret = self.l7.as_mut().unwrap().parse(packet, flow_id);
        if !self.is_success {
            if ret.is_ok() {
                app_table.set_protocol(packet, self.l7_protocol);
                self.is_success = true;
            } else {
                self.is_skip = app_table.set_protocol(packet, L7Protocol::Unknown);
            }
        }
        return ret;
    }

    fn l7_parse_log(
        &mut self,
        packet: &MetaPacket,
        app_table: &mut AppTable,
        parse_param: &ParseParam,
    ) -> Result<Vec<L7ProtocolInfo>> {
        if self.is_skip {
            return Err(Error::L7ProtocolParseLimit);
        }

        if let Some(payload) = packet.get_l4_payload() {
            let parser = self.l7_protocol_log_parser.as_mut().unwrap();
            parser.set_parse_config(&self.parse_config);
            let ret = parser.parse_payload(payload, parse_param);
            parser.reset();

            if !self.is_success {
                if ret.is_ok() {
                    app_table.set_protocol(packet, self.l7_protocol);
                    self.is_success = true;
                } else {
                    self.is_skip = app_table.set_protocol(packet, L7Protocol::Unknown);
                }
            }
            return ret;
        }

        return Err(Error::L7ProtocolUnknown);
    }

    fn l7_check(
        &mut self,
        packet: &MetaPacket,
        flow_id: u64,
        app_table: &mut AppTable,
    ) -> Result<Vec<L7ProtocolInfo>> {
        if self.is_skip {
            return Err(Error::L7ProtocolCheckLimit);
        }

        if let Some(payload) = packet.get_l4_payload() {
            let param = ParseParam::from(packet);
            for mut i in get_all_protocol() {
                if self.protocol_bitmap.is_disabled(i.protocol()) {
                    continue;
                }
                if i.check_payload(payload, &param) {
                    self.l7_protocol = i.protocol();
                    // perf 没有抽象出来,这里可能返回None，对于返回None即不解析perf，只解析log
                    self.l7 = Self::l7_new(i.protocol(), self.rrt_cache.clone());
                    if self.l7.is_some() {
                        self.l7_parse_perf(packet, flow_id, app_table)?;
                    }

                    self.l7_protocol_log_parser = Some(i);
                    return self.l7_parse_log(packet, app_table, &param);
                }
            }

            self.is_skip = app_table.set_protocol(packet, L7Protocol::Unknown);
        }

        return Err(Error::L7ProtocolUnknown);
    }

    fn l7_parse(
        &mut self,
        packet: &MetaPacket,
        flow_id: u64,
        app_table: &mut AppTable,
    ) -> Result<Vec<L7ProtocolInfo>> {
        if self.l7.is_some() {
            self.l7_parse_perf(packet, flow_id, app_table)?;
        }

        if self.l7_protocol_log_parser.is_some() {
            return self.l7_parse_log(packet, app_table, &ParseParam::from(packet));
        }

        if self.is_from_app {
            return Err(Error::L7ProtocolUnknown);
        }

        if packet.l4_payload_len() < 2 {
            return Err(Error::L7ProtocolUnknown);
        }

        return self.l7_check(packet, flow_id, app_table);
    }

    pub fn new(
        rrt_cache: Rc<RefCell<L7RrtCache>>,
        l4_proto: L4Protocol,
        l7_proto: Option<L7Protocol>,
        l7_parser: Option<L7ProtocolParser>,
        counter: Arc<FlowPerfCounter>,
        l7_prorocol_enable_bitmap: L7ProtocolBitmap,
        parse_config: LogParserAccess,
    ) -> Option<Self> {
        let l4 = match l4_proto {
            L4Protocol::Tcp => L4FlowPerfTable::from(TcpPerf::new(counter)),
            L4Protocol::Udp => L4FlowPerfTable::from(UdpPerf::new()),
            _ => {
                return None;
            }
        };

        let l7_protocol = l7_proto.unwrap_or(L7Protocol::Unknown);

        Some(Self {
            l4,
            l7: Self::l7_new(l7_protocol, rrt_cache.clone()),
            protocol_bitmap: {
                match l4_proto {
                    L4Protocol::Tcp => get_parse_bitmap(IpProtocol::Tcp, l7_prorocol_enable_bitmap),
                    _ => get_parse_bitmap(IpProtocol::Udp, l7_prorocol_enable_bitmap),
                }
            },
            l7_protocol_log_parser: l7_parser,
            rrt_cache,
            l7_protocol,
            is_from_app: l7_proto.is_some(),
            is_success: false,
            is_skip: false,
            parse_config,
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
        packet: &MetaPacket,
        is_first_packet_direction: bool,
        flow_id: u64,
        l4_performance_enabled: bool,
        l7_performance_enabled: bool,
        app_table: &mut AppTable,
    ) -> Result<Vec<L7ProtocolInfo>> {
        if l4_performance_enabled {
            self.l4.parse(packet, is_first_packet_direction)?;
        }
        if l7_performance_enabled {
            // 抛出错误由flowMap.FlowPerfCounter处理
            return self.l7_parse(packet, flow_id, app_table);
        }
        Ok(vec![])
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
