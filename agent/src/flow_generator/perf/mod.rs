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
use super::protocol_logs::AppProtoHead;

use crate::common::{
    enums::IpProtocol,
    flow::{FlowPerfStats, L4Protocol, L7Protocol},
    meta_packet::MetaPacket,
};

use super::protocol_logs::{
    dns_check_protocol, dubbo_check_protocol, http1_check_protocol, http2_check_protocol,
    kafka_check_protocol, mqtt_check_protocol, mysql_check_protocol, redis_check_protocol,
};
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
}

pub struct FlowPerf {
    l4: L4FlowPerfTable,
    l7: Option<L7FlowPerfTable>,

    rrt_cache: Rc<RefCell<L7RrtCache>>,

    protocol_bitmap: u128,
    l7_protocol: L7Protocol,

    is_from_app: bool,
    is_success: bool,
    is_skip: bool,
}

impl FlowPerf {
    const PROTOCOL_CHECK_LIMIT: usize = 5;

    fn l7_new(protocol: L7Protocol, rrt_cache: Rc<RefCell<L7RrtCache>>) -> Option<L7FlowPerfTable> {
        match protocol {
            L7Protocol::Dns => Some(L7FlowPerfTable::from(DnsPerfData::new(rrt_cache.clone()))),
            L7Protocol::Dubbo => Some(L7FlowPerfTable::from(DubboPerfData::new(rrt_cache.clone()))),
            L7Protocol::Kafka => Some(L7FlowPerfTable::from(KafkaPerfData::new(rrt_cache.clone()))),
            L7Protocol::Mqtt => Some(L7FlowPerfTable::from(MqttPerfData::new(rrt_cache.clone()))),
            L7Protocol::Mysql => Some(L7FlowPerfTable::from(MysqlPerfData::new(rrt_cache.clone()))),
            L7Protocol::Redis => Some(L7FlowPerfTable::from(RedisPerfData::new(rrt_cache.clone()))),
            L7Protocol::Http1 | L7Protocol::Http2 => {
                Some(L7FlowPerfTable::from(HttpPerfData::new(rrt_cache.clone())))
            }
            _ => None,
        }
    }

    fn _l7_check(&mut self, protocol: L7Protocol, packet: &MetaPacket) -> bool {
        match protocol {
            L7Protocol::Dns => dns_check_protocol(&mut self.protocol_bitmap, packet),
            L7Protocol::Dubbo => dubbo_check_protocol(&mut self.protocol_bitmap, packet),
            L7Protocol::Kafka => kafka_check_protocol(&mut self.protocol_bitmap, packet),
            L7Protocol::Mqtt => mqtt_check_protocol(&mut self.protocol_bitmap, packet),
            L7Protocol::Mysql => mysql_check_protocol(&mut self.protocol_bitmap, packet),
            L7Protocol::Redis => redis_check_protocol(&mut self.protocol_bitmap, packet),
            L7Protocol::Http1 => http1_check_protocol(&mut self.protocol_bitmap, packet),
            L7Protocol::Http2 => http2_check_protocol(&mut self.protocol_bitmap, packet),
            _ => false,
        }
    }

    fn _l7_parse(
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

    fn l7_check(
        &mut self,
        packet: &MetaPacket,
        flow_id: u64,
        app_table: &mut AppTable,
    ) -> Result<()> {
        if self.is_skip {
            return Err(Error::L7ProtocolCheckLimit);
        }

        let protocols = if packet.lookup_key.proto == IpProtocol::Tcp {
            vec![
                L7Protocol::Http1,
                L7Protocol::Http2,
                L7Protocol::Dubbo,
                L7Protocol::Mysql,
                L7Protocol::Redis,
                L7Protocol::Kafka,
                L7Protocol::Mqtt,
                L7Protocol::Dns,
            ]
        } else {
            vec![L7Protocol::Dns]
        };

        for i in protocols {
            if self.protocol_bitmap & 1 << (i as u8) == 0 {
                continue;
            }
            if self._l7_check(i, packet) {
                self.l7_protocol = i;
                self.l7 = Self::l7_new(i, self.rrt_cache.clone());
                return self._l7_parse(packet, flow_id, app_table);
            }
        }
        self.is_skip = app_table.set_protocol(packet, L7Protocol::Unknown);

        Err(Error::L7ProtocolUnknown)
    }

    fn l7_parse(
        &mut self,
        packet: &MetaPacket,
        flow_id: u64,
        app_table: &mut AppTable,
    ) -> Result<()> {
        if self.l7.is_some() {
            return self._l7_parse(packet, flow_id, app_table);
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
        counter: Arc<FlowPerfCounter>,
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
            protocol_bitmap: if l4_proto == L4Protocol::Tcp {
                1 << (L7Protocol::Http1 as u8)
                    | 1 << (L7Protocol::Http2 as u8)
                    | 1 << (L7Protocol::Dns as u8)
                    | 1 << (L7Protocol::Mysql as u8)
                    | 1 << (L7Protocol::Redis as u8)
                    | 1 << (L7Protocol::Dubbo as u8)
                    | 1 << (L7Protocol::Kafka as u8)
                    | 1 << (L7Protocol::Mqtt as u8)
            } else {
                1 << (L7Protocol::Dns as u8)
            },
            rrt_cache,
            l7_protocol,
            is_from_app: l7_proto.is_some(),
            is_success: false,
            is_skip: false,
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
    ) -> Result<()> {
        if l4_performance_enabled {
            self.l4.parse(packet, is_first_packet_direction)?;
        }
        if l7_performance_enabled {
            // 抛出错误由flowMap.FlowPerfCounter处理
            self.l7_parse(packet, flow_id, app_table)?;
        }
        Ok(())
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

    pub fn app_proto_head(&mut self, l7_performance_enabled: bool) -> Option<(AppProtoHead, u16)> {
        if !l7_performance_enabled {
            return None;
        }
        if let Some(l7) = self.l7.as_mut() {
            l7.app_proto_head()
        } else {
            None
        }
    }
}
