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
use log::debug;

use super::error::Result;
use super::protocol_logs::AppProtoHead;

use crate::common::{
    flow::{FlowPerfStats, L4Protocol, L7Protocol},
    meta_packet::MetaPacket,
};

use {
    self::http::HttpPerfData,
    dns::{DnsPerfData, DNS_PORT},
    mq::{KafkaPerfData, KAFKA_PORT},
    rpc::DubboPerfData,
    sql::{MysqlPerfData, RedisPerfData, MYSQL_PORT, REDIS_PORT},
    tcp::TcpPerf,
    udp::UdpPerf,
};

pub use l7_rrt::L7RrtCache;
pub use rpc::DUBBO_PORT;
pub use stats::FlowPerfCounter;

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
    RedisPerfData,
    DubboPerfData,
    MysqlPerfData,
    HttpPerfData,
}

pub struct FlowPerf {
    l4: L4FlowPerfTable,
    l7: L7FlowPerfTable,

    pub is_http: bool,
}

impl FlowPerf {
    pub fn new(
        rrt_cache: Rc<RefCell<L7RrtCache>>,
        l4_proto: L4Protocol,
        l7_proto: L7Protocol,
        counter: Arc<FlowPerfCounter>,
    ) -> Option<Self> {
        let l4 = match l4_proto {
            L4Protocol::Tcp => L4FlowPerfTable::from(TcpPerf::new(counter)),
            L4Protocol::Udp => L4FlowPerfTable::from(UdpPerf::new()),
            _ => {
                return None;
            }
        };
        let mut is_http = false;
        let l7 = match l7_proto {
            L7Protocol::Dns => L7FlowPerfTable::from(DnsPerfData::new(rrt_cache.clone())),
            L7Protocol::Dubbo => L7FlowPerfTable::from(DubboPerfData::new(rrt_cache.clone())),
            L7Protocol::Kafka => L7FlowPerfTable::from(KafkaPerfData::new(rrt_cache.clone())),
            L7Protocol::Mysql => L7FlowPerfTable::from(MysqlPerfData::new(rrt_cache.clone())),
            L7Protocol::Redis => L7FlowPerfTable::from(RedisPerfData::new(rrt_cache.clone())),
            L7Protocol::Http1 | L7Protocol::Http2 => {
                is_http = true;
                L7FlowPerfTable::from(HttpPerfData::new(rrt_cache.clone()))
            }
            _ => return None,
        };

        Some(Self { l4, l7, is_http })
    }

    pub fn parse_by_http(
        &mut self,
        rrt_cache: Rc<RefCell<L7RrtCache>>,
        packet: &MetaPacket,
        flow_id: u64,
    ) {
        debug!("change to http");
        self.l7 = L7FlowPerfTable::from(HttpPerfData::new(rrt_cache.clone()));
        self.is_http = true;
        let _ = self.l7.parse(packet, flow_id);
    }

    pub fn parse(
        &mut self,
        packet: &MetaPacket,
        is_first_packet_direction: bool,
        flow_id: u64,
        l4_performance_enabled: bool,
        l7_performance_enabled: bool,
    ) -> Result<()> {
        if l4_performance_enabled {
            self.l4.parse(packet, is_first_packet_direction)?;
        }
        if l7_performance_enabled {
            // 抛出错误由flowMap.FlowPerfCounter处理
            self.l7.parse(packet, flow_id)?;
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

        if l7_performance_enabled && self.l7.data_updated() {
            if let Some(stats) = stats.as_mut() {
                let FlowPerfStats {
                    l7, l7_protocol, ..
                } = self.l7.copy_and_reset_data(l7_timeout_count);
                stats.l7 = l7;
                stats.l7_protocol = l7_protocol;
            } else {
                stats.replace(self.l7.copy_and_reset_data(l7_timeout_count));
            }
        }

        stats
    }

    pub fn app_proto_head(&mut self, l7_performance_enabled: bool) -> Option<(AppProtoHead, u16)> {
        if !l7_performance_enabled {
            return None;
        }
        self.l7.app_proto_head()
    }
}

pub fn get_l7_protocol(src_port: u16, dst_port: u16, l7_performance_enabled: bool) -> L7Protocol {
    if !l7_performance_enabled {
        return L7Protocol::Unknown;
    }

    if src_port == DNS_PORT || dst_port == DNS_PORT {
        return L7Protocol::Dns;
    }

    if src_port == MYSQL_PORT || dst_port == MYSQL_PORT {
        return L7Protocol::Mysql;
    }

    if src_port == REDIS_PORT || dst_port == REDIS_PORT {
        return L7Protocol::Redis;
    }

    if src_port == DUBBO_PORT || dst_port == DUBBO_PORT {
        return L7Protocol::Dubbo;
    }

    if src_port == KAFKA_PORT || dst_port == KAFKA_PORT {
        return L7Protocol::Kafka;
    }

    L7Protocol::Http1
}
