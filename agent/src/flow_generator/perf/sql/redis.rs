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

use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;
use std::time::Duration;

use crate::{
    common::{
        enums::IpProtocol,
        flow::{FlowPerfStats, L7PerfStats, L7Protocol, PacketDirection},
        meta_packet::MetaPacket,
    },
    config::handler::LogParserConfig,
    flow_generator::{
        error::{Error, Result},
        perf::l7_rrt::L7RrtCache,
        perf::stats::PerfStats,
        perf::L7FlowPerf,
        protocol_logs::{decode, AppProtoHead, L7ResponseStatus, LogMessageType},
    },
};

pub const PORT: u16 = 6379;

pub struct RedisPerfData {
    pub stats: Option<PerfStats>,
    l7_proto: L7Protocol,
    msg_type: LogMessageType,
    active: u32,
    status: L7ResponseStatus,
    has_log_data: bool,
    rrt_cache: Rc<RefCell<L7RrtCache>>,
}

impl PartialEq for RedisPerfData {
    fn eq(&self, other: &RedisPerfData) -> bool {
        self.stats == other.stats
            && self.l7_proto == other.l7_proto
            && self.msg_type == other.msg_type
            && self.active == other.active
            && self.status == other.status
            && self.has_log_data == other.has_log_data
    }
}

impl Eq for RedisPerfData {}

impl fmt::Debug for RedisPerfData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(stats) = self.stats.as_ref() {
            write!(f, "status: {:?}", stats)?;
        } else {
            write!(f, "status: None")?;
        };
        write!(f, "l7_proto: {:?}", self.l7_proto)?;
        write!(f, "msg_type: {:?}", self.msg_type)?;
        write!(f, "active: {:?}", self.active)?;
        write!(f, "status {:?}", self.status)?;
        write!(f, "has_log_data: {:?}", self.has_log_data)
    }
}

impl L7FlowPerf for RedisPerfData {
    fn parse(
        &mut self,
        _: Option<&LogParserConfig>,
        packet: &MetaPacket,
        flow_id: u64,
    ) -> Result<()> {
        if packet.lookup_key.proto != IpProtocol::Tcp {
            return Err(Error::InvalidIpProtocol);
        }
        let payload = packet.get_l4_payload().ok_or(Error::ZeroPayloadLen)?;

        // 通过Redis请求判断是否为Redis协议
        if self.l7_proto == L7Protocol::Unknown
            && packet.lookup_key.direction == PacketDirection::ServerToClient
        {
            return Err(Error::RedisPerfParseFailed);
        }
        // Redis协议通过Redis请求来识别，对于请求报文格式严格检查，回应有分段的情况不会严格检查
        let (context, _, is_error_resp) = decode(
            payload,
            packet.lookup_key.direction == PacketDirection::ClientToServer,
        )
        .ok_or(Error::RedisPerfParseFailed)?;
        self.l7_proto = L7Protocol::Redis;
        self.has_log_data = true;
        if packet.lookup_key.direction == PacketDirection::ClientToServer {
            self.calc_request(packet.lookup_key.timestamp, flow_id);
        } else if self.calc_response(
            packet.lookup_key.timestamp,
            &context,
            flow_id,
            is_error_resp,
        ) {
            return Err(Error::L7ReqNotFound(1));
        }
        Ok(())
    }

    fn data_updated(&self) -> bool {
        self.stats.is_some()
    }

    fn copy_and_reset_data(&mut self, timeout_count: u32) -> FlowPerfStats {
        if let Some(stats) = self.stats.take() {
            FlowPerfStats {
                l7_protocol: L7Protocol::Redis,
                l7: L7PerfStats {
                    request_count: stats.req_count,
                    response_count: stats.resp_count,
                    rrt_count: stats.rrt_count,
                    rrt_sum: stats.rrt_sum.as_micros() as u64,
                    rrt_max: stats.rrt_max.as_micros() as u32,
                    err_client_count: stats.req_err_count,
                    err_server_count: stats.resp_err_count,
                    err_timeout: timeout_count,
                },
                ..Default::default()
            }
        } else {
            FlowPerfStats {
                l7_protocol: L7Protocol::Redis,
                l7: L7PerfStats {
                    err_timeout: timeout_count,
                    ..Default::default()
                },
                ..Default::default()
            }
        }
    }

    fn app_proto_head(&mut self) -> Option<(AppProtoHead, u16)> {
        if self.l7_proto != L7Protocol::Redis || !self.has_log_data {
            return None;
        }
        self.has_log_data = false;

        let rrt = self
            .stats
            .as_ref()
            .map(|s| s.rrt_last.as_micros() as u64)
            .unwrap_or_default();
        Some((
            AppProtoHead {
                proto: self.l7_proto,
                msg_type: self.msg_type,
                rrt: rrt,
            },
            0,
        ))
    }
}

impl RedisPerfData {
    pub fn new(rrt_cache: Rc<RefCell<L7RrtCache>>) -> Self {
        Self {
            stats: None,
            l7_proto: L7Protocol::default(),
            msg_type: LogMessageType::default(),
            active: 0,
            status: L7ResponseStatus::default(),
            has_log_data: false,
            rrt_cache: rrt_cache,
        }
    }

    fn calc_request(&mut self, timestamp: Duration, flow_id: u64) {
        let stats = self.stats.get_or_insert(PerfStats::default());
        stats.rrt_last = Duration::ZERO;
        stats.req_count += 1;
        self.active += 1;
        self.msg_type = LogMessageType::Request;
        self.rrt_cache
            .borrow_mut()
            .add_req_time(flow_id, None, timestamp);
    }

    // 返回是否无法匹配到request
    fn calc_response(
        &mut self,
        timestamp: Duration,
        context: &Vec<u8>,
        flow_id: u64,
        is_error_resp: bool,
    ) -> bool {
        let stats = self.stats.get_or_insert(PerfStats::default());
        stats.resp_count += 1;
        self.msg_type = LogMessageType::Response;
        if context.len() > 1 && context[0] == b'-' && is_error_resp {
            stats.resp_err_count += 1;
            self.status = L7ResponseStatus::ServerError;
        } else {
            self.status = L7ResponseStatus::Ok;
        }
        stats.rrt_last = Duration::ZERO;

        if self.active <= 0 {
            return true;
        }
        let req_timestamp = match self
            .rrt_cache
            .borrow_mut()
            .get_and_remove_l7_req_time(flow_id, None)
        {
            Some(t) => t,
            None => return true,
        };

        self.active -= 1;
        if timestamp < req_timestamp {
            return false;
        }
        let rrt = timestamp - req_timestamp;
        if rrt > stats.rrt_max {
            stats.rrt_max = rrt;
        }
        stats.rrt_last = rrt;
        stats.rrt_sum += rrt;
        stats.rrt_count += 1;
        false
    }

    fn reset(&mut self) {
        self.stats = None;
        self.l7_proto = L7Protocol::default();
        self.msg_type = LogMessageType::default();
        self.active = 0;
        self.status = L7ResponseStatus::default();
        self.has_log_data = false;
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    use crate::utils::test::Capture;

    const FILE_DIR: &str = "resources/test/flow_generator/redis";

    fn run(pcap: &str) -> RedisPerfData {
        let rrt_cache = Rc::new(RefCell::new(L7RrtCache::new(100)));
        let mut redis_perf_data = RedisPerfData::new(rrt_cache);

        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(pcap), None);
        let mut packets = capture.as_meta_packets();
        if packets.len() < 2 {
            return redis_perf_data;
        }

        let first_dst_port = packets[0].lookup_key.dst_port;
        for packet in packets.iter_mut() {
            if packet.lookup_key.dst_port == first_dst_port {
                packet.lookup_key.direction = PacketDirection::ClientToServer;
            } else {
                packet.lookup_key.direction = PacketDirection::ServerToClient;
            }
            let _ = redis_perf_data.parse(None, packet, 0x1f3c01010);
        }
        redis_perf_data
    }

    #[test]
    fn check() {
        let expected = vec![
            (
                "redis.pcap",
                RedisPerfData {
                    stats: Some(PerfStats {
                        req_count: 10,
                        resp_count: 11,
                        req_err_count: 0,
                        resp_err_count: 1,
                        rrt_count: 10,
                        rrt_max: Duration::from_nanos(96000),
                        rrt_last: Duration::ZERO,
                        rrt_sum: Duration::from_nanos(592000),
                    }),
                    l7_proto: L7Protocol::Redis,
                    status: L7ResponseStatus::ServerError,
                    active: 0,
                    has_log_data: true,
                    msg_type: LogMessageType::Response,
                    rrt_cache: Rc::new(RefCell::new(L7RrtCache::new(100))),
                },
            ),
            (
                "redis-error.pcap",
                RedisPerfData {
                    stats: Some(PerfStats {
                        req_count: 1,
                        resp_count: 1,
                        req_err_count: 0,
                        resp_err_count: 1,
                        rrt_count: 1,
                        rrt_max: Duration::from_nanos(73000),
                        rrt_last: Duration::from_nanos(73000),
                        rrt_sum: Duration::from_nanos(73000),
                    }),
                    l7_proto: L7Protocol::Redis,
                    active: 0,
                    status: L7ResponseStatus::ServerError,
                    has_log_data: true,
                    msg_type: LogMessageType::Response,
                    rrt_cache: Rc::new(RefCell::new(L7RrtCache::new(100))),
                },
            ),
            (
                "redis-debug.pcap",
                RedisPerfData {
                    stats: Some(PerfStats {
                        req_count: 1,
                        resp_count: 1,
                        req_err_count: 0,
                        resp_err_count: 0,
                        rrt_count: 1,
                        rrt_max: Duration::from_nanos(1209000),
                        rrt_last: Duration::from_nanos(1209000),
                        rrt_sum: Duration::from_nanos(1209000),
                    }),
                    l7_proto: L7Protocol::Redis,
                    active: 0,
                    status: L7ResponseStatus::Ok,
                    has_log_data: true,
                    msg_type: LogMessageType::Response,
                    rrt_cache: Rc::new(RefCell::new(L7RrtCache::new(100))),
                },
            ),
        ];

        for item in expected.iter() {
            assert_eq!(item.1, run(item.0), "parse pcap {} unexcepted", item.0);
        }
    }
}
