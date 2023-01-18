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
        flow::{FlowPerfStats, L7PerfStats, L7Protocol},
        meta_packet::MetaPacket,
    },
    config::handler::LogParserConfig,
    flow_generator::{
        error::{Error, Result},
        perf::l7_rrt::L7RrtCache,
        perf::stats::PerfStats,
        perf::L7FlowPerf,
        protocol_logs::{consts::*, AppProtoHead, L7ResponseStatus, LogMessageType, MysqlHeader},
    },
    utils::bytes,
};

pub const PORT: u16 = 3306;

pub struct MysqlPerfData {
    pub stats: Option<PerfStats>,

    l7_proto: L7Protocol,
    msg_type: LogMessageType,

    active: isize,
    status: L7ResponseStatus,
    has_log_data: bool,
    decode_response: bool,
    has_response: bool,
    rrt_cache: Rc<RefCell<L7RrtCache>>,
}

impl PartialEq for MysqlPerfData {
    fn eq(&self, other: &MysqlPerfData) -> bool {
        self.stats == other.stats
            && self.l7_proto == other.l7_proto
            && self.msg_type == other.msg_type
            && self.active == other.active
            && self.status == other.status
            && self.has_log_data == other.has_log_data
            && self.decode_response == other.decode_response
    }
}

impl Eq for MysqlPerfData {}

impl fmt::Debug for MysqlPerfData {
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
        write!(f, "has_log_data: {:?}", self.has_log_data)?;
        write!(f, "decode_response: {:?}", self.decode_response)
    }
}

// 参考来自: https://www.cnblogs.com/niuben/p/12423717.html
// 客户端错误从2000开始到2999，其他为服务端错误
const CLIENT_ERROR_MIN: u16 = 2000;
const CLIENT_ERROR_MAX: u16 = 2999;

impl L7FlowPerf for MysqlPerfData {
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

        let mut header = MysqlHeader::default();
        let offset = header.decode(payload);
        if offset < 0 {
            return Err(Error::MysqlPerfParseFailed);
        }
        let offset = offset as usize;
        let msg_type = header
            .check(packet.lookup_key.direction, offset, payload, self.l7_proto)
            .ok_or(Error::MysqlPerfParseFailed)?;

        match msg_type {
            LogMessageType::Request => {
                self.parse_request(packet.lookup_key.timestamp, flow_id);
                self.l7_proto = L7Protocol::MySQL;
                self.decode_response = true;
                self.has_response = false;
                Ok(())
            }
            LogMessageType::Response
                if !self.has_response
                    && self.decode_response
                    && self.l7_proto == L7Protocol::MySQL =>
            {
                self.has_response = true;
                if self.parse_response(packet.lookup_key.timestamp, flow_id, &payload[offset..]) {
                    Err(Error::L7ReqNotFound(1))
                } else {
                    Ok(())
                }
            }
            LogMessageType::Other => {
                // 在建立连接后，MySQL服务端会首先将自身的信息封装到Greeting中发送给客户端，客户端接受后发送登录请求报文,
                // 若认证插件和用户名密码正确后，服务端发送OK报文；如果在登录请求报文中的认证插件和服务端支持的不一致时，
                // 服务端在收到登录请求报文后会发送Auth Switch请求报文，客户端接收到后会重新将信息封装在Auth Switch响应报
                // 文中发送给服务端，服务端验证成功后，服务端发送OK报文。

                // 其中若服务端发送Auth Switch请求，客户端发送Auth Switch响应和其他请求响应方向相反，而且实际内容意义不大
                // 所以代码中会将Greeting后的Auth Switch请求响应报文忽略掉。

                // Greeting一定是第一个包，通过Greeting来判断流是否为MYSQL
                self.l7_proto = L7Protocol::MySQL;
                self.msg_type = LogMessageType::Other;
                let _ = self.stats.get_or_insert(PerfStats::default());
                self.has_log_data = true;
                self.decode_response = false;
                Ok(())
            }
            _ => Ok(()),
        }
    }
    fn data_updated(&self) -> bool {
        self.stats.is_some()
    }

    fn copy_and_reset_data(&mut self, timeout_count: u32) -> FlowPerfStats {
        if let Some(stats) = self.stats.take() {
            FlowPerfStats {
                l7_protocol: L7Protocol::MySQL,
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
                l7_protocol: L7Protocol::MySQL,
                l7: L7PerfStats {
                    err_timeout: timeout_count,
                    ..Default::default()
                },
                ..Default::default()
            }
        }
    }

    fn app_proto_head(&mut self) -> Option<(AppProtoHead, u16)> {
        if self.l7_proto != L7Protocol::MySQL || !self.has_log_data {
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

impl MysqlPerfData {
    pub fn new(rrt_cache: Rc<RefCell<L7RrtCache>>) -> Self {
        Self {
            stats: None,
            l7_proto: L7Protocol::default(),
            msg_type: LogMessageType::default(),
            active: 0,
            status: L7ResponseStatus::default(),
            has_log_data: false,
            decode_response: false,
            has_response: false,
            rrt_cache: rrt_cache,
        }
    }

    fn calc_request(&mut self, timestamp: Duration, flow_id: u64) {
        let stats = self.stats.get_or_insert(PerfStats::default());
        stats.req_count += 1;
        self.active += 1;
        stats.rrt_last = Duration::ZERO;
        self.rrt_cache
            .borrow_mut()
            .add_req_time(flow_id, None, timestamp);
    }

    fn calc_response(&mut self, timestamp: Duration, flow_id: u64, error_code: u16) -> bool {
        let stats = self.stats.get_or_insert(PerfStats::default());
        stats.resp_count += 1;

        self.status = match error_code {
            0 => L7ResponseStatus::Ok,
            CLIENT_ERROR_MIN..=CLIENT_ERROR_MAX => {
                stats.req_err_count += 1;
                L7ResponseStatus::ClientError
            }
            _ => {
                stats.resp_err_count += 1;
                L7ResponseStatus::ServerError
            }
        };

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

    fn parse_request(&mut self, timestamp: Duration, flow_id: u64) {
        self.msg_type = LogMessageType::Request;
        self.has_log_data = true;
        self.calc_request(timestamp, flow_id);
    }

    // MySQL通过Greeting报文判断该流是否为MySQL
    fn parse_response(&mut self, timestamp: Duration, flow_id: u64, payload: &[u8]) -> bool {
        self.msg_type = LogMessageType::Response;
        self.has_log_data = true;
        let error_code: u16 = if payload[RESPONSE_CODE_OFFSET] == MYSQL_RESPONSE_CODE_ERR
            && payload.len() >= ERROR_CODE_OFFSET + 2
        {
            bytes::read_u16_le(&payload[ERROR_CODE_OFFSET..])
        } else {
            0
        };
        self.calc_response(timestamp, flow_id, error_code)
    }
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use super::*;

    use crate::{common::flow::PacketDirection, utils::test::Capture};

    const FILE_DIR: &str = "resources/test/flow_generator/mysql";

    fn run(pcap: &str) -> MysqlPerfData {
        let rrt_cache = Rc::new(RefCell::new(L7RrtCache::new(100)));
        let mut perf_data = MysqlPerfData::new(rrt_cache);

        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(pcap), Some(1400));
        let mut packets = capture.as_meta_packets();

        let first_src_mac = packets[0].lookup_key.src_mac;
        for packet in packets.iter_mut() {
            if packet.lookup_key.src_mac == first_src_mac {
                packet.lookup_key.direction = PacketDirection::ClientToServer;
            } else {
                packet.lookup_key.direction = PacketDirection::ServerToClient;
            }
            let _ = perf_data.parse(None, packet, 0x1f3c01010);
        }
        perf_data
    }

    #[test]
    fn check() {
        let expecteds = vec![
            (
                "mysql.pcap",
                MysqlPerfData {
                    stats: Some(PerfStats {
                        req_count: 6,
                        resp_count: 5,
                        req_err_count: 0,
                        resp_err_count: 0,
                        rrt_count: 5,
                        rrt_max: Duration::from_nanos(123000),
                        rrt_sum: Duration::from_nanos(373000),
                        rrt_last: Duration::ZERO,
                    }),
                    l7_proto: L7Protocol::MySQL,
                    msg_type: LogMessageType::Request,
                    active: 1,
                    status: L7ResponseStatus::Ok,
                    has_log_data: true,
                    decode_response: true,
                    has_response: true,
                    rrt_cache: Rc::new(RefCell::new(L7RrtCache::new(100))),
                },
            ),
            (
                "mysql-error.pcap",
                MysqlPerfData {
                    stats: Some(PerfStats {
                        req_count: 4,
                        resp_count: 3,
                        req_err_count: 0,
                        resp_err_count: 1,
                        rrt_count: 3,
                        rrt_max: Duration::from_nanos(146000),
                        rrt_sum: Duration::from_nanos(226000),
                        rrt_last: Duration::ZERO,
                    }),
                    l7_proto: L7Protocol::MySQL,
                    msg_type: LogMessageType::Request,
                    active: 1,
                    status: L7ResponseStatus::ServerError,
                    has_log_data: true,
                    decode_response: true,
                    has_response: true,
                    rrt_cache: Rc::new(RefCell::new(L7RrtCache::new(100))),
                },
            ),
            (
                "171-mysql.pcap",
                MysqlPerfData {
                    stats: Some(PerfStats {
                        req_count: 390,
                        resp_count: 390,
                        req_err_count: 0,
                        resp_err_count: 0,
                        rrt_count: 390,
                        rrt_max: Duration::from_nanos(5355000),
                        rrt_sum: Duration::from_nanos(127090000),
                        rrt_last: Duration::from_nanos(692000),
                    }),
                    l7_proto: L7Protocol::MySQL,
                    msg_type: LogMessageType::Response,
                    active: 0,
                    status: L7ResponseStatus::Ok,
                    has_log_data: true,
                    decode_response: true,
                    has_response: false,
                    rrt_cache: Rc::new(RefCell::new(L7RrtCache::new(100))),
                },
            ),
        ];

        for item in expecteds.iter() {
            assert_eq!(item.1, run(item.0), "pcap {} check failed", item.0);
        }
    }
}
