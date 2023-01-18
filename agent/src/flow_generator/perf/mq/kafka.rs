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
        protocol_logs::{AppProtoHead, L7ResponseStatus, LogMessageType},
    },
    utils::bytes,
};

pub const PORT: u16 = 9092;

const KAFKA_REMAIN: u32 = 4;
const KAFKA_FETCH: i16 = 1;
const KAFKA_FETCH_STATUS_CODE_OFFSET: usize = 14;
const KAFKA_API_KEY_MASK_VALUE: u64 = 0x7fff000000000000;
const KAFKA_API_KEY_OFFSET: usize = 48;
const KAFKA_REQ_TIMESTAMP_MASK_VALUE: u64 = 0xffffffffffff;

const KAFKA_REQ_HEADER_LEN: usize = 14;
const KAFKA_RESP_HEADER_LEN: usize = 8;

pub struct KafkaPerfData {
    stats: Option<PerfStats>,

    correlation_id: u32,
    api_key: u16,
    status_code: u16,
    status: L7ResponseStatus,

    has_log_data: bool,

    l7_proto: L7Protocol,
    msg_type: LogMessageType,

    rrt_cache: Rc<RefCell<L7RrtCache>>,
}

impl PartialEq for KafkaPerfData {
    fn eq(&self, other: &KafkaPerfData) -> bool {
        self.stats == other.stats
            && self.l7_proto == other.l7_proto
            && self.msg_type == other.msg_type
            && self.correlation_id == other.correlation_id
            && self.api_key == other.api_key
            && self.status_code == other.status_code
            && self.status == other.status
            && self.has_log_data == other.has_log_data
    }
}

impl Eq for KafkaPerfData {}

impl fmt::Debug for KafkaPerfData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(stats) = self.stats.as_ref() {
            write!(f, "status: {:?}", stats)?;
        } else {
            write!(f, "status: None")?;
        };
        write!(f, "l7_proto: {:?}", self.l7_proto)?;
        write!(f, "msg_type: {:?}", self.msg_type)?;

        write!(f, "correlation_id: {:?}", self.correlation_id)?;
        write!(f, "api_key: {:?}", self.api_key)?;
        write!(f, "status_code: {:?}", self.status_code)?;
        write!(f, "status {:?}", self.status)?;
        write!(f, "has_log_data: {:?}", self.has_log_data)
    }
}

impl L7FlowPerf for KafkaPerfData {
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

        match packet.lookup_key.direction {
            PacketDirection::ClientToServer => {
                self.parse_request_header(payload, packet.payload_len)?;
                self.calc_request(packet.lookup_key.timestamp, flow_id);
                self.l7_proto = L7Protocol::Kafka;
                self.has_log_data = true;
                Ok(())
            }
            _ => {
                self.parse_response_header(payload, packet.payload_len)?;
                self.l7_proto = L7Protocol::Kafka;
                self.has_log_data = true;
                if self.calc_response(payload, packet.lookup_key.timestamp, flow_id) {
                    Err(Error::L7ReqNotFound(1))
                } else {
                    Ok(())
                }
            }
        }
    }

    fn copy_and_reset_data(&mut self, timeout_count: u32) -> FlowPerfStats {
        if let Some(stats) = self.stats.take() {
            FlowPerfStats {
                l7_protocol: L7Protocol::Kafka,
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
                l7_protocol: L7Protocol::Kafka,
                l7: L7PerfStats {
                    err_timeout: timeout_count,
                    ..Default::default()
                },
                ..Default::default()
            }
        }
    }

    fn app_proto_head(&mut self) -> Option<(AppProtoHead, u16)> {
        if self.l7_proto != L7Protocol::Kafka || !self.has_log_data {
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

    fn data_updated(&self) -> bool {
        self.stats.is_some()
    }
}

impl KafkaPerfData {
    pub fn new(rrt_cache: Rc<RefCell<L7RrtCache>>) -> Self {
        Self {
            stats: None,
            correlation_id: 0,
            api_key: 0,
            status_code: 0,
            l7_proto: L7Protocol::default(),
            msg_type: LogMessageType::default(),
            status: L7ResponseStatus::default(),
            has_log_data: false,
            rrt_cache: rrt_cache,
        }
    }

    // RequestOrResponse => Size (RequestMessage | ResponseMessage)
    //  message_size => int32
    //  RequestMessage ｜ ResponseMessage
    //
    //  Request Header：
    // RequestMessage => api_key api_version correlation_id client_id
    //  api_key => int16
    //  api_version => int16
    //  correlation_id => int32
    //  client_id => string
    //  MetadataRequest | ProduceRequest | FetchRequest | ListOffsetRequest |......
    fn parse_request_header(&mut self, payload: &[u8], payload_len: u16) -> Result<()> {
        if payload.len() < KAFKA_REQ_HEADER_LEN {
            return Err(Error::KafkaPerfParseFailed);
        }

        let message_size = bytes::read_u32_be(payload);

        if message_size + KAFKA_REMAIN != payload_len as u32 {
            return Err(Error::KafkaPerfParseFailed);
        }
        let client_id_len = bytes::read_u16_be(&payload[12..]) as usize;

        if payload.len() < KAFKA_REQ_HEADER_LEN + client_id_len {
            return Err(Error::KafkaPerfParseFailed);
        }

        self.api_key = bytes::read_u16_be(&payload[4..]);
        self.correlation_id = bytes::read_u32_be(&payload[8..]);
        Ok(())
    }

    // RequestOrResponse => Size (RequestMessage | ResponseMessage)
    //  message_size => int32
    //  RequestMessage ｜ ResponseMessage
    //
    // Reponse Header：
    //  ResponseMessage => correlation_id
    //  correlation_id => int32
    //  MetadataResponse | ProduceResponse | FetchResponse | ListOffsetResponse |......
    fn parse_response_header(&mut self, payload: &[u8], payload_len: u16) -> Result<()> {
        if payload.len() < KAFKA_RESP_HEADER_LEN {
            return Err(Error::KafkaPerfParseFailed);
        }

        let message_size = bytes::read_u32_be(payload);
        if message_size + KAFKA_REMAIN != payload_len as u32 {
            return Err(Error::KafkaPerfParseFailed);
        }

        self.correlation_id = bytes::read_u32_be(&payload[4..]);
        Ok(())
    }

    fn calc_request(&mut self, timestamp: Duration, flow_id: u64) {
        let stats = self.stats.get_or_insert(PerfStats::default());
        stats.rrt_last = Duration::ZERO;
        stats.req_count += 1;

        self.msg_type = LogMessageType::Request;

        self.has_log_data = true;

        let api_key = (self.api_key as u64) << KAFKA_API_KEY_OFFSET;

        let timestamp_nanos = (timestamp.as_nanos() as u64 & KAFKA_REQ_TIMESTAMP_MASK_VALUE)
            | (api_key & KAFKA_API_KEY_MASK_VALUE);

        self.rrt_cache.borrow_mut().add_req_time(
            flow_id,
            Some(self.correlation_id),
            Duration::from_nanos(timestamp_nanos),
        );
    }

    fn calc_response(&mut self, payload: &[u8], timestamp: Duration, flow_id: u64) -> bool {
        self.msg_type = LogMessageType::Response;

        let stats = self.stats.get_or_insert(PerfStats::default());
        stats.resp_count += 1;
        self.has_log_data = true;

        let req_timestmp_nanos = match self
            .rrt_cache
            .borrow_mut()
            .get_and_remove_l7_req_time(flow_id, Some(self.correlation_id))
        {
            Some(t) => t.as_nanos() as u64,
            None => return true,
        };

        let api_key = (req_timestmp_nanos & KAFKA_API_KEY_MASK_VALUE) >> KAFKA_API_KEY_OFFSET;
        // 只支持对fetch命令解析返回码
        if api_key as i16 == KAFKA_FETCH && payload.len() > KAFKA_FETCH_STATUS_CODE_OFFSET {
            self.status_code = bytes::read_u16_be(&payload[12..]);
            if self.status_code == 0 {
                self.status = L7ResponseStatus::Ok;
            } else {
                self.status = L7ResponseStatus::ServerError;
                stats.resp_err_count += 1;
            }
        } else {
            self.status_code = 0;
            self.status = L7ResponseStatus::NotExist;
        }

        if (timestamp.as_nanos() as u64 & KAFKA_REQ_TIMESTAMP_MASK_VALUE)
            < (req_timestmp_nanos & KAFKA_REQ_TIMESTAMP_MASK_VALUE)
        {
            stats.rrt_last = Duration::ZERO;
            return true;
        }

        let rrt = (timestamp.as_nanos() as u64 & KAFKA_REQ_TIMESTAMP_MASK_VALUE)
            - (req_timestmp_nanos & KAFKA_REQ_TIMESTAMP_MASK_VALUE);

        let rrt = Duration::from_nanos(rrt);
        if rrt > stats.rrt_max {
            stats.rrt_max = rrt;
        }
        stats.rrt_last = rrt;
        stats.rrt_sum += rrt;
        stats.rrt_count += 1;
        return false;
    }

    fn reset(&mut self) {
        self.stats = None;
        self.correlation_id = 0;
        self.api_key = 0;
        self.status_code = 0;
        self.l7_proto = L7Protocol::default();
        self.msg_type = LogMessageType::default();
        self.status = L7ResponseStatus::default();
        self.has_log_data = false;
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    use crate::utils::test::Capture;

    const FILE_DIR: &str = "resources/test/flow_generator/kafka";

    fn run(pcap: &str) -> PerfStats {
        let rrt_cache = Rc::new(RefCell::new(L7RrtCache::new(100)));
        let mut kafka_perf_data = KafkaPerfData::new(rrt_cache);

        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(pcap), None);
        let mut packets = capture.as_meta_packets();
        if packets.len() < 2 {
            return kafka_perf_data.stats.unwrap_or_default();
        }

        let first_dst_port = packets[0].lookup_key.dst_port;
        for packet in packets.iter_mut() {
            if packet.lookup_key.dst_port == first_dst_port {
                packet.lookup_key.direction = PacketDirection::ClientToServer;
            } else {
                packet.lookup_key.direction = PacketDirection::ServerToClient;
            }
            let _ = kafka_perf_data.parse(None, packet, 1608373855724393643);
        }
        kafka_perf_data.stats.unwrap_or_default()
    }

    #[test]
    fn check() {
        let expected = vec![
            (
                "kafka.pcap",
                PerfStats {
                    req_count: 1,
                    resp_count: 1,
                    req_err_count: 0,
                    resp_err_count: 0,
                    rrt_count: 1,
                    rrt_max: Duration::from_nanos(4941000),
                    rrt_last: Duration::from_nanos(4941000),
                    rrt_sum: Duration::from_nanos(4941000),
                },
            ),
            (
                "kafka_fetch.pcap",
                PerfStats {
                    req_count: 1,
                    resp_count: 1,
                    req_err_count: 0,
                    resp_err_count: 0,
                    rrt_count: 1,
                    rrt_max: Duration::from_nanos(504829000),
                    rrt_last: Duration::from_nanos(504829000),
                    rrt_sum: Duration::from_nanos(504829000),
                },
            ),
        ];

        for item in expected.iter() {
            assert_eq!(item.1, run(item.0), "parse pcap {} unexcepted", item.0);
        }
    }
}
