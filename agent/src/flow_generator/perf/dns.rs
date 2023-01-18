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

use super::super::protocol_logs::{consts::*, AppProtoHead, L7ResponseStatus, LogMessageType};
use super::{stats::PerfStats, L7FlowPerf, L7RrtCache};

use crate::{
    common::{
        enums::IpProtocol,
        flow::{FlowPerfStats, L7PerfStats, L7Protocol},
        meta_packet::MetaPacket,
    },
    config::handler::LogParserConfig,
    flow_generator::error::{Error, Result},
    utils::bytes::{read_u16_be, read_u16_le},
};

pub const DNS_PORT: u16 = 53;

#[derive(Clone)]
struct DnsSessionData {
    pub id: u16,
    pub status_code: u8,
    pub status: L7ResponseStatus,
    pub has_log_data: bool,

    pub l7_proto: L7Protocol,
    pub msg_type: LogMessageType,
    rrt_cache: Rc<RefCell<L7RrtCache>>,
}

pub struct DnsPerfData {
    perf_stats: Option<PerfStats>,
    session_data: DnsSessionData,
}

impl Eq for DnsPerfData {}

impl PartialEq for DnsPerfData {
    fn eq(&self, other: &DnsPerfData) -> bool {
        self.perf_stats == other.perf_stats
            && self.session_data.l7_proto == other.session_data.l7_proto
            && self.session_data.msg_type == other.session_data.msg_type
            && self.session_data.status == other.session_data.status
            && self.session_data.has_log_data == other.session_data.has_log_data
    }
}

impl fmt::Debug for DnsPerfData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(perf_stats) = self.perf_stats.as_ref() {
            write!(f, "perf_stats: {:?}", perf_stats)?;
        } else {
            write!(f, "perf_stats: None")?;
        };
        write!(f, "l7_proto: {:?}", self.session_data.l7_proto)?;
        write!(f, "msg_type: {:?}", self.session_data.msg_type)?;
        write!(f, "status {:?}", self.session_data.status)?;
        write!(f, "has_log_data: {:?}", self.session_data.has_log_data)
    }
}

impl L7FlowPerf for DnsPerfData {
    fn parse(
        &mut self,
        _: Option<&LogParserConfig>,
        packet: &MetaPacket,
        flow_id: u64,
    ) -> Result<()> {
        let payload = packet.get_l4_payload().ok_or(Error::ZeroPayloadLen)?;

        match packet.lookup_key.proto {
            IpProtocol::Udp => {
                self.decode_payload(payload, packet.lookup_key.timestamp, flow_id)?;
            }
            IpProtocol::Tcp => {
                if payload.len() <= DNS_TCP_PAYLOAD_OFFSET {
                    return Err(Error::DNSPerfParseFailed("dns payload length error"));
                }

                let size = read_u16_be(payload) as usize;
                if size < payload[DNS_TCP_PAYLOAD_OFFSET..].len() {
                    return Err(Error::DNSPerfParseFailed("dns payload length error"));
                }
                self.decode_payload(
                    &payload[DNS_TCP_PAYLOAD_OFFSET..],
                    packet.lookup_key.timestamp,
                    flow_id,
                )?;
            }
            _ => return Err(Error::DNSPerfParseFailed("dns translation type error")),
        }

        self.session_data.l7_proto = L7Protocol::DNS;
        self.session_data.has_log_data = true;

        Ok(())
    }

    fn data_updated(&self) -> bool {
        self.perf_stats.is_some()
    }

    fn copy_and_reset_data(&mut self, timeout_count: u32) -> FlowPerfStats {
        if let Some(stats) = self.perf_stats.take() {
            FlowPerfStats {
                l7_protocol: L7Protocol::DNS,
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
                l7_protocol: L7Protocol::DNS,
                l7: L7PerfStats {
                    err_timeout: timeout_count,
                    ..Default::default()
                },
                ..Default::default()
            }
        }
    }

    fn app_proto_head(&mut self) -> Option<(AppProtoHead, u16)> {
        if self.session_data.l7_proto != L7Protocol::DNS || !self.session_data.has_log_data {
            return None;
        }
        self.session_data.has_log_data = false;

        let rrt = self
            .perf_stats
            .as_ref()
            .map(|s| s.rrt_last.as_micros() as u64)
            .unwrap_or(0);
        Some((
            AppProtoHead {
                proto: self.session_data.l7_proto,
                msg_type: self.session_data.msg_type,
                rrt,
            },
            0,
        ))
    }
}

impl DnsPerfData {
    pub fn new(rrt_cache: Rc<RefCell<L7RrtCache>>) -> Self {
        let session_data = DnsSessionData {
            id: 0,
            status_code: 0,
            status: L7ResponseStatus::default(),
            has_log_data: false,
            l7_proto: L7Protocol::default(),
            msg_type: LogMessageType::default(),
            rrt_cache,
        };
        Self {
            perf_stats: None,
            session_data,
        }
    }

    fn reset(&mut self) {
        self.perf_stats = None;
        self.session_data.status = L7ResponseStatus::default();
        self.session_data.l7_proto = L7Protocol::default();
        self.session_data.msg_type = LogMessageType::default();
        self.session_data.has_log_data = false;
    }

    fn decode_payload(&mut self, payload: &[u8], timestamp: Duration, flow_id: u64) -> Result<()> {
        if payload.len() < DNS_HEADER_SIZE {
            return Err(Error::DNSPerfParseFailed("protocol mismatch"));
        }
        self.session_data.id = read_u16_le(&payload[..DNS_HEADER_FLAGS_OFFSET]);

        let qr = payload[DNS_HEADER_FLAGS_OFFSET] & DNS_HEADER_QR_MASK;
        self.session_data.status_code =
            payload[DNS_HEADER_FLAGS_OFFSET + 1] & DNS_HEADER_RESPCODE_MASK;

        if qr == DNS_OPCODE_REQUEST {
            self.session_data.msg_type = LogMessageType::Request;

            let perf_stats = self.perf_stats.get_or_insert(PerfStats::default());
            perf_stats.req_count += 1;
            perf_stats.rrt_last = Duration::ZERO;
            self.session_data.rrt_cache.borrow_mut().add_req_time(
                flow_id,
                Some(self.session_data.id as u32),
                timestamp,
            );
            return Ok(());
        } else if qr == DNS_OPCODE_RESPONSE {
            self.session_data.msg_type = LogMessageType::Response;

            let perf_stats = self.perf_stats.get_or_insert(PerfStats::default());
            perf_stats.resp_count += 1;

            match self.session_data.status_code {
                DNS_RESPCODE_SUCCESS => {
                    self.session_data.status = L7ResponseStatus::Ok;
                }
                DNS_RESPCODE_FORMAT | DNS_RESPCODE_NXDOMAIN => {
                    perf_stats.req_err_count += 1;
                    self.session_data.status = L7ResponseStatus::ClientError;
                }
                _ => {
                    perf_stats.resp_err_count += 1;
                    self.session_data.status = L7ResponseStatus::ServerError;
                }
            }

            perf_stats.rrt_last = Duration::ZERO;

            let req_timestamp = self
                .session_data
                .rrt_cache
                .borrow_mut()
                .get_and_remove_l7_req_time(flow_id, Some(self.session_data.id as u32))
                .ok_or(Error::L7ReqNotFound(1))?;

            if timestamp < req_timestamp {
                return Ok(());
            }

            let rrt = timestamp - req_timestamp;
            if rrt > perf_stats.rrt_max {
                perf_stats.rrt_max = rrt;
            }
            perf_stats.rrt_last = rrt;
            perf_stats.rrt_sum += rrt;
            perf_stats.rrt_count += 1;
            return Ok(());
        }

        return Err(Error::DNSPerfParseFailed("decode dns payload failed"));
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    use crate::common::flow::PacketDirection;
    use crate::utils::test::Capture;

    const FILE_DIR: &str = "resources/test/flow_generator/dns";

    fn run(pcap: &str) -> DnsPerfData {
        let rrt_cache = Rc::new(RefCell::new(L7RrtCache::new(100)));
        let mut dns_perf_data = DnsPerfData::new(rrt_cache);

        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(pcap), None);
        let mut packets = capture.as_meta_packets();
        if packets.len() < 2 {
            return dns_perf_data;
        }
        let first_dst_port = packets[0].lookup_key.dst_port;
        for packet in packets.iter_mut() {
            if packet.lookup_key.dst_port == first_dst_port {
                packet.lookup_key.direction = PacketDirection::ClientToServer;
            } else {
                packet.lookup_key.direction = PacketDirection::ServerToClient;
            }
            let _ = dns_perf_data.parse(None, packet, 0x1f3c01010);
        }
        dns_perf_data
    }

    #[test]
    fn check() {
        let expected = vec![(
            "dns.pcap",
            DnsPerfData {
                perf_stats: Some(PerfStats {
                    req_count: 2,
                    resp_count: 2,
                    req_err_count: 1,
                    resp_err_count: 0,
                    rrt_count: 2,
                    rrt_max: Duration::from_nanos(176754000),
                    rrt_last: Duration::from_nanos(4804000),
                    rrt_sum: Duration::from_nanos(181558000),
                }),
                session_data: DnsSessionData {
                    id: 0,
                    status_code: 0,
                    status: L7ResponseStatus::Ok,
                    has_log_data: true,
                    l7_proto: L7Protocol::DNS,
                    msg_type: LogMessageType::Response,
                    rrt_cache: Rc::new(RefCell::new(L7RrtCache::new(100))),
                },
            },
        )];

        for item in expected.iter() {
            assert_eq!(item.1, run(item.0), "parse pcap {} unexcepted", item.0);
        }
    }
}
