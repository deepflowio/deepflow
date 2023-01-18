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

use log::{debug, warn};
use nom::{bytes::complete::take, Parser};

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
        protocol_logs::{
            mqtt::{
                mqtt_fixed_header, parse_connack_packet, parse_connect_packet, parse_status_code,
                PacketKind, QualityOfService,
            },
            AppProtoHead, L7ResponseStatus, LogMessageType,
        },
    },
};

pub const PORT: u16 = 1883;

pub struct MqttPerfData {
    stats: Option<PerfStats>,

    status_code: u8,
    status: L7ResponseStatus,

    proto_version: u8,
    has_log_data: bool,

    l7_proto: L7Protocol,
    msg_type: LogMessageType,

    rrt_cache: Rc<RefCell<L7RrtCache>>,
}

impl PartialEq for MqttPerfData {
    fn eq(&self, other: &MqttPerfData) -> bool {
        self.stats == other.stats
            && self.l7_proto == other.l7_proto
            && self.msg_type == other.msg_type
            && self.status_code == other.status_code
            && self.status == other.status
            && self.has_log_data == other.has_log_data
    }
}

impl Eq for MqttPerfData {}

impl fmt::Debug for MqttPerfData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(stats) = self.stats.as_ref() {
            write!(f, "status: {:?}", stats)?;
        } else {
            write!(f, "status: None")?;
        };
        write!(f, "l7_proto: {:?}", self.l7_proto)?;
        write!(f, "msg_type: {:?}", self.msg_type)?;
        write!(f, "status_code: {:?}", self.status_code)?;
        write!(f, "status {:?}", self.status)?;
        write!(f, "has_log_data: {:?}", self.has_log_data)
    }
}

impl L7FlowPerf for MqttPerfData {
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
        self.parse_mqtt(payload, packet.lookup_key.timestamp, flow_id)?;

        Ok(())
    }

    fn copy_and_reset_data(&mut self, timeout_count: u32) -> FlowPerfStats {
        if let Some(stats) = self.stats.take() {
            FlowPerfStats {
                l7_protocol: L7Protocol::MQTT,
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
                l7_protocol: L7Protocol::MQTT,
                l7: L7PerfStats {
                    err_timeout: timeout_count,
                    ..Default::default()
                },
                ..Default::default()
            }
        }
    }

    fn app_proto_head(&mut self) -> Option<(AppProtoHead, u16)> {
        if self.l7_proto != L7Protocol::MQTT || !self.has_log_data {
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

impl MqttPerfData {
    pub fn new(rrt_cache: Rc<RefCell<L7RrtCache>>) -> Self {
        Self {
            stats: None,
            status_code: 0,
            l7_proto: L7Protocol::default(),
            msg_type: LogMessageType::default(),
            status: L7ResponseStatus::default(),
            has_log_data: false,
            rrt_cache,
            proto_version: 0,
        }
    }

    fn parse_mqtt(&mut self, mut payload: &[u8], timestamp: Duration, flow_id: u64) -> Result<()> {
        // 现在只支持 MQTT 3.1.1解析
        if self.proto_version != 0 && self.proto_version != 4 {
            warn!("cannot parse packet, perf parser only support to parse MQTT V3.1.1 packet");
            return Err(Error::MqttPerfParseFailed);
        }

        loop {
            let (input, header) =
                mqtt_fixed_header(payload).map_err(|_| Error::MqttPerfParseFailed)?;
            match header.kind {
                PacketKind::Connect => {
                    let data = take(header.remaining_length as u32);
                    let (_, (version, _)) = data
                        .and_then(parse_connect_packet)
                        .parse(input)
                        .map_err(|_| Error::MqttPerfParseFailed)?;
                    self.proto_version = version;
                    self.msg_type = LogMessageType::Request;
                    self.calc_request(timestamp, flow_id);
                }
                PacketKind::Connack => {
                    let (_, return_code) =
                        parse_connack_packet(input).map_err(|_| Error::MqttLogParseFailed)?;
                    self.status_code = return_code;
                    self.msg_type = LogMessageType::Response;
                    self.status = parse_status_code(return_code);
                    self.calc_response(timestamp, flow_id);
                }
                PacketKind::Publish { dup, qos, .. } => {
                    if dup && qos == QualityOfService::AtMostOnce {
                        debug!("mqtt publish packet has invalid dup flags={}", dup);
                        return Err(Error::MqttPerfParseFailed);
                    }
                    // QOS=1,2会有报文标识符
                    // QOS=1,2 there will be a message identifier
                    match qos {
                        QualityOfService::AtLeastOnce | QualityOfService::ExactlyOnce => {
                            self.msg_type = LogMessageType::Request;
                            self.calc_request(timestamp, flow_id);
                        }
                        QualityOfService::AtMostOnce => {
                            self.msg_type = LogMessageType::Response;
                            self.calc_response(timestamp, flow_id);
                        }
                    }
                }
                PacketKind::Suback
                | PacketKind::Pingresp
                | PacketKind::Pubcomp
                | PacketKind::Pubrec
                | PacketKind::Puback
                | PacketKind::Unsuback => {
                    self.msg_type = LogMessageType::Response;
                    self.calc_response(timestamp, flow_id);
                }
                PacketKind::Subscribe
                | PacketKind::Unsubscribe
                | PacketKind::Pingreq
                | PacketKind::Pubrel => {
                    self.msg_type = LogMessageType::Request;
                    self.calc_request(timestamp, flow_id);
                }
                PacketKind::Disconnect => {
                    self.msg_type = LogMessageType::Session;
                    self.calc_request(timestamp, flow_id);
                }
            }
            if input.len() <= header.remaining_length as usize {
                break;
            }

            payload = &input[header.remaining_length as usize..];
        }

        self.l7_proto = L7Protocol::MQTT;
        self.has_log_data = true;

        Ok(())
    }

    fn calc_request(&mut self, timestamp: Duration, flow_id: u64) {
        let stats = self.stats.get_or_insert(PerfStats::default());
        stats.req_count += 1;
        stats.rrt_last = Duration::ZERO;
        self.rrt_cache
            .borrow_mut()
            .add_req_time(flow_id, None, timestamp);
    }

    fn calc_response(&mut self, timestamp: Duration, flow_id: u64) {
        let stats = self.stats.get_or_insert(PerfStats::default());
        stats.resp_count += 1;

        let req_timestamp = match self
            .rrt_cache
            .borrow_mut()
            .get_and_remove_l7_req_time(flow_id, None)
            .filter(|t| *t <= timestamp)
        {
            Some(t) => t,
            None => return,
        };

        let rrt = timestamp - req_timestamp;
        stats.rrt_max = stats.rrt_max.max(rrt);
        stats.rrt_last = rrt;
        stats.rrt_sum += rrt;
        stats.rrt_count += 1;
    }

    fn reset(&mut self) {
        self.stats = None;
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

    use crate::common::flow::PacketDirection;
    use crate::utils::test::Capture;

    const FILE_DIR: &str = "resources/test/flow_generator/mqtt";

    fn run(pcap: &str) -> PerfStats {
        let rrt_cache = Rc::new(RefCell::new(L7RrtCache::new(100)));
        let mut mqtt_perf_data = MqttPerfData::new(rrt_cache);

        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(pcap), None);
        let mut packets = capture.as_meta_packets();
        if packets.len() < 2 {
            return mqtt_perf_data.stats.unwrap_or_default();
        }

        let first_dst_port = packets[0].lookup_key.dst_port;
        for packet in packets.iter_mut() {
            if packet.lookup_key.dst_port == first_dst_port {
                packet.lookup_key.direction = PacketDirection::ClientToServer;
            } else {
                packet.lookup_key.direction = PacketDirection::ServerToClient;
            }
            let _ = mqtt_perf_data.parse(None, packet, 1608373855724393643);
        }
        mqtt_perf_data.stats.unwrap_or_default()
    }

    #[test]
    fn check() {
        let expected = vec![
            (
                "mqtt_connect.pcap",
                PerfStats {
                    req_count: 1,
                    resp_count: 1,
                    req_err_count: 0,
                    resp_err_count: 0,
                    rrt_count: 1,
                    rrt_max: Duration::from_nanos(256746000),
                    rrt_last: Duration::from_nanos(256746000),
                    rrt_sum: Duration::from_nanos(256746000),
                },
            ),
            (
                "mqtt_sub.pcap",
                PerfStats {
                    req_count: 1,
                    resp_count: 1,
                    req_err_count: 0,
                    resp_err_count: 0,
                    rrt_count: 1,
                    rrt_max: Duration::from_nanos(272795000),
                    rrt_last: Duration::from_nanos(272795000),
                    rrt_sum: Duration::from_nanos(272795000),
                },
            ),
        ];

        for item in expected.iter() {
            assert_eq!(item.1, run(item.0), "parse pcap {} unexcepted", item.0);
        }
    }
}
