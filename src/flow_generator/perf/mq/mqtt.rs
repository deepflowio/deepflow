use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;
use std::time::Duration;

use crate::{
    common::{
        enums::{IpProtocol, PacketDirection},
        flow::{FlowPerfStats, L7PerfStats, L7Protocol},
        meta_packet::MetaPacket,
    },
    flow_generator::{
        error::{Error, Result},
        perf::l7_rrt::L7RrtCache,
        perf::stats::PerfStats,
        perf::L7FlowPerf,
        protocol_logs::{
            consts::*,
            mqtt::{get_status_code, parse_connect, parse_variable_length},
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
    fn parse(&mut self, packet: &MetaPacket, flow_id: u64) -> Result<()> {
        if packet.lookup_key.proto != IpProtocol::Tcp {
            return Err(Error::InvalidIpProtocol);
        }

        let payload = packet.get_l4_payload().ok_or(Error::ZeroPayloadLen)?;

        self.parse_mqtt(
            payload,
            packet.lookup_key.timestamp,
            packet.direction,
            flow_id,
        )?;

        Ok(())
    }

    fn copy_and_reset_data(&mut self, timeout_count: u32) -> FlowPerfStats {
        if let Some(stats) = self.stats.take() {
            FlowPerfStats {
                l7_protocol: L7Protocol::Mqtt,
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
                l7_protocol: L7Protocol::Mqtt,
                l7: L7PerfStats {
                    err_timeout: timeout_count,
                    ..Default::default()
                },
                ..Default::default()
            }
        }
    }

    fn app_proto_head(&mut self) -> Option<(AppProtoHead, u16)> {
        if self.l7_proto != L7Protocol::Mqtt || !self.has_log_data {
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
                status: self.status,
                code: self.status_code as u16,
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
            rrt_cache: rrt_cache,
            proto_version: 0,
        }
    }

    fn parse_mqtt(
        &mut self,
        payload: &[u8],
        timestamp: Duration,
        direction: PacketDirection,
        flow_id: u64,
    ) -> Result<()> {
        let message_type = (payload[0] & 0xf0) >> 4;
        let message_flag = payload[0] & 0x0f;

        match message_type {
            0 => {
                return Err(Error::MqttPerfParseFailed);
            }
            MQTT_PUBLISH => {}
            MQTT_PUBREL | MQTT_SUBSCRIBE | MQTT_UNSUBSCRIBE => {
                if message_flag != 2 {
                    return Err(Error::MqttPerfParseFailed);
                }
            }
            _ => {
                if message_flag != 0 {
                    return Err(Error::MqttPerfParseFailed);
                }
            }
        }

        let (var_len, _) = parse_variable_length(&payload[1..])?;
        let offset = var_len + 1;

        if message_type == MQTT_CONNECT {
            let (proto_version, _) = parse_connect(&payload[offset..], Error::MqttPerfParseFailed)?;
            self.proto_version = proto_version;
        } else {
            self.status_code = get_status_code(
                &payload[var_len..],
                message_type,
                self.proto_version,
                Error::MqttPerfParseFailed,
            )?;
        }

        match message_type {
            MQTT_CONNECT | MQTT_SUBSCRIBE | MQTT_UNSUBSCRIBE | MQTT_PINGREQ => {
                self.msg_type = LogMessageType::Request;
                self.calc_request(timestamp, flow_id);
            }
            MQTT_CONNACK | MQTT_SUBACK | MQTT_UNSUBACK | MQTT_PINGRESP => {
                self.msg_type = LogMessageType::Response;
                self.calc_response(timestamp, direction, flow_id);
            }
            _ => {
                self.msg_type = LogMessageType::Other;
            }
        }

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

    fn calc_response(
        &mut self,
        timestamp: Duration,
        direction: PacketDirection,
        flow_id: u64,
    ) -> bool {
        let stats = self.stats.get_or_insert(PerfStats::default());
        stats.resp_count += 1;

        if self.proto_version == 5 {
            match self.status_code {
                0 | 4 => self.status = L7ResponseStatus::Ok,
                MQTT_STATUS_FAILED_MIN..=MQTT_STATUS_FAILED_MAX => {
                    if direction == PacketDirection::ClientToServer {
                        self.status = L7ResponseStatus::ClientError;
                    } else {
                        self.status = L7ResponseStatus::ServerError
                    }
                }
                _ => return false,
            }
        } else {
            match self.status_code {
                0 => self.status = L7ResponseStatus::Ok,
                1..=3 => self.status = L7ResponseStatus::ServerError,
                _ => self.status = L7ResponseStatus::ClientError,
            }
        }

        stats.rrt_last = Duration::ZERO;

        let req_timestamp = match self
            .rrt_cache
            .borrow_mut()
            .get_and_remove_l7_req_time(flow_id, None)
        {
            Some(t) => t,
            None => return true,
        };

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
                packet.direction = PacketDirection::ClientToServer;
            } else {
                packet.direction = PacketDirection::ServerToClient;
            }
            let _ = mqtt_perf_data.parse(packet, 1608373855724393643);
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
