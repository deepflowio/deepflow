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
use serde::Serialize;

use super::super::{
    consts::KAFKA_REQ_HEADER_LEN, AppProtoHead, AppProtoInfoImpl, L7ProtocolInfoInterface,
    L7ResponseStatus, LogMessageType,
};

use crate::common::l7_protocol_log::{L7ProtocolParserInterface, ParseParam};
use crate::parse_common;
use crate::{
    common::enums::IpProtocol,
    common::flow::{L7Protocol, PacketDirection},
    flow_generator::{Error, Result},
    utils::bytes::{read_u16_be, read_u32_be},
};

use public::log_info_merge;
use public::protocol_logs::{l7_protocol_info::L7ProtocolInfo, KafkaInfo};

const KAFKA_FETCH: u16 = 1;
// https://kafka.apache.org/protocol.html
const API_KEY_MAX: u16 = 67;

impl L7ProtocolInfoInterface for KafkaInfo {
    fn session_id(&self) -> Option<u32> {
        Some(self.correlation_id)
    }

    fn merge_log(&mut self, other: L7ProtocolInfo) -> Result<()> {
        log_info_merge!(self, KafkaInfo, other);
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::Kafka,
            msg_type: self.msg_type,
            rrt: self.end_time - self.start_time,
        })
    }

    fn is_tls(&self) -> bool {
        self.is_tls
    }

    fn skip_send(&self) -> bool {
        false
    }
}

impl AppProtoInfoImpl for KafkaInfo {
    fn merge(&mut self, other: Self) -> Result<()> {
        if self.resp_msg_size.is_none() {
            self.resp_msg_size = other.resp_msg_size;
        }
        /*
            reference:  https://kafka.apache.org/protocol.html#protocol_messages

            only fetch api and api version > 7 parse the error code

            Fetch Response (Version: 7) => throttle_time_ms error_code session_id [responses]
                throttle_time_ms => INT32
                error_code => INT16
                ...
        */
        fn set_status_code(info: &mut KafkaInfo, code: i32) {
            info.status_code = Some(code);
            if code == 0 {
                info.status = L7ResponseStatus::Ok;
            } else {
                info.status = L7ResponseStatus::ServerError;
            }
        }
        match other.msg_type {
            LogMessageType::Response if self.api_key == KAFKA_FETCH && self.api_version >= 7 => {
                if let Some(d) = other.resp_data {
                    set_status_code(self, read_u16_be(&d[12..]) as i32)
                }
            }
            LogMessageType::Request if other.api_key == KAFKA_FETCH && other.api_version >= 7 => {
                if let Some(d) = self.resp_data {
                    set_status_code(self, read_u16_be(&d[12..]) as i32)
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn check(&self) -> bool {
        if self.api_key > API_KEY_MAX {
            return false;
        }
        return self.client_id.len() > 0 && self.client_id.is_ascii();
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct KafkaLog {
    info: KafkaInfo,
}

impl L7ProtocolParserInterface for KafkaLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol() {
            return false;
        }
        Self::kafka_check_protocol(payload, param)
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<Vec<L7ProtocolInfo>> {
        parse_common!(self, param);
        Self::parse(
            self,
            payload,
            param.l4_protocol,
            param.direction,
            None,
            None,
        )?;
        Ok(vec![L7ProtocolInfo::KafkaInfo(self.info.clone())])
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Kafka
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn reset(&mut self) {
        *self = Self::default();
        self.info.status = L7ResponseStatus::NotExist;
    }
}
impl KafkaLog {
    const MSG_LEN_SIZE: usize = 4;

    pub fn new() -> KafkaLog {
        let mut log = KafkaLog::default();
        log.reset();
        log
    }

    fn reset_logs(&mut self) {
        self.info.correlation_id = 0;
        self.info.req_msg_size = None;
        self.info.api_version = 0;
        self.info.api_key = 0;
        self.info.client_id = String::new();
        self.info.resp_msg_size = None;
        self.info.status = L7ResponseStatus::Ok;
        self.info.status_code = None;
    }

    // 协议识别的时候严格检查避免误识别，日志解析的时候不用严格检查因为可能有长度截断
    // ================================================================================
    // The protocol identification is strictly checked to avoid misidentification.
    // The log analysis is not strictly checked because there may be length truncation
    fn request(&mut self, payload: &[u8], strict: bool) -> Result<AppProtoHead> {
        let req_len = read_u32_be(payload);
        self.info.req_msg_size = Some(req_len);
        let client_id_len = read_u16_be(&payload[12..]) as usize;
        if payload.len() < KAFKA_REQ_HEADER_LEN + client_id_len {
            return Err(Error::KafkaLogParseFailed);
        }

        if strict && req_len as usize != payload.len() - Self::MSG_LEN_SIZE {
            return Err(Error::KafkaLogParseFailed);
        }

        self.info.msg_type = LogMessageType::Request;
        self.info.api_key = read_u16_be(&payload[4..]);
        self.info.api_version = read_u16_be(&payload[6..]);
        self.info.correlation_id = read_u32_be(&payload[8..]);
        self.info.client_id =
            String::from_utf8_lossy(&payload[14..14 + client_id_len]).into_owned();

        if !self.info.client_id.is_ascii() {
            return Err(Error::KafkaLogParseFailed);
        }

        Ok(AppProtoHead {
            proto: L7Protocol::Kafka,
            msg_type: self.info.msg_type,
            rrt: 0,
            ..Default::default()
        })
    }

    fn response(&mut self, payload: &[u8]) -> Result<AppProtoHead> {
        self.info.resp_msg_size = Some(read_u32_be(payload));
        self.info.correlation_id = read_u32_be(&payload[4..]);
        self.info.msg_type = LogMessageType::Response;
        if payload.len() >= 14 {
            self.info.resp_data = Some(payload[..14].try_into().unwrap())
        }
        Ok(AppProtoHead {
            proto: L7Protocol::Kafka,
            msg_type: self.info.msg_type,
            rrt: 0,
        })
    }

    pub fn kafka_check_protocol(payload: &[u8], param: &ParseParam) -> bool {
        if param.l4_protocol != IpProtocol::Tcp {
            return false;
        }

        if payload.len() < KAFKA_REQ_HEADER_LEN {
            return false;
        }
        let mut kafka = KafkaLog::default();

        let ret = kafka.request(payload, true);
        if ret.is_err() {
            return false;
        }
        kafka.info.check()
    }

    fn parse(
        &mut self,
        payload: &[u8],
        proto: IpProtocol,
        direction: PacketDirection,
        _is_req_end: Option<bool>,
        _is_resp_end: Option<bool>,
    ) -> Result<()> {
        if proto != IpProtocol::Tcp {
            return Err(Error::InvalidIpProtocol);
        }
        if payload.len() < KAFKA_REQ_HEADER_LEN {
            return Err(Error::KafkaLogParseFailed);
        }
        match direction {
            PacketDirection::ClientToServer => self.request(payload, false),
            PacketDirection::ServerToClient => self.response(payload),
        }?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    use crate::{
        common::{flow::PacketDirection, MetaPacket},
        utils::test::Capture,
    };

    const FILE_DIR: &str = "resources/test/flow_generator/kafka";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name), None);
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
        for packet in packets.iter_mut() {
            packet.direction = if packet.lookup_key.dst_port == first_dst_port {
                PacketDirection::ClientToServer
            } else {
                PacketDirection::ServerToClient
            };
            let payload = match packet.get_l4_payload() {
                Some(p) => p,
                None => continue,
            };

            let mut kafka = KafkaLog::default();
            let _ = kafka.parse(
                payload,
                packet.lookup_key.proto,
                packet.direction,
                None,
                None,
            );
            let is_kafka =
                KafkaLog::kafka_check_protocol(payload, &ParseParam::from(packet as &MetaPacket));
            output.push_str(&format!("{:?} is_kafka: {}\r\n", kafka.info, is_kafka));
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![("kafka.pcap", "kafka.result")];

        for item in files.iter() {
            let expected = fs::read_to_string(&Path::new(FILE_DIR).join(item.1)).unwrap();
            let output = run(item.0);

            if output != expected {
                let output_path = Path::new("actual.txt");
                fs::write(&output_path, &output).unwrap();
                assert!(
                    output == expected,
                    "output different from expected {}, written to {:?}",
                    item.1,
                    output_path
                );
            }
        }
    }
}
