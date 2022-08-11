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

use super::super::{
    consts::KAFKA_REQ_HEADER_LEN, AppProtoHead, AppProtoLogsInfo, L7LogParse, L7Protocol,
    L7ResponseStatus, LogMessageType,
};

use crate::flow_generator::protocol_logs::{AppProtoHeadEnum, AppProtoLogsInfoEnum};
use crate::proto::flow_log;
use crate::{
    common::enums::{IpProtocol, PacketDirection},
    common::meta_packet::MetaPacket,
    flow_generator::error::{Error, Result},
    utils::bytes::{read_u16_be, read_u32_be},
};

#[derive(Debug, Default, Clone)]
pub struct KafkaInfo {
    pub correlation_id: u32,

    // request
    pub req_msg_size: i32,
    pub api_version: u16,
    pub api_key: u16,
    pub client_id: String,

    // reponse
    pub resp_msg_size: i32,
}

impl KafkaInfo {
    // https://kafka.apache.org/protocol.html
    const API_KEY_MAX: u16 = 67;
    pub fn merge(&mut self, other: Self) {
        self.resp_msg_size = other.resp_msg_size;
    }
    pub fn check(&self) -> bool {
        if self.api_key > Self::API_KEY_MAX {
            return false;
        }
        return self.client_id.len() > 0 && self.client_id.is_ascii();
    }
}

impl From<KafkaInfo> for flow_log::KafkaInfo {
    fn from(f: KafkaInfo) -> Self {
        flow_log::KafkaInfo {
            correlation_id: f.correlation_id,
            req_msg_size: f.req_msg_size,
            api_version: f.api_version as u32,
            api_key: f.api_key as u32,
            client_id: f.client_id,
            resp_msg_size: f.resp_msg_size,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct KafkaLog {
    info: KafkaInfo,
    msg_type: LogMessageType,
    status: L7ResponseStatus,
    status_code: u16,
}

impl KafkaLog {
    const MSG_LEN_SIZE: usize = 4;
    fn reset_logs(&mut self) {
        self.info.correlation_id = 0;
        self.info.req_msg_size = -1;
        self.info.api_version = 0;
        self.info.api_key = 0;
        self.info.client_id = String::new();
        self.info.resp_msg_size = -1;
        self.status = L7ResponseStatus::Ok;
        self.status_code = 0;
    }

    // 协议识别的时候严格检查避免误识别，日志解析的时候不用严格检查因为可能有长度截断
    // ================================================================================
    // The protocol identification is strictly checked to avoid misidentification.
    // The log analysis is not strictly checked because there may be length truncation
    fn request(&mut self, payload: &[u8], strict: bool) -> Result<AppProtoHead> {
        self.info.req_msg_size = read_u32_be(payload) as i32;
        let client_id_len = read_u16_be(&payload[12..]) as usize;
        if payload.len() < KAFKA_REQ_HEADER_LEN + client_id_len {
            return Err(Error::KafkaLogParseFailed);
        }

        if strict && self.info.req_msg_size as usize != payload.len() - Self::MSG_LEN_SIZE {
            return Err(Error::KafkaLogParseFailed);
        }

        self.msg_type = LogMessageType::Request;
        self.info.api_key = read_u16_be(&payload[4..]);
        self.info.api_version = read_u16_be(&payload[6..]);
        self.info.correlation_id = read_u32_be(&payload[8..]);
        self.info.client_id =
            String::from_utf8_lossy(&payload[14..14 + client_id_len]).into_owned();

        Ok(AppProtoHead {
            proto: L7Protocol::Kafka,
            msg_type: self.msg_type,
            status: self.status,
            code: self.status_code,
            rrt: 0,
            version: 0,
        })
    }

    fn response(&mut self, payload: &[u8]) -> Result<AppProtoHead> {
        self.info.resp_msg_size = read_u32_be(payload) as i32;
        self.info.correlation_id = read_u32_be(&payload[4..]);
        self.msg_type = LogMessageType::Response;

        Ok(AppProtoHead {
            proto: L7Protocol::Kafka,
            msg_type: self.msg_type,
            status: L7ResponseStatus::Ok,
            code: 0,
            rrt: 0,
            version: 0,
        })
    }
}

impl L7LogParse for KafkaLog {
    fn parse(
        &mut self,
        payload: &[u8],
        proto: IpProtocol,
        direction: PacketDirection,
    ) -> Result<AppProtoHeadEnum> {
        if proto != IpProtocol::Tcp {
            return Err(Error::InvalidIpProtocol);
        }
        self.reset_logs();
        if payload.len() < KAFKA_REQ_HEADER_LEN {
            return Err(Error::KafkaLogParseFailed);
        }
        let head = match direction {
            PacketDirection::ClientToServer => self.request(payload, false),
            PacketDirection::ServerToClient => self.response(payload),
        }?;
        Ok(AppProtoHeadEnum::Single(head))
    }

    fn info(&self) -> AppProtoLogsInfoEnum {
        AppProtoLogsInfoEnum::Single(AppProtoLogsInfo::Kafka(self.info.clone()))
    }
}

pub fn kafka_check_protocol(bitmap: &mut u128, packet: &MetaPacket) -> bool {
    if packet.lookup_key.proto != IpProtocol::Tcp {
        *bitmap &= !(1 << u8::from(L7Protocol::Kafka));
        return false;
    }

    let payload = packet.get_l4_payload();
    if payload.is_none() {
        return false;
    }
    let payload = payload.unwrap();
    if payload.len() < KAFKA_REQ_HEADER_LEN {
        return false;
    }
    let mut kafka = KafkaLog::default();

    let ret = kafka.request(payload, true);
    if ret.is_err() {
        return false;
    }
    return kafka.info.check();
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    use crate::{common::enums::PacketDirection, utils::test::Capture};

    const FILE_DIR: &str = "resources/test/flow_generator/kafka";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name), None);
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
        let mut bitmap = 0;
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
            let _ = kafka.parse(payload, packet.lookup_key.proto, packet.direction);
            let is_kafka = kafka_check_protocol(&mut bitmap, packet);
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
