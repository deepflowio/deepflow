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
    consts::KAFKA_REQ_HEADER_LEN, value_is_default, value_is_negative, AppProtoHead,
    AppProtoLogsInfo, L7LogParse, L7ResponseStatus, LogMessageType,
};

use crate::common::flow::L7Protocol;
use crate::common::l7_protocol_log::{L7ProtocolLog, L7ProtocolLogInterface, ParseParam};
use crate::common::lookup_key::LookupKey;
use crate::flow_generator::protocol_logs::pb_adapter::{
    ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response,
};
use crate::flow_generator::protocol_logs::{AppProtoHeadEnum, AppProtoLogsInfoEnum};
use crate::{__log_info_merge, ignore_non_raw_protocol};
use crate::{
    common::enums::IpProtocol,
    common::flow::PacketDirection,
    common::meta_packet::MetaPacket,
    flow_generator::error::{Error, Result},
    utils::bytes::{read_u16_be, read_u32_be},
};

#[derive(Serialize, Debug, Default, Clone)]
pub struct KafkaInfo {
    #[serde(rename = "request_id", skip_serializing_if = "value_is_default")]
    pub correlation_id: u32,

    // request
    #[serde(rename = "request_length", skip_serializing_if = "value_is_negative")]
    pub req_msg_size: Option<u32>,
    #[serde(skip)]
    pub api_version: u16,
    #[serde(rename = "request_type")]
    pub api_key: u16,
    #[serde(skip)]
    pub client_id: String,

    // reponse
    #[serde(rename = "response_length", skip_serializing_if = "value_is_negative")]
    pub resp_msg_size: Option<u32>,
    pub status: L7ResponseStatus,
    pub status_code: Option<i32>,
}

impl KafkaInfo {
    // https://kafka.apache.org/protocol.html
    const API_KEY_MAX: u16 = 67;
    pub fn merge(&mut self, other: Self) {
        if self.resp_msg_size.is_none() {
            self.resp_msg_size = other.resp_msg_size;
        }
        if other.status != L7ResponseStatus::default() {
            self.status = other.status;
        }
        if self.status_code.is_none() {
            self.status_code = other.status_code;
        }
    }
    pub fn check(&self) -> bool {
        if self.api_key > Self::API_KEY_MAX {
            return false;
        }
        return self.client_id.len() > 0 && self.client_id.is_ascii();
    }

    pub fn get_command(&self) -> &'static str {
        let command_str = [
            "Produce",
            "Fetch",
            "ListOffsets",
            "Metadata",
            "LeaderAndIsr",
            "StopReplica",
            "UpdateMetadata",
            "ControlledShutdown",
            "OffsetCommit",
            "OffsetFetch",
            // 10
            "FindCoordinator",
            "JoinGroup",
            "Heartbeat",
            "LeaveGroup",
            "SyncGroup",
            "DescribeGroups",
            "ListGroups",
            "SaslHandshake",
            "ApiVersions",
            "CreateTopics",
            // 20
            "DeleteTopics",
            "DeleteRecords",
            "InitProducerId",
            "OffsetForLeaderEpoch",
            "AddPartitionsToTxn",
            "AddOffsetsToTxn",
            "EndTxn",
            "WriteTxnMarkers",
            "TxnOffsetCommit",
            "DescribeAcls",
            // 30
            "CreateAcls",
            "DeleteAcls",
            "DescribeConfigs",
            "AlterConfigs",
            "AlterReplicaLogDirs",
            "DescribeLogDirs",
            "SaslAuthenticate",
            "CreatePartitions",
            "CreateDelegationToken",
            "RenewDelegationToken",
            // 40
            "ExpireDelegationToken",
            "DescribeDelegationToken",
            "DeleteGroups",
            "ElectLeaders",
            "IncrementalAlterConfigs",
            "AlterPartitionReassignments",
            "ListPartitionReassignments",
            "OffsetDelete",
            "DescribeClientQuotas",
            "AlterClientQuotas",
            //50
            "DescribeUserScramCredentials",
            "AlterUserScramCredentials",
            "AlterIsr",
            "UpdateFeatures",
            "DescribeCluster",
            "DescribeProducers",
            "DescribeTransactions",
            "ListTransactions",
            "AllocateProducerIds",
        ];
        match self.api_key {
            0..=58 => command_str[self.api_key as usize],
            _ => "",
        }
    }
}

impl From<KafkaInfo> for L7ProtocolSendLog {
    fn from(f: KafkaInfo) -> Self {
        let command_str = f.get_command();
        let log = L7ProtocolSendLog {
            req_len: f.req_msg_size,
            resp_len: f.resp_msg_size,
            req: L7Request {
                req_type: String::from(command_str),
                ..Default::default()
            },
            resp: L7Response {
                status: f.status,
                code: f.status_code,
                ..Default::default()
            },
            ext_info: Some(ExtendedInfo {
                request_id: Some(f.correlation_id),
                ..Default::default()
            }),
            ..Default::default()
        };
        return log;
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct KafkaLog {
    info: KafkaInfo,
    msg_type: LogMessageType,
    start_time: u64,
    end_time: u64,
}

impl L7ProtocolLogInterface for KafkaLog {
    fn session_id(&self) -> Option<u32> {
        return Some(self.info.correlation_id);
    }

    fn merge_log(&mut self, other: L7ProtocolLog) -> Result<()> {
        __log_info_merge!(self, KafkaLog, other);
    }

    fn check_payload(&mut self, payload: &[u8], lookup_key: &LookupKey, param: ParseParam) -> bool {
        ignore_non_raw_protocol!(param);
        return Self::kafka_check_protocol(payload, lookup_key);
    }

    fn parse_payload(
        mut self,
        payload: &[u8],
        lookup_key: &crate::_LookupKey,
        param: crate::common::l7_protocol_log::ParseParam,
    ) -> Result<Vec<crate::common::l7_protocol_log::L7ProtocolLog>> {
        self.start_time = param.time;
        self.end_time = param.time;
        Self::parse(
            &mut self,
            payload,
            lookup_key.proto,
            param.direction,
            None,
            None,
        )?;
        return Ok(vec![L7ProtocolLog::KafkaLog(self)]);
    }

    fn protocol(&self) -> (L7Protocol, &str) {
        return (L7Protocol::Kafka, "KAFKA");
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        return Some(AppProtoHead {
            proto: L7Protocol::Kafka,
            msg_type: self.msg_type,
            rrt: self.end_time - self.start_time,
        });
    }

    fn is_tls(&self) -> bool {
        return false;
    }

    fn skip_send(&self) -> bool {
        return false;
    }

    fn into_l7_protocol_send_log(self) -> L7ProtocolSendLog {
        return self.info.into();
    }

    fn parse_on_udp(&self) -> bool {
        return false;
    }

    fn get_default(&self) -> L7ProtocolLog {
        return L7ProtocolLog::KafkaLog(Self::default());
    }
}
impl KafkaLog {
    const MSG_LEN_SIZE: usize = 4;
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
            self.reset_logs();
            return Err(Error::KafkaLogParseFailed);
        }

        if strict && req_len as usize != payload.len() - Self::MSG_LEN_SIZE {
            self.reset_logs();
            return Err(Error::KafkaLogParseFailed);
        }

        self.msg_type = LogMessageType::Request;
        self.info.api_key = read_u16_be(&payload[4..]);
        self.info.api_version = read_u16_be(&payload[6..]);
        self.info.correlation_id = read_u32_be(&payload[8..]);
        self.info.client_id =
            String::from_utf8_lossy(&payload[14..14 + client_id_len]).into_owned();

        if !self.info.client_id.is_ascii() {
            self.reset_logs();
            return Err(Error::KafkaLogParseFailed);
        }

        Ok(AppProtoHead {
            proto: L7Protocol::Kafka,
            msg_type: self.msg_type,
            rrt: 0,
            ..Default::default()
        })
    }

    fn response(&mut self, payload: &[u8]) -> Result<AppProtoHead> {
        self.info.resp_msg_size = Some(read_u32_be(payload));
        self.info.correlation_id = read_u32_be(&payload[4..]);
        self.msg_type = LogMessageType::Response;

        Ok(AppProtoHead {
            proto: L7Protocol::Kafka,
            msg_type: self.msg_type,
            rrt: 0,
        })
    }

    // 这个逻辑是直接复制 kafka_check_protocol(bitmap: &mut u128, packet: &MetaPacket)
    // 后面把perf抽象后只会保留在这个
    pub fn kafka_check_protocol(payload: &[u8], lookup_key: &LookupKey) -> bool {
        if lookup_key.proto != IpProtocol::Tcp {
            // *bitmap &= !(1 << u8::from(L7Protocol::Kafka));
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
        return kafka.info.check();
    }
}

impl L7LogParse for KafkaLog {
    fn parse(
        &mut self,
        payload: &[u8],
        proto: IpProtocol,
        direction: PacketDirection,
        _is_req_end: Option<bool>,
        _is_resp_end: Option<bool>,
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
        *bitmap &= !(1 << L7Protocol::Kafka as u8);
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

    use crate::{common::flow::PacketDirection, utils::test::Capture};

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
            let _ = kafka.parse(
                payload,
                packet.lookup_key.proto,
                packet.direction,
                None,
                None,
            );
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
