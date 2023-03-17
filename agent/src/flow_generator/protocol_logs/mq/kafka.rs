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

use crate::{
    common::{
        enums::IpProtocol,
        flow::{L7PerfStats, L7Protocol, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ProtocolParserInterface, ParseParam},
    },
    flow_generator::{
        error::{Error, Result},
        protocol_logs::{
            consts::KAFKA_REQ_HEADER_LEN,
            pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response},
            value_is_default, value_is_negative, AppProtoHead, L7ResponseStatus, LogMessageType,
        },
    },
    utils::bytes::{read_i16_be, read_u16_be, read_u32_be},
};

const KAFKA_FETCH: u16 = 1;

#[derive(Serialize, Debug, Default, Clone)]
pub struct KafkaInfo {
    msg_type: LogMessageType,
    #[serde(skip)]
    is_tls: bool,

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
    #[serde(rename = "response_status")]
    pub status: L7ResponseStatus,
    #[serde(rename = "response_code", skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i32>,

    // the first 14 byte of resp_data, use to parse error code
    // only fetch and api version > 7 can get the correct err code
    #[serde(skip)]
    pub resp_data: Option<[u8; 14]>,

    rrt: u64,
}

impl L7ProtocolInfoInterface for KafkaInfo {
    fn session_id(&self) -> Option<u32> {
        Some(self.correlation_id)
    }

    fn merge_log(&mut self, other: crate::common::l7_protocol_info::L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::KafkaInfo(other) = other {
            self.merge(other);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::Kafka,
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn is_tls(&self) -> bool {
        self.is_tls
    }
}

impl KafkaInfo {
    // https://kafka.apache.org/protocol.html
    const API_KEY_MAX: u16 = 67;
    pub fn merge(&mut self, other: Self) {
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
        match other.msg_type {
            LogMessageType::Response if self.api_key == KAFKA_FETCH && self.api_version >= 7 => {
                if let Some(d) = other.resp_data {
                    self.set_status_code(read_i16_be(&d[12..]) as i32)
                }
            }
            LogMessageType::Request if other.api_key == KAFKA_FETCH && other.api_version >= 7 => {
                if let Some(d) = self.resp_data {
                    self.set_status_code(read_i16_be(&d[12..]) as i32)
                }
            }
            _ => {}
        }
    }

    pub fn set_status_code(&mut self, code: i32) {
        self.status_code = Some(code);
        if code == 0 {
            self.status = L7ResponseStatus::Ok;
        } else {
            self.status = L7ResponseStatus::ServerError;
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

#[derive(Clone, Serialize, Default)]
pub struct KafkaLog {
    info: KafkaInfo,
    #[serde(skip)]
    perf_stats: Option<L7PerfStats>,
}

impl L7ProtocolParserInterface for KafkaLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol()
            || param.l4_protocol != IpProtocol::Tcp
            || payload.len() < KAFKA_REQ_HEADER_LEN
        {
            return false;
        }
        let ok = self.request(payload, true).is_ok() && self.info.check();
        self.reset();
        ok
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<Vec<L7ProtocolInfo>> {
        if self.perf_stats.is_none() {
            self.perf_stats = Some(L7PerfStats::default())
        };
        Self::parse(self, payload, param.l4_protocol, param.direction)?;
        self.info.cal_rrt(param).map(|rrt| {
            self.info.rrt = rrt;
            self.perf_stats.as_mut().unwrap().update_rrt(rrt);
        });
        Ok(vec![L7ProtocolInfo::KafkaInfo(self.info.clone())])
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Kafka
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn reset(&mut self) {
        self.info = KafkaInfo::default();
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

impl KafkaLog {
    const MSG_LEN_SIZE: usize = 4;

    // 协议识别的时候严格检查避免误识别，日志解析的时候不用严格检查因为可能有长度截断
    // ================================================================================
    // The protocol identification is strictly checked to avoid misidentification.
    // The log analysis is not strictly checked because there may be length truncation
    fn request(&mut self, payload: &[u8], strict: bool) -> Result<()> {
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
        Ok(())
    }

    fn response(&mut self, payload: &[u8]) -> Result<()> {
        self.info.resp_msg_size = Some(read_u32_be(payload));
        self.info.correlation_id = read_u32_be(&payload[4..]);
        self.info.msg_type = LogMessageType::Response;
        if payload.len() >= 14 {
            self.info.resp_data = Some(payload[..14].try_into().unwrap());
        }
        Ok(())
    }

    fn parse(
        &mut self,
        payload: &[u8],
        proto: IpProtocol,
        direction: PacketDirection,
    ) -> Result<()> {
        if proto != IpProtocol::Tcp {
            return Err(Error::InvalidIpProtocol);
        }
        if payload.len() < KAFKA_REQ_HEADER_LEN {
            return Err(Error::KafkaLogParseFailed);
        }
        match direction {
            PacketDirection::ClientToServer => {
                self.request(payload, false)?;
                self.perf_stats.as_mut().unwrap().inc_req();
            }
            PacketDirection::ServerToClient => {
                self.response(payload)?;
                self.perf_stats.as_mut().unwrap().inc_resp();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::rc::Rc;
    use std::{cell::RefCell, fs};

    use super::*;

    use crate::{
        common::{flow::PacketDirection, l7_protocol_log::L7PerfCache, MetaPacket},
        flow_generator::L7_RRT_CACHE_CAPACITY,
        utils::test::Capture,
    };

    const FILE_DIR: &str = "resources/test/flow_generator/kafka";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name), None);
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
        for packet in packets.iter_mut() {
            packet.lookup_key.direction = if packet.lookup_key.dst_port == first_dst_port {
                PacketDirection::ClientToServer
            } else {
                PacketDirection::ServerToClient
            };
            let payload = match packet.get_l4_payload() {
                Some(p) => p,
                None => continue,
            };

            let mut kafka = KafkaLog::default();
            let param = &ParseParam::from((packet as &MetaPacket, log_cache.clone(), false));

            let is_kafka = kafka.check_payload(payload, param);
            let _ = kafka.parse_payload(payload, param);

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

    #[test]
    fn check_perf() {
        let expected = vec![
            (
                "kafka.pcap",
                L7PerfStats {
                    request_count: 1,
                    response_count: 1,
                    err_client_count: 0,
                    err_server_count: 0,
                    err_timeout: 0,
                    rrt_count: 1,
                    rrt_sum: 4941,
                    rrt_max: 4941,
                },
            ),
            (
                "kafka_fetch.pcap",
                L7PerfStats {
                    request_count: 1,
                    response_count: 1,
                    err_client_count: 0,
                    err_server_count: 0,
                    err_timeout: 0,
                    rrt_count: 1,
                    rrt_sum: 504829,
                    rrt_max: 504829,
                },
            ),
        ];

        for item in expected.iter() {
            assert_eq!(item.1, run_perf(item.0), "parse pcap {} unexcepted", item.0);
        }
    }

    fn run_perf(pcap: &str) -> L7PerfStats {
        let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));
        let mut kafka = KafkaLog::default();

        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(pcap), None);
        let mut packets = capture.as_meta_packets();

        let first_dst_port = packets[0].lookup_key.dst_port;
        for packet in packets.iter_mut() {
            if packet.lookup_key.dst_port == first_dst_port {
                packet.lookup_key.direction = PacketDirection::ClientToServer;
            } else {
                packet.lookup_key.direction = PacketDirection::ServerToClient;
            }

            if packet.get_l4_payload().is_some() {
                let _ = kafka.parse_payload(
                    packet.get_l4_payload().unwrap(),
                    &ParseParam::from((&*packet, rrt_cache.clone(), true)),
                );
            }
        }
        kafka.perf_stats.unwrap()
    }
}
