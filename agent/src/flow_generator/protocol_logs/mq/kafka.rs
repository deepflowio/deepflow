/*
 * Copyright (c) 2023 Yunshan Networks
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
        l7_protocol_log::{KafkaInfoCache, L7ParseResult, L7ProtocolParserInterface, ParseParam},
        meta_packet::EbpfFlags,
    },
    config::handler::TraceType,
    flow_generator::{
        error::{Error, Result},
        protocol_logs::{
            consts::{
                KAFKA_REQ_HEADER_LEN, KAFKA_RESP_HEADER_LEN, KAFKA_STATUS_CODE_CHECKER,
                KAFKA_STATUS_CODE_OFFSET,
            },
            decode_base64_to_string,
            pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response, TraceInfo},
            value_is_default, value_is_negative, AppProtoHead, L7ResponseStatus, LogMessageType,
        },
    },
    utils::bytes::{read_i16_be, read_u16_be, read_u32_be},
};

const KAFKA_PRODUCE: u16 = 0;
const KAFKA_FETCH: u16 = 1;

#[derive(Serialize, Debug, Default, Clone)]
pub struct KafkaInfo {
    msg_type: LogMessageType,
    #[serde(skip)]
    is_tls: bool,

    #[serde(rename = "request_id", skip_serializing_if = "value_is_default")]
    pub correlation_id: u32,
    #[serde(skip_serializing_if = "value_is_default")]
    pub trace_id: String,

    // request
    #[serde(rename = "request_length", skip_serializing_if = "value_is_negative")]
    pub req_msg_size: Option<u32>,
    #[serde(skip)]
    pub api_version: u16,
    #[serde(rename = "request_type")]
    pub api_key: u16,
    #[serde(skip)]
    pub client_id: String,
    // Extract only from KAFKA_PRODUCE and KAFKA_FETCH
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub topic_name: String,

    // reponse
    #[serde(rename = "response_length", skip_serializing_if = "value_is_negative")]
    pub resp_msg_size: Option<u32>,
    #[serde(rename = "response_status")]
    pub status: L7ResponseStatus,
    #[serde(rename = "response_code", skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i32>,

    rrt: u64,
}

impl L7ProtocolInfoInterface for KafkaInfo {
    fn session_id(&self) -> Option<u32> {
        Some(self.correlation_id)
    }

    fn merge_log(
        &mut self,
        other: &mut crate::common::l7_protocol_info::L7ProtocolInfo,
    ) -> Result<()> {
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
    pub fn merge(&mut self, other: &mut Self) {
        if self.resp_msg_size.is_none() {
            self.resp_msg_size = other.resp_msg_size;
        }
        if other.status != L7ResponseStatus::default() {
            self.status = other.status;
        }
        if other.status_code.is_some() {
            self.status_code = other.status_code;
        }
        crate::flow_generator::protocol_logs::swap_if!(self, topic_name, is_empty, other);
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
        let flags = if f.is_tls {
            EbpfFlags::TLS.bits()
        } else {
            EbpfFlags::NONE.bits()
        };
        let log = L7ProtocolSendLog {
            req_len: f.req_msg_size,
            resp_len: f.resp_msg_size,
            req: L7Request {
                req_type: String::from(command_str),
                resource: f.topic_name,
                ..Default::default()
            },
            version: Some(f.api_version.to_string()),
            resp: L7Response {
                status: f.status,
                code: f.status_code,
                ..Default::default()
            },
            ext_info: Some(ExtendedInfo {
                request_id: Some(f.correlation_id),
                ..Default::default()
            }),
            trace_info: Some(TraceInfo {
                trace_id: if f.trace_id.is_empty() {
                    None
                } else {
                    Some(f.trace_id)
                },
                ..Default::default()
            }),
            flags,
            ..Default::default()
        };
        return log;
    }
}

#[derive(Default)]
pub struct KafkaLog {
    perf_stats: Option<L7PerfStats>,
}

impl L7ProtocolParserInterface for KafkaLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol()
            || param.l4_protocol != IpProtocol::TCP
            || payload.len() < KAFKA_REQ_HEADER_LEN
        {
            return false;
        }
        let mut info = KafkaInfo::default();
        let ok = self.request(payload, true, &mut info).is_ok() && info.check();
        self.reset();
        ok
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };
        let mut info = KafkaInfo::default();
        Self::parse(self, payload, param.l4_protocol, param.direction, &mut info)?;
        info.is_tls = param.is_tls();

        // handle kafka status code
        {
            let mut log_cache = param.l7_perf_cache.borrow_mut();
            if let Some(previous) = log_cache.rrt_cache.get(&info.cal_cache_key(param)) {
                match (previous.msg_type, info.msg_type) {
                    (LogMessageType::Request, LogMessageType::Response)
                        if param.time < previous.time + param.rrt_timeout as u64 =>
                    {
                        if let Some(req) = previous.kafka_info.as_ref() {
                            self.set_status_code(
                                req.api_key,
                                req.api_version,
                                if payload.len() >= KAFKA_STATUS_CODE_CHECKER {
                                    read_i16_be(&payload[KAFKA_STATUS_CODE_OFFSET..])
                                } else {
                                    0
                                },
                                &mut info,
                            )
                        }
                    }
                    (LogMessageType::Response, LogMessageType::Request)
                        if previous.time < param.time + param.rrt_timeout as u64 =>
                    {
                        if let Some(resp) = previous.kafka_info.as_ref() {
                            self.set_status_code(
                                info.api_key,
                                info.api_version,
                                resp.code,
                                &mut info,
                            )
                        }
                    }
                    _ => {}
                }
            }
        }

        info.cal_rrt(
            param,
            Some(KafkaInfoCache {
                api_key: info.api_key,
                api_version: info.api_version,
                code: if payload.len() >= KAFKA_STATUS_CODE_CHECKER {
                    read_i16_be(&payload[KAFKA_STATUS_CODE_OFFSET..])
                } else {
                    0
                },
            }),
        )
        .map(|rrt| {
            info.rrt = rrt;
            self.perf_stats.as_mut().map(|p| p.update_rrt(rrt));
        });
        if param.parse_log {
            Ok(L7ParseResult::Single(L7ProtocolInfo::KafkaInfo(info)))
        } else {
            Ok(L7ParseResult::None)
        }
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Kafka
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

impl KafkaLog {
    const MSG_LEN_SIZE: usize = 4;
    const MAX_TRACE_ID: usize = 255;

    fn decode_varint(buf: &[u8]) -> (usize, usize) {
        let mut shift = 0;
        let mut n = 0;
        let mut x = 0;
        while shift < 64 {
            if n >= buf.len() {
                return (0, 0);
            }
            let b = buf[n] as usize;
            n += 1;
            // The following is divided into three steps:
            // 1: b&0x7F: Get 7 bits of valid data
            // 2: (b & 0x7F) << shift: Since shift is small-endian, it is necessary to move 7bits
            //    to the high position for each Byte of data processed
            // 3: Perform or operations on x with the current byte
            // =======================================================================================
            // 下面这个分成三步走:
            // 1: b & 0x7F: 获取下7bits有效数据
            // 2: (b & 0x7F) << shift: 由于是小端序, 所以每次处理一个Byte数据, 都需要向高位移动7bits
            // 3: 将数据x和当前的这个字节数据 | 在一起
            x |= (b & 0x7F) << shift;
            if (b & 0x80) == 0 {
                return (x, n);
            }
            shift += 7;
        }
        return (0, 0);
    }

    fn get_topics_name_offset(api_key: u16, api_version: u16) -> Option<usize> {
        match api_key {
            KAFKA_PRODUCE => {
                if api_version <= 2 {
                    // Offset for API version <= 2
                    Some(24)
                } else if api_version <= 8 {
                    // Offset for API version <= 8
                    // Produce Request (Version: 8) => transactional_id acks timeout_ms [topic_data]
                    // transactional_id => NULLABLE_STRING
                    // acks => INT16
                    // timeout_ms => INT32
                    // topic_data => name [partition_data]
                    //     name => STRING
                    //     partition_data => index records
                    //     index => INT32
                    //     records => RECORDS
                    Some(26)
                } else if api_version == 9 {
                    // Offset for API version == 9
                    // Produce Request (Version: 9) => transactional_id acks timeout_ms [topic_data] TAG_BUFFER
                    // transactional_id => COMPACT_NULLABLE_STRING
                    // acks => INT16
                    // timeout_ms => INT32
                    // topic_data => name [partition_data] TAG_BUFFER
                    //     name => COMPACT_STRING
                    //     partition_data => index records TAG_BUFFER
                    //     index => INT32
                    //     records => COMPACT_RECORDS
                    Some(22)
                } else {
                    // Invalid API version
                    None
                }
            }
            KAFKA_FETCH => {
                if api_version <= 2 {
                    // Offset for API version <= 2
                    Some(30)
                } else if api_version == 3 {
                    // Offset for API version == 3
                    Some(34)
                } else if api_version <= 6 {
                    // Offset for API version <= 6
                    Some(35)
                } else if api_version <= 11 {
                    // Fetch Request (Version: 11) => replica_id max_wait_ms min_bytes max_bytes isolation_level session_id session_epoch [topics] [forgotten_topics_data] rack_id
                    // replica_id => INT32
                    // max_wait_ms => INT32
                    // min_bytes => INT32
                    // max_bytes => INT32
                    // isolation_level => INT8
                    // session_id => INT32
                    // session_epoch => INT32
                    // topics => topic [partitions]
                    //     topic => STRING
                    //     partitions => partition current_leader_epoch fetch_offset log_start_offset partition_max_bytes
                    //     partition => INT32
                    //     current_leader_epoch => INT32
                    //     fetch_offset => INT64
                    //     log_start_offset => INT64
                    //     partition_max_bytes => INT32
                    // forgotten_topics_data => topic [partitions]
                    //     topic => STRING
                    //     partitions => INT32
                    // rack_id => STRING
                    Some(43)
                } else if api_version == 12 {
                    // Fetch Request (Version: 12) => replica_id max_wait_ms min_bytes max_bytes isolation_level session_id session_epoch [topics] [forgotten_topics_data] rack_id TAG_BUFFER
                    // replica_id => INT32
                    // max_wait_ms => INT32
                    // min_bytes => INT32
                    // max_bytes => INT32
                    // isolation_level => INT8
                    // session_id => INT32
                    // session_epoch => INT32
                    // topics => topic [partitions] TAG_BUFFER
                    //     topic => COMPACT_STRING
                    //     partitions => partition current_leader_epoch fetch_offset last_fetched_epoch log_start_offset partition_max_bytes TAG_BUFFER
                    //     partition => INT32
                    //     current_leader_epoch => INT32
                    //    fetch_offset => INT64
                    //     last_fetched_epoch => INT32
                    //     log_start_offset => INT64
                    //     partition_max_bytes => INT32
                    // forgotten_topics_data => topic [partitions] TAG_BUFFER
                    //     topic => COMPACT_STRING
                    //     partitions => INT32
                    // rack_id => COMPACT_STRING
                    // TODO Some(39)
                    Some(40)
                } else {
                    // Invalid API version
                    None
                }
            }
            _ => None,
        }
    }

    fn decode_topics_name(payload: &[u8], client_id_len: usize, info: &mut KafkaInfo) {
        let Some(mut topic_offset) = Self::get_topics_name_offset(info.api_key, info.api_version)
        else {
            return;
        };
        topic_offset += client_id_len;
        match (info.api_key, info.api_version) {
            (KAFKA_PRODUCE, 9) | (KAFKA_FETCH, 12) if topic_offset + 1 < payload.len() => {
                let (topic_count, offset) = Self::decode_varint(&payload[topic_offset..]);
                if offset == 0 || topic_count <= 1 {
                    return;
                }
                topic_offset += offset;
                let (mut topic_name_len, offset) = Self::decode_varint(&payload[topic_offset..]);
                if offset == 0 {
                    return;
                }
                topic_offset += offset;
                topic_name_len -= 1;
                if topic_name_len <= payload[topic_offset..].len() {
                    info.topic_name = String::from_utf8_lossy(
                        &payload[topic_offset..topic_offset + topic_name_len],
                    )
                    .into_owned();
                }
            }
            _ if topic_offset + 2 < payload.len() => {
                let topic_name_len = read_u16_be(&payload[topic_offset..]) as usize;
                if topic_name_len <= payload[topic_offset + 2..].len() {
                    info.topic_name = String::from_utf8_lossy(
                        &payload[topic_offset + 2..topic_offset + 2 + topic_name_len],
                    )
                    .into_owned();
                }
            }
            _ => return,
        }
    }

    // traceparent: 00-TRACEID-SPANID-01
    fn decode_traceparent_trace_id(payload: &str, info: &mut KafkaInfo) {
        let tag = TraceType::TraceParent.to_string();
        let mut start = 0;
        let mut trace_id = "";
        while start < payload.len() {
            if !payload.is_char_boundary(start) {
                break;
            }
            let index = payload[start..].find(tag.as_str());
            if index.is_none() {
                break;
            }
            let index = index.unwrap();

            let start_index = payload[start + index..].find("00-");
            if let Some(current_index) = start_index {
                let trace_id_index = start + index + current_index + 3;
                let trace_id_length = payload[trace_id_index..].len().min(Self::MAX_TRACE_ID);
                trace_id = &payload[trace_id_index..trace_id_index + trace_id_length];
                break;
            }
            start += index + tag.len();
        }

        if trace_id.len() > 0 {
            if let Some(end_index) = trace_id.find("-") {
                info.trace_id = decode_base64_to_string(&trace_id[..end_index]);
            }
        }
    }

    // Example: 'sw8  1-{trace-id}-{other}'
    fn decode_sw8_trace_id(payload: &str, info: &mut KafkaInfo) {
        let tag = TraceType::Sw8.to_string();
        let mut start = 0;
        let mut trace_id = "";
        while start < payload.len() {
            if !payload.is_char_boundary(start) {
                break;
            }
            let index = payload[start..].find(tag.as_str());
            if index.is_none() {
                break;
            }
            let index = index.unwrap();

            let start_index = payload[start + index..].find("1-");
            if let Some(current_index) = start_index {
                let trace_id_index = start + index + current_index + 2;
                let trace_id_length = payload[trace_id_index..].len().min(Self::MAX_TRACE_ID);
                trace_id = &payload[trace_id_index..trace_id_index + trace_id_length];
                break;
            }
            start += index + tag.len();
        }

        if trace_id.len() > 0 {
            if let Some(end_index) = trace_id.find("-") {
                info.trace_id = decode_base64_to_string(&trace_id[..end_index]);
            }
        }
    }

    // 协议识别的时候严格检查避免误识别，日志解析的时候不用严格检查因为可能有长度截断
    // ================================================================================
    // The protocol identification is strictly checked to avoid misidentification.
    // The log analysis is not strictly checked because there may be length truncation
    fn request(&mut self, payload: &[u8], strict: bool, info: &mut KafkaInfo) -> Result<()> {
        let req_len = read_u32_be(payload);
        info.req_msg_size = Some(req_len);
        let client_id_len = read_u16_be(&payload[12..]) as usize;
        if payload.len() < KAFKA_REQ_HEADER_LEN + client_id_len {
            return Err(Error::KafkaLogParseFailed);
        }

        if strict && req_len as usize != payload.len() - Self::MSG_LEN_SIZE {
            return Err(Error::KafkaLogParseFailed);
        }

        info.msg_type = LogMessageType::Request;
        info.api_key = read_u16_be(&payload[4..]);
        info.api_version = read_u16_be(&payload[6..]);
        info.correlation_id = read_u32_be(&payload[8..]);
        info.client_id = String::from_utf8_lossy(&payload[14..14 + client_id_len]).into_owned();
        if !info.client_id.is_ascii() {
            return Err(Error::KafkaLogParseFailed);
        }
        // topic
        Self::decode_topics_name(payload, client_id_len, info);
        // sw8
        let payload = String::from_utf8_lossy(&payload[14..14 + client_id_len]);
        Self::decode_sw8_trace_id(&payload, info);
        Self::decode_traceparent_trace_id(&payload, info);
        Ok(())
    }

    fn response(&mut self, payload: &[u8], info: &mut KafkaInfo) -> Result<()> {
        info.resp_msg_size = Some(read_u32_be(payload));
        info.correlation_id = read_u32_be(&payload[4..]);
        info.msg_type = LogMessageType::Response;
        Ok(())
    }

    fn parse(
        &mut self,
        payload: &[u8],
        proto: IpProtocol,
        direction: PacketDirection,
        info: &mut KafkaInfo,
    ) -> Result<()> {
        if proto != IpProtocol::TCP {
            return Err(Error::InvalidIpProtocol);
        }

        match direction {
            PacketDirection::ClientToServer => {
                if payload.len() < KAFKA_REQ_HEADER_LEN {
                    return Err(Error::KafkaLogParseFailed);
                }
                self.request(payload, false, info)?;
                self.perf_stats.as_mut().map(|p| p.inc_req());
            }
            PacketDirection::ServerToClient => {
                if payload.len() < KAFKA_RESP_HEADER_LEN {
                    return Err(Error::KafkaLogParseFailed);
                }
                self.response(payload, info)?;
                self.perf_stats.as_mut().map(|p| p.inc_resp());
            }
        }
        Ok(())
    }

    /*
        reference:  https://kafka.apache.org/protocol.html#protocol_messages

        only fetch api and api version > 7 parse the error code

        Fetch Response (Version: 7) => throttle_time_ms error_code session_id [responses]
            throttle_time_ms => INT32
            error_code => INT16
            ...
    */
    pub fn set_status_code(
        &mut self,
        api_key: u16,
        api_version: u16,
        code: i16,
        info: &mut KafkaInfo,
    ) {
        if api_key == KAFKA_FETCH && api_version >= 7 {
            info.status_code = Some(code as i32);
            if code == 0 {
                info.status = L7ResponseStatus::Ok;
            } else {
                info.status = L7ResponseStatus::ServerError;
                self.perf_stats.as_mut().map(|p| p.inc_resp_err());
            }
        }
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
            let param = &ParseParam::new(
                packet as &MetaPacket,
                log_cache.clone(),
                Default::default(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Default::default(),
                true,
                true,
            );

            let is_kafka = kafka.check_payload(payload, param);
            let info = kafka.parse_payload(payload, param);
            if let Ok(info) = info {
                match info.unwrap_single() {
                    L7ProtocolInfo::KafkaInfo(i) => {
                        output.push_str(&format!("{:?} is_kafka: {}\n", i, is_kafka));
                    }
                    _ => unreachable!(),
                }
            } else {
                output.push_str(&format!(
                    "{:?} is_kafka: {}\n",
                    KafkaInfo::default(),
                    is_kafka
                ));
            }
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
            ("kafka.pcap", "kafka.result"),
            ("produce.pcap", "produce.result"),
            ("produce-v9.pcap", "produce-v9.result"),
        ];

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
                    ..Default::default()
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
                    ..Default::default()
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
                    &ParseParam::new(
                        &*packet,
                        rrt_cache.clone(),
                        Default::default(),
                        #[cfg(any(target_os = "linux", target_os = "android"))]
                        Default::default(),
                        true,
                        true,
                    ),
                );
            }
        }
        kafka.perf_stats.unwrap()
    }

    #[test]
    fn trace_id() {
        let payload =
            "sw8-abckejaij,sw8  1-abcdefghi-jjaiejfeajf traceparent: 00-123456789-01".as_bytes();
        let payload = String::from_utf8_lossy(payload);

        let mut info = KafkaInfo::default();

        KafkaLog::decode_sw8_trace_id(&payload, &mut info);
        assert_eq!(
            info.trace_id, "abcdefghi",
            "parse trace id {} unexcepted",
            info.trace_id
        );

        KafkaLog::decode_traceparent_trace_id(&payload, &mut info);
        assert_eq!(
            info.trace_id, "123456789",
            "parse trace id {} unexcepted",
            info.trace_id
        );
    }
}
