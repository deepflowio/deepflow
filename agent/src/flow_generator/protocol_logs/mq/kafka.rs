/*
 * Copyright (c) 2024 Yunshan Networks
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

use std::num::NonZeroUsize;

use lru::LruCache;
use serde::Serialize;

use crate::{
    common::{
        enums::IpProtocol,
        flow::{L7PerfStats, L7Protocol, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, ParseParam},
        meta_packet::EbpfFlags,
    },
    config::handler::TraceType,
    flow_generator::{
        error::{Error, Result},
        protocol_logs::{
            consts::{KAFKA_REQ_HEADER_LEN, KAFKA_RESP_HEADER_LEN},
            decode_base64_to_string,
            pb_adapter::{
                ExtendedInfo, KeyVal, L7ProtocolSendLog, L7Request, L7Response, TraceInfo,
            },
            set_captured_byte, value_is_default, value_is_negative, AppProtoHead, L7ResponseStatus,
            LogMessageType,
        },
    },
    utils::bytes::{read_i16_be, read_i32_be, read_i64_be, read_u16_be, read_u32_be},
};

const KAFKA_PRODUCE: u16 = 0;
const KAFKA_FETCH: u16 = 1;
const KAFKA_JOIN_GROUP: u16 = 11;
const KAFKA_LEAVE_GROUP: u16 = 13;
const KAFKA_SYNC_GROUP: u16 = 14;

#[derive(Serialize, Debug, Default, Clone)]
pub struct KafkaInfo {
    msg_type: LogMessageType,
    #[serde(skip)]
    is_tls: bool,

    #[serde(rename = "request_id", skip_serializing_if = "value_is_default")]
    pub correlation_id: u32,
    #[serde(skip_serializing_if = "value_is_default")]
    pub trace_id: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub span_id: String,

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
    pub partition: i32,
    pub offset: i64,
    pub group_id: String,

    // reponse
    #[serde(rename = "response_length", skip_serializing_if = "value_is_negative")]
    pub resp_msg_size: Option<u32>,
    #[serde(rename = "response_status")]
    pub status: L7ResponseStatus,
    #[serde(rename = "response_code", skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i32>,

    captured_request_byte: u32,
    captured_response_byte: u32,

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

    fn get_endpoint(&self) -> Option<String> {
        if self.topic_name.is_empty() {
            None
        } else {
            Some(self.topic_name.clone())
        }
    }

    fn get_request_resource_length(&self) -> usize {
        self.topic_name.len()
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
        if self.offset == 0 && other.offset > 0 {
            self.offset = other.offset;
        }
        if self.partition == 0 && other.partition > 0 {
            self.partition = other.partition;
        }
        self.msg_type = LogMessageType::Session;
        self.captured_response_byte = other.captured_response_byte;
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
        let resource = match (f.api_key, f.msg_type) {
            (KAFKA_FETCH, LogMessageType::Request) | (KAFKA_FETCH, LogMessageType::Session)
                if !f.topic_name.is_empty() =>
            {
                format!("{}-{}:{}", f.topic_name, f.partition, f.offset)
            }
            (KAFKA_PRODUCE, LogMessageType::Response)
            | (KAFKA_PRODUCE, LogMessageType::Session)
                if !f.topic_name.is_empty() =>
            {
                format!("{}-{}:{}", f.topic_name, f.partition, f.offset)
            }
            _ => String::new(),
        };
        let mut attributes = vec![];
        if !f.group_id.is_empty() {
            attributes.push(KeyVal {
                key: "group_id".to_string(),
                val: f.group_id,
            });
        }
        let log = L7ProtocolSendLog {
            captured_request_byte: f.captured_request_byte,
            captured_response_byte: f.captured_response_byte,
            req_len: f.req_msg_size,
            resp_len: f.resp_msg_size,
            req: L7Request {
                req_type: String::from(command_str),
                resource,
                endpoint: format!("{}-{}", f.topic_name, f.partition),
                domain: f.topic_name,
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
                x_request_id_0: Some(f.correlation_id.to_string()),
                x_request_id_1: Some(f.correlation_id.to_string()),
                attributes: if !attributes.is_empty() {
                    Some(attributes)
                } else {
                    None
                },
                ..Default::default()
            }),
            trace_info: Some(TraceInfo {
                trace_id: if f.trace_id.is_empty() {
                    None
                } else {
                    Some(f.trace_id)
                },
                span_id: if f.span_id.is_empty() {
                    None
                } else {
                    Some(f.span_id)
                },
                ..Default::default()
            }),
            flags,
            ..Default::default()
        };
        return log;
    }
}

pub struct KafkaLog {
    perf_stats: Option<L7PerfStats>,
    sessions: LruCache<u32, (u16, u16)>,
}

impl Default for KafkaLog {
    fn default() -> Self {
        Self {
            perf_stats: None,
            sessions: LruCache::new(NonZeroUsize::new(Self::MAX_SESSION_PER_FLOW).unwrap()),
        }
    }
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
        info.cal_rrt(param).map(|rrt| {
            info.rrt = rrt;
            self.perf_stats.as_mut().map(|p| p.update_rrt(rrt));
        });
        set_captured_byte!(info, param);
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
    const MAX_SESSION_PER_FLOW: usize = 32;

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

    fn decode_string(payload: &[u8]) -> Option<(String, usize)> {
        if 2 > payload.len() {
            return None;
        }

        let length = read_u16_be(payload) as usize;
        if length == 0xffff {
            return Some((String::new(), 2));
        }
        if length > payload[2..].len() {
            return None;
        }

        Some((
            String::from_utf8_lossy(&payload[2..2 + length]).into_owned(),
            length + 2,
        ))
    }

    fn decode_topic_name(payload: &[u8], info: &mut KafkaInfo) -> Result<usize> {
        if let Some((name, length)) = Self::decode_string(payload) {
            info.topic_name = name;
            return Ok(length);
        }

        return Err(Error::KafkaLogParseFailed);
    }

    fn decode_compact_string(payload: &[u8]) -> Option<(String, usize)> {
        let (total_len, header_len) = Self::decode_varint(payload);
        if header_len == 0 || total_len == 0 || total_len < header_len {
            return None;
        }

        let string_offset = header_len;
        let string_len = total_len - header_len;
        if string_len > payload[string_offset..].len() {
            return None;
        }

        Some((
            String::from_utf8_lossy(&payload[header_len..header_len + string_len]).into_owned(),
            total_len,
        ))
    }

    fn decode_compact_topic_name(payload: &[u8], info: &mut KafkaInfo) -> Result<usize> {
        if let Some((name, len)) = Self::decode_compact_string(payload) {
            info.topic_name = name;
            return Ok(len);
        }

        return Err(Error::KafkaLogParseFailed);
    }

    fn decode_produce_request(payload: &[u8], info: &mut KafkaInfo) -> Result<usize> {
        let mut offset = 0;
        match info.api_version {
            // Produce Request (Version: [1-2]) => acks timeout_ms [topic_data]
            //   acks => INT16
            //   timeout_ms => INT32
            //   topic_data => name [partition_data]
            //     name => STRING
            //     partition_data => index records
            //       index => INT32
            //       records => RECORDS
            0..=2 => {
                // topic_data.name: INT16 + INT32 + [topic_data]
                offset = 2 + 4 + 4;
                if offset > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }

                offset += Self::decode_topic_name(&payload[offset..], info)?;
            }
            // Produce Request (Version: [3-8]) => transactional_id acks timeout_ms [topic_data]
            //   transactional_id => NULLABLE_STRING
            //   acks => INT16
            //   timeout_ms => INT32
            //   topic_data => name [partition_data]
            //     name => STRING
            //     partition_data => index records
            //       index => INT32
            //       records => RECORDS
            3..=8 => {
                let Some((_, header_len)) = Self::decode_string(payload) else {
                    return Err(Error::KafkaLogParseFailed);
                };
                // topic_data.name: NULLABLE_STRING + INT16 + INT32 + [topic_data]
                offset = header_len + 2 + 4 + 4;
                if offset > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }

                offset += Self::decode_topic_name(&payload[offset..], info)?;
            }
            // Produce Request (Version: 9) => transactional_id acks timeout_ms [topic_data] TAG_BUFFER
            //   transactional_id => COMPACT_NULLABLE_STRING
            //   acks => INT16
            //   timeout_ms => INT32
            //   topic_data => name [partition_data] TAG_BUFFER
            //     name => COMPACT_STRING
            //     partition_data => index records TAG_BUFFER
            //       index => INT32
            //       records => COMPACT_RECORDS
            9..=10 => {
                let Some((_, header_len)) = Self::decode_string(payload) else {
                    return Err(Error::KafkaLogParseFailed);
                };
                // topic_data: COMPACT_NULLABLE_STRING? + INT16 + INT32
                offset = header_len + 2 + 4;
                if offset > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                let (topic_data_count, header_len) = Self::decode_varint(&payload[offset..]);
                if topic_data_count == 0 || offset + header_len > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                offset += header_len;

                offset += Self::decode_compact_topic_name(&payload[offset..], info)?;
            }
            // TODO
            _ => {}
        }

        Ok(offset)
    }

    fn decode_produce_response_partition(payload: &[u8], info: &mut KafkaInfo) -> Result<usize> {
        let mut offset = match info.api_version {
            0..=8 => {
                if 4 > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                let partition_respones_count = read_u32_be(payload);
                if partition_respones_count == 0 {
                    return Err(Error::KafkaLogParseFailed);
                }

                4
            }
            9..=10 => {
                let (partition_respones_count, partition_respones_header_len) =
                    Self::decode_varint(payload);
                if partition_respones_count == 0 {
                    return Err(Error::KafkaLogParseFailed);
                }

                partition_respones_header_len
            }
            _ => return Err(Error::KafkaLogParseFailed),
        };

        if offset + 4 > payload.len() {
            return Err(Error::KafkaLogParseFailed);
        }
        info.partition = read_i32_be(&payload[offset..]);
        offset += 4;

        if offset + 2 > payload.len() {
            return Err(Error::KafkaLogParseFailed);
        }
        info.status_code = Some(read_i16_be(&payload[offset..]) as i32);
        offset += 2;

        if offset + 8 > payload.len() {
            return Err(Error::KafkaLogParseFailed);
        }
        info.offset = read_i64_be(&payload[offset..]);
        offset += 8;

        Ok(offset)
    }

    fn decode_produce_response(payload: &[u8], info: &mut KafkaInfo) -> Result<()> {
        match info.api_version {
            // Produce Response (Version: 0) => [responses]
            //   responses => name [partition_responses]
            //     name => STRING
            //     partition_responses => index error_code base_offset
            //       index => INT32
            //       error_code => INT16
            //       base_offset => INT64
            0..=8 => {
                // topic name offset: [responses]
                if 4 > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                let respones_count = read_u32_be(payload);
                if respones_count == 0 {
                    return Err(Error::KafkaLogParseFailed);
                }
                let topic_name_len = Self::decode_topic_name(&payload[4..], info)?;

                Self::decode_produce_response_partition(&payload[4 + topic_name_len..], info)?;
            }
            // Produce Response (Version: [9-10]) => [responses]
            //   responses => name [partition_responses]
            //     name => COMPACT_STRING
            //     partition_responses => index error_code base_offset
            //       index => INT32
            //       error_code => INT16
            //       base_offset => INT64
            9..=10 => {
                let (responses_counter, responses_header_len) = Self::decode_varint(payload);
                // topic name offset: [responses]
                if responses_counter == 0 || responses_header_len > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                let topic_name_len =
                    Self::decode_compact_topic_name(&payload[responses_header_len..], info)?;

                Self::decode_produce_response_partition(
                    &payload[responses_header_len + topic_name_len..],
                    info,
                )?;
            }
            _ => return Err(Error::KafkaLogParseFailed),
        }

        Ok(())
    }

    fn decode_fetch_request_topics_partitions(
        payload: &[u8],
        info: &mut KafkaInfo,
    ) -> Result<usize> {
        let offset = match info.api_version {
            0..=8 => {
                let mut offset = 4;
                if offset > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                let topic_count = read_u32_be(payload);
                if topic_count == 0 {
                    return Err(Error::KafkaLogParseFailed);
                }

                if offset + 4 > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                info.partition = read_i32_be(&payload[offset..]);
                offset += 4;

                if offset + 8 > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                info.offset = read_i64_be(&payload[offset..]);
                offset += 8;

                offset
            }
            9..=11 => {
                let mut offset = 4;
                if offset > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                let topic_count = read_u32_be(payload);
                if topic_count == 0 {
                    return Err(Error::KafkaLogParseFailed);
                }

                if offset + 4 > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                info.partition = read_i32_be(&payload[offset..]);
                offset += 8;

                if offset + 8 > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                info.offset = read_i64_be(&payload[offset..]);
                offset += 8;

                offset
            }
            12 => {
                let (topic_count, mut offset) = Self::decode_varint(payload);
                if topic_count == 0 {
                    return Err(Error::KafkaLogParseFailed);
                }

                if offset + 4 > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                info.partition = read_i32_be(&payload[offset..]);
                offset += 8;

                if offset + 8 > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                info.offset = read_i64_be(&payload[offset..]);
                offset += 8;

                offset
            }
            _ => return Err(Error::KafkaLogParseFailed),
        };

        Ok(offset)
    }

    fn decode_fetch_request_topics(payload: &[u8], info: &mut KafkaInfo) -> Result<usize> {
        let mut offset = match info.api_version {
            0..=11 => {
                let mut offset = 4;
                if offset > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                let topic_count = read_u32_be(payload);
                if topic_count == 0 {
                    return Err(Error::KafkaLogParseFailed);
                }

                offset += Self::decode_topic_name(&payload[offset..], info)?;

                offset
            }
            12 => {
                let (topic_count, mut offset) = Self::decode_varint(payload);
                if topic_count == 0 {
                    return Err(Error::KafkaLogParseFailed);
                }

                offset += Self::decode_compact_topic_name(&payload[offset..], info)?;

                offset
            }
            _ => return Err(Error::KafkaLogParseFailed),
        };

        offset += Self::decode_fetch_request_topics_partitions(&payload[offset..], info)?;

        Ok(offset)
    }

    fn decode_fetch_request(payload: &[u8], info: &mut KafkaInfo) -> Result<usize> {
        let mut offset = 0;
        match info.api_version {
            // Fetch Request (Version: [0-2]) => replica_id max_wait_ms min_bytes [topics]
            //   replica_id => INT32
            //   max_wait_ms => INT32
            //   min_bytes => INT32
            //   topics => topic [partitions]
            //     topic => STRING
            //     partitions => partition fetch_offset partition_max_bytes
            //       partition => INT32
            //       fetch_offset => INT64
            //       partition_max_bytes => INT32
            0..=2 => {
                // topics: INT32 + INT32 + INT32
                offset = 4 + 4 + 4;
                if offset > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                offset += Self::decode_fetch_request_topics(&payload[offset..], info)?;
            }
            // Fetch Request (Version: [3]) => replica_id max_wait_ms min_bytes [topics]
            //   replica_id => INT32
            //   max_wait_ms => INT32
            //   min_bytes => INT32
            //   max_bytes => INT32
            //   topics => topic [partitions]
            //     topic => STRING
            //     partitions => partition fetch_offset partition_max_bytes
            //       partition => INT32
            //       fetch_offset => INT64
            //       partition_max_bytes => INT32
            3 => {
                // topics: INT32 + INT32 + INT32 + INT32
                offset = 4 + 4 + 4 + 4;
                if offset > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                offset += Self::decode_fetch_request_topics(&payload[offset..], info)?;
            }
            // Fetch Request (Version: [4-6]) => replica_id max_wait_ms min_bytes [topics]
            //   replica_id => INT32
            //   max_wait_ms => INT32
            //   min_bytes => INT32
            //   max_bytes => INT32
            //   isolation_level => INT8
            //   topics => topic [partitions]
            //     topic => STRING
            //     partitions => partition fetch_offset partition_max_bytes
            //       partition => INT32
            //       fetch_offset => INT64
            //       partition_max_bytes => INT32
            4..=6 => {
                // topics: INT32 + INT32 + INT32 + INT32 + INT8
                offset = 4 + 4 + 4 + 4 + 1;
                if offset > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                offset += Self::decode_fetch_request_topics(&payload[offset..], info)?;
            }
            // Fetch Request (Version: [7-11]) => replica_id max_wait_ms min_bytes [topics]
            //   replica_id => INT32
            //   max_wait_ms => INT32
            //   min_bytes => INT32
            //   max_bytes => INT32
            //   isolation_level => INT8
            //   session_id => INT32
            //   session_epoch => INT32
            //   topics => topic [partitions]
            //     topic => STRING
            //     partitions => partition fetch_offset partition_max_bytes
            //       partition => INT32
            //       fetch_offset => INT64
            //       partition_max_bytes => INT32
            7..=12 => {
                // topics: INT32 + INT32 + INT32 + INT32 + INT8 + INT32 + INT32
                offset = 4 + 4 + 4 + 4 + 1 + 4 + 4;
                if offset > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                offset += Self::decode_fetch_request_topics(&payload[offset..], info)?;
            }
            // TODO
            _ => {}
        }
        Ok(offset)
    }

    fn decode_fetch_partition_response(payload: &[u8], info: &mut KafkaInfo) -> Result<usize> {
        let mut offset = match info.api_version {
            0..=11 => {
                if 4 > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                let partition_respones_count = read_u32_be(payload);
                if partition_respones_count == 0 {
                    return Err(Error::KafkaLogParseFailed);
                }

                4
            }
            12 => {
                let (partition_respones_count, partition_respones_header_len) =
                    Self::decode_varint(payload);
                if partition_respones_count == 0 {
                    return Err(Error::KafkaLogParseFailed);
                }

                partition_respones_header_len
            }
            _ => return Err(Error::KafkaLogParseFailed),
        };

        if offset + 4 > payload.len() {
            return Err(Error::KafkaLogParseFailed);
        }
        info.partition = read_i32_be(&payload[offset..]);
        offset += 4;

        if offset + 2 > payload.len() {
            return Err(Error::KafkaLogParseFailed);
        }
        info.status_code = Some(read_i16_be(&payload[offset..]) as i32);
        offset += 2;

        Ok(offset)
    }

    fn decode_fetch_response(payload: &[u8], info: &mut KafkaInfo) -> Result<()> {
        match info.api_version {
            // Fetch Response (Version: 0) => [responses]
            // responses => topic [partitions]
            //   topic => STRING
            //   partitions => partition_index error_code high_watermark records
            //     partition_index => INT32
            //     error_code => INT16
            //     high_watermark => INT64
            //     records => RECORDS
            0 => {
                // topic name offset: [responses]
                if 4 > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                let respones_count = read_u32_be(payload);
                if respones_count == 0 {
                    return Err(Error::KafkaLogParseFailed);
                }
                let topic_name_len = Self::decode_topic_name(&payload[4..], info)?;

                Self::decode_fetch_partition_response(&payload[4 + topic_name_len..], info)?;
            }
            // Fetch Response (Version: [1-6]) => throttle_time_ms [responses]
            // throttle_time_ms => INT32
            // responses => topic [partitions]
            //   topic => STRING
            //   partitions => partition_index error_code high_watermark records
            //     partition_index => INT32
            //     error_code => INT16
            //     high_watermark => INT64
            //     records => RECORDS
            1..=6 => {
                if 8 > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                let respones_count = read_u32_be(&payload[4..]);
                if respones_count == 0 {
                    return Err(Error::KafkaLogParseFailed);
                }
                let topic_name_len = Self::decode_topic_name(&payload[8..], info)?;

                Self::decode_fetch_partition_response(&payload[8 + topic_name_len..], info)?;
            }
            // Fetch Response (Version: [7]) => throttle_time_ms error_code session_id [responses]
            // throttle_time_ms => INT32
            // error_code => INT16
            // session_id => INT32
            // responses => topic [partitions]
            //   topic => STRING
            //   partitions => partition_index error_code high_watermark records
            //     partition_index => INT32
            //     error_code => INT16
            //     high_watermark => INT64
            //     records => RECORDS
            7..=11 => {
                if 14 > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                let respones_count = read_u32_be(&payload[10..]);
                if respones_count == 0 {
                    return Err(Error::KafkaLogParseFailed);
                }
                let topic_name_len = Self::decode_topic_name(&payload[14..], info)?;

                Self::decode_fetch_partition_response(&payload[14 + topic_name_len..], info)?;
            }
            // Fetch Response (Version: 12) => throttle_time_ms error_code session_id [responses] TAG_BUFFER
            // throttle_time_ms => INT32
            // error_code => INT16
            // session_id => INT32
            // responses => topic [partitions] TAG_BUFFER
            //   topic => COMPACT_STRING
            //   partitions => partition_index error_code high_watermark last_stable_offset log_start_offset [aborted_transactions] preferred_read_replica records TAG_BUFFER
            //     partition_index => INT32
            //     error_code => INT16
            //     high_watermark => INT64
            12 => {
                if 10 > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                let (responses_counter, responses_header_len) = Self::decode_varint(&payload[10..]);
                // topic name offset: [responses]
                if responses_counter == 0 {
                    return Err(Error::KafkaLogParseFailed);
                }
                let topic_name_len =
                    Self::decode_compact_topic_name(&payload[10 + responses_header_len..], info)?;

                Self::decode_fetch_partition_response(
                    &payload[10 + responses_header_len + topic_name_len..],
                    info,
                )?;
            }
            // TODO
            _ => {}
        }

        Ok(())
    }

    fn decode_leave_group_request(payload: &[u8], info: &mut KafkaInfo) -> Result<usize> {
        let mut offset = 0;
        match info.api_version {
            // LeaveGroup Request (Version: [0-3]) => group_id [members]
            // group_id => STRING
            // members => member_id group_instance_id
            //   member_id => STRING
            //   group_instance_id => NULLABLE_STRING
            0..=3 => {
                if let Some((group_id, group_id_len)) = Self::decode_string(payload) {
                    info.group_id = group_id;
                    offset = group_id_len;
                }
            }
            // LeaveGroup Request (Version: [4-5]) => group_id [members] TAG_BUFFER
            // group_id => COMPACT_STRING
            // members => member_id group_instance_id reason TAG_BUFFER
            //   member_id => COMPACT_STRING
            //   group_instance_id => COMPACT_NULLABLE_STRING
            //   reason => COMPACT_NULLABLE_STRING
            4..=5 => {
                if let Some((group_id, group_id_len)) = Self::decode_compact_string(payload) {
                    info.group_id = group_id;
                    offset = group_id_len;
                }
            }
            _ => return Err(Error::KafkaLogParseFailed),
        }

        Ok(offset)
    }

    fn decode_leave_group_response(payload: &[u8], info: &mut KafkaInfo) -> Result<()> {
        match info.api_version {
            // LeaveGroup Response (Version: 0) => error_code
            //   error_code => INT16
            0 => {
                if 2 > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                info.status_code = Some(read_i16_be(payload) as i32);
            }
            // LeaveGroup Response (Version: 1) => throttle_time_ms error_code
            //   throttle_time_ms => INT32
            //   error_code => INT16
            1..=5 => {
                if 6 > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                info.status_code = Some(read_i16_be(&payload[4..]) as i32);
            }
            _ => return Err(Error::KafkaLogParseFailed),
        }

        Ok(())
    }

    fn decode_join_group_request(payload: &[u8], info: &mut KafkaInfo) -> Result<usize> {
        let mut offset = 0;
        match info.api_version {
            // JoinGroup Request (Version: 0) => group_id session_timeout_ms member_id protocol_type [protocols]
            //   group_id => STRING
            //   session_timeout_ms => INT32
            //   member_id => STRING
            //   protocol_type => STRING
            //   protocols => name metadata
            //     name => STRING
            //     metadata => BYTES
            0..=5 => {
                if let Some((group_id, group_id_len)) = Self::decode_string(payload) {
                    info.group_id = group_id;
                    offset = group_id_len;
                }
            }
            // JoinGroup Request (Version: 9) => group_id session_timeout_ms rebalance_timeout_ms member_id group_instance_id protocol_type [protocols] reason TAG_BUFFER
            //   group_id => COMPACT_STRING
            //   session_timeout_ms => INT32
            //   rebalance_timeout_ms => INT32
            //   member_id => COMPACT_STRING
            //   group_instance_id => COMPACT_NULLABLE_STRING
            //   protocol_type => COMPACT_STRING
            //   protocols => name metadata TAG_BUFFER
            //     name => COMPACT_STRING
            //     metadata => COMPACT_BYTES
            //   reason => COMPACT_NULLABLE_STRING
            6..=9 => {
                if let Some((group_id, group_id_len)) = Self::decode_compact_string(payload) {
                    info.group_id = group_id;
                    offset = group_id_len;
                }
            }
            _ => return Err(Error::KafkaLogParseFailed),
        }

        Ok(offset)
    }

    fn decode_join_group_response(payload: &[u8], info: &mut KafkaInfo) -> Result<()> {
        match info.api_version {
            // JoinGroup Response (Version: 0) => error_code generation_id protocol_name leader member_id [members]
            //   error_code => INT16
            //   generation_id => INT32
            //   protocol_name => STRING
            //   leader => STRING
            //   member_id => STRING
            //   members => member_id metadata
            //     member_id => STRING
            //     metadata => BYTES
            0..=1 => {
                if 2 > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                info.status_code = Some(read_i16_be(payload) as i32);
            }
            // JoinGroup Response (Version: 2) => throttle_time_ms error_code generation_id protocol_name leader member_id [members]
            //   throttle_time_ms => INT32
            //   error_code => INT16
            //   generation_id => INT32
            //   protocol_name => STRING
            //   leader => STRING
            //   member_id => STRING
            //   members => member_id metadata
            //     member_id => STRING
            //     metadata => BYTES
            2..=9 => {
                if 6 > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                info.status_code = Some(read_i16_be(&payload[4..]) as i32);
            }
            _ => return Err(Error::KafkaLogParseFailed),
        }

        Ok(())
    }

    fn decode_sync_group_request(payload: &[u8], info: &mut KafkaInfo) -> Result<usize> {
        let mut offset = 0;
        match info.api_version {
            // SyncGroup Request (Version: [0-3]) => group_id generation_id member_id group_instance_id [assignments]
            //   group_id => STRING
            //   generation_id => INT32
            //   member_id => STRING
            //   group_instance_id => NULLABLE_STRING
            //   assignments => member_id assignment
            //     member_id => STRING
            //     assignment => BYTES
            0..=3 => {
                if let Some((group_id, group_id_len)) = Self::decode_string(payload) {
                    info.group_id = group_id;
                    offset = group_id_len;
                }
            }
            // SyncGroup Request (Version: [4-5]) => group_id generation_id member_id group_instance_id protocol_type protocol_name [assignments] TAG_BUFFER
            //   group_id => COMPACT_STRING
            //   generation_id => INT32
            //   member_id => COMPACT_STRING
            //   group_instance_id => COMPACT_NULLABLE_STRING
            //   protocol_type => COMPACT_NULLABLE_STRING
            //   protocol_name => COMPACT_NULLABLE_STRING
            //   assignments => member_id assignment TAG_BUFFER
            //     member_id => COMPACT_STRING
            //     assignment => COMPACT_BYTES
            4..=5 => {
                if let Some((group_id, group_id_len)) = Self::decode_compact_string(payload) {
                    info.group_id = group_id;
                    offset = group_id_len;
                }
            }
            _ => return Err(Error::KafkaLogParseFailed),
        }

        Ok(offset)
    }

    fn decode_sync_group_response(payload: &[u8], info: &mut KafkaInfo) -> Result<()> {
        match info.api_version {
            // SyncGroup Response (Version: 0) => error_code assignment
            //   error_code => INT16
            //   assignment => BYTES
            0 => {
                if 2 > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                info.status_code = Some(read_i16_be(payload) as i32);
            }
            // SyncGroup Response (Version: [1-5]) => throttle_time_ms error_code protocol_type protocol_name assignment TAG_BUFFER
            //   throttle_time_ms => INT32
            //   error_code => INT16
            //   protocol_type => COMPACT_NULLABLE_STRING
            //   protocol_name => COMPACT_NULLABLE_STRING
            //   assignment => COMPACT_BYTES
            1..=5 => {
                if 6 > payload.len() {
                    return Err(Error::KafkaLogParseFailed);
                }
                info.status_code = Some(read_i16_be(&payload[4..]) as i32);
            }
            _ => return Err(Error::KafkaLogParseFailed),
        }

        Ok(())
    }

    fn decode_request_body(payload: &[u8], info: &mut KafkaInfo) {
        let offset = match info.api_key {
            // Support Version Range: [0, 9]
            KAFKA_PRODUCE => Self::decode_produce_request(payload, info),
            // Support Version Range: [0, 12]
            KAFKA_FETCH => Self::decode_fetch_request(payload, info),
            // Support Version Range: [0, 9]
            KAFKA_JOIN_GROUP => Self::decode_join_group_request(payload, info),
            // Support Version Range: [0, 5]
            KAFKA_LEAVE_GROUP => Self::decode_leave_group_request(payload, info),
            // Support Version Range: [0, 5]
            KAFKA_SYNC_GROUP => Self::decode_sync_group_request(payload, info),
            _ => return,
        };
        let payload = if let Ok(offset) = offset {
            &payload[offset..]
        } else {
            payload
        };

        // Trace info
        let payload = String::from_utf8_lossy(payload);
        Self::decode_sw8(&payload, info);
        Self::decode_traceparent(&payload, info);
    }

    fn decode_response_body(payload: &[u8], info: &mut KafkaInfo) {
        match info.api_key {
            // Support Version Range: [0, 10]
            KAFKA_PRODUCE => {
                let _ = Self::decode_produce_response(payload, info);
            }
            // Support Version Range: [0, 12]
            KAFKA_FETCH => {
                let _ = Self::decode_fetch_response(payload, info);
            }
            // Support Version Range: [0, 9]
            KAFKA_JOIN_GROUP => {
                let _ = Self::decode_join_group_response(payload, info);
            }
            // Support Version Range: [0, 5]
            KAFKA_LEAVE_GROUP => {
                let _ = Self::decode_leave_group_response(payload, info);
            }
            // Support Version Range: [0, 5]
            KAFKA_SYNC_GROUP => {
                let _ = Self::decode_sync_group_response(payload, info);
            }
            _ => return,
        }
    }

    // traceparent: 00-TRACEID-SPANID-01
    fn decode_traceparent(payload: &str, info: &mut KafkaInfo) {
        let tag = TraceType::TraceParent.as_str();
        let mut start = 0;
        let mut trace_id = "";
        while start < payload.len() {
            if !payload.is_char_boundary(start) {
                break;
            }
            let index = payload[start..].find(tag);
            if index.is_none() {
                break;
            }
            let index = index.unwrap();

            let start_index = payload[start + index..].find("00-");
            if let Some(current_index) = start_index {
                let trace_id_index = start + index + current_index + 3;
                if !payload.is_char_boundary(trace_id_index) {
                    start += index + tag.len();
                    continue;
                }
                let trace_id_length = payload[trace_id_index..].len().min(Self::MAX_TRACE_ID);
                if !payload.is_char_boundary(trace_id_index + trace_id_length) {
                    start += index + tag.len();
                    continue;
                }
                trace_id = &payload[trace_id_index..trace_id_index + trace_id_length];
                break;
            }
            start += index + tag.len();
        }

        if trace_id.len() > 0 {
            let mut segs = trace_id.split('-');
            if let Some(seg) = segs.next() {
                info.trace_id = seg.to_string();
            }
            if let Some(seg) = segs.next() {
                info.span_id = seg.to_string();
            }
        }
    }

    // Example: 'sw8  1-{trace-id}-{other}'
    fn decode_sw8(payload: &str, info: &mut KafkaInfo) {
        let tag = TraceType::Sw8.as_str();
        let mut start = 0;
        let mut trace_id = "";
        while start < payload.len() {
            if !payload.is_char_boundary(start) {
                break;
            }
            let index = payload[start..].find(tag);
            if index.is_none() {
                break;
            }
            let index = index.unwrap();

            let start_index = payload[start + index..].find("1-");
            if let Some(current_index) = start_index {
                let trace_id_index = start + index + current_index + 2;
                if !payload.is_char_boundary(trace_id_index) {
                    start += index + tag.len();
                    continue;
                }
                let trace_id_length = payload[trace_id_index..].len().min(Self::MAX_TRACE_ID);
                if !payload.is_char_boundary(trace_id_index + trace_id_length) {
                    start += index + tag.len();
                    continue;
                }
                trace_id = &payload[trace_id_index..trace_id_index + trace_id_length];
                break;
            }
            start += index + tag.len();
        }

        if trace_id.len() > 0 {
            let mut segs = trace_id.split('-');
            if let Some(seg) = segs.next() {
                info.trace_id = decode_base64_to_string(seg);
            }

            if let (Some(parent_trace_segment_id), Some(parent_span_id)) =
                (segs.next(), segs.next())
            {
                info.span_id = format!(
                    "{}-{}",
                    decode_base64_to_string(parent_trace_segment_id),
                    parent_span_id
                );
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

        self.sessions
            .push(info.correlation_id, (info.api_key, info.api_version));
        Self::decode_request_body(&payload[client_id_len + KAFKA_REQ_HEADER_LEN..], info);
        Ok(())
    }

    fn response(&mut self, payload: &[u8], info: &mut KafkaInfo) -> Result<()> {
        info.resp_msg_size = Some(read_u32_be(payload));
        info.correlation_id = read_u32_be(&payload[4..]);
        info.msg_type = LogMessageType::Response;

        if let Some((key, version)) = self.sessions.peek(&info.correlation_id) {
            info.api_key = *key;
            info.api_version = *version;
            Self::decode_response_body(&payload[KAFKA_RESP_HEADER_LEN..], info);

            if let Some(status_code) = info.status_code {
                if status_code == 0 {
                    info.status = L7ResponseStatus::Ok;
                } else {
                    info.status = L7ResponseStatus::ServerError;
                    self.perf_stats.as_mut().map(|p| p.inc_resp_err());
                }
            }
        }
        Ok(())
    }

    // reference:  https://kafka.apache.org/protocol.html#protocol_messages
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
        let mut kafka = KafkaLog::default();
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

            let param = &mut ParseParam::new(
                packet as &MetaPacket,
                log_cache.clone(),
                Default::default(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Default::default(),
                true,
                true,
            );
            param.set_captured_byte(payload.len());

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
            ("kafka-sw8.pcap", "kafka-sw8.result"),
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
            "sw8-abckejaij,sw8  1-abcdefghi-jjaiejfeajf-1-jaifjei traceparent: 00-123456789-abcdefg-01".as_bytes();
        let payload = String::from_utf8_lossy(payload);

        let mut info = KafkaInfo::default();

        KafkaLog::decode_sw8(&payload, &mut info);
        assert_eq!(
            info.trace_id, "abcdefghi",
            "parse trace id {} unexcepted",
            info.trace_id
        );
        assert_eq!(
            info.span_id, "jjaiejfeajf-1",
            "parse span id {} unexcepted",
            info.span_id
        );

        KafkaLog::decode_traceparent(&payload, &mut info);
        assert_eq!(
            info.trace_id, "123456789",
            "parse trace id {} unexcepted",
            info.trace_id
        );
        assert_eq!(
            info.span_id, "abcdefg",
            "parse span id {} unexcepted",
            info.span_id
        );
    }
}
