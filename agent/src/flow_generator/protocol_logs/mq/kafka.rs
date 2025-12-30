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

use std::{borrow::Cow, fmt, num::NonZeroUsize, str};

use log::debug;
use lru::LruCache;
use nom::{
    bytes::complete::take,
    number::complete::{be_i16, be_i32, be_i64, be_u16, be_u32},
};
use num_enum::FromPrimitive;
use serde::{Serialize, Serializer};

use crate::{
    common::{
        enums::IpProtocol,
        flow::{L7PerfStats, L7Protocol, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, LogCache, ParseParam},
        meta_packet::ApplicationFlags,
    },
    config::handler::{LogParserConfig, TraceType},
    flow_generator::{
        error,
        protocol_logs::{
            pb_adapter::{
                ExtendedInfo, KeyVal, L7ProtocolSendLog, L7Request, L7Response, TraceInfo,
            },
            set_captured_byte, swap_if, value_is_default, value_is_negative, AppProtoHead,
            L7ResponseStatus, PrioFields, BASE_FIELD_PRIORITY,
        },
    },
};

use public::l7_protocol::LogMessageType;

// Keys are from:
//     https://github.com/apache/kafka/blob/56a3c6dde929763aaf74a801bd043fdd474a8ed2/clients/src/main/java/org/apache/kafka/common/protocol/ApiKeys.java#L41
#[derive(Clone, Copy, Debug, FromPrimitive, Serialize)]
#[repr(u16)]
pub enum ApiKey {
    Produce = 0,
    Fetch = 1,
    ListOffsets = 2,
    Metadata = 3,
    LeaderAndIsr = 4,
    StopReplica = 5,
    UpdateMetadata = 6,
    ControlledShutdown = 7,
    OffsetCommit = 8,
    OffsetFetch = 9,
    FindCoordinator = 10,
    JoinGroup = 11,
    Heartbeat = 12,
    LeaveGroup = 13,
    SyncGroup = 14,
    DescribeGroups = 15,
    ListGroups = 16,
    SaslHandshake = 17,
    ApiVersions = 18,
    CreateTopics = 19,
    DeleteTopics = 20,
    DeleteRecords = 21,
    InitProducerId = 22,
    OffsetForLeaderEpoch = 23,
    AddPartitionsToTxn = 24,
    AddOffsetsToTxn = 25,
    EndTxn = 26,
    WriteTxnMarkers = 27,
    TxnOffsetCommit = 28,
    DescribeAcls = 29,
    CreateAcls = 30,
    DeleteAcls = 31,
    DescribeConfigs = 32,
    AlterConfigs = 33,
    AlterReplicaLogDirs = 34,
    DescribeLogDirs = 35,
    SaslAuthenticate = 36,
    CreatePartitions = 37,
    CreateDelegationToken = 38,
    RenewDelegationToken = 39,
    ExpireDelegationToken = 40,
    DescribeDelegationToken = 41,
    DeleteGroups = 42,
    ElectLeaders = 43,
    IncrementalAlterConfigs = 44,
    AlterPartitionReassignments = 45,
    ListPartitionReassignments = 46,
    OffsetDelete = 47,
    DescribeClientQuotas = 48,
    AlterClientQuotas = 49,
    DescribeUserScramCredentials = 50,
    AlterUserScramCredentials = 51,
    Vote = 52,
    BeginQuorumEpoch = 53,
    EndQuorumEpoch = 54,
    DescribeQuorum = 55,
    AlterPartition = 56,
    UpdateFeatures = 57,
    Envelope = 58,
    FetchSnapshot = 59,
    DescribeCluster = 60,
    DescribeProducers = 61,
    BrokerRegistration = 62,
    BrokerHeartbeat = 63,
    UnregisterBroker = 64,
    DescribeTransactions = 65,
    ListTransactions = 66,
    AllocateProducerIds = 67,
    ConsumerGroupHeartbeat = 68,
    ConsumerGroupDescribe = 69,
    ControllerRegistration = 70,
    GetTelemetrySubscriptions = 71,
    PushTelemetry = 72,
    AssignReplicasToDirs = 73,
    ListConfigResources = 74,
    DescribeTopicPartitions = 75,
    ShareGroupHeartbeat = 76,
    ShareGroupDescribe = 77,
    ShareFetch = 78,
    ShareAcknowledge = 79,
    AddRaftVoter = 80,
    RemoveRaftVoter = 81,
    UpdateRaftVoter = 82,
    InitializeShareGroupState = 83,
    ReadShareGroupState = 84,
    WriteShareGroupState = 85,
    DeleteShareGroupState = 86,
    ReadShareGroupStateSummary = 87,
    StreamsGroupHeartbeat = 88,
    StreamsGroupDescribe = 89,
    DescribeShareGroupOffsets = 90,
    AlterShareGroupOffsets = 91,
    DeleteShareGroupOffsets = 92,
    GetReplicaLogInfo = 93,

    #[num_enum(catch_all)]
    Unknown(u16),
}

impl Default for ApiKey {
    fn default() -> Self {
        Self::Unknown(u16::MAX)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Api {
    pub key: ApiKey,
    pub version: u16,
}

impl fmt::Display for Api {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} v{}", self.key, self.version)
    }
}

impl Api {
    fn header_versions(&self) -> Result<(u8, u8)> {
        match (self.key, self.version) {
            (ApiKey::Produce, 9..) => Ok((2, 1)),
            (ApiKey::Produce, 0..) => Ok((1, 0)),
            (ApiKey::Fetch, 12..) => Ok((2, 1)),
            (ApiKey::Fetch, 0..) => Ok((1, 0)),
            (ApiKey::JoinGroup, 6..) => Ok((2, 1)),
            (ApiKey::JoinGroup, 0..) => Ok((1, 0)),
            (ApiKey::LeaveGroup, 4..) => Ok((2, 1)),
            (ApiKey::LeaveGroup, 0..) => Ok((1, 0)),
            (ApiKey::SyncGroup, 4..) => Ok((2, 1)),
            (ApiKey::SyncGroup, 0..) => Ok((1, 0)),
            (ApiKey::ApiVersions, 3..) => Ok((2, 0)),
            (ApiKey::ApiVersions, 0..) => Ok((1, 0)),
            _ => Err(Error::UnsupportedApi(*self)),
        }
    }

    fn request_header_version(&self) -> Result<u8> {
        self.header_versions().map(|(req, _)| req)
    }

    fn response_header_version(&self) -> Result<u8> {
        self.header_versions().map(|(_, resp)| resp)
    }
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("unsupported api {0}")]
    UnsupportedApi(Api),
    #[error("truncated")]
    Truncated,
    #[error("parse failed: {0}")]
    ParseFailed(Cow<'static, str>),
    #[error("correlation id not found")]
    CorrelationIdNotFound,
}

impl From<nom::Err<nom::error::Error<&[u8]>>> for Error {
    fn from(e: nom::Err<nom::error::Error<&[u8]>>) -> Self {
        Error::ParseFailed(e.to_string().into())
    }
}

impl From<Error> for error::Error {
    fn from(e: Error) -> Self {
        error::Error::L7LogParseFailed {
            proto: L7Protocol::Kafka,
            reason: e.to_string().into(),
        }
    }
}

type Result<T, E = Error> = std::result::Result<T, E>;

// the format of types can be found in: https://kafka.apache.org/protocol#protocol_types
mod decoder {
    use std::str;

    use bytes::Buf;
    use log::debug;
    use nom::{
        bytes::complete::take,
        error::{Error as NomError, ErrorKind},
        number::complete::{be_i16, be_i32, be_i8},
        Err as NomErr, IResult,
    };
    use prost::encoding::decode_varint;

    pub fn unsigned_varint(mut input: &[u8]) -> IResult<&[u8], u32> {
        let data = &mut input;
        match decode_varint(data) {
            Ok(v) => {
                if v > u32::MAX as u64 {
                    return Err(NomErr::Failure(NomError::new(input, ErrorKind::MapRes)));
                }
                let remaining = data.remaining();
                let offset = input.len() - remaining;
                Ok((&input[offset..], v as u32))
            }
            Err(e) => {
                debug!("varint decode failed: {:?}", e);
                Err(NomErr::Failure(NomError::new(input, ErrorKind::MapRes)))
            }
        }
    }

    pub fn varint(input: &[u8]) -> IResult<&[u8], i32> {
        unsigned_varint(input).map(|(input, uv)| (input, ((uv >> 1) as i32) ^ (-((uv & 1) as i32))))
    }

    pub fn varlong(mut input: &[u8]) -> IResult<&[u8], i64> {
        let data = &mut input;
        match decode_varint(data) {
            Ok(v) => {
                let remaining = data.remaining();
                let offset = input.len() - remaining;
                Ok((&input[offset..], ((v >> 1) as i64) ^ (-((v & 1) as i64))))
            }
            Err(e) => {
                debug!("varint decode failed: {:?}", e);
                Err(NomErr::Failure(NomError::new(input, ErrorKind::MapRes)))
            }
        }
    }

    #[inline]
    fn str_helper(input: &[u8], length: usize) -> IResult<&[u8], &str> {
        let (input, s) = take(length)(input)?;
        match str::from_utf8(s) {
            Ok(s) => Ok((input, s)),
            Err(_) => Err(NomErr::Failure(NomError::new(input, ErrorKind::MapRes))),
        }
    }

    pub fn string(input: &[u8]) -> IResult<&[u8], &str> {
        let (input, length) = be_i16(input)?;
        if length < 0 {
            return Err(NomErr::Failure(NomError::new(input, ErrorKind::Verify)));
        }
        str_helper(input, length as usize)
    }

    pub fn compact_string(input: &[u8]) -> IResult<&[u8], &str> {
        let (input, length) = unsigned_varint(input)?;
        if length <= 1 {
            return Ok((input, ""));
        }
        str_helper(input, length as usize - 1)
    }

    pub fn nullable_string(input: &[u8]) -> IResult<&[u8], &str> {
        let (input, length) = be_i16(input)?;
        if length <= 0 {
            return Ok((input, ""));
        }
        str_helper(input, length as usize)
    }

    pub fn uuid(input: &[u8]) -> IResult<&[u8], uuid::Uuid> {
        let (input, bytes) = take(16usize)(input)?;
        Ok((input, uuid::Uuid::from_slice(bytes).unwrap()))
    }

    pub fn compact_nullable_string(input: &[u8]) -> IResult<&[u8], &str> {
        compact_string(input)
    }

    pub fn nullable_bytes(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let (input, length) = be_i32(input)?;
        if length <= 0 {
            return Ok((input, &[]));
        }
        Ok(take(length as usize)(input)?)
    }

    pub fn compact_nullable_bytes(input: &[u8]) -> IResult<&[u8], &[u8]> {
        let (input, length) = unsigned_varint(input)?;
        if length <= 1 {
            return Ok((input, &[]));
        }
        Ok(take(length as usize - 1)(input)?)
    }

    pub fn records(input: &[u8]) -> IResult<&[u8], ()> {
        Ok((nullable_bytes(input)?.0, ()))
    }

    pub fn compact_records(input: &[u8]) -> IResult<&[u8], ()> {
        Ok((compact_nullable_bytes(input)?.0, ()))
    }

    // ref: https://kafka.apache.org/documentation/#recordbatch
    #[inline]
    fn header_parser(input: &[u8]) -> IResult<&[u8], Vec<(&str, &str)>> {
        // skip irrelevant fields until `recordsCount`, check reference for details
        let records_count_offset = 8 + 4 + 4 + 1 + 4 + 2 + 4 + 8 + 8 + 8 + 2 + 4;
        let input = take(records_count_offset as usize)(input)?.0;

        let (mut input, records_count) = be_i32(input)?;
        if records_count <= 0 {
            return Ok((input, vec![]));
        }

        let mut headers = vec![];
        for _ in 0..records_count {
            // length
            input = varint(input)?.0;
            // attributes
            input = be_i8(input)?.0;
            // timestampDelta
            input = varlong(input)?.0;
            // offsetDelta
            input = varlong(input)?.0;
            // keyLength
            let result = varint(input)?;
            input = result.0;
            // key
            input = take(result.1 as usize)(input)?.0;
            // valueLength
            let result = varint(input)?;
            input = result.0;
            // value
            input = take(result.1 as usize)(input)?.0;

            // headersCount
            let result = varint(input)?;
            input = result.0;
            if result.1 <= 0 {
                continue;
            }

            // headers
            for _ in 0..result.1 {
                // headerKeyLength
                let result = varint(input)?;
                input = result.0;
                // headerKey
                let result = take(result.1 as usize)(input)?;
                input = result.0;
                let Ok(key) = str::from_utf8(result.1) else {
                    continue;
                };

                // headerValueLength
                let result = varint(input)?;
                input = result.0;
                // headerValue
                let result = take(result.1 as usize)(input)?;
                input = result.0;
                let Ok(value) = str::from_utf8(result.1) else {
                    continue;
                };

                headers.push((key, value));
            }
        }
        Ok((input, headers))
    }

    // parse headers from records to extract trace_id and span_id
    pub fn headers_from_records(input: &[u8]) -> IResult<&[u8], Vec<(&str, &str)>> {
        let (input, records) = nullable_bytes(input)?;
        if records.is_empty() {
            return Ok((input, vec![]));
        }
        match header_parser(records) {
            Ok((_, headers)) => Ok((input, headers)),
            Err(e) => {
                // some messages use the old format which is ignored at the moment
                // ref: https://kafka.apache.org/39/documentation/#messageset
                debug!("failed to parse headers from records: {:?}", e);
                Ok((input, vec![]))
            }
        }
    }

    // parse headers from compact records to extract trace_id and span_id
    pub fn headers_from_compact_records(input: &[u8]) -> IResult<&[u8], Vec<(&str, &str)>> {
        let (input, records) = compact_nullable_bytes(input)?;
        if records.is_empty() {
            return Ok((input, vec![]));
        }
        match header_parser(records) {
            Ok((_, headers)) => Ok((input, headers)),
            Err(e) => {
                // some messages use the old format which is ignored at the moment
                // ref: https://kafka.apache.org/39/documentation/#messageset
                debug!("failed to parse headers from records: {:?}", e);
                Ok((input, vec![]))
            }
        }
    }

    pub fn array(
        input: &[u8],
        mut obj_decoder: impl FnMut(&[u8]) -> IResult<&[u8], ()>,
    ) -> IResult<&[u8], ()> {
        let (mut input, length) = be_i32(input)?;
        if length <= 0 {
            return Ok((input, ()));
        }
        for _ in 0..length {
            let (sub_offset, _) = obj_decoder(input)?;
            input = sub_offset;
        }
        Ok((input, ()))
    }

    pub fn compact_array(
        input: &[u8],
        mut obj_decoder: impl FnMut(&[u8]) -> IResult<&[u8], ()>,
    ) -> IResult<&[u8], ()> {
        let (mut input, length) = unsigned_varint(input)?;
        if length <= 1 {
            return Ok((input, ()));
        }
        for _ in 0..(length - 1) {
            let (sub_offset, _) = obj_decoder(input)?;
            input = sub_offset;
        }
        Ok((input, ()))
    }

    // fields are consumed but not parsed
    // ref: https://cwiki.apache.org/confluence/display/KAFKA/KIP-482%3A+The+Kafka+Protocol+should+Support+Optional+Tagged+Fields#KIP482:TheKafkaProtocolshouldSupportOptionalTaggedFields-Serialization
    pub fn tagged_fields(input: &[u8]) -> IResult<&[u8], ()> {
        let (mut input, length) = unsigned_varint(input)?;
        for _ in 0..length {
            // field tag
            let (field, _) = unsigned_varint(input)?;
            // field length
            let (field, length) = unsigned_varint(field)?;
            // field data
            input = take(length as usize)(field)?.0;
        }
        Ok((input, ()))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn decode_varint_varlong() {
            let testcases = vec![
                // use [0xE, 0x0F] as remaining data because it looks like EOF
                (vec![0x0, 0xE, 0x0F], Some(0), Some(0)),
                (vec![0x1, 0xE, 0x0F], Some(-1), Some(-1)),
                (vec![0x2, 0xE, 0x0F], Some(1), Some(1)),
                (vec![0x81, 0x2, 0xE, 0x0F], Some(-129), Some(-129)),
                // largest/smallest i32
                (
                    vec![0xFE, 0xFF, 0xFF, 0xFF, 0x0F, 0xE, 0x0F],
                    Some(i32::MAX),
                    Some(i32::MAX as i64),
                ),
                (
                    vec![0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0xE, 0x0F],
                    Some(i32::MIN),
                    Some(i32::MIN as i64),
                ),
                // out of i32 range
                (
                    vec![0x80, 0x80, 0x80, 0x80, 0x10, 0xE, 0x0F],
                    None,
                    Some(i32::MAX as i64 + 1),
                ),
                // largest/smallest i64
                (
                    vec![
                        0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0xE, 0x0F,
                    ],
                    None,
                    Some(i64::MAX),
                ),
                (
                    vec![
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0xE, 0x0F,
                    ],
                    None,
                    Some(i64::MIN),
                ),
                // out of i64 range
                (
                    vec![
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0xE, 0x0F,
                    ],
                    None,
                    None,
                ),
            ];
            for (input, s32, s64) in testcases {
                let result = varint(&input);
                if let Some(exp) = s32 {
                    assert!(result.is_ok());
                    let (rest, v) = result.unwrap();
                    assert_eq!(v, exp);
                    assert_eq!(rest, &[0xe, 0x0f]);
                } else {
                    assert!(result.is_err(), "{:?}", result.unwrap());
                }
                let result = varlong(&input);
                if let Some(exp) = s64 {
                    assert!(result.is_ok());
                    let (rest, v) = result.unwrap();
                    assert_eq!(v, exp);
                    assert_eq!(rest, &[0xe, 0x0f]);
                } else {
                    assert!(result.is_err(), "{:?}", result.unwrap());
                }
            }
        }
    }
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct KafkaInfo {
    msg_type: LogMessageType,
    #[serde(skip)]
    is_tls: bool,

    #[serde(rename = "request_id", skip_serializing_if = "value_is_default")]
    pub correlation_id: Option<u32>,
    #[serde(skip_serializing_if = "value_is_default")]
    pub trace_ids: PrioFields,
    #[serde(skip_serializing_if = "value_is_default")]
    pub span_id: String,

    // request
    #[serde(rename = "request_length", skip_serializing_if = "value_is_negative")]
    pub req_msg_size: Option<u32>,
    #[serde(rename = "request_type", serialize_with = "serialize_api_as_api_key")]
    pub api: Api,
    #[serde(skip)]
    pub client_id: String,
    // Extract only from KAFKA_PRODUCE and KAFKA_FETCH
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub topic_name: String,
    pub partition: i32,
    pub offset: i64,
    pub group_id: String,

    // response
    #[serde(rename = "response_length", skip_serializing_if = "value_is_negative")]
    pub resp_msg_size: Option<u32>,
    #[serde(rename = "response_status")]
    pub status: L7ResponseStatus,
    #[serde(rename = "response_code", skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i32>,

    captured_request_byte: u32,
    captured_response_byte: u32,

    rrt: u64,
    #[serde(skip)]
    is_on_blacklist: bool,
    #[serde(skip)]
    resource: Option<String>,
    #[serde(skip)]
    endpoint: Option<String>,
    #[serde(skip)]
    command: Option<String>,
}

// omit version
fn serialize_api_as_api_key<S>(v: &Api, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("{:?}", v.key))
}

impl L7ProtocolInfoInterface for KafkaInfo {
    fn session_id(&self) -> Option<u32> {
        self.correlation_id
    }

    fn merge_log(
        &mut self,
        other: &mut crate::common::l7_protocol_info::L7ProtocolInfo,
    ) -> error::Result<()> {
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
        self.endpoint.clone()
    }

    fn get_request_resource_length(&self) -> usize {
        self.topic_name.len()
    }

    fn is_on_blacklist(&self) -> bool {
        self.is_on_blacklist
    }
}

impl KafkaInfo {
    fn generate_endpoint(&self) -> Option<String> {
        if self.topic_name.is_empty() || self.partition < 0 {
            None
        } else {
            Some(format!("{}-{}", self.topic_name, self.partition))
        }
    }

    pub fn merge(&mut self, other: &mut Self) {
        swap_if!(self, resp_msg_size, is_none, other);
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
        swap_if!(self, topic_name, is_empty, other);
        swap_if!(self, resource, is_none, other);
        swap_if!(self, endpoint, is_none, other);
        swap_if!(self, command, is_none, other);
        if other.is_on_blacklist {
            self.is_on_blacklist = other.is_on_blacklist;
        }
    }

    pub fn check(&self) -> bool {
        if matches!(self.api.key, ApiKey::Unknown(_)) {
            return false;
        }
        return self.client_id.len() > 0 && self.client_id.is_ascii();
    }

    fn set_is_on_blacklist(&mut self, config: &LogParserConfig) {
        if let Some(t) = config.l7_log_blacklist_trie.get(&L7Protocol::Kafka) {
            self.is_on_blacklist = self
                .command
                .as_ref()
                .map(|p| t.request_type.is_on_blacklist(p))
                .unwrap_or_default()
                || self
                    .resource
                    .as_ref()
                    .map(|p| t.request_resource.is_on_blacklist(p))
                    .unwrap_or_default()
                || self
                    .endpoint
                    .as_ref()
                    .map(|p| t.endpoint.is_on_blacklist(p))
                    .unwrap_or_default()
                || t.request_domain.is_on_blacklist(&self.topic_name);
        }
    }

    fn has_trace_info(&self) -> bool {
        !self.trace_ids.is_empty() && !self.span_id.is_empty()
    }
}

impl From<KafkaInfo> for L7ProtocolSendLog {
    fn from(f: KafkaInfo) -> Self {
        let flags = if f.is_tls {
            ApplicationFlags::TLS.bits()
        } else {
            ApplicationFlags::NONE.bits()
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
                req_type: f.command.unwrap_or_default(),
                resource: f.resource.unwrap_or_default(),
                endpoint: f.endpoint.unwrap_or_default(),
                domain: f.topic_name,
                ..Default::default()
            },
            version: Some(f.api.version.to_string()),
            resp: L7Response {
                status: f.status,
                code: f.status_code,
                exception: match f.status_code {
                    Some(KafkaLog::CODE_APIKEY_NOT_SUPPORTED) => {
                        KafkaLog::EXCEPTION_APIKEY_NOT_SUPPORTED.to_owned()
                    }
                    _ => String::new(),
                },
                ..Default::default()
            },
            ext_info: Some(ExtendedInfo {
                request_id: f.correlation_id,
                x_request_id_0: f.correlation_id.map(|id| id.to_string()),
                x_request_id_1: f.correlation_id.map(|id| id.to_string()),
                attributes: if !attributes.is_empty() {
                    Some(attributes)
                } else {
                    None
                },
                ..Default::default()
            }),
            trace_info: Some(TraceInfo {
                trace_ids: f.trace_ids.into_strings_top3(),
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

impl From<&KafkaInfo> for LogCache {
    fn from(info: &KafkaInfo) -> Self {
        LogCache {
            msg_type: info.msg_type,
            resp_status: info.status,
            on_blacklist: info.is_on_blacklist,
            endpoint: info.get_endpoint(),
            ..Default::default()
        }
    }
}

pub struct KafkaLog {
    perf_stats: Option<L7PerfStats>,
    sessions: LruCache<u32, Api>,
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
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> Option<LogMessageType> {
        if !param.ebpf_type.is_raw_protocol() || param.l4_protocol != IpProtocol::TCP {
            return None;
        }
        let mut info = KafkaInfo::default();
        let ok = self.request(payload, true, &mut info).is_ok() && info.check();
        self.reset();
        if ok {
            Some(LogMessageType::Request)
        } else {
            None
        }
    }

    fn parse_payload(
        &mut self,
        payload: &[u8],
        param: &ParseParam,
    ) -> error::Result<L7ParseResult> {
        if param.l4_protocol != IpProtocol::TCP {
            return Err(error::Error::InvalidIpProtocol);
        }
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };
        let mut info = KafkaInfo::default();
        match Self::parse(self, payload, param.direction, &mut info) {
            Ok(()) => {}
            Err(Error::ParseFailed(e)) => {
                // buffer may be truncated
                // if api key is known and correlation id is parsed, treat it as a normal log
                // otherwise return error
                debug!("parse failed: {e}");
                if matches!(info.api.key, ApiKey::Unknown(..)) || info.correlation_id.is_none() {
                    return Err(Error::ParseFailed(e).into());
                }
                if info.msg_type == LogMessageType::Response {
                    info.status = L7ResponseStatus::Ok;
                }
            }
            Err(Error::UnsupportedApi(api)) if !matches!(api.key, ApiKey::Unknown(..)) => {
                debug!("unsupported api: {api}");
                if info.msg_type == LogMessageType::Response {
                    info.status = L7ResponseStatus::Ok;
                    info.status_code = Some(Self::CODE_APIKEY_NOT_SUPPORTED);
                }
            }
            Err(e) => return Err(e.into()),
        }
        info.is_tls = param.is_tls();
        set_captured_byte!(info, param);
        info.resource = match (info.api.key, info.msg_type) {
            (ApiKey::Fetch, LogMessageType::Request) | (ApiKey::Fetch, LogMessageType::Session)
                if !info.topic_name.is_empty() =>
            {
                Some(format!(
                    "{}-{}:{}",
                    info.topic_name, info.partition, info.offset
                ))
            }
            (ApiKey::Produce, LogMessageType::Response)
            | (ApiKey::Produce, LogMessageType::Session)
                if !info.topic_name.is_empty() =>
            {
                Some(format!(
                    "{}-{}:{}",
                    info.topic_name, info.partition, info.offset
                ))
            }
            _ => None,
        };

        info.command = Some(format!("{:?}", info.api.key));
        info.endpoint = info.generate_endpoint();
        if let Some(config) = param.parse_config {
            info.set_is_on_blacklist(config);
        }
        if let Some(perf_stats) = self.perf_stats.as_mut() {
            if info.msg_type == LogMessageType::Response {
                if let Some(endpoint) = info.load_endpoint_from_cache(param, false) {
                    info.endpoint = Some(endpoint.to_string());
                }
            }
            if let Some(stats) = info.perf_stats(param) {
                info.rrt = stats.rrt_sum;
                perf_stats.sequential_merge(&stats);
            }
        }
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
    const MAX_SESSION_PER_FLOW: usize = 32;
    const CODE_APIKEY_NOT_SUPPORTED: i32 = -2;
    const EXCEPTION_APIKEY_NOT_SUPPORTED: &str = "Type not yet inspected by DeepFlow";

    // kafka message parsers
    // references:
    // - https://kafka.apache.org/protocol#protocol_api_keys
    // - https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-kafka.c
    // use kafka-apis.py to find the difference between different verisons of messages

    fn decode_produce_request<'a>(payload: &'a [u8], info: &mut KafkaInfo) -> Result<()> {
        let mut buffer = payload;

        // transactional_id
        if info.api.version >= 9 {
            buffer = decoder::compact_nullable_string(buffer)?.0;
        } else if info.api.version >= 3 {
            buffer = decoder::nullable_string(buffer)?.0;
        }

        // acks, timeout_ms
        let skip = 2 + 4;
        buffer = take(skip as usize)(buffer)?.0;

        if info.api.version >= 9 {
            // topic data
            let _ = decoder::compact_array(buffer, |input| {
                // topic data -> name
                let (input, name) = decoder::compact_string(input)?;
                if info.topic_name.is_empty() {
                    info.topic_name = name.to_string();
                }

                // topic_data -> partition_data (p_data)
                let input = decoder::compact_array(input, |input| {
                    // p_data -> index
                    let input = be_i32(input)?.0;
                    // p_data -> records
                    let input = if info.has_trace_info() {
                        decoder::compact_records(input)?.0
                    } else {
                        let (input, headers) = decoder::headers_from_compact_records(input)?;
                        Self::decode_trace_info(&headers, info);
                        input
                    };
                    // p_data -> _tagged_fields
                    let input = decoder::tagged_fields(input)?.0;
                    Ok((input, ()))
                })?
                .0;

                // topic_data -> _tagged_fields
                let input = decoder::tagged_fields(input)?.0;

                Ok((input, ()))
            })?;

            // _tagged_fields ignored
        } else {
            // topic data
            let _ = decoder::array(buffer, |input| {
                // topic data -> name
                let (input, name) = decoder::string(input)?;
                if info.topic_name.is_empty() {
                    info.topic_name = name.to_string();
                }

                // topic_data -> partition_data (p_data)
                let input = decoder::array(input, |input| {
                    // p_data -> index
                    let input = be_i32(input)?.0;
                    // p_data -> records
                    let input = if info.has_trace_info() {
                        decoder::records(input)?.0
                    } else {
                        let (input, headers) = decoder::headers_from_records(input)?;
                        Self::decode_trace_info(&headers, info);
                        input
                    };
                    Ok((input, ()))
                })?
                .0;

                Ok((input, ()))
            })?;
        };

        Ok(())
    }

    fn decode_produce_response<'a>(payload: &'a [u8], info: &mut KafkaInfo) -> Result<()> {
        let buffer = payload;

        if info.api.version >= 9 {
            // responses
            let _ = decoder::compact_array(buffer, |input| {
                // responses -> name
                let (input, name) = decoder::compact_string(input)?;
                if info.topic_name.is_empty() {
                    info.topic_name = name.to_string();
                }

                // responses -> partition_responses (pr)
                let input = decoder::compact_array(input, |mut input| {
                    // pr -> index
                    (input, info.partition) = be_i32(input)?;
                    // pr -> error_code
                    let error_code = be_i16(input)?;
                    input = error_code.0;
                    info.status_code = Some(error_code.1 as i32);
                    // pr -> base_offset
                    (input, info.offset) = be_i64(input)?;
                    // pr -> log_append_time_ms
                    input = be_i64(input)?.0;
                    // pr -> log_start_offset
                    input = be_i64(input)?.0;
                    // pr -> record_errors
                    input = decoder::compact_array(input, |input| {
                        // record_errors -> batch_index
                        let input = be_i32(input)?.0;
                        // record_errors -> batch_index_error_message
                        let input = decoder::compact_nullable_string(input)?.0;
                        // record_errors -> _tagged_fields
                        let input = decoder::tagged_fields(input)?.0;

                        Ok((input, ()))
                    })?
                    .0;
                    // pr -> error_message
                    input = decoder::compact_nullable_string(input)?.0;
                    // pr -> _tagged_fields
                    input = decoder::tagged_fields(input)?.0;

                    Ok((input, ()))
                })?
                .0;

                // responses -> _tagged_fields
                let input = decoder::tagged_fields(input)?.0;

                Ok((input, ()))
            })?;

            // throttle_time_ms, _tagged_fields ignored
        } else {
            // responses
            let _ = decoder::array(buffer, |input| {
                // responses -> name
                let (input, name) = decoder::string(input)?;
                if info.topic_name.is_empty() {
                    info.topic_name = name.to_string();
                }

                // responses -> partition_responses (pr)
                let input = decoder::array(input, |mut input| {
                    // pr -> index
                    (input, info.partition) = be_i32(input)?;
                    // pr -> error_code
                    let error_code = be_i16(input)?;
                    input = error_code.0;
                    info.status_code = Some(error_code.1 as i32);
                    // pr -> base_offset
                    (input, info.offset) = be_i64(input)?;

                    if info.api.version >= 2 {
                        // pr -> log_append_time_ms
                        input = be_i64(input)?.0;
                    }

                    if info.api.version >= 5 {
                        // pr -> log_start_offset
                        input = be_i64(input)?.0;
                    }

                    if info.api.version >= 8 {
                        // pr -> record_errors
                        input = decoder::array(input, |input| {
                            // record_errors -> batch_index
                            let input = be_i32(input)?.0;
                            // record_errors -> batch_index_error_message
                            let input = decoder::nullable_string(input)?.0;

                            Ok((input, ()))
                        })?
                        .0;
                        // pr -> error_message
                        input = decoder::nullable_string(input)?.0;
                    }

                    Ok((input, ()))
                })?
                .0;

                Ok((input, ()))
            })?;

            // throttle_time_ms ignored
        }

        Ok(())
    }

    fn decode_fetch_request<'a>(payload: &'a [u8], info: &mut KafkaInfo) -> Result<()> {
        let mut buffer = payload;

        let skip = match info.api.version {
            // replica_id, max_wait_ms, min_bytes
            0..=2 => 4 + 4 + 4,
            // replica_id, max_wait_ms, min_bytes, max_bytes
            3 => 4 + 4 + 4 + 4,
            // replica_id, max_wait_ms, min_bytes, max_bytes, isolation_level
            4..=6 => 4 + 4 + 4 + 4 + 1,
            // replica_id, max_wait_ms, min_bytes, max_bytes, isolation_level, session_id, session_epoch
            7..=14 => 4 + 4 + 4 + 4 + 1 + 4 + 4,
            // max_wait_ms, min_bytes, max_bytes, isolation_level, session_id, session_epoch
            _ => 4 + 4 + 4 + 1 + 4 + 4,
        };
        buffer = take(skip as usize)(buffer)?.0;

        if info.api.version >= 12 {
            // topics
            let _ = decoder::compact_array(buffer, |input| {
                let input = if info.api.version >= 13 {
                    // topic -> topic_id
                    let (input, topic_id) = decoder::uuid(input)?;
                    if info.topic_name.is_empty() {
                        info.topic_name = topic_id.hyphenated().to_string();
                    }
                    input
                } else {
                    // topic -> topic
                    let (input, topic) = decoder::compact_string(input)?;
                    if info.topic_name.is_empty() {
                        info.topic_name = topic.to_string();
                    }
                    input
                };

                // topic -> partitions
                let input = decoder::compact_array(input, |input| {
                    // partition -> partition
                    let (input, partition) = be_i32(input)?;
                    info.partition = partition;

                    // partition -> current_leader_epoch
                    let input = be_i32(input)?.0;

                    // partition -> fetch_offset
                    let (input, offset) = be_i64(input)?;
                    info.offset = offset;

                    // last_fetched_epoch, log_start_offset, partition_max_bytes
                    let skip = 4 + 8 + 4;
                    let input = take(skip as usize)(input)?.0;

                    // partition -> _tagged_fields
                    let input = decoder::tagged_fields(input)?.0;

                    Ok((input, ()))
                })?
                .0;

                // topic -> _tagged_fields
                let input = decoder::tagged_fields(input)?.0;

                Ok((input, ()))
            });

            // [forgotten_topics_data], rack_id, _tagged_fields ignored
        } else {
            // topics
            let _ = decoder::array(buffer, |input| {
                // topic -> topic
                let (input, topic) = decoder::string(input)?;
                if info.topic_name.is_empty() {
                    info.topic_name = topic.to_string();
                }

                // topic -> partitions
                let input = decoder::array(input, |input| {
                    // partition -> partition
                    let (mut input, partition) = be_i32(input)?;
                    info.partition = partition;

                    if info.api.version >= 9 {
                        // partition -> current_leader_epoch
                        input = be_i32(input)?.0;
                    }

                    // partition -> fetch_offset
                    let (mut input, offset) = be_i64(input)?;
                    info.offset = offset;

                    if info.api.version >= 5 {
                        // partition ->log_start_offset
                        input = be_i64(input)?.0;
                    }

                    // partition -> partition_max_bytes
                    let input = be_i32(input)?.0;

                    Ok((input, ()))
                })?
                .0;

                Ok((input, ()))
            });

            // [forgotten_topics_data], rack_id ignored
        }

        Ok(())
    }

    fn decode_fetch_response(payload: &[u8], info: &mut KafkaInfo) -> Result<()> {
        let mut buffer = payload;

        if info.api.version >= 1 {
            // throttle_time_ms
            buffer = be_i32(buffer)?.0;
        }

        if info.api.version >= 7 {
            // error_code
            let (b, status_code) = be_i16(buffer)?;
            info.status_code = Some(status_code as i32);
            // session_id
            buffer = be_i32(b)?.0;
        }

        // responses
        if info.api.version >= 12 {
            let _ = decoder::compact_array(buffer, |input| {
                let input = if info.api.version >= 13 {
                    // response -> topic_id
                    let (input, topic_id) = decoder::uuid(input)?;
                    if info.topic_name.is_empty() {
                        info.topic_name = topic_id.hyphenated().to_string();
                    }
                    input
                } else {
                    // response -> topic
                    let (input, topic) = decoder::compact_string(input)?;
                    if info.topic_name.is_empty() {
                        info.topic_name = topic.to_string();
                    }
                    input
                };

                // response -> partitions
                let input = decoder::compact_array(input, |input| {
                    // partition -> partition_index
                    let (input, partition) = be_i32(input)?;
                    info.partition = partition;

                    // partition -> error_code
                    let (input, error_code) = be_i16(input)?;
                    match info.status_code.as_ref() {
                        Some(c) if *c != 0 => (),
                        _ => info.status_code = Some(error_code as i32),
                    }

                    // high_watermark, last_stable_offset, log_start_offset
                    let skip = 8 + 8 + 8;
                    let input = take(skip as usize)(input)?.0;

                    // partition -> aborted_transactions
                    let input = decoder::compact_array(input, |input| {
                        // producer_id, first_offset
                        let skip = 8 + 8;
                        let input = take(skip as usize)(input)?.0;

                        // _tagged_fields
                        let input = decoder::tagged_fields(input)?.0;

                        Ok((input, ()))
                    })?
                    .0;

                    // partition -> preferred_read_replica
                    let input = be_i32(input)?.0;

                    // partition -> records
                    let input = decoder::compact_records(input)?.0;

                    // partition -> _tagged_fields
                    let input = decoder::tagged_fields(input)?.0;

                    Ok((input, ()))
                })?
                .0;

                // response -> _tagged_fields
                let input = decoder::tagged_fields(input)?.0;

                Ok((input, ()))
            })?;

            // _tagged_fields ignored
        } else {
            let _ = decoder::array(buffer, |input| {
                // response -> topic
                let (input, topic) = decoder::string(input)?;
                if info.topic_name.is_empty() {
                    info.topic_name = topic.to_string();
                }

                // response -> partitions
                let input = decoder::array(input, |input| {
                    // partition -> partition_index
                    let (input, partition) = be_i32(input)?;
                    info.partition = partition;

                    // partition -> error_code
                    let (input, error_code) = be_i16(input)?;
                    match info.status_code.as_ref() {
                        Some(c) if *c != 0 => (),
                        _ => info.status_code = Some(error_code as i32),
                    }

                    // partition -> high_watermark
                    let mut input = be_i64(input)?.0;

                    if info.api.version >= 4 {
                        // partition -> last_stable_offset
                        input = be_i64(input)?.0;
                    }

                    if info.api.version >= 5 {
                        // partition -> log_start_offset
                        input = be_i64(input)?.0;
                    }

                    if info.api.version >= 4 {
                        // partition -> aborted_transactions
                        input = decoder::array(input, |input| {
                            // producer_id, first_offset
                            let skip = 8 + 8;
                            let input = take(skip as usize)(input)?.0;

                            Ok((input, ()))
                        })?
                        .0;
                    }

                    if info.api.version >= 11 {
                        // partition -> preferred_read_replica
                        input = be_i32(input)?.0;
                    }

                    // partition -> records
                    let input = decoder::records(input)?.0;

                    Ok((input, ()))
                })?
                .0;

                Ok((input, ()))
            })?;
        }

        Ok(())
    }

    fn decode_join_group_request<'a>(payload: &'a [u8], info: &mut KafkaInfo) -> Result<()> {
        // group_id
        let group_id = if info.api.version >= 6 {
            decoder::compact_string(payload)?.1
        } else {
            decoder::string(payload)?.1
        };
        info.group_id = group_id.to_owned();

        Ok(())
    }

    fn decode_join_group_response(payload: &[u8], info: &mut KafkaInfo) -> Result<()> {
        let mut buffer = payload;

        if info.api.version >= 2 {
            // throttle_time_ms
            buffer = be_i32(buffer)?.0;
        }

        // error_code
        let error_code = be_i16(buffer)?.1;
        info.status_code = Some(error_code as i32);

        Ok(())
    }

    fn decode_leave_group_request<'a>(payload: &'a [u8], info: &mut KafkaInfo) -> Result<()> {
        // group_id
        let group_id = if info.api.version >= 4 {
            decoder::compact_string(payload)?.1
        } else {
            decoder::string(payload)?.1
        };
        info.group_id = group_id.to_owned();

        Ok(())
    }

    fn decode_leave_group_response(payload: &[u8], info: &mut KafkaInfo) -> Result<()> {
        let mut buffer = payload;

        if info.api.version >= 1 {
            // throttle_time_ms
            buffer = be_i32(buffer)?.0;
        }

        // error_code
        let error_code = be_i16(buffer)?.1;
        info.status_code = Some(error_code as i32);

        Ok(())
    }

    fn decode_sync_group_request<'a>(payload: &'a [u8], info: &mut KafkaInfo) -> Result<()> {
        // group_id
        let group_id = if info.api.version >= 4 {
            decoder::compact_string(payload)?.1
        } else {
            decoder::string(payload)?.1
        };
        info.group_id = group_id.to_owned();

        Ok(())
    }

    fn decode_sync_group_response(payload: &[u8], info: &mut KafkaInfo) -> Result<()> {
        let mut buffer = payload;

        if info.api.version >= 1 {
            // throttle_time_ms
            buffer = be_i32(buffer)?.0;
        }

        // error_code
        let error_code = be_i16(buffer)?.1;
        info.status_code = Some(error_code as i32);

        Ok(())
    }

    fn decode_api_versions_response(payload: &[u8], info: &mut KafkaInfo) -> Result<()> {
        let error_code = be_i16(payload)?.1;
        info.status_code = Some(error_code as i32);

        Ok(())
    }

    fn decode_request_body<'a>(payload: &'a [u8], info: &mut KafkaInfo) -> Result<()> {
        let _ = match info.api.key {
            ApiKey::Produce => Self::decode_produce_request(payload, info)?,
            ApiKey::Fetch => Self::decode_fetch_request(payload, info)?,
            ApiKey::JoinGroup => Self::decode_join_group_request(payload, info)?,
            ApiKey::LeaveGroup => Self::decode_leave_group_request(payload, info)?,
            ApiKey::SyncGroup => Self::decode_sync_group_request(payload, info)?,
            ApiKey::ApiVersions => (), // do nothing
            _ => return Err(Error::UnsupportedApi(info.api)),
        };

        Ok(())
    }

    fn decode_response_body(payload: &[u8], info: &mut KafkaInfo) -> Result<()> {
        let _ = match info.api.key {
            ApiKey::Produce => Self::decode_produce_response(payload, info)?,
            ApiKey::Fetch => Self::decode_fetch_response(payload, info)?,
            ApiKey::JoinGroup => Self::decode_join_group_response(payload, info)?,
            ApiKey::LeaveGroup => Self::decode_leave_group_response(payload, info)?,
            ApiKey::SyncGroup => Self::decode_sync_group_response(payload, info)?,
            ApiKey::ApiVersions => Self::decode_api_versions_response(payload, info)?,
            _ => return Err(Error::UnsupportedApi(info.api)),
        };

        Ok(())
    }

    fn decode_trace_info(headers: &[(&str, &str)], info: &mut KafkaInfo) {
        for (k, v) in headers {
            let tp = TraceType::from(*k);
            if !matches!(tp, TraceType::TraceParent | TraceType::Sw8) {
                continue;
            }
            if let Some(trace_id) = tp.decode_trace_id(v) {
                info.trace_ids
                    .merge_field(BASE_FIELD_PRIORITY, trace_id.to_string());
            }
            if let Some(span_id) = tp.decode_span_id(v) {
                info.span_id = span_id.to_string();
            }
        }
    }

    // 协议识别的时候严格检查避免误识别，日志解析的时候不用严格检查因为可能有长度截断
    // ================================================================================
    // The protocol identification is strictly checked to avoid misidentification.
    // The log analysis is not strictly checked because there may be length truncation
    fn request(&mut self, payload: &[u8], check: bool, info: &mut KafkaInfo) -> Result<()> {
        info.msg_type = LogMessageType::Request;

        let (payload, length) = be_u32(payload)?;
        if check && length as usize != payload.len() {
            return Err(Error::Truncated);
        }
        info.req_msg_size = Some(length);

        let (payload, api_key) = be_u16(payload)?;
        let (payload, version) = be_u16(payload)?;
        info.api = Api {
            key: ApiKey::from(api_key),
            version,
        };

        let (payload, correlation_id) = be_i32(payload)?;
        info.correlation_id = Some(correlation_id as u32);
        if !check {
            // do not update sessions on check_payload
            self.sessions.push(info.correlation_id.unwrap(), info.api);
        }

        let (payload, client_id) = decoder::nullable_string(payload)?;
        if !client_id.is_ascii() {
            return Err(Error::ParseFailed(
                format!("client id {} is not ascii", client_id).into(),
            ));
        }
        info.client_id = client_id.to_string();

        let payload = if info.api.request_header_version()? == 2 {
            decoder::tagged_fields(payload)?.0
        } else {
            payload
        };
        let _ = Self::decode_request_body(payload, info)?;
        Ok(())
    }

    fn response(&mut self, payload: &[u8], info: &mut KafkaInfo) -> Result<()> {
        info.msg_type = LogMessageType::Response;

        let (payload, length) = be_u32(payload)?;
        info.resp_msg_size = Some(length);

        let (payload, correlation_id) = be_i32(payload)?;
        info.correlation_id = Some(correlation_id as u32);

        let Some(api) = self.sessions.peek(&info.correlation_id.unwrap()) else {
            return Err(Error::CorrelationIdNotFound);
        };
        info.api = *api;

        let payload = if info.api.response_header_version()? == 1 {
            decoder::tagged_fields(payload)?.0
        } else {
            payload
        };
        let _ = Self::decode_response_body(payload, info)?;

        if let Some(status_code) = info.status_code {
            if status_code == 0 {
                info.status = L7ResponseStatus::Ok;
            } else {
                info.status = L7ResponseStatus::ServerError;
            }
        }

        Ok(())
    }

    fn parse(
        &mut self,
        payload: &[u8],
        direction: PacketDirection,
        info: &mut KafkaInfo,
    ) -> Result<()> {
        match direction {
            PacketDirection::ClientToServer => self.request(payload, false, info)?,
            PacketDirection::ServerToClient => self.response(payload, info)?,
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;
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

    struct ValidateInfo<'a>(&'a KafkaInfo);

    impl<'a> fmt::Display for ValidateInfo<'a> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("KafkaInfo")
                .field("msg_type", &self.0.msg_type)
                .field("correlation_id", &self.0.correlation_id)
                .field("api_key", &self.0.api.key)
                .field("api_version", &self.0.api.version)
                .field("client_id", &self.0.client_id)
                .field("topic_name", &self.0.topic_name)
                .field("partition", &self.0.partition)
                .field("offset", &self.0.offset)
                .field("group_id", &self.0.group_id)
                .field("resource", &self.0.resource)
                .field("endpoint", &self.0.endpoint)
                .field("command", &self.0.command)
                .field("status", &self.0.status)
                .field("status_code", &self.0.status_code)
                .field("req_msg_size", &self.0.req_msg_size)
                .field("resp_msg_size", &self.0.resp_msg_size)
                .field("captured_request_byte", &self.0.captured_request_byte)
                .field("captured_response_byte", &self.0.captured_response_byte)
                .field("rrt", &self.0.rrt)
                .field("trace_ids", &self.0.trace_ids)
                .field("span_id", &self.0.span_id)
                .finish()
        }
    }

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name));
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let mut packets = capture.collect::<Vec<_>>();
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

            let is_kafka = kafka.check_payload(payload, param).is_some();
            let info = kafka.parse_payload(payload, param);
            if let Ok(info) = info {
                match info.unwrap_single() {
                    L7ProtocolInfo::KafkaInfo(i) => {
                        let _ = write!(&mut output, "{} is_kafka: {is_kafka}\n", ValidateInfo(&i));
                    }
                    _ => unreachable!(),
                }
            } else {
                let _ = write!(&mut output, "is_kafka: {is_kafka}\n");
            }
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
            ("00-produce-v2.pcap", "00-produce-v2.result"),
            ("00-produce-v7-sw8.pcap", "00-produce-v7-sw8.result"),
            ("00-produce-v9.pcap", "00-produce-v9.result"),
            ("01-fetch-v12-ok.pcap", "01-fetch-v12-ok.result"),
            ("01-fetch-v12-unknown.pcap", "01-fetch-v12-unknown.result"),
            ("11-join-group-v7.pcap", "11-join-group-v7.result"),
            ("13-leave-group-v4.pcap", "13-leave-group-v4.result"),
            ("14-sync-group-v5.pcap", "14-sync-group-v5.result"),
            ("18-api-versions-v3.pcap", "18-api-versions-v3.result"),
            (
                "mixed-with-unsupported.pcap",
                "mixed-with-unsupported.result",
            ),
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
                "18-api-versions-v3.pcap",
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
                "01-fetch-v12-perf.pcap",
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

        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(pcap));
        let mut packets = capture.collect::<Vec<_>>();

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
}
