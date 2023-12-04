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

use std::str::Utf8Error;

use thiserror::Error;

use super::MetaAppProto;

use crate::common::l7_protocol_info::L7ProtocolInfo;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid packet timestamp")]
    InvalidPacketTimestamp,
    #[error("tcp retransmission packet")]
    RetransPacket,
    // call LayerFlowPerf::parse return Error(Layer7 mismatch_response_count)
    #[error("layer7 request not found")]
    L7ReqNotFound(u64),
    #[error("zero payload len")]
    ZeroPayloadLen,
    #[error("invalid ip protocol")]
    InvalidIpProtocol,
    #[error("dubbo header parse failed")]
    DubboHeaderParseFailed,
    #[error("http header parse failed")]
    HttpHeaderParseFailed,
    #[error("kafka log parse failed")]
    KafkaLogParseFailed,
    #[error("kafka perf parse failed")]
    KafkaPerfParseFailed,
    #[error("mqtt log parse failed")]
    MqttLogParseFailed,
    #[error("mqtt perf parse failed")]
    MqttPerfParseFailed,
    #[error("redis log parse failed")]
    RedisLogParseFailed,
    #[error("redis perf parse failed")]
    RedisPerfParseFailed,
    #[error("mysql log parse failed")]
    MysqlLogParseFailed,
    #[error("mysql perf parse failed")]
    MysqlPerfParseFailed,
    #[error("mongodb log parse failed")]
    MongoDBLogParseFailed,
    #[error("{0}")]
    DNSLogParseFailed(String),
    #[error("{0}")]
    DNSPerfParseFailed(&'static str),
    #[error("{0}")]
    TlsLogParseFailed(String),
    #[error("{0}")]
    TlsPerfParseFailed(&'static str),
    #[error("l7 protocol unknown")]
    L7ProtocolUnknown,
    #[error("l7 protocol check limit")]
    L7ProtocolCheckLimit,
    #[error("l7 protocol parse limit")]
    L7ProtocolParseLimit,
    #[error("l7 protocol can not merge")]
    L7ProtocolCanNotMerge(L7ProtocolInfo),
    #[error("l7 log can not merge")]
    L7LogCanNotMerge(MetaAppProto),
    #[error("parse config not provided")]
    NoParseConfig,
    #[error("wasm parse fail")]
    WasmParseFail,
    #[error("{0}")]
    WasmSerializeFail(String),
    #[error("{0}")]
    WasmVmError(String),
    #[error("{0}")]
    WasmInitFail(String),
    #[error("so plugin return unexpect value")]
    SoReturnUnexpectVal,
    #[error("so plugin parse fail")]
    SoParseFail,
    // need more data, cache to tcp reassemble buffer
    #[error("need more data")]
    NeedMoreData,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl From<Utf8Error> for Error {
    fn from(_: Utf8Error) -> Self {
        Self::HttpHeaderParseFailed
    }
}
