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

use serde::Serialize;
use serde_json::{value::Value, Map, Number};

const AMQPHEADER: &[u8] = b"AMQP\x00\x00\x09\x01";
const AMQPVERSION: &[u8] = b"v0.9.1";

use crate::{
    common::{
        enums::IpProtocol,
        flow::{L7PerfStats, L7Protocol},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, ParseParam},
        meta_packet::EbpfFlags,
    },
    flow_generator::{
        error::Result,
        protocol_logs::{
            decode_base64_to_string,
            pb_adapter::{L7ProtocolSendLog, L7Request, L7Response, TraceInfo},
            AppProtoHead, LogMessageType,
        },
    },
    utils::bytes::{read_u16_be, read_u32_be, read_u64_be},
};

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyCode {
    Success = 200,
    ContentTooLarge = 311,
    NoRoute = 312,
    NoConsumers = 313,
    ConnectionForced = 320,
    InvalidPath = 402,
    AccessRefused = 403,
    NotFound = 404,
    ResourceLocked = 405,
    PreconditionFailed = 406,
    FrameError = 501,
    SyntaxError = 502,
    CommandInvalid = 503,
    ChannelError = 504,
    UnexpectedFrame = 505,
    ResourceError = 506,
    NotAllowed = 530,
    NotImplemented = 540,
    InternalError = 541,
}

#[derive(Serialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FrameType {
    #[default]
    Unknown = 0,
    Method = 1,
    Header = 2,
    Body = 3,
    Heartbeat = 8,
}

#[derive(Serialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ClassType {
    #[default]
    Unknown = 0,
    Connection = 10,
    Channel = 20,
    Exchange = 40,
    Queue = 50,
    Basic = 60,
    Tx = 90,
    Confirm = 85,
}

#[derive(Serialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MethodType {
    #[default]
    Unknown,
    Start,
    StartOk,
    Secure,
    SecureOk,
    Tune,
    TuneOk,
    Open,
    OpenOk,
    Close,
    CloseOk,
    Blocked,
    Unblocked,
    UpdateSecret,
    UpdateSecretOk,
    Flow,
    FlowOk,
    Declare,
    DeclareOk,
    Delete,
    DeleteOk,
    Bind,
    BindOk,
    Unbind,
    UnbindOk,
    Purge,
    PurgeOk,
    Qos,
    QosOk,
    Consume,
    ConsumeOk,
    Cancel,
    CancelOk,
    Publish,
    Return,
    Deliver,
    Get,
    GetOk,
    GetEmpty,
    Ack,
    Reject,
    RecoverAsync,
    Recover,
    RecoverOk,
    Nack,
    Select,
    SelectOk,
    Commit,
    CommitOk,
    Rollback,
    RollbackOk,
}

impl From<u8> for FrameType {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::Method,
            2 => Self::Header,
            3 => Self::Body,
            8 => Self::Heartbeat,
            _ => Self::Unknown,
        }
    }
}

impl From<u16> for ClassType {
    fn from(v: u16) -> Self {
        match v {
            10 => Self::Connection,
            20 => Self::Channel,
            40 => Self::Exchange,
            50 => Self::Queue,
            60 => Self::Basic,
            90 => Self::Tx,
            85 => Self::Confirm,
            _ => Self::Unknown,
        }
    }
}

impl From<(ClassType, u16)> for MethodType {
    fn from(val: (ClassType, u16)) -> Self {
        let (class_type, v) = val;
        match (class_type, v) {
            (ClassType::Connection, 10) => Self::Start,
            (ClassType::Connection, 11) => Self::StartOk,
            (ClassType::Connection, 20) => Self::Secure,
            (ClassType::Connection, 21) => Self::SecureOk,
            (ClassType::Connection, 30) => Self::Tune,
            (ClassType::Connection, 31) => Self::TuneOk,
            (ClassType::Connection, 40) => Self::Open,
            (ClassType::Connection, 41) => Self::OpenOk,
            (ClassType::Connection, 50) => Self::Close,
            (ClassType::Connection, 51) => Self::CloseOk,
            (ClassType::Connection, 60) => Self::Blocked,
            (ClassType::Connection, 61) => Self::Unblocked,
            (ClassType::Connection, 70) => Self::UpdateSecret,
            (ClassType::Connection, 71) => Self::UpdateSecretOk,
            (ClassType::Channel, 10) => Self::Open,
            (ClassType::Channel, 11) => Self::OpenOk,
            (ClassType::Channel, 20) => Self::Flow,
            (ClassType::Channel, 21) => Self::FlowOk,
            (ClassType::Channel, 40) => Self::Close,
            (ClassType::Channel, 41) => Self::CloseOk,
            (ClassType::Exchange, 10) => Self::Declare,
            (ClassType::Exchange, 11) => Self::DeclareOk,
            (ClassType::Exchange, 20) => Self::Delete,
            (ClassType::Exchange, 21) => Self::DeleteOk,
            (ClassType::Exchange, 30) => Self::Bind,
            (ClassType::Exchange, 31) => Self::BindOk,
            (ClassType::Exchange, 40) => Self::Unbind,
            (ClassType::Exchange, 51) => Self::UnbindOk,
            (ClassType::Queue, 10) => Self::Declare,
            (ClassType::Queue, 11) => Self::DeclareOk,
            (ClassType::Queue, 20) => Self::Bind,
            (ClassType::Queue, 21) => Self::BindOk,
            (ClassType::Queue, 30) => Self::Purge,
            (ClassType::Queue, 31) => Self::PurgeOk,
            (ClassType::Queue, 40) => Self::Delete,
            (ClassType::Queue, 41) => Self::DeleteOk,
            (ClassType::Queue, 50) => Self::Unbind,
            (ClassType::Queue, 51) => Self::UnbindOk,
            (ClassType::Basic, 10) => Self::Qos,
            (ClassType::Basic, 11) => Self::QosOk,
            (ClassType::Basic, 20) => Self::Consume,
            (ClassType::Basic, 21) => Self::ConsumeOk,
            (ClassType::Basic, 30) => Self::Cancel,
            (ClassType::Basic, 31) => Self::CancelOk,
            (ClassType::Basic, 40) => Self::Publish,
            (ClassType::Basic, 50) => Self::Return,
            (ClassType::Basic, 60) => Self::Deliver,
            (ClassType::Basic, 70) => Self::Get,
            (ClassType::Basic, 71) => Self::GetOk,
            (ClassType::Basic, 72) => Self::GetEmpty,
            (ClassType::Basic, 80) => Self::Ack,
            (ClassType::Basic, 90) => Self::Reject,
            (ClassType::Basic, 100) => Self::RecoverAsync,
            (ClassType::Basic, 110) => Self::Recover,
            (ClassType::Basic, 111) => Self::RecoverOk,
            (ClassType::Basic, 120) => Self::Nack,
            (ClassType::Tx, 10) => Self::Select,
            (ClassType::Tx, 11) => Self::SelectOk,
            (ClassType::Tx, 20) => Self::Commit,
            (ClassType::Tx, 21) => Self::CommitOk,
            (ClassType::Tx, 30) => Self::Rollback,
            (ClassType::Tx, 31) => Self::RollbackOk,
            (ClassType::Confirm, 10) => Self::Select,
            (ClassType::Confirm, 11) => Self::SelectOk,
            _ => Self::Unknown,
        }
    }
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct AmqpInfo {
    msg_type: LogMessageType,
    #[serde(skip)]
    is_tls: bool,

    rtt: u64,

    vhost: Option<String>,

    #[serde(rename = "type")]
    frame_type: FrameType,
    #[serde(rename = "channel")]
    channel_id: u16,
    #[serde(rename = "length")]
    payload_size: u32,

    // Method Frame
    #[serde(rename = "class_id")]
    class_id: ClassType,
    #[serde(rename = "method_id")]
    method_id: MethodType,

    #[serde(skip)]
    raw_method_id: Option<u16>,

    // Header Frame
    // class_id: ClassType, // same as method frame
    #[serde(rename = "body_size")]
    body_size: u64, // 0 stands for no body frame

    #[serde(rename = "queue", skip_serializing_if = "Option::is_none")]
    queue: Option<String>,
    #[serde(rename = "exchange", skip_serializing_if = "Option::is_none")]
    exchange: Option<String>,
    #[serde(rename = "routing_key", skip_serializing_if = "Option::is_none")]
    routing_key: Option<String>,

    #[serde(rename = "trace_id", skip_serializing_if = "Option::is_none")]
    trace_id: Option<String>,
    #[serde(rename = "span_id", skip_serializing_if = "Option::is_none")]
    span_id: Option<String>,

    req_len: Option<u32>,
    resp_len: Option<u32>,
    resp_code: Option<i32>,
}

fn slice_to_string(slice: &[u8]) -> String {
    String::from_utf8_lossy(slice).to_string()
}

fn read_short_str(buffer: &[u8]) -> Option<(&[u8], &[u8])> {
    let sz = *buffer.get(0)? as usize;
    let s = buffer.get(1..=sz)?;
    let buffer = buffer.get(sz + 1..)?;
    Some((buffer, s))
}

fn read_field_value(payload: &[u8]) -> Option<(&[u8], Value)> {
    let (payload, value) = match payload.get(0)? {
        // boolean
        b't' => (payload.get(2..)?, Value::Bool(*payload.get(1)? != 0)),
        // short short int
        b'b' => (
            payload.get(2..)?,
            Value::Number((*payload.get(1)? as i8).into()),
        ),
        // short short uint
        b'B' => (
            payload.get(2..)?,
            Value::Number((*payload.get(1)? as u8).into()),
        ),
        // short int
        b'U' => (
            payload.get(3..)?,
            Value::Number((read_u16_be(payload.get(1..3)?) as i16).into()),
        ),
        // short uint
        b'u' => (
            payload.get(3..)?,
            Value::Number((read_u16_be(payload.get(1..3)?) as u16).into()),
        ),
        // long int
        b'I' => (
            payload.get(5..)?,
            Value::Number((read_u32_be(payload.get(1..5)?) as i32).into()),
        ),
        // long uint
        b'i' => (
            payload.get(5..)?,
            Value::Number((read_u32_be(payload.get(1..5)?) as u32).into()),
        ),
        // long long int
        b'L' => (
            payload.get(9..)?,
            Value::Number((read_u64_be(payload.get(1..9)?) as i64).into()),
        ),
        // long long uint
        b'l' => (
            payload.get(9..)?,
            Value::Number((read_u64_be(payload.get(1..9)?) as u64).into()),
        ),
        // float
        b'f' => (
            payload.get(5..)?,
            Number::from_f64(f32::from_be_bytes(payload.get(1..5)?.try_into().ok()?) as f64)?
                .into(),
        ),
        // double
        b'd' => (
            payload.get(9..)?,
            Number::from_f64(f64::from_be_bytes(payload.get(1..9)?.try_into().ok()?) as f64)?
                .into(),
        ),
        // decimal double
        // TODO: parse fixed-point number
        b'D' => (payload.get(6..)?, Value::Null),
        // shortstr
        b's' => {
            let (payload_tmp, s) = read_short_str(payload.get(1..)?)?;
            (payload_tmp, Value::String(slice_to_string(s)))
        }
        // longstr
        b'S' => {
            let size = read_u32_be(payload.get(1..5)?) as usize;
            let s = String::from_utf8_lossy(payload.get(5..5 + size)?).to_string();
            (payload.get(5 + size..)?, Value::String(s))
        }
        // field array
        b'A' => {
            let size = read_u32_be(payload.get(1..5)?) as usize;
            let mut payload = payload.get(5..)?;
            let mut vec = Vec::new();
            for _ in 0..size {
                let (payload_tmp, value) = read_field_value(payload)?;
                payload = payload_tmp;
                vec.push(value);
            }
            (payload, Value::Array(vec))
        }
        // timestamp
        b'T' => (
            payload.get(9..)?,
            Value::Number((read_u64_be(payload.get(1..9)?) as u64).into()),
        ),
        // field table
        b'F' => read_table(payload.get(1..)?)?,
        // void
        b'V' => (payload.get(1..)?, Value::Null),
        _ => return None,
    };
    Some((payload, value))
}

fn read_table(payload: &[u8]) -> Option<(&[u8], Value)> {
    let size = read_u32_be(payload.get(0..4)?) as usize;
    let payload_ret = payload.get(4 + size..)?;
    let mut payload = payload.get(4..4 + size)?;
    let mut map = Map::new();
    while payload.len() > 0 {
        let (payload_tmp, key) = read_short_str(payload)?;
        let (payload_tmp, value) = read_field_value(payload_tmp)?;
        payload = payload_tmp;
        map.insert(slice_to_string(key), value);
    }
    Some((payload_ret, Value::Object(map)))
}

impl AmqpInfo {
    fn get_packet_type(&self) -> String {
        match self.frame_type {
            FrameType::Method => format!("{:?}.{:?}", self.class_id, self.method_id),
            FrameType::Header => "Content-Header".to_string(),
            FrameType::Body => "Content-Body".to_string(),
            FrameType::Heartbeat => "Heartbeat".to_string(),
            FrameType::Unknown => "Unknown".to_string(),
        }
    }

    fn get_log_message_type(&self) -> LogMessageType {
        match self.frame_type {
            FrameType::Method => {}
            FrameType::Header => return LogMessageType::Session,
            FrameType::Body => return LogMessageType::Session,
            FrameType::Heartbeat => return LogMessageType::Session,
            FrameType::Unknown => return LogMessageType::Other,
        }
        match (self.class_id, self.method_id) {
            (ClassType::Connection, MethodType::Blocked)
            | (ClassType::Connection, MethodType::Unblocked)
            | (ClassType::Basic, MethodType::Publish)
            | (ClassType::Basic, MethodType::Return)
            | (ClassType::Basic, MethodType::Deliver)
            | (ClassType::Basic, MethodType::Ack)
            | (ClassType::Basic, MethodType::Reject)
            | (ClassType::Basic, MethodType::RecoverAsync)
            | (ClassType::Basic, MethodType::Nack) => LogMessageType::Session,
            (ClassType::Connection, MethodType::Start)
            | (ClassType::Connection, MethodType::Secure)
            | (ClassType::Connection, MethodType::Tune)
            | (ClassType::Connection, MethodType::Open)
            | (ClassType::Connection, MethodType::Close)
            | (ClassType::Connection, MethodType::UpdateSecret)
            | (ClassType::Channel, MethodType::Open)
            | (ClassType::Channel, MethodType::Flow)
            | (ClassType::Channel, MethodType::Close)
            | (ClassType::Exchange, MethodType::Declare)
            | (ClassType::Exchange, MethodType::Delete)
            | (ClassType::Exchange, MethodType::Bind)
            | (ClassType::Exchange, MethodType::Unbind)
            | (ClassType::Queue, MethodType::Declare)
            | (ClassType::Queue, MethodType::Bind)
            | (ClassType::Queue, MethodType::Purge)
            | (ClassType::Queue, MethodType::Delete)
            | (ClassType::Queue, MethodType::Unbind)
            | (ClassType::Basic, MethodType::Qos)
            | (ClassType::Basic, MethodType::Consume)
            | (ClassType::Basic, MethodType::Cancel)
            | (ClassType::Basic, MethodType::Get)
            | (ClassType::Basic, MethodType::Recover)
            | (ClassType::Tx, MethodType::Select)
            | (ClassType::Tx, MethodType::Commit)
            | (ClassType::Tx, MethodType::Rollback)
            | (ClassType::Confirm, MethodType::Select) => LogMessageType::Request,
            (ClassType::Connection, MethodType::StartOk)
            | (ClassType::Connection, MethodType::SecureOk)
            | (ClassType::Connection, MethodType::TuneOk)
            | (ClassType::Connection, MethodType::OpenOk)
            | (ClassType::Connection, MethodType::CloseOk)
            | (ClassType::Connection, MethodType::UpdateSecretOk)
            | (ClassType::Channel, MethodType::OpenOk)
            | (ClassType::Channel, MethodType::FlowOk)
            | (ClassType::Channel, MethodType::CloseOk)
            | (ClassType::Exchange, MethodType::DeclareOk)
            | (ClassType::Exchange, MethodType::DeleteOk)
            | (ClassType::Exchange, MethodType::BindOk)
            | (ClassType::Exchange, MethodType::UnbindOk)
            | (ClassType::Queue, MethodType::DeclareOk)
            | (ClassType::Queue, MethodType::BindOk)
            | (ClassType::Queue, MethodType::PurgeOk)
            | (ClassType::Queue, MethodType::DeleteOk)
            | (ClassType::Queue, MethodType::UnbindOk)
            | (ClassType::Basic, MethodType::QosOk)
            | (ClassType::Basic, MethodType::ConsumeOk)
            | (ClassType::Basic, MethodType::CancelOk)
            | (ClassType::Basic, MethodType::GetOk)
            | (ClassType::Basic, MethodType::GetEmpty)
            | (ClassType::Basic, MethodType::RecoverOk)
            | (ClassType::Tx, MethodType::SelectOk)
            | (ClassType::Tx, MethodType::CommitOk)
            | (ClassType::Tx, MethodType::RollbackOk)
            | (ClassType::Confirm, MethodType::SelectOk) => LogMessageType::Response,
            _ => LogMessageType::Other,
        }
    }

    fn parse_trace_span(&self, payload: &[u8]) -> Option<(String, String)> {
        if self.class_id != ClassType::Basic {
            return None;
        }
        let flags = read_u16_be(payload.get(0..2)?);
        let mut payload = payload.get(2..)?;
        // content-type: shortstr
        if (flags >> 15 & 1) == 1 {
            payload = read_short_str(payload)?.0;
        }
        // content-encoding: shortstr
        if (flags >> 14 & 1) == 1 {
            payload = read_short_str(payload)?.0;
        }
        // headers: table
        if (flags >> 13 & 1) == 0 {
            return None;
        }
        let (_, table) = read_table(payload)?;
        if let Value::Object(map) = table {
            if let Some(Value::String(s)) = map.get("traceparent") {
                // 00-TRACEID-SPANID-01
                let mut parts = s.split('-').skip(1);
                if let (Some(trace_id), Some(span_id)) = { (parts.next(), parts.next()) } {
                    return Some((trace_id.to_string(), span_id.to_string()));
                }
            }
            if let Some(Value::String(s)) = map.get("sw8") {
                if let Some(ret) = || -> Option<(String, String)> {
                    // 1-TRACEID-SEGMENTID-3-xxxxx
                    let mut parts = s.split('-');
                    let trace_id = decode_base64_to_string(parts.nth(1)?);
                    let span_id = format!(
                        "{}-{}",
                        decode_base64_to_string(parts.next()?),
                        parts.next()?
                    );
                    Some((trace_id, span_id))
                }() {
                    return Some(ret);
                }
            }
            if let Some(Value::String(s)) = map.get("sw6") {
                if let Some(ret) = || -> Option<(String, String)> {
                    // 1-TRACEID-SEGMENTID-3-xxxxx
                    let mut parts = s.split('-');
                    let trace_id = decode_base64_to_string(parts.nth(1)?);
                    let span_id = format!(
                        "{}-{}",
                        decode_base64_to_string(parts.next()?),
                        parts.next()?
                    );
                    Some((trace_id, span_id))
                }() {
                    return Some(ret);
                }
            }
            if let Some(Value::String(s)) = map.get("sw3") {
                let mut parts = s.split('|');
                if let (Some(trace_id), Some(span_id)) = { (parts.next(), parts.next()) } {
                    return Some((trace_id.to_string(), span_id.to_string()));
                }
            }
        }
        None
    }

    fn parse_queue(&self, arguments: &[u8]) -> Option<String> {
        let queue = match (self.class_id, self.method_id) {
            // [reserved: short] [queue: shortstr]
            (ClassType::Queue, MethodType::Declare)
            | (ClassType::Queue, MethodType::Bind)
            | (ClassType::Queue, MethodType::Unbind)
            | (ClassType::Queue, MethodType::Purge)
            | (ClassType::Queue, MethodType::Delete)
            | (ClassType::Basic, MethodType::Consume)
            | (ClassType::Basic, MethodType::Get) => {
                let (_arguments, queue) = read_short_str(arguments.get(2..)?)?;
                queue
            }
            // [queue: shortstr]
            (ClassType::Queue, MethodType::DeclareOk) => {
                let (_arguments, queue) = read_short_str(arguments)?;
                queue
            }
            _ => return None,
        };
        Some(slice_to_string(queue))
    }

    fn parse_exchange(&self, arguments: &[u8]) -> Option<String> {
        let exchange = match (self.class_id, self.method_id) {
            // [reserved: short] [exchange: shortstr]
            (ClassType::Exchange, MethodType::Declare)
            | (ClassType::Exchange, MethodType::Delete)
            | (ClassType::Basic, MethodType::Publish) => {
                let (_arguments, exchange) = read_short_str(arguments.get(2..)?)?;
                exchange
            }
            // [reserved: short] [queue: shortstr] [exchange: shortstr]
            (ClassType::Queue, MethodType::Bind) | (ClassType::Queue, MethodType::Unbind) => {
                let (arguments, _queue) = read_short_str(arguments.get(2..)?)?;
                let (_arguments, exchange) = read_short_str(arguments)?;
                exchange
            }
            // [reply-code: short] [reply-text: shortstr] [exchange: shortstr]
            (ClassType::Basic, MethodType::Return) => {
                let (arguments, _reply_text) = read_short_str(arguments.get(2..)?)?;
                let (_arguments, exchange) = read_short_str(arguments)?;
                exchange
            }
            // [consumer-tag: shortstr] [delivery-tag: long long] [redelivered: bool] [exchange: shortstr]
            (ClassType::Basic, MethodType::Deliver) => {
                let (arguments, _consumer_tag) = read_short_str(arguments)?;
                let (_arguments, exchange) = read_short_str(arguments.get(9..)?)?;
                exchange
            }
            // [delivery-tag: long long] [redelivered: bool] [exchange: shortstr]
            (ClassType::Basic, MethodType::GetOk) => {
                let (_arguments, exchange) = read_short_str(arguments.get(9..)?)?;
                exchange
            }
            _ => return None,
        };
        Some(slice_to_string(exchange))
    }

    fn parse_routing_key(&self, arguments: &[u8]) -> Option<String> {
        let routing_key = match (self.class_id, self.method_id) {
            // [reserved: short] [dst: shortstr] [src: shortstr] [routing-key: shortstr]
            (ClassType::Exchange, MethodType::Bind) | (ClassType::Exchange, MethodType::Unbind) => {
                let (arguments, _dst) = read_short_str(arguments.get(2..)?)?;
                let (arguments, _src) = read_short_str(arguments)?;
                let (_arguments, routing_key) = read_short_str(arguments)?;
                routing_key
            }
            // [reserved: short] [queue: shortstr] [exchange: shortstr] [routing-key: shortstr]
            (ClassType::Queue, MethodType::Bind) | (ClassType::Queue, MethodType::Unbind) => {
                let (arguments, _queue) = read_short_str(arguments.get(2..)?)?;
                let (arguments, _exchange) = read_short_str(arguments)?;
                let (_arguments, routing_key) = read_short_str(arguments)?;
                routing_key
            }
            // [reserved: short] [exchange: shortstr] [routing-key: shortstr]
            (ClassType::Basic, MethodType::Publish) => {
                let (arguments, _exchange) = read_short_str(arguments.get(2..)?)?;
                let (_arguments, routing_key) = read_short_str(arguments)?;
                routing_key
            }
            // [reply-code: short] [reply-text: shortstr] [exchange: shortstr] [routing-key: shortstr]
            (ClassType::Basic, MethodType::Return) => {
                let (arguments, _reply_text) = read_short_str(arguments.get(2..)?)?;
                let (arguments, _exchange) = read_short_str(arguments)?;
                let (_arguments, routing_key) = read_short_str(arguments)?;
                routing_key
            }
            // [consumer-tag: shortstr] [delivery-tag: long long] [redelivered: bool] [exchange: shortstr] [routing-key: shortstr]
            (ClassType::Basic, MethodType::Deliver) => {
                let (arguments, _consumer_tag) = read_short_str(arguments)?;
                let (arguments, _exchange) = read_short_str(arguments.get(9..)?)?;
                let (_arguments, routing_key) = read_short_str(arguments)?;
                routing_key
            }
            // [delivery-tag: long long] [redelivered: bool] [exchange: shortstr] [routing-key: shortstr]
            (ClassType::Basic, MethodType::GetOk) => {
                let (arguments, _exchange) = read_short_str(arguments.get(9..)?)?;
                let (_arguments, routing_key) = read_short_str(arguments)?;
                routing_key
            }
            _ => return None,
        };
        Some(slice_to_string(routing_key))
    }
}

#[derive(Default)]
pub struct AmqpLog {
    perf_stats: Option<L7PerfStats>,

    vhost: Option<String>,
}

impl From<AmqpInfo> for L7ProtocolSendLog {
    fn from(info: AmqpInfo) -> Self {
        let flags = match info.is_tls {
            true => EbpfFlags::TLS.bits(),
            false => EbpfFlags::NONE.bits(),
        };
        let endpoint = match (&info.routing_key, &info.queue) {
            (Some(x), _) if x.len() > 0 => x.clone(),
            (_, y) => y.clone().unwrap_or_default(),
        };
        let log = L7ProtocolSendLog {
            version: Some(std::str::from_utf8(AMQPVERSION).unwrap().to_string()),
            flags,
            req_len: info.req_len,
            resp_len: info.resp_len,
            req: L7Request {
                req_type: info.get_packet_type(),
                domain: info.vhost.unwrap_or_default(),
                resource: endpoint.clone(),
                endpoint: endpoint.clone(),
                ..Default::default()
            },
            resp: L7Response {
                code: info.resp_code,
                ..Default::default()
            },
            trace_info: Some(TraceInfo {
                trace_id: info.trace_id,
                span_id: info.span_id,
                ..Default::default()
            }),
            ..Default::default()
        };
        log
    }
}

impl L7ProtocolInfoInterface for AmqpInfo {
    fn is_tls(&self) -> bool {
        self.is_tls
    }

    fn session_id(&self) -> Option<u32> {
        None
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let (req, L7ProtocolInfo::AmqpInfo(rsp)) = (self, other) {
            if req.resp_len.is_none() {
                req.resp_len = rsp.resp_len;
            }
            if req.resp_code.is_none() {
                req.resp_code = rsp.raw_method_id.map(|x| x as i32);
            }
            if req.routing_key.as_ref().map_or(0, |r| r.len()) == 0 {
                req.routing_key = rsp.routing_key.clone();
            }
            if req.queue.as_ref().map_or(0, |r| r.len()) == 0 {
                req.queue = rsp.queue.clone();
            }
            if req.exchange.as_ref().map_or(0, |r| r.len()) == 0 {
                req.exchange = rsp.exchange.clone();
            }
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::AMQP,
            msg_type: self.msg_type,
            rrt: self.rtt,
        })
    }
}

impl L7ProtocolParserInterface for AmqpLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol() {
            return false;
        }
        if param.l4_protocol != IpProtocol::TCP {
            return false;
        }
        return payload.starts_with(AMQPHEADER);
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };

        let mut offset = 0;
        if payload.starts_with(AMQPHEADER) {
            offset += AMQPHEADER.len();
        }
        let mut vec = Vec::new();
        loop {
            let offset_begin = offset;
            let mut info = AmqpInfo::default();
            info.is_tls = param.is_tls();

            if payload.len() < offset + 8 {
                break;
            }

            info.frame_type = FrameType::from(payload[offset]);
            if info.frame_type == FrameType::Unknown {
                break;
            }
            info.channel_id = read_u16_be(&payload[offset + 1..offset + 3]);
            info.payload_size = read_u32_be(&payload[offset + 3..offset + 7]);
            offset += 7;
            if payload.get(offset + info.payload_size as usize) != Some(&b'\xCE') {
                break;
            }
            match info.frame_type {
                FrameType::Method => {
                    if info.payload_size < 4 {
                        break;
                    }
                    info.class_id = match ClassType::from(read_u16_be(&payload[offset..offset + 2]))
                    {
                        ClassType::Unknown => break,
                        x => x,
                    };
                    info.raw_method_id = Some(read_u16_be(&payload[offset + 2..offset + 4]));
                    info.method_id =
                        match MethodType::from((info.class_id, info.raw_method_id.unwrap())) {
                            MethodType::Unknown => break,
                            x => x,
                        };
                    info.queue = info.parse_queue(&payload[offset + 4..]);
                    info.exchange = info.parse_exchange(&payload[offset + 4..]);
                    info.routing_key = info.parse_routing_key(&payload[offset + 4..]);
                }
                FrameType::Header => {
                    if info.payload_size < 14 {
                        break;
                    }
                    info.class_id = match ClassType::from(read_u16_be(&payload[offset..offset + 2]))
                    {
                        ClassType::Unknown => break,
                        x => x,
                    };
                    match read_u16_be(&payload[offset + 2..offset + 4]) {
                        0 => {}
                        _ => break,
                    }
                    info.body_size = read_u64_be(&payload[offset + 4..offset + 12]);
                    if let Some((trace_id, span_id)) =
                        info.parse_trace_span(&payload[offset + 12..])
                    {
                        info.trace_id = Some(trace_id);
                        info.span_id = Some(span_id);
                    }
                }
                FrameType::Body => {}
                FrameType::Heartbeat => {}
                FrameType::Unknown => unreachable!(),
            }

            if info.class_id == ClassType::Connection {
                if info.method_id == MethodType::Open {
                    if let Some((_, vhost)) = read_short_str(&payload[offset + 4..]) {
                        self.vhost = Some(slice_to_string(vhost));
                    }
                }
            }
            info.vhost = self.vhost.clone();
            if info.class_id == ClassType::Connection {
                if info.method_id == MethodType::CloseOk {
                    self.vhost = None;
                }
            }

            offset += info.payload_size as usize;
            if payload.get(offset) != Some(&b'\xCE') {
                break;
            }
            offset += 1;

            info.msg_type = info.get_log_message_type();

            match info.msg_type {
                LogMessageType::Request => info.req_len = Some((offset - offset_begin) as u32),
                LogMessageType::Response => info.resp_len = Some((offset - offset_begin) as u32),
                _ => {}
            }
            vec.push(L7ProtocolInfo::AmqpInfo(info));
        }
        for info in &mut vec {
            if let L7ProtocolInfo::AmqpInfo(info) = info {
                info.cal_rrt(param, None).map(|rtt| {
                    info.rtt = rtt;
                    self.perf_stats.as_mut().map(|p| p.update_rrt(rtt));
                });
                info.is_tls = param.is_tls();

                match info.msg_type {
                    LogMessageType::Request => {
                        self.perf_stats.as_mut().map(|p| p.inc_req());
                    }
                    LogMessageType::Response => {
                        self.perf_stats.as_mut().map(|p| p.inc_resp());
                    }
                    _ => {}
                }
            }
        }
        if !param.parse_log {
            Ok(L7ParseResult::None)
        } else if vec.len() == 1 {
            Ok(L7ParseResult::Single(vec.remove(0)))
        } else if vec.len() > 1 {
            Ok(L7ParseResult::Multi(vec))
        } else {
            Ok(L7ParseResult::None)
        }
    }

    fn reset(&mut self) {
        let mut s = Self::default();
        s.vhost = self.vhost.take();
        s.perf_stats = self.perf_stats.take();
        *self = s;
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::AMQP
    }

    fn parsable_on_udp(&self) -> bool {
        false
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

    const FILE_DIR: &str = "resources/test/flow_generator/amqp";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name), None);
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut output: String = String::new();
        let mut first_packet = true;
        let mut amqp = AmqpLog::default();
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
            let param = &ParseParam::new(
                packet as &MetaPacket,
                log_cache.clone(),
                Default::default(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Default::default(),
                true,
                true,
            );

            if first_packet {
                first_packet = false;
                if !amqp.check_payload(payload, param) {
                    output.push_str("not amqp\r\n");
                    break;
                }
                if let Ok(L7ParseResult::None) = amqp.parse_payload(payload, param) {
                } else {
                    output.push_str("parse error\r\n");
                    break;
                }
            }

            let info = amqp.parse_payload(payload, param);
            if let Ok(info) = info {
                match info {
                    L7ParseResult::Single(s) => {
                        output.push_str(&format!("{:?}\r\n", s));
                    }
                    L7ParseResult::Multi(m) => {
                        for i in m {
                            output.push_str(&format!("{:?}\r\n", i));
                        }
                    }
                    L7ParseResult::None => {
                        output.push_str("None\r\n");
                    }
                }
            } else {
                output.push_str(&format!("{:?}\r\n", AmqpInfo::default()));
            }
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
            ("amqp1.pcap", "amqp1.result"),
            ("amqp2.pcap", "amqp2.result"),
            ("amqp3.pcap", "amqp3.result"),
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
}
