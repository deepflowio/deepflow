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
use std::borrow::Cow;

use std::sync::Arc;

use num_enum::{FromPrimitive, IntoPrimitive, TryFromPrimitive};
use serde::{Serialize, Serializer};

use super::enums::PacketDirection;
use super::types::PrioStrings;

use public_derive::L7Log;
use public_derive_internals::enums::L7ResponseStatus;

pub const DEFAULT_DNS_PORT: u16 = 53;
pub const DEFAULT_TLS_PORT: u16 = 443;

#[derive(
    Serialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    FromPrimitive,
    IntoPrimitive,
    num_enum::Default,
)]
#[repr(u8)]
pub enum L7Protocol {
    #[num_enum(default)]
    Unknown = 0,

    // HTTP
    Http1 = 20,
    Http2 = 21,

    // RPC
    Dubbo = 40,
    Grpc = 41,
    SofaRPC = 43,

    FastCGI = 44,
    Brpc = 45,
    Tars = 46,
    SomeIp = 47,
    Iso8583 = 48,
    Triple = 49,

    // SQL
    MySQL = 60,
    PostgreSQL = 61,
    Oracle = 62,

    // NoSQL
    Redis = 80,
    MongoDB = 81,
    Memcached = 82,

    // MQ
    Kafka = 100,
    MQTT = 101,
    AMQP = 102,
    OpenWire = 103,
    NATS = 104,
    Pulsar = 105,
    ZMTP = 106,
    RocketMQ = 107,
    WebSphereMq = 108,

    // INFRA
    DNS = 120,
    TLS = 121,
    Ping = 122,

    Custom = 127,

    Max = 255,
}

impl L7Protocol {
    pub fn has_session_id(&self) -> bool {
        match self {
            Self::DNS
            | Self::FastCGI
            | Self::Http2
            | Self::TLS
            | Self::Kafka
            | Self::Dubbo
            | Self::SofaRPC
            | Self::SomeIp
            | Self::Ping
            | Self::Triple
            | Self::Custom => true,
            _ => false,
        }
    }
}

// Translate the string value of l7_protocol into a L7Protocol enumeration value used by OTEL.
impl From<String> for L7Protocol {
    fn from(mut s: String) -> Self {
        s.make_ascii_lowercase();
        match s.as_str() {
            "http" | "https" => Self::Http1,
            "http2" => Self::Http2,
            "dubbo" => Self::Dubbo,
            "grpc" => Self::Grpc,
            "fastcgi" => Self::FastCGI,
            "brpc" => Self::Brpc,
            "tars" => Self::Tars,
            "custom" => Self::Custom,
            "sofarpc" => Self::SofaRPC,
            "mysql" => Self::MySQL,
            "mongodb" => Self::MongoDB,
            "postgresql" => Self::PostgreSQL,
            "redis" => Self::Redis,
            "memcached" => Self::Memcached,
            "kafka" => Self::Kafka,
            "mqtt" => Self::MQTT,
            "amqp" => Self::AMQP,
            "openwire" => Self::OpenWire,
            "nats" => Self::NATS,
            "pulsar" => Self::Pulsar,
            "zmtp" => Self::ZMTP,
            "rocketmq" => Self::RocketMQ,
            "webspheremq" => Self::WebSphereMq,
            "dns" => Self::DNS,
            "oracle" => Self::Oracle,
            "iso8583" | "iso-8583" => Self::Iso8583,
            "triple" => Self::Triple,
            "tls" => Self::TLS,
            "ping" => Self::Ping,
            "some/ip" | "someip" => Self::SomeIp,
            _ => Self::Unknown,
        }
    }
}

// separate impl for &str and &String because `From<AsRef<str>>` conflict with FromPrimitive trait
impl From<&str> for L7Protocol {
    fn from(s: &str) -> Self {
        s.to_lowercase().into()
    }
}
impl From<&String> for L7Protocol {
    fn from(s: &String) -> Self {
        s.to_lowercase().into()
    }
}

#[derive(Serialize, Debug, Clone, PartialEq, Hash, Eq)]
pub enum CustomProtocol {
    Wasm(u8, String),
    So(u8, String),
    #[serde(serialize_with = "serialize_arc_string")]
    CustomPolicy(Arc<String>),
}

fn serialize_arc_string<S>(arc: &Arc<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(arc)
}

#[derive(Serialize, Clone, Debug, PartialEq, Hash, Eq)]
pub enum L7ProtocolEnum {
    L7Protocol(L7Protocol),
    Custom(CustomProtocol),
}

impl Default for L7ProtocolEnum {
    fn default() -> Self {
        L7ProtocolEnum::L7Protocol(L7Protocol::Unknown)
    }
}

impl From<CustomProtocol> for L7ProtocolEnum {
    fn from(protocol: CustomProtocol) -> Self {
        L7ProtocolEnum::Custom(protocol)
    }
}

impl From<L7Protocol> for L7ProtocolEnum {
    fn from(protocol: L7Protocol) -> Self {
        L7ProtocolEnum::L7Protocol(protocol)
    }
}

impl L7ProtocolEnum {
    pub fn get_l7_protocol(&self) -> L7Protocol {
        match self {
            L7ProtocolEnum::L7Protocol(p) => *p,
            L7ProtocolEnum::Custom(_) => L7Protocol::Custom,
        }
    }
}

#[derive(Serialize, Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum LogMessageType {
    Request,
    Response,
    Session,
    Other,
    Max,
}

impl Default for LogMessageType {
    fn default() -> Self {
        LogMessageType::Other
    }
}

impl From<PacketDirection> for LogMessageType {
    fn from(d: PacketDirection) -> LogMessageType {
        match d {
            PacketDirection::ClientToServer => LogMessageType::Request,
            PacketDirection::ServerToClient => LogMessageType::Response,
        }
    }
}

pub trait L7ProtocolChecker {
    fn is_disabled(&self, p: L7Protocol) -> bool;
    fn is_enabled(&self, p: L7Protocol) -> bool;
}

pub use public_derive_internals::l7_protocol::{
    Field, FieldSetter, L7Log, L7LogAttribute, NativeTag,
};

#[derive(Default, Debug)]
pub struct L7Request {
    pub req_type: String,
    pub domain: String,
    pub resource: String,
    pub endpoint: String,
}

#[derive(Default, Debug)]
pub struct L7Response {
    pub status: L7ResponseStatus,
    pub code: Option<i32>,
    pub exception: String,
    pub result: String,
}

#[derive(Default, Debug)]
pub struct TraceInfo {
    pub trace_ids: Vec<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyVal {
    pub key: String,
    pub val: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MetricKeyVal {
    pub key: String,
    pub val: f32,
}

impl Eq for MetricKeyVal {}

#[derive(Default, Debug)]
pub struct ExtendedInfo {
    pub service_name: Option<String>,
    pub rpc_service: Option<String>,
    pub client_ip: Option<String>,
    pub request_id: Option<u32>,
    pub x_request_id_0: Option<String>,
    pub x_request_id_1: Option<String>,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub protocol_str: Option<String>,
    pub attributes: Option<Vec<KeyVal>>,
    pub metrics: Option<Vec<MetricKeyVal>>,
}

#[derive(L7Log, Serialize, Debug, Default, Clone)]
#[l7_log(trace_id.getter = "L7LogBase::get_trace_id", trace_id.setter = "L7LogBase::set_trace_id")]
pub struct L7LogBase {
    pub msg_type: LogMessageType,
    pub version: String,

    pub request_type: String,
    pub request_domain: String,
    pub request_resource: String,
    pub endpoint: String,

    pub response_status: L7ResponseStatus,
    pub response_code: String,
    pub response_exception: String,
    pub response_result: String,

    pub request_id: Option<u32>,
    pub x_request_id: String,
    pub http_proxy_client: String,

    pub trace_ids: PrioStrings,
    pub span_id: String,

    #[serde(skip)]
    pub attributes: Vec<KeyVal>,

    pub is_async: bool,
    pub is_reversed: bool,
    pub biz_type: u8,
    pub biz_code: String,
    pub biz_scenario: String,
    pub biz_response_code: String,
}

impl L7LogAttribute for L7LogBase {
    fn add_attribute(&mut self, name: Cow<'_, str>, value: Cow<'_, str>) {
        self.attributes.push(KeyVal {
            key: name.into_owned(),
            val: value.into_owned(),
        });
    }
}

impl L7LogBase {
    pub fn merge(&mut self, other: &mut Self) {
        if self.version.is_empty() {
            self.version = std::mem::take(&mut other.version);
        }
        if self.request_type.is_empty() {
            self.request_type = std::mem::take(&mut other.request_type);
        }
        if self.request_domain.is_empty() {
            self.request_domain = std::mem::take(&mut other.request_domain);
        }
        if self.request_resource.is_empty() {
            self.request_resource = std::mem::take(&mut other.request_resource);
        }
        if self.endpoint.is_empty() {
            self.endpoint = std::mem::take(&mut other.endpoint);
        }

        if self.response_status == L7ResponseStatus::default() {
            self.response_status = other.response_status;
        }
        if self.response_code.is_empty() {
            self.response_code = std::mem::take(&mut other.response_code);
        }
        if self.response_exception.is_empty() {
            self.response_exception = std::mem::take(&mut other.response_exception);
        }
        if self.response_result.is_empty() {
            self.response_result = std::mem::take(&mut other.response_result);
        }

        if self.request_id.is_none() {
            self.request_id = other.request_id.take();
        }
        if self.x_request_id.is_empty() {
            self.x_request_id = std::mem::take(&mut other.x_request_id);
        }
        if self.http_proxy_client.is_empty() {
            self.http_proxy_client = std::mem::take(&mut other.http_proxy_client);
        }

        let other_trace_ids = std::mem::take(&mut other.trace_ids);
        self.trace_ids.merge(other_trace_ids);
        if self.span_id.is_empty() {
            self.span_id = std::mem::take(&mut other.span_id);
        }

        self.attributes.append(&mut other.attributes);
        if self.biz_type == 0 {
            self.biz_type = other.biz_type;
        }
        if self.biz_code.is_empty() {
            self.biz_code = std::mem::take(&mut other.biz_code);
        }
        if self.biz_scenario.is_empty() {
            self.biz_scenario = std::mem::take(&mut other.biz_scenario);
        }
        if other.is_async {
            self.is_async = other.is_async;
        }
        if other.is_reversed {
            self.is_reversed = other.is_reversed;
        }
        if self.biz_response_code.is_empty() {
            self.biz_response_code = std::mem::take(&mut other.biz_response_code);
        }
    }

    fn get_trace_id(&self) -> Field {
        if let Some(v) = self.trace_ids.first() {
            Field::Str(Cow::Borrowed(v.as_str()))
        } else {
            Field::Str(Cow::Borrowed(""))
        }
    }

    fn set_trace_id(&mut self, trace_id: FieldSetter) {
        let (prio, trace_id) = (trace_id.prio(), trace_id.into_inner());
        match trace_id {
            Field::Str(s) => {
                self.trace_ids.push(prio, s.into_owned().into());
            }
            _ => return,
        }
    }
}
