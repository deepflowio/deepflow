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

use std::borrow::{Borrow, Cow};

use num_enum::{FromPrimitive, IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};

use super::{
    enums::{L7ResponseStatus, PacketDirection},
    types::PrioField,
};

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
    SqlServer = 63,

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
            "sqlserver" => Self::SqlServer,
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
    CustomPolicy(String),
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
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

#[derive(Debug, Default, PartialEq, Eq)]
pub enum Field<'a> {
    #[default]
    None,
    Int(i64),
    Str(Cow<'a, str>),
}

impl Field<'_> {
    pub fn to_string(&self) -> String {
        match self {
            Field::Str(s) => s.to_string(),
            Field::Int(i) => i.to_string(),
            Field::None => String::new(),
        }
    }
}

impl PartialEq<&str> for Field<'_> {
    fn eq(&self, other: &&str) -> bool {
        match self {
            Field::Str(s) => s == *other,
            _ => false,
        }
    }
}

impl PartialEq<i64> for Field<'_> {
    fn eq(&self, other: &i64) -> bool {
        match self {
            Field::Int(i) => i == other,
            _ => false,
        }
    }
}

macro_rules! impl_from_num_for_field {
    ($type:ty) => {
        impl From<$type> for Field<'_> {
            fn from(value: $type) -> Self {
                Field::Int(value as i64)
            }
        }
    };
}

impl_from_num_for_field!(i8);
impl_from_num_for_field!(i16);
impl_from_num_for_field!(i32);
impl_from_num_for_field!(i64);
impl_from_num_for_field!(isize);
impl_from_num_for_field!(u8);
impl_from_num_for_field!(u16);
impl_from_num_for_field!(u32);
impl_from_num_for_field!(u64);
impl_from_num_for_field!(usize);

impl<'a> From<&'a str> for Field<'a> {
    fn from(value: &'a str) -> Self {
        Field::Str(Cow::Borrowed(value))
    }
}

impl<'a> From<&'a String> for Field<'a> {
    fn from(value: &'a String) -> Self {
        Field::Str(Cow::Borrowed(value.as_str()))
    }
}

impl From<String> for Field<'_> {
    fn from(value: String) -> Self {
        Field::Str(Cow::Owned(value))
    }
}

pub type FieldSetter<'a> = PrioField<Field<'a>>;

impl<'a> From<Field<'a>> for FieldSetter<'a> {
    fn from(field: Field<'a>) -> Self {
        PrioField::new(0, field)
    }
}

macro_rules! impl_from_for_field_setter {
    ($type:ty) => {
        impl From<$type> for FieldSetter<'_> {
            fn from(value: $type) -> Self {
                FieldSetter::from(Field::from(value))
            }
        }
    };
    ($type:ty, $lt:lifetime) => {
        impl<$lt> From<&$lt $type> for FieldSetter<$lt> {
            fn from(value: &$lt $type) -> Self {
                FieldSetter::from(Field::from(value))
            }
        }
    };
}

impl_from_for_field_setter!(i8);
impl_from_for_field_setter!(i16);
impl_from_for_field_setter!(i32);
impl_from_for_field_setter!(i64);
impl_from_for_field_setter!(isize);
impl_from_for_field_setter!(u8);
impl_from_for_field_setter!(u16);
impl_from_for_field_setter!(u32);
impl_from_for_field_setter!(u64);
impl_from_for_field_setter!(usize);

impl_from_for_field_setter!(str, 'a);
impl_from_for_field_setter!(String, 'a);
impl_from_for_field_setter!(String);

#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    strum::AsRefStr,
    strum::EnumString,
    strum::Display,
    strum::IntoStaticStr,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[strum(serialize_all = "snake_case", ascii_case_insensitive)]
#[serde(rename_all = "snake_case")]
pub enum NativeTag {
    Version,
    RequestType,
    RequestDomain,
    RequestResource,
    RequestId,
    Endpoint,
    ResponseCode,
    ResponseStatus,
    ResponseException,
    ResponseResult,
    TraceId,
    SpanId,
    XRequestId,
    #[serde(rename = "x_request_id_0")]
    #[strum(serialize = "x_request_id_0")]
    XRequestId0,
    #[serde(rename = "x_request_id_1")]
    #[strum(serialize = "x_request_id_1")]
    XRequestId1,
    HttpProxyClient,
    BizType,
    BizCode,
    BizScenario,
}

pub trait L7LogAttribute {
    fn add_attribute(&mut self, _name: Cow<'_, str>, _value: Cow<'_, str>) {}
}

pub trait L7Log: L7LogAttribute {
    fn get_response_status(&self) -> L7ResponseStatus;
    fn set_response_status(&mut self, response_status: L7ResponseStatus);

    fn get_version(&self) -> Field<'_>;
    fn set_version(&mut self, setter: FieldSetter<'_>);

    fn get_request_type(&self) -> Field<'_>;
    fn set_request_type(&mut self, setter: FieldSetter<'_>);

    fn get_request_domain(&self) -> Field<'_>;
    fn set_request_domain(&mut self, setter: FieldSetter<'_>);

    fn get_request_resource(&self) -> Field<'_>;
    fn set_request_resource(&mut self, setter: FieldSetter<'_>);

    fn get_request_id(&self) -> Field<'_>;
    fn set_request_id(&mut self, setter: FieldSetter<'_>);

    fn get_endpoint(&self) -> Field<'_>;
    fn set_endpoint(&mut self, setter: FieldSetter<'_>);

    fn get_response_code(&self) -> Field<'_>;
    fn set_response_code(&mut self, setter: FieldSetter<'_>);

    fn get_response_exception(&self) -> Field<'_>;
    fn set_response_exception(&mut self, setter: FieldSetter<'_>);

    fn get_response_result(&self) -> Field<'_>;
    fn set_response_result(&mut self, setter: FieldSetter<'_>);

    fn get_trace_id(&self) -> Field<'_>;
    fn set_trace_id(&mut self, setter: FieldSetter<'_>);

    fn get_span_id(&self) -> Field<'_>;
    fn set_span_id(&mut self, setter: FieldSetter<'_>);

    fn get_x_request_id(&self) -> Field<'_>;
    fn set_x_request_id(&mut self, setter: FieldSetter<'_>);
    fn get_x_request_id_0(&self) -> Field<'_> {
        self.get_x_request_id()
    }
    fn get_x_request_id_1(&self) -> Field<'_> {
        self.get_x_request_id()
    }
    fn set_x_request_id_0(&mut self, setter: FieldSetter<'_>) {
        self.set_x_request_id(setter)
    }
    fn set_x_request_id_1(&mut self, setter: FieldSetter<'_>) {
        self.set_x_request_id(setter)
    }

    fn get_http_proxy_client(&self) -> Field<'_>;
    fn set_http_proxy_client(&mut self, setter: FieldSetter<'_>);

    fn get_biz_type(&self) -> Field<'_>;
    fn set_biz_type(&mut self, setter: FieldSetter<'_>);

    fn get_biz_code(&self) -> Field<'_>;
    fn set_biz_code(&mut self, setter: FieldSetter<'_>);

    fn get_biz_scenario(&self) -> Field<'_>;
    fn set_biz_scenario(&mut self, setter: FieldSetter<'_>);

    fn get(&self, tag: NativeTag) -> Field<'_> {
        match tag {
            NativeTag::Version => self.get_version(),
            NativeTag::RequestType => self.get_request_type(),
            NativeTag::RequestDomain => self.get_request_domain(),
            NativeTag::RequestResource => self.get_request_resource(),
            NativeTag::RequestId => self.get_request_id(),
            NativeTag::Endpoint => self.get_endpoint(),
            NativeTag::ResponseCode => self.get_response_code(),
            NativeTag::ResponseStatus => self.get_response_status().as_str().into(),
            NativeTag::ResponseException => self.get_response_exception(),
            NativeTag::ResponseResult => self.get_response_result(),
            NativeTag::TraceId => self.get_trace_id(),
            NativeTag::SpanId => self.get_span_id(),
            NativeTag::XRequestId => self.get_x_request_id(),
            NativeTag::XRequestId0 => self.get_x_request_id_0(),
            NativeTag::XRequestId1 => self.get_x_request_id_1(),
            NativeTag::HttpProxyClient => self.get_http_proxy_client(),
            NativeTag::BizType => self.get_biz_type(),
            NativeTag::BizCode => self.get_biz_code(),
            NativeTag::BizScenario => self.get_biz_scenario(),
        }
    }

    fn set(&mut self, tag: NativeTag, setter: FieldSetter<'_>) {
        match tag {
            NativeTag::Version => self.set_version(setter),
            NativeTag::RequestType => self.set_request_type(setter),
            NativeTag::RequestDomain => self.set_request_domain(setter),
            NativeTag::RequestResource => self.set_request_resource(setter),
            NativeTag::RequestId => self.set_request_id(setter),
            NativeTag::Endpoint => self.set_endpoint(setter),
            NativeTag::ResponseCode => self.set_response_code(setter),
            NativeTag::ResponseStatus => match setter.into_inner() {
                Field::Str(s) => self.set_response_status(L7ResponseStatus::from(s.borrow())),
                Field::Int(i) => self
                    .set_response_status(L7ResponseStatus::try_from(i as u8).unwrap_or_default()),
                Field::None => self.set_response_status(L7ResponseStatus::Unknown),
            },
            NativeTag::ResponseException => self.set_response_exception(setter),
            NativeTag::ResponseResult => self.set_response_result(setter),
            NativeTag::TraceId => self.set_trace_id(setter),
            NativeTag::SpanId => self.set_span_id(setter),
            NativeTag::XRequestId => self.set_x_request_id(setter),
            NativeTag::XRequestId0 => self.set_x_request_id_0(setter),
            NativeTag::XRequestId1 => self.set_x_request_id_1(setter),
            NativeTag::HttpProxyClient => self.set_http_proxy_client(setter),
            NativeTag::BizType => self.set_biz_type(setter),
            NativeTag::BizCode => self.set_biz_code(setter),
            NativeTag::BizScenario => self.set_biz_scenario(setter),
        }
    }
}
