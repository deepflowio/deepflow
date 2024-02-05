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

use num_enum::{FromPrimitive, IntoPrimitive};
use serde::Serialize;

pub const DEFAULT_DNS_PORT: u16 = 53;
pub const DEFAULT_TLS_PORT: u16 = 443;

#[derive(
    Serialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Hash,
    Eq,
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

    // SQL
    MySQL = 60,
    PostgreSQL = 61,
    Oracle = 62,

    // NoSQL
    Redis = 80,
    MongoDB = 81,

    // MQ
    Kafka = 100,
    MQTT = 101,
    AMQP = 102,
    OpenWire = 103,

    // INFRA
    DNS = 120,
    TLS = 121,

    Custom = 127,

    Max = 255,
}

// Translate the string value of l7_protocol into a L7Protocol enumeration value used by OTEL.
impl From<String> for L7Protocol {
    fn from(l7_protocol_str: String) -> Self {
        let l7_protocol_str = l7_protocol_str.to_lowercase();
        match l7_protocol_str.as_str() {
            "http" | "https" => Self::Http1,
            "http2" => Self::Http2,
            "dubbo" => Self::Dubbo,
            "grpc" => Self::Grpc,
            "fastcgi" => Self::FastCGI,
            "custom" => Self::Custom,
            "sofarpc" => Self::SofaRPC,
            "mysql" => Self::MySQL,
            "mongodb" => Self::MongoDB,
            "postgresql" => Self::PostgreSQL,
            "redis" => Self::Redis,
            "kafka" => Self::Kafka,
            "mqtt" => Self::MQTT,
            "amqp" => Self::AMQP,
            "openwire" => Self::OpenWire,
            "dns" => Self::DNS,
            "oracle" => Self::Oracle,
            "tls" => Self::TLS,
            _ => Self::Unknown,
        }
    }
}

#[derive(Serialize, Debug, Clone, PartialEq, Hash, Eq)]
pub enum CustomProtocol {
    Wasm(u8, String),
    So(u8, String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum L7ProtocolEnum {
    L7Protocol(L7Protocol),
    Custom(CustomProtocol),
}

impl Default for L7ProtocolEnum {
    fn default() -> Self {
        L7ProtocolEnum::L7Protocol(L7Protocol::Unknown)
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
