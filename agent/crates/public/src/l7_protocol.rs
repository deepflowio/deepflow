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

use num_enum::FromPrimitive;
use serde::Serialize;

pub const DEFAULT_DNS_PORT: u16 = 53;

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Hash, Eq, FromPrimitive, num_enum::Default)]
#[repr(u8)]
pub enum L7Protocol {
    #[num_enum(default)]
    Unknown = 0,
    Other = 1,

    // HTTP
    Http1 = 20,
    Http2 = 21,
    Http1TLS = 22,
    Http2TLS = 23,

    // RPC
    Dubbo = 40,
    Grpc = 41,
    ProtobufRPC = 42,
    SofaRPC = 43,

    FastCGI = 44,

    // SQL
    MySQL = 60,
    PostgreSQL = 61,

    // NoSQL
    Redis = 80,
    MongoDB = 81,

    // MQ
    Kafka = 100,
    MQTT = 101,

    // INFRA
    DNS = 120,

    Custom = 127,

    Max = 255,
}

// Translate the string value of l7_protocol into a L7Protocol enumeration value
impl From<String> for L7Protocol {
    fn from(l7_protocol_str: String) -> Self {
        let l7_protocol_str = l7_protocol_str.to_lowercase();
        match l7_protocol_str.as_str() {
            "http" => Self::Http1,
            "https" => Self::Http1TLS,
            "dubbo" => Self::Dubbo,
            "grpc" => Self::Grpc,
            "protobufrpc" => Self::ProtobufRPC,
            "fastcgi" => Self::FastCGI,
            "custom" => Self::Custom,
            "sofarpc" => Self::SofaRPC,
            "mysql" => Self::MySQL,
            "mongodb" => Self::MongoDB,
            "postgresql" => Self::PostgreSQL,
            "redis" => Self::Redis,
            "kafka" => Self::Kafka,
            "mqtt" => Self::MQTT,
            "dns" => Self::DNS,
            _ => Self::Other,
        }
    }
}

// the actually rpc protocol when l7 protocol is ProtobufRPC
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Hash, Eq)]
#[repr(u64)]
pub enum ProtobufRpcProtocol {
    Krpc = 1,
}

#[derive(Serialize, Debug, Clone, PartialEq, Hash, Eq)]
pub enum CustomProtocol {
    Wasm(u8, String),
    So(u8, String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum L7ProtocolEnum {
    L7Protocol(L7Protocol),
    ProtobufRpc(ProtobufRpcProtocol),
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
            L7ProtocolEnum::ProtobufRpc(_) => L7Protocol::ProtobufRPC,
            L7ProtocolEnum::Custom(_) => L7Protocol::Custom,
        }
    }
}
