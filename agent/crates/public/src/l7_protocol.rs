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

use num_enum::FromPrimitive;
use serde::Serialize;

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

    // SQL
    MySQL = 60,
    PostgreSQL = 61,

    // NoSQL
    Redis = 80,

    // MQ
    Kafka = 100,
    MQTT = 101,

    // INFRA
    DNS = 120,

    Max = 255,
}

// Translate the string value of l7_protocol into a L7Protocol enumeration value
impl From<String> for L7Protocol {
    fn from(l7_protocol_str: String) -> Self {
        let l7_protocol_str = l7_protocol_str.to_lowercase();
        match l7_protocol_str.as_str() {
            "http" => Self::Http1,
            "http2" => Self::Http2,
            "dubbo" => Self::Dubbo,
            "grpc" => Self::Grpc,
            "protobufrpc" => Self::ProtobufRPC,
            "sofarpc" => Self::SofaRPC,
            "mysql" => Self::MySQL,
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

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum L7ProtocolEnum {
    L7Protocol(L7Protocol),
    ProtobufRpc(ProtobufRpcProtocol),
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
        }
    }

    pub fn get_protobuf_rpc_protocol(&self) -> Option<ProtobufRpcProtocol> {
        match self {
            L7ProtocolEnum::L7Protocol(_) => None,
            L7ProtocolEnum::ProtobufRpc(p) => Some(*p),
        }
    }
}
