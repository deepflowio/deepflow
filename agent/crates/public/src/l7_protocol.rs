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

use serde::Serialize;

const L7_PROTOCOL_UNKNOWN: u8 = 0;
const L7_PROTOCOL_OTHER: u8 = 1;
const L7_PROTOCOL_HTTP1: u8 = 20;
const L7_PROTOCOL_HTTP2: u8 = 21;
const L7_PROTOCOL_HTTP1_TLS: u8 = 22;
const L7_PROTOCOL_HTTP2_TLS: u8 = 23;
const L7_PROTOCOL_DUBBO: u8 = 40;
const L7_PROTOCOL_MYSQL: u8 = 60;
const L7_PROTOCOL_POSTGRESQL: u8 = 61;
const L7_PROTOCOL_REDIS: u8 = 80;
const L7_PROTOCOL_KAFKA: u8 = 100;
const L7_PROTOCOL_MQTT: u8 = 101;
const L7_PROTOCOL_DNS: u8 = 120;
const L7_PROTOCOL_MAX: u8 = 255;

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Hash, Eq)]
#[repr(u8)]
pub enum L7Protocol {
    Unknown = L7_PROTOCOL_UNKNOWN,
    Other = L7_PROTOCOL_OTHER,
    Http1 = L7_PROTOCOL_HTTP1,
    Http2 = L7_PROTOCOL_HTTP2,
    Http1TLS = L7_PROTOCOL_HTTP1_TLS,
    Http2TLS = L7_PROTOCOL_HTTP2_TLS,
    Dubbo = L7_PROTOCOL_DUBBO,
    Mysql = L7_PROTOCOL_MYSQL,
    Redis = L7_PROTOCOL_REDIS,
    Kafka = L7_PROTOCOL_KAFKA,
    Mqtt = L7_PROTOCOL_MQTT,
    Dns = L7_PROTOCOL_DNS,

    // add new protocol below
    Postgresql = L7_PROTOCOL_POSTGRESQL,

    Max = L7_PROTOCOL_MAX,
}

impl Default for L7Protocol {
    fn default() -> Self {
        L7Protocol::Unknown
    }
}

// 这个仅用与ebpf, 从l7_protocol_hint获取对应L7Protocol.
// only use for ebpf get l7 protocol from l7_protocol_hint
impl From<u8> for L7Protocol {
    fn from(v: u8) -> Self {
        match v {
            L7_PROTOCOL_OTHER => L7Protocol::Other,
            L7_PROTOCOL_HTTP1 => L7Protocol::Http1,
            L7_PROTOCOL_HTTP2 => L7Protocol::Http2,
            L7_PROTOCOL_HTTP1_TLS => L7Protocol::Http1TLS,
            L7_PROTOCOL_HTTP2_TLS => L7Protocol::Http2TLS,
            L7_PROTOCOL_DUBBO => L7Protocol::Dubbo,
            L7_PROTOCOL_MYSQL => L7Protocol::Mysql,
            L7_PROTOCOL_REDIS => L7Protocol::Redis,
            L7_PROTOCOL_KAFKA => L7Protocol::Kafka,
            L7_PROTOCOL_MQTT => L7Protocol::Mqtt,
            L7_PROTOCOL_DNS => L7Protocol::Dns,

            // add new protocol below
            L7_PROTOCOL_POSTGRESQL => L7Protocol::Postgresql,

            _ => L7Protocol::Unknown,
        }
    }
}
