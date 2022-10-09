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

macro_rules! l7_protocol {
    ($($proto:ident = $num:literal),+$(,)*) => {

        /*
        expand like:

        pub enum L7Protocol {
            Dns = 120,
            ...
        }

        */
        #[derive(Serialize, Debug, Clone, Copy, PartialEq, Hash, Eq)]
        #[repr(u8)]
        pub enum L7Protocol {
            $(
                $proto = $num,
            )+
        }

        /*
        expand like:

        impl From<u8> for L7Protocol {
            fn from(v: u8) -> Self {
                match v {
                    120 => L7Protocol::Dns,
                    ...

                    _ => L7Protocol::Unknown,
                }
            }
        }

        */

        // 这个仅用于ebpf从l7_protocol_hint获取对应L7Protocol.
        // ======================================================
        // only use for ebpf get l7 protocol from l7_protocol_hint
        impl From<u8> for L7Protocol {
            fn from(v: u8) -> Self {
                match v {
                    $(
                        $num=>L7Protocol::$proto,
                    )+

                    _ => L7Protocol::Unknown,
                }
            }
        }

    };
}

impl Default for L7Protocol {
    fn default() -> Self {
        L7Protocol::Unknown
    }
}

l7_protocol!(
    Unknown = 0,
    Other = 1,
    Max = 255,
    Http1 = 20,
    Http2 = 21,
    Http1TLS = 22,
    Http2TLS = 23,
    Dubbo = 40,
    Mysql = 60,
    Postgresql = 61,
    Redis = 80,
    Kafka = 100,
    Mqtt = 101,
    Dns = 120,
    // add protocol below
);
