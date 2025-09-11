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

pub mod l7 {
    pub mod sql {
        pub mod oracle {
            use std::fmt;

            use serde::Serialize;

            pub struct Request {
                pub sql: String,
                pub req_data_flags: DataFlags, // 仅 TnsPacketType 为 TnsTypeData 时有值
                pub req_data_id: Option<DataId>, // 仅 TnsPacketType 为 TnsTypeData 时有值
                pub req_call_id: Option<CallId>, // 仅 TnsPacketType 为 TnsTypeData 时有值
            }

            pub struct Response {
                pub ret_code: u16,
                pub affected_rows: Option<u32>,
                pub error_message: String,
                pub resp_data_flags: DataFlags, // 仅 TnsPacketType 为 TnsTypeData 时有值
                pub resp_data_id: Option<DataId>, // 仅 TnsPacketType 为 TnsTypeData 时有值
            }

            pub enum Body {
                Request(Request),
                Response(Response),
            }

            #[derive(Clone, Debug, PartialEq)]
            pub struct CallId;

            impl CallId {
                pub fn as_str(&self) -> &str {
                    unimplemented!()
                }
            }

            #[derive(Clone, Copy, Debug, Default, PartialEq)]
            pub struct DataFlags;

            impl DataFlags {
                pub fn bits(&self) -> u64 {
                    unimplemented!()
                }
            }

            impl fmt::Display for DataFlags {
                fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
                    unimplemented!()
                }
            }

            #[derive(Clone, Debug, PartialEq)]
            pub struct DataId;

            impl DataId {
                pub fn as_str(&self) -> &str {
                    unimplemented!()
                }
            }

            pub struct OracleParseConfig {
                pub is_be: bool,
                pub int_compress: bool,
                // 0x04 结构有差异，个别结构有一个额外的 0x01 字节
                pub resp_0x04_extra_byte: bool,
            }

            pub struct Frame {
                pub packet_type: TnsPacketType,
                pub length: usize,
                pub body: Body,
            }

            #[derive(Default)]
            pub struct OracleParser {
                pub frames: Vec<Frame>,
            }

            impl OracleParser {
                pub fn check_payload(&mut self, _: &[u8], _: &OracleParseConfig) -> bool {
                    unimplemented!()
                }

                pub fn parse_payload(&mut self, _: &[u8], _: bool, _: &OracleParseConfig) -> bool {
                    unimplemented!()
                }
            }

            #[derive(Serialize, Clone, Copy, Debug, Default, PartialEq)]
            pub enum TnsPacketType {
                #[default]
                Unknown,
            }

            impl TnsPacketType {
                pub fn as_str(&self) -> &str {
                    unimplemented!()
                }
            }
        }
    }

    pub mod iso {
        pub mod iso8583 {
            use public::bitmap::Bitmap;

            pub struct Iso8583ParseConfig {
                pub extract_fields: Bitmap,
                pub translation_enabled: bool,
                pub pan_obfuscate: bool,
            }

            #[derive(Debug, Clone)]
            pub struct FieldValue {
                pub id: u32,
                pub description: String,
                pub value: String,
                pub translated: Option<String>, // if translation_enabled configured
            }

            #[derive(Default)]
            pub struct Iso8583Parser {
                pub fields: Vec<FieldValue>,
            }

            impl Iso8583Parser {
                pub fn check_payload(&mut self, _: &[u8], _: &Iso8583ParseConfig) -> bool {
                    unimplemented!()
                }

                pub fn parse_payload(&mut self, _: &[u8], _: bool, _: &Iso8583ParseConfig) -> bool {
                    unimplemented!()
                }
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod utils {
    bitflags::bitflags! {
        #[derive(Default)]
        pub struct ActionFlags: u8 {
            const NONE  = 0b000000;
            const WARN  = 0b000001;
            const ERROR = 0b000010;
            const ALARM = 0b000100;
            const MELTDOWN = 0b001000;
            const TERMINATE = 0b010000;
        }
    }

    pub fn kernel_version_check() -> ActionFlags {
        unimplemented!()
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod rpc {
    pub mod remote_exec {
        pub fn extra_commands() -> Vec<public::rpc::remote_exec::Command> {
            unimplemented!()
        }
    }
}
