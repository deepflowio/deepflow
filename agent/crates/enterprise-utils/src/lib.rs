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
    pub mod plugin {
        pub mod custom_field_policy {
            use std::collections::HashMap;

            #[macro_export]
            macro_rules! set_from_tag {
                ($($_:expr),+) => {};
            }
            pub use set_from_tag;

            #[derive(Clone, Debug, Default, PartialEq, Eq)]
            pub struct ExtraField {
                pub field_match_type: public::enums::MatchType,
                pub field_match_keyword: String,
                pub subfield_match_keyword: Option<String>,
                pub separator_between_subfield_kv_pair: Option<String>,
                pub separator_between_subfield_key_and_value: Option<String>,
                pub check_value_charset: bool,
                pub value_primary_charset: Vec<public::enums::Charset>,
                pub value_special_charset: String,
                pub attribute_name: Option<String>,
                pub rewrite_native_tag: String,
                pub response_success_values: Vec<String>,
                pub metric_name: Option<String>,
            }
            impl ExtraField {
                pub const VERSION: &'static str = "";
                pub const REQUEST_TYPE: &'static str = "";
                pub const REQUEST_DOMAIN: &'static str = "";
                pub const REQUEST_RESOURCE: &'static str = "";
                pub const REQUEST_ID: &'static str = "";
                pub const ENDPOINT: &'static str = "";
                pub const RESPONSE_CODE: &'static str = "";
                pub const RESPONSE_STATUS: &'static str = "";
                pub const RESPONSE_EXCEPTION: &'static str = "";
                pub const RESPONSE_RESULT: &'static str = "";
                pub const TRACE_ID: &'static str = "";
                pub const SPAN_ID: &'static str = "";
                pub const X_REQUEST_ID: &'static str = "";
                pub const HTTP_PROXY_CLIENT: &'static str = "";

                pub fn match_key(&self, _: &str) -> bool {
                    unimplemented!()
                }
                pub fn check_value(&self, _: &String) -> bool {
                    unimplemented!()
                }
                pub fn get_subvalue(&self, _: &str) -> Option<String> {
                    unimplemented!()
                }
                pub fn set_value(
                    &self,
                    _: &str,
                    _: &mut HashMap<&'static str, String>,
                ) -> Option<String> {
                    unimplemented!()
                }
                pub fn get_value_from_payload(
                    &self,
                    _: &super::custom_protocol_policy::ParsedPayload,
                ) -> Option<String> {
                    unimplemented!()
                }
            }

            #[derive(Clone, Debug, Default, PartialEq, Eq)]
            pub struct ExtraCustomFieldPolicy {
                pub from_req_key:
                    HashMap<public::enums::FieldType, HashMap<String, Vec<ExtraField>>>,
                pub from_resp_key:
                    HashMap<public::enums::FieldType, HashMap<String, Vec<ExtraField>>>,
                pub from_req_body: HashMap<public::enums::FieldType, Vec<ExtraField>>,
                pub from_resp_body: HashMap<public::enums::FieldType, Vec<ExtraField>>,
            }

            #[derive(Clone, Debug, Default, PartialEq, Eq)]
            pub struct KeywordMatcher {
                pub match_type: public::enums::MatchType,
                pub match_from_begining: bool,
                pub match_keyword_bytes: Vec<u8>,
            }

            #[derive(Clone, Debug, Default, PartialEq, Eq)]
            pub struct ExtraProtocolCharacters {
                pub protocol_name: String,
                pub request_characters: Vec<Vec<KeywordMatcher>>,
                pub response_characters: Vec<Vec<KeywordMatcher>>,
            }

            #[derive(Clone, Debug, Default, PartialEq, Eq)]
            pub struct ExtraCustomProtocolConfig {
                pub port_segmentmap: public::segment_map::SegmentMap<usize>,
                pub protocol_characters: Vec<ExtraProtocolCharacters>,
            }

            pub fn field_type_support_protocol(
                _: &public::enums::FieldType,
                _: public::l7_protocol::L7Protocol,
            ) -> bool {
                unimplemented!()
            }

            pub fn format_payload<'a>(
                _: &public::enums::FieldType,
                _: &'a [u8],
            ) -> Option<super::custom_protocol_policy::ParsedPayload<'a>> {
                unimplemented!()
            }
        }

        pub mod custom_protocol_policy {
            use std::collections::HashMap;

            pub struct ParsedPayload<'a> {
                _p: std::marker::PhantomData<&'a ()>,
            }

            #[derive(Default, Debug)]
            pub struct CustomPolicyInfo {
                pub is_request: bool,
                pub version: String,
                pub request_type: String,
                pub request_domain: String,
                pub request_resource: String,
                pub endpoint: String,
                pub request_id: Option<u32>,
                pub response_code: Option<i32>,
                pub response_status: String,
                pub response_exception: String,
                pub response_result: String,
                pub trace_id: Option<String>,
                pub span_id: Option<String>,
                pub http_proxy_client: Option<String>,
                pub x_request_id: Option<String>,
                pub attributes: HashMap<String, String>,
                pub metrics: HashMap<String, f32>,
            }

            #[derive(Default, Debug)]
            pub struct CustomPolicyParser {
                pub info: CustomPolicyInfo,
            }
            impl CustomPolicyParser {
                pub fn check_payload(
                    &mut self,
                    _: &[u8],
                    _: &super::custom_field_policy::ExtraCustomProtocolConfig,
                    _: public::enums::TrafficDirection,
                    _: u16,
                ) -> Option<String> {
                    unimplemented!()
                }
                pub fn parse_payload(
                    &mut self,
                    _: &[u8],
                    _: public::enums::TrafficDirection,
                    _: &Vec<super::custom_field_policy::ExtraCustomFieldPolicy>,
                    _: &Vec<usize>,
                ) -> bool {
                    unimplemented!()
                }
            }
        }
    }

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
