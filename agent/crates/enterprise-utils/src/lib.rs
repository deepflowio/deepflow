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
    pub mod custom_policy {
        pub mod config {
            use std::collections::HashMap;

            use serde::Deserialize;

            use public::l7_protocol::L7ProtocolEnum;

            use super::custom_field_policy::PolicyMap;

            #[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
            pub struct CustomProtocolConfigs;
            impl CustomProtocolConfigs {
                pub fn port_range(&self) -> String {
                    unimplemented!()
                }
            }

            #[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
            pub struct CustomFieldPolicies;
            impl CustomFieldPolicies {
                pub fn get_extra_field_policies(&self) -> HashMap<L7ProtocolEnum, PolicyMap> {
                    unimplemented!()
                }
            }
        }

        pub mod custom_field_policy {
            use std::collections::HashMap;
            use std::sync::Arc;

            #[macro_export]
            macro_rules! set_from_tag {
                ($($_:expr),+) => {};
            }
            pub use set_from_tag;

            #[derive(Clone, Debug, Default, PartialEq)]
            pub struct ExtraField {
                pub field_match_type: super::enums::MatchType,
                pub field_match_keyword: String,
                pub subfield_match_keyword: Option<String>,
                pub separator_between_subfield_kv_pair: Option<String>,
                pub separator_between_subfield_key_and_value: Option<String>,
                pub check_value_charset: bool,
                pub value_primary_charset: Vec<super::enums::Charset>,
                pub value_special_charset: String,
                pub attribute_name: Option<String>,
                pub rewrite_native_tag: Option<super::enums::NativeTag>,
                pub response_success_values: Vec<String>,
                pub metric_name: Option<String>,
            }
            impl ExtraField {
                pub fn match_key(&self, _: &str) -> bool {
                    unimplemented!()
                }
                pub fn check_value(&self, _: &String) -> bool {
                    unimplemented!()
                }
                pub fn get_subvalue(&self, _: &str) -> Option<String> {
                    unimplemented!()
                }
                pub fn get_value(&self, _: &str) -> Option<String> {
                    unimplemented!()
                }
                pub fn insert_value(&self, _: String, _: &mut HashMap<&'static str, String>) {
                    unimplemented!()
                }
                pub fn get_value_from_payload(
                    &self,
                    _: &[u8],
                    _: &super::enums::FieldType,
                ) -> Option<String> {
                    unimplemented!()
                }
            }

            #[derive(Clone, Debug, Default, PartialEq)]
            pub struct Policy {
                pub feature_string: Option<String>,

                pub from_req_key:
                    HashMap<super::enums::FieldType, HashMap<String, Vec<ExtraField>>>,
                pub from_resp_key:
                    HashMap<super::enums::FieldType, HashMap<String, Vec<ExtraField>>>,
                pub from_req_body: HashMap<super::enums::FieldType, Vec<ExtraField>>,
                pub from_resp_body: HashMap<super::enums::FieldType, Vec<ExtraField>>,
            }
            impl Policy {
                pub fn apply_in(
                    &self,
                    _: &mut Vec<Operation>,
                    _: &super::enums::FieldType,
                    _: &[u8],
                ) {
                    unimplemented!()
                }
                pub fn apply(&self, _: &super::enums::FieldType, _: &[u8]) -> Vec<Operation> {
                    unimplemented!()
                }
            }

            #[derive(Clone, Default, Debug, PartialEq)]
            pub struct PolicyMap {
                pub indices: public::segment_map::SegmentMap<usize>,
                pub policies: Vec<Policy>,
            }
            impl PolicyMap {
                pub fn select(&self, _: u16) -> Option<PolicyMapSlice> {
                    unimplemented!()
                }
            }

            pub struct PolicyMapSlice;
            impl PolicyMapSlice {
                pub fn apply_in(
                    &self,
                    _: &mut Vec<Operation>,
                    _: &super::enums::FieldType,
                    _: &[u8],
                ) {
                    unimplemented!()
                }
                pub fn apply(&self, _: &super::enums::FieldType, _: &[u8]) -> Vec<Operation> {
                    unimplemented!()
                }
            }

            pub fn field_type_support_protocol(
                _: &super::enums::FieldType,
                _: public::l7_protocol::L7Protocol,
            ) -> bool {
                unimplemented!()
            }

            #[derive(Clone, Debug, PartialEq)]
            pub enum Operation {
                Rewrite(super::enums::NativeTag, Option<Arc<String>>),
                AddAttribute(String, Option<Arc<String>>),
                AddMetric(String, Option<f32>),
            }
        }

        pub mod custom_protocol_policy {
            use std::collections::HashMap;

            use super::config::CustomProtocolConfigs;

            #[derive(Clone, Debug, Default, PartialEq)]
            pub struct KeywordMatcher {
                pub match_type: super::enums::MatchType,
                pub match_from_begining: bool,
                pub match_keyword_bytes: Vec<u8>,
            }

            #[derive(Clone, Debug, Default, PartialEq)]
            pub struct ExtraProtocolCharacters {
                pub protocol_name: String,
                pub request_characters: Vec<Vec<KeywordMatcher>>,
                pub response_characters: Vec<Vec<KeywordMatcher>>,
            }

            #[derive(Clone, Debug, Default, PartialEq)]
            pub struct ExtraCustomProtocolConfig {
                pub port_map: public::segment_map::SegmentMap<usize>,
                pub protocol_characters: Vec<ExtraProtocolCharacters>,
            }
            impl From<&CustomProtocolConfigs> for ExtraCustomProtocolConfig {
                fn from(_: &CustomProtocolConfigs) -> Self {
                    unimplemented!()
                }
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
                    _: &ExtraCustomProtocolConfig,
                    _: super::enums::TrafficDirection,
                    _: u16,
                ) -> Option<String> {
                    unimplemented!()
                }
                pub fn parse_payload(
                    &mut self,
                    _: &[u8],
                    _: super::enums::TrafficDirection,
                    _: &Vec<super::custom_field_policy::Policy>,
                    _: &Vec<usize>,
                ) -> bool {
                    unimplemented!()
                }
            }
        }

        pub mod enums {
            use serde::Deserialize;

            #[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
            pub enum MatchType {
                String(bool),
            }
            impl Default for MatchType {
                fn default() -> Self {
                    Self::String(false)
                }
            }

            #[derive(Clone, Copy, Debug, Default, Deserialize, Hash, PartialEq, Eq)]
            pub enum TrafficDirection {
                Request,
                Response,
                #[default]
                Both,
            }

            #[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
            pub enum Charset {
                Dummy,
            }

            #[derive(Clone, Copy, Debug, Default, Deserialize, Hash, PartialEq, Eq, PartialOrd)]
            pub enum FieldType {
                #[default]
                Header,
                HttpUrl,
                PayloadJson,
                PayloadXml,
                DubboHeader,
                DubboPayloadMapString,
                PayloadHessian2,
                SqlInsertionColumn,
            }

            #[derive(
                Clone,
                Copy,
                Debug,
                strum::AsRefStr,
                strum::EnumString,
                strum::Display,
                strum::IntoStaticStr,
                Hash,
                PartialEq,
                Eq,
            )]
            #[strum(serialize_all = "snake_case", ascii_case_insensitive)]
            pub enum NativeTag {
                Version,
                RequestType,
                RequestDomain,
                RequestResource,
                RequestId,
                Endpoint,
                ResponseCode,
                // can not be set, only extracted by response_code match success_value
                ResponseStatus,
                ResponseException,
                ResponseResult,
                TraceId,
                SpanId,
                XRequestId,
                HttpProxyClient,
                BizType,
                BizCode,
                BizScenario,
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

    pub mod mq {
        pub mod web_sphere_mq {

            #[derive(Default)]
            pub struct WebSphereMqParser {
                pub request_type: Option<String>,
                pub end_to_end_id: Option<String>,
                pub ret_code: Option<String>,
                pub exception: Option<String>,
            }

            impl WebSphereMqParser {
                pub fn check_payload(&mut self, _: &[u8], _: bool) -> bool {
                    unimplemented!()
                }

                pub fn parse_payload(&mut self, _: &[u8], _: bool) -> bool {
                    unimplemented!()
                }
            }
        }
    }

    pub mod rpc {
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
pub mod kernel_version {
    bitflags::bitflags! {
        #[derive(Default)]
        pub struct ActionFlags: u8 {
            const NONE  = 0b000000;
            const WARN  = 0b000001;
            const ERROR = 0b000010;
            const ALARM = 0b000100;
            const MELTDOWN = 0b001000;
            const TERMINATE = 0b010000;
            const EBPF_MELTDOWN = 0b0100000;
            const EBPF_UPROBE_MELTDOWN = 0b1000000;
        }
    }

    pub fn kernel_version_check() -> ActionFlags {
        unimplemented!()
    }

    pub fn is_kernel_meltdown() -> bool {
        unimplemented!()
    }

    pub fn is_kernel_ebpf_meltdown() -> bool {
        unimplemented!()
    }

    pub fn is_kernel_ebpf_uprobe_meltdown() -> bool {
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
