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
            use serde::Deserialize;

            #[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
            pub struct CustomProtocolConfig;

            #[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
            pub struct CustomFieldPolicy;
            impl CustomFieldPolicy {
                pub fn get_http2_headers(&self) -> impl Iterator<Item = &str> {
                    std::iter::empty()
                }
            }
        }

        pub mod custom_field_policy {
            use std::marker::PhantomData;

            pub mod enums {
                use std::sync::Arc;

                bitflags::bitflags! {
                    pub struct PayloadType: u8 {
                        const JSON = 0x01;
                        const XML = 0x02;
                        const HESSIAN2 = 0x04;
                    }
                }

                #[derive(Clone, Copy, PartialEq, Eq)]
                pub enum Source<'a> {
                    Url(&'a str),
                    Header(&'a str, &'a str),
                    Payload(PayloadType, &'a [u8]),
                    Sql(&'a str),
                }

                #[derive(Clone, Debug, PartialEq)]
                pub struct Operation {
                    pub op: Op,
                    pub prio: u8,
                }

                #[derive(Clone, Debug, PartialEq)]
                pub enum Op {
                    RewriteResponseStatus(public::enums::L7ResponseStatus),
                    RewriteNativeTag(public::l7_protocol::NativeTag, Arc<String>),
                    AddAttribute(Arc<String>, Arc<String>),
                    AddMetric(Arc<String>, f32),
                    SavePayload(Arc<String>),
                }
            }

            #[derive(Clone, Default, Debug, PartialEq)]
            pub struct CustomFieldPolicy;
            impl CustomFieldPolicy {
                pub fn new(_: &[super::config::CustomFieldPolicy]) -> Self {
                    unimplemented!()
                }
                pub fn select(
                    &self,
                    _: public::l7_protocol::L7ProtocolEnum,
                    _: u16,
                ) -> Option<PolicySlice> {
                    unimplemented!()
                }
                pub fn counters(
                    &self,
                ) -> impl Iterator<Item = (&dyn public::counter::Module, public::counter::Countable)> + '_
                {
                    std::iter::empty()
                }
            }

            #[derive(Clone, Copy, Debug)]
            pub struct PolicySlice<'a> {
                _marker: PhantomData<&'a ()>,
            }

            impl<'a> PolicySlice<'a> {
                pub fn apply(
                    &self,
                    _: &mut Store,
                    _: super::enums::TrafficDirection,
                    _: enums::Source,
                ) {
                    unimplemented!()
                }
            }

            #[derive(Default, Debug)]
            pub struct Store;
            impl Store {
                pub fn is_empty(&self) -> bool {
                    unimplemented!()
                }

                pub fn clear(&mut self) {
                    unimplemented!()
                }

                pub fn into_iter_with<L: public::l7_protocol::L7Log>(
                    self,
                    _: PolicySlice,
                    _: &L,
                ) -> impl Iterator<Item = enums::Operation> {
                    std::iter::empty()
                }

                pub fn drain_with<L: public::l7_protocol::L7Log>(
                    &mut self,
                    _: PolicySlice,
                    _: &L,
                ) -> impl Iterator<Item = enums::Operation> + '_ {
                    std::iter::empty()
                }
            }
        }

        pub mod custom_protocol_policy {
            use std::collections::HashMap;

            #[derive(Clone, Default, Debug, PartialEq, Eq)]
            pub struct ExtraProtocolCharacters;

            #[derive(Clone, Debug, Default, PartialEq)]
            pub struct ExtraCustomProtocolConfig {
                pub protocol_characters: Vec<ExtraProtocolCharacters>,
            }
            impl ExtraCustomProtocolConfig {
                pub fn port_range(_: &[super::config::CustomProtocolConfig]) -> String {
                    unimplemented!()
                }
                pub fn new(_: &[super::config::CustomProtocolConfig]) -> Self {
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
                    _: super::custom_field_policy::PolicySlice,
                ) -> bool {
                    unimplemented!()
                }
            }
        }

        pub mod enums {
            use serde::Deserialize;

            bitflags::bitflags! {
                #[derive(Deserialize)]
                #[serde(rename_all = "snake_case")]
                pub struct TrafficDirection: u8 {
                    const REQUEST = 0x01;
                    const RESPONSE = 0x10;
                    const BOTH = Self::REQUEST.bits() | Self::RESPONSE.bits();
                }
            }

            impl From<public::enums::PacketDirection> for TrafficDirection {
                fn from(_: public::enums::PacketDirection) -> Self {
                    unimplemented!()
                }
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
        }
    }

    pub mod sql {
        pub mod oracle {
            use std::fmt;

            use public::l7_protocol::LogMessageType;
            use serde::Serialize;

            pub struct Request {
                pub sql: String,
                pub req_data_flags: DataFlags, // 仅 TnsPacketType 为 TnsTypeData 时有值
                pub req_data_id: Option<DataId>, // 仅 TnsPacketType 为 TnsTypeData 时有值
                pub req_call_id: Option<CallId>, // 仅 TnsPacketType 为 TnsTypeData 时有值
                pub connect_data: Option<String>, // 仅 TnsPacketType 为 TnsTypeConnect 时有值
            }

            pub struct Response {
                pub ret_code: u16,
                pub affected_rows: Option<u32>,
                pub error_message: String,
                pub resp_data_flags: DataFlags, // 仅 TnsPacketType 为 TnsTypeData 时有值
                pub resp_data_id: Option<DataId>, // 仅 TnsPacketType 为 TnsTypeData 时有值
                pub auth_session_id: Option<String>,
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
                pub fn check_payload(
                    &mut self,
                    _: &[u8],
                    _: &OracleParseConfig,
                ) -> Option<LogMessageType> {
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
            use public::{
                enums::{L7ResponseStatus, PacketDirection},
                l7_protocol::{KeyVal, LogMessageType},
            };

            #[derive(Default)]
            pub struct WebSphereMqParser {
                pub msg_type: LogMessageType,
                pub is_async: bool,
                pub is_reversed: bool,

                pub ntfctn_id: String,
                pub orgnl_msg_id: String,
                pub msg_id: String,

                pub mesg_id: String,
                pub mesg_ref_id: String,
                pub mesg_type: String,
                pub mesg_priority: String,
                pub mesg_direction: String,

                pub endpoint: String,
                pub status: L7ResponseStatus,
                pub response_code: String,
                pub response_exception: String,

                pub attributes: Vec<KeyVal>,

                pub biz_type: u8,
                pub biz_code: String,
                pub biz_scenario: String,
            }

            impl WebSphereMqParser {
                pub fn check_payload(&mut self, _: &[u8]) -> Option<LogMessageType> {
                    unimplemented!()
                }

                pub fn parse_payload(&mut self, _: &[u8], _: PacketDirection) -> usize {
                    unimplemented!()
                }
            }
        }
    }

    pub mod rpc {
        pub mod iso8583 {
            use public::bitmap::Bitmap;

            use public::l7_protocol::LogMessageType;

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
                pub fn check_payload(
                    &mut self,
                    _: &[u8],
                    _: &Iso8583ParseConfig,
                ) -> Option<LogMessageType> {
                    unimplemented!()
                }

                pub fn parse_payload_multiple(
                    &mut self,
                    _: &[u8],
                    _: &Iso8583ParseConfig,
                ) -> Vec<Vec<FieldValue>> {
                    unimplemented!()
                }
            }
        }
    }
}

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
