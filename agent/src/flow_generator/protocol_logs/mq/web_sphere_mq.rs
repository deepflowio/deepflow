/*
 * Copyright (c) 2025 Yunshan Networks
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

use std::borrow::Cow;

use serde::Serialize;

use public::l7_protocol::{
    Field, FieldSetter, L7Log, L7LogAttribute, L7ProtocolEnum, LogMessageType,
};
use public_derive::L7Log;

use enterprise_utils::l7::{
    custom_policy::custom_field_policy::{enums::Op, PolicySlice, Store},
    mq::web_sphere_mq::WebSphereMqParser,
};

use crate::{
    common::{
        flow::{L7PerfStats, L7Protocol},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, LogCache, ParseParam},
        meta_packet::ApplicationFlags,
    },
    config::handler::LogParserConfig,
    flow_generator::{
        error::{Error, Result},
        protocol_logs::{
            auto_merge_custom_field,
            consts::*,
            pb_adapter::{
                ExtendedInfo, KeyVal, L7ProtocolSendLog, L7Request, L7Response, TraceInfo,
            },
            set_captured_byte, swap_if, value_is_default, AppProtoHead, L7ResponseStatus,
            PrioFields, BASE_FIELD_PRIORITY, PLUGIN_FIELD_PRIORITY,
        },
    },
    plugin::CustomInfo,
};

#[derive(L7Log, Serialize, Debug, Default, Clone)]
#[l7_log(version.skip = "true")]
#[l7_log(response_result.skip = "true")]
#[l7_log(x_request_id.skip = "true")]
#[l7_log(http_proxy_client.skip = "true")]
#[l7_log(request_id.skip = "true")]
#[l7_log(trace_id.getter = "WebSphereMqInfo::get_trace_id", trace_id.setter = "WebSphereMqInfo::set_trace_id")]
pub struct WebSphereMqInfo {
    msg_type: LogMessageType,
    #[serde(skip)]
    is_tls: bool,
    #[serde(skip)]
    is_async: bool,
    #[serde(skip)]
    is_reversed: bool,

    #[serde(skip_serializing_if = "value_is_default")]
    pub trace_ids: PrioFields,
    #[serde(skip_serializing_if = "value_is_default")]
    pub span_id: String,

    // request
    #[serde(skip_serializing_if = "value_is_default")]
    pub request_type: String,

    #[serde(skip_serializing_if = "value_is_default")]
    pub request_domain: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub request_resource: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub endpoint: String,

    // response
    #[l7_log(response_status)]
    #[serde(rename = "response_status", skip_serializing_if = "value_is_default")]
    pub status: L7ResponseStatus,
    #[serde(skip_serializing_if = "value_is_default")]
    pub response_code: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub response_exception: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub response_result: String,

    #[serde(skip)]
    attributes: Vec<KeyVal>,

    captured_request_byte: u32,
    captured_response_byte: u32,

    rrt: u64,

    #[serde(skip)]
    is_on_blacklist: bool,

    #[serde(skip_serializing_if = "value_is_default")]
    biz_type: u8,
    #[serde(skip_serializing_if = "value_is_default")]
    biz_code: String,
    #[serde(skip_serializing_if = "value_is_default")]
    biz_scenario: String,
}

impl L7ProtocolInfoInterface for WebSphereMqInfo {
    fn session_id(&self) -> Option<u32> {
        None
    }

    fn needs_session_aggregation(&self) -> bool {
        false
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::WebSphereMqInfo(mq) = other {
            self.merge(mq);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::WebSphereMq,
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn is_tls(&self) -> bool {
        self.is_tls
    }

    fn get_request_resource_length(&self) -> usize {
        0
    }

    fn is_on_blacklist(&self) -> bool {
        self.is_on_blacklist
    }

    fn get_biz_type(&self) -> u8 {
        self.biz_type
    }

    fn is_reversed(&self) -> bool {
        self.is_reversed
    }

    fn get_endpoint(&self) -> Option<String> {
        if self.endpoint.is_empty() {
            return None;
        }
        Some(self.endpoint.clone())
    }
}

impl L7LogAttribute for WebSphereMqInfo {
    fn add_attribute(&mut self, name: Cow<'_, str>, value: Cow<'_, str>) {
        self.attributes.push(KeyVal {
            key: name.into_owned(),
            val: value.into_owned(),
        });
    }
}

impl WebSphereMqInfo {
    pub fn merge(&mut self, other: &mut Self) {
        if self.status == L7ResponseStatus::default() {
            self.status = other.status;
        }
        let other_trace_ids = std::mem::take(&mut other.trace_ids);
        self.trace_ids.merge(other_trace_ids);
        swap_if!(self, span_id, is_empty, other);
        swap_if!(self, request_type, is_empty, other);
        swap_if!(self, response_exception, is_empty, other);
        self.captured_response_byte = other.captured_response_byte;
        self.attributes.append(&mut other.attributes);
        if other.is_on_blacklist {
            self.is_on_blacklist = other.is_on_blacklist;
        }
        if other.is_async {
            self.is_async = other.is_async;
        }
        if other.is_reversed {
            self.is_reversed = other.is_reversed;
        }
    }

    // when response_code is overwritten, put it into the attributes.
    fn response_code_to_attribute(&mut self) {
        self.attributes.push(KeyVal {
            key: SYS_RESPONSE_CODE_ATTR.to_string(),
            val: self.response_code.clone(),
        });
    }

    fn set_is_on_blacklist(&mut self, config: &LogParserConfig) {
        if let Some(t) = config.l7_log_blacklist_trie.get(&L7Protocol::WebSphereMq) {
            self.is_on_blacklist = t.request_type.is_on_blacklist(&self.request_type)
        }
    }

    pub fn merge_custom_info(&mut self, custom: CustomInfo) {
        // req rewrite
        if !custom.req.domain.is_empty() {
            self.msg_type = LogMessageType::Request;
            self.request_domain = custom.req.domain;
        }

        if !custom.req.req_type.is_empty() {
            self.msg_type = LogMessageType::Request;
            self.request_type = custom.req.req_type;
        }

        if !custom.req.resource.is_empty() {
            self.msg_type = LogMessageType::Request;
            self.request_resource = custom.req.resource;
        }

        if !custom.req.endpoint.is_empty() {
            self.endpoint = custom.req.endpoint;
        }

        //resp rewrite
        if let Some(code) = custom.resp.code {
            self.msg_type = LogMessageType::Response;
            self.response_code_to_attribute();
            self.response_code = code.to_string();
        }

        if custom.resp.status != L7ResponseStatus::default() {
            self.msg_type = LogMessageType::Response;
            self.status = custom.resp.status;
        }

        if !custom.resp.result.is_empty() {
            self.msg_type = LogMessageType::Response;
            self.response_result = custom.resp.result;
        }

        if !custom.resp.exception.is_empty() {
            self.msg_type = LogMessageType::Response;
            self.response_exception = custom.resp.exception;
        }

        if !custom.resp.req_type.is_empty() {
            self.request_type = custom.resp.req_type;
        }

        if !custom.resp.endpoint.is_empty() {
            self.endpoint = custom.resp.endpoint;
        }

        //trace info rewrite
        self.trace_ids
            .merge_same_priority(PLUGIN_FIELD_PRIORITY, custom.trace.trace_ids);

        if let Some(span_id) = custom.trace.span_id {
            self.span_id = span_id;
        }

        // extend attribute
        if !custom.attributes.is_empty() {
            self.attributes.extend(custom.attributes);
        }
        if let Some(is_async) = custom.is_async {
            self.is_async = is_async;
        }
        if let Some(is_reversed) = custom.is_reversed {
            self.is_reversed = is_reversed;
        }

        if custom.biz_type > 0 {
            self.biz_type = custom.biz_type;
        }
        if let Some(biz_code) = custom.biz_code {
            self.biz_code = biz_code;
        }
        if let Some(biz_scenario) = custom.biz_scenario {
            self.biz_scenario = biz_scenario;
        }
    }

    pub fn merge_parsed_info(&mut self, mut parser: WebSphereMqParser) {
        self.is_async = parser.is_async;
        self.is_reversed = parser.is_reversed;
        self.msg_type = parser.msg_type;
        self.trace_ids
            .merge_field(BASE_FIELD_PRIORITY, std::mem::take(&mut parser.ntfctn_id));
        self.trace_ids.merge_field(
            BASE_FIELD_PRIORITY,
            std::mem::take(&mut parser.orgnl_msg_id),
        );
        self.trace_ids
            .merge_field(BASE_FIELD_PRIORITY, std::mem::take(&mut parser.msg_id));
        if self.msg_type == LogMessageType::Response {
            self.span_id = std::mem::take(&mut parser.mesg_ref_id);
        } else {
            self.span_id = std::mem::take(&mut parser.mesg_id);
        }
        self.request_type = std::mem::take(&mut parser.mesg_type);
        self.request_domain = std::mem::take(&mut parser.mesg_direction);
        self.endpoint = std::mem::take(&mut parser.endpoint);
        self.response_code = std::mem::take(&mut parser.response_code);
        self.status = parser.status;
        self.response_exception = std::mem::take(&mut parser.response_exception);
        self.attributes = std::mem::take(&mut parser.attributes);
        self.biz_type = parser.biz_type;
        self.biz_code = std::mem::take(&mut parser.biz_code);
        self.biz_scenario = std::mem::take(&mut parser.biz_scenario);
    }

    fn get_trace_id(&self) -> Field {
        Field::Str(Cow::Borrowed(&self.trace_ids.highest()))
    }

    fn set_trace_id(&mut self, trace_id: FieldSetter) {
        let (prio, trace_id) = (trace_id.prio(), trace_id.into_inner());
        match trace_id {
            Field::Str(s) => {
                self.trace_ids.merge_field(prio, s.into_owned());
            }
            _ => return,
        }
    }
}

impl From<WebSphereMqInfo> for L7ProtocolSendLog {
    fn from(f: WebSphereMqInfo) -> Self {
        let mut flags = if f.is_tls {
            ApplicationFlags::TLS
        } else {
            ApplicationFlags::NONE
        };
        if f.is_async {
            flags = flags | ApplicationFlags::ASYNC;
        }
        if f.is_reversed {
            flags = flags | ApplicationFlags::REVERSED;
        }
        L7ProtocolSendLog {
            captured_request_byte: f.captured_request_byte,
            captured_response_byte: f.captured_response_byte,
            req: L7Request {
                req_type: f.request_type,
                domain: f.request_domain,
                endpoint: f.endpoint,
                ..Default::default()
            },
            resp: L7Response {
                status: f.status,
                exception: f.response_exception,
                result: f.response_result,
                code: f.response_code.parse::<i32>().ok(),
                ..Default::default()
            },
            trace_info: Some(TraceInfo {
                trace_ids: f.trace_ids.into_strings_top3(),
                span_id: Some(f.span_id),
                ..Default::default()
            }),
            ext_info: Some(ExtendedInfo {
                attributes: Some(f.attributes),
                ..Default::default()
            }),
            flags: flags.bits(),
            biz_code: f.biz_code,
            biz_scenario: f.biz_scenario,
            ..Default::default()
        }
    }
}

impl From<&WebSphereMqInfo> for LogCache {
    fn from(info: &WebSphereMqInfo) -> Self {
        LogCache {
            msg_type: info.msg_type,
            resp_status: info.status,
            on_blacklist: info.is_on_blacklist,
            ..Default::default()
        }
    }
}

#[derive(Default)]
pub struct WebSphereMqLog {
    perf_stats: Option<L7PerfStats>,
    parser: WebSphereMqParser,

    custom_field_store: Store,
}

impl L7ProtocolParserInterface for WebSphereMqLog {
    fn check_payload(&mut self, payload: &[u8], _param: &ParseParam) -> Option<LogMessageType> {
        self.parser.check_payload(payload)
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        let Some(config) = param.parse_config else {
            return Err(Error::NoParseConfig);
        };

        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };

        self.custom_field_store.clear();
        let custom_policies = config
            .l7_log_dynamic
            .get_custom_field_policies(L7ProtocolEnum::L7Protocol(L7Protocol::WebSphereMq), param);

        let mut pos = 0;
        let mut loop_count = 0;
        let mut results: Vec<L7ProtocolInfo> = Vec::with_capacity(3);
        while pos < payload.len() {
            loop_count += 1;
            let parsed_size = self.parser.parse_payload(&payload[pos..], param.direction);
            if parsed_size == 0 {
                break;
            }
            let mut info = WebSphereMqInfo::default();
            set_captured_byte!(info, param);
            info.is_tls = param.is_tls();
            let parser = std::mem::take(&mut self.parser);
            info.merge_parsed_info(parser);

            let wasm_results = self.wasm_hook(param, payload[pos..pos + parsed_size].as_ref());
            if let Some(customs) = wasm_results {
                if customs.len() == 1 {
                    let custom = customs.into_iter().next().unwrap();
                    info.merge_custom_info(custom);
                }
            }
            self.merge_custom_fields(
                custom_policies,
                payload[pos..pos + parsed_size].as_ref(),
                &mut info,
            );

            match info.status {
                L7ResponseStatus::ServerError => {
                    self.perf_stats.as_mut().map(|p| p.inc_resp_err());
                }
                L7ResponseStatus::ClientError => {
                    self.perf_stats.as_mut().map(|p| p.inc_req_err());
                }
                _ => {}
            }
            match info.msg_type {
                LogMessageType::Request => {
                    self.perf_stats.as_mut().map(|p| p.inc_req());
                }
                LogMessageType::Response => {
                    self.perf_stats.as_mut().map(|p| p.inc_resp());
                }
                _ => {}
            }
            info.attributes.push(KeyVal {
                key: "mq_Index".to_string(),
                val: loop_count.to_string(),
            });
            results.push(L7ProtocolInfo::WebSphereMqInfo(info));

            pos += parsed_size;
        }

        if results.is_empty() {
            return Err(Error::L7ProtocolUnknown);
        }

        if results.len() == 1 {
            return Ok(L7ParseResult::Single(results.into_iter().next().unwrap()));
        } else {
            return Ok(L7ParseResult::Multi(results));
        }
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::WebSphereMq
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

impl WebSphereMqLog {
    fn wasm_hook(&mut self, param: &ParseParam, payload: &[u8]) -> Option<Vec<CustomInfo>> {
        let mut vm_ref = param.wasm_vm.borrow_mut();
        let Some(vm) = vm_ref.as_mut() else {
            return None;
        };
        let proto = L7Protocol::WebSphereMq as u8;
        vm.on_parse_payload(payload, param, proto)
    }

    fn merge_custom_fields(
        &mut self,
        policies: Option<PolicySlice>,
        l7_payload: &[u8],
        info: &mut WebSphereMqInfo,
    ) {
        let Some(policies) = policies else {
            return;
        };

        for op in self.custom_field_store.drain_with(policies, &*info) {
            match &op.op {
                Op::SavePayload(key) => {
                    info.attributes.push(KeyVal {
                        key: key.to_string(),
                        val: String::from_utf8_lossy(l7_payload).to_string(),
                    });
                }
                _ => auto_merge_custom_field(op, info),
            }
        }
    }
}
