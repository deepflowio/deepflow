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

use serde::Serialize;

use enterprise_utils::l7::mq::web_sphere_mq::WebSphereMqParser;
use public::l7_protocol::LogMessageType;

use crate::plugin::{wasm::WasmData, CustomInfo};
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
            consts::*,
            pb_adapter::{
                ExtendedInfo, KeyVal, L7ProtocolSendLog, L7Request, L7Response, TraceInfo,
            },
            set_captured_byte, swap_if, value_is_default, AppProtoHead, L7ResponseStatus,
            PrioFields, BASE_FIELD_PRIORITY, PLUGIN_FIELD_PRIORITY,
        },
    },
};

#[derive(Serialize, Debug, Default, Clone)]
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
    #[serde(rename = "response_status", skip_serializing_if = "value_is_default")]
    pub status: L7ResponseStatus,
    #[serde(skip_serializing_if = "value_is_default")]
    pub response_code: i32,
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
            val: self.response_code.to_string(),
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
            self.response_code = code;
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
}

const RESPONSE_CODE_OK_SUFFIX: &str = "0000";
impl L7ProtocolParserInterface for WebSphereMqLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> Option<LogMessageType> {
        let has_wasm = param.wasm_vm.borrow().is_some();
        self.parser.check_payload(payload, has_wasm)
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        let has_wasm = param.wasm_vm.borrow().is_some();
        if !self.parser.parse_payload(payload, has_wasm) {
            return Err(Error::L7ProtocolUnknown);
        }
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };

        let mut info = WebSphereMqInfo::default();
        if let Some(request_type) = &self.parser.request_type {
            info.request_type = request_type.to_string();
        }
        if let Some(exception) = &self.parser.exception {
            info.response_exception = exception.to_string();
        }
        if let Some(end_to_end_id) = &self.parser.end_to_end_id {
            info.trace_ids
                .merge_field(BASE_FIELD_PRIORITY, end_to_end_id.to_string());
        }
        info.msg_type = LogMessageType::Request;
        info.status = L7ResponseStatus::Ok;
        if let Some(code) = &self.parser.ret_code {
            info.msg_type = LogMessageType::Response;
            if !code.ends_with(RESPONSE_CODE_OK_SUFFIX) {
                info.status = L7ResponseStatus::ClientError;
            }
        }

        info.is_async = true;
        let has_wasm_result = self.wasm_hook(param, payload, &mut info);
        if has_wasm && !has_wasm_result {
            return Err(Error::L7ProtocolUnknown);
        }

        info.is_tls = param.is_tls();
        set_captured_byte!(info, param);
        if let Some(perf_stats) = self.perf_stats.as_mut() {
            if let Some(stats) = info.perf_stats(param) {
                perf_stats.sequential_merge(&stats);
            }
        }

        Ok(L7ParseResult::Single(L7ProtocolInfo::WebSphereMqInfo(info)))
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
    fn wasm_hook(
        &mut self,
        param: &ParseParam,
        payload: &[u8],
        info: &mut WebSphereMqInfo,
    ) -> bool {
        let mut vm_ref = param.wasm_vm.borrow_mut();
        let Some(vm) = vm_ref.as_mut() else {
            return false;
        };
        let wasm_data = WasmData::new(L7Protocol::WebSphereMq);
        if let Some(custom) = vm.on_custom_message(payload, param, wasm_data) {
            info.merge_custom_info(custom);
            return true;
        }
        false
    }
}
