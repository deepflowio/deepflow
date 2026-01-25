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

use enterprise_utils::l7::{
    custom_policy::{
        custom_field_policy::{
            enums::{Op, PayloadType, Source},
            PolicySlice, Store,
        },
        enums::TrafficDirection,
    },
    mq::web_sphere_mq::WebSphereMqParser,
};
use public::l7_protocol::{L7LogBase, LogMessageType};

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
            pb_adapter::{
                ExtendedInfo, KeyVal, L7ProtocolSendLog, L7Request, L7Response, TraceInfo,
            },
            set_captured_byte, AppProtoHead, L7ResponseStatus, PLUGIN_FIELD_PRIORITY,
        },
    },
    plugin::CustomInfo,
};

#[derive(Serialize, Debug, Default, Clone)]
pub struct WebSphereMqInfo {
    #[serde(flatten)]
    pub base: L7LogBase,
    // from base.msg_type, for set_captured_byte!
    pub msg_type: LogMessageType,

    #[serde(skip)]
    is_tls: bool,

    captured_request_byte: u32,
    captured_response_byte: u32,

    rrt: u64,

    #[serde(skip)]
    is_on_blacklist: bool,
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
            msg_type: self.base.msg_type,
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
        self.base.biz_type
    }

    fn is_reversed(&self) -> bool {
        self.base.is_reversed
    }

    fn get_endpoint(&self) -> Option<String> {
        if self.base.endpoint.is_empty() {
            return None;
        }
        Some(self.base.endpoint.clone())
    }
}

impl WebSphereMqInfo {
    pub fn merge(&mut self, other: &mut Self) {
        self.base.merge(&mut other.base);
        if self.captured_request_byte == 0 {
            self.captured_request_byte = other.captured_request_byte;
        };
        if self.captured_response_byte == 0 {
            self.captured_response_byte = other.captured_response_byte;
        };
    }

    fn set_is_on_blacklist(&mut self, config: &LogParserConfig) {
        if let Some(t) = config.l7_log_blacklist_trie.get(&L7Protocol::WebSphereMq) {
            self.is_on_blacklist = t.request_type.is_on_blacklist(&self.base.request_type)
        }
    }

    pub fn merge_wasm_info(&mut self, custom: CustomInfo) {
        let base = &mut self.base;
        // req rewrite
        if !custom.req.domain.is_empty() {
            base.msg_type = LogMessageType::Request;
            base.request_domain = custom.req.domain;
        }

        if !custom.req.req_type.is_empty() {
            base.msg_type = LogMessageType::Request;
            base.request_type = custom.req.req_type;
        }

        if !custom.req.resource.is_empty() {
            base.msg_type = LogMessageType::Request;
            base.request_resource = custom.req.resource;
        }

        if !custom.req.endpoint.is_empty() {
            base.endpoint = custom.req.endpoint;
        }

        //resp rewrite
        if let Some(code) = custom.resp.code {
            base.msg_type = LogMessageType::Response;
            base.response_code = code.to_string();
        }

        if custom.resp.status != L7ResponseStatus::default() {
            base.msg_type = LogMessageType::Response;
            base.response_status = custom.resp.status;
        }

        if !custom.resp.result.is_empty() {
            base.msg_type = LogMessageType::Response;
            base.response_result = custom.resp.result;
        }

        if !custom.resp.exception.is_empty() {
            base.msg_type = LogMessageType::Response;
            base.response_exception = custom.resp.exception;
        }

        if !custom.resp.req_type.is_empty() {
            base.request_type = custom.resp.req_type;
        }

        if !custom.resp.endpoint.is_empty() {
            base.endpoint = custom.resp.endpoint;
        }

        //trace info rewrite
        for v in custom.trace.trace_ids {
            base.trace_ids.push(PLUGIN_FIELD_PRIORITY, Cow::Owned(v))
        }

        if let Some(span_id) = custom.trace.span_id {
            base.span_id = span_id;
        }

        // extend attribute
        if !custom.attributes.is_empty() {
            base.attributes.extend(custom.attributes);
        }
        if let Some(is_async) = custom.is_async {
            base.is_async = is_async;
        }
        if let Some(is_reversed) = custom.is_reversed {
            base.is_reversed = is_reversed;
        }

        if custom.biz_type > 0 {
            base.biz_type = custom.biz_type;
        }
        if let Some(biz_code) = custom.biz_code {
            base.biz_code = biz_code;
        }
        if let Some(biz_scenario) = custom.biz_scenario {
            base.biz_scenario = biz_scenario;
        }
        if let Some(biz_response_code) = custom.biz_response_code {
            base.biz_response_code = biz_response_code;
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
        if f.base.is_async {
            flags = flags | ApplicationFlags::ASYNC;
        }
        if f.base.is_reversed {
            flags = flags | ApplicationFlags::REVERSED;
        }
        L7ProtocolSendLog {
            captured_request_byte: f.captured_request_byte,
            captured_response_byte: f.captured_response_byte,
            req: L7Request {
                req_type: f.base.request_type,
                domain: f.base.request_domain,
                endpoint: f.base.endpoint,
                ..Default::default()
            },
            resp: L7Response {
                status: f.base.response_status,
                exception: f.base.response_exception,
                result: f.base.response_result,
                code: f.base.response_code.parse::<i32>().ok(),
                ..Default::default()
            },
            trace_info: Some(TraceInfo {
                trace_ids: f.base.trace_ids.into_sorted_vec(),
                span_id: Some(f.base.span_id),
                ..Default::default()
            }),
            ext_info: Some(ExtendedInfo {
                attributes: Some(f.base.attributes),
                ..Default::default()
            }),
            flags: flags.bits(),
            biz_code: f.base.biz_code,
            biz_scenario: f.base.biz_scenario,
            ..Default::default()
        }
    }
}

impl From<&WebSphereMqInfo> for LogCache {
    fn from(info: &WebSphereMqInfo) -> Self {
        LogCache {
            msg_type: info.base.msg_type,
            resp_status: info.base.response_status,
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

        let custom_policies =
            config.get_custom_field_policies(L7Protocol::WebSphereMq.into(), param);
        let mut pos = 0;
        let mut loop_count = 0;
        let mut results: Vec<L7ProtocolInfo> = Vec::with_capacity(Self::INIT_L7_RESULT_CAPACITY);
        while pos < payload.len() {
            loop_count += 1;
            let parsed_size = self.parser.parse_payload(
                &payload[pos..],
                param.direction,
                param.web_sphere_mq_parse_conf.parse_xml_enabled,
            );
            if parsed_size == 0 {
                break;
            }
            let mut info = WebSphereMqInfo::default();
            info.is_tls = param.is_tls();
            info.base.is_async = true;
            info.base = std::mem::take(&mut self.parser.base);
            info.msg_type = info.base.msg_type;
            set_captured_byte!(info, param);

            self.merge_custom_fields(
                custom_policies,
                payload[pos..pos + parsed_size].as_ref(),
                &mut info.base,
            );

            let wasm_results = self.wasm_hook(param, payload[pos..pos + parsed_size].as_ref());
            if let Some(customs) = wasm_results {
                if customs.len() >= 1 {
                    let custom = customs.into_iter().next().unwrap();
                    info.merge_wasm_info(custom);
                }
            }
            match info.base.response_status {
                L7ResponseStatus::ServerError => {
                    self.perf_stats.as_mut().map(|p| p.inc_resp_err());
                }
                L7ResponseStatus::ClientError => {
                    self.perf_stats.as_mut().map(|p| p.inc_req_err());
                }
                _ => {}
            }
            match info.base.msg_type {
                LogMessageType::Request => {
                    self.perf_stats.as_mut().map(|p| p.inc_req());
                }
                LogMessageType::Response => {
                    self.perf_stats.as_mut().map(|p| p.inc_resp());
                }
                _ => {}
            }
            info.base.attributes.push(KeyVal {
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
    pub const INIT_L7_RESULT_CAPACITY: usize = 2;

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
        info: &mut L7LogBase,
    ) {
        let Some(policies) = policies else {
            return;
        };

        self.custom_field_store.clear();
        let direction = if info.msg_type == LogMessageType::Response {
            TrafficDirection::RESPONSE
        } else {
            TrafficDirection::REQUEST
        };
        policies.apply(
            &mut self.custom_field_store,
            info,
            direction,
            Source::Payload(PayloadType::JSON | PayloadType::XML, l7_payload),
        );

        for op in self.custom_field_store.drain_with(policies, &*info) {
            match &op.op {
                Op::SaveHeader(_) => (),
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
