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

mod consts;
mod hessian2;

use std::mem::replace;

use serde::Serialize;

use crate::{
    common::{
        enums::IpProtocol,
        flow::{L7PerfStats, L7Protocol, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, LogCache, ParseParam},
        meta_packet::EbpfFlags,
    },
    config::handler::{L7LogDynamicConfig, LogParserConfig, TraceType},
    flow_generator::{
        error::{Error, Result},
        protocol_logs::{
            consts::*,
            pb_adapter::{
                ExtendedInfo, KeyVal, L7ProtocolSendLog, L7Request, L7Response, MetricKeyVal,
                TraceInfo,
            },
            set_captured_byte, swap_if, value_is_default, value_is_negative, AppProtoHead,
            L7ResponseStatus, LogMessageType, PrioField,
        },
    },
    plugin::{wasm::WasmData, CustomInfo},
    utils::bytes::{read_u32_be, read_u64_be},
};

use self::consts::*;

#[cfg(feature = "enterprise")]
use enterprise_utils::l7::plugin::custom_field_policy::{set_from_tag, ExtraField};

const TRACE_ID_MAX_LEN: usize = 1024;

const HESSIAN2_SERIALIZATION_ID: u8 = 2;
const JAVA_SERIALIZATION_ID: u8 = 3;
const COMPACTED_JAVA_SERIALIZATION_ID: u8 = 4;
const FASTJSON_SERIALIZATION_ID: u8 = 6;
const NATIVE_JAVA_SERIALIZATION_ID: u8 = 7;
const KRYO_SERIALIZATION_ID: u8 = 8;
const FST_SERIALIZATION_ID: u8 = 9;
const NATIVE_HESSIAN_SERIALIZATION_ID: u8 = 10;
const PROTOSTUFF_SERIALIZATION_ID: u8 = 12;
const AVRO_SERIALIZATION_ID: u8 = 11;
const GSON_SERIALIZATION_ID: u8 = 16;
const PROTOBUF_JSON_SERIALIZATION_ID: u8 = 21;
const PROTOBUF_SERIALIZATION_ID: u8 = 22;
const FASTJSON2_SERIALIZATION_ID: u8 = 23;
const KRYO_SERIALIZATION2_ID: u8 = 25;
const CUSTOM_MESSAGE_PACK_ID: u8 = 31;

// priority: base field < custom policy < plugin
const PLUGIN_FIELD_PRIORITY: u8 = 0;
const CUSTOM_FIELD_POLICY_PRIORITY: u8 = PLUGIN_FIELD_PRIORITY + 1;
const BASE_FIELD_PRIORITY: u8 = CUSTOM_FIELD_POLICY_PRIORITY + 1;

#[derive(Serialize, Debug, Default, Clone)]
pub struct DubboInfo {
    #[serde(skip)]
    msg_type: LogMessageType,
    #[serde(skip)]
    is_tls: bool,

    // header
    #[serde(skip)]
    pub event: u8,
    #[serde(skip)]
    pub serial_id: u8,
    #[serde(skip)]
    pub data_type: u8,
    #[serde(rename = "request_id", skip_serializing_if = "value_is_default")]
    pub request_id: i64,

    // req
    #[serde(rename = "request_length", skip_serializing_if = "value_is_negative")]
    pub req_msg_size: Option<u32>,
    #[serde(rename = "version", skip_serializing_if = "value_is_default")]
    pub dubbo_version: String,
    #[serde(rename = "request_domain", skip_serializing_if = "value_is_default")]
    pub service_name: String,
    #[serde(skip)]
    pub service_version: String,
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub method_name: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub trace_id: PrioField<String>,
    #[serde(skip_serializing_if = "value_is_default")]
    pub span_id: PrioField<String>,
    #[serde(rename = "x_request_id_0", skip_serializing_if = "Option::is_none")]
    pub x_request_id_0: Option<PrioField<String>>,
    #[serde(rename = "http_proxy_client", skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,

    // resp
    #[serde(rename = "response_length", skip_serializing_if = "Option::is_none")]
    pub resp_msg_size: Option<u32>,
    #[serde(rename = "response_status")]
    pub resp_status: L7ResponseStatus,
    #[serde(rename = "response_code", skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i32>,
    #[serde(rename = "x_request_id_1", skip_serializing_if = "Option::is_none")]
    pub x_request_id_1: Option<PrioField<String>>,

    captured_request_byte: u32,
    captured_response_byte: u32,

    rrt: u64,

    // set by wasm plugin
    custom_result: Option<String>,
    custom_exception: Option<String>,

    #[serde(skip)]
    attributes: Vec<KeyVal>,

    #[serde(skip)]
    metrics: Vec<MetricKeyVal>,

    #[serde(skip)]
    is_on_blacklist: bool,
    #[serde(skip)]
    endpoint: Option<String>,
}

impl DubboInfo {
    pub fn generate_endpoint(&self) -> Option<String> {
        if !self.service_name.is_empty() || !self.method_name.is_empty() {
            Some(format!("{}/{}", self.service_name, self.method_name))
        } else {
            None
        }
    }

    pub fn merge(&mut self, other: &mut Self) {
        if other.is_tls {
            self.is_tls = other.is_tls;
        }
        if other.event > 0 {
            self.event = other.event;
        }
        if other.serial_id > 0 {
            self.serial_id = other.serial_id;
        }
        swap_if!(self, req_msg_size, is_none, other);
        swap_if!(self, dubbo_version, is_empty, other);
        swap_if!(self, service_name, is_empty, other);
        swap_if!(self, service_version, is_empty, other);
        swap_if!(self, method_name, is_empty, other);
        swap_if!(self, resp_msg_size, is_none, other);
        if other.resp_status != L7ResponseStatus::default() {
            self.resp_status = other.resp_status;
        }
        swap_if!(self, status_code, is_none, other);
        swap_if!(self, custom_result, is_none, other);
        swap_if!(self, custom_exception, is_none, other);
        swap_if!(self, trace_id, is_default, other);
        swap_if!(self, span_id, is_default, other);
        self.attributes.append(&mut other.attributes);
        if other.captured_request_byte > 0 {
            self.captured_request_byte = other.captured_request_byte;
        }
        if other.captured_response_byte > 0 {
            self.captured_response_byte = other.captured_response_byte;
        }
        if other.is_on_blacklist {
            self.is_on_blacklist = other.is_on_blacklist;
        }
    }

    fn set_trace_id(&mut self, trace_id: String, trace_type: &TraceType) {
        if self.trace_id.prio <= BASE_FIELD_PRIORITY {
            return;
        }
        self.trace_id = match trace_type.decode_trace_id(&trace_id) {
            Some(id) => PrioField::new(BASE_FIELD_PRIORITY, id.to_string()),
            None => PrioField::new(BASE_FIELD_PRIORITY, trace_id),
        }
    }

    fn set_span_id(&mut self, span_id: String, trace_type: &TraceType) {
        if self.span_id.prio <= BASE_FIELD_PRIORITY {
            return;
        }
        self.span_id = match trace_type.decode_span_id(&span_id) {
            Some(id) => PrioField::new(BASE_FIELD_PRIORITY, id.to_string()),
            None => PrioField::new(BASE_FIELD_PRIORITY, span_id),
        }
    }

    pub fn merge_custom_info(&mut self, custom: CustomInfo) {
        // req rewrite
        if !custom.req.domain.is_empty() {
            self.service_name = custom.req.domain;
        }

        if !custom.req.req_type.is_empty() {
            self.method_name = custom.req.req_type;
        }

        //resp rewrite
        if let Some(code) = custom.resp.code {
            self.status_code = Some(code);
        }

        if custom.resp.status != self.resp_status {
            self.resp_status = custom.resp.status;
        }

        if !custom.resp.result.is_empty() {
            self.custom_result = Some(custom.resp.result);
        }

        if !custom.resp.exception.is_empty() {
            self.custom_exception = Some(custom.resp.exception);
        }

        //trace info rewrite
        if let Some(trace_id) = custom.trace.trace_id {
            let prev = replace(
                &mut self.trace_id,
                PrioField::new(PLUGIN_FIELD_PRIORITY, trace_id),
            );
            if !prev.is_default() {
                self.attributes.push(KeyVal {
                    key: APM_TRACE_ID_ATTR.to_string(),
                    val: prev.into_inner(),
                });
            }
        }

        if let Some(span_id) = custom.trace.span_id {
            let prev = replace(
                &mut self.span_id,
                PrioField::new(PLUGIN_FIELD_PRIORITY, span_id),
            );
            if !prev.is_default() {
                self.attributes.push(KeyVal {
                    key: APM_SPAN_ID_ATTR.to_string(),
                    val: prev.into_inner(),
                });
            }
        }

        // extend attribute
        if !custom.attributes.is_empty() {
            self.attributes.extend(custom.attributes);
        }
    }

    fn set_is_on_blacklist(&mut self, config: &LogParserConfig) {
        if let Some(t) = config.l7_log_blacklist_trie.get(&L7Protocol::Dubbo) {
            self.is_on_blacklist = t.request_resource.is_on_blacklist(&self.service_name)
                || t.request_type.is_on_blacklist(&self.method_name)
                || t.request_domain.is_on_blacklist(&self.service_name)
                || self
                    .endpoint
                    .as_ref()
                    .map(|p| t.endpoint.is_on_blacklist(p))
                    .unwrap_or_default();
        }
    }

    #[cfg(feature = "enterprise")]
    fn merge_policy_tags_to_dubbo(
        &mut self,
        tags: &mut std::collections::HashMap<&'static str, String>,
    ) {
        log::debug!("dubbo merge custom policy tags: {:?}", tags);
        if tags.is_empty() {
            return;
        }
        set_from_tag!(self.dubbo_version, tags, ExtraField::VERSION);
        // req
        // request_resource priority greater than request_type, ignore request_type setting
        // set_from_tag!(self.method_name, tags, ExtraField::REQUEST_TYPE);
        set_from_tag!(self.service_name, tags, ExtraField::REQUEST_DOMAIN);
        set_from_tag!(self.method_name, tags, ExtraField::REQUEST_RESOURCE);
        self.endpoint = tags.remove(ExtraField::ENDPOINT);

        if let Some(req_id) = tags.remove(ExtraField::REQUEST_ID) {
            self.request_id = req_id.parse::<i64>().unwrap_or_default();
        }
        if let Some(resp_code) = tags.remove(ExtraField::RESPONSE_CODE) {
            self.status_code = Some(resp_code.parse::<i32>().unwrap_or_default());
        }

        // res
        if let Some(resp_status) = tags.remove(ExtraField::RESPONSE_STATUS) {
            self.resp_status = L7ResponseStatus::from(resp_status.as_str());
        }
        self.custom_exception = tags.remove(ExtraField::RESPONSE_EXCEPTION);
        self.custom_result = tags.remove(ExtraField::RESPONSE_RESULT);

        // trace info
        if CUSTOM_FIELD_POLICY_PRIORITY < self.trace_id.prio {
            if let Some(trace_id) = tags.remove(ExtraField::TRACE_ID) {
                let prev = replace(
                    &mut self.trace_id,
                    PrioField::new(CUSTOM_FIELD_POLICY_PRIORITY, trace_id),
                );
                if !prev.is_default() {
                    self.attributes.push(KeyVal {
                        key: APM_TRACE_ID_ATTR.to_string(),
                        val: prev.into_inner(),
                    });
                }
            }
        }
        if CUSTOM_FIELD_POLICY_PRIORITY < self.span_id.prio {
            if let Some(span_id) = tags.remove(ExtraField::SPAN_ID) {
                let prev = replace(
                    &mut self.span_id,
                    PrioField::new(CUSTOM_FIELD_POLICY_PRIORITY, span_id),
                );
                if !prev.is_default() {
                    self.attributes.push(KeyVal {
                        key: APM_SPAN_ID_ATTR.to_string(),
                        val: prev.into_inner(),
                    });
                }
            }
        }
        self.client_ip = tags.remove(ExtraField::HTTP_PROXY_CLIENT);

        let x_req_id = match self.msg_type {
            LogMessageType::Request => &mut self.x_request_id_0,
            LogMessageType::Response => &mut self.x_request_id_1,
            _ => return,
        };
        let prio_check = match x_req_id.as_ref() {
            Some(p) => CUSTOM_FIELD_POLICY_PRIORITY < p.prio,
            _ => true,
        };
        if prio_check {
            if let Some(x_request_id) = tags.remove(ExtraField::X_REQUEST_ID) {
                *x_req_id = Some(PrioField::new(CUSTOM_FIELD_POLICY_PRIORITY, x_request_id));
            }
        }
    }
}

impl L7ProtocolInfoInterface for DubboInfo {
    fn session_id(&self) -> Option<u32> {
        Some(self.request_id as u32)
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::DubboInfo(other) = other {
            self.merge(other);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::Dubbo,
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn is_tls(&self) -> bool {
        self.is_tls
    }

    fn get_endpoint(&self) -> Option<String> {
        self.endpoint.clone()
    }

    fn get_request_domain(&self) -> String {
        self.service_name.clone()
    }

    fn get_request_resource_length(&self) -> usize {
        self.method_name.len()
    }

    fn is_on_blacklist(&self) -> bool {
        self.is_on_blacklist
    }
}

impl From<DubboInfo> for L7ProtocolSendLog {
    fn from(f: DubboInfo) -> Self {
        let serial_id_attr = KeyVal {
            key: "serialization_id".into(),
            // reference https://github.com/apache/dubbo/blob/3.2/dubbo-serialization/dubbo-serialization-api/src/main/java/org/apache/dubbo/common/serialize/Constants.java
            val: match f.serial_id {
                HESSIAN2_SERIALIZATION_ID => "HESSIAN2".to_string(),
                JAVA_SERIALIZATION_ID => "JAVA".to_string(),
                COMPACTED_JAVA_SERIALIZATION_ID => "COMPACTED_JAVA".to_string(),
                FASTJSON_SERIALIZATION_ID => "FASTJSON".to_string(),
                NATIVE_JAVA_SERIALIZATION_ID => "NATIVE_JAVA".to_string(),
                KRYO_SERIALIZATION_ID => "KRYO".to_string(),
                FST_SERIALIZATION_ID => "FST".to_string(),
                NATIVE_HESSIAN_SERIALIZATION_ID => "NATIVE_HESSIAN".to_string(),
                PROTOSTUFF_SERIALIZATION_ID => "PROTOSTUFF".to_string(),
                AVRO_SERIALIZATION_ID => "AVRO".to_string(),
                GSON_SERIALIZATION_ID => "GSON".to_string(),
                PROTOBUF_JSON_SERIALIZATION_ID => "PROTOBUF_JSON".to_string(),
                PROTOBUF_SERIALIZATION_ID => "PROTOBUF".to_string(),
                FASTJSON2_SERIALIZATION_ID => "FASTJSON2".to_string(),
                KRYO_SERIALIZATION2_ID => "KRYO_".to_string(),
                CUSTOM_MESSAGE_PACK_ID => "CUSTO".to_string(),
                _ => f.serial_id.to_string(),
            },
        };
        let mut attrs = vec![serial_id_attr];
        if f.event != 0 {
            attrs.push(KeyVal {
                key: "event".into(),
                val: f.event.to_string(),
            });
        }
        attrs.extend(f.attributes);
        let flags = if f.is_tls {
            EbpfFlags::TLS.bits()
        } else {
            EbpfFlags::NONE.bits()
        };
        L7ProtocolSendLog {
            captured_request_byte: f.captured_request_byte,
            captured_response_byte: f.captured_response_byte,
            req_len: f.req_msg_size,
            resp_len: f.resp_msg_size,
            version: Some(f.dubbo_version),
            req: L7Request {
                resource: f.service_name.clone(),
                req_type: f.method_name.clone(),
                endpoint: f.endpoint.unwrap_or_default(),
                domain: f.service_name.clone(),
            },
            resp: L7Response {
                status: f.resp_status,
                code: f.status_code,
                exception: f.custom_exception.unwrap_or_default(),
                result: f.custom_result.unwrap_or_default(),
            },
            trace_info: Some(TraceInfo {
                trace_id: Some(f.trace_id.into_inner()),
                span_id: Some(f.span_id.into_inner()),
                ..Default::default()
            }),
            ext_info: Some(ExtendedInfo {
                rpc_service: Some(f.service_name),
                request_id: Some(f.request_id as u32),
                x_request_id_0: match f.x_request_id_0 {
                    Some(id) => Some(id.into_inner()),
                    None => None,
                },
                x_request_id_1: match f.x_request_id_1 {
                    Some(id) => Some(id.into_inner()),
                    None => None,
                },
                client_ip: f.client_ip.clone(),
                attributes: Some(attrs),
                metrics: Some(f.metrics),
                ..Default::default()
            }),
            flags,
            ..Default::default()
        }
    }
}

impl From<&DubboInfo> for LogCache {
    fn from(info: &DubboInfo) -> Self {
        LogCache {
            msg_type: info.msg_type,
            resp_status: info.resp_status,
            on_blacklist: info.is_on_blacklist,
            endpoint: info.get_endpoint(),
            ..Default::default()
        }
    }
}

#[derive(Default)]
pub struct DubboLog {
    perf_stats: Option<L7PerfStats>,
}

impl L7ProtocolParserInterface for DubboLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol() {
            return false;
        }
        if param.l4_protocol != IpProtocol::TCP {
            return false;
        }

        let mut header = DubboHeader::default();
        let ret = header.parse_headers(payload);
        if ret.is_err() {
            return false;
        }

        header.check()
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        let Some(config) = param.parse_config else {
            return Err(Error::NoParseConfig);
        };
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };
        let mut info = DubboInfo::default();
        self.parse(&config.l7_log_dynamic, payload, &mut info, param)?;
        info.is_tls = param.is_tls();
        set_captured_byte!(info, param);
        info.endpoint = info.generate_endpoint();
        self.wasm_hook(param, payload, &mut info);
        if let Some(config) = param.parse_config {
            info.set_is_on_blacklist(config);
        }
        if let Some(perf_stats) = self.perf_stats.as_mut() {
            if info.msg_type == LogMessageType::Response {
                if let Some(endpoint) = info.load_endpoint_from_cache(param) {
                    info.endpoint = Some(endpoint.to_string());
                }
            }
            if let Some(stats) = info.perf_stats(param) {
                info.rrt = stats.rrt_sum;
                perf_stats.sequential_merge(&stats);
            }
        }
        if param.parse_log {
            Ok(L7ParseResult::Single(L7ProtocolInfo::DubboInfo(info)))
        } else {
            Ok(L7ParseResult::None)
        }
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Dubbo
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

mod kryo {
    use nom::FindSubstring;

    use super::DubboInfo;
    use crate::config::handler::{L7LogDynamicConfig, TraceType};

    fn decode_ascii_string(payload: &[u8], start: usize) -> Option<(String, usize)> {
        if start >= payload.len() {
            return None;
        }

        let mut s = String::new();
        for i in start..payload[start..].len() {
            s.push((payload[i] & 0x7f) as char);
            if payload[i] >> 7 == 1 {
                return Some((s, i + 1 - start));
            }
        }
        return None;
    }

    fn lookup_str(payload: &[u8], trace_type: &TraceType) -> Option<String> {
        let tag = match trace_type {
            TraceType::Sw3 | TraceType::Sw8 | TraceType::CloudWise | TraceType::Customize(_) => {
                trace_type.as_str()
            }
            _ => return None,
        };
        if tag.len() <= 1 {
            return None;
        }

        let mut start = 0;
        let flag = &tag[..tag.len() - 1];
        while start < payload.len() {
            let Some(index) = (&payload[start..]).find_substring(flag) else {
                break;
            };

            let Some(s) = decode_ascii_string(payload, start + index) else {
                start += index + tag.len();
                continue;
            };
            if s.0 != tag {
                start += index + s.1;
                continue;
            }

            if let Some(s) = decode_ascii_string(payload, start + index + tag.len()) {
                return Some(s.0);
            }

            start += index + tag.len();
        }
        return None;
    }

    fn decode_trace_id(payload: &[u8], trace_type: &TraceType, info: &mut DubboInfo) {
        if let Some(trace_id) = lookup_str(payload, trace_type) {
            info.set_trace_id(trace_id, trace_type);
        }
    }

    fn decode_span_id(payload: &[u8], trace_type: &TraceType, info: &mut DubboInfo) {
        if let Some(span_id) = lookup_str(payload, trace_type) {
            info.set_span_id(span_id, trace_type);
        }
    }

    pub fn get_req_body_info(config: &L7LogDynamicConfig, payload: &[u8], info: &mut DubboInfo) {
        let mut offset = 0;
        let Some(version) = decode_ascii_string(payload, offset) else {
            return;
        };
        info.dubbo_version = version.0;
        offset += version.1;

        let Some(service_name) = decode_ascii_string(payload, offset) else {
            return;
        };
        info.service_name = service_name.0;
        offset += service_name.1;

        let Some(service_version) = decode_ascii_string(payload, offset) else {
            return;
        };
        info.service_version = service_version.0;
        offset += service_version.1;

        let Some(method_name) = decode_ascii_string(payload, offset) else {
            return;
        };
        info.method_name = method_name.0;
        offset += method_name.1;

        if config.trace_types.is_empty() || offset >= payload.len() {
            return;
        }

        for trace_type in config.trace_types.iter() {
            if trace_type.as_str().len() > u8::MAX as usize {
                continue;
            }

            decode_trace_id(&payload[offset..], &trace_type, info);
            if info.trace_id.field.len() != 0 {
                break;
            }
        }
        for span_type in config.span_types.iter() {
            if span_type.as_str().len() > u8::MAX as usize {
                continue;
            }

            decode_span_id(&payload[offset..], &span_type, info);
            if info.span_id.field.len() != 0 {
                break;
            }
        }
    }
}

mod fastjson2 {
    use nom::FindSubstring;

    use super::DubboInfo;
    use crate::config::handler::{L7LogDynamicConfig, TraceType};
    use crate::utils::bytes::read_u32_be;

    const ASCII_HEADER_SIZE: usize = 4;

    const BC_STR_ASCII_HEADER_SIZE: usize = 1;
    const BC_STR_ASCII: i8 = 121; // 0x79

    const BC_INT32_MAX_SIZE: usize = 5;
    const BC_INT32_NUM_MIN: i8 = -16; // 0xf0
    const BC_INT32_NUM_MAX: i8 = 47; // 0x2f

    const BC_INT32_BYTE_MIN: i8 = 48; // 0x30
    const BC_INT32_BYTE_ZERO: i8 = 56; // 0x38
    const BC_INT32_BYTE_MAX: i8 = 63; // 0x3f

    const BC_INT32_SHORT_MIN: i8 = 64; // 0x40
    const BC_INT32_SHORT_ZERO: i8 = 68; // 0x44
    const BC_INT32_SHORT_MAX: i8 = 71; // 0x47

    const BC_INT32: i8 = 72; // 0x48
    const BC_INT32_MAX: u32 = 1024 * 1024 * 256;

    fn decode_int32(payload: &[u8], start: usize) -> Option<(u32, usize)> {
        if start + BC_INT32_MAX_SIZE >= payload.len() {
            return None;
        }

        let payload = &payload[start..];
        let n = payload[0] as i8;
        let mut offset = 1;
        if (BC_INT32_NUM_MIN..=BC_INT32_NUM_MAX).contains(&n) {
            return Some((n as u32, offset));
        }

        if (BC_INT32_BYTE_MIN..=BC_INT32_BYTE_MAX).contains(&n) {
            let m = payload[offset] as u32 & 0xFF;
            offset += 1;
            return Some(((((n - BC_INT32_BYTE_ZERO) as u32) << 8) + m, offset));
        }

        if (BC_INT32_SHORT_MIN..=BC_INT32_SHORT_MAX).contains(&n) {
            let first = (((n - BC_INT32_SHORT_ZERO) as i32) << 16) as u32;
            let second = ((payload[offset] & 0xFF) as u32) << 8;
            let third = (payload[offset + 1] & 0xFF) as u32;
            offset += 2;
            return Some((first + second + third, offset));
        }

        if n == BC_INT32 {
            let length = read_u32_be(&payload[offset..]);
            offset += 4;
            if length > BC_INT32_MAX {
                return None;
            }
            return Some((length, offset));
        }

        None
    }

    fn decode_object_ascii_string(payload: &[u8]) -> Option<(String, usize)> {
        if BC_STR_ASCII_HEADER_SIZE >= payload.len() {
            return None;
        }
        if payload[0] != BC_STR_ASCII as u8 {
            return None;
        }

        let mut offset = BC_STR_ASCII_HEADER_SIZE;
        let Some((length, n)) = decode_int32(payload, offset) else {
            return None;
        };

        offset += n;

        let payload = &payload[offset..];
        let length = ((length + 1) as usize).min(payload.len());

        offset += length;

        let mut s = String::new();
        for i in 0..length {
            s.push(payload[i] as char);
        }

        Some((s, offset))
    }

    fn decode_ascii_string(payload: &[u8], start: usize) -> Option<(String, usize)> {
        if start + ASCII_HEADER_SIZE >= payload.len() {
            return None;
        }
        let length = read_u32_be(&payload[start..]) as usize;
        let start = start + ASCII_HEADER_SIZE;
        if start + length >= payload.len() {
            return None;
        }
        let mut s = String::new();
        for i in start..(length + start) {
            s.push(payload[i] as char);
        }
        return Some((s, length + ASCII_HEADER_SIZE));
    }

    fn lookup_str(payload: &[u8], trace_type: &TraceType) -> Option<String> {
        let tag = match trace_type {
            TraceType::Sw3 | TraceType::Sw8 | TraceType::CloudWise | TraceType::Customize(_) => {
                trace_type.as_str()
            }
            _ => return None,
        };
        if tag.len() <= 1 {
            return None;
        }

        let mut start = 0;
        while start < payload.len() {
            let Some(index) = (&payload[start..]).find_substring(tag) else {
                break;
            };

            start += index + tag.len();
            if start >= payload.len() {
                break;
            }

            if let Some(s) = decode_object_ascii_string(&payload[start..]) {
                return Some(s.0);
            }
        }
        return None;
    }

    fn decode_trace_id(payload: &[u8], trace_type: &TraceType, info: &mut DubboInfo) {
        if let Some(trace_id) = lookup_str(payload, trace_type) {
            info.set_trace_id(trace_id, trace_type);
        }
    }

    fn decode_span_id(payload: &[u8], trace_type: &TraceType, info: &mut DubboInfo) {
        if let Some(span_id) = lookup_str(payload, trace_type) {
            info.set_span_id(span_id, trace_type);
        }
    }

    pub fn get_req_body_info(config: &L7LogDynamicConfig, payload: &[u8], info: &mut DubboInfo) {
        let mut offset = 0;
        let Some(version) = decode_ascii_string(payload, offset) else {
            return;
        };
        info.dubbo_version = version.0;
        offset += version.1;

        let Some(service_name) = decode_ascii_string(payload, offset) else {
            return;
        };
        info.service_name = service_name.0;
        offset += service_name.1;

        let Some(service_version) = decode_ascii_string(payload, offset) else {
            return;
        };
        info.service_version = service_version.0;
        offset += service_version.1;

        let Some(method_name) = decode_ascii_string(payload, offset) else {
            return;
        };
        info.method_name = method_name.0;
        offset += method_name.1;

        if config.trace_types.is_empty() || offset >= payload.len() {
            return;
        }

        for trace_type in config.trace_types.iter() {
            if trace_type.as_str().len() > u8::MAX as usize {
                continue;
            }

            decode_trace_id(&payload[offset..], &trace_type, info);
            if info.trace_id.field.len() != 0 {
                break;
            }
        }
        for span_type in config.span_types.iter() {
            if span_type.as_str().len() > u8::MAX as usize {
                continue;
            }

            decode_span_id(&payload[offset..], &span_type, info);
            if info.span_id.field.len() != 0 {
                break;
            }
        }
    }
}

impl DubboLog {
    fn decode_body(
        config: &L7LogDynamicConfig,
        payload: &[u8],
        info: &mut DubboInfo,
        #[cfg(feature = "enterprise")] direction: PacketDirection,
        #[cfg(feature = "enterprise")] port: u16,
    ) {
        match info.serial_id {
            HESSIAN2_SERIALIZATION_ID => hessian2::get_req_body_info(
                config,
                payload,
                info,
                #[cfg(feature = "enterprise")]
                direction,
                #[cfg(feature = "enterprise")]
                port,
            ),
            KRYO_SERIALIZATION2_ID => kryo::get_req_body_info(config, payload, info),
            KRYO_SERIALIZATION_ID => kryo::get_req_body_info(config, payload, info),
            FASTJSON2_SERIALIZATION_ID => fastjson2::get_req_body_info(config, payload, info),
            _ => {}
        }
    }

    fn request(
        &mut self,
        config: &L7LogDynamicConfig,
        payload: &[u8],
        dubbo_header: &DubboHeader,
        info: &mut DubboInfo,
        #[cfg(feature = "enterprise")] direction: PacketDirection,
        #[cfg(feature = "enterprise")] port: u16,
    ) {
        info.msg_type = LogMessageType::Request;
        info.event = dubbo_header.event;
        info.data_type = dubbo_header.data_type;
        info.req_msg_size = Some(dubbo_header.data_length as u32);
        info.serial_id = dubbo_header.serial_id;
        info.request_id = dubbo_header.request_id;

        Self::decode_body(
            config,
            &payload[DUBBO_HEADER_LEN..],
            info,
            #[cfg(feature = "enterprise")]
            direction,
            #[cfg(feature = "enterprise")]
            port,
        );
    }

    fn set_status(&mut self, status_code: u8, info: &mut DubboInfo) {
        info.resp_status = match status_code {
            20 => L7ResponseStatus::Ok,
            30 | 40 | 90 => {
                self.perf_stats.as_mut().map(|p| p.inc_req_err());
                L7ResponseStatus::ClientError
            }
            31 | 50 | 60 | 70 | 80 | 100 => {
                self.perf_stats.as_mut().map(|p| p.inc_resp_err());
                L7ResponseStatus::ServerError
            }
            _ => L7ResponseStatus::Ok,
        }
    }

    fn response(&mut self, dubbo_header: &DubboHeader, info: &mut DubboInfo) {
        info.msg_type = LogMessageType::Response;
        info.event = dubbo_header.event;
        info.data_type = dubbo_header.data_type;
        info.resp_msg_size = Some(dubbo_header.data_length as u32);
        info.serial_id = dubbo_header.serial_id;
        info.request_id = dubbo_header.request_id;
        info.status_code = Some(dubbo_header.status_code as i32);
        self.set_status(dubbo_header.status_code, info);
    }

    fn parse(
        &mut self,
        config: &L7LogDynamicConfig,
        payload: &[u8],
        info: &mut DubboInfo,
        param: &ParseParam,
    ) -> Result<()> {
        let direction = param.direction;

        let mut dubbo_header = DubboHeader::default();
        dubbo_header.parse_headers(payload)?;

        match direction {
            PacketDirection::ClientToServer => {
                self.request(
                    &config,
                    payload,
                    &dubbo_header,
                    info,
                    #[cfg(feature = "enterprise")]
                    param.direction,
                    #[cfg(feature = "enterprise")]
                    param.port_dst,
                );
            }
            PacketDirection::ServerToClient => {
                self.response(&dubbo_header, info);
            }
        }
        Ok(())
    }

    fn wasm_hook(&mut self, param: &ParseParam, payload: &[u8], info: &mut DubboInfo) {
        let mut vm_ref = param.wasm_vm.borrow_mut();
        let Some(vm) = vm_ref.as_mut() else {
            return;
        };
        let wasm_data = WasmData::new(L7Protocol::Dubbo);
        if let Some(custom) = vm.on_custom_message(payload, param, wasm_data) {
            info.merge_custom_info(custom);
        }
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct DubboHeader {
    // Dubbo Header
    pub event: u8,
    pub serial_id: u8,
    pub data_type: u8,
    pub status_code: u8,
    pub data_length: i32,
    pub request_id: i64,
}

impl DubboHeader {
    // Dubbo协议https://dubbo.apache.org/zh/blog/2018/10/05/dubbo-%E5%8D%8F%E8%AE%AE%E8%AF%A6%E8%A7%A3/#dubbo-%E5%8D%8F%E8%AE%AE
    // Dubbo协议帧
    // +-----------------------------------------------+
    // |       header           |       body           |
    // +---------------+---------------+---------------+
    // header格式
    // +------------------------------------------------------------------------------------------------------------+
    // | magic (16) | request and serialization flag (8) | response status (8) | request id (64) | body length (32) |
    // +------------------------------------------------------------------------------------------------------------+
    pub fn parse_headers(&mut self, payload: &[u8]) -> Result<()> {
        if payload.len() < DUBBO_HEADER_LEN {
            return Err(Error::DubboHeaderParseFailed);
        }
        if payload[0] != DUBBO_MAGIC_HIGH || payload[1] != DUBBO_MAGIC_LOW {
            return Err(Error::DubboHeaderParseFailed);
        }

        self.event = (payload[2] & 0x20) >> 5;
        self.serial_id = payload[2] & 0x1f;
        self.data_type = payload[2] & 0x80;
        self.status_code = payload[3];
        self.request_id = read_u64_be(&payload[4..]) as i64;
        self.data_length = read_u32_be(&payload[12..]) as i32;
        Ok(())
    }

    pub fn check(&self) -> bool {
        // 不通过响应识别Dubbo
        if self.data_type == 0 {
            return false;
        }
        // 请求时状态码一定是0
        if self.status_code != 0 {
            return false;
        }

        // TODO：增加检查serial_id字段
        return true;
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::path::Path;
    use std::time::Duration;
    use std::{fs, rc::Rc};

    use super::*;

    use crate::common::l7_protocol_log::L7PerfCache;
    use crate::config::{
        handler::{LogParserConfig, TraceType},
        ExtraLogFields,
    };
    use crate::flow_generator::L7_RRT_CACHE_CAPACITY;
    use crate::{
        common::{flow::PacketDirection, MetaPacket},
        utils::test::Capture,
    };

    cfg_if::cfg_if! {
    if #[cfg(feature = "enterprise")] {
            use std::collections::HashMap;

            use enterprise_utils::l7::plugin::custom_field_policy::{ExtraCustomFieldPolicy, ExtraField};
            use crate::flow_generator::protocol_logs::LogMessageType;
            use crate::common::flow::L7ProtocolEnum;
            use crate::config::config::ExtraCustomFieldPolicyMap;
            use public::segment_map::SegmentBuilder;
            use public::enums::{FieldType, MatchType};
        }
    }

    const FILE_DIR: &str = "resources/test/flow_generator/dubbo";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name));
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let mut packets = capture.collect::<Vec<_>>();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
        for packet in packets.iter_mut() {
            packet.lookup_key.direction = if packet.lookup_key.dst_port == first_dst_port {
                PacketDirection::ClientToServer
            } else {
                PacketDirection::ServerToClient
            };
            let payload = match packet.get_l4_payload() {
                Some(p) => p,
                None => continue,
            };

            let config = LogParserConfig {
                l7_log_dynamic: L7LogDynamicConfig::new(
                    vec![],
                    vec![],
                    vec![
                        TraceType::Customize("EagleEye-TraceID".to_string()),
                        TraceType::Sw8,
                    ],
                    vec![
                        TraceType::Customize("EagleEye-SpanID".to_string()),
                        TraceType::Sw8,
                    ],
                    ExtraLogFields::default(),
                    false,
                    #[cfg(feature = "enterprise")]
                    HashMap::new(),
                ),
                ..Default::default()
            };
            let mut dubbo = DubboLog::default();
            let param = &mut ParseParam::new(
                packet as &MetaPacket,
                log_cache.clone(),
                Default::default(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Default::default(),
                true,
                true,
            );
            param.set_captured_byte(payload.len());
            param.set_log_parser_config(&config);
            let is_dubbo = dubbo.check_payload(payload, param);

            let i = dubbo.parse_payload(payload, param);
            let info = if let Ok(info) = i {
                match info.unwrap_single() {
                    L7ProtocolInfo::DubboInfo(d) => d,
                    _ => unreachable!(),
                }
            } else {
                DubboInfo::default()
            };
            output.push_str(&format!("{:?} is_dubbo: {}\n", info, is_dubbo));
        }
        output
    }

    #[test]
    fn test_fastjson2() {
        let packet = [
            // header
            0x00, 0x16, 0x3e, 0x35, 0x2c, 0x05, 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0x08, 0x00,
            0x45, 0x00, 0x0b, 0x48, 0x1e, 0xfe, 0x40, 0x00, 0x40, 0x06, 0x51, 0x1e, 0x64, 0x76,
            0x3a, 0x08, 0x0a, 0x01, 0x17, 0x15, 0x01, 0xbb, 0x4f, 0x60, 0x9c, 0x06, 0xdf, 0x01,
            0x71, 0xcc, 0xb3, 0x91, 0x50, 0x10, 0x00, 0x53, 0xca, 0xce, 0x00, 0x00,
            // dubbo
            0xdau8, 0xbb, 0xd7, 0x00, 0xca, 0x83, 0xd7, 0x74, 0x26, 0xdb, 0x38, 0xee, 0x00, 0x00,
            0x02, 0xc7, 0x00, 0x00, 0x00, 0x06, 0x4e, 0x32, 0x2e, 0x30, 0x2e, 0x32, 0x00, 0x00,
            0x00, 0x2d, 0x75, 0x63, 0x6f, 0x6d, 0x2e, 0x62, 0x79, 0x64, 0x2e, 0x63, 0x6c, 0x6f,
            0x75, 0x64, 0x2e, 0x70, 0x75, 0x62, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x63, 0x65, 0x6e,
            0x74, 0x65, 0x72, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x53, 0x65,
            0x72, 0x76, 0x69, 0x63, 0x65, 0x00, 0x00, 0x00, 0x06, 0x4e, 0x30, 0x2e, 0x30, 0x2e,
            0x30, 0x00, 0x00, 0x00, 0x14, 0x5c, 0x71, 0x75, 0x65, 0x72, 0x79, 0x55, 0x73, 0x65,
            0x72, 0x49, 0x6e, 0x66, 0x6f, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x00, 0x00, 0x00,
            0x11, 0x59, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4c,
            0x6f, 0x6e, 0x67, 0x3b, 0x00, 0x00, 0x00, 0x09, 0xbe, 0x01, 0x7d, 0x8c, 0x70, 0x2b,
            0x02, 0x20, 0x00, 0x00, 0x00, 0x02, 0x44, 0xa6, 0x4d, 0x70, 0x61, 0x74, 0x68, 0x75,
            0x63, 0x6f, 0x6d, 0x2e, 0x62, 0x79, 0x64, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e,
            0x70, 0x75, 0x62, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x63, 0x65, 0x6e, 0x74, 0x65, 0x72,
            0x2e, 0x61, 0x70, 0x69, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x53, 0x65, 0x72, 0x76, 0x69,
            0x63, 0x65, 0x5b, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x2e, 0x61, 0x70, 0x70, 0x6c,
            0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x69, 0x70, 0x75, 0x62, 0x2d, 0x73, 0x65,
            0x72, 0x76, 0x65, 0x72, 0x32, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2d, 0x70, 0x72,
            0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x2d, 0x64, 0x75, 0x62, 0x62, 0x6f, 0x59, 0x64,
            0x75, 0x62, 0x62, 0x6f, 0x41, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
            0x6e, 0x69, 0x70, 0x75, 0x62, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x32, 0x73,
            0x65, 0x72, 0x76, 0x65, 0x72, 0x2d, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72,
            0x2d, 0x64, 0x75, 0x62, 0x62, 0x6f, 0x4e, 0x73, 0x77, 0x38, 0x2d, 0x78, 0x4c, 0x30,
            0x2d, 0x20, 0x4c, 0x73, 0x77, 0x38, 0x79, 0x39, 0x35, 0x31, 0x2d, 0x4d, 0x54, 0x67,
            0x35, 0x5a, 0x44, 0x4d, 0x34, 0x4d, 0x7a, 0x55, 0x30, 0x5a, 0x6d, 0x4d, 0x79, 0x4e,
            0x44, 0x42, 0x6c, 0x59, 0x54, 0x67, 0x77, 0x4e, 0x47, 0x4d, 0x78, 0x4e, 0x54, 0x4d,
            0x35, 0x4e, 0x57, 0x49, 0x79, 0x5a, 0x44, 0x56, 0x69, 0x59, 0x57, 0x59, 0x75, 0x4d,
            0x54, 0x63, 0x31, 0x4c, 0x6a, 0x45, 0x33, 0x4d, 0x7a, 0x6b, 0x30, 0x4f, 0x54, 0x67,
            0x7a, 0x4e, 0x54, 0x63, 0x30, 0x4e, 0x7a, 0x63, 0x33, 0x4d, 0x7a, 0x55, 0x7a, 0x2d,
            0x4d, 0x54, 0x67, 0x35, 0x5a, 0x44, 0x4d, 0x34, 0x4d, 0x7a, 0x55, 0x30, 0x5a, 0x6d,
            0x4d, 0x79, 0x4e, 0x44, 0x42, 0x6c, 0x59, 0x54, 0x67, 0x77, 0x4e, 0x47, 0x4d, 0x78,
            0x4e, 0x54, 0x4d, 0x35, 0x4e, 0x57, 0x49, 0x79, 0x5a, 0x44, 0x56, 0x69, 0x59, 0x57,
            0x59, 0x75, 0x4d, 0x6a, 0x4d, 0x34, 0x4c, 0x6a, 0x45, 0x33, 0x4d, 0x7a, 0x6d, 0x30,
            0x4f, 0x54, 0x67, 0x7a, 0x4e, 0x54, 0x63, 0x30, 0x4e, 0x7a, 0x63, 0x32, 0x4e, 0x7a,
            0x63, 0x79, 0x2d, 0x32, 0x2d, 0x55, 0x31, 0x56, 0x51, 0x52, 0x56, 0x49, 0x36, 0x4f,
            0x6e, 0x42,
        ];
        let mut meta_packet = MetaPacket::empty();
        let _ = meta_packet.update(
            &packet[..],
            true,
            true,
            Duration::from_secs(10),
            packet.len(),
        );
        meta_packet.lookup_key.direction = PacketDirection::ClientToServer;
        let Some(payload) = meta_packet.get_l4_payload() else {
            return;
        };

        let config = LogParserConfig {
            l7_log_dynamic: L7LogDynamicConfig::new(
                vec![],
                vec![],
                vec![TraceType::Sw8],
                vec![TraceType::Sw8],
                ExtraLogFields::default(),
                false,
                #[cfg(feature = "enterprise")]
                HashMap::new(),
            ),
            ..Default::default()
        };
        let mut dubbo = DubboLog::default();
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let param = &mut ParseParam::new(
            &meta_packet,
            log_cache.clone(),
            Default::default(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Default::default(),
            true,
            true,
        );
        param.set_captured_byte(payload.len());
        param.set_log_parser_config(&config);
        let is_dubbo = dubbo.check_payload(payload, param);

        let i = dubbo.parse_payload(payload, param);
        let info = if let Ok(info) = i {
            match info.unwrap_single() {
                L7ProtocolInfo::DubboInfo(d) => d,
                _ => unreachable!(),
            }
        } else {
            DubboInfo::default()
        };

        assert_eq!(is_dubbo, true);
        assert_eq!(
            info.trace_id.field,
            "189d38354fc240ea804c15395b2d5baf.175.17394983574777353"
        );
    }

    #[test]
    fn test_cloud_wise() {
        let packet = [
            // header
            0x00u8, 0x16, 0x3e, 0x35, 0x2c, 0x05, 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0x08, 0x00,
            0x45, 0x00, 0x0b, 0x48, 0x1e, 0xfe, 0x40, 0x00, 0x40, 0x06, 0x51, 0x1e, 0x64, 0x76,
            0x3a, 0x08, 0x0a, 0x01, 0x17, 0x15, 0x01, 0xbb, 0x4f, 0x60, 0x9c, 0x06, 0xdf, 0x01,
            0x71, 0xcc, 0xb3, 0x91, 0x50, 0x10, 0x00, 0x53, 0xca, 0xce, 0x00, 0x00,
            // dubbo
            0xda, 0xbb, 0xc2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x25, 0x10, 0x00, 0x00,
            0x03, 0xea, 0x05, 0x32, 0x2e, 0x30, 0x2e, 0x32, 0x30, 0x3d, 0x63, 0x6f, 0x6d, 0x2e,
            0x62, 0x79, 0x64, 0x2e, 0x64, 0x69, 0x6c, 0x69, 0x6e, 0x6b, 0x2e, 0x64, 0x62, 0x2e,
            0x76, 0x65, 0x68, 0x69, 0x63, 0x6c, 0x65, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65,
            0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x41, 0x75, 0x74, 0x6f, 0x50, 0x69, 0x63, 0x4d,
            0x6f, 0x64, 0x75, 0x6c, 0x65, 0x64, 0x44, 0x62, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
            0x65, 0x05, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x09, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74,
            0x41, 0x6c, 0x6c, 0x00, 0x48, 0x05, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x03, 0x36, 0x36,
            0x36, 0x04, 0x70, 0x61, 0x74, 0x68, 0x30, 0x3d, 0x63, 0x6f, 0x6d, 0x2e, 0x62, 0x79,
            0x64, 0x2e, 0x64, 0x69, 0x6c, 0x69, 0x6e, 0x6b, 0x2e, 0x64, 0x62, 0x2e, 0x76, 0x65,
            0x68, 0x69, 0x63, 0x6c, 0x65, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x73, 0x65, 0x72, 0x76,
            0x69, 0x63, 0x65, 0x2e, 0x41, 0x75, 0x74, 0x6f, 0x50, 0x69, 0x63, 0x4d, 0x6f, 0x64,
            0x75, 0x6c, 0x65, 0x54, 0x44, 0x62, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12,
            0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61,
            0x74, 0x69, 0x6f, 0x6e, 0x07, 0x76, 0x65, 0x68, 0x69, 0x63, 0x6c, 0x65, 0x09, 0x43,
            0x4c, 0x4f, 0x55, 0x44, 0x57, 0x49, 0x53, 0x45, 0x30, 0xe8, 0x4a, 0x41, 0x56, 0x41,
            0x3a, 0x30, 0x3a, 0x36, 0x39, 0x30, 0x34, 0x34, 0x32, 0x34, 0x36, 0x36, 0x36, 0x30,
            0x35, 0x37, 0x34, 0x36, 0x39, 0x3a, 0x36, 0x38, 0x36, 0x35, 0x35, 0x30, 0x39, 0x35,
            0x38, 0x38, 0x30, 0x38, 0x39, 0x38, 0x30, 0x32, 0x3a, 0x33, 0x33, 0x36, 0x33, 0x38,
            0x33, 0x38, 0x35, 0x33, 0x33, 0x33, 0x31, 0x31, 0x38, 0x36, 0x36, 0x3a, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2d, 0x33, 0x33, 0x32, 0x64, 0x2d, 0x33, 0x35,
            0x31, 0x66, 0x2d, 0x66, 0x66, 0x66, 0x66, 0x2d, 0x66, 0x66, 0x66, 0x66, 0x38, 0x34,
            0x61, 0x66, 0x62, 0x31, 0x62, 0x61, 0x3a, 0x37, 0x35, 0x30, 0x32, 0x36, 0x31, 0x32,
            0x33, 0x32, 0x30, 0x31, 0x36, 0x33, 0x30, 0x35, 0x36, 0x3a, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x2d, 0x33, 0x39, 0x64, 0x37, 0x2d, 0x63, 0x39, 0x62, 0x32,
            0x2d, 0x66, 0x66, 0x66, 0x66, 0x2d, 0x66, 0x66, 0x66, 0x66, 0x39, 0x33, 0x63, 0x66,
            0x33, 0x32, 0x65, 0x30, 0x3a, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x2d,
            0x64, 0x66, 0x33, 0x61, 0x2d, 0x62, 0x66, 0x66, 0x66, 0x2d, 0x30, 0x30, 0x30, 0x30,
            0x2d, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x63, 0x34, 0x33, 0x65, 0x66, 0x34, 0x3a,
            0x64, 0x69, 0x6c, 0x69, 0x6e, 0x6b, 0x61, 0x70, 0x70, 0x5f, 0x64, 0x69, 0x6c, 0x69,
            0x6e, 0x6b, 0x61, 0x70, 0x70, 0x2d, 0x76, 0x65, 0x68, 0x69, 0x63, 0x6c, 0x65, 0x2d,
            0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x3a, 0x2d,
            0x31, 0x3a, 0x2d, 0x31, 0x0f, 0x73, 0x77, 0x38, 0x2d, 0x63, 0x6f, 0x72, 0x72, 0x65,
            0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x09, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x66,
            0x61, 0x63, 0x65,
        ];
        let mut meta_packet = MetaPacket::empty();
        let _ = meta_packet.update(
            &packet[..],
            true,
            true,
            Duration::from_secs(10),
            packet.len(),
        );
        meta_packet.lookup_key.direction = PacketDirection::ClientToServer;
        let Some(payload) = meta_packet.get_l4_payload() else {
            return;
        };

        let config = LogParserConfig {
            l7_log_dynamic: L7LogDynamicConfig::new(
                vec![],
                vec![],
                vec![TraceType::CloudWise],
                vec![],
                ExtraLogFields::default(),
                false,
                #[cfg(feature = "enterprise")]
                HashMap::new(),
            ),
            ..Default::default()
        };
        let mut dubbo = DubboLog::default();
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let param = &mut ParseParam::new(
            &meta_packet,
            log_cache.clone(),
            Default::default(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Default::default(),
            true,
            true,
        );
        param.set_captured_byte(payload.len());
        param.set_log_parser_config(&config);
        let is_dubbo = dubbo.check_payload(payload, param);

        let i = dubbo.parse_payload(payload, param);
        let info = if let Ok(info) = i {
            match info.unwrap_single() {
                L7ProtocolInfo::DubboInfo(d) => d,
                _ => unreachable!(),
            }
        } else {
            DubboInfo::default()
        };

        assert_eq!(is_dubbo, true);
        // EE: assert_eq!(info.trace_id, "00000000-332d-351f-ffff-ffff84afb1ba");
        assert_eq!(info.trace_id.field, "JAVA:0:6904424666057469:6865509588089802:3363838533311866:00000000-332d-351f-ffff-ffff84afb1ba:7502612320163056:00000000-39d7-c9b2-ffff-ffff93cf32e0:ffffffff-df3a-bfff-0000-000001c43ef4:dilinkapp_dilinkapp-vehicle-provide-test:-1:-1");
    }

    #[test]
    fn check() {
        let files = vec![
            ("dubbo_hessian2.pcap", "dubbo_hessian.result"),
            ("dubbo-eys.pcap", "dubbo-eys.result"),
            ("dubbo-sw8.pcap", "dubbo-sw8.result"),
            ("dubbo-kryo.pcap", "dubbo-kryo.result"),
        ];

        for item in files.iter() {
            let expected = fs::read_to_string(&Path::new(FILE_DIR).join(item.1)).unwrap();
            let output = run(item.0);

            if output != expected {
                let output_path = Path::new("actual.txt");
                fs::write(&output_path, &output).unwrap();
                assert!(
                    output == expected,
                    "{} output different from expected {}, written to {:?}",
                    item.0,
                    item.1,
                    output_path
                );
            }
        }
    }

    #[test]
    fn check_perf() {
        let expected = vec![(
            "dubbo_hessian2.pcap",
            L7PerfStats {
                request_count: 1,
                response_count: 1,
                err_client_count: 0,
                err_server_count: 0,
                err_timeout: 0,
                rrt_count: 1,
                rrt_sum: 4332,
                rrt_max: 4332,
                ..Default::default()
            },
        )];

        for item in expected.iter() {
            assert_eq!(item.1, run_perf(item.0), "parse pcap {} unexcepted", item.0);
        }
    }

    fn run_perf(pcap: &str) -> L7PerfStats {
        let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));
        let mut dubbo = DubboLog::default();

        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(pcap));
        let mut packets = capture.collect::<Vec<_>>();

        let config = LogParserConfig {
            l7_log_dynamic: L7LogDynamicConfig::new(
                vec![],
                vec![],
                vec![
                    TraceType::Customize("EagleEye-TraceID".to_string()),
                    TraceType::Sw8,
                ],
                vec![
                    TraceType::Customize("EagleEye-SpanID".to_string()),
                    TraceType::Sw8,
                ],
                ExtraLogFields::default(),
                false,
                #[cfg(feature = "enterprise")]
                HashMap::new(),
            ),
            ..Default::default()
        };

        let first_dst_port = packets[0].lookup_key.dst_port;
        for packet in packets.iter_mut() {
            if packet.lookup_key.dst_port == first_dst_port {
                packet.lookup_key.direction = PacketDirection::ClientToServer;
            } else {
                packet.lookup_key.direction = PacketDirection::ServerToClient;
            }
            let param = &mut ParseParam::new(
                &*packet,
                rrt_cache.clone(),
                Default::default(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Default::default(),
                true,
                true,
            );
            param.set_log_parser_config(&config);
            if packet.get_l4_payload().is_some() {
                let _ = dubbo.parse_payload(packet.get_l4_payload().unwrap(), param);
            }
        }
        dubbo.perf_stats.unwrap()
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn test_parse_hessian2_payload() {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join("dubbo-sw8.pcap"));
        let mut packets = capture.collect::<Vec<_>>();
        let first_dst_port = packets[0].lookup_key.dst_port;
        let rewrite_header_fields = vec![
            ExtraField {
                field_match_type: MatchType::String(false),
                field_match_keyword: "path".into(),
                rewrite_native_tag: ExtraField::ENDPOINT.into(),
                attribute_name: Some("path".into()),
                ..Default::default()
            },
            ExtraField {
                field_match_type: MatchType::String(false),
                field_match_keyword: "remote.application".into(),
                rewrite_native_tag: ExtraField::REQUEST_DOMAIN.into(),
                attribute_name: Some("remote.appliaction".into()),
                ..Default::default()
            },
        ];
        let mut segment_map_builder = SegmentBuilder::new();
        segment_map_builder.add_single(20080, 0);

        let config = L7LogDynamicConfig::new(
            vec![],
            vec!["x-request-id".into()],
            vec!["trace_id".into()],
            vec!["span_id".into()],
            ExtraLogFields::default(),
            false,
            HashMap::from([(
                L7ProtocolEnum::L7Protocol(L7Protocol::Dubbo),
                ExtraCustomFieldPolicyMap {
                    policies: vec![ExtraCustomFieldPolicy {
                        from_req_key: HashMap::from([(
                            FieldType::Header,
                            HashMap::from([
                                ("path".into(), vec![rewrite_header_fields[0].clone()]),
                                (
                                    "remote.application".into(),
                                    vec![rewrite_header_fields[1].clone()],
                                ),
                            ]),
                        )]),
                        ..Default::default()
                    }],
                    indices: segment_map_builder.merge_segments(),
                },
            )]),
        );

        for packet in packets.iter_mut() {
            if packet.lookup_key.dst_port == first_dst_port {
                packet.lookup_key.direction = PacketDirection::ClientToServer;
            } else {
                packet.lookup_key.direction = PacketDirection::ServerToClient;
            }
            let tcp_payload = packet.get_l4_payload().unwrap_or_default();
            let mut info = DubboInfo::default();
            hessian2::get_req_body_info(
                &config,
                &tcp_payload[DUBBO_HEADER_LEN..],
                &mut info,
                PacketDirection::ClientToServer,
                20080,
            );
            assert_eq!(info.service_name, "shop-web", "get service_name failed");
            assert_eq!(
                info.endpoint,
                Some("my.demo.service.ItemService".into()),
                "get endpoint failed"
            );

            assert!(info.attributes.len() > 0, "get attrs failed");
            for i in 0..info.attributes.len() {
                match info.attributes[i].key.as_str() {
                    "path" => assert_eq!(
                        "my.demo.service.ItemService", info.attributes[i].val,
                        "get path failed"
                    ),
                    "remote.application" => {
                        assert_eq!("shop-web", info.attributes[i].val, "get app failed")
                    }
                    _ => (),
                }
            }
        }
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn test_parse_hessian2_payload_with_args() {
        let hessian_payload = vec![
            0xda, 0xbb, 0xc2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
            0x01, 0x7e, 0x05, 0x32, 0x2e, 0x30, 0x2e, 0x32, 0x30, 0x24, 0x6f, 0x72, 0x67, 0x2e,
            0x61, 0x70, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x64, 0x75, 0x62, 0x62, 0x6f, 0x2e, 0x73,
            0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x50, 0x72, 0x6f, 0x76,
            0x69, 0x64, 0x65, 0x72, 0x09, 0x6d, 0x79, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
            0x07, 0x47, 0x65, 0x74, 0x55, 0x73, 0x65, 0x72, 0x1e, 0x4c, 0x6f, 0x72, 0x67, 0x2f,
            0x61, 0x70, 0x61, 0x63, 0x68, 0x65, 0x2f, 0x64, 0x75, 0x62, 0x62, 0x6f, 0x2f, 0x73,
            0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x55, 0x73, 0x65, 0x72, 0x3b, 0x43, 0x1c, 0x6f,
            0x72, 0x67, 0x2e, 0x61, 0x70, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x64, 0x75, 0x62, 0x62,
            0x6f, 0x2e, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x95,
            0x02, 0x69, 0x64, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x03, 0x61, 0x67, 0x65, 0x04, 0x74,
            0x69, 0x6d, 0x65, 0x03, 0x73, 0x65, 0x78, 0x60, 0x03, 0x30, 0x30, 0x33, 0x08, 0x54,
            0x65, 0x73, 0x74, 0x55, 0x73, 0x65, 0x72, 0xc8, 0x63, 0x4a, 0x00, 0x00, 0x01, 0x97,
            0x3d, 0xf0, 0xad, 0x8d, 0x43, 0x1e, 0x6f, 0x72, 0x67, 0x2e, 0x61, 0x70, 0x61, 0x63,
            0x68, 0x65, 0x2e, 0x64, 0x75, 0x62, 0x62, 0x6f, 0x2e, 0x73, 0x61, 0x6d, 0x70, 0x6c,
            0x65, 0x2e, 0x47, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x91, 0x04, 0x6e, 0x61, 0x6d, 0x65,
            0x61, 0x03, 0x4d, 0x41, 0x4e, 0x48, 0x09, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61,
            0x63, 0x65, 0x30, 0x24, 0x6f, 0x72, 0x67, 0x2e, 0x61, 0x70, 0x61, 0x63, 0x68, 0x65,
            0x2e, 0x64, 0x75, 0x62, 0x62, 0x6f, 0x2e, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
            0x55, 0x73, 0x65, 0x72, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x05, 0x67,
            0x72, 0x6f, 0x75, 0x70, 0x0a, 0x6d, 0x79, 0x41, 0x70, 0x70, 0x47, 0x72, 0x6f, 0x75,
            0x70, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x09, 0x6d, 0x79, 0x76, 0x65,
            0x72, 0x73, 0x69, 0x6f, 0x6e, 0x07, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x04,
            0x33, 0x30, 0x30, 0x30, 0x05, 0x61, 0x73, 0x79, 0x6e, 0x63, 0x05, 0x66, 0x61, 0x6c,
            0x73, 0x65, 0x0b, 0x65, 0x6e, 0x76, 0x69, 0x72, 0x6f, 0x6e, 0x6d, 0x65, 0x6e, 0x74,
            0x03, 0x70, 0x72, 0x6f, 0x04, 0x70, 0x61, 0x74, 0x68, 0x30, 0x24, 0x6f, 0x72, 0x67,
            0x2e, 0x61, 0x70, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x64, 0x75, 0x62, 0x62, 0x6f, 0x2e,
            0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x50, 0x72, 0x6f,
            0x76, 0x69, 0x64, 0x65, 0x72, 0x5a,
        ];
        let rewrite_hessian2_payload = vec![
            ExtraField {
                field_match_type: MatchType::String(false),
                field_match_keyword: "id".into(),
                rewrite_native_tag: ExtraField::REQUEST_RESOURCE.into(),
                attribute_name: Some("id".into()),
                ..Default::default()
            },
            ExtraField {
                field_match_type: MatchType::String(false),
                field_match_keyword: "name".into(),
                rewrite_native_tag: ExtraField::ENDPOINT.into(),
                attribute_name: Some("name".into()),
                ..Default::default()
            },
            ExtraField {
                field_match_type: MatchType::String(false),
                field_match_keyword: "age".into(),
                rewrite_native_tag: ExtraField::X_REQUEST_ID.into(),
                attribute_name: Some("age".into()),
                ..Default::default()
            },
        ];
        let mut segment_map_builder = SegmentBuilder::new();
        segment_map_builder.add_single(20000, 0);

        let config = L7LogDynamicConfig::new(
            vec![],
            vec!["x-request-id".into()],
            vec!["trace_id".into()],
            vec!["span_id".into()],
            ExtraLogFields::default(),
            false,
            HashMap::from([(
                L7ProtocolEnum::L7Protocol(L7Protocol::Dubbo),
                ExtraCustomFieldPolicyMap {
                    policies: vec![ExtraCustomFieldPolicy {
                        from_req_key: HashMap::from([(
                            FieldType::PayloadHessian2,
                            HashMap::from([
                                ("id".into(), vec![rewrite_hessian2_payload[0].clone()]),
                                ("name".into(), vec![rewrite_hessian2_payload[1].clone()]),
                                ("age".into(), vec![rewrite_hessian2_payload[2].clone()]),
                            ]),
                        )]),
                        ..Default::default()
                    }],
                    indices: segment_map_builder.merge_segments(),
                },
            )]),
        );

        let mut info = DubboInfo::default();
        info.msg_type = LogMessageType::Request;
        hessian2::get_req_body_info(
            &config,
            &hessian_payload[DUBBO_HEADER_LEN..],
            &mut info,
            PacketDirection::ClientToServer,
            20000,
        );
        assert_eq!(
            info.endpoint,
            Some("TestUser".into()),
            "get endpoint failed"
        );
        assert_eq!(
            info.x_request_id_0.as_ref().unwrap().field,
            "99",
            "get x_request_id_0 failed"
        );
        assert_eq!(info.method_name, "003", "get method_name failed");

        assert!(info.attributes.len() > 0, "get attrs failed");
        for i in 0..info.attributes.len() {
            match info.attributes[i].key.as_str() {
                "id" => assert_eq!("003", info.attributes[i].val, "get id failed"),
                "name" => assert_eq!("TestUser", info.attributes[i].val, "get name failed"),
                "age" => assert_eq!("99", info.attributes[i].val, "get age failed"),
                _ => (),
            }
        }
    }
}
