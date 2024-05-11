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

use serde::Serialize;

use crate::{
    common::{
        enums::IpProtocol,
        flow::{L7PerfStats, L7Protocol, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, ParseParam},
        meta_packet::EbpfFlags,
    },
    config::handler::{L7LogDynamicConfig, TraceType},
    flow_generator::{
        error::{Error, Result},
        protocol_logs::{
            consts::*,
            decode_base64_to_string,
            pb_adapter::{
                ExtendedInfo, KeyVal, L7ProtocolSendLog, L7Request, L7Response, TraceInfo,
            },
            set_captured_byte, swap_if, value_is_default, value_is_negative, AppProtoHead,
            L7ResponseStatus, LogMessageType,
        },
    },
    plugin::{wasm::WasmData, CustomInfo},
    utils::bytes::{read_u32_be, read_u64_be},
};

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
    pub trace_id: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub span_id: String,

    // resp
    #[serde(rename = "response_length", skip_serializing_if = "Option::is_none")]
    pub resp_msg_size: Option<u32>,
    #[serde(rename = "response_status")]
    pub resp_status: L7ResponseStatus,
    #[serde(rename = "response_code", skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i32>,

    captured_request_byte: u32,
    captured_response_byte: u32,

    rrt: u64,

    // set by wasm plugin
    custom_result: Option<String>,
    custom_exception: Option<String>,

    #[serde(skip)]
    attributes: Vec<KeyVal>,
}

impl DubboInfo {
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
        swap_if!(self, trace_id, is_empty, other);
        swap_if!(self, span_id, is_empty, other);
        self.attributes.append(&mut other.attributes);
        if other.captured_request_byte > 0 {
            self.captured_request_byte = other.captured_request_byte;
        }
        if other.captured_response_byte > 0 {
            self.captured_response_byte = other.captured_response_byte;
        }
    }

    fn set_trace_id(&mut self, trace_id: String, trace_type: &TraceType) {
        self.trace_id = trace_id;
        match trace_type {
            TraceType::Sw3 => {
                // sw3: SEGMENTID|SPANID|100|100|#IPPORT|#PARENT_ENDPOINT|#ENDPOINT|TRACEID|SAMPLING
                if self.trace_id.len() > 2 {
                    let segs: Vec<&str> = self.trace_id.split("|").collect();
                    if segs.len() > 7 {
                        self.trace_id = segs[7].to_string();
                    }
                }
            }
            TraceType::Sw8 => {
                if self.trace_id.len() > 2 {
                    if let Some(index) = self.trace_id[2..].find("-") {
                        self.trace_id = self.trace_id[2..2 + index].to_string();
                    }
                }
                self.trace_id = decode_base64_to_string(&self.trace_id);
            }
            _ => return,
        };
    }

    fn set_span_id(&mut self, span_id: String, trace_type: &TraceType) {
        self.span_id = span_id;
        match trace_type {
            TraceType::Sw3 => {
                // sw3: SEGMENTID|SPANID|100|100|#IPPORT|#PARENT_ENDPOINT|#ENDPOINT|TRACEID|SAMPLING
                if self.span_id.len() > 2 {
                    let segs: Vec<&str> = self.span_id.split("|").collect();
                    if segs.len() > 3 {
                        self.span_id = format!("{}-{}", segs[0], segs[1]);
                    }
                }
            }
            TraceType::Sw8 => {
                // Format:
                // sw8: 1-TRACEID-SEGMENTID-3-PARENT_SERVICE-PARENT_INSTANCE-PARENT_ENDPOINT-IPPORT
                let mut skip = false;
                if self.span_id.len() > 2 {
                    let segs: Vec<&str> = self.span_id.split("-").collect();
                    if segs.len() > 4 {
                        self.span_id = format!("{}-{}", decode_base64_to_string(segs[2]), segs[3]);
                        skip = true;
                    }
                }
                if !skip {
                    self.span_id = decode_base64_to_string(&self.span_id);
                }
            }
            _ => return,
        };
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
        if custom.trace.trace_id.is_some() {
            self.trace_id = custom.trace.trace_id.unwrap();
        }
        if custom.trace.span_id.is_some() {
            self.span_id = custom.trace.span_id.unwrap();
        }

        // extend attribute
        if !custom.attributes.is_empty() {
            self.attributes.extend(custom.attributes);
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
        if !self.service_name.is_empty() || !self.method_name.is_empty() {
            Some(format!("{}/{}", self.service_name, self.method_name))
        } else {
            None
        }
    }

    fn get_request_domain(&self) -> String {
        self.service_name.clone()
    }

    fn get_request_resource_length(&self) -> usize {
        self.method_name.len()
    }
}

impl From<DubboInfo> for L7ProtocolSendLog {
    fn from(f: DubboInfo) -> Self {
        let endpoint = format!("{}/{}", f.service_name, f.method_name);
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
                endpoint,
                domain: f.service_name.clone(),
            },
            resp: L7Response {
                status: f.resp_status,
                code: f.status_code,
                exception: f.custom_exception.unwrap_or_default(),
                result: f.custom_result.unwrap_or_default(),
            },
            trace_info: Some(TraceInfo {
                trace_id: Some(f.trace_id),
                span_id: Some(f.span_id),
                ..Default::default()
            }),
            ext_info: Some(ExtendedInfo {
                rpc_service: Some(f.service_name),
                request_id: Some(f.request_id as u32),
                attributes: Some(attrs),
                ..Default::default()
            }),
            flags,
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
        info.cal_rrt(param, None).map(|rrt| {
            info.rrt = rrt;
            self.perf_stats.as_mut().map(|p| p.update_rrt(rrt));
        });
        set_captured_byte!(info, param);
        if param.parse_log {
            self.wasm_hook(param, payload, &mut info);
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

mod hessian2 {
    use std::borrow::Cow;

    use super::{DubboInfo, BODY_PARAM_MAX, BODY_PARAM_MIN, TRACE_ID_MAX_LEN};
    use crate::config::handler::{L7LogDynamicConfig, TraceType};
    use crate::flow_generator::protocol_logs::consts::*;

    fn check_char_boundary(payload: &Cow<'_, str>, start: usize, end: usize) -> bool {
        let mut invalid = false;
        for index in start..end {
            if !payload.is_char_boundary(index) {
                invalid = true;
                break;
            }
        }
        return invalid;
    }

    fn decode_field(payload: &Cow<'_, str>, mut start: usize, end: usize) -> Option<String> {
        if start >= payload.len() {
            return None;
        }

        let bytes = payload.as_bytes();
        match bytes[start] {
            BC_STRING_SHORT..=BC_STRING_SHORT_MAX => {
                if start + 2 >= payload.len() {
                    return None;
                }
                let field_len =
                    (((bytes[start] - BC_STRING_SHORT) as usize) << 8) + bytes[start + 1] as usize;
                start += 2;
                if start + field_len < end {
                    return Some(payload[start..start + field_len].to_string());
                }
            }
            0..=STRING_DIRECT_MAX => {
                let field_len = bytes[start] as usize;
                start += 1;
                if start + field_len < end {
                    return Some(payload[start..start + field_len].to_string());
                }
            }
            b'S' => {
                if start + 3 >= payload.len() {
                    return None;
                }
                let field_len = ((bytes[start + 1] as usize) << 8) + bytes[start + 2] as usize;
                start += 3;
                if start + field_len < end {
                    return Some(payload[start..start + field_len].to_string());
                }
            }
            _ => {}
        };
        return None;
    }

    fn lookup_str(payload: &Cow<'_, str>, trace_type: &TraceType) -> Option<String> {
        let tag = match trace_type {
            TraceType::Sw3 | TraceType::Sw8 | TraceType::Customize(_) => trace_type.as_str(),
            _ => return None,
        };

        let mut start = 0;
        while start < payload.len() {
            if !payload.is_char_boundary(start) {
                break;
            }
            let index = payload[start..].find(tag);
            if index.is_none() {
                break;
            }
            let index = index.unwrap();
            // 注意这里tag长度不会超过256
            if index == 0 || tag.len() != payload.as_bytes()[start + index - 1] as usize {
                start += index + tag.len();
                continue;
            }
            let last_index = payload
                .len()
                .min(TRACE_ID_MAX_LEN + start + index + tag.len());
            if check_char_boundary(&payload, start + index, last_index) {
                start += index + tag.len();
                continue;
            }

            if let Some(context) = decode_field(payload, start + index + tag.len(), last_index) {
                return Some(context);
            }
            start += index + tag.len();
        }
        return None;
    }

    // 注意 dubbo trace id 解析是区分大小写的
    fn decode_trace_id(payload: &Cow<'_, str>, trace_type: &TraceType, info: &mut DubboInfo) {
        if let Some(trace_id) = lookup_str(payload, trace_type) {
            info.set_trace_id(trace_id, trace_type);
        }
    }

    fn decode_span_id(payload: &Cow<'_, str>, trace_type: &TraceType, info: &mut DubboInfo) {
        if let Some(span_id) = lookup_str(payload, trace_type) {
            info.set_span_id(span_id, trace_type);
        }
    }

    // 参考开源代码解析：https://github.com/apache/dubbo-go-hessian2/blob/master/decode.go#L289
    // 返回offset和数据length
    pub fn get_req_param_len(payload: &[u8]) -> (usize, usize) {
        let tag = payload[0];
        match tag {
            BC_STRING_DIRECT..=STRING_DIRECT_MAX => (1, tag as usize),
            0x30..=0x33 if payload.len() > 2 => {
                (2, ((tag as usize - 0x30) << 8) + payload[1] as usize)
            }
            BC_STRING_CHUNK | BC_STRING if payload.len() > 3 => {
                (3, ((payload[1] as usize) << 8) + payload[2] as usize)
            }
            _ => (0, 0),
        }
    }

    // 尽力而为的去解析Dubbo请求中Body各参数
    pub fn get_req_body_info(config: &L7LogDynamicConfig, payload: &[u8], info: &mut DubboInfo) {
        let mut n = BODY_PARAM_MIN;
        let mut para_index = 0;
        let payload_len = payload.len();

        while n < BODY_PARAM_MAX && para_index < payload_len {
            let (offset, para_len) = get_req_param_len(&payload[para_index..]);
            para_index += offset;
            if para_len == 0 || para_len + para_index > payload_len {
                return;
            }

            match n {
                BODY_PARAM_DUBBO_VERSION => {
                    info.dubbo_version =
                        String::from_utf8_lossy(&payload[para_index..para_index + para_len])
                            .into_owned()
                }
                BODY_PARAM_SERVICE_NAME => {
                    info.service_name =
                        String::from_utf8_lossy(&payload[para_index..para_index + para_len])
                            .into_owned();
                }
                BODY_PARAM_SERVICE_VERSION => {
                    info.service_version =
                        String::from_utf8_lossy(&payload[para_index..para_index + para_len])
                            .into_owned();
                }
                BODY_PARAM_METHOD_NAME => {
                    info.method_name =
                        String::from_utf8_lossy(&payload[para_index..para_index + para_len])
                            .into_owned();
                }
                _ => return,
            }

            para_index += para_len;
            if payload_len <= para_index {
                return;
            }
            n += 1;
        }

        if config.trace_types.is_empty() || para_index >= payload.len() {
            return;
        }

        let payload_str = String::from_utf8_lossy(&payload[para_index..]);
        for trace_type in config.trace_types.iter() {
            if trace_type.as_str().len() > u8::MAX as usize {
                continue;
            }

            decode_trace_id(&payload_str, &trace_type, info);
            if info.trace_id.len() != 0 {
                break;
            }
        }
        for span_type in config.span_types.iter() {
            if span_type.as_str().len() > u8::MAX as usize {
                continue;
            }

            decode_span_id(&payload_str, &span_type, info);
            if info.span_id.len() != 0 {
                break;
            }
        }
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
            TraceType::Sw3 | TraceType::Sw8 | TraceType::Customize(_) => trace_type.as_str(),
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
            if info.trace_id.len() != 0 {
                break;
            }
        }
        for span_type in config.span_types.iter() {
            if span_type.as_str().len() > u8::MAX as usize {
                continue;
            }

            decode_span_id(&payload[offset..], &span_type, info);
            if info.span_id.len() != 0 {
                break;
            }
        }
    }
}

impl DubboLog {
    fn decode_body(config: &L7LogDynamicConfig, payload: &[u8], info: &mut DubboInfo) {
        match info.serial_id {
            HESSIAN2_SERIALIZATION_ID => hessian2::get_req_body_info(config, payload, info),
            KRYO_SERIALIZATION2_ID => kryo::get_req_body_info(config, payload, info),
            KRYO_SERIALIZATION_ID => kryo::get_req_body_info(config, payload, info),
            _ => {}
        }
    }

    fn request(
        &mut self,
        config: &L7LogDynamicConfig,
        payload: &[u8],
        dubbo_header: &DubboHeader,
        info: &mut DubboInfo,
    ) {
        info.msg_type = LogMessageType::Request;
        info.event = dubbo_header.event;
        info.data_type = dubbo_header.data_type;
        info.req_msg_size = Some(dubbo_header.data_length as u32);
        info.serial_id = dubbo_header.serial_id;
        info.request_id = dubbo_header.request_id;

        Self::decode_body(config, &payload[DUBBO_HEADER_LEN..], info);
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
                self.request(&config, payload, &dubbo_header, info);
                self.perf_stats.as_mut().map(|p| p.inc_req());
            }
            PacketDirection::ServerToClient => {
                self.response(&dubbo_header, info);
                self.perf_stats.as_mut().map(|p| p.inc_resp());
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

    const FILE_DIR: &str = "resources/test/flow_generator/dubbo";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name), Some(1024));
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let mut packets = capture.as_meta_packets();
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
                    "".to_owned(),
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
            param.set_log_parse_config(&config);
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

        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(pcap), None);
        let mut packets = capture.as_meta_packets();

        let config = LogParserConfig {
            l7_log_dynamic: L7LogDynamicConfig::new(
                "".to_owned(),
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
            param.set_log_parse_config(&config);
            if packet.get_l4_payload().is_some() {
                let _ = dubbo.parse_payload(packet.get_l4_payload().unwrap(), param);
            }
        }
        dubbo.perf_stats.unwrap()
    }
}
