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

use nom::FindSubstring;

use super::DubboInfo;
use crate::config::handler::{L7LogDynamicConfig, TraceType};
use crate::utils::bytes::{read_u16_be, read_u32_be};

const TC_STRING: u8 = 0x74;
const TC_BLOCKDATA: u8 = 0x77;

fn decode_tc_string(payload: &[u8]) -> Option<String> {
    let offset = 3;
    if payload.len() <= 3 || payload[0] != TC_STRING {
        return None;
    }
    let length = read_u16_be(&payload[1..]) as usize;
    if offset + length >= payload.len() {
        return None;
    }
    let Ok(value) = std::str::from_utf8(&payload[offset..offset + length]) else {
        return None;
    };
    Some(value.to_string())
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

        if let Some(s) = decode_tc_string(&payload[start..]) {
            return Some(s);
        }
    }
    return None;
}

pub fn decode_trace_id(payload: &[u8], trace_type: &TraceType, info: &mut DubboInfo) {
    if let Some(trace_id) = lookup_str(payload, trace_type) {
        info.add_trace_id(trace_id, trace_type);
    }
}

fn decode_span_id(payload: &[u8], trace_type: &TraceType, info: &mut DubboInfo) {
    if let Some(span_id) = lookup_str(payload, trace_type) {
        info.set_span_id(span_id, trace_type);
    }
}

fn decode_header_string(payload: &[u8], offset: usize) -> Option<(String, usize)> {
    if offset + 4 >= payload.len() {
        return None;
    }
    let payload = &payload[offset..];
    let mut offset = 0;
    let first_length = read_u32_be(&payload[offset..]) as usize;
    offset += 4;

    if offset + 2 >= payload.len() {
        return None;
    }
    let second_length = read_u16_be(&payload[offset..]) as usize;
    offset += 2;
    if first_length != second_length
        || second_length == 0
        || offset + second_length >= payload.len()
    {
        return None;
    }

    let Ok(value) = std::str::from_utf8(&payload[offset..offset + second_length]) else {
        return None;
    };

    Some((value.to_string(), offset + second_length))
}

pub fn get_req_body_info(config: &L7LogDynamicConfig, payload: &[u8], info: &mut DubboInfo) {
    // Java Body
    // +---------------------------------------------------------------------------------------+
    // | Magic (2B) | Magic Version (2B) | TC BLOCKDATA Header (2B) | Double version (*) | ... |
    // +---------------------------------------------------------------------------------------+
    let mut offset = 6;
    let Some(version) = decode_header_string(&payload, offset) else {
        return;
    };
    info.dubbo_version = version.0;
    offset += version.1;

    let Some(service_name) = decode_header_string(&payload, offset) else {
        return;
    };
    info.service_name = service_name.0;
    offset += service_name.1;

    let Some(service_version) = decode_header_string(&payload, offset) else {
        return;
    };
    info.service_version = service_version.0;
    offset += service_version.1;

    let Some(method_name) = decode_header_string(&payload, offset) else {
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
        if !config.multiple_trace_id_collection && !info.trace_ids.0.is_empty() {
            break;
        }
    }
    for span_type in config.span_types.iter() {
        if span_type.as_str().len() > u8::MAX as usize {
            continue;
        }

        decode_span_id(&payload[offset..], &span_type, info);
        if info.span_id.get().len() != 0 {
            break;
        }
    }
}
