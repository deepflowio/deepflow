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

use public::codecs::hessian2::{consts::*, Hessian2Decoder};

use super::consts::*;
use super::{DubboInfo, BODY_PARAM_MAX, BODY_PARAM_MIN};

use crate::{
    common::l7_protocol_log::ParseParam,
    config::handler::{L7LogDynamicConfig, TraceType},
};

cfg_if::cfg_if! {
if #[cfg(feature = "enterprise")] {
        use crate::{
            common::flow::L7Protocol,
            flow_generator::{
                LogMessageType,
                protocol_logs::{consts::APM_SPAN_ID_ATTR, pb_adapter::{KeyVal, MetricKeyVal}, CUSTOM_FIELD_POLICY_PRIORITY, PrioField},
            },
        };
        use enterprise_utils::l7::custom_policy::{
            custom_field_policy::{enums::{Op, Operation, PayloadType, Source}, Store},
            enums::NativeTag,
        };
    }
}

fn lookup_str(payload: &[u8], trace_type: &TraceType) -> Option<String> {
    let tag = match trace_type {
        TraceType::Sw3 | TraceType::Sw8 | TraceType::CloudWise | TraceType::Customize(_) => {
            trace_type.as_str()
        }
        _ => return None,
    };

    let mut start = 0;
    while start < payload.len() {
        if !payload[start].is_ascii() {
            break;
        }
        let Some(index) = (&payload[start..]).find_substring(tag) else {
            break;
        };
        // 注意这里tag长度不会超过256
        if index == 0 || tag.len() != payload[start + index - 1] as usize {
            start += index + tag.len();
            continue;
        }

        if let (Some(context), _) =
            Hessian2Decoder::decode_string(payload, start + index + tag.len())
        {
            return Some(context);
        }
        start += index + tag.len();
    }
    return None;
}

// 注意 dubbo trace id 解析是区分大小写的
fn decode_trace_ids(payload: &[u8], trace_type: &TraceType, info: &mut DubboInfo) {
    if let Some(trace_id) = lookup_str(payload, trace_type) {
        info.add_trace_id(trace_id, trace_type);
    }
}

fn decode_span_id(payload: &[u8], trace_type: &TraceType, info: &mut DubboInfo) {
    if let Some(span_id) = lookup_str(payload, trace_type) {
        info.set_span_id(span_id, trace_type);
    }
}

// 参考开源代码解析：https://github.com/apache/dubbo-go-hessian2/blob/master/decode.go#L289
// https://github.com/apache/dubbo-go-hessian2/blob/v2.0.0/string.go#L169
// 返回offset和数据length
fn get_req_param_len(payload: &[u8]) -> (usize, usize) {
    let tag = payload[0];
    match tag {
        BC_STRING_DIRECT..=STRING_DIRECT_MAX => (1, tag as usize),
        BC_STRING_SHORT..=BC_STRING_SHORT_MAX if payload.len() > 2 => {
            (2, ((tag as usize - 0x30) << 8) + payload[1] as usize)
        }
        BC_STRING_CHUNK | BC_STRING if payload.len() > 3 => {
            (3, ((payload[1] as usize) << 8) + payload[2] as usize)
        }
        _ => (0, 0),
    }
}

// 尽力而为的去解析Dubbo请求中Body各参数
// 解析逻辑：https://github.com/apache/dubbo-go/blob/v3.3.0/protocol/dubbo/impl/hessian.go
pub fn get_req_body_info(
    config: &L7LogDynamicConfig,
    payload: &[u8],
    info: &mut DubboInfo,
    #[allow(unused)] param: &ParseParam,
) {
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

    for trace_type in config.trace_types.iter() {
        if trace_type.as_str().len() > u8::MAX as usize {
            continue;
        }

        decode_trace_ids(&payload[para_index..], &trace_type, info);
        if !config.multiple_trace_id_collection && !info.trace_ids.is_empty() {
            break;
        }
    }
    for span_type in config.span_types.iter() {
        if span_type.as_str().len() > u8::MAX as usize {
            continue;
        }

        decode_span_id(&payload[para_index..], &span_type, info);
        if info.span_id.field.len() != 0 {
            break;
        }
    }

    #[cfg(feature = "enterprise")]
    apply_custom_field_policies(config, param, payload, info);
}

#[allow(unused_variables)]
pub fn get_resp_body_info(
    config: &L7LogDynamicConfig,
    payload: &[u8],
    info: &mut DubboInfo,
    param: &ParseParam,
) {
    #[cfg(feature = "enterprise")]
    apply_custom_field_policies(config, param, payload, info);
}

#[cfg(feature = "enterprise")]
fn apply_custom_field_policies(
    config: &L7LogDynamicConfig,
    param: &ParseParam,
    payload: &[u8],
    info: &mut DubboInfo,
) {
    let Some(policies) = config.get_custom_field_policies(L7Protocol::Dubbo.into(), param) else {
        return;
    };
    let mut store = Store::default();
    policies.apply(
        &mut store,
        param.direction.into(),
        Source::Payload(PayloadType::HESSIAN2, payload),
    );
    for Operation { op, prio } in store.into_iter_with(policies) {
        match op {
            Op::RewriteResponseStatus(status) => {
                info.status_code.replace(status as u32 as i32);
            }
            Op::RewriteNativeTag(tag, value) => {
                match tag {
                    NativeTag::Version => info.dubbo_version = value.to_string(),
                    // req
                    // request_resource priority greater than request_type
                    NativeTag::RequestType => {
                        if info.method_name.is_empty() {
                            info.method_name = value.to_string();
                        }
                    }
                    NativeTag::RequestDomain => info.service_name = value.to_string(),
                    NativeTag::RequestResource => info.method_name = value.to_string(),
                    NativeTag::Endpoint => {
                        info.endpoint.replace(value.to_string());
                    }
                    NativeTag::RequestId => {
                        info.request_id = value.parse::<i64>().unwrap_or_default()
                    }
                    // res
                    NativeTag::ResponseCode => info.status_code = value.parse::<i32>().ok(),
                    NativeTag::ResponseException => info.custom_exception = Some(value.to_string()),
                    NativeTag::ResponseResult => info.custom_result = Some(value.to_string()),
                    // trace info
                    NativeTag::TraceId => info
                        .trace_ids
                        .merge_field(CUSTOM_FIELD_POLICY_PRIORITY + prio, value.to_string()),
                    NativeTag::SpanId => {
                        if CUSTOM_FIELD_POLICY_PRIORITY < info.span_id.prio {
                            let old = std::mem::replace(
                                &mut info.span_id,
                                PrioField::new(CUSTOM_FIELD_POLICY_PRIORITY, value.to_string()),
                            );
                            if !old.is_default() {
                                info.attributes.push(KeyVal {
                                    key: APM_SPAN_ID_ATTR.to_string(),
                                    val: old.into_inner(),
                                });
                            }
                        }
                    }
                    NativeTag::HttpProxyClient => info.client_ip = Some(value.to_string()),
                    NativeTag::XRequestId => {
                        let x_req_id = match info.msg_type {
                            LogMessageType::Request => &mut info.x_request_id_0,
                            LogMessageType::Response => &mut info.x_request_id_1,
                            _ => return,
                        };
                        match x_req_id {
                            Some(old) if old.prio < CUSTOM_FIELD_POLICY_PRIORITY => (),
                            _ => {
                                *x_req_id = Some(PrioField::new(
                                    CUSTOM_FIELD_POLICY_PRIORITY,
                                    value.to_string(),
                                ));
                            }
                        }
                    }
                    NativeTag::BizType => info.biz_type = value.parse::<u8>().unwrap_or_default(),
                    NativeTag::BizCode => info.biz_code = value.to_string(),
                    NativeTag::BizScenario => info.biz_scenario = value.to_string(),
                }
            }
            Op::AddAttribute(key, value) => {
                info.attributes.push(KeyVal {
                    key: key.to_string(),
                    val: value.to_string(),
                });
            }
            Op::AddMetric(key, value) => {
                info.metrics.push(MetricKeyVal {
                    key: key.to_string(),
                    val: value,
                });
            }
            // not supported
            Op::SavePayload(_) => (),
        }
    }
}
