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

use super::L7ResponseStatus;

use public::proto::flow_log;

#[derive(Default, Debug)]
pub struct L7Request {
    pub req_type: String,
    pub domain: String,
    pub resource: String,
    pub endpoint: String,
}

#[derive(Default, Debug)]
pub struct L7Response {
    pub status: L7ResponseStatus,
    pub code: Option<i32>,
    pub exception: String,
    pub result: String,
}

#[derive(Default, Debug)]
pub struct TraceInfo {
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyVal {
    pub key: String,
    pub val: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MetricKeyVal {
    pub key: String,
    pub val: f32,
}

impl Eq for MetricKeyVal {}

#[derive(Default, Debug)]
pub struct ExtendedInfo {
    pub service_name: Option<String>,
    pub rpc_service: Option<String>,
    pub client_ip: Option<String>,
    pub request_id: Option<u32>,
    pub x_request_id_0: Option<String>,
    pub x_request_id_1: Option<String>,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub protocol_str: Option<String>,
    pub attributes: Option<Vec<KeyVal>>,
    pub metrics: Option<Vec<MetricKeyVal>>,
}

/*
 * server 的协议适配结构，用于把所有协议转换成统一的结构发送到 server
 * 目前暂时所有协议都需要实现 From<xxx> for L7ProtocolSendLog, 将协议转为 L7ProtocolSendLog 这个通用结构，后面考虑将协议抽象成 trait
 * 这个结构最终用于填充 AppProtoLogsData 这个 pb 结构体，然后 pb 编码后发送到 server
 *
 * 在 server 中，req_len、resp_len = -1 时会认为没有值； resp.code = -32768 会认为没有值
 */
#[derive(Default, Debug)]
pub struct L7ProtocolSendLog {
    pub req_len: Option<u32>,
    pub resp_len: Option<u32>,
    pub row_effect: u32,
    pub req: L7Request,
    pub resp: L7Response,
    pub version: Option<String>,
    pub trace_info: Option<TraceInfo>,
    pub ext_info: Option<ExtendedInfo>,
    pub flags: u32,
    pub captured_request_byte: u32,
    pub captured_response_byte: u32,
}

impl L7ProtocolSendLog {
    pub const SECONDS_PER_DAY: f32 = 60.0 * 60.0 * 24.0;

    pub fn fill_app_proto_log(self, log: &mut flow_log::AppProtoLogsData) {
        let req_len = if let Some(len) = self.req_len {
            len as i32
        } else {
            -1
        };

        let resp_len = if let Some(len) = self.resp_len {
            len as i32
        } else {
            -1
        };
        let captured_request_byte = if self.captured_request_byte > 0 {
            self.captured_request_byte as i32
        } else {
            -1
        };
        let captured_response_byte = if self.captured_response_byte > 0 {
            self.captured_response_byte as i32
        } else {
            -1
        };

        log.req_len = req_len;
        log.resp_len = resp_len;
        log.captured_request_byte = captured_request_byte;
        log.captured_response_byte = captured_response_byte;
        log.row_effect = self.row_effect;

        log.req = Some(flow_log::L7Request {
            req_type: self.req.req_type.into(),
            domain: self.req.domain.into(),
            resource: self.req.resource.into(),
            endpoint: self.req.endpoint.into(),
        });
        log.resp = Some(flow_log::L7Response {
            code: self.resp.code.unwrap_or(i16::MIN as i32),
            status: self.resp.status as u32,
            exception: self.resp.exception.into(),
            result: self.resp.result.into(),
        });

        if let Some(version) = self.version {
            log.version = version.into();
        }

        if let Some(trace_info) = self.trace_info {
            let mut t = flow_log::TraceInfo::default();
            if let Some(s) = trace_info.span_id {
                t.span_id = s.into();
            }
            if let Some(s) = trace_info.parent_span_id {
                t.parent_span_id = s.into();
            }
            if let Some(s) = trace_info.trace_id {
                t.trace_id = s.into();
            }

            log.trace_info = Some(t);
        }

        if let Some(ext) = self.ext_info {
            let mut ext_info = flow_log::ExtendedInfo::default();

            if let Some(s) = ext.service_name {
                ext_info.service_name = s.into();
            }
            if let Some(s) = ext.rpc_service {
                ext_info.rpc_service = s.into();
            }
            if let Some(s) = ext.client_ip {
                ext_info.client_ip = s.into();
            }
            if let Some(s) = ext.request_id {
                ext_info.request_id = s;
            }
            if let Some(s) = ext.x_request_id_0 {
                ext_info.x_request_id_0 = s.into();
            }
            if let Some(s) = ext.x_request_id_1 {
                ext_info.x_request_id_1 = s.into();
            }
            if let Some(ua) = ext.user_agent {
                ext_info.http_user_agent = ua;
            }
            if let Some(referer) = ext.referer {
                ext_info.http_referer = referer;
            }
            if let Some(proto_str) = ext.protocol_str {
                ext_info.protocol_str = proto_str;
            }
            if let Some(attr) = ext.attributes {
                for kv in attr.into_iter() {
                    ext_info.attribute_names.push(kv.key);
                    ext_info.attribute_values.push(kv.val);
                }
            }
            if let Some(metrics) = ext.metrics {
                for kv in metrics.into_iter() {
                    ext_info.metrics_names.push(kv.key);
                    ext_info.metrics_values.push(kv.val as f64);
                }
            }
            log.ext_info = Some(ext_info);
        }
        log.flags = self.flags;
    }
}
