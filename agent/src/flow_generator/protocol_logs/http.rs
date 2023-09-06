/*
 * Copyright (c) 2023 Yunshan Networks
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

use std::str;

use nom::AsBytes;
use serde::Serialize;

use super::pb_adapter::{
    ExtendedInfo, KeyVal, L7ProtocolSendLog, L7Request, L7Response, TraceInfo,
};
use super::value_is_default;
use super::{consts::*, AppProtoHead, L7ResponseStatus};
use super::{decode_new_rpc_trace_context_with_type, LogMessageType};

use crate::common::flow::L7PerfStats;
use crate::common::l7_protocol_log::L7ParseResult;
use crate::plugin::CustomInfo;
use crate::{
    common::{
        ebpf::EbpfType,
        enums::IpProtocol,
        flow::L7Protocol,
        flow::PacketDirection,
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ProtocolParserInterface, ParseParam},
    },
    config::handler::{L7LogDynamicConfig, TraceType},
    flow_generator::error::{Error, Result},
    flow_generator::protocol_logs::{decode_base64_to_string, L7ProtoRawDataType},
    utils::bytes::{read_u32_be, read_u32_le},
};
use cloud_platform::tingyun;
use public::utils::net::h2pack;

#[derive(Serialize, Debug, Default, Clone)]
pub struct HttpInfo {
    // 流是否结束，用于 http2 ebpf uprobe 处理.
    // 由于ebpf有可能响应会比请求先到，所以需要 is_req_end 和 is_resp_end 同时为true才认为结束
    #[serde(skip)]
    is_req_end: bool,
    #[serde(skip)]
    is_resp_end: bool,
    #[serde(skip)]
    rrt: u64,

    #[serde(skip)]
    pub proto: L7Protocol,
    #[serde(skip)]
    is_tls: bool,
    msg_type: LogMessageType,
    // 数据原始类型，标准的协议格式或者是ebpf上报的自定义格式
    #[serde(skip)]
    raw_data_type: L7ProtoRawDataType,

    #[serde(rename = "request_id", skip_serializing_if = "value_is_default")]
    pub stream_id: Option<u32>,
    #[serde(skip_serializing_if = "value_is_default")]
    pub version: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub trace_id: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub span_id: String,

    #[serde(rename = "request_type", skip_serializing_if = "value_is_default")]
    pub method: String,
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub path: String,
    #[serde(rename = "request_domain", skip_serializing_if = "value_is_default")]
    pub host: String,
    #[serde(rename = "user_agent", skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(rename = "referer", skip_serializing_if = "Option::is_none")]
    pub referer: Option<String>,
    #[serde(rename = "http_proxy_client", skip_serializing_if = "value_is_default")]
    pub client_ip: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub x_request_id_0: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub x_request_id_1: String,

    #[serde(rename = "request_length", skip_serializing_if = "Option::is_none")]
    pub req_content_length: Option<u32>,
    #[serde(rename = "response_length", skip_serializing_if = "Option::is_none")]
    pub resp_content_length: Option<u32>,

    #[serde(rename = "response_code", skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i32>,
    #[serde(rename = "response_status")]
    pub status: L7ResponseStatus,

    // set by wasm plugin
    custom_endpoint: Option<String>,
    custom_result: Option<String>,
    custom_exception: Option<String>,

    #[serde(skip)]
    attributes: Vec<KeyVal>,
}

impl HttpInfo {
    pub fn merge_custom_to_http1(&mut self, custom: CustomInfo) {
        // req rewrite
        if !custom.req.domain.is_empty() {
            self.host = custom.req.domain;
        }

        if !custom.req.req_type.is_empty() {
            self.method = custom.req.req_type;
        }

        if !custom.req.resource.is_empty() {
            self.path = custom.req.resource;
        }

        if !custom.req.endpoint.is_empty() {
            self.custom_endpoint = Some(custom.req.endpoint)
        }

        //req write
        if custom.resp.code.is_some() {
            self.status_code = custom.resp.code;
        }

        if custom.resp.status != self.status {
            self.status = custom.resp.status;
        }

        if !custom.resp.result.is_empty() {
            self.custom_result = Some(custom.resp.result)
        }

        if !custom.resp.exception.is_empty() {
            self.custom_exception = Some(custom.resp.exception)
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

impl L7ProtocolInfoInterface for HttpInfo {
    fn session_id(&self) -> Option<u32> {
        self.stream_id
    }

    fn merge_log(&mut self, other: L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::HttpInfo(other) = other {
            return self.merge(other);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: self.get_l7_protocol_with_tls(),
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn is_tls(&self) -> bool {
        self.is_tls
    }

    fn skip_send(&self) -> bool {
        // filter the empty data from go http uprobe.
        self.raw_data_type == L7ProtoRawDataType::GoHttp2Uprobe && self.is_empty()
    }

    fn need_merge(&self) -> bool {
        match self.raw_data_type {
            L7ProtoRawDataType::GoHttp2Uprobe => true,
            _ => false,
        }
    }

    fn is_req_resp_end(&self) -> (bool, bool) {
        (self.is_req_end, self.is_resp_end)
    }

    fn get_endpoint(&self) -> Option<String> {
        if self.is_grpc() {
            if self.path.is_empty() {
                None
            } else {
                Some(self.path.clone())
            }
        } else {
            None
        }
    }
}

impl HttpInfo {
    pub fn merge(&mut self, other: Self) -> Result<()> {
        let other_is_grpc = other.is_grpc();

        match other.msg_type {
            // merge with request
            LogMessageType::Request => {
                if self.path.is_empty() {
                    self.path = other.path;
                }
                if self.host.is_empty() {
                    self.host = other.host;
                }
                if self.method.is_empty() {
                    self.method = other.method;
                }
                if self.user_agent.is_some() {
                    self.user_agent = other.user_agent;
                }
                if self.referer.is_some() {
                    self.referer = other.referer;
                }
                // 下面用于判断是否结束
                // ================
                // determine whether request is end
                if other.is_req_end {
                    self.is_req_end = true;
                }
                if self.req_content_length.is_none() {
                    self.req_content_length = other.req_content_length;
                }
            }
            // merge with response
            LogMessageType::Response => {
                if other.status != L7ResponseStatus::default() {
                    self.status = other.status;
                }
                if self.status_code.is_none() {
                    self.status_code = other.status_code;
                }

                if other.custom_exception.is_some() {
                    self.custom_exception = other.custom_exception;
                }

                if other.custom_result.is_some() {
                    self.custom_result = other.custom_result
                }

                if self.resp_content_length.is_none() {
                    self.resp_content_length = other.resp_content_length;
                }

                if other.is_resp_end {
                    self.is_resp_end = true;
                }
            }
            _ => {}
        }

        if other_is_grpc {
            self.proto = L7Protocol::Grpc;
        }
        if self.trace_id.is_empty() {
            self.trace_id = other.trace_id;
        }
        if self.span_id.is_empty() {
            self.span_id = other.span_id;
        }
        if self.x_request_id_0.is_empty() {
            self.x_request_id_0 = other.x_request_id_0.clone();
        }
        if self.x_request_id_1.is_empty() {
            self.x_request_id_1 = other.x_request_id_1.clone();
        }
        self.attributes.extend(other.attributes);
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        return self.host.is_empty()
            && self.method.is_empty()
            && self.path.is_empty()
            && self.status_code == None;
    }

    pub fn is_req_resp_end(&self) -> (bool, bool) {
        (self.is_req_end, self.is_resp_end)
    }

    pub fn get_l7_protocol_with_tls(&self) -> L7Protocol {
        match self.proto {
            L7Protocol::Http1 => {
                if self.is_tls {
                    L7Protocol::Http1TLS
                } else {
                    L7Protocol::Http1
                }
            }
            L7Protocol::Http2 => {
                if self.is_tls {
                    L7Protocol::Http2TLS
                } else {
                    L7Protocol::Http2
                }
            }

            L7Protocol::Grpc => L7Protocol::Grpc,
            _ => unreachable!(),
        }
    }

    fn is_grpc(&self) -> bool {
        self.proto == L7Protocol::Grpc
    }
    // grpc path: /packageName.Servicename/rcpMethodName
    // return packetName, ServiceName
    fn grpc_package_service_name(&self) -> Option<(String, String)> {
        if !self.is_grpc() || self.path.len() < 6 {
            return None;
        }

        let idx: Vec<_> = self.path.match_indices("/").collect();
        if idx.len() != 2 {
            return None;
        }
        let (start, end) = (idx[0].0, idx[1].0);
        if let Some((p, _)) = self.path.match_indices(".").next() {
            if p > start && p < end {
                return Some((
                    String::from(&self.path[start + 1..p]),
                    String::from(&self.path[p + 1..end]),
                ));
            }
        }
        None
    }
}

impl From<HttpInfo> for L7ProtocolSendLog {
    fn from(f: HttpInfo) -> Self {
        let is_grpc = f.is_grpc();
        let service_name = if let Some((package, service)) = f.grpc_package_service_name() {
            let svc_name = format!("{}.{}", package, service);
            Some(svc_name)
        } else {
            None
        };

        // grpc protocol special treatment
        let (req_type, resource, domain, endpoint) = if is_grpc {
            // server endpoint = req_type
            (
                String::from("POST"), // grpc method always post, reference https://chromium.googlesource.com/external/github.com/grpc/grpc/+/HEAD/doc/PROTOCOL-HTTP2.md
                service_name.clone().unwrap_or_default(),
                f.host,
                f.path,
            )
        } else {
            (
                f.method,
                f.path.clone(),
                f.host,
                f.custom_endpoint.unwrap_or_default(),
            )
        };

        L7ProtocolSendLog {
            req_len: f.req_content_length,
            resp_len: f.resp_content_length,
            version: Some(f.version),
            req: L7Request {
                req_type,
                resource,
                domain,
                endpoint,
            },
            resp: L7Response {
                status: f.status,
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
                request_id: f.stream_id,
                x_request_id_0: Some(f.x_request_id_0),
                x_request_id_1: Some(f.x_request_id_1),
                client_ip: Some(f.client_ip),
                user_agent: f.user_agent,
                referer: f.referer,
                rpc_service: service_name,
                attributes: {
                    if f.attributes.is_empty() {
                        None
                    } else {
                        Some(f.attributes)
                    }
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct HttpLog {
    proto: L7Protocol,
    perf_stats: Option<L7PerfStats>,
}

impl L7ProtocolParserInterface for HttpLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if param.l4_protocol != IpProtocol::TCP {
            return false;
        }

        let mut info = HttpInfo::default();

        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };
        // http2 有两个版本, 现在可以直接通过proto区分解析哪个版本的协议.
        match self.proto {
            L7Protocol::Http1 => self.http1_check_protocol(payload),
            L7Protocol::Http2 | L7Protocol::Grpc => {
                let Some(config) = param.parse_config else {
                    return false;
                };
                match param.ebpf_type {
                    EbpfType::GoHttp2Uprobe => self
                        .parse_http2_go_uprobe(&config.l7_log_dynamic, payload, param, &mut info)
                        .is_ok(),
                    _ => self.parse_http_v2(payload, param, &mut info).is_ok(),
                }
            }
            _ => unreachable!(),
        }
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        let Some(config) = param.parse_config else {
            return Err(Error::NoParseConfig);
        };

        let mut info = HttpInfo::default();
        info.proto = self.proto;
        info.is_tls = param.is_tls();

        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };

        match self.proto {
            L7Protocol::Http1 => {
                self.parse_http_v1(payload, param, &mut info)?;
                if param.parse_log {
                    self.wasm_hook(param, payload, &mut info);
                }
            }
            L7Protocol::Http2 | L7Protocol::Grpc => match param.ebpf_type {
                EbpfType::GoHttp2Uprobe => {
                    self.parse_http2_go_uprobe(&config.l7_log_dynamic, payload, param, &mut info)?;
                    if param.parse_log {
                        return Ok(L7ParseResult::Single(L7ProtocolInfo::HttpInfo(info)));
                    } else {
                        return Ok(L7ParseResult::None);
                    }
                }
                _ => self.parse_http_v2(payload, param, &mut info)?,
            },
            _ => unreachable!(),
        }
        if param.parse_log {
            Ok(L7ParseResult::Single(L7ProtocolInfo::HttpInfo(info)))
        } else {
            Ok(L7ParseResult::None)
        }
    }

    fn protocol(&self) -> L7Protocol {
        match self.proto {
            L7Protocol::Http1 => L7Protocol::Http1,

            L7Protocol::Http2 => L7Protocol::Http2,

            L7Protocol::Grpc => L7Protocol::Grpc,
            _ => unreachable!(),
        }
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn reset(&mut self) {
        let mut new_log = match self.proto {
            L7Protocol::Http1 => Self::new_v1(),
            L7Protocol::Http2 => Self::new_v2(false),
            L7Protocol::Grpc => Self::new_v2(true),
            _ => unreachable!(),
        };
        new_log.perf_stats = self.perf_stats.take();
        *self = new_log
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

impl HttpLog {
    pub const TRACE_ID: u8 = 0;
    pub const SPAN_ID: u8 = 1;

    pub fn new_v1() -> Self {
        Self {
            proto: L7Protocol::Http1,
            ..Default::default()
        }
    }

    pub fn new_v2(is_grpc: bool) -> Self {
        let l7_protcol = if is_grpc {
            L7Protocol::Grpc
        } else {
            L7Protocol::Http2
        };
        Self {
            proto: l7_protcol,
            ..Default::default()
        }
    }

    fn http1_check_protocol(&mut self, payload: &[u8]) -> bool {
        let mut headers = parse_v1_headers(payload);
        let Some(first_line) = headers.next() else {
            // request is not http v1 without '\r\n'
            return false;
        };

        is_http_req_line(first_line)
    }

    fn set_status(&mut self, status_code: u16, info: &mut HttpInfo) {
        if status_code >= HTTP_STATUS_CLIENT_ERROR_MIN
            && status_code <= HTTP_STATUS_CLIENT_ERROR_MAX
        {
            // http客户端请求存在错误
            self.perf_stats.as_mut().map(|p| p.inc_req_err());
            info.status = L7ResponseStatus::ClientError;
        } else if status_code >= HTTP_STATUS_SERVER_ERROR_MIN
            && status_code <= HTTP_STATUS_SERVER_ERROR_MAX
        {
            // http服务端响应存在错误
            self.perf_stats.as_mut().map(|p| p.inc_resp_err());
            info.status = L7ResponseStatus::ServerError;
        } else {
            info.status = L7ResponseStatus::Ok;
        }
    }

    // 解析由 ebpf probe 上报的自定义数据类型,小端编码,一次只带一个头.
    // +---------------------------------------------------------------+
    // |                          fd (32)                              |
    // +---------------------------------------------------------------+
    // |                          streadID (32)                        |
    // +---------------------------------------------------------------+
    // |                          keyLength (32)                       |
    // +---------------------------------------------------------------+
    // |                          valueLength (32)                     |
    // +---------------------------------------------------------------+
    // |                          key (keyLength,变长)               ...|
    // +---------------------------------------------------------------+
    // |                          value (valueLength,变长)           ...|
    // +---------------------------------------------------------------+
    pub fn parse_http2_go_uprobe(
        &mut self,
        config: &L7LogDynamicConfig,
        payload: &[u8],
        param: &ParseParam,
        info: &mut HttpInfo,
    ) -> Result<()> {
        if payload.len() < HTTPV2_CUSTOM_DATA_MIN_LENGTH {
            return Err(Error::HttpHeaderParseFailed);
        }
        let Some(p) = &param.ebpf_param else {
            return Err(Error::L7ProtocolUnknown);
        };

        (info.is_req_end, info.is_resp_end) = (p.is_req_end, p.is_resp_end);
        let direction = param.direction;

        let stream_id = read_u32_le(&payload[4..8]);
        let key_len = read_u32_le(&payload[8..12]) as usize;
        let val_len = read_u32_le(&payload[12..16]) as usize;
        if key_len + val_len + HTTPV2_CUSTOM_DATA_MIN_LENGTH != payload.len() {
            // 长度不够
            return Err(Error::HttpHeaderParseFailed);
        }

        info.raw_data_type = L7ProtoRawDataType::GoHttp2Uprobe; // 用于区分是否需要多段merge

        // adjuest msg type
        match direction {
            PacketDirection::ClientToServer => info.msg_type = LogMessageType::Request,
            PacketDirection::ServerToClient => info.msg_type = LogMessageType::Response,
        }

        let val_offset = HTTPV2_CUSTOM_DATA_MIN_LENGTH + key_len;
        let key = &payload[HTTPV2_CUSTOM_DATA_MIN_LENGTH..val_offset];
        let val = &payload[val_offset..val_offset + val_len];
        self.on_header(config, key, val, direction, info);
        if key == b"content-length" {
            info.req_content_length = Some(
                str::from_utf8(val)
                    .unwrap_or_default()
                    .parse::<u32>()
                    .unwrap_or_default(),
            );
        }

        if info.is_req_end {
            self.perf_stats.as_mut().map(|p| p.inc_req());
        }
        if info.is_resp_end {
            self.perf_stats.as_mut().map(|p| p.inc_resp());
        }

        info.version = String::from("2");
        info.stream_id = Some(stream_id);

        info.cal_rrt_for_multi_merge_log(param).map(|rrt| {
            info.rrt = rrt;
        });

        if info.is_req_end || info.is_resp_end {
            self.perf_stats.as_mut().map(|p| p.update_rrt(info.rrt));
        }
        return Ok(());
    }

    pub fn parse_http_v1(
        &mut self,
        payload: &[u8],
        param: &ParseParam,
        info: &mut HttpInfo,
    ) -> Result<()> {
        let (direction, config) = (
            param.direction,
            &param.parse_config.as_ref().unwrap().l7_log_dynamic,
        );
        if !is_http_v1_payload(payload) {
            return Err(Error::HttpHeaderParseFailed);
        }

        let mut headers = parse_v1_headers(payload);
        let Some(first_line) = headers.next() else {
            return Err(Error::HttpHeaderParseFailed);
        };

        if direction == PacketDirection::ServerToClient {
            // HTTP响应行：HTTP/1.1 404 Not Found.
            let (version, status_code) = get_http_resp_info(first_line)?;

            info.version = version.to_owned();
            info.status_code = Some(status_code as i32);

            info.msg_type = LogMessageType::Response;

            self.perf_stats.as_mut().map(|p| p.inc_resp());
            self.set_status(status_code, info);
        } else {
            // HTTP请求行：GET /background.png HTTP/1.0
            let Ok((method, path, version)) = get_http_request_info(first_line) else {
                return Err(Error::HttpHeaderParseFailed);
            };

            info.method = method.to_owned();
            info.path = path.to_owned();
            info.version = get_http_request_version(version)?.to_owned();

            info.msg_type = LogMessageType::Request;
            self.perf_stats.as_mut().map(|p| p.inc_req());
        }

        info.cal_rrt(param, None).map(|rrt| {
            info.rrt = rrt;
            self.perf_stats.as_mut().map(|p| p.update_rrt(rrt));
        });

        if !param.parse_log {
            return Ok(());
        }
        let mut content_length: Option<u32> = None;
        for body_line in headers {
            let col_index = body_line.find(':');
            if col_index.is_none() {
                continue;
            }
            let col_index = col_index.unwrap();
            if col_index + 1 >= body_line.len() {
                continue;
            }

            let key = &body_line[..col_index];
            let value = &body_line[col_index + 1..];

            let lower_key = key.to_ascii_lowercase();
            self.on_header(
                config,
                lower_key.as_bytes(),
                value.trim().as_bytes(),
                direction,
                info,
            );
            if &lower_key == "content-length" {
                content_length = Some(value.trim_start().parse::<u32>().unwrap_or_default());
            }
        }

        // 当解析完所有Header仍未找到Content-Length，则认为该字段值为0
        if direction == PacketDirection::ServerToClient {
            info.resp_content_length = content_length;
        } else {
            info.req_content_length = content_length;
        }
        Ok(())
    }

    fn has_magic(payload: &[u8]) -> bool {
        if payload.len() < HTTPV2_MAGIC_LENGTH {
            return false;
        }
        &payload[..HTTPV2_MAGIC_PREFIX.len()] == HTTPV2_MAGIC_PREFIX.as_bytes()
    }

    fn parse_http_v2(
        &mut self,
        payload: &[u8],
        param: &ParseParam,
        info: &mut HttpInfo,
    ) -> Result<()> {
        let (direction, config) = (
            param.direction,
            &param.parse_config.as_ref().unwrap().l7_log_dynamic,
        );
        let mut content_length: Option<u32> = None;
        let mut header_frame_parsed = false;
        let mut is_httpv2 = false;
        let mut frame_payload = payload;
        let mut httpv2_header = Httpv2Headers::default();

        while frame_payload.len() > HTTPV2_FRAME_HEADER_LENGTH {
            if Self::has_magic(frame_payload) {
                frame_payload = &frame_payload[HTTPV2_MAGIC_LENGTH..];
                continue;
            }
            if httpv2_header.parse_headers_frame(frame_payload).is_err() {
                // 当已经解析了Headers帧(该Headers帧未携带“Content-Length”)且发现该报文被截断时，无法进行后续解析，ContentLength为None
                if header_frame_parsed {
                    info.stream_id = Some(httpv2_header.stream_id);
                    is_httpv2 = true
                }
                break;
            }

            frame_payload = &frame_payload[HTTPV2_FRAME_HEADER_LENGTH..];

            if !header_frame_parsed && httpv2_header.frame_type == HTTPV2_FRAME_HEADERS_TYPE {
                if httpv2_header.stream_id == 0 {
                    // Headers帧的StreamId不为0
                    // 参考协议：https://tools.ietf.org/html/rfc7540#section-6.2
                    break;
                }

                let mut l_offset = 0;
                if httpv2_header.flags & FLAG_HEADERS_PADDED != 0 {
                    if httpv2_header.frame_length <= frame_payload[0] as u32 {
                        break;
                    }
                    httpv2_header.frame_length -= frame_payload[0] as u32;
                    l_offset += 1;
                }
                if httpv2_header.flags & FLAG_HEADERS_PRIORITY != 0 {
                    l_offset += 5;
                }
                if l_offset >= httpv2_header.frame_length
                    || httpv2_header.frame_length > frame_payload.len() as u32
                {
                    break;
                }

                let header_frame_payload =
                    &frame_payload[l_offset as usize..httpv2_header.frame_length as usize];

                let mut parser = h2pack::parser::Parser::new();
                let parse_rst = parser.parse(header_frame_payload);

                if let Err(_) = parse_rst {
                    return Err(Error::HttpHeaderParseFailed);
                }
                let header_list = parse_rst.unwrap();

                for (key, val) in header_list.iter() {
                    self.on_header(config, key, val, direction, info);
                    if key == b"content-length" {
                        content_length = Some(
                            str::from_utf8(val.as_slice())
                                .unwrap_or_default()
                                .parse::<u32>()
                                .unwrap_or_default(),
                        )
                    }
                }
                header_frame_parsed = true;
                if content_length.is_some() {
                    is_httpv2 = true;
                    break;
                }
            } else if header_frame_parsed && httpv2_header.frame_type == HTTPV2_FRAME_DATA_TYPE {
                if httpv2_header.stream_id == 0 {
                    // Data帧的StreamId不为0
                    // 参考协议：https://tools.ietf.org/html/rfc7540#section-6.1
                    break;
                }
                // HTTPv2协议中存在可以通过Headers帧中携带“Content-Length”字段，即可直接进行解析
                // 若未在Headers帧中携带，则去解析Headers帧后的Data帧的数据长度以进行“Content-Length”解析
                // 如grpc-go源码中，在封装FrameHeader头时，不封装“Content-Length”，需要解析其关联的Data帧进行“Content-Length”解析
                // 参考：https://github.com/grpc/grpc-go/blob/master/internal/transport/handler_server.go#L246
                content_length = Some(httpv2_header.frame_length);
                if httpv2_header.flags & FLAG_HEADERS_PADDED != 0 {
                    if content_length.unwrap_or_default() > frame_payload[0] as u32 {
                        content_length =
                            Some(content_length.unwrap_or_default() - frame_payload[0] as u32);
                    }
                }
                break;
            }

            if httpv2_header.stream_id > 0 {
                info.stream_id = Some(httpv2_header.stream_id);
            }
            if httpv2_header.frame_length >= frame_payload.len() as u32 {
                break;
            }
            frame_payload = &frame_payload[httpv2_header.frame_length as usize..];
        }
        // 流量中可能仅存在Headers帧且Headers帧中没有传输实体，“Content-Length”为0
        if header_frame_parsed && !is_httpv2 {
            if !content_length.is_some() {
                content_length = Some(0);
            }
            is_httpv2 = true;
        }

        if is_httpv2 {
            if direction == PacketDirection::ClientToServer {
                if check_http_method(&info.method).is_err() {
                    return Err(Error::HttpHeaderParseFailed);
                }
                self.perf_stats.as_mut().map(|p| p.inc_req());
                info.req_content_length = content_length;
            } else {
                if let Some(code) = info.status_code {
                    let code = code as u16;
                    if code < HTTP_STATUS_CODE_MIN || code > HTTP_STATUS_CODE_MAX {
                        return Err(Error::HttpHeaderParseFailed);
                    }
                } else {
                    return Err(Error::HttpHeaderParseFailed);
                }
                self.perf_stats.as_mut().map(|p| p.inc_resp());
                info.resp_content_length = content_length;
            }
            info.version = String::from("2");
            if info.stream_id.is_none() {
                info.stream_id = Some(httpv2_header.stream_id);
            }
            info.cal_rrt(param, None).map(|rrt| {
                info.rrt = rrt;
                self.perf_stats.as_mut().map(|p| p.update_rrt(rrt));
            });
            return Ok(());
        }
        Err(Error::HttpHeaderParseFailed)
    }

    fn on_header(
        &mut self,
        config: &L7LogDynamicConfig,
        key: &[u8],
        val: &[u8],
        direction: PacketDirection,
        info: &mut HttpInfo,
    ) {
        // key must be valid utf8
        let Ok(key) = str::from_utf8(key) else {
            return;
        };

        match key {
            ":method" => {
                info.msg_type = LogMessageType::Request;
                info.method = String::from_utf8_lossy(val).into_owned();
            }
            ":status" => {
                info.msg_type = LogMessageType::Response;
                let code = str::from_utf8(val)
                    .unwrap_or_default()
                    .parse::<u16>()
                    .unwrap_or_default();
                info.status_code = Some(code as i32);
                self.set_status(code, info);
            }
            "host" | ":authority" => info.host = String::from_utf8_lossy(val).into_owned(),
            ":path" => info.path = String::from_utf8_lossy(val).into_owned(),
            "content-type" => {
                // change to grpc protocol
                if val.starts_with(b"application/grpc") {
                    self.proto = L7Protocol::Grpc;
                    info.proto = L7Protocol::Grpc;
                }
            }
            "user-agent" => info.user_agent = Some(String::from_utf8_lossy(val).into_owned()),
            "referer" => info.referer = Some(String::from_utf8_lossy(val).into_owned()),
            _ => {}
        }

        if !key.is_ascii() {
            return;
        }

        // value must be valid utf8 from here
        let Ok(val) = str::from_utf8(val) else {
            return;
        };

        if config.is_trace_id(key) {
            if let Some(id) = Self::decode_id(val, key, Self::TRACE_ID) {
                info.trace_id = id;
            }
        }
        if config.is_span_id(key) {
            if let Some(id) = Self::decode_id(val, key, Self::SPAN_ID) {
                info.span_id = id;
            }
        }
        if config.x_request_id.contains(key) {
            if direction == PacketDirection::ClientToServer {
                info.x_request_id_0 = val.to_owned();
            } else {
                info.x_request_id_1 = val.to_owned();
            }
        }
        if direction == PacketDirection::ClientToServer && key == &config.proxy_client {
            info.client_ip = val.to_owned();
        }
    }

    // uber-trace-id: TRACEID:SPANID:PARENTSPANID:FLAGS
    // 使用':'分隔，第一个字段为TRACEID，第三个字段为SPANID
    fn decode_uber_id(value: &str, id_type: u8) -> Option<String> {
        let segs = value.split(":");
        let mut i = 0;
        for seg in segs {
            if id_type == Self::TRACE_ID && i == 0 {
                return Some(seg.to_string());
            }
            if id_type == Self::SPAN_ID && i == 2 {
                return Some(seg.to_string());
            }

            i += 1;
        }
        None
    }

    // sw6: 1-TRACEID-SEGMENTID-3-5-2-IPPORT-ENTRYURI-PARENTURI
    // sw8: 1-TRACEID-SEGMENTID-3-PARENT_SERVICE-PARENT_INSTANCE-PARENT_ENDPOINT-IPPORT
    // sw6和sw8的value全部使用'-'分隔，TRACEID前为SAMPLE字段取值范围仅有0或1
    // 提取`TRACEID`展示为HTTP日志中的`TraceID`字段
    // 提取`SEGMENTID-SPANID`展示为HTTP日志中的`SpanID`字段
    fn decode_skywalking_id(value: &str, id_type: u8) -> Option<String> {
        let segs: Vec<&str> = value.split("-").collect();

        if id_type == Self::TRACE_ID && segs.len() > 2 {
            return Some(decode_base64_to_string(segs[1]));
        }
        if id_type == Self::SPAN_ID && segs.len() > 4 {
            return Some(format!("{}-{}", decode_base64_to_string(segs[2]), segs[3]));
        }

        None
    }

    // OTel HTTP Trace format:
    // traceparent: 00-TRACEID-SPANID-01
    fn decode_traceparent(value: &str, id_type: u8) -> Option<String> {
        let segs = value.split("-");
        let mut i = 0;
        for seg in segs {
            if id_type == Self::TRACE_ID && i == 1 {
                return Some(seg.to_string());
            }
            if id_type == Self::SPAN_ID && i == 2 {
                return Some(seg.to_string());
            }

            i += 1;
        }
        None
    }

    fn decode_tingyun(value: &str, id_type: u8) -> Option<String> {
        if id_type != Self::TRACE_ID {
            return None;
        }
        tingyun::decode_trace_id(value)
    }

    pub fn decode_id(payload: &str, trace_key: &str, id_type: u8) -> Option<String> {
        let trace_type = TraceType::from(trace_key);
        match trace_type {
            TraceType::Disabled | TraceType::XB3 | TraceType::XB3Span | TraceType::Customize(_) => {
                Some(payload.to_owned())
            }
            TraceType::Uber => Self::decode_uber_id(payload, id_type),
            TraceType::Sw6 | TraceType::Sw8 => Self::decode_skywalking_id(payload, id_type),
            TraceType::TraceParent => Self::decode_traceparent(payload, id_type),
            TraceType::NewRpcTraceContext => {
                /*
                    referer https://github.com/sofastack/sofa-rpc/blob/7931102255d6ea95ee75676d368aad37c56b57ee/tracer/tracer-opentracing-resteasy/src/main/java/com/alipay/sofa/rpc/tracer/sofatracer/RestTracerAdapter.java#L75
                    in new version of sofarpc, use new_rpc_trace_context header store trace info
                */
                decode_new_rpc_trace_context_with_type(payload.as_bytes(), id_type)
            }
            TraceType::XTingyun => Self::decode_tingyun(payload, id_type),
        }
    }

    fn wasm_hook(&mut self, param: &ParseParam, payload: &[u8], info: &mut HttpInfo) {
        let Some(vm) = param.wasm_vm.as_ref() else {
            return;
        };
        let mut vm = vm.borrow_mut();
        match param.direction {
            PacketDirection::ClientToServer => vm.on_http_req(payload, param, info),
            PacketDirection::ServerToClient => vm.on_http_resp(payload, param, info),
        }
        .map(|custom| {
            info.merge_custom_to_http1(custom);
        });
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct Httpv2Headers {
    pub frame_length: u32,
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: u32,
}

impl Httpv2Headers {
    // HTTPv2帧头格式:https://tools.ietf.org/html/rfc7540#section-4.1
    // +-----------------------------------------------+
    // |                 Length (24)                   |
    // +---------------+---------------+---------------+
    // |   Type (8)    |   Flags (8)   |
    // +-+-------------+---------------+-------------------------------+
    // |R|                 Stream Identifier (31)                      |
    // +=+=============================================================+
    // |                   Frame Payload (0...)                      ...
    // +---------------------------------------------------------------+
    pub fn parse_headers_frame(&mut self, payload: &[u8]) -> Result<()> {
        let frame_type = payload[3];
        if frame_type < HTTPV2_FRAME_TYPE_MIN || frame_type > HTTPV2_FRAME_TYPE_MAX {
            return Err(Error::HttpHeaderParseFailed);
        }

        if payload[5] & 0x80 != 0 {
            return Err(Error::HttpHeaderParseFailed);
        }

        self.frame_length = read_u32_be(&payload) >> 8;
        self.frame_type = frame_type;
        self.flags = payload[4];
        self.stream_id = read_u32_be(&payload[5..]);

        Ok(())
    }
}

const HTTP_METHODS: [&'static str; 15] = [
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "OPTIONS",
    "HEAD",
    "TRACE",
    "CONNECT",
    "PATCH",
    "LINK",
    "UNLINK",
    "COPY",
    "MOVE",
    "WRAPPED",
    "EXTENSION-METHOD",
];
const RESPONSE_PREFIX: &'static str = "HTTP/";

pub fn is_http_v1_payload(buf: &[u8]) -> bool {
    if buf.starts_with(RESPONSE_PREFIX.as_bytes()) {
        return true;
    }
    for m in HTTP_METHODS {
        if buf.starts_with(m.as_bytes()) {
            return true;
        }
    }
    false
}

// check first line is http request line
pub fn is_http_req_line(line: &str) -> bool {
    if line.len() < "GET / HTTP/1.1".len() {
        return false;
    }

    // consider use prefix tree in future
    for i in HTTP_METHODS.iter() {
        if line.starts_with(i) {
            let end = &line[line.len() - 8..];
            match end {
                "HTTP/0.9" | "HTTP/1.0" | "HTTP/1.1" => return true,
                _ => return false,
            }
        }
    }
    false
}

// 参考：https://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html
pub fn check_http_method(method: &str) -> Result<()> {
    match method {
        "OPTIONS" | "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "TRACE" | "CONNECT" | "PATCH" => {
            Ok(())
        }
        _ => Err(Error::HttpHeaderParseFailed),
    }
}

pub fn get_http_request_version(version: &str) -> Result<&str> {
    // 参考：https://baike.baidu.com/item/HTTP/243074?fr=aladdin#2
    // HTTPv1版本只有1.0及1.1
    match version {
        HTTP_V1_0_VERSION => return Ok("1.0"),
        HTTP_V1_1_VERSION => return Ok("1.1"),
        _ => return Err(Error::HttpHeaderParseFailed),
    }
}

pub fn get_http_request_info(line_info: &str) -> Result<(&str, &str, &str)> {
    let line_info = line_info.as_bytes();
    let mut iter = line_info.splitn(3, |c| c.is_ascii_whitespace());
    let method = iter.next();
    let path = iter.next();
    let version = iter.next();
    if version.is_none() {
        return Err(Error::HttpHeaderParseFailed);
    }
    unsafe {
        // safe because line_info is utf8
        Ok((
            str::from_utf8_unchecked(method.unwrap()),
            str::from_utf8_unchecked(path.unwrap()),
            str::from_utf8_unchecked(version.unwrap()),
        ))
    }
}

pub fn get_http_resp_info(line_info: &str) -> Result<(&str, u16)> {
    const VERSION_LEN: usize = HTTP_V1_0_VERSION.len();
    const CODE_OFFSET: usize = VERSION_LEN + 1;
    const CODE_LEN: usize = 3;
    if line_info.len() < HTTP_RESP_MIN_LEN || !line_info.is_ascii() {
        return Err(Error::HttpHeaderParseFailed);
    }
    // HTTP response line: HTTP/1.1 404 Not Found.
    let version = match &line_info[..VERSION_LEN] {
        HTTP_V1_0_VERSION => "1.0",
        HTTP_V1_1_VERSION => "1.1",
        _ => return Err(Error::HttpHeaderParseFailed),
    };

    // response code validating
    // ref: https://baike.baidu.com/item/HTTP%E7%8A%B6%E6%80%81%E7%A0%81/5053660?fr=aladdin
    let Ok(status_code) = (&line_info[CODE_OFFSET..CODE_OFFSET + CODE_LEN]).parse::<u16>() else {
        return Err(Error::HttpHeaderParseFailed);
    };

    if status_code < HTTP_STATUS_CODE_MIN || status_code > HTTP_STATUS_CODE_MAX {
        return Err(Error::HttpHeaderParseFailed);
    }
    Ok((version, status_code))
}

pub struct V1HeaderIterator<'a>(&'a [u8]);

impl<'a> Iterator for V1HeaderIterator<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.len() < 2 {
            return None;
        }
        const SEP: &'static str = "\r\n";
        let mut end = 0;
        loop {
            // handle the case len is odd (such as "HTTP/1.0 200 OK\r\n" where encounter in istio),
            if end == self.0.len() - 1
                && self.0[end] == b'\n'
                && end >= 1
                && self.0[end - 1] == b'\r'
            {
                end -= 1;
                break;
            }

            if end + SEP.len() > self.0.len() {
                return None;
            }
            match &self.0[end] {
                b'\r' if self.0[end + 1] == b'\n' => break,
                b'\n' if end >= 1 && self.0[end - 1] == b'\r' => {
                    end -= 1;
                    break;
                }
                c if !c.is_ascii() => return None,
                _ => (),
            }
            // the length of SEP is 2 so step 2 is ok
            end += 2;
        }
        if end == 0 {
            None
        } else {
            let result = unsafe {
                // this is safe because all bytes are checked to be ascii
                str::from_utf8_unchecked(&self.0[..end])
            };
            self.0 = &self.0[end + 2..];
            Some(result)
        }
    }
}

pub fn parse_v1_headers(payload: &[u8]) -> V1HeaderIterator<'_> {
    V1HeaderIterator(payload)
}

#[cfg(test)]
mod tests {
    use crate::common::l7_protocol_log::{EbpfParam, L7PerfCache};
    use crate::common::MetaPacket;
    use crate::config::handler::LogParserConfig;
    use crate::flow_generator::L7_RRT_CACHE_CAPACITY;
    use crate::utils::test::Capture;

    use std::cell::RefCell;
    use std::collections::HashSet;
    use std::fs;
    use std::mem::size_of;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::Path;
    use std::rc::Rc;
    use std::slice::from_raw_parts;
    use std::time::Duration;

    use super::*;

    const FILE_DIR: &str = "resources/test/flow_generator/http";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name), Some(1500));
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
        let config = L7LogDynamicConfig::new(
            "".to_owned(),
            vec![],
            vec![TraceType::Sw8],
            vec![TraceType::Sw8],
        );
        let parse_config = &LogParserConfig {
            l7_log_collect_nps_threshold: 10,
            l7_log_session_aggr_timeout: Duration::from_secs(10),
            l7_log_dynamic: config,
            ..Default::default()
        };
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

            let mut trace_set = HashSet::new();
            trace_set.insert(TraceType::Sw8.to_checker_string());
            let mut span_set = HashSet::new();
            span_set.insert(TraceType::Sw8.to_checker_string());
            let mut http1 = HttpLog::new_v1();
            let mut http2 = HttpLog::new_v2(false);
            let param = &mut ParseParam::new(packet as &MetaPacket, log_cache.clone(), true, true);
            param.set_log_parse_config(parse_config);

            let get_http_info = |i: L7ProtocolInfo| match i {
                L7ProtocolInfo::HttpInfo(mut h) => {
                    h.rrt = 0;
                    h
                }
                _ => unreachable!(),
            };

            if let Ok(info) = http1.parse_payload(payload, param) {
                output.push_str(&format!(
                    "{:?} is_http: {}\n",
                    get_http_info(info.unwrap_single()),
                    true
                ));
            } else if let Ok(info) = http2.parse_payload(payload, param) {
                output.push_str(&format!(
                    "{:?} is_http: {}\n",
                    get_http_info(info.unwrap_single()),
                    true
                ));
            } else {
                let mut info = HttpInfo::default();
                info.proto = http1.proto;
                output.push_str(&format!("{:?} is_http: {}\n", info, false));
            }
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
            ("httpv1.pcap", "httpv1.result"),
            ("sw8.pcap", "sw8.result"),
            ("h2c_ascii.pcap", "h2c_ascii.result"),
            ("httpv2-stream-id.pcap", "httpv2-stream-id.result"),
            ("istio-tcp-frag.pcap", "istio-tcp-frag.result"),
        ];
        for item in files.iter() {
            let expected = fs::read_to_string(&Path::new(FILE_DIR).join(item.1)).unwrap();
            let output = run(item.0);

            if output != expected {
                let output_path = Path::new("actual.txt");
                fs::write(&output_path, &output).unwrap();
                assert!(
                    output == expected,
                    "output different from expected {}, written to {:?}",
                    item.1,
                    output_path
                );
            }
        }
    }

    #[test]
    fn test_go_uprobe() {
        #[derive(Debug)]
        struct H2CustomHdr {
            fd: u32,
            stream_id: u32,
            k_len: u32,
            v_len: u32,
        }
        impl H2CustomHdr {
            fn to_bytes(self, key: &str, val: &str) -> Vec<u8> {
                let hdr_p;
                unsafe {
                    hdr_p = from_raw_parts(&self as *const Self as *const u8, size_of::<Self>());
                }
                return [hdr_p, key.as_bytes(), val.as_bytes()].concat();
            }
        }
        let conf = LogParserConfig::default();
        let param = &ParseParam {
            l4_protocol: IpProtocol::TCP,
            ip_src: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            ip_dst: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port_src: 0,
            port_dst: 0,
            flow_id: 0,
            direction: PacketDirection::ClientToServer,
            ebpf_type: EbpfType::GoHttp2Uprobe,
            ebpf_param: Some(EbpfParam {
                is_tls: false,
                is_req_end: false,
                is_resp_end: false,
                process_kname: "".to_string(),
            }),
            packet_seq: 0,
            time: 0,
            parse_perf: true,
            parse_log: true,
            parse_config: Some(&conf),
            l7_perf_cache: Rc::new(RefCell::new(L7PerfCache::new(1))),
            wasm_vm: None,
            #[cfg(target_os = "linux")]
            so_func: None,
            #[cfg(target_os = "linux")]
            so_plugin_counter_map: None,
            stats_counter: None,
            rrt_timeout: Duration::from_secs(10).as_micros() as usize,
            buf_size: 0,
        };

        //测试长度不正确
        {
            for i in 1..3 {
                let key = "asd";
                let val = "asd";
                let key_len: u32 = key.len() as u32 + (i - 1) % 2;
                let val_len: u32 = val.len() as u32 + i % 2;
                let hdr = H2CustomHdr {
                    fd: 1,
                    stream_id: 1,
                    k_len: key_len,
                    v_len: val_len,
                };
                let payload = hdr.to_bytes(key, val);
                let mut h = HttpLog::new_v2(false);
                let mut info = HttpInfo::default();
                info.raw_data_type = L7ProtoRawDataType::GoHttp2Uprobe;
                let res = h.parse_http2_go_uprobe(
                    &L7LogDynamicConfig::default(),
                    &payload,
                    param,
                    &mut info,
                );
                assert_eq!(res.is_ok(), false);
                println!("{:#?}", res.err().unwrap());
            }
        }
        let headers = [
            ("content-length", "55"),
            ("content-length", "dd"),
            (":method", "GET"),
            (":status", "202"),
            (":path", "/asd"),
            ("host", "a.com"),
            ("aaa", "bbb"),
            ("ccc", "ddd"),
        ];
        for (key, val) in headers {
            println!("-----------------------------------");
            println!("{}:{}", key, val);
            let key_len: u32 = key.len() as u32;
            let val_len: u32 = val.len() as u32;
            let hdr = H2CustomHdr {
                fd: 1,
                stream_id: 1,
                k_len: key_len,
                v_len: val_len,
            };
            let mut info = HttpInfo::default();
            let payload = hdr.to_bytes(key, val);
            let mut h = HttpLog::new_v2(false);
            info.raw_data_type = L7ProtoRawDataType::GoHttp2Uprobe;
            let res =
                h.parse_http2_go_uprobe(&L7LogDynamicConfig::default(), &payload, param, &mut info);
            assert_eq!(res.is_ok(), true);
            println!("{:#?}", info);
        }
    }

    #[test]
    fn test_one_line_resp() {
        let testcases = vec![
            "HTTP/1.0 200 OK\r\n",
            "HTTP/1.0 200 OK\r\n\r\n",
            "HTT\n\rP/1.0 200 OK\r\n",
            "HTT\n\rP/1.0 200\r OK",
            "HTT\n\rP/1.0 200\n OK",
            "\r\n",
            "\r\n\r",
            "\n\r",
        ];
        let mut iter = parse_v1_headers(testcases[0].as_bytes());
        assert_eq!("HTTP/1.0 200 OK", iter.next().unwrap());
        assert_eq!(None, iter.next());

        let mut iter = parse_v1_headers(testcases[1].as_bytes());
        assert_eq!("HTTP/1.0 200 OK", iter.next().unwrap());
        assert_eq!(None, iter.next());

        let mut iter = parse_v1_headers(testcases[2].as_bytes());
        assert_eq!("HTT\n\rP/1.0 200 OK", iter.next().unwrap());
        assert_eq!(None, iter.next());

        for expected in &testcases[3..] {
            let mut iter = parse_v1_headers(expected.as_bytes());
            assert_eq!(None, iter.next());
        }
    }

    #[test]
    fn get_http_v1_header_from_payload() {
        let testcases = vec![
            vec![
                "POST /query?1590632942 HTTP/1.1",
                "Host: rq.cct.cloud.duba.net",
                "Accept: */*",
                "Content-Length: 85",
                "Content-Type: application/x-www-form-urlencoded",
            ],
            vec!["aaaa\rbbb", "ccc", "\rddd"],
            vec![],
        ];
        for expected in testcases {
            let mut payload = expected.join("\r\n").as_bytes().to_owned();
            payload.extend("\r\n\r\n".as_bytes());
            // add some garbage
            payload.extend(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
            let mut iter = parse_v1_headers(&payload);
            for h in expected {
                assert_eq!(h, iter.next().unwrap());
            }
            assert_eq!(None, iter.next());
        }
    }

    #[test]
    fn check_perf() {
        let expected = vec![
            (
                "httpv1.pcap",
                L7PerfStats {
                    request_count: 1,
                    response_count: 1,
                    err_client_count: 0,
                    err_server_count: 0,
                    err_timeout: 0,
                    rrt_count: 1,
                    rrt_sum: 84051,
                    rrt_max: 84051,
                },
            ),
            (
                "h2c_ascii.pcap",
                L7PerfStats {
                    request_count: 1,
                    response_count: 1,
                    err_client_count: 0,
                    err_server_count: 0,
                    err_timeout: 0,
                    rrt_count: 1,
                    rrt_sum: 2023,
                    rrt_max: 2023,
                },
            ),
        ];

        assert_eq!(
            expected[0].1,
            run_perf(expected[0].0, HttpLog::new_v1()),
            "parse pcap {} unexcepted",
            expected[0].0
        );
        assert_eq!(
            expected[1].1,
            run_perf(expected[1].0, HttpLog::new_v2(false)),
            "parse pcap {} unexcepted",
            expected[1].0
        );
    }

    fn run_perf(pcap: &str, mut http: HttpLog) -> L7PerfStats {
        let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));

        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(pcap), Some(512));
        let mut packets = capture.as_meta_packets();

        let first_dst_port = packets[0].lookup_key.dst_port;

        let config = LogParserConfig::default();

        for packet in packets.iter_mut() {
            if packet.lookup_key.dst_port == first_dst_port {
                packet.lookup_key.direction = PacketDirection::ClientToServer;
            } else {
                packet.lookup_key.direction = PacketDirection::ServerToClient;
            }
            if packet.get_l4_payload().is_some() {
                let param = &mut ParseParam::new(&*packet, rrt_cache.clone(), true, true);
                param.set_log_parse_config(&config);
                let _ = http.parse_payload(packet.get_l4_payload().unwrap(), param);
            }
        }
        http.perf_stats.unwrap()
    }
}
