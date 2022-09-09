/*
 * Copyright (c) 2022 Yunshan Networks
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

use arc_swap::access::Access;
use log::info;
use regex::Regex;
use serde::Serialize;

use super::pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response, TraceInfo};
use super::value_is_default;
use super::{consts::*, AppProtoHead, AppProtoLogsInfo, L7LogParse, L7ResponseStatus};
use super::{AppProtoHeadEnum, AppProtoLogsInfoEnum, LogMessageType};

use crate::common::enums::{IpProtocol, PacketDirection};
use crate::common::flow::L7Protocol;
use crate::common::meta_packet::MetaPacket;
use crate::config::handler::{L7LogDynamicConfig, LogParserAccess, TraceType};
use crate::flow_generator::error::{Error, Result};
use crate::utils::bytes::read_u32_be;
use crate::utils::net::h2pack;

#[derive(Serialize, Debug, Default, Clone)]
pub struct HttpInfo {
    #[serde(rename = "request_id", skip_serializing_if = "value_is_default")]
    pub stream_id: u32,
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
    #[serde(rename = "http_proxy_client", skip_serializing_if = "value_is_default")]
    pub client_ip: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub x_request_id: String,

    #[serde(rename = "request_length", skip_serializing_if = "Option::is_none")]
    pub req_content_length: Option<u64>,
    #[serde(rename = "response_length", skip_serializing_if = "Option::is_none")]
    pub resp_content_length: Option<u64>,

    status_code: u16,
    status: L7ResponseStatus,
}

impl HttpInfo {
    pub fn merge(&mut self, other: Self) {
        self.resp_content_length = other.resp_content_length;
        if self.trace_id.is_empty() {
            self.trace_id = other.trace_id;
        }
        if self.span_id.is_empty() {
            self.span_id = other.span_id;
        }
        if self.x_request_id.is_empty() {
            self.x_request_id = other.x_request_id;
        }
        if other.status != L7ResponseStatus::default() {
            self.status = other.status;
        }
        if other.status_code != 0 {
            self.status_code = other.status_code;
        }
    }
}

impl From<HttpInfo> for L7ProtocolSendLog {
    fn from(f: HttpInfo) -> Self {
        let mut log = L7ProtocolSendLog {
            version: Some(f.version),
            req: L7Request {
                req_type: f.method,
                resource: f.path,
                domain: f.host,
            },
            resp: L7Response {
                status: f.status,
                code: f.status_code as i32,
                ..Default::default()
            },
            trace_info: Some(TraceInfo {
                trace_id: Some(f.trace_id),
                span_id: Some(f.span_id),
                ..Default::default()
            }),
            ext_info: Some(ExtendedInfo {
                request_id: Some(f.stream_id),
                x_request_id: Some(f.x_request_id),
                client_ip: Some(f.client_ip),
                ..Default::default()
            }),
            ..Default::default()
        };
        if let Some(l) = f.req_content_length {
            log.req_len = l as u32;
        }
        if let Some(l) = f.resp_content_length {
            log.resp_len = l as u32;
        }

        return log;
    }
}

#[derive(Clone, Debug, Default)]
pub struct HttpLog {
    msg_type: LogMessageType,
    proto: L7Protocol,

    info: HttpInfo,

    is_https: bool,

    l7_log_dynamic_config: L7LogDynamicConfig,
}

fn parse_lines(payload: &[u8], limit: usize) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut p = payload;
    while lines.len() < limit {
        let mut next_index = None;
        for (i, c) in p.iter().enumerate() {
            if i > 2 && *c == b'\n' && p[i - 1] == b'\r' {
                lines.push(&p[0..i - 1]);
                next_index = Some(i + 1);
                break;
            }
        }
        match next_index {
            None => return lines,
            Some(i) if i >= p.len() => return lines,
            Some(i) => p = &p[i..],
        }
    }
    return lines;
}

impl HttpLog {
    const TRACE_ID: u8 = 0;
    const SPAN_ID: u8 = 1;

    pub fn new(config: &LogParserAccess, is_https: bool) -> Self {
        Self {
            l7_log_dynamic_config: config.load().l7_log_dynamic.clone(),
            is_https,
            ..Default::default()
        }
    }

    fn get_l7_protocol(&self) -> L7Protocol {
        match self.proto {
            L7Protocol::Http1 => {
                if self.is_https {
                    L7Protocol::Http1TLS
                } else {
                    L7Protocol::Http1
                }
            }
            L7Protocol::Http2 => {
                if self.is_https {
                    L7Protocol::Http2TLS
                } else {
                    L7Protocol::Http2
                }
            }
            _ => L7Protocol::Unknown,
        }
    }

    pub fn update_config(&mut self, config: &LogParserAccess) {
        self.l7_log_dynamic_config = config.load().l7_log_dynamic.clone();
        info!(
            "http log update l7 log dynamic config to {:#?}",
            self.l7_log_dynamic_config
        );
    }

    fn reset_logs(&mut self) {
        self.info.status_code = 0;
        self.info = HttpInfo::default();
    }

    fn set_status(&mut self, status_code: u16) {
        if status_code >= HTTP_STATUS_CLIENT_ERROR_MIN
            && status_code <= HTTP_STATUS_CLIENT_ERROR_MAX
        {
            // http客户端请求存在错误
            self.info.status = L7ResponseStatus::ClientError;
        } else if status_code >= HTTP_STATUS_SERVER_ERROR_MIN
            && status_code <= HTTP_STATUS_SERVER_ERROR_MAX
        {
            // http服务端响应存在错误
            self.info.status = L7ResponseStatus::ServerError;
        } else {
            self.info.status = L7ResponseStatus::Ok;
        }
    }

    fn parse_http_v1(&mut self, payload: &[u8], direction: PacketDirection) -> Result<()> {
        if !is_http_v1_payload(payload) {
            return Err(Error::HttpHeaderParseFailed);
        }
        let lines = parse_lines(payload, 20);
        if lines.len() == 0 {
            return Err(Error::HttpHeaderParseFailed);
        }

        if direction == PacketDirection::ServerToClient {
            // HTTP响应行：HTTP/1.1 404 Not Found.
            let (version, status_code) = get_http_resp_info(str::from_utf8(lines[0])?)?;

            self.info.version = version;
            self.info.status_code = status_code as u16;

            self.msg_type = LogMessageType::Response;

            self.set_status(status_code);
        } else {
            // HTTP请求行：GET /background.png HTTP/1.0
            let contexts: Vec<&str> = str::from_utf8(lines[0])?.split(" ").collect();
            if contexts.len() != 3 {
                return Err(Error::HttpHeaderParseFailed);
            }

            self.info.method = contexts[0].to_string();
            self.info.path = contexts[1].to_string();
            self.info.version = get_http_request_version(contexts[2])?.to_string();

            self.msg_type = LogMessageType::Request;
        }

        let mut content_length: Option<u64> = None;
        for body_line in &lines[1..] {
            let col_index = body_line.iter().position(|x| *x == b':');
            if col_index.is_none() {
                continue;
            }
            let col_index = col_index.unwrap();
            if col_index + 1 >= body_line.len() {
                continue;
            }
            let key = str::from_utf8(&body_line[..col_index])?.to_lowercase();
            let value = str::from_utf8(&body_line[col_index + 1..])?.trim();
            if &key == "content-length" {
                content_length = Some(value.parse::<u64>().unwrap_or_default());
            } else if self.l7_log_dynamic_config.is_trace_id(key.as_str()) {
                if let Some(id) = Self::decode_id(value, key.as_str(), Self::TRACE_ID) {
                    self.info.trace_id = id;
                }
                // 存在配置相同字段的情况，如“sw8”
                if self.l7_log_dynamic_config.is_span_id(key.as_str()) {
                    if let Some(id) = Self::decode_id(value, key.as_str(), Self::SPAN_ID) {
                        self.info.span_id = id;
                    }
                }
            } else if self.l7_log_dynamic_config.is_span_id(key.as_str()) {
                if let Some(id) = Self::decode_id(value, key.as_str(), Self::SPAN_ID) {
                    self.info.span_id = id;
                }
            } else if !self.l7_log_dynamic_config.x_request_id_origin.is_empty()
                && key == self.l7_log_dynamic_config.x_request_id_lower
            {
                self.info.x_request_id = value.to_owned();
            } else if direction == PacketDirection::ClientToServer {
                if &key == "host" {
                    self.info.host = value.to_owned();
                } else if !self.l7_log_dynamic_config.proxy_client_origin.is_empty()
                    && key == self.l7_log_dynamic_config.proxy_client_lower
                {
                    self.info.client_ip = value.to_owned();
                }
            }
        }

        // 当解析完所有Header仍未找到Content-Length，则认为该字段值为0
        if direction == PacketDirection::ServerToClient {
            self.info.resp_content_length = content_length;
        } else {
            self.info.req_content_length = content_length;
        }
        self.proto = L7Protocol::Http1;
        Ok(())
    }

    fn has_magic(payload: &[u8]) -> bool {
        if payload.len() < HTTPV2_MAGIC_LENGTH {
            return false;
        }
        if let Ok(payload_str) = str::from_utf8(&payload[..HTTPV2_MAGIC_PREFIX.len()]) {
            payload_str.starts_with(HTTPV2_MAGIC_PREFIX)
        } else {
            false
        }
    }

    fn parse_http_v2(&mut self, payload: &[u8], direction: PacketDirection) -> Result<()> {
        let mut content_length: Option<u64> = None;
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
                    self.info.stream_id = httpv2_header.stream_id;
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

                for header in header_list.iter() {
                    match header.0.as_slice() {
                        b":method" => {
                            self.msg_type = LogMessageType::Request;
                            self.info.method =
                                String::from_utf8_lossy(header.1.as_slice()).into_owned()
                        }
                        b":status" => {
                            self.msg_type = LogMessageType::Response;

                            self.info.status_code = str::from_utf8(header.1.as_slice())
                                .unwrap_or_default()
                                .parse::<u16>()
                                .unwrap_or_default();
                            self.set_status(self.info.status_code);
                        }
                        b"host" | b":authority" => {
                            self.info.host =
                                String::from_utf8_lossy(header.1.as_slice()).into_owned()
                        }
                        b":path" => {
                            self.info.path =
                                String::from_utf8_lossy(header.1.as_slice()).into_owned()
                        }
                        b"content-length" => {
                            content_length = Some(
                                str::from_utf8(header.1.as_slice())
                                    .unwrap_or_default()
                                    .parse::<u64>()
                                    .unwrap_or_default(),
                            )
                        }
                        _ => {}
                    }

                    if !header.0.is_ascii() {
                        continue;
                    }

                    let key = String::from_utf8_lossy(header.0.as_ref()).into_owned();
                    let key = key.as_str();

                    if self.l7_log_dynamic_config.is_trace_id(key) {
                        if let Some(id) = Self::decode_id(
                            &String::from_utf8_lossy(header.1.as_ref()),
                            key,
                            Self::TRACE_ID,
                        ) {
                            self.info.trace_id = id;
                        }
                        // 存在配置相同字段的情况，如“sw8”
                        if self.l7_log_dynamic_config.is_span_id(key) {
                            if let Some(id) = Self::decode_id(
                                &String::from_utf8_lossy(header.1.as_ref()),
                                key,
                                Self::SPAN_ID,
                            ) {
                                self.info.span_id = id;
                            }
                        }
                    } else if self.l7_log_dynamic_config.is_span_id(key) {
                        if let Some(id) = Self::decode_id(
                            &String::from_utf8_lossy(header.1.as_ref()),
                            key,
                            Self::SPAN_ID,
                        ) {
                            self.info.span_id = id;
                        }
                    } else if !self.l7_log_dynamic_config.x_request_id_origin.is_empty()
                        && header.0 == self.l7_log_dynamic_config.x_request_id_lower.as_bytes()
                    {
                        self.info.x_request_id =
                            String::from_utf8_lossy(header.1.as_ref()).into_owned();
                    } else if direction == PacketDirection::ClientToServer
                        && !self.l7_log_dynamic_config.proxy_client_origin.is_empty()
                        && header.0 == self.l7_log_dynamic_config.proxy_client_lower.as_bytes()
                    {
                        self.info.client_ip =
                            String::from_utf8_lossy(header.1.as_ref()).into_owned();
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
                content_length = Some(httpv2_header.frame_length as u64);
                if httpv2_header.flags & FLAG_HEADERS_PADDED != 0 {
                    if content_length.unwrap_or_default() > frame_payload[0] as u64 {
                        content_length =
                            Some(content_length.unwrap_or_default() - frame_payload[0] as u64);
                    }
                }
                break;
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
                if check_http_method(&self.info.method).is_err() {
                    return Err(Error::HttpHeaderParseFailed);
                }
                self.info.req_content_length = content_length;
            } else {
                if self.info.status_code < HTTP_STATUS_CODE_MIN
                    || self.info.status_code > HTTP_STATUS_CODE_MAX
                {
                    return Err(Error::HttpHeaderParseFailed);
                }
                self.info.resp_content_length = content_length;
            }
            self.info.version = String::from("2");
            self.info.stream_id = httpv2_header.stream_id;
            self.proto = L7Protocol::Http2;
            return Ok(());
        }
        Err(Error::HttpHeaderParseFailed)
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

    fn decode_base64_to_string(value: &str) -> String {
        let bytes = match base64::decode(value) {
            Ok(v) => v,
            Err(_) => return value.to_string(),
        };
        match str::from_utf8(&bytes) {
            Ok(s) => s.to_string(),
            Err(_) => value.to_string(),
        }
    }

    // sw6: 1-TRACEID-SEGMENTID-3-5-2-IPPORT-ENTRYURI-PARENTURI
    // sw8: 1-TRACEID-SEGMENTID-3-PARENT_SERVICE-PARENT_INSTANCE-PARENT_ENDPOINT-IPPORT
    // sw6和sw8的value全部使用'-'分隔，TRACEID前为SAMPLE字段取值范围仅有0或1
    // 提取`TRACEID`展示为HTTP日志中的`TraceID`字段
    // 提取`SEGMENTID-SPANID`展示为HTTP日志中的`SpanID`字段
    fn decode_skywalking_id(value: &str, id_type: u8) -> Option<String> {
        let segs: Vec<&str> = value.split("-").collect();

        if id_type == Self::TRACE_ID && segs.len() > 2 {
            return Some(Self::decode_base64_to_string(segs[1]));
        }
        if id_type == Self::SPAN_ID && segs.len() > 4 {
            return Some(format!(
                "{}-{}",
                Self::decode_base64_to_string(segs[2]),
                segs[3]
            ));
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

    fn decode_id(payload: &str, trace_type: &str, id_type: u8) -> Option<String> {
        let trace_type = TraceType::from(trace_type);
        match trace_type {
            TraceType::Disabled | TraceType::XB3 | TraceType::XB3Span | TraceType::Customize(_) => {
                Some(payload.to_owned())
            }
            TraceType::Uber => Self::decode_uber_id(payload, id_type),
            TraceType::Sw6 | TraceType::Sw8 => Self::decode_skywalking_id(payload, id_type),
            TraceType::TraceParent => Self::decode_traceparent(payload, id_type),
        }
    }
}

impl L7LogParse for HttpLog {
    fn parse(
        &mut self,
        payload: &[u8],
        proto: IpProtocol,
        direction: PacketDirection,
    ) -> Result<AppProtoHeadEnum> {
        if proto != IpProtocol::Tcp {
            return Err(Error::InvalidIpProtocol);
        }
        self.reset_logs();

        self.parse_http_v1(payload, direction)
            .or(self.parse_http_v2(payload, direction))?;

        Ok(AppProtoHeadEnum::Single(AppProtoHead {
            proto: self.get_l7_protocol(),
            msg_type: self.msg_type,
            rrt: 0,
            ..Default::default()
        }))
    }

    fn info(&self) -> AppProtoLogsInfoEnum {
        if self.info.version == "2" {
            return AppProtoLogsInfoEnum::Single(AppProtoLogsInfo::HttpV2(self.info.clone()));
        }
        if self.is_https {
            return AppProtoLogsInfoEnum::Single(AppProtoLogsInfo::HttpV1TLS(self.info.clone()));
        }
        AppProtoLogsInfoEnum::Single(AppProtoLogsInfo::HttpV1(self.info.clone()))
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

        let stream_id = read_u32_be(&payload[5..]);
        if stream_id & 0x80000000 != 0 {
            return Err(Error::HttpHeaderParseFailed);
        }

        self.frame_length = read_u32_be(&payload) >> 8;
        self.frame_type = frame_type;
        self.flags = payload[4];
        self.stream_id = stream_id;

        Ok(())
    }
}

const HTTP_METHODS: [&'static str; 9] = [
    "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT", "PATCH",
];
const RESPONSE_PREFIX: &'static str = "HTTP/";

fn has_prefix(s: &[u8], prefix: &[u8]) -> bool {
    s.len() >= prefix.len() && &s[..prefix.len()] == prefix
}

pub fn is_http_v1_payload(buf: &[u8]) -> bool {
    if has_prefix(buf, RESPONSE_PREFIX.as_bytes()) {
        return true;
    }
    for m in HTTP_METHODS {
        if has_prefix(buf, m.as_bytes()) {
            return true;
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

// HTTP请求行：GET /background.png HTTP/1.0
pub fn get_http_method(line_info: &[u8]) -> Result<(String, usize)> {
    // 截取请求行第一个空格前，进行method匹配
    if line_info.len() < HTTP_METHOD_AND_SPACE_MAX_OFFSET {
        return Err(Error::HttpHeaderParseFailed);
    }
    let line_str = str::from_utf8(line_info).unwrap_or_default();
    if let Some(space_index) = line_str.find(' ') {
        let method = &line_str[..space_index];
        check_http_method(method)?;
        return Ok((method.to_string(), space_index));
    }
    Err(Error::HttpHeaderParseFailed)
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

pub fn get_http_resp_info(line_info: &str) -> Result<(String, u16)> {
    if line_info.len() < HTTP_RESP_MIN_LEN {
        return Err(Error::HttpHeaderParseFailed);
    }
    // HTTP响应行：HTTP/1.1 404 Not Found.
    let mut params = line_info.split(' ');
    // version解析
    let version = match params.next().unwrap_or_default() {
        HTTP_V1_0_VERSION => "1.0".to_string(),
        HTTP_V1_1_VERSION => "1.1".to_string(),
        _ => return Err(Error::HttpHeaderParseFailed),
    };

    // 响应码值校验
    // 参考：https://baike.baidu.com/item/HTTP%E7%8A%B6%E6%80%81%E7%A0%81/5053660?fr=aladdin
    let status_code = params
        .next()
        .unwrap_or_default()
        .parse::<u16>()
        .unwrap_or_default();

    if status_code < HTTP_STATUS_CODE_MIN || status_code > HTTP_STATUS_CODE_MAX {
        return Err(Error::HttpHeaderParseFailed);
    }
    Ok((version, status_code))
}

// 通过请求识别HTTPv1
pub fn http1_check_protocol(bitmap: &mut u128, packet: &MetaPacket) -> bool {
    if packet.lookup_key.proto != IpProtocol::Tcp {
        *bitmap &= !(1 << u8::from(L7Protocol::Http1));
        return false;
    }

    let payload = packet.get_l4_payload();
    if payload.is_none() {
        return false;
    }
    let payload = payload.unwrap();
    let lines = parse_lines(payload, 1);
    if lines.len() == 0 {
        // 没有/r/n认为一定不是HTTPv1
        *bitmap &= !(1 << u8::from(L7Protocol::Http1));
        return false;
    }

    let regex = Regex::new("^(GET|POST|HEAD|PUT|DELETE|CONNECT|TRACE|OPTIONS|LINK|UNLINK|COPY|MOVE|PATCH|WRAPPED|EXTENSION\\-METHOD).+HTTP/1.[01]$").unwrap();
    let line = String::from_utf8_lossy(lines[0]).into_owned();
    return regex.is_match(line.as_str());
}

// 通过请求识别HTTPv2
pub fn http2_check_protocol(bitmap: &mut u128, packet: &MetaPacket) -> bool {
    if packet.lookup_key.proto != IpProtocol::Tcp {
        *bitmap &= !(1 << u8::from(L7Protocol::Http2));
        return false;
    }

    let payload = packet.get_l4_payload();
    if payload.is_none() {
        return false;
    }
    let payload = payload.unwrap();
    let mut http2 = HttpLog::default();
    return http2
        .parse_http_v2(payload, PacketDirection::ClientToServer)
        .is_ok();
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    use crate::{common::enums::PacketDirection, utils::test::Capture};

    const FILE_DIR: &str = "resources/test/flow_generator/http";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name), Some(1500));
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
        let mut bitmap = 0;
        for packet in packets.iter_mut() {
            packet.direction = if packet.lookup_key.dst_port == first_dst_port {
                PacketDirection::ClientToServer
            } else {
                PacketDirection::ServerToClient
            };
            let payload = match packet.get_l4_payload() {
                Some(p) => p,
                None => continue,
            };

            let mut http = HttpLog::default();
            http.l7_log_dynamic_config = L7LogDynamicConfig {
                proxy_client_origin: "".to_string(),
                proxy_client_lower: "".to_string(),
                proxy_client_with_colon: "".to_string(),
                x_request_id_origin: "".to_string(),
                x_request_id_lower: "".to_string(),
                x_request_id_with_colon: "".to_string(),
                trace_types: vec![TraceType::Sw8],
                span_types: vec![TraceType::Sw8],
            };
            let _ = http.parse(payload, packet.lookup_key.proto, packet.direction);
            let mut is_http = http1_check_protocol(&mut bitmap, packet);
            is_http |= http2_check_protocol(&mut bitmap, packet);

            output.push_str(&format!("{:?} is_http: {}\r\n", http.info, is_http));
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
            ("httpv1.pcap", "httpv1.result"),
            ("sw8.pcap", "sw8.result"),
            ("h2c_ascii.pcap", "h2c_ascii.result"),
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
}
