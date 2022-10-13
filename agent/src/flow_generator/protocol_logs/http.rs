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
use log::debug;
use regex::Regex;
use serde::Serialize;

use super::pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response, TraceInfo};
use super::value_is_default;
use super::LogMessageType;
use super::{consts::*, AppProtoHead, L7ResponseStatus};

use crate::common::ebpf::EbpfType;
use crate::common::enums::IpProtocol;
use crate::common::flow::L7Protocol;
use crate::common::flow::PacketDirection;
use crate::common::l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface};
use crate::common::l7_protocol_log::{L7ProtocolParserInterface, ParseParam};
use crate::config::handler::{L7LogDynamicConfig, LogParserAccess, TraceType};
use crate::flow_generator::error::{Error, Result};
use crate::flow_generator::protocol_logs::L7ProtoRawDataType;
use crate::utils::bytes::{read_u32_be, read_u32_le};
use crate::utils::net::h2pack;
use crate::{log_info_merge, parse_common};

#[derive(Serialize, Debug, Default, Clone)]
pub struct HttpInfo {
    // 流是否结束，用于 http2 ebpf uprobe 处理.
    // 由于ebpf有可能响应会比请求先到，所以需要 is_req_end 和 is_resp_end 同时为true才认为结束
    is_req_end: bool,
    is_resp_end: bool,
    proto: L7Protocol,
    start_time: u64,
    end_time: u64,
    is_tls: bool,
    msg_type: LogMessageType,
    // 数据原始类型，标准的协议格式或者是ebpf上报的自定义格式
    #[serde(skip)]
    raw_data_type: L7ProtoRawDataType,

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
    pub req_content_length: Option<u32>,
    #[serde(rename = "response_length", skip_serializing_if = "Option::is_none")]
    pub resp_content_length: Option<u32>,

    status_code: Option<i32>,
    status: L7ResponseStatus,
}

impl L7ProtocolInfoInterface for HttpInfo {
    fn session_id(&self) -> Option<u32> {
        Some(self.stream_id)
    }

    fn merge_log(&mut self, other: L7ProtocolInfo) -> Result<()> {
        log_info_merge!(self, HttpInfo, other);
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: self.get_l7_protocol_with_tls(),
            msg_type: self.msg_type,
            rrt: self.end_time - self.start_time,
        })
    }

    fn is_tls(&self) -> bool {
        self.is_tls
    }

    fn skip_send(&self) -> bool {
        self.is_empty()
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
}

impl HttpInfo {
    pub fn merge(&mut self, other: Self) {
        if self.trace_id.is_empty() {
            self.trace_id = other.trace_id;
        }
        if self.span_id.is_empty() {
            self.span_id = other.span_id;
        }
        if self.x_request_id.is_empty() {
            self.x_request_id = other.x_request_id;
        }
        // 下面用于请求合并
        if self.path.is_empty() {
            self.path = other.path;
        }
        if self.host.is_empty() {
            self.host = other.host;
        }
        if self.method.is_empty() {
            self.method = other.method;
        }

        if other.status != L7ResponseStatus::default() {
            self.status = other.status;
        }
        if self.status_code.is_none() {
            self.status_code = other.status_code;
        }

        if self.req_content_length.is_none() {
            self.req_content_length = other.req_content_length;
        }
        if self.resp_content_length.is_none() {
            self.resp_content_length = other.resp_content_length;
        }
        // 下面用于判断是否结束
        if other.is_req_end {
            self.is_req_end = true;
        }
        if other.is_resp_end {
            self.is_resp_end = true;
        }
    }

    pub fn is_empty(&self) -> bool {
        return self.host.is_empty() && self.method.is_empty() && self.path.is_empty();
    }

    // return (is_req_end, is_resp_end)
    pub fn is_req_resp_end(&self) -> (bool, bool) {
        (self.is_req_end, self.is_resp_end)
    }

    fn get_l7_protocol_with_tls(&self) -> L7Protocol {
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
            _ => unreachable!(),
        }
    }
}

impl From<HttpInfo> for L7ProtocolSendLog {
    fn from(f: HttpInfo) -> Self {
        L7ProtocolSendLog {
            // http2 可能没有:content-length头. 默认长度设置-1 防止server判断为0
            req_len: f.req_content_length,
            resp_len: f.resp_content_length,
            version: Some(f.version),
            req: L7Request {
                req_type: f.method,
                resource: f.path,
                domain: f.host,
            },
            resp: L7Response {
                status: f.status,
                code: f.status_code,
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
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct HttpLog {
    info: HttpInfo,

    // check 是否已经解析过，已经解析过parse会跳过
    parsed: bool,
    #[serde(skip)]
    l7_log_dynamic_config: L7LogDynamicConfig,
    proto: L7Protocol,
}

impl L7ProtocolParserInterface for HttpLog {
    fn set_parse_config(&mut self, log_parser_config: &LogParserAccess) {
        self.update_config(log_parser_config)
    }

    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        parse_common!(self, param);
        match param.ebpf_type {
            EbpfType::GoHttp2Uprobe => {
                self.info.raw_data_type = L7ProtoRawDataType::GoHttp2Uprobe; // 用于区分是否需要多段merge
                if let Some(p) = &param.ebpf_param {
                    self.parsed = self
                        .parse_http2_go_uprobe(
                            payload,
                            param.direction,
                            false,
                            Some(p.is_req_end),
                            Some(p.is_resp_end),
                        )
                        .is_ok();
                    self.parsed
                } else {
                    false
                }
            }
            _ => {
                // http2 有两个版本, 现在可以直接通过proto区分解析哪个版本的协议.
                match self.proto {
                    L7Protocol::Http1 => self.http1_check_protocol(payload, param),
                    L7Protocol::Http2 => self.http2_check_protocol(payload, param),
                    _ => unreachable!(),
                }
            }
        }
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<Vec<L7ProtocolInfo>> {
        if self.parsed {
            return Ok(vec![L7ProtocolInfo::HttpInfo(self.info.clone())]);
        }
        parse_common!(self, param);
        match param.ebpf_type {
            EbpfType::GoHttp2Uprobe => {
                self.info.raw_data_type = L7ProtoRawDataType::GoHttp2Uprobe; // 用于区分是否需要多段merge
                if let Some(p) = &param.ebpf_param {
                    self.parse_http2_go_uprobe(
                        payload,
                        param.direction,
                        false,
                        Some(p.is_req_end),
                        Some(p.is_resp_end),
                    )?;
                    return Ok(vec![L7ProtocolInfo::HttpInfo(self.info.clone())]);
                } else {
                    return Err(Error::L7ProtocolUnknown);
                };
            }
            _ => {
                match self.proto {
                    L7Protocol::Http1 => self.parse_http_v1(payload, param.direction)?,
                    L7Protocol::Http2 => self.parse_http_v2(payload, param.direction)?,
                    _ => unreachable!(),
                }
                Ok(vec![L7ProtocolInfo::HttpInfo(self.info.clone())])
            }
        }
    }

    fn protocol(&self) -> L7Protocol {
        match self.proto {
            L7Protocol::Http1 => {
                if self.info.is_tls() {
                    L7Protocol::Http1TLS
                } else {
                    L7Protocol::Http1
                }
            }

            L7Protocol::Http2 => {
                if self.info.is_tls() {
                    L7Protocol::Http2TLS
                } else {
                    L7Protocol::Http2
                }
            }
            _ => unreachable!(),
        }
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn reset(&mut self) {
        let mut log = Self::default();
        log.l7_log_dynamic_config = self.l7_log_dynamic_config.clone();
        log.proto = self.proto;
        log.info.proto = self.proto;
        *self = log;
    }
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

    pub fn new(config: &LogParserAccess) -> Self {
        Self {
            l7_log_dynamic_config: config.load().l7_log_dynamic.clone(),
            ..Default::default()
        }
    }

    pub fn new_v1() -> Self {
        Self {
            proto: L7Protocol::Http1,
            info: HttpInfo {
                proto: L7Protocol::Http1,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    pub fn new_v2() -> Self {
        Self {
            proto: L7Protocol::Http2,
            info: HttpInfo {
                proto: L7Protocol::Http2,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    pub fn set_config(&mut self, config: &LogParserAccess) {
        self.l7_log_dynamic_config = config.load().l7_log_dynamic.clone();
    }

    pub fn http1_check_protocol(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if param.l4_protocol != IpProtocol::Tcp {
            return false;
        }

        let lines = parse_lines(payload, 1);
        if lines.len() == 0 {
            // 没有/r/n认为一定不是HTTPv1
            return false;
        }

        let regex = Regex::new("^(GET|POST|HEAD|PUT|DELETE|CONNECT|TRACE|OPTIONS|LINK|UNLINK|COPY|MOVE|PATCH|WRAPPED|EXTENSION\\-METHOD).+HTTP/1.[01]$").unwrap();
        let line = String::from_utf8_lossy(lines[0]).into_owned();
        if regex.is_match(line.as_str()) {
            self.proto = L7Protocol::Http1;
            return true;
        }
        false
    }

    pub fn http2_check_protocol(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if param.l4_protocol != IpProtocol::Tcp {
            return false;
        }
        self.parsed = self
            .parse_http_v2(payload, PacketDirection::ClientToServer)
            .is_ok();
        if self.parsed {
            self.proto = L7Protocol::Http2;
        }
        self.parsed
    }

    pub fn update_config(&mut self, config: &LogParserAccess) {
        self.l7_log_dynamic_config = config.load().l7_log_dynamic.clone();
        debug!(
            "http log update l7 log dynamic config to {:#?}",
            self.l7_log_dynamic_config
        );
    }

    fn reset_logs(&mut self) {
        self.info.status_code = None;
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
        payload: &[u8],
        direction: PacketDirection,
        check_only: bool,
        is_req_end: Option<bool>,
        is_resp_end: Option<bool>,
    ) -> Result<()> {
        if payload.len() < HTTPV2_CUSTOM_DATA_MIN_LENGTH {
            return Err(Error::HttpHeaderParseFailed);
        }
        let stream_id = read_u32_le(&payload[4..8]);
        let key_len = read_u32_le(&payload[8..12]) as usize;
        let val_len = read_u32_le(&payload[12..16]) as usize;
        if key_len + val_len + HTTPV2_CUSTOM_DATA_MIN_LENGTH != payload.len() {
            // 长度不够
            return Err(Error::HttpHeaderParseFailed);
        }
        if check_only {
            return Ok(());
        }

        let val_offset = HTTPV2_CUSTOM_DATA_MIN_LENGTH + key_len;
        let key = Vec::from(&payload[HTTPV2_CUSTOM_DATA_MIN_LENGTH..val_offset]);
        let val = Vec::from(&payload[val_offset..val_offset + val_len]);
        self.on_http2_header(&key, &val, direction);
        if key.as_slice() == b"content-length" {
            self.info.req_content_length = Some(
                str::from_utf8(val.as_slice())
                    .unwrap_or_default()
                    .parse::<u32>()
                    .unwrap_or_default(),
            );
        }

        self.info.is_req_end = is_req_end.unwrap_or_default();
        self.info.is_resp_end = is_resp_end.unwrap_or_default();
        self.info.version = String::from("2");
        self.info.stream_id = stream_id;
        self.proto = L7Protocol::Http2;
        return Ok(());
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
            self.info.status_code = Some(status_code as i32);

            self.info.msg_type = LogMessageType::Response;

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

            self.info.msg_type = LogMessageType::Request;
        }

        let mut content_length: Option<u32> = None;
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
                content_length = Some(value.parse::<u32>().unwrap_or_default());
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

                for (key, val) in header_list.iter() {
                    self.on_http2_header(key, val, direction);
                    if key.as_slice() == b"content-length" {
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
                if let Some(code) = self.info.status_code {
                    let code = code as u16;
                    if code < HTTP_STATUS_CODE_MIN || code > HTTP_STATUS_CODE_MAX {
                        return Err(Error::HttpHeaderParseFailed);
                    }
                } else {
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

    fn on_http2_header(&mut self, key: &Vec<u8>, val: &Vec<u8>, direction: PacketDirection) {
        match key.as_slice() {
            b":method" => {
                self.info.msg_type = LogMessageType::Request;
                self.info.method = String::from_utf8_lossy(val.as_slice()).into_owned()
            }
            b":status" => {
                self.info.msg_type = LogMessageType::Response;
                let code = str::from_utf8(val.as_slice())
                    .unwrap_or_default()
                    .parse::<u16>()
                    .unwrap_or_default();
                self.info.status_code = Some(code as i32);
                self.set_status(code);
            }
            b"host" | b":authority" => {
                self.info.host = String::from_utf8_lossy(val.as_slice()).into_owned()
            }
            b":path" => self.info.path = String::from_utf8_lossy(val.as_slice()).into_owned(),
            _ => {}
        }

        if !key.is_ascii() {
            return;
        }

        let key = String::from_utf8_lossy(key.as_ref()).into_owned();
        let key_str = key.as_str();
        let key_bytes = key.as_bytes();

        if self.l7_log_dynamic_config.is_trace_id(key_str) {
            if let Some(id) = Self::decode_id(
                &String::from_utf8_lossy(val.as_ref()),
                key_str,
                Self::TRACE_ID,
            ) {
                self.info.trace_id = id;
            }
            // 存在配置相同字段的情况，如“sw8”
            if self.l7_log_dynamic_config.is_span_id(key_str) {
                if let Some(id) = Self::decode_id(
                    &String::from_utf8_lossy(val.as_ref()),
                    key_str,
                    Self::SPAN_ID,
                ) {
                    self.info.span_id = id;
                }
            }
        } else if self.l7_log_dynamic_config.is_span_id(key_str) {
            if let Some(id) = Self::decode_id(
                &String::from_utf8_lossy(val.as_ref()),
                key_str,
                Self::SPAN_ID,
            ) {
                self.info.span_id = id;
            }
        } else if !self.l7_log_dynamic_config.x_request_id_origin.is_empty()
            && key_bytes == self.l7_log_dynamic_config.x_request_id_lower.as_bytes()
        {
            self.info.x_request_id = String::from_utf8_lossy(val.as_ref()).into_owned();
        } else if direction == PacketDirection::ClientToServer
            && !self.l7_log_dynamic_config.proxy_client_origin.is_empty()
            && key_bytes == self.l7_log_dynamic_config.proxy_client_lower.as_bytes()
        {
            self.info.client_ip = String::from_utf8_lossy(val.as_ref()).into_owned();
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

    fn parse(
        &mut self,
        payload: &[u8],
        proto: IpProtocol,
        direction: PacketDirection,
        is_req_end: Option<bool>,
        is_resp_end: Option<bool>,
    ) -> Result<()> {
        if proto != IpProtocol::Tcp {
            return Err(Error::InvalidIpProtocol);
        }
        self.reset_logs();

        match self.info.raw_data_type {
            L7ProtoRawDataType::GoHttp2Uprobe => {
                self.parse_http2_go_uprobe(payload, direction, false, is_req_end, is_resp_end)?;
            }
            _ => {
                self.parse_http_v1(payload, direction)
                    .or(self.parse_http_v2(payload, direction))?;
            }
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use crate::common::MetaPacket;
    use crate::utils::test::Capture;
    use std::fs;
    use std::mem::size_of;
    use std::path::Path;
    use std::slice::from_raw_parts;

    use super::*;

    const FILE_DIR: &str = "resources/test/flow_generator/http";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name), Some(1500));
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
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
            let _ = http.parse(
                payload,
                packet.lookup_key.proto,
                packet.direction,
                None,
                None,
            );
            let param = &ParseParam::from(packet as &MetaPacket);
            let mut is_http = http.http1_check_protocol(payload, param);
            is_http |= http.http2_check_protocol(payload, param);

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
                let mut h = HttpLog::default();
                h.info.raw_data_type = L7ProtoRawDataType::GoHttp2Uprobe;
                let res = h.parse_http2_go_uprobe(
                    &payload,
                    PacketDirection::ClientToServer,
                    true,
                    None,
                    None,
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
            let payload = hdr.to_bytes(key, val);
            let mut h = HttpLog::default();
            h.info.raw_data_type = L7ProtoRawDataType::GoHttp2Uprobe;
            let res = h.parse_http2_go_uprobe(
                &payload,
                PacketDirection::ClientToServer,
                false,
                None,
                None,
            );
            assert_eq!(res.is_ok(), true);
            println!("{:#?}", h);
        }
    }
}
