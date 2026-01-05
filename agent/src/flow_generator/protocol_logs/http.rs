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

use std::{
    borrow::{Borrow, Cow},
    cell::OnceCell,
    collections::{HashMap, HashSet},
    mem, str,
    sync::Arc,
};

use hpack::Decoder;
use nom::{AsBytes, ParseTo};
use serde::Serialize;

use public::l7_protocol::{
    Field, FieldSetter, L7Log, L7LogAttribute, L7ProtocolChecker, LogMessageType,
};
use public_derive::L7Log;

use super::{
    consts::*,
    pb_adapter::{
        ExtendedInfo, KeyVal, L7ProtocolSendLog, L7Request, L7Response, MetricKeyVal, TraceInfo,
    },
    value_is_default, AppProtoHead, L7ResponseStatus, PrioField,
};

use crate::{
    common::{
        ebpf::EbpfType,
        enums::IpProtocol,
        flow::{L7PerfStats, L7Protocol, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{
            L7ParseResult, L7ProtocolParserInterface, LogCache, MultiMergeInfo, ParseParam,
        },
        meta_packet::ApplicationFlags,
    },
    config::handler::{L7LogDynamicConfig, LogParserConfig},
    flow_generator::error::{Error, Result},
    flow_generator::protocol_logs::{
        set_captured_byte, L7ProtoRawDataType, BASE_FIELD_PRIORITY, PLUGIN_FIELD_PRIORITY,
    },
    plugin::CustomInfo,
    utils::bytes::{read_u32_be, read_u32_le},
};

cfg_if::cfg_if! {
if #[cfg(feature = "enterprise")] {
        use enterprise_utils::l7::custom_policy::{
            custom_field_policy::{
                enums::{Op, PayloadType, Source},
                PolicySlice, Store,
            },
        };
        use public::l7_protocol::NativeTag;

        use crate::flow_generator::protocol_logs::{auto_merge_custom_field, CUSTOM_FIELD_POLICY_PRIORITY};
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum Version {
    #[default]
    Unknown,
    V1_0,
    V1_1,
    V2,
}

impl Version {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V1_0 => "1.0",
            Self::V1_1 => "1.1",
            Self::V2 => "2",
            _ => "",
        }
    }
}

impl TryFrom<&str> for Version {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "1.0" => Ok(Self::V1_0),
            "1.1" => Ok(Self::V1_1),
            "2" => Ok(Self::V2),
            _ => Err(Error::HttpHeaderParseFailed),
        }
    }
}

impl Serialize for Version {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum Method {
    #[default]
    None,
    Get,
    Head,
    Post,
    Put,
    Delete,
    Connect,
    Options,
    Trace,
    Patch,
    _RequestData,
    _ResponseData,
    _RequestHeader,
    _ResponseHeader,
}

impl Method {
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "",
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Connect => "CONNECT",
            Self::Options => "OPTIONS",
            Self::Trace => "TRACE",
            Self::Patch => "PATCH",
            Self::_RequestData => "_REQUEST_DATA",
            Self::_ResponseData => "_RESPONSE_DATA",
            Self::_RequestHeader => "_REQUEST_HEADER",
            Self::_ResponseHeader => "_RESPONSE_HEADER",
        }
    }
}

impl Method {
    fn from_frame_type(value: u8, direction: PacketDirection) -> Self {
        match value {
            HTTPV2_FRAME_DATA_TYPE if direction == PacketDirection::ClientToServer => {
                Method::_RequestData
            }
            HTTPV2_FRAME_DATA_TYPE if direction == PacketDirection::ServerToClient => {
                Method::_ResponseData
            }
            HTTPV2_FRAME_HEADERS_TYPE if direction == PacketDirection::ClientToServer => {
                Method::_RequestHeader
            }
            HTTPV2_FRAME_HEADERS_TYPE if direction == PacketDirection::ServerToClient => {
                Method::_ResponseHeader
            }
            _ => Self::None,
        }
    }

    fn from_ebpf_type(value: EbpfType, direction: PacketDirection) -> Self {
        match value {
            EbpfType::GoHttp2UprobeData if direction == PacketDirection::ClientToServer => {
                Method::_RequestData
            }
            EbpfType::GoHttp2UprobeData if direction == PacketDirection::ServerToClient => {
                Method::_ResponseData
            }
            EbpfType::GoHttp2Uprobe if direction == PacketDirection::ClientToServer => {
                Method::_RequestHeader
            }
            EbpfType::GoHttp2Uprobe if direction == PacketDirection::ServerToClient => {
                Method::_ResponseHeader
            }
            _ => Self::None,
        }
    }
}

impl TryFrom<&str> for Method {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "GET" => Ok(Self::Get),
            "HEAD" => Ok(Self::Head),
            "POST" => Ok(Self::Post),
            "PUT" => Ok(Self::Put),
            "DELETE" => Ok(Self::Delete),
            "CONNECT" => Ok(Self::Connect),
            "OPTIONS" => Ok(Self::Options),
            "TRACE" => Ok(Self::Trace),
            "PATCH" => Ok(Self::Patch),
            _ => Err(Error::HttpHeaderParseFailed),
        }
    }
}

impl Serialize for Method {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[derive(L7Log, Serialize, Debug, Default, Clone)]
#[l7_log(version.getter = "HttpInfo::get_version", version.setter = "HttpInfo::set_version")]
#[l7_log(request_type.getter = "HttpInfo::get_method", request_type.setter = "HttpInfo::set_method")]
#[l7_log(endpoint.getter = "HttpInfo::get_endpoint", endpoint.setter = "HttpInfo::set_endpoint")]
#[l7_log(trace_id.getter = "HttpInfo::get_trace_id", trace_id.setter = "HttpInfo::set_trace_id")]
pub struct HttpInfo {
    // Offset for HTTP2 HEADERS:
    // Example:
    //                   0            8           ...
    //                   |____________|___________|__
    // HTTP2 Request:    |SETTINGS[0], HEADERS[1];
    //
    // tcp_seq_offset is 8
    #[serde(skip)]
    headers_offset: Option<u32>,
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

    #[l7_log(request_id)]
    #[serde(rename = "request_id", skip_serializing_if = "value_is_default")]
    pub stream_id: Option<u32>,
    #[serde(skip_serializing_if = "value_is_default")]
    pub version: Version,
    #[serde(skip_serializing_if = "value_is_default")]
    pub trace_ids: super::PrioFields,
    #[serde(skip)]
    copy_apm_trace_id: bool,
    #[serde(skip_serializing_if = "value_is_default")]
    pub span_id: PrioField<String>,

    #[serde(rename = "request_type", skip_serializing_if = "value_is_default")]
    pub method: Method,
    #[l7_log(request_resource)]
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub path: String,
    #[l7_log(request_domain)]
    #[serde(rename = "request_domain", skip_serializing_if = "value_is_default")]
    pub host: String,
    #[serde(rename = "user_agent", skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(rename = "referer", skip_serializing_if = "Option::is_none")]
    pub referer: Option<String>,
    #[l7_log(http_proxy_client)]
    #[serde(rename = "http_proxy_client", skip_serializing_if = "value_is_default")]
    pub client_ip: Option<PrioField<String>>,
    #[serde(skip_serializing_if = "value_is_default")]
    pub x_request_id_0: PrioField<String>,
    #[serde(skip_serializing_if = "value_is_default")]
    pub x_request_id_1: PrioField<String>,

    #[serde(rename = "request_length", skip_serializing_if = "Option::is_none")]
    pub req_content_length: Option<u32>,
    #[serde(rename = "response_length", skip_serializing_if = "Option::is_none")]
    pub resp_content_length: Option<u32>,

    #[l7_log(response_code)]
    #[serde(rename = "response_code", skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[l7_log(response_status)]
    #[serde(rename = "response_status")]
    pub status: L7ResponseStatus,
    #[serde(skip_serializing_if = "value_is_default")]
    pub grpc_status_code: Option<u16>,

    endpoint: Option<String>,
    // set by wasm plugin
    #[l7_log(response_result)]
    custom_result: Option<String>,
    #[l7_log(response_exception)]
    custom_exception: Option<String>,

    captured_request_byte: u32,
    captured_response_byte: u32,

    request_header: Option<Vec<u8>>,
    request_payload: Option<Vec<u8>>,
    response_header: Option<Vec<u8>>,
    response_payload: Option<Vec<u8>>,

    #[serde(skip_serializing_if = "value_is_default")]
    biz_type: u8,
    #[serde(skip_serializing_if = "value_is_default")]
    biz_code: String,
    #[serde(skip_serializing_if = "value_is_default")]
    biz_scenario: String,

    #[serde(skip)]
    attributes: Vec<KeyVal>,

    #[serde(skip)]
    metrics: Vec<MetricKeyVal>,

    #[serde(skip)]
    is_on_blacklist: bool,

    #[serde(skip)]
    service_name: Option<String>,

    #[serde(skip_serializing_if = "value_is_default")]
    is_async: bool,
    #[serde(skip_serializing_if = "value_is_default")]
    is_reversed: bool,

    #[serde(skip)]
    dubbo_service_version: String,
}

impl L7LogAttribute for HttpInfo {
    fn add_attribute(&mut self, name: Cow<'_, str>, value: Cow<'_, str>) {
        self.attributes.push(KeyVal {
            key: name.into_owned(),
            val: value.into_owned(),
        });
    }
}

impl L7ProtocolInfoInterface for HttpInfo {
    fn session_id(&self) -> Option<u32> {
        self.stream_id
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::HttpInfo(other) = other {
            return self.merge(other);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: self.proto,
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
        match L7Log::get_endpoint(self) {
            Field::Str(s) => Some(s.into_owned()),
            _ => None,
        }
    }

    fn tcp_seq_offset(&self) -> u32 {
        self.headers_offset.unwrap_or_default()
    }

    fn get_request_domain(&self) -> String {
        match L7Log::get_request_domain(self) {
            Field::Str(s) => s.into_owned(),
            _ => String::new(),
        }
    }

    fn get_request_resource_length(&self) -> usize {
        self.path.len()
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
}

impl HttpInfo {
    fn is_invalid_status_code(&self) -> bool {
        match self.status_code {
            Some(code) => !(HTTP_STATUS_CODE_MIN..=HTTP_STATUS_CODE_MAX).contains(&code),
            None => true,
        }
    }

    fn is_invalid(&self) -> bool {
        (self.msg_type == LogMessageType::Request && self.method.is_none())
            || (self.msg_type == LogMessageType::Response && self.is_invalid_status_code())
            || self.msg_type == LogMessageType::Other
    }

    // when response_code is overwritten, put it into the attributes.
    fn response_code_to_attribute(&mut self) {
        if let Some(code) = self.status_code {
            self.attributes.push(KeyVal {
                key: SYS_RESPONSE_CODE_ATTR.to_string(),
                val: code.to_string(),
            });
        }
    }

    pub fn merge_custom_to_http(&mut self, custom: CustomInfo, dir: PacketDirection) {
        if dir == PacketDirection::ClientToServer {
            if let Ok(v) = Version::try_from(custom.req.version.as_str()) {
                self.version = v;
            }

            if let Ok(m) = Method::try_from(custom.req.req_type.as_str()) {
                self.method = m;
            }

            if !custom.req.domain.is_empty() {
                self.host = custom.req.domain;
            }

            if !custom.req.resource.is_empty() {
                self.path = custom.req.resource;
            }

            if let Some(id) = custom.request_id {
                self.stream_id = Some(id);
            }

            if !custom.req.endpoint.is_empty() {
                self.endpoint = Some(custom.req.endpoint)
            }
        }

        if dir == PacketDirection::ServerToClient {
            if let Some(code) = custom.resp.code {
                self.response_code_to_attribute();
                self.status_code = Some(code as u16);
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
        }

        self.trace_ids
            .merge_same_priority(PLUGIN_FIELD_PRIORITY, custom.trace.trace_ids);

        if let Some(span_id) = custom.trace.span_id {
            let prev = mem::replace(
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
        if let Some(x_request_id_0) = custom.trace.x_request_id_0 {
            self.x_request_id_0 = PrioField::new(PLUGIN_FIELD_PRIORITY, x_request_id_0);
        }
        if let Some(x_request_id_1) = custom.trace.x_request_id_1 {
            self.x_request_id_1 = PrioField::new(PLUGIN_FIELD_PRIORITY, x_request_id_1);
        }
        if let Some(http_proxy_client) = custom.trace.http_proxy_client {
            self.client_ip = Some(PrioField::new(PLUGIN_FIELD_PRIORITY, http_proxy_client));
        }

        // extend attribute
        if !custom.attributes.is_empty() {
            self.attributes.extend(custom.attributes);
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

        if let Some(is_async) = custom.is_async {
            self.is_async = is_async;
        }
        if let Some(is_reversed) = custom.is_reversed {
            self.is_reversed = is_reversed;
        }
    }

    pub fn merge(&mut self, other: &mut Self) -> Result<()> {
        let other_is_grpc = other.is_grpc();

        if other.is_on_blacklist {
            self.is_on_blacklist = other.is_on_blacklist;
        }
        match other.msg_type {
            // merge with request
            LogMessageType::Request => {
                super::swap_if!(self, path, is_empty, other);
                super::swap_if!(self, host, is_empty, other);
                super::swap_if!(self, method, is_none, other);
                super::swap_if!(self, user_agent, is_none, other);
                super::swap_if!(self, referer, is_none, other);
                super::swap_if!(self, endpoint, is_none, other);
                super::swap_if!(self, service_name, is_none, other);
                // 下面用于判断是否结束
                // ================
                // determine whether request is end
                if other.is_req_end {
                    self.is_req_end = true;
                }
                if self.req_content_length.is_none() {
                    self.req_content_length = other.req_content_length;
                }
                if self.status != L7ResponseStatus::Ok {
                    self.request_header = other.request_header.take();
                    self.request_payload = other.request_payload.take();
                } else {
                    self.response_header = None;
                    self.response_payload = None;
                }
                self.captured_request_byte += other.captured_request_byte;
            }
            // merge with response
            LogMessageType::Response => {
                if other.status != L7ResponseStatus::default() {
                    self.status = other.status;
                }
                if self.status_code.is_none() {
                    self.status_code = other.status_code;
                }
                if self.grpc_status_code.is_none() && other.grpc_status_code.is_some() {
                    self.grpc_status_code = other.grpc_status_code.take();
                }

                super::swap_if!(self, custom_exception, is_none, other);
                super::swap_if!(self, custom_result, is_none, other);

                if self.resp_content_length.is_none() {
                    self.resp_content_length = other.resp_content_length;
                }

                if other.is_resp_end {
                    self.is_resp_end = true;
                }
                self.captured_response_byte += other.captured_response_byte;

                if other.status != L7ResponseStatus::Ok {
                    self.response_header = other.response_header.take();
                    self.response_payload = other.response_payload.take();
                } else {
                    self.request_header = None;
                    self.request_payload = None;
                }
            }
            _ => {}
        }

        if other_is_grpc {
            self.proto = L7Protocol::Grpc;
        }
        if other.proto == L7Protocol::Triple {
            self.proto = L7Protocol::Triple;
        }
        if other.is_reversed {
            self.is_reversed = other.is_reversed;
        }
        if other.biz_type > 0 {
            self.biz_type = other.biz_type;
        }

        super::swap_if!(self, dubbo_service_version, is_empty, other);
        super::swap_if!(self, biz_code, is_empty, other);
        super::swap_if!(self, biz_scenario, is_empty, other);

        let other_trace_ids = mem::take(&mut other.trace_ids);
        self.trace_ids.merge(other_trace_ids);
        super::swap_if!(self, span_id, is_default, other);
        super::swap_if!(self, x_request_id_0, is_default, other);
        super::swap_if!(self, x_request_id_1, is_default, other);
        self.attributes.append(&mut other.attributes);
        self.metrics.append(&mut other.metrics);
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.host.is_empty()
            && self.method.is_none()
            && self.path.is_empty()
            && self.status_code.is_none()
    }

    pub fn is_req_resp_end(&self) -> (bool, bool) {
        (self.is_req_end, self.is_resp_end)
    }

    fn is_grpc(&self) -> bool {
        self.proto == L7Protocol::Grpc
    }
    // grpc path: /packageName.Servicename/rcpMethodName
    // return packageName.Servicename
    // grpc path: /StreamingService/ClientStreamRPC
    // return StreamingService
    fn grpc_package_service_name(&self) -> Option<String> {
        if !self.is_grpc() || self.path.len() < 6 {
            return None;
        }

        let idx: Vec<_> = self.path.match_indices("/").collect();
        if idx.len() != 2 {
            return None;
        }
        let (start, end) = (idx[0].0, idx[1].0);
        if start + 1 == end {
            return None;
        }
        return Some(self.path[start + 1..end].to_string());
    }

    fn check_on_blacklist(&self, config: &LogParserConfig) -> bool {
        let Some(blacklist) = config.l7_log_blacklist_trie.get(&self.proto) else {
            return false;
        };

        if self.is_grpc() {
            if let Some(name) = self.service_name.as_ref() {
                if blacklist.request_resource.is_on_blacklist(name) {
                    return true;
                }
            }
        } else {
            if blacklist.request_resource.is_on_blacklist(&self.path) {
                return true;
            }
        }

        if blacklist.request_type.is_on_blacklist(self.method.as_str()) {
            return true;
        }

        if blacklist.request_domain.is_on_blacklist(&self.host) {
            return true;
        }

        if let Some(endpoint) = self.endpoint.as_ref() {
            if blacklist.endpoint.is_on_blacklist(endpoint) {
                return true;
            }
        }

        false
    }

    fn get_version(&self) -> Field {
        if self.proto == L7Protocol::Triple {
            return Field::Str(Cow::Borrowed(&self.dubbo_service_version.as_str()));
        }
        Field::Str(Cow::Borrowed(&self.version.as_str()))
    }

    fn set_version(&mut self, version: FieldSetter) {
        match version.into_inner() {
            Field::Str(s) => {
                if self.proto == L7Protocol::Triple {
                    self.dubbo_service_version = s.as_ref().to_string();
                } else {
                    self.version = Version::try_from(s.borrow()).unwrap_or_default();
                }
            }
            _ => self.version = Version::Unknown,
        }
    }

    fn get_method(&self) -> Field {
        Field::Str(Cow::Borrowed(self.method.as_str()))
    }

    fn set_method(&mut self, method: FieldSetter) {
        match method.into_inner() {
            Field::Str(s) => self.method = Method::try_from(s.borrow()).unwrap_or_default(),
            _ => self.method = Method::None,
        }
    }

    fn get_endpoint(&self) -> Field {
        if self.is_grpc() {
            if self.path.is_empty() {
                Field::None
            } else {
                Field::Str(Cow::Borrowed(&self.path))
            }
        } else {
            match self.endpoint.as_ref() {
                Some(s) if !s.is_empty() => Field::Str(Cow::Borrowed(s)),
                _ => Field::None,
            }
        }
    }

    fn set_endpoint(&mut self, endpoint: FieldSetter) {
        match endpoint.into_inner() {
            Field::Int(_) => return,
            Field::Str(s) if !s.is_empty() => {
                if self.is_grpc() {
                    self.path = s.into_owned();
                } else {
                    self.endpoint = Some(s.into_owned());
                }
            }
            _ => {
                if self.is_grpc() {
                    self.path = String::new();
                } else {
                    self.endpoint = None;
                }
            }
        }
    }

    fn get_trace_id(&self) -> Field {
        Field::Str(Cow::Borrowed(&self.trace_ids.highest()))
    }

    fn set_trace_id(&mut self, trace_id: FieldSetter) {
        let (prio, trace_id) = (trace_id.prio(), trace_id.into_inner());
        match trace_id {
            Field::Str(s) => {
                self.trace_ids.merge_field(prio, s.into_owned());
            }
            _ => return,
        }
    }
}

impl From<HttpInfo> for L7ProtocolSendLog {
    fn from(mut f: HttpInfo) -> Self {
        let is_grpc = f.is_grpc();

        // grpc protocol special treatment
        let (req_type, resource, domain, endpoint) = if is_grpc {
            // server endpoint = req_type
            (
                if f.msg_type != LogMessageType::Session {
                    String::from("POST") // grpc method always post, reference https://chromium.googlesource.com/external/github.com/grpc/grpc/+/HEAD/doc/PROTOCOL-HTTP2.md
                } else {
                    f.method.as_str().to_owned()
                },
                f.service_name.clone().unwrap_or_default(),
                f.host,
                f.path,
            )
        } else {
            (
                f.method.as_str().to_owned(),
                f.path.clone(),
                f.host,
                f.endpoint.unwrap_or_default(),
            )
        };
        let mut flags = ApplicationFlags::default();
        if f.is_tls {
            flags = flags | ApplicationFlags::TLS;
        };
        if f.is_async {
            flags = flags | ApplicationFlags::ASYNC;
        }
        if f.is_reversed {
            flags = flags | ApplicationFlags::REVERSED;
        }

        if f.status != L7ResponseStatus::Ok {
            if let Some(request_header) = f.request_header {
                f.attributes.push(KeyVal {
                    key: "request_header".to_string(),
                    val: String::from_utf8_lossy(request_header.as_slice()).to_string(),
                });
            }
            if let Some(request_payload) = f.request_payload {
                f.attributes.push(KeyVal {
                    key: "request_payload".to_string(),
                    val: String::from_utf8_lossy(request_payload.as_slice()).to_string(),
                });
            }
            if let Some(response_header) = f.response_header {
                f.attributes.push(KeyVal {
                    key: "response_header".to_string(),
                    val: String::from_utf8_lossy(response_header.as_slice()).to_string(),
                });
            }
            if let Some(response_payload) = f.response_payload {
                f.attributes.push(KeyVal {
                    key: "response_payload".to_string(),
                    val: String::from_utf8_lossy(response_payload.as_slice()).to_string(),
                });
            }
        }

        L7ProtocolSendLog {
            req_len: f.req_content_length,
            resp_len: f.resp_content_length,
            captured_request_byte: f.captured_request_byte,
            captured_response_byte: f.captured_response_byte,
            version: if f.proto == L7Protocol::Triple {
                Some(f.dubbo_service_version)
            } else {
                Some(f.version.as_str().to_owned())
            },
            req: L7Request {
                req_type,
                resource,
                domain,
                endpoint,
            },
            resp: L7Response {
                status: f.status,
                code: match f.proto {
                    L7Protocol::Grpc => {
                        if let Some(code) = f.grpc_status_code {
                            Some(code as i32)
                        } else if let Some(code) = f.status_code {
                            Some(code as i32)
                        } else {
                            None
                        }
                    }
                    _ => {
                        if let Some(code) = f.status_code {
                            Some(code as i32)
                        } else {
                            None
                        }
                    }
                },
                exception: if f.status != L7ResponseStatus::Ok {
                    f.custom_exception.unwrap_or_default()
                } else {
                    Default::default()
                },
                result: f.custom_result.unwrap_or_default(),
            },
            trace_info: Some(TraceInfo {
                trace_ids: f.trace_ids.to_strings(),
                span_id: Some(f.span_id.into_inner()),
                ..Default::default()
            }),
            ext_info: Some(ExtendedInfo {
                request_id: f.stream_id,
                x_request_id_0: Some(f.x_request_id_0.into_inner()),
                x_request_id_1: Some(f.x_request_id_1.into_inner()),
                client_ip: f.client_ip.map(|ip| ip.into_inner()),
                user_agent: f.user_agent,
                referer: f.referer,
                rpc_service: f.service_name,
                attributes: {
                    if f.attributes.is_empty() {
                        None
                    } else {
                        Some(f.attributes)
                    }
                },
                metrics: {
                    if f.metrics.is_empty() {
                        None
                    } else {
                        Some(f.metrics)
                    }
                },
                ..Default::default()
            }),
            flags: flags.bits(),
            biz_code: f.biz_code,
            biz_scenario: f.biz_scenario,
            ..Default::default()
        }
    }
}

impl From<&HttpInfo> for LogCache {
    fn from(info: &HttpInfo) -> Self {
        LogCache {
            msg_type: info.msg_type,
            resp_status: info.status,
            on_blacklist: info.is_on_blacklist,
            multi_merge_info: if info.need_merge() {
                Some(MultiMergeInfo {
                    req_end: info.is_req_end,
                    resp_end: info.is_resp_end,
                    merged: false,
                })
            } else {
                None
            },
            endpoint: L7ProtocolInfoInterface::get_endpoint(info),
            ..Default::default()
        }
    }
}

#[derive(Default)]
pub struct HttpLog {
    proto: L7Protocol,
    perf_stats: Option<L7PerfStats>,
    http2_req_decoder: Option<Decoder<'static>>,
    http2_resp_decoder: Option<Decoder<'static>>,

    #[cfg(feature = "enterprise")]
    custom_field_store: Store,
}

impl L7ProtocolParserInterface for HttpLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> Option<LogMessageType> {
        if param.l4_protocol != IpProtocol::TCP {
            return None;
        }

        let mut info = HttpInfo::default();

        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };
        // http2 有两个版本, 现在可以直接通过proto区分解析哪个版本的协议.
        match self.proto {
            L7Protocol::Http1 => self.http1_check_protocol(payload),
            L7Protocol::Http2 | L7Protocol::Grpc | L7Protocol::Triple => {
                let Some(config) = param.parse_config else {
                    return None;
                };
                if self.http2_req_decoder.is_none() {
                    self.set_header_decoder(config.l7_log_dynamic.expected_headers_set.clone());
                }
                match param.ebpf_type {
                    EbpfType::GoHttp2Uprobe
                    | EbpfType::GoHttp2UprobeData
                    | EbpfType::UnixSocket => {
                        if param.direction == PacketDirection::ServerToClient {
                            return None;
                        }
                        if self
                            .check_http2_go_uprobe(
                                &config.l7_log_dynamic,
                                payload,
                                param,
                                &mut info,
                                #[cfg(feature = "enterprise")]
                                None,
                            )
                            .is_ok()
                        {
                            Some(LogMessageType::Request)
                        } else {
                            None
                        }
                    }
                    _ => {
                        if self
                            .check_http_v2(
                                payload,
                                param,
                                &mut info,
                                #[cfg(feature = "enterprise")]
                                None,
                            )
                            .is_ok()
                            && info.msg_type != LogMessageType::Other
                        {
                            Some(LogMessageType::Request)
                        } else {
                            None
                        }
                    }
                }
            }
            _ => unreachable!(),
        }
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        let Some(config) = param.parse_config else {
            return Err(Error::NoParseConfig);
        };

        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };

        #[cfg(feature = "enterprise")]
        self.custom_field_store.clear();
        #[cfg(feature = "enterprise")]
        let custom_policies = config
            .l7_log_dynamic
            .get_custom_field_policies(self.proto.into(), param);

        match self.proto {
            L7Protocol::Http1 => {
                let mut info = HttpInfo {
                    proto: self.proto,
                    is_tls: param.is_tls(),
                    copy_apm_trace_id: config.l7_log_dynamic.copy_apm_trace_id,
                    ..Default::default()
                };

                let l7_payload = self.parse_http_v1(
                    payload,
                    param,
                    &mut info,
                    #[cfg(feature = "enterprise")]
                    custom_policies,
                )?;
                self.set_info_by_config(
                    param,
                    config,
                    payload,
                    Some(l7_payload),
                    &mut info,
                    #[cfg(feature = "enterprise")]
                    custom_policies,
                );

                if param.parse_log {
                    Ok(L7ParseResult::Single(L7ProtocolInfo::HttpInfo(info)))
                } else {
                    Ok(L7ParseResult::None)
                }
            }
            L7Protocol::Http2 | L7Protocol::Grpc | L7Protocol::Triple => {
                let mut infos = vec![];
                let mut offset = 0;
                let mut last_error = Err(Error::HttpHeaderParseFailed);

                if self.http2_req_decoder.is_none() {
                    self.set_header_decoder(config.l7_log_dynamic.expected_headers_set.clone());
                }

                loop {
                    if offset > payload.len() {
                        break;
                    }

                    let mut info = HttpInfo {
                        proto: self.proto,
                        is_tls: param.is_tls(),
                        copy_apm_trace_id: config.l7_log_dynamic.copy_apm_trace_id,
                        ..Default::default()
                    };

                    let ret = match param.ebpf_type {
                        EbpfType::GoHttp2Uprobe => self.parse_http2_go_uprobe(
                            &config.l7_log_dynamic,
                            &payload[offset..],
                            param,
                            &mut info,
                            #[cfg(feature = "enterprise")]
                            custom_policies,
                        ),
                        _ => self.parse_http_v2(
                            &payload[offset..],
                            param,
                            &mut info,
                            #[cfg(feature = "enterprise")]
                            custom_policies,
                        ),
                    };
                    let n = match ret {
                        Err(e) => {
                            last_error = Err(e);
                            break;
                        }
                        Ok(n) => n,
                    };
                    self.set_info_by_config(
                        param,
                        config,
                        &payload[offset..],
                        None,
                        &mut info,
                        #[cfg(feature = "enterprise")]
                        custom_policies,
                    );

                    if !info.is_invalid()
                        || info.proto == L7Protocol::Grpc
                        || info.proto == L7Protocol::Triple
                    {
                        if let Some(h) = info.headers_offset.as_mut() {
                            *h += offset as u32;
                        }
                        infos.push(L7ProtocolInfo::HttpInfo(info));
                    }

                    offset += n;
                }

                if param.parse_log {
                    if !infos.is_empty() {
                        Ok(L7ParseResult::Multi(infos))
                    } else {
                        last_error
                    }
                } else {
                    Ok(L7ParseResult::None)
                }
            }
            _ => unreachable!(),
        }
    }

    fn protocol(&self) -> L7Protocol {
        self.proto
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn reset(&mut self) {
        let mut new_log = match self.proto {
            L7Protocol::Http1 => Self::new_v1(),
            L7Protocol::Http2 => Self {
                proto: L7Protocol::Http2,
                ..Default::default()
            },
            L7Protocol::Grpc => Self {
                proto: L7Protocol::Grpc,
                ..Default::default()
            },
            L7Protocol::Triple => Self {
                proto: L7Protocol::Triple,
                ..Default::default()
            },
            _ => unreachable!(),
        };
        new_log.perf_stats = self.perf_stats.take();
        new_log.http2_req_decoder = self.http2_req_decoder.take();
        new_log.http2_resp_decoder = self.http2_resp_decoder.take();
        *self = new_log;
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

impl HttpLog {
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

    pub fn new_triple() -> Self {
        Self {
            proto: L7Protocol::Triple,
            ..Default::default()
        }
    }

    fn set_info_by_config(
        &mut self,
        param: &ParseParam,
        config: &LogParserConfig,
        payload: &[u8],
        l7_payload: Option<&[u8]>,
        info: &mut HttpInfo,
        #[cfg(feature = "enterprise")] custom_policies: Option<PolicySlice>,
    ) {
        if config
            .obfuscate_enabled_protocols
            .is_enabled(L7Protocol::Http1)
            || config
                .obfuscate_enabled_protocols
                .is_enabled(L7Protocol::Http2)
        {
            if let Some(index) = info.path.find('?') {
                info.path.truncate(index + 1); // retain `?`
            }
        }
        info.service_name = info.grpc_package_service_name();
        if !config.http_endpoint_disabled && info.path.len() > 0 {
            // Priority use of info.endpoint, because info.endpoint may be set by the wasm plugin
            let path = match info.endpoint.as_ref() {
                Some(p) if !p.is_empty() => p,
                _ => &info.path,
            };
            info.endpoint = Some(handle_endpoint(config, path));
        }

        let l7_dynamic_config = &config.l7_log_dynamic;
        if param.direction == PacketDirection::ServerToClient {
            if let Some(code) = info.grpc_status_code {
                self.set_grpc_status(code, info);
            } else if let Some(code) = info.status_code {
                self.set_status(code, info);
            } else {
                // default to ok
                info.status = L7ResponseStatus::Ok;
            }

            if let Some(l7_payload) = l7_payload {
                if info.status != L7ResponseStatus::Ok {
                    if l7_dynamic_config.error_response_header > 0 {
                        let error_response_header = (payload.len() - l7_payload.len())
                            .min(l7_dynamic_config.error_response_header);
                        if error_response_header > 0 {
                            info.response_header = Some(payload[..error_response_header].to_vec());
                        }
                    }
                    if l7_dynamic_config.error_response_payload > 0 {
                        let error_response_payload = l7_payload
                            .len()
                            .min(l7_dynamic_config.error_response_payload);
                        if error_response_payload > 0 {
                            info.response_payload =
                                Some(l7_payload[..error_response_payload].to_vec());
                        }
                    }
                }
            }
        } else {
            if let Some(l7_payload) = l7_payload {
                if l7_dynamic_config.error_request_header > 0 {
                    let error_request_header = (payload.len() - l7_payload.len())
                        .min(l7_dynamic_config.error_request_header);
                    if error_request_header > 0 {
                        info.request_header = Some(payload[..error_request_header].to_vec());
                    }
                } else {
                    info.request_header = Some(vec![]);
                }

                if l7_dynamic_config.error_request_payload > 0 {
                    let error_request_payload = l7_payload
                        .len()
                        .min(l7_dynamic_config.error_request_payload);
                    if error_request_payload > 0 {
                        info.request_payload = Some(l7_payload[..error_request_payload].to_vec());
                    }
                } else {
                    info.request_payload = Some(vec![]);
                }
            }
        }

        #[cfg(feature = "enterprise")]
        self.merge_custom_fields(custom_policies, l7_payload, info);

        // In uprobe mode, headers are reported in a way different from other modes:
        // one payload contains one header.
        // Calling wasm plugin on every payload would be wasted effort,
        // in this condition the call to the wasm plugin will be skipped.
        if param.ebpf_type != EbpfType::GoHttp2Uprobe {
            self.wasm_hook(param, payload, info);
        }

        info.is_on_blacklist = info.check_on_blacklist(config);

        if let Some(perf_stats) = self.perf_stats.as_mut() {
            if info.msg_type == LogMessageType::Response {
                if let Some(endpoint) = info.load_endpoint_from_cache(param, info.is_reversed) {
                    info.endpoint = Some(endpoint.to_string());
                }
            }
            if let Some(stats) = info.perf_stats(param) {
                info.rrt = stats.rrt_sum;
                perf_stats.sequential_merge(&stats);
            }
        }
    }

    fn set_header_decoder(&mut self, expected_headers_set: Arc<HashSet<Vec<u8>>>) {
        self.http2_req_decoder = Some(Decoder::new_with_expected_headers(
            expected_headers_set.clone(),
        ));
        self.http2_resp_decoder = Some(Decoder::new_with_expected_headers(expected_headers_set));
    }

    fn http1_check_protocol(&mut self, payload: &[u8]) -> Option<LogMessageType> {
        let mut headers = parse_v1_headers(payload);
        let Some(first_line) = headers.next() else {
            // request is not http v1 without '\r\n'
            return None;
        };

        if is_http_req_line(first_line) {
            Some(LogMessageType::Request)
        } else {
            None
        }
    }

    fn set_grpc_status(&mut self, status_code: u16, info: &mut HttpInfo) {
        match status_code {
            GRPC_STATUS_OK => info.status = L7ResponseStatus::Ok,
            GRPC_STATUS_CANCELLED
            | GRPC_STATUS_INVALID_ARGUMENT
            | GRPC_STATUS_FAILED_PRECONDITION
            | GRPC_STATUS_OUT_OF_RANGE
            | GRPC_STATUS_UNAUTHENTICATED
            | GRPC_STATUS_NOT_FOUND..=GRPC_STATUS_PERMISSION_DENIED => {
                info.status = L7ResponseStatus::ClientError;
            }
            _ => {
                info.status = L7ResponseStatus::ServerError;
            }
        }
    }

    fn set_status(&mut self, status_code: u16, info: &mut HttpInfo) {
        if status_code >= HTTP_STATUS_CLIENT_ERROR_MIN
            && status_code <= HTTP_STATUS_CLIENT_ERROR_MAX
        {
            info.status = L7ResponseStatus::ClientError;
        } else if status_code >= HTTP_STATUS_SERVER_ERROR_MIN
            && status_code <= HTTP_STATUS_SERVER_ERROR_MAX
        {
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
    pub fn check_http2_go_uprobe(
        &mut self,
        config: &L7LogDynamicConfig,
        payload: &[u8],
        param: &ParseParam,
        info: &mut HttpInfo,
        #[cfg(feature = "enterprise")] custom_policies: Option<PolicySlice>,
    ) -> Result<usize> {
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
        info.msg_type = LogMessageType::from(direction);

        let val_offset = HTTPV2_CUSTOM_DATA_MIN_LENGTH + key_len;
        let key = &payload[HTTPV2_CUSTOM_DATA_MIN_LENGTH..val_offset];
        let val = &payload[val_offset..val_offset + val_len];
        self.on_header(config, key, val, direction, info)?;
        #[cfg(feature = "enterprise")]
        if let Some(policies) = custom_policies {
            if let Some((key, val)) = str::from_utf8(key).ok().zip(str::from_utf8(val).ok()) {
                policies.apply(
                    &mut self.custom_field_store,
                    direction.into(),
                    Source::Header(key, val),
                );
                if key == ":path" {
                    policies.apply(
                        &mut self.custom_field_store,
                        direction.into(),
                        Source::Url(&info.path),
                    );
                }
            }
        }

        let content_length = if key == b"content-length" {
            Some(val.parse_to().unwrap_or_default())
        } else {
            None
        };

        if self.proto == L7Protocol::Grpc {
            info.method = Method::from_ebpf_type(param.ebpf_type, param.direction);
            let ret = Self::modify_http2_and_grpc(
                config.grpc_streaming_data_enabled,
                direction,
                content_length,
                stream_id,
                info,
            );
            if ret.is_err() || info.is_invalid() {
                return Err(Error::HttpHeaderParseFailed);
            }

            Ok(payload.len())
        } else {
            info.version = Version::V2;
            info.stream_id = Some(stream_id);
            Ok(payload.len())
        }
    }

    pub fn parse_http2_go_uprobe(
        &mut self,
        config: &L7LogDynamicConfig,
        payload: &[u8],
        param: &ParseParam,
        info: &mut HttpInfo,
        #[cfg(feature = "enterprise")] custom_policies: Option<PolicySlice>,
    ) -> Result<usize> {
        let n = self.check_http2_go_uprobe(
            config,
            payload,
            param,
            info,
            #[cfg(feature = "enterprise")]
            custom_policies,
        )?;
        set_captured_byte!(info, param);
        Ok(n)
    }

    // Note: Windows is compiled using Rust 1.75.0 and does not support the APIs added in the higher
    // version of Rust.
    #[cfg(target_os = "windows")]
    pub const fn trim_ascii_start(bytes: &[u8]) -> &[u8] {
        let mut bytes = bytes;
        // Note: A pattern matching based approach (instead of indexing) allows
        // making the function const.
        while let [first, rest @ ..] = bytes {
            if first.is_ascii_whitespace() {
                bytes = rest;
            } else {
                break;
            }
        }
        bytes
    }

    pub fn parse_http_v1<'a>(
        &mut self,
        payload: &'a [u8],
        param: &ParseParam,
        info: &mut HttpInfo,
        #[cfg(feature = "enterprise")] custom_policies: Option<PolicySlice>,
    ) -> Result<&'a [u8]> {
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
            const HTTP_STATUS_CODE_CONTINUE: u16 = 100;
            const HTTP_STATUS_CODE_PROCESSING: u16 = 102;
            const HTTP_STATUS_CODE_EARLY_HINTS: u16 = 103;
            // HTTP响应行：HTTP/1.1 404 Not Found.
            let (version, status_code) = get_http_resp_info(first_line)?;
            // reference https://developer.mozilla.org/en-US/docs/Web/HTTP/Status the 100 102 103 status code should be ignore
            // because it will have the actually response after the send the full request
            if status_code == HTTP_STATUS_CODE_CONTINUE
                || status_code == HTTP_STATUS_CODE_PROCESSING
                || status_code == HTTP_STATUS_CODE_EARLY_HINTS
            {
                return Err(Error::HttpHeaderParseFailed);
            }
            info.version = version;
            info.status_code = Some(status_code);

            info.msg_type = LogMessageType::Response;
        } else {
            // HTTP请求行：GET /background.png HTTP/1.0
            let Ok((method, path, version)) = get_http_request_info(first_line) else {
                return Err(Error::HttpHeaderParseFailed);
            };

            info.method = method;
            info.path = path.to_owned();
            info.version = get_http_request_version(version)?;
            info.msg_type = LogMessageType::Request;

            #[cfg(feature = "enterprise")]
            if let Some(policies) = custom_policies {
                policies.apply(
                    &mut self.custom_field_store,
                    direction.into(),
                    Source::Url(&info.path),
                );
            }
        }

        let mut content_length: Option<u32> = None;
        for body_line in headers.by_ref() {
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
            let trim_value = value.trim();
            self.on_header(
                config,
                lower_key.as_bytes(),
                trim_value.as_bytes(),
                direction,
                info,
            )?;

            if &lower_key == "content-length" {
                content_length = Some(value.trim_start().parse::<u32>().unwrap_or_default());
            }

            #[cfg(feature = "enterprise")]
            if let Some(policies) = custom_policies {
                policies.apply(
                    &mut self.custom_field_store,
                    direction.into(),
                    Source::Header(key, trim_value),
                );
            }
        }

        #[cfg(target_os = "linux")]
        let l7_payload = headers.remaining_buf().trim_ascii_start();
        #[cfg(target_os = "windows")]
        let l7_payload = Self::trim_ascii_start(headers.remaining_buf());

        set_captured_byte!(info, param);
        // 当解析完所有Header仍未找到Content-Length，则认为该字段值为0
        if direction == PacketDirection::ServerToClient {
            info.resp_content_length = content_length;
        } else {
            info.req_content_length = content_length;
        }

        #[cfg(feature = "enterprise")]
        if let Some(policies) = custom_policies {
            policies.apply(
                &mut self.custom_field_store,
                direction.into(),
                Source::Payload(PayloadType::JSON | PayloadType::XML, l7_payload),
            );
        }

        Ok(l7_payload)
    }

    fn has_magic(payload: &[u8]) -> bool {
        if payload.len() < HTTPV2_MAGIC_LENGTH {
            return false;
        }
        &payload[..HTTPV2_MAGIC_PREFIX.len()] == HTTPV2_MAGIC_PREFIX.as_bytes()
    }

    fn modify_http2_and_grpc(
        grpc_streaming_data_enabled: bool,
        direction: PacketDirection,
        content_length: Option<u32>,
        stream_id: u32,
        info: &mut HttpInfo,
    ) -> Result<usize> {
        info.version = Version::V2;
        if info.stream_id.is_none() {
            info.stream_id = Some(stream_id);
        }

        match info.proto {
            L7Protocol::Grpc | L7Protocol::Triple => match (direction, info.method) {
                (PacketDirection::ClientToServer, Method::_RequestData) => {
                    if !grpc_streaming_data_enabled {
                        return Err(Error::HttpHeaderParseFailed);
                    }
                    info.msg_type = LogMessageType::Session;
                    if content_length.is_some() {
                        info.req_content_length = content_length;
                    }
                }
                (PacketDirection::ServerToClient, Method::_ResponseData) => {
                    if !grpc_streaming_data_enabled {
                        return Err(Error::HttpHeaderParseFailed);
                    }
                    info.msg_type = LogMessageType::Session;
                    if content_length.is_some() {
                        info.resp_content_length = content_length;
                    }
                }
                (PacketDirection::ServerToClient, Method::_ResponseHeader) => {
                    if info.grpc_status_code.is_none() {
                        match info.status_code {
                            None | Some(0) => return Err(Error::HttpHeaderParseFailed),
                            _ => (),
                        }
                        if !grpc_streaming_data_enabled {
                            info.msg_type = LogMessageType::Response;
                        } else {
                            info.msg_type = LogMessageType::Session;
                        }
                    }
                    if content_length.is_some() {
                        info.resp_content_length = content_length;
                    }
                }
                (PacketDirection::ClientToServer, _) => {
                    if content_length.is_some() {
                        info.req_content_length = content_length;
                    }
                }
                (PacketDirection::ServerToClient, _) => {
                    if content_length.is_some() {
                        info.resp_content_length = content_length;
                    }
                }
            },
            _ => {
                if direction == PacketDirection::ClientToServer {
                    if content_length.is_some() {
                        info.req_content_length = content_length;
                    }
                } else {
                    if content_length.is_some() {
                        info.resp_content_length = content_length;
                    }
                }
            }
        }
        Ok(0)
    }

    fn check_http_v2(
        &mut self,
        payload: &[u8],
        param: &ParseParam,
        info: &mut HttpInfo,
        #[cfg(feature = "enterprise")] custom_policies: Option<PolicySlice>,
    ) -> Result<usize> {
        let (direction, config) = (
            param.direction,
            &param.parse_config.as_ref().unwrap().l7_log_dynamic,
        );
        let grpc_streaming_data_enabled = config.grpc_streaming_data_enabled;
        let mut content_length: Option<u32> = None;
        let mut header_frame_parsed = false;
        let mut is_httpv2 = false;
        let mut frame_payload = payload;
        let mut httpv2_header = Httpv2Headers::default();
        let mut headers_offset = 0;
        let mut stream_id = 0;
        let mut offset = 0;

        while frame_payload.len() > HTTPV2_FRAME_HEADER_LENGTH {
            if Self::has_magic(frame_payload) {
                frame_payload = &frame_payload[HTTPV2_MAGIC_LENGTH..];
                headers_offset += HTTPV2_MAGIC_LENGTH;
                offset += HTTPV2_MAGIC_LENGTH;
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

            offset += httpv2_header.frame_length as usize + HTTPV2_FRAME_HEADER_LENGTH;

            if httpv2_header.stream_id == 0 {
                // Headers和Data帧的StreamId不为0
                // 参考协议：https://tools.ietf.org/html/rfc7540#section-6.2
                if httpv2_header.frame_length as usize + HTTPV2_FRAME_HEADER_LENGTH
                    >= frame_payload.len()
                {
                    break;
                }
                frame_payload = &frame_payload
                    [httpv2_header.frame_length as usize + HTTPV2_FRAME_HEADER_LENGTH..];
                headers_offset += httpv2_header.frame_length as usize + HTTPV2_FRAME_HEADER_LENGTH;
                continue;
            }

            if stream_id == 0 && httpv2_header.stream_id != 0 {
                stream_id = httpv2_header.stream_id;
            } else if stream_id != 0 && stream_id != httpv2_header.stream_id {
                return Ok(offset);
            }

            frame_payload = &frame_payload[HTTPV2_FRAME_HEADER_LENGTH..];

            if !header_frame_parsed && httpv2_header.frame_type == HTTPV2_FRAME_HEADERS_TYPE {
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

                let mut decoder = if param.direction == PacketDirection::ClientToServer {
                    self.http2_req_decoder.take().unwrap()
                } else {
                    self.http2_resp_decoder.take().unwrap()
                };

                let result = decoder.decode_with_cb(header_frame_payload, |key, val| {
                    let key: &[u8] = &key;
                    let val: &[u8] = &val;
                    let _ = self.on_header(config, key, val, direction, info);
                    if key == b"content-length" {
                        content_length = Some(val.parse_to().unwrap_or_default())
                    }
                    #[cfg(feature = "enterprise")]
                    if let Some(policies) = custom_policies {
                        if let Some((key, val)) =
                            str::from_utf8(key).ok().zip(str::from_utf8(val).ok())
                        {
                            policies.apply(
                                &mut self.custom_field_store,
                                direction.into(),
                                Source::Header(key, val),
                            );
                            if key == ":path" {
                                policies.apply(
                                    &mut self.custom_field_store,
                                    direction.into(),
                                    Source::Url(&info.path),
                                );
                            }
                        }
                    }
                });
                if param.direction == PacketDirection::ClientToServer {
                    self.http2_req_decoder.replace(decoder);
                } else {
                    self.http2_resp_decoder.replace(decoder);
                }

                if result.is_err() {
                    return Err(Error::HttpHeaderParseFailed);
                }

                header_frame_parsed = true;

                if self.proto == L7Protocol::Grpc {
                    info.method =
                        Method::from_frame_type(httpv2_header.frame_type, param.direction);
                }
                if info.headers_offset.is_none() || info.grpc_status_code.is_some() {
                    info.headers_offset = Some(headers_offset as u32);
                }

                if content_length.is_some() {
                    is_httpv2 = true;
                    break;
                }
            } else if (header_frame_parsed
                || self.proto == L7Protocol::Grpc
                || self.proto == L7Protocol::Triple)
                && httpv2_header.frame_type == HTTPV2_FRAME_DATA_TYPE
            {
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

                is_httpv2 = true;
                if info.method.is_none() {
                    info.method =
                        Method::from_frame_type(httpv2_header.frame_type, param.direction);
                }

                if httpv2_header.is_stream_end() {
                    break;
                }

                if httpv2_header.frame_length >= frame_payload.len() as u32 {
                    break;
                }

                header_frame_parsed = false;
            }

            if httpv2_header.stream_id > 0 {
                info.stream_id = Some(httpv2_header.stream_id);
            }
            if httpv2_header.frame_length >= frame_payload.len() as u32 {
                break;
            }
            frame_payload = &frame_payload[httpv2_header.frame_length as usize..];
            headers_offset += httpv2_header.frame_length as usize + HTTPV2_FRAME_HEADER_LENGTH;
        }
        // 流量中可能仅存在Headers帧且Headers帧中没有传输实体，“Content-Length”为0
        if header_frame_parsed && !is_httpv2 {
            if !content_length.is_some() {
                content_length = Some(0);
            }
            is_httpv2 = true;
        }

        if is_httpv2 {
            if info.msg_type == LogMessageType::Other {
                info.msg_type = LogMessageType::from(direction);
            }
            Self::modify_http2_and_grpc(
                grpc_streaming_data_enabled,
                direction,
                content_length,
                httpv2_header.stream_id,
                info,
            )?;

            return Ok(offset);
        }

        Err(Error::HttpHeaderParseFailed)
    }

    fn parse_http_v2(
        &mut self,
        payload: &[u8],
        param: &ParseParam,
        info: &mut HttpInfo,
        #[cfg(feature = "enterprise")] custom_policies: Option<PolicySlice>,
    ) -> Result<usize> {
        let n = self.check_http_v2(
            payload,
            param,
            info,
            #[cfg(feature = "enterprise")]
            custom_policies,
        )?;
        set_captured_byte!(info, param);
        Ok(n)
    }

    fn on_header(
        &mut self,
        config: &L7LogDynamicConfig,
        key: &[u8],
        val: &[u8],
        direction: PacketDirection,
        info: &mut HttpInfo,
    ) -> Result<()> {
        // key must be valid utf8
        let Ok(key) = str::from_utf8(key) else {
            return Ok(());
        };

        match key {
            ":method" => {
                info.msg_type = LogMessageType::Request;
                info.method = Method::try_from(String::from_utf8_lossy(val).as_ref())?;
            }
            ":status" => {
                info.msg_type = LogMessageType::Response;
                let code: u16 = val.parse_to().unwrap_or_default();
                info.status_code = Some(code);
            }
            "host" | ":authority" => info.host = String::from_utf8_lossy(val).into_owned(),
            ":path" if info.path.is_empty() => {
                info.path = String::from_utf8_lossy(val).into_owned();
            }
            "grpc-status" if config.grpc_streaming_data_enabled => {
                info.msg_type = LogMessageType::Response;
                let code = val.parse_to().unwrap_or_default();
                info.grpc_status_code = Some(code);
            }
            "tri-service-version" => {
                // change to triple protocol
                self.proto = L7Protocol::Triple;
                info.proto = L7Protocol::Triple;
                info.method = Method::Post;
                info.dubbo_service_version = String::from_utf8_lossy(val).into_owned();
            }
            "content-type" if self.proto != L7Protocol::Triple => {
                // change to grpc protocol
                if val.starts_with(b"application/grpc") {
                    self.proto = L7Protocol::Grpc;
                    info.proto = L7Protocol::Grpc;
                }
            }
            _ => {}
        }

        if !key.is_ascii() {
            return Ok(());
        }

        // value must be valid utf8 from here
        let Ok(val) = str::from_utf8(val) else {
            return Ok(());
        };

        if config.is_trace_id(key) {
            for (i, trace) in config.trace_types.iter().enumerate() {
                let prio = i as u8 + BASE_FIELD_PRIORITY;
                if info.trace_ids.highest_priority() <= prio && !config.multiple_trace_id_collection
                {
                    break;
                }
                if !trace.check(key) {
                    continue;
                }

                if let Some(trace_id) = trace.decode_trace_id(val) {
                    if info.copy_apm_trace_id {
                        info.copy_apm_trace_id = false;
                        info.attributes.push(KeyVal {
                            key: APM_TRACE_ID_ATTR.to_string(),
                            val: trace_id.to_string(),
                        });
                    }
                    info.trace_ids.merge_field(prio, trace_id.to_string());
                }
            }
        }
        if config.is_span_id(key) {
            for (i, span) in config.span_types.iter().enumerate() {
                let prio = i as u8 + BASE_FIELD_PRIORITY;
                if info.span_id.prio() <= prio {
                    break;
                }
                if !span.check(key) {
                    continue;
                }
                span.decode_span_id(val)
                    .map(|id| info.span_id = PrioField::new(prio, id.to_string()));
            }
        }

        let x_req_id = if direction == PacketDirection::ClientToServer {
            &mut info.x_request_id_0
        } else {
            &mut info.x_request_id_1
        };
        for (i, req_id) in config.x_request_id.iter().enumerate() {
            let prio = i as u8 + BASE_FIELD_PRIORITY;
            if x_req_id.prio() <= prio {
                break;
            }
            if req_id == key {
                *x_req_id = PrioField::new(prio, val.to_owned());
                break;
            }
        }

        if direction == PacketDirection::ClientToServer {
            for (i, pc) in config.proxy_client.iter().enumerate() {
                let prio = i as u8 + BASE_FIELD_PRIORITY;
                match info.client_ip.as_ref() {
                    Some(p) if p.prio() <= prio => break,
                    _ => (),
                }
                if pc == key {
                    info.client_ip = Some(PrioField::new(prio, val.to_owned()));
                    break;
                }
            }
        }

        fn process_attributes(
            config: &L7LogDynamicConfig,
            info: &mut HttpInfo,
            key: &str,
            val: &str,
        ) {
            let field_iter = match info.proto {
                L7Protocol::Http1 => config.extra_log_fields.http.iter(),
                L7Protocol::Http2 | L7Protocol::Grpc | L7Protocol::Triple => {
                    config.extra_log_fields.http2.iter()
                }
                _ => return,
            };

            info.attributes.extend(field_iter.filter_map(|f| {
                if f.field_name.eq_ignore_ascii_case(key) {
                    Some(KeyVal {
                        key: key.replace("-", "_"),
                        val: val.to_owned(),
                    })
                } else {
                    None
                }
            }));
        }

        process_attributes(config, info, key, val);

        Ok(())
    }

    fn wasm_hook(&mut self, param: &ParseParam, payload: &[u8], info: &mut HttpInfo) {
        let mut vm_ref = param.wasm_vm.borrow_mut();
        let Some(vm) = vm_ref.as_mut() else {
            return;
        };
        match param.direction {
            PacketDirection::ClientToServer => vm.on_http_req(payload, param, info),
            PacketDirection::ServerToClient => vm.on_http_resp(payload, param, info),
        }
        .map(|custom| {
            info.merge_custom_to_http(custom, param.direction);
        });
    }

    #[cfg(feature = "enterprise")]
    fn merge_custom_fields(
        &mut self,
        policies: Option<PolicySlice>,
        l7_payload: Option<&[u8]>,
        info: &mut HttpInfo,
    ) {
        let Some(policies) = policies else {
            return;
        };

        for op in self.custom_field_store.drain_with(policies, &*info) {
            match &op.op {
                Op::RewriteNativeTag(tag, value) => {
                    match tag {
                        // req
                        NativeTag::RequestType => {
                            if info.method.is_none() {
                                info.method = Method::try_from(value.as_str()).unwrap_or_default();
                            }
                        }
                        // trace
                        NativeTag::SpanId => {
                            if CUSTOM_FIELD_POLICY_PRIORITY <= info.span_id.prio() {
                                let prev = mem::replace(
                                    &mut info.span_id,
                                    PrioField::new(CUSTOM_FIELD_POLICY_PRIORITY, value.to_string()),
                                );
                                if !prev.is_default() {
                                    info.attributes.push(KeyVal {
                                        key: APM_SPAN_ID_ATTR.to_string(),
                                        val: prev.into_inner(),
                                    });
                                }
                            }
                        }
                        _ => auto_merge_custom_field(op, info),
                    }
                }
                Op::AddMetric(key, value) => {
                    info.metrics.push(MetricKeyVal {
                        key: key.to_string(),
                        val: *value,
                    });
                }
                Op::SavePayload(key) => {
                    if let Some(l7_payload) = l7_payload {
                        info.attributes.push(KeyVal {
                            key: key.to_string(),
                            val: String::from_utf8_lossy(l7_payload).to_string(),
                        });
                    }
                }
                _ => auto_merge_custom_field(op, info),
            }
        }
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
    thread_local! {
        static VALID_FLAGS_FOR_HTTP2_FRAME_TYPE: OnceCell<HashMap<u8, u8>> = OnceCell::new();
    }

    fn validate_flags(frame_type: u8, flags: u8) -> bool {
        Self::VALID_FLAGS_FOR_HTTP2_FRAME_TYPE.with(|f| {
            let valid_map = f.get_or_init(|| {
                // Check https://datatracker.ietf.org/doc/html/rfc9113#name-frame-definitions for valid flags for each frame type
                HashMap::from([
                    (0x00, 0b00001001),
                    (0x01, 0b00101101),
                    (0x02, 0b00000000),
                    (0x03, 0b00000000),
                    (0x04, 0b00000001),
                    (0x05, 0b00001100),
                    (0x06, 0b00000001),
                    (0x07, 0b00000000),
                    (0x08, 0b00000000),
                    (0x09, 0b00000100),
                ])
            });
            match valid_map.get(&frame_type) {
                None => false,
                Some(vf) => (!vf) & flags == 0,
            }
        })
    }

    const FLAGS_STREAM_END: u8 = 1;
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

        let flags = payload[4];
        if !Self::validate_flags(frame_type, flags) {
            return Err(Error::HttpHeaderParseFailed);
        }

        if payload[5] & 0x80 != 0 {
            return Err(Error::HttpHeaderParseFailed);
        }

        self.frame_length = read_u32_be(&payload) >> 8;
        self.frame_type = frame_type;
        self.flags = flags;
        self.stream_id = read_u32_be(&payload[5..]);

        Ok(())
    }

    fn is_stream_end(&self) -> bool {
        self.flags & Self::FLAGS_STREAM_END == Self::FLAGS_STREAM_END
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

// check if `s` starts with `prefix` and a space
fn has_prefix(s: &[u8], prefix: &[u8]) -> bool {
    s.len() >= prefix.len() + 1 && s.starts_with(prefix) && s[prefix.len()] == b' '
}

pub fn is_http_v1_payload(buf: &[u8]) -> bool {
    if buf.starts_with(RESPONSE_PREFIX.as_bytes()) {
        return true;
    }
    HTTP_METHODS
        .iter()
        .position(|m| has_prefix(buf, m.as_bytes()))
        .is_some()
}

// check first line is http request line
pub fn is_http_req_line(line: &str) -> bool {
    if line.len() < "GET / HTTP/1.1".len() {
        return false;
    }

    // consider use prefix tree in future
    if HTTP_METHODS
        .iter()
        .position(|m| has_prefix(line.as_bytes(), m.as_bytes()))
        .is_none()
    {
        return false;
    };
    match line.rsplit_once(' ') {
        Some((_, "HTTP/0.9" | "HTTP/1.0" | "HTTP/1.1")) => true,
        _ => false,
    }
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

pub fn get_http_request_version(version: &str) -> Result<Version> {
    // 参考：https://baike.baidu.com/item/HTTP/243074?fr=aladdin#2
    // HTTPv1版本只有1.0及1.1
    match version {
        HTTP_V1_0_VERSION => return Ok(Version::V1_0),
        HTTP_V1_1_VERSION => return Ok(Version::V1_1),
        _ => return Err(Error::HttpHeaderParseFailed),
    }
}

pub fn get_http_request_info(line_info: &str) -> Result<(Method, &str, &str)> {
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
            Method::try_from(str::from_utf8_unchecked(method.unwrap()))?,
            str::from_utf8_unchecked(path.unwrap()),
            str::from_utf8_unchecked(version.unwrap()),
        ))
    }
}

pub fn get_http_resp_info(line_info: &str) -> Result<(Version, u16)> {
    const VERSION_LEN: usize = HTTP_V1_0_VERSION.len();
    const CODE_OFFSET: usize = VERSION_LEN + 1;
    const CODE_LEN: usize = 3;
    if line_info.len() < HTTP_RESP_MIN_LEN || !line_info.is_ascii() {
        return Err(Error::HttpHeaderParseFailed);
    }
    // HTTP response line: HTTP/1.1 404 Not Found.
    let version = match &line_info[..VERSION_LEN] {
        HTTP_V1_0_VERSION => Version::V1_0,
        HTTP_V1_1_VERSION => Version::V1_1,
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

impl<'a> V1HeaderIterator<'a> {
    pub fn remaining_buf(&self) -> &'a [u8] {
        self.0
    }
}

impl<'a> Iterator for V1HeaderIterator<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.len() < 2 {
            return None;
        }

        const SEP: &[u8] = b"\r\n";
        match self.0.windows(2).position(|w| w == SEP) {
            Some(end) if end != 0 => match str::from_utf8(&self.0[..end]) {
                Ok(s) => {
                    self.0 = &self.0[end + 2..];
                    return Some(s);
                }
                _ => (),
            },
            Some(end) if end == 0 => {
                self.0 = &self.0[end + 2..];
            }
            _ => (),
        }
        None
    }
}

pub fn parse_v1_headers(payload: &[u8]) -> V1HeaderIterator<'_> {
    V1HeaderIterator(payload)
}

pub fn handle_endpoint(config: &LogParserConfig, path: &String) -> String {
    let keep_segments = config.http_endpoint_trie.find_matching_rule(path);
    if keep_segments <= 0 {
        return "".to_string();
    }
    let output = path.split('?').next().unwrap();
    let cleaned_output = output.split('/').collect::<Vec<&str>>();
    let mut start = 0;
    let mut end = 0;
    let mut k = 0;
    // if endpoint start with '/', remove excess '/'
    if let Some(f) = cleaned_output.get(start) {
        if f.is_empty() {
            start += 1;
            end += 1;
        }
    }
    for (i, segment) in cleaned_output.iter().enumerate() {
        if k >= keep_segments {
            break;
        }
        if segment.is_empty() || segment.eq(&".") {
            continue;
        }
        k += 1;
        end = i + 1;
    }
    format!("/{}", cleaned_output[start..end].join("/"))
}

#[cfg(test)]
mod tests {
    use crate::config::{
        config::TagFilterOperator,
        handler::{BlacklistTrie, L7LogDynamicConfigBuilder, LogParserConfig, TraceType},
        HttpEndpoint, HttpEndpointMatchRule, HttpEndpointTrie,
    };
    use crate::flow_generator::L7_RRT_CACHE_CAPACITY;
    use crate::utils::test::Capture;
    use crate::{
        common::{
            l7_protocol_log::{EbpfParam, L7PerfCache},
            MetaPacket,
        },
        config::{config::Iso8583ParseConfig, OracleConfig},
    };

    use std::cell::RefCell;
    use std::collections::HashSet;
    use std::fmt;
    use std::fs;
    use std::mem::size_of;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::Path;
    use std::rc::Rc;
    use std::slice::from_raw_parts;
    use std::time::Duration;

    use super::*;

    const FILE_DIR: &str = "resources/test/flow_generator/http";

    struct ValidateInfo<'a>(&'a HttpInfo);

    impl<'a> fmt::Display for ValidateInfo<'a> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("HttpInfo")
                .field("headers_offset", &self.0.headers_offset)
                .field("proto", &self.0.proto)
                .field("msg_type", &self.0.msg_type)
                .field("stream_id", &self.0.stream_id)
                .field("version", &self.0.version)
                .field("trace_ids", &self.0.trace_ids)
                .field("span_id", &self.0.span_id)
                .field("method", &self.0.method)
                .field("path", &self.0.path)
                .field("host", &self.0.host)
                .field("user_agent", &self.0.user_agent)
                .field("referer", &self.0.referer)
                .field("client_ip", &self.0.client_ip)
                .field("x_request_id_0", &self.0.x_request_id_0)
                .field("x_request_id_1", &self.0.x_request_id_1)
                .field("req_content_length", &self.0.req_content_length)
                .field("resp_content_length", &self.0.resp_content_length)
                .field("status_code", &self.0.status_code)
                .field("status", &self.0.status)
                .field("grpc_status_code", &self.0.grpc_status_code)
                .field("endpoint", &self.0.endpoint)
                .field("custom_result", &self.0.custom_result)
                .field("custom_exception", &self.0.custom_exception)
                .field("captured_request_byte", &self.0.captured_request_byte)
                .field("captured_response_byte", &self.0.captured_response_byte)
                .field("biz_type", &self.0.biz_type)
                .field("attributes", &self.0.attributes)
                .field("service_name", &self.0.service_name)
                .finish()
        }
    }

    fn run(name: &str, grpc_streaming_data_enabled: bool) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name));
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let mut packets = capture.collect::<Vec<_>>();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
        let config: L7LogDynamicConfig = L7LogDynamicConfigBuilder {
            proxy_client: vec!["x-forwarded-for".to_owned()],
            trace_types: vec![TraceType::Sw8],
            span_types: vec![TraceType::Sw8],
            grpc_streaming_data_enabled,
            ..Default::default()
        }
        .into();
        let parse_config = &LogParserConfig {
            l7_log_collect_nps_threshold: 10,
            l7_log_session_aggr_timeout: [
                (L7Protocol::Http1, Duration::from_secs(10)),
                (L7Protocol::Http2, Duration::from_secs(10)),
                (L7Protocol::Grpc, Duration::from_secs(10)),
            ]
            .into(),
            l7_log_dynamic: config.clone(),
            ..Default::default()
        };
        let mut http1 = HttpLog::new_v1();
        let mut http2 = HttpLog::new_v2(false);
        let mut protocol = L7Protocol::Unknown;
        http1.set_header_decoder(config.expected_headers_set.clone());
        http2.set_header_decoder(config.expected_headers_set.clone());
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
            trace_set.insert(TraceType::Sw8.as_str());
            let mut span_set = HashSet::new();
            span_set.insert(TraceType::Sw8.as_str());
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
            param.set_log_parser_config(parse_config);

            let get_http_info = |i: L7ProtocolInfo| match i {
                L7ProtocolInfo::HttpInfo(mut h) => {
                    h.rrt = 0;
                    h
                }
                _ => unreachable!(),
            };

            match protocol {
                L7Protocol::Http1 => {
                    if let Ok(info) = http1.parse_payload(payload, param) {
                        output.push_str(&format!(
                            "{} is_http: {}\n",
                            ValidateInfo(&get_http_info(info.unwrap_single())),
                            true
                        ));
                    } else {
                        let mut info = HttpInfo::default();
                        info.proto = protocol;
                        output.push_str(&format!("{} is_http: {}\n", ValidateInfo(&info), false));
                    }
                }
                L7Protocol::Http2 | L7Protocol::Grpc => {
                    if let Ok(info) = http2.parse_payload(payload, param) {
                        match info {
                            L7ParseResult::Multi(m) => {
                                for i in m {
                                    output.push_str(&format!(
                                        "{} is_http: {}\n",
                                        ValidateInfo(&get_http_info(i)),
                                        true
                                    ))
                                }
                            }
                            L7ParseResult::Single(s) => output.push_str(&format!(
                                "{} is_http: {}\n",
                                ValidateInfo(&get_http_info(s)),
                                true
                            )),
                            _ => (),
                        };
                    } else {
                        let mut info = HttpInfo::default();
                        info.proto = protocol;
                        output.push_str(&format!("{} is_http: {}\n", ValidateInfo(&info), false));
                    }
                }
                _ => {
                    if let Ok(info) = http1.parse_payload(payload, param) {
                        protocol = L7Protocol::Http1;
                        output.push_str(&format!(
                            "{} is_http: {}\n",
                            ValidateInfo(&get_http_info(info.unwrap_single())),
                            true
                        ));
                    } else if let Ok(info) = http2.parse_payload(payload, param) {
                        protocol = L7Protocol::Http2;
                        match info {
                            L7ParseResult::Multi(m) => {
                                for i in m {
                                    output.push_str(&format!(
                                        "{} is_http: {}\n",
                                        ValidateInfo(&get_http_info(i)),
                                        true
                                    ))
                                }
                            }
                            L7ParseResult::Single(s) => output.push_str(&format!(
                                "{} is_http: {}\n",
                                ValidateInfo(&get_http_info(s)),
                                true
                            )),
                            _ => (),
                        };
                    } else {
                        let mut info = HttpInfo::default();
                        info.proto = protocol;
                        output.push_str(&format!("{} is_http: {}\n", ValidateInfo(&info), false));
                    }
                }
            }
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
            ("grpc-service-name.pcap", "grpc-service-name.result"),
            ("http2-multi.pcap", "http2-multi.result"),
            ("grpc-unknown.pcap", "grpc-unknown.result"),
            ("grpc-server-stream.pcap", "grpc-server-stream.result"),
            ("httpv1.pcap", "httpv1.result"),
            ("sw8.pcap", "sw8.result"),
            ("h2c_ascii.pcap", "h2c_ascii.result"),
            ("httpv2-stream-id.pcap", "httpv2-stream-id.result"),
            ("istio-tcp-frag.pcap", "istio-tcp-frag.result"),
            ("client-ip.pcap", "client-ip.result"),
            ("grpc-segmented.pcap", "grpc-segmented.result"),
        ];
        for item in files.iter() {
            let expected = fs::read_to_string(&Path::new(FILE_DIR).join(item.1)).unwrap();
            let output = run(item.0, true);

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
    fn check_grpc_unary() {
        let files = vec![
            (
                "grpc-server-stream.pcap",
                "grpc-server-stream-as-unary.result",
            ),
            ("grpc-unary.pcap", "grpc-unary.result"),
        ];
        for item in files.iter() {
            let expected = fs::read_to_string(&Path::new(FILE_DIR).join(item.1)).unwrap();
            let output = run(item.0, false);

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
                process_kname: "",
            }),
            packet_start_seq: 0,
            packet_end_seq: 0,
            time: 0,
            parse_perf: true,
            parse_log: true,
            parse_config: Some(&conf),
            l7_perf_cache: Rc::new(RefCell::new(L7PerfCache::new(1))),
            wasm_vm: Default::default(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            so_func: Default::default(),
            stats_counter: None,
            rrt_timeout: Duration::from_secs(10).as_micros() as usize,
            buf_size: 0,
            captured_byte: 1000,
            oracle_parse_conf: OracleConfig::default(),
            iso8583_parse_conf: Iso8583ParseConfig::default(),
            icmp_data: None,
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
                    #[cfg(feature = "enterprise")]
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
            let mut info = HttpInfo::default();
            let payload = hdr.to_bytes(key, val);
            let mut h = HttpLog::new_v2(false);
            info.raw_data_type = L7ProtoRawDataType::GoHttp2Uprobe;
            let res = h.parse_http2_go_uprobe(
                &L7LogDynamicConfig::default(),
                &payload,
                param,
                &mut info,
                #[cfg(feature = "enterprise")]
                None,
            );
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
    fn panic_caused_by_invalid_header() {
        let packet = MetaPacket::empty();
        let mut param = ParseParam::new(
            &packet,
            Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY))),
            Default::default(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Default::default(),
            true,
            true,
        );
        let parse_config = LogParserConfig::default();
        param.l4_protocol = IpProtocol::TCP;
        param.set_log_parser_config(&parse_config);

        let mut payload = "GET / HTTP/1.1\r\naccepd:  */*\r\n".as_bytes().to_vec();
        // change one of the bytes to simulate corrupted header
        payload[23] = 155;

        let _ = HttpLog::new_v1().parse_http_v1(
            &payload,
            &param,
            &mut HttpInfo::default(),
            #[cfg(feature = "enterprise")]
            None,
        );
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
                    ..Default::default()
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
                    ..Default::default()
                },
            ),
            (
                "grpc-server-stream.pcap",
                L7PerfStats {
                    request_count: 2,
                    response_count: 5,
                    err_client_count: 0,
                    err_server_count: 0,
                    err_timeout: 0,
                    rrt_count: 1,
                    rrt_sum: 2506326,
                    rrt_max: 2506326,
                    ..Default::default()
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
        assert_eq!(
            expected[2].1,
            run_perf(expected[2].0, HttpLog::new_v2(true)),
            "parse pcap {} unexcepted",
            expected[2].0
        );
    }

    fn run_perf(pcap: &str, mut http: HttpLog) -> L7PerfStats {
        let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));

        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(pcap));
        let mut packets = capture.collect::<Vec<_>>();

        let first_dst_port = packets[0].lookup_key.dst_port;

        let mut config = LogParserConfig::default();
        config.l7_log_dynamic.grpc_streaming_data_enabled = true;
        if http.protocol() == L7Protocol::Http2 || http.protocol() == L7Protocol::Grpc {
            http.set_header_decoder(config.l7_log_dynamic.expected_headers_set.clone());
        }

        for packet in packets.iter_mut() {
            if packet.lookup_key.dst_port == first_dst_port {
                packet.lookup_key.direction = PacketDirection::ClientToServer;
            } else {
                packet.lookup_key.direction = PacketDirection::ServerToClient;
            }
            if packet.get_l4_payload().is_some() {
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
                let _ = http.parse_payload(packet.get_l4_payload().unwrap(), param);
            }
        }
        http.perf_stats.unwrap()
    }

    #[test]
    fn blacklist() {
        fn execute_case(config: &LogParserConfig, packets: &[MetaPacket]) -> L7PerfStats {
            let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));
            let mut http = HttpLog::new_v1();
            for packet in packets {
                let Some(payload) = packet.get_l4_payload() else {
                    continue;
                };
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
                let _ = http.parse_payload(payload, param);
            }
            http.perf_stats.unwrap()
        }

        let capture = Capture::load_pcap(Path::new(FILE_DIR).join("httpv1.pcap"));
        let mut packets = capture.collect::<Vec<_>>();
        packets[0].lookup_key.direction = PacketDirection::ClientToServer;
        packets[1].lookup_key.direction = PacketDirection::ServerToClient;

        let config = LogParserConfig::default();
        let blacklist_config = LogParserConfig {
            l7_log_blacklist_trie: HashMap::from([(
                L7Protocol::Http1,
                BlacklistTrie::new(&vec![TagFilterOperator {
                    field_name: "endpoint".to_string(),
                    operator: "prefix".to_string(),
                    value: "/query".to_string(),
                }])
                .unwrap(),
            )]),
            ..Default::default()
        };
        let expected = L7PerfStats {
            request_count: 1,
            response_count: 1,
            rrt_count: 1,
            rrt_sum: 84051,
            rrt_max: 84051,
            ..Default::default()
        };

        // normal order
        let stats = execute_case(&config, &packets);
        assert_eq!(stats, expected);

        // normal with blacklist
        let stats = execute_case(&blacklist_config, &packets);
        assert_eq!(stats, Default::default());

        // reversed
        packets.reverse();
        let stats = execute_case(&config, &packets);
        assert_eq!(stats, expected);

        // reversed with blacklist
        let stats = execute_case(&blacklist_config, &packets);
        assert_eq!(stats, Default::default());
    }

    #[test]
    fn test_handle_endpoint() {
        let mut config = LogParserConfig::default();
        let path = String::from("");
        let expected_output = "/"; // take "/" for an empty string
        assert_eq!(handle_endpoint(&config, &path), expected_output.to_string());
        let path = String::from("api/v1/users");
        let expected_output = "/api/v1";
        assert_eq!(handle_endpoint(&config, &path), expected_output.to_string());
        let path = String::from("/api/v1/users/123");
        let expected_output = "/api/v1"; // the default value is 2 segments
        assert_eq!(handle_endpoint(&config, &path), expected_output.to_string());
        let path = String::from("/api/v1/users/123?query=456");
        let expected_output = "/api/v1"; // without parameters
        assert_eq!(handle_endpoint(&config, &path), expected_output.to_string());
        let path = String::from("///././/api/v1//.//./users/123?query=456");
        let expected_output = "///././/api/v1"; // appear continuous "/" or appear "."
        assert_eq!(handle_endpoint(&config, &path), expected_output.to_string());
        let trie = HttpEndpointTrie::from(&HttpEndpoint {
            extraction_disabled: false,
            match_rules: vec![HttpEndpointMatchRule {
                url_prefix: "/api".to_string(),
                keep_segments: 1,
            }],
        });
        config.http_endpoint_trie = trie;
        let path = String::from("/api/v1/users/123?query=456");
        let expected_output = "/api"; // prefixes match, take 1 segment
        assert_eq!(handle_endpoint(&config, &path), expected_output.to_string());
        let path = String::from("/app/v1/users/123?query=456");
        let expected_output = ""; // prefixes do not match, endpoint is ""
        assert_eq!(handle_endpoint(&config, &path), expected_output.to_string());
        let trie = HttpEndpointTrie::from(&HttpEndpoint {
            extraction_disabled: false,
            match_rules: vec![
                HttpEndpointMatchRule {
                    url_prefix: "/api".to_string(),
                    keep_segments: 1,
                },
                HttpEndpointMatchRule {
                    url_prefix: "/api/v1/users".to_string(),
                    keep_segments: 4,
                },
            ],
        });
        config.http_endpoint_trie = trie;
        let path = String::from("/api/v1/users/123?query=456");
        let expected_output = "/api/v1/users/123"; // longest prefix match: /api/v1/users, take 4 segments
        assert_eq!(handle_endpoint(&config, &path), expected_output.to_string());
        let path = String::from("/api/v1/users?query=456");
        let expected_output = "/api/v1/users"; // the longest prefix matches: /api/v1/users, but there are only 3 segments in path
        assert_eq!(handle_endpoint(&config, &path), expected_output.to_string());
        let path = String::from("/api/v1/123?query=456");
        let expected_output = "/api"; // longest prefix match: /api, take 1 segment
        assert_eq!(handle_endpoint(&config, &path), expected_output.to_string());
        let trie = HttpEndpointTrie::from(&HttpEndpoint {
            extraction_disabled: false,
            match_rules: vec![HttpEndpointMatchRule {
                url_prefix: "".to_string(),
                keep_segments: 3,
            }],
        });
        config.http_endpoint_trie = trie;
        let path = String::from("/api/v1/users/123?query=456");
        let expected_output = "/api/v1/users"; // the default value is changed to 3 segments
        assert_eq!(handle_endpoint(&config, &path), expected_output.to_string());
        let trie = HttpEndpointTrie::from(&HttpEndpoint {
            extraction_disabled: false,
            match_rules: vec![HttpEndpointMatchRule {
                url_prefix: "/api/v1".to_string(),
                keep_segments: 0,
            }],
        });
        config.http_endpoint_trie = trie;
        let path = String::from("/api/v1/users/123?query=456");
        let expected_output = "/api/v1"; // prefixes match, but the keep_segments is 0, use the default value 2 segments
        assert_eq!(handle_endpoint(&config, &path), expected_output.to_string());
    }

    #[test]
    fn header_priority() {
        let mut parser = HttpLog::new_v1();
        let mut info = HttpInfo::default();
        let config = L7LogDynamicConfigBuilder {
            proxy_client: vec!["X_Forwarded_For".into(), "Client".into()],
            x_request_id: vec!["X_Request_ID".into(), "x-request-id".into()],
            trace_types: vec!["x-b3-traceid".into(), "traceparent".into(), "sw8".into()],
            span_types: vec!["x-b3-spanid".into(), "traceparent".into(), "sw8".into()],
            ..Default::default()
        }
        .into();

        // check field overwritten by higher priority field but not backwards
        let _ = parser.on_header(
            &config,
            b"Client",
            b"172.1.23.41",
            PacketDirection::ClientToServer,
            &mut info,
        );
        assert_eq!(
            info.client_ip.as_ref().map(|ip| ip.get().as_str()),
            Some("172.1.23.41")
        );
        let _ = parser.on_header(
            &config,
            b"X_Forwarded_For",
            b"172.1.23.42",
            PacketDirection::ClientToServer,
            &mut info,
        );
        assert_eq!(
            info.client_ip.as_ref().map(|ip| ip.get().as_str()),
            Some("172.1.23.42")
        );
        let _ = parser.on_header(
            &config,
            b"Client",
            b"172.1.23.41",
            PacketDirection::ClientToServer,
            &mut info,
        );
        assert_eq!(
            info.client_ip.as_ref().map(|ip| ip.get().as_str()),
            Some("172.1.23.42")
        );

        let _ = parser.on_header(
            &config,
            b"x-request-id",
            b"123",
            PacketDirection::ClientToServer,
            &mut info,
        );
        assert_eq!(info.x_request_id_0.get(), "123");
        let _ = parser.on_header(
            &config,
            b"X_Request_ID",
            b"456",
            PacketDirection::ClientToServer,
            &mut info,
        );
        assert_eq!(info.x_request_id_0.get(), "456");
        let _ = parser.on_header(
            &config,
            b"x-request-id",
            b"123",
            PacketDirection::ClientToServer,
            &mut info,
        );
        assert_eq!(info.x_request_id_0.get(), "456");

        let _ = parser.on_header(
            &config,
            b"traceparent",
            b"00-trace-span-01",
            PacketDirection::ClientToServer,
            &mut info,
        );
        let _ = parser.on_header(
            &config,
            b"x-b3-traceid",
            b"b3traceid",
            PacketDirection::ClientToServer,
            &mut info,
        );
        assert_eq!(info.trace_ids.highest(), "b3traceid");
        let _ = parser.on_header(
            &config,
            b"traceparent",
            b"00-trace-span-01",
            PacketDirection::ClientToServer,
            &mut info,
        );
        assert_eq!(info.trace_ids.highest(), "b3traceid");
        assert_eq!(info.span_id.get(), "span");
    }

    #[test]
    fn segmented_tcp_false_positive() {
        let packet = MetaPacket::empty();
        let mut param = ParseParam::new(
            &packet,
            Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY))),
            Default::default(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Default::default(),
            true,
            true,
        );
        param.l4_protocol = IpProtocol::TCP;

        let mut parser = HttpLog::new_v1();
        assert!(parser
            .check_payload(
                concat!(r#"POST","name":"一些中文""#, "\r\nblablabla\r\n").as_bytes(),
                &param
            )
            .is_none());
        assert!(parser
            .check_payload("GET / HTTP/1.1\r\n\r\n".as_bytes(), &param)
            .is_some());
    }
}
