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
use log::debug;
use nom::{AsBytes, ParseTo};
use serde::Serialize;

use public::l7_protocol::{
    Field, FieldSetter, L7Log, L7LogAttribute, L7ProtocolChecker, LogMessageType,
};
use public_derive::L7Log;

use super::{
    consts::*,
    openai_api,
    pb_adapter::{
        ExtendedInfo, KeyVal, L7ProtocolSendLog, L7Request, L7Response, MetricKeyVal, TraceInfo,
    },
    serialize_attributes, value_is_default, AppProtoHead, L7ResponseStatus, PrioField,
};

#[cfg(feature = "libtrace")]
use crate::utils::bytes::read_u32_le;
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
    utils::bytes::read_u32_be,
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

    pub endpoint: Option<String>,
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
    #[serde(skip_serializing_if = "value_is_default")]
    biz_response_code: String,

    #[serde(
        serialize_with = "serialize_attributes",
        skip_serializing_if = "Vec::is_empty"
    )]
    attributes: Vec<KeyVal>,

    #[serde(skip)]
    metrics: Vec<MetricKeyVal>,

    /// OpenAI API accumulated session state; Some only when this HttpInfo
    /// carries OpenAI-specific data (request biz-dims, response metrics, etc.).
    #[serde(skip)]
    pub openai_session: Option<Box<openai_api::OpenAISession>>,

    /// True when this is an OpenAI streaming request that requires multi-merge.
    /// Drives `need_merge()` for HTTP/1 streaming sessions.
    #[serde(skip)]
    openai_need_merge: bool,

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
            _ => self.openai_need_merge,
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
        if let Some(biz_response_code) = custom.biz_response_code {
            self.biz_response_code = biz_response_code;
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
                // For OpenAI multi-merge: the request entry is cached with is_req_end=false
                // so the session aggregator doesn't discard it. Each response packet
                // carries is_req_end=true so we propagate it here to let is_session_end()
                // = is_req_end && is_resp_end eventually return true.
                // For normal HTTP this is a no-op since responses never set is_req_end.
                if other.is_req_end {
                    self.is_req_end = true;
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
        super::swap_if!(self, biz_response_code, is_empty, other);

        let other_trace_ids = mem::take(&mut other.trace_ids);
        self.trace_ids.merge(other_trace_ids);
        super::swap_if!(self, span_id, is_default, other);
        super::swap_if!(self, x_request_id_0, is_default, other);
        super::swap_if!(self, x_request_id_1, is_default, other);
        self.attributes.append(&mut other.attributes);
        self.metrics.append(&mut other.metrics);

        // Merge OpenAI session: the response (or final SSE packet) carries the
        // fully-accumulated session. Always prefer the incoming session over the
        // stored one because:
        //   • For non-streaming: the request stores a partial clone; the response
        //     has the complete session with parsed usage.
        //   • For streaming: the request stores None; the final SSE packet has the
        //     complete session.
        // Replacing unconditionally is safe — SSE continuations that have not
        // completed yet carry None, so the `if let` guard prevents overwriting.
        if let Some(other_session) = other.openai_session.take() {
            debug!(
                "openai: merge – {} openai_session (kind={:?} events={} usage={:?})",
                if self.openai_session.is_some() {
                    "replacing"
                } else {
                    "setting"
                },
                other_session.kind,
                other_session.stream_event_count,
                other_session.usage.as_ref().map(|u| u.total_tokens),
            );
            self.openai_session = Some(other_session);
        }
        if other.openai_need_merge {
            self.openai_need_merge = true;
        }

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

    fn get_version(&self) -> Field<'_> {
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

    fn get_method(&self) -> Field<'_> {
        Field::Str(Cow::Borrowed(self.method.as_str()))
    }

    fn set_method(&mut self, method: FieldSetter) {
        match method.into_inner() {
            Field::Str(s) => self.method = Method::try_from(s.borrow()).unwrap_or_default(),
            _ => self.method = Method::None,
        }
    }

    fn get_endpoint(&self) -> Field<'_> {
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

    fn get_trace_id(&self) -> Field<'_> {
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

        // OpenAI API: populate attributes/metrics from the accumulated session state.
        let openai_protocol_str = if let Some(session) = f.openai_session.take() {
            let (ttft, tpot) = session.compute_timings();
            debug!(
                "openai: converting to send log: kind={:?} stream={} usage_status={:?} \
                 events={} ttft={:?} tpot={:?} tokens={:?} stream_end_ts={:?} req_ts={}",
                session.kind,
                session.is_stream,
                session.usage_status,
                session.stream_event_count,
                ttft,
                tpot,
                session.usage.as_ref().map(|u| u.total_tokens),
                session.stream_end_ts_us,
                session.request_ts_us,
            );
            // Biz dimension attrs (org_path/user_id/app_id) are pushed directly to
            // f.attributes at REQUEST time so they appear even on timed-out sessions.
            // populate_log also emits them (to capture body-sourced attrs from TCP
            // continuation segments). Remove the direct-push duplicates first so the
            // merged log has each attr exactly once with the latest session value.
            f.attributes.retain(|kv| {
                kv.key != openai_api::ATTR_BIZ_ORG_PATH
                    && kv.key != openai_api::ATTR_BIZ_USER_ID
                    && kv.key != openai_api::ATTR_BIZ_APP_ID
            });
            session.populate_log(&mut f.attributes, &mut f.metrics);
            Some(openai_api::BIZ_PROTOCOL.to_string())
        } else {
            None
        };

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
                protocol_str: openai_protocol_str,
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
            biz_response_code: f.biz_response_code,
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
    perf_stats: Vec<L7PerfStats>,
    http2_req_decoder: Option<Decoder<'static>>,
    http2_resp_decoder: Option<Decoder<'static>>,

    /// Per-session OpenAI state accumulated across multiple response packets.
    /// Created when an OpenAI streaming request is first seen; cleared when the
    /// stream ends or the session is reset.
    openai_session: Option<Box<openai_api::OpenAISession>>,

    #[cfg(feature = "enterprise")]
    custom_field_store: Store,
}

impl L7ProtocolParserInterface for HttpLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> Option<LogMessageType> {
        if param.l4_protocol != IpProtocol::TCP {
            return None;
        }

        let mut info = HttpInfo::default();

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
                    #[cfg(feature = "libtrace")]
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

        self.perf_stats.clear();

        #[cfg(feature = "enterprise")]
        self.custom_field_store.clear();
        #[cfg(feature = "enterprise")]
        let custom_policies = config.get_custom_field_policies(self.proto.into(), param);

        match self.proto {
            L7Protocol::Http1 => {
                // Per-packet trace: only at debug level to avoid flooding production logs.
                if config.openai_api.enabled && param.direction == PacketDirection::ServerToClient {
                    debug!(
                        "openai: flow={} parse_payload Http1 direction={:?} \
                         len={} starts={:?} session={}",
                        param.flow_id,
                        param.direction,
                        payload.len(),
                        &payload[..payload.len().min(8)],
                        if self.openai_session.is_some() {
                            "Some"
                        } else {
                            "None"
                        },
                    );
                }

                let mut info = HttpInfo {
                    proto: self.proto,
                    is_tls: param.is_tls(),
                    copy_apm_trace_id: config.l7_log_dynamic.copy_apm_trace_id,
                    ..Default::default()
                };

                // Try standard HTTP/1 parsing first.
                let parse_result = self.parse_http_v1(
                    payload,
                    param,
                    &mut info,
                    #[cfg(feature = "enterprise")]
                    custom_policies,
                );

                match parse_result {
                    Ok(l7_payload) => {
                        self.set_info_by_config(
                            param,
                            config,
                            payload,
                            Some(l7_payload),
                            &mut info,
                            #[cfg(feature = "enterprise")]
                            custom_policies,
                        );

                        // OpenAI API enhancement after successful HTTP parse.
                        self.handle_openai_http1(payload, l7_payload, param, config, &mut info);

                        if param.parse_log {
                            Ok(L7ParseResult::Single(L7ProtocolInfo::HttpInfo(info)))
                        } else {
                            Ok(L7ParseResult::None)
                        }
                    }
                    Err(http_err) => {
                        // Not a valid HTTP/1 header – check if this is an OpenAI SSE
                        // continuation packet belonging to an active streaming session.
                        if let Some(sse_info) =
                            self.handle_openai_sse_continuation(payload, param, config)
                        {
                            if param.parse_log {
                                Ok(L7ParseResult::Single(L7ProtocolInfo::HttpInfo(sse_info)))
                            } else {
                                Ok(L7ParseResult::None)
                            }
                        } else {
                            Err(http_err)
                        }
                    }
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
                        #[cfg(feature = "libtrace")]
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
        new_log.perf_stats = self.perf_stats();
        new_log.http2_req_decoder = self.http2_req_decoder.take();
        new_log.http2_resp_decoder = self.http2_resp_decoder.take();
        // Preserve an active OpenAI streaming session across per-packet resets.
        // reset() is called after every packet; without this the RESPONSE packet
        // would find openai_session=None because the REQUEST packet's session was
        // discarded. Matches the same pattern as http2_req/resp_decoder above.
        new_log.openai_session = self.openai_session.take();
        *self = new_log;
    }

    fn perf_stats(&mut self) -> Vec<L7PerfStats> {
        std::mem::take(&mut self.perf_stats)
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
        self.merge_custom_fields(custom_policies, payload, l7_payload, info);

        // In uprobe mode, headers are reported in a way different from other modes:
        // one payload contains one header.
        // Calling wasm plugin on every payload would be wasted effort,
        // in this condition the call to the wasm plugin will be skipped.
        if param.ebpf_type != EbpfType::GoHttp2Uprobe {
            self.wasm_hook(param, payload, info);
        }

        info.is_on_blacklist = info.check_on_blacklist(config);

        if param.parse_perf {
            let mut perf_stat = L7PerfStats::default();
            if info.msg_type == LogMessageType::Response && info.endpoint.is_none() {
                if let Some(endpoint) = info.load_endpoint_from_cache(param, info.is_reversed) {
                    info.endpoint = Some(endpoint.to_string());
                }
            }
            if let Some(stats) = info.perf_stats(param) {
                info.rrt = stats.rrt_sum;
                perf_stat.sequential_merge(&stats);
            }
            self.perf_stats.push(perf_stat);
        }
    }

    fn set_header_decoder(&mut self, expected_headers_set: Arc<HashSet<Vec<u8>>>) {
        self.http2_req_decoder = Some(Decoder::new_with_expected_headers(
            expected_headers_set.clone(),
        ));
        self.http2_resp_decoder = Some(Decoder::new_with_expected_headers(expected_headers_set));
    }

    // ─── OpenAI API integration helpers ─────────────────────────────────────

    /// Called after a successful HTTP/1 parse to apply OpenAI-specific logic:
    /// - On request: create/init an OpenAISession if the path matches.
    /// - On response: feed the body into the SSE state machine or parse JSON usage.
    fn handle_openai_http1(
        &mut self,
        full_payload: &[u8],
        body: &[u8],
        param: &ParseParam,
        config: &LogParserConfig,
        info: &mut HttpInfo,
    ) {
        if !config.openai_api.enabled {
            return;
        }

        match info.msg_type {
            LogMessageType::Request => {
                if info.method != Method::Post {
                    return;
                }
                if !openai_api::is_openai_path(&info.path, config) {
                    debug!(
                        "openai: flow={} path={} not matched by prefixes={:?} suffixes={:?}",
                        param.flow_id,
                        info.path,
                        config.openai_api.path_prefixes,
                        config.openai_api.path_suffixes
                    );
                    return;
                }

                let kind = openai_api::kind_from_path(&info.path);
                let mut session = Box::new(openai_api::OpenAISession::new(
                    kind,
                    false,
                    param.time,
                    config.openai_api.sse_buffer_max_bytes,
                    &config.openai_api.usage_field_paths,
                ));

                self.extract_openai_headers_from_payload(full_payload, &mut session, config);

                if !body.is_empty() {
                    openai_api::parse_request_body(&mut session, body, config);
                }

                // is_req_end must stay false: the session aggregator discards any
                // first-seen packet with need_merge=true && (req_end || resp_end).
                // The response side propagates is_req_end back via merge().
                info.stream_id = Some(session.stream_id);
                info.is_resp_end = false;
                info.openai_need_merge = true;

                debug!(
                    "openai: flow={} REQUEST path={} kind={:?} stream={} stream_id={} \
                     biz_user={:?} biz_app={:?} biz_org={:?} body_bytes={}",
                    param.flow_id,
                    info.path,
                    kind,
                    session.is_stream,
                    session.stream_id,
                    session.biz_user_id,
                    session.biz_app_id,
                    session.biz_org_path,
                    body.len(),
                );

                // Write biz-dimension attributes on the request packet so they survive
                // even if the final merged entry loses them.
                if let Some(v) = &session.biz_org_path {
                    info.attributes.push(KeyVal {
                        key: openai_api::ATTR_BIZ_ORG_PATH.to_string(),
                        val: v.clone(),
                    });
                }
                if let Some(v) = &session.biz_user_id {
                    info.attributes.push(KeyVal {
                        key: openai_api::ATTR_BIZ_USER_ID.to_string(),
                        val: v.clone(),
                    });
                }
                if let Some(v) = &session.biz_app_id {
                    info.attributes.push(KeyVal {
                        key: openai_api::ATTR_BIZ_APP_ID.to_string(),
                        val: v.clone(),
                    });
                }

                // For non-streaming sessions, also attach a clone of the initial
                // session state to the REQUEST info. If the response is never seen
                // (packet drop, MTU issue, etc.) the session-aggregator times out
                // the REQUEST entry but it will still be tagged as openai-api with
                // the request-side metadata (path, biz dimensions).
                // When the real response arrives, merge() replaces this clone with
                // the response's fully-populated session.
                if !session.is_stream {
                    info.openai_session = Some(session.clone());
                }

                self.openai_session = Some(session);
            }

            LogMessageType::Response => {
                let (stream_id, is_already_stream) = match self.openai_session.as_ref() {
                    Some(s) => (s.stream_id, s.is_stream),
                    None => {
                        debug!(
                            "openai: flow={} RESPONSE arrived but no openai_session \
                             (mid-flow capture or session already finished)",
                            param.flow_id
                        );
                        return;
                    }
                };

                info.stream_id = Some(stream_id);
                // is_req_end=true will be propagated into the stored REQUEST entry
                // via merge(), satisfying is_session_end() = is_req_end && is_resp_end.
                info.is_req_end = true;
                info.openai_need_merge = true;

                // Scan headers once and derive both flags from the same pass.
                let (is_sse, is_chunked) = Self::response_sse_and_chunked(full_payload, body);
                let is_stream = is_already_stream || is_sse;

                debug!(
                    "openai: flow={} RESPONSE stream_id={} status={:?} is_already_stream={} \
                     is_sse={} is_chunked={} body_bytes={}",
                    param.flow_id,
                    stream_id,
                    info.status_code,
                    is_already_stream,
                    is_sse,
                    is_chunked,
                    body.len(),
                );

                // Propagate chunked flag to the session so continuation packets
                // can decode chunk framing before feeding to the SSE state machine.
                if is_chunked {
                    if let Some(s) = self.openai_session.as_mut() {
                        s.is_chunked_transfer = true;
                    }
                }

                if is_stream {
                    let done = {
                        let session = self.openai_session.as_mut().unwrap();
                        session.is_stream = true;
                        // Upgrade Unknown → Missing now that we know this is a stream.
                        // Unknown means "not yet determined"; Missing means "expected but
                        // not yet seen", which is the correct state for an in-progress SSE.
                        if session.usage_status == openai_api::UsageStatus::Unknown {
                            session.usage_status = openai_api::UsageStatus::Missing;
                        }
                        // For chunked SSE, the first response body is empty (headers
                        // only) so feed_sse is a no-op here; actual SSE events arrive
                        // in subsequent continuation packets.
                        session.feed_sse(body, param.time)
                    };
                    info.is_resp_end = done;
                    debug!(
                        "openai: flow={} SSE response fed stream_id={} done={} \
                         events={} usage_status={:?}",
                        param.flow_id,
                        stream_id,
                        done,
                        self.openai_session
                            .as_ref()
                            .map(|s| s.stream_event_count)
                            .unwrap_or(0),
                        self.openai_session
                            .as_ref()
                            .map(|s| s.usage_status)
                            .unwrap_or_default(),
                    );
                    if done {
                        info.openai_session = self.openai_session.take();
                    }
                } else {
                    {
                        let session = self.openai_session.as_mut().unwrap();
                        if !body.is_empty() {
                            openai_api::parse_response_json(session, body, config);
                        }
                        // Non-streaming: stream ends at the response packet.
                        session.stream_end_ts_us = Some(param.time);
                    }
                    info.is_resp_end = true;
                    info.openai_session = self.openai_session.take();
                    debug!(
                        "openai: flow={} non-stream RESPONSE done stream_id={} usage_status={:?}",
                        param.flow_id,
                        stream_id,
                        info.openai_session
                            .as_ref()
                            .map(|s| s.usage_status)
                            .unwrap_or_default(),
                    );
                }
            }

            _ => {}
        }
    }

    /// Scan raw HTTP/1 headers in `payload` and extract OpenAI biz dimensions.
    fn extract_openai_headers_from_payload(
        &self,
        payload: &[u8],
        session: &mut openai_api::OpenAISession,
        config: &LogParserConfig,
    ) {
        let mut headers = parse_v1_headers(payload);
        let _ = headers.next(); // skip request line
        for line in headers {
            if let Some(col) = line.find(':') {
                if col + 1 >= line.len() {
                    continue;
                }
                // extract_biz_from_header uses eq_ignore_ascii_case internally,
                // so no need to lowercase here.
                let key = line[..col].trim();
                let val = line[col + 1..].trim();
                openai_api::extract_biz_from_header(session, key, val, config);
            }
        }
    }

    /// Scan the HTTP/1 response headers once and return `(is_sse, is_chunked)`.
    ///
    /// Combining both checks avoids two separate O(n) scans for `\r\n\r\n`.
    fn response_sse_and_chunked(full_payload: &[u8], body: &[u8]) -> (bool, bool) {
        // Fast path: body already starts with SSE markers (no header scan needed).
        let body_is_sse = body.starts_with(b"data:") || body.starts_with(b"event:");

        // Find the end of headers (single O(n) scan).
        let header_end = full_payload
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .unwrap_or(full_payload.len());
        let headers = &full_payload[..header_end];

        // Case-insensitive header search without allocation: compare each
        // window byte-by-byte with the lower-case needle.
        let header_contains = |needle: &[u8]| -> bool {
            if headers.len() < needle.len() {
                return false;
            }
            headers.windows(needle.len()).any(|w| {
                w.iter()
                    .zip(needle.iter())
                    .all(|(a, b)| a.to_ascii_lowercase() == *b)
            })
        };

        let is_sse = body_is_sse || header_contains(b"text/event-stream");
        let is_chunked = header_contains(b"transfer-encoding: chunked");
        (is_sse, is_chunked)
    }

    /// Handle raw TCP payload that is NOT a valid HTTP/1 header but belongs to
    /// an active OpenAI session. Covers three cases:
    ///
    /// 1. **Request body continuation** (`ClientToServer`): when the POST body arrives
    ///    in a separate TCP segment from the headers, parse it to detect `"stream": true`
    ///    before the response arrives.
    ///
    /// 2. **SSE continuation** (`is_stream=true`, `ServerToClient`): feed the raw bytes
    ///    into the SSE state machine and forward progress to the session aggregator.
    ///
    /// 3. **Non-streaming fallback** (`is_stream=false`, `ServerToClient`): when
    ///    `parse_http_v1` fails for a non-streaming response (e.g., body-only TCP
    ///    segment, or an unusual response format), complete the session immediately
    ///    so the cached REQUEST is not left to time out.
    fn handle_openai_sse_continuation(
        &mut self,
        payload: &[u8],
        param: &ParseParam,
        config: &LogParserConfig,
    ) -> Option<HttpInfo> {
        if !config.openai_api.enabled {
            return None;
        }

        let (stream_id, is_stream) = match self.openai_session.as_ref() {
            Some(s) => (s.stream_id, s.is_stream),
            None => {
                // No active session — normal for non-OpenAI flows.
                if param.direction == PacketDirection::ServerToClient {
                    debug!(
                        "openai: flow={} non-HTTP server→client payload but no active session",
                        param.flow_id,
                    );
                }
                return None;
            }
        };

        // ── Client→server continuation (request body in separate TCP segment) ──
        // When the POST body arrives after the HTTP headers in a later TCP segment,
        // parse_http_v1 fails for that segment. Parse the payload as a request body
        // to pick up the "stream" flag before the response arrives.
        if param.direction == PacketDirection::ClientToServer {
            if !is_stream && !payload.is_empty() {
                let session = self.openai_session.as_mut().unwrap();
                openai_api::parse_request_body(session, payload, config);
                debug!(
                    "openai: flow={} request body continuation parsed stream_id={} is_stream={}",
                    param.flow_id, stream_id, session.is_stream,
                );
            }
            return None;
        }

        // ── Non-streaming fallback ────────────────────────────────────────────
        // parse_http_v1 failed for a server→client packet while a non-streaming
        // session is active. The packet is likely a body-continuation segment
        // (headers were in a prior segment) or an oddly-formatted first response.
        // Complete the session now so the cached REQUEST is not left to time out.
        //
        // EXCEPTION: any HTTP-looking payload (starts with "HTTP/") where
        // parse_http_v1 failed — e.g. 1xx informational responses (100 Continue,
        // 103 Early Hints) or a reason-phrase-less "HTTP/1.1 NNN" that was
        // rejected by a too-strict length check. Preserve the session so the
        // real response that follows can be matched.
        if !is_stream {
            // Don't consume the session for any packet that looks like an HTTP
            // response header (starts with "HTTP/"). parse_http_v1 may have
            // legitimately rejected it (1xx status, reason-phrase-less status
            // line, unsupported version), but the actual response is coming.
            if payload.starts_with(b"HTTP/") {
                debug!(
                    "openai: flow={} HTTP-header-like packet rejected by parse_http_v1 \
                     (preserving session stream_id={}), starts={:?}",
                    param.flow_id,
                    stream_id,
                    &payload[..payload.len().min(16)],
                );
                return None;
            }
            let session = self.openai_session.as_mut().unwrap();
            if !payload.is_empty() {
                // Best-effort: the payload might be the JSON body; extract usage
                // if it parses. Failure is silent (usage_status stays Missing).
                openai_api::parse_response_json(session, payload, config);
            }
            session.stream_end_ts_us = Some(param.time);
            let mut info = HttpInfo {
                proto: self.proto,
                is_tls: param.is_tls(),
                msg_type: LogMessageType::Response,
                stream_id: Some(stream_id),
                is_req_end: true,
                is_resp_end: true,
                openai_need_merge: true,
                ..Default::default()
            };
            info.openai_session = self.openai_session.take();
            debug!(
                "openai: flow={} non-stream RESPONSE fallback stream_id={} \
                 (HTTP parse failed, completing session) usage_status={:?}",
                param.flow_id,
                stream_id,
                info.openai_session
                    .as_ref()
                    .map(|s| s.usage_status)
                    .unwrap_or_default(),
            );
            return Some(info);
        }

        // ── SSE continuation ─────────────────────────────────────────────────

        let done = {
            let session = self.openai_session.as_mut().unwrap();
            if session.is_chunked_transfer {
                // Decode HTTP chunked framing into the session's reusable scratch
                // buffer (zero extra allocation per continuation packet).
                let ok = {
                    // Temporarily move the scratch buffer out so we can mutably
                    // borrow both it and the rest of `session`.
                    let mut scratch = std::mem::take(&mut session.chunked_decode_buf);
                    // Terminal chunk can appear in the same TCP segment as the
                    // final SSE events (usage + [DONE]). Always feed decoded data
                    // first; mark stream done afterward.
                    let is_terminal = openai_api::decode_chunked_sse_into(payload, &mut scratch);
                    let sse_done = if !scratch.is_empty() {
                        session.feed_sse(&scratch, param.time)
                    } else {
                        false
                    };
                    let result = if is_terminal {
                        if !session.stream_completed {
                            session.stream_completed = true;
                        }
                        session.stream_end_ts_us.get_or_insert(param.time);
                        true
                    } else {
                        sse_done
                    };
                    session.chunked_decode_buf = scratch; // restore (reuses capacity)
                    result
                };
                ok
            } else {
                session.feed_sse(payload, param.time)
            }
        };

        debug!(
            "openai: flow={} SSE continuation stream_id={} payload_bytes={} done={} \
             events={} usage_status={:?}",
            param.flow_id,
            stream_id,
            payload.len(),
            done,
            self.openai_session
                .as_ref()
                .map(|s| s.stream_event_count)
                .unwrap_or(0),
            self.openai_session
                .as_ref()
                .map(|s| s.usage_status)
                .unwrap_or_default(),
        );

        let mut info = HttpInfo {
            proto: self.proto,
            is_tls: param.is_tls(),
            msg_type: LogMessageType::Response,
            stream_id: Some(stream_id),
            is_req_end: true,
            is_resp_end: done,
            openai_need_merge: true,
            ..Default::default()
        };

        if done {
            info.openai_session = self.openai_session.take();
            debug!(
                "openai: flow={} SSE stream DONE stream_id={} – moving session to HttpInfo",
                param.flow_id, stream_id,
            );
        }

        Some(info)
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
    #[cfg(feature = "libtrace")]
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
                    info,
                    direction.into(),
                    Source::Header(key, val),
                );
                if key == ":path" {
                    policies.apply(
                        &mut self.custom_field_store,
                        info,
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

    #[cfg(feature = "libtrace")]
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
                    info,
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
                    info,
                    direction.into(),
                    Source::Header(key, trim_value),
                );
            }
        }

        let l7_payload = V1Structure::new(payload).body;

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
                info,
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
                                info,
                                direction.into(),
                                Source::Header(key, val),
                            );
                            if key == ":path" {
                                policies.apply(
                                    &mut self.custom_field_store,
                                    info,
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
        // HTTP responses don't carry endpoint information. Look it up from the cached
        // request so that on_http_resp wasm hooks can access it via HttpRespCtx.Endpoint.
        if param.direction == PacketDirection::ServerToClient && info.endpoint.is_none() {
            if let Some(endpoint) = info.load_endpoint_from_cache(param, info.is_reversed) {
                info.endpoint = Some(endpoint);
            }
        }
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
        payload: &[u8],
        l7_payload: Option<&[u8]>,
        info: &mut HttpInfo,
    ) {
        let Some(policies) = policies else {
            return;
        };

        let mut headers: Option<&[u8]> = None;

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
                Op::SaveHeader(key) => {
                    let header = headers.get_or_insert_with(|| V1Structure::new(payload).headers);
                    if !header.is_empty() {
                        info.attributes.push(KeyVal {
                            key: key.to_string(),
                            val: String::from_utf8_lossy(header).to_string(),
                        });
                    }
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

struct V1Structure<'a> {
    first_line: &'a [u8],
    headers: &'a [u8],
    body: &'a [u8],
}

impl<'a> V1Structure<'a> {
    pub fn new(payload: &'a [u8]) -> Self {
        let Some(end) = payload.windows(2).position(|w| w == b"\r\n") else {
            return Self {
                first_line: payload,
                headers: &[],
                body: &[],
            };
        };
        let first_line = &payload[..end];
        let payload = &payload[end + 2..];
        match payload.windows(4).position(|w| w == b"\r\n\r\n") {
            None => Self {
                first_line,
                headers: payload,
                body: &[],
            },
            Some(end) => Self {
                first_line,
                headers: &payload[..end + 2], // include one "\r\n"
                body: &payload[end + 4..],
            },
        }
    }
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
    use super::*;

    #[cfg(feature = "libtrace")]
    use std::net::{IpAddr, Ipv4Addr};
    use std::{cell::RefCell, collections::HashSet, fmt, fs, path::Path, rc::Rc, time::Duration};

    #[cfg(feature = "libtrace")]
    use crate::config::{
        config::{Iso8583ParseConfig, NetSignParseConfig, WebSphereMqParseConfig},
        OracleConfig,
    };
    use crate::{
        common::{l7_protocol_log::L7PerfCache, MetaPacket},
        config::{
            config::TagFilterOperator,
            handler::{BlacklistTrie, L7LogDynamicConfigBuilder, LogParserConfig, TraceType},
            HttpEndpoint, HttpEndpointMatchRule, HttpEndpointTrie,
        },
        flow_generator::L7_RRT_CACHE_CAPACITY,
        utils::test_utils::Capture,
    };

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
                Some(log_cache.clone()),
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

    #[cfg(feature = "libtrace")]
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
                    hdr_p = std::slice::from_raw_parts(
                        &self as *const Self as *const u8,
                        std::mem::size_of::<Self>(),
                    );
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
            ebpf_param: Some(crate::common::l7_protocol_log::EbpfParam {
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
            obfuscate_cache: None,
            l7_perf_cache: Some(Rc::new(RefCell::new(L7PerfCache::new(1)))),
            wasm_vm: Default::default(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            so_func: Default::default(),
            stats_counter: None,
            rrt_timeout: Duration::from_secs(10).as_micros() as usize,
            buf_size: 0,
            captured_byte: 1000,
            oracle_parse_conf: OracleConfig::default(),
            iso8583_parse_conf: Iso8583ParseConfig::default(),
            web_sphere_mq_parse_conf: WebSphereMqParseConfig::default(),
            net_sign_parse_conf: NetSignParseConfig::default(),
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
            Some(Rc::new(RefCell::new(L7PerfCache::new(
                L7_RRT_CACHE_CAPACITY,
            )))),
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
            run_perf(expected[0].0, HttpLog::new_v1()).iter().fold(
                L7PerfStats::default(),
                |mut s, i| {
                    s.sequential_merge(&i);
                    s
                }
            ),
            "parse pcap {} unexcepted",
            expected[0].0
        );
        assert_eq!(
            expected[1].1,
            run_perf(expected[1].0, HttpLog::new_v2(false)).iter().fold(
                L7PerfStats::default(),
                |mut s, i| {
                    s.sequential_merge(&i);
                    s
                }
            ),
            "parse pcap {} unexcepted",
            expected[1].0
        );
        assert_eq!(
            expected[2].1,
            run_perf(expected[2].0, HttpLog::new_v2(true)).iter().fold(
                L7PerfStats::default(),
                |mut s, i| {
                    s.sequential_merge(&i);
                    s
                }
            ),
            "parse pcap {} unexcepted",
            expected[2].0
        );
    }

    fn run_perf(pcap: &str, mut http: HttpLog) -> Vec<L7PerfStats> {
        let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));

        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(pcap));
        let mut packets = capture.collect::<Vec<_>>();

        let first_dst_port = packets[0].lookup_key.dst_port;

        let mut config = LogParserConfig::default();
        config.l7_log_dynamic.grpc_streaming_data_enabled = true;
        if http.protocol() == L7Protocol::Http2 || http.protocol() == L7Protocol::Grpc {
            http.set_header_decoder(config.l7_log_dynamic.expected_headers_set.clone());
        }
        let mut perf_stats = vec![];
        for packet in packets.iter_mut() {
            if packet.lookup_key.dst_port == first_dst_port {
                packet.lookup_key.direction = PacketDirection::ClientToServer;
            } else {
                packet.lookup_key.direction = PacketDirection::ServerToClient;
            }
            if packet.get_l4_payload().is_some() {
                let param = &mut ParseParam::new(
                    &*packet,
                    Some(rrt_cache.clone()),
                    Default::default(),
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    Default::default(),
                    true,
                    true,
                );
                param.set_log_parser_config(&config);
                let _ = http.parse_payload(packet.get_l4_payload().unwrap(), param);
            }
            perf_stats.append(&mut http.perf_stats());
        }
        perf_stats
    }

    #[test]
    fn blacklist() {
        fn execute_case(config: &LogParserConfig, packets: &[MetaPacket]) -> L7PerfStats {
            let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));
            let mut http = HttpLog::new_v1();
            let mut perf_stat = L7PerfStats::default();
            for packet in packets {
                let Some(payload) = packet.get_l4_payload() else {
                    continue;
                };
                let param = &mut ParseParam::new(
                    &*packet,
                    Some(rrt_cache.clone()),
                    Default::default(),
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    Default::default(),
                    true,
                    true,
                );
                param.set_log_parser_config(&config);
                let _ = http.parse_payload(payload, param);
                for i in http.perf_stats() {
                    perf_stat.sequential_merge(&i);
                }
            }
            perf_stat
        }

        let capture = Capture::load_pcap(Path::new(FILE_DIR).join("httpv1.pcap"));
        let mut packets = capture.collect::<Vec<_>>();
        packets[0].lookup_key.direction = PacketDirection::ClientToServer;
        packets[1].lookup_key.direction = PacketDirection::ServerToClient;

        let config = LogParserConfig::default();
        let blacklist_config = LogParserConfig {
            l7_log_blacklist_trie: HashMap::from([(
                L7Protocol::Http1,
                BlacklistTrie::new(vec![TagFilterOperator {
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
            Some(Rc::new(RefCell::new(L7PerfCache::new(
                L7_RRT_CACHE_CAPACITY,
            )))),
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

    // ── OpenAI API tests ────────────────────────────────────────────────────

    /// Build a LogParserConfig with OpenAI API enabled, accepting any path that
    /// contains "completions" as suffix, so that the test pcap paths (which may
    /// not start with "/v1/") still match.
    fn openai_test_config() -> LogParserConfig {
        use crate::config::config::{
            OpenAIApiConfig, OpenAIBizDimExtractor, OpenAIBizDimExtractors, OpenAIUsageFieldPaths,
        };
        LogParserConfig {
            openai_api: OpenAIApiConfig {
                enabled: true,
                // Accept paths that end with "completions" so that the test pcap
                // path /model-center/api/llm/openai/v1/chat/completions matches.
                path_prefixes: vec![],
                path_suffixes: vec!["completions".to_string()],
                request_body_max_bytes: 65536,
                response_event_max_bytes: 32768,
                sse_buffer_max_bytes: 524288,
                usage_field_paths: OpenAIUsageFieldPaths::default(),
                biz_dimension_extractors: OpenAIBizDimExtractors {
                    org_path: OpenAIBizDimExtractor {
                        headers: vec!["x-org-path".to_string()],
                        json_paths: vec!["metadata.org_path".to_string()],
                    },
                    user_id: OpenAIBizDimExtractor {
                        headers: vec!["x-user-id".to_string()],
                        json_paths: vec![
                            "safety_identifier".to_string(),
                            "user".to_string(),
                            "source_aigc_appid".to_string(),
                            "metadata.user_id".to_string(),
                        ],
                    },
                    app_id: OpenAIBizDimExtractor {
                        headers: vec!["x-app-id".to_string()],
                        json_paths: vec![
                            "appid".to_string(),
                            "source_appid".to_string(),
                            "metadata.app_id".to_string(),
                        ],
                    },
                },
            },
            ..Default::default()
        }
    }

    /// Run all packets in a pcap file through the HTTP1 parser and collect the
    /// resulting `HttpInfo` objects (merged request+response pairs).
    fn run_openai_pcap(pcap_name: &str, config: &LogParserConfig) -> Vec<HttpInfo> {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(pcap_name));
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let mut packets: Vec<_> = capture.collect();
        if packets.is_empty() {
            return vec![];
        }

        let first_dst_port = packets[0].lookup_key.dst_port;
        let mut parser = HttpLog::new_v1();
        let mut results: Vec<HttpInfo> = Vec::new();

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

            let param = &mut ParseParam::new(
                packet as &MetaPacket,
                Some(log_cache.clone()),
                Default::default(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Default::default(),
                true,
                true,
            );
            param.set_captured_byte(payload.len());
            param.set_log_parser_config(config);

            match parser.parse_payload(payload, param) {
                Ok(L7ParseResult::Single(L7ProtocolInfo::HttpInfo(info))) => {
                    // Merge responses / SSE continuations into the previous entry.
                    // A Request starts a new session; everything else merges into the current one.
                    if info.msg_type != LogMessageType::Request {
                        if let Some(last) = results.last_mut() {
                            let mut other = info;
                            let _ = last.merge(&mut other);
                            continue;
                        }
                    }
                    results.push(info);
                }
                _ => {}
            }
        }
        results
    }

    fn attr_val<'a>(info: &'a HttpInfo, key: &str) -> Option<&'a str> {
        info.attributes
            .iter()
            .find(|kv| kv.key == key)
            .map(|kv| kv.val.as_str())
    }

    fn metric_val(info: &HttpInfo, key: &str) -> Option<f32> {
        info.metrics
            .iter()
            .find(|kv| kv.key == key)
            .map(|kv| kv.val)
    }

    #[test]
    fn test_openai_normal_usage_pcap() {
        let config = openai_test_config();
        let results = run_openai_pcap("openai_normal_usage.pcap", &config);

        // Expect at least one merged request+response.
        assert!(
            !results.is_empty(),
            "no results from openai_normal_usage.pcap"
        );
        let info = &results[0];

        // openai_session should carry the final state.
        let session = info.openai_session.as_ref().expect("openai_session absent");

        // For a non-streaming response, usage should be available.
        assert!(
            matches!(
                session.usage_status,
                crate::flow_generator::protocol_logs::openai_api::UsageStatus::Available
            ),
            "usage_status should be Available, got {:?}",
            session.usage_status
        );
        let usage = session.usage.as_ref().expect("usage absent");
        assert!(usage.input_tokens > 0, "input_tokens should be > 0");
        assert!(usage.output_tokens > 0, "output_tokens should be > 0");
    }

    #[test]
    fn test_openai_stream_usage_pcap() {
        let config = openai_test_config();
        let results = run_openai_pcap("openai_stream_usage.pcap", &config);

        assert!(
            !results.is_empty(),
            "no results from openai_stream_usage.pcap"
        );
        // Find the merged entry that has openai_session populated.
        let info = results
            .iter()
            .find(|i| i.openai_session.is_some())
            .expect("no result with openai_session");

        let session = info.openai_session.as_ref().unwrap();

        // Streaming pcap should be detected as stream.
        assert!(session.is_stream, "should be detected as stream");

        // Usage should be available (stream includes usage in chunks).
        assert!(
            matches!(
                session.usage_status,
                crate::flow_generator::protocol_logs::openai_api::UsageStatus::Available
            ),
            "usage_status should be Available"
        );

        let usage = session.usage.as_ref().expect("usage absent");
        assert!(usage.input_tokens > 0, "input_tokens should be > 0");
        assert!(usage.output_tokens > 0, "output_tokens should be > 0");
        assert!(
            session.stream_event_count > 0,
            "stream_event_count should be > 0"
        );
    }

    /// Regression test for `openai_stream_v537.pcap`.
    ///
    /// This pcap uses HTTP chunked-transfer-encoding where each SSE event is
    /// spread across three chunks: `data:`, `{json}\n`, and `\r\n` (blank line).
    /// After chunk decoding the event boundary is `\n\r\n` (not `\n\n`).
    /// Also, every chunk in this pcap includes inline usage data.
    #[test]
    fn test_openai_stream_v537_pcap() {
        let config = openai_test_config();
        let results = run_openai_pcap("openai_stream_v537.pcap", &config);

        assert!(
            !results.is_empty(),
            "no results from openai_stream_v537.pcap"
        );

        let info = results
            .iter()
            .find(|i| i.openai_session.is_some())
            .expect("no result with openai_session");
        let session = info.openai_session.as_ref().unwrap();

        assert!(session.is_stream, "should be detected as stream");
        assert!(
            matches!(
                session.usage_status,
                crate::flow_generator::protocol_logs::openai_api::UsageStatus::Available
            ),
            "usage_status should be Available (inline usage in every chunk), got {:?}",
            session.usage_status,
        );
        let usage = session.usage.as_ref().expect("usage absent");
        assert!(usage.input_tokens > 0, "input_tokens should be > 0");
        assert!(usage.output_tokens > 0, "output_tokens should be > 0");
        assert!(
            session.stream_event_count > 0,
            "stream_event_count should be > 0"
        );
        assert!(session.stream_completed, "stream should be completed");
    }

    #[test]
    fn test_openai_stream_pcap() {
        let config = openai_test_config();
        let results = run_openai_pcap("openai_stream.pcap", &config);

        // The stream pcap without explicit usage may still produce a result.
        // Just verify parsing doesn't panic and produces reasonable output.
        // If there are results, verify stream is detected.
        for info in &results {
            if let Some(session) = &info.openai_session {
                // If detected as openai, it should at least be kind=ChatCompletions.
                assert!(
                    matches!(
                        session.kind,
                        crate::flow_generator::protocol_logs::openai_api::OpenAIKind::ChatCompletions
                    ),
                    "kind should be ChatCompletions"
                );
            }
        }
    }

    /// Test that OpenAI metrics are correctly propagated into the L7ProtocolSendLog.
    #[test]
    fn test_openai_metrics_in_send_log() {
        use crate::flow_generator::protocol_logs::openai_api::{
            OpenAIKind, OpenAISession, OpenAIUsage, UsageStatus,
        };

        // request_ts_us = 0, stream_end_ts_us = 5_000_000 µs → 5000 ms total.
        let mut session = Box::new(OpenAISession::new(
            OpenAIKind::ChatCompletions,
            true,
            0,
            131072,
            &Default::default(),
        ));
        session.usage = Some(OpenAIUsage {
            input_tokens: 100,
            output_tokens: 50,
            total_tokens: 150,
            cached_tokens: None,
        });
        session.usage_status = UsageStatus::Available;
        session.first_output_ts_us = Some(100_000);
        session.last_output_ts_us = Some(600_000);
        session.stream_end_ts_us = Some(5_000_000); // 5 s after request
        session.stream_event_count = 5;
        session.stream_completed = true;
        session.biz_user_id = Some("test-user".to_string());
        session.biz_app_id = Some("test-app".to_string());

        let info = HttpInfo {
            proto: L7Protocol::Http1,
            msg_type: LogMessageType::Session,
            openai_session: Some(session),
            ..Default::default()
        };

        let send_log: L7ProtocolSendLog = info.into();
        let ext = send_log.ext_info.expect("ext_info absent");

        // protocol_str should be "openai-api"
        assert_eq!(
            ext.protocol_str.as_deref(),
            Some("openai-api"),
            "protocol_str should be openai-api"
        );

        // Attributes should contain biz_user_id and biz_app_id.
        let attrs = ext.attributes.expect("attributes absent");
        let attr_map: std::collections::HashMap<_, _> = attrs
            .iter()
            .map(|kv| (kv.key.as_str(), kv.val.as_str()))
            .collect();
        assert_eq!(attr_map.get("biz_user_id"), Some(&"test-user"));
        assert_eq!(attr_map.get("biz_app_id"), Some(&"test-app"));

        // Metrics should contain token counts.
        let metrics = ext.metrics.expect("metrics absent");
        let metric_map: std::collections::HashMap<_, _> =
            metrics.iter().map(|kv| (kv.key.as_str(), kv.val)).collect();
        assert_eq!(metric_map.get("llm_input_tokens"), Some(&100.0f32));
        assert_eq!(metric_map.get("llm_output_tokens"), Some(&50.0f32));
        assert_eq!(metric_map.get("llm_total_tokens"), Some(&150.0f32));

        // TTFT and TPOT should be present.
        assert!(metric_map.contains_key("llm_ttft_us"), "ttft missing");
        assert!(metric_map.contains_key("llm_tpot_us"), "tpot missing");

        // Total stream duration: 5_000_000 µs - 0 µs = 5_000_000 µs.
        let total_us = metric_map
            .get("llm_total_stream_us")
            .copied()
            .expect("llm_total_stream_us missing");
        assert!(
            (total_us - 5_000_000.0).abs() < 1.0,
            "expected ~5_000_000 µs total stream, got {total_us}"
        );
    }
}
