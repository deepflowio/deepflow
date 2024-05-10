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

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, str};

const MAX_METHOD_LEN: usize = 8;

use crate::{
    common::{
        enums::IpProtocol,
        flow::{L7PerfStats, L7Protocol, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, ParseParam},
        meta_packet::EbpfFlags,
    },
    config::handler::{L7LogDynamicConfig, LogParserConfig},
    flow_generator::{
        error::Result,
        protocol_logs::{
            pb_adapter::{
                ExtendedInfo, KeyVal, L7ProtocolSendLog, L7Request, L7Response, TraceInfo,
            },
            set_captured_byte, AppProtoHead, LogMessageType,
        },
    },
    plugin::wasm::{wasm_plugin::NatsMessage as WasmNatsMessage, WasmData},
};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Info {
    #[serde(rename = "server_id")]
    server_id: String,
    #[serde(rename = "server_name")]
    server_name: String,

    #[serde(rename = "version")]
    version: String,
    #[serde(rename = "go")]
    go_version: String,

    #[serde(rename = "host")]
    host: String,
    #[serde(rename = "port")]
    port: u16,

    #[serde(rename = "max_payload")]
    max_payload: usize,
    #[serde(rename = "tls_required", skip_serializing_if = "Option::is_none")]
    tls_required: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Connect {
    #[serde(rename = "verbose", default = "bool::default")]
    verbose: bool,
    #[serde(rename = "pedantic", default = "bool::default")]
    pedantic: bool,
    #[serde(rename = "tls_required", default = "bool::default")]
    tls_required: bool,
    #[serde(rename = "name", skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(rename = "version")]
    version: String,
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct Pub {
    #[serde(rename = "subject")]
    subject: String,
    #[serde(rename = "reply_to", skip_serializing_if = "Option::is_none")]
    reply_to: Option<String>,
    #[serde(rename = "payload_size")]
    payload_size: usize,
    #[serde(rename = "payload")]
    payload: Vec<u8>,
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct Hpub {
    #[serde(rename = "subject")]
    subject: String,
    #[serde(rename = "reply_to", skip_serializing_if = "Option::is_none")]
    reply_to: Option<String>,
    #[serde(rename = "payload_size")]
    payload_size: usize,
    #[serde(rename = "header_size")]
    header_size: usize,
    #[serde(rename = "header_version")]
    header_version: String,
    #[serde(rename = "headers")]
    headers: BTreeMap<String, String>,
    #[serde(rename = "payload")]
    payload: Vec<u8>,
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct Sub {
    #[serde(rename = "subject")]
    subject: String,
    #[serde(rename = "queue_group", skip_serializing_if = "Option::is_none")]
    queue_group: Option<String>,
    #[serde(rename = "sid")]
    sid: String,
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct Unsub {
    #[serde(rename = "sid")]
    sid: String,
    #[serde(rename = "max_msgs", skip_serializing_if = "Option::is_none")]
    max_msgs: Option<usize>,
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct Msg {
    #[serde(rename = "subject")]
    subject: String,
    #[serde(rename = "sid")]
    sid: String,
    #[serde(rename = "reply_to", skip_serializing_if = "Option::is_none")]
    reply_to: Option<String>,
    #[serde(rename = "payload_size")]
    payload_size: usize,
    #[serde(rename = "payload")]
    payload: Vec<u8>,
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct Hmsg {
    #[serde(rename = "subject")]
    subject: String,
    #[serde(rename = "sid")]
    sid: String,
    #[serde(rename = "reply_to", skip_serializing_if = "Option::is_none")]
    reply_to: Option<String>,
    #[serde(rename = "header_size")]
    header_size: usize,
    #[serde(rename = "payload_size")]
    payload_size: usize,
    #[serde(rename = "header_version")]
    header_version: String,
    #[serde(rename = "headers")]
    headers: BTreeMap<String, String>,
    #[serde(rename = "payload")]
    payload: Vec<u8>,
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct Ping {}

#[derive(Serialize, Debug, Default, Clone)]
pub struct Pong {}

#[derive(Serialize, Debug, Default, Clone)]
pub struct Ok {}

#[derive(Serialize, Debug, Default, Clone)]
pub struct Err {
    #[serde(rename = "error_message")]
    error_message: String,
}

trait Parsable: Sized {
    fn try_parse(payload: &[u8]) -> Option<(&[u8], Self)>;
}

#[derive(Serialize, Debug, Clone)]
pub enum NatsMessage {
    Info(Info),
    Connect(Connect),
    Pub(Pub),
    Hpub(Hpub),
    Sub(Sub),
    Unsub(Unsub),
    Msg(Msg),
    Hmsg(Hmsg),
    Ping(Ping),
    Pong(Pong),
    Ok(Ok),
    Err(Err),
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct NatsInfo {
    msg_type: LogMessageType,
    #[serde(skip)]
    is_tls: bool,

    rtt: u64,

    version: String,
    server_name: String,
    req_len: Option<u32>,
    resp_len: Option<u32>,

    #[serde(rename = "trace_id", skip_serializing_if = "Option::is_none")]
    trace_id: Option<String>,
    #[serde(rename = "span_id", skip_serializing_if = "Option::is_none")]
    span_id: Option<String>,

    message: NatsMessage,

    #[serde(skip)]
    attributes: Vec<KeyVal>,

    l7_protocol_str: Option<String>,

    captured_request_byte: u32,
    captured_response_byte: u32,
}

#[derive(Default)]
pub struct NatsLog {
    perf_stats: Option<L7PerfStats>,

    version: String,
    server_name: String,
}

fn slice_split(slice: &[u8], n: usize) -> Option<(&[u8], &[u8])> {
    Some((slice.get(n..)?, slice.get(..n)?))
}

fn slice_to_string(slice: &[u8]) -> String {
    String::from_utf8_lossy(slice).to_string()
}

fn slice_to_usize(slice: &[u8]) -> Option<usize> {
    str::from_utf8(slice).ok()?.parse().ok()
}

fn read_line(payload: &[u8]) -> Option<(&[u8], &[u8])> {
    match payload.windows(2).position(|x| x == b"\r\n") {
        Some(p) => Some((&payload[p + 2..], &payload[..p])),
        None => None,
    }
}

fn read_field(payload: &[u8]) -> Option<(&[u8], &[u8])> {
    let p = |x: &u8| *x == b' ' || *x == b'\t' || *x == b'\r' || *x == b'\n';
    match payload.iter().position(p) {
        Some(0) => None,
        Some(p) => Some((&payload[p..], &payload[..p])),
        None => None,
    }
}

fn read_headers<'a>(
    payload: &'a [u8],
    header_size: usize,
    header_version: &mut String,
) -> Option<(&'a [u8], BTreeMap<String, String>)> {
    if payload.len() < header_size {
        return None;
    }
    let buf = &payload[..header_size];
    let payload = &payload[header_size..];

    let (buf, hv) = read_line(buf)?;
    *header_version = slice_to_string(hv);

    let mut headers = BTreeMap::new();
    let mut buf = buf;
    loop {
        let (tmp, kv) = read_line(buf)?;
        buf = tmp;
        if kv.is_empty() && buf.is_empty() {
            break;
        }
        let kv = slice_to_string(kv);
        let mut kv = kv.splitn(2, ':');
        if let (Some(key), Some(val)) = (kv.next(), kv.next()) {
            headers.insert(key.trim().to_string(), val.trim().to_string());
        }
    }
    Some((payload, headers))
}

impl Parsable for Info {
    fn try_parse(payload: &[u8]) -> Option<(&[u8], Self)> {
        // INFO {"option_name":option_value,...}␍␊
        let (payload, json) = read_line(payload)?;
        let json = str::from_utf8(json).ok()?;
        serde_json::from_str::<Info>(json)
            .ok()
            .map(|x| (payload, x))
    }
}

impl Parsable for Connect {
    fn try_parse(payload: &[u8]) -> Option<(&[u8], Self)> {
        // CONNECT {"option_name":option_value,...}␍␊
        let (payload, json) = read_line(payload)?;
        let json = str::from_utf8(json).ok()?;
        serde_json::from_str::<Connect>(json)
            .ok()
            .map(|x| (payload, x))
    }
}

impl Parsable for Pub {
    fn try_parse(payload: &[u8]) -> Option<(&[u8], Self)> {
        // PUB <subject> [reply-to] <#bytes>␍␊[payload]␍␊
        let (payload, line) = read_line(payload)?;
        let mut gen = line
            .split(|v| *v == b' ' || *v == b'\t')
            .filter(|v| !v.is_empty());
        let mut pub_obj = Pub::default();
        pub_obj.subject = slice_to_string(gen.next()?);
        match (gen.next(), gen.next(), gen.next()) {
            (_, _, Some(_)) => return None,
            (Some(reply_to), Some(size), _) => {
                pub_obj.reply_to = Some(slice_to_string(reply_to));
                pub_obj.payload_size = slice_to_usize(size)?;
            }
            (Some(size), _, _) => {
                pub_obj.payload_size = slice_to_usize(size)?;
            }
            _ => return None,
        }
        let (payload, body) = slice_split(payload, pub_obj.payload_size)?;
        pub_obj.payload = body.to_vec();
        if payload.starts_with(b"\r\n") {
            Some((&payload[2..], pub_obj))
        } else {
            None
        }
    }
}

impl Parsable for Hpub {
    fn try_parse(payload: &[u8]) -> Option<(&[u8], Self)> {
        // HPUB <subject> [reply-to] <#header bytes> <#total bytes>␍␊[headers]␍␊␍␊[payload]␍␊
        let (payload, line) = read_line(payload)?;
        let mut gen = line
            .split(|v| *v == b' ' || *v == b'\t')
            .filter(|v| !v.is_empty());
        let mut hpub_obj = Hpub::default();
        hpub_obj.subject = slice_to_string(gen.next()?);
        match (gen.next(), gen.next(), gen.next(), gen.next()) {
            (_, _, _, Some(_)) => return None,
            (Some(reply_to), Some(header_size), Some(total_size), _) => {
                hpub_obj.reply_to = Some(slice_to_string(reply_to));
                hpub_obj.header_size = slice_to_usize(header_size)?;
                hpub_obj.payload_size = slice_to_usize(total_size)? - hpub_obj.header_size;
            }
            (Some(header_size), Some(total_size), _, _) => {
                hpub_obj.header_size = slice_to_usize(header_size)?;
                hpub_obj.payload_size = slice_to_usize(total_size)? - hpub_obj.header_size;
            }
            _ => return None,
        }
        let (payload, headers) =
            read_headers(payload, hpub_obj.header_size, &mut hpub_obj.header_version)?;
        let (payload, body) = slice_split(payload, hpub_obj.payload_size)?;
        hpub_obj.headers = headers;
        hpub_obj.payload = body.to_vec();
        if payload.starts_with(b"\r\n") {
            Some((&payload[2..], hpub_obj))
        } else {
            None
        }
    }
}

impl Parsable for Sub {
    fn try_parse(payload: &[u8]) -> Option<(&[u8], Self)> {
        // SUB <subject> [queue group] <sid>␍␊
        let (payload, line) = read_line(payload)?;
        let mut gen = line
            .split(|v| *v == b' ' || *v == b'\t')
            .filter(|v| !v.is_empty());
        let mut sub_obj = Sub::default();
        sub_obj.subject = slice_to_string(gen.next()?);
        match (gen.next(), gen.next(), gen.next()) {
            (_, _, Some(_)) => return None,
            (Some(queue_group), Some(sid), _) => {
                sub_obj.queue_group = Some(slice_to_string(queue_group));
                sub_obj.sid = slice_to_string(sid);
            }
            (Some(sid), _, _) => {
                sub_obj.sid = slice_to_string(sid);
            }
            _ => return None,
        }
        Some((payload, sub_obj))
    }
}

impl Parsable for Unsub {
    fn try_parse(payload: &[u8]) -> Option<(&[u8], Self)> {
        // UNSUB <sid> [max_msgs]␍␊
        let (payload, line) = read_line(payload)?;
        let mut gen = line
            .split(|v| *v == b' ' || *v == b'\t')
            .filter(|v| !v.is_empty());
        let mut unsub_obj = Unsub::default();
        unsub_obj.sid = slice_to_string(gen.next()?);
        match (gen.next(), gen.next()) {
            (_, Some(_)) => return None,
            (Some(max_msgs), _) => {
                unsub_obj.max_msgs = Some(slice_to_usize(max_msgs)?);
            }
            _ => {}
        }
        Some((payload, unsub_obj))
    }
}

impl Parsable for Msg {
    fn try_parse(payload: &[u8]) -> Option<(&[u8], Self)> {
        // MSG <subject> <sid> [reply-to] <#bytes>␍␊[payload]␍␊
        let (payload, line) = read_line(payload)?;
        let mut gen = line
            .split(|v| *v == b' ' || *v == b'\t')
            .filter(|v| !v.is_empty());
        let mut msg_obj = Msg::default();
        msg_obj.subject = slice_to_string(gen.next()?);
        msg_obj.sid = slice_to_string(gen.next()?);
        match (gen.next(), gen.next(), gen.next()) {
            (_, _, Some(_)) => return None,
            (Some(reply_to), Some(size), _) => {
                msg_obj.reply_to = Some(slice_to_string(reply_to));
                msg_obj.payload_size = slice_to_usize(size)?;
            }
            (Some(size), _, _) => {
                msg_obj.payload_size = slice_to_usize(size)?;
            }
            _ => return None,
        }
        let (payload, body) = slice_split(payload, msg_obj.payload_size)?;
        msg_obj.payload = body.to_vec();
        if payload.starts_with(b"\r\n") {
            Some((&payload[2..], msg_obj))
        } else {
            None
        }
    }
}

impl Parsable for Hmsg {
    fn try_parse(payload: &[u8]) -> Option<(&[u8], Self)> {
        // HMSG <subject> <sid> [reply-to] <#header bytes> <#total bytes>␍␊[headers]␍␊␍␊[payload]␍␊
        let (payload, line) = read_line(payload)?;
        let mut gen = line
            .split(|v| *v == b' ' || *v == b'\t')
            .filter(|v| !v.is_empty());
        let mut hmsg_obj = Hmsg::default();
        hmsg_obj.subject = slice_to_string(gen.next()?);
        hmsg_obj.sid = slice_to_string(gen.next()?);
        match (gen.next(), gen.next(), gen.next(), gen.next()) {
            (_, _, _, Some(_)) => return None,
            (Some(reply_to), Some(header_size), Some(total_size), _) => {
                hmsg_obj.reply_to = Some(slice_to_string(reply_to));
                hmsg_obj.header_size = slice_to_usize(header_size)?;
                hmsg_obj.payload_size = slice_to_usize(total_size)? - hmsg_obj.header_size;
            }
            (Some(header_size), Some(total_size), _, _) => {
                hmsg_obj.header_size = slice_to_usize(header_size)?;
                hmsg_obj.payload_size = slice_to_usize(total_size)? - hmsg_obj.header_size;
            }
            _ => return None,
        }
        let (payload, headers) =
            read_headers(payload, hmsg_obj.header_size, &mut hmsg_obj.header_version)?;
        let (payload, body) = slice_split(payload, hmsg_obj.payload_size)?;
        hmsg_obj.headers = headers;
        hmsg_obj.payload = body.to_vec();
        if payload.starts_with(b"\r\n") {
            Some((&payload[2..], hmsg_obj))
        } else {
            None
        }
    }
}

impl Parsable for Ping {
    fn try_parse(payload: &[u8]) -> Option<(&[u8], Self)> {
        // PING␍␊
        if payload.starts_with(b"\r\n") {
            Some((&payload[2..], Ping::default()))
        } else {
            None
        }
    }
}

impl Parsable for Pong {
    fn try_parse(payload: &[u8]) -> Option<(&[u8], Self)> {
        // PONG␍␊
        if payload.starts_with(b"\r\n") {
            Some((&payload[2..], Pong::default()))
        } else {
            None
        }
    }
}

impl Parsable for Ok {
    fn try_parse(payload: &[u8]) -> Option<(&[u8], Self)> {
        // +OK␍␊
        if payload.starts_with(b"\r\n") {
            Some((&payload[2..], Ok::default()))
        } else {
            None
        }
    }
}

impl Parsable for Err {
    fn try_parse(payload: &[u8]) -> Option<(&[u8], Self)> {
        // -ERR <error message>␍␊
        let pos = payload.iter().position(|&x| x != b' ' && x != b'\t')?;
        let (payload, line) = read_line(&payload[pos..])?;
        let error_message = slice_to_string(line);
        Some((payload, Err { error_message }))
    }
}

impl NatsInfo {
    fn try_parse<'a>(
        payload: &'a [u8],
        config: Option<&LogParserConfig>,
    ) -> Option<(&'a [u8], Self)> {
        let mut info = NatsInfo::default();
        let length_begin = payload.len();

        let (payload, method) = read_field(payload)?;
        if method.len() > MAX_METHOD_LEN {
            return None;
        }
        let method = slice_to_string(method).to_uppercase();
        let payload = match method.as_str() {
            "INFO" => {
                info.msg_type = LogMessageType::Request;
                let (payload, obj) = Info::try_parse(payload)?;
                info.message = NatsMessage::Info(obj);
                payload
            }
            "CONNECT" => {
                info.msg_type = LogMessageType::Response;
                let (payload, obj) = Connect::try_parse(payload)?;
                info.message = NatsMessage::Connect(obj);
                payload
            }
            "PUB" => {
                info.msg_type = LogMessageType::Session;
                let (payload, obj) = Pub::try_parse(payload)?;
                info.message = NatsMessage::Pub(obj);
                payload
            }
            "HPUB" => {
                info.msg_type = LogMessageType::Session;
                let (payload, obj) = Hpub::try_parse(payload)?;
                info.message = NatsMessage::Hpub(obj);
                payload
            }
            "SUB" => {
                info.msg_type = LogMessageType::Session;
                let (payload, obj) = Sub::try_parse(payload)?;
                info.message = NatsMessage::Sub(obj);
                payload
            }
            "UNSUB" => {
                info.msg_type = LogMessageType::Session;
                let (payload, obj) = Unsub::try_parse(payload)?;
                info.message = NatsMessage::Unsub(obj);
                payload
            }
            "MSG" => {
                info.msg_type = LogMessageType::Session;
                let (payload, obj) = Msg::try_parse(payload)?;
                info.message = NatsMessage::Msg(obj);
                payload
            }
            "HMSG" => {
                info.msg_type = LogMessageType::Session;
                let (payload, obj) = Hmsg::try_parse(payload)?;
                info.message = NatsMessage::Hmsg(obj);
                payload
            }
            "PING" => {
                info.msg_type = LogMessageType::Request;
                let (payload, obj) = Ping::try_parse(payload)?;
                info.message = NatsMessage::Ping(obj);
                payload
            }
            "PONG" => {
                info.msg_type = LogMessageType::Response;
                let (payload, obj) = Pong::try_parse(payload)?;
                info.message = NatsMessage::Pong(obj);
                payload
            }
            "+OK" => {
                info.msg_type = LogMessageType::Session;
                let (payload, obj) = Ok::try_parse(payload)?;
                info.message = NatsMessage::Ok(obj);
                payload
            }
            "-ERR" => {
                info.msg_type = LogMessageType::Session;
                let (payload, obj) = Err::try_parse(payload)?;
                info.message = NatsMessage::Err(obj);
                payload
            }
            _ => return None,
        };
        if let Some(config) = config {
            (info.trace_id, info.span_id) = info.parse_trace_span(&config.l7_log_dynamic);
        }
        match info.msg_type {
            LogMessageType::Request => info.req_len = Some((length_begin - payload.len()) as u32),
            LogMessageType::Response => info.resp_len = Some((length_begin - payload.len()) as u32),
            _ => {}
        }
        Some((payload, info))
    }

    fn get_subject(&self) -> Option<&str> {
        match &self.message {
            NatsMessage::Info(_)
            | NatsMessage::Connect(_)
            | NatsMessage::Unsub(_)
            | NatsMessage::Ping(_)
            | NatsMessage::Pong(_)
            | NatsMessage::Ok(_)
            | NatsMessage::Err(_) => None,
            NatsMessage::Pub(x) => Some(x.subject.as_str()),
            NatsMessage::Hpub(x) => Some(x.subject.as_str()),
            NatsMessage::Sub(x) => Some(x.subject.as_str()),
            NatsMessage::Msg(x) => Some(x.subject.as_str()),
            NatsMessage::Hmsg(x) => Some(x.subject.as_str()),
        }
    }

    fn get_name(&self) -> &'static str {
        match self.message {
            NatsMessage::Info(_) => "INFO",
            NatsMessage::Connect(_) => "CONNECT",
            NatsMessage::Pub(_) => "PUB",
            NatsMessage::Hpub(_) => "HPUB",
            NatsMessage::Sub(_) => "SUB",
            NatsMessage::Unsub(_) => "UNSUB",
            NatsMessage::Msg(_) => "MSG",
            NatsMessage::Hmsg(_) => "HMSG",
            NatsMessage::Ping(_) => "PING",
            NatsMessage::Pong(_) => "PONG",
            NatsMessage::Ok(_) => "OK",
            NatsMessage::Err(_) => "ERR",
        }
    }

    fn parse_trace_span(&self, config: &L7LogDynamicConfig) -> (Option<String>, Option<String>) {
        let headers = match &self.message {
            NatsMessage::Hpub(x) => &x.headers,
            NatsMessage::Hmsg(x) => &x.headers,
            _ => return (None, None),
        };
        let mut trace_id = None;
        let mut span_id = None;
        for (k, v) in headers.iter() {
            for tt in config.trace_types.iter() {
                if tt.check(k) {
                    trace_id = tt.decode_trace_id(v).map(|x| x.to_string());
                    break;
                }
            }
            for st in config.span_types.iter() {
                if st.check(k) {
                    span_id = st.decode_span_id(v).map(|x| x.to_string());
                    break;
                }
            }
        }
        (trace_id, span_id)
    }
}

impl Default for NatsMessage {
    fn default() -> Self {
        NatsMessage::Err(Err {
            error_message: "unknown message".to_string(),
        })
    }
}

impl From<NatsInfo> for L7ProtocolSendLog {
    fn from(info: NatsInfo) -> Self {
        let flags = match info.is_tls {
            true => EbpfFlags::TLS.bits(),
            false => EbpfFlags::NONE.bits(),
        };
        let name = info.get_name();
        let subject = info
            .get_subject()
            .map(|x| x.to_string())
            .unwrap_or_default();
        let endpoint = info.get_endpoint().unwrap_or_default();
        let log = L7ProtocolSendLog {
            captured_request_byte: info.captured_request_byte,
            captured_response_byte: info.captured_response_byte,
            flags,
            version: Some(info.version),
            req_len: info.req_len,
            resp_len: info.resp_len,
            req: L7Request {
                req_type: name.to_string(),
                domain: info.server_name,
                resource: subject,
                endpoint,
                ..Default::default()
            },
            resp: L7Response {
                ..Default::default()
            },
            trace_info: Some(TraceInfo {
                trace_id: info.trace_id,
                span_id: info.span_id,
                ..Default::default()
            }),
            ext_info: Some(ExtendedInfo {
                attributes: {
                    if info.attributes.is_empty() {
                        None
                    } else {
                        Some(info.attributes)
                    }
                },
                protocol_str: info.l7_protocol_str,
                ..Default::default()
            }),
            ..Default::default()
        };
        log
    }
}

impl L7ProtocolInfoInterface for NatsInfo {
    fn is_tls(&self) -> bool {
        self.is_tls
    }

    fn session_id(&self) -> Option<u32> {
        None
    }

    fn get_endpoint(&self) -> Option<String> {
        self.get_subject()
            .and_then(|x| x.split('.').next())
            .map(|x| x.to_string())
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let (req, L7ProtocolInfo::NatsInfo(rsp)) = (self, other) {
            if req.resp_len.is_none() {
                req.resp_len = rsp.resp_len;
            }
            req.captured_response_byte = rsp.captured_response_byte;
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::NATS,
            msg_type: self.msg_type,
            rrt: self.rtt,
        })
    }

    fn get_request_domain(&self) -> String {
        self.server_name.clone()
    }
}

impl NatsLog {
    fn wasm_hook(&self, param: &ParseParam, payload: &[u8], info: &mut NatsInfo) {
        let (subject, reply_to, nats_payload) = {
            match &info.message {
                NatsMessage::Msg(msg) => (
                    msg.subject.clone(),
                    msg.reply_to.clone(),
                    msg.payload.clone(),
                ),
                NatsMessage::Hmsg(msg) => (
                    msg.subject.clone(),
                    msg.reply_to.clone(),
                    msg.payload.clone(),
                ),
                NatsMessage::Pub(msg) => (
                    msg.subject.clone(),
                    msg.reply_to.clone(),
                    msg.payload.clone(),
                ),
                NatsMessage::Hpub(msg) => (
                    msg.subject.clone(),
                    msg.reply_to.clone(),
                    msg.payload.clone(),
                ),
                _ => return,
            }
        };

        let wasm_nats_message = WasmNatsMessage {
            subject,
            reply_to: reply_to.unwrap_or_default(),
            payload: nats_payload,
        };

        let mut vm_ref = param.wasm_vm.borrow_mut();
        let Some(vm) = vm_ref.as_mut() else {
            return;
        };

        let wasm_data = WasmData::from_request(self.protocol(), wasm_nats_message);

        if let Some(custom) = vm.on_custom_message(payload, param, wasm_data) {
            if !custom.attributes.is_empty() {
                info.attributes.extend(custom.attributes);
            }
            if custom.proto_str.len() > 0 {
                info.l7_protocol_str = Some(custom.proto_str);
            }
        }
    }
}

impl L7ProtocolParserInterface for NatsLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol() {
            return false;
        }
        if param.l4_protocol != IpProtocol::TCP {
            return false;
        }

        NatsInfo::try_parse(payload, param.parse_config).is_some()
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };

        let mut vec = Vec::new();
        let mut payload = payload;

        let config = param.parse_config;

        while let Some((tmp, info)) = NatsInfo::try_parse(payload, config) {
            payload = tmp;
            if let NatsMessage::Info(info) = &info.message {
                self.version = info.version.clone();
                self.server_name = info.server_name.clone();
            }
            vec.push(L7ProtocolInfo::NatsInfo(info));
        }

        for info in &mut vec {
            if let L7ProtocolInfo::NatsInfo(info) = info {
                if info.msg_type != LogMessageType::Session {
                    info.cal_rrt(param).map(|rtt| {
                        info.rtt = rtt;
                        self.perf_stats.as_mut().map(|p| p.update_rrt(rtt));
                    });
                }

                info.is_tls = param.is_tls();
                info.version = self.version.clone();
                info.server_name = self.server_name.clone();

                self.wasm_hook(param, payload, info);
                set_captured_byte!(info, param);
                match param.direction {
                    PacketDirection::ClientToServer => {
                        self.perf_stats.as_mut().map(|p| p.inc_req());
                    }
                    PacketDirection::ServerToClient => {
                        self.perf_stats.as_mut().map(|p| p.inc_resp());
                    }
                }
            }
        }

        if !param.parse_log {
            Ok(L7ParseResult::None)
        } else if vec.len() == 1 {
            Ok(L7ParseResult::Single(vec.remove(0)))
        } else if vec.len() > 1 {
            Ok(L7ParseResult::Multi(vec))
        } else {
            Ok(L7ParseResult::None)
        }
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::NATS
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn reset(&mut self) {
        let mut s = Self::default();
        s.version = self.version.clone();
        s.server_name = self.server_name.clone();
        s.perf_stats = self.perf_stats.take();
        *self = s;
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::rc::Rc;
    use std::{cell::RefCell, fs};

    use super::*;

    use crate::{
        common::{flow::PacketDirection, l7_protocol_log::L7PerfCache, MetaPacket},
        config::{handler::TraceType, ExtraLogFields},
        flow_generator::L7_RRT_CACHE_CAPACITY,
        utils::test::Capture,
    };

    const FILE_DIR: &str = "resources/test/flow_generator/nats";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name), None);
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut output: String = String::new();
        let mut first_packet = true;
        let first_dst_port = packets[0].lookup_key.dst_port;
        let mut nats = NatsLog::default();
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
                log_cache.clone(),
                Default::default(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Default::default(),
                true,
                true,
            );
            param.set_captured_byte(payload.len());

            let config = L7LogDynamicConfig::new(
                "".to_owned(),
                vec![],
                vec![TraceType::Sw8, TraceType::TraceParent],
                vec![TraceType::Sw8, TraceType::TraceParent],
                ExtraLogFields::default(),
            );
            let parse_config = &LogParserConfig {
                l7_log_dynamic: config.clone(),
                ..Default::default()
            };

            param.set_log_parse_config(parse_config);

            if first_packet {
                first_packet = false;
                if !nats.check_payload(payload, param) {
                    output.push_str("not nats\n");
                    break;
                }
            }

            let info = nats.parse_payload(payload, param);
            if let Ok(info) = info {
                match info {
                    L7ParseResult::Single(s) => {
                        output.push_str(&format!("{:?}\n", s));
                    }
                    L7ParseResult::Multi(m) => {
                        for i in m {
                            output.push_str(&format!("{:?}\n", i));
                        }
                    }
                    L7ParseResult::None => {
                        output.push_str("None\n");
                    }
                }
            } else {
                output.push_str(&format!("{:?}\n", NatsInfo::default()));
            }
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
            ("nats-nrpc1.pcap", "nats-nrpc1.result"),
            ("nats-nrpc2.pcap", "nats-nrpc2.result"),
            ("nats-nrpc3.pcap", "nats-nrpc3.result"),
            ("nats-err.pcap", "nats-err.result"),
            ("nats-headers.pcap", "nats-headers.result"),
            ("nats-skywalking.pcap", "nats-skywalking.result"),
            ("nats-opentelemetry.pcap", "nats-opentelemetry.result"),
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
    fn check_read_line() {
        let test = |payload: &[u8], expected: Option<&[u8]>| {
            if expected.is_none() {
                assert_eq!(read_line(payload), None);
            } else {
                let expected = expected.unwrap();
                assert_eq!(
                    read_line(payload),
                    Some((&payload[expected.len() + 2..], expected))
                );
            }
        };
        test(b"abc\r\n", Some(b"abc"));
        test(b"abc\r", None);
        test(b"abc\n", None);
        test(b"abc", None);
        test(b"abcd\r\nabc", Some(b"abcd"));
        test(b"\r\n", Some(b""));
        test(b"\rasdf\r\n", Some(b"\rasdf"));
        test(b"\nasdf\r\n", Some(b"\nasdf"));
        test(b"", None);
    }

    #[test]
    fn check_read_field() {
        let test = |payload: &[u8], expected: Option<&[u8]>| {
            if expected.is_none() {
                assert_eq!(read_field(payload), None);
            } else {
                let expected = expected.unwrap();
                assert_eq!(
                    read_field(payload),
                    Some((&payload[expected.len()..], expected))
                );
            }
        };
        test(b"abc ", Some(b"abc"));
        test(b"abc\t", Some(b"abc"));
        test(b"abc\rd", Some(b"abc"));
        test(b" abc ", None);
        test(b"\tabc ", None);
        test(b"\rabc ", None);
        test(b"\nabc ", None);
        test(b"aabca", None);
        test(b"", None);
    }
}
