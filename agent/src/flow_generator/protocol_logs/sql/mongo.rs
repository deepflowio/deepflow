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

use serde::Serialize;

use super::super::{AppProtoHead, LogMessageType};

use crate::common::flow::L7PerfStats;
use crate::common::l7_protocol_log::L7ParseResult;
use crate::{
    common::{
        enums::IpProtocol,
        flow::L7Protocol,
        flow::PacketDirection,
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ProtocolParserInterface, ParseParam},
    },
    flow_generator::{
        protocol_logs::{
            pb_adapter::{L7ProtocolSendLog, L7Request, L7Response},
            L7ResponseStatus,
        },
        Error, Result,
    },
    utils::bytes,
};
// 加载bson库
use bson::{self, Document};

#[derive(Serialize, Debug, Default, Clone)]
pub struct MongoDBInfo {
    msg_type: LogMessageType,
    #[serde(skip)]
    is_tls: bool,

    // req_len and resp_len are from message length
    #[serde(rename = "req_len")]
    pub req_len: u32,
    #[serde(rename = "resp_len")]
    pub resp_len: u32,

    #[serde(rename = "request_id")]
    pub request_id: u32,
    #[serde(rename = "response_id")]
    pub response_id: u32,
    #[serde(rename = "op_code")]
    pub op_code: u32,
    #[serde(skip)]
    pub op_code_name: String,
    #[serde(skip)]
    pub request: String,
    #[serde(skip)]
    pub response: String,
    #[serde(skip)]
    pub exception: String,
}

impl L7ProtocolInfoInterface for MongoDBInfo {
    fn session_id(&self) -> Option<u32> {
        None
    }

    fn merge_log(&mut self, other: L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::MongoDBInfo(other) = other {
            self.merge(other);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::MongoDB,
            msg_type: self.msg_type,
            rrt: 0,
        })
    }

    fn is_tls(&self) -> bool {
        self.is_tls
    }
}

// 协议文档: https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/
impl MongoDBInfo {
    fn merge(&mut self, other: Self) {
        if self.response_id == 0 {
            self.request_id = other.request_id
        }
        self.request_id = other.request_id;

        if other.response_id > 0 {
            self.response_id = other.response_id;
        }
        self.request = other.request;
        self.response = other.response;
        match other.msg_type {
            LogMessageType::Request => {
                self.req_len = other.req_len;
                self.op_code_name = other.op_code_name;
                self.op_code = other.op_code;
            }
            LogMessageType::Response => {
                self.resp_len = other.resp_len;
            }
            _ => {}
        }
    }
}

impl From<MongoDBInfo> for L7ProtocolSendLog {
    fn from(f: MongoDBInfo) -> Self {
        let log = L7ProtocolSendLog {
            req_len: std::option::Option::<u32>::from(f.req_len),
            req: L7Request {
                req_type: f.op_code_name,
                resource: f.request.to_string(),
                ..Default::default()
            },
            resp_len: std::option::Option::<u32>::from(f.resp_len),
            resp: L7Response {
                result: f.response.to_string(),
                exception: f.exception.to_string(),
                status: L7ResponseStatus::Ok,
                ..Default::default()
            },
            ..Default::default()
        };
        return log;
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct MongoDBLog {
    info: MongoDBInfo,
    #[serde(skip)]
    perf_stats: Option<L7PerfStats>,
}

impl L7ProtocolParserInterface for MongoDBLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol() {
            return false;
        }
        if param.l4_protocol != IpProtocol::TCP {
            return false;
        }
        let mut header = MongoDBHeader::default();
        let offset = header.decode(payload);
        if offset < 0 {
            return false;
        }

        self.info.is_tls = param.is_tls();
        return true;
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        let mut info = MongoDBInfo::default();
        self.info.is_tls = param.is_tls();
        if self.perf_stats.is_none() {
            self.perf_stats = Some(L7PerfStats::default())
        };

        self.parse(payload, param.l4_protocol, param.direction, &mut info)?;
        if param.parse_log {
            Ok(L7ParseResult::Single(L7ProtocolInfo::MongoDBInfo(info)))
        } else {
            Ok(L7ParseResult::None)
        }
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::MongoDB
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

impl MongoDBLog {
    // TODO: tracing
    fn parse(
        &mut self,
        payload: &[u8],
        proto: IpProtocol,
        _direction: PacketDirection,
        info: &mut MongoDBInfo,
    ) -> Result<bool> {
        if proto != IpProtocol::TCP {
            return Err(Error::InvalidIpProtocol);
        }

        let mut header = MongoDBHeader::default();
        let offset = header.decode(payload);
        if offset <= 0 {
            return Err(Error::MongoDBLogParseFailed);
        }
        if header.response_to > 0 {
            // response_to is the request_id, when 0 means the request
            info.msg_type = LogMessageType::Response;
            self.info.resp_len = header.length;
            info.request_id = header.response_to;
            info.response_id = header.request_id;
        } else {
            info.msg_type = LogMessageType::Request;
            self.info.req_len = header.length;
            info.request_id = header.request_id;
        }
        info.op_code = header.op_code;
        info.op_code_name = header.op_code_name;
        // command decode
        match info.op_code_name.as_str() {
            "OP_MSG" => {
                let mut msg_body = MongoOpMsg::default();
                msg_body.decode(&payload[16..offset as usize + 16])?;
                match info.msg_type {
                    LogMessageType::Response => {
                        info.response = msg_body.sections.doc.to_string();
                        info.exception = msg_body.sections.c_string.unwrap_or("unknown".to_string());
                    }
                    _ => {
                        info.request = msg_body.sections.doc.to_string();
                    }
                }
            }
            _ => {
                info.request = info.op_code_name.clone();
            }
        }
        Ok(false)
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct MongoDBHeader {
    length: u32,
    request_id: u32,
    response_to: u32,
    op_code: u32,
    op_code_name: String,
}

impl MongoDBHeader {
    fn decode(&mut self, payload: &[u8]) -> isize {
        if payload.len() < 16 {
            return -1;
        }
        self.length = bytes::read_u32_le(payload) & 0xffffff;
        if self.length != payload.len() as u32 {
            return -1;
        }
        self.op_code = bytes::read_u32_le(&payload[12..16]);
        self.op_code_name = self.get_op_str().to_string();
        if "OP_UNKNOWN".to_string() == self.op_code_name {
            return -1;
        }
        self.request_id = bytes::read_u32_le(&payload[4..8]);
        self.response_to = bytes::read_u32_le(&payload[8..12]);
        return self.length as isize - 16;
    }

    pub fn get_op_str(&self) -> &'static str {
        match self.op_code {
            1 => "OP_REPLY",
            1000 => "DB_MSG",
            2001 => "OP_UPDATE",
            2002 => "OP_INSERT",
            2003 => "RESERVED",
            2004 => "OP_QUERY",
            2005 => "OP_GET_MORE",
            2006 => "OP_DELETE",
            2007 => "OP_KILL_CURSORS",
            2012 => "OP_COMPRESSED",
            2013 => "OP_MSG",
            _ => "OP_UNKNOWN",
        }
    }
}

// TODO: support compressed
pub struct MongoOpCompressed {
    original_op_code: u32,
    uncompressed_size: u32,
    compressor_id: u8,
    //char: String,
}

// TODO: support op msg
#[derive(Clone, Debug, Default, Serialize)]
pub struct MongoOpMsg {
    flag: u32,
    sections: Sections,
    checksum: Option<u32>,
}

impl MongoOpMsg {
    fn decode(&mut self, payload: &[u8]) -> Result<bool> {
        // todo: decode flag
        let mut sections = Sections::default();
        //sections.kind = payload[4];
        let section_len = bytes::read_u32_le(&payload[5..9]);
        if payload.len() < 4 + section_len as usize {
            return Ok(false);
        }
        let _ = sections.decode(&payload[4..]);
        self.sections = sections;
        // todo: decode checksum
        Ok(true)
    }
}

#[derive(Clone, Debug, Default, Serialize)]
struct Sections {
    kind: u8,
    kind_name: String,
    // kind: 0 mean doc
    doc: Document,
    // kind: 1 mean body
    size: Option<i32>,
    c_string: Option<String>,
}

impl Sections {
    pub fn decode(&mut self, payload: &[u8]) -> Result<bool> {
        if payload.len() < 6 {
            return Ok(false);
        }
        self.kind = payload[0];
        // todo: decode doc
        match self.kind {
            0 => {
                // Body
                self.kind_name = "BODY".to_string();
                let lenght = bytes::read_u32_le(&payload[1..5]);
                if lenght != payload.len() as u32 - 1 {
                    return Ok(false);
                }
                self.doc = Document::from_reader(&payload[1..]).unwrap_or(Document::default());
            }
            1 => {
                // Doc
                self.kind_name = "DOC".to_string();
                self.size =
                    std::option::Option::<i32>::from(bytes::read_u32_le(&payload[1..5]) as i32);
                self.c_string = std::option::Option::Some(read_c_string(&payload[5..]));
                self.doc = Document::from_reader(&payload[1..]).unwrap_or(Document::default());
            }
            2 => {
                // Internal
                self.kind_name = "INTERNAL".to_string();
                // This section is used for internal purposes.
                return Ok(false);
            }
            _ => {
                // Unknown
                self.kind_name = "UNKNOWN".to_string();
                return Ok(false);
            }
        }
        Ok(true)
    }
}

use std::ffi::CString;

fn read_c_string(bytes: &[u8]) -> String {
    let mut buffer = Vec::new();
    for &byte in bytes.iter() {
        if byte == 0 {
            break;
        }
        buffer.push(byte);
    }
    let c_string = CString::new(buffer).expect("Failed to create CString");
    c_string
        .into_string()
        .expect("Failed to convert CString to String")
}

// Deprecated as of MongoDB 5.0.
// Unsupported as of MongoDB 5.1.
// TODO: support
pub struct MongoOpDel {
    zero: u32,
}

// TODO: support
pub struct MongoOpGetMore {
    zero: u32,
}

// TODO: support
pub struct MongoOpInsert {
    zero: u32,
}

// TODO: support
pub struct MongoOpKillCursors {
    zero: u32,
}

// TODO: support
pub struct MongoOpQuery {
    flags: u32,
}

// TODO: support
pub struct MongoOpReply {
    response_flags: u32,
    cursor_id: u64,
    starting_from: u32,
    number_to_return: u32,
}

// TODO: support
pub struct MongoOpUpdate {
    zero: u32,
}
