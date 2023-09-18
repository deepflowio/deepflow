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
use std::ffi::CStr;

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
    pub response_code: i32,
    #[serde(skip)]
    pub exception: String,

    rrt: u64,
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
            rrt: self.rrt,
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
            self.request_id = other.request_id;
            self.request = other.request;
        }
        //self.request_id = other.request_id;

        if self.response_id == 0 {
            self.response_id = other.response_id;
            self.response = other.response;
        }

        match other.msg_type {
            LogMessageType::Request => {
                self.req_len = other.req_len;
                self.op_code_name = other.op_code_name;
                self.op_code = other.op_code;
            }
            LogMessageType::Response => {
                self.response_code = other.response_code;
                self.resp_len = other.resp_len;
                self.exception = other.exception;
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
                code: std::option::Option::<i32>::from(f.response_code),
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
        info.cal_rrt(param, None).map(|rrt| {
            info.rrt = rrt;
            self.perf_stats.as_mut().map(|p| p.update_rrt(rrt));
        });
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

const _OP_REPLY: u32 = 1;
const _OP_MSG: u32 = 2013;
const _OP_UPDATE: u32 = 2001;
const _OP_INSERT: u32 = 2002;
const _OP_QUERY: u32 = 2004;
const _OP_GET_MORE: u32 = 2005;
const _OP_DELETE: u32 = 2006;

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
        info.op_code = header.op_code;
        info.op_code_name = header.op_code_name;
        // command decode
        match info.op_code {
            _OP_MSG => {
                // OP_MSG
                let mut msg_body = MongoOpMsg::default();
                msg_body.decode(&payload[16..offset as usize + 16])?;
                match info.msg_type {
                    LogMessageType::Response => {
                        info.response = msg_body.sections.doc.to_string();
                        info.exception =
                            msg_body.sections.c_string.unwrap_or("unknown".to_string());
                        info.response_code =
                            msg_body.sections.doc.get_f64("code").unwrap_or(0.0) as i32;
                        if info.response_code > 0 {
                            self.perf_stats.as_mut().map(|p| p.inc_resp_err());
                        }
                    }
                    _ => {
                        info.request = msg_body.sections.doc.to_string();
                    }
                }
            }
            _OP_REPLY => {
                // "OP_REPLY"
                let mut msg_body = MongoOpReply::default();
                msg_body.decode(&payload[16..])?;
                if !msg_body.reply_ok {
                    self.perf_stats.as_mut().map(|p| p.inc_resp_err());
                }
                info.response = msg_body.doc.to_string();
                info.exception = msg_body.response_msg;
            }
            _OP_UPDATE => {
                // "OP_UPDATE"
                info.exception = CStr::from_bytes_until_nul(&payload[20..])
                    .map_err(|_| Error::L7ProtocolUnknown)?
                    .to_string_lossy()
                    .into_owned();
                let update = Document::from_reader(&payload[24 + info.exception.len() + 1..])
                    .unwrap_or(Document::default());
                info.request = update.to_string();
            }
            _OP_INSERT => {
                // OP_INSERT
                info.exception = CStr::from_bytes_until_nul(&payload[20..])
                    .map_err(|_| Error::L7ProtocolUnknown)?
                    .to_string_lossy()
                    .into_owned();
                let insert = Document::from_reader(&payload[20 + info.exception.len() + 1..])
                    .unwrap_or(Document::default());
                info.request = insert.to_string();
            }
            _OP_QUERY => {
                // "OP_QUERY"
                info.exception = CStr::from_bytes_until_nul(&payload[..20])
                    .map_err(|_| Error::L7ProtocolUnknown)?
                    .to_string_lossy()
                    .into_owned();

                let query = Document::from_reader(&payload[28 + info.exception.len() + 1..])
                    .unwrap_or(Document::default());
                info.request = query.to_string();
            }
            _OP_GET_MORE | _OP_DELETE => {
                // OP_GET_MORE
                info.request = CStr::from_bytes_until_nul(&payload[..20])
                    .map_err(|_| Error::L7ProtocolUnknown)?
                    .to_string_lossy()
                    .into_owned();
            }
            _ => {
                info.request = info.op_code_name.clone();
            }
        }

        if header.response_to > 0 {
            // response_to is the request_id, when 0 means the request
            info.msg_type = LogMessageType::Response;
            self.info.resp_len = header.length;
            info.request_id = header.response_to;
            info.response_id = header.request_id;
            self.perf_stats.as_mut().map(|p| p.inc_resp());
        } else {
            info.msg_type = LogMessageType::Request;
            self.info.req_len = header.length;
            info.request_id = header.request_id;
            self.perf_stats.as_mut().map(|p| p.inc_req());
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
            2001 => "OP_UPDATE", // 用于更新集合中的文档
            2002 => "OP_INSERT", // 用于将一个或多个文档插入集合中。
            2003 => "RESERVED",
            2004 => "OP_QUERY",        // 用于在数据库中查询集合中的文档。
            2005 => "OP_GET_MORE",     // 用于在数据库中查询集合中的文档。
            2006 => "OP_DELETE",       // 用于从集合中删除一个或多个文档。
            2007 => "OP_KILL_CURSORS", // 用于关闭数据库中的活动游标。这是确保在查询结束时回收数据库资源所必需的。
            2010 => "OP_COMMAND",      // 表示命令请求的集群内部协议。已过时
            2011 => "OP_COMMANDREPLY", // 群内部协议表示对OP_COMMAND的回复。已过时
            2012 => "OP_COMPRESSED",
            2013 => "OP_MSG", // 使用MongoDB 3.6中引入的格式发送消息
            _ => "OP_UNKNOWN",
        }
    }
}

// TODO: support compressed
#[derive(Clone, Debug, Default, Serialize)]
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
                self.c_string = Some(
                    CStr::from_bytes_until_nul(&payload[5..])
                        .map_err(|_| Error::L7ProtocolUnknown)?
                        .to_string_lossy()
                        .into_owned(),
                );

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

// Deprecated as of MongoDB 5.0.
// Unsupported as of MongoDB 5.1.
#[derive(Clone, Debug, Default, Serialize)]
pub struct MongoOpReply {
    response_flags: u32,
    response_msg: String,
    reply_ok: bool,
    //cursor_id: u64,
    //starting_from: u32,
    //number_to_return: u32,
    doc: Document,
}

impl MongoOpReply {
    pub fn decode(&mut self, payload: &[u8]) -> Result<bool> {
        if payload.len() < 20 {
            return Ok(false);
        }
        self.response_flags = bytes::read_u32_le(&payload[0..4]);
        // todo: decode doc
        match self.response_flags {
            0 => {
                // CursorNotFound
                self.response_msg = "CursorNotFound".to_string();
                self.reply_ok = true;
            }
            1 => {
                // QueryFailure
                self.response_msg = "QueryFailure".to_string();
                self.reply_ok = false;
            }
            2 => {
                // ShardConfigStale
                self.response_msg = "ShardConfigStale".to_string();
                self.reply_ok = true;
            }
            _ => {
                // Unknown is Undecoded
                self.response_msg = "UNKNOWN".to_string();
                self.reply_ok = true;
            }
        }
        self.doc = Document::from_reader(&payload[20..]).unwrap_or(Document::default());
        Ok(true)
    }
}
// TODO: support or Simple decoding
/*
pub struct MongoOpDel {
    zero: u32,
}

pub struct MongoOpGetMore {
    zero: u32,
}

pub struct MongoOpInsert {
    zero: u32,
}

pub struct MongoOpKillCursors {
    zero: u32,
}

pub struct MongoOpQuery {
    flags: u32,
    full_collection_name: String,
    number_to_skip: u32,
    number_to_return: u32,
    query: Document,
}

pub struct MongoOpUpdate {
    zero: u32,
}
*/
