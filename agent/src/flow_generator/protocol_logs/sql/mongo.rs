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

use std::ffi::CStr;

use bson::{self, Document};
use serde::Serialize;

use super::super::{AppProtoHead, LogMessageType};
use crate::common::flow::L7PerfStats;
use crate::common::l7_protocol_log::L7ParseResult;
use crate::flow_generator::protocol_logs::set_captured_byte;
use crate::{
    common::{
        enums::IpProtocol,
        flow::L7Protocol,
        flow::PacketDirection,
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ProtocolParserInterface, ParseParam},
        meta_packet::EbpfFlags,
    },
    flow_generator::{
        protocol_logs::{
            pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response},
            value_is_default, L7ResponseStatus,
        },
        Error, Result,
    },
    utils::bytes,
};

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
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub request: String,
    #[serde(skip)]
    pub response: String,
    #[serde(rename = "response_code", skip_serializing_if = "value_is_default")]
    pub response_code: i32,
    #[serde(skip)]
    pub exception: String,
    #[serde(rename = "response_status")]
    pub status: L7ResponseStatus,

    captured_request_byte: u32,
    captured_response_byte: u32,

    rrt: u64,
}

impl L7ProtocolInfoInterface for MongoDBInfo {
    fn session_id(&self) -> Option<u32> {
        None
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
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

    fn get_request_resource_length(&self) -> usize {
        self.request.len()
    }
}

// 协议文档: https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/
impl MongoDBInfo {
    fn merge(&mut self, other: &mut Self) {
        match other.msg_type {
            LogMessageType::Request => {
                self.req_len = other.req_len;
                std::mem::swap(&mut self.op_code_name, &mut other.op_code_name);
                self.op_code = other.op_code;
                std::mem::swap(&mut self.request, &mut other.request);
                self.request_id = other.request_id;
                self.captured_request_byte = other.captured_request_byte;
            }
            LogMessageType::Response => {
                self.response_code = other.response_code;
                self.resp_len = other.resp_len;
                std::mem::swap(&mut self.exception, &mut other.exception);
                self.status = other.status;
                self.response_id = other.response_id;
                std::mem::swap(&mut self.response, &mut other.response);
                self.captured_response_byte = other.captured_response_byte;
            }
            _ => {}
        }
    }
}

impl From<MongoDBInfo> for L7ProtocolSendLog {
    fn from(f: MongoDBInfo) -> Self {
        let flags = if f.is_tls {
            EbpfFlags::TLS.bits()
        } else {
            EbpfFlags::NONE.bits()
        };
        let log = L7ProtocolSendLog {
            captured_request_byte: f.captured_request_byte,
            captured_response_byte: f.captured_response_byte,
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
                status: f.status,
                ..Default::default()
            },
            ext_info: Some(ExtendedInfo {
                request_id: Option::<u32>::from(f.request_id),
                ..Default::default()
            }),
            flags,
            ..Default::default()
        };
        return log;
    }
}

#[derive(Default)]
pub struct MongoDBLog {
    info: MongoDBInfo,
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
        return header.is_request();
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        let mut info = MongoDBInfo::default();
        if self.perf_stats.is_none() {
            self.perf_stats = Some(L7PerfStats::default())
        };

        self.parse(payload, param.l4_protocol, param.direction, &mut info)?;
        info.cal_rrt(param).map(|rrt| {
            info.rrt = rrt;
            self.perf_stats.as_mut().map(|p| p.update_rrt(rrt));
        });
        info.is_tls = param.is_tls();
        set_captured_byte!(info, param);
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
const _DB_MSG: u32 = 1000;
const _OP_UPDATE: u32 = 2001;
const _OP_INSERT: u32 = 2002;
const _RESERVED: u32 = 2003;
const _OP_QUERY: u32 = 2004;
const _OP_GET_MORE: u32 = 2005;
const _OP_DELETE: u32 = 2006;
const _OP_KILL_CURSORS: u32 = 2007;
const _OP_COMMAND: u32 = 2010;
const _OP_COMMANDREPLY: u32 = 2011;
const _OP_COMPRESSED: u32 = 2012;
const _OP_MSG: u32 = 2013;
const _UNKNOWN: &str = "";

const _HEADER_SIZE: usize = 16;

const _EXCEPTION_OFFSET: usize = 20;
const _COLLECTION_NAME_OFFSET: usize = 20;
const _QUERY_DOC_OFFSET: usize = _COLLECTION_NAME_OFFSET + 8; // 8 is sizeof(Number to skip + Number to Reture)
const _MSG_DOC_SECTION_OFFSET: usize = _HEADER_SIZE + 4; // 4 is sizeof(Message Flags)

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
        info.op_code_name = header.op_code_name.clone();

        if header.is_request() {
            info.msg_type = LogMessageType::Request;
            self.info.req_len = header.length;
            info.request_id = header.request_id;
            self.perf_stats
                .as_mut()
                .map(|p: &mut L7PerfStats| p.inc_req());
        } else {
            info.msg_type = LogMessageType::Response;
            self.info.resp_len = header.length;
            info.request_id = header.response_to;
            info.response_id = header.request_id;
            self.perf_stats.as_mut().map(|p| p.inc_resp());
        }

        // command decode
        match info.op_code {
            _OP_MSG if payload.len() > _MSG_DOC_SECTION_OFFSET => {
                // OP_MSG
                let mut msg_body = MongoOpMsg::default();
                // TODO: Message Flags
                msg_body.decode(&payload[_MSG_DOC_SECTION_OFFSET..])?;
                match info.msg_type {
                    LogMessageType::Response => {
                        // The data structure of doc is Bson, which is a normal response when there is no errmsg in it
                        if msg_body.sections.doc.get_str("errmsg").is_err() {
                            info.response = msg_body.sections.doc.to_string();
                        } else {
                            info.exception =
                                msg_body.sections.doc.get_str("errmsg").unwrap().to_string();
                            // TODO: Distinguish error types
                            info.status = L7ResponseStatus::ClientError;
                        }
                        if info.exception.len() == 0 {
                            info.exception =
                                msg_body.sections.c_string.unwrap_or(_UNKNOWN.to_string());
                        }
                        info.response_code = msg_body.sections.doc.get_i32("code").unwrap_or(0);
                        if info.response_code > 0 {
                            self.perf_stats.as_mut().map(|p| p.inc_req_err());
                        }
                    }
                    _ => {
                        info.request = msg_body.sections.doc.to_string();
                    }
                }
            }
            _OP_REPLY if payload.len() > _HEADER_SIZE => {
                // "OP_REPLY"
                let mut msg_body = MongoOpReply::default();
                msg_body.decode(&payload[_HEADER_SIZE..])?;
                if !msg_body.reply_ok {
                    self.perf_stats.as_mut().map(|p| p.inc_resp_err());
                }
                info.response = msg_body.doc.to_string();
                info.exception = msg_body.response_msg;
            }
            _OP_UPDATE if payload.len() > 24 => {
                // "OP_UPDATE"
                info.exception = CStr::from_bytes_until_nul(&payload[20..])
                    .map_err(|_| Error::L7ProtocolUnknown)?
                    .to_string_lossy()
                    .into_owned();
                if payload.len() > 24 + info.exception.len() + 1 {
                    let update = Document::from_reader(&payload[24 + info.exception.len() + 1..])
                        .unwrap_or(Document::default());
                    info.request = update.to_string();
                }
            }
            _OP_INSERT if payload.len() > 20 => {
                // OP_INSERT
                info.exception = CStr::from_bytes_until_nul(&payload[20..])
                    .map_err(|_| Error::L7ProtocolUnknown)?
                    .to_string_lossy()
                    .into_owned();
                if payload.len() > 20 + info.exception.len() + 1 {
                    let insert = Document::from_reader(&payload[20 + info.exception.len() + 1..])
                        .unwrap_or(Document::default());
                    info.request = insert.to_string();
                }
            }
            _OP_QUERY if payload.len() > 28 => {
                // "OP_QUERY"
                let collection_name =
                    CStr::from_bytes_until_nul(&payload[_COLLECTION_NAME_OFFSET..])
                        .map_err(|_| Error::L7ProtocolUnknown)?
                        .to_string_lossy()
                        .into_owned();

                if payload.len() > _QUERY_DOC_OFFSET + collection_name.len() + 1 {
                    let query = Document::from_reader(
                        &payload[_QUERY_DOC_OFFSET + collection_name.len() + 1..],
                    )
                    .unwrap_or(Document::default());
                    info.request = query.to_string();
                }
            }
            _OP_GET_MORE | _OP_DELETE if payload.len() > 20 => {
                // OP_GET_MORE
                info.request = CStr::from_bytes_until_nul(&payload[..20])
                    .map_err(|_| Error::L7ProtocolUnknown)?
                    .to_string_lossy()
                    .into_owned();
            }
            _ => {}
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
    fn is_request(&self) -> bool {
        match self.op_code {
            _OP_QUERY | _OP_UPDATE | _OP_INSERT | _OP_DELETE => true,
            _OP_REPLY => false,
            // response_to is the request_id, when 0 means the request
            _ => self.response_to == 0,
        }
    }

    fn decode(&mut self, payload: &[u8]) -> isize {
        if payload.len() < 16 {
            return -1;
        }
        self.length = bytes::read_u32_le(payload);
        if self.length < payload.len() as u32 {
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
            _OP_REPLY => "OP_REPLY",
            _DB_MSG => "DB_MSG",
            _OP_UPDATE => "OP_UPDATE", // 用于更新集合中的文档
            _OP_INSERT => "OP_INSERT", // 用于将一个或多个文档插入集合中。
            _RESERVED => "RESERVED",
            _OP_QUERY => "OP_QUERY", // 用于在数据库中查询集合中的文档。
            _OP_GET_MORE => "OP_GET_MORE", // 用于在数据库中查询集合中的文档。
            _OP_DELETE => "OP_DELETE", // 用于从集合中删除一个或多个文档。
            _OP_KILL_CURSORS => "OP_KILL_CURSORS", // 用于关闭数据库中的活动游标。这是确保在查询结束时回收数据库资源所必需的。
            _OP_COMMAND => "OP_COMMAND",           // 表示命令请求的集群内部协议。已过时
            _OP_COMMANDREPLY => "OP_COMMANDREPLY", // 群内部协议表示对OP_COMMAND的回复。已过时
            _OP_COMPRESSED => "OP_COMPRESSED",
            _OP_MSG => "OP_MSG", // 使用MongoDB 3.6中引入的格式发送消息
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
    const _KIND_OFFSET: usize = 0;
    const _KIND_LEN: usize = 1;
    const _DOC_LENGTH_OFFSET: usize = Self::_KIND_OFFSET + Self::_KIND_LEN;
    const _DOC_LENGTH_LEN: usize = 4;

    fn decode(&mut self, payload: &[u8]) -> Result<bool> {
        if payload.len() < Self::_DOC_LENGTH_OFFSET + Self::_DOC_LENGTH_LEN {
            return Ok(false);
        }
        let mut sections = Sections::default();
        //sections.kind = payload[4];
        let section_len = bytes::read_u32_le(
            &payload[Self::_DOC_LENGTH_OFFSET..Self::_DOC_LENGTH_OFFSET + Self::_DOC_LENGTH_LEN],
        );
        if payload.len() < Self::_DOC_LENGTH_LEN + section_len as usize {
            return Ok(false);
        }
        let _ = sections.decode(&payload);
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
                let length = bytes::read_u32_le(&payload[1..5]);
                // TODO: When ChecksumPresent is 1, there will be checksum in the payload
                if length != payload.len() as u32 - 1 && length != payload.len() as u32 - 5 {
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
                self.kind_name = _UNKNOWN.to_string();
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
                self.response_msg = _UNKNOWN.to_string();
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

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::rc::Rc;
    use std::{cell::RefCell, fs};

    use super::*;

    use crate::{
        common::{flow::PacketDirection, l7_protocol_log::L7PerfCache, MetaPacket},
        flow_generator::L7_RRT_CACHE_CAPACITY,
        utils::test::Capture,
    };

    const FILE_DIR: &str = "resources/test/flow_generator/mongo";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name), None);
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
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

            let mut mongo = MongoDBLog::default();
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

            let is_mongo = mongo.check_payload(payload, param);
            let info = mongo.parse_payload(payload, param);
            if let Ok(info) = info {
                match info.unwrap_single() {
                    L7ProtocolInfo::MongoDBInfo(i) => {
                        output.push_str(&format!("{:?} is_mongo: {}\n", i, is_mongo));
                    }
                    _ => unreachable!(),
                }
            } else {
                output.push_str(&format!(
                    "{:?} is_mongo: {}\n",
                    MongoDBInfo::default(),
                    is_mongo
                ));
            }
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![("mongo.pcap", "mongo.result")];

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
