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

#[derive(Serialize, Debug, Default, Clone)]
pub struct MongoDBInfo {
    msg_type: LogMessageType,
    #[serde(skip)]
    is_tls: bool,

    // Server Greeting
    #[serde(rename = "message_length")]
    pub message_length: u32,
    #[serde(rename = "request_id")]
    pub request_id: u32,
    #[serde(rename = "response_to")]
    pub response_to: u32,
    #[serde(rename = "op_code")]
    pub op_code: u32,
    #[serde(skip)]
    pub op_code_name: String,
    //#[serde(rename = "context")]
    //pub context: String,
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
        self.message_length = other.message_length;
        self.request_id = other.request_id;
        self.response_to = other.response_to;
        self.op_code = other.op_code;
        self.op_code_name = other.op_code_name;
        //self.context = other.context;
    }
}

impl From<MongoDBInfo> for L7ProtocolSendLog {
    fn from(f: MongoDBInfo) -> Self {
        let log = L7ProtocolSendLog {
            req: L7Request {
                req_type: f.op_code_name,
                resource: f.request_id.to_string(),
                ..Default::default()
            },
            resp: L7Response {
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
        if param.l4_protocol != IpProtocol::Tcp {
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
        if self.parse(payload, param.l4_protocol, param.direction, &mut info)? {
            // ignore greeting
            return Ok(L7ParseResult::None);
        }
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

    // TODO
    fn reset(&mut self) {
        self.info = MongoDBInfo::default();
        self.perf_stats = self.perf_stats.take();
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
        direction: PacketDirection,
        info: &mut MongoDBInfo,
    ) -> Result<bool> {
        if proto != IpProtocol::Tcp {
            return Err(Error::InvalidIpProtocol);
        }

        let mut header = MongoDBHeader::default();
        let offset = header.decode(payload);
        if offset < 0 {
            return Err(Error::MongoDBLogParseFailed);
        }
        info.message_length = header.length;
        info.request_id = header.request_id;
        info.response_to = header.response_to;
        info.op_code = header.op_code;
        info.op_code_name = header.op_code_name;
        //let offset = offset as usize;
        match direction {
            PacketDirection::ServerToClient => info.msg_type = LogMessageType::Response,
            PacketDirection::ClientToServer => info.msg_type = LogMessageType::Request,
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
        if payload.len() < 32 * 4 {
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
        return self.length as isize;
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
pub struct MongoOpMsg {
    flag: u32,
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
