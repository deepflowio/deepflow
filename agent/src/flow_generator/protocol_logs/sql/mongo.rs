use serde::Serialize;

use super::super::{consts::*, value_is_default, AppProtoHead, LogMessageType};

use crate::common::flow::L7PerfStats;
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
            pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response},
            L7ResponseStatus,
        },
        Error, Result,
    },
};

#[derive(Serialize, Debug, Default, Clone)]
pub struct MongoDBInfo {
    msg_type: LogMessageType,
    #[serde(skip)]
    is_tls: bool,

    // Server Greeting
    #[serde(rename = "message_length", skip_serializing_if = "value_is_default")]
    pub message_length: u32,
    #[serde(rename = "request_id", skip_serializing_if = "value_is_default")]
    pub request_id: u32,
    #[serde(rename = "response_to", skip_serializing_if = "value_is_default")]
    pub response_to: u32,
    #[serde(rename = "op_code", skip_serializing_if = "value_is_default")]
    pub op_code: u32,

    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub context: String,
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

impl MongoDBInfo {
    fn merge(&mut self, other: Self) {
        self.message_length = swap_endianess_u32(other.message_length);
        self.request_id = swap_endianess_u32(other.request_id);
        self.response_to = swap_endianess_u32(other.response_to);
        self.op_code = swap_endianess_u32(other.op_code);
        self.context = other.context;
    }
    pub fn get_op_str(&self) -> &'static str {
        match self.op_code {
            0x00000001 => "OP_REPLY",
            0x000003E8 => "DB_MSG",
            0x000007D1 => "OP_UPDATE",
            0x000007D2 => "OP_INSERT",
            0x000007D3 => "RESERVED",
            0x000007D4 => "OP_QUERY",
            0x000007D5 => "OP_GET_MORE",
            0x000007D6 => "OP_DELETE",
            0x000007D7 => "OP_KILL_CURSORS",
            0x000007DC => "OP_COMPRESSED",
            0x000007DD => "OP_MSG",
            _ => "OP_UNKNOWN",
        }
    }
}

impl From<MongoDBInfo> for L7ProtocolSendLog {
    fn from(f: MongoDBInfo) -> Self {
        let log = L7ProtocolSendLog {
            version: None,
            trace_info: None,
            req_len: None,
            resp_len: None,
            row_effect: f.op_code as u32,
            req: L7Request {
                req_type: String::from(f.get_op_str()),
                resource: f.context,
                ..Default::default()
            },
            resp: L7Response {
                status: L7ResponseStatus::Ok,
                ..Default::default()
            },
            ext_info: Some(ExtendedInfo {
                ..Default::default()
            }),
            ..Default::default()
        };
        return log;
    }
}

fn swap_endianess_u32(value: u32) -> u32 {
    ((value & 0xFF) << 24) |
    ((value & 0xFF00) << 8) |
    ((value >> 8) & 0xFF00) |
    ((value >> 24) & 0xFF)
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
        self.info.is_tls = param.is_tls();
        return true;
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<Vec<L7ProtocolInfo>> {
        self.info.is_tls = param.is_tls();
        if self.perf_stats.is_none() {
            self.perf_stats = Some(L7PerfStats::default())
        };
        if self.parse(
            payload,
            param.l4_protocol,
            param.direction,
            param.parse_config.and_then(|c| {
                for i in c.l7_log_dynamic.trace_types.iter() {
                    match i {
                        crate::config::handler::TraceType::Customize(c) => return Some(c.as_str()),
                        _ => continue,
                    }
                }
                None
            }),
        )? {
            // ignore greeting
            return Ok(vec![]);
        }
        self.info.cal_rrt(param, None).map(|rrt| {
            self.perf_stats.as_mut().unwrap().update_rrt(rrt);
        });
        Ok(vec![L7ProtocolInfo::MongoDBInfo(self.info.clone())])
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::MongoDB
    }

    fn reset(&mut self) {
        self.info = MongoDBInfo::default();
        self.perf_stats = self.perf_stats.take();
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

impl MongoDBLog{
    // return is_greeting?
    fn parse(
        &mut self,
        payload: &[u8],
        proto: IpProtocol,
        direction: PacketDirection,
        trace_id: Option<&str>,
    ) -> Result<bool> {
        if proto != IpProtocol::Tcp {
            return Err(Error::InvalidIpProtocol);
        }

        let mut header = MongoDBHeader::default();
        let offset = header.decode(payload);
        if offset < 0 {
            return Err(Error::MongoDBLogParseFailed);
        }
        let offset = offset as usize;
        let msg_type = header
            .check(direction, offset, payload)
            .ok_or(Error::MongoDBLogParseFailed)?;

        match msg_type {
            LogMessageType::Request => self.request(&payload[offset..], trace_id)?,
            LogMessageType::Response => self.response(&payload[offset..])?,
            LogMessageType::Other => {
                self.greeting(&payload[offset..])?;
                return Ok(true);
            }
            _ => return Err(Error::MongoDBLogParseFailed),
        };
        self.info.msg_type = msg_type;

        Ok(false)
    }
}

pub struct MongoDBHeader {
    length: u32,
    request_id: u32,
    response_to: u32,
    op_code: u32,
}