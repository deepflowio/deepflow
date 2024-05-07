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

mod comment_parser;

use std::str;

use log::{debug, trace};
use serde::Serialize;

use super::super::{consts::*, value_is_default, AppProtoHead, L7ResponseStatus, LogMessageType};
use super::sql_check::{is_mysql, is_valid_sql, trim_head_comment_and_get_first_word};
use super::sql_obfuscate::attempt_obfuscation;
use super::ObfuscateCache;

use crate::flow_generator::protocol_logs::set_captured_byte;
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
        error::{Error, Result},
        protocol_logs::pb_adapter::{
            ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response, TraceInfo,
        },
    },
    utils::bytes,
};
use public::bytes::read_u32_le;

const SERVER_STATUS_CODE_MIN: u16 = 1000;
const CLIENT_STATUS_CODE_MIN: u16 = 2000;
const CLIENT_STATUS_CODE_MAX: u16 = 2999;

#[derive(Serialize, Debug, Default, Clone)]
pub struct MysqlInfo {
    msg_type: LogMessageType,
    #[serde(skip)]
    is_tls: bool,

    // Server Greeting
    #[serde(rename = "version", skip_serializing_if = "value_is_default")]
    pub protocol_version: u8,
    #[serde(skip)]
    pub server_version: String,
    #[serde(skip)]
    pub server_thread_id: u32,
    // request
    #[serde(rename = "request_type")]
    pub command: u8,
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub context: String,
    // response
    pub response_code: u8,
    #[serde(skip)]
    pub error_code: Option<i32>,
    #[serde(rename = "sql_affected_rows", skip_serializing_if = "value_is_default")]
    pub affected_rows: u64,
    #[serde(
        rename = "response_execption",
        skip_serializing_if = "value_is_default"
    )]
    pub error_message: String,
    #[serde(rename = "response_status")]
    pub status: L7ResponseStatus,

    rrt: u64,
    // This field is extracted in the following message:
    // 1. Response message corresponding to COM_STMT_PREPARE request
    // 2. COM_STMT_EXECUTE request message
    statement_id: u32,

    captured_request_byte: u32,
    captured_response_byte: u32,

    trace_id: Option<String>,
    span_id: Option<String>,
}

impl L7ProtocolInfoInterface for MysqlInfo {
    fn session_id(&self) -> Option<u32> {
        None
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::MysqlInfo(other) = other {
            self.merge(other);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::MySQL,
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn is_tls(&self) -> bool {
        self.is_tls
    }

    fn get_request_resource_length(&self) -> usize {
        self.context.len()
    }
}

impl MysqlInfo {
    pub fn merge(&mut self, other: &mut Self) {
        if self.protocol_version == 0 {
            self.protocol_version = other.protocol_version
        }
        match other.msg_type {
            LogMessageType::Request => {
                self.command = other.command;
                std::mem::swap(&mut self.context, &mut other.context);
                self.captured_request_byte = other.captured_request_byte;
            }
            LogMessageType::Response => {
                self.response_code = other.response_code;
                self.affected_rows = other.affected_rows;
                std::mem::swap(&mut self.error_message, &mut other.error_message);
                self.status = other.status;
                if self.error_code.is_none() {
                    self.error_code = other.error_code;
                }
                if self.command == COM_STMT_PREPARE && other.statement_id > 0 {
                    self.statement_id = other.statement_id;
                } else {
                    self.statement_id = 0;
                }
                self.captured_response_byte = other.captured_response_byte;
            }
            _ => {}
        }
    }

    pub fn get_command_str(&self) -> &'static str {
        let command = [
            "", // command 0 is resp, ignore
            "COM_QUIT",
            "COM_INIT_DB",
            "COM_QUERY",
            "COM_FIELD_LIST",
            "COM_CREATE_DB",
            "COM_DROP_DB",
            "COM_REFRESH",
            "COM_SHUTDOWN",
            "COM_STATISTICS",
            "COM_PROCESS_INFO",
            "COM_CONNECT",
            "COM_PROCESS_KILL",
            "COM_DEBUG",
            "COM_PING",
            "COM_TIME",
            "COM_DELAYED_INSERT",
            "COM_CHANGE_USER",
            "COM_BINLOG_DUMP",
            "COM_TABLE_DUMP",
            "COM_CONNECT_OUT",
            "COM_REGISTER_SLAVE",
            "COM_STMT_PREPARE",
            "COM_STMT_EXECUTE",
            "COM_STMT_SEND_LONG_DATA",
            "COM_STMT_CLOSE",
            "COM_STMT_RESET",
            "COM_SET_OPTION",
            "COM_STMT_FETCH",
            "COM_DAEMON",
            "COM_BINLOG_DUMP_GTID",
            "COM_RESET_CONNECTION",
        ];
        match self.command {
            0x00..=0x1f => command[self.command as usize],
            _ => "",
        }
    }

    fn request_string(
        &mut self,
        config: Option<&LogParserConfig>,
        payload: &[u8],
        obfuscate_cache: &Option<ObfuscateCache>,
    ) -> Result<()> {
        let payload = mysql_string(payload);
        if (self.command == COM_QUERY || self.command == COM_STMT_PREPARE) && !is_mysql(payload) {
            return Err(Error::MysqlLogParseFailed);
        };
        let context = match attempt_obfuscation(obfuscate_cache, payload) {
            Some(mut m) => {
                let valid_len = match str::from_utf8(&m) {
                    Ok(_) => m.len(),
                    Err(e) => e.valid_up_to(),
                };
                m.truncate(valid_len);
                unsafe {
                    // SAFTY: str in m is checked to be valid utf8 up to `valid_len`
                    String::from_utf8_unchecked(m)
                }
            }
            _ => String::from_utf8_lossy(payload).to_string(),
        };
        if let Some(c) = config {
            self.extract_trace_and_span_id(&c.l7_log_dynamic, context.as_str());
        }
        self.context = context;
        Ok(())
    }

    // extra trace id from comment like # TraceID: xxxxxxxxxxxxxxx
    fn extract_trace_and_span_id(&mut self, config: &L7LogDynamicConfig, sql: &str) {
        if config.trace_types.is_empty() && config.span_types.is_empty() {
            return;
        }
        debug!("extract id from sql {}", sql);
        'outer: for comment in comment_parser::MysqlCommentParserIter::new(sql) {
            trace!("comment={}", comment);
            let mut segs = comment.split(":");
            let mut value = segs.next();
            loop {
                let key = value;
                value = segs.next();
                if value.is_none() {
                    break;
                };

                // take last word before ':' and first word after it
                let Some(rk) = key.as_ref().unwrap().trim().split_whitespace().last() else {
                    continue;
                };
                let Some(rv) = value.as_ref().unwrap().trim().split_whitespace().next() else {
                    continue;
                };
                let rk = rk.trim();
                let rv = rv.trim();
                trace!("key={} value={}", rk, rv);
                for tt in config.trace_types.iter() {
                    if tt.check(rk) {
                        self.trace_id = tt.decode_trace_id(rv).map(|s| s.to_string());
                        break;
                    }
                }
                for st in config.span_types.iter() {
                    if st.check(rk) {
                        self.span_id = st.decode_span_id(rv).map(|s| s.to_string());
                        break;
                    }
                }
                if self.trace_id.is_some() && config.span_types.is_empty()
                    || self.span_id.is_some() && config.trace_types.is_empty()
                    || self.trace_id.is_some() && self.span_id.is_some()
                {
                    break 'outer;
                }
            }
        }
        debug!(
            "extracted trace_id={:?} span_id={:?}",
            self.trace_id, self.span_id
        );
    }

    fn statement_id(&mut self, payload: &[u8]) {
        if payload.len() >= STATEMENT_ID_LEN {
            self.statement_id = read_u32_le(payload)
        }
    }
}

impl From<MysqlInfo> for L7ProtocolSendLog {
    fn from(f: MysqlInfo) -> Self {
        let flags = if f.is_tls {
            EbpfFlags::TLS.bits()
        } else {
            EbpfFlags::NONE.bits()
        };
        let log = L7ProtocolSendLog {
            captured_request_byte: f.captured_request_byte,
            captured_response_byte: f.captured_response_byte,
            version: if f.protocol_version == 0 {
                None
            } else {
                Some(f.protocol_version.to_string())
            },

            row_effect: if f.command == COM_QUERY {
                trim_head_comment_and_get_first_word(f.context.as_bytes(), 8)
                    .map(|first| {
                        if is_valid_sql(first, &["INSERT", "UPDATE", "DELETE"]) {
                            f.affected_rows as u32
                        } else {
                            0
                        }
                    })
                    .unwrap_or_default()
            } else {
                0
            },
            req: L7Request {
                req_type: String::from(f.get_command_str()),
                resource: f.context,
                ..Default::default()
            },
            resp: L7Response {
                status: f.status,
                code: f.error_code,
                exception: f.error_message,
                ..Default::default()
            },
            ext_info: Some(ExtendedInfo {
                request_id: f.statement_id.into(),
                ..Default::default()
            }),
            trace_info: if let (Some(tid), Some(sid)) = (f.trace_id, f.span_id) {
                Some(TraceInfo {
                    trace_id: Some(tid),
                    span_id: Some(sid),
                    ..Default::default()
                })
            } else {
                None
            },
            flags,
            ..Default::default()
        };
        return log;
    }
}

#[derive(Default)]
pub struct MysqlLog {
    pub protocol_version: u8,
    perf_stats: Option<L7PerfStats>,
    obfuscate_cache: Option<ObfuscateCache>,

    // This field is extracted in the COM_STMT_PREPARE request and calculate based on SQL statements
    parameter_counter: u32,
    has_request: bool,
}

impl L7ProtocolParserInterface for MysqlLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol() {
            return false;
        }
        Self::check(payload, param)
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        let mut info = MysqlInfo::default();
        info.protocol_version = self.protocol_version;
        info.is_tls = param.is_tls();
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };
        if self.parse(
            param.parse_config,
            payload,
            param.l4_protocol,
            param.direction,
            &mut info,
        )? {
            // ignore greeting
            return Ok(L7ParseResult::None);
        }
        set_captured_byte!(info, param);
        if info.msg_type != LogMessageType::Session {
            info.cal_rrt(param, None).map(|rrt| {
                info.rrt = rrt;
                self.perf_stats.as_mut().map(|p| p.update_rrt(rrt));
            });
        }
        if param.parse_log {
            Ok(L7ParseResult::Single(L7ProtocolInfo::MysqlInfo(info)))
        } else {
            Ok(L7ParseResult::None)
        }
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::MySQL
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }

    fn set_obfuscate_cache(&mut self, obfuscate_cache: Option<ObfuscateCache>) {
        self.obfuscate_cache = obfuscate_cache;
    }
}

fn mysql_string(payload: &[u8]) -> &[u8] {
    if payload.len() > 2 && payload[0] == 0 && payload[1] == 1 {
        // MYSQL 8.0.26返回字符串前有0x0、0x1，MYSQL 8.0.21版本没有这个问题
        // https://gitlab.yunshan.net/platform/trident/-/merge_requests/2592#note_401425
        &payload[2..]
    } else {
        payload
    }
}

#[derive(PartialEq)]
enum SqlState {
    None,
    Equal,
    Less,
    Greater,
    In1,
    In2,
    In3,
    Values1,
    Values2,
    Values3,
    Values4,
    Values5,
    Values6,
    Values7,
    Like1,
    Like2,
    Like3,
    Like4,
    ValuesPause,
}

impl MysqlLog {
    fn reset_parameter_counter(&mut self) {
        self.parameter_counter = 0;
    }

    fn set_parameter_counter(&mut self, sql: &[u8]) {
        let mut counter = 0;
        let mut state = SqlState::None;
        for byte in sql.iter() {
            match *byte {
                b'=' => state = SqlState::Equal,
                b'?' if state == SqlState::Equal => {
                    counter += 1;
                    state = SqlState::None;
                }
                b'>' if state == SqlState::None => state = SqlState::Greater,
                b'?' if state == SqlState::Greater => {
                    counter += 1;
                    state = SqlState::None;
                }
                _ if state == SqlState::Greater => state = SqlState::None,
                b'<' if state == SqlState::None => state = SqlState::Less,
                b'>' if state == SqlState::Less => state = SqlState::Greater,
                b'?' if state == SqlState::Less => {
                    counter += 1;
                    state = SqlState::None;
                }
                _ if state == SqlState::Less => state = SqlState::None,
                b'I' if state == SqlState::None => state = SqlState::In1,
                b'N' if state == SqlState::In1 => state = SqlState::In2,
                b'(' if state == SqlState::In2 => state = SqlState::In3,
                b',' if state == SqlState::In3 => {}
                b'?' if state == SqlState::In3 => counter += 1,
                b')' if state == SqlState::In3 => state = SqlState::None,
                b'V' if state == SqlState::None => state = SqlState::Values1,
                b'A' if state == SqlState::Values1 => state = SqlState::Values2,
                b'L' if state == SqlState::Values2 => state = SqlState::Values3,
                b'U' if state == SqlState::Values3 => state = SqlState::Values4,
                b'E' if state == SqlState::Values4 => state = SqlState::Values5,
                b'S' if state == SqlState::Values5 => state = SqlState::Values6,
                b' ' | b',' if state == SqlState::Values6 => {}
                b'(' if state == SqlState::Values6 => state = SqlState::Values7,
                b'?' if state == SqlState::Values7 => {
                    counter += 1;
                    state = SqlState::ValuesPause;
                }
                _ if state == SqlState::Values7 => {}
                b')' if state == SqlState::ValuesPause => state = SqlState::Values6,
                b'?' if state == SqlState::ValuesPause => {}
                b',' if state == SqlState::ValuesPause => state = SqlState::Values7,
                b'L' if state == SqlState::None => state = SqlState::Like1,
                b'I' if state == SqlState::Like1 => state = SqlState::Like2,
                b'K' if state == SqlState::Like2 => state = SqlState::Like3,
                b'E' if state == SqlState::Like3 => state = SqlState::Like4,
                b'?' if state == SqlState::Like4 => {
                    counter += 1;
                    state = SqlState::None;
                }
                b' ' => {}
                _ => state = SqlState::None,
            }
        }

        self.parameter_counter = counter;
    }

    fn get_parameters(&mut self, payload: &[u8], info: &mut MysqlInfo) {
        if self.parameter_counter == 0 {
            return;
        }
        let mut params = vec![];
        let mut offset = 0;
        // TODO: Only support first call or rebound.
        for byte in payload {
            offset += 1;
            if *byte == 0x01 {
                break;
            }
        }
        for _ in 0..self.parameter_counter as usize {
            if offset + PARAMETER_TYPE_LEN > payload.len() {
                return;
            }
            params.push((FieldType::from(payload[offset]), payload[offset + 1]));
            offset += PARAMETER_TYPE_LEN;
        }

        let mut context = String::new();
        for (i, (field_type, _)) in params.iter().enumerate() {
            if offset > payload.len() {
                break;
            }

            if let Some(length) = field_type.decode(&payload[offset..], &mut context) {
                if i != params.len() - 1 {
                    context.push_str(" , ");
                }
                offset += length;
            }
        }

        info.context = context;
    }

    fn greeting(&mut self, payload: &[u8]) -> Result<()> {
        let mut remain = payload.len();
        if remain < PROTOCOL_VERSION_LEN {
            return Err(Error::MysqlLogParseFailed);
        }
        self.protocol_version = payload[PROTOCOL_VERSION_OFFSET];
        remain -= PROTOCOL_VERSION_LEN;
        let server_version_pos = payload[SERVER_VERSION_OFFSET..]
            .iter()
            .position(|&x| x == SERVER_VERSION_EOF)
            .unwrap_or_default();
        if server_version_pos <= 0 {
            return Err(Error::MysqlLogParseFailed);
        }
        remain -= server_version_pos as usize;
        if remain < THREAD_ID_LEN + 1 {
            return Err(Error::MysqlLogParseFailed);
        }
        Ok(())
    }

    fn request(
        &mut self,
        config: Option<&LogParserConfig>,
        payload: &[u8],
        info: &mut MysqlInfo,
    ) -> Result<LogMessageType> {
        if payload.len() < COMMAND_LEN {
            return Err(Error::MysqlLogParseFailed);
        }
        info.command = payload[COMMAND_OFFSET];
        let mut msg_type = LogMessageType::Request;
        match info.command {
            COM_QUIT | COM_STMT_CLOSE => msg_type = LogMessageType::Session,
            COM_FIELD_LIST | COM_STMT_FETCH => (),
            COM_INIT_DB | COM_QUERY => {
                info.request_string(
                    config,
                    &payload[COMMAND_OFFSET + COMMAND_LEN..],
                    &self.obfuscate_cache,
                )?;
            }
            COM_STMT_PREPARE => {
                info.request_string(
                    config,
                    &payload[COMMAND_OFFSET + COMMAND_LEN..],
                    &self.obfuscate_cache,
                )?;
                if let Some(config) = config {
                    if config
                        .obfuscate_enabled_protocols
                        .is_disabled(L7Protocol::MySQL)
                    {
                        self.set_parameter_counter(info.context.as_bytes());
                    }
                }
            }
            COM_STMT_EXECUTE => {
                info.statement_id(&payload[STATEMENT_ID_OFFSET..]);
                if payload.len() > EXECUTE_STATEMENT_PARAMS_OFFSET {
                    self.get_parameters(&payload[EXECUTE_STATEMENT_PARAMS_OFFSET..], info);
                }
                self.reset_parameter_counter();
            }
            COM_PING => {}
            _ => return Err(Error::MysqlLogParseFailed),
        }
        self.perf_stats.as_mut().map(|p| p.inc_req());
        Ok(msg_type)
    }

    fn decode_compress_int(payload: &[u8]) -> u64 {
        let remain = payload.len();
        if remain == 0 {
            return 0;
        }
        let value = payload[0];
        match value {
            INT_FLAGS_2 if remain > INT_BASE_LEN + 2 => {
                bytes::read_u16_le(&payload[INT_BASE_LEN..]) as u64
            }
            INT_FLAGS_3 if remain > INT_BASE_LEN + 3 => {
                bytes::read_u16_le(&payload[INT_BASE_LEN..]) as u64
                    | ((payload[INT_BASE_LEN + 2] as u64) << 16)
            }
            INT_FLAGS_8 if remain > INT_BASE_LEN + 8 => {
                bytes::read_u64_le(&payload[INT_BASE_LEN..])
            }
            _ => value as u64,
        }
    }

    fn set_status(&mut self, status_code: u16, info: &mut MysqlInfo) {
        if status_code != 0 {
            if status_code >= CLIENT_STATUS_CODE_MIN && status_code <= CLIENT_STATUS_CODE_MAX {
                info.status = L7ResponseStatus::ClientError;
            } else {
                info.status = L7ResponseStatus::ServerError;
            }
        } else {
            info.status = L7ResponseStatus::Ok;
        }
    }

    fn response(&mut self, payload: &[u8], info: &mut MysqlInfo) -> Result<()> {
        let mut remain = payload.len();
        if remain < RESPONSE_CODE_LEN {
            return Err(Error::MysqlLogParseFailed);
        }
        info.response_code = payload[RESPONSE_CODE_OFFSET];
        remain -= RESPONSE_CODE_LEN;
        match info.response_code {
            MYSQL_RESPONSE_CODE_ERR => {
                if remain > ERROR_CODE_LEN {
                    let code = bytes::read_u16_le(&payload[ERROR_CODE_OFFSET..]);
                    if code < SERVER_STATUS_CODE_MIN || code > CLIENT_STATUS_CODE_MAX {
                        return Err(Error::MysqlLogParseFailed);
                    }
                    info.error_code = Some(code as i32);
                    self.set_status(code, info);
                    remain -= ERROR_CODE_LEN;
                }
                let error_message_offset =
                    if remain > SQL_STATE_LEN && payload[SQL_STATE_OFFSET] == SQL_STATE_MARKER {
                        SQL_STATE_OFFSET + SQL_STATE_LEN
                    } else {
                        SQL_STATE_OFFSET
                    };
                if error_message_offset < payload.len() {
                    let context = mysql_string(&payload[error_message_offset..]);
                    if !context.is_ascii() {
                        return Err(Error::MysqlLogParseFailed);
                    }
                    info.error_message = String::from_utf8_lossy(context).into_owned();
                }
                self.perf_stats.as_mut().map(|p| p.inc_resp_err());
            }
            MYSQL_RESPONSE_CODE_OK => {
                info.status = L7ResponseStatus::Ok;
                info.affected_rows =
                    MysqlLog::decode_compress_int(&payload[AFFECTED_ROWS_OFFSET..]);
                info.statement_id(&payload[STATEMENT_ID_OFFSET..]);
            }
            _ => (),
        }
        self.perf_stats.as_mut().map(|p| p.inc_resp());
        Ok(())
    }

    fn check(payload: &[u8], param: &ParseParam) -> bool {
        if param.l4_protocol != IpProtocol::TCP {
            return false;
        }

        let mut header = MysqlHeader::default();
        let offset = header.decode(payload);
        if offset < 0 {
            return false;
        }
        let offset = offset as usize;

        if header.number != 0 || offset + header.length as usize > payload.len() {
            return false;
        }

        let protocol_version_or_query_type = payload[offset];
        match protocol_version_or_query_type {
            COM_QUERY | COM_STMT_PREPARE => {
                let context = mysql_string(&payload[offset + 1..]);
                return context.is_ascii() && is_mysql(context);
            }
            _ => {}
        }
        false
    }

    // return is_greeting?
    fn parse(
        &mut self,
        config: Option<&LogParserConfig>,
        payload: &[u8],
        proto: IpProtocol,
        direction: PacketDirection,
        info: &mut MysqlInfo,
    ) -> Result<bool> {
        if proto != IpProtocol::TCP {
            return Err(Error::InvalidIpProtocol);
        }

        let mut header = MysqlHeader::default();
        let offset = header.decode(payload);
        if offset < 0 {
            return Err(Error::MysqlLogParseFailed);
        }
        let offset = offset as usize;
        let mut msg_type = header
            .check(direction, offset, payload)
            .ok_or(Error::MysqlLogParseFailed)?;

        match msg_type {
            LogMessageType::Request => {
                msg_type = self.request(config, &payload[offset..], info)?;
                if msg_type == LogMessageType::Request {
                    self.has_request = true;
                }
            }
            LogMessageType::Response if self.has_request => {
                self.response(&payload[offset..], info)?;
                self.has_request = false;
            }
            LogMessageType::Other => {
                self.greeting(&payload[offset..])?;
                return Ok(true);
            }
            _ => return Err(Error::MysqlLogParseFailed),
        };
        info.msg_type = msg_type;

        Ok(false)
    }
}

#[derive(Debug, Default)]
pub struct MysqlHeader {
    length: u32,
    number: u8,
}

impl MysqlHeader {
    pub fn decode(&mut self, payload: &[u8]) -> isize {
        if payload.len() < 5 {
            return -1;
        }
        let len = bytes::read_u32_le(payload) & 0xffffff;
        if payload[HEADER_LEN + RESPONSE_CODE_OFFSET] == MYSQL_RESPONSE_CODE_OK
            || payload[HEADER_LEN + RESPONSE_CODE_OFFSET] == MYSQL_RESPONSE_CODE_ERR
            || payload[HEADER_LEN + RESPONSE_CODE_OFFSET] == MYSQL_RESPONSE_CODE_EOF
            || payload[NUMBER_OFFSET] == 0
        {
            self.length = len;
            self.number = payload[NUMBER_OFFSET];
            return HEADER_LEN as isize;
        }
        let offset = len as usize + HEADER_LEN;
        if offset >= payload.len() {
            return 0;
        }
        let offset = offset as isize;
        offset + self.decode(&payload[offset as usize..])
    }

    pub fn check(
        &self,
        direction: PacketDirection,
        offset: usize,
        payload: &[u8],
    ) -> Option<LogMessageType> {
        if offset >= payload.len() || self.length == 0 {
            return None;
        }

        match direction {
            // greeting
            PacketDirection::ServerToClient if self.number == 0 => {
                let payload = &payload[offset..];
                if payload.len() < PROTOCOL_VERSION_LEN {
                    return None;
                }
                let protocol_version = payload[PROTOCOL_VERSION_OFFSET];
                let index = payload[SERVER_VERSION_OFFSET..]
                    .iter()
                    .position(|&x| x == SERVER_VERSION_EOF)?;
                if index != 0 && protocol_version == PROTOCOL_VERSION {
                    Some(LogMessageType::Other)
                } else {
                    None
                }
            }
            PacketDirection::ServerToClient => Some(LogMessageType::Response),
            PacketDirection::ClientToServer if self.number == 0 => Some(LogMessageType::Request),
            _ => None,
        }
    }
}

// test log parse
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

    const FILE_DIR: &str = "resources/test/flow_generator/mysql";

    fn run(name: &str) -> String {
        let pcap_file = Path::new(FILE_DIR).join(name);
        let capture = Capture::load_pcap(pcap_file, Some(1400));
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut mysql = MysqlLog::default();
        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
        let mut previous_command = 0u8;
        let mut log_config = LogParserConfig::default();
        log_config
            .obfuscate_enabled_protocols
            .set_enabled(L7Protocol::MySQL);
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
            let is_mysql = mysql.check_payload(
                payload,
                &ParseParam::new(
                    packet as &MetaPacket,
                    log_cache.clone(),
                    Default::default(),
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    Default::default(),
                    true,
                    true,
                ),
            );

            let mut param = ParseParam::new(
                &*packet,
                log_cache.clone(),
                Default::default(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Default::default(),
                true,
                true,
            );
            param.parse_config = Some(&log_config);
            param.set_captured_byte(payload.len());

            let info = mysql.parse_payload(payload, &param);

            if let Ok(info) = info {
                if info.is_none() {
                    let mut i = MysqlInfo::default();
                    i.protocol_version = mysql.protocol_version;
                    output.push_str(&format!("{:?} is_mysql: {}\n", i, is_mysql));
                    previous_command = 0;
                    continue;
                }
                match info.unwrap_single() {
                    L7ProtocolInfo::MysqlInfo(mut i) => {
                        if i.app_proto_head().unwrap().msg_type == LogMessageType::Request {
                            previous_command = i.command;
                        } else {
                            if previous_command != COM_QUERY {
                                i.affected_rows = 0;
                            }
                            previous_command = 0;
                        }

                        i.rrt = 0;
                        output.push_str(&format!("{:?} is_mysql: {}\n", i, is_mysql));
                    }
                    _ => unreachable!(),
                }
            } else {
                let mut i = MysqlInfo::default();
                i.protocol_version = mysql.protocol_version;
                output.push_str(&format!("{:?} is_mysql: {}\n", i, is_mysql));
            }
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
            ("mysql-exec.pcap", "mysql-exec.result"),
            ("mysql-statement-id.pcap", "mysql-statement-id.result"),
            ("mysql-statement.pcap", "mysql-statement.result"),
            ("mysql.pcap", "mysql.result"),
            ("mysql-error.pcap", "mysql-error.result"),
            ("mysql-table-desc.pcap", "mysql-table-desc.result"),
            ("mysql-table-insert.pcap", "mysql-table-insert.result"),
            ("mysql-table-delete.pcap", "mysql-table-delete.result"),
            ("mysql-table-update.pcap", "mysql-table-update.result"),
            ("mysql-table-select.pcap", "mysql-table-select.result"),
            ("mysql-table-create.pcap", "mysql-table-create.result"),
            ("mysql-table-destroy.pcap", "mysql-table-destroy.result"),
            ("mysql-table-alter.pcap", "mysql-table-alter.result"),
            ("mysql-database.pcap", "mysql-database.result"),
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
    fn check_perf() {
        let expecteds = vec![
            (
                "mysql.pcap",
                L7PerfStats {
                    request_count: 6,
                    response_count: 5,
                    err_client_count: 0,
                    err_server_count: 0,
                    err_timeout: 0,
                    rrt_count: 5,
                    rrt_sum: 373,
                    rrt_max: 123,
                    ..Default::default()
                },
            ),
            (
                "mysql-error.pcap",
                L7PerfStats {
                    request_count: 4,
                    response_count: 3,
                    err_client_count: 0,
                    err_server_count: 1,
                    err_timeout: 0,
                    rrt_count: 3,
                    rrt_sum: 226,
                    rrt_max: 146,
                    ..Default::default()
                },
            ),
            (
                "171-mysql.pcap",
                L7PerfStats {
                    request_count: 390,
                    response_count: 390,
                    err_client_count: 0,
                    err_server_count: 0,
                    err_timeout: 0,
                    rrt_count: 390,
                    rrt_sum: 127090,
                    rrt_max: 5355,
                    ..Default::default()
                },
            ),
        ];

        for item in expecteds.iter() {
            assert_eq!(item.1, run_perf(item.0), "pcap {} check failed", item.0);
        }
    }

    fn run_perf(pcap: &str) -> L7PerfStats {
        let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));
        let mut mysql = MysqlLog::default();

        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(pcap), Some(1400));
        let mut packets = capture.as_meta_packets();

        let first_src_mac = packets[0].lookup_key.src_mac;
        for packet in packets.iter_mut() {
            if packet.lookup_key.src_mac == first_src_mac {
                packet.lookup_key.direction = PacketDirection::ClientToServer;
            } else {
                packet.lookup_key.direction = PacketDirection::ServerToClient;
            }
            if packet.get_l4_payload().is_some() {
                let param = &ParseParam::new(
                    &*packet,
                    rrt_cache.clone(),
                    Default::default(),
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    Default::default(),
                    true,
                    true,
                );
                let _ = mysql.parse_payload(packet.get_l4_payload().unwrap(), param);
            }
        }
        mysql.perf_stats.unwrap()
    }

    #[test]
    fn comment_extractor() {
        flexi_logger::Logger::try_with_env()
            .unwrap()
            .start()
            .unwrap();
        let testcases = vec![
        (
            "/* traceparent: 00-trace_id-span_id-01 */ SELECT * FROM table",
            Some("trace_id"),
            Some("span_id"),
        ),
        (
            "/* traceparent: traceparent   \t : 00-trace_id-span_id-01 */ SELECT * FROM table",
            Some("trace_id"),
            Some("span_id"),
        ),
        (
            " SELECT * FROM table # traceparent: traceparent   \ttRaCeId \t: 00-trace_id-span_id-01: traceparent",
            Some("00-trace_id-span_id-01"),
            None,
        ),
        ];
        let mut info = MysqlInfo::default();
        let config = L7LogDynamicConfig::new(
            "".to_owned(),
            vec![],
            vec![
                TraceType::TraceParent,
                TraceType::Customize("TraceID".to_owned()),
            ],
            vec![TraceType::TraceParent],
            ExtraLogFields::default(),
        );
        for (input, tid, sid) in testcases {
            info.trace_id = None;
            info.span_id = None;
            info.extract_trace_and_span_id(&config, input);
            assert_eq!(info.trace_id.as_ref().map(|s| s.as_str()), tid);
            assert_eq!(info.span_id.as_ref().map(|s| s.as_str()), sid);
        }
    }

    #[test]
    fn test_set_parameter_counter() {
        let cases =
            vec![
            ("=?", 1),
            ("= ?", 1),
            ("<> ?", 0),
            ("<>?", 1),
            ("< ?", 0),
            (">?", 1),
            ("<?", 1),
            ("IN (?) ?", 1),
            ("IN (?,?,?)", 3),
            ("VALUES (?,?,?,?,?,??),(?,?,?,?,?,?,?)", 13),
            ("VALUES (?,?,?,?,?,?,?)", 7),
            ("VALUES (?,?,?,DEFAULT,?,?,?,?)", 7),
            ("VALUES (?,?,?),(DEFAULT,?,?,?,?)", 7),
            (
                "SELECT * FROM ` ? ` WHERE ` ? `=? ? BY ` ? `.` ? ` LIMIT ?",
                1,
            ),
            (
                "SELECT ` ? `,` ? `,` ? ` FROM ` ? ` WHERE (namespace =?) AND (` ? ` LIKE ?)",
                2,
            ),
            ("SELECT ` ? ` FROM ` ? ` WHERE domain =? AND content <> ?  BY ` ? `.` ? ` LIMIT ?", 1),
        ];
        for case in cases {
            let mut log = MysqlLog::default();
            log.set_parameter_counter(case.0.as_bytes());
            assert_eq!(
                log.parameter_counter, case.1,
                "Cases {:?} error, actual is {}",
                case, log.parameter_counter
            );
        }
    }

    #[test]
    fn test_parse_parameter() {
        fn parse_parameter(field_type: FieldType, payload: Vec<u8>) -> String {
            let mut output = String::new();
            field_type.decode(&payload, &mut output);
            output
        }

        let mut cases = vec![
            (FieldType::Long, vec![1, 0, 0, 0], "Long(1)"),
            (FieldType::Int24, vec![1, 0, 0, 0], "Int24(1)"),
            (FieldType::Short, vec![1, 0], "Short(1)"),
            (FieldType::Year, vec![1, 0], "Years(1)"),
            (FieldType::Tiny, vec![1], "Tiny(1)"),
            (
                FieldType::Double,
                vec![0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x24, 0x40],
                "Double(10.2)",
            ),
            (
                FieldType::Float,
                vec![0x33, 0x33, 0x23, 0x41],
                "Float(10.2)",
            ),
            (
                FieldType::Date,
                vec![
                    0x0b, 0xda, 0x07, 0x0a, 0x11, 0x13, 0x1b, 0x1e, 0x01, 00, 00, 00,
                ],
                "datetime 2010-10-17 19:27:30.000001",
            ),
            (
                FieldType::Datetime,
                vec![0x04, 0xda, 0x07, 0x0a, 0x11],
                "datetime 2010-10-17",
            ),
            (
                FieldType::Timestamp,
                vec![
                    0x0b, 0xda, 0x07, 0x0a, 0x11, 0x13, 0x1b, 0x1e, 0x01, 00, 00, 00,
                ],
                "datetime 2010-10-17 19:27:30.000001",
            ),
            (
                FieldType::Time,
                vec![
                    0x0c, 0x01, 0x78, 0x00, 0x00, 0x00, 0x13, 0x1b, 0x1e, 0x01, 0x00, 0x00, 0x00,
                ],
                "time -120d 19:27:30.000001",
            ),
            (
                FieldType::Time,
                vec![0x08, 0x01, 0x78, 0x00, 0x00, 0x00, 0x13, 0x1b, 0x1e],
                "time -120d 19:27:30",
            ),
            (FieldType::Time, vec![0x1], "time 0d 00:00:00.000000"),
        ];

        for (i, (field_type, payload, except)) in cases.drain(..).enumerate() {
            let actual = parse_parameter(field_type, payload);
            assert_eq!(
                actual,
                except.to_string(),
                "Cases {:3} field type {:?} error: except: {} but actual: {}.",
                i + 1,
                field_type,
                except,
                actual
            );
        }
    }
}
