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

use serde::Serialize;

use super::super::{value_is_default, LogMessageType};
use crate::config::handler::LogParserConfig;
use crate::flow_generator::protocol_logs::{set_captured_byte, L7ResponseStatus};
use crate::flow_generator::Error;
use crate::{
    common::{
        flow::{L7PerfStats, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, ParseParam},
    },
    flow_generator::{
        protocol_logs::pb_adapter::{L7ProtocolSendLog, L7Request, L7Response},
        AppProtoHead, Result,
    },
};
use l7::oracle::{OracleParseConfig, OracleParser};
use public::l7_protocol::L7Protocol;

#[derive(Serialize, Debug, Default, Clone, PartialEq)]
pub struct OracleInfo {
    pub msg_type: LogMessageType,
    #[serde(skip)]
    pub is_tls: bool,

    // req
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub sql: String,
    #[serde(rename = "request_type")]
    pub data_id: u8,
    pub call_id: u8,

    // response
    pub ret_code: u16,
    #[serde(rename = "sql_affected_rows", skip_serializing_if = "value_is_default")]
    pub affected_rows: Option<u32>,
    #[serde(
        rename = "response_execption",
        skip_serializing_if = "value_is_default"
    )]
    pub error_message: String,
    #[serde(rename = "response_status")]
    pub status: L7ResponseStatus,

    captured_request_byte: u32,
    captured_response_byte: u32,

    pub rrt: u64,

    #[serde(skip)]
    is_on_blacklist: bool,
}
impl OracleInfo {
    pub fn merge(&mut self, other: &mut Self) {
        self.affected_rows = other.affected_rows;
        self.ret_code = other.ret_code;
        std::mem::swap(&mut self.error_message, &mut other.error_message);
        self.status = other.status;
        self.captured_response_byte = other.captured_response_byte;
        if other.is_on_blacklist {
            self.is_on_blacklist = other.is_on_blacklist;
        }
    }

    fn get_req_type(&self) -> String {
        const DATA_ID_USER_OCI_FUNC: u8 = 0x03;
        const DATA_ID_PIGGY_BACK_FUNC: u8 = 0x11;

        const CALL_ID_CURSOR_CLOSE_ALL: u8 = 0x69;
        const CALL_ID_SWITCHING_PIGGYBACK: u8 = 0x6b;
        const CALL_ID_BUNDLED_EXE_ALL: u8 = 0x5e;

        match (self.data_id, self.call_id) {
            (DATA_ID_PIGGY_BACK_FUNC, CALL_ID_CURSOR_CLOSE_ALL)
            | (DATA_ID_PIGGY_BACK_FUNC, CALL_ID_SWITCHING_PIGGYBACK) => {
                "PIGGY_BACK_FUNCTION_FOLLOW".to_string()
            }
            (DATA_ID_USER_OCI_FUNC, CALL_ID_BUNDLED_EXE_ALL) => "USER_OCI_FUNCTIONS".to_string(),
            _ => "".to_string(),
        }
    }

    fn set_is_on_blacklist(&mut self, config: &LogParserConfig) {
        if let Some(t) = config.l7_log_blacklist_trie.get(&L7Protocol::Oracle) {
            self.is_on_blacklist = t.request_resource.is_on_blacklist(&self.sql)
                || t.request_type.is_on_blacklist(&self.get_req_type());
        }
    }
}

impl L7ProtocolInfoInterface for OracleInfo {
    fn session_id(&self) -> Option<u32> {
        None
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::OracleInfo(other) = other {
            self.merge(other);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::Oracle,
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn is_tls(&self) -> bool {
        self.is_tls
    }

    fn get_request_resource_length(&self) -> usize {
        self.sql.len()
    }

    fn is_on_blacklist(&self) -> bool {
        self.is_on_blacklist
    }
}

impl From<OracleInfo> for L7ProtocolSendLog {
    fn from(f: OracleInfo) -> Self {
        let log = L7ProtocolSendLog {
            captured_request_byte: f.captured_request_byte,
            captured_response_byte: f.captured_response_byte,
            row_effect: f.affected_rows.unwrap_or_default(),
            req: L7Request {
                req_type: f.get_req_type(),
                resource: f.sql,
                ..Default::default()
            },
            resp: L7Response {
                status: f.status,
                code: Some(f.ret_code.into()),
                exception: f.error_message,
                ..Default::default()
            },
            ..Default::default()
        };
        return log;
    }
}

#[derive(Default)]
pub struct OracleLog {
    perf_stats: Option<L7PerfStats>,
    parser: OracleParser,
    last_is_on_blacklist: bool,
}

impl L7ProtocolParserInterface for OracleLog {
    fn check_payload(&mut self, payload: &[u8], _: &ParseParam) -> bool {
        self.parser.check_payload(payload)
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        if !self.parser.parse_payload(
            payload,
            param.direction == PacketDirection::ClientToServer,
            &OracleParseConfig {
                is_be: param.oracle_parse_conf.is_be,
                int_compress: param.oracle_parse_conf.int_compress,
                resp_0x04_extra_byte: param.oracle_parse_conf.resp_0x04_extra_byte,
            },
        ) {
            return Err(Error::L7ProtocolUnknown);
        };

        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };

        let mut log_info = OracleInfo {
            msg_type: param.direction.into(),
            is_tls: false,
            sql: self.parser.sql.clone(),
            data_id: self.parser.data_id,
            call_id: self.parser.call_id,
            ret_code: self.parser.ret_code,
            affected_rows: self.parser.affected_rows,
            error_message: self.parser.error_message.clone(),
            status: match self.parser.ret_code {
                0 => L7ResponseStatus::Ok,
                // TODO 错误码需要参考 https://docs.oracle.com/cd/E11882_01/server.112/e17766/e29250.htm 目前简单处理都认为是客户端错误
                _ => L7ResponseStatus::ClientError,
            },
            rrt: 0,
            captured_request_byte: 0,
            captured_response_byte: 0,
            is_on_blacklist: false,
        };
        set_captured_byte!(log_info, param);

        if let Some(config) = param.parse_config {
            log_info.set_is_on_blacklist(config);
        }
        if !log_info.is_on_blacklist && !self.last_is_on_blacklist {
            match param.direction {
                PacketDirection::ClientToServer => self.perf_stats.as_mut().map(|p| p.inc_req()),
                PacketDirection::ServerToClient => self.perf_stats.as_mut().map(|p| p.inc_resp()),
            };
            match log_info.status {
                L7ResponseStatus::ServerError => {
                    self.perf_stats.as_mut().map(|p| p.inc_resp_err());
                }
                L7ResponseStatus::ClientError => {
                    self.perf_stats.as_mut().map(|p| p.inc_req_err());
                }
                _ => {}
            }
            log_info.cal_rrt(param).map(|rrt| {
                log_info.rrt = rrt;
                self.perf_stats.as_mut().map(|p| p.update_rrt(log_info.rrt));
            });
        }
        self.last_is_on_blacklist = log_info.is_on_blacklist;
        Ok(L7ParseResult::Single(L7ProtocolInfo::OracleInfo(log_info)))
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Oracle
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }
}
