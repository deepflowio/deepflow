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
use crate::flow_generator::{
    protocol_logs::{
        pb_adapter::{ExtendedInfo, KeyVal},
        set_captured_byte, swap_if, L7ResponseStatus,
    },
    Error,
};
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

use l7::oracle::{CallId, DataFlags, DataId, OracleParseConfig, OracleParser, TnsPacketType};
use public::l7_protocol::L7Protocol;

#[derive(Serialize, Debug, Default, Clone, PartialEq)]
pub struct OracleInfo {
    pub msg_type: LogMessageType,
    #[serde(skip)]
    pub is_tls: bool,

    #[serde(rename = "request_type", skip_serializing_if = "value_is_default")]
    pub packet_type: TnsPacketType,
    // req
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub sql: String,
    #[serde(skip)]
    pub req_data_flags: DataFlags,
    #[serde(skip)]
    pub req_data_id: Option<DataId>,
    #[serde(skip)]
    pub req_call_id: Option<CallId>,

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
    #[serde(skip)]
    pub resp_data_flags: DataFlags,
    #[serde(skip)]
    pub resp_data_id: Option<DataId>,

    captured_request_byte: u32,
    captured_response_byte: u32,

    pub rrt: u64,

    #[serde(skip)]
    is_on_blacklist: bool,
}
impl OracleInfo {
    pub fn merge(&mut self, other: &mut Self) {
        self.packet_type = other.packet_type;
        swap_if!(self, sql, is_empty, other);
        if other.req_data_flags.bits() > 0 {
            self.req_data_flags = other.req_data_flags;
        }
        swap_if!(self, req_data_id, is_none, other);
        swap_if!(self, req_call_id, is_none, other);
        if other.ret_code > 0 {
            self.ret_code = other.ret_code;
        }
        swap_if!(self, affected_rows, is_none, other);
        swap_if!(self, error_message, is_empty, other);
        if other.status != L7ResponseStatus::default() {
            self.status = other.status;
        }
        if other.resp_data_flags.bits() > 0 {
            self.resp_data_flags = other.resp_data_flags;
        }
        swap_if!(self, resp_data_id, is_none, other);
        self.captured_request_byte += other.captured_request_byte;
        self.captured_response_byte += other.captured_response_byte;
        if other.is_on_blacklist {
            self.is_on_blacklist = other.is_on_blacklist;
        }
    }

    fn set_is_on_blacklist(&mut self, config: &LogParserConfig) {
        if let Some(t) = config.l7_log_blacklist_trie.get(&L7Protocol::Oracle) {
            self.is_on_blacklist = t.request_resource.is_on_blacklist(&self.sql)
                || t.request_type.is_on_blacklist(self.packet_type.as_str());
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
        let mut attrs = vec![];

        if let Some(d) = &f.req_data_id {
            attrs.push(KeyVal {
                key: "request_data_id".to_string(),
                val: d.as_str().to_owned(),
            });
        }
        if let Some(d) = &f.req_call_id {
            attrs.push(KeyVal {
                key: "request_call_id".to_string(),
                val: d.as_str().to_owned(),
            });
        }
        if let Some(d) = &f.resp_data_id {
            attrs.push(KeyVal {
                key: "response_data_id".to_string(),
                val: d.as_str().to_owned(),
            });
        }
        if f.req_data_flags.bits() > 0 {
            attrs.push(KeyVal {
                key: "request_data_flags".to_string(),
                val: f.req_data_flags.to_string(),
            });
        }
        if f.resp_data_flags.bits() > 0 {
            attrs.push(KeyVal {
                key: "response_data_flags".to_string(),
                val: f.resp_data_flags.to_string(),
            });
        }
        let log = L7ProtocolSendLog {
            captured_request_byte: f.captured_request_byte,
            captured_response_byte: f.captured_response_byte,
            row_effect: f.affected_rows.unwrap_or_default(),
            req: L7Request {
                req_type: f.packet_type.as_str().to_owned(),
                resource: f.sql,
                ..Default::default()
            },
            resp: L7Response {
                status: f.status,
                code: Some(f.ret_code.into()),
                exception: f.error_message,
                ..Default::default()
            },
            ext_info: Some(ExtendedInfo {
                attributes: Some(attrs),
                ..Default::default()
            }),
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
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        self.parser.check_payload(
            payload,
            &OracleParseConfig {
                is_be: param.oracle_parse_conf.is_be,
                int_compress: param.oracle_parse_conf.int_compressed,
                resp_0x04_extra_byte: param.oracle_parse_conf.resp_0x04_extra_byte,
                buf_size: param.buf_size,
            },
        )
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        if !self.parser.parse_payload(
            payload,
            param.direction == PacketDirection::ClientToServer,
            &OracleParseConfig {
                is_be: param.oracle_parse_conf.is_be,
                int_compress: param.oracle_parse_conf.int_compressed,
                resp_0x04_extra_byte: param.oracle_parse_conf.resp_0x04_extra_byte,
                buf_size: param.buf_size,
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
            packet_type: self.parser.packet_type,
            sql: self.parser.sql.clone(),
            req_data_flags: self.parser.req_data_flags,
            req_data_id: self.parser.req_data_id.clone(),
            req_call_id: self.parser.req_call_id.clone(),
            ret_code: self.parser.ret_code,
            affected_rows: self.parser.affected_rows,
            error_message: self.parser.error_message.clone(),
            status: match self.parser.ret_code {
                0 => L7ResponseStatus::Ok,
                // TODO: Error code needs to be referenced: https://docs.oracle.com/cd/E11882_01/server.112/e17766/e29250.htm. Currently, simple processing is considered to be a client error
                _ => L7ResponseStatus::ClientError,
            },
            resp_data_flags: self.parser.resp_data_flags,
            resp_data_id: self.parser.resp_data_id.clone(),
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
