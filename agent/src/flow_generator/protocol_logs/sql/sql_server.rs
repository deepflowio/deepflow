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

use std::fmt;

use serde::Serialize;

use crate::{
    common::{
        enums::IpProtocol,
        flow::{L7PerfStats, L7Protocol, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, LogCache, ParseParam},
        meta_packet::ApplicationFlags,
    },
    config::handler::LogParserConfig,
    flow_generator::{
        error::Result,
        protocol_logs::{
            pb_adapter::{L7ProtocolSendLog, L7Request, L7Response},
            set_captured_byte,
            sql::ObfuscateCache,
            value_is_default, AppProtoHead, L7ResponseStatus,
        },
    },
};
use l7::sql_server::TdsParser;
use public::l7_protocol::LogMessageType;

#[derive(Serialize, Debug, Default, Clone)]
pub struct SqlServerInfo {
    msg_type: LogMessageType,
    #[serde(skip)]
    is_tls: bool,

    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub sql: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub status_code: i32,
    pub error_message: String,
    pub affected_row: u64,
    pub resp_status: L7ResponseStatus,

    captured_request_byte: u32,
    captured_response_byte: u32,

    rrt: u64,

    #[serde(skip)]
    is_on_blacklist: bool,
}

impl L7ProtocolInfoInterface for SqlServerInfo {
    fn session_id(&self) -> Option<u32> {
        None
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::SqlServerInfo(other) = other {
            return self.merge(other);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::Redis,
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

impl SqlServerInfo {
    pub fn merge(&mut self, other: &mut Self) -> Result<()> {
        std::mem::swap(&mut self.status_code, &mut other.status_code);
        std::mem::swap(&mut self.error_message, &mut other.error_message);
        std::mem::swap(&mut self.affected_row, &mut other.affected_row);
        self.resp_status = other.resp_status;
        self.captured_response_byte = other.captured_response_byte;
        if other.is_on_blacklist {
            self.is_on_blacklist = other.is_on_blacklist;
        }
        Ok(())
    }

    fn set_is_on_blacklist(&mut self, config: &LogParserConfig) {
        if let Some(t) = config.l7_log_blacklist_trie.get(&L7Protocol::Redis) {
            self.is_on_blacklist = t.request_resource.is_on_blacklist(&self.sql.as_str())
        }
    }
}

impl fmt::Display for SqlServerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SqlServerInfo {{ sql: {:?}, ", self.sql)?;
        write!(f, "status_code: {:?}, ", &self.status_code)?;
        write!(f, "error_message: {:?}, ", &self.error_message)?;
        write!(f, "affected_row: {:?} }}", &self.affected_row)
    }
}

impl From<SqlServerInfo> for L7ProtocolSendLog {
    fn from(f: SqlServerInfo) -> Self {
        let flags = if f.is_tls {
            ApplicationFlags::TLS.bits()
        } else {
            ApplicationFlags::NONE.bits()
        };
        let log = L7ProtocolSendLog {
            captured_request_byte: f.captured_request_byte,
            captured_response_byte: f.captured_response_byte,
            req: L7Request {
                resource: f.sql,
                ..Default::default()
            },
            resp: L7Response {
                status: f.resp_status,
                exception: f.error_message,
                code: if f.status_code > 0 {
                    Some(f.status_code)
                } else {
                    None
                },
                ..Default::default()
            },
            row_effect: f.affected_row as u32,
            flags,
            ..Default::default()
        };
        return log;
    }
}

impl From<&SqlServerInfo> for LogCache {
    fn from(info: &SqlServerInfo) -> Self {
        LogCache {
            msg_type: info.msg_type,
            resp_status: info.resp_status,
            on_blacklist: info.is_on_blacklist,
            ..Default::default()
        }
    }
}

#[derive(Default)]
pub struct SqlServerLog {
    has_request: bool,
    perf_stats: Option<L7PerfStats>,
    obfuscate: bool,
}

impl L7ProtocolParserInterface for SqlServerLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> Option<LogMessageType> {
        if !param.ebpf_type.is_raw_protocol() {
            return None;
        }
        if param.l4_protocol != IpProtocol::TCP {
            return None;
        }

        let mut tds = TdsParser::new(payload.into());

        tds.parse().ok();

        if tds.sql.is_some() {
            return Some(LogMessageType::Request);
        }

        None
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };
        let mut info = SqlServerInfo::default();
        info.is_tls = param.is_tls();
        let mut tds = TdsParser::new(payload.into());

        tds.parse().ok();

        match param.direction {
            PacketDirection::ClientToServer => {
                let Some(sql) = tds.sql else {
                    return Ok(L7ParseResult::None);
                };
                info.msg_type = LogMessageType::Request;
                info.sql = sql;
                self.has_request = true;
            }
            PacketDirection::ServerToClient if self.has_request => {
                if tds.affected_row.is_none()
                    && tds.status_code.is_none()
                    && tds.error_message.is_none()
                {
                    return Ok(L7ParseResult::None);
                };

                if let Some(affected_row) = tds.affected_row {
                    info.affected_row = affected_row;
                }
                if let Some(status_code) = tds.status_code {
                    info.status_code = status_code;
                }
                if let Some(error_message) = tds.error_message {
                    info.error_message = error_message;
                }
                info.msg_type = LogMessageType::Response;

                self.has_request = false;
            }
            _ => return Ok(L7ParseResult::None),
        }

        set_captured_byte!(info, param);
        if let Some(config) = param.parse_config {
            info.set_is_on_blacklist(config);
        }
        if let Some(perf_stats) = self.perf_stats.as_mut() {
            if let Some(stats) = info.perf_stats(param) {
                info.rrt = stats.rrt_sum;
                perf_stats.sequential_merge(&stats);
            }
        }
        if param.parse_log {
            Ok(L7ParseResult::Single(L7ProtocolInfo::SqlServerInfo(info)))
        } else {
            Ok(L7ParseResult::None)
        }
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::SqlServer
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }

    fn set_obfuscate_cache(&mut self, obfuscate_cache: Option<ObfuscateCache>) {
        self.obfuscate = obfuscate_cache.is_some();
    }
}

impl SqlServerLog {
    fn reset(&mut self) {
        self.perf_stats = None;
    }
}
