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

struct TDS {}



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

use std::{cell::OnceCell, collections::HashMap, fmt, str};

use serde::{Serialize, Serializer};
use strum_macros::Display;

use super::{
    super::{value_is_default, AppProtoHead, L7ResponseStatus},
    ObfuscateCache,
};
use public::l7_protocol::LogMessageType;

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
        error::{Error, Result},
        protocol_logs::{
            pb_adapter::{L7ProtocolSendLog, L7Request, L7Response},
            set_captured_byte,
        },
    },
};

#[derive(Serialize, Debug, Default, Clone)]
pub struct SqlServerInfo {
    msg_type: LogMessageType,
    #[serde(skip)]
    is_tls: bool,

    #[serde(
        rename = "request_resource",
        skip_serializing_if = "value_is_default",
        serialize_with = "vec_u8_to_string"
    )]
    pub request: Vec<u8>, // 命令字段包括参数例如："set key value"
    #[serde(
        skip_serializing_if = "value_is_default",
        serialize_with = "vec_u8_to_string"
    )]
    pub request_type: Vec<u8>, // 命令类型不包括参数例如：命令为"set key value"，命令类型为："set"
    #[serde(
        rename = "response_result",
        skip_serializing_if = "value_is_default",
        serialize_with = "vec_u8_to_string"
    )]
    #[serde(skip)]
    pub status: Vec<u8>, // '+'
    #[serde(
        rename = "response_expection",
        skip_serializing_if = "value_is_default",
        serialize_with = "vec_u8_to_string"
    )]
    pub error: Vec<u8>, // '-'
    #[serde(rename = "response_status")]
    pub resp_status: L7ResponseStatus,
    response_result: ResponseType,

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
        self.request.len()
    }

    fn is_on_blacklist(&self) -> bool {
        self.is_on_blacklist
    }
}

pub fn vec_u8_to_string<S>(v: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&String::from_utf8_lossy(v))
}

impl SqlServerInfo {
    pub fn merge(&mut self, other: &mut Self) -> Result<()> {
        std::mem::swap(&mut self.status, &mut other.status);
        std::mem::swap(&mut self.error, &mut other.error);
        std::mem::swap(&mut self.response_result, &mut other.response_result);
        self.resp_status = other.resp_status;
        self.captured_response_byte = other.captured_response_byte;
        if other.is_on_blacklist {
            self.is_on_blacklist = other.is_on_blacklist;
        }
        Ok(())
    }

    fn set_is_on_blacklist(&mut self, config: &LogParserConfig) {
        if let Some(t) = config.l7_log_blacklist_trie.get(&L7Protocol::Redis) {
            self.is_on_blacklist = t
                .request_resource
                .is_on_blacklist(str::from_utf8(&self.request).unwrap_or_default())
                || t.request_type
                    .is_on_blacklist(str::from_utf8(&self.request_type).unwrap_or_default());
        }
    }
}

impl fmt::Display for SqlServerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SqlServerInfo {{ request: {:?}, ",
            str::from_utf8(&self.request).unwrap_or_default()
        )?;
        write!(
            f,
            "request_type: {:?}, ",
            str::from_utf8(&self.request_type).unwrap_or_default()
        )?;
        write!(
            f,
            "status: {:?}, ",
            str::from_utf8(&self.status).unwrap_or_default()
        )?;
        write!(f, "response_result: {:?}, ", &self.response_result)?;
        write!(
            f,
            "error: {:?} }}",
            str::from_utf8(&self.error).unwrap_or_default()
        )
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
                req_type: String::from_utf8_lossy(f.request_type.as_slice()).to_string(),
                resource: String::from_utf8_lossy(f.request.as_slice()).to_string(),
                ..Default::default()
            },
            resp: L7Response {
                status: f.resp_status,
                exception: String::from_utf8_lossy(f.error.as_slice()).to_string(),
                result: f.response_result.to_string(),
                ..Default::default()
            },
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

        if CommandLine::new(payload).is_ok() {
            Some(LogMessageType::Request)
        } else {
            None
        }
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };
        let mut info = SqlServerInfo::default();
        info.is_tls = param.is_tls();
        self.parse(payload, param.l4_protocol, param.direction, &mut info)?;
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
        L7Protocol::Redis
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

    fn fill_request(&mut self, request: CommandLine, info: &mut SqlServerInfo) {
        info.request_type = Vec::from(request.command());
        info.msg_type = LogMessageType::Request;
        info.request = request.stringify(self.obfuscate);
        self.has_request = true;
    }

    fn fill_response(&mut self, context: (Vec<u8>, ResponseType), info: &mut SqlServerInfo) {
        info.msg_type = LogMessageType::Response;
        self.has_request = false;
        let (context, response_type) = context;
        info.resp_status = L7ResponseStatus::Ok;
        info.response_result = response_type;
        if context.is_empty() {
            return;
        }
        match context[0] {
            b'+' => info.status = context,
            b'-' | b'!' => {
                info.error = context;
                info.resp_status = L7ResponseStatus::ServerError;
            }
            _ => {}
        }
    }

    fn parse(
        &mut self,
        payload: &[u8],
        proto: IpProtocol,
        direction: PacketDirection,
        info: &mut SqlServerInfo,
    ) -> Result<()> {
        if proto != IpProtocol::TCP {
            return Err(Error::InvalidIpProtocol);
        }
        if payload.is_empty() {
            return Err(Error::L7ProtocolUnknown);
        }

        match direction {
            // only parse the request with payload start with '*' which indicate is a command start, otherwise assume tcp fragment of request
            PacketDirection::ClientToServer if payload.get(0) == Some(&b'*') => {
                self.fill_request(CommandLine::new(payload)?, info)
            }
            PacketDirection::ServerToClient if self.has_request => {
                self.fill_response(stringifier::decode(payload, false)?, info)
            }
            _ => return Err(Error::L7ProtocolUnknown),
        };
        Ok(())
    }
}
