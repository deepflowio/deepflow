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

use std::borrow::Cow;

use serde::Serialize;

use super::super::value_is_default;
use crate::config::handler::LogParserConfig;
use crate::flow_generator::{
    protocol_logs::{
        pb_adapter::{ExtendedInfo, KeyVal},
        swap_if, L7ResponseStatus,
    },
    Error,
};
use crate::{
    common::{
        flow::L7PerfStats,
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, LogCache, ParseParam},
    },
    flow_generator::{
        protocol_logs::pb_adapter::{L7ProtocolSendLog, L7Request, L7Response},
        AppProtoHead, Result,
    },
};

use enterprise_utils::l7::sql::dameng::{DamengParseConfig, DamengParser};
use public::l7_protocol::{L7Log, L7LogAttribute, L7Protocol, LogMessageType};
use public_derive::L7Log;

#[derive(L7Log, Serialize, Debug, Default, Clone, PartialEq)]
#[l7_log(version.skip = "true", request_domain.skip = "true", endpoint.skip = "true")]
#[l7_log(request_id.skip = "true", http_proxy_client.skip = "true")]
#[l7_log(trace_id.skip = "true", span_id.skip = "true", x_request_id.skip = "true")]
#[l7_log(response_result.skip = "true")]
#[l7_log(biz_type.skip = "true", biz_code.skip = "true", biz_scenario.skip = "true")]
#[l7_log(biz_response_code.skip = "true")]
pub struct DamengInfo {
    pub msg_type: LogMessageType,
    #[serde(skip)]
    pub is_tls: bool,

    #[l7_log(request_type)]
    #[serde(rename = "request_type", skip_serializing_if = "value_is_default")]
    pub request_type: String,
    #[l7_log(request_resource)]
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub sql: String,

    #[l7_log(response_code)]
    #[serde(skip_serializing_if = "value_is_default")]
    pub ret_code: i32,
    #[l7_log(response_exception)]
    #[serde(
        rename = "response_exception",
        skip_serializing_if = "value_is_default"
    )]
    pub error_message: String,
    #[l7_log(response_status)]
    #[serde(rename = "response_status")]
    pub status: L7ResponseStatus,

    captured_request_byte: u32,
    captured_response_byte: u32,

    pub rrt: u64,

    #[serde(skip)]
    pub session_id: Option<u32>,

    #[serde(skip)]
    is_on_blacklist: bool,

    #[serde(skip)]
    pub attributes: Vec<KeyVal>,
}

impl L7LogAttribute for DamengInfo {
    fn add_attribute(&mut self, name: Cow<'_, str>, value: Cow<'_, str>) {
        self.attributes.push(KeyVal {
            key: name.into_owned(),
            val: value.into_owned(),
        });
    }
}

impl DamengInfo {
    pub fn merge(&mut self, other: &mut Self) {
        swap_if!(self, request_type, is_empty, other);
        swap_if!(self, sql, is_empty, other);
        if other.ret_code != 0 {
            self.ret_code = other.ret_code;
        }
        swap_if!(self, error_message, is_empty, other);
        if other.status != L7ResponseStatus::default() {
            self.status = other.status;
        }
        if self.session_id.is_none() {
            self.session_id = other.session_id;
        }
        self.captured_request_byte += other.captured_request_byte;
        self.captured_response_byte += other.captured_response_byte;
        if other.is_on_blacklist {
            self.is_on_blacklist = other.is_on_blacklist;
        }
        self.attributes.append(&mut other.attributes);
    }

    fn set_is_on_blacklist(&mut self, config: &LogParserConfig) {
        if let Some(t) = config.l7_log_blacklist_trie.get(&L7Protocol::Dameng) {
            self.is_on_blacklist = t.request_resource.is_on_blacklist(&self.sql)
                || t.request_type.is_on_blacklist(&self.request_type);
        }
    }
}

impl L7ProtocolInfoInterface for DamengInfo {
    fn session_id(&self) -> Option<u32> {
        self.session_id
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::DamengInfo(other) = other {
            self.merge(other);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::Dameng,
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

impl From<DamengInfo> for L7ProtocolSendLog {
    fn from(f: DamengInfo) -> Self {
        let mut attrs = vec![];
        attrs.extend(f.attributes);
        L7ProtocolSendLog {
            captured_request_byte: f.captured_request_byte,
            captured_response_byte: f.captured_response_byte,
            req: L7Request {
                req_type: f.request_type,
                resource: f.sql,
                ..Default::default()
            },
            resp: L7Response {
                status: f.status,
                code: Some(f.ret_code),
                exception: f.error_message,
                ..Default::default()
            },
            ext_info: Some(ExtendedInfo {
                attributes: Some(attrs),
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

impl From<&DamengInfo> for LogCache {
    fn from(info: &DamengInfo) -> Self {
        LogCache {
            msg_type: info.msg_type,
            resp_status: info.status,
            on_blacklist: info.is_on_blacklist,
            ..Default::default()
        }
    }
}

#[derive(Default)]
pub struct DamengLog {
    perf_stats: Vec<L7PerfStats>,
}

impl L7ProtocolParserInterface for DamengLog {
    fn check_payload(&mut self, payload: &[u8], _param: &ParseParam) -> Option<LogMessageType> {
        DamengParser::check_payload(payload, &DamengParseConfig {})
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        let frames = DamengParser::parse_payload(payload, &DamengParseConfig {});
        if frames.is_empty() {
            return Err(Error::L7ProtocolUnknown);
        }

        self.perf_stats.clear();

        let mut info = vec![];
        for (index, frame) in frames.into_iter().enumerate() {
            let captured_byte = if index == 0 { payload.len() as u32 } else { 0 };
            let mut log_info = match frame.msg_type {
                LogMessageType::Request => DamengInfo {
                    msg_type: LogMessageType::Request,
                    request_type: frame.request_type,
                    sql: frame.request_resource,
                    session_id: frame.request_id,
                    captured_request_byte: captured_byte,
                    ..Default::default()
                },
                LogMessageType::Response => DamengInfo {
                    msg_type: LogMessageType::Response,
                    request_type: "".to_string(),
                    ret_code: frame.response_code.parse::<i32>().unwrap_or_default(),
                    error_message: frame.response_exception,
                    status: frame.response_status,
                    session_id: frame.request_id,
                    captured_response_byte: captured_byte,
                    ..Default::default()
                },
                _ => continue,
            };

            if let Some(config) = param.parse_config {
                log_info.set_is_on_blacklist(config);
            }
            if param.parse_perf {
                let mut perf_stat = L7PerfStats::default();
                if let Some(stats) = log_info.perf_stats(param) {
                    log_info.rrt = stats.rrt_sum;
                    perf_stat.sequential_merge(&stats);
                }
                self.perf_stats.push(perf_stat);
            }

            info.push(L7ProtocolInfo::DamengInfo(log_info));
        }
        Ok(L7ParseResult::Multi(info))
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Dameng
    }

    fn perf_stats(&mut self) -> Vec<L7PerfStats> {
        std::mem::take(&mut self.perf_stats)
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }
}
