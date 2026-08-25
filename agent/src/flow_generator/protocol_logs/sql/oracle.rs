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
use sqlparser::{
    dialect::GenericDialect,
    tokenizer::{Token, Tokenizer},
};

use super::super::value_is_default;
use super::sql_check::trim_head_comment_and_get_first_word;
use crate::config::handler::LogParserConfig;
use crate::flow_generator::{
    protocol_logs::{
        auto_merge_custom_field,
        pb_adapter::{ExtendedInfo, KeyVal},
        swap_if, L7ResponseStatus,
    },
    Error,
};
use crate::{
    common::{
        flow::{L7PerfStats, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, LogCache, ParseParam},
    },
    flow_generator::{
        protocol_logs::pb_adapter::{L7ProtocolSendLog, L7Request, L7Response},
        AppProtoHead, Result,
    },
};

use enterprise_utils::l7::{
    custom_policy::{
        custom_field_policy::{
            enums::{Op, Source},
            PolicySlice, Store,
        },
        enums::TrafficDirection,
    },
    sql::oracle::{
        find_bind_values, Body, CallId, DataFlags, DataId, OracleParseConfig, OracleParser,
        TnsPacketType,
    },
};
use public::l7_protocol::{Field, FieldSetter, L7Log, L7LogAttribute, L7Protocol, LogMessageType};
use public_derive::L7Log;

#[derive(L7Log, Serialize, Debug, Default, Clone, PartialEq)]
#[l7_log(request_type.getter = "OracleInfo::get_request_type", request_type.setter = "OracleInfo::set_request_type")]
#[l7_log(version.skip = "true", request_domain.skip = "true", endpoint.skip = "true")]
#[l7_log(request_id.skip = "true", http_proxy_client.skip = "true")]
#[l7_log(trace_id.skip = "true", span_id.skip = "true", x_request_id.skip = "true")]
#[l7_log(response_result.skip = "true", response_code.skip = "true")]
#[l7_log(biz_type.skip = "true", biz_code.skip = "true", biz_scenario.skip = "true")]
#[l7_log(biz_response_code.skip = "true")]
pub struct OracleInfo {
    pub msg_type: LogMessageType,
    #[serde(skip)]
    pub is_tls: bool,

    #[serde(rename = "request_type", skip_serializing_if = "value_is_default")]
    pub packet_type: TnsPacketType,
    // req
    #[l7_log(request_resource)]
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub sql: String,
    #[serde(skip)]
    pub req_data_flags: DataFlags,
    #[serde(skip)]
    pub req_data_id: Option<DataId>,
    #[serde(skip)]
    pub req_call_id: Option<CallId>,
    #[serde(skip)]
    pub connect_data: Option<String>,
    #[serde(skip)]
    pub auth_session_id: Option<String>,

    // response
    pub ret_code: u16,
    #[serde(rename = "sql_affected_rows", skip_serializing_if = "value_is_default")]
    pub affected_rows: Option<u32>,
    #[l7_log(response_exception)]
    #[serde(
        rename = "response_exception",
        skip_serializing_if = "value_is_default"
    )]
    pub error_message: String,
    #[l7_log(response_status)]
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

    #[serde(skip)]
    pub attributes: Vec<KeyVal>,
}
impl L7LogAttribute for OracleInfo {
    fn add_attribute(&mut self, name: Cow<'_, str>, value: Cow<'_, str>) {
        self.attributes.push(KeyVal {
            key: name.into_owned(),
            val: value.into_owned(),
        });
    }
}

impl OracleInfo {
    pub fn get_request_type(&self) -> Field<'_> {
        Field::from(self.packet_type.as_str())
    }

    pub fn set_request_type(&mut self, _setter: FieldSetter<'_>) {
        // TnsPacketType is an enum, skip rewrite
    }

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
        if other.connect_data.is_some() {
            self.connect_data = other.connect_data.take();
        }
        if other.auth_session_id.is_some() {
            self.auth_session_id = other.auth_session_id.take();
        }
        self.attributes.append(&mut other.attributes);
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
        if let Some(d) = &f.connect_data {
            attrs.push(KeyVal {
                key: "connect_data".to_string(),
                val: d.as_str().to_owned(),
            });
        }
        if let Some(d) = &f.auth_session_id {
            attrs.push(KeyVal {
                key: "auth_session_id".to_string(),
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
        attrs.extend(f.attributes);
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

impl From<&OracleInfo> for LogCache {
    fn from(info: &OracleInfo) -> Self {
        LogCache {
            msg_type: info.msg_type,
            resp_status: info.status,
            on_blacklist: info.is_on_blacklist,
            ..Default::default()
        }
    }
}

#[derive(Default)]
pub struct OracleLog {
    perf_stats: Vec<L7PerfStats>,
    custom_field_store: Store,
    cached_info: Option<CachedOracleInfo>,
}

struct CachedOracleInfo {
    info: OracleInfo,
    perf_stats_recorded: bool,
}

const INSERT_KEYWORD: &[u8] = b"INSERT";
const UPDATE_KEYWORD: &[u8] = b"UPDATE";
const SET_KEYWORD: &[u8] = b"set";
const VALUES_KEYWORD: &[u8] = b"values";

fn sql_has_bind_placeholder(sql: &str) -> bool {
    let Some(scan_start) = upsert_bind_scan_start(sql) else {
        return false;
    };

    let sql = &sql[scan_start..];
    let dialect = GenericDialect;
    let Ok(tokens) = Tokenizer::new(&dialect, sql)
        .with_unescape(false)
        .tokenize()
    else {
        return false;
    };

    // `sqlparser` splits `:1` into `Colon + Number("1")`,
    // and `:x1` into `Colon + Word("x1")`.
    tokens
        .windows(2)
        .any(|window| matches!(window[0], Token::Colon) && token_bind_placeholder(&window[1]))
}

// 这里需要和 SqlUpsertColumnExtractor::FieldIter::new() 保持一致。
// 目前只支持带空白边界的简单 upsert 语句：
// `insert ... values ...`、`insert ... set ...`、`update ... set ...`。
// 像 `insert into t(a)values(:1)` 这种没有空白边界的形式暂时不支持。
//
// This must stay aligned with SqlUpsertColumnExtractor::FieldIter::new().
// We currently only support whitespace-delimited simple upsert statements:
// `insert ... values ...`, `insert ... set ...`, and `update ... set ...`.
// Forms such as `insert into t(a)values(:1)` are intentionally unsupported.
fn upsert_bind_scan_start(sql: &str) -> Option<usize> {
    let sql = sql.as_bytes();
    let first = trim_head_comment_and_get_first_word(sql, 6)?;
    if first.eq_ignore_ascii_case(INSERT_KEYWORD) {
        find_keyword_with_spaces(sql, VALUES_KEYWORD)
            .or_else(|| find_keyword_with_spaces(sql, SET_KEYWORD))
            .map(|(index, len)| index + 1 + len)
    } else if first.eq_ignore_ascii_case(UPDATE_KEYWORD) {
        find_keyword_with_spaces(sql, SET_KEYWORD).map(|(index, len)| index + 1 + len)
    } else {
        None
    }
}

fn find_keyword_with_spaces(sql: &[u8], keyword: &[u8]) -> Option<(usize, usize)> {
    if keyword.is_empty() || sql.len() < keyword.len() + 2 {
        return None;
    }

    sql.windows(keyword.len() + 2)
        .position(|window| {
            window[0].is_ascii_whitespace()
                && window[1..1 + keyword.len()].eq_ignore_ascii_case(keyword)
                && window[1 + keyword.len()].is_ascii_whitespace()
        })
        .map(|index| (index, keyword.len()))
}

fn token_bind_placeholder(token: &Token) -> bool {
    match token {
        Token::Number(value, _) => value.parse::<usize>().ok().is_some_and(|n| n > 0),
        Token::Word(word) => word_bind_placeholder(&word.value),
        _ => false,
    }
}

fn word_bind_placeholder(word: &str) -> bool {
    let value = word
        .strip_prefix('x')
        .or_else(|| word.strip_prefix('X'))
        .unwrap_or(word);
    !value.is_empty()
        && value.bytes().all(|b| b.is_ascii_digit())
        && value.parse::<usize>().ok().is_some_and(|n| n > 0)
}

impl OracleLog {
    fn cache_pending_request(&mut self, mut info: OracleInfo, param: &ParseParam) {
        let perf_stats_recorded = self.record_perf_stats(&mut info, param);
        self.cached_info = Some(CachedOracleInfo {
            info,
            perf_stats_recorded,
        });
    }

    fn apply_custom_field_operations(
        &mut self,
        policies: PolicySlice,
        info: &mut OracleInfo,
        frame_payload: &[u8],
    ) {
        policies.apply(
            &mut self.custom_field_store,
            info,
            TrafficDirection::REQUEST,
            Source::Sql(&info.sql, Some(frame_payload)),
        );
        for op in self.custom_field_store.drain_with(policies, info) {
            match &op.op {
                Op::AddMetric(_, _) | Op::SaveHeader(_) | Op::SavePayload(_) => (),
                _ => auto_merge_custom_field(op, info),
            }
        }
    }

    fn record_perf_stats(&mut self, log_info: &mut OracleInfo, param: &ParseParam) -> bool {
        if !param.parse_perf {
            return false;
        }

        let mut perf_stat = L7PerfStats::default();
        if let Some(stats) = log_info.perf_stats(param) {
            log_info.rrt = stats.rrt_sum;
            perf_stat.sequential_merge(&stats);
        }
        self.perf_stats.push(perf_stat);
        true
    }
}

impl L7ProtocolParserInterface for OracleLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> Option<LogMessageType> {
        OracleParser::check_payload(
            payload,
            &OracleParseConfig {
                is_be: param.oracle_parse_conf.is_be,
                int_compress: param.oracle_parse_conf.int_compressed,
                resp_0x04_extra_byte: param.oracle_parse_conf.resp_0x04_extra_byte,
            },
        )
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        let frames = OracleParser::parse_payload(
            payload,
            param.direction == PacketDirection::ClientToServer,
            &OracleParseConfig {
                is_be: param.oracle_parse_conf.is_be,
                int_compress: param.oracle_parse_conf.int_compressed,
                resp_0x04_extra_byte: param.oracle_parse_conf.resp_0x04_extra_byte,
            },
        );
        if frames.is_empty() {
            return Err(Error::L7ProtocolUnknown);
        }

        let custom_policies = {
            self.custom_field_store.clear();
            param
                .parse_config
                .as_ref()
                .and_then(|c| c.get_custom_field_policies(L7Protocol::Oracle.into(), param))
        };

        self.perf_stats.clear();

        let mut info = vec![];
        for frame in frames {
            let frame_payload = frame.payload;
            let is_request = matches!(&frame.body, Body::Request(_));
            let mut log_info = match frame.body {
                Body::Request(req) => OracleInfo {
                    msg_type: param.direction.into(),
                    packet_type: frame.packet_type,
                    sql: req.sql,
                    req_data_flags: req.req_data_flags,
                    req_data_id: req.req_data_id,
                    req_call_id: req.req_call_id,
                    captured_request_byte: frame.length as u32,
                    connect_data: req.connect_data,
                    ..Default::default()
                },
                Body::Response(resp) => OracleInfo {
                    msg_type: param.direction.into(),
                    packet_type: frame.packet_type,
                    ret_code: resp.ret_code,
                    affected_rows: resp.affected_rows,
                    error_message: resp.error_message,
                    status: match resp.ret_code {
                        0 => L7ResponseStatus::Ok,
                        // TODO: Error code needs to be referenced: https://docs.oracle.com/cd/E11882_01/server.112/e17766/e29250.htm. Currently, simple processing is considered to be a client error
                        _ => L7ResponseStatus::ClientError,
                    },
                    resp_data_flags: resp.resp_data_flags,
                    resp_data_id: resp.resp_data_id,
                    captured_response_byte: frame.length as u32,
                    auth_session_id: resp.auth_session_id,
                    ..Default::default()
                },
            };

            if let Some(config) = param.parse_config {
                log_info.set_is_on_blacklist(config);
            }

            let mut custom_fields_applied = false;
            // 缓存 SQL-only request 时已经记录过 perf stats，用来固定 RRT 起点在原始 SQL 帧。
            // 后续 bind-only frame 合并回来时要跳过第二次 perf 记账，避免重复更新 perf cache。
            //
            // The cached SQL-only request already recorded perf stats so the RRT start
            // stays on the original SQL frame. When a later bind-only frame merges back
            // into it, skip a second perf accounting pass to avoid double-updating the cache.
            let mut perf_stats_recorded = false;
            if let Some(policies) = custom_policies {
                // Oracle 请求里，SQL 文本和 bind value 可能分布在两个 request frame 中。
                // 先缓存只携带 SQL 的请求，等待下一帧带上 bind value 后再重新执行自定义 SQL 提取。
                //
                // In Oracle requests, the SQL text and bind values may be split across two
                // request frames. Cache the SQL-only request first, then re-run custom SQL
                // extraction when the next request frame carries the bind values.
                if !is_request {
                    if let Some(cached) = self.cached_info.take() {
                        info.push(L7ProtocolInfo::OracleInfo(cached.info));
                    }
                } else if let Some(mut cached) = self.cached_info.take() {
                    if log_info.sql.is_empty() && find_bind_values(frame_payload, 0).is_some() {
                        cached.info.merge(&mut log_info);
                        perf_stats_recorded = cached.perf_stats_recorded;
                        log_info = cached.info;
                        self.apply_custom_field_operations(policies, &mut log_info, frame_payload);
                        custom_fields_applied = true;
                    } else {
                        info.push(L7ProtocolInfo::OracleInfo(cached.info));
                    }
                }

                if !custom_fields_applied && !log_info.sql.is_empty() {
                    let has_bind_placeholder = sql_has_bind_placeholder(&log_info.sql);
                    let can_apply_custom_fields =
                        !has_bind_placeholder || find_bind_values(frame_payload, 0).is_some();
                    if can_apply_custom_fields {
                        self.apply_custom_field_operations(policies, &mut log_info, frame_payload);
                    } else {
                        self.cache_pending_request(log_info, param);
                        continue;
                    }
                }
            }

            if !perf_stats_recorded {
                self.record_perf_stats(&mut log_info, param);
            }

            info.push(L7ProtocolInfo::OracleInfo(log_info));
        }
        Ok(L7ParseResult::Multi(info))
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Oracle
    }

    fn perf_stats(&mut self) -> Vec<L7PerfStats> {
        std::mem::take(&mut self.perf_stats)
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::sql_has_bind_placeholder;

    #[test]
    fn sql_has_bind_placeholder_only_tracks_simple_upsert() {
        assert!(!sql_has_bind_placeholder("select ':1' from dual"));
        assert!(!sql_has_bind_placeholder("select * from t where a = :1"));
        assert!(sql_has_bind_placeholder(
            "insert into t values (':1', :1, :x2, /* :3 */ :4)"
        ));
        assert!(sql_has_bind_placeholder(
            "update t set a = :1, b = ':2', c = :X51 -- :9"
        ));
        assert!(sql_has_bind_placeholder(
            "insert into t set a = ':1', b = :1"
        ));
        assert!(!sql_has_bind_placeholder(
            "insert into t select :1 from dual"
        ));
    }
}
