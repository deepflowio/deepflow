/*
 * Copyright (c) 2025 Yunshan Networks
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

use enterprise_utils::l7::rpc::iso8583::{Iso8583ParseConfig, Iso8583Parser};
use public::l7_protocol::{L7Protocol, LogMessageType};

use crate::config::handler::LogParserConfig;
use crate::{
    common::{
        flow::L7PerfStats,
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, LogCache, ParseParam},
        meta_packet::ApplicationFlags,
    },
    flow_generator::{
        protocol_logs::{
            pb_adapter::{
                ExtendedInfo, KeyVal, L7ProtocolSendLog, L7Request, L7Response, TraceInfo,
            },
            set_captured_byte, swap_if, value_is_default, L7ResponseStatus, PrioFields,
            BASE_FIELD_PRIORITY,
        },
        AppProtoHead, Error, Result,
    },
};

#[derive(Serialize, Debug, Default, Clone, PartialEq)]
pub struct Iso8583Info {
    pub msg_type: LogMessageType,

    #[serde(rename = "request_type", skip_serializing_if = "value_is_default")]
    pub mti: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub endpoint: String,

    // value of field 7, 11, 32, 33
    f7: String,
    f11: String,
    f32: String,
    f33: String,
    f3: String,
    f25: String,
    // it is formed by connecting f7,f11,f32,f33 with -
    pub trace_ids: PrioFields,

    #[serde(skip_serializing_if = "value_is_default")]
    pub response_status: L7ResponseStatus,
    #[serde(skip_serializing_if = "value_is_default")]
    pub response_exception: String,

    captured_request_byte: u32,
    captured_response_byte: u32,

    pub rrt: u64,

    #[serde(skip)]
    attributes: Vec<KeyVal>,

    #[serde(skip)]
    is_on_blacklist: bool,

    is_async: bool,
    is_reversed: bool,
}

impl Iso8583Info {
    pub fn merge(&mut self, other: &mut Self) {
        swap_if!(self, mti, is_empty, other);

        swap_if!(self, response_exception, is_empty, other);
        if other.response_status != L7ResponseStatus::default() {
            self.response_status = other.response_status;
        }
        self.captured_request_byte += other.captured_request_byte;
        self.captured_response_byte += other.captured_response_byte;
        if other.is_on_blacklist {
            self.is_on_blacklist = other.is_on_blacklist;
        }
        self.attributes.append(&mut other.attributes);
        if other.is_async {
            self.is_async = other.is_async;
        }
        if other.is_reversed {
            self.is_reversed = other.is_reversed;
        }
    }

    fn set_is_on_blacklist(&mut self, config: &LogParserConfig) {
        if let Some(t) = config.l7_log_blacklist_trie.get(&L7Protocol::Iso8583) {
            self.is_on_blacklist = t.request_resource.is_on_blacklist(&self.mti)
                || t.request_type.is_on_blacklist(&self.mti.as_str());
        }
    }
}

impl L7ProtocolInfoInterface for Iso8583Info {
    fn session_id(&self) -> Option<u32> {
        None
    }

    // asynchronous response, no session aggregation required
    fn needs_session_aggregation(&self) -> bool {
        false
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::Iso8583Info(other) = other {
            self.merge(other);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::Iso8583,
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn is_tls(&self) -> bool {
        false
    }

    fn get_request_resource_length(&self) -> usize {
        0
    }

    fn is_on_blacklist(&self) -> bool {
        self.is_on_blacklist
    }

    fn get_endpoint(&self) -> Option<String> {
        if self.endpoint.is_empty() {
            return None;
        }
        Some(self.endpoint.clone())
    }
}

impl From<Iso8583Info> for L7ProtocolSendLog {
    fn from(f: Iso8583Info) -> Self {
        let mut flags = if f.is_async {
            ApplicationFlags::ASYNC
        } else {
            ApplicationFlags::NONE
        };
        if f.is_reversed {
            flags = flags | ApplicationFlags::REVERSED;
        }
        let log = L7ProtocolSendLog {
            captured_request_byte: f.captured_request_byte,
            captured_response_byte: f.captured_response_byte,
            req: L7Request {
                req_type: f.mti,
                endpoint: f.endpoint,
                ..Default::default()
            },
            resp: L7Response {
                status: if f.response_status == L7ResponseStatus::Timeout {
                    L7ResponseStatus::Ok
                } else {
                    f.response_status
                },
                exception: f.response_exception,
                ..Default::default()
            },
            trace_info: Some(TraceInfo {
                trace_ids: f.trace_ids.into_strings_top3(),
                ..Default::default()
            }),
            ext_info: Some(ExtendedInfo {
                attributes: Some(f.attributes),
                ..Default::default()
            }),
            flags: flags.bits(),
            ..Default::default()
        };
        log
    }
}

impl From<&Iso8583Info> for LogCache {
    fn from(info: &Iso8583Info) -> Self {
        LogCache {
            msg_type: info.msg_type,
            resp_status: info.response_status,
            on_blacklist: info.is_on_blacklist,
            ..Default::default()
        }
    }
}

#[derive(Default)]
pub struct Iso8583Log {
    perf_stats: Option<L7PerfStats>,
    parser: Iso8583Parser,
}

impl L7ProtocolParserInterface for Iso8583Log {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> Option<LogMessageType> {
        self.parser.check_payload(
            payload,
            &Iso8583ParseConfig {
                extract_fields: param.iso8583_parse_conf.extract_fields.clone(),
                translation_enabled: param.iso8583_parse_conf.translation_enabled,
                pan_obfuscate: param.iso8583_parse_conf.pan_obfuscate,
            },
        )
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        // 支持 payload 中包含多个 ISO8583 消息
        let msgs = self.parser.parse_payload_multiple(
            payload,
            &Iso8583ParseConfig {
                extract_fields: param.iso8583_parse_conf.extract_fields.clone(),
                translation_enabled: param.iso8583_parse_conf.translation_enabled,
                pan_obfuscate: param.iso8583_parse_conf.pan_obfuscate,
            },
        );
        if msgs.is_empty() {
            return Err(Error::L7ProtocolUnknown);
        }

        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default());
        };

        // 对每条解析到的消息构造 Iso8583Info，并返回 Multiple 或 Single
        let mut results: Vec<L7ProtocolInfo> = Vec::with_capacity(msgs.len());
        for (idx, fields) in msgs.into_iter().enumerate() {
            let mut info = Iso8583Info::default();
            for field in fields.into_iter() {
                if info.mti.is_empty() && field.id == 0 {
                    info.mti = field.translated.clone().unwrap_or(field.value.clone());
                    // Determine if it's a response based on MTI
                    if let Some(&b) = info.mti.as_bytes().get(2) {
                        if b % 2 == 1 {
                            info.msg_type = LogMessageType::Response;
                        } else {
                            info.msg_type = LogMessageType::Request;
                            info.response_status = L7ResponseStatus::Ok;
                        }
                    }
                } else if field.id == 7 {
                    info.f7 = field.value.clone();
                } else if field.id == 11 {
                    info.f11 = field.value.clone();
                } else if field.id == 32 {
                    info.f32 = field.value.clone();
                } else if field.id == 33 {
                    info.f33 = field.value.clone();
                } else if field.id == 3 {
                    info.f3 = field.value.clone();
                } else if field.id == 25 {
                    info.f25 = field.value.clone();
                } else if field.id == 39 {
                    info.msg_type = LogMessageType::Response;
                    if field.value == "00"
                        || field.value == "10"
                        || field.value == "11"
                        || field.value == "16"
                        || field.value == "A2"
                        || field.value == "A4"
                        || field.value == "A5"
                        || field.value == "A6"
                        || field.value == "Y1"
                        || field.value == "Y3"
                    {
                        info.response_status = L7ResponseStatus::Ok;
                    } else {
                        info.response_status = L7ResponseStatus::ClientError;
                        info.response_exception =
                            field.translated.clone().unwrap_or(field.value.clone());
                    }
                };
                set_captured_byte!(info, param);

                if !param
                    .iso8583_parse_conf
                    .extract_fields
                    .get(field.id as usize)
                    .unwrap_or(false)
                {
                    continue;
                }

                if field.id == 2 && param.iso8583_parse_conf.pan_obfuscate {
                    info.attributes.push(KeyVal {
                        key: field.description,
                        val: mask_card_number(&field.value),
                    });
                    continue;
                }
                info.attributes.push(KeyVal {
                    key: field.description,
                    val: field.translated.unwrap_or(field.value),
                });
            }

            if !info.f7.is_empty()
                && !info.f11.is_empty()
                && !info.f32.is_empty()
                && !info.f33.is_empty()
            {
                info.trace_ids.merge_field(
                    BASE_FIELD_PRIORITY,
                    format!("{}-{}-{}-{}", info.f7, info.f11, info.f32, info.f33),
                );
            }

            if let Some(config) = param.parse_config {
                info.set_is_on_blacklist(config);
            }
            info.is_async = true;

            if let Some(perf_stats) = self.perf_stats.as_mut() {
                if let Some(stats) = info.perf_stats(param) {
                    perf_stats.sequential_merge(&stats);
                }
            }

            if is_00x000(&info.f3) {
                if info.f25 == "28" {
                    if info.mti == "0200-金融类请求" {
                        info.endpoint = format!(
                            "{}:{}-28消费一次性付款类",
                            info.mti,
                            take_first_n(&info.f3, 6)
                        );
                    } else if info.mti == "0210-金融类应答" {
                        info.endpoint = format!(
                            "{}:{}-28消费一次性付款类",
                            info.mti,
                            take_first_n(&info.f3, 6)
                        );
                    }
                } else if info.f25 == "00" {
                    if info.mti == "0200-金融类请求" {
                        info.endpoint =
                            format!("{}:{}-00-代收", info.mti, take_first_n(&info.f3, 6));
                    } else if info.mti == "0210-金融类应答" {
                        info.endpoint =
                            format!("{}:{}-00-代收", info.mti, take_first_n(&info.f3, 6));
                    }
                }
            }

            info.attributes.push(KeyVal {
                key: "packet_index".to_string(),
                val: idx.to_string(),
            });
            results.push(L7ProtocolInfo::Iso8583Info(info));
        }
        if results.len() == 1 {
            Ok(L7ParseResult::Single(results.into_iter().next().unwrap()))
        } else {
            Ok(L7ParseResult::Multi(results))
        }
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Iso8583
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }
}

fn take_first_n(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

#[inline]
fn is_00x000(s: &str) -> bool {
    let b = s.as_bytes();

    if b.len() < 6 {
        return false;
    }

    // 00 x 000
    b[0] == b'0'
        && b[1] == b'0'
        && b[2].is_ascii_digit()
        && b[3] == b'0'
        && b[4] == b'0'
        && b[5] == b'0'
}

// preserve the first 6 and last 4 digits, mask the remaining characters with *
fn mask_card_number(card: &str) -> String {
    let chars: Vec<char> = card.chars().collect();
    let len = chars.len();

    if len < 10 {
        return card.to_string();
    }

    let mut result = String::with_capacity(len);

    result.extend(&chars[..6]);
    for _ in 0..(len - 10) {
        result.push('*');
    }
    result.extend(&chars[len - 4..]);

    result
}
