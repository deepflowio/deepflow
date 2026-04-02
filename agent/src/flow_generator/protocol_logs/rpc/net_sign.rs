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

use chrono::{DateTime, FixedOffset, TimeZone};
use serde::Serialize;

use enterprise_utils::l7::rpc::net_sign::{NetSignParser, PROCESSOR_SIGN, PROCESSOR_VERIFY};
use public::{
    enums::PacketDirection,
    l7_protocol::{L7Protocol, LogMessageType},
};

use crate::config::handler::LogParserConfig;
use crate::{
    common::{
        flow::L7PerfStats,
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, LogCache, ParseParam},
    },
    flow_generator::{
        protocol_logs::{
            pb_adapter::{
                ExtendedInfo, KeyVal, L7ProtocolSendLog, L7Request, L7Response, MetricKeyVal,
                TraceInfo,
            },
            set_captured_byte, value_is_default, L7ResponseStatus, PrioStrings,
            BASE_FIELD_PRIORITY,
        },
        AppProtoHead, Error, Result,
    },
};

/// request_type values
const REQ_TYPE_SIGN: &str = "sign";
const REQ_TYPE_VERIFY: &str = "verify";

#[derive(Serialize, Debug, Default, Clone)]
pub struct NetSignInfo {
    pub msg_type: LogMessageType,

    /// endpoint = biz_system
    #[serde(skip_serializing_if = "value_is_default")]
    pub endpoint: String,

    /// request_resource = processorName ("RAWSignProcessor" | "PBCRAWVerifyProcessor")
    #[serde(skip_serializing_if = "value_is_default")]
    pub request_resource: String,

    /// request_type: "sign" | "verify" (derived from processorName)
    #[serde(rename = "request_type", skip_serializing_if = "value_is_default")]
    pub request_type: String,

    /// version from appVer / version field
    #[serde(rename = "version", skip_serializing_if = "value_is_default")]
    pub version: String,

    /// response status
    #[serde(skip_serializing_if = "value_is_default")]
    pub response_status: L7ResponseStatus,
    pub op_result: String,

    /// raw resultCode from response
    #[serde(skip_serializing_if = "value_is_default")]
    pub response_code: String,

    /// trace_ids from bizData[0]
    #[serde(skip)]
    pub trace_ids: PrioStrings,

    /// SM2 signature present flag (attribute)
    sig_present: bool,
    /// SM2 signature byte length (attribute)
    sig_len: u32,
    /// certId (request) or subjectDN CN (response)
    cert_id: String,
    /// certSerial from verify response
    cert_serial: String,
    /// certValidity Unix timestamp from verify response
    cert_validity: String,
    /// issuerDN_ca common name from verify response
    ca_name: String,
    /// signer_id = subjectDN CN from verify response
    signer_id: String,
    /// business system type from bizData[6]
    biz_system: String,
    /// full bizData string
    biz_data: String,

    captured_request_byte: u32,
    captured_response_byte: u32,

    pub rrt: u64,

    #[serde(skip)]
    attributes: Vec<KeyVal>,
    #[serde(skip)]
    metrics: Vec<MetricKeyVal>,

    #[serde(skip)]
    pub is_on_blacklist: bool,

    is_reversed: bool,
}

impl NetSignInfo {
    fn merge(&mut self, other: &mut Self) {
        self.trace_ids.merge(std::mem::take(&mut other.trace_ids));
        if other.response_status != L7ResponseStatus::default() {
            self.response_status = other.response_status;
        }
        if !other.response_code.is_empty() {
            self.response_code = std::mem::take(&mut other.response_code);
        }
        if !other.cert_serial.is_empty() {
            self.cert_serial = std::mem::take(&mut other.cert_serial);
        }
        if !other.cert_validity.is_empty() {
            self.cert_validity = std::mem::take(&mut other.cert_validity);
        }
        if !other.ca_name.is_empty() {
            self.ca_name = std::mem::take(&mut other.ca_name);
        }
        if !other.signer_id.is_empty() {
            self.signer_id = std::mem::take(&mut other.signer_id);
        }
        if other.sig_present {
            self.sig_present = true;
            self.sig_len = other.sig_len;
        }
        if !other.biz_data.is_empty() {
            self.biz_data = std::mem::take(&mut other.biz_data);
        }
        self.captured_request_byte += other.captured_request_byte;
        self.captured_response_byte += other.captured_response_byte;
        if other.is_on_blacklist {
            self.is_on_blacklist = true;
        }
        self.attributes.append(&mut other.attributes);
        self.metrics.append(&mut other.metrics);
    }

    fn set_is_on_blacklist(&mut self, config: &LogParserConfig) {
        if let Some(t) = config.l7_log_blacklist_trie.get(&L7Protocol::NetSign) {
            self.is_on_blacklist = t.request_type.is_on_blacklist(&self.request_type)
                || t.endpoint.is_on_blacklist(&self.endpoint);
        }
    }

    fn build_attributes_metrics(&mut self, param_time_us: u64, extract_biz_data_enabled: bool) {
        if !self.biz_system.is_empty() {
            self.attributes.push(KeyVal {
                key: "biz_system".to_string(),
                val: self.biz_system.clone(),
            });
        }
        if extract_biz_data_enabled && !self.biz_data.is_empty() {
            self.attributes.push(KeyVal {
                key: "biz_data".to_string(),
                val: self.biz_data.clone(),
            });
        }
        if self.sig_present {
            self.attributes.push(KeyVal {
                key: "sig_present".to_string(),
                val: "true".to_string(),
            });
            self.attributes.push(KeyVal {
                key: "sig_len".to_string(),
                val: self.sig_len.to_string(),
            });
        }
        if !self.cert_id.is_empty() {
            self.attributes.push(KeyVal {
                key: "key_index".to_string(),
                val: self.cert_id.clone(),
            });
        }
        if !self.cert_serial.is_empty() {
            self.attributes.push(KeyVal {
                key: "cert_serial".to_string(),
                val: self.cert_serial.clone(),
            });
        }
        if !self.cert_validity.is_empty() {
            // cert_valid_days: (expiry_sec - now_sec) / 86400
            if let Ok(expiry_sec) = self.cert_validity.parse::<u64>() {
                let beijing = FixedOffset::east_opt(8 * 3600).unwrap();
                let dt: DateTime<FixedOffset> =
                    beijing.timestamp_opt(expiry_sec as i64, 0).unwrap();

                self.attributes.push(KeyVal {
                    key: "cert_validity".to_string(),
                    val: dt.format("%Y-%m-%d %H:%M:%S").to_string(),
                });

                let now_sec = param_time_us / 1_000_000;
                if expiry_sec > now_sec {
                    let days = (expiry_sec - now_sec) as f32 / 86400.0;
                    self.metrics.push(MetricKeyVal {
                        key: "cert_valid_days".to_string(),
                        val: days,
                    });
                }
            }
        }
        if !self.signer_id.is_empty() {
            self.attributes.push(KeyVal {
                key: "signer_id".to_string(),
                val: self.signer_id.clone(),
            });
        }
        if !self.ca_name.is_empty() {
            self.attributes.push(KeyVal {
                key: "ca_name".to_string(),
                val: self.ca_name.clone(),
            });
        }
        if !self.op_result.is_empty() {
            self.attributes.push(KeyVal {
                key: "op_result".to_string(),
                val: self.op_result.clone(),
            });
        }
    }
}

impl L7ProtocolInfoInterface for NetSignInfo {
    fn session_id(&self) -> Option<u32> {
        None
    }

    fn needs_session_aggregation(&self) -> bool {
        true
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::NetSignInfo(other) = other {
            self.merge(other);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::NetSign,
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn is_tls(&self) -> bool {
        false
    }

    fn get_endpoint(&self) -> Option<String> {
        if self.endpoint.is_empty() {
            None
        } else {
            Some(self.endpoint.clone())
        }
    }

    fn is_reversed(&self) -> bool {
        self.is_reversed
    }

    fn is_on_blacklist(&self) -> bool {
        self.is_on_blacklist
    }

    fn get_request_resource_length(&self) -> usize {
        0
    }
}

impl From<NetSignInfo> for L7ProtocolSendLog {
    fn from(f: NetSignInfo) -> Self {
        L7ProtocolSendLog {
            captured_request_byte: f.captured_request_byte,
            captured_response_byte: f.captured_response_byte,
            version: if f.version.is_empty() {
                None
            } else {
                Some(f.version)
            },
            req: L7Request {
                req_type: f.request_type,
                resource: f.request_resource,
                endpoint: f.endpoint,
                ..Default::default()
            },
            resp: L7Response {
                status: f.response_status,
                code: if f.response_code.is_empty() {
                    None
                } else {
                    f.response_code.parse::<i32>().ok()
                },
                exception: if f.response_code.is_empty()
                    || f.response_status == L7ResponseStatus::Ok
                {
                    String::new()
                } else {
                    f.response_code.clone()
                },
                ..Default::default()
            },
            trace_info: if f.trace_ids.is_default() {
                None
            } else {
                Some(TraceInfo {
                    trace_ids: f.trace_ids.into_sorted_vec(),
                    ..Default::default()
                })
            },
            ext_info: if f.attributes.is_empty() && f.metrics.is_empty() {
                None
            } else {
                Some(ExtendedInfo {
                    attributes: {
                        if f.attributes.is_empty() {
                            None
                        } else {
                            Some(f.attributes)
                        }
                    },
                    metrics: {
                        if f.metrics.is_empty() {
                            None
                        } else {
                            Some(f.metrics)
                        }
                    },
                    ..Default::default()
                })
            },
            biz_response_code: f.response_code,
            ..Default::default()
        }
    }
}

impl From<&NetSignInfo> for LogCache {
    fn from(info: &NetSignInfo) -> Self {
        LogCache {
            msg_type: info.msg_type,
            resp_status: info.response_status,
            on_blacklist: info.is_on_blacklist,
            ..Default::default()
        }
    }
}

#[derive(Default)]
pub struct NetSignLog {
    perf_stats: Vec<L7PerfStats>,
    parser: NetSignParser,
}

impl L7ProtocolParserInterface for NetSignLog {
    fn check_payload(&mut self, payload: &[u8], _param: &ParseParam) -> Option<LogMessageType> {
        self.parser.check_payload(payload)
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        self.perf_stats.clear();

        let Some(fields) = self.parser.parse_payload(payload) else {
            return Err(Error::L7ProtocolUnknown);
        };

        let mut info = NetSignInfo::default();

        // msg_type
        info.msg_type = if fields.operation == "request" {
            LogMessageType::Request
        } else {
            LogMessageType::Response
        };

        // endpoint = biz_system
        info.endpoint = fields.biz_system().to_string();
        info.request_resource = fields.processor_name.to_string();

        // request_type derived from processorName
        info.request_type = if fields.processor_name == PROCESSOR_SIGN {
            REQ_TYPE_SIGN.to_string()
        } else if fields.processor_name == PROCESSOR_VERIFY {
            REQ_TYPE_VERIFY.to_string()
        } else {
            fields.processor_name.clone()
        };

        // version
        info.version = fields.app_ver.clone();

        // trace_ids from bizData[0]
        if !fields.trace_id().is_empty() {
            info.trace_ids.push(
                BASE_FIELD_PRIORITY,
                std::borrow::Cow::Borrowed(fields.trace_id()),
            );
        }

        // response fields
        if info.msg_type == LogMessageType::Response {
            info.response_code = fields.result_code.clone();
            info.response_status = if fields.result_code == "1" {
                info.op_result = "success".to_string();
                L7ResponseStatus::Ok
            } else if fields.result_code.is_empty() {
                info.op_result = "unknown".to_string();
                L7ResponseStatus::default()
            } else {
                info.op_result = "failure".to_string();
                L7ResponseStatus::ServerError
            };
            info.cert_serial = fields.cert_serial.clone();
            info.cert_validity = fields.cert_validity.clone();
            info.ca_name = extract_cn(&fields.issuer_dn_ca);
            info.signer_id = fields.signer_id();
        } else {
            // request fields
            info.cert_id = fields.cert_id.clone();
        }

        // signature attributes (both req/resp can have signature)
        info.sig_present = fields.sig_present;
        info.sig_len = fields.sig_len;

        // biz_system
        info.biz_system = fields.biz_system().to_string();
        info.biz_data = fields.biz_data();

        // direction reversal check
        info.is_reversed = matches!(
            (info.msg_type, param.direction),
            (LogMessageType::Request, PacketDirection::ServerToClient)
                | (LogMessageType::Response, PacketDirection::ClientToServer)
        );

        // captured bytes
        set_captured_byte!(info, param);

        // blacklist
        if let Some(config) = param.parse_config {
            info.set_is_on_blacklist(config);
        }

        // build metrics (needs param.time for cert_valid_days)
        info.build_attributes_metrics(
            param.time,
            param.net_sign_parse_conf.extract_biz_data_enabled,
        );

        if param.parse_perf {
            let mut perf_stat = L7PerfStats::default();
            if let Some(stats) = info.perf_stats(param) {
                info.rrt = stats.rrt_sum;
                perf_stat.sequential_merge(&stats);
            }
            self.perf_stats.push(perf_stat);
        }

        if param.parse_log {
            Ok(L7ParseResult::Single(L7ProtocolInfo::NetSignInfo(info)))
        } else {
            Ok(L7ParseResult::None)
        }
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::NetSign
    }

    fn perf_stats(&mut self) -> Vec<L7PerfStats> {
        std::mem::take(&mut self.perf_stats)
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }
}

fn extract_cn(input: &str) -> String {
    let key = "CN=";
    if let Some(start) = input.find(key) {
        let start = start + key.len();
        let rest = &input[start..];
        if let Some(end) = rest.find(',') {
            rest[..end].to_string()
        } else {
            rest.to_string()
        }
    } else {
        String::new()
    }
}
