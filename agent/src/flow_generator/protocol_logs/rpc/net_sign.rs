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

    /// request_domain = processorName ("RAWSignProcessor" | "PBCRAWVerifyProcessor")
    #[serde(skip_serializing_if = "value_is_default")]
    pub request_domain: String,

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
        self.captured_request_byte += other.captured_request_byte;
        self.captured_response_byte += other.captured_response_byte;
        if other.is_on_blacklist {
            self.is_on_blacklist = true;
        }
        self.attributes.append(&mut other.attributes);
    }

    fn set_is_on_blacklist(&mut self, config: &LogParserConfig) {
        if let Some(t) = config.l7_log_blacklist_trie.get(&L7Protocol::NetSign) {
            self.is_on_blacklist = t.request_type.is_on_blacklist(&self.request_type)
                || t.endpoint.is_on_blacklist(&self.endpoint);
        }
    }

    fn build_attributes_metrics(&mut self, param_time_us: u64) {
        if !self.biz_system.is_empty() {
            self.attributes.push(KeyVal {
                key: "biz_system".to_string(),
                val: self.biz_system.clone(),
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
            self.attributes.push(KeyVal {
                key: "cert_validity".to_string(),
                val: self.cert_validity.clone(),
            });
            // cert_valid_days: (expiry_sec - now_sec) / 86400
            if let Ok(expiry_sec) = self.cert_validity.parse::<u64>() {
                let now_sec = param_time_us / 1_000_000;
                if expiry_sec > now_sec {
                    let days = ((expiry_sec - now_sec) as f32 / 86400.0 * 100.0).round() / 100.0;
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
                domain: f.request_domain,
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
                    attributes: Some(f.attributes),
                    metrics: Some(f.metrics),
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
        info.request_domain = fields.processor_name.to_string();

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
            info.response_status = if fields.result_code == "1" || fields.result_code == "11" {
                info.op_result = "success".to_string();
                L7ResponseStatus::Ok
            } else {
                info.op_result = "unknown".to_string();
                L7ResponseStatus::default()
            };
            info.cert_serial = fields.cert_serial.clone();
            info.cert_validity = fields.cert_validity.clone();
            info.ca_name = extract_cn(&fields.issuer_dn_ca);
            info.signer_id = fields.signer_id();
        } else {
            // request fields
            info.cert_id = fields.cert_id.clone();
            info.response_status = L7ResponseStatus::Ok;
        }

        // signature attributes (both req/resp can have signature)
        info.sig_present = fields.sig_present;
        info.sig_len = fields.sig_len;

        // biz_system
        info.biz_system = fields.biz_system().to_string();

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
        info.build_attributes_metrics(param.time);

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

#[cfg(test)]
mod tests {
    use enterprise_utils::l7::rpc::net_sign::NetSignParser;
    use public::l7_protocol::LogMessageType;

    // Real pcap payloads extracted from z:/deepflowio/net_sign/sign.pcap

    // Pkt#8: sign request  35480->5678
    const SIGN_REQ: &[u8] = &[
        2, 48, 48, 48, 48, 48, 48, 48, 48, 48, 52, 51, 56, 1, 1, 48, 48, 48, 48, 48, 48, 48, 48,
        48, 48, 49, 54, 82, 65, 87, 83, 105, 103, 110, 80, 114, 111, 99, 101, 115, 115, 111, 114,
        2, 1, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 55, 114, 101, 113, 117, 101, 115, 116, 6,
        2, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 49, 1, 10, 4, 48, 48, 48, 48, 48, 48, 48,
        48, 48, 50, 56, 51, 50, 48, 50, 54, 48, 50, 48, 53, 48, 51, 48, 51, 51, 51, 54, 53, 124,
        50, 48, 50, 54, 45, 48, 50, 45, 48, 53, 84, 49, 52, 58, 52, 52, 58, 53, 50, 124, 51, 49,
        51, 54, 53, 49, 48, 55, 49, 53, 48, 52, 124, 51, 49, 51, 54, 53, 57, 48, 48, 48, 48, 49,
        54, 124, 49, 124, 67, 78, 89, 50, 50, 50, 50, 51, 51, 46, 55, 57, 124, 66, 69, 80, 83, 124,
        50, 48, 50, 54, 48, 50, 48, 53, 48, 50, 55, 57, 54, 50, 49, 51, 124, 231, 187, 181, 233,
        152, 179, 229, 155, 189, 228, 188, 151, 231, 145, 158, 229, 190, 183, 231, 167, 145, 230,
        138, 128, 230, 156, 137, 233, 153, 144, 229, 133, 172, 229, 143, 184, 124, 55, 56, 50, 50,
        48, 49, 48, 48, 48, 54, 48, 51, 56, 52, 50, 55, 52, 124, 51, 49, 51, 54, 53, 49, 48, 55,
        49, 53, 49, 50, 124, 51, 49, 51, 54, 53, 49, 48, 55, 49, 53, 49, 50, 124, 51, 49, 51, 54,
        53, 57, 48, 48, 55, 48, 52, 50, 124, 231, 187, 181, 233, 152, 179, 229, 155, 189, 228, 188,
        151, 231, 145, 158, 229, 190, 183, 231, 167, 145, 230, 138, 128, 230, 156, 137, 233, 153,
        144, 229, 133, 172, 229, 143, 184, 124, 48, 55, 48, 52, 49, 55, 48, 48, 48, 48, 48, 57, 51,
        52, 124, 51, 49, 51, 54, 53, 57, 48, 48, 55, 48, 52, 50, 124, 67, 78, 89, 50, 50, 50, 50,
        51, 51, 46, 55, 57, 124, 65, 49, 48, 48, 124, 48, 50, 49, 48, 50, 124, 17, 1, 48, 48, 48,
        48, 48, 48, 48, 48, 48, 48, 49, 48, 50, 48, 54, 49, 53, 54, 53, 53, 54, 48, 52, 1, 48, 48,
        48, 48, 48, 48, 48, 48, 48, 48, 48, 51, 49, 46, 48, 41, 1, 48, 48, 48, 48, 48, 48, 48, 48,
        48, 48, 50, 48, 64, 189, 0, 21, 99, 8, 95, 195, 81, 101, 50, 158, 161, 255, 92, 94, 203,
        219, 190, 239,
    ];

    // Pkt#10: sign response  5678->35480
    const SIGN_RESP: &[u8] = &[
        2, 48, 48, 48, 48, 48, 48, 48, 48, 48, 49, 56, 51, 1, 1, 48, 48, 48, 48, 48, 48, 48, 48,
        48, 48, 49, 54, 82, 65, 87, 83, 105, 103, 110, 80, 114, 111, 99, 101, 115, 115, 111, 114,
        2, 1, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 56, 114, 101, 115, 112, 111, 110, 115,
        101, 4, 2, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 49, 49, 6, 2, 48, 48, 48, 48, 48,
        48, 48, 48, 48, 48, 48, 49, 1, 11, 4, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 55, 48, 48,
        68, 2, 32, 58, 176, 161, 68, 96, 108, 102, 173, 146, 214, 18, 101, 209, 164, 15, 39, 145,
        180, 246, 228, 235, 33, 5, 230, 252, 172, 204, 78, 205, 121, 186, 77, 2, 32, 68, 36, 2,
        136, 187, 249, 239, 155, 176, 111, 238, 59, 69, 219, 28, 11, 20, 93, 121, 249, 1, 192, 148,
        30, 153, 73, 195, 123, 52, 78, 22, 119, 52, 1, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        51, 49, 46, 48,
    ];

    // Pkt#20: verify request  49552->5678
    const VERIFY_REQ: &[u8] = &[
        2, 48, 48, 48, 48, 48, 48, 48, 48, 48, 52, 48, 54, 1, 1, 48, 48, 48, 48, 48, 48, 48, 48,
        48, 48, 50, 49, 80, 66, 67, 82, 65, 87, 86, 101, 114, 105, 102, 121, 80, 114, 111, 99, 101,
        115, 115, 111, 114, 2, 1, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 55, 114, 101, 113,
        117, 101, 115, 116, 6, 2, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 49, 1, 10, 4, 48, 48,
        48, 48, 48, 48, 48, 48, 48, 49, 53, 50, 50, 48, 50, 54, 48, 50, 48, 53, 52, 50, 53, 56, 53,
        52, 49, 56, 124, 50, 48, 50, 54, 45, 48, 50, 45, 48, 53, 84, 49, 52, 58, 52, 52, 58, 53,
        50, 124, 48, 48, 48, 48, 124, 48, 48, 48, 48, 124, 51, 49, 51, 54, 53, 49, 48, 55, 49, 53,
        48, 52, 124, 51, 49, 51, 54, 53, 49, 48, 55, 49, 53, 48, 52, 124, 66, 69, 80, 83, 124, 50,
        48, 50, 54, 48, 50, 48, 53, 48, 51, 48, 51, 51, 51, 54, 53, 124, 51, 49, 51, 54, 53, 49,
        48, 55, 49, 53, 48, 52, 124, 98, 101, 112, 115, 46, 49, 50, 49, 46, 48, 48, 49, 46, 48, 49,
        124, 80, 82, 48, 51, 124, 67, 85, 49, 73, 48, 48, 48, 48, 124, 50, 48, 50, 54, 45, 48, 50,
        45, 48, 53, 124, 48, 53, 124, 11, 4, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 55, 49, 48,
        69, 2, 32, 10, 19, 192, 99, 49, 88, 126, 208, 205, 103, 76, 106, 12, 128, 246, 244, 234,
        105, 97, 55, 92, 65, 151, 90, 243, 152, 122, 143, 90, 246, 73, 130, 2, 33, 0, 159, 232,
        130, 131, 166, 14, 214, 218, 26, 106, 239, 253, 137, 155, 97, 217, 98, 220, 112, 249, 20,
        197, 169, 177, 163, 254, 76, 100, 87, 2, 107, 159, 17, 1, 48, 48, 48, 48, 48, 48, 48, 48,
        48, 48, 48, 52, 48, 48, 48, 48, 15, 2, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 49, 49,
        52, 1, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 51, 49, 46, 48, 41, 1, 48, 48, 48, 48,
        48, 48, 48, 48, 48, 48, 50, 48, 64, 189, 0, 21, 99, 8, 95, 195, 81, 101, 50, 158, 161, 255,
        92, 94, 203, 219, 190, 239,
    ];

    // Pkt#22: verify response  5678->49552
    const VERIFY_RESP: &[u8] = &[
        2, 48, 48, 48, 48, 48, 48, 48, 48, 48, 52, 51, 53, 1, 1, 48, 48, 48, 48, 48, 48, 48, 48,
        48, 48, 50, 49, 80, 66, 67, 82, 65, 87, 86, 101, 114, 105, 102, 121, 80, 114, 111, 99, 101,
        115, 115, 111, 114, 2, 1, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 56, 114, 101, 115,
        112, 111, 110, 115, 101, 4, 2, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 49, 49, 6, 2,
        48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 49, 1, 17, 1, 48, 48, 48, 48, 48, 48, 48, 48,
        48, 48, 55, 53, 67, 61, 99, 110, 44, 79, 61, 67, 70, 67, 65, 32, 67, 83, 32, 79, 67, 65,
        49, 49, 44, 79, 85, 61, 67, 78, 65, 80, 83, 44, 79, 85, 61, 69, 110, 116, 101, 114, 112,
        114, 105, 115, 101, 115, 44, 67, 78, 61, 48, 52, 49, 64, 90, 48, 48, 48, 48, 64, 67, 78,
        65, 80, 83, 78, 80, 67, 64, 48, 48, 48, 48, 48, 48, 48, 49, 52, 1, 48, 48, 48, 48, 48, 48,
        48, 48, 48, 48, 48, 51, 49, 46, 48, 20, 1, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 55, 53,
        67, 61, 99, 110, 44, 79, 61, 67, 70, 67, 65, 32, 67, 83, 32, 79, 67, 65, 49, 49, 44, 79,
        85, 61, 67, 78, 65, 80, 83, 44, 79, 85, 61, 69, 110, 116, 101, 114, 112, 114, 105, 115,
        101, 115, 44, 67, 78, 61, 48, 52, 49, 64, 90, 48, 48, 48, 48, 64, 67, 78, 65, 80, 83, 78,
        80, 67, 64, 48, 48, 48, 48, 48, 48, 48, 49, 21, 1, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        49, 48, 50, 48, 53, 57, 48, 57, 55, 56, 49, 52, 22, 1, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        48, 54, 55, 67, 61, 67, 78, 44, 79, 61, 67, 104, 105, 110, 97, 32, 70, 105, 110, 97, 110,
        99, 105, 97, 108, 32, 67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 105, 111, 110, 32, 65,
        117, 116, 104, 111, 114, 105, 116, 121, 44, 67, 78, 61, 67, 70, 67, 65, 32, 67, 83, 32, 83,
        77, 50, 32, 79, 67, 65, 49, 49, 23, 1, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 49, 48, 49,
        54, 57, 52, 48, 52, 57, 56, 49, 53, 24, 1, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 49, 48,
        49, 55, 57, 52, 53, 56, 53, 53, 57, 57,
    ];

    #[test]
    fn test_check_sign_req_pcap() {
        let parser = NetSignParser;
        assert_eq!(
            parser.check_payload(SIGN_REQ),
            Some(LogMessageType::Request)
        );
    }

    #[test]
    fn test_check_sign_resp_pcap() {
        let parser = NetSignParser;
        assert_eq!(
            parser.check_payload(SIGN_RESP),
            Some(LogMessageType::Response)
        );
    }

    #[test]
    fn test_check_verify_req_pcap() {
        let parser = NetSignParser;
        assert_eq!(
            parser.check_payload(VERIFY_REQ),
            Some(LogMessageType::Request)
        );
    }

    #[test]
    fn test_check_verify_resp_pcap() {
        let parser = NetSignParser;
        assert_eq!(
            parser.check_payload(VERIFY_RESP),
            Some(LogMessageType::Response)
        );
    }

    #[test]
    fn test_parse_sign_req_pcap() {
        let parser = NetSignParser;
        let f = parser.parse_payload(SIGN_REQ).unwrap();
        assert_eq!(f.processor_name, "RAWSignProcessor");
        assert_eq!(f.operation, "request");
        assert_eq!(f.trace_id(), "2026020503033365");
        assert_eq!(f.biz_system(), "BEPS");
        // signature present in sign request
        assert!(f.sig_present);
    }

    #[test]
    fn test_parse_sign_resp_pcap() {
        let parser = NetSignParser;
        let f = parser.parse_payload(SIGN_RESP).unwrap();
        assert_eq!(f.processor_name, "RAWSignProcessor");
        assert_eq!(f.operation, "response");
        assert_eq!(f.result_code, "1");
        assert!(f.sig_present);
    }

    #[test]
    fn test_parse_verify_req_pcap() {
        let parser = NetSignParser;
        let f = parser.parse_payload(VERIFY_REQ).unwrap();
        assert_eq!(f.processor_name, "PBCRAWVerifyProcessor");
        assert_eq!(f.operation, "request");
        assert_eq!(f.trace_id(), "2026020542585418");
        assert_eq!(f.biz_system(), "BEPS");
        assert!(f.sig_present);
    }

    #[test]
    fn test_parse_verify_resp_pcap() {
        let parser = NetSignParser;
        let f = parser.parse_payload(VERIFY_RESP).unwrap();
        assert_eq!(f.processor_name, "PBCRAWVerifyProcessor");
        assert_eq!(f.operation, "response");
        assert_eq!(f.result_code, "1");
        assert_eq!(f.cert_serial, "2059097814");
        assert_eq!(f.cert_validity, "1794585599");
        assert!(f.issuer_dn_ca.contains("CFCA CS SM2 OCA11"));
    }

    #[test]
    fn test_reject_random_data() {
        let parser = NetSignParser;
        assert!(parser.check_payload(&[0u8; 100]).is_none());
        assert!(parser.check_payload(b"GET / HTTP/1.1\r\n").is_none());
    }
}
