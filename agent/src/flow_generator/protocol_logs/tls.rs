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

use std::fmt::Display;

use chrono::{DateTime, Utc};
use serde::Serialize;

use super::pb_adapter::{
    ExtendedInfo, KeyVal, L7ProtocolSendLog, L7Request, L7Response, MetricKeyVal,
};
use super::{set_captured_byte, value_is_default, AppProtoHead, L7ResponseStatus};
use crate::config::handler::LogParserConfig;
use crate::{
    common::{
        enums::IpProtocol,
        flow::{L7PerfStats, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, LogCache, ParseParam},
        meta_packet::ApplicationFlags,
        Timestamp,
    },
    flow_generator::error::{Error, Result},
};
use l7::tls::TlsHeader;
use public::l7_protocol::{L7Protocol, LogMessageType};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum CipherSuite {
    Named(&'static str),
    Unknown(u16),
}

impl Default for CipherSuite {
    fn default() -> Self {
        Self::Unknown(0)
    }
}

impl Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Named(c) => f.write_str(c),
            Self::Unknown(c) => write!(f, "Unknown(0x{:x})", c),
        }
    }
}

impl From<u16> for CipherSuite {
    fn from(cipher_suite: u16) -> Self {
        match cipher_suite {
            0x0 => CipherSuite::Named("TLS_NULL_WITH_NULL_NULL"),
            0x1 => CipherSuite::Named("TLS_RSA_WITH_NULL_MD5"),
            0x2 => CipherSuite::Named("TLS_RSA_WITH_NULL_SHA"),
            0x03 => CipherSuite::Named("TLS_RSA_EXPORT_WITH_RC4_40_MD5"),
            0x06 => CipherSuite::Named("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"),
            0x07 => CipherSuite::Named("TLS_RSA_WITH_IDEA_CBC_SHA"),
            0x08 => CipherSuite::Named("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"),
            0x09 => CipherSuite::Named("TLS_RSA_WITH_DES_CBC_SHA"),
            0x0B => CipherSuite::Named("TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"),
            0x0C => CipherSuite::Named("TLS_DH_DSS_WITH_DES_CBC_SHA"),
            0x0D => CipherSuite::Named("TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"),
            0x0E => CipherSuite::Named("TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"),
            0x0F => CipherSuite::Named("TLS_DH_RSA_WITH_DES_CBC_SHA"),
            0x10 => CipherSuite::Named("TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"),
            0x11 => CipherSuite::Named("TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"),
            0x12 => CipherSuite::Named("TLS_DHE_DSS_WITH_DES_CBC_SHA"),
            0x13 => CipherSuite::Named("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"),
            0x14 => CipherSuite::Named("TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"),
            0x15 => CipherSuite::Named("TLS_DHE_RSA_WITH_DES_CBC_SHA"),
            0x16 => CipherSuite::Named("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"),
            0x17 => CipherSuite::Named("TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"),
            0x19 => CipherSuite::Named("TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"),
            0x1A => CipherSuite::Named("TLS_DH_anon_WITH_DES_CBC_SHA"),
            0x3b => CipherSuite::Named("TLS_RSA_WITH_NULL_SHA256"),
            0x4 => CipherSuite::Named("TLS_RSA_WITH_RC4_128_MD5"),
            0x5 => CipherSuite::Named("TLS_RSA_WITH_RC4_128_SHA"),
            0xa => CipherSuite::Named("TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
            0x2f => CipherSuite::Named("TLS_RSA_WITH_AES_128_CBC_SHA"),
            0x35 => CipherSuite::Named("TLS_RSA_WITH_AES_256_CBC_SHA"),
            0x3c => CipherSuite::Named("TLS_RSA_WITH_AES_128_CBC_SHA256"),
            0x3d => CipherSuite::Named("TLS_RSA_WITH_AES_256_CBC_SHA256"),
            0x30 => CipherSuite::Named("TLS_DH_DSS_WITH_AES_128_CBC_SHA"),
            0x31 => CipherSuite::Named("TLS_DH_RSA_WITH_AES_128_CBC_SHA"),
            0x32 => CipherSuite::Named("TLS_DHE_DSS_WITH_AES_128_CBC_SHA"),
            0x33 => CipherSuite::Named("TLS_DHE_RSA_WITH_AES_128_CBC_SHA"),
            0x36 => CipherSuite::Named("TLS_DH_DSS_WITH_AES_256_CBC_SHA"),
            0x37 => CipherSuite::Named("TLS_DH_RSA_WITH_AES_256_CBC_SHA"),
            0x38 => CipherSuite::Named("TLS_DHE_DSS_WITH_AES_256_CBC_SHA"),
            0x39 => CipherSuite::Named("TLS_DHE_RSA_WITH_AES_256_CBC_SHA"),
            0x3E => CipherSuite::Named("TLS_DH_DSS_WITH_AES_128_CBC_SHA256"),
            0x3F => CipherSuite::Named("TLS_DH_RSA_WITH_AES_128_CBC_SHA256"),
            0x40 => CipherSuite::Named("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"),
            0x67 => CipherSuite::Named("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"),
            0x68 => CipherSuite::Named("TLS_DH_DSS_WITH_AES_256_CBC_SHA256"),
            0x69 => CipherSuite::Named("TLS_DH_RSA_WITH_AES_256_CBC_SHA256"),
            0x6A => CipherSuite::Named("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"),
            0x6B => CipherSuite::Named("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"),
            0x18 => CipherSuite::Named("TLS_DH_anon_WITH_RC4_128_MD5"),
            0x1B => CipherSuite::Named("TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"),
            0x34 => CipherSuite::Named("TLS_DH_anon_WITH_AES_128_CBC_SHA"),
            0x3A => CipherSuite::Named("TLS_DH_anon_WITH_AES_256_CBC_SHA"),
            0x6C => CipherSuite::Named("TLS_DH_anon_WITH_AES_128_CBC_SHA256"),
            0x6D => CipherSuite::Named("TLS_DH_anon_WITH_AES_256_CBC_SHA256"),
            0x1301 => CipherSuite::Named("TLS_AES_128_GCM_SHA256"),
            0x1302 => CipherSuite::Named("TLS_AES_256_GCM_SHA256"),
            0x1303 => CipherSuite::Named("TLS_CHACHA20_POLY1305_SHA256"),
            0x1304 => CipherSuite::Named("TLS_AES_128_CCM_SHA256"),
            0x1305 => CipherSuite::Named("TLS_AES_128_CCM_8_SHA256"),
            0xC001 => CipherSuite::Named("TLS_ECDH_ECDSA_WITH_NULL_SHA"),
            0xC002 => CipherSuite::Named("TLS_ECDH_ECDSA_WITH_RC4_128_SHA"),
            0xC003 => CipherSuite::Named("TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"),
            0xC004 => CipherSuite::Named("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"),
            0xC005 => CipherSuite::Named("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"),
            0xC006 => CipherSuite::Named("TLS_ECDHE_ECDSA_WITH_NULL_SHA"),
            0xC007 => CipherSuite::Named("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"),
            0xC008 => CipherSuite::Named("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"),
            0xC009 => CipherSuite::Named("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"),
            0xC00A => CipherSuite::Named("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"),
            0xC00B => CipherSuite::Named("TLS_ECDH_RSA_WITH_NULL_SHA"),
            0xC00C => CipherSuite::Named("TLS_ECDH_RSA_WITH_RC4_128_SHA"),
            0xC00D => CipherSuite::Named("TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"),
            0xC00E => CipherSuite::Named("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"),
            0xC00F => CipherSuite::Named("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"),
            0xC010 => CipherSuite::Named("TLS_ECDHE_RSA_WITH_NULL_SHA"),
            0xC011 => CipherSuite::Named("TLS_ECDHE_RSA_WITH_RC4_128_SHA"),
            0xC012 => CipherSuite::Named("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"),
            0xC013 => CipherSuite::Named("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
            0xC014 => CipherSuite::Named("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
            0xC015 => CipherSuite::Named("TLS_ECDH_anon_WITH_NULL_SHA"),
            0xC016 => CipherSuite::Named("TLS_ECDH_anon_WITH_RC4_128_SHA"),
            0xC017 => CipherSuite::Named("TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"),
            0xC018 => CipherSuite::Named("TLS_ECDH_anon_WITH_AES_128_CBC_SHA"),
            0xC019 => CipherSuite::Named("TLS_ECDH_anon_WITH_AES_256_CBC_SHA"),
            0xC09C => CipherSuite::Named("TLS_RSA_WITH_AES_128_CCM"),
            0xC09D => CipherSuite::Named("TLS_RSA_WITH_AES_256_CCM"),
            0xC09E => CipherSuite::Named("TLS_DHE_RSA_WITH_AES_128_CCM"),
            0xC09F => CipherSuite::Named("TLS_DHE_RSA_WITH_AES_256_CCM"),
            0xC0A0 => CipherSuite::Named("TLS_RSA_WITH_AES_128_CCM_8"),
            0xC0A1 => CipherSuite::Named("TLS_RSA_WITH_AES_256_CCM_8"),
            0xC0A2 => CipherSuite::Named("TLS_DHE_RSA_WITH_AES_128_CCM_8"),
            0xC0A3 => CipherSuite::Named("TLS_DHE_RSA_WITH_AES_256_CCM_8"),
            0xC0A4 => CipherSuite::Named("TLS_PSK_WITH_AES_128_CCM"),
            0xC0A5 => CipherSuite::Named("TLS_PSK_WITH_AES_256_CCM"),
            0xC0A6 => CipherSuite::Named("TLS_DHE_PSK_WITH_AES_128_CCM"),
            0xC0A7 => CipherSuite::Named("TLS_DHE_PSK_WITH_AES_256_CCM"),
            0xC0A8 => CipherSuite::Named("TLS_PSK_WITH_AES_128_CCM_8"),
            0xC0A9 => CipherSuite::Named("TLS_PSK_WITH_AES_256_CCM_8"),
            0xC0AA => CipherSuite::Named("TLS_PSK_DHE_WITH_AES_128_CCM_8"),
            0xC0AB => CipherSuite::Named("TLS_PSK_DHE_WITH_AES_256_CCM_8"),
            0xC023 => CipherSuite::Named("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"),
            0xC024 => CipherSuite::Named("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"),
            0xC025 => CipherSuite::Named("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"),
            0xC026 => CipherSuite::Named("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"),
            0xC027 => CipherSuite::Named("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"),
            0xC028 => CipherSuite::Named("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"),
            0xC029 => CipherSuite::Named("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"),
            0xC02A => CipherSuite::Named("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"),
            0xC02B => CipherSuite::Named("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
            0xC02C => CipherSuite::Named("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
            0xC02D => CipherSuite::Named("TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"),
            0xC02E => CipherSuite::Named("TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"),
            0xC02F => CipherSuite::Named("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
            0xC030 => CipherSuite::Named("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
            0xC031 => CipherSuite::Named("TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"),
            0xC032 => CipherSuite::Named("TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"),
            _ => CipherSuite::Unknown(cipher_suite),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Version {
    Named(&'static str),
    Unknown(u16),
}

impl Version {
    fn is_empty(&self) -> bool {
        match self {
            Self::Unknown(v) => *v == 0,
            _ => false,
        }
    }
}

impl Default for Version {
    fn default() -> Self {
        Self::Unknown(0)
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Named(c) => f.write_str(c),
            Self::Unknown(c) => write!(f, "Unknown(0x{:x})", c),
        }
    }
}

impl From<u16> for Version {
    fn from(v: u16) -> Self {
        match v {
            0x304 => Self::Named("1.3"),
            0x303 => Self::Named("1.2"),
            0x302 => Self::Named("1.1"),
            0x301 => Self::Named("1.0"),
            _ => Self::Unknown(v),
        }
    }
}

#[derive(Serialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct TlsInfo {
    pub handshake_protocol: String,
    #[serde(rename = "version", skip_serializing_if = "value_is_default")]
    pub version: Version,
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub request_resource: String,
    #[serde(rename = "request_type", skip_serializing_if = "value_is_default")]
    pub request_type: String,
    #[serde(rename = "request_domain", skip_serializing_if = "value_is_default")]
    pub request_domain: String,

    #[serde(rename = "response_status")]
    pub status: L7ResponseStatus,
    #[serde(rename = "response_result", skip_serializing_if = "value_is_default")]
    pub response_result: String,

    // Attribute
    #[serde(skip)]
    pub cipher_suite: Option<CipherSuite>,
    #[serde(skip)]
    pub server_cert_not_before: Timestamp,
    #[serde(skip)]
    pub server_cert_not_after: Timestamp,
    #[serde(skip)]
    pub client_cert_not_before: Timestamp,
    #[serde(skip)]
    pub client_cert_not_after: Timestamp,

    captured_request_byte: u32,
    captured_response_byte: u32,

    msg_type: LogMessageType,
    rrt: u64,
    tls_rtt: u64,
    cal_tls_rtt: bool,

    #[serde(skip)]
    is_on_blacklist: bool,
}

impl L7ProtocolInfoInterface for TlsInfo {
    fn session_id(&self) -> Option<u32> {
        // 0xff is a random non-zero value for tls rtt calculation
        // Calling `info.perf_stats` with cal_tls_rtt `on` or `off` will generate two different results
        if self.cal_tls_rtt {
            Some(0xff)
        } else {
            None
        }
    }

    fn merge_log(
        &mut self,
        other: &mut crate::common::l7_protocol_info::L7ProtocolInfo,
    ) -> Result<()> {
        if let L7ProtocolInfo::TlsInfo(other) = other {
            self.merge(other);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::TLS,
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn is_tls(&self) -> bool {
        true
    }

    fn get_request_domain(&self) -> String {
        self.request_domain.clone()
    }

    fn get_request_resource_length(&self) -> usize {
        self.request_resource.len()
    }

    fn is_on_blacklist(&self) -> bool {
        self.is_on_blacklist
    }
}

impl TlsInfo {
    pub fn merge(&mut self, other: &mut Self) {
        if other.is_on_blacklist {
            self.is_on_blacklist = other.is_on_blacklist;
        }
        match other.msg_type {
            LogMessageType::Request => {
                std::mem::swap(&mut self.handshake_protocol, &mut other.handshake_protocol);
                std::mem::swap(&mut self.request_resource, &mut other.request_resource);
                std::mem::swap(&mut self.request_type, &mut other.request_type);
                std::mem::swap(&mut self.request_domain, &mut other.request_domain);
                std::mem::swap(
                    &mut self.client_cert_not_after,
                    &mut other.client_cert_not_after,
                );
                std::mem::swap(
                    &mut self.client_cert_not_before,
                    &mut other.client_cert_not_before,
                );
                self.captured_request_byte = other.captured_request_byte;
            }
            LogMessageType::Response => {
                self.status = other.status;
                std::mem::swap(&mut self.response_result, &mut other.response_result);
                std::mem::swap(&mut self.cipher_suite, &mut other.cipher_suite);
                std::mem::swap(&mut self.rrt, &mut other.rrt);
                std::mem::swap(&mut self.tls_rtt, &mut other.tls_rtt);
                std::mem::swap(&mut self.version, &mut other.version);
                std::mem::swap(
                    &mut self.server_cert_not_after,
                    &mut other.server_cert_not_after,
                );
                std::mem::swap(
                    &mut self.server_cert_not_before,
                    &mut other.server_cert_not_before,
                );
                self.captured_response_byte = other.captured_response_byte;
            }
            _ => {}
        }
    }

    fn set_is_on_blacklist(&mut self, config: &LogParserConfig) {
        if let Some(t) = config.l7_log_blacklist_trie.get(&L7Protocol::TLS) {
            self.is_on_blacklist = t.request_resource.is_on_blacklist(&self.request_resource)
                || t.request_type.is_on_blacklist(&self.request_type)
                || t.request_domain.is_on_blacklist(&self.request_domain);
        }
    }
}

impl From<TlsInfo> for L7ProtocolSendLog {
    fn from(f: TlsInfo) -> Self {
        let now = Utc::now().timestamp();
        let mut attributes = vec![];
        let mut metrics = vec![];
        if let Some(cipher_suite) = f.cipher_suite {
            attributes.push(KeyVal {
                key: "cipher_suite".to_string(),
                val: cipher_suite.to_string(),
            });
        }
        if !f.client_cert_not_before.is_zero() {
            attributes.push(KeyVal {
                key: "client_cert_not_before".to_string(),
                val: DateTime::from_timestamp(f.client_cert_not_before.as_secs() as i64, 0)
                    .unwrap()
                    .to_string(),
            });
        }
        if !f.client_cert_not_after.is_zero() {
            let valid_days =
                (f.client_cert_not_after.as_secs() as i64 - now) as f32 / Self::SECONDS_PER_DAY;
            attributes.push(KeyVal {
                key: "client_cert_not_after".to_string(),
                val: DateTime::from_timestamp(f.client_cert_not_after.as_secs() as i64, 0)
                    .unwrap()
                    .to_string(),
            });
            metrics.push(MetricKeyVal {
                key: "client_cert_valid_days".to_string(),
                val: valid_days,
            });
        }
        if !f.server_cert_not_before.is_zero() {
            attributes.push(KeyVal {
                key: "server_cert_not_before".to_string(),
                val: DateTime::from_timestamp(f.server_cert_not_before.as_secs() as i64, 0)
                    .unwrap()
                    .to_string(),
            });
        }
        if !f.server_cert_not_after.is_zero() {
            let valid_days =
                (f.server_cert_not_after.as_secs() as i64 - now) as f32 / Self::SECONDS_PER_DAY;
            attributes.push(KeyVal {
                key: "server_cert_not_after".to_string(),
                val: DateTime::from_timestamp(f.server_cert_not_after.as_secs() as i64, 0)
                    .unwrap()
                    .to_string(),
            });
            metrics.push(MetricKeyVal {
                key: "server_cert_valid_days".to_string(),
                val: valid_days,
            });
        }
        let log = L7ProtocolSendLog {
            captured_request_byte: f.captured_request_byte,
            captured_response_byte: f.captured_response_byte,
            req: L7Request {
                resource: f.request_resource,
                domain: f.request_domain,
                req_type: if f.request_type.is_empty() {
                    f.handshake_protocol
                } else {
                    f.request_type
                },
                ..Default::default()
            },
            resp: L7Response {
                result: f.response_result,
                status: f.status,
                ..Default::default()
            },
            version: if !f.version.is_empty() {
                Some(f.version.to_string())
            } else {
                None
            },
            ext_info: if attributes.len() > 0 || metrics.len() > 0 {
                Some(ExtendedInfo {
                    attributes: if attributes.len() > 0 {
                        Some(attributes)
                    } else {
                        None
                    },
                    metrics: if metrics.len() > 0 {
                        Some(metrics)
                    } else {
                        None
                    },
                    ..Default::default()
                })
            } else {
                None
            },
            flags: ApplicationFlags::TLS.bits(),
            ..Default::default()
        };

        return log;
    }
}

impl From<&TlsInfo> for LogCache {
    fn from(info: &TlsInfo) -> Self {
        LogCache {
            msg_type: info.msg_type,
            resp_status: info.status,
            on_blacklist: info.is_on_blacklist,
            ..Default::default()
        }
    }
}

#[derive(Default)]
pub struct TlsLog {
    change_cipher_spec_count: u8,
    is_change_cipher_spec: bool,
    perf_stats: Option<L7PerfStats>,
}

//解析器接口实现
impl L7ProtocolParserInterface for TlsLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> Option<LogMessageType> {
        if !param.ebpf_type.is_raw_protocol() || param.l4_protocol != IpProtocol::TCP {
            return None;
        }

        if payload.len() < TlsHeader::HEADER_LEN {
            return None;
        }

        let tls_header = TlsHeader::new(payload);
        if tls_header.is_handshake() && tls_header.is_client_hello() {
            Some(LogMessageType::Request)
        } else {
            None
        }
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        let mut info = TlsInfo::default();
        self.parse(payload, &mut info, param)?;

        if let Some(config) = param.parse_config {
            info.set_is_on_blacklist(config);
        }
        if let Some(perf_stats) = self.perf_stats.as_mut() {
            // Triggered by Client Hello and the last Change cipher spec
            if info.cal_tls_rtt {
                if let Some(stats) = info.perf_stats(param) {
                    info.tls_rtt = stats.rrt_sum;
                    perf_stats.update_tls_rtt(stats.rrt_sum);
                }
                info.cal_tls_rtt = false;
            }

            // In some scenarios, the last Change cipher spec does not have a corresponding response,
            // and this is directly set to be reported by session
            if self.is_change_cipher_spec && info.msg_type == LogMessageType::Request {
                info.status = L7ResponseStatus::Ok;
                info.msg_type = LogMessageType::Session
            }

            // This `perf_stats` is called with info.cal_tls_rtt == false
            if let Some(stats) = info.perf_stats(param) {
                info.rrt = stats.rrt_sum;
                perf_stats.sequential_merge(&stats);
            }
        }
        if param.parse_log {
            Ok(L7ParseResult::Single(L7ProtocolInfo::TlsInfo(info)))
        } else {
            Ok(L7ParseResult::None)
        }
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::TLS
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

impl TlsLog {
    const CHNAGE_CIPHER_SPEC_LIMIT: u8 = 2;

    fn parse(&mut self, payload: &[u8], info: &mut TlsInfo, param: &ParseParam) -> Result<()> {
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };

        let mut tls_headers = vec![];
        let mut offset = 0;
        while offset + TlsHeader::HEADER_LEN <= payload.len() {
            let header = TlsHeader::new(&payload[offset..]);
            if header.is_last() {
                tls_headers.push(header);
                break;
            }
            if header.is_unsupport_content_type() {
                return Err(Error::TlsLogParseFailed(format!(
                    "Content type unsupport {}",
                    header.content_type()
                )));
            }
            offset += header.next();
            tls_headers.push(header);
        }

        if tls_headers.len() == 0 {
            return Err(Error::TlsLogParseFailed(format!("Invalid payload")));
        }

        match param.direction {
            PacketDirection::ClientToServer => {
                match Version::from(tls_headers[0].version()) {
                    Version::Unknown(v) => {
                        return Err(Error::TlsLogParseFailed(format!(
                            "Unknown tls version 0x{:x}",
                            v
                        )))
                    }
                    v => info.version = v,
                }
                info.msg_type = LogMessageType::Request;
                tls_headers.iter().for_each(|h| {
                    if h.is_client_hello() {
                        info.cal_tls_rtt = true;
                    }
                    if h.is_alert() {
                        info.status = L7ResponseStatus::ClientError;
                        info.msg_type = LogMessageType::Session;
                    }
                    if h.is_change_cipher_spec() {
                        self.change_cipher_spec_count += 1;
                        self.is_change_cipher_spec = true;
                        if self.change_cipher_spec_count >= Self::CHNAGE_CIPHER_SPEC_LIMIT {
                            self.change_cipher_spec_count = 0;
                            info.cal_tls_rtt = true;
                        }
                    } else {
                        self.is_change_cipher_spec = false;
                    }

                    if info.handshake_protocol.is_empty() && h.handshake_headers.len() > 0 {
                        info.handshake_protocol = h.handshake_headers[0].to_string();
                    }

                    if let Some(server_name) = h.domain_name() {
                        info.request_domain = server_name.clone();
                        info.request_resource = server_name;
                    }

                    if let Some(v) = h.validity() {
                        if info.client_cert_not_after.is_zero() {
                            info.client_cert_not_before = Timestamp::from(v.0);
                            info.client_cert_not_after = Timestamp::from(v.1);
                        }
                    }
                });

                info.request_type = tls_headers
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<String>>()
                    .join("|")
                    .to_string();
            }
            PacketDirection::ServerToClient => {
                info.status = L7ResponseStatus::Ok;
                info.msg_type = LogMessageType::Response;

                if info.version.is_empty() {
                    match Version::from(tls_headers[0].version()) {
                        Version::Unknown(v) => {
                            return Err(Error::TlsLogParseFailed(format!(
                                "Unknown tls version 0x{:x}",
                                v
                            )))
                        }
                        v => info.version = v,
                    }
                }

                tls_headers.iter().for_each(|h| {
                    if h.is_alert() {
                        info.status = L7ResponseStatus::ServerError;
                        info.msg_type = LogMessageType::Session;
                    }

                    if let Some(v) = h.supported_version() {
                        info.version = Version::from(v);
                    }

                    if h.is_change_cipher_spec() {
                        self.change_cipher_spec_count += 1;
                        self.is_change_cipher_spec = true;
                        if self.change_cipher_spec_count >= Self::CHNAGE_CIPHER_SPEC_LIMIT {
                            self.change_cipher_spec_count = 0;
                            info.cal_tls_rtt = true;
                        }
                    } else {
                        self.is_change_cipher_spec = false;
                    }

                    if h.cipher_suite().is_some() && info.cipher_suite.is_none() {
                        info.cipher_suite = h.cipher_suite().map(|c| CipherSuite::from(c));
                    }

                    if let Some(v) = h.validity() {
                        if info.server_cert_not_after.is_zero() {
                            info.server_cert_not_before = Timestamp::from(v.0);
                            info.server_cert_not_after = Timestamp::from(v.1);
                        }
                    }
                });

                if let Version::Unknown(v) = info.version {
                    return Err(Error::TlsLogParseFailed(format!(
                        "Unknown tls version 0x{:x}",
                        v
                    )));
                }

                info.response_result = tls_headers
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<String>>()
                    .join("|")
                    .to_string();
            }
        }
        set_captured_byte!(info, param);
        Ok(())
    }
}
