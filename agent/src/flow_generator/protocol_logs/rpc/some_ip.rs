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

use public::l7_protocol::LogMessageType;

use crate::{
    common::{
        flow::{L7PerfStats, L7Protocol, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, LogCache, ParseParam},
        meta_packet::ApplicationFlags,
    },
    flow_generator::{
        error::{Error, Result},
        protocol_logs::{
            pb_adapter::{ExtendedInfo, KeyVal, L7ProtocolSendLog, L7Request, L7Response},
            set_captured_byte, swap_if, value_is_default, AppProtoHead, L7ResponseStatus,
        },
    },
};
use l7::some_ip::{
    SomeIpHeader, E_OK, E_UNKNOWN_METHOD, E_UNKNOWN_SERVICE, E_WRONG_INTERFACE_VERSION,
    E_WRONG_MESSAGE_TYPE, E_WRONG_PROTOCOL_VERSION,
};

#[derive(Serialize, Debug, Default, Clone)]
pub struct SomeIpInfo {
    #[serde(skip)]
    msg_type: LogMessageType,
    #[serde(skip)]
    is_tls: bool,

    #[serde(rename = "version", skip_serializing_if = "value_is_default")]
    pub version: String, // protocol_verseion + interface_version
    #[serde(rename = "request_type", skip_serializing_if = "value_is_default")]
    pub message_type: String,
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub service_id: u16,
    pub client_id: u16,
    pub session_id: u16,
    #[serde(rename = "response_code", skip_serializing_if = "value_is_default")]
    pub return_code: Option<u8>,
    pub exception: Option<String>,
    #[serde(rename = "response_status")]
    pub resp_status: L7ResponseStatus,
    pub endpoint: u16,

    #[serde(rename = "request_length", skip_serializing_if = "Option::is_none")]
    pub req_msg_size: Option<u32>,
    #[serde(rename = "response_length", skip_serializing_if = "Option::is_none")]
    pub resp_msg_size: Option<u32>,

    captured_request_byte: u32,
    captured_response_byte: u32,

    rrt: u64,
}

impl SomeIpInfo {
    pub fn merge(&mut self, other: &mut Self) {
        if other.is_tls {
            self.is_tls = other.is_tls;
        }

        swap_if!(self, version, is_empty, other);
        swap_if!(self, message_type, is_empty, other);

        swap_if!(self, return_code, is_none, other);
        swap_if!(self, req_msg_size, is_none, other);
        swap_if!(self, resp_msg_size, is_none, other);

        if other.resp_status != L7ResponseStatus::default() {
            self.resp_status = other.resp_status;
        }

        if other.captured_request_byte > 0 {
            self.captured_request_byte = other.captured_request_byte;
        }
        if other.captured_response_byte > 0 {
            self.captured_response_byte = other.captured_response_byte;
        }
        if other.rrt > 0 {
            self.rrt = other.rrt;
        }
    }
}

impl L7ProtocolInfoInterface for SomeIpInfo {
    fn session_id(&self) -> Option<u32> {
        Some(self.session_id as u32)
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::SomeIpInfo(other) = other {
            self.merge(other);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::SomeIp,
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn is_tls(&self) -> bool {
        self.is_tls
    }
}

impl From<SomeIpInfo> for L7ProtocolSendLog {
    fn from(f: SomeIpInfo) -> Self {
        let flags = if f.is_tls {
            ApplicationFlags::TLS.bits()
        } else {
            ApplicationFlags::NONE.bits()
        };
        let attributes = vec![KeyVal {
            key: "client_id".to_string(),
            val: f.client_id.to_string(),
        }];

        L7ProtocolSendLog {
            captured_request_byte: f.captured_request_byte,
            captured_response_byte: f.captured_response_byte,
            req_len: f.req_msg_size,
            resp_len: f.resp_msg_size,
            version: Some(f.version),
            req: L7Request {
                resource: f.service_id.to_string(),
                req_type: f.message_type,
                endpoint: f.endpoint.to_string(),
                ..Default::default()
            },
            resp: L7Response {
                status: f.resp_status,
                code: f.return_code.map(|c| c as i32),
                exception: f.exception.unwrap_or_default(),
                ..Default::default()
            },
            ext_info: Some(ExtendedInfo {
                request_id: Some(f.session_id as u32),
                attributes: Some(attributes),
                ..Default::default()
            }),
            flags,
            ..Default::default()
        }
    }
}

impl From<&SomeIpInfo> for LogCache {
    fn from(info: &SomeIpInfo) -> Self {
        LogCache {
            msg_type: info.msg_type,
            resp_status: info.resp_status,
            ..Default::default()
        }
    }
}

#[derive(Debug, Default)]
pub struct SomeIpLog {
    perf_stats: Option<L7PerfStats>,
}

impl L7ProtocolParserInterface for SomeIpLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> Option<LogMessageType> {
        if !param.ebpf_type.is_raw_protocol() {
            return None;
        }

        let Ok(header) = SomeIpHeader::try_from(payload) else {
            return None;
        };

        if header.check() {
            Some(LogMessageType::Request)
        } else {
            None
        }
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };
        let mut info = SomeIpInfo::default();
        self.parse(payload, &mut info, param)?;
        info.is_tls = param.is_tls();
        set_captured_byte!(info, param);
        if let Some(perf_stats) = self.perf_stats.as_mut() {
            if let Some(stats) = info.perf_stats(param) {
                info.rrt = stats.rrt_sum;
                perf_stats.sequential_merge(&stats);
            }
        }
        if param.parse_log {
            Ok(L7ParseResult::Single(L7ProtocolInfo::SomeIpInfo(info)))
        } else {
            Ok(L7ParseResult::None)
        }
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::SomeIp
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

impl SomeIpLog {
    fn request(&mut self, header: &SomeIpHeader, info: &mut SomeIpInfo) {
        info.msg_type = LogMessageType::Request;
        info.message_type = header.to_message_type();
        info.version = header.to_version();
        info.service_id = header.service_id;
        info.session_id = header.session_id;
        info.client_id = header.client_id;
        info.endpoint = header.method_id;
        info.req_msg_size = Some(header.length);
    }

    fn set_status(&mut self, status_code: u8, info: &mut SomeIpInfo) {
        info.resp_status = match status_code {
            E_OK => L7ResponseStatus::Ok,
            E_UNKNOWN_SERVICE
            | E_UNKNOWN_METHOD
            | E_WRONG_PROTOCOL_VERSION
            | E_WRONG_INTERFACE_VERSION
            | E_WRONG_MESSAGE_TYPE => {
                self.perf_stats.as_mut().map(|p| p.inc_req_err());
                L7ResponseStatus::ClientError
            }
            _ => {
                self.perf_stats.as_mut().map(|p| p.inc_resp_err());
                L7ResponseStatus::ServerError
            }
        }
    }

    fn response(&mut self, header: &SomeIpHeader, info: &mut SomeIpInfo) {
        info.msg_type = LogMessageType::Response;
        info.message_type = header.to_message_type();
        info.session_id = header.session_id;
        info.client_id = header.client_id;
        info.return_code = Some(header.return_code);
        info.resp_msg_size = Some(header.length);
        info.version = header.to_version();
        info.service_id = header.service_id;
        info.exception = Some(header.to_exception());
        info.endpoint = header.method_id;
        self.set_status(header.return_code, info);
    }

    fn parse(&mut self, payload: &[u8], info: &mut SomeIpInfo, param: &ParseParam) -> Result<()> {
        let direction = param.direction;
        let header =
            SomeIpHeader::try_from(payload).map_err(|_| Error::InsufficientPayloadLength)?;
        if !header.does_supported() {
            return Err(Error::SomeIpUnsupportedMessageType);
        }

        match direction {
            PacketDirection::ClientToServer => {
                self.request(&header, info);
            }
            PacketDirection::ServerToClient => {
                self.response(&header, info);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json;
    use std::path::Path;
    use std::rc::Rc;
    use std::{cell::RefCell, fs};

    use super::SomeIpLog;
    use crate::{
        common::{
            flow::PacketDirection,
            l7_protocol_log::{L7ParseResult, L7PerfCache, L7ProtocolParserInterface, ParseParam},
            MetaPacket,
        },
        config::handler::{L7LogDynamicConfigBuilder, LogParserConfig, TraceType},
        flow_generator::L7_RRT_CACHE_CAPACITY,
        utils::test::Capture,
    };

    const FILE_DIR: &str = "resources/test/flow_generator/some_ip";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name));
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let mut packets = capture.collect::<Vec<_>>();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut output: String = String::new();
        let first_dst_mac = packets[0].lookup_key.dst_mac;
        let mut some_ip = SomeIpLog::default();
        for packet in packets.iter_mut() {
            packet.lookup_key.direction = if packet.lookup_key.dst_mac == first_dst_mac {
                PacketDirection::ClientToServer
            } else {
                PacketDirection::ServerToClient
            };
            let payload = match packet.get_l4_payload() {
                Some(p) => p,
                None => continue,
            };
            let param = &mut ParseParam::new(
                packet as &MetaPacket,
                log_cache.clone(),
                Default::default(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Default::default(),
                true,
                true,
            );
            param.set_captured_byte(payload.len());

            let config = L7LogDynamicConfigBuilder {
                proxy_client: vec![],
                x_request_id: vec![],
                trace_types: vec![TraceType::Sw8, TraceType::TraceParent],
                span_types: vec![TraceType::Sw8, TraceType::TraceParent],
                ..Default::default()
            };
            let parse_config = &LogParserConfig {
                l7_log_dynamic: config.into(),
                ..Default::default()
            };

            param.set_log_parser_config(parse_config);

            let info = some_ip.parse_payload(payload, param);
            if let Ok(info) = info {
                match info {
                    L7ParseResult::Single(s) => {
                        output.push_str(&serde_json::to_string(&s).unwrap());
                        output.push_str(
                            format!(" check: {:?}", some_ip.check_payload(payload, param)).as_str(),
                        );
                        output.push_str("\n");
                    }
                    L7ParseResult::Multi(m) => {
                        for i in m {
                            output.push_str(&serde_json::to_string(&i).unwrap());
                            output.push_str(
                                format!(" check: {:?}", some_ip.check_payload(payload, param))
                                    .as_str(),
                            );
                            output.push_str("\n");
                        }
                    }
                    L7ParseResult::None => {
                        output.push_str("None\n");
                    }
                }
            } else {
                output.push_str(&format!("{:?}\n", SomeIpLog::default()));
            }
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![("some_ip.pcap", "some_ip.result")];

        for item in files.iter() {
            let expected = fs::read_to_string(&Path::new(FILE_DIR).join(item.1)).unwrap();
            let output = run(item.0);

            if output != expected {
                let output_path = Path::new("actual.txt");
                fs::write(&output_path, &output).unwrap();
                assert!(
                    output == expected,
                    "{} output different from expected {}, written to {:?}",
                    item.0,
                    item.1,
                    output_path
                );
            }
        }
    }
}
