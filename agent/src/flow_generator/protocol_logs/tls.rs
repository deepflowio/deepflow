/*
 * Copyright (c) 2023 Yunshan Networks
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

use serde::Serialize;

use super::pb_adapter::{L7ProtocolSendLog, L7Request, L7Response};
use super::{value_is_default, AppProtoHead, L7ResponseStatus, LogMessageType};
use crate::{
    common::{
        enums::IpProtocol,
        flow::{L7PerfStats, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, ParseParam},
        meta_packet::EbpfFlags,
    },
    flow_generator::error::{Error, Result},
    utils::bytes::{read_u16_be, read_u32_be},
};
use public::l7_protocol::L7Protocol;

struct HandshakeHeader {
    raw: u32,
}

impl Display for HandshakeHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.handshake_type() {
            Self::HANDSHAKE_TYPE_CLIENT_HELLO => write!(f, "Client hello"),
            Self::HANDSHAKE_TYPE_SERVER_HELLO => write!(f, "Server hello"),
            Self::HANDSHAKE_TYPE_NEW_SESSION_TICKET => write!(f, "New session ticket"),
            Self::HANDSHAKE_TYPE_CERTIFICATE => write!(f, "Certificate"),
            Self::HANDSHAKE_TYPE_SERVER_KEY => write!(f, "Server key"),
            Self::HANDSHAKE_TYPE_CERTIFICATE_REQUEST => write!(f, "Certificate request"),
            Self::HANDSHAKE_TYPE_SERVER_HELLO_DONE => write!(f, "Hello done"),
            Self::HANDSHAKE_TYPE_CLIENT_KEY => write!(f, "Client key"),
            _ => write!(f, "Unsupport({})", self.handshake_type()),
        }
    }
}

impl HandshakeHeader {
    const HEADER_LEN: usize = 4;

    const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
    const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 2;
    const HANDSHAKE_TYPE_NEW_SESSION_TICKET: u8 = 4;
    const HANDSHAKE_TYPE_CERTIFICATE: u8 = 11;
    const HANDSHAKE_TYPE_SERVER_KEY: u8 = 12;
    const HANDSHAKE_TYPE_CERTIFICATE_REQUEST: u8 = 13;
    const HANDSHAKE_TYPE_SERVER_HELLO_DONE: u8 = 14;
    const HANDSHAKE_TYPE_CLIENT_KEY: u8 = 16;

    fn new(payload: &[u8]) -> Self {
        assert!(payload.len() >= Self::HEADER_LEN);
        Self {
            raw: read_u32_be(payload),
        }
    }

    fn handshake_type(&self) -> u8 {
        (self.raw >> 24) as u8
    }

    fn length(&self) -> usize {
        (self.raw & 0xffffff) as usize
    }

    fn is_client_hello(&self) -> bool {
        self.handshake_type() == Self::HANDSHAKE_TYPE_CLIENT_HELLO
    }

    fn next(&self) -> usize {
        Self::HEADER_LEN + self.length()
    }
}

struct TlsHeader {
    content_type: u8,
    version: u16,
    length: u16,
    handshake_headers: Vec<HandshakeHeader>,
    last: bool,
}

impl Display for TlsHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.content_type {
            Self::CONTENT_TYPE_HANDSHAKE => {
                write!(
                    f,
                    "{}",
                    self.handshake_headers
                        .iter()
                        .map(|h| h.to_string())
                        .collect::<Vec<String>>()
                        .join("|")
                )
            }
            Self::CONTENT_TYPE_CHANGE_CIPHER_SPEC => write!(f, "Change cipher spec"),
            _ => write!(f, "Unsupport content type {}", self.content_type),
        }
    }
}

impl TlsHeader {
    const HEADER_LEN: usize = 5;
    const CONTEXT_TYPE_OFFSET: usize = 0;
    const VERSION_OFFSET: usize = 1;
    const LENGTH_OFFSET: usize = 3;

    const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
    const CONTENT_TYPE_HANDSHAKE: u8 = 22;

    fn new(payload: &[u8]) -> Self {
        assert!(payload.len() >= Self::HEADER_LEN);

        let mut handshake_headers = vec![];
        let mut offset = Self::HEADER_LEN;
        let last = payload[Self::CONTEXT_TYPE_OFFSET] == Self::CONTENT_TYPE_CHANGE_CIPHER_SPEC;
        let length = read_u16_be(&payload[Self::LENGTH_OFFSET..]) as usize + Self::HEADER_LEN;
        if payload[Self::CONTEXT_TYPE_OFFSET] == Self::CONTENT_TYPE_HANDSHAKE {
            while offset + HandshakeHeader::HEADER_LEN <= payload.len().min(length) {
                let header = HandshakeHeader::new(&payload[offset..]);
                offset += header.next();
                handshake_headers.push(header);
            }
        }

        Self {
            content_type: payload[Self::CONTEXT_TYPE_OFFSET],
            version: read_u16_be(&payload[Self::VERSION_OFFSET..]),
            length: read_u16_be(&payload[Self::LENGTH_OFFSET..]),
            handshake_headers,
            last,
        }
    }

    fn is_unsupport_content_type(&self) -> bool {
        self.content_type != Self::CONTENT_TYPE_HANDSHAKE
            && self.content_type != Self::CONTENT_TYPE_CHANGE_CIPHER_SPEC
    }

    fn is_handshake(&self) -> bool {
        self.content_type == Self::CONTENT_TYPE_HANDSHAKE
    }

    fn is_client_hello(&self) -> bool {
        self.handshake_headers
            .iter()
            .find(|&h| h.is_client_hello())
            .is_some()
    }

    fn is_last(&self) -> bool {
        self.last
    }

    fn next(&self) -> usize {
        Self::HEADER_LEN + self.length as usize
    }
}

#[derive(Serialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct TlsInfo {
    #[serde(rename = "request_type", skip_serializing_if = "value_is_default")]
    pub handshake_protocol: String,
    #[serde(rename = "version", skip_serializing_if = "value_is_default")]
    pub version: String,
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub request_resource: String,

    #[serde(rename = "response_status")]
    pub status: L7ResponseStatus,
    #[serde(rename = "response_result", skip_serializing_if = "value_is_default")]
    pub response_result: String,

    msg_type: LogMessageType,
    rrt: u64,
}

impl L7ProtocolInfoInterface for TlsInfo {
    fn session_id(&self) -> Option<u32> {
        None
    }

    fn merge_log(&mut self, other: crate::common::l7_protocol_info::L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::TlsInfo(other) = other {
            self.merge(other);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::Tls,
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn is_tls(&self) -> bool {
        true
    }
}

impl TlsInfo {
    pub fn merge(&mut self, other: Self) {
        match other.msg_type {
            LogMessageType::Request => {
                self.handshake_protocol = other.handshake_protocol;
                self.version = other.version;
                self.request_resource = other.request_resource;
            }
            LogMessageType::Response => {
                self.status = other.status;
                self.response_result = other.response_result;
            }
            _ => {}
        }
    }
}

impl From<TlsInfo> for L7ProtocolSendLog {
    fn from(f: TlsInfo) -> Self {
        let log = L7ProtocolSendLog {
            req: L7Request {
                req_type: f.handshake_protocol,
                resource: f.request_resource,
                ..Default::default()
            },
            resp: L7Response {
                result: f.response_result,
                status: f.status,
                ..Default::default()
            },
            version: if f.version.len() > 0 {
                Some(f.version)
            } else {
                None
            },
            flags: EbpfFlags::TLS.bits(),
            ..Default::default()
        };

        return log;
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TlsLog {
    perf_stats: Option<L7PerfStats>,
}

//解析器接口实现
impl L7ProtocolParserInterface for TlsLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol() || param.l4_protocol != IpProtocol::TCP {
            return false;
        }

        if payload.len() < TlsHeader::HEADER_LEN {
            return false;
        }

        let tls_header = TlsHeader::new(payload);
        tls_header.is_handshake() && tls_header.is_client_hello()
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        let mut info = TlsInfo::default();
        self.parse(payload, &mut info, param)?;
        info.cal_rrt(param, None).map(|rrt| {
            info.rrt = rrt;
            self.perf_stats.as_mut().map(|p| p.update_rrt(rrt));
        });
        if param.parse_log {
            Ok(L7ParseResult::Single(L7ProtocolInfo::TlsInfo(info)))
        } else {
            Ok(L7ParseResult::None)
        }
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Tls
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

impl TlsLog {
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
                    header.content_type
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
                if tls_headers.len() > 0 {
                    info.version = format!("0x{:x}", tls_headers[0].version);
                    if tls_headers[0].handshake_headers.len() > 0 {
                        info.handshake_protocol = tls_headers[0].handshake_headers[0].to_string();
                    }
                    info.request_resource = tls_headers
                        .iter()
                        .map(|i| i.to_string())
                        .collect::<Vec<String>>()
                        .join("|")
                        .to_string();
                    info.msg_type = LogMessageType::Request;

                    self.perf_stats.as_mut().map(|p| p.inc_req());
                }
            }
            PacketDirection::ServerToClient => {
                if tls_headers.len() > 0 {
                    info.response_result = tls_headers
                        .iter()
                        .map(|i| i.to_string())
                        .collect::<Vec<String>>()
                        .join("|")
                        .to_string();
                    info.status = L7ResponseStatus::Ok;
                    info.msg_type = LogMessageType::Response;

                    self.perf_stats.as_mut().map(|p| p.inc_resp());
                }
            }
        }
        Ok(())
    }
}

// test log parse
#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::rc::Rc;
    use std::{cell::RefCell, fs};

    use super::*;

    use crate::{
        common::{flow::PacketDirection, l7_protocol_log::L7PerfCache, MetaPacket},
        flow_generator::L7_RRT_CACHE_CAPACITY,
        utils::test::Capture,
    };

    const FILE_DIR: &str = "resources/test/flow_generator/tls";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name), None);
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut output = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
        for packet in packets.iter_mut() {
            packet.lookup_key.direction = if packet.lookup_key.dst_port == first_dst_port {
                PacketDirection::ClientToServer
            } else {
                PacketDirection::ServerToClient
            };
            let payload = match packet.get_l4_payload() {
                Some(p) => p,
                None => continue,
            };

            let mut tls = TlsLog::default();
            let param = &ParseParam::new(packet as &MetaPacket, log_cache.clone(), true, true);
            let is_tls = tls.check_payload(payload, param);
            tls.reset();
            let info = tls.parse_payload(payload, param);
            if let Ok(info) = info {
                match info.unwrap_single() {
                    L7ProtocolInfo::TlsInfo(i) => {
                        output.push_str(&format!("{:?} is_tls: {}\r\n", i, is_tls));
                    }
                    _ => unreachable!(),
                }
            } else {
                output.push_str(&format!("{:?} is_tls: {}\r\n", TlsInfo::default(), is_tls));
            }
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![("tls.pcap", "tls.result")];

        for item in files.iter() {
            let expected = fs::read_to_string(&Path::new(FILE_DIR).join(item.1)).unwrap();
            let output = run(item.0);

            if output != expected {
                let output_path = Path::new("actual.txt");
                fs::write(&output_path, &output).unwrap();
                assert!(
                    output == expected,
                    "output different from expected {}, written to {:?}",
                    item.1,
                    output_path
                );
            }
        }
    }

    #[test]
    fn check_perf() {
        let expected = vec![(
            "tls.pcap",
            L7PerfStats {
                request_count: 2,
                response_count: 2,
                err_client_count: 0,
                err_server_count: 0,
                err_timeout: 0,
                rrt_count: 2,
                rrt_sum: 102011,
                rrt_max: 55453,
            },
        )];

        for item in expected.iter() {
            assert_eq!(item.1, run_perf(item.0), "parse pcap {} unexcepted", item.0);
        }
    }

    fn run_perf(pcap: &str) -> L7PerfStats {
        let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));
        let mut tls = TlsLog::default();

        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(pcap), None);
        let mut packets = capture.as_meta_packets();
        if packets.len() < 2 {
            unreachable!()
        }
        let first_dst_port = packets[0].lookup_key.dst_port;
        for packet in packets.iter_mut() {
            if packet.lookup_key.dst_port == first_dst_port {
                packet.lookup_key.direction = PacketDirection::ClientToServer;
            } else {
                packet.lookup_key.direction = PacketDirection::ServerToClient;
            }
            let _ = tls.parse_payload(
                packet.get_l4_payload().unwrap(),
                &ParseParam::new(&*packet, rrt_cache.clone(), true, true),
            );
        }
        tls.perf_stats.unwrap()
    }
}
