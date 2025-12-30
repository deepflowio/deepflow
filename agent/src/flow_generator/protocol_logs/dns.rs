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

use std::fmt::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

use log::debug;
use serde::{ser::SerializeStruct, Serialize, Serializer};
use simple_dns::{rdata::RData, Packet, PacketFlag, SimpleDnsError, OPCODE, QTYPE, RCODE, TYPE};

use super::{
    pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response},
    AppProtoHead, L7ResponseStatus,
};
use crate::{
    common::{
        enums::IpProtocol,
        flow::L7PerfStats,
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, LogCache, ParseParam},
        meta_packet::ApplicationFlags,
    },
    config::handler::LogParserConfig,
    flow_generator::{
        error::{Error, Result},
        protocol_logs::{pb_adapter::KeyVal, set_captured_byte},
    },
    utils::bytes::read_u16_be,
};
use public::l7_protocol::{L7Protocol, LogMessageType};

const TCP_PAYLOAD_OFFSET: usize = 2;
const DNS_HEADER_LEN: usize = 12;
const ANSWER_SPLIT: &str = "; ";

impl From<SimpleDnsError> for Error {
    fn from(e: SimpleDnsError) -> Self {
        Error::L7LogParseFailed {
            proto: L7Protocol::DNS,
            reason: e.to_string().into(),
        }
    }
}

fn qtype_to_string(qtype: QTYPE) -> String {
    match qtype {
        QTYPE::TYPE(t) => format!("{t:?}"),
        _ => format!("{qtype:?}"),
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DnsInfo {
    pub trans_id: u16,
    pub query_type: Option<QTYPE>,
    pub opcode: Option<OPCODE>,

    pub query_name: String,
    pub answers: Vec<(TYPE, String, u32)>,

    pub is_unconcerned: bool,
    pub status_code: Option<u8>,

    msg_type: LogMessageType,

    captured_request_byte: u32,
    captured_response_byte: u32,
    rrt: u64,

    // non serialize fields
    headers_offset: u32,
    is_tls: bool,
    is_on_blacklist: bool,
}

impl Serialize for DnsInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // initial count for: msg_type, captured_request_byte, captured_response_byte, rrt, status
        let mut field_count = 5;
        if self.trans_id != 0 {
            field_count += 1;
        }
        if self.query_type.is_some() {
            field_count += 1;
        }
        if !self.query_name.is_empty() {
            field_count += 1;
        }
        if !self.answers.is_empty() {
            field_count += 1;
        }
        if self.status_code.is_some() {
            field_count += 1;
        }

        let mut state = serializer.serialize_struct("DnsInfo", field_count)?;
        if self.trans_id != 0 {
            state.serialize_field("request_id", &self.trans_id)?;
        }
        if let Some(qtype) = self.query_type {
            state.serialize_field("request_type", &qtype_to_string(qtype))?;
        }
        if let Some(opcode) = self.opcode {
            state.serialize_field("opcode", &format!("{:?}", opcode))?;
        }
        if !self.query_name.is_empty() {
            state.serialize_field("request_resource", &self.query_name)?;
        }
        if !self.answers.is_empty() {
            state.serialize_field("response_result", &self.answers_to_string())?;
        }
        state.serialize_field("response_status", &self.status())?;
        if let Some(status_code) = self.status_code {
            state.serialize_field("response_code", &status_code)?;
        }
        state.serialize_field("msg_type", &self.msg_type)?;
        state.serialize_field("captured_request_byte", &self.captured_request_byte)?;
        state.serialize_field("captured_response_byte", &self.captured_response_byte)?;
        state.serialize_field("rrt", &self.rrt)?;
        state.end()
    }
}

impl L7ProtocolInfoInterface for DnsInfo {
    fn session_id(&self) -> Option<u32> {
        Some(self.trans_id as u32)
    }

    fn tcp_seq_offset(&self) -> u32 {
        self.headers_offset
    }

    fn merge_log(
        &mut self,
        other: &mut crate::common::l7_protocol_info::L7ProtocolInfo,
    ) -> Result<()> {
        if let L7ProtocolInfo::DnsInfo(other) = other {
            self.merge(other);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::DNS,
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn is_tls(&self) -> bool {
        self.is_tls
    }

    fn get_endpoint(&self) -> Option<String> {
        if self.query_name.is_empty() {
            return None;
        }
        Some(self.query_name.clone())
    }

    fn get_request_resource_length(&self) -> usize {
        self.query_name.len() + self.answers.iter().map(|(_, s, _)| s.len()).sum::<usize>()
    }

    fn is_on_blacklist(&self) -> bool {
        self.is_on_blacklist
    }
}

impl DnsInfo {
    pub fn merge(&mut self, other: &mut Self) {
        std::mem::swap(&mut self.answers, &mut other.answers);
        self.is_unconcerned |= other.is_unconcerned;
        match (self.status_code, other.status_code) {
            (None, Some(code)) => self.status_code = Some(code),
            (Some(code), Some(other_code))
                if code != other_code && RCODE::from(code as u16) == RCODE::NoError =>
            {
                self.status_code = Some(other_code)
            }
            _ => (),
        }
        self.captured_response_byte = other.captured_response_byte;
        if other.is_on_blacklist {
            self.is_on_blacklist = other.is_on_blacklist;
        }
    }

    fn is_query_address(&self) -> bool {
        match self.query_type {
            Some(QTYPE::TYPE(TYPE::A | TYPE::AAAA)) => true,
            _ => false,
        }
    }

    fn set_is_on_blacklist(&mut self, config: &LogParserConfig) {
        if let Some(t) = config.l7_log_blacklist_trie.get(&L7Protocol::DNS) {
            self.is_on_blacklist = t.request_resource.is_on_blacklist(&self.query_name)
                || t.request_domain.is_on_blacklist(&self.query_name)
                || t.endpoint.is_on_blacklist(&self.query_name);
            if let Some(qtype) = self.query_type {
                self.is_on_blacklist |= t.request_type.is_on_blacklist(&qtype_to_string(qtype));
            }
        }
    }

    fn parse_request(p: &Packet) -> Result<Self> {
        let mut info = DnsInfo {
            trans_id: p.id(),
            msg_type: LogMessageType::Request,
            ..Default::default()
        };
        // in practice only one question in a DNS request
        if p.questions.len() != 1 {
            debug!("found DNS request with {} questions", p.questions.len());
        }
        let Some(question) = p.questions.first() else {
            return Err(Error::L7LogParseFailed {
                proto: L7Protocol::DNS,
                reason: "no question in DNS request".into(),
            });
        };
        info.query_name = question.qname.to_string();
        info.query_type = Some(question.qtype);
        info.opcode = Some(p.opcode());
        Ok(info)
    }

    fn parse_response(p: &Packet) -> Result<Self> {
        let mut info = DnsInfo {
            trans_id: p.id(),
            msg_type: LogMessageType::Response,
            status_code: Some(p.rcode() as u8),
            ..Default::default()
        };
        // also asserting only one question here
        let Some(question) = p.questions.first() else {
            return Err(Error::L7LogParseFailed {
                proto: L7Protocol::DNS,
                reason: "no question in DNS request".into(),
            });
        };
        info.query_name = question.qname.to_string();
        info.query_type = Some(question.qtype);
        info.opcode = Some(p.opcode());
        for rr in p.answers.iter().chain(p.name_servers.iter()) {
            let answer = match &rr.rdata {
                RData::A(d) => Ipv4Addr::from(d.address).to_string(),
                RData::AAAA(d) => Ipv6Addr::from(d.address).to_string(),
                RData::NS(d) => d.0.to_string(),
                RData::SOA(d) => d.mname.to_string(),
                RData::WKS(d) => Ipv4Addr::from(d.address).to_string(),
                RData::PTR(d) => d.0.to_string(),
                // TODO: DNAME
                // simple-dns do not have dname support, perhaps this is not often used
                _ => String::new(),
            };
            info.answers.push((rr.rdata.type_code(), answer, rr.ttl));
        }
        Ok(info)
    }

    // parse a UDP DNS packet
    fn parse(params: &ParseParam, payload: &[u8]) -> Result<Self> {
        let p = Packet::parse(payload)?;
        let mut info = if p.has_flags(PacketFlag::RESPONSE) {
            let mut info = Self::parse_response(&p)?;
            if let Some(c) = params.parse_config {
                for (_, answer, _) in info.answers.iter() {
                    if c.unconcerned_dns_nxdomain_trie.is_unconcerned(answer) {
                        info.is_unconcerned = true;
                        break;
                    }
                }
            }
            info
        } else {
            Self::parse_request(&p)?
        };
        set_captured_byte!(info, params);
        Ok(info)
    }

    fn status(&self) -> L7ResponseStatus {
        if let Some(status_code) = self.status_code {
            if self.is_unconcerned {
                return L7ResponseStatus::Ok;
            }
            match RCODE::from(status_code as u16) {
                RCODE::NoError => L7ResponseStatus::Ok,
                RCODE::FormatError | RCODE::NameError => L7ResponseStatus::ClientError,
                _ => L7ResponseStatus::ServerError,
            }
        } else {
            L7ResponseStatus::Unknown
        }
    }

    fn answers_to_string(&self) -> String {
        let mut answers = String::new();
        for (i, (rtype, answer, ttl)) in self.answers.iter().enumerate() {
            if i > 0 {
                answers.push_str(ANSWER_SPLIT);
            }
            if answer.is_empty() {
                let _ = write!(&mut answers, "{rtype:?}");
            } else {
                let _ = write!(&mut answers, "{rtype:?}={answer} TTL={ttl}");
            }
        }
        answers
    }
}

impl From<DnsInfo> for L7ProtocolSendLog {
    fn from(f: DnsInfo) -> Self {
        let flags = if f.is_tls {
            ApplicationFlags::TLS.bits()
        } else {
            ApplicationFlags::NONE.bits()
        };
        let status = f.status();
        let result = f.answers_to_string();
        let log = L7ProtocolSendLog {
            captured_request_byte: f.captured_request_byte,
            captured_response_byte: f.captured_response_byte,
            req: L7Request {
                req_type: f
                    .query_type
                    .map(|qtype| qtype_to_string(qtype))
                    .unwrap_or_default(),
                resource: f.query_name.clone(),
                domain: if f.is_query_address() {
                    f.query_name.clone()
                } else {
                    String::new()
                },
                endpoint: f.query_name,
                ..Default::default()
            },
            resp: L7Response {
                result,
                code: f.status_code.map(|c| c as i32),
                status,
                ..Default::default()
            },
            ext_info: Some(ExtendedInfo {
                request_id: Some(f.trans_id as u32),
                attributes: Some(vec![KeyVal {
                    key: "opcode".to_string(),
                    val: format!("{:?}", f.opcode.unwrap_or_else(|| OPCODE::Reserved)),
                }]),
                ..Default::default()
            }),
            flags,
            ..Default::default()
        };

        return log;
    }
}

impl From<&DnsInfo> for LogCache {
    fn from(info: &DnsInfo) -> Self {
        LogCache {
            msg_type: info.msg_type,
            resp_status: info.status(),
            on_blacklist: info.is_on_blacklist,
            ..Default::default()
        }
    }
}

#[derive(Default)]
pub struct DnsLog {
    perf_stats: Option<L7PerfStats>,
}

//解析器接口实现
impl L7ProtocolParserInterface for DnsLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> Option<LogMessageType> {
        if !param.ebpf_type.is_raw_protocol() {
            return None;
        }

        match self.parse(payload, param, true) {
            Ok(info) => match info.get(0) {
                Some(info)
                    if info.msg_type == LogMessageType::Request && !info.query_name.is_empty() =>
                {
                    Some(LogMessageType::Request)
                }
                _ => None,
            },
            _ => None,
        }
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        let mut infos = self.parse(payload, param, false)?;

        for info in &mut infos {
            info.is_tls = param.is_tls();
            if let Some(config) = param.parse_config {
                info.set_is_on_blacklist(config);
            }
            if let Some(perf_stats) = self.perf_stats.as_mut() {
                if let Some(stats) = info.perf_stats(param) {
                    info.rrt = stats.rrt_sum;
                    perf_stats.sequential_merge(&stats);
                }
            }
        }

        if param.parse_log {
            Ok(L7ParseResult::Multi(
                infos
                    .drain(..)
                    .map(|i| L7ProtocolInfo::DnsInfo(i))
                    .collect(),
            ))
        } else {
            Ok(L7ParseResult::None)
        }
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::DNS
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

impl DnsLog {
    fn parse(&mut self, payload: &[u8], param: &ParseParam, check: bool) -> Result<Vec<DnsInfo>> {
        let proto = param.l4_protocol;
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };
        match proto {
            IpProtocol::UDP => Ok(vec![DnsInfo::parse(param, payload)?]),
            IpProtocol::TCP => {
                let mut offset = 0;
                let mut all_info = vec![];

                while offset < payload.len() {
                    let frame = &payload[offset..];
                    let Some(length_bytes) = frame.get(..TCP_PAYLOAD_OFFSET) else {
                        break;
                    };
                    let len = read_u16_be(length_bytes) as usize;
                    if len < DNS_HEADER_LEN || frame.len() < DNS_HEADER_LEN {
                        break;
                    }
                    // Offset for TCP DNS:
                    // Example:
                    //                 0            2               ...
                    //                 |____________|_______________|__
                    // DNS Request:    | Length     | UDP DNS Header
                    //
                    // eBPF Data: tcp seq is 0 and payload is tcp.payload or tcp.payload[2..]
                    //
                    // if remaining bytes is exact match to len, only try parsing at &frame[2..]
                    // if remaining bytes is greater than len, try parsing at &frame[2..] then &frame[0..]
                    // if remaining bytes is less than len, try parsing at &frame[0..] then &frame[2..]
                    let tries = if frame[TCP_PAYLOAD_OFFSET..].len() == len {
                        [Some(2), None]
                    } else if frame[TCP_PAYLOAD_OFFSET..].len() > len {
                        [Some(2), Some(0)]
                    } else {
                        [Some(0), Some(2)]
                    };
                    let mut valid = false;
                    for t in tries.iter() {
                        if t.is_none() {
                            continue;
                        }
                        let start = t.unwrap();
                        let end_of_frame = frame.len().min(start + len);
                        if let Ok(mut info) = DnsInfo::parse(&param, &frame[start..end_of_frame]) {
                            valid = true;
                            info.headers_offset = offset as u32;
                            offset += end_of_frame;
                            all_info.push(info);
                            break;
                        }
                    }
                    if !valid {
                        // didn't find a valid DNS packet, finish parsing
                        break;
                    }

                    if check {
                        return Ok(all_info);
                    }
                }

                if all_info.is_empty() {
                    return Err(Error::L7LogParseFailed {
                        proto: L7Protocol::DNS,
                        reason: "no valid DNS info found".into(),
                    });
                }

                Ok(all_info)
            }
            _ => return Err(Error::InvalidIpProtocol),
        }
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

    const FILE_DIR: &str = "resources/test/flow_generator/dns";

    fn test_output(s: &mut String, info: &DnsInfo, is_dns: bool) {
        let _ = write!(
            s,
            "{} headers_offset: {} is_dns: {}\n",
            &serde_json::to_string(info).unwrap(),
            info.headers_offset,
            is_dns
        );
    }

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name));
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let mut packets = capture.collect::<Vec<_>>();
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

            let mut dns = DnsLog::default();
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
            let is_dns = dns.check_payload(payload, param).is_some();
            let info = dns.parse_payload(payload, param);
            if let Ok(info) = info {
                for i in info.unwrap_multi() {
                    match i {
                        L7ProtocolInfo::DnsInfo(i) => test_output(&mut output, &i, is_dns),
                        _ => unreachable!(),
                    }
                }
            } else {
                test_output(&mut output, &DnsInfo::default(), is_dns);
            }
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
            ("dns-tcp-multi.pcap", "dns-tcp-multi.result"),
            ("dns.pcap", "dns.result"),
            ("a-and-ns.pcap", "a-and-ns.result"),
            ("not-handled-qtype.pcap", "not-handled-qtype.result"),
        ];

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
        let expected = vec![
            (
                "dns.pcap",
                L7PerfStats {
                    request_count: 2,
                    response_count: 2,
                    err_client_count: 1,
                    err_server_count: 0,
                    err_timeout: 0,
                    rrt_count: 2,
                    rrt_sum: 181558,
                    rrt_max: 176754,
                    ..Default::default()
                },
            ),
            (
                "dns-tcp-multi.pcap",
                L7PerfStats {
                    request_count: 2,
                    response_count: 2,
                    err_client_count: 0,
                    err_server_count: 0,
                    err_timeout: 0,
                    rrt_count: 2,
                    rrt_sum: 649,
                    rrt_max: 355,
                    ..Default::default()
                },
            ),
        ];

        for item in expected.iter() {
            assert_eq!(item.1, run_perf(item.0), "parse pcap {} unexcepted", item.0);
        }
    }

    fn run_perf(pcap: &str) -> L7PerfStats {
        let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));
        let mut dns = DnsLog::default();

        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(pcap));
        let mut packets = capture.collect::<Vec<_>>();
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
            let Some(payload) = packet.get_l4_payload() else {
                continue;
            };
            let _ = dns.parse_payload(
                payload,
                &ParseParam::new(
                    &*packet,
                    rrt_cache.clone(),
                    Default::default(),
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    Default::default(),
                    true,
                    true,
                ),
            );
        }
        dns.perf_stats.unwrap()
    }

    #[test]
    fn malformed_packet() {
        let packet = MetaPacket::empty();
        let mut pp = ParseParam::new(
            &packet,
            Rc::new(RefCell::new(L7PerfCache::new(100))),
            Default::default(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Default::default(),
            true,
            true,
        );
        pp.l4_protocol = IpProtocol::TCP;

        let mut dns = DnsLog::default();
        let _ = dns.parse_payload(&[0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &pp);
    }
}
