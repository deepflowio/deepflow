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

use super::pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response};
use super::{consts::*, value_is_default, AppProtoHead, L7ResponseStatus, LogMessageType};
use crate::common::flow::L7PerfStats;
use crate::common::l7_protocol_log::L7ParseResult;
use crate::{
    common::{
        enums::IpProtocol,
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ProtocolParserInterface, ParseParam},
        meta_packet::EbpfFlags,
        IPV4_ADDR_LEN, IPV6_ADDR_LEN,
    },
    flow_generator::error::{Error, Result},
    utils::bytes::read_u16_be,
};
use public::{l7_protocol::L7Protocol, utils::net::parse_ip_slice};

#[derive(Serialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct DnsInfo {
    #[serde(rename = "request_id", skip_serializing_if = "value_is_default")]
    pub trans_id: u16,
    #[serde(rename = "request_type", skip_serializing_if = "value_is_default")]
    pub query_type: u8,
    #[serde(skip)]
    pub domain_type: u16,

    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub query_name: String,
    // 根据查询类型的不同而不同，如：
    // A: ipv4/ipv6地址
    // NS: name server
    // SOA: primary name server
    #[serde(rename = "response_result", skip_serializing_if = "value_is_default")]
    pub answers: String,

    #[serde(rename = "response_status")]
    pub status: L7ResponseStatus,
    #[serde(rename = "response_code", skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i32>,

    msg_type: LogMessageType,
    #[serde(skip)]
    is_tls: bool,
    rrt: u64,
}

impl L7ProtocolInfoInterface for DnsInfo {
    fn session_id(&self) -> Option<u32> {
        Some(self.trans_id as u32)
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
        self.query_name.len()
    }
}

impl DnsInfo {
    const QUERY_IPV4: u16 = 1;
    const QUERY_IPV6: u16 = 28;

    pub fn merge(&mut self, other: &mut Self) {
        std::mem::swap(&mut self.answers, &mut other.answers);
        if other.status != L7ResponseStatus::default() {
            self.status = other.status;
        }

        if let Some(code) = other.status_code {
            if code != 0 {
                self.status_code = Some(code);
            }
        }
    }

    fn is_query_address(&self) -> bool {
        self.domain_type == Self::QUERY_IPV4 || self.domain_type == Self::QUERY_IPV6
    }

    pub fn get_domain_str(&self) -> &'static str {
        let typ = [
            "", "A", "NS", "MD", "MF", "CNAME", "SOA", "MB", "MG", "MR", "NULL", "WKS", "PTR",
            "HINFO", "MINFO", "MX", "TXT",
        ];

        match self.domain_type {
            1..=16 => typ[self.domain_type as usize],
            28 => "AAAA",
            252 => "AXFR",
            253 => "MAILB",
            254 => "MAILA",
            255 => "ANY",
            _ => "",
        }
    }
}

impl From<DnsInfo> for L7ProtocolSendLog {
    fn from(f: DnsInfo) -> Self {
        let req_type = String::from(f.get_domain_str());
        let flags = if f.is_tls {
            EbpfFlags::TLS.bits()
        } else {
            EbpfFlags::NONE.bits()
        };
        let log = L7ProtocolSendLog {
            req: L7Request {
                req_type,
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
                result: f.answers,
                code: f.status_code,
                status: f.status,
                ..Default::default()
            },
            ext_info: Some(ExtendedInfo {
                request_id: Some(f.trans_id as u32),
                ..Default::default()
            }),
            flags,
            ..Default::default()
        };

        return log;
    }
}

#[derive(Default)]
pub struct DnsLog {
    perf_stats: Option<L7PerfStats>,
}

//解析器接口实现
impl L7ProtocolParserInterface for DnsLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol() {
            return false;
        }
        let mut info = DnsInfo::default();
        self.parse(payload, &mut info, param).is_ok()
            && info.msg_type == LogMessageType::Request
            && !info.query_name.is_empty()
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        let mut info = DnsInfo::default();
        self.parse(payload, &mut info, param)?;
        info.cal_rrt(param, None).map(|rrt| {
            info.rrt = rrt;
            self.perf_stats.as_mut().map(|p| p.update_rrt(rrt));
        });
        info.is_tls = param.is_tls();
        if param.parse_log {
            Ok(L7ParseResult::Single(L7ProtocolInfo::DnsInfo(info)))
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
    fn decode_name(&self, payload: &[u8], g_offset: usize) -> Result<(String, usize)> {
        let mut l_offset = g_offset;
        let mut index = g_offset;
        let mut buffer = String::new();

        if payload.len() <= l_offset {
            let err_msg = format!("payload too short: {}", payload.len());
            return Err(Error::DNSLogParseFailed(err_msg));
        }

        if payload[index] == DNS_NAME_TAIL {
            return Ok((buffer, index + 1));
        }

        while payload[index] != DNS_NAME_TAIL {
            let name_type = payload[index] & 0xc0;
            match name_type {
                DNS_NAME_RESERVERD_40 | DNS_NAME_RESERVERD_80 => {
                    let err_msg = format!("dns name label type error: {}", payload[index]);
                    return Err(Error::DNSLogParseFailed(err_msg));
                }
                DNS_NAME_COMPRESS_POINTER => {
                    if index + 2 > payload.len() {
                        let err_msg = format!("dns name invalid index: {}", index);
                        return Err(Error::DNSLogParseFailed(err_msg));
                    }
                    let index_ptr = read_u16_be(&payload[index..]) as usize & 0x3fff;
                    if index_ptr >= index {
                        let err_msg = format!("dns name compress pointer invalid: {}", index_ptr);
                        return Err(Error::DNSLogParseFailed(err_msg));
                    }
                    index = index_ptr;
                }
                _ => {
                    let size = index + 1 + payload[index] as usize;
                    if size > payload.len()
                        || (size > g_offset && (size - g_offset) > DNS_NAME_MAX_SIZE)
                    {
                        let err_msg = format!("dns name invalid index: {}", size);
                        return Err(Error::DNSLogParseFailed(err_msg));
                    }

                    if buffer.len() > 0 {
                        buffer.push('.');
                    }
                    match std::str::from_utf8(&payload[index + 1..size]) {
                        Ok(s) => {
                            buffer.push_str(s);
                        }
                        Err(e) => {
                            let err_msg = format!("decode name error {}", e);
                            return Err(Error::DNSLogParseFailed(err_msg));
                        }
                    }
                    if buffer.len() > DNS_NAME_MAX_SIZE {
                        let err_msg = format!("dns name invalid length:{}", buffer.len());
                        return Err(Error::DNSLogParseFailed(err_msg));
                    }
                    index = size;
                    if index >= payload.len() {
                        let err_msg = format!("dns name invalid index: {}", index);
                        return Err(Error::DNSLogParseFailed(err_msg));
                    }

                    if index > l_offset {
                        l_offset = size;
                    } else if payload[index] == DNS_NAME_TAIL {
                        l_offset += 1;
                    }
                }
            }
        }

        Ok((buffer, l_offset + 1))
    }

    fn decode_question(
        &mut self,
        payload: &[u8],
        g_offset: usize,
        info: &mut DnsInfo,
    ) -> Result<usize> {
        let (name, offset) = self.decode_name(payload, g_offset)?;
        let qtype_size = payload[offset..].len();
        if qtype_size < QUESTION_CLASS_TYPE_SIZE {
            let err_msg = format!("question length error: {}", qtype_size);
            return Err(Error::DNSLogParseFailed(err_msg));
        }

        if info.query_name.len() > 0 {
            info.query_name.push(DOMAIN_NAME_SPLIT);
        }
        info.query_name.push_str(&name);
        if info.query_type == DNS_REQUEST {
            info.domain_type = read_u16_be(&payload[offset..]);
            info.msg_type = LogMessageType::Request;
        }

        Ok(offset + QUESTION_CLASS_TYPE_SIZE)
    }

    fn decode_resource_record(
        &mut self,
        payload: &[u8],
        g_offset: usize,
        info: &mut DnsInfo,
    ) -> Result<usize> {
        let (_, offset) = self.decode_name(payload, g_offset)?;

        if payload.len() <= offset {
            let err_msg = format!("payload length error: {}", payload.len());
            return Err(Error::DNSLogParseFailed(err_msg));
        }

        let resource_len = payload[offset..].len();
        if resource_len < RR_RDATA_OFFSET {
            let err_msg = format!("resource record length error: {}", resource_len);
            return Err(Error::DNSLogParseFailed(err_msg));
        }

        info.domain_type = read_u16_be(&payload[offset..]);
        let data_length = read_u16_be(&payload[offset + RR_DATALENGTH_OFFSET..]) as usize;
        if data_length != 0 {
            self.decode_rdata(payload, offset + RR_RDATA_OFFSET, data_length, info)?;
        }

        Ok(offset + RR_RDATA_OFFSET + data_length)
    }

    fn decode_rdata(
        &mut self,
        payload: &[u8],
        g_offset: usize,
        data_length: usize,
        info: &mut DnsInfo,
    ) -> Result<()> {
        if payload.len() < g_offset + data_length {
            return Err(Error::DNSLogParseFailed(
                "invalid data: payload.len() < g_offset + data_length".to_string(),
            ));
        }

        let answer_name_len = info.answers.len();
        if answer_name_len > 0
            && info.answers[answer_name_len - 1..] != DOMAIN_NAME_SPLIT.to_string()
        {
            info.answers.push(DOMAIN_NAME_SPLIT);
        }

        match info.domain_type {
            DNS_TYPE_A | DNS_TYPE_AAAA => match data_length {
                IPV4_ADDR_LEN | IPV6_ADDR_LEN => {
                    if let Some(ipaddr) = parse_ip_slice(&payload[g_offset..g_offset + data_length])
                    {
                        info.answers.push_str(&ipaddr.to_string());
                    }
                }
                _ => {
                    let err_msg = format!(
                        "domain type {} data length {} invalid",
                        info.domain_type, data_length
                    );
                    return Err(Error::DNSLogParseFailed(err_msg));
                }
            },
            DNS_TYPE_NS | DNS_TYPE_DNAME | DNS_TYPE_SOA => {
                if data_length > DNS_NAME_MAX_SIZE {
                    let err_msg = format!(
                        "domain type {} data length {} invalid",
                        info.domain_type, data_length
                    );
                    return Err(Error::DNSLogParseFailed(err_msg));
                }

                let (name, _) = self.decode_name(payload, g_offset)?;
                info.answers.push_str(&name);
            }
            DNS_TYPE_WKS => {
                if data_length < DNS_TYPE_WKS_LENGTH {
                    let err_msg = format!(
                        "domain type {} data length {} invalid",
                        info.domain_type, data_length
                    );
                    return Err(Error::DNSLogParseFailed(err_msg));
                }
                if let Some(ipaddr) = parse_ip_slice(&payload[g_offset..g_offset + data_length]) {
                    info.answers.push_str(&ipaddr.to_string());
                }
            }
            DNS_TYPE_PTR => {
                if data_length != DNS_TYPE_PTR_LENGTH {
                    let err_msg = format!(
                        "domain type {} data length {} invalid",
                        info.domain_type, data_length
                    );
                    return Err(Error::DNSLogParseFailed(err_msg));
                }
            }
            DNS_TYPE_CNAME => {
                // doing nothing
            }
            _ => {
                let err_msg = format!(
                    "other domain type {} data length {} invalid",
                    info.domain_type, data_length
                );
                return Err(Error::DNSLogParseFailed(err_msg));
            }
        }
        Ok(())
    }

    fn set_status(&mut self, status_code: u8, info: &mut DnsInfo) {
        if status_code == 0 {
            info.status = L7ResponseStatus::Ok;
        } else if status_code == 1 || status_code == 3 {
            self.perf_stats.as_mut().map(|p| p.inc_req_err());
            info.status = L7ResponseStatus::ClientError;
        } else {
            self.perf_stats.as_mut().map(|p| p.inc_resp_err());
            info.status = L7ResponseStatus::ServerError;
        }
    }

    fn decode_payload(&mut self, payload: &[u8], info: &mut DnsInfo) -> Result<()> {
        if payload.len() <= DNS_HEADER_SIZE {
            let err_msg = format!("dns payload length too short:{}", payload.len());
            return Err(Error::DNSLogParseFailed(err_msg));
        }
        info.trans_id = read_u16_be(&payload[..DNS_HEADER_FLAGS_OFFSET]);
        info.query_type = payload[DNS_HEADER_FLAGS_OFFSET] & 0x80;
        let code = payload[DNS_HEADER_FLAGS_OFFSET + 1] & 0xf;
        info.status_code = Some(code as i32);

        let qd_count = read_u16_be(&payload[DNS_HEADER_QDCOUNT_OFFSET..]);
        let an_count = read_u16_be(&payload[DNS_HEADER_ANCOUNT_OFFSET..]);
        let ns_count = read_u16_be(&payload[DNS_HEADER_NSCOUNT_OFFSET..]);

        let mut g_offset = DNS_HEADER_SIZE;
        for _i in 0..qd_count {
            g_offset = self.decode_question(payload, g_offset, info)?;
        }

        if info.query_type == DNS_RESPONSE {
            info.query_type = 1;

            for _i in 0..an_count {
                g_offset = self.decode_resource_record(payload, g_offset, info)?;
            }

            for _i in 0..ns_count {
                g_offset = self.decode_resource_record(payload, g_offset, info)?;
            }

            self.perf_stats.as_mut().map(|p| p.inc_resp());
            self.set_status(code, info);
            info.msg_type = LogMessageType::Response;
        } else {
            self.perf_stats.as_mut().map(|p| p.inc_req());
        }

        Ok(())
    }

    fn parse(&mut self, payload: &[u8], info: &mut DnsInfo, param: &ParseParam) -> Result<()> {
        let proto = param.l4_protocol;
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };
        match proto {
            IpProtocol::UDP => self.decode_payload(payload, info),
            IpProtocol::TCP => {
                if payload.len() <= DNS_TCP_PAYLOAD_OFFSET {
                    let err_msg = format!("dns payload length error:{}", payload.len());
                    return Err(Error::DNSLogParseFailed(err_msg));
                }

                let size = read_u16_be(payload) as usize;
                if size != payload[DNS_TCP_PAYLOAD_OFFSET..].len() {
                    self.decode_payload(payload, info)
                } else {
                    self.decode_payload(&payload[DNS_TCP_PAYLOAD_OFFSET..], info)
                        .or_else(|_| {
                            self.reset();
                            self.decode_payload(payload, info)
                        })
                }
            }
            _ => {
                let err_msg = format!("dns payload length error:{}", payload.len());
                Err(Error::DNSLogParseFailed(err_msg))
            }
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

            let mut dns = DnsLog::default();
            let param = &ParseParam::new(
                packet as &MetaPacket,
                log_cache.clone(),
                Default::default(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Default::default(),
                true,
                true,
            );
            let is_dns = dns.check_payload(payload, param);
            dns.reset();
            let info = dns.parse_payload(payload, param);
            if let Ok(info) = info {
                match info.unwrap_single() {
                    L7ProtocolInfo::DnsInfo(i) => {
                        output.push_str(&format!("{:?} is_dns: {}\n", i, is_dns));
                    }
                    _ => unreachable!(),
                }
            } else {
                output.push_str(&format!("{:?} is_dns: {}\n", DnsInfo::default(), is_dns));
            }
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
            ("dns.pcap", "dns.result"),
            ("a-and-ns.pcap", "a-and-ns.result"),
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
        let expected = vec![(
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
        )];

        for item in expected.iter() {
            assert_eq!(item.1, run_perf(item.0), "parse pcap {} unexcepted", item.0);
        }
    }

    fn run_perf(pcap: &str) -> L7PerfStats {
        let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));
        let mut dns = DnsLog::default();

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
            let _ = dns.parse_payload(
                packet.get_l4_payload().unwrap(),
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
}
