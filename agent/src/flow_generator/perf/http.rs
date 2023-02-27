/*
 * Copyright (c) 2022 Yunshan Networks
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

use std::{cell::RefCell, fmt, rc::Rc, time::Duration};

use nom::AsBytes;

use crate::{
    common::{
        ebpf::EbpfType,
        enums::IpProtocol,
        flow::{FlowPerfStats, L7PerfStats, L7Protocol, PacketDirection},
        l7_protocol_info::L7ProtocolInfo,
        l7_protocol_log::{L7ProtocolParser, L7ProtocolParserInterface, ParseParam},
        meta_packet::MetaPacket,
    },
    config::handler::LogParserConfig,
    flow_generator::{
        error::{Error, Result},
        perf::l7_rrt::L7RrtCache,
        perf::stats::PerfStats,
        perf::L7FlowPerf,
        protocol_logs::{
            check_http_method, consts::*, get_http_request_info, get_http_request_version,
            get_http_resp_info, is_http_v1_payload, parse_v1_headers, AppProtoHead, Httpv2Headers,
            L7ResponseStatus, LogMessageType,
        },
        HttpLog,
    },
};
use public::utils::net::h2pack;

struct HttpSessionData {
    // HTTPv2 Header
    httpv2_headers: Httpv2Headers,

    pub status: L7ResponseStatus,
    pub status_code: u16,
    pub has_log_data: bool,
    pub l7_proto: L7Protocol,
    pub msg_type: LogMessageType,
    rrt_cache: Rc<RefCell<L7RrtCache>>,
}

impl HttpSessionData {
    fn set_http_protocol(&mut self, proto: L7Protocol) {
        match proto {
            L7Protocol::Http1 => self.l7_proto = L7Protocol::Http1,
            L7Protocol::Http2 => {
                if self.l7_proto != L7Protocol::Grpc {
                    self.l7_proto = L7Protocol::Http2
                }
            }
            L7Protocol::Grpc => self.l7_proto = L7Protocol::Grpc,
            _ => {}
        }
    }
}

pub struct HttpPerfData {
    perf_stats: Option<PerfStats>,
    session_data: HttpSessionData,
}

impl PartialEq for HttpPerfData {
    fn eq(&self, other: &HttpPerfData) -> bool {
        self.perf_stats == other.perf_stats
            && self.session_data.l7_proto == other.session_data.l7_proto
            && self.session_data.msg_type == other.session_data.msg_type
            && self.session_data.status == other.session_data.status
            && self.session_data.has_log_data == other.session_data.has_log_data
    }
}

impl Eq for HttpPerfData {}

impl fmt::Debug for HttpPerfData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(perf_stats) = self.perf_stats.as_ref() {
            write!(f, "perf_stats: {:?}", perf_stats)?;
        } else {
            write!(f, "perf_stats: None")?;
        };
        write!(f, "l7_proto: {:?}", self.session_data.l7_proto)?;
        write!(f, "msg_type: {:?}", self.session_data.msg_type)?;
        write!(f, "status {:?}", self.session_data.status)?;
        write!(f, "has_log_data: {:?}", self.session_data.has_log_data)
    }
}

impl L7FlowPerf for HttpPerfData {
    fn parse(
        &mut self,
        config: Option<&LogParserConfig>,
        meta: &MetaPacket,
        flow_id: u64,
    ) -> Result<()> {
        if meta.lookup_key.proto != IpProtocol::Tcp {
            return Err(Error::InvalidIpProtocol);
        }
        let Some(config) = config else {
            return Err(Error::NoParseConfig);
        };
        let payload = meta.get_l4_payload().ok_or(Error::ZeroPayloadLen)?;

        if ParseParam::from(meta).ebpf_type == EbpfType::GoHttp2Uprobe {
            return self.parse_go_http2_uprobe(payload, &ParseParam::from((meta, config)));
        }

        if self
            .parse_http_v1(
                payload,
                meta.lookup_key.timestamp,
                meta.lookup_key.direction,
                flow_id,
            )
            .is_ok()
        {
            self.session_data.has_log_data = true;
            self.session_data.set_http_protocol(L7Protocol::Http1);
            return Ok(());
        }
        if self
            .parse_http_v2(
                payload,
                meta.lookup_key.timestamp,
                meta.lookup_key.direction,
                flow_id,
            )
            .is_ok()
        {
            self.session_data.has_log_data = true;
            self.session_data.set_http_protocol(L7Protocol::Http2);
            return Ok(());
        }

        Err(Error::HttpHeaderParseFailed)
    }

    fn data_updated(&self) -> bool {
        self.perf_stats.is_some()
    }

    fn copy_and_reset_data(&mut self, timeout_count: u32) -> FlowPerfStats {
        if let Some(stats) = self.perf_stats.take() {
            FlowPerfStats {
                l7_protocol: self.session_data.l7_proto,
                l7: L7PerfStats {
                    request_count: stats.req_count,
                    response_count: stats.resp_count,
                    rrt_count: stats.rrt_count,
                    rrt_sum: stats.rrt_sum.as_micros() as u64,
                    rrt_max: stats.rrt_max.as_micros() as u32,
                    err_client_count: stats.req_err_count,
                    err_server_count: stats.resp_err_count,
                    err_timeout: timeout_count,
                },
                ..Default::default()
            }
        } else {
            FlowPerfStats {
                l7_protocol: self.session_data.l7_proto,
                l7: L7PerfStats {
                    err_timeout: timeout_count,
                    ..Default::default()
                },
                ..Default::default()
            }
        }
    }

    fn app_proto_head(&mut self) -> Option<(AppProtoHead, u16)> {
        if (self.session_data.l7_proto != L7Protocol::Http1
            && self.session_data.l7_proto != L7Protocol::Http2
            && self.session_data.l7_proto != L7Protocol::Grpc)
            || !self.session_data.has_log_data
        {
            return None;
        }
        self.session_data.has_log_data = false;

        let rrt = self
            .perf_stats
            .as_ref()
            .map(|s| s.rrt_last.as_micros() as u64)
            .unwrap_or_default();

        Some((
            AppProtoHead {
                proto: self.session_data.l7_proto,
                msg_type: self.session_data.msg_type,
                rrt,
            },
            0,
        ))
    }
}

impl HttpPerfData {
    pub fn new(rrt_cache: Rc<RefCell<L7RrtCache>>) -> Self {
        let session_data = HttpSessionData {
            httpv2_headers: Httpv2Headers::default(),
            status_code: 0,
            status: L7ResponseStatus::default(),
            has_log_data: false,
            l7_proto: L7Protocol::default(),
            msg_type: LogMessageType::default(),
            rrt_cache: rrt_cache,
        };

        Self {
            perf_stats: None,
            session_data,
        }
    }

    fn parse_http_v1(
        &mut self,
        payload: &[u8],
        timestamp: Duration,
        direction: PacketDirection,
        flow_id: u64,
    ) -> Result<()> {
        if !is_http_v1_payload(payload) {
            return Err(Error::HttpHeaderParseFailed);
        }

        let mut headers = parse_v1_headers(payload);
        let Some(first_line) = headers.next() else {
            return Err(Error::HttpHeaderParseFailed);
        };

        if direction == PacketDirection::ServerToClient {
            // HTTP响应行：HTTP/1.1 404 Not Found.
            let (_, status_code) = get_http_resp_info(first_line)?;
            self.session_data.msg_type = LogMessageType::Response;

            let perf_stats = self.perf_stats.get_or_insert(PerfStats::default());
            self.session_data.status_code = status_code as u16;
            match status_code {
                HTTP_STATUS_CLIENT_ERROR_MIN..=HTTP_STATUS_CLIENT_ERROR_MAX => {
                    perf_stats.req_err_count += 1;
                    self.session_data.status = L7ResponseStatus::ClientError;
                }
                HTTP_STATUS_SERVER_ERROR_MIN..=HTTP_STATUS_SERVER_ERROR_MAX => {
                    perf_stats.resp_err_count += 1;
                    self.session_data.status = L7ResponseStatus::ServerError;
                }
                _ => {
                    self.session_data.status = L7ResponseStatus::Ok;
                }
            }

            perf_stats.resp_count += 1;
            perf_stats.rrt_last = Duration::ZERO;

            let req_timestamp = match self
                .session_data
                .rrt_cache
                .borrow_mut()
                .get_and_remove_l7_req_time(flow_id, None)
            {
                Some(t) => t,
                None => return Ok(()),
            };

            if timestamp < req_timestamp {
                return Ok(());
            }

            let rrt = timestamp - req_timestamp;
            if rrt > perf_stats.rrt_max {
                perf_stats.rrt_max = rrt;
            }
            perf_stats.rrt_last = rrt;
            perf_stats.rrt_sum += rrt;
            perf_stats.rrt_count += 1;
        } else {
            // HTTP请求行：GET /background.png HTTP/1.0
            let Ok((method, _, version)) = get_http_request_info(first_line) else {
                return Err(Error::HttpHeaderParseFailed);
            };
            check_http_method(method)?;
            get_http_request_version(version)?;

            self.session_data.msg_type = LogMessageType::Request;

            let perf_stats = self.perf_stats.get_or_insert(PerfStats::default());
            perf_stats.req_count += 1;
            perf_stats.rrt_last = Duration::ZERO;
            self.session_data
                .rrt_cache
                .borrow_mut()
                .add_req_time(flow_id, None, timestamp);
        }
        Ok(())
    }

    // HTTPv2-HEADERS-FramePayload类型格式:https://tools.ietf.org/html/rfc7540#section-6.2
    // +---------------+
    // |Pad Length? (8)|
    // +-+-------------+-----------------------------------------------+
    // |E|                 Stream Dependency? (31)                     |
    // +-+-------------+-----------------------------------------------+
    // |  Weight? (8)  |
    // +-+-------------+-----------------------------------------------+
    // |                   Header Block Fragment (*)                 ...
    // +---------------------------------------------------------------+
    // |                           Padding (*)                       ...
    // +---------------------------------------------------------------+
    fn parse_headers_frame_payload(&mut self, payload: &[u8]) -> Result<u16> {
        let mut l_offset = 0;
        let mut end_index = 0;

        if self.session_data.httpv2_headers.flags & FLAG_HEADERS_PADDED != 0 {
            if u32::from(payload[0]) > self.session_data.httpv2_headers.frame_length {
                return Err(Error::HttpHeaderParseFailed);
            }
            l_offset += 1;
            end_index = payload[0] as usize;
        }

        if self.session_data.httpv2_headers.flags & FLAG_HEADERS_PRIORITY != 0 {
            l_offset += 5;
        }

        if payload.len() <= l_offset {
            return Err(Error::HttpHeaderParseFailed);
        }

        end_index = self.session_data.httpv2_headers.frame_length as usize - end_index;

        if end_index > payload.len() || end_index < l_offset {
            return Err(Error::HttpHeaderParseFailed);
        }

        let frame_payload = &payload[l_offset..end_index];

        let mut parser = h2pack::parser::Parser::new();

        let parse_rst = parser.parse(frame_payload);

        if let Err(_) = parse_rst {
            return Err(Error::HttpHeaderParseFailed);
        }

        let header_list = parse_rst.unwrap();
        let mut ret = Err(Error::HttpHeaderParseFailed);
        for header in header_list.iter() {
            match header.0.as_slice() {
                b":method" => {
                    ret = Ok(0);
                }
                b":status" => {
                    ret = Ok(std::str::from_utf8(header.1.as_slice())
                        .unwrap_or_default()
                        .parse::<u16>()
                        .unwrap_or_default())
                }
                b"content-type" => {
                    if header.1.starts_with(b"application/grpc") {
                        // change to grpc protocol
                        self.session_data.set_http_protocol(L7Protocol::Grpc);
                    }
                }
                _ => {}
            }
        }
        ret
    }

    fn has_magic(payload: &[u8]) -> bool {
        if payload.len() < HTTPV2_MAGIC_LENGTH {
            return false;
        }
        &payload[..HTTPV2_MAGIC_PREFIX.len()] == HTTPV2_MAGIC_PREFIX.as_bytes()
    }

    fn parse_frame(&mut self, payload: &[u8]) -> Result<u16> {
        let mut frame_payload = payload;
        while frame_payload.len() > H2C_HEADER_SIZE {
            if Self::has_magic(frame_payload) {
                frame_payload = &frame_payload[HTTPV2_MAGIC_LENGTH..];
                continue;
            }
            self.session_data
                .httpv2_headers
                .parse_headers_frame(frame_payload)?;

            // 值得注意的是，关于H2存在发送端主动通过Settings帧发起WindowUpdate请求时或发送方测量最小往返时间（PING）时，
            // 接收端如果支持配置会在其发送第一个请求时携带上述帧，可能会影响H2-HEADERS帧的位置，将HEADERS帧前的其它帧跳过。
            // 参考：https://tools.ietf.org/html/rfc7540#section-6.5
            if self.session_data.httpv2_headers.frame_type == FRAME_HEADERS {
                if self.session_data.httpv2_headers.stream_id == 0 {
                    return Err(Error::HttpHeaderParseFailed);
                }

                // TODO 调用第三库解析有时会导致panic, 先默认返回成功
                // return Ok(200);
                frame_payload = &frame_payload[H2C_HEADER_SIZE..];
                return self.parse_headers_frame_payload(frame_payload);
            }
            let offset = self.session_data.httpv2_headers.frame_length as usize + H2C_HEADER_SIZE;

            if frame_payload.len() <= offset {
                return Err(Error::HttpHeaderParseFailed);
            }
            frame_payload = &frame_payload[offset..];
        }
        Err(Error::HttpHeaderParseFailed)
    }

    // HTTPv2协议参考:https://tools.ietf.org/html/rfc7540
    fn parse_http_v2(
        &mut self,
        payload: &[u8],
        timestamp: Duration,
        direction: PacketDirection,
        flow_id: u64,
    ) -> Result<()> {
        let status_code = self.parse_frame(payload)?;
        if direction == PacketDirection::ServerToClient {
            self.session_data.msg_type = LogMessageType::Response;

            let perf_stats = self.perf_stats.get_or_insert(PerfStats::default());
            self.session_data.status_code = status_code as u16;
            match status_code {
                HTTP_STATUS_CLIENT_ERROR_MIN..=HTTP_STATUS_CLIENT_ERROR_MAX => {
                    perf_stats.req_err_count += 1;
                    self.session_data.status = L7ResponseStatus::ClientError;
                }
                HTTP_STATUS_SERVER_ERROR_MIN..=HTTP_STATUS_SERVER_ERROR_MAX => {
                    perf_stats.resp_err_count += 1;
                    self.session_data.status = L7ResponseStatus::ServerError;
                }
                _ => {
                    self.session_data.status = L7ResponseStatus::Ok;
                }
            }
            perf_stats.rrt_last = Duration::ZERO;

            let req_timestamp = match self
                .session_data
                .rrt_cache
                .borrow_mut()
                .get_and_remove_l7_req_time(
                    flow_id,
                    Some(self.session_data.httpv2_headers.stream_id),
                ) {
                Some(t) => t,
                None => return Ok(()),
            };

            if timestamp < req_timestamp {
                return Ok(());
            }

            let rrt = timestamp - req_timestamp;
            if rrt > perf_stats.rrt_max {
                perf_stats.rrt_max = rrt;
            }
            perf_stats.rrt_last = rrt;
            perf_stats.rrt_sum += rrt;
            perf_stats.rrt_count += 1;
            perf_stats.resp_count += 1;
        } else {
            self.session_data.msg_type = LogMessageType::Request;
            let perf_stats = self.perf_stats.get_or_insert(PerfStats::default());
            perf_stats.req_count += 1;
            perf_stats.rrt_last = Duration::ZERO;
            self.session_data.rrt_cache.borrow_mut().add_req_time(
                flow_id,
                Some(self.session_data.httpv2_headers.stream_id),
                timestamp,
            );
        }
        Ok(())
    }

    fn parse_go_http2_uprobe(&mut self, payload: &[u8], param: &ParseParam) -> Result<()> {
        let mut log = L7ProtocolParser::Http(Box::new(HttpLog::new_v2(false)));
        let perf_stats = self.perf_stats.get_or_insert(PerfStats::default());
        if let L7ProtocolInfo::HttpInfo(h) = log.parse_payload(payload, param)?.get(0).unwrap() {
            self.session_data.httpv2_headers.stream_id = h.stream_id.unwrap_or_default();
            self.session_data.l7_proto = h.get_l7_protocol_with_tls();
            if let Some(code) = h.status_code {
                match code as u16 {
                    HTTP_STATUS_CLIENT_ERROR_MIN..=HTTP_STATUS_CLIENT_ERROR_MAX => {
                        perf_stats.req_err_count += 1;
                    }
                    HTTP_STATUS_SERVER_ERROR_MIN..=HTTP_STATUS_SERVER_ERROR_MAX => {
                        perf_stats.resp_err_count += 1;
                    }
                    _ => {}
                }
            }

            let ebpf_param = param.ebpf_param.unwrap();
            if ebpf_param.is_req_end {
                perf_stats.req_count += 1;
            } else if ebpf_param.is_resp_end {
                perf_stats.resp_count += 1;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    use crate::{config::handler::L7LogDynamicConfig, utils::test::Capture};

    const FILE_DIR: &str = "resources/test/flow_generator/http";

    fn run(pcap: &str) -> HttpPerfData {
        let rrt_cache = Rc::new(RefCell::new(L7RrtCache::new(100)));
        let mut http_perf_data = HttpPerfData::new(rrt_cache);

        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(pcap), Some(512));
        let mut packets = capture.as_meta_packets();
        if packets.len() < 2 {
            return http_perf_data;
        }

        let first_dst_port = packets[0].lookup_key.dst_port;
        for packet in packets.iter_mut() {
            if packet.lookup_key.dst_port == first_dst_port {
                packet.lookup_key.direction = PacketDirection::ClientToServer;
            } else {
                packet.lookup_key.direction = PacketDirection::ServerToClient;
            }
            let _ = http_perf_data.parse(
                Some(&LogParserConfig {
                    l7_log_collect_nps_threshold: 0,
                    l7_log_session_aggr_timeout: Duration::new(0, 0),
                    l7_log_dynamic: L7LogDynamicConfig::default(),
                }),
                packet,
                0x1f3c01010,
            );
        }
        http_perf_data
    }

    #[test]
    fn check() {
        let expected = vec![
            (
                "httpv1.pcap",
                HttpPerfData {
                    perf_stats: Some(PerfStats {
                        req_count: 1,
                        resp_count: 1,
                        req_err_count: 0,
                        resp_err_count: 0,
                        rrt_count: 1,
                        rrt_max: Duration::from_nanos(84051000),
                        rrt_last: Duration::from_nanos(84051000),
                        rrt_sum: Duration::from_nanos(84051000),
                    }),
                    session_data: HttpSessionData {
                        l7_proto: L7Protocol::Http1,
                        status_code: 200,
                        status: L7ResponseStatus::Ok,
                        has_log_data: true,
                        msg_type: LogMessageType::Response,
                        rrt_cache: Rc::new(RefCell::new(L7RrtCache::new(100))),
                        httpv2_headers: Httpv2Headers::default(),
                    },
                },
            ),
            (
                "h2c_ascii.pcap",
                HttpPerfData {
                    perf_stats: Some(PerfStats {
                        req_count: 1,
                        resp_count: 1,
                        req_err_count: 0,
                        resp_err_count: 0,
                        rrt_count: 1,
                        rrt_max: Duration::from_nanos(2023000),
                        rrt_last: Duration::from_nanos(2023000),
                        rrt_sum: Duration::from_nanos(2023000),
                    }),
                    session_data: HttpSessionData {
                        l7_proto: L7Protocol::Grpc,
                        status_code: 200,
                        status: L7ResponseStatus::Ok,
                        has_log_data: true,
                        msg_type: LogMessageType::Response,
                        rrt_cache: Rc::new(RefCell::new(L7RrtCache::new(100))),
                        httpv2_headers: Httpv2Headers::default(),
                    },
                },
            ),
        ];

        for item in expected.iter() {
            assert_eq!(item.1, run(item.0), "parse pcap {} unexcepted", item.0);
        }
    }
}
