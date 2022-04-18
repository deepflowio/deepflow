use bytes::Bytes;
use httpbis::for_test::hpack;

use super::LogMessageType;
use super::{consts::*, AppProtoLogsInfo, L7LogParse};

use crate::common::enums::{IpProtocol, PacketDirection};
use crate::flow_generator::error::{Error, Result};
use crate::proto::flow_log;
use crate::utils::bytes::read_u32_be;

#[derive(Debug, Default, Clone)]
pub struct HttpInfo {
    pub stream_id: u32,
    pub version: String,
    pub trace_id: String,
    pub span_id: String,

    pub method: String,
    pub path: String,
    pub host: String,
    pub client_ip: String,

    pub req_content_length: Option<u64>,
    pub resp_content_length: Option<u64>,
}

impl HttpInfo {
    pub fn merge(&mut self, other: Self) {
        self.resp_content_length = other.resp_content_length;
        if self.trace_id.is_empty() {
            self.trace_id = other.trace_id;
        }
        if self.span_id.is_empty() {
            self.span_id = other.span_id;
        }
    }
}

impl From<HttpInfo> for flow_log::HttpInfo {
    fn from(f: HttpInfo) -> Self {
        flow_log::HttpInfo {
            stream_id: f.stream_id,
            version: f.version,
            method: f.method,
            path: f.path,
            host: f.host,
            client_ip: f.client_ip,
            trace_id: f.trace_id,
            span_id: f.span_id,
            req_content_length: match f.req_content_length {
                Some(length) => length as i64,
                _ => -1,
            },
            resp_content_length: match f.resp_content_length {
                Some(length) => length as i64,
                _ => -1,
            },
        }
    }
}

#[derive(Debug, Default)]
pub struct HttpLog {
    status_code: u16,
    msg_type: LogMessageType,

    info: HttpInfo,
}

impl HttpLog {
    fn reset_logs(&mut self) {
        self.info = HttpInfo::default();
    }

    fn parse_http_v1(&mut self, payload: &[u8], direction: PacketDirection) -> Result<()> {
        let http_payload =
            std::str::from_utf8(payload).map_err(|_| Error::HttpHeaderParseFailed)?;

        let mut content_length: Option<u64> = None;
        if direction == PacketDirection::ServerToClient {
            if payload.len() < HTTP_RESP_MAX_LINE {
                return Err(Error::HttpHeaderParseFailed);
            }
        }

        let (line_info, body_info) = http_payload
            .split_once("\r\n")
            .ok_or(Error::HttpHeaderParseFailed)?;

        if direction == PacketDirection::ServerToClient {
            // HTTP响应行：HTTP/1.1 404 Not Found.
            let (version, status_code) = get_http_resp_info(line_info)?;

            self.info.version = version;
            self.status_code = status_code as u16;

            self.msg_type = LogMessageType::Request;
        } else {
            // HTTP请求行：GET /background.png HTTP/1.0
            let (method, _) = line_info
                .split_once(' ')
                .ok_or(Error::HttpHeaderParseFailed)?;
            check_http_method(method)?;
            let first_space_index = method.len();

            let (_, mut version) = line_info
                .rsplit_once(' ')
                .ok_or(Error::HttpHeaderParseFailed)?;
            version = get_http_request_version(version)?;

            let last_space_index = line_info.len() - HTTP_V1_VERSION_LEN - 1;
            if last_space_index < first_space_index + 1 {
                return Err(Error::HttpHeaderParseFailed);
            }

            self.info.method = method.to_string();
            self.info.path = line_info[first_space_index + 1..last_space_index].to_string();
            self.info.version = version.to_string();

            self.msg_type = LogMessageType::Response;
        }

        let body_lines = body_info.split("\r\n");
        for body_line in body_lines {
            if body_line.starts_with("Content-Length:") {
                content_length = Some(
                    body_line[HTTP_CONTENT_LENGTH_OFFSET..]
                        .parse::<u64>()
                        .unwrap_or_default(),
                );
            } else if direction == PacketDirection::ClientToServer {
                if body_line.starts_with("Host:") {
                    self.info.host = body_line[HTTP_HOST_OFFSET..].to_string();
                }
            }
            // TODO:traceID计算，需要依赖rpc-config部分
        }

        // 当解析完所有Header仍未找到Content-Length，则认为该字段值为0
        if direction == PacketDirection::ServerToClient {
            self.info.resp_content_length = content_length;
        } else {
            self.info.req_content_length = content_length;
        }

        Ok(())
    }

    fn parse_http_v2(&mut self, payload: &[u8], direction: PacketDirection) -> Result<()> {
        let mut content_length: Option<u64> = None;
        let mut header_frame_parsed = false;
        let mut is_httpv2 = false;
        let mut frame_payload = payload;
        let mut httpv2_header = Httpv2Headers::default();

        while frame_payload.len() > HTTPV2_FRAME_HEADER_LENGTH {
            if httpv2_header.parse_headers_frame(frame_payload).is_err() {
                // 当已经解析了Headers帧(该Headers帧未携带“Content-Length”)且发现该报文被截断时，无法进行后续解析，ContentLength为None
                if header_frame_parsed {
                    self.info.stream_id = httpv2_header.stream_id;
                    is_httpv2 = true
                }
                break;
            }

            frame_payload = &frame_payload[HTTPV2_FRAME_HEADER_LENGTH..];

            if !header_frame_parsed && httpv2_header.frame_type == HTTPV2_FRAME_HEADERS_TYPE {
                if httpv2_header.stream_id == 0 {
                    // Headers帧的StreamId不为0
                    // 参考协议：https://tools.ietf.org/html/rfc7540#section-6.2
                    break;
                }

                let mut l_offset = 0;
                if httpv2_header.flags & FLAG_HEADERS_PADDED != 0 {
                    if httpv2_header.frame_length <= frame_payload[0] as u32 {
                        break;
                    }
                    httpv2_header.frame_length -= frame_payload[0] as u32;
                    l_offset += 1;
                }
                if httpv2_header.flags & FLAG_HEADERS_PRIORITY != 0 {
                    l_offset += 5;
                }
                if l_offset >= httpv2_header.frame_length
                    || httpv2_header.frame_length > frame_payload.len() as u32
                {
                    break;
                }

                let header_frame_payload = &frame_payload[..httpv2_header.frame_length as usize];
                let mut decoder = hpack::decoder::Decoder::new();
                let header_list = decoder
                    .decode(Bytes::copy_from_slice(header_frame_payload.as_ref()))
                    .unwrap_or_default();

                for header in header_list.iter() {
                    match header.0.as_ref() {
                        b":method" => {
                            self.msg_type = LogMessageType::Request;
                            self.info.method =
                                String::from_utf8_lossy(header.1.as_ref()).into_owned()
                        }
                        b":status" => {
                            self.msg_type = LogMessageType::Response;

                            self.status_code = std::str::from_utf8(header.1.as_ref())
                                .unwrap_or_default()
                                .parse::<u16>()
                                .unwrap_or_default()
                        }
                        b"host" | b":authority" => {
                            self.info.host = String::from_utf8_lossy(header.1.as_ref()).into_owned()
                        }
                        b":path" => {
                            self.info.path = String::from_utf8_lossy(header.1.as_ref()).into_owned()
                        }
                        b"content-length" => {
                            content_length = Some(
                                std::str::from_utf8(header.1.as_ref())
                                    .unwrap_or_default()
                                    .parse::<u64>()
                                    .unwrap_or_default(),
                            )
                        }
                        _ => {}
                    }
                }
                header_frame_parsed = true;
                if content_length.is_some() {
                    is_httpv2 = true;
                    break;
                }
            } else if header_frame_parsed && httpv2_header.frame_type == HTTPV2_FRAME_DATA_TYPE {
                if httpv2_header.stream_id == 0 {
                    // Data帧的StreamId不为0
                    // 参考协议：https://tools.ietf.org/html/rfc7540#section-6.1
                    break;
                }
                // HTTPv2协议中存在可以通过Headers帧中携带“Content-Length”字段，即可直接进行解析
                // 若未在Headers帧中携带，则去解析Headers帧后的Data帧的数据长度以进行“Content-Length”解析
                // 如grpc-go源码中，在封装FrameHeader头时，不封装“Content-Length”，需要解析其关联的Data帧进行“Content-Length”解析
                // 参考：https://github.com/grpc/grpc-go/blob/master/internal/transport/handler_server.go#L246
                content_length = Some(httpv2_header.frame_length as u64);
                if httpv2_header.flags & FLAG_HEADERS_PADDED != 0 {
                    content_length =
                        Some(content_length.unwrap_or_default() - frame_payload[0] as u64);
                }
                break;
            }

            if httpv2_header.frame_length >= frame_payload.len() as u32 {
                break;
            }
            frame_payload = &frame_payload[httpv2_header.frame_length as usize..];
        }

        if is_httpv2 {
            if direction == PacketDirection::ClientToServer {
                if check_http_method(&self.info.method).is_err() {
                    return Err(Error::HttpHeaderParseFailed);
                }
                self.info.req_content_length = content_length;
            } else {
                if self.status_code < HTTP_STATUS_CODE_MIN
                    || self.status_code > HTTP_STATUS_CODE_MAX
                {
                    return Err(Error::HttpHeaderParseFailed);
                }
                self.info.resp_content_length = content_length;
            }
            self.info.version = "2".to_string();
            return Ok(());
        }
        Err(Error::HttpHeaderParseFailed)
    }
}

impl L7LogParse for HttpLog {
    fn parse(
        &mut self,
        payload: &[u8],
        proto: IpProtocol,
        direction: PacketDirection,
    ) -> Result<()> {
        if proto != IpProtocol::Tcp {
            return Err(Error::InvalidIpProtocol);
        }
        self.reset_logs();

        self.parse_http_v1(payload, direction)
            .or(self.parse_http_v2(payload, direction))
    }

    fn info(&self) -> AppProtoLogsInfo {
        if self.info.version == "2" {
            return AppProtoLogsInfo::HttpV2(self.info.clone());
        }
        AppProtoLogsInfo::HttpV1(self.info.clone())
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct Httpv2Headers {
    pub frame_length: u32,
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: u32,
}

impl Httpv2Headers {
    // HTTPv2帧头格式:https://tools.ietf.org/html/rfc7540#section-4.1
    // +-----------------------------------------------+
    // |                 Length (24)                   |
    // +---------------+---------------+---------------+
    // |   Type (8)    |   Flags (8)   |
    // +-+-------------+---------------+-------------------------------+
    // |R|                 Stream Identifier (31)                      |
    // +=+=============================================================+
    // |                   Frame Payload (0...)                      ...
    // +---------------------------------------------------------------+
    pub fn parse_headers_frame(&mut self, payload: &[u8]) -> Result<()> {
        let frame_type = payload[3];
        if frame_type < HTTPV2_FRAME_TYPE_MIN || frame_type > HTTPV2_FRAME_TYPE_MAX {
            return Err(Error::HttpHeaderParseFailed);
        }

        self.frame_length = read_u32_be(&payload) >> 8;

        self.frame_type = frame_type;
        self.flags = payload[4];
        self.stream_id = read_u32_be(&payload[5..]);
        Ok(())
    }
}

// 参考：https://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html
pub fn check_http_method(method: &str) -> Result<()> {
    match method {
        "OPTIONS" | "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "TRACE" | "CONNECT" => Ok(()),
        _ => Err(Error::HttpHeaderParseFailed),
    }
}

// HTTP请求行：GET /background.png HTTP/1.0
pub fn get_http_method(line_info: &[u8]) -> Result<(String, usize)> {
    // 截取请求行第一个空格前，进行method匹配
    if line_info.len() < HTTP_METHOD_AND_SPACE_MAX_OFFSET {
        return Err(Error::HttpHeaderParseFailed);
    }
    let line_str = std::str::from_utf8(line_info).unwrap_or_default();
    if let Some(space_index) = line_str.find(' ') {
        let method = &line_str[..space_index];
        check_http_method(method)?;
        return Ok((method.to_string(), space_index));
    }
    Err(Error::HttpHeaderParseFailed)
}

pub fn get_http_request_version(version: &str) -> Result<&str> {
    // 参考：https://baike.baidu.com/item/HTTP/243074?fr=aladdin#2
    // HTTPv1版本只有1.0及1.1
    match version {
        HTTP_V1_0_VERSION => return Ok("1.0"),
        HTTP_V1_1_VERSION => return Ok("1.1"),
        _ => return Err(Error::HttpHeaderParseFailed),
    }
}

pub fn get_http_resp_info(line_info: &str) -> Result<(String, u16)> {
    if line_info.len() < HTTP_RESP_MIN_LEN {
        return Err(Error::HttpHeaderParseFailed);
    }
    // HTTP响应行：HTTP/1.1 404 Not Found.
    let mut params = line_info.split(' ');
    // version解析
    let version = match params.next().unwrap_or_default() {
        HTTP_V1_0_VERSION => "1.0".to_string(),
        HTTP_V1_1_VERSION => "1.1".to_string(),
        _ => return Err(Error::HttpHeaderParseFailed),
    };

    // 响应码值校验
    // 参考：https://baike.baidu.com/item/HTTP%E7%8A%B6%E6%80%81%E7%A0%81/5053660?fr=aladdin
    let status_code = params
        .next()
        .unwrap_or_default()
        .parse::<u16>()
        .unwrap_or_default();

    if status_code < HTTP_STATUS_CODE_MIN || status_code > HTTP_STATUS_CODE_MAX {
        return Err(Error::HttpHeaderParseFailed);
    }
    Ok((version, status_code))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    use crate::{common::enums::PacketDirection, utils::test::Capture};

    const FILE_DIR: &str = "resources/test/flow_generator/http";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name), None);
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
        for packet in packets.iter_mut() {
            packet.direction = if packet.lookup_key.dst_port == first_dst_port {
                PacketDirection::ClientToServer
            } else {
                PacketDirection::ServerToClient
            };
            let payload = match packet.get_l4_payload() {
                Some(p) => p,
                None => continue,
            };

            let mut http = HttpLog::default();
            let _ = http.parse(payload, packet.lookup_key.proto, packet.direction);

            output.push_str(&format!("{:?}\r\n", http.info));
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
            ("httpv1.pcap", "httpv1.result"),
            //("h2c_ascii.pcap", "h2c_ascii.result"),
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
}
