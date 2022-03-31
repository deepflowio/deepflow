mod consts;
mod flow_http;
mod flow_http_log;

use consts::*;
pub use flow_http::HttpPerfData;

use crate::{
    flow_generator::error::{Error, Result},
    utils::bytes::*,
};

#[derive(Debug, Default, PartialEq)]
pub struct Httpv2Headers {
    frame_length: u32,
    frame_type: u8,
    flags: u8,
    stream_id: u32,
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
        _ => Err(Error::L7ParseFailed),
    }
}

// HTTP请求行：GET /background.png HTTP/1.0
pub fn get_http_method(line_info: &[u8]) -> Result<(String, usize)> {
    // 截取请求行第一个空格前，进行method匹配
    if line_info.len() < HTTP_METHOD_AND_SPACE_MAX_OFFSET {
        return Err(Error::L7ParseFailed);
    }
    let line_str = std::str::from_utf8(line_info).unwrap_or_default();
    if let Some(space_index) = line_str.find(' ') {
        let method = &line_str[..space_index];
        check_http_method(method)?;
        return Ok((method.to_string(), space_index));
    }
    Err(Error::L7ParseFailed)
}

pub fn get_http_request_version(version: &str) -> Result<&str> {
    // 参考：https://baike.baidu.com/item/HTTP/243074?fr=aladdin#2
    // HTTPv1版本只有1.0及1.1
    match version {
        HTTP_V1_0_VERSION => return Ok("1.0"),
        HTTP_V1_1_VERSION => return Ok("1.1"),
        _ => return Err(Error::L7ParseFailed),
    }
}

pub fn get_http_resp_info(line_info: &str) -> Result<(String, u16)> {
    if line_info.len() < HTTP_RESP_MIN_LEN {
        return Err(Error::L7ParseFailed);
    }
    // HTTP响应行：HTTP/1.1 404 Not Found.
    let mut params = line_info.split(' ');
    // version解析
    let version = match params.next().unwrap_or_default() {
        HTTP_V1_0_VERSION => "1.0".to_string(),
        HTTP_V1_1_VERSION => "1.1".to_string(),
        _ => return Err(Error::L7ParseFailed),
    };

    // 响应码值校验
    // 参考：https://baike.baidu.com/item/HTTP%E7%8A%B6%E6%80%81%E7%A0%81/5053660?fr=aladdin
    let status_code = params
        .next()
        .unwrap_or_default()
        .parse::<u16>()
        .unwrap_or_default();

    if status_code < HTTP_STATUS_CODE_MIN || status_code > HTTP_STATUS_CODE_MAX {
        return Err(Error::L7ParseFailed);
    }
    Ok((version, status_code))
}
