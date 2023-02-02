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

use serde::{Serialize, Serializer};

use std::{fmt, str};

use super::super::{value_is_default, AppProtoHead, L7ResponseStatus, LogMessageType};

use crate::{
    common::{
        enums::IpProtocol,
        flow::L7Protocol,
        flow::PacketDirection,
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ProtocolParserInterface, ParseParam},
    },
    flow_generator::{
        error::{Error, Result},
        protocol_logs::pb_adapter::{L7ProtocolSendLog, L7Request, L7Response},
    },
    parse_common,
};

const SEPARATOR_SIZE: usize = 2;

#[derive(Serialize, Debug, Default, Clone)]
pub struct RedisInfo {
    msg_type: LogMessageType,
    #[serde(skip)]
    start_time: u64,
    #[serde(skip)]
    end_time: u64,
    #[serde(skip)]
    is_tls: bool,

    #[serde(
        rename = "request_resource",
        skip_serializing_if = "value_is_default",
        serialize_with = "vec_u8_to_string"
    )]
    pub request: Vec<u8>, // 命令字段包括参数例如："set key value"
    #[serde(
        skip_serializing_if = "value_is_default",
        serialize_with = "vec_u8_to_string"
    )]
    pub request_type: Vec<u8>, // 命令类型不包括参数例如：命令为"set key value"，命令类型为："set"
    #[serde(
        rename = "response_result",
        skip_serializing_if = "value_is_default",
        serialize_with = "vec_u8_to_string"
    )]
    pub response: Vec<u8>, // 整数回复 + 批量回复 + 多条批量回复
    #[serde(skip)]
    pub status: Vec<u8>, // '+'
    #[serde(
        rename = "response_expection",
        skip_serializing_if = "value_is_default",
        serialize_with = "vec_u8_to_string"
    )]
    pub error: Vec<u8>, // '-'
    #[serde(rename = "response_status")]
    pub resp_status: L7ResponseStatus,

    cap_seq: Option<u64>,
}

impl L7ProtocolInfoInterface for RedisInfo {
    fn session_id(&self) -> Option<u32> {
        None
    }

    fn merge_log(&mut self, other: L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::RedisInfo(other) = other {
            if other.start_time < self.start_time {
                self.start_time = other.start_time;
            }
            if other.end_time > self.end_time {
                self.end_time = other.end_time;
            }
            return self.merge(other);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::Redis,
            msg_type: self.msg_type,
            rrt: self.end_time - self.start_time,
        })
    }

    fn is_tls(&self) -> bool {
        self.is_tls
    }
}

pub fn vec_u8_to_string<S>(v: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&String::from_utf8_lossy(v))
}

impl RedisInfo {
    pub fn merge(&mut self, other: Self) -> Result<()> {
        if !self.can_merge(&other) {
            return Err(Error::L7ProtocolCanNotMerge(L7ProtocolInfo::RedisInfo(
                other,
            )));
        }
        self.response = other.response;
        self.status = other.status;
        self.error = other.error;
        self.resp_status = other.resp_status;
        Ok(())
    }

    pub fn set_packet_seq(&mut self, param: &ParseParam) {
        if let Some(p) = param.ebpf_param {
            self.cap_seq = Some(p.cap_seq);
        }
    }

    pub fn can_merge(&self, resp: &Self) -> bool {
        if let (Some(req_seq), Some(resp_seq)) = (self.cap_seq, resp.cap_seq) {
            return resp_seq > req_seq && resp_seq - req_seq == 1;
        }
        true
    }
}

impl fmt::Display for RedisInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RedisInfo {{ request: {:?}, ",
            str::from_utf8(&self.request).unwrap_or_default()
        )?;
        write!(
            f,
            "request_type: {:?}, ",
            str::from_utf8(&self.request_type).unwrap_or_default()
        )?;
        write!(
            f,
            "response: {:?}, ",
            str::from_utf8(&self.response).unwrap_or_default()
        )?;
        write!(
            f,
            "status: {:?}, ",
            str::from_utf8(&self.status).unwrap_or_default()
        )?;
        write!(
            f,
            "error: {:?} }}",
            str::from_utf8(&self.error).unwrap_or_default()
        )
    }
}

impl From<RedisInfo> for L7ProtocolSendLog {
    fn from(f: RedisInfo) -> Self {
        let log = L7ProtocolSendLog {
            req: L7Request {
                req_type: String::from_utf8_lossy(f.request_type.as_slice()).to_string(),
                resource: String::from_utf8_lossy(f.request.as_slice()).to_string(),
                ..Default::default()
            },
            resp: L7Response {
                status: f.resp_status,
                exception: String::from_utf8_lossy(f.error.as_slice()).to_string(),
                result: String::from_utf8_lossy(f.response.as_slice()).to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        return log;
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RedisLog {
    info: RedisInfo,
}

impl L7ProtocolParserInterface for RedisLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol() {
            return false;
        }
        self.info.is_tls = param.is_tls();
        self.info.set_packet_seq(param);
        Self::redis_check_protocol(payload, param)
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<Vec<L7ProtocolInfo>> {
        parse_common!(self, param);
        self.info.is_tls = param.is_tls();
        self.info.set_packet_seq(param);
        self.parse(payload, param.l4_protocol, param.direction, None, None)?;
        Ok(vec![L7ProtocolInfo::RedisInfo(self.info.clone())])
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Redis
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

impl RedisLog {
    fn reset(&mut self) {
        *self = RedisLog::default();
    }

    fn fill_request(&mut self, context: Vec<u8>) {
        self.info.request_type = match (&context).iter().position(|&x| x == b' ') {
            Some(i) if i > 0 => Vec::from(&context[..i]),
            _ => context.clone(),
        };
        self.info.msg_type = LogMessageType::Request;
        self.info.request = context;
    }

    fn fill_response(&mut self, context: Vec<u8>, error_response: bool) {
        self.info.msg_type = LogMessageType::Response;
        if context.is_empty() {
            return;
        }

        self.info.resp_status = L7ResponseStatus::Ok;
        match context[0] {
            b'+' => self.info.status = context,
            b'-' if error_response => {
                self.info.error = context;
                self.info.resp_status = L7ResponseStatus::ServerError;
            }
            b'-' if !error_response => self.info.response = context,
            _ => self.info.response = context,
        }
    }

    pub fn redis_check_protocol(payload: &[u8], param: &ParseParam) -> bool {
        if param.l4_protocol != IpProtocol::Tcp {
            return false;
        }

        if payload[0] != b'*' {
            return false;
        }
        decode_asterisk(payload, true).is_some()
    }

    fn parse(
        &mut self,
        payload: &[u8],
        proto: IpProtocol,
        direction: PacketDirection,
        _is_req_end: Option<bool>,
        _is_resp_end: Option<bool>,
    ) -> Result<()> {
        if proto != IpProtocol::Tcp {
            return Err(Error::InvalidIpProtocol);
        }

        let (context, _, error_response) =
            decode(payload, direction == PacketDirection::ClientToServer)
                .ok_or(Error::RedisLogParseFailed)?;
        match direction {
            PacketDirection::ClientToServer => self.fill_request(context),
            PacketDirection::ServerToClient => self.fill_response(context, error_response),
        };
        Ok(())
    }
}

// 协议解析：http://redisdoc.com/topic/protocol.html#
fn find_separator(payload: &[u8]) -> Option<usize> {
    let len = payload.len();
    if len < 2 {
        return None;
    }

    for i in 0..len - 1 {
        if payload[i] == b'\r' && payload[i + 1] == b'\n' {
            return Some(i);
        }
    }
    None
}

fn decode_integer(payload: &[u8]) -> Option<(isize, usize)> {
    let separator_pos = find_separator(payload)?;
    // 整数至少占一位
    if separator_pos < 1 {
        return None;
    }

    let integer = str::from_utf8(&payload[..separator_pos])
        .unwrap_or_default()
        .parse::<isize>()
        .ok()?;

    Some((integer, separator_pos + SEPARATOR_SIZE))
}

// 格式为"$3\r\nSET\r\n"
fn decode_dollor(payload: &[u8], strict: bool) -> Option<(&[u8], usize)> {
    let mut offset = 1; // 开头的$
    let (next_data_len, sub_offset) = decode_integer(&payload[offset..])?;

    // $-1 $0时返回
    if next_data_len <= 0 {
        return Some((
            &payload[offset..offset + sub_offset - SEPARATOR_SIZE],
            offset + sub_offset,
        ));
    }

    offset += sub_offset;
    let next_data_len = next_data_len as usize;

    if offset + next_data_len + SEPARATOR_SIZE > payload.len()
        || payload[offset + next_data_len] != b'\r'
        || payload[offset + next_data_len + 1] != b'\n'
    {
        if strict {
            return None;
        }
        // 返回所有内容
        return Some((&payload[offset..], payload.len()));
    }

    // 完全合法
    Some((
        &payload[offset..offset + next_data_len],
        offset + next_data_len + 2,
    ))
}

// 命令为"set mykey myvalue"，实际封装为"*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n"
fn decode_asterisk(payload: &[u8], strict: bool) -> Option<(Vec<u8>, usize)> {
    let mut offset = 1; // 开头的 *

    // 提取请求参数个数/批量回复个数
    let (next_data_num, sub_offset) = decode_integer(&payload[offset..])?;

    if next_data_num <= 0 {
        // 无内容的多条批量回复: "*-1\r\n"
        // 空白内容的多条批量回复: "*0\r\n"
        return Some((
            payload[offset..offset + sub_offset - SEPARATOR_SIZE].to_vec(),
            offset + sub_offset,
        ));
    }
    offset += sub_offset;

    let mut ret_vec = Vec::new();
    let len = payload.len();

    for _ in 0..next_data_num {
        if let Some((sub_vec, sub_offset, _)) = decode(&payload[offset..], strict) {
            if sub_offset == 0 {
                if strict {
                    return None;
                }
                return Some((ret_vec, offset));
            }

            if !ret_vec.is_empty() {
                ret_vec.push(b' ');
            }
            ret_vec.extend_from_slice(sub_vec.as_slice());

            offset += sub_offset;
            if offset >= len {
                return Some((ret_vec, len));
            }
        }
    }
    Some((ret_vec, offset))
}

fn decode_str(payload: &[u8], limit: usize) -> Option<(&[u8], usize)> {
    let len = payload.len();
    let separator_pos = find_separator(payload).unwrap_or(len);

    if separator_pos > limit {
        return Some((
            // 截取数据后，并不会在末尾增加'...'提示
            &payload[..limit],
            limit,
        ));
    }

    Some((&payload[..separator_pos], separator_pos))
}

// 函数在入参为"$-1"或"-1"时都返回"-1", 使用第三个参数区分是否为错误回复
pub fn decode(payload: &[u8], strict: bool) -> Option<(Vec<u8>, usize, bool)> {
    if payload.len() < SEPARATOR_SIZE {
        return None;
    }

    match payload[0] {
        // 请求或多条批量回复
        b'*' => decode_asterisk(payload, strict).map(|(v, s)| (v, s, false)),
        // 状态回复,整数回复
        b'+' | b':' => decode_str(payload, 32).map(|(v, s)| (v.to_vec(), s, false)),
        // 错误回复
        b'-' => decode_str(payload, 256).map(|(v, s)| (v.to_vec(), s, true)),
        // 批量回复
        b'$' => decode_dollor(payload, strict).map(|(v, s)| (v.to_vec(), s, false)),
        _ => None,
    }
}

pub fn decode_error_code(context: &[u8]) -> Option<&[u8]> {
    for (i, ch) in context.iter().enumerate() {
        if *ch == b' ' || *ch == b'\n' {
            return Some(&context[..i]);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    use crate::{
        common::{flow::PacketDirection, MetaPacket},
        utils::test::Capture,
    };

    const FILE_DIR: &str = "resources/test/flow_generator/redis";

    fn run(name: &str) -> String {
        let pcap_file = Path::new(FILE_DIR).join(name);
        let capture = Capture::load_pcap(pcap_file, None);
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut output: String = String::new();
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

            let mut redis = RedisLog::default();
            let _ = redis.parse(
                payload,
                packet.lookup_key.proto,
                packet.lookup_key.direction,
                None,
                None,
            );
            let is_redis =
                RedisLog::redis_check_protocol(payload, &ParseParam::from(packet as &MetaPacket));
            output.push_str(&format!("{} is_redis: {}\r\n", redis.info, is_redis));
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
            ("redis.pcap", "redis.result"),
            ("redis-error.pcap", "redis-error.result"),
            ("redis-debug.pcap", "redis-debug.result"),
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
    fn test_decode() {
        let payload = [b'*', b'-', b'1', b'\r', b'\n'];
        let (context, n, e) = decode(payload.as_slice(), true).unwrap();
        assert_eq!(context, "-1".as_bytes());
        assert_eq!(n, payload.len());
        assert_eq!(e, false);

        let payload = [
            b'*', b'3', b'\r', b'\n', b'$', b'3', b'\r', b'\n', b'S', b'E', b'T', b'\r', b'\n',
            b'$', b'5', b'\r', b'\n', b'm', b'y', b'k', b'e', b'y', b'\r', b'\n', b'$', b'7',
            b'\r', b'\n', b'm', b'y', b'v', b'a', b'l', b'u', b'e', b'\r', b'\n',
        ];

        let (context, n, e) = decode(payload.as_slice(), true).unwrap();
        assert_eq!(context, "SET mykey myvalue".as_bytes());
        assert_eq!(n, payload.len());
        assert_eq!(e, false);

        let payload = [b'$', b'0', b'\r', b'\n'];
        let (context, n, _) = decode(payload.as_slice(), true).unwrap();
        assert_eq!(context, "0".as_bytes());
        assert_eq!(n, payload.len());

        let payload = [b'$', b'-', b'1', b'\r', b'\n'];
        let (context, n, e) = decode(payload.as_slice(), false).unwrap();
        assert_eq!(context, "-1".as_bytes());
        assert_eq!(n, payload.len());
        assert_eq!(e, false);

        let payload = [b'$', b'9', b'\r', b'\n', b'1', b'2', b'3', b'4', b'5'];
        let (context, n, _) = decode(payload.as_slice(), false).unwrap();
        assert_eq!(context, "12345".as_bytes());
        assert_eq!(n, payload.len());

        let payload = [b'$', b'9', b'\r', b'\n', b'1', b'2', b'3', b'4', b'5'];
        assert_eq!(decode(payload.as_slice(), true), None);

        let payload = [b'-', b'1', b'\r', b'\n'];
        let (context, n, e) = decode(payload.as_slice(), true).unwrap();
        assert_eq!(context, "-1".as_bytes());
        assert_eq!(n, 2);
        assert_eq!(e, true);
    }
}
