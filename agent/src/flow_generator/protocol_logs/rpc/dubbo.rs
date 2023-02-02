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

use std::borrow::Cow;

use serde::Serialize;

use crate::{
    common::{
        enums::IpProtocol,
        flow::{L7Protocol, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ProtocolParserInterface, ParseParam},
    },
    config::handler::{L7LogDynamicConfig, TraceType},
    flow_generator::{
        error::{Error, Result},
        protocol_logs::{
            consts::*,
            decode_base64_to_string,
            pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response, TraceInfo},
            value_is_default, value_is_negative, AppProtoHead, L7ResponseStatus, LogMessageType,
        },
    },
    log_info_merge, parse_common,
    utils::bytes::{read_u32_be, read_u64_be},
};

const TRACE_ID_MAX_LEN: usize = 1024;

#[derive(Serialize, Debug, Default, Clone)]
pub struct DubboInfo {
    #[serde(skip)]
    start_time: u64,
    #[serde(skip)]
    end_time: u64,
    msg_type: LogMessageType,
    #[serde(skip)]
    is_tls: bool,

    // header
    #[serde(skip)]
    pub serial_id: u8,
    #[serde(skip)]
    pub data_type: u8,
    #[serde(rename = "request_id", skip_serializing_if = "value_is_default")]
    pub request_id: i64,

    // req
    #[serde(rename = "request_length", skip_serializing_if = "value_is_negative")]
    pub req_msg_size: Option<u32>,
    #[serde(rename = "version", skip_serializing_if = "value_is_default")]
    pub dubbo_version: String,
    #[serde(rename = "request_domain", skip_serializing_if = "value_is_default")]
    pub service_name: String,
    #[serde(skip)]
    pub service_version: String,
    #[serde(rename = "request_resource", skip_serializing_if = "value_is_default")]
    pub method_name: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub trace_id: String,
    #[serde(skip_serializing_if = "value_is_default")]
    pub span_id: String,

    // resp
    #[serde(rename = "response_length", skip_serializing_if = "Option::is_none")]
    pub resp_msg_size: Option<u32>,
    #[serde(rename = "response_status")]
    pub resp_status: L7ResponseStatus,
    #[serde(rename = "response_code", skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i32>,
}

impl DubboInfo {
    pub fn merge(&mut self, other: Self) {
        if self.resp_msg_size.is_none() {
            self.resp_msg_size = other.resp_msg_size;
        }
        if other.resp_status != L7ResponseStatus::default() {
            self.resp_status = other.resp_status;
        }
        if self.status_code.is_none() {
            self.status_code = other.status_code;
        }
    }
}

impl L7ProtocolInfoInterface for DubboInfo {
    fn session_id(&self) -> Option<u32> {
        Some(self.request_id as u32)
    }

    fn merge_log(&mut self, other: crate::common::l7_protocol_info::L7ProtocolInfo) -> Result<()> {
        log_info_merge!(self, DubboInfo, other);
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::Dubbo,
            msg_type: self.msg_type,
            rrt: self.end_time - self.start_time,
        })
    }

    fn is_tls(&self) -> bool {
        self.is_tls
    }
}

impl From<DubboInfo> for L7ProtocolSendLog {
    fn from(f: DubboInfo) -> Self {
        let endpoint = format!("{}/{}", f.service_name, f.method_name);
        L7ProtocolSendLog {
            req_len: f.req_msg_size,
            resp_len: f.resp_msg_size,
            version: Some(f.dubbo_version),
            req: L7Request {
                resource: f.service_name.clone(),
                req_type: f.method_name.clone(),
                endpoint,
                ..Default::default()
            },
            resp: L7Response {
                status: f.resp_status,
                code: f.status_code,
                ..Default::default()
            },
            trace_info: Some(TraceInfo {
                trace_id: Some(f.trace_id),
                span_id: Some(f.span_id),
                ..Default::default()
            }),
            ext_info: Some(ExtendedInfo {
                rpc_service: Some(f.service_name),
                request_id: Some(f.request_id as u32),
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DubboLog {
    info: DubboInfo,
}

impl L7ProtocolParserInterface for DubboLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol() {
            return false;
        }
        Self::dubbo_check_protocol(payload, param)
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<Vec<L7ProtocolInfo>> {
        let Some(config) = param.parse_config else {
            return Err(Error::NoParseConfig);
        };
        parse_common!(self, param);
        self.parse(
            &config.l7_log_dynamic,
            payload,
            param.l4_protocol,
            param.direction,
            None,
            None,
        )?;
        Ok(vec![L7ProtocolInfo::DubboInfo((&self.info).clone())])
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Dubbo
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

impl DubboLog {
    fn reset_logs(&mut self) {
        self.info.serial_id = 0;
        self.info.data_type = 0;
        self.info.request_id = 0;
        self.info.req_msg_size = None;
        self.info.dubbo_version = String::new();
        self.info.service_name = String::new();
        self.info.service_version = String::new();
        self.info.method_name = String::new();
        self.info.resp_msg_size = None;
        self.info.resp_status = L7ResponseStatus::Ok;
        self.info.status_code = None;
    }

    fn check_char_boundary(payload: &Cow<'_, str>, start: usize, end: usize) -> bool {
        let mut invalid = false;
        for index in start..end {
            if !payload.is_char_boundary(index) {
                invalid = true;
                break;
            }
        }
        return invalid;
    }

    fn decode_field(payload: &Cow<'_, str>, mut start: usize, end: usize) -> Option<String> {
        if start >= payload.len() {
            return None;
        }

        let bytes = payload.as_bytes();
        match bytes[start] {
            BC_STRING_SHORT..=BC_STRING_SHORT_MAX => {
                if start + 2 >= payload.len() {
                    return None;
                }
                let field_len =
                    (((bytes[start] - BC_STRING_SHORT) as usize) << 8) + bytes[start + 1] as usize;
                start += 2;
                if start + field_len < end {
                    return Some(payload[start..start + field_len].to_string());
                }
            }
            0..=STRING_DIRECT_MAX => {
                let field_len = bytes[start] as usize;
                start += 1;
                if start + field_len < end {
                    return Some(payload[start..start + field_len].to_string());
                }
            }
            b'S' => {
                if start + 3 >= payload.len() {
                    return None;
                }
                let field_len = ((bytes[start + 1] as usize) << 8) + bytes[start + 2] as usize;
                start += 3;
                if start + field_len < end {
                    return Some(payload[start..start + field_len].to_string());
                }
            }
            _ => {}
        };
        return None;
    }

    // 注意 dubbo trace id 解析是区分大小写的
    fn decode_trace_id(payload: &Cow<'_, str>, trace_type: &TraceType, info: &mut DubboInfo) {
        let tag = match trace_type {
            TraceType::Sw8 => TraceType::Sw8.to_string(),
            TraceType::Customize(tag) => tag.to_string(),
            _ => return,
        };

        let mut start = 0;
        while start < payload.len() {
            if !payload.is_char_boundary(start) {
                break;
            }
            let index = payload[start..].find(tag.as_str());
            if index.is_none() {
                break;
            }
            let index = index.unwrap();
            // 注意这里tag长度不会超过256
            if index == 0 || tag.len() != payload.as_bytes()[start + index - 1] as usize {
                start += index + tag.len();
                continue;
            }
            let last_index = payload
                .len()
                .min(TRACE_ID_MAX_LEN + start + index + tag.len());
            if Self::check_char_boundary(&payload, start + index, last_index) {
                start += index + tag.len();
                continue;
            }

            if let Some(trace_id) =
                Self::decode_field(payload, start + index + tag.len(), last_index)
            {
                info.trace_id = trace_id;
                break;
            }
            start += index + tag.len();
        }

        match trace_type {
            TraceType::Sw8 => {
                if info.trace_id.len() > 2 {
                    if let Some(index) = info.trace_id[2..].find("-") {
                        info.trace_id = info.trace_id[2..2 + index].to_string();
                    }
                }
                info.trace_id = decode_base64_to_string(&info.trace_id);
            }
            _ => return,
        };
    }

    fn decode_span_id(payload: &Cow<'_, str>, trace_type: &TraceType, info: &mut DubboInfo) {
        let tag = match trace_type {
            TraceType::Customize(tag) => tag.to_string(),
            TraceType::Sw8 => TraceType::Sw8.to_string(),
            _ => return,
        };

        let mut start = 0;
        while start < payload.len() {
            if !payload.is_char_boundary(start) {
                break;
            }
            let index = payload[start..].find(tag.as_str());
            if index.is_none() {
                break;
            }
            let index = index.unwrap();
            // 注意这里tag长度不会超过256
            if index == 0 || tag.len() != payload.as_bytes()[start + index - 1] as usize {
                start += index + tag.len();
                continue;
            }
            let last_index = payload
                .len()
                .min(TRACE_ID_MAX_LEN + start + index + tag.len());
            if Self::check_char_boundary(&payload, start + index, last_index) {
                start += index + tag.len();
                continue;
            }

            if let Some(span_id) =
                Self::decode_field(payload, start + index + tag.len(), last_index)
            {
                info.span_id = span_id;
                break;
            }
            start += index + tag.len();
        }

        match trace_type {
            TraceType::Sw8 => {
                // Format:
                // sw8: 1-TRACEID-SEGMENTID-3-PARENT_SERVICE-PARENT_INSTANCE-PARENT_ENDPOINT-IPPORT
                let mut skip = false;
                if info.span_id.len() > 2 {
                    let segs: Vec<&str> = info.span_id.split("-").collect();
                    if segs.len() > 4 {
                        info.span_id = format!("{}-{}", decode_base64_to_string(segs[2]), segs[3]);
                        skip = true;
                    }
                }
                if !skip {
                    info.span_id = decode_base64_to_string(&info.span_id);
                }
            }
            _ => return,
        };
    }

    // 尽力而为的去解析Dubbo请求中Body各参数
    fn get_req_body_info(&mut self, config: &L7LogDynamicConfig, payload: &[u8]) {
        let mut n = BODY_PARAM_MIN;
        let mut para_index = 0;
        let payload_len = payload.len();

        while n < BODY_PARAM_MAX && para_index < payload_len {
            let (offset, para_len) = get_req_param_len(&payload[para_index..]);
            para_index += offset;
            if para_len == 0 || para_len + para_index > payload_len {
                return;
            }

            match n {
                BODY_PARAM_DUBBO_VERSION => {
                    self.info.dubbo_version =
                        String::from_utf8_lossy(&payload[para_index..para_index + para_len])
                            .into_owned()
                }
                BODY_PARAM_SERVICE_NAME => {
                    self.info.service_name =
                        String::from_utf8_lossy(&payload[para_index..para_index + para_len])
                            .into_owned();
                }
                BODY_PARAM_SERVICE_VERSION => {
                    self.info.service_version =
                        String::from_utf8_lossy(&payload[para_index..para_index + para_len])
                            .into_owned();
                }
                BODY_PARAM_METHOD_NAME => {
                    self.info.method_name =
                        String::from_utf8_lossy(&payload[para_index..para_index + para_len])
                            .into_owned();
                }
                _ => return,
            }

            para_index += para_len;
            if payload_len <= para_index {
                return;
            }
            n += 1;
        }

        if config.trace_types.is_empty() || para_index >= payload.len() {
            return;
        }

        let payload_str = String::from_utf8_lossy(&payload[para_index..]);
        for trace_type in config.trace_types.iter() {
            if trace_type.to_string().len() > u8::MAX as usize {
                continue;
            }

            Self::decode_trace_id(&payload_str, &trace_type, &mut self.info);
            if self.info.trace_id.len() != 0 {
                break;
            }
        }
        for span_type in config.span_types.iter() {
            if span_type.to_string().len() > u8::MAX as usize {
                continue;
            }

            Self::decode_span_id(&payload_str, &span_type, &mut self.info);
            if self.info.span_id.len() != 0 {
                break;
            }
        }
    }

    fn request(&mut self, config: &L7LogDynamicConfig, payload: &[u8], dubbo_header: &DubboHeader) {
        self.info.msg_type = LogMessageType::Request;

        self.info.data_type = dubbo_header.data_type;
        self.info.req_msg_size = Some(dubbo_header.data_length as u32);
        self.info.serial_id = dubbo_header.serial_id;
        self.info.request_id = dubbo_header.request_id;

        self.get_req_body_info(config, &payload[DUBBO_HEADER_LEN..]);
    }

    fn set_status(&mut self, status_code: u8) {
        self.info.resp_status = match status_code {
            20 => L7ResponseStatus::Ok,
            30 => L7ResponseStatus::ClientError,
            31 => L7ResponseStatus::ServerError,
            40 => L7ResponseStatus::ClientError,
            50 => L7ResponseStatus::ServerError,
            60 => L7ResponseStatus::ServerError,
            70 => L7ResponseStatus::ServerError,
            80 => L7ResponseStatus::ServerError,
            90 => L7ResponseStatus::ClientError,
            100 => L7ResponseStatus::ServerError,
            _ => L7ResponseStatus::Ok,
        }
    }

    fn response(&mut self, dubbo_header: &DubboHeader) {
        self.info.msg_type = LogMessageType::Response;

        self.info.data_type = dubbo_header.data_type;
        self.info.resp_msg_size = Some(dubbo_header.data_length as u32);
        self.info.serial_id = dubbo_header.serial_id;
        self.info.request_id = dubbo_header.request_id;
        self.info.status_code = Some(dubbo_header.status_code as i32);
        self.set_status(dubbo_header.status_code);
    }

    pub fn dubbo_check_protocol(payload: &[u8], param: &ParseParam) -> bool {
        if param.l4_protocol != IpProtocol::Tcp {
            return false;
        }

        let mut header = DubboHeader::default();
        let ret = header.parse_headers(payload);
        if ret.is_err() {
            // *bitmap &= !(1 << u8::from(L7Protocol::Dubbo));
            return false;
        }

        header.check()
    }

    fn parse(
        &mut self,
        config: &L7LogDynamicConfig,
        payload: &[u8],
        proto: IpProtocol,
        direction: PacketDirection,
        _is_req_end: Option<bool>,
        _is_resp_end: Option<bool>,
    ) -> Result<()> {
        if proto != IpProtocol::Tcp {
            return Err(Error::InvalidIpProtocol);
        }

        self.reset_logs();
        let mut dubbo_header = DubboHeader::default();
        dubbo_header.parse_headers(payload)?;

        match direction {
            PacketDirection::ClientToServer => {
                self.request(&config, payload, &dubbo_header);
            }
            PacketDirection::ServerToClient => {
                self.response(&dubbo_header);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct DubboHeader {
    // Dubbo Header
    pub serial_id: u8,
    pub data_type: u8,
    pub status_code: u8,
    pub data_length: i32,
    pub request_id: i64,
}

impl DubboHeader {
    // Dubbo协议https://dubbo.apache.org/zh/blog/2018/10/05/dubbo-%E5%8D%8F%E8%AE%AE%E8%AF%A6%E8%A7%A3/#dubbo-%E5%8D%8F%E8%AE%AE
    // Dubbo协议帧
    // +-----------------------------------------------+
    // |       header           |       body           |
    // +---------------+---------------+---------------+
    // header格式
    // +------------------------------------------------------------------------------------------------------------+
    // | magic (16) | request and serialization flag (8) | response status (8) | request id (64) | body length (32) |
    // +------------------------------------------------------------------------------------------------------------+
    pub fn parse_headers(&mut self, payload: &[u8]) -> Result<()> {
        if payload.len() < DUBBO_HEADER_LEN {
            return Err(Error::DubboHeaderParseFailed);
        }
        if payload[0] != DUBBO_MAGIC_HIGH || payload[1] != DUBBO_MAGIC_LOW {
            return Err(Error::DubboHeaderParseFailed);
        }

        self.serial_id = payload[2] & 0x1f;
        self.data_type = payload[2] & 0x80;
        self.status_code = payload[3];
        self.request_id = read_u64_be(&payload[4..]) as i64;
        self.data_length = read_u32_be(&payload[12..]) as i32;
        Ok(())
    }

    pub fn check(&self) -> bool {
        // 不通过响应识别Dubbo
        if self.data_type == 0 {
            return false;
        }
        // 请求时状态码一定是0
        if self.status_code != 0 {
            return false;
        }

        // TODO：增加检查serial_id字段
        return true;
    }
}

// 参考开源代码解析：https://github.com/apache/dubbo-go-hessian2/blob/master/decode.go#L289
// 返回offset和数据length
pub fn get_req_param_len(payload: &[u8]) -> (usize, usize) {
    let tag = payload[0];
    match tag {
        BC_STRING_DIRECT..=STRING_DIRECT_MAX => (1, tag as usize),
        0x30..=0x33 if payload.len() > 2 => (2, ((tag as usize - 0x30) << 8) + payload[1] as usize),
        BC_STRING_CHUNK | BC_STRING if payload.len() > 3 => {
            (3, ((payload[1] as usize) << 8) + payload[2] as usize)
        }
        _ => (0, 0),
    }
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

    const FILE_DIR: &str = "resources/test/flow_generator/dubbo";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name), Some(1024));
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

            let config = L7LogDynamicConfig::new(
                "".to_owned(),
                "".to_owned(),
                vec![
                    TraceType::Customize("EagleEye-TraceID".to_string()),
                    TraceType::Sw8,
                ],
                vec![
                    TraceType::Customize("EagleEye-SpanID".to_string()),
                    TraceType::Sw8,
                ],
            );
            let mut dubbo = DubboLog::default();
            let _ = dubbo.parse(
                &config,
                payload,
                packet.lookup_key.proto,
                packet.lookup_key.direction,
                None,
                None,
            );
            let is_dubbo =
                DubboLog::dubbo_check_protocol(payload, &ParseParam::from(packet as &MetaPacket));
            output.push_str(&format!("{:?} is_dubbo: {}\r\n", dubbo.info, is_dubbo));
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
            ("dubbo_hessian2.pcap", "dubbo_hessian.result"),
            ("dubbo-eys.pcap", "dubbo-eys.result"),
            ("dubbo-sw8.pcap", "dubbo-sw8.result"),
        ];

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
