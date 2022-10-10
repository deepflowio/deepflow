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

use arc_swap::access::Access;
use log::info;
use serde::Serialize;

use super::super::{
    consts::*, value_is_default, value_is_negative, AppProtoHead, AppProtoLogsInfo, L7LogParse,
    L7Protocol, L7ResponseStatus, LogMessageType,
};

use crate::common::enums::IpProtocol;
use crate::common::flow::PacketDirection;
use crate::common::meta_packet::MetaPacket;
use crate::config::handler::{L7LogDynamicConfig, LogParserAccess};
use crate::flow_generator::error::{Error, Result};
use crate::flow_generator::protocol_logs::pb_adapter::{L7ProtocolSendLog, L7Request, L7Response};
use crate::flow_generator::{AppProtoHeadEnum, AppProtoLogsInfoEnum};
use crate::utils::bytes::{read_u32_be, read_u64_be};

const TRACE_ID_MAX_LEN: usize = 51;

#[derive(Serialize, Debug, Default, Clone)]
pub struct DubboInfo {
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

    // resp
    #[serde(rename = "response_length", skip_serializing_if = "value_is_negative")]
    pub resp_msg_size: Option<u32>,
    pub resp_status: L7ResponseStatus,
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

impl From<DubboInfo> for L7ProtocolSendLog {
    fn from(f: DubboInfo) -> Self {
        let log = L7ProtocolSendLog {
            req_len: f.req_msg_size,
            resp_len: f.resp_msg_size,
            version: Some(f.dubbo_version),
            req: L7Request {
                domain: f.service_name,
                resource: f.method_name,
                ..Default::default()
            },
            resp: L7Response {
                status: f.resp_status,
                code: f.status_code,
                ..Default::default()
            },
            ..Default::default()
        };
        return log;
    }
}

#[derive(Clone, Debug, Default)]
pub struct DubboLog {
    info: DubboInfo,
    msg_type: LogMessageType,

    l7_log_dynamic_config: L7LogDynamicConfig,
}

impl DubboLog {
    pub fn new(config: &LogParserAccess) -> Self {
        Self {
            l7_log_dynamic_config: config.load().l7_log_dynamic.clone(),
            ..Default::default()
        }
    }

    pub fn update_config(&mut self, config: &LogParserAccess) {
        self.l7_log_dynamic_config = config.load().l7_log_dynamic.clone();
        info!(
            "dubbo log update l7 log dynamic config to {:#?}",
            self.l7_log_dynamic_config
        );
    }

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

    // 尽力而为的去解析Dubbo请求中Body各参数
    fn get_req_body_info(&mut self, payload: &[u8]) {
        let mut n = BODY_PARAM_MIN;
        let mut para_index = 0;
        let payload_len = payload.len();

        while n < BODY_PARAM_MAX {
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

        if self.l7_log_dynamic_config.trace_types.is_empty() || para_index >= payload.len() {
            return;
        }
        let payload_str = String::from_utf8_lossy(&payload[para_index..]);
        let mut offset = 0;

        let trace_id_tags = self
            .l7_log_dynamic_config
            .trace_types
            .iter()
            .map(|trace_type| trace_type.to_string())
            .collect::<Vec<String>>();

        for tag in &trace_id_tags {
            if let Some(index) = payload_str.find(tag.as_str()) {
                offset += index + tag.len();
                if offset + 20 >= payload_str.len() {
                    continue;
                }
                // sw8匹配 以'1-'开头'-'结尾的部分
                if let Some(begin_index) = payload_str[offset..offset + 20].find("1-") {
                    offset += begin_index + 2;
                    if let Some(end_index) = payload_str[offset..].find("-") {
                        self.info.trace_id = payload_str[offset..offset + end_index].to_string();
                        break;
                    }
                // logId匹配到'.'
                } else if let Some(end_index) = payload_str[offset..].find(".") {
                    self.info.trace_id =
                        payload_str[offset..offset + TRACE_ID_MAX_LEN.min(end_index)].to_string();
                    break;
                } else {
                    self.info.trace_id = payload_str
                        [offset..payload_str.len().min(offset + TRACE_ID_MAX_LEN)]
                        .to_string();
                    break;
                }
            }
        }
    }

    fn request(&mut self, payload: &[u8], dubbo_header: &DubboHeader) {
        self.msg_type = LogMessageType::Request;

        self.info.data_type = dubbo_header.data_type;
        self.info.req_msg_size = Some(dubbo_header.data_length as u32);
        self.info.serial_id = dubbo_header.serial_id;
        self.info.request_id = dubbo_header.request_id;

        self.get_req_body_info(&payload[DUBBO_HEADER_LEN..]);
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
        self.msg_type = LogMessageType::Response;

        self.info.data_type = dubbo_header.data_type;
        self.info.resp_msg_size = Some(dubbo_header.data_length as u32);
        self.info.serial_id = dubbo_header.serial_id;
        self.info.request_id = dubbo_header.request_id;
        self.info.status_code = Some(dubbo_header.status_code as i32);
        self.set_status(dubbo_header.status_code);
    }
}

impl L7LogParse for DubboLog {
    fn parse(
        &mut self,
        payload: &[u8],
        proto: IpProtocol,
        direction: PacketDirection,
        _is_req_end: Option<bool>,
        _is_resp_end: Option<bool>,
    ) -> Result<AppProtoHeadEnum> {
        if proto != IpProtocol::Tcp {
            return Err(Error::InvalidIpProtocol);
        }

        self.reset_logs();
        let mut dubbo_header = DubboHeader::default();
        dubbo_header.parse_headers(payload)?;

        match direction {
            PacketDirection::ClientToServer => {
                self.request(payload, &dubbo_header);
            }
            PacketDirection::ServerToClient => {
                self.response(&dubbo_header);
            }
        }
        Ok(AppProtoHeadEnum::Single(AppProtoHead {
            proto: L7Protocol::Dubbo,
            msg_type: self.msg_type,
            rrt: 0,
            ..Default::default()
        }))
    }

    fn info(&self) -> AppProtoLogsInfoEnum {
        AppProtoLogsInfoEnum::Single(AppProtoLogsInfo::Dubbo(self.info.clone()))
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

// 通过请求来识别Dubbo
pub fn dubbo_check_protocol(bitmap: &mut u128, packet: &MetaPacket) -> bool {
    if packet.lookup_key.proto != IpProtocol::Tcp {
        *bitmap &= !(1 << u8::from(L7Protocol::Dubbo));
        return false;
    }

    let payload = packet.get_l4_payload();
    if payload.is_none() {
        return false;
    }
    let payload = payload.unwrap();

    let mut header = DubboHeader::default();
    let ret = header.parse_headers(payload);
    if ret.is_err() {
        *bitmap &= !(1 << u8::from(L7Protocol::Dubbo));
        return false;
    }

    return header.check();
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    use crate::{common::flow::PacketDirection, utils::test::Capture};

    const FILE_DIR: &str = "resources/test/flow_generator/dubbo";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name), None);
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
        let mut bitmap = 0;
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

            let mut dubbo = DubboLog::default();
            let _ = dubbo.parse(
                payload,
                packet.lookup_key.proto,
                packet.direction,
                None,
                None,
            );
            let is_dubbo = dubbo_check_protocol(&mut bitmap, packet);
            output.push_str(&format!("{:?} is_dubbo: {}\r\n", dubbo.info, is_dubbo));
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![("dubbo_hessian2.pcap", "dubbo_hessian.result")];

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
