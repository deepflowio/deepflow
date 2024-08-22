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

use crate::{
    common::{
        flow::{L7PerfStats, L7Protocol, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, ParseParam},
    },
    config::handler::LogParserConfig,
    flow_generator::{
        error::Result,
        protocol_logs::{
            pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response},
            AppProtoHead, L7ResponseStatus, LogMessageType,
        },
    },
    utils::bytes::{read_u16_be, read_u32_be},
};
use serde::Serialize;
use std::str;

/*
These parameters can be determined from the framework code (Refer to the notes below)
based on the actual value range of some data in the header.
*/
const MIN_BODY_SIZE: usize = 12;
const HEADER_SIZE: usize = 4;
const VERSION_INDEX: usize = 5;
const INITIAL_LEN: usize = 7;

const TARS_SERVER_SUCCESS: i32 = 0; // Server-side processing is successful
const TARS_SERVER_DECODE_ERR: i32 = -1; // Server-side decoding exception
const TARS_SERVER_ENCODE_ERR: i32 = -2; // Server-side encoding exception
const TARS_SERVER_NO_FUNC_ERR: i32 = -3; // Server-side does not have the function
const TARS_SERVER_NO_SERVANT_ERR: i32 = -4; // Server-side does not have the Servant object
const TARS_SERVER_RESET_GRID: i32 = -5; // Server-side gray status is inconsistent
const TARS_SERVER_QUEUE_TIMEOUT: i32 = -6; // Server-side queue exceeds the limit
const TARS_ASYNC_CALL_OR_INVOKE_TIMEOUT: i32 = -7; // Asynchronous call timeout or Invocation timeout, duplicate of TARS_ASYNC_CALL_TIMEOUT
const TARS_PROXY_CONNECT_ERR: i32 = -8; // Proxy connection exception
const TARS_SERVER_OVERLOAD: i32 = -9; // Server-side overload, exceeds queue length
const TARS_ADAPTER_NULL: i32 = -10; // Client-side routing is empty, service does not exist or all services are down
const TARS_INVOKE_BY_INVALID_ESET: i32 = -11; // Client-side invocation by set rule is illegal
const TARS_CLIENT_DECODE_ERR: i32 = -12; // Client-side decoding exception
const TARS_SERVER_UNKNOWN_ERR: i32 = -99; // Server-side unknown exception

#[derive(Debug, Clone)]
struct ByteParser {
    byte_type: u8,
    tag: u8,
}

impl From<u8> for ByteParser {
    fn from(byte: u8) -> Self {
        let byte_type = byte & 0x0F;
        let tag = (byte >> 4) & 0x0F;
        ByteParser { byte_type, tag }
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct TarsInfo {
    msg_type: LogMessageType,

    rrt: u64,

    is_tls: bool,

    req_len: u32,
    resp_len: u32,
    resp_status: L7ResponseStatus,

    request_id: u32,
    imsg_type: u32,
    pkg_type: u32,

    req_service_name: Option<String>,
    req_method_name: Option<String>,

    captured_request_byte: u32,
    captured_response_byte: u32,

    ret: i32,

    is_on_blacklist: bool,

    tars_version: u8,

    endpoint: Option<String>,
}

/*
tars reference
-----------------------
1. Basic types and packets of TARS protocols
https://doc.tarsyun.com/#/base/tars-protocol.md

-----------------------
2. For detailed protocol implementation,
   maybe you need to refer to the official framework code,
   and the protocol documentation is not very detailed
https://github.com/TarsCloud

PS:
Framework code discovery is not mentioned in the protocol documentation:
1. The protocol does not have a magic number header
2. The first four bytes of the data packet represent the entire length of the data packet.
3. The string type in the data packet may contain binary data
4. The data type will be compressed and the shortest type will be selected for transmission.
-----------------------
*/

const TYPE_INT8: u8 = 0;
const TYPE_INT16: u8 = 1;
const TYPE_INT32: u8 = 2;
const TYPE_INT64: u8 = 3;
const TYPE_FLOAT: u8 = 4;
const TYPE_DOUBLE: u8 = 5;
const TYPE_STRING1: u8 = 6;
const TYPE_STRING4: u8 = 7;
const TYPE_MAPS: u8 = 8;
const TYPE_LIST: u8 = 9;
const TYPE_STRUCT_BEGIN: u8 = 10;
const TYPE_STRUCT_END: u8 = 11;
const TYPE_ZERO: u8 = 12;
const TYPE_SIMPLE_LIST: u8 = 13;

/*
The parsing rules are:
1. The current field gets tag and type based on the header of the data type.(use ByteParser)
2. Get data.
3. Do the same for the next field.

The meaning of parameters in some codes:
head_x: Data header of the xth field
data_x: The actual data of the xth field

Since the value range of the first few fields is limited,
it may not be necessary to distinguish all shaping types.
For details, please refer to the protocol document and actual framework code.
*/

impl TarsInfo {
    fn parse<'a>(payload: &'a [u8], _param: &ParseParam) -> Option<(&'a [u8], TarsInfo)> {
        let mut info = TarsInfo::default();
        let body_size = read_u32_be(payload.get(0..HEADER_SIZE)?) as usize;
        if body_size < MIN_BODY_SIZE {
            return None;
        }

        let head_ver = ByteParser::from(payload[HEADER_SIZE]);
        if head_ver.tag != TYPE_INT16 || head_ver.byte_type != TYPE_INT8 {
            return None;
        }

        if !matches!(payload[VERSION_INDEX], 1 | 3) {
            return None;
        }

        let mut len = INITIAL_LEN;
        let head_pkt_type = ByteParser::from(payload[INITIAL_LEN - 1]);
        let pkt_type = match head_pkt_type.byte_type {
            TYPE_INT8 => {
                let value = payload[len] as u32;
                len += 1;
                value
            }
            TYPE_ZERO => 0,
            _ => return None,
        };

        let mut head_fields = Vec::new();
        let mut data_fields = Vec::new();

        for _ in 0..2 {
            let head_field = ByteParser::from(payload[len]);
            len += 1;

            let data_field = match head_field.byte_type {
                TYPE_INT8 => {
                    let value = payload[len] as u32;
                    len += 1;
                    value
                }
                TYPE_INT16 => {
                    let value = read_u16_be(payload.get(len..len + 2)?) as u32;
                    len += 2;
                    value
                }
                TYPE_INT32 => {
                    let value = read_u32_be(payload.get(len..len + 4)?) as u32;
                    len += 4;
                    value
                }
                TYPE_ZERO => 0,
                _ => return None,
            };
            head_fields.push(head_field);
            data_fields.push(data_field);
        }

        let head_name_or_ret = ByteParser::from(payload[len]);
        len += 1;

        match head_name_or_ret.tag {
            5 => match head_name_or_ret.byte_type {
                TYPE_STRING1 | TYPE_STRING4 => {
                    info.msg_type = LogMessageType::Request;
                    info.tars_version = payload[VERSION_INDEX] as u8;
                    info.req_len = payload.len() as u32;
                    info.request_id = data_fields[1];
                    info.imsg_type = data_fields[0];
                    info.pkg_type = pkt_type;
                    info.captured_request_byte = (payload.len() - len) as u32;

                    let size = if head_name_or_ret.byte_type == TYPE_STRING1 {
                        let size = payload[len] as usize;
                        len += 1;
                        size
                    } else {
                        0
                    };

                    info.req_service_name =
                        Some(str::from_utf8(&payload[len..len + size]).ok()?.to_string());
                    len += size;

                    let head_func_name = ByteParser::from(payload[len]);
                    len += 1;
                    let size = if head_func_name.byte_type == TYPE_STRING1 {
                        let size = payload[len] as usize;
                        len += 1;
                        size
                    } else {
                        0
                    };

                    if len + size >= payload.len() {
                        return None;
                    }
                    info.req_method_name =
                        Some(str::from_utf8(&payload[len..len + size]).ok()?.to_string());

                    info.endpoint = info.get_endpoint();
                }
                _ => {
                    info.msg_type = LogMessageType::Response;
                    info.tars_version = payload[VERSION_INDEX] as u8;
                    info.resp_len = payload.len() as u32;
                    info.request_id = data_fields[0];
                    info.imsg_type = data_fields[1];
                    info.pkg_type = pkt_type;
                    info.captured_response_byte = (payload.len() - len) as u32;
                    info.ret = if head_name_or_ret.byte_type == 0 {
                        payload[len] as i32
                    } else {
                        0
                    };
                    match info.ret {
                        TARS_ADAPTER_NULL
                        | TARS_INVOKE_BY_INVALID_ESET
                        | TARS_CLIENT_DECODE_ERR => {
                            info.resp_status = L7ResponseStatus::ClientError;
                        }

                        TARS_SERVER_DECODE_ERR
                        | TARS_SERVER_ENCODE_ERR
                        | TARS_SERVER_NO_FUNC_ERR
                        | TARS_SERVER_NO_SERVANT_ERR
                        | TARS_SERVER_RESET_GRID
                        | TARS_SERVER_QUEUE_TIMEOUT
                        | TARS_ASYNC_CALL_OR_INVOKE_TIMEOUT
                        | TARS_PROXY_CONNECT_ERR
                        | TARS_SERVER_UNKNOWN_ERR => {
                            info.resp_status = L7ResponseStatus::ServerError;
                        }

                        _ => {
                            info.resp_status = L7ResponseStatus::Ok;
                        }
                    }
                }
            },
            _ => return None,
        }

        Some((payload, info))
    }

    fn merge(&mut self, other: &mut Self) {
        if other.is_on_blacklist {
            self.is_on_blacklist = other.is_on_blacklist;
        }
        match other.msg_type {
            LogMessageType::Request => {
                self.req_len = other.req_len;
                self.request_id = other.request_id;
                self.captured_request_byte = other.captured_request_byte;
            }
            LogMessageType::Response => {
                self.resp_len = other.resp_len;
                self.captured_response_byte = other.captured_response_byte;
                self.ret = other.ret;
            }
            _ => {}
        }
    }

    fn set_is_on_blacklist(&mut self, config: &LogParserConfig) {
        if let Some(t) = config.l7_log_blacklist_trie.get(&L7Protocol::Tars) {
            self.is_on_blacklist = self
                .req_method_name
                .as_ref()
                .map(|p| t.request_type.is_on_blacklist(p))
                .unwrap_or_default()
                || self
                    .req_service_name
                    .as_ref()
                    .map(|p| t.request_resource.is_on_blacklist(p))
                    .unwrap_or_default()
                || self
                    .endpoint
                    .as_ref()
                    .map(|p| t.endpoint.is_on_blacklist(p))
                    .unwrap_or_default();
        }
    }
}

#[derive(Default)]
pub struct TarsLog {
    info: TarsInfo,
    perf_stats: Option<L7PerfStats>,
    last_is_on_blacklist: bool,
}

impl L7ProtocolParserInterface for TarsLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol() {
            return false;
        }
        if payload.len() < 12 {
            return false;
        }
        TarsInfo::parse(payload, param).is_some()
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        if self.perf_stats.is_none() {
            self.perf_stats = Some(L7PerfStats::default())
        };
        let mut info = TarsInfo::parse(payload, param).unwrap().1;

        if let Some(config) = param.parse_config {
            info.set_is_on_blacklist(config);
        }

        if !info.is_on_blacklist && !self.last_is_on_blacklist {
            match param.direction {
                PacketDirection::ClientToServer => {
                    self.perf_stats.as_mut().map(|p| p.inc_req());
                }
                PacketDirection::ServerToClient => {
                    self.perf_stats.as_mut().map(|p| p.inc_resp());
                }
            }
            info.cal_rrt(param).map(|rrt| {
                info.rrt = rrt;
                self.perf_stats.as_mut().map(|p| p.update_rrt(rrt));
            });
        }
        self.last_is_on_blacklist = info.is_on_blacklist;
        if param.parse_log {
            Ok(L7ParseResult::Single(L7ProtocolInfo::TarsInfo(info)))
        } else {
            Ok(L7ParseResult::None)
        }
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Tars
    }

    fn reset(&mut self) {
        let mut s = Self::default();
        s.last_is_on_blacklist = self.last_is_on_blacklist;
        s.perf_stats = self.perf_stats.take();
        *self = s;
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

impl From<TarsInfo> for L7ProtocolSendLog {
    fn from(info: TarsInfo) -> Self {
        let log = L7ProtocolSendLog {
            req_len: info.req_len.into(),
            resp_len: info.resp_len.into(),
            req: L7Request {
                req_type: info.req_method_name.unwrap_or_default(),
                resource: info.req_service_name.unwrap_or_default(),
                endpoint: info.endpoint.unwrap_or_default(),
                ..Default::default()
            },
            resp: L7Response {
                code: info.ret.into(),
                status: info.resp_status,
                ..Default::default()
            },
            ext_info: Some(ExtendedInfo {
                request_id: Some(info.request_id),
                ..Default::default()
            }),
            version: info.tars_version.to_string().into(),
            captured_request_byte: info.captured_request_byte,
            captured_response_byte: info.captured_response_byte,
            ..Default::default()
        };
        return log;
    }
}

impl L7ProtocolInfoInterface for TarsInfo {
    fn session_id(&self) -> Option<u32> {
        None
    }

    fn is_tls(&self) -> bool {
        self.is_tls
    }

    fn is_on_blacklist(&self) -> bool {
        self.is_on_blacklist
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::Tars,
            msg_type: self.msg_type,
            rrt: 0,
        })
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::TarsInfo(other) = other {
            self.merge(other);
        }
        Ok(())
    }

    fn get_endpoint(&self) -> Option<String> {
        format!(
            "{}/{}",
            self.req_service_name.as_ref()?,
            self.req_method_name.as_ref()?
        )
        .into()
    }
}

#[cfg(test)]
mod tests {
    use serde_json;
    use std::path::Path;
    use std::rc::Rc;
    use std::{cell::RefCell, fs};

    use super::*;

    use crate::{
        common::{flow::PacketDirection, l7_protocol_log::L7PerfCache, MetaPacket},
        config::{
            handler::{L7LogDynamicConfig, LogParserConfig, TraceType},
            ExtraLogFields,
        },
        flow_generator::L7_RRT_CACHE_CAPACITY,
        utils::test::Capture,
    };

    const FILE_DIR: &str = "resources/test/flow_generator/tars";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name), None);
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
        let mut tars = TarsLog::default();
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

            let config = L7LogDynamicConfig::new(
                "".to_owned(),
                vec![],
                vec![TraceType::Sw8, TraceType::TraceParent],
                vec![TraceType::Sw8, TraceType::TraceParent],
                ExtraLogFields::default(),
            );
            let parse_config = &LogParserConfig {
                l7_log_dynamic: config.clone(),
                ..Default::default()
            };

            param.set_log_parse_config(parse_config);

            if !tars.check_payload(payload, param) {
                output.push_str("not tars\n");
                continue;
            }

            let info = tars.parse_payload(payload, param);
            if let Ok(info) = info {
                match info {
                    L7ParseResult::Single(s) => {
                        output.push_str(&serde_json::to_string(&s).unwrap());
                        output.push_str("\n");
                    }
                    L7ParseResult::Multi(m) => {
                        for i in m {
                            output.push_str(&serde_json::to_string(&i).unwrap());
                            output.push_str("\n");
                        }
                    }
                    L7ParseResult::None => {
                        output.push_str("None\n");
                    }
                }
            } else {
                output.push_str(&format!("{:?}\n", TarsInfo::default()));
            }
        }

        output
    }
    #[test]
    fn tarscheck() {
        let files = vec![("tars-echo.pcap", "tars-echo.result")];
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
