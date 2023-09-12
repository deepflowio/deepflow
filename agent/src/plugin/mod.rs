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

pub mod c_ffi;
#[cfg(target_os = "linux")]
pub mod shared_obj;
pub mod wasm;

use bitflags::bitflags;
use public::{
    bytes::{read_u16_be, read_u32_be},
    l7_protocol::L7Protocol,
};
use serde::Serialize;

use crate::{
    common::flow::PacketDirection,
    common::l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
    flow_generator::{
        protocol_logs::pb_adapter::{
            ExtendedInfo, KeyVal, L7ProtocolSendLog, L7Request, L7Response, TraceInfo,
        },
        protocol_logs::{L7ResponseStatus, LogMessageType},
        AppProtoHead, Error,
    },
};

use self::wasm::read_wasm_str;

#[derive(Debug, Default, Serialize, Clone)]
pub struct CustomInfoRequest {
    pub req_type: String,
    pub domain: String,
    pub resource: String,
    pub endpoint: String,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct CustomInfoResp {
    pub status: L7ResponseStatus,
    pub code: Option<i32>,
    pub exception: String,
    pub result: String,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct CustomInfoTrace {
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct CustomExtInfo {
    pub row_effect: Option<u32>,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct CustomInfo {
    #[serde(skip)]
    pub(super) proto: u8,
    pub(super) proto_str: String,
    pub(super) msg_type: LogMessageType,
    #[serde(skip)]
    pub(super) rrt: u64,

    pub req_len: Option<u32>,
    pub resp_len: Option<u32>,

    pub request_id: Option<u32>,

    pub req: CustomInfoRequest,

    pub resp: CustomInfoResp,

    pub trace: CustomInfoTrace,
    pub ext_info: CustomExtInfo,

    pub need_protocol_merge: bool,
    pub is_req_end: bool,
    pub is_resp_end: bool,

    #[serde(skip)]
    pub attributes: Vec<KeyVal>,
}

bitflags! {
    struct InfoFlag: u8 {
        const HAS_REQ_ID = 1<<7;
        const HAS_TRACE = 1 << 6;
        const HAS_EXT_INFO = 1 << 5;
        const HAS_KV = 1 << 4;
    }
}

impl TryFrom<(&[u8], PacketDirection)> for CustomInfo {
    /*
        req len:        4 bytes: | 1 bit: is nil? | 31bit length |

        resp len:       4 bytes: | 1 bit: is nil? | 31bit length |

        bit flag:       1 bytes: | has req_id | has trace |  has ext_info | has kv | 4 bit reserve |

        if has request id:

            request	id: 4 bytes

        if direction is c2s:

            ReqType, Endpoint, Domain, Resource
            (

                len:    2 bytes
                val:    $(len) bytes

            ) x 4

        if direction is s2c:

            status:     1 byte,
            has code:   1 byte, 0 or 1,

            if has code:

                code:   4 bytes,


            Result, Exception
            (

                len:    2 bytes
                val:    $(len) bytes

            ) x 2

        need_protocol_merge: 1 byte, the msb indicate is need protocol merge, the lsb indicate is end, such as 1 000000 1

        if has trace:

            trace_id, span_id, parent_span_id
            (

                key len: 2 bytes
                key:     $(key len) bytes

                val len: 2 bytes
                val:     $(val len) bytes

            ) x 3


        if has ext info:
            ext info size: 2 bytes

            row_effect:    4 bytes

        if has kv
            (
                key len: 2 bytes
                key:     $(key len) bytes

                val len: 2 bytes
                val:     $(val len) bytes

            ) x len(kv)
    */

    type Error = Error;

    fn try_from(f: (&[u8], PacketDirection)) -> std::result::Result<Self, Self::Error> {
        let (buf, dir) = f;
        let mut off = 0;
        let mut info = Self::default();
        if buf.len() < 9 {
            return Err(Error::WasmSerializeFail("buf len too short".to_string()));
        }

        if buf[off] >> 7 != 0 {
            let req_len = read_u32_be(&buf[off..off + 4]);
            info.req_len = Some(req_len & (i32::MAX as u32))
        }
        off += 4;

        if buf[off] >> 7 != 0 {
            let resp_len = read_u32_be(&buf[off..off + 4]);
            info.resp_len = Some(resp_len & (i32::MAX as u32))
        }
        off += 4;

        let flags = InfoFlag::from_bits_truncate(buf[off]);
        let (has_req_id, has_trace, has_kv, has_ext) = (
            flags.contains(InfoFlag::HAS_REQ_ID),
            flags.contains(InfoFlag::HAS_TRACE),
            flags.contains(InfoFlag::HAS_KV),
            flags.contains(InfoFlag::HAS_EXT_INFO),
        );
        off += 1;

        // parse request id
        if has_req_id {
            if off + 4 > buf.len() {
                return Err(Error::WasmSerializeFail(
                    "buf len too short when parse request id".to_string(),
                ));
            }
            info.request_id = Some(read_u32_be(&buf[off..off + 4]));
            off += 4
        }

        match dir {
            PacketDirection::ClientToServer => {
                // parse req
                if read_wasm_str(buf, &mut off)
                    .and_then(|s| {
                        info.req.req_type = s;
                        read_wasm_str(buf, &mut off)
                    })
                    .and_then(|s| {
                        info.req.endpoint = s;
                        read_wasm_str(buf, &mut off)
                    })
                    .and_then(|s| {
                        info.req.domain = s;
                        read_wasm_str(buf, &mut off)
                    })
                    .and_then(|s| {
                        info.req.resource = s;
                        Some(())
                    })
                    .is_none()
                {
                    return Err(Error::WasmSerializeFail(
                        "buf len too short when parse request".to_string(),
                    ));
                }
            }
            PacketDirection::ServerToClient => {
                // parse resp
                let status = buf[off];
                match status {
                    0 => info.resp.status = L7ResponseStatus::Ok,
                    2 => info.resp.status = L7ResponseStatus::NotExist,
                    3 => info.resp.status = L7ResponseStatus::ServerError,
                    4 => info.resp.status = L7ResponseStatus::ClientError,
                    _ => {
                        return Err(Error::WasmSerializeFail(
                            "recv unexpected status ".to_string(),
                        ))
                    }
                }
                off += 1;
                let has_code = buf[off];

                match has_code {
                    0 => off += 1,
                    1 => {
                        off += 1;
                        if off + 4 > buf.len() {
                            return Err(Error::WasmSerializeFail(
                                "buf len too short when parse response code".to_string(),
                            ));
                        }
                        info.resp.code = Some(read_u32_be(&buf[off..off + 4]) as i32);
                        off += 4;
                    }
                    _ => {
                        return Err(Error::WasmSerializeFail(
                            "recv unexpected has_code ".to_string(),
                        ))
                    }
                }

                if read_wasm_str(buf, &mut off)
                    .and_then(|s| {
                        info.resp.result = s;
                        read_wasm_str(buf, &mut off)
                    })
                    .and_then(|s| {
                        info.resp.exception = s;
                        Some(())
                    })
                    .is_none()
                {
                    return Err(Error::WasmSerializeFail(
                        "buf len too short when parse exception and result".to_string(),
                    ));
                }
            }
        }

        // need_protocol_merge
        if off + 1 > buf.len() {
            return Err(Error::WasmSerializeFail(
                "buf len too short when parse need protocol merge".to_string(),
            ));
        }
        info.need_protocol_merge = buf[off] & 128 != 0;

        if info.need_protocol_merge {
            let is_end = buf[off] & 1 != 0;
            match dir {
                PacketDirection::ClientToServer => info.is_req_end = is_end,
                PacketDirection::ServerToClient => info.is_resp_end = is_end,
            }
        }
        off += 1;

        // trace info
        if has_trace {
            if read_wasm_str(buf, &mut off)
                .and_then(|s| {
                    info.trace.trace_id = Some(s);
                    read_wasm_str(buf, &mut off)
                })
                .and_then(|s| {
                    info.trace.span_id = Some(s);
                    read_wasm_str(buf, &mut off)
                })
                .and_then(|s| {
                    info.trace.parent_span_id = Some(s);
                    Some(())
                })
                .is_none()
            {
                return Err(Error::WasmSerializeFail(
                    "buf len too short when parse trace info".to_string(),
                ));
            }
        }

        // ext info
        if has_ext {
            let err = Err(Error::WasmSerializeFail(
                "buf len too short when parse ext info".to_string(),
            ));

            if off + 2 > buf.len() {
                return err;
            }

            let ext_len = read_u16_be(&buf[off..off + 2]) as usize;
            off += 2;
            if off + ext_len > buf.len() || ext_len < 4 {
                return err;
            }

            info.ext_info.row_effect = Some(read_u32_be(&buf[off..off + 4]));

            off += ext_len;
        }

        // key val
        if has_kv {
            loop {
                if let (Some(key), Some(val)) =
                    (read_wasm_str(buf, &mut off), read_wasm_str(buf, &mut off))
                {
                    info.attributes.push(KeyVal { key: key, val: val });
                } else {
                    break;
                }
            }
        }
        Ok(info)
    }
}

impl L7ProtocolInfoInterface for CustomInfo {
    fn session_id(&self) -> Option<u32> {
        self.request_id
    }

    fn merge_log(&mut self, other: L7ProtocolInfo) -> crate::flow_generator::Result<()> {
        if let L7ProtocolInfo::CustomInfo(w) = other {
            // req merge
            if self.req.domain.is_empty() {
                self.req.domain = w.req.domain;
            }
            if self.req.endpoint.is_empty() {
                self.req.endpoint = w.req.endpoint;
            }

            if self.req.req_type.is_empty() {
                self.req.req_type = w.req.req_type;
            }

            if self.req.resource.is_empty() {
                self.req.resource = w.req.resource;
            }

            if self.req_len.is_none() {
                self.req_len = w.req_len;
            }

            if w.is_req_end {
                self.is_req_end = true;
            }

            // resp merge
            if self.resp.exception.is_empty() {
                self.resp.exception = w.resp.exception;
            }

            if self.resp.status == L7ResponseStatus::default() {
                self.resp.status = w.resp.status;
            }

            if self.resp.code.is_none() {
                self.resp.code = w.resp.code;
            }

            if self.resp.result.is_empty() {
                self.resp.result = w.resp.result;
            }

            if self.resp_len.is_none() {
                self.resp_len = w.resp_len;
            }

            if w.is_resp_end {
                self.is_resp_end = true;
            }

            // trace merge
            if self.trace.trace_id.is_none() {
                self.trace.trace_id = w.trace.trace_id;
            }

            if self.trace.span_id.is_none() {
                self.trace.span_id = w.trace.span_id;
            }
            if self.trace.parent_span_id.is_none() {
                self.trace.parent_span_id = w.trace.parent_span_id;
            }

            // ext info
            if self.ext_info.row_effect.is_none() {
                self.ext_info.row_effect = w.ext_info.row_effect;
            }

            self.attributes.extend(w.attributes);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::Custom,
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn is_tls(&self) -> bool {
        false
    }

    fn need_merge(&self) -> bool {
        self.need_protocol_merge
    }

    fn is_req_resp_end(&self) -> (bool, bool) {
        (self.is_req_end, self.is_resp_end)
    }

    fn get_endpoint(&self) -> Option<String> {
        None
    }
}

impl From<CustomInfo> for L7ProtocolSendLog {
    fn from(w: CustomInfo) -> Self {
        Self {
            req_len: w.req_len,
            resp_len: w.resp_len,

            req: L7Request {
                req_type: w.req.req_type,
                domain: w.req.domain,
                resource: w.req.resource,
                endpoint: w.req.endpoint,
            },
            resp: L7Response {
                status: w.resp.status,
                code: w.resp.code,
                exception: w.resp.exception,
                result: w.resp.result,
            },
            trace_info: if w.trace.trace_id.is_some()
                || w.trace.span_id.is_some()
                || w.trace.parent_span_id.is_some()
            {
                Some(TraceInfo {
                    trace_id: w.trace.trace_id,
                    span_id: w.trace.span_id,
                    parent_span_id: w.trace.parent_span_id,
                })
            } else {
                None
            },
            ext_info: Some(ExtendedInfo {
                request_id: w.request_id,
                attributes: Some(w.attributes),
                protocol_str: Some(w.proto_str),
                ..Default::default()
            }),
            row_effect: w.ext_info.row_effect.unwrap_or_default(),
            ..Default::default()
        }
    }
}
