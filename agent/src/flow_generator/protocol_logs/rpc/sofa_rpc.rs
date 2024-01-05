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
mod hessian;

use nom::InputTakeAtPosition;
use public::{
    bytes::{read_u16_be, read_u32_be},
    l7_protocol::L7Protocol,
};
use serde::Serialize;

use crate::{
    common::{
        flow::L7PerfStats,
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, ParseParam},
        meta_packet::EbpfFlags,
    },
    flow_generator::{
        protocol_logs::{
            pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response, TraceInfo},
            L7ResponseStatus,
        },
        AppProtoHead, Error, HttpLog, LogMessageType, Result,
    },
};

use self::hessian::{FieldEnum, HessianObjIterator};

const REQ_HDR_LEN: usize = 22;
const RESP_HDR_LEN: usize = 20;

const PROTO_BOLT_V1: u8 = 1;

const TYPE_REQ: u8 = 1;
const TYPE_RESP: u8 = 0;

const CMD_CODE_HEARTBEAT: u16 = 0;
const CMD_CODE_REQ: u16 = 1;
const CMD_CODE_RESP: u16 = 2;

const CODE_C_HESSIAN: u8 = 1;

const HDR_SERVICE_KEY: &'static str = "sofa_head_target_service";
const SERVICE_KEY: &'static str = "targetServiceUniqueName";
const HDR_METHOD_KEY: &'static str = "sofa_head_method_name";
const METHOD_KEY: &'static str = "methodName";
const HDR_TRACE_ID_KEY: &'static str = "rpc_trace_context.sofaTraceId";
const TRACE_ID_KEY: &'static str = "sofaTraceId";

pub const SOFA_NEW_RPC_TRACE_CTX_KEY: &'static str = "new_rpc_trace_context";

struct Hdr {
    proto: u8,
    typ: u8,
    cmd_code: u16,
    req_id: u32,
    code_c: u8,
    class_len: u16,
    resp_code: u16,
    hdr_len: u16,
    content_len: u32,
}

impl TryFrom<&[u8]> for Hdr {
    type Error = Error;

    /*
        * Request command protocol for v1
        * 0     1     2           4           6           8          10           12          14         16
        * +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
        * |proto| type| cmdcode   |ver2 |   requestId           |codec|        timeout        |  classLen |
        * +-----------+-----------+-----------+-----------+-----------+-----------+-----------+-----------+
        * |headerLen  | contentLen            |                             ... ...                       |
        * +-----------+-----------+-----------+                                                           +
        * |               className + header  + content  bytes                                            |
        * +                                                                                               +
        * |                               ... ...                                                         |
        * +-----------------------------------------------------------------------------------------------+

        * Response command protocol for v1
        * 0     1     2     3     4           6           8          10           12          14         16
        * +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
        * |proto| type| cmdcode   |ver2 |   requestId           |codec|respstatus |  classLen |headerLen  |
        * +-----------+-----------+-----------+-----------+-----------+-----------+-----------+-----------+
        * | contentLen            |                  ... ...                                              |
        * +-----------------------+                                                                       +
        * |                         className + header  + content  bytes                                  |
        * +                                                                                               +
        * |                               ... ...                                                         |
        * +-----------------------------------------------------------------------------------------------+
    */
    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
        if payload.len() < 10 {
            return Err(Error::L7ProtocolUnknown);
        }
        let proto = payload[0];
        let typ = payload[1];
        let code_c = payload[9];
        match typ {
            TYPE_REQ => {
                if payload.len() < REQ_HDR_LEN {
                    return Err(Error::L7ProtocolUnknown);
                }
                let cmd_code = read_u16_be(&payload[2..4]);
                let req_id = read_u32_be(&payload[5..9]);
                let (class_len, hdr_len, content_len) = (
                    read_u16_be(&payload[14..16]),
                    read_u16_be(&payload[16..18]),
                    read_u32_be(&payload[18..22]),
                );
                Ok(Self {
                    proto,
                    typ,
                    cmd_code,
                    req_id,
                    code_c,
                    resp_code: 0,
                    class_len,
                    hdr_len,
                    content_len,
                })
            }
            TYPE_RESP => {
                if payload.len() < RESP_HDR_LEN {
                    return Err(Error::L7ProtocolUnknown);
                }
                let cmd_code = read_u16_be(&payload[2..4]);
                let req_id = read_u32_be(&payload[5..9]);
                let resp_code = read_u16_be(&payload[10..12]);
                let (class_len, hdr_len, content_len) = (
                    read_u16_be(&payload[12..14]),
                    read_u16_be(&payload[14..16]),
                    read_u32_be(&payload[16..20]),
                );
                Ok(Self {
                    proto,
                    typ,
                    cmd_code,
                    req_id,
                    code_c,
                    resp_code,
                    class_len,
                    hdr_len,
                    content_len,
                })
            }
            _ => return Err(Error::L7ProtocolUnknown),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct SofaRpcInfo {
    is_tls: bool,

    proto: u8,
    req_id: u32,
    msg_type: LogMessageType,
    rrt: u64,

    target_serv: String,
    method: String,
    cmd_code: u16,
    trace_id: String,
    span_id: String,
    parent_span_id: String,

    req_len: u32,
    resp_len: u32,

    resp_code: u16,
    status: L7ResponseStatus,
}

impl SofaRpcInfo {
    fn fill_with_trace_ctx(&mut self, ctx: String) {
        let ctx = decode_new_rpc_trace_context(ctx.as_bytes());
        if !ctx.trace_id.is_empty() {
            self.trace_id = ctx.trace_id;
        }
        if !ctx.span_id.is_empty() {
            self.span_id = ctx.span_id;
        }
        if !ctx.parent_span_id.is_empty() {
            self.parent_span_id = ctx.parent_span_id;
        }
    }
}

impl L7ProtocolInfoInterface for SofaRpcInfo {
    fn session_id(&self) -> Option<u32> {
        Some(self.req_id)
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::SofaRpcInfo(s) = other {
            self.resp_len = s.resp_len;
            self.resp_code = s.resp_code;
            self.status = s.status;
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::SofaRPC,
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn is_tls(&self) -> bool {
        self.is_tls
    }

    fn get_endpoint(&self) -> Option<String> {
        if !self.target_serv.is_empty() || !self.method.is_empty() {
            Some(format!("{}/{}", self.target_serv, self.method))
        } else {
            None
        }
    }
}

impl From<SofaRpcInfo> for L7ProtocolSendLog {
    fn from(s: SofaRpcInfo) -> Self {
        let flags = if s.is_tls {
            EbpfFlags::TLS.bits()
        } else {
            EbpfFlags::NONE.bits()
        };
        Self {
            req_len: Some(s.req_len),
            resp_len: Some(s.resp_len),
            req: L7Request {
                req_type: s.method.clone(),
                resource: s.target_serv.clone(),
                endpoint: format!("{}/{}", s.target_serv.clone(), s.method),
                ..Default::default()
            },
            resp: L7Response {
                status: s.status,
                code: Some(s.resp_code as i32),
                ..Default::default()
            },
            trace_info: Some(TraceInfo {
                trace_id: Some(s.trace_id),
                span_id: Some(s.span_id),
                parent_span_id: Some(s.parent_span_id),
                ..Default::default()
            }),
            ext_info: Some(ExtendedInfo {
                rpc_service: Some(s.target_serv),
                request_id: Some(s.req_id),
                ..Default::default()
            }),
            flags,
            ..Default::default()
        }
    }
}

#[derive(Debug)]
pub struct SofaRpcLog {
    perf_stats: Option<L7PerfStats>,
}

impl Default for SofaRpcLog {
    fn default() -> Self {
        Self { perf_stats: None }
    }
}

impl L7ProtocolParserInterface for SofaRpcLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        let mut info = SofaRpcInfo::default();
        self.parse(payload, true, &mut info, param).is_ok()
            && info.msg_type == LogMessageType::Request
            && info.cmd_code != CMD_CODE_HEARTBEAT
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        let mut info = SofaRpcInfo::default();
        match self.parse(payload, false, &mut info, param) {
            Ok(ok) => {
                if !ok {
                    return Ok(L7ParseResult::None);
                }
                self.cal_perf(param, &mut info);
                info.is_tls = param.is_tls();
                if param.parse_log {
                    Ok(L7ParseResult::Single(L7ProtocolInfo::SofaRpcInfo(info)))
                } else {
                    Ok(L7ParseResult::None)
                }
            }
            Err(e) => Err(e),
        }
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::SofaRPC
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }
}

impl SofaRpcLog {
    fn parse(
        &mut self,
        mut payload: &[u8],
        check: bool,
        info: &mut SofaRpcInfo,
        param: &ParseParam,
    ) -> Result<bool> {
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };

        let hdr = Hdr::try_from(payload)?;
        info.proto = hdr.proto;
        // now only support bolt v1
        if info.proto != PROTO_BOLT_V1 {
            return Err(Error::L7ProtocolUnknown);
        }

        info.cmd_code = hdr.cmd_code;
        if info.cmd_code == CMD_CODE_HEARTBEAT {
            // skip heartbeat
            return if check {
                Err(Error::L7ProtocolUnknown)
            } else {
                Ok(false)
            };
        }
        info.req_id = hdr.req_id;
        info.msg_type = match hdr.typ {
            TYPE_REQ => {
                payload = &payload[REQ_HDR_LEN..];
                info.req_len = hdr.content_len + (hdr.hdr_len as u32) + (hdr.class_len as u32);
                LogMessageType::Request
            }
            TYPE_RESP => {
                payload = &payload[RESP_HDR_LEN..];
                info.resp_code = hdr.resp_code;
                info.resp_len = hdr.content_len + (hdr.hdr_len as u32) + (hdr.class_len as u32);
                if info.resp_code == 8 {
                    info.status = L7ResponseStatus::ClientError;
                } else if info.resp_code != 0 {
                    info.status = L7ResponseStatus::ServerError;
                }
                LogMessageType::Response
            }
            _ => return Err(Error::L7ProtocolUnknown),
        };

        if hdr.class_len as usize > payload.len() {
            return if check {
                Err(Error::L7ProtocolUnknown)
            } else {
                Ok(true)
            };
        }

        // due to sofa is susceptible to mischeck, need to check the class name is ascii when is strict
        if check {
            // java class name is not empty
            if hdr.class_len == 0
                || (&payload[0..hdr.class_len as usize]).iter().any(|b| {
                    *b == 0 || b.is_ascii_whitespace() || b.is_ascii_control() || !b.is_ascii()
                })
            {
                return Err(Error::L7ProtocolUnknown);
            };
        }

        payload = &payload[hdr.class_len as usize..];

        if hdr.hdr_len != 0 {
            let hdr_len = hdr.hdr_len as usize;
            let hdr_payload = if hdr_len as usize > payload.len() {
                // if hdr_len as usize > payload.len() likey ebpf not read full data from java process, parse hdr to payload end
                if check {
                    return Err(Error::L7ProtocolUnknown);
                }
                payload
            } else {
                let hdr_payload = &payload[..hdr_len];
                payload = &payload[hdr_len..];
                hdr_payload
            };

            let sofa_hdr = SofaHdr::from(hdr_payload);
            info.target_serv = sofa_hdr.service;
            info.method = sofa_hdr.method;
            info.trace_id = sofa_hdr.trace_id;

            if !sofa_hdr.new_rpc_trace_context.is_empty() {
                info.fill_with_trace_ctx(sofa_hdr.new_rpc_trace_context);
            }
        }
        // parse req hessian2 obj
        if hdr.code_c == CODE_C_HESSIAN && payload.len() != 0 && hdr.typ == TYPE_REQ {
            if let Some(h) = HessianObjIterator::new(payload) {
                for (k, v) in h {
                    let FieldEnum::String(val) = v else {
                        continue;
                    };
                    match k {
                        METHOD_KEY if info.method.is_empty() => info.method = val.to_string(),
                        SERVICE_KEY if info.target_serv.is_empty() => {
                            info.target_serv = val.to_string()
                        }
                        TRACE_ID_KEY if info.trace_id.is_empty() => info.trace_id = val.to_string(),
                        _ => {
                            if !info.trace_id.is_empty()
                                && !info.target_serv.is_empty()
                                && !info.method.is_empty()
                            {
                                break;
                            }
                        }
                    }
                }
            }
        }

        if check && (info.target_serv.is_empty() || info.method.is_empty()) {
            return Err(Error::L7ProtocolUnknown);
        }

        if check {
            Ok(false)
        } else {
            Ok(true)
        }
    }

    fn cal_perf(&mut self, param: &ParseParam, info: &mut SofaRpcInfo) {
        match info.msg_type {
            LogMessageType::Request => {
                self.perf_stats.as_mut().map(|p| p.inc_req());
            }
            LogMessageType::Response => {
                self.perf_stats.as_mut().map(|p| p.inc_resp());
            }
            _ => {}
        }

        match info.status {
            L7ResponseStatus::ClientError => {
                self.perf_stats.as_mut().map(|p| p.inc_req_err());
            }
            L7ResponseStatus::ServerError => {
                self.perf_stats.as_mut().map(|p| p.inc_resp_err());
            }
            _ => {}
        }

        info.cal_rrt(param, None).map(|rrt| {
            info.rrt = rrt;
            self.perf_stats.as_mut().map(|p| p.update_rrt(rrt));
        });
    }
}

struct SofaHdr {
    service: String,
    method: String,
    trace_id: String,
    new_rpc_trace_context: String,
}

/*
    referer https://github.com/sofastack/sofa-rpc/blob/7931102255d6ea95ee75676d368aad37c56b57ee/tracer/tracer-opentracing/src/main/java/com/alipay/sofa/rpc/tracer/sofatracer/RpcSofaTracer.java#L192
    sofarpc only have two trace type

    1. when version >= 5.1.0, use header like
       new_rpc_trace_context: tcid=ac11000116703149173111002125786&spid=0&pspid=1&sample=true&

    2. when version < 5.1.0  use header
       rpc_trace_context.sofaTraceId: ${trace_id}

    the const var define in source: https://github.com/sofastack/sofa-rpc/blob/7931102255d6ea95ee75676d368aad37c56b57ee/core/api/src/main/java/com/alipay/sofa/rpc/common/RemotingConstants.java
*/
impl From<&[u8]> for SofaHdr {
    fn from(mut payload: &[u8]) -> Self {
        let mut ret = Self {
            service: "".to_string(),
            method: "".to_string(),
            trace_id: "".to_string(),
            new_rpc_trace_context: "".to_string(),
        };
        while let Some((key, val)) = read_b32_kv(&mut payload) {
            let Ok(key_str) = std::str::from_utf8(key) else {
                return ret;
            };
            match key_str {
                HDR_SERVICE_KEY => ret.service = String::from_utf8_lossy(val).to_string(),
                HDR_METHOD_KEY => ret.method = String::from_utf8_lossy(val).to_string(),
                HDR_TRACE_ID_KEY => ret.trace_id = String::from_utf8_lossy(val).to_string(),
                SOFA_NEW_RPC_TRACE_CTX_KEY => {
                    ret.new_rpc_trace_context = String::from_utf8_lossy(val).to_string()
                }
                _ => {}
            }
        }
        ret
    }
}

fn read_b32_kv<'a>(payload: &mut &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
    if payload.len() < 4 {
        return None;
    }
    let key_len = read_u32_be(payload) as usize;
    *payload = &payload[4..];
    if payload.len() < key_len + 4 {
        return None;
    }
    let key = &payload[..key_len];

    *payload = &payload[key_len..];
    let val_len = read_u32_be(payload) as usize;
    *payload = &payload[4..];
    if payload.len() < val_len {
        return None;
    }

    let value = &payload[..val_len];
    *payload = &payload[val_len..];
    Some((key, value))
}

pub struct RpcTraceContext {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: String,
}

const RPC_TRACE_CONTEXT_TCID: &[u8] = b"tcid";
const RPC_TRACE_CONTEXT_SPID: &[u8] = b"spid";
const RPC_TRACE_CONTEXT_PSPID: &[u8] = b"pspid";

// example  tcid=ac11000116703149173111002125786&spid=0&pspid=1&sample=true&
pub fn decode_new_rpc_trace_context(mut payload: &[u8]) -> RpcTraceContext {
    let mut ctx = RpcTraceContext {
        trace_id: "".to_string(),
        span_id: "".to_string(),
        parent_span_id: "".to_string(),
    };
    while let Some((key, val)) = read_url_param_kv(&mut payload) {
        match key {
            RPC_TRACE_CONTEXT_TCID => ctx.trace_id = String::from_utf8_lossy(val).to_string(),
            RPC_TRACE_CONTEXT_SPID => ctx.span_id = String::from_utf8_lossy(val).to_string(),
            RPC_TRACE_CONTEXT_PSPID => {
                ctx.parent_span_id = String::from_utf8_lossy(val).to_string()
            }
            _ => {}
        }
    }
    ctx
}

pub fn decode_new_rpc_trace_context_with_type(mut payload: &[u8], id_type: u8) -> Option<String> {
    while let Some((key, val)) = read_url_param_kv(&mut payload) {
        match key {
            RPC_TRACE_CONTEXT_TCID if id_type == HttpLog::TRACE_ID => {
                return Some(String::from_utf8_lossy(val).to_string())
            }
            RPC_TRACE_CONTEXT_SPID if id_type == HttpLog::SPAN_ID => {
                return Some(String::from_utf8_lossy(val).to_string())
            }
            _ => {}
        }
    }
    None
}

fn read_url_param_kv<'a>(payload: &mut &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
    let Ok((rest, key)) = payload.split_at_position::<_, ()>(|b| b == b'=') else {
        return None;
    };
    let Ok((rest, val)) = (&rest[1..]).split_at_position::<_, ()>(|b| b == b'&') else {
        return None;
    };
    *payload = &rest[1..];
    Some((key, val))
}

#[cfg(test)]
mod test {
    use std::{cell::RefCell, path::Path, rc::Rc};

    use crate::{
        common::{
            flow::{L7PerfStats, PacketDirection},
            l7_protocol_info::L7ProtocolInfo,
            l7_protocol_log::{L7PerfCache, L7ProtocolParserInterface, ParseParam},
        },
        flow_generator::{
            protocol_logs::rpc::sofa_rpc::{CMD_CODE_REQ, CMD_CODE_RESP, PROTO_BOLT_V1},
            LogMessageType, L7_RRT_CACHE_CAPACITY,
        },
        utils::test::Capture,
    };

    use super::{decode_new_rpc_trace_context, SofaRpcLog};

    #[test]
    fn test_decode_new_rpc_trace_context() {
        let sample = b"tcid=ac11000116703149173111002125786&spid=fffff&pspid=cccc&";
        let ctx = decode_new_rpc_trace_context(sample);
        assert_eq!(ctx.trace_id, "ac11000116703149173111002125786");
        assert_eq!(ctx.span_id, "fffff");
        assert_eq!(ctx.parent_span_id, "cccc");

        let sample = b"0116703149173111002125786&spid=fffff&&";
        let ctx = decode_new_rpc_trace_context(sample);
        assert_eq!(ctx.trace_id, "");
        assert_eq!(ctx.span_id, "");
        assert_eq!(ctx.parent_span_id, "");

        let sample = b"tcid=ac11000116703149173111002125786";
        let ctx = decode_new_rpc_trace_context(sample);
        assert_eq!(ctx.trace_id, "");
        assert_eq!(ctx.span_id, "");
        assert_eq!(ctx.parent_span_id, "");

        let sample = b"zzzzzzzz";
        let ctx = decode_new_rpc_trace_context(sample);
        assert_eq!(ctx.trace_id, "");
        assert_eq!(ctx.span_id, "");
        assert_eq!(ctx.parent_span_id, "");
    }

    #[test]
    fn test_sofarpc_old() {
        let pcap_file = Path::new("resources/test/flow_generator/sofarpc/sofa-old.pcap");
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let capture = Capture::load_pcap(pcap_file, None);
        let mut p = capture.as_meta_packets();
        p[0].lookup_key.direction = PacketDirection::ClientToServer;
        p[1].lookup_key.direction = PacketDirection::ServerToClient;
        let mut parser = SofaRpcLog::default();

        let req_param = &mut ParseParam::new(&p[0], log_cache.clone(), true, true);
        let req_payload = p[0].get_l4_payload().unwrap();
        assert_eq!(parser.check_payload(req_payload, req_param), true);
        let req_info = parser
            .parse_payload(req_payload, req_param)
            .unwrap()
            .unwrap_single();

        if let L7ProtocolInfo::SofaRpcInfo(k) = &req_info {
            assert_eq!(k.msg_type, LogMessageType::Request);
            assert_eq!(k.cmd_code, CMD_CODE_REQ);
            assert_eq!(k.method, "testSuccess");
            assert_eq!(k.req_id, 2);
            assert_eq!(k.trace_id, "0a2200ce167089845152310016143");
            assert_eq!(k.span_id, "");
            assert_eq!(k.parent_span_id, "");
            assert_eq!(k.proto, PROTO_BOLT_V1);
            assert_eq!(k.req_len, 874);
            assert_eq!(k.target_serv, "com.mycompany.app.common.ServInterface:1.0");
        } else {
            unreachable!()
        }

        parser.reset();

        let resp_param = &mut ParseParam::new(&p[1], log_cache.clone(), true, true);
        let resp_payload = p[1].get_l4_payload().unwrap();

        let resp_info = parser
            .parse_payload(resp_payload, resp_param)
            .unwrap()
            .unwrap_single();

        if let L7ProtocolInfo::SofaRpcInfo(k) = &resp_info {
            assert_eq!(k.msg_type, LogMessageType::Response);
            assert_eq!(k.cmd_code, CMD_CODE_RESP);
            assert_eq!(k.req_id, 2);
            assert_eq!(k.proto, PROTO_BOLT_V1);
            assert_eq!(k.resp_code, 0);
            assert_eq!(k.resp_len, 210);
        } else {
            unreachable!()
        }

        assert_eq!(
            parser.perf_stats.unwrap(),
            L7PerfStats {
                request_count: 1,
                response_count: 1,
                err_client_count: 0,
                err_server_count: 0,
                err_timeout: 0,
                rrt_count: 1,
                rrt_sum: 127254,
                rrt_max: 127254,
                ..Default::default()
            }
        );
    }

    #[test]
    fn test_sofarpc_new() {
        let pcap_file = Path::new("resources/test/flow_generator/sofarpc/sofa-new.pcap");
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let capture = Capture::load_pcap(pcap_file, None);
        let mut p = capture.as_meta_packets();
        p[0].lookup_key.direction = PacketDirection::ClientToServer;
        p[1].lookup_key.direction = PacketDirection::ServerToClient;
        let mut parser = SofaRpcLog::default();

        let req_param = &mut ParseParam::new(&p[0], log_cache.clone(), true, true);
        let req_payload = p[0].get_l4_payload().unwrap();
        assert_eq!(parser.check_payload(req_payload, req_param), true);
        let req_info = parser
            .parse_payload(req_payload, req_param)
            .unwrap()
            .unwrap_single();

        if let L7ProtocolInfo::SofaRpcInfo(k) = &req_info {
            assert_eq!(k.msg_type, LogMessageType::Request);
            assert_eq!(k.cmd_code, CMD_CODE_REQ);
            assert_eq!(k.method, "testSuccess");
            assert_eq!(k.req_id, 2);
            assert_eq!(k.trace_id, "0a2200ce1670900283956100813525");
            assert_eq!(k.span_id, "0");
            assert_eq!(k.parent_span_id, "");
            assert_eq!(k.proto, PROTO_BOLT_V1);
            assert_eq!(k.req_len, 730);
            assert_eq!(k.target_serv, "com.mycompany.app.common.ServInterface:1.0");
        } else {
            unreachable!()
        }

        parser.reset();

        let resp_param = &mut ParseParam::new(&p[1], log_cache.clone(), true, true);
        let resp_payload = p[1].get_l4_payload().unwrap();

        let resp_info = parser
            .parse_payload(resp_payload, resp_param)
            .unwrap()
            .unwrap_single();

        if let L7ProtocolInfo::SofaRpcInfo(k) = &resp_info {
            assert_eq!(k.msg_type, LogMessageType::Response);
            assert_eq!(k.cmd_code, CMD_CODE_RESP);
            assert_eq!(k.req_id, 2);
            assert_eq!(k.proto, PROTO_BOLT_V1);
            assert_eq!(k.resp_code, 0);
            assert_eq!(k.resp_len, 210);
        } else {
            unreachable!()
        }

        assert_eq!(
            parser.perf_stats.unwrap(),
            L7PerfStats {
                request_count: 1,
                response_count: 1,
                err_client_count: 0,
                err_server_count: 0,
                err_timeout: 0,
                rrt_count: 1,
                rrt_sum: 3922,
                rrt_max: 3922,
                ..Default::default()
            }
        );
    }
}
