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

use lru::LruCache;
use nom::InputTakeAtPosition;
use public::{
    bytes::{read_u16_be, read_u32_be},
    l7_protocol::L7Protocol,
};
use serde::Serialize;

use crate::{
    common::{
        flow::{FlowPerfStats, L7PerfStats, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ProtocolParserInterface, ParseParam},
        MetaPacket,
    },
    config::handler::LogParserConfig,
    flow_generator::{
        perf::{L7FlowPerf, PerfStats},
        protocol_logs::{
            pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response, TraceInfo},
            L7ResponseStatus,
        },
        AppProtoHead, Error, HttpLog, LogMessageType, Result,
    },
    perf_impl,
};

const REQ_HDR_LEN: usize = 22;
const RESP_HDR_LEN: usize = 20;

const PROTO_BOLT_V1: u8 = 1;

const TYPE_REQ: u8 = 1;
const TYPE_RESP: u8 = 0;

const CMD_CODE_HEARTBEAT: u16 = 0;
const CMD_CODE_REQ: u16 = 1;
const CMD_CODE_RESP: u16 = 2;

const SERVICE_KEY: &'static str = "sofa_head_target_service";
const METHOD_KEY: &'static str = "sofa_head_method_name";
const TRACE_ID_KEY: &'static str = "rpc_trace_context.sofaTraceId";
pub const SOFA_NEW_RPC_TRACE_CTX_KEY: &'static str = "new_rpc_trace_context";

struct Hdr {
    proto: u8,
    typ: u8,
    cmd_code: u16,
    req_id: u32,
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
        if payload.len() < 2 {
            return Err(Error::L7ProtocolUnknown);
        }
        let proto = payload[0];
        let typ = payload[1];
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
    proto: u8,
    req_id: u32,
    msg_type: LogMessageType,

    #[serde(skip)]
    start_time: u64,
    #[serde(skip)]
    end_time: u64,

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

impl L7ProtocolInfoInterface for SofaRpcInfo {
    fn session_id(&self) -> Option<u32> {
        Some(self.req_id)
    }

    fn merge_log(&mut self, other: L7ProtocolInfo) -> Result<()> {
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
            rrt: self.end_time - self.start_time,
        })
    }

    fn is_tls(&self) -> bool {
        false
    }
}

impl From<SofaRpcInfo> for L7ProtocolSendLog {
    fn from(s: SofaRpcInfo) -> Self {
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
            ..Default::default()
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SofaRpcLog {
    info: SofaRpcInfo,
    perf_stats: Option<PerfStats>,
    parsed: bool,
    // <session_id,(type,time)>, use for calculate perf
    #[serde(skip)]
    previous_log_info: LruCache<u32, (LogMessageType, u64)>,
}

impl Default for SofaRpcLog {
    fn default() -> Self {
        Self {
            previous_log_info: LruCache::new(100.try_into().unwrap()),
            info: SofaRpcInfo::default(),
            perf_stats: None,
            parsed: false,
        }
    }
}

perf_impl!(SofaRpcLog);

impl L7ProtocolParserInterface for SofaRpcLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        self.parsed = self.parse_with_strict(payload, param, true).is_ok()
            && self.info.msg_type == LogMessageType::Request
            && self.info.cmd_code != CMD_CODE_HEARTBEAT;
        self.parsed
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<Vec<L7ProtocolInfo>> {
        self.parse_with_strict(payload, param, false)
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::SofaRPC
    }

    fn reset(&mut self) {
        self.parsed = false;
        self.save_info_time();

        self.info = SofaRpcInfo::default();
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }
}

impl SofaRpcLog {
    fn parse_with_strict(
        &mut self,
        mut payload: &[u8],
        param: &ParseParam,
        strict: bool,
    ) -> Result<Vec<L7ProtocolInfo>> {
        if self.parsed {
            return Ok(vec![L7ProtocolInfo::SofaRpcInfo(self.info.clone())]);
        }
        self.info.start_time = param.time;
        self.info.end_time = param.time;

        let hdr = Hdr::try_from(payload)?;

        self.info.proto = hdr.proto;
        // now only support bolt v1
        if self.info.proto != PROTO_BOLT_V1 {
            return Err(Error::L7ProtocolUnknown);
        }

        self.info.cmd_code = hdr.cmd_code;
        if self.info.cmd_code == CMD_CODE_HEARTBEAT {
            // skip heartbeat
            return if strict {
                Err(Error::L7ProtocolUnknown)
            } else {
                Ok(vec![])
            };
        }
        self.info.req_id = hdr.req_id;
        self.info.msg_type = match hdr.typ {
            TYPE_REQ => {
                payload = &payload[REQ_HDR_LEN..];
                self.info.req_len = hdr.content_len + (hdr.hdr_len as u32) + (hdr.class_len as u32);
                LogMessageType::Request
            }
            TYPE_RESP => {
                payload = &payload[RESP_HDR_LEN..];
                self.info.resp_code = hdr.resp_code;
                self.info.resp_len =
                    hdr.content_len + (hdr.hdr_len as u32) + (hdr.class_len as u32);
                if self.info.resp_code == 8 {
                    self.perf_inc_req_err();
                    self.info.status = L7ResponseStatus::ClientError;
                } else if self.info.resp_code != 0 {
                    self.perf_inc_resp_err();
                    self.info.status = L7ResponseStatus::ServerError;
                }
                LogMessageType::Response
            }
            _ => return Err(Error::L7ProtocolUnknown),
        };
        match self.info.msg_type {
            LogMessageType::Request => self.perf_inc_req(param.time),
            LogMessageType::Response => self.perf_inc_resp(param.time),
            _ => {}
        }

        if hdr.class_len as usize > payload.len() {
            return if strict {
                Err(Error::L7ProtocolUnknown)
            } else {
                Ok(vec![L7ProtocolInfo::SofaRpcInfo(self.info.clone())])
            };
        }
        payload = &payload[hdr.class_len as usize..];

        if hdr.hdr_len != 0 {
            let hdr_len = hdr.hdr_len as usize;
            let hdr_payload = if hdr_len as usize > payload.len() {
                // if hdr_len as usize > payload.len() likey ebpf not read full data from java process, parse hdr to payload end
                if strict {
                    return Err(Error::L7ProtocolUnknown);
                }
                payload
            } else {
                &payload[..hdr_len]
            };

            let sofa_hdr = SofaHdr::from(hdr_payload);
            self.info.target_serv = sofa_hdr.service;
            self.info.method = sofa_hdr.method;
            self.info.trace_id = sofa_hdr.trace_id;

            if strict && (self.info.target_serv.is_empty() || self.info.method.is_empty()) {
                return Err(Error::L7ProtocolUnknown);
            }

            if !sofa_hdr.new_rpc_trace_context.is_empty() {
                self.fill_with_trace_ctx(sofa_hdr.new_rpc_trace_context);
            }
        }
        self.revert_info_time(param.direction, param.time);
        Ok(vec![L7ProtocolInfo::SofaRpcInfo(self.info.clone())])
    }

    fn fill_with_trace_ctx(&mut self, ctx: String) {
        let ctx = decode_new_rpc_trace_context(ctx.as_bytes());
        if !ctx.trace_id.is_empty() {
            self.info.trace_id = ctx.trace_id;
        }
        if !ctx.span_id.is_empty() {
            self.info.span_id = ctx.span_id;
        }
        if !ctx.parent_span_id.is_empty() {
            self.info.parent_span_id = ctx.parent_span_id;
        }
    }
}

impl L7FlowPerf for SofaRpcLog {
    fn parse(&mut self, _: Option<&LogParserConfig>, packet: &MetaPacket, _: u64) -> Result<()> {
        if let Some(payload) = packet.get_l4_payload() {
            self.parse_payload(payload, &ParseParam::from(packet))?;
            return Ok(());
        }
        Err(Error::L7ProtocolUnknown)
    }

    fn data_updated(&self) -> bool {
        self.perf_stats.is_some()
    }

    fn copy_and_reset_data(&mut self, timeout_count: u32) -> crate::common::flow::FlowPerfStats {
        FlowPerfStats {
            l7_protocol: L7Protocol::SofaRPC,
            l7: if let Some(perf) = self.perf_stats.take() {
                L7PerfStats {
                    request_count: perf.req_count,
                    response_count: perf.resp_count,
                    err_client_count: perf.req_err_count,
                    err_server_count: perf.resp_err_count,
                    err_timeout: timeout_count,
                    rrt_count: perf.rrt_count,
                    rrt_sum: perf.rrt_sum.as_micros() as u64,
                    rrt_max: perf.rrt_max.as_micros() as u32,
                }
            } else {
                L7PerfStats::default()
            },
            ..Default::default()
        }
    }

    fn app_proto_head(&mut self) -> Option<(AppProtoHead, u16)> {
        if let Some(h) = L7ProtocolInfoInterface::app_proto_head(&self.info) {
            return Some((h, 0));
        }
        None
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
            let Ok(key_str) = std::str::from_utf8(key) else{
                return ret;
            };
            match key_str {
                SERVICE_KEY => ret.service = String::from_utf8_lossy(val).to_string(),
                METHOD_KEY => ret.method = String::from_utf8_lossy(val).to_string(),
                TRACE_ID_KEY => ret.trace_id = String::from_utf8_lossy(val).to_string(),
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
    let Ok((rest, key)) = payload.split_at_position::<_,()>(|b| b == b'=')else{
        return None;
    };
    let Ok((rest, val)) = (&rest[1..]).split_at_position::<_,()>(|b| b == b'&')else{
        return None;
    };
    *payload = &rest[1..];
    Some((key, val))
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use crate::{
        common::{
            flow::PacketDirection,
            l7_protocol_info::L7ProtocolInfo,
            l7_protocol_log::{L7ProtocolParserInterface, ParseParam},
        },
        flow_generator::{
            protocol_logs::rpc::sofa_rpc::{CMD_CODE_REQ, CMD_CODE_RESP, PROTO_BOLT_V1},
            LogMessageType,
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
        let capture = Capture::load_pcap(pcap_file, None);
        let mut p = capture.as_meta_packets();
        p[0].lookup_key.direction = PacketDirection::ClientToServer;
        p[1].lookup_key.direction = PacketDirection::ServerToClient;
        let mut parser = SofaRpcLog::default();

        let req_param = &mut ParseParam::from(&p[0]);
        let req_payload = p[0].get_l4_payload().unwrap();
        assert_eq!(parser.check_payload(req_payload, req_param), true);
        let req_info = parser
            .parse_payload(req_payload, req_param)
            .unwrap()
            .remove(0);

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

        let resp_param = &mut ParseParam::from(&p[1]);
        let resp_payload = p[1].get_l4_payload().unwrap();

        let resp_info = parser
            .parse_payload(resp_payload, resp_param)
            .unwrap()
            .remove(0);

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
    }

    #[test]
    fn test_sofarpc_new() {
        let pcap_file = Path::new("resources/test/flow_generator/sofarpc/sofa-new.pcap");
        let capture = Capture::load_pcap(pcap_file, None);
        let mut p = capture.as_meta_packets();
        p[0].lookup_key.direction = PacketDirection::ClientToServer;
        p[1].lookup_key.direction = PacketDirection::ServerToClient;
        let mut parser = SofaRpcLog::default();

        let req_param = &mut ParseParam::from(&p[0]);
        let req_payload = p[0].get_l4_payload().unwrap();
        assert_eq!(parser.check_payload(req_payload, req_param), true);
        let req_info = parser
            .parse_payload(req_payload, req_param)
            .unwrap()
            .remove(0);

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

        let resp_param = &mut ParseParam::from(&p[1]);
        let resp_payload = p[1].get_l4_payload().unwrap();

        let resp_info = parser
            .parse_payload(resp_payload, resp_param)
            .unwrap()
            .remove(0);

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
    }
}
