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
use prost::Message;
use public::{
    bytes::read_u16_be,
    l7_protocol::{L7Protocol, ProtobufRpcProtocol},
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
        AppProtoHead, Error, LogMessageType, Result,
    },
    perf_impl,
};

use super::ProtobufRpcInfo;
use public::proto::protobuf_rpc::KrpcMeta;

const KRPC_FIX_HDR_LEN: usize = 8;
const KRPC_DIR_REQ: i32 = 1;
const KRPC_DIR_RESP: i32 = 2;

#[derive(Debug, Default, Clone, Serialize)]
pub struct KrpcInfo {
    #[serde(skip)]
    start_time: u64,
    #[serde(skip)]
    end_time: u64,

    msg_type: LogMessageType,
    msg_id: i32,
    serv_id: i32,
    sequence: i32,
    // 0 success, negative indicate error, no positive number.
    ret_code: i32,

    //trace info
    trace_id: String,
    span_id: String,
    parent_span_id: String,
    status: L7ResponseStatus,
}

impl KrpcInfo {
    fn fill_from_pb(&mut self, k: KrpcMeta) -> Result<()> {
        self.msg_type = match k.direction {
            KRPC_DIR_REQ => LogMessageType::Request,
            KRPC_DIR_RESP => LogMessageType::Response,
            _ => return Err(Error::L7ProtocolUnknown),
        };
        self.msg_id = k.msg_id;
        self.serv_id = k.service_id;
        self.sequence = k.sequence;
        self.ret_code = k.ret_code;

        if let Some(t) = k.trace {
            self.trace_id = t.trace_id;
            self.span_id = t.span_id;
            self.parent_span_id = t.parent_span_id;
        }

        if self.ret_code == 0 {
            self.status = L7ResponseStatus::Ok;
        } else {
            self.status = L7ResponseStatus::ServerError;
        }

        Ok(())
    }

    fn is_heartbeat(&self) -> bool {
        // reference https://github.com/bruceran/krpc/blob/master/doc/develop.md#krpc%E7%BD%91%E7%BB%9C%E5%8C%85%E5%8D%8F%E8%AE%AE
        self.sequence == 0 && self.msg_id == 1 && self.serv_id == 1
    }
}

impl L7ProtocolInfoInterface for KrpcInfo {
    fn session_id(&self) -> Option<u32> {
        Some(self.sequence as u32)
    }

    fn merge_log(&mut self, other: L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::ProtobufRpcInfo(rpc_info) = other {
            #[allow(irrefutable_let_patterns)]
            if let ProtobufRpcInfo::KrpcInfo(k) = rpc_info {
                self.ret_code = k.ret_code;
                self.status = k.status;

                if self.trace_id.is_empty() {
                    self.trace_id = k.trace_id;
                }
                if self.span_id.is_empty() {
                    self.span_id = k.span_id;
                }
            }
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::ProtobufRPC,
            msg_type: self.msg_type,
            rrt: self.end_time - self.start_time,
        })
    }

    fn is_tls(&self) -> bool {
        false
    }
}

impl From<KrpcInfo> for L7ProtocolSendLog {
    fn from(k: KrpcInfo) -> Self {
        let req_id = k.session_id();
        Self {
            req: L7Request {
                req_type: k.msg_id.to_string(),
                resource: k.serv_id.to_string(),
                endpoint: format!("{}/{}", k.serv_id, k.msg_id),
                ..Default::default()
            },
            resp: L7Response {
                status: k.status,
                code: Some(k.ret_code),
                ..Default::default()
            },
            trace_info: Some(TraceInfo {
                trace_id: Some(k.trace_id),
                span_id: Some(k.span_id),
                parent_span_id: Some(k.parent_span_id),
                ..Default::default()
            }),
            ext_info: Some(ExtendedInfo {
                rpc_service: Some(k.serv_id.to_string()),
                request_id: req_id,
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

#[derive(Debug, Serialize)]
pub struct KrpcLog {
    info: KrpcInfo,
    perf_stats: Option<PerfStats>,

    parsed: bool,

    // <session_id,(type,time)>, use for calculate perf
    #[serde(skip)]
    previous_log_info: LruCache<u32, (LogMessageType, u64)>,
}

impl Default for KrpcLog {
    fn default() -> Self {
        Self {
            previous_log_info: LruCache::new(100.try_into().unwrap()),
            info: KrpcInfo::default(),
            perf_stats: None,
            parsed: false,
        }
    }
}

perf_impl!(KrpcLog);

impl KrpcLog {
    pub fn new() -> Self {
        Self::default()
    }

    /*
        krpc hdr reference https://github.com/bruceran/krpc/blob/master/doc/develop.md#krpc%E7%BD%91%E7%BB%9C%E5%8C%85%E5%8D%8F%E8%AE%AE

        0  .......8........16........24.........32
        1  |-----KR---------|----- headLen--------|
        2  |---------------packetLen--------------|
    */
    fn parse(
        &mut self,
        payload: &[u8],
        param: &ParseParam,
        strict: bool,
    ) -> Result<Vec<L7ProtocolInfo>> {
        if self.parsed {
            return if self.info.is_heartbeat() {
                Ok(vec![])
            } else {
                Ok(vec![L7ProtocolInfo::ProtobufRpcInfo(
                    ProtobufRpcInfo::KrpcInfo(self.info.clone()),
                )])
            };
        }
        self.info.start_time = param.time;
        self.info.end_time = param.time;
        if payload.len() < KRPC_FIX_HDR_LEN || &payload[..2] != b"KR" {
            return Err(Error::L7ProtocolUnknown);
        }

        let hdr_len = read_u16_be(&payload[2..]) as usize;

        let pb_paylaod = if hdr_len + KRPC_FIX_HDR_LEN > payload.len() {
            // if hdr_len + KRPC_FIX_HDR_LEN > payload.len() likely ebpf not read full data from syscall, pb parse to the payload end.
            if strict {
                return Err(Error::L7ProtocolUnknown);
            }
            &payload[KRPC_FIX_HDR_LEN..payload.len()]
        } else {
            &payload[KRPC_FIX_HDR_LEN..KRPC_FIX_HDR_LEN + hdr_len]
        };

        let mut hdr = KrpcMeta::default();
        if let Err(_) = hdr.merge(pb_paylaod) {
            if strict {
                return Err(Error::L7ProtocolUnknown);
            }
        }

        self.info.fill_from_pb(hdr)?;

        // filter heartbreat
        if self.info.is_heartbeat() {
            return Ok(vec![]);
        }
        match self.info.msg_type {
            LogMessageType::Request => self.perf_inc_req(param.time),
            LogMessageType::Response => {
                self.perf_inc_resp(param.time);
                if self.info.ret_code != 0 {
                    self.perf_inc_resp_err();
                }
            }
            _ => unreachable!(),
        }

        self.revert_info_time(param.direction, param.time);
        Ok(vec![L7ProtocolInfo::ProtobufRpcInfo(
            ProtobufRpcInfo::KrpcInfo(self.info.clone()),
        )])
    }
}

impl L7ProtocolParserInterface for KrpcLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol() {
            return false;
        }
        self.info.start_time = param.time;
        self.info.end_time = param.time;
        self.parsed = self.parse(payload, param, true).is_ok();
        self.parsed && self.info.msg_type == LogMessageType::Request
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<Vec<L7ProtocolInfo>> {
        self.parse(payload, param, false)
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::ProtobufRPC
    }

    fn protobuf_rpc_protocol(&self) -> Option<ProtobufRpcProtocol> {
        Some(ProtobufRpcProtocol::Krpc)
    }

    fn reset(&mut self) {
        self.parsed = false;
        self.save_info_time();
        self.info = KrpcInfo::default();
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }
}

impl L7FlowPerf for KrpcLog {
    fn parse(
        &mut self,
        _: Option<&LogParserConfig>,
        _packet: &MetaPacket,
        _flow_id: u64,
    ) -> Result<()> {
        unreachable!()
    }

    fn data_updated(&self) -> bool {
        return self.perf_stats.is_some();
    }

    fn copy_and_reset_data(&mut self, l7_timeout_count: u32) -> FlowPerfStats {
        FlowPerfStats {
            l7_protocol: L7Protocol::ProtobufRPC,
            l7: if let Some(perf) = self.perf_stats.take() {
                L7PerfStats {
                    request_count: perf.req_count,
                    response_count: perf.resp_count,
                    err_client_count: perf.req_err_count,
                    err_server_count: perf.resp_err_count,
                    err_timeout: l7_timeout_count,
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

#[cfg(test)]
mod test {
    use std::path::Path;

    use crate::common::flow::PacketDirection;
    use crate::common::l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface};
    use crate::common::l7_protocol_log::{L7ProtocolParserInterface, ParseParam};

    use crate::flow_generator::protocol_logs::{L7ResponseStatus, ProtobufRpcInfo};
    use crate::flow_generator::LogMessageType;
    use crate::utils::test::Capture;

    use super::KrpcLog;

    #[test]
    fn test_krpc() {
        let pcap_file = Path::new("resources/test/flow_generator/krpc/krpc.pcap");
        let capture = Capture::load_pcap(pcap_file, None);
        let mut p = capture.as_meta_packets();
        p[3].lookup_key.direction = PacketDirection::ClientToServer;
        p[5].lookup_key.direction = PacketDirection::ServerToClient;

        let mut parser = KrpcLog::new();

        let req_param = &mut ParseParam::from(&p[3]);
        let req_payload = p[3].get_l4_payload().unwrap();
        assert_eq!(parser.check_payload(req_payload, req_param), true);
        let mut req_info = parser
            .parse_payload(req_payload, req_param)
            .unwrap()
            .remove(0);

        if let L7ProtocolInfo::ProtobufRpcInfo(rpc_info) = &req_info {
            #[allow(irrefutable_let_patterns)]
            if let ProtobufRpcInfo::KrpcInfo(k) = rpc_info {
                assert_eq!(k.msg_id, 30);
                assert_eq!(k.serv_id, 455);
                assert_eq!(k.ret_code, 0);
                assert_eq!(k.sequence, 1);
                assert_eq!(k.trace_id, "gtwdemo-ac110006-463659-122997101");
                assert_eq!(k.span_id, "gtwdemo-ac110006-463659-122997102");
                assert_eq!(k.msg_type, LogMessageType::Request);
            } else {
                unreachable!()
            }
        } else {
            unreachable!()
        }

        parser.reset();

        let resp_param = &mut ParseParam::from(&p[5]);
        let resp_payload = p[5].get_l4_payload().unwrap();

        let resp_info = parser
            .parse_payload(resp_payload, resp_param)
            .unwrap()
            .remove(0);

        if let L7ProtocolInfo::ProtobufRpcInfo(rpc_info) = &resp_info {
            #[allow(irrefutable_let_patterns)]
            if let ProtobufRpcInfo::KrpcInfo(k) = rpc_info {
                assert_eq!(k.msg_id, 30);
                assert_eq!(k.serv_id, 455);
                assert_eq!(k.ret_code, 0);
                assert_eq!(k.sequence, 1);
                assert_eq!(k.trace_id, "");
                assert_eq!(k.span_id, "");
                assert_eq!(k.msg_type, LogMessageType::Response);
            } else {
                unreachable!()
            }
        } else {
            unimplemented!()
        }

        req_info.merge_log(resp_info).unwrap();

        if let L7ProtocolInfo::ProtobufRpcInfo(rpc_info) = &req_info {
            #[allow(irrefutable_let_patterns)]
            if let ProtobufRpcInfo::KrpcInfo(k) = rpc_info {
                assert_eq!(k.msg_id, 30);
                assert_eq!(k.serv_id, 455);
                assert_eq!(k.ret_code, 0);
                assert_eq!(k.sequence, 1);
                assert_eq!(k.status, L7ResponseStatus::Ok);
                assert_eq!(k.trace_id, "gtwdemo-ac110006-463659-122997101");
                assert_eq!(k.span_id, "gtwdemo-ac110006-463659-122997102");
            } else {
                unreachable!()
            }
        } else {
            unreachable!()
        }
    }
}
