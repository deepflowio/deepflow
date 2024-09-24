#[path = "brpc/brpc.policy.rs"]
#[rustfmt::skip]
mod brpc_policy;

use brpc_policy::RpcMeta;

use crate::{
    common::{
        enums::IpProtocol,
        flow::{L7PerfStats, L7Protocol, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, ParseParam},
        meta_packet::EbpfFlags,
    },
    config::handler::LogParserConfig,
    flow_generator::{
        error::Result,
        protocol_logs::{
            pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response, TraceInfo},
            set_captured_byte, swap_if, AppProtoHead, L7ResponseStatus, LogMessageType,
        },
    },
    utils::bytes::read_u32_be,
};

use prost::Message;
use serde::Serialize;

#[derive(Serialize, Debug, Default, Clone)]
pub struct BrpcInfo {
    msg_type: LogMessageType,
    #[serde(skip)]
    is_tls: bool,

    rtt: u64,

    correlation_id: Option<i64>,

    req_service_name: Option<String>,
    req_method_name: Option<String>,
    req_len: Option<u32>,
    req_log_id: Option<i64>,

    resp_status: L7ResponseStatus,
    resp_code: Option<i32>,
    resp_exception: Option<String>,
    resp_len: Option<u32>,

    trace_id: Option<String>,
    span_id: Option<String>,

    captured_request_byte: u32,
    captured_response_byte: u32,

    #[serde(skip)]
    is_on_blacklist: bool,
    #[serde(skip)]
    endpoint: Option<String>,
}

#[derive(Default)]
pub struct BrpcLog {
    perf_stats: Option<L7PerfStats>,
    last_is_on_blacklist: bool,
}

impl BrpcInfo {
    fn parse<'a>(payload: &'a [u8], param: &ParseParam) -> Option<(&'a [u8], Self)> {
        let mut info = BrpcInfo::default();

        let magic = payload.get(0..4)?;
        if magic != b"PRPC" {
            return None;
        }
        let body_size = read_u32_be(payload.get(4..8)?) as usize;
        let meta_size = read_u32_be(payload.get(8..12)?) as usize;

        let body = payload.get(12..12 + body_size)?;
        let payload = payload.get(12 + body_size..)?;

        let meta = RpcMeta::decode(body.get(0..meta_size)?).ok()?;

        info.correlation_id = meta.correlation_id;

        if let Some(req) = meta.request {
            info.req_service_name = Some(req.service_name);
            info.req_method_name = Some(req.method_name);
            info.req_log_id = req.log_id;
            info.req_len = Some(body_size as u32 + 12);
            info.endpoint = info.get_endpoint();
            info.msg_type = LogMessageType::Request;
        } else if let Some(resp) = meta.response {
            info.resp_code = resp.error_code;
            info.resp_exception = resp.error_text;
            info.resp_status = match resp.error_code {
                Some(x) if x != 0 => L7ResponseStatus::ServerError,
                _ => L7ResponseStatus::Ok,
            };
            info.resp_len = Some(body_size as u32 + 12);
            info.msg_type = LogMessageType::Response;
        } else {
            return None;
        }

        (info.trace_id, info.span_id) = {
            let mut trace_id = None;
            let mut span_id = None;
            if let Some(config) = param.parse_config.map(|x| &x.l7_log_dynamic) {
                for (k, v) in meta.user_fields.iter() {
                    for tt in config.trace_types.iter() {
                        if tt.check(k) {
                            trace_id = tt.decode_trace_id(v).map(|x| x.to_string());
                            break;
                        }
                    }
                    for st in config.span_types.iter() {
                        if st.check(k) {
                            span_id = st.decode_span_id(v).map(|x| x.to_string());
                            break;
                        }
                    }
                }
            }
            (trace_id, span_id)
        };

        Some((payload, info))
    }

    fn get_request_id(&self) -> Option<u32> {
        /*
        file: brpc/src/bthread/id.cpp

        inline bthread_id_t make_id(uint32_t version, IdResourceId slot) {
            const bthread_id_t tmp =
                { (((uint64_t)slot.value) << 32) | (uint64_t)version };
            return tmp;
        }
        */
        self.correlation_id.map(|x| (x >> 32) as u32)
    }

    fn set_is_on_blacklist(&mut self, config: &LogParserConfig) {
        if let Some(t) = config.l7_log_blacklist_trie.get(&L7Protocol::Brpc) {
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

impl From<BrpcInfo> for L7ProtocolSendLog {
    fn from(info: BrpcInfo) -> Self {
        let flags = match info.is_tls {
            true => EbpfFlags::TLS.bits(),
            false => EbpfFlags::NONE.bits(),
        };

        let request_id = info.get_request_id();

        let log = L7ProtocolSendLog {
            captured_request_byte: info.captured_request_byte,
            captured_response_byte: info.captured_response_byte,
            flags,
            req_len: info.req_len,
            resp_len: info.resp_len,
            req: L7Request {
                req_type: info.req_method_name.unwrap_or_default(),
                resource: info.req_service_name.unwrap_or_default(),
                endpoint: info.endpoint.unwrap_or_default(),
                ..Default::default()
            },
            resp: L7Response {
                status: info.resp_status,
                code: info.resp_code,
                exception: info.resp_exception.unwrap_or_default(),
                ..Default::default()
            },
            trace_info: Some(TraceInfo {
                trace_id: info.trace_id,
                span_id: info.span_id,
                ..Default::default()
            }),
            ext_info: Some(ExtendedInfo {
                request_id: request_id,
                x_request_id_0: info.req_log_id.map(|x| x.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        log
    }
}

impl L7ProtocolInfoInterface for BrpcInfo {
    fn is_tls(&self) -> bool {
        self.is_tls
    }

    fn session_id(&self) -> Option<u32> {
        self.get_request_id()
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> Result<()> {
        if let (req, L7ProtocolInfo::BrpcInfo(rsp)) = (self, other) {
            req.resp_len = req.resp_len.or(rsp.resp_len);
            if rsp.resp_status != L7ResponseStatus::Ok {
                req.resp_status = rsp.resp_status;
            }
            req.resp_code = req.resp_code.or(rsp.resp_code);
            if req.resp_exception.is_none() {
                req.resp_exception = rsp.resp_exception.clone();
            }
            if rsp.is_on_blacklist {
                req.is_on_blacklist = rsp.is_on_blacklist;
            }
            swap_if!(req, endpoint, is_none, rsp);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::Brpc,
            msg_type: self.msg_type,
            rrt: self.rtt,
        })
    }

    fn get_endpoint(&self) -> Option<String> {
        format!(
            "{}/{}",
            self.req_service_name.as_ref()?,
            self.req_method_name.as_ref()?
        )
        .into()
    }

    fn is_on_blacklist(&self) -> bool {
        self.is_on_blacklist
    }
}

impl L7ProtocolParserInterface for BrpcLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol() {
            return false;
        }
        if param.l4_protocol != IpProtocol::TCP {
            return false;
        }
        if payload.len() < 12 {
            return false;
        }
        BrpcInfo::parse(payload, param).is_some()
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        if self.perf_stats.is_none() && param.parse_perf {
            self.perf_stats = Some(L7PerfStats::default())
        };

        let mut vec = Vec::new();
        let mut payload = payload;

        while let Some((tmp, info)) = BrpcInfo::parse(payload, param) {
            payload = tmp;
            vec.push(L7ProtocolInfo::BrpcInfo(info));
        }

        for info in &mut vec {
            if let L7ProtocolInfo::BrpcInfo(info) = info {
                info.is_tls = param.is_tls();
                set_captured_byte!(info, param);

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
                    match info.resp_status {
                        L7ResponseStatus::ClientError => {
                            self.perf_stats
                                .as_mut()
                                .map(|p: &mut L7PerfStats| p.inc_req_err());
                        }
                        L7ResponseStatus::ServerError => {
                            self.perf_stats
                                .as_mut()
                                .map(|p: &mut L7PerfStats| p.inc_resp_err());
                        }
                        _ => {}
                    }
                    if info.msg_type != LogMessageType::Session {
                        info.cal_rrt(param).map(|rtt| {
                            info.rtt = rtt;
                            self.perf_stats.as_mut().map(|p| p.update_rrt(rtt));
                        });
                    }
                }
                self.last_is_on_blacklist = info.is_on_blacklist;
            }
        }

        if !param.parse_log {
            Ok(L7ParseResult::None)
        } else if vec.len() == 1 {
            Ok(L7ParseResult::Single(vec.remove(0)))
        } else if vec.len() > 1 {
            Ok(L7ParseResult::Multi(vec))
        } else {
            Ok(L7ParseResult::None)
        }
    }

    fn perf_stats(&mut self) -> Option<L7PerfStats> {
        self.perf_stats.take()
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Brpc
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn reset(&mut self) {
        let mut s = Self::default();
        s.last_is_on_blacklist = self.last_is_on_blacklist;
        s.perf_stats = self.perf_stats.take();
        *self = s;
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

    const FILE_DIR: &str = "resources/test/flow_generator/brpc";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name), None);
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
        let mut brpc = BrpcLog::default();
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

            if !brpc.check_payload(payload, param) {
                output.push_str("not brpc\n");
                continue;
            }

            let info = brpc.parse_payload(payload, param);
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
                output.push_str(&format!("{:?}\n", BrpcInfo::default()));
            }
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
            ("brpc-echo.pcap", "brpc-echo.result"),
            ("brpc-echo.pcap", "brpc-echo.result"),
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
