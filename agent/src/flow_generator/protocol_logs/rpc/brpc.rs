#[path = "brpc/brpc.policy.rs"]
#[rustfmt::skip]
mod brpc_policy;

use brpc_policy::RpcMeta;
use public::l7_protocol::LogMessageType;

use crate::{
    common::{
        enums::IpProtocol,
        flow::{L7PerfStats, L7Protocol},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, LogCache, ParseParam},
        meta_packet::ApplicationFlags,
    },
    config::handler::LogParserConfig,
    flow_generator::{
        error::Result,
        protocol_logs::{
            pb_adapter::{ExtendedInfo, L7ProtocolSendLog, L7Request, L7Response, TraceInfo},
            set_captured_byte, swap_if, AppProtoHead, L7ResponseStatus, PrioFields,
            BASE_FIELD_PRIORITY,
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

    trace_ids: PrioFields,
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
    fn generate_endpoint(&self) -> Option<String> {
        format!(
            "{}/{}",
            self.req_service_name.as_ref()?,
            self.req_method_name.as_ref()?
        )
        .into()
    }

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
            info.endpoint = info.generate_endpoint();
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

        if let Some(config) = param.parse_config.map(|x| &x.l7_log_dynamic) {
            for (k, v) in meta.user_fields.iter() {
                for (index, tt) in config.trace_types.iter().enumerate() {
                    let prio = index as u8 + BASE_FIELD_PRIORITY;
                    if tt.check(k) {
                        if info.trace_ids.highest_priority() <= prio
                            || !config.multiple_trace_id_collection
                        {
                            if let Some(trace_id) = tt.decode_trace_id(v) {
                                info.trace_ids.merge_field(prio, trace_id.to_string())
                            }
                        }
                    }
                }
                for st in config.span_types.iter() {
                    if st.check(k) {
                        info.span_id = st.decode_span_id(v).map(|x| x.to_string());
                        break;
                    }
                }
            }
        }

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
            true => ApplicationFlags::TLS.bits(),
            false => ApplicationFlags::NONE.bits(),
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
                trace_ids: info.trace_ids.into_strings_top3(),
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

impl From<&BrpcInfo> for LogCache {
    fn from(info: &BrpcInfo) -> Self {
        LogCache {
            msg_type: info.msg_type,
            resp_status: info.resp_status,
            on_blacklist: info.is_on_blacklist,
            endpoint: info.get_endpoint(),
            ..Default::default()
        }
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
        self.endpoint.clone()
    }

    fn is_on_blacklist(&self) -> bool {
        self.is_on_blacklist
    }
}

impl L7ProtocolParserInterface for BrpcLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> Option<LogMessageType> {
        if !param.ebpf_type.is_raw_protocol() {
            return None;
        }
        if param.l4_protocol != IpProtocol::TCP {
            return None;
        }
        if payload.len() < 12 {
            return None;
        }
        if BrpcInfo::parse(payload, param).is_some() {
            Some(LogMessageType::Request)
        } else {
            None
        }
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
                if let Some(perf_stats) = self.perf_stats.as_mut() {
                    if info.msg_type == LogMessageType::Response {
                        if let Some(endpoint) = info.load_endpoint_from_cache(param, false) {
                            info.endpoint = Some(endpoint.to_string());
                        }
                    }
                    if let Some(stats) = info.perf_stats(param) {
                        info.rtt = stats.rrt_sum;
                        perf_stats.sequential_merge(&stats);
                    }
                }
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
        config::handler::{L7LogDynamicConfigBuilder, LogParserConfig, TraceType},
        flow_generator::L7_RRT_CACHE_CAPACITY,
        utils::test::Capture,
    };

    const FILE_DIR: &str = "resources/test/flow_generator/brpc";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name));
        let log_cache = Rc::new(RefCell::new(L7PerfCache::new(L7_RRT_CACHE_CAPACITY)));
        let mut packets = capture.collect::<Vec<_>>();
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

            let config = L7LogDynamicConfigBuilder {
                proxy_client: vec![],
                x_request_id: vec![],
                trace_types: vec![TraceType::Sw8, TraceType::TraceParent],
                span_types: vec![TraceType::Sw8, TraceType::TraceParent],
                ..Default::default()
            };
            let parse_config = &LogParserConfig {
                l7_log_dynamic: config.into(),
                ..Default::default()
            };

            param.set_log_parser_config(parse_config);

            if brpc.check_payload(payload, param).is_none() {
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
