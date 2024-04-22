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

use std::collections::HashMap;
use std::fmt::{self, Debug, Formatter};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

use flate2::{read::GzDecoder, write::ZlibEncoder, Compression};
use http::header::{CONTENT_ENCODING, CONTENT_TYPE};
use http::HeaderMap;
use hyper::{
    body::{aggregate, Buf},
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server, StatusCode,
};
use log::{debug, error, info, log_enabled, warn, Level};
use prost::Message;
use public::{
    buffer::{Allocator, BatchedBox},
    sender::{SendMessageType, Sendable},
};
use tokio::{
    runtime::Runtime,
    select,
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time,
};

use crate::{
    common::{
        flow::{Flow, FlowPerfStats, L7PerfStats, L7Stats, SignalSource},
        lookup_key::LookupKey,
        TaggedFlow, Timestamp,
    },
    config::{handler::LogParserConfig, PrometheusExtraConfig},
    exception::ExceptionHandler,
    flow_generator::protocol_logs::{http::handle_endpoint, L7ResponseStatus},
    metric::document::{Direction, TapSide},
    policy::PolicyGetter,
};

use public::{
    counter::{Counter, CounterType, CounterValue, OwnedCountable},
    enums::{EthernetType, L4Protocol, TapType},
    l7_protocol::L7Protocol,
    proto::{
        integration::opentelemetry::proto::{
            common::v1::{
                any_value::Value::{IntValue, StringValue},
                AnyValue, KeyValue,
            },
            trace::v1::{span::SpanKind, Span, TracesData},
        },
        metric,
        trident::Exception,
    },
    queue::DebugSender,
    utils::net::ipv6_enabled,
};

type GenericError = Box<dyn std::error::Error + Send + Sync>;

const NOT_FOUND: &[u8] = b"Not Found";
const GZIP: &str = "gzip";
const OPEN_TELEMETRY: u32 = 20220607;
const OPEN_TELEMETRY_COMPRESSED: u32 = 20221024;
const PROMETHEUS: u32 = 20220613;
const TELEGRAF: u32 = 20220613;

// Otel的protobuf数据
// ingester使用该proto https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/trace/v1/trace.proto进行解析
#[derive(Debug, PartialEq)]
pub struct OpenTelemetry(Vec<u8>);

impl Sendable for OpenTelemetry {
    fn encode(mut self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        let length = self.0.len();
        buf.append(&mut self.0);
        Ok(length)
    }

    fn message_type(&self) -> SendMessageType {
        SendMessageType::OpenTelemetry
    }

    fn version(&self) -> u32 {
        OPEN_TELEMETRY
    }
}

#[derive(Debug, PartialEq)]
pub struct OpenTelemetryCompressed(Vec<u8>);

impl Sendable for OpenTelemetryCompressed {
    fn encode(mut self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        let length = self.0.len();
        buf.append(&mut self.0);
        Ok(length)
    }

    fn message_type(&self) -> SendMessageType {
        SendMessageType::OpenTelemetryCompressed
    }

    fn version(&self) -> u32 {
        OPEN_TELEMETRY_COMPRESSED
    }
}

/// Prometheus metrics, in snappy compressed petabytes of data
/// You can refer to https://github.com/prometheus/prometheus/tree/main/documentation/examples/remote_storage/example_write_adapter to parse
pub struct PrometheusExtra {
    metrics: Vec<u8>,
    extra_label_names: Vec<String>,
    extra_label_values: Vec<String>,
}

impl Debug for PrometheusExtra {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "PrometheusExtra {{ metrics's len: {}, extra_label_names: {:?}, extra_label_values: {:?}",
            self.metrics.len(), self.extra_label_names, self.extra_label_values
        ))
    }
}

#[derive(Debug)]
pub struct BoxedPrometheusExtra(pub Box<PrometheusExtra>);

impl Sendable for BoxedPrometheusExtra {
    fn encode(self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        let pb_prometheus_metric = metric::PrometheusMetric {
            metrics: self.0.metrics,
            extra_label_names: self.0.extra_label_names,
            extra_label_values: self.0.extra_label_values,
        };
        let _ = pb_prometheus_metric.encode(buf)?;
        Ok(pb_prometheus_metric.encoded_len())
    }

    fn message_type(&self) -> SendMessageType {
        SendMessageType::Prometheus
    }

    fn version(&self) -> u32 {
        PROMETHEUS
    }
}

/// Telegraf metric， 是influxDB标准行协议的UTF8编码的文本数据
#[derive(Debug, PartialEq)]
pub struct TelegrafMetric(Vec<u8>);

impl Sendable for TelegrafMetric {
    fn encode(mut self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        let length = self.0.len();
        buf.append(&mut self.0);
        Ok(length)
    }

    fn message_type(&self) -> SendMessageType {
        SendMessageType::Telegraf
    }

    fn version(&self) -> u32 {
        TELEGRAF
    }
}

/// java profile xxxx
#[derive(Debug, PartialEq)]
pub struct Profile(pub metric::Profile);

impl Sendable for Profile {
    fn encode(self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        self.0.encode(buf).map(|_| self.0.encoded_len())
    }

    fn message_type(&self) -> SendMessageType {
        SendMessageType::Profile
    }
}

fn decode_metric(mut whole_body: impl Buf, headers: &HeaderMap) -> Result<Vec<u8>, GenericError> {
    let metric = if headers
        .get(CONTENT_ENCODING)
        .filter(|&v| v == GZIP)
        .is_some()
    {
        let mut metric = vec![];
        let mut gz = GzDecoder::new(whole_body.reader());
        gz.read_to_end(&mut metric)?;
        metric
    } else {
        let mut metric = vec![0u8; whole_body.remaining()];
        whole_body.copy_to_slice(metric.as_mut_slice());
        metric
    };

    Ok(metric)
}

async fn aggregate_with_catch_exception(
    body: Body,
    exception_handler: &ExceptionHandler,
) -> Result<impl Buf, Response<Body>> {
    aggregate(body).await.map_err(|e| {
        if e.is_user() {
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(e.to_string().into())
                .unwrap()
        } else {
            error!("integration collector error: {}", e);
            exception_handler.set(Exception::IntegrationSocketError);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(e.to_string().into())
                .unwrap()
        }
    })
}

fn decode_otel_trace_data(
    peer_addr: SocketAddr,
    data: Vec<u8>,
    local_epc_id: u32,
    policy_getter: Arc<PolicyGetter>,
    time_diff: i64,
    flow_id: Arc<AtomicU64>,
    log_parser_config: Arc<LogParserConfig>,
) -> Result<(Vec<u8>, Vec<BatchedBox<L7Stats>>), GenericError> {
    let mut l7_stats: Vec<BatchedBox<L7Stats>> = vec![];
    let mut d = TracesData::decode(data.as_slice())?;
    // 因为collector传过来traceData的全部resource都有"app.host.ip"的属性，所以只检查第一个resource有没有“app.host.ip”即可，
    // sdk传过来的traceData因没有该属性则要补上(key: “app.host.ip”, value: 对端IP)属性值
    // =======================================================================
    // Because all the resources of the traceData passed by the collector have the attribute "app.host.ip",
    // only check whether the first resource has "app.host.ip". The traceData passed by the sdk does not have this attribute.
    //  Fill in the (key: "app.host.ip", value: peer IP) attribute value
    let mut skip_verify_ip = true;

    let mut ip = get_ip(peer_addr.ip());
    let host_ip = KeyValue {
        key: "app.host.ip".into(),
        value: Some(AnyValue {
            value: { Some(StringValue(ip.to_string())) },
        }),
    };

    let mut allocator = Allocator::new(16);
    for resource_span in d.resource_spans.iter_mut() {
        let mut otel_service = None;
        let mut otel_instance = None;
        if let Some(resource) = resource_span.resource.as_mut() {
            for attr in resource.attributes.iter() {
                match attr.key.as_str() {
                    "app.host.ip" => {
                        skip_verify_ip = false;
                        // the format such as: ResourceSpans { resource: Some(Resource {attributes:[KeyValue { key: "app.host.ip", value: Some(AnyValue { value: Some(StringValue("0.0.0.0")) }) }]
                        if let Some(value) = attr.value.clone() {
                            if let Some(StringValue(val)) = value.value {
                                if let Ok(ip_addr) = val.parse::<IpAddr>() {
                                    ip = ip_addr;
                                }
                            }
                        }
                    }
                    "service.name" => {
                        // the format such as: ResourceSpans { resource: Some(Resource {attributes:[KeyValue { key: "service.name", value: Some(AnyValue { value: Some(StringValue("someservice")) }) }]
                        if let Some(value) = attr.value.clone() {
                            if let Some(StringValue(val)) = value.value {
                                otel_service = Some(val);
                            }
                        }
                    }
                    "service.instance.id" => {
                        // the format such as: ResourceSpans { resource: Some(Resource {attributes:[KeyValue { key: "service.instance.id", value: Some(AnyValue { value: Some(StringValue("someserviceinstabceid")) }) }]
                        if let Some(value) = attr.value.clone() {
                            if let Some(StringValue(val)) = value.value {
                                otel_instance = Some(val);
                            }
                        }
                    }
                    _ => {}
                }
            }
            if skip_verify_ip {
                // if resource.attributes doesn't have the "app.host.ip" attribute, add this attribute.
                resource.attributes.push(host_ip.clone());
            }
        }
        // collect otel metrics
        let mut id = flow_id.load(Ordering::Relaxed);
        for scope_spans in resource_span.scope_spans.iter() {
            for span in scope_spans.spans.iter() {
                let stats = fill_l7_stats(
                    id,
                    span,
                    ip,
                    policy_getter.clone(),
                    local_epc_id,
                    otel_service.clone(),
                    otel_instance.clone(),
                    time_diff,
                    log_parser_config.clone(),
                );
                l7_stats.push(allocator.allocate_one_with(stats));
                id += 1;
            }
        }
        flow_id.store(id, Ordering::Relaxed); // FIXME: flow_id may conflict
    }
    let sdk_data = d.encode_to_vec();
    debug!("send otel sdk traces_data to sender: {:?}", d);
    return Ok((sdk_data, l7_stats));
}

fn fill_l7_stats(
    flow_id: u64,
    span: &Span,
    ip: IpAddr,
    policy_getter: Arc<PolicyGetter>,
    local_epc_id: u32,
    otel_service: Option<String>,
    otel_instance: Option<String>,
    time_diff: i64,
    log_parser_config: Arc<LogParserConfig>,
) -> L7Stats {
    let (mut ip0, mut ip1, eth_type) = if ip.is_ipv4() {
        (
            IpAddr::from(Ipv4Addr::UNSPECIFIED),
            IpAddr::from(Ipv4Addr::UNSPECIFIED),
            EthernetType::IPV4,
        )
    } else {
        (
            IpAddr::from(Ipv6Addr::UNSPECIFIED),
            IpAddr::from(Ipv6Addr::UNSPECIFIED),
            EthernetType::IPV6,
        )
    };
    let mut l4_protocol = L4Protocol::Tcp;
    let mut l7_protocol = L7Protocol::Unknown;
    let mut status = L7ResponseStatus::NotExist;
    let mut is_http2 = false;
    let (mut l2_end_0, mut l2_end_1) = (false, false);

    let mut flow = Flow::default();
    flow.signal_source = SignalSource::OTel;
    flow.otel_service = otel_service;
    flow.otel_instance = otel_instance;
    flow.eth_type = eth_type;
    flow.tap_side = TapSide::from(SpanKind::from_i32(span.kind).unwrap());
    if flow.tap_side == TapSide::ClientApp {
        l2_end_0 = true;
        ip0 = ip;
        flow.directions = [Direction::ClientAppToServer, Direction::None];
    } else if flow.tap_side == TapSide::ServerApp {
        l2_end_1 = true;
        ip1 = ip;
        flow.directions = [Direction::None, Direction::ServerAppToClient];
    } else {
        l2_end_1 = true;
        ip1 = ip;
        flow.directions = [Direction::None, Direction::None];
    }
    for attr in &span.attributes {
        match attr.key.as_str() {
            // According to https://opentelemetry.io/docs/reference/specification/trace/semantic_conventions/
            // the format such as:
            // {
            //     "scope_spans": [
            //         {
            //             "spans": [
            //                 {
            //                     "attributes": [
            //                         {
            //                             "key": "rpc.system",
            //                             "value": "grpc"
            //                         }
            //                     ]
            //                 }
            //             ]
            //         }
            //     ]
            // }
            "http.scheme" | "db.system" | "rpc.system" | "messaging.system"
            | "messaging.protocol" => {
                if let Some(value) = attr.value.clone() {
                    if let Some(StringValue(val)) = value.value {
                        l7_protocol = L7Protocol::from(val);
                    }
                }
            }
            // Format as above, "net.peer.ip": "0.0.0.0"
            "net.peer.ip" => {
                if let Some(value) = attr.value.clone() {
                    if let Some(StringValue(val)) = value.value {
                        if let Ok(ip_addr) = val.parse::<IpAddr>() {
                            let ip_addr = get_ip(ip_addr);
                            if flow.tap_side == TapSide::ClientApp {
                                ip1 = ip_addr;
                            } else {
                                ip0 = ip_addr;
                            }
                        }
                    }
                }
            }
            // Format as above, "net.transport": "ip_tcp"
            "net.transport" => {
                if let Some(value) = attr.value.clone() {
                    if let Some(StringValue(val)) = value.value {
                        l4_protocol = L4Protocol::from(val);
                    }
                }
            }
            // Format as above, "http.status_code": 200
            "http.status_code" => {
                if let Some(value) = attr.value.clone() {
                    if let Some(IntValue(val)) = value.value {
                        status = http_code_to_response_status(val);
                    }
                }
            }
            // Format as above, "http.flavor": "1.1"
            "http.flavor" => {
                if let Some(value) = attr.value.clone() {
                    if let Some(StringValue(val)) = value.value {
                        if val == "2.0" {
                            is_http2 = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    match l7_protocol {
        L7Protocol::Http1 | L7Protocol::Http2 => {
            flow.last_endpoint = Some(handle_endpoint(log_parser_config.as_ref(), &span.name))
        }
        _ => {
            flow.last_endpoint = Some(span.name.clone());
        }
    }

    if is_http2 {
        if l7_protocol == L7Protocol::Http1 {
            l7_protocol = L7Protocol::Http2;
        }
    }

    (flow.flow_key.ip_src, flow.flow_key.ip_dst) = (ip0, ip1);

    // According to https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/trace/api.md#set-status
    // Unset = 0, Ok = 1, Error = 2
    if status == L7ResponseStatus::NotExist && span.status.is_some() {
        status = match span.status.as_ref().unwrap().code {
            1 => L7ResponseStatus::Ok,
            2 => L7ResponseStatus::ServerError,
            _ => L7ResponseStatus::NotExist,
        }
    }

    let start_time = span.start_time_unix_nano;
    let end_time = span.end_time_unix_nano;
    if time_diff >= 0 {
        flow.flow_stat_time = Timestamp::from_nanos(end_time + time_diff as u64);
    } else {
        flow.flow_stat_time = Timestamp::from_nanos(end_time - -time_diff as u64);
    }
    let rrt = if end_time > start_time {
        (end_time - start_time) / 1000 // unit: μs
    } else {
        0
    };
    let stats = L7PerfStats {
        request_count: 1,
        response_count: 1, // otel data is all session logs, so the number of requests is the same as the number of responses
        err_client_count: if status == L7ResponseStatus::ClientError {
            1
        } else {
            0
        },
        err_server_count: if status == L7ResponseStatus::ServerError {
            1
        } else {
            0
        },
        err_timeout: 0,
        rrt_count: if rrt > 0 { 1 } else { 0 },
        rrt_sum: if rrt > 0 { rrt } else { 0 },
        rrt_max: if rrt > 0 { rrt as u32 } else { 0 },
        ..Default::default()
    };
    let flow_perf_stats = FlowPerfStats {
        tcp: Default::default(),
        l7: stats.clone(),
        l4_protocol,
        l7_protocol,
        ..Default::default()
    };
    flow.flow_perf_stats = Some(flow_perf_stats);
    let mut lookup_key = LookupKey {
        src_ip: flow.flow_key.ip_src,
        dst_ip: flow.flow_key.ip_dst,
        l2_end_0,
        l2_end_1,
        ..Default::default()
    };
    let (endpoint, _) = policy_getter
        .policy()
        .lookup_all_by_epc(&mut lookup_key, local_epc_id as i32);
    let (src_info, dst_info) = (endpoint.src_info, endpoint.dst_info);
    let peer_src = &mut flow.flow_metrics_peers[0];
    peer_src.l3_epc_id = src_info.l3_epc_id;
    peer_src.nat_real_ip = flow.flow_key.ip_src;
    let peer_dst = &mut flow.flow_metrics_peers[1];
    peer_dst.l3_epc_id = dst_info.l3_epc_id;
    peer_dst.nat_real_ip = flow.flow_key.ip_dst;
    flow.flow_key.tap_type = TapType::Cloud;
    let flow_stat_time = flow.flow_stat_time;
    let flow_endpoint = flow.last_endpoint.clone();
    let mut tagged_flow = TaggedFlow::default();
    tagged_flow.flow = flow;
    let mut allocator = Allocator::new(1);
    L7Stats {
        stats,
        flow: Some(Arc::new(allocator.allocate_one_with(tagged_flow))),
        endpoint: flow_endpoint,
        flow_id,
        l7_protocol,
        signal_source: SignalSource::OTel,
        time_in_second: flow_stat_time.into(),
        biz_type: 0,
    }
}

fn get_ip(ip_addr: IpAddr) -> IpAddr {
    match ip_addr {
        IpAddr::V4(s) => IpAddr::V4(s),
        IpAddr::V6(s) => match s.to_ipv4() {
            // Some values are like: "::ffff:0.0.0.0"it is either an IPv4-compatible address
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(s),
        },
    }
}

fn http_code_to_response_status(status_code: i64) -> L7ResponseStatus {
    if status_code >= 400 && status_code <= 499 {
        L7ResponseStatus::ClientError
    } else if status_code >= 500 && status_code <= 600 {
        L7ResponseStatus::ServerError
    } else {
        L7ResponseStatus::Ok
    }
}

fn compress_data(input: Vec<u8>) -> std::io::Result<Vec<u8>> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(input.as_slice())?;
    e.finish()
}

/// 接收metric server发送的请求，根据路由处理分发
async fn handler(
    peer_addr: SocketAddr,
    req: Request<Body>,
    otel_sender: DebugSender<OpenTelemetry>,
    compressed_otel_sender: DebugSender<OpenTelemetryCompressed>,
    otel_l7_stats_sender: DebugSender<BatchedBox<L7Stats>>,
    prometheus_sender: DebugSender<BoxedPrometheusExtra>,
    telegraf_sender: DebugSender<TelegrafMetric>,
    profile_sender: DebugSender<Profile>,
    exception_handler: ExceptionHandler,
    compressed: bool,
    counter: Arc<CompressedMetric>,
    local_epc_id: u32,
    policy_getter: Arc<PolicyGetter>,
    time_diff: Arc<AtomicI64>,
    prometheus_extra_config: Arc<PrometheusExtraConfig>,
    log_parser_config: Arc<LogParserConfig>,
    flow_id: Arc<AtomicU64>,
    external_profile_integration_disabled: bool,
    external_trace_integration_disabled: bool,
    external_metric_integration_disabled: bool,
) -> Result<Response<Body>, GenericError> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            let doc_bytes = include_bytes!("../resources/doc/integration_collector.pdf");
            Ok(Response::builder()
                .header("Content-Type", "application/pdf")
                .body(doc_bytes.as_slice().into())
                .unwrap())
        }
        // OpenTelemetry trace integration
        (&Method::POST, "/api/v1/otel/trace") => {
            if external_trace_integration_disabled {
                return Ok(Response::builder().body(Body::empty()).unwrap());
            }
            let (part, body) = req.into_parts();
            let whole_body = match aggregate_with_catch_exception(body, &exception_handler).await {
                Ok(b) => b,
                Err(e) => {
                    return Ok(e);
                }
            };
            let tracing_data = decode_metric(whole_body, &part.headers)?;
            let time_diff = time_diff.load(Ordering::Relaxed);
            let mut decode_data = decode_otel_trace_data(
                peer_addr,
                tracing_data,
                local_epc_id,
                policy_getter,
                time_diff,
                flow_id.clone(),
                log_parser_config.clone(),
            )
            .map_err(|e| {
                debug!("decode otel trace data error: {}", e);
                e
            })?;
            if !decode_data.1.is_empty() {
                if let Err(e) = otel_l7_stats_sender.send_all(&mut decode_data.1) {
                    warn!("otel_l7_stats_sender failed to send data, because {:?}", e);
                }
            }
            if compressed {
                counter
                    .uncompressed
                    .fetch_add(decode_data.0.len() as u64, Ordering::Relaxed);
                let compressed_data = compress_data(decode_data.0)?;
                counter
                    .compressed
                    .fetch_add(compressed_data.len() as u64, Ordering::Relaxed);
                if let Err(e) =
                    compressed_otel_sender.send(OpenTelemetryCompressed(compressed_data))
                {
                    warn!(
                        "compressed_otel_sender failed to send data, because {:?}",
                        e
                    );
                }
            } else {
                if let Err(e) = otel_sender.send(OpenTelemetry(decode_data.0)) {
                    warn!("otel_sender failed to send data, because {:?}", e);
                }
            }

            Ok(Response::builder().body(Body::empty()).unwrap())
        }
        // Prometheus integration
        (&Method::POST, "/api/v1/prometheus") => {
            if external_metric_integration_disabled {
                return Ok(Response::builder().body(Body::empty()).unwrap());
            }
            let headers = req.headers();
            let labels = &prometheus_extra_config.labels;
            let labels_limit = prometheus_extra_config.labels_limit;
            let values_limit = prometheus_extra_config.values_limit;
            let mut labels_count = 0;
            let mut values_count = 0;
            let mut extra_label_names = vec![];
            let mut extra_label_values = vec![];

            if prometheus_extra_config.enabled {
                for label in labels {
                    if headers.contains_key(label) {
                        let value = headers
                            .get(label)
                            .unwrap()
                            .to_str()
                            .unwrap_or_default()
                            .to_string();
                        labels_count += label.len() as u32;
                        values_count += value.len() as u32;
                        if labels_count > labels_limit || values_count > values_limit {
                            debug!("labels_count exceeds the labels limit:{} or values_count exceeds the values limit:{} ", labels_limit, values_limit);
                            break;
                        }
                        extra_label_names.push(label.to_string());
                        extra_label_values.push(value);
                    }
                }
            }

            let mut whole_body =
                match aggregate_with_catch_exception(req.into_body(), &exception_handler).await {
                    Ok(b) => b,
                    Err(e) => {
                        return Ok(e);
                    }
                };
            let mut metric = vec![0u8; whole_body.remaining()];
            whole_body.copy_to_slice(metric.as_mut_slice());

            let prometheus_with_extra = PrometheusExtra {
                metrics: metric,
                extra_label_names,
                extra_label_values,
            };
            if let Err(e) =
                prometheus_sender.send(BoxedPrometheusExtra(Box::new(prometheus_with_extra)))
            {
                warn!("prometheus_sender failed to send data, because {:?}", e);
            }

            Ok(Response::builder().body(Body::empty()).unwrap())
        }
        // Telegraf integration
        (&Method::POST, "/api/v1/telegraf") => {
            if external_metric_integration_disabled {
                return Ok(Response::builder().body(Body::empty()).unwrap());
            }
            let (part, body) = req.into_parts();
            let whole_body = match aggregate_with_catch_exception(body, &exception_handler).await {
                Ok(b) => b,
                Err(e) => {
                    return Ok(e);
                }
            };
            let metric = decode_metric(whole_body, &part.headers)?;
            if log_enabled!(Level::Debug) {
                if let Ok(r) = String::from_utf8(metric.clone()) {
                    debug!("telegraf metric: {}", r)
                }
            }
            if let Err(e) = telegraf_sender.send(TelegrafMetric(metric)) {
                warn!("telegraf_sender failed to send data, because {:?}", e);
            }
            Ok(Response::builder().body(Body::empty()).unwrap())
        }
        // profile integration
        (&Method::POST, "/api/v1/profile/ingest") => {
            if external_profile_integration_disabled {
                return Ok(Response::builder().body(Body::empty()).unwrap());
            }
            let mut profile = metric::Profile::default();
            if let Some(query) = req.uri().query() {
                parse_profile_query(query, &mut profile);
            }
            let (part, body) = req.into_parts();
            let whole_body = match aggregate_with_catch_exception(body, &exception_handler).await {
                Ok(b) => b,
                Err(e) => {
                    return Ok(e);
                }
            };
            profile.data = decode_metric(whole_body, &part.headers)?;
            profile.ip = match peer_addr.ip() {
                IpAddr::V4(ip4) => ip4.octets().to_vec(),
                IpAddr::V6(ip6) => ip6.octets().to_vec(),
            };
            profile.event_type = metric::ProfileEventType::External.into();
            if let Some(content_type) = part.headers.get(CONTENT_TYPE) {
                profile.content_type = content_type.as_bytes().to_vec();
            }

            if let Err(e) = profile_sender.send(Profile(profile)) {
                warn!("profile_sender failed to send data, because {:?}", e);
            }

            Ok(Response::builder().body(Body::empty()).unwrap())
        }
        // Return the 404 Not Found for other routes.
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(NOT_FOUND.into())
            .unwrap()),
    }
}

fn parse_profile_query(query: &str, profile: &mut metric::Profile) {
    let query_hash: HashMap<String, String> = query
        .split('&')
        .filter_map(|s| {
            s.split_once('=')
                .and_then(|t| Some((t.0.to_owned(), t.1.to_owned())))
        })
        .collect();
    if let Some(name) = query_hash.get("name") {
        profile.name = name.to_string();
    }
    if let Some(units) = query_hash.get("units") {
        profile.units = units.to_string();
    };
    if let Some(aggregation_type) = query_hash.get("aggregrationType") {
        profile.aggregation_type = aggregation_type.to_string();
    };
    if let Some(sample_rate) = query_hash.get("sampleRate") {
        profile.sample_rate = sample_rate.parse::<u32>().unwrap_or_default();
    };
    if let Some(from) = query_hash.get("from") {
        profile.from = from.parse::<u32>().unwrap_or_default();
    };
    if let Some(until) = query_hash.get("until") {
        profile.until = until.parse::<u32>().unwrap_or_default();
    };
    if let Some(spy_name) = query_hash.get("spyName") {
        profile.spy_name = spy_name.to_string();
    }
    if let Some(format) = query_hash.get("format") {
        profile.format = format.to_string();
    };
}

#[derive(Default)]
struct CompressedMetric {
    compressed: AtomicU64,   // unit (bytes)
    uncompressed: AtomicU64, // unit (bytes)
}

#[derive(Default)]
pub struct IntegrationCounter {
    metrics: Arc<CompressedMetric>,
}

impl OwnedCountable for IntegrationCounter {
    fn get_counters(&self) -> Vec<Counter> {
        let (compressed, uncomressed) = (
            self.metrics.compressed.swap(0, Ordering::Relaxed),
            self.metrics.uncompressed.swap(0, Ordering::Relaxed),
        );
        vec![
            (
                "compressed",
                CounterType::Counted,
                CounterValue::Unsigned(compressed),
            ),
            (
                "uncompressed",
                CounterType::Counted,
                CounterValue::Unsigned(uncomressed),
            ),
            (
                "compressed_ratio",
                CounterType::Gauged,
                CounterValue::Float(if compressed == 0 {
                    // avoid divide by zero
                    0.0f64
                } else {
                    uncomressed as f64 / compressed as f64
                }),
            ),
        ]
    }

    fn closed(&self) -> bool {
        false
    }
}

/// 监听HTTP端口，接收OpenTelemetry的trace pb数据，然后发送到Sender
pub struct MetricServer {
    running: Arc<AtomicBool>,
    runtime: Arc<Runtime>,
    thread: Arc<Mutex<Option<JoinHandle<()>>>>,
    otel_sender: DebugSender<OpenTelemetry>,
    compressed_otel_sender: DebugSender<OpenTelemetryCompressed>,
    otel_l7_stats_sender: DebugSender<BatchedBox<L7Stats>>,
    prometheus_sender: DebugSender<BoxedPrometheusExtra>,
    telegraf_sender: DebugSender<TelegrafMetric>,
    profile_sender: DebugSender<Profile>,
    port: Arc<AtomicU16>,
    exception_handler: ExceptionHandler,
    server_shutdown_tx: Mutex<Option<mpsc::Sender<()>>>,
    counter: Arc<CompressedMetric>,
    compressed: Arc<AtomicBool>,
    local_epc_id: u32,
    policy_getter: Arc<PolicyGetter>,
    time_diff: Arc<AtomicI64>,
    prometheus_extra_config: Arc<PrometheusExtraConfig>,
    log_parser_config: Arc<LogParserConfig>,
    external_profile_integration_disabled: bool,
    external_trace_integration_disabled: bool,
    external_metric_integration_disabled: bool,
}

impl MetricServer {
    pub fn new(
        runtime: Arc<Runtime>,
        otel_sender: DebugSender<OpenTelemetry>,
        compressed_otel_sender: DebugSender<OpenTelemetryCompressed>,
        otel_l7_stats_sender: DebugSender<BatchedBox<L7Stats>>,
        prometheus_sender: DebugSender<BoxedPrometheusExtra>,
        telegraf_sender: DebugSender<TelegrafMetric>,
        profile_sender: DebugSender<Profile>,
        port: u16,
        exception_handler: ExceptionHandler,
        compressed: bool,
        local_epc_id: u32,
        policy_getter: PolicyGetter,
        time_diff: Arc<AtomicI64>,
        prometheus_extra_config: PrometheusExtraConfig,
        log_parser_config: LogParserConfig,
        external_profile_integration_disabled: bool,
        external_trace_integration_disabled: bool,
        external_metric_integration_disabled: bool,
    ) -> (Self, IntegrationCounter) {
        let counter = IntegrationCounter::default();
        (
            Self {
                running: Default::default(),
                runtime,
                thread: Arc::new(Mutex::new(None)),
                compressed: Arc::new(AtomicBool::new(compressed)),
                otel_sender,
                compressed_otel_sender,
                prometheus_sender,
                telegraf_sender,
                profile_sender,
                port: Arc::new(AtomicU16::new(port)),
                exception_handler,
                server_shutdown_tx: Default::default(),
                counter: counter.metrics.clone(),
                local_epc_id,
                policy_getter: Arc::new(policy_getter),
                time_diff,
                prometheus_extra_config: Arc::new(prometheus_extra_config),
                log_parser_config: Arc::new(log_parser_config),
                otel_l7_stats_sender,
                external_profile_integration_disabled,
                external_trace_integration_disabled,
                external_metric_integration_disabled,
            },
            counter,
        )
    }

    pub fn enable_compressed(&self, enable: bool) {
        self.compressed.store(enable, Ordering::Relaxed);
    }

    pub fn set_port(&self, port: u16) {
        if self.port.swap(port, Ordering::Release) != port {
            // port changes, resets server
            info!("port changes to {}", port);
            if let Some(tx) = self.server_shutdown_tx.lock().unwrap().as_ref() {
                let _ = self.runtime.block_on(tx.send(()));
            }
        }
    }

    pub fn start(&self) {
        if self.running.swap(true, Ordering::Relaxed) {
            return;
        }

        let otel_sender = self.otel_sender.clone();
        let compressed_otel_sender = self.compressed_otel_sender.clone();
        let otel_l7_stats_sender = self.otel_l7_stats_sender.clone();
        let prometheus_sender = self.prometheus_sender.clone();
        let telegraf_sender = self.telegraf_sender.clone();
        let profile_sender = self.profile_sender.clone();
        let port = self.port.clone();
        let monitor_port = Arc::new(AtomicU16::new(port.load(Ordering::Acquire)));
        let (mon_tx, mon_rx) = oneshot::channel();
        let exception_handler = self.exception_handler.clone();
        let running = self.running.clone();
        let counter = self.counter.clone();
        let compressed = self.compressed.clone();
        let local_epc_id = self.local_epc_id.clone();
        let policy_getter = self.policy_getter.clone();
        let time_diff = self.time_diff.clone();
        let prometheus_extra_config = self.prometheus_extra_config.clone();
        let log_parser_config = self.log_parser_config.clone();
        let external_profile_integration_disabled = self.external_profile_integration_disabled;
        let external_trace_integration_disabled = self.external_trace_integration_disabled;
        let external_metric_integration_disabled = self.external_metric_integration_disabled;
        let (tx, mut rx) = mpsc::channel(8);
        self.runtime
            .spawn(Self::alive_check(monitor_port.clone(), tx.clone(), mon_rx));
        self.server_shutdown_tx.lock().unwrap().replace(tx);

        self.thread
            .lock()
            .unwrap()
            .replace(self.runtime.spawn(async move {
                info!("integration collector starting");
                while running.load(Ordering::Relaxed) {
                    let mut max_tries = 0;
                    let (server_builder, addr) = loop {
                        if !running.load(Ordering::Relaxed) {
                            return;
                        }
                        while let Ok(_) = rx.try_recv() {} // drain useless messages
                        let port = port.load(Ordering::Acquire);
                        let addr = if ipv6_enabled() {
                            (Ipv6Addr::UNSPECIFIED, port).into()
                        } else {
                            (Ipv4Addr::UNSPECIFIED, port).into()
                        };
                        match Server::try_bind(&addr) {
                            Ok(s) => {
                                monitor_port.store(port, Ordering::Release);
                                break (s, addr);
                            }
                            Err(e) => {
                                // 因为有场景是停止server之后立刻开启server，Server::stop采用丢弃线程的方法会直接返回，而操作系统回收监听端口资源需要时间，
                                // 为了没有spurious error log，需要睡眠一会等待操作系统完成回收资源。
                                // =================================================================================================
                                // Because there is a scenario where the server is started immediately after the server is stopped, Server::stop will return directly
                                // by discarding the thread, and it takes time for the operating system to recycle the listening port resources.
                                // In order to have no spurious error log, you need to sleep for a while and wait for the operating system to finish recycling resources.
                                if max_tries < 2 {
                                    max_tries += 1;
                                    sleep(Duration::from_secs(1));
                                    continue;
                                }
                                error!("integration collector error: {} with addr={}", e, addr);
                                exception_handler.set(Exception::IntegrationSocketError);
                                sleep(Duration::from_secs(60));
                                continue;
                            }
                        }
                    };

                    let otel_sender = otel_sender.clone();
                    let compressed_otel_sender = compressed_otel_sender.clone();
                    let otel_l7_stats_sender = otel_l7_stats_sender.clone();
                    let prometheus_sender = prometheus_sender.clone();
                    let telegraf_sender = telegraf_sender.clone();
                    let profile_sender = profile_sender.clone();
                    let exception_handler_inner = exception_handler.clone();
                    let counter = counter.clone();
                    let compressed = compressed.clone();
                    let local_epc_id = local_epc_id.clone();
                    let policy_getter = policy_getter.clone();
                    let time_diff = time_diff.clone();
                    let prometheus_extra_config = prometheus_extra_config.clone();
                    let log_parser_config = log_parser_config.clone();
                    let service = make_service_fn(move |conn: &AddrStream| {
                        let otel_sender = otel_sender.clone();
                        let compressed_otel_sender = compressed_otel_sender.clone();
                        let otel_l7_stats_sender = otel_l7_stats_sender.clone();
                        let prometheus_sender = prometheus_sender.clone();
                        let telegraf_sender = telegraf_sender.clone();
                        let profile_sender = profile_sender.clone();
                        let exception_handler = exception_handler_inner.clone();
                        let peer_addr = conn.remote_addr();
                        let counter = counter.clone();
                        let compressed = compressed.clone();
                        let local_epc_id = local_epc_id.clone();
                        let policy_getter = policy_getter.clone();
                        let time_diff = time_diff.clone();
                        let prometheus_extra_config = prometheus_extra_config.clone();
                        let log_parser_config = log_parser_config.clone();
                        let flow_id = Arc::new(AtomicU64::new(0));
                        async move {
                            Ok::<_, GenericError>(service_fn(move |req| {
                                handler(
                                    peer_addr,
                                    req,
                                    otel_sender.clone(),
                                    compressed_otel_sender.clone(),
                                    otel_l7_stats_sender.clone(),
                                    prometheus_sender.clone(),
                                    telegraf_sender.clone(),
                                    profile_sender.clone(),
                                    exception_handler.clone(),
                                    compressed.load(Ordering::Relaxed),
                                    counter.clone(),
                                    local_epc_id,
                                    policy_getter.clone(),
                                    time_diff.clone(),
                                    prometheus_extra_config.clone(),
                                    log_parser_config.clone(),
                                    flow_id.clone(),
                                    external_profile_integration_disabled,
                                    external_trace_integration_disabled,
                                    external_metric_integration_disabled,
                                )
                            }))
                        }
                    });

                    let server = server_builder.serve(service).with_graceful_shutdown(async {
                        let _ = rx.recv().await;
                    });

                    info!("integration collector started");
                    info!("integration collector listening on http://{}", addr);
                    if let Err(e) = server.await {
                        error!("external metric collector error: {}", e);
                        exception_handler.set(Exception::IntegrationSocketError);
                    }
                }

                let _ = mon_tx.send(());
            }));
    }

    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            return;
        }

        if let Some(tx) = self.server_shutdown_tx.lock().unwrap().take() {
            let _ = self.runtime.block_on(tx.send(()));
        }

        if let Some(t) = self.thread.lock().unwrap().take() {
            t.abort();
        }

        info!("integration collector stopped");
    }

    //FIXME: 现在integration collector 在K8S环境下，会概率性出现监听端口一段时间后会失去监听。所以先探测下发的端口是否监听，
    // 没监听的话重启collector再监听。等找到根因后再去掉下面的代码
    // =============================================
    //FIXME: Now, in the K8S environment, the integration collector will probabilistically appear on the listening port and
    // lose monitoring after a period of time. So first detect whether the issued port is listening,
    // If not listening, restart the collector and listen again. After finding the root cause, remove the following code
    async fn alive_check(
        port: Arc<AtomicU16>,
        server_shutdown_tx: mpsc::Sender<()>,
        mut mon_rx: oneshot::Receiver<()>,
    ) {
        let mut ticker = time::interval(Duration::from_secs(60));
        loop {
            select! {
                _ = ticker.tick() => {
                    let p = port.load(Ordering::Relaxed);
                    if let Err(_) = TcpStream::connect(("localhost", p)) {
                        warn!(
                            "the port=({}) listen by the integration collector lost, restart the collector",
                            p
                        );
                        let _ = server_shutdown_tx.send(()).await;
                    }
                },
                _ = &mut mon_rx => return,
            }
        }
    }
}
