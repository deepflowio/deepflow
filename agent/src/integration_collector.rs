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

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

use flate2::{read::GzDecoder, write::ZlibEncoder, Compression};
use http::header::CONTENT_ENCODING;
use http::HeaderMap;
use hyper::{
    body::{aggregate, Buf},
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server, StatusCode,
};
use log::{debug, error, info, log_enabled, warn, Level};
use prost::Message;
use public::sender::{SendMessageType, Sendable};
use tokio::{
    runtime::Runtime,
    select,
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time,
};

use crate::exception::ExceptionHandler;
use public::counter::{Counter, CounterType, CounterValue, OwnedCountable};
use public::proto::integration::opentelemetry::proto::{
    common::v1::any_value::Value,
    common::v1::{AnyValue, KeyValue},
    trace::v1::TracesData,
};
use public::proto::trident::Exception;
use public::queue::{DebugSender, Error};

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

/// Prometheus metrics, 格式是snappy压缩的pb数据
/// 可以参考https://github.com/prometheus/prometheus/tree/main/documentation/examples/remote_storage/example_write_adapter来解析
#[derive(Debug, PartialEq)]
pub struct PrometheusMetric(Vec<u8>);

impl Sendable for PrometheusMetric {
    fn encode(mut self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        let length = self.0.len();
        buf.append(&mut self.0);
        Ok(length)
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

fn decode_otel_trace_data(peer_addr: SocketAddr, data: Vec<u8>) -> Result<Vec<u8>, GenericError> {
    let mut d = TracesData::decode(data.as_slice())?;
    // 因为collector传过来traceData的全部resource都有"app.host.ip"的属性，所以只检查第一个resource有没有“app.host.ip”即可，
    // sdk传过来的traceData因没有该属性则要补上(key: “app.host.ip”, value: 对端IP)属性值
    // =======================================================================
    // Because all the resources of the traceData passed by the collector have the attribute "app.host.ip",
    // only check whether the first resource has "app.host.ip". The traceData passed by the sdk does not have this attribute.
    //  Fill in the (key: "app.host.ip", value: peer IP) attribute value
    let mut skip_verify_ip = false;
    let host_ip = KeyValue {
        key: "app.host.ip".into(),
        value: Some(AnyValue {
            value: {
                let ip_str = match peer_addr.ip() {
                    IpAddr::V4(s) => s.to_string(),
                    IpAddr::V6(s) => match s.to_ipv4() {
                        Some(v4) => v4.to_string(),
                        None => s.to_string(),
                    },
                };
                Some(Value::StringValue(ip_str))
            },
        }),
    };
    for resource_span in d.resource_spans.iter_mut() {
        if let Some(resource) = resource_span.resource.as_mut() {
            if skip_verify_ip {
                resource.attributes.push(host_ip.clone());
            } else if resource
                .attributes
                .iter()
                .find(|attr| attr.key.as_str() == "app.host.ip")
                .is_some()
            {
                debug!("send otel collector traces_data to sender: {:?}", d);
                return Ok(data);
            } else {
                skip_verify_ip = true;
                resource.attributes.push(host_ip.clone());
            }
        }
    }
    let sdk_data = d.encode_to_vec();
    debug!("send otel sdk traces_data to sender: {:?}", d);
    return Ok(sdk_data);
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
    prometheus_sender: DebugSender<PrometheusMetric>,
    telegraf_sender: DebugSender<TelegrafMetric>,
    exception_handler: ExceptionHandler,
    compressed: bool,
    counter: Arc<CompressedMetric>,
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
            let (part, body) = req.into_parts();
            let whole_body = match aggregate_with_catch_exception(body, &exception_handler).await {
                Ok(b) => b,
                Err(e) => {
                    return Ok(e);
                }
            };
            let tracing_data = decode_metric(whole_body, &part.headers)?;
            let decode_data = decode_otel_trace_data(peer_addr, tracing_data).map_err(|e| {
                debug!("decode otel trace data error: {}", e);
                e
            })?;
            if compressed {
                counter
                    .uncompressed
                    .fetch_add(decode_data.len() as u64, Ordering::Relaxed);
                let compressed_data = compress_data(decode_data)?;
                counter
                    .compressed
                    .fetch_add(compressed_data.len() as u64, Ordering::Relaxed);
                if let Err(Error::Terminated(..)) =
                    compressed_otel_sender.send(OpenTelemetryCompressed(compressed_data))
                {
                    warn!("sender queue has terminated");
                }
            } else {
                if let Err(Error::Terminated(..)) = otel_sender.send(OpenTelemetry(decode_data)) {
                    warn!("sender queue has terminated");
                }
            }

            Ok(Response::builder().body(Body::empty()).unwrap())
        }
        // Prometheus integration
        (&Method::POST, "/api/v1/prometheus") => {
            let mut whole_body =
                match aggregate_with_catch_exception(req.into_body(), &exception_handler).await {
                    Ok(b) => b,
                    Err(e) => {
                        return Ok(e);
                    }
                };
            let mut metric = vec![0u8; whole_body.remaining()];
            whole_body.copy_to_slice(metric.as_mut_slice());
            if let Err(Error::Terminated(..)) = prometheus_sender.send(PrometheusMetric(metric)) {
                warn!("sender queue has terminated");
            }

            Ok(Response::builder().body(Body::empty()).unwrap())
        }
        // Telegraf integration
        (&Method::POST, "/api/v1/telegraf") => {
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
            if let Err(Error::Terminated(..)) = telegraf_sender.send(TelegrafMetric(metric)) {
                warn!("sender queue has terminated");
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
    prometheus_sender: DebugSender<PrometheusMetric>,
    telegraf_sender: DebugSender<TelegrafMetric>,
    port: Arc<AtomicU16>,
    exception_handler: ExceptionHandler,
    server_shutdown_tx: Mutex<Option<mpsc::Sender<()>>>,
    counter: Arc<CompressedMetric>,
    compressed: Arc<AtomicBool>,
}

impl MetricServer {
    pub fn new(
        runtime: Arc<Runtime>,
        otel_sender: DebugSender<OpenTelemetry>,
        compressed_otel_sender: DebugSender<OpenTelemetryCompressed>,
        prometheus_sender: DebugSender<PrometheusMetric>,
        telegraf_sender: DebugSender<TelegrafMetric>,
        port: u16,
        exception_handler: ExceptionHandler,
        compressed: bool,
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
                port: Arc::new(AtomicU16::new(port)),
                exception_handler,
                server_shutdown_tx: Default::default(),
                counter: counter.metrics.clone(),
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
        let prometheus_sender = self.prometheus_sender.clone();
        let telegraf_sender = self.telegraf_sender.clone();
        let port = self.port.clone();
        let monitor_port = Arc::new(AtomicU16::new(port.load(Ordering::Acquire)));
        let (mon_tx, mon_rx) = oneshot::channel();
        let exception_handler = self.exception_handler.clone();
        let running = self.running.clone();
        let counter = self.counter.clone();
        let compressed = self.compressed.clone();
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
                        let addr = (IpAddr::from(Ipv6Addr::UNSPECIFIED), port).into();
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
                    let prometheus_sender = prometheus_sender.clone();
                    let telegraf_sender = telegraf_sender.clone();
                    let exception_handler_inner = exception_handler.clone();
                    let counter = counter.clone();
                    let compressed = compressed.clone();
                    let service = make_service_fn(move |conn: &AddrStream| {
                        let otel_sender = otel_sender.clone();
                        let compressed_otel_sender = compressed_otel_sender.clone();
                        let prometheus_sender = prometheus_sender.clone();
                        let telegraf_sender = telegraf_sender.clone();
                        let exception_handler = exception_handler_inner.clone();
                        let peer_addr = conn.remote_addr();
                        let counter = counter.clone();
                        let compressed = compressed.clone();
                        async move {
                            Ok::<_, GenericError>(service_fn(move |req| {
                                handler(
                                    peer_addr,
                                    req,
                                    otel_sender.clone(),
                                    compressed_otel_sender.clone(),
                                    prometheus_sender.clone(),
                                    telegraf_sender.clone(),
                                    exception_handler.clone(),
                                    compressed.load(Ordering::Relaxed),
                                    counter.clone(),
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
                    if let Err(_) = TcpStream::connect(format!("127.0.0.1:{}", p)) {
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
