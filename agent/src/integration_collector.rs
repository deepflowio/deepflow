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

use std::io::Read;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

use arc_swap::access::Access;
use flate2::read::GzDecoder;
use http::header::CONTENT_ENCODING;
use http::HeaderMap;
use hyper::service::{make_service_fn, service_fn};
use hyper::{
    body::{aggregate, Buf},
    Body, Method, Request, Response, Server, StatusCode,
};
use log::{error, info, warn};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

use crate::config::handler::MetricServerAccess;
use crate::exception::ExceptionHandler;
use crate::proto::trident::Exception;
use crate::sender::SendItem;
use crate::utils::queue::{DebugSender, Error};

type GenericError = Box<dyn std::error::Error + Send + Sync>;

const NOT_FOUND: &[u8] = b"Not Found";
const GZIP: &str = "gzip";

// Otel的protobuf数据
// ingester使用该proto https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/trace/v1/trace.proto进行解析
#[derive(Debug, PartialEq)]
pub struct OpenTelemetry(Vec<u8>);

impl OpenTelemetry {
    pub fn encode(mut self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        let length = self.0.len();
        buf.append(&mut self.0);
        Ok(length)
    }
}

/// Prometheus metrics, 格式是snappy压缩的pb数据
/// 可以参考https://github.com/prometheus/prometheus/tree/main/documentation/examples/remote_storage/example_write_adapter来解析
#[derive(Debug, PartialEq)]
pub struct PrometheusMetric(Vec<u8>);

impl PrometheusMetric {
    pub fn encode(mut self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        let length = self.0.len();
        buf.append(&mut self.0);
        Ok(length)
    }
}

/// Telegraf metric， 是influxDB标准行协议的UTF8编码的文本数据
#[derive(Debug, PartialEq)]
pub struct TelegrafMetric(Vec<u8>);

impl TelegrafMetric {
    pub fn encode(mut self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        let length = self.0.len();
        buf.append(&mut self.0);
        Ok(length)
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

/// 接收metric server发送的请求，根据路由处理分发
async fn handler(
    req: Request<Body>,
    otel_sender: DebugSender<SendItem>,
    prometheus_sender: DebugSender<SendItem>,
    telegraf_sender: DebugSender<SendItem>,
    exception_handler: ExceptionHandler,
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
            if let Err(Error::Terminated(..)) =
                otel_sender.send(SendItem::ExternalOtel(OpenTelemetry(tracing_data)))
            {
                warn!("sender queue has terminated");
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
            if let Err(Error::Terminated(..)) =
                prometheus_sender.send(SendItem::ExternalProm(PrometheusMetric(metric)))
            {
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
            if let Err(Error::Terminated(..)) =
                telegraf_sender.send(SendItem::ExternalTelegraf(TelegrafMetric(metric)))
            {
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

/// 监听HTTP端口，接收OpenTelemetry的trace pb数据，然后发送到Sender
pub struct MetricServer {
    running: Arc<AtomicBool>,
    rt: Runtime,
    thread: Arc<Mutex<Option<JoinHandle<()>>>>,
    otel_sender: DebugSender<SendItem>,
    prometheus_sender: DebugSender<SendItem>,
    telegraf_sender: DebugSender<SendItem>,
    conf: MetricServerAccess,
    exception_handler: ExceptionHandler,
}

impl MetricServer {
    pub fn new(
        otel_sender: DebugSender<SendItem>,
        prometheus_sender: DebugSender<SendItem>,
        telegraf_sender: DebugSender<SendItem>,
        conf: MetricServerAccess,
        exception_handler: ExceptionHandler,
    ) -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            rt: Runtime::new().unwrap(),
            thread: Arc::new(Mutex::new(None)),
            otel_sender,
            prometheus_sender,
            telegraf_sender,
            conf,
            exception_handler,
        }
    }

    pub fn start(&self) {
        if !self.conf.load().enabled {
            return;
        }

        if self.running.swap(true, Ordering::Relaxed) {
            return;
        }

        let addr = (IpAddr::from(Ipv6Addr::UNSPECIFIED), self.conf.load().port).into();
        let otel_sender = self.otel_sender.clone();
        let prometheus_sender = self.prometheus_sender.clone();
        let telegraf_sender = self.telegraf_sender.clone();
        let exception_handler = self.exception_handler.clone();

        self.thread
            .lock()
            .unwrap()
            .replace(self.rt.spawn(async move {
                info!("integration collector starting");
                let mut max_tries = 0;
                let server_builder = loop {
                    match Server::try_bind(&addr) {
                        Ok(s) => break s,
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
                            sleep(Duration::from_secs(1));
                            continue;
                        }
                    }
                };

                let exception_handler_clone = exception_handler.clone();
                let service = make_service_fn(move |_| {
                    let otel_sender = otel_sender.clone();
                    let prometheus_sender = prometheus_sender.clone();
                    let telegraf_sender = telegraf_sender.clone();
                    let exception_handler = exception_handler_clone.clone();
                    async {
                        Ok::<_, GenericError>(service_fn(move |req| {
                            handler(
                                req,
                                otel_sender.clone(),
                                prometheus_sender.clone(),
                                telegraf_sender.clone(),
                                exception_handler.clone(),
                            )
                        }))
                    }
                });

                let server = server_builder.serve(service);
                info!("integration collector started");
                info!("integration collector listening on http://{}", addr);
                if let Err(e) = server.await {
                    error!("external metric collector error: {}", e);
                    exception_handler.set(Exception::IntegrationSocketError);
                }
            }));
    }

    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            return;
        }

        if let Some(t) = self.thread.lock().unwrap().take() {
            t.abort();
        }

        info!("integration collector stopped");
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::Duration;

    use arc_swap::{access::Map, ArcSwap};
    use hyper::{Client, Request};
    use rand::random;

    use super::*;
    use crate::config::{handler::MetricServerConfig, ModuleConfig};
    use crate::debug::QueueDebugger;
    use crate::utils::queue;

    #[test]
    fn otel_api() {
        let queue_debugger = QueueDebugger::new();
        let (sender, receiver, _) =
            queue::bounded_with_debug(1000, "test_external_metrics", &queue_debugger);

        let port = 20000 + random::<u16>() % 10000;
        let mut rt_conf = ModuleConfig::default();
        rt_conf.metric_server.enabled = true;
        rt_conf.metric_server.port = port;
        let current_config = Arc::new(ArcSwap::from_pointee(rt_conf));

        let conf: MetricServerAccess =
            Map::new(current_config.clone(), |config| -> &MetricServerConfig {
                &config.metric_server
            });

        let server = MetricServer::new(
            sender.clone(),
            sender.clone(),
            sender,
            conf,
            ExceptionHandler::default(),
        );
        server.start();
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let uri = format!("http://127.0.0.1:{}/api/v1/otel/trace", port);
            let client = Client::new();

            let expected_data = fs::read("resources/test/external_metrics/otel_trace").unwrap();
            let body = Body::from(expected_data.clone());
            let req = Request::post(uri.as_str()).body(body).unwrap();
            let _ = client.request(req).await.unwrap();
            if let SendItem::ExternalOtel(t) = receiver.recv(Some(Duration::from_secs(1))).unwrap()
            {
                assert_eq!(OpenTelemetry(expected_data.clone()), t);
            } else {
                assert_eq!(1, 2);
            }

            let gzip_data = fs::read("resources/test/external_metrics/otel_trace.gzip").unwrap();
            let body = Body::from(gzip_data);
            let req = Request::post(uri.as_str())
                .header("Content-Encoding", "gzip")
                .body(body)
                .unwrap();
            let _ = client.request(req).await.unwrap();
            if let SendItem::ExternalOtel(t) = receiver.recv(Some(Duration::from_secs(1))).unwrap()
            {
                assert_eq!(OpenTelemetry(expected_data), t);
            } else {
                assert_eq!(1, 2);
            }
        });
        server.stop();
    }
}
