use std::convert::Infallible;
use std::io::Read;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

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

/// 接收metric server发送的请求，根据路由处理分发
async fn handler(
    req: Request<Body>,
    otel_sender: DebugSender<SendItem>,
    prometheus_sender: DebugSender<SendItem>,
    telegraf_sender: DebugSender<SendItem>,
) -> Result<Response<Body>, GenericError> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            let doc_bytes = include_bytes!("../resources/doc/external_metrics.pdf");
            Ok(Response::builder()
                .header("Content-Type", "application/pdf")
                .body(doc_bytes.as_slice().into())
                .unwrap())
        }
        // OpenTelemetry trace数据接口
        (&Method::POST, "/api/v1/otel/trace") => {
            let (part, body) = req.into_parts();
            let whole_body = aggregate(body).await?;

            let tracing_data = decode_metric(whole_body, &part.headers)?;
            if let Err(Error::Terminated(..)) =
                otel_sender.send(SendItem::ExternalOtel(OpenTelemetry(tracing_data)))
            {
                warn!("sender queue has terminated");
            }
            Ok(Response::builder().body(Body::empty()).unwrap())
        }
        // Prometheus数据接口
        (&Method::POST, "/api/v1/prometheus") => {
            let mut whole_body = aggregate(req.into_body()).await?;
            let mut metric = vec![0u8; whole_body.remaining()];
            whole_body.copy_to_slice(metric.as_mut_slice());
            if let Err(Error::Terminated(..)) =
                prometheus_sender.send(SendItem::ExternalProm(PrometheusMetric(metric)))
            {
                warn!("sender queue has terminated");
            }

            Ok(Response::builder().body(Body::empty()).unwrap())
        }
        // Telegraf数据接口
        (&Method::POST, "/api/v1/telegraf") => {
            let (part, body) = req.into_parts();
            let whole_body = aggregate(body).await?;
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
}

impl MetricServer {
    pub fn new(
        otel_sender: DebugSender<SendItem>,
        prometheus_sender: DebugSender<SendItem>,
        telegraf_sender: DebugSender<SendItem>,
        conf: MetricServerAccess,
    ) -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            rt: Runtime::new().unwrap(),
            thread: Arc::new(Mutex::new(None)),
            otel_sender,
            prometheus_sender,
            telegraf_sender,
            conf,
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

        self.thread
            .lock()
            .unwrap()
            .replace(self.rt.spawn(async move {
                let service = make_service_fn(move |_| {
                    let otel_sender = otel_sender.clone();
                    let prometheus_sender = prometheus_sender.clone();
                    let telegraf_sender = telegraf_sender.clone();
                    async {
                        Ok::<_, Infallible>(service_fn(move |req| {
                            handler(
                                req,
                                otel_sender.clone(),
                                prometheus_sender.clone(),
                                telegraf_sender.clone(),
                            )
                        }))
                    }
                });
                let server = Server::bind(&addr).serve(service);

                info!("external metrics server listening on http://{}", addr);
                if let Err(e) = server.await {
                    error!("external metric server error: {}", e);
                }
            }));

        info!("external metrics server started");
    }

    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            return;
        }

        if let Some(t) = self.thread.lock().unwrap().take() {
            t.abort();
        }

        info!("external metrics server stopped");
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

        let port = 44444 + random::<u16>() % 1000;
        let mut rt_conf = ModuleConfig::default();
        rt_conf.metric_server.enabled = true;
        rt_conf.metric_server.port = port;
        let current_config = Arc::new(ArcSwap::from_pointee(rt_conf));

        let conf: MetricServerAccess =
            Map::new(current_config.clone(), |config| -> &MetricServerConfig {
                &config.metric_server
            });
        let server = MetricServer::new(sender.clone(), sender.clone(), sender, conf);
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
