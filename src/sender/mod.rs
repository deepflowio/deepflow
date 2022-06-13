// NpbBandwidthWatcher NewFragmenterBuilder NewCompressorBuilder NewPCapBuilder NewUniformCollectSender
mod tcp_packet;
pub(crate) mod uniform_sender;

use num_enum::IntoPrimitive;

use std::fmt;
use std::time::Duration;

use crate::common::tagged_flow::TaggedFlow;
use crate::external_metrics::{OpenTelemetry, PrometheusMetric, TelegrafMetric};
use crate::flow_generator::AppProtoLogsData;
use crate::metric::document::Document;

const COMPRESSOR_PORT: u16 = 20033;
const SEQUENCE_OFFSET: usize = 8;
const RCV_TIMEOUT: Duration = Duration::from_secs(1);
const ERR_INTERVAL: Duration = Duration::from_secs(30);
const FLOW_LOG_VERSION: u32 = 20220128;
const METRICS_VERSION: u32 = 20220117;
const OPEN_TELEMETRY: u32 = 20220607;
const PROMETHEUS: u32 = 20220613;
const TELEGRAF: u32 = 20220613;

pub enum SendItem {
    L4FlowLog(TaggedFlow),
    L7FlowLog(AppProtoLogsData),
    Metrics(Document),
    ExternalOtel(OpenTelemetry),
    ExternalProm(PrometheusMetric),
    ExternalTelegraf(TelegrafMetric),
}

impl SendItem {
    pub fn encode(self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        match self {
            Self::L4FlowLog(l4) => l4.encode(buf),
            Self::L7FlowLog(l7) => l7.encode(buf),
            Self::Metrics(m) => m.encode(buf),
            Self::ExternalOtel(o) => o.encode(buf),
            Self::ExternalProm(p) => p.encode(buf),
            Self::ExternalTelegraf(p) => p.encode(buf),
        }
    }

    pub fn message_type(&self) -> SendMessageType {
        match self {
            Self::L4FlowLog(_) => SendMessageType::TaggedFlow,
            Self::L7FlowLog(_) => SendMessageType::ProtocolLog,
            Self::Metrics(_) => SendMessageType::Metrics,
            Self::ExternalOtel(_) => SendMessageType::OpenTelemetry,
            Self::ExternalProm(_) => SendMessageType::Prometheus,
            Self::ExternalTelegraf(_) => SendMessageType::Telegraf,
        }
    }

    pub fn version(&self) -> u32 {
        match self {
            Self::L4FlowLog(_) => FLOW_LOG_VERSION,
            Self::L7FlowLog(_) => FLOW_LOG_VERSION,
            Self::Metrics(_) => METRICS_VERSION,
            Self::ExternalOtel(_) => OPEN_TELEMETRY,
            Self::ExternalProm(_) => PROMETHEUS,
            Self::ExternalTelegraf(_) => TELEGRAF,
        }
    }
}

impl fmt::Display for SendItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::L4FlowLog(l) => write!(f, "l4: {}", l),
            Self::L7FlowLog(l) => write!(f, "l7: {}", l),
            Self::Metrics(l) => write!(f, "metric: {:?}", l),
            Self::ExternalOtel(o) => write!(f, "open_telemetry: {:?}", o),
            Self::ExternalProm(p) => write!(f, "prometheus: {:?}", p),
            Self::ExternalTelegraf(p) => write!(f, "telegraf: {:?}", p),
        }
    }
}

impl fmt::Debug for SendItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::L4FlowLog(l) => write!(f, "l4: {}", l),
            Self::L7FlowLog(l) => write!(f, "l7: {}", l),
            Self::Metrics(l) => write!(f, "metric: {:?}", l),
            Self::ExternalOtel(o) => write!(f, "open_telemetry: {:?}", o),
            Self::ExternalProm(p) => write!(f, "prometheus: {:?}", p),
            Self::ExternalTelegraf(p) => write!(f, "telegraf: {:?}", p),
        }
    }
}

#[derive(Debug, Clone, Copy, IntoPrimitive)]
#[repr(u8)]
pub enum SendMessageType {
    Compress = 0,
    Syslog = 1,
    Statsd = 2,
    Metrics = 3,
    TaggedFlow = 4,
    ProtocolLog = 5,
    OpenTelemetry = 6,
    Prometheus = 7,
    Telegraf = 8,
}

impl fmt::Display for SendMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compress => write!(f, "compress"),
            Self::Syslog => write!(f, "syslog"),
            Self::Statsd => write!(f, "statsd"),
            Self::Metrics => write!(f, "metrics"),
            Self::TaggedFlow => write!(f, "l4_log"),
            Self::ProtocolLog => write!(f, "l7_log"),
            Self::OpenTelemetry => write!(f, "open_telemetry"),
            Self::Prometheus => write!(f, "prometheus"),
            Self::Telegraf => write!(f, "telegraf"),
        }
    }
}
