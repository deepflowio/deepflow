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

// NpbBandwidthWatcher NewFragmenterBuilder NewCompressorBuilder NewPCapBuilder NewUniformCollectSender
pub mod npb_sender;
mod tcp_packet;
pub(crate) mod uniform_sender;

use num_enum::IntoPrimitive;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::common::tagged_flow::TaggedFlow;
use crate::flow_generator::AppProtoLogsData;
use crate::integration_collector::{
    OpenTelemetry, OpenTelemetryCompressed, PrometheusMetric, TelegrafMetric,
};
use crate::metric::document::Document;
use crate::utils::stats::Batch;

const SEQUENCE_OFFSET: usize = 8;
const RCV_TIMEOUT: Duration = Duration::from_secs(1);
const ERR_INTERVAL: Duration = Duration::from_secs(30);
const FLOW_LOG_VERSION: u32 = 20220128;
const METRICS_VERSION: u32 = 20220117;
const OPEN_TELEMETRY: u32 = 20220607;
const OPEN_TELEMETRY_COMPRESSED: u32 = 20221024;
const PROMETHEUS: u32 = 20220613;
const TELEGRAF: u32 = 20220613;
const PACKET_SEQUENCE_BLOCK: u32 = 20220712; // Enterprise Edition Feature: packet-sequence

const PRE_FILE_SUFFIX: &str = ".pre";

pub enum SendItem {
    L4FlowLog(Box<TaggedFlow>),
    L7FlowLog(Box<AppProtoLogsData>),
    Metrics(Box<Document>),
    ExternalOtel(OpenTelemetry),
    ExternalProm(PrometheusMetric),
    ExternalTelegraf(TelegrafMetric),
    PacketSequenceBlock(Box<packet_sequence_block::PacketSequenceBlock>), // Enterprise Edition Feature: packet-sequence
    DeepflowStats(Arc<Batch>),
    ExternalOtelCompressed(OpenTelemetryCompressed),
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
            Self::PacketSequenceBlock(p) => p.encode(buf), // Enterprise Edition Feature: packet-sequence
            Self::DeepflowStats(b) => b.encode(buf),
            Self::ExternalOtelCompressed(o) => o.encode(buf),
        }
    }

    pub fn to_kv_string(&self, kv_string: &mut String) {
        match self {
            Self::L4FlowLog(l4) => l4.to_kv_string(kv_string),
            Self::L7FlowLog(l7) => l7.to_kv_string(kv_string),
            _ => return,
        }
    }

    pub fn file_name(&self) -> &str {
        match self {
            Self::L4FlowLog(_) => "l4_flow_log",
            Self::L7FlowLog(_) => "l7_flow_log",
            _ => "other",
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
            Self::PacketSequenceBlock(_) => SendMessageType::PacketSequenceBlock, // Enterprise Edition Feature: packet-sequence
            Self::DeepflowStats(_) => SendMessageType::DeepflowStats,
            Self::ExternalOtelCompressed(_) => SendMessageType::OpenTelemetryCompressed,
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
            Self::PacketSequenceBlock(_) => PACKET_SEQUENCE_BLOCK, // Enterprise Edition Feature: packet-sequence
            Self::ExternalOtelCompressed(_) => OPEN_TELEMETRY_COMPRESSED,
            _ => 0,
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
            Self::PacketSequenceBlock(p) => write!(f, "packet_sequence_block: {:?}", p), // Enterprise Edition Feature: packet-sequence
            Self::DeepflowStats(s) => write!(f, "deepflow_stats: {:?}", s),
            Self::ExternalOtelCompressed(o) => write!(f, "open_telemetry compressed: {:?}", o),
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
            Self::PacketSequenceBlock(p) => write!(f, "packet_sequence_block: {:?}", p), // Enterprise Edition Feature: packet-sequence
            Self::DeepflowStats(s) => write!(f, "deepflow_stats: {:?}", s),
            Self::ExternalOtelCompressed(o) => write!(f, "open_telemetry compressed: {:?}", o),
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
    PacketSequenceBlock = 9, // Enterprise Edition Feature: packet-sequence
    DeepflowStats = 10,
    OpenTelemetryCompressed = 11,
    RawPcap = 12, // Enterprise Edition Feature: pcap
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
            Self::PacketSequenceBlock => write!(f, "packet_sequence_block"), // Enterprise Edition Feature: packet-sequence
            Self::DeepflowStats => write!(f, "deepflow_stats"),
            Self::OpenTelemetryCompressed => write!(f, "open_telemetry compressed"),
            Self::RawPcap => write!(f, "raw_pcap"), // Enterprise Edition Feature: pcap
        }
    }
}
