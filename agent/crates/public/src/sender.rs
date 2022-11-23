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
use std::fmt;

use super::common::tagged_flow::TaggedFlow;
use super::protocol_logs::AppProtoLogsData;
use crate::proto::{metric::Document, stats::Stats, trident::PcapBatch};

pub enum SendItem {
    L4FlowLog(Box<TaggedFlow>),
    L7FlowLog(Box<AppProtoLogsData>),
    Metrics(Box<Document>),
    ExternalOtel(Vec<u8>),
    ExternalProm(Vec<u8>),
    ExternalTelegraf(Vec<u8>),
    PacketSequenceBlock(Vec<u8>), // Enterprise Edition Feature: packet-sequence
    DeepflowStats(Box<Stats>),
    ExternalOtelCompressed(Vec<u8>),
    RawPcap(Box<PcapBatch>),
}

impl fmt::Display for SendItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RawPcap(p) => write!(f, "raw_pcap: {:?}", p), // Enterprise Edition Feature: pcap
            Self::L4FlowLog(l) => write!(f, "l4: {:?}", l),
            Self::L7FlowLog(l) => write!(f, "l7: {:?}", l),
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
            Self::RawPcap(p) => write!(f, "raw_pcap: {:?}", p), // Enterprise Edition Feature: pcap
            Self::L4FlowLog(l) => write!(f, "l4: {:?}", l),
            Self::L7FlowLog(l) => write!(f, "l7: {:?}", l),
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
