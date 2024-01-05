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

use std::fmt;
use std::fmt::Debug;

use num_enum::IntoPrimitive;

/// A abstraction for sending data and serialize data
pub trait Sendable: Debug + Send + 'static {
    // Encode data to bytes stream and wait for sender to send
    fn encode(self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError>;
    // The message type identified by the sender
    fn message_type(&self) -> SendMessageType;
    // Serialization result file name
    fn file_name(&self) -> &str {
        ""
    }
    // Send data's version
    fn version(&self) -> u32 {
        0
    }
    // Serialize data to key-value and append to a string
    fn to_kv_string(&self, _: &mut String) {}
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
    Profile = 13,
    ProcEvents = 14,
    AlarmEvent = 15,
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
            Self::Profile => write!(f, "profile"),
            Self::ProcEvents => write!(f, "proc_events"),
            Self::AlarmEvent => write!(f, "alarm_event"),
        }
    }
}
