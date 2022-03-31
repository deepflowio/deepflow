// NpbBandwidthWatcher NewFragmenterBuilder NewCompressorBuilder NewPCapBuilder NewUniformCollectSender
mod tcp_packet;
pub(crate) mod uniform_sender;

use num_enum::IntoPrimitive;

use std::fmt;
use std::time::Duration;

use crate::common::tagged_flow::TaggedFlow;
use crate::flow_generator::AppProtoLogsData;
use crate::metric::document::Document;

const COMPRESSOR_PORT: u16 = 20033;
const SEQUENCE_OFFSET: usize = 8;
const RCV_TIMEOUT: Duration = Duration::from_secs(1);
const ERR_INTERVAL: Duration = Duration::from_secs(30);
const FLOW_LOG_VERSION: u32 = 20220404;
const METRICS_VERSION: u32 = 20220117;

pub enum SendItem {
    L4FlowLog(TaggedFlow),
    L7FlowLog(AppProtoLogsData),
    Metrics(Document),
}

impl SendItem {
    pub fn encode(self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        match self {
            Self::L4FlowLog(l4) => l4.encode(buf),
            Self::L7FlowLog(l7) => l7.encode(buf),
            Self::Metrics(m) => m.encode(buf),
        }
    }

    pub fn message_type(&self) -> SendMessageType {
        match self {
            Self::L4FlowLog(_) => SendMessageType::TaggedFlow,
            Self::L7FlowLog(_) => SendMessageType::ProtocolLog,
            Self::Metrics(_) => SendMessageType::Metrics,
        }
    }

    pub fn version(&self) -> u32 {
        match self {
            Self::L4FlowLog(_) => FLOW_LOG_VERSION,
            Self::L7FlowLog(_) => FLOW_LOG_VERSION,
            Self::Metrics(_) => METRICS_VERSION,
        }
    }
}

impl fmt::Display for SendItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::L4FlowLog(l) => write!(f, "{}", l),
            Self::L7FlowLog(l) => write!(f, "{}", l),
            Self::Metrics(l) => write!(f, "{:?}", l),
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
}
