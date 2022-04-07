pub(crate) mod acc_flow;
mod collector;
mod consts;
pub(crate) mod flow_aggr;
pub(crate) mod quadruple_generator;

pub use collector::Collector;

use bitflags::bitflags;
use std::time::Duration;

use self::{flow_aggr::FlowAggrThread, quadruple_generator::QuadrupleGeneratorThread};

const SECONDS_IN_MINUTE: u64 = 60;

bitflags! {
    pub struct MetricsType: u32 {
        const SECOND = 1;
        const MINUTE = 1<<1;
   }
}

pub fn round_to_minute(t: Duration) -> Duration {
    Duration::from_secs(t.as_secs() / SECONDS_IN_MINUTE * SECONDS_IN_MINUTE)
}

pub struct CollectorThread {
    quadruple_generator: QuadrupleGeneratorThread,
    l4_flow_aggr: Option<FlowAggrThread>,
}

impl CollectorThread {
    pub fn new(
        quadruple_generator: QuadrupleGeneratorThread,
        l4_flow_aggr: Option<FlowAggrThread>,
    ) -> Self {
        Self {
            quadruple_generator,
            l4_flow_aggr,
        }
    }

    pub fn start(&mut self) {
        self.quadruple_generator.start();
        if let Some(l4_flow_aggr) = self.l4_flow_aggr.as_mut() {
            l4_flow_aggr.start();
        }
    }

    pub fn stop(&mut self) {
        self.quadruple_generator.start();
        if let Some(l4_flow_aggr) = self.l4_flow_aggr.as_mut() {
            l4_flow_aggr.stop();
        }
    }
}

const RCV_TIMEOUT: Duration = Duration::from_secs(1);
const QUEUE_BATCH_SIZE: usize = 1024;
const FLOW_METRICS_PEER_SRC: usize = 0;
const FLOW_METRICS_PEER_DST: usize = 1;
