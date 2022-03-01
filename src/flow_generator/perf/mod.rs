pub mod tcp_perf_quantifier;

use std::sync::atomic::{AtomicBool, AtomicU64};

use super::error::Result;

use crate::common::{flow::FlowPerfStats, meta_packet::MetaPacket};

pub trait L4FlowPerf {
    fn update(&mut self, packet: &MetaPacket, direction: bool) -> Result<()>;
    fn data_updated(&self) -> bool;
    fn copy_and_reset_data(&mut self, stats: &mut FlowPerfStats, direction: bool);
    fn reset(&mut self);
}

#[derive(Default)]
pub struct Counter {
    closed: AtomicBool,

    // tcp stats
    pub ignored_packet_count: AtomicU64,
    pub invalid_packet_count: AtomicU64,

    // L7 stats
    pub mismatched_response: AtomicU64,
}
