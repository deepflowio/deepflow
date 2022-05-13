use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use crate::utils::stats::{Counter, CounterType, CounterValue, RefCountable};

// 每次获取统计数据后此结构体都会被清零，不能在其中保存Flow级别的信息避免被清空
#[derive(Debug, Default, PartialEq)]
pub struct PerfStats {
    pub req_count: u32,
    pub resp_count: u32,
    pub req_err_count: u32,
    pub resp_err_count: u32,
    pub rrt_count: u32,
    pub rrt_max: Duration,
    pub rrt_last: Duration,
    pub rrt_sum: Duration,
}

#[derive(Default)]
pub struct FlowPerfCounter {
    closed: AtomicBool,

    // tcp stats
    pub ignored_packet_count: AtomicU64,
    pub invalid_packet_count: AtomicU64,

    // L7 stats
    pub mismatched_response: AtomicU64,
}

impl RefCountable for FlowPerfCounter {
    fn get_counters(&self) -> Vec<Counter> {
        let ignored = self.ignored_packet_count.swap(0, Ordering::Relaxed);
        let invalid = self.invalid_packet_count.swap(0, Ordering::Relaxed);
        let mismatched = self.mismatched_response.swap(0, Ordering::Relaxed);

        vec![
            (
                "ignore_packet_count",
                CounterType::Counted,
                CounterValue::Unsigned(ignored),
            ),
            (
                "invalid_packet_count",
                CounterType::Counted,
                CounterValue::Unsigned(invalid),
            ),
            (
                "l7_mismatch_response",
                CounterType::Counted,
                CounterValue::Unsigned(mismatched),
            ),
        ]
    }
}
