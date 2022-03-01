use std::time::Instant;

use criterion::*;

use trident::{
    _FlowPerfStats as FlowPerfStats, _MetaFlowPerf as MetaFlowPerf,
    _benchmark_report as benchmark_report,
    _benchmark_session_peer_seq_no_assert as benchmark_session_peer_seq_no_assert,
    _meta_flow_perf_update as meta_flow_perf_update,
};

fn bench_perf(c: &mut Criterion) {
    c.bench_function("perf_stats_report", |b| {
        b.iter_custom(|iters| {
            let (mut perf, _) = MetaFlowPerf::new();
            let mut report = FlowPerfStats::default();
            let start = Instant::now();
            for _ in 0..iters {
                benchmark_report(&mut perf, &mut report);
            }
            start.elapsed()
        })
    });
    c.bench_function("perf_update", |b| {
        b.iter_custom(|iters| {
            let (mut perf, _) = MetaFlowPerf::new();
            let start = Instant::now();
            for _ in 0..iters {
                meta_flow_perf_update(&mut perf);
            }
            start.elapsed()
        })
    });
    c.bench_function("perf_session_peer_seq_no_assert_desc", |b| {
        b.iter(|| {
            benchmark_session_peer_seq_no_assert(true);
        })
    });
    c.bench_function("perf_session_peer_seq_no_assert", |b| {
        b.iter(|| {
            benchmark_session_peer_seq_no_assert(false);
        })
    });
}

criterion_group!(benches, bench_perf);
criterion_main!(benches);
