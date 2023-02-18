use std::time::Instant;

use criterion::*;

use deepflow_agent::common::TapTyper;

fn bench_tap_typer(c: &mut Criterion) {
    c.bench_function("get_tap_type_by_vlan", |b| {
        let tap_typer = TapTyper::new();

        b.iter_custom(|iters| {
            let start = Instant::now();
            for i in 0..iters {
                let _ = tap_typer.get_tap_type_by_vlan((i & 4095) as u16);
            }
            start.elapsed()
        })
    });
}

criterion_group!(benches, bench_tap_typer);
criterion_main!(benches);
