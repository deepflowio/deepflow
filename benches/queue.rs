use std::mem;
use std::time::Instant;

use criterion::*;

use trident::_queue_bounded;

fn bench(c: &mut Criterion) {
    c.bench_function("send", |b| {
        b.iter_custom(|iters| {
            let (s, _r, _) = _queue_bounded(iters as usize);
            let start = Instant::now();
            for i in 0..iters {
                s.send(i).unwrap();
            }
            start.elapsed()
        })
    });
    c.bench_function("receive", |b| {
        b.iter_custom(|iters| {
            let (s, r, _) = _queue_bounded(iters as usize);
            for i in 0..iters {
                s.send(i).unwrap();
            }
            mem::drop(s);
            let start = Instant::now();
            for _ in r {}
            start.elapsed()
        })
    });
    c.bench_function("receive_n", |b| {
        b.iter_custom(|iters| {
            let (s, r, _) = _queue_bounded(iters as usize);
            for i in 0..iters {
                s.send(i).unwrap();
            }
            mem::drop(s);
            let start = Instant::now();
            while r.recv_n(4, None).is_ok() {}
            start.elapsed()
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
