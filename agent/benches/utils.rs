use std::mem;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use criterion::*;

use metaflow_agent::{_LeakyBucket as LeakyBucket, _queue_bounded as queue_bounded};

fn queue(c: &mut Criterion) {
    c.bench_function("queue_send", |b| {
        b.iter_custom(|iters| {
            let (s, _r, _) = queue_bounded(iters as usize);
            let start = Instant::now();
            for i in 0..iters {
                s.send(i).unwrap();
            }
            start.elapsed()
        })
    });
    c.bench_function("queue_receive", |b| {
        b.iter_custom(|iters| {
            let (s, r, _) = queue_bounded(iters as usize);
            for i in 0..iters {
                s.send(i).unwrap();
            }
            mem::drop(s);
            let start = Instant::now();
            for _ in r {}
            start.elapsed()
        })
    });
    c.bench_function("queue_receive_n", |b| {
        b.iter_custom(|iters| {
            let (s, r, _) = queue_bounded(iters as usize);
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

fn leaky_bucket(c: &mut Criterion) {
    c.bench_function("leaky_bucket_single_thread", |b| {
        b.iter_custom(|iters| {
            let bucket = LeakyBucket::new(Some(iters));
            thread::sleep(Duration::from_millis(10));
            let start = Instant::now();
            for _ in 0..iters {
                bucket.acquire(1);
            }
            start.elapsed()
        })
    });
    c.bench_function("leaky_bucket_4_threads", |b| {
        b.iter_custom(|iters| {
            let bucket = Arc::new(LeakyBucket::new(Some(4 * iters)));
            thread::sleep(Duration::from_millis(10));
            let ts = (0..4)
                .map(|_| {
                    let bucket = bucket.clone();
                    thread::spawn(move || {
                        let start = Instant::now();
                        for _ in 0..(iters / 4) {
                            bucket.acquire(1);
                        }
                        start.elapsed()
                    })
                })
                .collect::<Vec<_>>();
            ts.into_iter().map(|t| t.join().unwrap()).max().unwrap()
        })
    });
}

criterion_group!(benches, queue, leaky_bucket);
criterion_main!(benches);
