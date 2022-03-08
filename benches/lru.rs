use std::hash::Hash;
use std::net::Ipv6Addr;
use std::{net::Ipv4Addr, time::Instant};

use criterion::*;
use lru::LruCache;
use rand::prelude::*;
use uluru::LRUCache;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct SmallStruct {
    pub id: u64,
    pub ip: Ipv4Addr,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct BigStruct {
    pub id: u64,
    pub ip: Ipv6Addr,
}

fn lru_64b(c: &mut Criterion) {
    c.bench_function("uluru-insert", |b| {
        b.iter_custom(|iters| {
            let mut seeds = vec![];
            for i in 0..iters {
                seeds.push(SmallStruct {
                    id: i,
                    ip: Ipv4Addr::new(i as u8, (i >> 8) as u8, (i >> 16) as u8, (i >> 24) as u8),
                });
            }
            let mut cache = LRUCache::<SmallStruct, 1000>::default();
            let start = Instant::now();
            for item in seeds {
                cache.insert(item);
            }
            start.elapsed()
        })
    });

    c.bench_function("uluru-get-randomly", |b| {
        b.iter_custom(|iters| {
            let mut seeds = vec![];
            let mut indexes = vec![];
            let mut rng = thread_rng();
            for i in 0..iters {
                seeds.push(SmallStruct {
                    id: i,
                    ip: Ipv4Addr::new(i as u8, (i >> 8) as u8, (i >> 16) as u8, (i >> 24) as u8),
                });
                indexes.push(rng.gen_range(0..iters as usize));
            }
            let mut cache = LRUCache::<SmallStruct, 1000>::default();
            for item in seeds.iter() {
                cache.insert(*item);
            }
            let start = Instant::now();
            for &index in indexes.iter() {
                let _ = cache.find(|s| s.id == seeds[index].id);
            }
            start.elapsed()
        })
    });

    c.bench_function("uluru-get-cache-friendly", |b| {
        b.iter_custom(|iters| {
            let mut seeds = vec![];
            for i in 0..iters {
                seeds.push(SmallStruct {
                    id: i,
                    ip: Ipv4Addr::new(i as u8, (i >> 8) as u8, (i >> 16) as u8, (i >> 24) as u8),
                });
            }
            let mut cache = LRUCache::<SmallStruct, 1000>::default();
            for item in seeds.iter() {
                cache.insert(*item);
            }
            let start = Instant::now();
            for item in seeds.iter().rev() {
                cache.find(|s| s.id == item.id);
            }
            start.elapsed()
        })
    });

    c.bench_function("lru-insert", |b| {
        b.iter_custom(|iters| {
            let mut seeds = vec![];
            for i in 0..iters {
                seeds.push(SmallStruct {
                    id: i,
                    ip: Ipv4Addr::new(i as u8, (i >> 8) as u8, (i >> 16) as u8, (i >> 24) as u8),
                });
            }
            let mut cache = LruCache::new(1000);
            let start = Instant::now();
            for item in seeds {
                cache.put(item.id, item.ip);
            }
            start.elapsed()
        })
    });

    c.bench_function("lru-get-randomly", |b| {
        b.iter_custom(|iters| {
            let mut seeds = vec![];
            let mut rng = thread_rng();
            let mut indexes = vec![];
            for i in 0..iters {
                seeds.push(SmallStruct {
                    id: i,
                    ip: Ipv4Addr::new(i as u8, (i >> 8) as u8, (i >> 16) as u8, (i >> 24) as u8),
                });
                indexes.push(rng.gen_range(0..iters as usize));
            }
            let mut cache = LruCache::new(1000);
            for item in seeds.iter() {
                cache.put(item.id, item.ip);
            }
            let start = Instant::now();
            for &index in indexes.iter() {
                let _ = cache.get(&seeds[index].id);
            }
            start.elapsed()
        })
    });

    c.bench_function("lru-get-cache-friendly", |b| {
        b.iter_custom(|iters| {
            let mut seeds = vec![];
            for i in 0..iters {
                seeds.push(SmallStruct {
                    id: i,
                    ip: Ipv4Addr::new(i as u8, (i >> 8) as u8, (i >> 16) as u8, (i >> 24) as u8),
                });
            }
            let mut cache = LruCache::new(1000);
            for item in seeds.iter() {
                cache.put(item.id, item.ip);
            }
            let start = Instant::now();
            for item in seeds.iter().rev() {
                let _ = cache.get(&item.id);
            }
            start.elapsed()
        })
    });
}

fn lru_192b(c: &mut Criterion) {
    c.bench_function("uluru-insert", |b| {
        b.iter_custom(|iters| {
            let mut seeds = vec![];
            for i in 0..iters {
                seeds.push(BigStruct {
                    id: i,
                    ip: Ipv6Addr::from(i as u128 * 1024),
                });
            }
            let mut cache = LRUCache::<BigStruct, 1000>::default();
            let start = Instant::now();
            for item in seeds {
                cache.insert(item);
            }
            start.elapsed()
        })
    });

    c.bench_function("uluru-get-randomly", |b| {
        b.iter_custom(|iters| {
            let mut seeds = vec![];
            let mut indexes = vec![];
            let mut rng = thread_rng();
            for i in 0..iters {
                seeds.push(BigStruct {
                    id: i,
                    ip: Ipv6Addr::from(i as u128 * 1024),
                });
                indexes.push(rng.gen_range(0..iters as usize));
            }
            let mut cache = LRUCache::<BigStruct, 1000>::default();
            for item in seeds.iter() {
                cache.insert(*item);
            }
            let start = Instant::now();
            for &index in indexes.iter() {
                let _ = cache.find(|s| *s == seeds[index]);
            }
            start.elapsed()
        })
    });

    c.bench_function("uluru-get-cache-friendly", |b| {
        b.iter_custom(|iters| {
            let mut seeds = vec![];
            for i in 0..iters {
                seeds.push(BigStruct {
                    id: i,
                    ip: Ipv6Addr::from(i as u128 * 1024),
                });
            }
            let mut cache = LRUCache::<BigStruct, 1000>::default();
            for item in seeds.iter() {
                cache.insert(*item);
            }
            let start = Instant::now();
            for item in seeds.iter().rev() {
                cache.find(|s| s == item);
            }
            start.elapsed()
        })
    });

    c.bench_function("lru-insert", |b| {
        b.iter_custom(|iters| {
            let mut seeds = vec![];
            for i in 0..iters {
                seeds.push(BigStruct {
                    id: i,
                    ip: Ipv6Addr::from(i as u128 * 1024),
                });
            }
            let mut cache = LruCache::new(1000);
            let start = Instant::now();
            for item in seeds {
                cache.put(item, item.id);
            }
            start.elapsed()
        })
    });

    c.bench_function("lru-get-randomly", |b| {
        b.iter_custom(|iters| {
            let mut seeds = vec![];
            let mut rng = thread_rng();
            let mut indexes = vec![];
            for i in 0..iters {
                seeds.push(BigStruct {
                    id: i,
                    ip: Ipv6Addr::from(i as u128 * 1024),
                });
                indexes.push(rng.gen_range(0..iters as usize));
            }
            let mut cache = LruCache::new(1000);
            for item in seeds.iter() {
                cache.put(*item, item.id);
            }
            let start = Instant::now();
            for &index in indexes.iter() {
                let _ = cache.get(&seeds[index]);
            }
            start.elapsed()
        })
    });

    c.bench_function("lru-get-cache-friendly", |b| {
        b.iter_custom(|iters| {
            let mut seeds = vec![];
            for i in 0..iters {
                seeds.push(BigStruct {
                    id: i,
                    ip: Ipv6Addr::from(i as u128 * 1024),
                });
            }
            let mut cache = LruCache::new(1000);
            for item in seeds.iter() {
                cache.put(*item, item.id);
            }
            let start = Instant::now();
            for item in seeds.iter().rev() {
                let _ = cache.get(item);
            }
            start.elapsed()
        })
    });
}

fn lru_128b(c: &mut Criterion) {
    c.bench_function("uluru-insert", |b| {
        b.iter_custom(|iters| {
            let mut seeds = vec![];
            for i in 0..iters {
                seeds.push(Ipv6Addr::from(i as u128 * 1024));
            }
            let mut cache = LRUCache::<Ipv6Addr, 1000>::default();
            let start = Instant::now();
            for item in seeds {
                cache.insert(item);
            }
            start.elapsed()
        })
    });

    c.bench_function("uluru-get-randomly", |b| {
        b.iter_custom(|iters| {
            let mut seeds = vec![];
            let mut indexes = vec![];
            let mut rng = thread_rng();
            for i in 0..iters {
                seeds.push(Ipv6Addr::from(i as u128 * 1024));
                indexes.push(rng.gen_range(0..iters as usize));
            }
            let mut cache = LRUCache::<Ipv6Addr, 1000>::default();
            for item in seeds.iter() {
                cache.insert(*item);
            }
            let start = Instant::now();
            for &index in indexes.iter() {
                let _ = cache.find(|s| *s == seeds[index]);
            }
            start.elapsed()
        })
    });

    c.bench_function("uluru-get-cache-friendly", |b| {
        b.iter_custom(|iters| {
            let mut seeds = vec![];
            for i in 0..iters {
                seeds.push(Ipv6Addr::from(i as u128 * 1024));
            }
            let mut cache = LRUCache::<Ipv6Addr, 1000>::default();
            for item in seeds.iter() {
                cache.insert(*item);
            }
            let start = Instant::now();
            for item in seeds.iter().rev() {
                cache.find(|s| s == item);
            }
            start.elapsed()
        })
    });

    c.bench_function("lru-insert", |b| {
        b.iter_custom(|iters| {
            let mut seeds = vec![];
            for i in 0..iters {
                seeds.push(Ipv6Addr::from(i as u128 * 1024));
            }
            let mut cache = LruCache::new(1000);
            let start = Instant::now();
            for item in seeds {
                cache.put(item, item);
            }
            start.elapsed()
        })
    });

    c.bench_function("lru-get-randomly", |b| {
        b.iter_custom(|iters| {
            let mut seeds = vec![];
            let mut rng = thread_rng();
            let mut indexes = vec![];
            for i in 0..iters {
                seeds.push(Ipv6Addr::from(i as u128 * 1024));
                indexes.push(rng.gen_range(0..iters as usize));
            }
            let mut cache = LruCache::new(1000);
            for item in seeds.iter() {
                cache.put(*item, *item);
            }
            let start = Instant::now();
            for &index in indexes.iter() {
                let _ = cache.get(&seeds[index]);
            }
            start.elapsed()
        })
    });

    c.bench_function("lru-get-cache-friendly", |b| {
        b.iter_custom(|iters| {
            let mut seeds = vec![];
            for i in 0..iters {
                seeds.push(Ipv6Addr::from(i as u128));
            }
            let mut cache = LruCache::new(1000);
            for item in seeds.iter() {
                cache.put(*item, *item);
            }
            let start = Instant::now();
            for item in seeds.iter().rev() {
                let _ = cache.get(item);
            }
            start.elapsed()
        })
    });
}

/*
//go 版本代码
import (
    "math/rand"
    "time"
)

// Returns an int >= min, < max
func randomInt(min, max int) int {
        return min + rand.Intn(max-min)
}

func BenchmarkU64LRUGetRandomly(b *testing.B) {
        rand.Seed(time.Now().UnixNano())
        capacity := b.N
        lru := NewU64LRU("test", int(capacity), int(capacity))
        indexes := make([]int, capacity)

        for i := 0; i < b.N; i++ {
                lru.Add(uint64(i), uint64(i))
                indexes[i] = randomInt(0, capacity)
        }
        b.ResetTimer()
        for i := 0; i < capacity; i++ {
                lru.Get(uint64(indexes[i]), false)
        }

        lru.Close()
}

func BenchmarkU64LRUGetCacheFriendly(b *testing.B) {
        capacity := b.N
        lru := NewU64LRU("test", int(capacity), int(capacity))

        for i := 0; i < b.N; i++ {
                lru.Add(uint64(i), uint64(i))
        }
        b.ResetTimer()
        for i := b.N - 1; i >= 0; i-- {
                lru.Get(uint64(i), false)
        }

        lru.Close()
}

func BenchmarkU64LRUInsert(b *testing.B) {
        capacity := b.N
        lru := NewU64LRU("test", int(capacity), int(capacity))

        b.ResetTimer()
        for i := 0; i < b.N; i++ {
                lru.Add(uint64(i), uint64(i))
        }

        lru.Close()
}
func BenchmarkU128LRUGetRandomly(b *testing.B) {
        rand.Seed(time.Now().UnixNano())
        capacity := b.N
        lru := NewU128LRU("test", int(capacity), int(capacity))
        indexes := make([]int, capacity)

        for i := 0; i < b.N; i++ {
                lru.Add(uint64(i), uint64(i*2+b.N), uint64(i))
                indexes[i] = randomInt(0, capacity)
        }
        b.ResetTimer()
        for i := 0; i < capacity; i++ {
                lru.Get(uint64(indexes[i]), uint64(i*2+b.N), false)
        }

        lru.Close()
}

func BenchmarkU128LRUGetCacheFriendly(b *testing.B) {
        capacity := b.N
        lru := NewU128LRU("test", int(capacity), int(capacity))

        for i := 0; i < b.N; i++ {
                lru.Add(uint64(i), uint64(i*2+b.N), uint64(i))
        }
        b.ResetTimer()
        for i := b.N - 1; i >= 0; i-- {
                lru.Get(uint64(i), uint64(i*2+b.N), false)
        }

        lru.Close()
}

func BenchmarkU128LRUInsert(b *testing.B) {
        capacity := b.N
        lru := NewU128LRU("test", int(capacity), int(capacity))

        b.ResetTimer()
        for i := 0; i < b.N; i++ {
                lru.Add(uint64(i), uint64(i*2+b.N), uint64(i))
        }

        lru.Close()
}

func BenchmarkU128U64LRUGetRandomly(b *testing.B) {
        capacity := b.N
        rand.Seed(time.Now().UnixNano())
        indexes := make([]int, capacity)
        lru := NewU128U64DoubleKeyLRU("test", capacity, capacity/2, capacity)
        half := capacity / 2
        // 添加TCP流数据
        for i := 1; i <= half; i++ {
                lru.Add(_FLOW_ID_TCP, uint64(i), _FLOW_ID_TCP, uint64(i+10))
                indexes[i] = randomInt(0, capacity)
        }

        // 添加UDP流数据
        for i := half; i < capacity; i++ {
                lru.Add(_FLOW_ID_UDP, uint64(i), _FLOW_ID_UDP, uint64(i+100))
                indexes[i] = randomInt(0, capacity)
        }

        b.ResetTimer()
        for i := 0; i < capacity; i++ {
                var t uint64
                if indexes[i] < half {
                        t = _FLOW_ID_TCP
                } else {
                        t = _FLOW_ID_UDP
                }
                lru.Get(t, uint64(indexes[i]), true)
        }

        lru.Close()
}

func BenchmarkU128U64LRUGetCacheFriendly(b *testing.B) {
        capacity := b.N
        lru := NewU128U64DoubleKeyLRU("test", capacity, capacity/2, capacity)
        half := capacity / 2
        // 添加TCP流数据
        for i := 1; i <= half; i++ {
                lru.Add(_FLOW_ID_TCP, uint64(i), _FLOW_ID_TCP, uint64(i+10))
        }

        // 添加UDP流数据
        for i := half; i <= capacity; i++ {
                lru.Add(_FLOW_ID_UDP, uint64(i), _FLOW_ID_UDP, uint64(i+100))
        }

        b.ResetTimer()
        for i := b.N - 1; i >= half; i-- {
                lru.Get(_FLOW_ID_UDP, uint64(i), true)
        }
        for i := half; i >= 0; i-- {
                lru.Get(_FLOW_ID_TCP, uint64(i), true)
        }
        lru.Close()
}

func BenchmarkU128U64LRUInsert(b *testing.B) {
        capacity := b.N

        lru := NewU128U64DoubleKeyLRU("test", capacity, capacity/2, capacity)

        b.ResetTimer()

        half := capacity / 2
        // 添加TCP流数据
        for i := 1; i <= half; i++ {
                lru.Add(_FLOW_ID_TCP, uint64(i), _FLOW_ID_TCP, uint64(i+10))
        }

        // 添加UDP流数据
        for i := 1; i <= half; i++ {
                lru.Add(_FLOW_ID_UDP, uint64(i), _FLOW_ID_UDP, uint64(i+100))
        }
        lru.Close()
}
*/

criterion_group!(benches, lru_64b, lru_128b, lru_192b);
criterion_main!(benches);
