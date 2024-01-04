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

use std::hash::Hash;
use std::net::Ipv6Addr;
use std::time::Duration;
use std::{net::Ipv4Addr, time::Instant};

use criterion::*;
use deepflow_agent::{
    _L7PerfCache as L7PerfCache, _LogCache as LogCache, _LogMessageType as LogMessageType,
};
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
            let mut cache = LruCache::new(1000.try_into().unwrap());
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
            let mut cache = LruCache::new(1000.try_into().unwrap());
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
            let mut cache = LruCache::new(1000.try_into().unwrap());
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
            let mut cache = LruCache::new(1000.try_into().unwrap());
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
            let mut cache = LruCache::new(1000.try_into().unwrap());
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
            let mut cache = LruCache::new(1000.try_into().unwrap());
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
            let mut cache = LruCache::new(1000.try_into().unwrap());
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
            let mut cache = LruCache::new(1000.try_into().unwrap());
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
            let mut cache = LruCache::new(1000.try_into().unwrap());
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

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Request {
    pub flow_id: u64,
    pub stream_id: Option<u32>,
    pub duration: Duration,
}

fn rrt_lru(c: &mut Criterion) {
    c.bench_function("rrt_lru-add", |b| {
        b.iter_custom(|iters| {
            let mut seeds = vec![];
            let mut rng = thread_rng();
            for _ in 0..iters {
                let i = rng.gen_range(0..iters as usize);
                // 50%的flow,的stream_id数量为1-1000
                seeds.push(Request {
                    flow_id: ((4 * i) as f64).sqrt() as u64 / 2, // 0,1,1,1,2,2,2,2...
                    stream_id: if (i % 2) == 0 { None } else { Some(i as u32) },
                    duration: Duration::new(i as u64, i as u32),
                });
            }
            let mut cache = L7PerfCache::new(1000);
            let start = Instant::now();
            for item in seeds {
                cache.rrt_cache.put(
                    ((item.flow_id as u128) << 64) | item.stream_id.unwrap_or_default() as u128,
                    LogCache {
                        msg_type: LogMessageType::Request,
                        time: item.duration.as_micros() as u64,
                        kafka_info: None,
                        multi_merge_info: None,
                    },
                );
            }
            start.elapsed()
        })
    });
    c.bench_function("rrt_lru-get", |b| {
        b.iter_custom(|iters| {
            let mut seeds = vec![];
            let mut rng = thread_rng();
            for _ in 0..iters {
                let i = rng.gen_range(0..iters as usize);
                seeds.push(Request {
                    flow_id: ((4 * i) as f64).sqrt() as u64 / 2,
                    stream_id: if (i % 2) == 0 { None } else { Some(i as u32) },
                    duration: Duration::new(i as u64, i as u32),
                });
            }
            let mut cache = L7PerfCache::new(1000);
            for item in &seeds {
                cache.rrt_cache.put(
                    ((item.flow_id as u128) << 64) | item.stream_id.unwrap_or_default() as u128,
                    LogCache {
                        msg_type: LogMessageType::Request,
                        time: item.duration.as_micros() as u64,
                        kafka_info: None,
                        multi_merge_info: None,
                    },
                );
            }
            let start = Instant::now();
            for item in &seeds {
                cache.rrt_cache.get(
                    &(((item.flow_id as u128) << 64) | item.stream_id.unwrap_or_default() as u128),
                );
            }
            start.elapsed()
        })
    });
    c.bench_function("rrt_lru-timeout", |b| {
        b.iter_custom(|iters| {
            let mut seeds = vec![];
            let mut rng = thread_rng();
            for _ in 0..iters {
                let i = rng.gen_range(0..iters as usize);
                seeds.push(Request {
                    flow_id: ((4 * i) as f64).sqrt() as u64 / 2,
                    stream_id: if (i % 2) == 0 { None } else { Some(i as u32) },
                    duration: Duration::new(i as u64, i as u32),
                });
            }
            let mut cache = L7PerfCache::new(1000);
            for item in &seeds {
                cache.rrt_cache.put(
                    ((item.flow_id as u128) << 64) | item.stream_id.unwrap_or_default() as u128,
                    LogCache {
                        msg_type: LogMessageType::Request,
                        time: item.duration.as_micros() as u64,
                        kafka_info: None,
                        multi_merge_info: None,
                    },
                );
            }
            let start = Instant::now();
            for item in &seeds {
                cache.rrt_cache.get(
                    &(((item.flow_id as u128) << 64) | item.stream_id.unwrap_or_default() as u128),
                );
            }
            start.elapsed()
        })
    });
    /* 对比go的bench结果
    顺序数据
    rust:
      rrt_lru-add             time:   [29.340 ns 29.671 ns 29.985 ns]
      rrt_lru-get             time:   [21.912 ns 22.042 ns 22.183 ns]
      rrt_lru-timeout         time:   [14.077 ns 14.165 ns 14.263 ns]
    go:
      BenchmarkLruAdd-20        	10530165	       116.3 ns/op
      BenchmarkLruGet-20        	79841413	        14.29 ns/op
      BenchmarkLruTimeout-20    	175275356	         6.560 ns/op

    随机数据测试：
      rrt_lru-add             time:   [100.92 ns 102.35 ns 103.49 ns]
      rrt_lru-get             time:   [75.997 ns 77.185 ns 78.149 ns]
      rrt_lru-timeout         time:   [13.783 ns 13.827 ns 13.876 ns]

      BenchmarkLruAdd-20        	 7348380	       157.0 ns/op
      BenchmarkLruGet-20        	82796860	        13.43 ns/op
      BenchmarkLruTimeout-20    	189908188	         6.304 ns/op
     */
    /* go bench 对比代码
    type Request struct {
        FlowID   uint64
        StreamID uint32
        time     time.Duration
    }

    func BenchmarkLruAdd(b *testing.B) {
        capacity := b.N
        lru := NewL7RRTCache(0, 100, 1000)
        seeds := make([]Request, 0, capacity)
        for j := 0; j < b.N; j++ {
            i := rand.Intn(b.N)
            streamid := uint32(i)
            if i%2 == 0 {
                streamid = 0
            }
            seeds = append(seeds, Request{
                FlowID:   uint64(math.Sqrt(float64(4*i))) / 2,
                StreamID: streamid,
                time:     time.Duration(i),
            })
        }
        b.ResetTimer()
        for i := b.N - 1; i >= 0; i-- {
            lru.AddReqTime(seeds[i].FlowID, seeds[i].StreamID, seeds[i].time)
        }
        lru.Close()
    }

    func BenchmarkLruGet(b *testing.B) {
        capacity := b.N
        lru := NewL7RRTCache(0, 100, 1000)
        seeds := make([]Request, 0, capacity)
        for j := 0; j < b.N; j++ {
            i := rand.Intn(b.N)
            streamid := uint32(i)
            if i%2 == 0 {
                streamid = 0
            }
            seeds = append(seeds, Request{
                FlowID:   uint64(math.Sqrt(float64(4*i))) / 2,
                StreamID: streamid,
                time:     time.Duration(i),
            })
        }
        b.ResetTimer()
        for i := b.N - 1; i >= 0; i-- {
            lru.GetAndRemoveL7ReqTime(seeds[i].FlowID, seeds[i].StreamID)
        }
        lru.Close()
    }

    func BenchmarkLruTimeout(b *testing.B) {
        capacity := b.N
        lru := NewL7RRTCache(0, 100, 1000)
        seeds := make([]Request, 0, capacity)
        for j := 0; j < b.N; j++ {
            i := rand.Intn(b.N)
            streamid := uint32(i)
            if i%2 == 0 {
                streamid = 0
            }
            seeds = append(seeds, Request{
                FlowID:   uint64(math.Sqrt(float64(4*i))) / 2,
                StreamID: streamid,
                time:     time.Duration(i),
            })
        }
        b.ResetTimer()
        for i := b.N - 1; i >= 0; i-- {
            lru.GetAndRemoveL7ReqTimeouts(seeds[i].FlowID)
        }
        lru.Close()
    }
    */
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

criterion_group!(benches, lru_64b, lru_128b, lru_192b, rrt_lru);
criterion_main!(benches);
