/*
 * Copyright (c) 2022 Yunshan Networks
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

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

use criterion::*;

use deepflow_agent::{
    _FlowPerfCounter as FlowPerfCounter, _HttpPerfData as HttpPerfData, _L7FlowPerf as L7FlowPerf,
    _L7RrtCache as L7RrtCache, _PacketDirection as PacketDirection, _TcpPerf as TcpPerf,
    _benchmark_report as benchmark_report,
    _benchmark_session_peer_seq_no_assert as benchmark_session_peer_seq_no_assert,
    _meta_flow_perf_update as meta_flow_perf_update, utils::test::Capture,
};

pub(super) fn bench(c: &mut Criterion) {
    c.bench_function("perf_stats_report", |b| {
        b.iter_custom(|iters| {
            let mut perf = TcpPerf::new(Arc::new(FlowPerfCounter::default()));
            let start = Instant::now();
            for _ in 0..iters {
                benchmark_report(&mut perf);
            }
            start.elapsed()
        })
    });
    c.bench_function("perf_update", |b| {
        b.iter_custom(|iters| {
            let mut perf = TcpPerf::new(Arc::new(FlowPerfCounter::default()));
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
    c.bench_function("perf_parse_http_v1", |b| {
        b.iter_custom(|iters| {
            let capture = Capture::load_pcap(
                Path::new("./resources/test/flow_generator/http/httpv1.pcap"),
                None,
            );
            let mut packets = capture.as_meta_packets();
            if packets.len() < 2 {
                panic!("unable to load pcap file");
            }

            let rrt_cache = L7RrtCache::new(8);
            let mut parser = HttpPerfData::new(Rc::new(RefCell::new(rrt_cache)));

            let first_dst_port = packets[0].lookup_key.dst_port;
            for packet in packets.iter_mut().take(2) {
                if packet.lookup_key.dst_port == first_dst_port {
                    packet.lookup_key.direction = PacketDirection::ClientToServer;
                } else {
                    packet.lookup_key.direction = PacketDirection::ServerToClient;
                }
            }

            let start = Instant::now();
            for _ in 0..iters {
                let _ = parser.parse(None, &packets[0], 0x1f3c01010);
                let _ = parser.parse(None, &packets[1], 0x1f3c01010);
            }
            start.elapsed()
        })
    });
}
