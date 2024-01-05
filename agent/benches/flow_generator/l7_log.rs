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

use std::path::Path;
use std::time::Instant;
use std::{cell::RefCell, rc::Rc, sync::Arc};

use criterion::*;

use deepflow_agent::{
    _FlowPerfCounter as FlowPerfCounter, _L7PerfCache as L7PerfCache,
    _PacketDirection as PacketDirection, _TcpPerf as TcpPerf,
    _benchmark_report as benchmark_report,
    _benchmark_session_peer_seq_no_assert as benchmark_session_peer_seq_no_assert,
    _meta_flow_perf_update as meta_flow_perf_update,
    common::l7_protocol_log::{L7ProtocolParserInterface, ParseParam},
    utils::test::Capture,
    HttpLog,
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
    c.bench_function("parse_http_v1_log", |b| {
        b.iter_custom(|iters| {
            let capture = Capture::load_pcap(
                Path::new("./resources/test/flow_generator/http/httpv1.pcap"),
                None,
            );
            let mut packets = capture.as_meta_packets();
            if packets.len() < 2 {
                panic!("unable to load pcap file");
            }

            let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(8)));
            let req_param = ParseParam::new(&packets[0], rrt_cache.clone(), true, true);
            let resp_param = ParseParam::new(&packets[1], rrt_cache.clone(), true, true);
            let mut parser = HttpLog::new_v1();

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
                let _ = parser.parse_payload(packets[0].get_l4_payload().unwrap(), &req_param);
                let _ = parser.parse_payload(packets[1].get_l4_payload().unwrap(), &resp_param);
            }
            start.elapsed()
        })
    });
}
