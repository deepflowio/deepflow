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

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;

use deepflow_agent::{
    _PacketDirection as PacketDirection,
    common::l7_protocol_log::{L7PerfCache, L7ProtocolParserInterface, ParseParam},
    utils::test::Capture,
    HttpLog,
};

fn main() {
    let iters: usize = std::env::args()
        .nth(1)
        .unwrap_or_default()
        .parse()
        .unwrap_or(1024);

    let capture = Capture::load_pcap(
        Path::new("./resources/test/flow_generator/http/httpv1.pcap"),
        None,
    );
    let log_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));
    let mut packets = capture.as_meta_packets();
    if packets.len() < 2 {
        panic!("unable to load pcap file");
    }

    let mut parser = HttpLog::new_v1();

    let first_dst_port = packets[0].lookup_key.dst_port;
    for packet in packets.iter_mut().take(2) {
        if packet.lookup_key.dst_port == first_dst_port {
            packet.lookup_key.direction = PacketDirection::ClientToServer;
        } else {
            packet.lookup_key.direction = PacketDirection::ServerToClient;
        }
    }

    for _ in 0..iters {
        let _ = parser.parse_payload(
            &packets[0].get_l4_payload().unwrap(),
            &ParseParam::new(
                &packets[0],
                log_cache.clone(),
                Default::default(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Default::default(),
                true,
                true,
            ),
        );
        let _ = parser.parse_payload(
            &packets[1].get_l4_payload().unwrap(),
            &ParseParam::new(
                &packets[1],
                log_cache.clone(),
                Default::default(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Default::default(),
                true,
                true,
            ),
        );
    }
}
