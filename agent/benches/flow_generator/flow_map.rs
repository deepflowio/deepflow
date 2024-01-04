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

use std::time::Instant;

use criterion::*;

use deepflow_agent::{
    _FlowMapConfig as Config, _TcpFlags as TcpFlags, _Timestamp as Timestamp,
    _new_flow_map_and_receiver as new_flow_map_and_receiver, _new_meta_packet as new_meta_packet,
    _reverse_meta_packet as reverse_meta_packet, common::meta_packet::ProtocolData,
};

use public::proto::common::TridentType;

pub(super) fn bench(c: &mut Criterion) {
    c.bench_function("flow_map_syn_flood", |b| {
        b.iter_custom(|iters| {
            let (module_config, mut map, _) =
                new_flow_map_and_receiver(TridentType::TtProcess, None, false);
            let config = Config {
                flow: &module_config.flow,
                log_parser: &module_config.log_parser,
                collector: &module_config.collector,
                #[cfg(any(target_os = "linux", target_os = "android"))]
                ebpf: None,
            };
            let packets = (0..iters)
                .into_iter()
                .map(|i| {
                    let mut pkt = new_meta_packet();
                    pkt.lookup_key.src_port = i as u16;
                    pkt.lookup_key.dst_port = (i >> 16) as u16;
                    pkt
                })
                .collect::<Vec<_>>();
            let start = Instant::now();
            for mut pkt in packets {
                map.inject_meta_packet(&config, &mut pkt);
            }
            start.elapsed()
        })
    });

    c.bench_function("flow_map_with_ten_packets_flow_flood", |b| {
        b.iter_custom(|iters| {
            let (module_config, mut map, _) =
                new_flow_map_and_receiver(TridentType::TtProcess, None, false);
            let config = Config {
                flow: &module_config.flow,
                log_parser: &module_config.log_parser,
                collector: &module_config.collector,
                #[cfg(any(target_os = "linux", target_os = "android"))]
                ebpf: None,
            };
            let iters = (iters + 9) / 10 * 10;

            let mut packets = vec![];
            for i in (0..iters).step_by(10) {
                let src_port = i as u16;
                let dst_port = (i >> 16) as u16;

                let mut pkt = new_meta_packet();
                pkt.lookup_key.timestamp += Timestamp::from_nanos(100 * i);
                pkt.lookup_key.src_port = src_port;
                pkt.lookup_key.dst_port = dst_port;
                packets.push(pkt);

                let mut pkt = new_meta_packet();
                pkt.lookup_key.timestamp += Timestamp::from_nanos(100 * (i + 1));
                reverse_meta_packet(&mut pkt);
                pkt.lookup_key.src_port = dst_port;
                pkt.lookup_key.dst_port = src_port;
                if let ProtocolData::TcpHeader(tcp_data) = &mut pkt.protocol_data {
                    tcp_data.flags = TcpFlags::SYN_ACK;
                }
                packets.push(pkt);

                for k in 2..10 {
                    let mut pkt = new_meta_packet();
                    pkt.lookup_key.timestamp += Timestamp::from_nanos(100 * (i + k));
                    pkt.lookup_key.src_port = src_port;
                    pkt.lookup_key.dst_port = dst_port;
                    if let ProtocolData::TcpHeader(tcp_data) = &mut pkt.protocol_data {
                        tcp_data.flags = TcpFlags::ACK;
                    }
                    packets.push(pkt);
                }
            }

            let start = Instant::now();
            for mut pkt in packets {
                map.inject_meta_packet(&config, &mut pkt);
            }
            start.elapsed()
        })
    });
}
