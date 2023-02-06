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

use std::cmp::max;

use crate::common::{
    flow::{FlowPerfStats, L4Protocol, PacketDirection},
    meta_packet::MetaPacket,
    Timestamp,
};
use crate::flow_generator::error::{Error, Result};

use super::{L4FlowPerf, ART_MAX};

#[derive(Debug, Default)]
pub struct UdpPerf {
    req_timestamp: Timestamp,
    art_max: Timestamp,
    art_sum: Timestamp,
    art_count: u32,
    last_pkt_direction: PacketDirection,
    data_update_flag: bool,
}

impl UdpPerf {
    pub fn new() -> Self {
        UdpPerf::default()
    }
}

impl L4FlowPerf for UdpPerf {
    fn parse(&mut self, header: &MetaPacket, _: bool) -> Result<()> {
        if header.payload_len == 0 {
            return Err(Error::ZeroPayloadLen);
        }

        let pkt_timestamp = header.lookup_key.timestamp;
        if header.lookup_key.direction == PacketDirection::ClientToServer {
            self.req_timestamp = pkt_timestamp.into();
        } else if self.req_timestamp != Timestamp::ZERO
            && self.req_timestamp <= pkt_timestamp
            && header.lookup_key.direction != self.last_pkt_direction
        {
            let art = Timestamp::from(pkt_timestamp - self.req_timestamp);
            if art <= ART_MAX {
                self.art_max = max(self.art_max, art);
                self.art_sum += art;
                self.art_count += 1;
                self.data_update_flag = true;
            }
        }

        self.last_pkt_direction = header.lookup_key.direction;

        Ok(())
    }

    fn data_updated(&self) -> bool {
        self.data_update_flag
    }

    fn copy_and_reset_data(&mut self, _: bool) -> FlowPerfStats {
        let mut stats = FlowPerfStats::default();
        stats.l4_protocol = L4Protocol::Udp;
        stats.tcp.art_max = (self.art_max.as_nanos() / Timestamp::from_micros(1).as_nanos()) as u32;
        stats.tcp.art_sum = (self.art_sum.as_nanos() / Timestamp::from_micros(1).as_nanos()) as u32;
        stats.tcp.art_count = self.art_count;

        stats
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use crate::utils::test::Capture;

    use super::*;

    const FILE_DIR: &'static str = "resources/test/flow_generator";

    fn update_from_pcap<P: AsRef<Path>>(path: P, reverse_pkt: bool) -> (UdpPerf, String) {
        let capture = Capture::load_pcap(path, None);
        let packets = capture.as_meta_packets();
        let mut flow_perf = UdpPerf::new();
        let mut result = String::from("");

        let first_pkt_src_ip = packets[0].lookup_key.src_ip;
        for (i, mut pkt) in packets.into_iter().enumerate() {
            if first_pkt_src_ip == pkt.lookup_key.src_ip {
                pkt.lookup_key.direction = PacketDirection::ClientToServer;
            } else {
                pkt.lookup_key.direction = PacketDirection::ServerToClient;
            }

            if reverse_pkt {
                pkt.lookup_key.direction = pkt.lookup_key.direction.reversed();
            }

            flow_perf.parse(&pkt, false).unwrap();
            result.push_str(format!("{}th udp perf data:\n{:?}\n\n", i, flow_perf).as_str());
        }

        (flow_perf, result)
    }

    fn udp_perf_helper<P: AsRef<Path>>(path: P, result_path: P, reverse_pkt: bool) {
        let (_, actual) = update_from_pcap(path, reverse_pkt);
        let result = fs::read_to_string(result_path).unwrap();
        assert_eq!(result, actual)
    }

    fn udp_report_helper<P: AsRef<Path>>(path: P, result_path: P, reverse_pkt: bool) {
        let (mut flow_perf, _) = update_from_pcap(path, reverse_pkt);
        let stats = flow_perf.copy_and_reset_data(false);
        let actual = format!("{:?}\n", stats);
        let result = fs::read_to_string(result_path).unwrap();
        assert_eq!(result, actual)
    }

    #[test]
    fn udp_normal() {
        udp_perf_helper(
            Path::new(FILE_DIR).join("udp_normal.pcap"),
            Path::new(FILE_DIR).join("udp_normal.result"),
            false,
        )
    }

    #[test]
    fn udp_single_packet() {
        udp_perf_helper(
            Path::new(FILE_DIR).join("udp_1_packet.pcap"),
            Path::new(FILE_DIR).join("udp_1_packet.result"),
            true,
        )
    }

    #[test]
    fn udp_continuous_packet() {
        udp_perf_helper(
            Path::new(FILE_DIR).join("udp_continuous_packet.pcap"),
            Path::new(FILE_DIR).join("udp_continuous_packet.result"),
            false,
        )
    }

    #[test]
    fn udp_report() {
        udp_perf_helper(
            Path::new(FILE_DIR).join("udp_normal.pcap"),
            Path::new(FILE_DIR).join("udp_report_packet.result"),
            false,
        )
    }
}
