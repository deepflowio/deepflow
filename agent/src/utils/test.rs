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

use std::path::Path;
use std::time::Duration;

use pcap::{self, PacketHeader};

use crate::common::meta_packet::MetaPacket;

pub struct Capture(Vec<(PacketHeader, Vec<u8>)>);

impl Capture {
    pub fn load_pcap<P: AsRef<Path>>(path: P, parse_len: Option<usize>) -> Self {
        let parse_len = parse_len.unwrap_or(1500);
        let mut packets = vec![];
        let mut capture = pcap::Capture::from_file(path).unwrap();
        #[cfg(target_os = "linux")]
        while let Ok(packet) = capture.next() {
            packets.push((
                packet.header.clone(),
                Vec::from(&packet.data[..packet.data.len().min(parse_len)]),
            ));
        }
        #[cfg(target_os = "windows")]
        while let Ok(packet) = capture.next_packet() {
            packets.push((
                packet.header.clone(),
                Vec::from(&packet.data[..packet.data.len().min(parse_len)]),
            ));
        }
        Self(packets)
    }

    pub fn as_meta_packets(&self) -> Vec<MetaPacket<'_>> {
        self.0
            .iter()
            .map(|(h, p)| {
                let mut meta = MetaPacket::empty();
                meta.update_without_raw_copy(
                    &p,
                    true,
                    true,
                    Duration::new(h.ts.tv_sec as u64, h.ts.tv_usec as u32 * 1000),
                    0,
                )
                .unwrap();
                meta
            })
            .collect()
    }
}

impl From<Capture> for Vec<Vec<u8>> {
    fn from(c: Capture) -> Self {
        c.0.into_iter().map(|(_, p)| p).collect()
    }
}
