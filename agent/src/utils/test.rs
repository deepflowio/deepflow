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

use std::{fmt, net::IpAddr, path::Path, time::Duration};

use pcap::{self, Linktype};

use crate::common::meta_packet::MetaPacket;

pub struct Capture {
    cap: pcap::Capture<pcap::Offline>,
    dl_type: Linktype,
}

impl Capture {
    pub fn load_pcap<P: AsRef<Path>>(path: P) -> Self {
        let cap = pcap::Capture::from_file(path).unwrap();
        let dl_type = cap.get_datalink();
        Self { cap, dl_type }
    }

    fn build_meta_packet(dl_type: Linktype, packet: &pcap::Packet) -> Option<MetaPacket<'static>> {
        match dl_type {
            Linktype::ETHERNET => {
                let mut meta = MetaPacket::empty();
                meta.update(
                    packet.data.to_vec(),
                    true,
                    true,
                    Duration::new(
                        packet.header.ts.tv_sec as u64,
                        packet.header.ts.tv_usec as u32 * 1000,
                    ),
                    0,
                )
                .unwrap();
                return Some(meta);
            }
            _ => (),
        }

        // change SLL header to look like ethernet header just before L3 header
        let mut data = match dl_type {
            // 2 bytes longer than ethernet header
            Linktype::LINUX_SLL => (&packet.data[2..]).to_vec(),
            Linktype::LINUX_SLL2 => {
                // 6 bytes longer, and L3 type is in first 2 bytes
                let mut data = (&packet.data[6..]).to_vec();
                data[12..14].copy_from_slice(&packet.data[0..2]);
                data
            }
            _ => unimplemented!(),
        };

        let mut meta = MetaPacket::empty();
        meta.update(
            &data[..],
            true,
            true,
            Duration::new(
                packet.header.ts.tv_sec as u64,
                packet.header.ts.tv_usec as u32 * 1000,
            ),
            0,
        )
        .unwrap();

        let src_ip = meta.lookup_key.src_ip;
        let dst_ip = meta.lookup_key.dst_ip;
        // fake mac with ip
        (&mut data[0..12]).fill(0);
        match dst_ip {
            IpAddr::V4(ip) => {
                data[0..4].copy_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                data[0..6].copy_from_slice(&ip.octets()[0..6]);
            }
        }
        match src_ip {
            IpAddr::V4(ip) => {
                data[6..10].copy_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                data[6..12].copy_from_slice(&ip.octets()[0..6]);
            }
        }

        let mut meta = MetaPacket::empty();
        meta.update(
            data,
            true,
            true,
            Duration::new(
                packet.header.ts.tv_sec as u64,
                packet.header.ts.tv_usec as u32 * 1000,
            ),
            0,
        )
        .unwrap();
        Some(meta)
    }
}

impl Iterator for Capture {
    type Item = MetaPacket<'static>;

    fn next(&mut self) -> Option<Self::Item> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        while let Ok(packet) = self.cap.next() {
            if let Some(meta) = Self::build_meta_packet(self.dl_type, &packet) {
                return Some(meta);
            }
        }

        #[cfg(target_os = "windows")]
        while let Ok(packet) = self.cap.next_packet() {
            if let Some(meta) = Self::build_meta_packet(self.dl_type, &packet) {
                return Some(meta);
            }
        }

        None
    }
}

impl From<Capture> for Vec<Vec<u8>> {
    fn from(c: Capture) -> Self {
        c.into_iter().map(|p| p.raw.unwrap().to_vec()).collect()
    }
}

pub struct WrappedDebugStruct<'a, 'b: 'a>(fmt::DebugStruct<'a, 'b>);

impl<'a, 'b> From<fmt::DebugStruct<'a, 'b>> for WrappedDebugStruct<'a, 'b> {
    fn from(ds: fmt::DebugStruct<'a, 'b>) -> Self {
        Self(ds)
    }
}

impl<'a, 'b: 'a> WrappedDebugStruct<'a, 'b> {
    pub fn field_skip_default<F>(
        &mut self,
        field: &str,
        value: &F,
    ) -> &mut WrappedDebugStruct<'a, 'b>
    where
        F: fmt::Debug + Default + PartialEq,
    {
        if value != &F::default() {
            self.0.field(field, value);
        }
        self
    }

    pub fn field<F>(&mut self, field: &str, value: &F) -> &mut WrappedDebugStruct<'a, 'b>
    where
        F: fmt::Debug,
    {
        self.0.field(field, value);
        self
    }

    pub fn finish(&mut self) -> fmt::Result {
        self.0.finish()
    }
}
