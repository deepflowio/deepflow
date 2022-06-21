use std::path::Path;
use std::time::Duration;

use pcap::{self, PacketHeader};

use crate::common::meta_packet::MetaPacket;

pub struct Capture(Vec<(PacketHeader, Vec<u8>)>);

impl Capture {
    pub fn load_pcap<P: AsRef<Path>>(path: P, parse_len: Option<usize>) -> Self {
        let parse_len = parse_len.unwrap_or(128);
        let mut packets = vec![];
        let mut capture = pcap::Capture::from_file(path).unwrap();
        while let Ok(packet) = capture.next() {
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
                meta.update(
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
