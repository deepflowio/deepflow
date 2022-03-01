use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use pcap::{Capture, Packet};

use crate::common::meta_packet::MetaPacket;

pub fn load_pcap<P: AsRef<Path>>(path: P) -> Vec<MetaPacket> {
    let mut meta_packets = vec![];
    let mut capture = Capture::from_file(path).unwrap();
    while let Ok(packet) = capture.next() {
        meta_packets.push(parse_packet(&packet));
    }
    meta_packets
}

fn parse_packet(p: &Packet) -> MetaPacket {
    let mut meta = MetaPacket::empty();
    meta.update(
        Arc::new(p.data[..p.data.len().min(128)].to_vec()),
        true,
        true,
        Duration::new(p.header.ts.tv_sec as u64, p.header.ts.tv_usec as u32 * 1000),
        0,
    )
    .unwrap();
    meta
}
