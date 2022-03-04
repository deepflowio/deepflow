use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use pcap::{Capture, Packet};

use crate::common::meta_packet::MetaPacket;

pub fn load_pcap<T: FromPacket, P: AsRef<Path>>(path: P, parse_len: Option<usize>) -> Vec<T> {
    let mut packets: Vec<T> = vec![];
    let mut capture = Capture::from_file(path).unwrap();
    let len = parse_len.unwrap_or(128);
    while let Ok(packet) = capture.next() {
        packets.push(T::parse(&packet, len));
    }
    packets
}

pub trait FromPacket {
    fn parse(p: &Packet, len: usize) -> Self;
}

impl FromPacket for MetaPacket {
    fn parse(p: &Packet, len: usize) -> Self {
        let mut meta = MetaPacket::empty();
        meta.update(
            Arc::new(p.data[..p.data.len().min(len)].to_vec()),
            true,
            true,
            Duration::new(p.header.ts.tv_sec as u64, p.header.ts.tv_usec as u32 * 1000),
            0,
        )
        .unwrap();
        meta
    }
}

impl FromPacket for Vec<u8> {
    fn parse(packet: &Packet, len: usize) -> Self {
        let packet_len = packet.data.len().min(len);
        Vec::from(&packet.data[..packet_len])
    }
}
