use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;

use deepflow_agent::{
    _HttpPerfData as HttpPerfData, _L7FlowPerf as L7FlowPerf, _L7RrtCache as L7RrtCache,
    _PacketDirection as PacketDirection, utils::test::Capture,
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

    for _ in 0..iters {
        let _ = parser.parse(None, &packets[0], 0x1f3c01010);
        let _ = parser.parse(None, &packets[1], 0x1f3c01010);
    }
}
