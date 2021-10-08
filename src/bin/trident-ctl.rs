use std::ffi::CString;

use trident::dispatcher::recv_engine::afpacket::{options, options::Options, tpacket::Tpacket};

fn main() {
    let mut opts: Options = Default::default();
    opts.version = options::OptTpacketVersion::TpacketVersion2;
    let mut socket = Tpacket::new(opts).unwrap();
    println!("afpacket init ok.");
    let mut last: u64 = 0;
    let mut flags = false;

    println!(
        "2: {:?} 3: {:?}",
        options::OptTpacketVersion::TpacketVersion2 as u32,
        options::OptTpacketVersion::TpacketVersion3 as u32
    );
    if let Err(e) = socket.set_bpf(CString::new("arp").unwrap()) {
        println!("set bpf error: {}", e);
        return;
    }
    loop {
        if let Some(packet) = socket.read() {
            let now = packet.timestamp.as_secs();
            if now - last >= 1 {
                last = now;
                flags = true;
            }
            println!("{:?}", packet.data);
        }
        if flags {
            let stats = socket.get_socket_stats();
            println!("{:?} {:?}", last, stats);
            flags = false;
        }
    }
}
