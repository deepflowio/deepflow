use std::collections::HashMap;
use std::ptr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    RingBufferBuilder,
};

use profile::bpf::UprobeSkelBuilder;

#[repr(C)]
#[derive(Debug)]
struct MemInfo {
    pid: u32,
    size: u32,
    address: u64,
    duration: u64,
}

#[derive(Debug, Default)]
struct MemStats {
    allocates: u64,
    frees: u64,
    allocated_bytes: u64,
    freed_bytes: u64,
}

pub fn main() {
    let mut args = std::env::args();
    let Some(pid) = args.nth(1).and_then(|p| p.parse::<u32>().ok()) else {
        eprintln!("no pid");
        return;
    };

    let skel_builder = UprobeSkelBuilder::default();
    let open_skel = skel_builder.open().unwrap();
    let mut skel = open_skel.load().unwrap();
    let mut linked = vec![];
    for prog in skel.object_mut().progs_iter_mut() {
        println!("attaching {}", prog.name());
        match prog.attach() {
            Ok(link) => linked.push(link),
            Err(e) => eprintln!("attaching {} failed: {}", prog.name(), e),
        }
    }

    let mut mem_by_addr = HashMap::new();
    let mem_stats = Arc::new(Mutex::new(HashMap::new()));
    let mem_stats_for_cb = mem_stats.clone();
    let mut maps = skel.maps_mut();
    let mut ring_buf = RingBufferBuilder::new();

    ring_buf
        .add(maps.memperf_output(), |v| {
            let info: MemInfo = unsafe { ptr::read(v.as_ptr() as *const _) };
            let mut mem_stats = mem_stats_for_cb.lock().unwrap();
            let stats = mem_stats.entry(info.pid).or_insert(MemStats::default());
            if info.size > 0 {
                mem_by_addr.insert(info.address, info.size);
                stats.allocates += 1;
                stats.allocated_bytes += info.size as u64;
                println!("{} bytes allocated in {}ns", info.size, info.duration);
            } else if let Some(size) = mem_by_addr.get(&info.address) {
                stats.frees += 1;
                stats.freed_bytes += *size as u64;
            } else {
                eprintln!("mem addr {} not found", info.address);
            }
            0
        })
        .unwrap();
    let ring_buf = ring_buf.build().unwrap();

    println!("done");

    loop {
        let _ = ring_buf.poll(Duration::from_secs(10));
        {
            let mem_stats = mem_stats_for_cb.lock().unwrap();
            for (pid, stats) in mem_stats.iter() {
                println!("{pid}: {stats:?}");
            }
            println!("--------");
        }
    }
}
