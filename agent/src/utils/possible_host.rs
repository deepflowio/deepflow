use std::net::{IpAddr, Ipv6Addr};

use lru::LruCache;
pub struct PossibleHost(LruCache<u64, bool>);

impl PossibleHost {
    pub fn new(capacity: usize) -> Self {
        PossibleHost(LruCache::new(capacity))
    }

    fn get_ip6_hash(ip6: &Ipv6Addr) -> u32 {
        let mut hash1 = 0 as u16;
        let mut hash2 = 0 as u16;
        let segs = ip6.segments();
        for i in (0..8).step_by(2) {
            hash1 ^= segs[i];
            hash2 ^= segs[i + 1];
        }
        (hash1 as u32) << 16 | hash2 as u32
    }

    fn gen_key(host: &IpAddr, epc_id: i32) -> u64 {
        match host {
            IpAddr::V4(ip4) => {
                u32::from_le_bytes(ip4.octets()) as u64 | ((epc_id & 0xffff) as u64) << 32
            }
            IpAddr::V6(ip6) => {
                1u64 << 48 | ((epc_id & 0xffff) as u64) << 32 | Self::get_ip6_hash(ip6) as u64
            }
        }
    }

    pub fn add(&mut self, host: &IpAddr, epc_id: i32) {
        self.0.put(Self::gen_key(host, epc_id), true);
    }

    pub fn check(&mut self, host: &IpAddr, epc_id: i32) -> bool {
        self.0.get(&Self::gen_key(host, epc_id)).is_some()
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }
}
