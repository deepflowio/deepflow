mod consts;
pub mod decapsulate;
pub mod endpoint;
pub mod enums;
pub mod flow;
pub mod lookup_key;
mod matched_field;
pub mod meta_packet;
pub mod platform_data;
pub mod policy;
mod tag;
pub mod tagged_flow;
pub mod tap_port;
mod tap_types;

pub use consts::*;

use std::{
    fmt,
    hash::{Hash, Hasher},
    net::Ipv4Addr,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct XflowKey {
    ip: Ipv4Addr,
    tap_idx: u32,
}

impl Hash for XflowKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let key = ((u32::from(self.ip) as u64) << 32) + self.tap_idx as u64;
        key.hash(state)
    }
}

impl fmt::Display for XflowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "source_ip:{}, interface_index:{}", self.ip, self.tap_idx)
    }
}
