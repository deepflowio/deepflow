mod consts;
mod decapsulate;
mod endpoint;
mod enums;
mod flow;
mod lookup_key;
mod matched_field;
mod meta_packet;
mod platform_data;
mod policy;
mod tag;
mod tagged_flow;
mod tap_port;
mod tap_types;
pub use consts::*;

pub use decapsulate::{TunnelInfo, TunnelType};
pub use endpoint::{EndpointData, FeatureFlags};
pub use enums::*;
pub use flow::FlowMetricsPeer;
pub use lookup_key::LookupKey;
pub use platform_data::PlatformData;
pub use policy::{DirectionType, PolicyData};
pub use tap_port::TapPort;

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
