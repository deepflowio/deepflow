/*
 * Copyright (c) 2023 Yunshan Networks
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

mod consts;
pub mod decapsulate;
pub mod ebpf;
pub mod endpoint;
mod error;
pub mod feature;
pub mod flow;
pub mod l7_protocol_info;
pub mod l7_protocol_log;
pub mod lookup_key;
pub mod matched_field;
pub mod meta_packet;
pub mod platform_data;
pub mod policy;
pub mod port_range;
pub mod proc_event;
pub(crate) mod tag;
pub mod tagged_flow;
pub mod tap_port;
pub mod tap_types;
pub mod timestamp;

pub use consts::*;
pub use feature::FeatureFlags;
pub use meta_packet::MetaPacket;
pub use platform_data::PlatformData;
pub use public::enums;
pub use tagged_flow::TaggedFlow;
pub use tap_port::TapPort;
pub use tap_types::TapTyper;
pub use timestamp::{timestamp_to_micros, Timestamp};

use std::{
    fmt,
    hash::{Hash, Hasher},
    net::Ipv4Addr,
    sync::Arc,
};

use num_enum::IntoPrimitive;

use crate::common::policy::Acl;
use public::proto::common::TridentType;

use policy::{Cidr, Container, IpGroupData, PeerConnection};

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

#[derive(Debug, PartialEq, Clone, Copy, IntoPrimitive)]
#[repr(u16)]
pub enum FlowAclListenerId {
    Policy = 0,
    NpbBandWatcher = 1,
    EbpfDispatcher = 2,
    // There are multiple Dispatcher in Agent, and Dispatcher ID increases from FlowAclListenerId::Dispatcher.
    // FlowAclListenerId::Dispatcher must be the last one.
    Dispatcher = 3,
}

pub trait FlowAclListener: Send + Sync {
    fn flow_acl_change(
        &mut self,
        trident_type: TridentType,
        local_epc: i32,
        ip_groups: &Vec<Arc<IpGroupData>>,
        platform_data: &Vec<Arc<PlatformData>>,
        peers: &Vec<Arc<PeerConnection>>,
        cidrs: &Vec<Arc<Cidr>>,
        acls: &Vec<Arc<Acl>>,
    ) -> Result<(), String>;
    fn containers_change(&mut self, _: &Vec<Arc<Container>>) {}
    fn id(&self) -> usize;
}
