/*
 * Copyright (c) 2024 Yunshan Networks
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

//! Enterprise Edition Feature: policy
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use bitflags::bitflags;

use num_enum::{IntoPrimitive, TryFromPrimitive};

pub const NOT_SUPPORT: bool = true;

bitflags! {
    #[derive(Default)]
    pub struct TapSide: u8 {
        const NONE = 0;
        const SRC = 0x1;
        const DST = 0x2;
        const MASK = Self::SRC.bits | Self::DST.bits;
        const ALL = Self::SRC.bits | Self::DST.bits;
    }
}

impl From<DirectionType> for TapSide {
    fn from(_d: DirectionType) -> Self {
        TapSide::NONE
    }
}

impl TapSide {
    pub fn new(_flags: u8) -> Self {
        TapSide::NONE
    }
}

bitflags! {
    #[derive(Default)]
    pub struct ActionFlags: u8 {
        const NONE = 0;
        const PCAP = 0x1;
        const NPB = 0x2;
        const NPB_DROP = 0x4;
    }
}

bitflags! {
    pub struct DirectionType: u8 {
        const FORWARD = 0x1;
        const BACKWARD = 0x2;
        const ALL = 0x3;
    }
}

impl From<TapSide> for DirectionType {
    fn from(_d: TapSide) -> Self {
        DirectionType::ALL
    }
}

impl Default for DirectionType {
    fn default() -> Self {
        Self::ALL
    }
}

impl DirectionType {
    pub fn new(_: u8) -> Self {
        Self::ALL
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum NpbTunnelType {
    VxLan,
    GreErspan,
    Pcap,
    NpbDrop,
    TcpNpb,
    Max,
}

impl NpbTunnelType {
    pub fn new(_flags: u8) -> Self {
        Self::VxLan
    }
}

#[derive(Debug, Clone)]
pub struct NpbAction {
    acl_gids: Vec<u16>,
    tunnel_ip_ids: Vec<u16>,
}

impl Default for NpbAction {
    fn default() -> Self {
        Self {
            acl_gids: vec![],
            tunnel_ip_ids: vec![],
        }
    }
}

impl NpbAction {
    pub fn new(
        acl_gid: u32,
        _id: u32,
        _tunnel_ip: IpAddr,
        tunnel_ip_id: u16,
        _tunnel_type: NpbTunnelType,
        _tap_side: TapSide,
        _direction_capacity: DirectionType,
        _slice: u16,
    ) -> Self {
        Self {
            acl_gids: vec![acl_gid as u16],
            tunnel_ip_ids: vec![tunnel_ip_id],
        }
    }

    pub const fn tap_side(&self) -> TapSide {
        TapSide::SRC
    }

    pub const fn tunnel_id(&self) -> u32 {
        100
    }

    pub const fn payload_slice(&self) -> usize {
        65535
    }

    pub fn tunnel_type(&self) -> NpbTunnelType {
        NpbTunnelType::VxLan
    }

    pub fn add_acl_gid(&mut self, acl_gids: &[u16], tunnel_ip_ids: &[u16]) {
        acl_gids.into_iter().for_each(|x| self.acl_gids.push(*x));
        tunnel_ip_ids
            .into_iter()
            .for_each(|x| self.tunnel_ip_ids.push(*x));
    }

    pub fn acl_gids(&self) -> &[u16] {
        self.acl_gids.as_ref()
    }

    pub fn tunnel_ip(&self) -> IpAddr {
        IpAddr::from(Ipv4Addr::UNSPECIFIED)
    }

    pub fn tunnel_ip_ids(&self) -> &[u16] {
        &self.tunnel_ip_ids
    }

    pub fn reverse_tap_side(&mut self) {}

    pub fn set_payload_slice(&mut self, _payload_slice: u16) {}

    pub fn add_tap_side(&mut self, _tap_side: TapSide) {}

    pub fn set_tap_side(&mut self, _tap_side: TapSide) {}
}

impl fmt::Display for NpbAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Not support.")
    }
}

#[derive(Debug, Default, Clone)]
pub struct PolicyData {
    pub npb_actions: Vec<NpbAction>,
    pub acl_id: u32,
    pub action_flags: ActionFlags,
}

impl fmt::Display for PolicyData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl PolicyData {
    pub fn new(npb_actions: Vec<NpbAction>, acl_id: u32) -> Self {
        let mut policy = Self {
            npb_actions: npb_actions.clone(),
            acl_id,
            ..Default::default()
        };
        for action in &npb_actions {
            policy.set_action_flags(action);
        }
        return policy;
    }

    pub fn contain_npb(&self) -> bool {
        self.acl_id > 0
            && self.action_flags.contains(ActionFlags::NPB)
            && !self.action_flags.contains(ActionFlags::NPB_DROP)
    }

    pub fn contain_pcap(&self) -> bool {
        self.acl_id > 0 && self.action_flags.contains(ActionFlags::PCAP)
    }

    pub fn format_npb_action(&mut self) {}

    pub fn merge_and_dedup_npb_actions(
        &mut self,
        actions: &Vec<NpbAction>,
        acl_id: u32,
        reverse: bool,
    ) {
        self.acl_id = acl_id;
        actions.into_iter().for_each(|x| {
            let mut action = x.clone();
            if reverse {
                action.reverse_tap_side();
            }
            self.npb_actions.push(action)
        })
    }

    pub fn merge_npb_actions(
        &mut self,
        actions: &Vec<NpbAction>,
        acl_id: u32,
        direction: DirectionType,
    ) {
        self.acl_id = acl_id;
        let tap_side = TapSide::from(direction);
        actions.into_iter().for_each(|x| {
            let mut action = x.clone();
            action.set_tap_side(tap_side);
            self.npb_actions.push(action)
        })
    }

    pub fn merge_reverse_npb_action(&mut self, actions: &Vec<NpbAction>, acl_id: u32) {
        self.acl_id = acl_id;
        actions.into_iter().for_each(|x| {
            let mut action = x.clone();
            action.reverse_tap_side();
            self.npb_actions.push(action)
        })
    }

    // return true if policy have changes
    pub fn dedup(&mut self, _: &dyn DedupOperator) -> bool {
        false
    }

    pub fn set_action_flags(&mut self, _actions: &NpbAction) {}
}

pub trait DedupOperator: Send + Sync {
    fn is_tor(&self) -> bool;
    fn is_valid(&self, tap_side: TapSide) -> bool;
}
