/*
 * Copyright (c) 2022 Yunshan Networks
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

type ActionFlag = u16;

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

impl TapSide {
    pub fn new(_flags: u8) -> Self {
        TapSide::NONE
    }
}

#[derive(TryFromPrimitive, IntoPrimitive, Clone, Copy, Debug)]
#[repr(u8)]
pub enum DirectionType {
    NoDirection = 0,
    Forward = 1,
    Backward = 2,
}

impl From<DirectionType> for TapSide {
    fn from(_d: DirectionType) -> Self {
        TapSide::NONE
    }
}

impl Default for DirectionType {
    fn default() -> Self {
        Self::NoDirection
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum NpbTunnelType {
    VxLan,
}

impl NpbTunnelType {
    pub fn new(_flags: u8) -> Self {
        Self::VxLan
    }
}

#[derive(Debug, Clone)]
pub struct NpbAction {
    acl_gids: Vec<u16>,
}

impl Default for NpbAction {
    fn default() -> Self {
        Self {
            acl_gids: vec![],
        }
    }
}

impl NpbAction {
    pub fn new(
        acl_gid: u32,
        _id: u32,
        _tunnel_ip: IpAddr,
        _tunnel_type: NpbTunnelType,
        _tap_side: TapSide,
        _slice: u16,
    ) -> Self {
        Self {
            acl_gids: vec![acl_gid as u16],
        }
    }

    pub const fn tap_side(&self) -> TapSide {
        TapSide::SRC
    }

    pub const fn tunnel_id(&self) -> u32 {
        0
    }

    pub const fn payload_slice(&self) -> u16 {
        65535
    }

    pub fn tunnel_type(&self) -> NpbTunnelType {
        NpbTunnelType::VxLan
    }

    pub fn add_acl_gid(&mut self, acl_gids: &[u16]) {
        acl_gids.into_iter().for_each(|x| self.acl_gids.push(*x));
    }

    pub fn acl_gids(&self) -> &[u16] {
        self.acl_gids.as_ref()
    }

    pub fn tunnel_ip(&self) -> IpAddr {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    }

    pub fn set_payload_slice(&mut self, _payload_slice: u16) {
    }

    pub fn add_tap_side(&mut self, _tap_side: TapSide) {
    }

    pub fn set_tap_side(&mut self, _tap_side: TapSide) {
    }
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
    pub action_flags: ActionFlag,
}

impl PolicyData {
    pub fn new(npb_actions: Vec<NpbAction>, acl_id: u32, action_flags: ActionFlag) -> Self {
        Self {
            npb_actions,
            acl_id,
            action_flags,
        }
    }

    pub fn format_npb_action(&mut self) {
    }

    pub fn merge_npb_action(
        &mut self,
        actions: &Vec<NpbAction>,
        acl_id: u32,
        _directions: Vec<DirectionType>,
    ) {
        self.acl_id = acl_id;
        actions.into_iter().for_each(|x| {
            self.npb_actions.push(x.clone())
        })
    }

    fn dedup_npb_actions(&self, _packet: &dyn DedupOperator) -> Vec<NpbAction> {
        vec![]
    }

    pub fn dedup(&mut self, packet: &dyn DedupOperator) {
        let _ = self.dedup_npb_actions(packet);
    }
}

pub trait DedupOperator: Send + Sync {
    fn is_tor(&self) ->bool;
    fn is_valid(&self, tap_side: TapSide) ->bool;
}
