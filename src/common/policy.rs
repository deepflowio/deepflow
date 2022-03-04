use bitflags::bitflags;
use num_enum::{IntoPrimitive, TryFromPrimitive};

const ACTION_PCAP: u16 = 1;

type ActionFlag = u16;

bitflags! {
    #[derive(Default)]
    pub struct TapSide: u8 {
        const SRC = 0x1;
        const DST = 0x2;
        const MASK = Self::SRC.bits | Self::DST.bits;
        const ALL = Self::SRC.bits | Self::DST.bits;
    }
}

#[derive(TryFromPrimitive, IntoPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum DirectionType {
    NoDirection = 0,
    Forward = 1,
    Backward = 2,
}

impl From<DirectionType> for TapSide {
    fn from(d: DirectionType) -> Self {
        match d {
            DirectionType::Forward => TapSide::SRC,
            DirectionType::Backward => TapSide::DST,
            _ => TapSide::empty(),
        }
    }
}

impl Default for DirectionType {
    fn default() -> Self {
        Self::NoDirection
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum NpbTunnelType {
    VxLan,
    GreErspan,
    Pcap,
}

// 64              48              32            30          26                      0
// +---------------+---------------+-------------+-----------+-----------------------+
// |   acl_gid     | payload_slice | tunnel_type | tap_side  |      tunnel_id        |
// +---------------+---------------+-------------+-----------+-----------------------+
#[derive(Debug, Default, Clone)]
pub struct NpbAction {
    action: u64,
    acl_gids: Vec<u16>,
}

impl NpbAction {
    const PAYLOAD_SLICE_MASK: u64 = 0xffff;
    const TUNNEL_ID_MASK: u64 = 0x3ffffff;
    const TUNNEL_TYPE_MASK: u64 = 0x3;

    pub fn new(
        acl_gid: u32,
        id: u32,
        tunnel_type: NpbTunnelType,
        tap_side: TapSide,
        slice: u16,
    ) -> Self {
        Self {
            action: (acl_gid as u64) << 48
                | (slice as u64 & Self::PAYLOAD_SLICE_MASK) << 32
                | (u8::from(tunnel_type) as u64) << 30
                | (tap_side.bits() as u64) << 26
                | id as u64 & Self::TUNNEL_ID_MASK,
            acl_gids: vec![],
        }
    }

    pub const fn tap_side(&self) -> TapSide {
        TapSide::from_bits_truncate((self.action >> 26) as u8 & TapSide::MASK.bits)
    }

    pub const fn tunnel_id(&self) -> u32 {
        (self.action & Self::TUNNEL_ID_MASK) as u32
    }

    pub const fn payload_slice(&self) -> u16 {
        (self.action >> 32 & Self::PAYLOAD_SLICE_MASK) as u16
    }

    pub fn tunnel_type(&self) -> NpbTunnelType {
        NpbTunnelType::try_from((self.action >> 30 & Self::TUNNEL_TYPE_MASK) as u8).unwrap()
    }

    pub fn add_acl_gid(&mut self, acl_gids: &[u16]) {
        for gid in acl_gids {
            if self.acl_gids.contains(gid) {
                continue;
            }
            self.acl_gids.push(*gid);
        }
    }

    /// Get a reference to the npb actions's acl gids.
    pub fn acl_gids(&self) -> &[u16] {
        self.acl_gids.as_ref()
    }

    pub fn tunnel_ip_id(&self) -> u16 {
        if self.tunnel_type() == NpbTunnelType::Pcap {
            return 0;
        }

        todo!("get tunnel ip id")
    }

    pub fn set_payload_slice(&mut self, payload_slice: u16) {
        self.action ^= !(Self::PAYLOAD_SLICE_MASK << 32);
        self.action |= (payload_slice as u64 & Self::PAYLOAD_SLICE_MASK) << 32;
    }

    pub fn add_tap_side(&mut self, tap_side: TapSide) {
        self.action |= (tap_side.bits() as u64) << 26;
    }

    pub fn set_tap_side(&mut self, tap_side: TapSide) {
        self.action ^= !((TapSide::MASK.bits() as u64) << 26);
        self.action |= (tap_side.bits() as u64) << 26;
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

    pub fn merge_npb_action(
        &mut self,
        actions: Vec<NpbAction>,
        acl_id: u32,
        directions: Vec<DirectionType>,
    ) {
        if self.acl_id == 0 {
            self.acl_id = acl_id;
        }

        for mut candidate_action in actions {
            let mut repeat = false;
            for action in self.npb_actions.iter_mut() {
                if action.action == candidate_action.action {
                    action.add_acl_gid(candidate_action.acl_gids());
                    repeat = true;
                    break;
                }

                if action.tunnel_ip_id() != candidate_action.tunnel_ip_id()
                    || action.tunnel_id() != candidate_action.tunnel_id()
                    || action.tunnel_type() != candidate_action.tunnel_type()
                {
                    continue;
                }
                // PCAP相同aclgid的合并为一个，不同aclgid的不能合并
                if candidate_action.tunnel_type() == NpbTunnelType::Pcap {
                    // 应该有且仅有一个
                    let mut repeat_pcap_acl_gid = false;
                    if let Some(acl_gid) = candidate_action.acl_gids().first() {
                        if action.acl_gids().contains(acl_gid) {
                            repeat_pcap_acl_gid = true;
                        }
                    }
                    if !repeat_pcap_acl_gid {
                        continue;
                    }
                }

                if candidate_action.payload_slice() == 0
                    || candidate_action.payload_slice() > action.payload_slice()
                {
                    action.set_payload_slice(candidate_action.payload_slice());
                }

                if directions.is_empty() {
                    action.add_tap_side(candidate_action.tap_side());
                } else {
                    action.set_tap_side(directions[0].into());
                }
                action.add_acl_gid(candidate_action.acl_gids());
                repeat = true;
            }

            if !repeat {
                if !directions.is_empty() {
                    candidate_action.set_tap_side(directions[0].into());
                }
                if candidate_action.tunnel_type() == NpbTunnelType::Pcap {
                    self.action_flags |= ACTION_PCAP;
                }

                self.npb_actions.push(candidate_action);
            }
        }
    }
}
