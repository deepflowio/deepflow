use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bitflags::bitflags;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use num_enum::{IntoPrimitive, TryFromPrimitive};

use super::endpoint::EPC_FROM_DEEPFLOW;
use super::enums::TapType;
use super::error::Error;
use super::matched_field::{MatchedFieldv4, MatchedFieldv6};
use super::port_range::{PortRange, PortRangeList};
use super::{IPV4_MAX_MASK_LEN, IPV6_MAX_MASK_LEN, MIN_MASK_LEN};

use crate::proto::trident;

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

impl From<trident::TapSide> for TapSide {
    fn from(t: trident::TapSide) -> Self {
        match t {
            trident::TapSide::Src => TapSide::SRC,
            trident::TapSide::Dst => TapSide::DST,
            trident::TapSide::Both => TapSide::ALL,
        }
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

impl From<trident::TunnelType> for NpbTunnelType {
    fn from(t: trident::TunnelType) -> Self {
        match t {
            trident::TunnelType::GreErspan => Self::GreErspan,
            trident::TunnelType::Pcap => Self::Pcap,
            trident::TunnelType::Vxlan => Self::VxLan,
        }
    }
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

impl From<trident::NpbAction> for NpbAction {
    fn from(n: trident::NpbAction) -> Self {
        Self::new(
            n.npb_acl_group_id(),
            n.tunnel_id(),
            n.tunnel_type().into(),
            n.tap_side().into(),
            n.payload_slice() as u16,
        )
    }
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

    pub fn format_npb_action(&mut self) {
        for item in &mut self.npb_actions {
            if item.tap_side() == TapSide::ALL && item.tunnel_type() != NpbTunnelType::Pcap {
                item.set_tap_side(TapSide::SRC);
            }
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

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum GroupType {
    Named = 0,
    Anonymous = 1,
}

impl From<trident::GroupType> for GroupType {
    fn from(t: trident::GroupType) -> Self {
        match t {
            trident::GroupType::Named => Self::Named,
            trident::GroupType::Anonymous => Self::Anonymous,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct IpGroupData {
    pub epc_id: u32,
    pub ips: Vec<IpNet>,
}

impl TryFrom<&trident::Group> for IpGroupData {
    type Error = Error;
    fn try_from(g: &trident::Group) -> Result<Self, Self::Error> {
        if g.ips.is_empty() && g.ip_ranges.is_empty() {
            return Err(Error::ParseIpGroupData(format!(
                "IpGroup({:?}) is invalid, ips and ip-range is none",
                g
            )));
        }

        let mut ips = vec![];
        for s in g.ips.iter() {
            let ip = s.parse::<IpNet>().map_err(|e| {
                Error::ParseIpGroupData(format!("IpGroup({}) parse ip string failed: {}", s, e))
            })?;
            ips.push(ip);
        }
        for ip_range in g.ip_ranges.iter() {
            let ip_peers = match ip_range.split_once('-') {
                Some(p) => p,
                None => {
                    return Err(Error::ParseIpGroupData(format!(
                        "IpGroup ({}) split ip string failed",
                        ip_range
                    )));
                }
            };
            let (start, end) = match (ip_peers.0.parse::<IpAddr>(), ip_peers.1.parse::<IpAddr>()) {
                (Ok(s), Ok(e)) => (s, e),
                _ => {
                    return Err(Error::ParseIpGroupData(format!(
                        "IpGroup ({}, {}) parse ip string failed",
                        ip_peers.0, ip_peers.1
                    )));
                }
            };
            ips.append(&mut ip_range_convert_to_cidr(start, end));
        }

        Ok(IpGroupData {
            epc_id: (g.epc_id() & 0xffff) as u32,
            ips,
        })
    }
}

fn ipv4_range_convert(mut start: u32, end: u32) -> Vec<IpNet> {
    fn v4_get_first_mask(start: u32, end: u32) -> u8 {
        for len in (MIN_MASK_LEN..IPV4_MAX_MASK_LEN).rev() {
            if start & (1 << IPV4_MAX_MASK_LEN - len) != 0 {
                // len继续减少将会使得start不是所在网段的第一个IP
                return len;
            }
            if start | !v4_mask_len_to_netmask(len) >= end
                || start | !v4_mask_len_to_netmask(len - 1) > end
            {
                // len继续减少将会使得网段包含end之后的IP
                return len;
            }
        }
        0
    }

    fn v4_mask_len_to_netmask(mask: u8) -> u32 {
        u32::MAX << IPV4_MAX_MASK_LEN - mask
    }

    fn v4_get_last_ip(ip: u32, mask: u8) -> u32 {
        ip | !v4_mask_len_to_netmask(mask)
    }

    let mut ips = vec![];
    while start <= end {
        let mask_len = v4_get_first_mask(start, end);
        let ip = Ipv4Net::new(Ipv4Addr::from(start), mask_len).unwrap();
        ips.push(ip.into());

        let last_ip = v4_get_last_ip(start, mask_len);
        if last_ip == u32::MAX {
            break;
        }
        let rhs = 1 << IPV4_MAX_MASK_LEN - mask_len;
        start = match start.checked_add(rhs) {
            Some(s) => s,
            None => break,
        };
    }
    ips
}

fn ipv6_range_convert(mut start: u128, end: u128) -> Vec<IpNet> {
    fn v6_get_first_mask(start: u128, end: u128) -> u8 {
        for len in (MIN_MASK_LEN..IPV6_MAX_MASK_LEN).rev() {
            if start & (1 << IPV6_MAX_MASK_LEN - len) != 0 {
                return len;
            }
            if start | !v6_mask_len_to_netmask(len) >= end
                || start | !v6_mask_len_to_netmask(len - 1) > end
            {
                return len;
            }
        }
        0
    }

    fn v6_mask_len_to_netmask(mask: u8) -> u128 {
        u128::MAX << IPV6_MAX_MASK_LEN - mask
    }

    fn v6_get_last_ip(ip: u128, mask: u8) -> u128 {
        ip | !v6_mask_len_to_netmask(mask)
    }

    let mut ips = vec![];

    while start <= end {
        let mask_len = v6_get_first_mask(start, end);
        let ip = Ipv6Net::new(Ipv6Addr::from(start).into(), mask_len).unwrap();
        ips.push(ip.into());

        let last_ip = v6_get_last_ip(start, mask_len);
        if last_ip == u128::MAX {
            break;
        }
        let rhs = 1 << IPV6_MAX_MASK_LEN - mask_len;
        start = match start.checked_add(rhs) {
            Some(s) => s,
            None => break,
        };
    }
    ips
}

pub fn ip_range_convert_to_cidr(start: IpAddr, end: IpAddr) -> Vec<IpNet> {
    match (start, end) {
        (IpAddr::V4(s), IpAddr::V4(e)) => ipv4_range_convert(s.into(), e.into()),
        (IpAddr::V6(s), IpAddr::V6(e)) => ipv6_range_convert(s.into(), e.into()),
        _ => unreachable!(),
    }
}

/*
#[derive(Debug)]
pub struct Acl {
    id: u32,
    tap_type: TapType,
    src_groups: Vec<u16>,
    dst_groups: Vec<u16>,
    src_port_range: Vec<RangeInclusive<u16>>, // 0仅表示采集端口0
    dst_port_range: Vec<RangeInclusive<u16>>, // 0仅表示采集端口0
    proto: IpProtocol,                        // 256表示全采集, 0表示采集采集协议0
    npb_actions: Vec<NpbAction>,
    v4_fields: Vec<MatchNodev4>,
    v6_fields: Vec<MatchNodev6>,
    policy: PolicyData,
}

impl From<trident::FlowAcl> for Acl {
    fn from(mut f: trident::FlowAcl) -> Self {
        Self {
            id: f.id(),
            tap_type: (f.tap_type() as u16).try_into().unwrap_or_default(),
            src_groups: f.src_group_ids.drain(..).map(|id| id as u16).collect(),
            dst_groups: f.dst_group_ids.drain(..).map(|id| id as u16).collect(),
            src_port_range: split_port(f.src_ports()),
            dst_port_range: split_port(f.dst_ports()),
            proto: IpProtocol::try_from(f.protocol() as u8).unwrap_or_default(),
            npb_actions: f.npb_actions.into_iter().map(Into::into).collect(),
            v4_fields: vec![],
            v6_fields: vec![],
            policy: PolicyData::default(),
        }
    }
}
*/

#[derive(Debug)]
pub struct MatchNodev4 {
    matched: MatchedFieldv4,
    matched_mask: MatchedFieldv4,
}

#[derive(Debug)]
pub struct MatchNodev6 {
    matched: MatchedFieldv6,
    matched_mask: MatchedFieldv6,
}

#[derive(Debug, Default)]
pub struct Acl {
    pub id: u32,
    pub tap_type: TapType,
    pub src_groups: Vec<u32>,
    pub dst_groups: Vec<u32>,
    pub src_port_ranges: Vec<PortRange>, // 0仅表示采集端口0
    pub dst_port_ranges: Vec<PortRange>, // 0仅表示采集端口0
    pub proto: u16,                      // 256表示全采集, 0表示采集采集协议0

    pub npb_actions: Vec<NpbAction>,
    pub policy: PolicyData,
    // TODO: DDBS
}

// 这个函数不安全，仅用于测试和debug
/*
impl From<trident::FlowAcl> for Acl {
    fn from(mut f: trident::FlowAcl) -> Self {
        Self {
            id: f.id(),
            tap_type: (f.tap_type() as u16).try_into().unwrap_or_default(),
            src_groups: f.src_group_ids.drain(..).map(|id| id as u16).collect(),
            dst_groups: f.dst_group_ids.drain(..).map(|id| id as u16).collect(),
            src_port_ranges: PortRangeList::try_from(f.src_ports.unwrap_or_default()).unwrap().element().to_vec(),
            dst_port_ranges: PortRangeList::try_from(f.dst_ports.unwrap_or_default()).unwrap().element().to_vec(),
            proto: f.protocol() as u16,
            npb_actions: f.npb_actions.into_iter().map(Into::into).collect(),
            policy: PolicyData::default(),
        }
    }
}
*/

impl TryFrom<trident::FlowAcl> for Acl {
    type Error = String;

    fn try_from(a: trident::FlowAcl) -> Result<Self, Self::Error> {
        let tap_type = TapType::try_from((a.tap_type.unwrap_or_default() & 0xff) as u16);
        if tap_type.is_err() {
            return Err(format!(
                "Acl tap_type parse error: {:?}.\n",
                tap_type.unwrap_err()
            ));
        }
        let src_ports = PortRangeList::try_from(a.src_ports.unwrap_or_default());
        if src_ports.is_err() {
            return Err(format!(
                "Acl src port parse error: {:?}.\n",
                src_ports.unwrap_err()
            ));
        }
        let dst_ports = PortRangeList::try_from(a.dst_ports.unwrap_or_default());
        if dst_ports.is_err() {
            return Err(format!(
                "Acl dst port parse error: {:?}.\n",
                dst_ports.unwrap_err()
            ));
        }
        Ok(Acl {
            id: a.id.unwrap_or_default(),
            tap_type: tap_type.unwrap(),
            src_groups: a
                .src_group_ids
                .iter()
                .map(|x| (x & 0xffff) as u32)
                .collect(),
            dst_groups: a
                .dst_group_ids
                .iter()
                .map(|x| (x & 0xffff) as u32)
                .collect(),
            src_port_ranges: src_ports.unwrap().element().to_vec(),
            dst_port_ranges: dst_ports.unwrap().element().to_vec(),
            proto: (a.protocol.unwrap_or_default() & 0xffff) as u16,
            ..Default::default()
        })
    }
}

impl fmt::Display for Acl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id:{} TapType:{} SrcGroups:{:?} DstGroups:{:?} SrcPortRange:{:?} DstPortRange:{:?} Proto:{} NpbActions:{:?}",
            self.id, self.tap_type, self.src_groups, self.dst_groups, self.src_port_ranges, self.dst_port_ranges, self.proto, self.npb_actions)
    }
}

/*
pub fn split_port(src: impl AsRef<str>) -> Vec<RangeInclusive<u16>> {
    fn get_port(src: &str) -> Result<RangeInclusive<u16>, ParseIntError> {
        let split_src_ports = match src.split_once('-') {
            Some(p) => p,
            None => {
                let port = src.parse::<u32>()?;
                return Ok(port as u16..=port as u16);
            }
        };
        let min = split_src_ports.0.parse::<u32>()?;
        let max = split_src_ports.1.parse::<u32>()?;

        Ok(min as u16..=max as u16)
    }

    let port_ranges = src.as_ref();
    if port_ranges.len() == 0 {
        return vec![(0..=65535)];
    }

    let mut src_ports = port_ranges
        .split(',')
        .filter_map(|p| get_port(p).ok())
        .collect::<Vec<_>>();
    src_ports.sort_by(|a, b| a.start().cmp(b.start()));

    let mut retain_flags = vec![true; src_ports.len()];
    for i in 0..src_ports.len() - 1 {
        // 合并连续的端口号
        if *src_ports[i].end() + 1 >= *src_ports[i + 1].start() {
            src_ports[i + 1] =
                *src_ports[i].start()..=max(*src_ports[i].end(), *src_ports[i + 1].end());
            retain_flags[i] = false;
        }
    }

    // 删除无效数据
    let mut iter = retain_flags.into_iter();
    src_ports.retain(|_| iter.next().unwrap());
    src_ports
}
*/

// IsVIP为true时不影响cidr epcid表的建立, 但是会单独建立VIP表
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub ip: IpNet,
    pub tunnel_id: u32,
    pub epc_id: i32,
    pub cidr_type: CidrType,
    pub is_vip: bool,
    pub region_id: u32,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum CidrType {
    Wan = 1,
    Lan = 2,
}

impl From<trident::CidrType> for CidrType {
    fn from(t: trident::CidrType) -> Self {
        match t {
            trident::CidrType::Lan => CidrType::Lan,
            trident::CidrType::Wan => CidrType::Wan,
        }
    }
}

impl TryFrom<&trident::Cidr> for Cidr {
    type Error = Error;
    fn try_from(c: &trident::Cidr) -> Result<Self, Self::Error> {
        if c.prefix.is_none() {
            return Err(Error::ParseCidr(format!("Cidr({:?}) is invalid", &c)));
        }
        let ip: IpNet = c.prefix().parse().map_err(|_| {
            Error::ParseCidr(format!("Cidr({:?}) has invalid prefix({})", c, c.prefix()))
        })?;

        let mut epc_id = c.epc_id();
        if epc_id > 0 {
            epc_id &= 0xffff;
        } else if epc_id == 0 {
            epc_id = EPC_FROM_DEEPFLOW;
        }

        Ok(Cidr {
            ip,
            tunnel_id: c.tunnel_id(),
            epc_id,
            cidr_type: c.r#type().into(),
            is_vip: c.is_vip(),
            region_id: c.region_id(),
        })
    }
}

impl Cidr {
    pub fn netmask_len(&self) -> u8 {
        match self.ip {
            IpNet::V4(ip) => ip.prefix_len(),
            IpNet::V6(ip) => ip.prefix_len(),
        }
    }
}

impl Default for Cidr {
    fn default() -> Self {
        Self {
            ip: Ipv4Net::from(Ipv4Addr::UNSPECIFIED).into(),
            tunnel_id: 0,
            epc_id: 0,
            region_id: 0,
            cidr_type: CidrType::Lan,
            is_vip: false,
        }
    }
}

#[derive(Debug, Default)]
pub struct PeerConnection {
    pub id: u32,
    pub local_epc: i32,
    pub remote_epc: i32,
}

impl From<&trident::PeerConnection> for PeerConnection {
    fn from(p: &trident::PeerConnection) -> Self {
        Self {
            id: p.id(),
            local_epc: (p.local_epc_id() & 0xffff) as i32,
            remote_epc: (p.remote_epc_id() & 0xffff) as i32,
        }
    }
}
