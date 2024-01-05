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

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use log::warn;
use num_enum::{IntoPrimitive, TryFromPrimitive};

use super::endpoint::EPC_FROM_DEEPFLOW;
use super::enums::{IpProtocol, TapType};
use super::error::Error;
use super::matched_field::{MatchedFieldv4, MatchedFieldv6, MatchedFlag};
use super::port_range::{PortRange, PortRangeList};
use super::{IPV4_MAX_MASK_LEN, IPV6_MAX_MASK_LEN, MIN_MASK_LEN};
use npb_pcap_policy::{DirectionType, NpbAction, NpbTunnelType, PolicyData, TapSide};

use public::proto::trident;

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
    pub id: u16,
    pub epc_id: u16,
    pub ips: Vec<IpNet>,
}

impl IpGroupData {
    pub fn new(id: u16, epc_id: u16, cidr: &str) -> Self {
        IpGroupData {
            id,
            epc_id,
            ips: vec![cidr.parse().unwrap()],
        }
    }
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
            epc_id: (g.epc_id() & 0xffff) as u16,
            ips,
            id: (g.id() & 0xffff) as u16,
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

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub struct PortSegment {
    port: u16,
    mask: u16,
}

impl PortSegment {
    pub const ALL: PortSegment = PortSegment { port: 0, mask: 0 };

    fn calc_right_zero(port: u16) -> u16 {
        let mut count = 0;
        for i in 0..u16::BITS {
            if (port >> i) & 0x1 != 0 {
                return count;
            }
            count += 1;
        }
        return count;
    }

    fn calc_mask(port: u16, max_port: u16, count: u16) -> (u16, u16) {
        for i in 0..count {
            if max_port >= port + (((1u32 << (count - i)) - 1) as u16) {
                return (((u16::MAX as u32) << (count - i)) as u16, count - i);
            }
        }
        return (u16::MAX, 0);
    }

    fn new(port: &PortRange) -> Vec<PortSegment> {
        let mut port_segments = Vec::new();

        let mut i = port.min() as usize;
        while i < port.max() as usize + 1 {
            let n = Self::calc_right_zero(i as u16);
            let (mask, n) = Self::calc_mask(i as u16, port.max(), n);

            port_segments.push(PortSegment {
                port: i as u16,
                mask,
            });

            i += 1 << n;
            if i == 0 {
                break;
            }
        }

        return port_segments;
    }
}

#[derive(Debug, Copy, Clone)]
pub struct IpSegment {
    ip: IpAddr,
    mask: IpAddr,
    epc_id: u16,
}

impl Default for IpSegment {
    fn default() -> Self {
        Self {
            ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            mask: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            epc_id: 0,
        }
    }
}

impl From<IpNet> for IpSegment {
    fn from(cidr: IpNet) -> Self {
        IpSegment::from(&cidr)
    }
}

impl From<&IpNet> for IpSegment {
    fn from(cidr: &IpNet) -> Self {
        match (cidr.network().is_ipv4(), cidr.netmask().is_ipv4()) {
            (true, true) | (false, false) => IpSegment {
                ip: cidr.network(),
                mask: cidr.netmask(),
                ..Default::default()
            },
            _ => {
                panic!("Cidr({:?}) network and netmask mismatched", cidr)
            }
        }
    }
}

impl IpSegment {
    pub const IPV4_ANY: IpSegment = IpSegment::new_zero(false);
    pub const IPV6_ANY: IpSegment = IpSegment::new_zero(true);

    const fn new_zero(is_ipv6: bool) -> Self {
        Self {
            ip: if is_ipv6 {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            },
            mask: if is_ipv6 {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            },
            epc_id: 0,
        }
    }

    fn new<T: AsRef<str>>(cidr: T, epc_id: u16) -> Option<Self> {
        let ip_net = IpNet::from_str(cidr.as_ref());
        if ip_net.is_err() {
            warn!("Cidr {} EPC {} parse error.", cidr.as_ref(), epc_id);
            return None;
        }
        let mut ip_segment = IpSegment::from(ip_net.unwrap());
        ip_segment.epc_id = epc_id;
        return Some(ip_segment);
    }

    pub fn get_epc_id(&self) -> u16 {
        return self.epc_id;
    }

    pub fn set_epc_id(&mut self, epc_id: u16) {
        self.epc_id = epc_id;
    }

    pub fn get_ip(&self) -> IpAddr {
        return self.ip;
    }

    pub fn get_mask(&self) -> IpAddr {
        return self.mask;
    }

    pub fn is_ipv6(&self) -> bool {
        return self.ip.is_ipv6();
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct Fieldv4 {
    pub field: MatchedFieldv4,
    pub mask: MatchedFieldv4,
}

impl Fieldv4 {
    pub const SIZE: usize = MatchedFieldv4::SIZE * 2;

    pub fn get_all_table_index(
        &self,
        mask_vector: &MatchedFieldv4,
        min: usize,
        max: usize,
        vector_bits: &Vec<usize>,
    ) -> Vec<u16> {
        self.field
            .get_all_table_index(mask_vector, &self.mask, min, max, vector_bits)
    }
}

impl fmt::Display for Fieldv4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "field: {}:{} -> {}:{} epc: {} -> {} proto: {} tap: {}\nmask : {}:{} -> {}:{} epc: {} -> {} proto: {} tap: {}",
            self.field.get_ip(MatchedFlag::SrcIp),
            self.field.get(MatchedFlag::SrcPort),
            self.field.get_ip(MatchedFlag::DstIp),
            self.field.get(MatchedFlag::DstPort),
            self.field.get(MatchedFlag::SrcEpc),
            self.field.get(MatchedFlag::DstEpc),
            self.field.get(MatchedFlag::Proto),
            self.field.get(MatchedFlag::TapType),
            self.mask.get_ip(MatchedFlag::SrcIp),
            self.mask.get(MatchedFlag::SrcPort),
            self.mask.get_ip(MatchedFlag::DstIp),
            self.mask.get(MatchedFlag::DstPort),
            self.mask.get(MatchedFlag::SrcEpc),
            self.mask.get(MatchedFlag::DstEpc),
            self.mask.get(MatchedFlag::Proto),
            self.mask.get(MatchedFlag::TapType)
        )
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct Fieldv6 {
    pub field: MatchedFieldv6,
    pub mask: MatchedFieldv6,
}

impl Fieldv6 {
    pub const SIZE: usize = MatchedFieldv6::SIZE * 2;

    pub fn get_all_table_index(
        &self,
        mask_vector: &MatchedFieldv6,
        min: usize,
        max: usize,
        vector_bits: &Vec<usize>,
    ) -> Vec<u16> {
        self.field
            .get_all_table_index(mask_vector, &self.mask, min, max, vector_bits)
    }
}

impl fmt::Display for Fieldv6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "field: {}:{} -> {}:{} epc: {} -> {} proto: {} tap: {}\nmask : {}:{} -> {}:{} epc: {} -> {} proto: {} tap: {}",
            self.field.get_ip(MatchedFlag::SrcIp),
            self.field.get(MatchedFlag::SrcPort),
            self.field.get_ip(MatchedFlag::DstIp),
            self.field.get(MatchedFlag::DstPort),
            self.field.get(MatchedFlag::SrcEpc),
            self.field.get(MatchedFlag::DstEpc),
            self.field.get(MatchedFlag::Proto),
            self.field.get(MatchedFlag::TapType),
            self.mask.get_ip(MatchedFlag::SrcIp),
            self.mask.get(MatchedFlag::SrcPort),
            self.mask.get_ip(MatchedFlag::DstIp),
            self.mask.get(MatchedFlag::DstPort),
            self.mask.get(MatchedFlag::SrcEpc),
            self.mask.get(MatchedFlag::DstEpc),
            self.mask.get(MatchedFlag::Proto),
            self.mask.get(MatchedFlag::TapType)
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct Acl {
    pub id: u32,
    pub tap_type: TapType,
    pub src_groups: Vec<u32>,
    pub dst_groups: Vec<u32>,
    pub src_port_ranges: Vec<PortRange>, // 0仅表示采集端口0
    pub dst_port_ranges: Vec<PortRange>, // 0仅表示采集端口0

    pub proto: u16, // 256表示全采集, 0表示采集采集协议0

    pub npb_actions: Vec<NpbAction>,

    pub match_field: Vec<Arc<Fieldv4>>,
    pub match_field6: Vec<Arc<Fieldv6>>,

    pub policy: Arc<PolicyData>,
}

impl Acl {
    const PROTOCOL_ANY: u16 = 256;
    pub fn new(
        id: u32,
        src_groups: Vec<u32>,
        dst_groups: Vec<u32>,
        src_port_ranges: Vec<PortRange>,
        dst_port_ranges: Vec<PortRange>,
        actions: NpbAction,
    ) -> Self {
        Acl {
            id,
            tap_type: TapType::Cloud,
            src_groups,
            dst_groups,
            src_port_ranges,
            dst_port_ranges,
            proto: Self::PROTOCOL_ANY,
            npb_actions: vec![actions.clone()],
            policy: Arc::new(PolicyData::new(vec![actions], id)),
            ..Default::default()
        }
    }

    pub fn reset(&mut self) {
        self.match_field.clear();
        self.match_field6.clear();
    }

    fn get_port_range(ports: &Vec<u16>) -> Vec<PortRange> {
        let mut port_ranges = Vec::new();
        let mut min = 0;
        let mut max = 0;

        for (i, port) in ports.iter().enumerate() {
            if i == 0 {
                min = *port;
                max = *port;
                if ports.len() == i + 1 {
                    port_ranges.push(PortRange::new(min, max));
                }
                continue;
            }

            if *port == max + 1 {
                max = *port;
            } else {
                port_ranges.push(PortRange::new(min, max));
            }

            if ports.len() == i + 1 {
                port_ranges.push(PortRange::new(min, max));
            }
        }

        return port_ranges;
    }

    fn generate_port_segment(&self) -> (Vec<PortSegment>, Vec<PortSegment>) {
        let mut src_segments = Vec::new();
        let mut dst_segments = Vec::new();

        for ports in &self.src_port_ranges {
            src_segments.append(&mut PortSegment::new(ports));
        }
        for ports in &self.dst_port_ranges {
            dst_segments.append(&mut PortSegment::new(ports));
        }

        if src_segments.is_empty() {
            src_segments.push(PortSegment::ALL);
        }
        if dst_segments.is_empty() {
            dst_segments.push(PortSegment::ALL);
        }
        return (src_segments, dst_segments);
    }

    pub fn generate_match_field(
        &mut self,
        src_ip: &IpSegment,
        dst_ip: &IpSegment,
        src_ports: &Vec<PortSegment>,
        dst_ports: &Vec<PortSegment>,
    ) {
        if let (
            IpAddr::V4(src_ip4),
            IpAddr::V4(dst_ip4),
            IpAddr::V4(src_mask4),
            IpAddr::V4(dst_mask4),
        ) = (
            src_ip.get_ip(),
            dst_ip.get_ip(),
            src_ip.get_mask(),
            dst_ip.get_mask(),
        ) {
            for src_port in src_ports {
                for dst_port in dst_ports {
                    let mut item = Fieldv4::default();

                    let field = &mut item.field;
                    field.set(MatchedFlag::TapType, u16::from(self.tap_type));
                    field.set_ip(MatchedFlag::SrcIp, src_ip4);
                    field.set(MatchedFlag::SrcEpc, src_ip.get_epc_id());
                    field.set_ip(MatchedFlag::DstIp, dst_ip4);
                    field.set(MatchedFlag::DstEpc, dst_ip.get_epc_id());
                    field.set(MatchedFlag::SrcPort, src_port.port);
                    field.set(MatchedFlag::DstPort, dst_port.port);

                    let mask = &mut item.mask;
                    mask.set_mask(MatchedFlag::TapType, self.tap_type != TapType::Any);
                    mask.set_ip(MatchedFlag::SrcIp, src_mask4);
                    mask.set_mask(MatchedFlag::SrcEpc, src_ip.get_epc_id() > 0);
                    mask.set_ip(MatchedFlag::DstIp, dst_mask4);
                    mask.set_mask(MatchedFlag::DstEpc, dst_ip.get_epc_id() > 0);
                    mask.set(MatchedFlag::SrcPort, src_port.mask);
                    mask.set(MatchedFlag::DstPort, dst_port.mask);

                    if self.proto == Self::PROTOCOL_ANY {
                        item.field.set(MatchedFlag::Proto, 0);
                        item.mask.set(MatchedFlag::Proto, 0);
                    } else {
                        item.field.set(MatchedFlag::Proto, self.proto);
                        item.mask.set_mask(MatchedFlag::Proto, true);
                    }

                    self.match_field.push(Arc::new(item));
                }
            }
        }
    }

    pub fn generate_match_field6(
        &mut self,
        src_ip: &IpSegment,
        dst_ip: &IpSegment,
        src_ports: &Vec<PortSegment>,
        dst_ports: &Vec<PortSegment>,
    ) {
        if let (
            IpAddr::V6(src_ip6),
            IpAddr::V6(dst_ip6),
            IpAddr::V6(src_mask6),
            IpAddr::V6(dst_mask6),
        ) = (
            src_ip.get_ip(),
            dst_ip.get_ip(),
            src_ip.get_mask(),
            dst_ip.get_mask(),
        ) {
            for src_port in src_ports {
                for dst_port in dst_ports {
                    let mut item = Fieldv6::default();

                    let field = &mut item.field;
                    field.set(MatchedFlag::TapType, u16::from(self.tap_type));
                    field.set_ip(MatchedFlag::SrcIp, src_ip6);
                    field.set(MatchedFlag::SrcEpc, src_ip.get_epc_id());
                    field.set_ip(MatchedFlag::DstIp, dst_ip6);
                    field.set(MatchedFlag::DstEpc, dst_ip.get_epc_id());
                    field.set(MatchedFlag::SrcPort, src_port.port);
                    field.set(MatchedFlag::DstPort, dst_port.port);

                    let mask = &mut item.mask;
                    mask.set_mask(MatchedFlag::TapType, self.tap_type != TapType::Any);
                    mask.set_ip(MatchedFlag::SrcIp, src_mask6);
                    mask.set_mask(MatchedFlag::SrcEpc, src_ip.get_epc_id() > 0);
                    mask.set_ip(MatchedFlag::DstIp, dst_mask6);
                    mask.set_mask(MatchedFlag::DstEpc, dst_ip.get_epc_id() > 0);
                    mask.set(MatchedFlag::SrcPort, src_port.mask);
                    mask.set(MatchedFlag::DstPort, dst_port.mask);

                    if self.proto == Self::PROTOCOL_ANY {
                        item.field.set(MatchedFlag::Proto, 0);
                        item.mask.set(MatchedFlag::Proto, 0);
                    } else {
                        item.field.set(MatchedFlag::Proto, self.proto);
                        item.mask.set_mask(MatchedFlag::Proto, true);
                    }

                    self.match_field6.push(Arc::new(item));
                }
            }
        }
    }

    pub fn generate_match(&mut self, src_ips: &Vec<IpSegment>, dst_ips: &Vec<IpSegment>) {
        let (src_ports, dst_ports) = self.generate_port_segment();
        for src_ip in src_ips {
            for dst_ip in dst_ips {
                match (src_ip.is_ipv6(), dst_ip.is_ipv6()) {
                    (true, true) => {
                        self.generate_match_field6(src_ip, dst_ip, &src_ports, &dst_ports)
                    }
                    (false, false) => {
                        self.generate_match_field(src_ip, dst_ip, &src_ports, &dst_ports)
                    }
                    _ => continue,
                }
            }
        }
    }
}

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
        let npb_actions: Vec<NpbAction> = a
            .npb_actions
            .iter()
            .map(|n| {
                NpbAction::new(
                    n.npb_acl_group_id(),
                    n.tunnel_id(),
                    n.tunnel_ip()
                        .parse::<IpAddr>()
                        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                    n.tunnel_ip_id.unwrap_or_default() as u16,
                    NpbTunnelType::new(n.tunnel_type.unwrap() as u8),
                    TapSide::new(n.tap_side.unwrap() as u8),
                    DirectionType::new(n.direction.unwrap_or(1) as u8),
                    n.payload_slice() as u16,
                )
            })
            .collect();

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
            npb_actions: npb_actions.clone(),
            policy: Arc::new(PolicyData::new(npb_actions, a.id.unwrap_or_default())),
            ..Default::default()
        })
    }
}

impl fmt::Display for Acl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id:{} TapType:{} SrcGroups:{:?} DstGroups:{:?} SrcPortRange:[{}] DstPortRange:[{}] Proto:{} NpbActions:{}",
            self.id, self.tap_type, self.src_groups, self.dst_groups,
            self.src_port_ranges.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(", "),
            self.dst_port_ranges.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(", "),
            self.proto, self.npb_actions.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(","))
    }
}

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

#[derive(Debug, PartialEq, Eq, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum GpidProtocol {
    Tcp = 0,
    Udp = 1,
    Max = 2,
}

impl TryFrom<trident::ServiceProtocol> for GpidProtocol {
    type Error = Error;

    fn try_from(value: trident::ServiceProtocol) -> Result<Self, Self::Error> {
        match value {
            trident::ServiceProtocol::Any => Err(Error::ParseGpid(format!(
                "Parse GPIDEntry error: {:?}",
                value
            ))),
            trident::ServiceProtocol::TcpService => Ok(GpidProtocol::Tcp),
            trident::ServiceProtocol::UdpService => Ok(GpidProtocol::Udp),
        }
    }
}

impl TryFrom<IpProtocol> for GpidProtocol {
    type Error = Error;

    fn try_from(value: IpProtocol) -> Result<Self, Self::Error> {
        match value {
            IpProtocol::TCP => Ok(GpidProtocol::Tcp),
            IpProtocol::UDP => Ok(GpidProtocol::Udp),
            _ => Err(Error::InvalidProtocol(format!(
                "Invalid protocol {:?}",
                value
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GpidEntry {
    pub protocol: GpidProtocol,
    // Server side
    pub epc_id_1: i32,
    pub ip_1: u32, // Only support IPV4.
    pub port_1: u16,
    pub pid_1: u32, // PID or GPID
    // Client side
    pub epc_id_0: i32,
    pub ip_0: u32, // Only support IPV4.
    pub port_0: u16,
    pub pid_0: u32, // PID or GPID
    // Real ip
    pub role_real: trident::RoleType,
    pub epc_id_real: i32,
    pub ip_real: u32, // Only support IPV4.
    pub port_real: u16,
    pub pid_real: u32, // PID or GPID
}

impl Default for GpidEntry {
    fn default() -> Self {
        Self {
            role_real: trident::RoleType::RoleNone,
            protocol: GpidProtocol::Udp,
            epc_id_1: 0,
            ip_1: 0,
            port_1: 0,
            pid_1: 0,
            epc_id_0: 0,
            ip_0: 0,
            port_0: 0,
            pid_0: 0,
            epc_id_real: 0,
            ip_real: 0,
            port_real: 0,
            pid_real: 0,
        }
    }
}

pub fn gpid_key(ip: u32, epc_id: i32, port: u16) -> u64 {
    let epc_id = (epc_id & 0xffff) as u64;
    (ip as u64) << 32 | epc_id << 16 | port as u64
}

impl GpidEntry {
    pub fn client_key(&self) -> u64 {
        return gpid_key(self.ip_0, self.epc_id_0, self.port_0);
    }

    pub fn server_key(&self) -> u64 {
        return gpid_key(self.ip_1, self.epc_id_1, self.port_1);
    }

    pub fn real_key(&self) -> u64 {
        return gpid_key(self.ip_real, self.epc_id_real, self.port_real);
    }
}

impl TryFrom<&trident::GpidSyncEntry> for GpidEntry {
    type Error = Error;
    fn try_from(value: &trident::GpidSyncEntry) -> Result<Self, Self::Error> {
        let protocol = GpidProtocol::try_from(value.protocol())?;
        // FIXME: Support epc id
        // let mut epc_id_0 = value.epc_id_0() as i32;
        // if epc_id_0 > 0 {
        //     epc_id_0 &= 0xffff;
        // } else if epc_id_0 == 0 {
        //     epc_id_0 = EPC_FROM_DEEPFLOW;
        // }
        // let mut epc_id_1 = value.epc_id_1() as i32;
        // if epc_id_1 > 0 {
        //     epc_id_1 &= 0xffff;
        // } else if epc_id_1 == 0 {
        //     epc_id_1 = EPC_FROM_DEEPFLOW;
        // }
        // let mut epc_id_real = value.epc_id_real() as i32;
        // if epc_id_real > 0 {
        //     epc_id_real &= 0xffff;
        // } else if epc_id_real == 0 {
        //     epc_id_real = EPC_FROM_DEEPFLOW;
        // }
        Ok(GpidEntry {
            epc_id_0: 0,
            ip_0: value.ipv4_0(),
            port_0: (value.port_0() & 0xffff) as u16,
            pid_0: (value.pid_0() & 0xffffffff) as u32,
            epc_id_1: 0,
            ip_1: value.ipv4_1(),
            port_1: (value.port_1() & 0xffff) as u16,
            pid_1: (value.pid_1() & 0xffffffff) as u32,
            epc_id_real: 0,
            ip_real: value.ipv4_real(),
            port_real: (value.port_real() & 0xffff) as u16,
            pid_real: (value.pid_real() & 0xffffffff) as u32,
            protocol,
            role_real: value.role_real(),
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Container {
    pub pod_id: u32,
    pub container_id: String,
}

impl From<&trident::Container> for Container {
    fn from(value: &trident::Container) -> Self {
        Self {
            pod_id: value.pod_id(),
            container_id: value.container_id().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_segment() {
        assert_eq!(PortSegment::calc_right_zero(u16::MAX), 0);
        assert_eq!(PortSegment::calc_right_zero(0xff00), 8);
        assert_eq!(PortSegment::calc_right_zero(0), 16);

        assert_eq!(
            PortSegment::new(&PortRange::new(0, 65535)),
            vec![PortSegment { port: 0, mask: 0 }]
        );

        assert_eq!(
            PortSegment::new(&PortRange::new(100, 10000)),
            vec![
                PortSegment {
                    port: 100,
                    mask: 65532
                },
                PortSegment {
                    port: 104,
                    mask: 65528
                },
                PortSegment {
                    port: 112,
                    mask: 65520
                },
                PortSegment {
                    port: 128,
                    mask: 65408
                },
                PortSegment {
                    port: 256,
                    mask: 65280
                },
                PortSegment {
                    port: 512,
                    mask: 65024
                },
                PortSegment {
                    port: 1024,
                    mask: 64512
                },
                PortSegment {
                    port: 2048,
                    mask: 63488
                },
                PortSegment {
                    port: 4096,
                    mask: 61440
                },
                PortSegment {
                    port: 8192,
                    mask: 64512
                },
                PortSegment {
                    port: 9216,
                    mask: 65024
                },
                PortSegment {
                    port: 9728,
                    mask: 65280
                },
                PortSegment {
                    port: 9984,
                    mask: 65520
                },
                PortSegment {
                    port: 10000,
                    mask: 65535
                }
            ]
        );
    }
}
