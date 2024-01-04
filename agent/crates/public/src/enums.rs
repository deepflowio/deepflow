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

//! Referfence `gopacket/layers/enums.go`

use std::fmt;

use bitflags::bitflags;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::Serialize;

/// EthernetType is an enumeration of ethernet type values, and acts as a decoder
/// for any type it supports.
#[derive(Serialize, Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
pub struct EthernetType(u16);

impl EthernetType {
    pub const LLC: Self = Self(0);
    pub const IPV4: Self = Self(0x0800);
    pub const ARP: Self = Self(0x0806);
    pub const IPV6: Self = Self(0x86DD);
    pub const DOT1Q: Self = Self(0x8100);
    pub const TRANSPARENT_ETHERNET_BRIDGING: Self = Self(0x6558);
    pub const QINQ: Self = Self(0x88a8);
    pub const LINK_LAYER_DISCOVERY: Self = Self(0x88cc);
}

impl Default for EthernetType {
    fn default() -> Self {
        Self::LLC
    }
}

impl From<u16> for EthernetType {
    fn from(t: u16) -> Self {
        Self(t)
    }
}

impl From<EthernetType> for u16 {
    fn from(t: EthernetType) -> Self {
        t.0
    }
}

impl PartialEq<u16> for EthernetType {
    fn eq(&self, other: &u16) -> bool {
        &self.0 == other
    }
}

impl PartialEq<EthernetType> for u16 {
    fn eq(&self, other: &EthernetType) -> bool {
        self == &other.0
    }
}

// IPProtocol is an enumeration of IP protocol values, and acts as a decoder
// for any type it supports.
#[derive(Serialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct IpProtocol(u8);

impl IpProtocol {
    pub const IPV6_HOP_BY_HOP: Self = Self(0);
    pub const ICMPV4: Self = Self(1);
    pub const IPV4: Self = Self(4);
    pub const TCP: Self = Self(6);
    pub const UDP: Self = Self(17);
    pub const IPV6: Self = Self(41);
    pub const IPV6_ROUTING: Self = Self(43);
    pub const IPV6_FRAGMENT: Self = Self(44);
    pub const GRE: Self = Self(47);
    pub const ESP: Self = Self(50);
    pub const AH: Self = Self(51);
    pub const ICMPV6: Self = Self(58);
    pub const NO_NEXT_HEADER: Self = Self(59);
    pub const IPV6_DESTINATION: Self = Self(60);
    pub const IPIP: Self = Self(94);
}

impl Default for IpProtocol {
    fn default() -> Self {
        Self(0)
    }
}

impl From<u8> for IpProtocol {
    fn from(protocol: u8) -> Self {
        Self(protocol)
    }
}

impl From<IpProtocol> for u8 {
    fn from(protocol: IpProtocol) -> Self {
        protocol.0
    }
}

impl PartialEq<u8> for IpProtocol {
    fn eq(&self, other: &u8) -> bool {
        &self.0 == other
    }
}

impl PartialEq<IpProtocol> for u8 {
    fn eq(&self, other: &IpProtocol) -> bool {
        self == &other.0
    }
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum L4Protocol {
    Unknown = 0,
    Tcp = 1,
    Udp = 2,
    Icmp = 3,
}

impl From<IpProtocol> for L4Protocol {
    fn from(proto: IpProtocol) -> Self {
        match proto {
            IpProtocol::TCP => Self::Tcp,
            IpProtocol::UDP => Self::Udp,
            IpProtocol::ICMPV4 | IpProtocol::ICMPV6 => Self::Icmp,
            _ => Self::Unknown,
        }
    }
}

// Translate the string value of otel l4_protocol into a L4Protocol enumeration value
// According to https://opentelemetry.io/docs/reference/specification/trace/semantic_conventions/span-general/#network-transport-attributes
impl From<String> for L4Protocol {
    fn from(l4_protocol_str: String) -> Self {
        let l4_protocol_str = l4_protocol_str.to_lowercase();
        if l4_protocol_str.eq("ip_tcp") {
            Self::Tcp
        } else if l4_protocol_str.eq("ip_udp") {
            Self::Udp
        } else {
            Self::Unknown
        }
    }
}

impl Default for L4Protocol {
    fn default() -> Self {
        L4Protocol::Unknown
    }
}

#[derive(Serialize, Debug, Clone, Copy, Hash, PartialEq, Eq, Ord)]
pub enum TapType {
    Any,
    Idc(u8),
    Cloud,
    Max,
    Unknown,
}

impl PartialOrd for TapType {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        u16::from(*self).partial_cmp(&u16::from(*other))
    }
}

impl TryFrom<u16> for TapType {
    type Error = &'static str;
    fn try_from(t: u16) -> Result<TapType, Self::Error> {
        match t {
            0 => Ok(TapType::Any),
            3 => Ok(TapType::Cloud),
            0xffff => Ok(TapType::Unknown),
            v if v < 256 => Ok(TapType::Idc(v as u8)),
            _ => Err("TapType not in [0, 256)"),
        }
    }
}

impl From<TapType> for u16 {
    fn from(t: TapType) -> u16 {
        match t {
            TapType::Any => 0,
            TapType::Idc(v) => v as u16,
            TapType::Cloud => 3,
            TapType::Max => 256,
            TapType::Unknown => 0xffff,
        }
    }
}

impl Default for TapType {
    fn default() -> TapType {
        TapType::Any
    }
}

impl fmt::Display for TapType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TapType::Any => write!(f, "any"),
            TapType::Idc(n) => write!(f, "isp{}", n),
            TapType::Cloud => write!(f, "tor"),
            TapType::Max => write!(f, "max"),
            TapType::Unknown => write!(f, "unknown"),
        }
    }
}

// 因为不知道Windows 的iftype 有那些，只能写一些常用的
//https://docs.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh
#[derive(Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive, IntoPrimitive)]
#[repr(u32)]
pub enum IfType {
    Other = 1,
    Ethernet = 6,
    TokenRing = 9,
    Ppp = 23,
    Loopback = 24,
    Atm = 37,
    Ieee80211 = 71,
    Tunnel = 131,
    Ieee1394 = 144,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum HeaderType {
    Invalid = 0,
    Eth = 0x1,
    Arp = 0x2,
    Ipv4 = 0x20,
    Ipv4Icmp = 0x21,
    Ipv6 = 0x40,
    Ipv4Tcp = 0x80,
    Ipv4Udp = 0x81,
    Ipv6Tcp = 0xb0,
    Ipv6Udp = 0xb1,
}

#[allow(non_upper_case_globals)]
impl HeaderType {
    pub const L2: HeaderType = HeaderType::Eth;
    pub const L3: HeaderType = HeaderType::Ipv4;
    pub const L3Ipv6: HeaderType = HeaderType::Ipv6;
    pub const L4: HeaderType = HeaderType::Ipv4Tcp;
    pub const L4Ipv6: HeaderType = HeaderType::Ipv6Tcp;

    pub const fn min_packet_size(self) -> usize {
        match self {
            Self::Eth => 14,               // 不包括DOT1Q
            Self::Arp => 14 + 28,          // 不包括DOT1Q
            Self::Ipv4 => 14 + 20,         // 不包括DOT1Q + IPv4 option0,
            Self::Ipv4Icmp => 14 + 20 + 8, // 不包括DOT1Q + IPv4 option 0x21,
            Self::Ipv6 => 14 + 20, // 不包括DOT1Q + IPv6 option，IPv6大于IPv4的20个字节计算在m.l2L3OptSize里面0,
            Self::Ipv4Tcp => 14 + 20 + 20, // 不包括DOT1Q + IPv4 option0x80,
            Self::Ipv4Udp => 14 + 20 + 8, // 不包括DOT1Q + IPv4 option0x81,
            Self::Ipv6Tcp => 14 + 40 + 20, // 不包括DOT1Q + IPv6 option，IPv6大于40字节的option计算在m.l2L3OptSize里面0xb0,
            Self::Ipv6Udp => 14 + 40 + 8, // 不包括DOT1Q + IPv6 option，IPv6大于40字节的option计算在m.l2L3OptSize里面0xb1,
            Self::Invalid => unreachable!(),
        }
    }

    pub const fn min_header_size(self) -> usize {
        match self {
            Self::Eth => 14,
            Self::Arp => 28,
            Self::Ipv4 => 20,
            Self::Ipv4Icmp => 8,
            Self::Ipv6 => 20,
            Self::Ipv4Tcp => 20,
            Self::Ipv4Udp => 8,
            Self::Ipv6Tcp => 20,
            Self::Ipv6Udp => 8,
            Self::Invalid => unreachable!(),
        }
    }
}

impl Default for HeaderType {
    fn default() -> HeaderType {
        HeaderType::Invalid
    }
}

bitflags! {
    #[derive(Default)]
    pub struct TcpFlags: u8 {
        const FIN = 0b000001;
        const SYN = 0b000010;
        const RST = 0b000100;
        const PSH = 0b001000;
        const ACK = 0b010000;
        const URG = 0b100000;
        const MASK = 0x3F;

        const SYN_ACK = Self::SYN.bits | Self::ACK.bits;
        const FIN_ACK = Self::FIN.bits | Self::ACK.bits;
        const FIN_PSH_ACK = Self::FIN.bits | Self::PSH.bits | Self::ACK.bits;
        const RST_ACK = Self::RST.bits | Self::ACK.bits;
        const RST_PSH_ACK = Self::RST.bits | Self::PSH.bits | Self::ACK.bits;
        const PSH_ACK = Self::PSH.bits | Self::ACK.bits;
        const PSH_ACK_URG = Self::PSH.bits | Self::ACK.bits | Self::URG.bits;
    }
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bit_strs = vec![];
        if self.contains(Self::FIN) {
            bit_strs.push("FIN");
        }
        if self.contains(Self::SYN) {
            bit_strs.push("SYN");
        }
        if self.contains(Self::RST) {
            bit_strs.push("RST");
        }
        if self.contains(Self::PSH) {
            bit_strs.push("PSH");
        }
        if self.contains(Self::ACK) {
            bit_strs.push("ACK");
        }
        if self.contains(Self::URG) {
            bit_strs.push("URG");
        }
        write!(f, "{}", bit_strs.join("|"))
    }
}

impl TcpFlags {
    pub fn is_invalid(&self) -> bool {
        match *self & TcpFlags::MASK {
            TcpFlags::SYN => false,
            TcpFlags::SYN_ACK => false,
            TcpFlags::FIN => false,
            TcpFlags::FIN_ACK => false,
            TcpFlags::FIN_PSH_ACK => false,
            TcpFlags::RST => false,
            TcpFlags::RST_ACK => false,
            TcpFlags::RST_PSH_ACK => false,
            TcpFlags::ACK => false,
            TcpFlags::PSH_ACK => false,
            TcpFlags::PSH_ACK_URG => false,
            _ => true,
        }
    }
}

// according to https://man7.org/linux/man-pages/man7/packet.7.html sll_pkttype
pub enum LinuxSllPacketType {
    Host = 0,      // To us
    Broadcast = 1, // To all
    Multicast = 2, // To group
    OtherHost = 3, // To someone else
    Outgoing = 4,  // Outgoing of any type
    // These ones are invisible user level,
    Loopback = 5,  // MC/BRD frame looped back
    FastRoute = 6, // FastRoute frame
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn assert_ethernet_type() {
        let eth_type = EthernetType::IPV6;
        let ipv6: u16 = eth_type.into();
        assert_eq!(eth_type, 0x86DDu16);
        assert_eq!(0x86DDu16, eth_type);
        assert_eq!(ipv6, 0x86DDu16);
        assert_eq!(Ok(EthernetType::ARP), EthernetType::try_from(0x806u16));
    }

    #[test]
    fn assert_ip_protocol() {
        let ip = IpProtocol::ICMPV6;
        assert_eq!(ip, 58);
        assert_eq!(58, ip);
        assert_eq!(Ok(IpProtocol::UDP), IpProtocol::try_from(17u8));
    }

    #[test]
    fn check_type_sizes() {
        assert_eq!(size_of::<EthernetType>(), 2);
        assert_eq!(size_of::<IpProtocol>(), 1);
        assert_eq!(size_of::<TapType>(), 2);
    }
}
