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

//! Referfence `gopacket/layers/enums.go`

use std::fmt;

use bitflags::bitflags;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::Serialize;

/// EthernetType is an enumeration of ethernet type values, and acts as a decoder
/// for any type it supports.
#[derive(Serialize, Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
pub enum EthernetType {
    // EthernetTypeLLC is not an actual ethernet type.  It is instead a
    // placeholder we use in Ethernet frames that use the 802.3 standard of
    // srcmac|dstmac|length|LLC instead of srcmac|dstmac|ethertype.
    Llc,
    Ipv4,
    Arp,
    Ipv6,
    TransparentEthernetBridging,
    Dot1Q,
    QinQ,
    LinkLayerDiscovery,
    Unknown(u16),
}

impl EthernetType {
    const LLC: u16 = 0;
    const IPV4: u16 = 0x0800;
    const ARP: u16 = 0x0806;
    const IPV6: u16 = 0x86DD;
    const DOT1Q: u16 = 0x8100;
    const TRANSPARENT_ETHERNET_BRIDGING: u16 = 0x6558;
    const QINQ: u16 = 0x88a8;
    const LINKLAYER_DISCOVERY: u16 = 0x88cc;
}

impl Default for EthernetType {
    fn default() -> Self {
        EthernetType::Llc
    }
}

impl From<u16> for EthernetType {
    fn from(t: u16) -> Self {
        match t {
            EthernetType::IPV4 => Self::Ipv4,
            EthernetType::ARP => Self::Arp,
            EthernetType::IPV6 => Self::Ipv6,
            EthernetType::DOT1Q => Self::Dot1Q,
            EthernetType::TRANSPARENT_ETHERNET_BRIDGING => Self::TransparentEthernetBridging,
            EthernetType::QINQ => Self::QinQ,
            EthernetType::LINKLAYER_DISCOVERY => Self::LinkLayerDiscovery,
            EthernetType::LLC => Self::Llc,
            _ => Self::Unknown(t),
        }
    }
}

impl From<EthernetType> for u16 {
    fn from(t: EthernetType) -> Self {
        match t {
            EthernetType::Ipv4 => EthernetType::IPV4,
            EthernetType::Arp => EthernetType::ARP,
            EthernetType::Ipv6 => EthernetType::IPV6,
            EthernetType::Dot1Q => EthernetType::DOT1Q,
            EthernetType::TransparentEthernetBridging => {
                EthernetType::TRANSPARENT_ETHERNET_BRIDGING
            }
            EthernetType::QinQ => EthernetType::QINQ,
            EthernetType::LinkLayerDiscovery => EthernetType::LINKLAYER_DISCOVERY,
            EthernetType::Llc => EthernetType::LLC,
            EthernetType::Unknown(t) => t,
        }
    }
}

impl PartialEq<u16> for EthernetType {
    fn eq(&self, other: &u16) -> bool {
        u16::from(*self).eq(other)
    }
}

impl PartialEq<EthernetType> for u16 {
    fn eq(&self, other: &EthernetType) -> bool {
        u16::from(*other).eq(self)
    }
}

// IPProtocol is an enumeration of IP protocol values, and acts as a decoder
// for any type it supports.
#[derive(Serialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum IpProtocol {
    Ipv6HopByHop,
    Icmpv4,
    Ipv4,
    Tcp,
    Udp,
    Ipv6,
    Ipv6Routing,
    Ipv6Fragment,
    Gre,
    Esp,
    Ah,
    Icmpv6,
    NoNextHeader,
    Ipv6Destination,
    Ipip,
    Unknown(u8),
}

impl IpProtocol {
    const IPV6_HOPBYHOP: u8 = 0;
    const ICMPV4: u8 = 1;
    const IPV4: u8 = 4;
    const TCP: u8 = 6;
    const UDP: u8 = 17;
    const IPV6: u8 = 41;
    const IPV6_ROUTING: u8 = 43;
    const IPV6_FRAGMENT: u8 = 44;
    const GRE: u8 = 47;
    const ESP: u8 = 50;
    const AH: u8 = 51;
    const ICMPV6: u8 = 58;
    const NO_NEXT_HEADER: u8 = 59;
    const IPV6_DESTINATION: u8 = 60;
    const IPIP: u8 = 94;
}

impl Default for IpProtocol {
    fn default() -> Self {
        IpProtocol::Unknown(0)
    }
}

impl From<u8> for IpProtocol {
    fn from(protocol: u8) -> Self {
        match protocol {
            Self::IPV6_HOPBYHOP => Self::Ipv6HopByHop,
            Self::ICMPV4 => Self::Icmpv4,
            Self::IPV4 => Self::Ipv4,
            Self::TCP => Self::Tcp,
            Self::UDP => Self::Udp,
            Self::IPV6 => Self::Ipv6,
            Self::ICMPV6 => Self::Icmpv6,
            Self::GRE => Self::Gre,
            Self::ESP => Self::Esp,
            Self::AH => Self::Ah,
            Self::IPV6_ROUTING => Self::Ipv6Routing,
            Self::IPV6_FRAGMENT => Self::Ipv6Fragment,
            Self::NO_NEXT_HEADER => Self::NoNextHeader,
            Self::IPV6_DESTINATION => Self::Ipv6Destination,
            Self::IPIP => Self::Ipip,
            p => Self::Unknown(p),
        }
    }
}

impl From<IpProtocol> for u8 {
    fn from(protocol: IpProtocol) -> Self {
        match protocol {
            IpProtocol::Tcp => IpProtocol::TCP,
            IpProtocol::Udp => IpProtocol::UDP,
            IpProtocol::Icmpv4 => IpProtocol::ICMPV4,
            IpProtocol::Ipv4 => IpProtocol::IPV4,
            IpProtocol::Ipv6 => IpProtocol::IPV6,
            IpProtocol::Icmpv6 => IpProtocol::ICMPV6,
            IpProtocol::Gre => IpProtocol::GRE,
            IpProtocol::Ah => IpProtocol::AH,
            IpProtocol::Esp => IpProtocol::ESP,
            IpProtocol::Ipv6HopByHop => IpProtocol::IPV6_HOPBYHOP,
            IpProtocol::Ipv6Routing => IpProtocol::IPV6_ROUTING,
            IpProtocol::Ipv6Fragment => IpProtocol::IPV6_FRAGMENT,
            IpProtocol::NoNextHeader => IpProtocol::NO_NEXT_HEADER,
            IpProtocol::Ipv6Destination => IpProtocol::IPV6_DESTINATION,
            IpProtocol::Ipip => IpProtocol::IPIP,
            IpProtocol::Unknown(p) => p,
        }
    }
}

impl PartialEq<u8> for IpProtocol {
    fn eq(&self, other: &u8) -> bool {
        u8::from(*self).eq(other)
    }
}

impl PartialEq<IpProtocol> for u8 {
    fn eq(&self, other: &IpProtocol) -> bool {
        u8::from(*other).eq(self)
    }
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum L4Protocol {
    Unknown = 0,
    Tcp = 1,
    Udp = 2,
}

impl From<IpProtocol> for L4Protocol {
    fn from(proto: IpProtocol) -> Self {
        match proto {
            IpProtocol::Tcp => Self::Tcp,
            IpProtocol::Udp => Self::Udp,
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
#[repr(u16)]
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
    use super::*;
    #[test]
    fn assert_ethernet_type() {
        let eth_type = EthernetType::Ipv6;
        let ipv6: u16 = eth_type.into();
        assert_eq!(eth_type, 0x86DDu16);
        assert_eq!(0x86DDu16, eth_type);
        assert_eq!(ipv6, 0x86DDu16);
        assert_eq!(Ok(EthernetType::Arp), EthernetType::try_from(0x806u16));
    }

    #[test]
    fn assert_ip_protocol() {
        let ip = IpProtocol::Icmpv6;
        assert_eq!(ip, 58);
        assert_eq!(58, ip);
        assert_eq!(Ok(IpProtocol::Udp), IpProtocol::try_from(17u8));
    }
}
