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

#[cfg(target_os = "linux")]
use super::super::ebpf::{MSG_REQUEST, MSG_RESPONSE};
use super::flow::FlowMetricsPeer;

/// EthernetType is an enumeration of ethernet type values, and acts as a decoder
/// for any type it supports.
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, TryFromPrimitive, IntoPrimitive)]
#[repr(u16)]
pub enum EthernetType {
    // EthernetTypeLLC is not an actual ethernet type.  It is instead a
    // placeholder we use in Ethernet frames that use the 802.3 standard of
    // srcmac|dstmac|length|LLC instead of srcmac|dstmac|ethertype.
    Llc = 0,
    Ipv4 = 0x0800,
    Arp = 0x0806,
    Ipv6 = 0x86DD,
    CiscoDiscovery = 0x2000,
    NortelDiscovery = 0x01a2,
    TransparentEthernetBridging = 0x6558,
    Dot1Q = 0x8100,
    Ppp = 0x880b,
    PppoeDiscovery = 0x8863,
    PppoeSession = 0x8864,
    MplsUnicast = 0x8847,
    MplsMulticast = 0x8848,
    Eapol = 0x888e,
    QinQ = 0x88a8,
    LinkLayerDiscovery = 0x88cc,
    EthernetCtp = 0x9000,
    #[num_enum(default)]
    Unknown = 0xFFFF,
}

impl Default for EthernetType {
    fn default() -> Self {
        EthernetType::Llc
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
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum IpProtocol {
    Ipv6HopByHop = 0,
    Icmpv4 = 1,
    Igmp = 2,
    Ipv4 = 4,
    Tcp = 6,
    Udp = 17,
    Rudp = 27,
    Ipv6 = 41,
    Ipv6Routing = 43,
    Ipv6Fragment = 44,
    Gre = 47,
    Esp = 50,
    Ah = 51,
    Icmpv6 = 58,
    NoNextHeader = 59,
    Ipv6Destination = 60,
    Ospf = 89,
    Ipip = 94,
    EtherIp = 97,
    Vrrp = 112,
    Sstp = 132,
    UdpLite = 136,
    MplsInIp = 137,
    Unknown = 255,
}

impl Default for IpProtocol {
    fn default() -> Self {
        IpProtocol::Unknown
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

// LinkType is an enumeration of link types, and acts as a decoder for any
// link type it supports.
#[derive(Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum LinkType {
    // According to pcap-linktype(7) and http://www.tcpdump.org/linktypes.html
    Null = 0,
    Ethernet = 1,
    Ax25 = 3,
    TokenRing = 6,
    ArcNet = 7,
    Slip = 8,
    Ppp = 9,
    Fddi = 10,
    PppHdlc = 50,
    PppEthernet = 51,
    AtmRfc1483 = 100,
    Raw = 101,
    Chdlc = 104,
    Ieee802_11 = 105,
    Relay = 107,
    Loop = 108,
    LinuxSLL = 113,
    Talk = 114,
    PfLog = 117,
    PrismHeader = 119,
    IpOverFc = 122,
    SunAtm = 123,
    Ieee80211Radio = 127,
    ArcNetLinux = 129,
    IpOver1394 = 138,
    Mtp2Phdr = 139,
    Mtp2 = 140,
    Mtp3 = 141,
    Sccp = 142,
    Docsis = 143,
    LinuxIrda = 144,
    LinuxLapd = 177,
    LinuxUsb = 220,
    Ipv4 = 228,
    Ipv6 = 229,
}

impl PartialEq<u8> for LinkType {
    fn eq(&self, other: &u8) -> bool {
        u8::from(*self).eq(other)
    }
}

impl PartialEq<LinkType> for u8 {
    fn eq(&self, other: &LinkType) -> bool {
        u8::from(*other).eq(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord)]
#[repr(u16)]
pub enum TapType {
    Any,
    Isp(u8),
    Tor,
    Max,
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
            3 => Ok(TapType::Tor),
            v if v < 256 => Ok(TapType::Isp(v as u8)),
            _ => Err("TapType not in [0, 256)"),
        }
    }
}

impl From<TapType> for u16 {
    fn from(t: TapType) -> u16 {
        match t {
            TapType::Any => 0,
            TapType::Isp(v) => v as u16,
            TapType::Tor => 3,
            TapType::Max => 256,
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
            TapType::Isp(n) => write!(f, "isp{}", n),
            TapType::Tor => write!(f, "tor"),
            TapType::Max => write!(f, "max"),
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

    pub fn min_packet_size(self) -> usize {
        match self {
            Self::Eth => 14,               // 不包括DOT1Q
            Self::Arp => 14 + 28,          // 不包括DOT1Q
            Self::Ipv4 => 14 + 20,         // 不包括DOT1Q + IPv4 option0,
            Self::Ipv4Icmp => 14 + 20 + 8, // 不包括DOT1Q + IPv4 option 0x21,
            Self::Ipv6 => 14 + 20, // 不包括DOT1Q + IPv6 option，IPv6大于IPv4的20个字节计算在m.l2L3OptSize里面0,
            Self::Ipv4Tcp => 14 + 20 + 20, // 不包括DOT1Q + IPv4 option0x80,
            Self::Ipv4Udp => 14 + 20 + 8, // 不包括DOT1Q + IPv4 option0x81,
            Self::Ipv6Tcp => 14 + 20 + 20, // 不包括DOT1Q + IPv6 option，IPv6大于IPv4的20个字节计算在m.l2L3OptSize里面0xb0,
            Self::Ipv6Udp => 14 + 20 + 8, // 不包括DOT1Q + IPv6 option，IPv6大于IPv4的20个字节计算在m.l2L3OptSize里面0xb1,
            Self::Invalid => unreachable!(),
        }
    }

    pub fn min_header_size(self) -> usize {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketDirection {
    ClientToServer = FlowMetricsPeer::SRC,
    ServerToClient = FlowMetricsPeer::DST,
}

impl PacketDirection {
    pub fn reversed(&self) -> Self {
        match self {
            PacketDirection::ClientToServer => PacketDirection::ServerToClient,
            PacketDirection::ServerToClient => PacketDirection::ClientToServer,
        }
    }
}

impl Default for PacketDirection {
    fn default() -> PacketDirection {
        PacketDirection::ClientToServer
    }
}

#[cfg(target_os = "linux")]
impl From<u8> for PacketDirection {
    fn from(msg_type: u8) -> Self {
        match msg_type {
            MSG_REQUEST => Self::ClientToServer,
            MSG_RESPONSE => Self::ServerToClient,
            _ => panic!("ebpf direction({}) unknown.", msg_type),
        }
    }
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
    fn assert_link_type() {
        let link_type = LinkType::Ppp;
        assert_eq!(link_type, 9);
        assert_eq!(9, link_type);
        assert_eq!(Ok(LinkType::Talk), LinkType::try_from(114u8));
    }

    #[test]
    fn assert_ip_protocol() {
        let ip = IpProtocol::Icmpv6;
        assert_eq!(ip, 58);
        assert_eq!(58, ip);
        assert_eq!(Ok(IpProtocol::Udp), IpProtocol::try_from(17u8));
    }
}
