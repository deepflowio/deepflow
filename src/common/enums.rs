//! Referfence `gopacket/layers/enums.go`

use std::fmt;

use num_enum::{IntoPrimitive, TryFromPrimitive};

/// EthernetType is an enumeration of ethernet type values, and acts as a decoder
/// for any type it supports.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, TryFromPrimitive, IntoPrimitive)]
#[repr(u16)]
pub enum EthernetType {
    // EthernetTypeLLC is not an actual ethernet type.  It is instead a
    // placeholder we use in Ethernet frames that use the 802.3 standard of
    // srcmac|dstmac|length|LLC instead of srcmac|dstmac|ethertype.
    LLC = 0,
    IPv4 = 0x0800,
    ARP = 0x0806,
    IPv6 = 0x86DD,
    CiscoDiscovery = 0x2000,
    NortelDiscovery = 0x01a2,
    TransparentEthernetBridging = 0x6558,
    Dot1Q = 0x8100,
    PPP = 0x880b,
    PPPoEDiscovery = 0x8863,
    PPPoESession = 0x8864,
    MPLSUnicast = 0x8847,
    MPLSMulticast = 0x8848,
    EAPOL = 0x888e,
    QinQ = 0x88a8,
    LinkLayerDiscovery = 0x88cc,
    EthernetCTP = 0x9000,
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
    IPv6HopByHop = 0,
    ICMPv4 = 1,
    IGMP = 2,
    IPv4 = 4,
    TCP = 6,
    UDP = 17,
    RUDP = 27,
    IPv6 = 41,
    IPv6Routing = 43,
    IPv6Fragment = 44,
    GRE = 47,
    ESP = 50,
    AH = 51,
    ICMPv6 = 58,
    NoNextHeader = 59,
    IPv6Destination = 60,
    OSPF = 89,
    IPIP = 94,
    EtherIP = 97,
    VRRP = 112,
    SCTP = 132,
    UDPLite = 136,
    MPLSInIP = 137,
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
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum LinkType {
    // According to pcap-linktype(7) and http://www.tcpdump.org/linktypes.html
    Null = 0,
    Ethernet = 1,
    AX25 = 3,
    TokenRing = 6,
    ArcNet = 7,
    SLIP = 8,
    PPP = 9,
    FDDI = 10,
    PppHdlc = 50,
    PppEthernet = 51,
    AtmRFC1483 = 100,
    Raw = 101,
    CHdlc = 104,
    IEEE802_11 = 105,
    Relay = 107,
    Loop = 108,
    LinuxSLL = 113,
    Talk = 114,
    PFLog = 117,
    PrismHeader = 119,
    IPOverFC = 122,
    SunATM = 123,
    IEEE80211Radio = 127,
    ARCNetLinux = 129,
    IPOver1394 = 138,
    MTP2Phdr = 139,
    MTP2 = 140,
    MTP3 = 141,
    SCCP = 142,
    DOCSIS = 143,
    LinuxIRDA = 144,
    LinuxLAPD = 177,
    LinuxUSB = 220,
    IPv4 = 228,
    IPv6 = 229,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, TryFromPrimitive, IntoPrimitive)]
#[repr(u16)]
pub enum TapType {
    #[num_enum(default)]
    Any = 0,
    Isp1 = 1,
    Isp2 = 2,
    Tor = 3,
    Max = 256,
}

impl fmt::Display for TapType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TapType::Any => write!(f, "any"),
            TapType::Isp1 => write!(f, "isp1"),
            TapType::Isp2 => write!(f, "isp2"),
            TapType::Tor => write!(f, "tor"),
            TapType::Max => write!(f, "max"),
        }
    }
}

// 因为不知道Windows 的iftype 有那些，只能写一些常用的
//https://docs.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, TryFromPrimitive, IntoPrimitive)]
#[repr(u32)]
pub enum IfType {
    Other = 1,
    Ethernet = 6,
    TokenRing = 9,
    PPP = 23,
    Loopback = 24,
    ATM = 37,
    IEEE80211 = 71,
    Tunnel = 131,
    IEEE1394 = 144,
}

impl fmt::Display for IfType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IfType::Other => write!(f, "other"),
            IfType::Ethernet => write!(f, "ethernet"),
            IfType::TokenRing => write!(f, "tokenping"),
            IfType::PPP => write!(f, "ppp"),
            IfType::Loopback => write!(f, "loopback"),
            IfType::ATM => write!(f, "atm"),
            IfType::IEEE80211 => write!(f, "ieee80211"),
            IfType::Tunnel => write!(f, "tunnel"),
            IfType::IEEE1394 => write!(f, "ieee1394"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn assert_ethernet_type() {
        let eth_type = EthernetType::IPv6;
        let ipv6: u16 = eth_type.into();
        assert_eq!(eth_type, 0x86DDu16);
        assert_eq!(0x86DDu16, eth_type);
        assert_eq!(ipv6, 0x86DDu16);
        assert_eq!(Ok(EthernetType::ARP), EthernetType::try_from(0x806u16));
    }

    #[test]
    fn assert_link_type() {
        let link_type = LinkType::PPP;
        assert_eq!(link_type, 9);
        assert_eq!(9, link_type);
        assert_eq!(Ok(LinkType::Talk), LinkType::try_from(114u8));
    }

    #[test]
    fn assert_ip_protocol() {
        let ip = IpProtocol::ICMPv6;
        assert_eq!(ip, 58);
        assert_eq!(58, ip);
        assert_eq!(Ok(IpProtocol::UDP), IpProtocol::try_from(17u8));
    }
}
