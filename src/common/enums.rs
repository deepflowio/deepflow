//! Referfence `gopacket/layers/enums.go`

use std::fmt;

use num_enum::{IntoPrimitive, TryFromPrimitive};

// LinkType is an enumeration of link types, and acts as a decoder for any
// link type it supports.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum Link {
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

impl PartialEq<u8> for Link {
    fn eq(&self, other: &u8) -> bool {
        u8::from(*self).eq(other)
    }
}

impl PartialEq<Link> for u8 {
    fn eq(&self, other: &Link) -> bool {
        u8::from(*other).eq(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, TryFromPrimitive, IntoPrimitive)]
#[repr(u16)]
pub enum TapType {
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn assert_link_type() {
        let link_type = Link::PPP;
        assert_eq!(link_type, 9);
        assert_eq!(9, link_type);
        assert_eq!(Ok(Link::Talk), Link::try_from(114u8));
    }
}
