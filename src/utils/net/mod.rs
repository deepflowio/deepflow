use std::{
    array::TryFromSliceError,
    fmt,
    net::{IpAddr, Ipv6Addr},
    str::FromStr,
};

mod error;
pub use error::{Error, Result};

#[cfg(target_os = "linux")]
mod ethtool;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use ethtool::*;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;

#[derive(Debug)]
pub struct NeighborEntry {
    pub src_addr: IpAddr,
    pub src_link: Link,
    pub dest_addr: IpAddr,
    pub dest_mac_addr: MacAddr,
}

#[derive(Debug)]
pub struct Link {
    pub if_index: u32,
    pub mac_addr: MacAddr,
    pub name: String,
    pub if_type: Option<String>,
    pub parent_index: Option<u32>,
}

impl PartialEq for Link {
    fn eq(&self, other: &Self) -> bool {
        self.if_index.eq(&other.if_index)
    }
}

impl Eq for Link {}

impl PartialOrd for Link {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.if_index.partial_cmp(&other.if_index)
    }
}

impl Ord for Link {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.if_index.cmp(&other.if_index)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Addr {
    pub if_index: u32,
    pub ip_addr: IpAddr,
    pub scope: u8,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct Route {
    pub src_ip: IpAddr,
    pub oif_index: u32,
    pub gateway: Option<IpAddr>,
}

pub const MAC_ADDR_ZERO: MacAddr = MacAddr([0, 0, 0, 0, 0, 0]);
pub const MAC_ADDR_LEN: usize = 6;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Default, Copy)]
// slice is in bigendian
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub fn octets(&self) -> [u8; 6] {
        self.0
    }

    pub fn is_multicast(octets: &[u8]) -> bool {
        assert!(octets.len() > MAC_ADDR_LEN);
        octets[0] & 0x1 == 1
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl From<MacAddr> for u64 {
    fn from(mac: MacAddr) -> Self {
        ((u16::from_be_bytes(mac.0[0..2].try_into().unwrap()) as u64) << 32)
            | u32::from_be_bytes(mac.0[2..6].try_into().unwrap()) as u64
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(octets: [u8; 6]) -> Self {
        MacAddr(octets)
    }
}

impl TryFrom<&[u8]> for MacAddr {
    type Error = TryFromSliceError;
    fn try_from(octets: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 6]>::try_from(octets).map(Self::from)
    }
}

impl TryFrom<u64> for MacAddr {
    type Error = u64;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value & 0xFFFF_0000_0000_0000 != 0 {
            return Err(value);
        }
        Ok(MacAddr(value.to_be_bytes()[2..].try_into().unwrap()))
    }
}

impl FromStr for MacAddr {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut addr = [0u8; 6];
        for (idx, n_s) in s.split(":").enumerate() {
            if idx >= MAC_ADDR_LEN {
                return Err(Error::ParseMacFailed(s.to_string()));
            }
            match u8::from_str_radix(n_s, 16) {
                Ok(n) => addr[idx] = n,
                Err(_) => return Err(Error::ParseMacFailed(s.to_string())),
            }
        }
        Ok(MacAddr(addr))
    }
}

pub fn is_unicast_link_local(ip: &Ipv6Addr) -> bool {
    // Ipv6Addr::is_unicast_link_local()是实验API无法使用
    ip.segments()[0] & 0xffc0 == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_constructions() {
        let expected = MacAddr([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]);
        assert_eq!("12:34:56:78:9a:bc", format!("{}", expected));

        assert_eq!("12:34:56:78:9a:bc".parse::<MacAddr>().unwrap(), expected);
        assert_eq!(MacAddr::try_from(0x123456789abc).unwrap(), expected);
        assert_eq!(
            MacAddr::try_from([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]).unwrap(),
            expected
        );
        assert_eq!(
            MacAddr::try_from(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc][..]).unwrap(),
            expected
        );
    }

    #[test]
    fn mac_to_u64() {
        assert_eq!(
            u64::from(MacAddr([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc])),
            0x123456789abc
        );
    }
}
