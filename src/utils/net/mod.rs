use std::{fmt, net::IpAddr, str::FromStr};

use crate::error::Error;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

pub const MAC_ADDR_ZERO: MacAddr = MacAddr([0, 0, 0, 0, 0, 0]);

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Default, Copy)]
pub struct MacAddr(pub [u8; 6]);

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
        mac.0.into_iter().fold(0, |r, a| (r + a as u64) << 8)
    }
}

impl TryFrom<u64> for MacAddr {
    type Error = core::array::TryFromSliceError;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let slice = &value.to_le_bytes()[..6];
        <&[u8; 6]>::try_from(slice).map(|a| MacAddr(*a))
    }
}

impl FromStr for MacAddr {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut addr = [0u8; 6];
        for (idx, n_s) in s.split(":").enumerate() {
            if idx >= 6 {
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
