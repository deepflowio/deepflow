use std::fmt;
use std::net::Ipv4Addr;

// 64     60                                    0
// +------+-------------------------------------+
// | from |              ip/id/mac              |
// +------+-------------------------------------+
#[derive(Default)]
pub struct TapPort(u64);

impl TapPort {
    pub const FROM_LOCAL_MAC: u8 = 0;
    pub const FROM_GATEWAY_MAC: u8 = 1;
    pub const FROM_TUNNEL_IPV4: u8 = 2;
    pub const FROM_TUNNEL_IPV6: u8 = 3;
    pub const FROM_ID: u8 = 4;
    pub const FROM_NETFLOW: u8 = 5;
    pub const FROM_SFLOW: u8 = 6;
    const FROM_OFFSET: u64 = 60;

    pub fn from_local_mac(mac: u32) -> TapPort {
        TapPort(mac as u64 | ((TapPort::FROM_LOCAL_MAC as u64) << TapPort::FROM_OFFSET))
    }

    pub fn from_netflow(mac: u32) -> TapPort {
        TapPort(mac as u64 | ((TapPort::FROM_NETFLOW as u64) << TapPort::FROM_OFFSET))
    }

    pub fn from_sflow(mac: u32) -> TapPort {
        TapPort(mac as u64 | ((TapPort::FROM_SFLOW as u64) << TapPort::FROM_OFFSET))
    }

    pub fn from_gateway_mac(mac: u32) -> TapPort {
        TapPort(mac as u64 | ((TapPort::FROM_GATEWAY_MAC as u64) << TapPort::FROM_OFFSET))
    }

    pub fn from_tunnel_ip(ip: u32, is_ip_v6: bool) -> TapPort {
        TapPort(
            ip as u64
                | ((if is_ip_v6 {
                    TapPort::FROM_TUNNEL_IPV6
                } else {
                    TapPort::FROM_TUNNEL_IPV4
                } as u64)
                    << TapPort::FROM_OFFSET),
        )
    }

    pub fn from_id(id: u32) -> TapPort {
        TapPort(id as u64 | ((TapPort::FROM_ID as u64) << TapPort::FROM_OFFSET))
    }

    pub fn split_to_port_and_type(&self) -> (u32, u8) {
        (self.0 as u32, (self.0 >> TapPort::FROM_OFFSET) as u8)
    }
}

impl fmt::Display for TapPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (p, t) = self.split_to_port_and_type();
        match t {
            TapPort::FROM_LOCAL_MAC => {
                let bs = p.to_be_bytes();
                write!(
                    f,
                    "LMAC@{:02x}:{:02x}:{:02x}:{:02x}",
                    bs[0], bs[1], bs[2], bs[3]
                )
            }
            TapPort::FROM_GATEWAY_MAC => {
                let bs = p.to_be_bytes();
                write!(
                    f,
                    "GMAC@{:02x}:{:02x}:{:02x}:{:02x}",
                    bs[0], bs[1], bs[2], bs[3]
                )
            }
            TapPort::FROM_TUNNEL_IPV4 => {
                write!(f, "IPv4@{}", Ipv4Addr::from(p))
            }
            TapPort::FROM_TUNNEL_IPV6 => {
                write!(f, "IPv6@{:#10x}", p)
            }
            TapPort::FROM_ID => {
                write!(f, "ID@{}", p)
            }
            TapPort::FROM_NETFLOW => {
                write!(f, "NetFlow@{}", p)
            }
            TapPort::FROM_SFLOW => {
                write!(f, "sFlow@{}", p)
            }
            _ => panic!("Invalid tap_port type {}.", t),
        }
    }
}

impl fmt::Debug for TapPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}
