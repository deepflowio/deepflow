use std::{fmt, net::Ipv4Addr};

use crate::proto::trident::DecapType;

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u16)]
pub enum TunnelType {
    None = DecapType::None as u16,
    Vxlan = DecapType::Vxlan as u16,
    Ipip = DecapType::Ipip as u16,
    TencentGre = DecapType::Tencent as u16,
    ErspanOrTeb = DecapType::Tencent as u16 + 1,
}

impl TryFrom<&DecapType> for TunnelType {
    type Error = &'static str;
    fn try_from(t: &DecapType) -> Result<TunnelType, Self::Error> {
        match t {
            DecapType::None => Ok(TunnelType::None),
            DecapType::Vxlan => Ok(TunnelType::Vxlan),
            DecapType::Ipip => Ok(TunnelType::Ipip),
            DecapType::Tencent => Ok(TunnelType::TencentGre),
            _ => Err("TunnelType not accept the value"),
        }
    }
}

impl fmt::Display for TunnelType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TunnelType::None => write!(f, "none"),
            TunnelType::Vxlan => write!(f, "VXLAN"),
            TunnelType::Ipip => write!(f, "IPIP"),
            TunnelType::TencentGre => write!(f, "GRE"),
            TunnelType::ErspanOrTeb => write!(f, "ERSPAN_TEB"),
        }
    }
}

impl Default for TunnelType {
    fn default() -> Self {
        TunnelType::None
    }
}

struct TunnelTypeBitmap(u16);

impl TunnelTypeBitmap {
    pub fn new(tunnel_types: &Vec<TunnelType>) -> Self {
        let mut bitmap = TunnelTypeBitmap(0);
        for tunnel_type in tunnel_types.iter() {
            bitmap.0 |= 1 << *tunnel_type as u16;
        }
        return bitmap;
    }

    pub fn add(&mut self, tunnel_type: TunnelType) {
        self.0 |= 1 << tunnel_type as u16
    }

    pub fn has(&self, tunnel_type: TunnelType) -> bool {
        self.0 & (1 << tunnel_type as u16) != 0
    }

    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for TunnelTypeBitmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return write!(f, "{}", TunnelType::None);
        }
        let mut separation = "";
        if self.has(TunnelType::Vxlan) {
            write!(f, "{}", TunnelType::Vxlan)?;
            separation = " ";
        }
        if self.has(TunnelType::Ipip) {
            write!(f, "{}{}", separation, TunnelType::Ipip)?;
            separation = " ";
        }
        if self.has(TunnelType::TencentGre) {
            write!(f, "{}{}", separation, TunnelType::TencentGre)?;
            separation = " ";
        }
        if self.has(TunnelType::ErspanOrTeb) {
            write!(f, "{}{}", separation, TunnelType::ErspanOrTeb)?;
        }
        write!(f, "")
    }
}

const LE_IPV4_PROTO_TYPE_I: u16 = 0x0008; // 0x0008's LittleEndian
const LE_IPV6_PROTO_TYPE_I: u16 = 0xDD86; // 0x86dd's LittleEndian
const LE_ERSPAN_PROTO_TYPE_II: u16 = 0xBE88; // 0x88BE's LittleEndian
const LE_ERSPAN_PROTO_TYPE_III: u16 = 0xEB22; // 0x22EB's LittleEndian
const LE_VXLAN_PROTO_UDP_DPORT: u16 = 0xB512; // 0x12B5(4789)'s LittleEndian
const LE_VXLAN_PROTO_UDP_DPORT2: u16 = 0x1821; // 0x2118(8472)'s LittleEndian
const LE_VXLAN_PROTO_UDP_DPORT3: u16 = 0x801A; // 0x1A80(6784)'s LittleEndian
const LE_TEB_PROTO: u16 = 0x5865; // 0x6558(25944)'s LittleEndian

const VXLAN_FLAGS: u8 = 8;
const _TUNNEL_TIER_LIMIT: u8 = 2;

#[derive(Debug)]
pub struct TunnelInfo {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub mac_src: u32, // lowest 4B
    pub mac_dst: u32, // lowest 4B
    pub id: u32,
    pub tunnel_type: TunnelType,
    pub tier: u8,
    pub is_ipv6: bool,
}

impl TunnelInfo {
    // TODO
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitmap_new() {
        let tvec = vec![TunnelType::Ipip, TunnelType::TencentGre];
        let bitmap = TunnelTypeBitmap::new(&tvec);
        assert!(bitmap.has(TunnelType::TencentGre));
        assert!(bitmap.has(TunnelType::Ipip));
        assert!(!bitmap.has(TunnelType::Vxlan));
    }

    #[test]
    fn bitmap_add() {
        let mut bitmap = TunnelTypeBitmap(0);
        assert!(bitmap.is_empty());
        bitmap.add(TunnelType::Ipip);
        bitmap.add(TunnelType::Vxlan);
        assert!(bitmap.has(TunnelType::Ipip));
        assert!(bitmap.has(TunnelType::Vxlan));
        assert!(!bitmap.has(TunnelType::TencentGre));
    }
}
