use std::net::Ipv4Addr;

use crate::proto::trident::DecapType;

#[repr(u16)]
pub enum TunnelType {
    None = DecapType::None as u16,
    Vxlan = DecapType::Vxlan as u16,
    Ipip = DecapType::Ipip as u16,
    TencentGre = DecapType::Tencent as u16,
    ErspanOrTeb = 0xf,
}

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
