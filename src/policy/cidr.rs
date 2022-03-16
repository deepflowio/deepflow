use cidr_utils::cidr::IpCidr;

use crate::proto::trident::CidrType;

pub struct Cidr {
    pub ip_net: IpCidr,
    pub tunnel_id: u32,
    pub epc_id: i32,
    pub region_id: u32,
    pub ttype: CidrType,
    pub is_vip: bool,
}

impl Cidr {
    pub fn netmask_len(&self) -> u8 {
        match self.ip_net {
            IpCidr::V4(addr) => addr.get_bits(),
            IpCidr::V6(addr) => addr.get_bits(),
        }
    }
}

impl Default for Cidr {
    fn default() -> Cidr {
        Cidr {
            ip_net: IpCidr::from_str("0.0.0.0/32").unwrap(),
            tunnel_id: 0,
            epc_id: 0,
            region_id: 0,
            ttype: CidrType::Lan,
            is_vip: false,
        }
    }
}
