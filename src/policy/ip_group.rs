use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

use crate::proto::trident::Group;

#[derive(Clone, Default)]
pub struct IpGroup {
    pub epc_id: u32,
    pub ips: Vec<IpNet>,
}

impl IpGroup {
    // TODO：这里需要优化一下，考虑找个更好的算法来减少IP段
    fn get_mask(start: u32, end: u32) -> u8 {
        let mut mask = 32;
        let diff = end - start;
        while mask > 0 {
            if start & (1 << (32 - mask)) != 0 {
                break;
            }
            let count = if mask == 32 {
                0
            } else {
                u32::MAX.checked_shr(mask).unwrap()
            };
            if count >= diff {
                break;
            }
            let count = u32::MAX.checked_shr(mask - 1).unwrap();
            if count >= diff {
                break;
            }
            mask -= 1;
        }
        return mask as u8;
    }

    fn get_mask6(start: u128, end: u128) -> u8 {
        let mut mask = 128;
        let diff = end - start;
        while mask > 0 {
            if start & (1 << (128 - mask)) != 0 {
                break;
            }
            let count = if mask == 128 {
                0
            } else {
                u128::MAX.checked_shr(mask).unwrap()
            };
            if count >= diff {
                break;
            }
            let count = u128::MAX.checked_shr(mask - 1).unwrap();
            if count >= diff {
                break;
            }
            mask -= 1;
        }
        return mask as u8;
    }

    fn ipv4_to_cidr(list: &mut Vec<IpNet>, start: u32, end: u32) {
        let mut start = start;
        while start <= end {
            let mask = Self::get_mask(start, end);
            let ip = Ipv4Addr::from(start);

            list.push(IpNet::new(IpAddr::from(ip), mask).unwrap());

            if 1 << (32 - mask) > end - start {
                break;
            }
            start += 1 << (32 - mask);
        }
    }

    fn ipv6_to_cidr(list: &mut Vec<IpNet>, start: u128, end: u128) {
        let mut start = start;
        while start <= end {
            let mask = Self::get_mask6(start, end);
            let ip = Ipv6Addr::from(start);

            list.push(IpNet::new(IpAddr::from(ip), mask).unwrap());

            if 1 << (128 - mask) > end - start {
                break;
            }
            start += 1 << (128 - mask);
        }
    }
}

impl TryFrom<Group> for IpGroup {
    type Error = String;

    fn try_from(g: Group) -> Result<IpGroup, Self::Error> {
        if g.ips.len() == 0 && g.ip_ranges.len() == 0 {
            return Err(format!(
                "ip-group({:?}) is invalid, because ips and ip_ranges is nil.\n",
                g
            ));
        }
        let mut list = Vec::new();
        for item in &g.ips {
            if let Ok(cidr) = item.parse::<IpNet>() {
                list.push(cidr);
            } else {
                return Err(format!(
                    "ip-group({:?}) is invalid, because ips({}) is invalid.\n",
                    g, item
                ));
            }
        }

        for item in &g.ip_ranges {
            let ips: Vec<&str> = item.split("-").collect();
            if ips.len() != 2 {
                return Err(format!(
                    "ip-group({:?}) is invalid, because ip_ranges({}) is invalid.\n",
                    g, item
                ));
            }

            if ips[0].parse::<Ipv4Addr>().is_ok() && ips[1].parse::<Ipv4Addr>().is_ok() {
                let start = ips[0].parse::<Ipv4Addr>().unwrap();
                let end = ips[1].parse::<Ipv4Addr>().unwrap();
                let start = u32::from_be_bytes(start.octets());
                let end = u32::from_be_bytes(end.octets());
                if end < start {
                    return Err(format!(
                        "ip-group({:?}) is invalid, because ips({}) is invalid, ip start lesser than end.\n",
                        g, item
                    ));
                }
                Self::ipv4_to_cidr(&mut list, start, end);
            } else if ips[0].parse::<Ipv6Addr>().is_ok() && ips[1].parse::<Ipv6Addr>().is_ok() {
                let start = ips[0].parse::<Ipv6Addr>().unwrap();
                let end = ips[1].parse::<Ipv6Addr>().unwrap();
                let start = u128::from_be_bytes(start.octets());
                let end = u128::from_be_bytes(end.octets());
                if end < start {
                    return Err(format!(
                        "ip-group({:?}) is invalid, because ips({}) is invalid, ip start lesser than end.\n",
                        g, item
                    ));
                }
                Self::ipv6_to_cidr(&mut list, start, end);
            } else {
                return Err(format!(
                    "ip-group({:?}) is invalid, because ip_ranges({}) is invalid.\n",
                    g, item
                ));
            }
        }
        Ok(IpGroup {
            epc_id: g.epc_id.unwrap_or_default(),
            ips: list,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_group() {
        let mut list = Vec::new();

        fn ipv4_to_u32(ip: &str) -> u32 {
            u32::from_be_bytes(ip.parse::<Ipv4Addr>().unwrap().octets())
        }
        fn ipv6_to_u128(ip: &str) -> u128 {
            u128::from_be_bytes(ip.parse::<Ipv6Addr>().unwrap().octets())
        }

        IpGroup::ipv4_to_cidr(&mut list, ipv4_to_u32("0.0.0.0"), ipv4_to_u32("0.0.0.255"));
        assert_eq!(list.len(), 9);
        list.clear();

        IpGroup::ipv4_to_cidr(
            &mut list,
            ipv4_to_u32("0.0.0.255"),
            ipv4_to_u32("0.0.0.255"),
        );
        assert_eq!(list.len(), 1);
        list.clear();

        IpGroup::ipv4_to_cidr(
            &mut list,
            ipv4_to_u32("0.0.0.0"),
            ipv4_to_u32("255.255.255.255"),
        );
        assert_eq!(list.len(), 33);
        list.clear();

        IpGroup::ipv4_to_cidr(&mut list, ipv4_to_u32("0.0.0.0"), ipv4_to_u32("255.0.0.0"));
        assert_eq!(list.len(), 9);
        list.clear();

        IpGroup::ipv6_to_cidr(
            &mut list,
            ipv6_to_u128("::"),
            ipv6_to_u128("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        );
        assert_eq!(list.len(), 129);
        list.clear();

        IpGroup::ipv6_to_cidr(
            &mut list,
            ipv6_to_u128("fd76:a43e:ea96:8:8218:44ff:fee3:2651"),
            ipv6_to_u128("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        );
        assert_eq!(list.len(), 188);
        list.clear();

        IpGroup::ipv6_to_cidr(
            &mut list,
            ipv6_to_u128("fd76:a43e:ea96:8:8218:44ff:fee3:2651"),
            ipv6_to_u128("fd76:a43e:ea96:8:8218:44ff:fee3:2651"),
        );
        assert_eq!(list.len(), 1);
        list.clear();
    }
}
