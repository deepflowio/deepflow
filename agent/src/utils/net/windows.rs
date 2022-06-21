use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};

use windows::Win32::{
    Foundation::{CHAR, ERROR_BUFFER_OVERFLOW, NO_ERROR},
    NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GetBestInterfaceEx, GetBestRoute2, IfOperStatusUp,
        ResolveIpNetEntry2, AF_INET, AF_INET6, AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES,
        IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_ADDRESSES_LH_0, IP_ADAPTER_ADDRESSES_LH_0_0,
        MIB_IPFORWARD_ROW2, MIB_IPNET_ROW2,
    },
    Networking::WinSock::{
        IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
        SOCKADDR_IN6_0, SOCKADDR_INET,
    },
};

use super::{Addr, Link, MacAddr, NeighborEntry, Route, MAC_ADDR_ZERO};
use super::{Error, Result};
use crate::{common::IfType, utils::WIN_ERROR_CODE_STR};

/*
* TODO
*  BPF socket 构造
*
*/

enum SafetySockAddr {
    Ipv4(SOCKADDR_IN),
    Ipv6(SOCKADDR_IN6),
}

pub fn neighbor_lookup(mut dest_addr: IpAddr) -> Result<NeighborEntry> {
    let route = route_get(dest_addr)?;

    let dest_sockaddr = match (route.gateway, dest_addr) {
        (Some(IpAddr::V4(v4)), _) | (None, IpAddr::V4(v4)) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET as u16,
                sin_port: 0,
                sin_zero: [CHAR::default(); 8],
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from(v4).to_be(),
                    },
                },
            },
        },
        (Some(IpAddr::V6(v6)), _) | (None, IpAddr::V6(v6)) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6 as u16,
                sin6_port: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: v6.octets() },
                },
                sin6_flowinfo: 0,
                Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
            },
        },
    };

    let mut ipnet_row = MIB_IPNET_ROW2::default();
    ipnet_row.InterfaceIndex = route.oif_index;
    ipnet_row.Address = dest_sockaddr;

    // 发送ARP/NDP request 获取目的IP的mac address
    if let Err(err) = unsafe { ResolveIpNetEntry2(&mut ipnet_row, ptr::null()) } {
        return Err(Error::Windows(format!(
            "resolve (ip -> mac address) error: {}",
            err
        )));
    }

    // mac addr length=6
    if ipnet_row.PhysicalAddressLength != 6 {
        return Err(Error::Windows(format!(
            "get wrong mac address length={}",
            ipnet_row.PhysicalAddressLength
        )));
    }

    let link = get_interface_by_index(route.oif_index)?;

    let mac_addr = MacAddr(
        ipnet_row
            .PhysicalAddress
            .get(..6)
            .and_then(|m| <&[u8; 6]>::try_from(m).ok())
            .map(|m| *m)
            .unwrap(),
    );

    dest_addr = match route.gateway {
        Some(addr) => addr,
        None => dest_addr,
    };

    Ok(NeighborEntry {
        src_addr: route.src_ip,
        dest_addr,
        dest_mac_addr: mac_addr,
        src_link: link,
    })
}

pub fn get_interface_by_name(friendly_name: &str) -> Result<Link> {
    let (adapters, _) = get_adapters_addresses()?;
    adapters
        .into_iter()
        .find(|link| link.name.as_str() == friendly_name)
        .ok_or(Error::Windows(format!(
            "cannot find correspond interface by name={}",
            friendly_name
        )))
}

pub fn get_interface_by_index(if_index: u32) -> Result<Link> {
    let (adapters, _) = get_adapters_addresses()?;
    adapters
        .into_iter()
        .find(|link| link.if_index == if_index)
        .ok_or(Error::Windows(format!(
            "cannot find correspond interface by if_index={}",
            if_index
        )))
}

pub fn get_interface_ips(if_index: u32) -> Result<Vec<Addr>> {
    let (_, addresses) = get_adapters_addresses()?;
    Ok(addresses
        .into_iter()
        .filter(|address| address.if_index == if_index)
        .collect())
}

pub fn addr_list() -> Result<Vec<Addr>> {
    get_adapters_addresses().map(|(_, addresses)| addresses)
}

pub fn link_by_name(name: String) -> Result<Link> {
    todo!()
}

pub fn link_list() -> Result<Vec<Link>> {
    get_adapters_addresses().map(|(adapters, _)| adapters)
}

pub fn get_src_ip_and_mac(dest_addr: IpAddr) -> Result<(IpAddr, MacAddr)> {
    route_get(dest_addr)
        .and_then(|r| get_interface_by_index(r.oif_index).map(|link| (r.src_ip, link.mac_addr)))
}

pub fn get_route_src_ip(dest_addr: IpAddr) -> Result<IpAddr> {
    route_get(dest_addr).map(|r| r.src_ip)
}

pub fn route_get(dest_addr: IpAddr) -> Result<Route> {
    let dest_safety_sockaddr = match dest_addr {
        IpAddr::V4(v4) => SafetySockAddr::Ipv4(SOCKADDR_IN {
            sin_family: AF_INET as u16,
            sin_port: 0,
            sin_zero: [CHAR::default(); 8],
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from(v4).to_be(),
                },
            },
        }),
        IpAddr::V6(v6) => SafetySockAddr::Ipv6(SOCKADDR_IN6 {
            sin6_family: AF_INET6 as u16,
            sin6_port: 0,
            sin6_addr: IN6_ADDR {
                u: IN6_ADDR_0 { Byte: v6.octets() },
            },

            sin6_flowinfo: 0,
            Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
        }),
    };

    unsafe {
        let dest_sockaddr_ptr = match &dest_safety_sockaddr {
            SafetySockAddr::Ipv4(v4) => {
                let dest_addr: *const SOCKADDR_IN = v4;
                dest_addr.cast::<SOCKADDR>()
            }
            SafetySockAddr::Ipv6(v6) => {
                let dest_addr: *const SOCKADDR_IN6 = v6;
                dest_addr.cast::<SOCKADDR>()
            }
        };

        // 获取出口 if_index
        let mut best_if_index = 0u32;
        let ret_code = GetBestInterfaceEx(dest_sockaddr_ptr, &mut best_if_index);
        if ret_code != NO_ERROR {
            let err_msg = format!(
                "failed to run GetBestInterfaceEx function with destination address={} because of win32 error code({}),\n{}",
                dest_addr, ret_code, WIN_ERROR_CODE_STR
            );
            return Err(Error::Windows(err_msg));
        }

        let dest_sockaddr = match dest_safety_sockaddr {
            SafetySockAddr::Ipv4(v4) => SOCKADDR_INET { Ipv4: v4 },
            SafetySockAddr::Ipv6(v6) => SOCKADDR_INET { Ipv6: v6 },
        };

        let mut route_row = MIB_IPFORWARD_ROW2::default();
        let mut best_src_addr = SOCKADDR_INET::default();

        // 获取目的地址路由
        if let Err(err) = GetBestRoute2(
            ptr::null(),
            best_if_index,
            ptr::null(),
            &dest_sockaddr,
            0,
            &mut route_row,
            &mut best_src_addr,
        ) {
            let err_msg = format!(
                "failed to run GetBestRoute2 function with destination address={} error: {}",
                dest_addr, err
            );
            return Err(Error::Windows(err_msg));
        }

        // 解析 best_src_addr, gateway
        let (src_addr, gateway) = match dest_addr {
            IpAddr::V4(_) => {
                let src_addr = IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    best_src_addr.Ipv4.sin_addr.S_un.S_addr,
                )));
                let gateway_addr = route_row.NextHop.Ipv4.sin_addr.S_un.S_addr;
                let gateway = if gateway_addr != 0 {
                    Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(gateway_addr))))
                } else {
                    None
                };
                (src_addr, gateway)
            }
            IpAddr::V6(_) => {
                let src_addr = IpAddr::V6(Ipv6Addr::from(best_src_addr.Ipv6.sin6_addr.u.Byte));
                let gateway_addr = route_row.NextHop.Ipv6.sin6_addr.u.Word;

                let gateway = if gateway_addr.iter().all(|&w| w == 0) {
                    None
                } else {
                    Some(IpAddr::V6(Ipv6Addr::from(gateway_addr)))
                };

                (src_addr, gateway)
            }
        };

        Ok(Route {
            src_ip: src_addr,
            oif_index: best_if_index,
            gateway,
        })
    }
}

fn get_adapters_addresses() -> Result<(Vec<Link>, Vec<Addr>)> {
    // recommended initial size
    const RECOMMENDED_BUF_SIZE: u32 = 15000;
    let mut size = RECOMMENDED_BUF_SIZE;
    let mut adapter_address: Vec<u8> = vec![0u8; size as usize];
    let mut adapter_ptr = adapter_address
        .as_mut_ptr()
        .cast::<IP_ADAPTER_ADDRESSES_LH>();

    unsafe {
        // 获取所有网卡信息
        loop {
            let ret_code = GetAdaptersAddresses(
                AF_UNSPEC,
                GAA_FLAG_INCLUDE_ALL_INTERFACES,
                ptr::null_mut(),
                adapter_ptr,
                &mut size,
            );

            if ret_code == NO_ERROR {
                if size == 0 {
                    return Err(Error::Windows(String::from(
                    "failed to run GetAdaptersAddresses function because cannot get data from kernel size=0",
                )));
                }
                break;
            }

            if ret_code != ERROR_BUFFER_OVERFLOW {
                let err_msg = format!(
                "failed to run get_adapters_addresses function because of win32 error code({}),\n{}",
                ret_code, WIN_ERROR_CODE_STR
            );
                return Err(Error::Windows(err_msg));
            }

            if size <= adapter_address.len() as u32 {
                return Err(Error::Windows(String::from(
                "failed to run get adapters_addresses function because buffer's size less than buffer's length",
            )));
            }

            // buffer小了, 增大buffer
            adapter_address = vec![0u8; size as usize];
            adapter_ptr = adapter_address
                .as_mut_ptr()
                .cast::<IP_ADAPTER_ADDRESSES_LH>();
        }

        let (mut links, mut addresses) = (vec![], vec![]);
        // 读取网卡信息链表
        while !adapter_ptr.is_null() {
            let adapter = adapter_ptr.as_ref().unwrap();

            // 跳过status=down, adapter_name == null, friendly_name == null的interface
            if adapter.OperStatus != IfOperStatusUp
                || adapter.AdapterName.is_null()
                || adapter.FriendlyName.is_null()
            {
                adapter_ptr = adapter.Next;
                continue;
            }

            let friendly_name = match count_len(adapter.FriendlyName.0, 0)
                .map(|len| std::slice::from_raw_parts(adapter.FriendlyName.0, len))
                .and_then(|s| String::from_utf16(s).ok())
            {
                Some(name) => name,
                None => {
                    adapter_ptr = adapter.Next;
                    continue;
                }
            };

            let mac_addr = match adapter
                .PhysicalAddress
                .get(..adapter.PhysicalAddressLength as usize)
                .and_then(|s| <&[u8; 6]>::try_from(s).ok())
                .map(|mac| MacAddr(*mac))
                .filter(|&addr| addr != MAC_ADDR_ZERO)
            {
                Some(mac) => mac,
                None => {
                    adapter_ptr = adapter.Next;
                    continue;
                }
            };

            // W 会不会一直匹配 Anonymous 即使是Alignment
            // A: Alignment 保留字段，不再使用, 可以大胆match Anonymous
            // Ipv6IfIndex 是字段ifIndex替代
            let if_index = match adapter.Anonymous1 {
                IP_ADAPTER_ADDRESSES_LH_0 {
                    Anonymous:
                        IP_ADAPTER_ADDRESSES_LH_0_0 {
                            Length: _,
                            IfIndex: if_index,
                        },
                } if if_index != 0 => if_index,
                _ => adapter.Ipv6IfIndex,
            };

            links.push(Link {
                name: friendly_name,
                mac_addr,
                if_index,
                if_type: IfType::try_from(adapter.IfType).ok().map(|t| t.to_string()),
                parent_index: None,
            });

            // 现在支持单播地址获取,组播/多播地址未支持
            let mut unicast_addrs_ptr = adapter.FirstUnicastAddress;
            while !unicast_addrs_ptr.is_null() {
                let ip_list = unicast_addrs_ptr.as_ref().unwrap();

                let address = match parse_sockaddr(ip_list.Address.lpSockaddr) {
                    Some(addr) => addr,
                    None => {
                        unicast_addrs_ptr = ip_list.Next;
                        continue;
                    }
                };

                addresses.push(Addr {
                    if_index,
                    ip_addr: address,
                    scope: 0,
                    prefix_len: ip_list.OnLinkPrefixLength,
                });

                unicast_addrs_ptr = ip_list.Next;
            }

            adapter_ptr = adapter.Next;
        }
        Ok((links, addresses))
    }
}

unsafe fn parse_sockaddr(sockaddr: *const SOCKADDR) -> Option<IpAddr> {
    sockaddr.as_ref().and_then(|addr| {
        if addr.sa_family == AF_INET as u16 {
            let sockaddr_in = (addr as *const SOCKADDR)
                .cast::<SOCKADDR_IN>()
                .as_ref()
                .unwrap();
            let addr_num = sockaddr_in.sin_addr.S_un.S_addr;
            if addr_num == 0 {
                None
            } else {
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(addr_num))))
            }
        } else if addr.sa_family == AF_INET6 as u16 {
            let sockaddr_in6 = (addr as *const SOCKADDR)
                .cast::<SOCKADDR_IN6>()
                .as_ref()
                .unwrap();
            let addr_word = sockaddr_in6.sin6_addr.u.Word;
            if addr_word.iter().all(|&w| w == 0) {
                None
            } else {
                Some(IpAddr::V6(Ipv6Addr::from(addr_word)))
            }
        } else {
            None
        }
    })
}

unsafe fn count_len<T: Copy + PartialEq>(p: *const T, terminator: T) -> Option<usize> {
    const MAX_LEN: usize = 1 << 30;
    (0..MAX_LEN)
        .into_iter()
        .find(|&len| *p.add(len) == terminator)
}
