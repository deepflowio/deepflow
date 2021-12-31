use std::{ffi::CStr, net::IpAddr};

use anyhow::{anyhow, Context, Result};
use neli::{
    consts::{nl::*, rtnl::*, socket::*},
    err::NlError,
    nl::{NlPayload, Nlmsghdr},
    rtnl::*,
    socket::*,
    types::{Buffer, RtBuffer},
};
use nix::libc::IFLA_INFO_KIND;

use super::{Addr, Link, MacAddr, Route, MAC_ADDR_ZERO};

/*
* TODO
*  BPF socket 构造
*
*/

pub fn link_list() -> Result<Vec<Link>, NlError> {
    let msg = Ifinfomsg::new(
        RtAddrFamily::Unspecified,
        Arphrd::None,
        0,
        IffFlags::empty(),
        IffFlags::empty(),
        RtBuffer::new(),
    );
    let req = Nlmsghdr::new(
        None,
        Rtm::Getlink,
        NlmFFlags::new(&[NlmF::Request, NlmF::Dump]),
        None,
        None,
        NlPayload::Payload(msg),
    );
    let mut socket = NlSocketHandle::connect(NlFamily::Route, None, &[])?;
    socket.send(req)?;

    let mut links = vec![];
    for m in socket.iter::<Ifinfomsg>(false) {
        let m = m?;
        if let NlTypeWrapper::GenlId(_) = m.nl_type {
            let payload = m.get_payload()?;

            let mut mac_addr = None;
            let mut if_type = None;
            let mut parent_index = None;
            let mut if_name = None;

            for attr in payload.rtattrs.iter() {
                match attr.rta_type {
                    Ifla::Address => {
                        mac_addr = <&[u8; 6]>::try_from(attr.rta_payload.as_ref()).ok()
                    }
                    Ifla::Linkinfo => {
                        let info = attr.rta_payload.as_ref();
                        let len = u16::from_le_bytes(*<&[u8; 2]>::try_from(&info[..2]).unwrap());
                        let attr_type =
                            u16::from_le_bytes(*<&[u8; 2]>::try_from(&info[2..4]).unwrap());

                        if let Some(attr_payload) = info.get(4..len as usize) {
                            // INFO_KIND 排列payload第一， IFLA_INFO_KIND = 1
                            if attr_type == IFLA_INFO_KIND {
                                if_type = CStr::from_bytes_with_nul(attr_payload)
                                    .ok()
                                    .and_then(|c| c.to_str().ok())
                                    .map(String::from);
                            }
                        }
                    }
                    Ifla::Ifname => {
                        if_name = CStr::from_bytes_with_nul(attr.rta_payload.as_ref())
                            .ok()
                            .and_then(|c| c.to_str().ok())
                            .map(String::from);
                    }
                    Ifla::Link => {
                        if let Some(payload) = attr.rta_payload.as_ref().get(..4) {
                            parent_index =
                                Some(u32::from_le_bytes(*<&[u8; 4]>::try_from(payload).unwrap()));
                        }
                    }
                    _ => {}
                }
            }

            if let Some(mac) = mac_addr {
                links.push(Link {
                    if_index: payload.ifi_index as u32,
                    name: if_name.unwrap_or_default(),
                    mac_addr: MacAddr(*mac),
                    if_type,
                    parent_index,
                });
            }
        }
    }

    Ok(links)
}

fn parse_ip_slice(bs: &[u8]) -> Option<IpAddr> {
    if let Ok(s) = <&[u8; 4]>::try_from(bs) {
        Some(IpAddr::from(*s))
    } else if let Ok(s) = <&[u8; 16]>::try_from(bs) {
        Some(IpAddr::from(*s))
    } else {
        None
    }
}

pub fn addr_list() -> Result<Vec<Addr>, NlError> {
    let msg = Ifaddrmsg {
        ifa_family: RtAddrFamily::Unspecified,
        ifa_prefixlen: 0,
        ifa_flags: IfaFFlags::empty(),
        ifa_scope: 0,
        ifa_index: 0,
        rtattrs: RtBuffer::new(),
    };
    let req = Nlmsghdr::new(
        None,
        Rtm::Getaddr,
        NlmFFlags::new(&[NlmF::Request, NlmF::Dump]),
        None,
        None,
        NlPayload::Payload(msg),
    );
    let mut socket = NlSocketHandle::connect(NlFamily::Route, None, &[])?;
    socket.send(req)?;

    let mut addrs = vec![];
    for m in socket.iter::<Ifaddrmsg>(false) {
        let m = m?;
        if m.nl_type != Rtm::Newaddr.into() {
            continue;
        }

        let payload = m.get_payload()?;

        let mut ip_addr = None;
        for attr in payload.rtattrs.iter() {
            match attr.rta_type {
                Ifa::Address => ip_addr = parse_ip_slice(attr.rta_payload.as_ref()),
                _ => (),
            }
        }
        if let Some(ip_addr) = ip_addr {
            addrs.push(Addr {
                if_index: payload.ifa_index as u32,
                ip_addr,
                prefix_len: payload.ifa_prefixlen as u8,
                scope: payload.ifa_scope as u8,
            });
        }
    }
    Ok(addrs)
}

pub fn route_get(dest: &IpAddr) -> Result<Vec<Route>, NlError> {
    let msg = {
        let (rtm_family, rtm_dst_len, buf): (_, _, Buffer) = match dest {
            IpAddr::V4(addr) => (RtAddrFamily::Inet, 32, addr.octets()[..].into()),
            IpAddr::V6(addr) => (RtAddrFamily::Inet6, 128, addr.octets()[..].into()),
        };
        Rtmsg {
            rtm_family,
            rtm_dst_len,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: RtTable::Unspec,
            rtm_protocol: Rtprot::Unspec,
            rtm_scope: RtScope::Universe,
            rtm_type: Rtn::Unspec,
            rtm_flags: RtmFFlags::new(&[RtmF::LookupTable]),
            rtattrs: vec![Rtattr::new(None, Rta::Dst, buf)?]
                .into_iter()
                .collect(),
        }
    };
    let req = Nlmsghdr::new(
        None,
        Rtm::Getroute,
        NlmFFlags::new(&[NlmF::Request]),
        None,
        None,
        NlPayload::Payload(msg),
    );
    let mut socket = NlSocketHandle::connect(NlFamily::Route, None, &[])?;
    socket.send(req)?;

    let mut routes = vec![];
    for m in socket.iter::<Rtmsg>(false) {
        let m = m?;
        if let NlTypeWrapper::Rtm(_) = m.nl_type {
            let payload = m.get_payload()?;

            let mut src_ip = None;
            let mut oif_index = None;
            let mut gateway = None;
            for attr in payload.rtattrs.iter() {
                match attr.rta_type {
                    Rta::Prefsrc => src_ip = parse_ip_slice(attr.rta_payload.as_ref()),
                    Rta::Oif => {
                        oif_index = <&[u8; 4]>::try_from(attr.rta_payload.as_ref())
                            .ok()
                            .map(|x| u32::from_le_bytes(*x))
                    }
                    Rta::Gateway => gateway = parse_ip_slice(attr.rta_payload.as_ref()),
                    _ => (),
                }
            }
            match (src_ip, oif_index) {
                (Some(src_ip), Some(oif_index)) => routes.push(Route {
                    src_ip,
                    oif_index,
                    gateway,
                }),
                _ => (),
            }
        }
    }
    Ok(routes)
}

pub fn get_route_src_ip_and_mac(dest: &IpAddr) -> Result<(IpAddr, MacAddr)> {
    let (src_ip, oif_index) = get_route_src_ip_and_ifindex(dest)?;
    let links = link_list().context("failed to get links")?;
    for link in links.iter() {
        if link.if_index == oif_index {
            if link.mac_addr == MAC_ADDR_ZERO {
                // loopback，需要从ip地址找mac
                break;
            }
            return Ok((src_ip, link.mac_addr.clone()));
        }
    }
    for addr in addr_list().context("failed to get addrs")? {
        if addr.ip_addr != src_ip {
            continue;
        }
        for link in links {
            if addr.if_index == link.if_index {
                return Ok((src_ip, link.mac_addr));
            }
        }
        break;
    }
    Err(anyhow!("link with index {} not found", oif_index))
}

pub fn get_route_src_ip(dest: &IpAddr) -> Result<IpAddr> {
    get_route_src_ip_and_ifindex(dest).map(|r| r.0)
}

fn get_route_src_ip_and_ifindex(dest: &IpAddr) -> Result<(IpAddr, u32)> {
    let routes = route_get(dest).with_context(|| format!("failed to get routes for {}", dest))?;
    if routes.is_empty() {
        return Err(anyhow!("no route found for {}", dest));
    }
    Ok((routes[0].src_ip, routes[0].oif_index))
}
