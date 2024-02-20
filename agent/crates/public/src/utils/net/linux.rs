/*
 * Copyright (c) 2023 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::{
    ffi::{CStr, CString},
    fs,
    mem::MaybeUninit,
    net::{IpAddr, Ipv6Addr, SocketAddrV6},
    path::{Path, PathBuf},
    time::Duration,
};

use ipnet::IpNet;
use log::warn;
use neli::{
    consts::{nl::*, rtnl::*, socket::*},
    err::NlError::Nlmsgerr,
    nl::{NlPayload, Nlmsghdr},
    rtnl::{Ifaddrmsg, Ifinfomsg, Rtattr, Rtmsg},
    socket::NlSocketHandle,
    types::{Buffer, RtBuffer},
};
use nix::libc::IFLA_INFO_KIND;
use pnet::{
    datalink::{self, NetworkInterface},
    packet::icmpv6::{
        ndp::{MutableNeighborSolicitPacket, NdpOption, NdpOptionTypes, NeighborAdvertPacket},
        Icmpv6Code, Icmpv6Types,
    },
};
use regex::Regex;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use super::parse_ip_slice;
use super::{arp::lookup as arp_lookup, Error, Result};
use super::{Addr, Link, LinkFlags, LinkStats, MacAddr, NeighborEntry, Route, Rule};

use crate::bytes::{read_u16_le, read_u32_le, read_u64_le};

pub const IF_TYPE_IPVLAN: &'static str = "ipvlan";

const NETLINK_ERROR_NOADDR: i32 = -19;

/*
* TODO
*  BPF socket 构造
*
*/

pub fn neighbor_lookup(mut dest_addr: IpAddr) -> Result<NeighborEntry> {
    let routes = route_get(&dest_addr)?;
    let Some(route) = routes.iter().find(|&r| r.pref_src.is_some()) else {
        return Err(Error::NeighborLookup(format!(
            "no such route with destination address=({})",
            dest_addr
        )));
    };
    let src_addr = route.pref_src.unwrap();

    // 如果是外部网地址，那么能获取到gateway
    if let Some(gw) = route.gateway {
        dest_addr = gw;
    }

    let selected_interface = match datalink::interfaces()
        .into_iter()
        .find(|i| i.index == route.oif_index)
    {
        Some(interface) => interface,
        None => {
            return Err(Error::NeighborLookup(format!(
                "could not find selected interface (if_index={})",
                route.oif_index
            )));
        }
    };

    let target_mac = match (dest_addr, src_addr) {
        (IpAddr::V4(dest_addr), IpAddr::V4(src_addr)) => {
            arp_lookup(&selected_interface, src_addr, dest_addr)?
        }
        (IpAddr::V6(dest_addr), IpAddr::V6(_)) => ndp_lookup(&selected_interface, dest_addr)?,
        _ => unreachable!(),
    };

    let NetworkInterface {
        name,
        index,
        mac,
        flags,
        ..
    } = selected_interface;

    if mac.is_none() {
        return Err(Error::NeighborLookup(String::from(
            "source interface MAC address is none",
        )));
    }

    Ok(NeighborEntry {
        src_addr: src_addr,
        src_link: Link {
            if_index: index,
            mac_addr: MacAddr(mac.unwrap().octets()),
            name,
            flags: flags.into(),
            ..Default::default()
        },
        dest_addr,
        dest_mac_addr: target_mac,
    })
}

fn ndp_lookup(selected_interface: &NetworkInterface, dest_addr: Ipv6Addr) -> Result<MacAddr> {
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6));
    if socket.is_err() {
        return Err(Error::NeighborLookup("raw socket".to_string()));
    }
    let socket = socket.unwrap();

    let ret = socket.bind_device(Some(selected_interface.name.as_bytes()));
    if ret.is_err() {
        return Err(Error::NeighborLookup("bind device".to_string()));
    }
    let ret = socket.set_multicast_hops_v6(255);
    if ret.is_err() {
        return Err(Error::NeighborLookup("multi hops limit".to_string()));
    }
    let ret = socket.set_unicast_hops_v6(255);
    if ret.is_err() {
        return Err(Error::NeighborLookup("unicast hops limit".to_string()));
    }
    let ret = socket.set_read_timeout(Some(Duration::from_millis(200)));
    if ret.is_err() {
        return Err(Error::NeighborLookup("read timeout".to_string()));
    }

    for ip_net in selected_interface.ips.iter() {
        match ip_net.ip() {
            IpAddr::V6(addr) if ip_net.contains(IpAddr::from(dest_addr)) => {
                let ret = socket.bind(&SockAddr::from(SocketAddrV6::new(addr, 0, 0, 0)));
                if ret.is_err() {
                    warn!("bind {:?}", ret.unwrap_err());
                }
                break;
            }
            _ => {}
        }
    }

    let mut request = [0u8; 32];
    let mut ns_packet = MutableNeighborSolicitPacket::new(&mut request[..]).unwrap();
    ns_packet.set_icmpv6_type(Icmpv6Types::NeighborSolicit);
    ns_packet.set_icmpv6_code(Icmpv6Code(0));
    ns_packet.set_target_addr(dest_addr.clone());
    let mac = selected_interface.mac.unwrap().octets();
    // length = size_of(type) + size_of(length) + size_of(data) 单位是8字节，所以是1
    // https://mirrors.ustc.edu.cn/rfc/rfc4861.html#section-4.6.1
    let ndp_option = NdpOption {
        option_type: NdpOptionTypes::SourceLLAddr,
        length: 1,
        data: Vec::from(mac),
    };
    ns_packet.set_options(&[ndp_option]);
    let ret = socket.send_to(&request, &to_multi_address(dest_addr));
    if ret.is_err() {
        return Err(Error::NeighborLookup("send to".to_string()));
    }

    let mut response: [MaybeUninit<u8>; 1000] = unsafe { MaybeUninit::uninit().assume_init() };

    let ret = socket.recv(&mut response);
    if ret.is_err() {
        return Err(Error::NeighborLookup("recv".to_string()));
    }
    let n = ret.unwrap();
    let response = response[..n]
        .iter()
        .map(|x| unsafe { x.assume_init_read() })
        .collect::<Vec<u8>>();

    NeighborAdvertPacket::new(response.as_slice())
        .and_then(|pkt| {
            pkt.get_options()
                .into_iter()
                .find(|option| option.option_type == NdpOptionTypes::TargetLLAddr)
                .and_then(|option| {
                    <&[u8; 6]>::try_from(option.data.as_slice())
                        .ok()
                        .map(|m| MacAddr(*m))
                })
        })
        .ok_or(Error::NeighborLookup(String::from(
            "parse neighbor advertisement packet failed and get none MAC address",
        )))
}

fn to_multi_address(addr: Ipv6Addr) -> SockAddr {
    let suffix = addr.segments();
    let multi = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00 | suffix[6], suffix[7]);
    SockAddr::from(SocketAddrV6::new(multi, 0, 0, 0))
}

const MIN_RTNL_LINK_STATS64_LEN: usize = 64;

fn request_link_info(name: Option<&str>) -> Result<Vec<Link>> {
    let rtattrs = match name {
        Some(n) => RtBuffer::from_iter(
            vec![Rtattr::new(
                None,
                Ifla::Ifname,
                CString::new(n).unwrap().to_bytes(),
            )?]
            .into_iter(),
        ),
        _ => RtBuffer::new(),
    };
    let msg = Ifinfomsg::new(
        RtAddrFamily::Unspecified,
        Arphrd::None,
        0,
        IffFlags::empty(),
        IffFlags::empty(),
        rtattrs,
    );
    let mut req = Nlmsghdr::new(
        None,
        Rtm::Getlink,
        NlmFFlags::new(&[NlmF::Request]),
        None,
        None,
        NlPayload::Payload(msg),
    );
    match name {
        Some(_) => req.nl_flags.set(&NlmF::Ack),
        None => req.nl_flags.set(&NlmF::Dump),
    }

    let mut socket = NlSocketHandle::connect(NlFamily::Route, None, &[])?;
    socket.send(req)?;

    let mut links = vec![];
    for m in socket.iter::<NlTypeWrapper, Ifinfomsg>(false) {
        if let Err(Nlmsgerr(e)) = m.as_ref() {
            if e.error == NETLINK_ERROR_NOADDR && name.is_some() {
                return Err(Error::LinkNotFound(name.unwrap().into()));
            }
        }
        let m = m?;
        if let NlTypeWrapper::GenlId(_) = m.nl_type {
            let payload = m.get_payload()?;

            let mut mac_addr = None;
            let mut if_type = None;
            let mut peer_index = None;
            let mut if_name = None;
            let mut link_netnsid = None;
            let mut link_stats = None;

            for attr in payload.rtattrs.iter() {
                match attr.rta_type {
                    Ifla::Address => {
                        mac_addr = <&[u8; 6]>::try_from(attr.rta_payload.as_ref()).ok()
                    }
                    Ifla::Linkinfo => {
                        let info = attr.rta_payload.as_ref();
                        let len = read_u16_le(&info[..2]);
                        let attr_type = read_u16_le(&info[2..4]);

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
                            peer_index = Some(read_u32_le(payload));
                        }
                    }
                    Ifla::LinkNetnsid => {
                        if let Some(payload) = attr.rta_payload.as_ref().get(..4) {
                            link_netnsid = Some(read_u32_le(payload));
                        }
                    }
                    Ifla::Stats64 if attr.rta_payload.len() >= MIN_RTNL_LINK_STATS64_LEN => {
                        /* the buffer is rtnl_link_stat64

                        link: https://github.com/torvalds/linux/blob/1c59d383390f970b891b503b7f79b63a02db2ec5/include/uapi/linux/if_link.h#L218C27-L218C27

                            struct rtnl_link_stats64 {
                                __u64   rx_packets;
                                __u64   tx_packets;
                                __u64   rx_bytes;
                                __u64   tx_bytes;
                                __u64   rx_errors;
                                __u64   tx_errors;
                                __u64   rx_dropped;
                                __u64   tx_dropped;

                                ... (more)
                            }

                        */
                        let payload = attr.rta_payload.as_ref();
                        link_stats = Some(LinkStats {
                            rx_packets: read_u64_le(payload),
                            tx_packets: read_u64_le(&payload[8..]),
                            rx_bytes: read_u64_le(&payload[16..]),
                            tx_bytes: read_u64_le(&payload[24..]),
                            rx_dropped: read_u64_le(&payload[48..]),
                            tx_dropped: read_u64_le(&payload[56..]),
                        });
                    }
                    _ => {}
                }
            }

            if let Some(mac) = mac_addr {
                links.push(Link {
                    if_index: payload.ifi_index as u32,
                    name: if_name.unwrap_or_default(),
                    mac_addr: MacAddr(*mac),
                    flags: (&payload.ifi_flags).into(),
                    if_type,
                    peer_index,
                    link_netnsid,
                    stats: link_stats.unwrap_or_default(),
                });
            }
        }
    }

    Ok(links)
}

fn inner_link_by_name<S: AsRef<str>>(name: S) -> Result<Link> {
    request_link_info(Some(name.as_ref())).map(|mut links| {
        if links.len() > 0 {
            links.pop().unwrap()
        } else {
            unreachable!()
        }
    })
}

pub fn link_by_name<S: AsRef<str>>(name: S) -> Result<Link> {
    let name = name.as_ref();
    match inner_link_by_name(name) {
        Ok(link) => return Ok(link),
        Err(last_error) => {
            // In some Centos6 environments link_by_name will return an error,
            // by using link_list instead.
            match link_list() {
                Err(e) => {
                    return Err(Error::LinkNotFound(format!(
                        "link_by_name error: {:?} and link_list error: {:?}",
                        last_error, e
                    )))
                }
                Ok(list) => {
                    for nic in &list {
                        if nic.name == name.to_string() {
                            return Ok(nic.clone());
                        }
                    }
                    return Err(Error::LinkNotFound(format!(
                        "link_by_name error: {:?} and link_list error: not found by name {}",
                        last_error, name
                    )));
                }
            };
        }
    };
}

pub fn links_by_name_regex<S: AsRef<str>>(regex: S) -> Result<Vec<Link>> {
    let regex = regex.as_ref();
    if regex == "" {
        return Ok(vec![]);
    }
    let regex = if regex.ends_with('$') {
        Regex::new(regex)
    } else {
        Regex::new(&format!("{}$", regex))
    }?;
    Ok(link_list()?
        .into_iter()
        .filter(|link| {
            if !link.flags.contains(LinkFlags::LOOPBACK) {
                // filter zero mac
                if link.mac_addr == MacAddr::ZERO {
                    if regex.is_match(&link.name) {
                        warn!(
                            "link {} has invalid mac address {}",
                            link.name, link.mac_addr
                        );
                    }
                    return false;
                }
            }
            regex.is_match(&link.name)
        })
        .collect())
}

pub fn link_list() -> Result<Vec<Link>> {
    request_link_info(None)
}

pub fn addr_list() -> Result<Vec<Addr>> {
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
    for m in socket.iter::<NlTypeWrapper, Ifaddrmsg>(false) {
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

fn route_send_req(req: Nlmsghdr<Rtm, Rtmsg>) -> Result<Vec<Route>> {
    let mut socket = NlSocketHandle::connect(NlFamily::Route, None, &[])?;
    socket.send(req)?;

    let mut routes = vec![];
    for m in socket.iter::<NlTypeWrapper, Rtmsg>(false) {
        let m = m?;
        if let NlTypeWrapper::Rtm(_) = m.nl_type {
            let payload = m.get_payload()?;

            let mut table = None;
            let mut pref_src = None;
            let mut dst_ip = None;
            let mut oif_index = None;
            let mut gateway = None;
            for attr in payload.rtattrs.iter() {
                match attr.rta_type {
                    Rta::Table => {
                        if let Ok(bs) = <&[u8; 4]>::try_from(attr.rta_payload.as_ref()) {
                            table.replace(u32::from_le_bytes(*bs));
                        }
                    }
                    Rta::Prefsrc => pref_src = parse_ip_slice(attr.rta_payload.as_ref()),
                    Rta::Dst => dst_ip = parse_ip_slice(attr.rta_payload.as_ref()),
                    Rta::Oif => {
                        if let Ok(bs) = <&[u8; 4]>::try_from(attr.rta_payload.as_ref()) {
                            oif_index.replace(u32::from_le_bytes(*bs));
                        }
                    }
                    Rta::Gateway => gateway = parse_ip_slice(attr.rta_payload.as_ref()),
                    _ => (),
                }
            }
            if let (Some(table), Some(oif_index)) = (table, oif_index) {
                routes.push(Route {
                    table,
                    pref_src,
                    dst_ip: dst_ip.and_then(|ip| IpNet::new(ip, payload.rtm_dst_len).ok()),
                    oif_index,
                    gateway,
                });
            }
        }
    }
    Ok(routes)
}

pub fn route_get(dest: &IpAddr) -> Result<Vec<Route>> {
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
            rtm_flags: RtmFFlags::empty(),
            rtattrs: vec![Rtattr::new(None, Rta::Dst, buf)?]
                .into_iter()
                .collect(),
        }
    };
    route_send_req(Nlmsghdr::new(
        None,
        Rtm::Getroute,
        NlmFFlags::new(&[NlmF::Request]),
        None,
        None,
        NlPayload::Payload(msg),
    ))
}

pub fn get_route_src_ip_and_mac(dest: &IpAddr) -> Result<(IpAddr, MacAddr)> {
    let (src_ip, oif_index) = get_route_src_ip_and_ifindex(dest)?;
    let links = link_list()?;
    for link in links.iter() {
        if link.if_index == oif_index {
            if link.mac_addr == MacAddr::ZERO {
                // loopback，需要从ip地址找mac
                break;
            }
            return Ok((src_ip, link.mac_addr.clone()));
        }
    }
    for addr in addr_list()? {
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
    Err(Error::LinkNotFoundIndex(oif_index))
}

pub fn get_route_src_ip(dest: &IpAddr) -> Result<IpAddr> {
    get_route_src_ip_and_ifindex(dest).map(|r| r.0)
}

fn get_route_src_ip_and_ifindex(dest: &IpAddr) -> Result<(IpAddr, u32)> {
    let routes = route_get(dest)?;
    let Some(route) = routes.iter().find(|&r| r.pref_src.is_some()) else {
        return Err(Error::NoRouteToHost(dest.to_string()));
    };
    Ok((route.pref_src.unwrap(), routes[0].oif_index))
}

pub fn get_route_src_ip_interface_name(dest_addr: &IpAddr) -> Result<String> {
    let if_index = get_route_src_ip_and_ifindex(dest_addr).map(|r| r.1)?;
    let links = link_list()?;
    for link in links {
        if link.if_index == if_index {
            return Ok(link.name.clone());
        }
    }
    return Err(Error::LinkNotFound(dest_addr.to_string()));
}

pub fn route_list() -> Result<Vec<Route>> {
    let msg = Rtmsg {
        rtm_family: RtAddrFamily::Unspecified,
        rtm_dst_len: 0,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: RtTable::Unspec,
        rtm_protocol: Rtprot::Unspec,
        rtm_scope: RtScope::Universe,
        rtm_type: Rtn::Unspec,
        rtm_flags: RtmFFlags::empty(),
        rtattrs: Default::default(),
    };
    route_send_req(Nlmsghdr::new(
        None,
        Rtm::Getroute,
        NlmFFlags::new(&[NlmF::Request, NlmF::Dump]),
        None,
        None,
        NlPayload::Payload(msg),
    ))
}

pub fn rule_list() -> Result<Vec<Rule>> {
    let msg = Rtmsg {
        rtm_family: RtAddrFamily::Unspecified,
        rtm_dst_len: 0,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: RtTable::Unspec,
        rtm_protocol: Rtprot::Unspec,
        rtm_scope: RtScope::Universe,
        rtm_type: Rtn::Unspec,
        rtm_flags: RtmFFlags::empty(),
        rtattrs: Default::default(),
    };
    let req = Nlmsghdr::new(
        None,
        Rtm::Getrule,
        NlmFFlags::new(&[NlmF::Request, NlmF::Dump]),
        None,
        None,
        NlPayload::Payload(msg),
    );
    let mut socket = NlSocketHandle::connect(NlFamily::Route, None, &[])?;
    socket.send(req)?;

    let mut rules = vec![];
    for m in socket.iter::<NlTypeWrapper, Rtmsg>(false) {
        let m = m?;
        if m.nl_type != Rtm::Newrule.into() {
            continue;
        }

        let payload = m.get_payload()?;

        let mut table = None;
        let mut dst_ip = None;
        for attr in payload.rtattrs.iter() {
            match attr.rta_type {
                Rta::Table => {
                    if let Ok(bs) = <&[u8; 4]>::try_from(attr.rta_payload.as_ref()) {
                        table.replace(u32::from_le_bytes(*bs));
                    }
                }
                Rta::Dst => dst_ip = parse_ip_slice(attr.rta_payload.as_ref()),
                _ => (),
            }
        }
        if let Some(table) = table {
            rules.push(Rule {
                table,
                dst_ip: dst_ip.and_then(|ip| IpNet::new(ip, payload.rtm_dst_len).ok()),
            });
        }
    }
    Ok(rules)
}

fn read_u8_from_file<P: AsRef<Path>>(path: P) -> Option<u8> {
    match fs::read_to_string(path.as_ref()) {
        Ok(value) => value.trim().parse().ok(),
        _ => None,
    }
}

pub fn ipv6_enabled() -> bool {
    match read_u8_from_file("/sys/module/ipv6/parameters/disable") {
        Some(v) if v != 0 => false,
        _ => true,
    }
}

pub fn ipv6_enabled_for_link<S: AsRef<str>>(name: S) -> bool {
    if !ipv6_enabled() {
        return false;
    }

    let mut path = PathBuf::from("/proc/sys/net/ipv6/conf");
    path.push(name.as_ref());
    path.push("disable_ipv6");
    match read_u8_from_file(&path) {
        None => false, // file not found means no ipv6
        Some(v) => v == 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_link_by_name() {
        let links = link_list().unwrap();
        assert!(links.len() > 0);
        for link in links {
            assert_eq!(link.if_index, link_by_name(&link.name).unwrap().if_index);
        }
    }

    #[test]
    fn get_link_by_regex() {
        let links = links_by_name_regex("^lo").unwrap();
        assert_eq!(&links[0].name, "lo");

        for link in links_by_name_regex("^et.*").unwrap() {
            assert!(link.name.starts_with("et"));
        }

        for link in links_by_name_regex("^tap.*").unwrap() {
            assert!(link.name.starts_with("tap"));
        }

        assert!(links_by_name_regex("***").is_err());
    }

    #[test]
    fn get_nonexist_link() {
        match link_by_name("nonexist42") {
            Err(Error::LinkNotFound(link)) => assert_eq!(link, String::from("nonexist42")),
            _ => assert!(false),
        }
    }
}
