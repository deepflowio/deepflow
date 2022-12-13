/*
 * Copyright (c) 2022 Yunshan Networks
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
    io::ErrorKind,
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV6},
    time::Duration,
};

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
    datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface},
    packet::{
        arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
        ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
        icmpv6::{
            ndp::{MutableNeighborSolicitPacket, NdpOption, NdpOptionTypes, NeighborAdvertPacket},
            Icmpv6Code, Icmpv6Types,
        },
        Packet,
    },
};
use regex::Regex;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use super::parse_ip_slice;
use super::{Addr, Link, LinkFlags, MacAddr, NeighborEntry, Route};
use super::{Error, Result};

pub const IF_TYPE_IPVLAN: &'static str = "ipvlan";

const RCV_TIMEOUT: Duration = Duration::from_millis(500);

const NETLINK_ERROR_NOADDR: i32 = -19;

/*
* TODO
*  BPF socket 构造
*
*/

pub fn neighbor_lookup(mut dest_addr: IpAddr) -> Result<NeighborEntry> {
    let mut routes = route_get(&dest_addr)?;
    if routes.is_empty() {
        return Err(Error::NeighborLookup(format!(
            "no such route with destination address=({})",
            dest_addr
        )));
    }
    let route = routes.swap_remove(0);

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

    let target_mac = match (dest_addr, route.src_ip) {
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
        src_addr: route.src_ip,
        src_link: Link {
            if_index: index,
            mac_addr: MacAddr(mac.unwrap().octets()),
            name,
            flags: flags.into(),
            if_type: None,
            peer_index: None,
            link_netnsid: None,
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

// lo ip，MAC地址返为 MAC_ADDR_ZERO
// source_ip: 发包IP
// target_ip： 要查询mac 的IP
// MacAddr: target_ip 的mac
// Link: 发包Link
fn arp_lookup(
    selected_interface: &NetworkInterface,
    source_addr: Ipv4Addr,
    dest_addr: Ipv4Addr,
) -> Result<MacAddr> {
    let channel_config = datalink::Config {
        // 设置接收timeout
        read_timeout: Some(RCV_TIMEOUT),
        ..datalink::Config::default()
    };

    let (mut tx, mut rx) = match datalink::channel(&selected_interface, channel_config) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            return Err(Error::NeighborLookup(String::from(
                "not an ethernet datalink channel",
            )));
        }
        Err(error) => {
            return Err(Error::NeighborLookup(format!(
                "datalink channel creation failed error: {}",
                error
            )));
        }
    };

    send_arp_request(&mut tx, selected_interface, source_addr, dest_addr)?;
    receive_arp_response(&mut rx)
}

fn to_multi_address(addr: Ipv6Addr) -> SockAddr {
    let suffix = addr.segments();
    let multi = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00 | suffix[6], suffix[7]);
    SockAddr::from(SocketAddrV6::new(multi, 0, 0, 0))
}

fn send_arp_request(
    tx: &mut Box<dyn DataLinkSender>,
    interface: &NetworkInterface,
    source_addr: Ipv4Addr,
    dest_addr: Ipv4Addr,
) -> Result<()> {
    const ETHERNET_STD_PACKET_SIZE: usize = 42;
    const ARP_PACKET_SIZE: usize = 28;
    const HW_ADDR_LEN: u8 = 6;
    const IP_ADDR_LEN: u8 = 4;

    let mut ethernet_buffer = [0u8; ETHERNET_STD_PACKET_SIZE];

    let mut ethernet_packet = match MutableEthernetPacket::new(&mut ethernet_buffer) {
        Some(pkt) => pkt,
        None => {
            return Err(Error::NeighborLookup(String::from(
                "could not create ethernet packet",
            )));
        }
    };

    let src_mac = match interface.mac {
        Some(mac) => mac,
        None => {
            return Err(Error::NeighborLookup(String::from(
                "interface should have a MAC address",
            )));
        }
    };
    let target_mac = datalink::MacAddr::broadcast();

    ethernet_packet.set_destination(target_mac);
    ethernet_packet.set_source(src_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; ARP_PACKET_SIZE];

    let mut arp_packet = match MutableArpPacket::new(&mut arp_buffer) {
        Some(p) => p,
        None => {
            return Err(Error::NeighborLookup(String::from(
                "could not create ARP packet",
            )));
        }
    };

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(HW_ADDR_LEN);
    arp_packet.set_proto_addr_len(IP_ADDR_LEN);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(src_mac);
    arp_packet.set_sender_proto_addr(source_addr);
    arp_packet.set_target_hw_addr(target_mac);
    arp_packet.set_target_proto_addr(dest_addr);
    ethernet_packet.set_payload(arp_packet.packet());

    tx.send_to(ethernet_packet.packet(), Some(interface.clone()));

    Ok(())
}

fn receive_arp_response(rx: &mut Box<dyn DataLinkReceiver>) -> Result<MacAddr> {
    match rx.next() {
        Ok(buffer) => match EthernetPacket::new(buffer) {
            Some(ethernet_packet) => {
                let is_arp_type = matches!(ethernet_packet.get_ethertype(), EtherTypes::Arp);
                if !is_arp_type {
                    return Err(Error::NeighborLookup(String::from("invalid ARP type")));
                }
                let arp_packet =
                    ArpPacket::new(&buffer[MutableEthernetPacket::minimum_packet_size()..]);
                match arp_packet {
                    Some(arp) => {
                        return Ok(MacAddr(arp.get_sender_hw_addr().octets()));
                    }
                    None => {
                        return Err(Error::NeighborLookup(String::from(
                            "could not create ARP packet",
                        )));
                    }
                }
            }
            None => {
                return Err(Error::NeighborLookup(String::from(
                    "could not build ethernet packet",
                )));
            }
        },
        Err(e) => match e.kind() {
            // 因为 channel_config 设置了timeout，所以等不到就会报错
            ErrorKind::TimedOut => {
                return Err(Error::NeighborLookup(String::from(
                    "receive ethernet packet timeout",
                )));
            }
            _ => {
                return Err(Error::NeighborLookup(format!(
                    "receive ARP request error: {}",
                    e
                )));
            }
        },
    }
}

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
                            peer_index =
                                Some(u32::from_le_bytes(*<&[u8; 4]>::try_from(payload).unwrap()));
                        }
                    }
                    Ifla::LinkNetnsid => {
                        if let Some(payload) = attr.rta_payload.as_ref().get(..4) {
                            link_netnsid =
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
                    flags: (&payload.ifi_flags).into(),
                    if_type,
                    peer_index,
                    link_netnsid,
                });
            }
        }
    }

    Ok(links)
}

pub fn link_by_name<S: AsRef<str>>(name: S) -> Result<Link> {
    request_link_info(Some(name.as_ref())).map(|mut links| {
        if links.len() > 0 {
            links.pop().unwrap()
        } else {
            unreachable!()
        }
    })
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
                    warn!(
                        "link {} has invalid mac address {}",
                        link.name, link.mac_addr
                    );
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
    for m in socket.iter::<NlTypeWrapper, Rtmsg>(false) {
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
    if routes.is_empty() {
        return Err(Error::NoRouteToHost(dest.to_string()));
    }
    Ok((routes[0].src_ip, routes[0].oif_index))
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
