use std::convert::TryFrom;
use std::fmt;
use std::iter::FromIterator;
use std::net::IpAddr;

use anyhow::{anyhow, Context, Result};
use neli::{
    consts::{
        nl::{NlTypeWrapper, NlmF, NlmFFlags},
        rtnl::*,
        socket::NlFamily,
    },
    err::NlError,
    nl::{NlPayload, Nlmsghdr},
    rtnl::{Ifinfomsg, Rtattr, Rtmsg},
    socket::NlSocketHandle,
    types::{Buffer, RtBuffer},
};

pub struct MacAddr([u8; 6]);

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

#[derive(Debug)]
pub struct Link {
    pub if_index: u32,
    pub mac_addr: MacAddr,
}

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
            for attr in payload.rtattrs.iter() {
                match attr.rta_type {
                    Ifla::Address => {
                        mac_addr = <&[u8; 6]>::try_from(attr.rta_payload.as_ref()).ok()
                    }
                    _ => (),
                }
            }
            if let Some(mac_addr) = mac_addr {
                links.push(Link {
                    if_index: payload.ifi_index as u32,
                    mac_addr: MacAddr(*mac_addr),
                })
            }
        }
    }
    Ok(links)
}

#[derive(Debug)]
pub struct Route {
    pub src_ip: IpAddr,
    pub oif_index: u32,
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
            for attr in payload.rtattrs.iter() {
                match attr.rta_type {
                    Rta::Prefsrc => src_ip = parse_ip_slice(attr.rta_payload.as_ref()),
                    Rta::Oif => {
                        oif_index = <&[u8; 4]>::try_from(attr.rta_payload.as_ref())
                            .ok()
                            .map(|x| u32::from_le_bytes(*x))
                    }
                    _ => (),
                }
            }
            match (src_ip, oif_index) {
                (Some(src_ip), Some(oif_index)) => routes.push(Route { src_ip, oif_index }),
                _ => (),
            }
        }
    }
    Ok(routes)
}

pub fn get_route_src_ip_and_mac(dest: &IpAddr) -> Result<(IpAddr, MacAddr)> {
    let (src_ip, oif_index) = get_route_src_ip_and_ifindex(dest)?;
    for link in link_list().context("failed to get links")? {
        if link.if_index == oif_index {
            return Ok((src_ip, link.mac_addr));
        }
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
