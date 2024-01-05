/*
 * Copyright (c) 2024 Yunshan Networks
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
    mem::{self, MaybeUninit},
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use libc::{sockaddr_storage, socklen_t};
use nix::libc::{c_int, c_void, sockaddr_ll, AF_PACKET, ARPHRD_ETHER, ETH_P_ARP};
use pnet::{
    datalink::{self, MacAddr as pMacAddr, NetworkInterface},
    packet::{
        arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
        ethernet::{EtherTypes, MutableEthernetPacket},
        Packet,
    },
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use super::{Error, MacAddr, Result};

const RECV_TIMEOUT: Duration = Duration::from_secs(1);
const ETHERNET_STD_PACKET_SIZE: usize = 42;

fn broadcast_request(
    interface: &NetworkInterface,
    source_addr: Ipv4Addr,
    dest_addr: Ipv4Addr,
) -> Result<[u8; ETHERNET_STD_PACKET_SIZE]> {
    const ETHERNET_STD_PACKET_SIZE: usize = 42;
    const ARP_PACKET_SIZE: usize = 28;
    const HW_ADDR_LEN: u8 = 6;
    const IP_ADDR_LEN: u8 = 4;

    let mut ethernet_buffer = [0u8; ETHERNET_STD_PACKET_SIZE];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
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
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

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

    Ok(ethernet_buffer)
}

pub fn lookup(
    selected_interface: &NetworkInterface,
    source_addr: Ipv4Addr,
    dest_addr: Ipv4Addr,
) -> Result<MacAddr> {
    let socket = Socket::new(
        Domain::from(AF_PACKET as c_int),
        Type::RAW,
        Some(Protocol::from(ETH_P_ARP as i32)),
    )?;

    let mut addr_storage: sockaddr_storage = unsafe { mem::zeroed() };
    let len = mem::size_of_val(&addr_storage) as socklen_t;

    let sockaddr_ll = &mut addr_storage as &mut sockaddr_storage as *const sockaddr_storage
        as *const c_void as *mut sockaddr_ll;
    let sockaddr_ll = unsafe { &mut (*sockaddr_ll) };
    sockaddr_ll.sll_family = AF_PACKET as u16;
    sockaddr_ll.sll_protocol = (ETH_P_ARP as u16).to_be();
    sockaddr_ll.sll_ifindex = selected_interface.index as i32;
    sockaddr_ll.sll_hatype = ARPHRD_ETHER;
    sockaddr_ll.sll_pkttype = 1;
    sockaddr_ll.sll_halen = 6;
    if let Some(pMacAddr(a, b, c, d, e, f)) = selected_interface.mac {
        sockaddr_ll.sll_addr = [a, b, c, d, e, f, 0, 0];
    }

    let address = unsafe { SockAddr::new(addr_storage, len) };
    socket.bind(&address)?;
    socket.set_nonblocking(true)?;

    let request = broadcast_request(selected_interface, source_addr, dest_addr)?;
    socket.send(&request)?;

    let last = Instant::now();
    let mut now = Instant::now();
    while last + RECV_TIMEOUT > now {
        let mut response = [MaybeUninit::<u8>::uninit(); ETHERNET_STD_PACKET_SIZE];
        let n = socket.recv(response.as_mut());
        now = Instant::now();
        if n.is_err() {
            continue;
        }
        let n = n.unwrap();
        if n < MutableEthernetPacket::minimum_packet_size() {
            return Err(Error::NeighborLookup(String::from("invalid packet")));
        }

        let arp_buffer = response[MutableEthernetPacket::minimum_packet_size()..n]
            .iter()
            .map(|x| unsafe { x.assume_init() })
            .collect::<Vec<u8>>();
        let arp_packet = ArpPacket::new(arp_buffer.as_slice());
        if arp_packet.is_none() {
            continue;
        }

        let arp_packet = arp_packet.unwrap();
        if dest_addr != arp_packet.get_sender_proto_addr() {
            continue;
        }
        return Ok(MacAddr(arp_packet.get_sender_hw_addr().octets()));
    }
    return Err(Error::NeighborLookup(String::from("arp not found")));
}
