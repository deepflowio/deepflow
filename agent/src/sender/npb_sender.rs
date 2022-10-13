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

use std::collections::HashMap;
use std::io::{Error as IOError, ErrorKind, Result as IOResult};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex, Weak,
};

use libc::{c_int, socket, AF_INET, AF_INET6, SOCK_RAW};
use log::{info, warn};
use public::counter::{Countable, CounterType, CounterValue, OwnedCountable};
use socket2::{SockAddr, Socket};
#[cfg(unix)]
use std::os::unix::io::FromRawFd;
#[cfg(windows)]
use std::os::windows::io::{FromRawSocket, IntoRawSocket, RawSocket};

use crate::common::{
    enums::IpProtocol, erspan, vxlan, IPV4_ADDR_LEN, IPV4_DST_OFFSET, IPV4_PACKET_SIZE,
    IPV4_PROTO_OFFSET, IPV4_SRC_OFFSET, IPV6_ADDR_LEN, IPV6_DST_OFFSET, IPV6_PACKET_SIZE,
    IPV6_PROTO_OFFSET, IPV6_SRC_OFFSET, UDP6_PACKET_SIZE, UDP_PACKET_SIZE,
};
use crate::config::NpbConfig;
use crate::dispatcher::af_packet::{Options, Tpacket};
use crate::proto::trident::SocketType;
use crate::utils::stats::{self, StatsOption};
use public::{
    queue::Receiver,
    utils::net::{
        get_route_src_ip_and_mac, get_route_src_ip_interface_name, neighbor_lookup, MacAddr,
        MAC_ADDR_LEN,
    },
};

fn serialize_seq(
    packet: &mut Vec<u8>,
    seq: u32,
    underlay_l2_opt_size: usize,
    underlay_is_ipv6: bool,
) {
    if !underlay_is_ipv6 {
        if packet[underlay_l2_opt_size + IPV4_PROTO_OFFSET] == IpProtocol::Udp {
            let offset = UDP_PACKET_SIZE + underlay_l2_opt_size + vxlan::SEQUENCE_OFFSET;
            packet[offset] = (seq >> 16) as u8;
            packet[offset + 1..offset + 3].copy_from_slice(&(seq as u16).to_be_bytes());
        } else {
            let offset = IPV4_PACKET_SIZE + underlay_l2_opt_size + erspan::GRE_SEQUENCE_OFFSET;
            packet[offset..offset + 4].copy_from_slice(&seq.to_be_bytes());
        }
    } else {
        if packet[underlay_l2_opt_size + IPV4_PROTO_OFFSET] == IpProtocol::Udp {
            let offset = UDP6_PACKET_SIZE + underlay_l2_opt_size + vxlan::SEQUENCE_OFFSET;
            packet[offset] = (seq >> 16) as u8;
            packet[offset + 1..offset + 3].copy_from_slice(&(seq as u16).to_be_bytes());
        } else {
            let offset = IPV6_PACKET_SIZE + underlay_l2_opt_size + erspan::GRE_SEQUENCE_OFFSET;
            packet[offset..offset + 4].copy_from_slice(&seq.to_be_bytes());
        }
    }
}

#[derive(Debug)]
struct AfpacketSender {
    af_packet: Tpacket,
    underlay_dst_mac: MacAddr,
    underlay_src_mac: MacAddr,
    underlay_src_ip: IpAddr,
    seq: u32,
}

impl AfpacketSender {
    fn new(
        if_name: String,
        underlay_src_ip: IpAddr,
        underlay_src_mac: MacAddr,
        underlay_dst_mac: MacAddr,
    ) -> Result<Self, &'static str> {
        let mut options = Options::default();
        options.iface = if_name.clone();
        let af_packet = Tpacket::new(options.clone());
        if af_packet.is_err() {
            return Err("Afpacket error");
        }
        info!("Npb AfpacketSender init with {:?}.", options);

        Ok(Self {
            af_packet: af_packet.unwrap(),
            underlay_src_ip,
            underlay_src_mac,
            underlay_dst_mac,
            seq: 1,
        })
    }

    fn serialize_underlay(&self, underlay_l2_opt_size: usize, packet: &mut Vec<u8>) {
        packet[..MAC_ADDR_LEN].copy_from_slice(&self.underlay_dst_mac.octets());
        packet[MAC_ADDR_LEN..MAC_ADDR_LEN + MAC_ADDR_LEN]
            .copy_from_slice(&self.underlay_src_mac.octets());

        match self.underlay_src_ip {
            IpAddr::V4(addr) => {
                let src_ip_offset = IPV4_SRC_OFFSET + underlay_l2_opt_size;
                packet[src_ip_offset..src_ip_offset + IPV4_ADDR_LEN]
                    .copy_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                let src_ip_offset = IPV6_SRC_OFFSET + underlay_l2_opt_size;
                packet[src_ip_offset..src_ip_offset + IPV6_ADDR_LEN]
                    .copy_from_slice(&addr.octets());
            }
        }
    }

    fn send(&mut self, underlay_l2_opt_size: usize, mut packet: Vec<u8>) -> IOResult<usize> {
        self.serialize_underlay(underlay_l2_opt_size, &mut packet);
        serialize_seq(
            &mut packet,
            self.seq,
            underlay_l2_opt_size,
            self.underlay_src_ip.is_ipv6(),
        );
        self.seq += 1;
        let n = self.af_packet.write(&packet.as_slice());
        if n > 0 {
            return Ok(n as usize);
        }
        return Err(IOError::new(ErrorKind::Other, "Afpacket write error."));
    }

    fn close(&mut self) {}
}

#[derive(Debug)]
struct IpSender {
    socket: Socket,
    seq: u32,
    underlay_is_ipv6: bool,

    remote: SockAddr,
}

impl IpSender {
    fn new(remote: IpAddr, protocol: u8) -> IOResult<Self> {
        let fd = unsafe {
            if remote.is_ipv6() {
                socket(AF_INET6, SOCK_RAW, protocol as c_int)
            } else {
                socket(AF_INET, SOCK_RAW, protocol as c_int)
            }
        };
        if fd < 0 {
            return Err(IOError::new(ErrorKind::Other, "socket error."));
        }
        #[cfg(windows)]
        let socket = Socket::from_raw_socket(fd as RawSocket);
        #[cfg(unix)]
        let socket = unsafe { Socket::from_raw_fd(fd) };
        socket.set_send_buffer_size(30 << 20)?;

        info!("Npb IpSender init with {} {}.", remote, protocol);
        Ok(Self {
            socket,
            seq: 1,
            underlay_is_ipv6: remote.is_ipv6(),
            remote: match remote {
                IpAddr::V4(ip) => SockAddr::from(SocketAddrV4::new(ip, 0)),
                IpAddr::V6(ip) => SockAddr::from(SocketAddrV6::new(ip, 0, 0, 0)),
            },
        })
    }

    fn send(
        &mut self,
        underlay_l2_opt_size: usize,
        header_size: usize,
        mut packet: Vec<u8>,
    ) -> IOResult<usize> {
        serialize_seq(
            &mut packet,
            self.seq,
            underlay_l2_opt_size,
            self.underlay_is_ipv6,
        );
        self.seq += 1;
        info!(
            "npb header size {}: port {:x}{:x} {:x}{:x}",
            header_size,
            packet.as_slice()[header_size],
            packet.as_slice()[header_size + 1],
            packet.as_slice()[header_size + 2],
            packet.as_slice()[header_size + 3],
        );
        self.socket
            .send_to(&packet.as_slice()[header_size..], &self.remote)
    }

    fn close(&mut self) {}
}

#[derive(Debug)]
enum NpbSender {
    IpSender(IpSender),
    RawSender(AfpacketSender),
}

impl NpbSender {
    fn send(
        &mut self,
        underlay_l2_opt_size: usize,
        header_size: usize,
        packet: Vec<u8>,
    ) -> IOResult<usize> {
        match self {
            Self::IpSender(s) => s.send(underlay_l2_opt_size, header_size, packet),
            Self::RawSender(s) => s.send(underlay_l2_opt_size, packet),
        }
    }
}

#[derive(Default)]
pub struct NpbSenderCounter {
    pub tx: AtomicUsize,
    pub tx_bytes: AtomicUsize,
}

impl NpbSenderCounter {
    fn reset(&self) {
        self.tx.store(0, Ordering::Relaxed);
        self.tx_bytes.store(0, Ordering::Relaxed);
    }
}

pub struct StatsNpbSenderCounter(Weak<NpbSenderCounter>);

impl OwnedCountable for StatsNpbSenderCounter {
    fn closed(&self) -> bool {
        return self.0.strong_count() == 0;
    }

    fn get_counters(&self) -> Vec<public::counter::Counter> {
        match self.0.upgrade() {
            Some(x) => {
                let (tx, tx_bytes) = (
                    x.tx.load(Ordering::Relaxed) as u64,
                    x.tx_bytes.load(Ordering::Relaxed) as u64,
                );
                x.reset();

                vec![
                    ("tx", CounterType::Counted, CounterValue::Unsigned(tx)),
                    (
                        "tx_bytes",
                        CounterType::Counted,
                        CounterValue::Unsigned(tx_bytes),
                    ),
                ]
            }
            None => vec![],
        }
    }
}

pub struct NpbConnectionPool {
    connections: HashMap<(u128, u8), NpbSender>,
    socket_type: SocketType,
    underlay_is_ipv6: bool,

    counter: Arc<NpbSenderCounter>,
}

impl NpbConnectionPool {
    pub fn new(
        id: usize,
        underlay_is_ipv6: bool,
        socket_type: SocketType,
        stats_collector: Arc<stats::Collector>,
    ) -> Self {
        let counter = Arc::new(NpbSenderCounter::default());
        stats_collector.register_countable(
            "npb_packet_sender",
            Countable::Owned(Box::new(StatsNpbSenderCounter(Arc::downgrade(&counter)))),
            vec![StatsOption::Tag("id", id.to_string())],
        );

        Self {
            connections: HashMap::new(),
            socket_type,
            underlay_is_ipv6,
            counter,
        }
    }

    fn create_sender(&self, remote: IpAddr, protocol: u8) -> Result<NpbSender, String> {
        match self.socket_type {
            SocketType::Udp => {
                let sender = IpSender::new(remote, protocol);
                if sender.is_err() {
                    return Err(format!("IpSender error: {:?}.", sender.unwrap_err()));
                }
                Ok(NpbSender::IpSender(sender.unwrap()))
            }
            SocketType::RawUdp => {
                let local_addr = get_route_src_ip_and_mac(&remote);
                if local_addr.is_err() {
                    return Err(format!(
                        "Afpacket route error: {:?}.",
                        local_addr.unwrap_err()
                    ));
                }
                let if_name = get_route_src_ip_interface_name(&remote);
                if if_name.is_err() {
                    return Err(format!("Afpacket route error: {:?}.", if_name.unwrap_err()));
                }
                let neighbor = neighbor_lookup(remote);
                if neighbor.is_err() {
                    return Err(format!(
                        "Afpacket route error: {:?}.",
                        neighbor.unwrap_err()
                    ));
                }
                let (underlay_src_ip, underlay_src_mac) = local_addr.unwrap();
                let sender = AfpacketSender::new(
                    if_name.unwrap(),
                    underlay_src_ip,
                    underlay_src_mac,
                    neighbor.unwrap().dest_mac_addr,
                )?;
                Ok(NpbSender::RawSender(sender))
            }
            _ => panic!("NPB not support socket type: {:?}.", self.socket_type),
        }
    }

    fn send_to(&mut self, underlay_l2_opt_size: usize, packet: Vec<u8>) -> IOResult<usize> {
        let (remote, key, header_size) = if self.underlay_is_ipv6 {
            let offset = IPV6_DST_OFFSET + underlay_l2_opt_size;
            let header_size = IPV6_PACKET_SIZE + underlay_l2_opt_size;
            let ip = Ipv6Addr::from(
                *<&[u8; 16]>::try_from(&packet[offset..offset + IPV6_ADDR_LEN]).unwrap(),
            );
            (
                IpAddr::from(ip),
                (
                    u128::from(ip),
                    packet[IPV6_PROTO_OFFSET + underlay_l2_opt_size],
                ),
                header_size,
            )
        } else {
            let offset = IPV4_DST_OFFSET + underlay_l2_opt_size;
            let header_size = IPV4_PACKET_SIZE + underlay_l2_opt_size;
            let ip = Ipv4Addr::from(
                *<&[u8; 4]>::try_from(&packet[offset..offset + IPV4_ADDR_LEN]).unwrap(),
            );
            (
                IpAddr::from(ip),
                (
                    u32::from(ip) as u128,
                    packet[IPV4_PROTO_OFFSET + underlay_l2_opt_size],
                ),
                header_size,
            )
        };

        let mut conn = self.connections.get_mut(&key);
        if conn.is_some() {
            return conn
                .as_mut()
                .unwrap()
                .send(underlay_l2_opt_size, header_size, packet);
        }

        let conn = self.create_sender(remote, key.1);
        if conn.is_err() {
            return Err(IOError::new(ErrorKind::Other, conn.unwrap_err()));
        }
        let mut conn = conn.unwrap();
        let ret = conn.send(underlay_l2_opt_size, header_size, packet);
        self.connections.insert(key, conn);
        return ret;
    }

    pub fn send(&mut self, underlay_l2_opt_size: usize, packet: Vec<u8>) -> IOResult<usize> {
        let bytes = packet.len();
        let ret = self.send_to(underlay_l2_opt_size, packet);
        if ret.is_err() {
            return ret;
        }
        self.counter.tx.fetch_add(1, Ordering::Relaxed);
        self.counter.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
        return ret;
    }

    pub fn clear(&mut self) {
        self.connections.clear();
    }
}

pub struct NpbPacketSender {
    connections: Mutex<NpbConnectionPool>,
    receiver: Receiver<(usize, Vec<u8>)>,
    disable: AtomicBool,
}

impl NpbPacketSender {
    pub fn new(
        id: usize,
        receiver: Receiver<(usize, Vec<u8>)>,
        config: &NpbConfig,
        stats_collector: Arc<stats::Collector>,
    ) -> Self {
        NpbPacketSender {
            connections: Mutex::new(NpbConnectionPool::new(
                id,
                config.underlay_is_ipv6,
                config.socket_type,
                stats_collector,
            )),
            receiver,
            disable: AtomicBool::new(true),
        }
    }

    pub fn run(&self) {
        while !self.disable.load(Ordering::Relaxed) {
            let packet = self.receiver.recv(None);
            if packet.is_err() {
                continue;
            }
            let (underlay_l2_opt_size, packet) = packet.unwrap();
            let ret = self
                .connections
                .lock()
                .unwrap()
                .send(underlay_l2_opt_size, packet);
            if ret.is_err() {
                warn!("Npb packet sender error: {:?}.", ret);
            }
        }
    }

    pub fn is_running(&self) -> bool {
        !self.disable.load(Ordering::Relaxed)
    }

    pub fn start(&self) {
        self.disable.store(false, Ordering::Relaxed);
    }

    pub fn stop(&self) {
        self.disable.store(true, Ordering::Relaxed);
    }
}
