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
#[cfg(unix)]
use std::os::unix::io::FromRawFd;
#[cfg(windows)]
use std::os::windows::io::{FromRawSocket, RawSocket};
use std::sync::atomic::AtomicU64;
use std::sync::{
    atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    Arc, Mutex, RwLock, Weak,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[cfg(unix)]
use libc::{c_int, socket, AF_INET, AF_INET6, SOCK_RAW};
use log::{info, warn};
use socket2::{Domain, SockAddr, Socket, Type};
#[cfg(windows)]
use windows::Win32::Networking::WinSock::socket;

use super::QUEUE_BATCH_SIZE;

use crate::common::{
    enums::IpProtocol, erspan, vxlan, IPV4_ADDR_LEN, IPV4_DST_OFFSET, IPV4_PACKET_SIZE,
    IPV4_PROTO_OFFSET, IPV6_ADDR_LEN, IPV6_DST_OFFSET, IPV6_PACKET_SIZE, IPV6_PROTO_OFFSET,
    TCP6_PACKET_SIZE, TCP_PACKET_SIZE, UDP6_PACKET_SIZE, UDP_PACKET_SIZE,
};
#[cfg(unix)]
use crate::common::{IPV4_SRC_OFFSET, IPV6_SRC_OFFSET};
use crate::config::NpbConfig;
#[cfg(unix)]
use crate::dispatcher::af_packet::{Options, Tpacket};
use crate::exception::ExceptionHandler;
use crate::utils::stats::{self, StatsOption};
use npb_handler::{NpbHeader, NOT_SUPPORT};
use public::counter::{Countable, CounterType, CounterValue, OwnedCountable};
use public::proto::trident::{Exception, SocketType};
use public::queue::Receiver;
#[cfg(unix)]
use public::utils::net::MAC_ADDR_LEN;
use public::utils::net::{
    get_route_src_ip_and_mac, get_route_src_ip_interface_name, neighbor_lookup, MacAddr,
};

#[cfg(windows)]
const AF_INET: i32 = 2;
#[cfg(windows)]
const AF_INET6: i32 = 23;
#[cfg(windows)]
const SOCK_RAW: i32 = 3;

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

#[cfg(unix)]
#[derive(Debug)]
struct AfpacketSender {
    af_packet: Option<Tpacket>,
    underlay_dst_mac: MacAddr,
    underlay_src_mac: MacAddr,
    underlay_src_ip: IpAddr,
    if_name: String,
    remote: IpAddr,

    last_arp_update: u64,
}

#[cfg(unix)]
impl AfpacketSender {
    const ARP_UPDATE_INTERVAL: u64 = 300 * 1000000000;
    fn new(remote: &IpAddr) -> AfpacketSender {
        Self {
            af_packet: None,
            underlay_dst_mac: MacAddr::ZERO,
            underlay_src_mac: MacAddr::ZERO,
            underlay_src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            if_name: String::new(),
            remote: remote.clone(),
            last_arp_update: 0,
        }
    }

    fn serialize_underlay(&self, underlay_l2_opt_size: usize, packet: &mut Vec<u8>) {
        packet[..MAC_ADDR_LEN].copy_from_slice(&self.underlay_dst_mac.octets()[..]);
        packet[MAC_ADDR_LEN..MAC_ADDR_LEN + MAC_ADDR_LEN]
            .copy_from_slice(&self.underlay_src_mac.octets()[..]);

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

    fn check_arp(&mut self, now: u64, arp: &Arc<NpbArpTable>) -> IOResult<u32> {
        if self.af_packet.is_some() && self.last_arp_update + Self::ARP_UPDATE_INTERVAL < now {
            let seq = arp.lookup_counter(&self.remote);
            return Ok(seq);
        }
        self.last_arp_update = now;

        let entry = arp.lookup(&self.remote);
        if entry.is_none() {
            return Err(IOError::new(
                ErrorKind::NotFound,
                format!("Arp not found: {}", self.remote),
            ));
        }
        let (src_mac, dst_mac, src_ip, if_name) = entry.unwrap();
        if if_name != self.if_name {
            let options = Options {
                iface: if_name.clone(),
                ..Default::default()
            };
            let af_packet = Tpacket::new(options.clone());
            if af_packet.is_err() {
                return Err(IOError::new(
                    ErrorKind::Other,
                    format!("Afpacket init failed with: {:?}", options),
                ));
            }
            info!("Npb Afpacket sender init with: {:?}.", options);
            self.af_packet.replace(af_packet.unwrap());
            self.if_name = if_name;
        }
        self.underlay_dst_mac = dst_mac;
        self.underlay_src_mac = src_mac;
        self.underlay_src_ip = src_ip;
        let seq = arp.lookup_counter(&self.remote);
        Ok(seq)
    }

    fn send(
        &mut self,
        timestamp: u64,
        underlay_l2_opt_size: usize,
        mut packet: Vec<u8>,
        arp: &Arc<NpbArpTable>,
    ) -> IOResult<usize> {
        let seq = self.check_arp(timestamp, arp)?;
        self.serialize_underlay(underlay_l2_opt_size, &mut packet);
        serialize_seq(
            &mut packet,
            seq,
            underlay_l2_opt_size,
            self.underlay_src_ip.is_ipv6(),
        );
        let n = self.af_packet.as_mut().unwrap().write(&packet.as_slice());
        if n > 0 {
            return Ok(n as usize);
        }
        return Err(IOError::new(ErrorKind::Other, "Afpacket write error"));
    }

    fn close(&mut self) {}
}

#[derive(Debug)]
struct IpSender {
    socket: Socket,
    underlay_is_ipv6: bool,
    underlay_header_size: usize,

    dst_ip: IpAddr,
    remote: SockAddr,
}

impl IpSender {
    #[cfg(windows)]
    fn new(remote: &IpAddr, protocol: u8) -> IOResult<Self> {
        let socket = unsafe {
            if remote.is_ipv6() {
                socket(AF_INET6, SOCK_RAW as i32, protocol as i32)
            } else {
                socket(AF_INET, SOCK_RAW as i32, protocol as i32)
            }
        };
        if socket.0 == 0 {
            return Err(IOError::new(ErrorKind::Other, "socket error."));
        }
        let socket = unsafe { Socket::from_raw_socket(socket.0 as RawSocket) };
        socket.set_send_buffer_size(30 << 20)?;

        info!("Npb IpSender init with {} {}.", remote, protocol);
        Ok(Self {
            socket,
            underlay_is_ipv6: remote.is_ipv6(),
            underlay_header_size: if remote.is_ipv6() {
                IPV6_PACKET_SIZE
            } else {
                IPV4_PACKET_SIZE
            },
            remote: match remote {
                IpAddr::V4(ip) => SockAddr::from(SocketAddrV4::new(ip.clone(), 0)),
                IpAddr::V6(ip) => SockAddr::from(SocketAddrV6::new(ip.clone(), 0, 0, 0)),
            },
            dst_ip: remote.clone(),
        })
    }

    #[cfg(unix)]
    fn new(remote: &IpAddr, protocol: u8) -> IOResult<Self> {
        let fd = unsafe {
            if remote.is_ipv6() {
                socket(AF_INET6, SOCK_RAW, protocol as c_int)
            } else {
                socket(AF_INET, SOCK_RAW, protocol as c_int)
            }
        };
        if fd < 0 {
            return Err(IOError::new(ErrorKind::Other, "socket error"));
        }
        let socket = unsafe { Socket::from_raw_fd(fd) };
        socket.set_send_buffer_size(30 << 20)?;

        info!("Npb IpSender init with {} {}.", remote, protocol);
        Ok(Self {
            socket,
            underlay_is_ipv6: remote.is_ipv6(),
            underlay_header_size: if remote.is_ipv6() {
                IPV6_PACKET_SIZE
            } else {
                IPV4_PACKET_SIZE
            },
            dst_ip: remote.clone(),
            remote: match remote {
                IpAddr::V4(ip) => SockAddr::from(SocketAddrV4::new(ip.clone(), 0)),
                IpAddr::V6(ip) => SockAddr::from(SocketAddrV6::new(ip.clone(), 0, 0, 0)),
            },
        })
    }

    fn send(
        &mut self,
        underlay_l2_opt_size: usize,
        mut packet: Vec<u8>,
        arp: &Arc<NpbArpTable>,
    ) -> IOResult<usize> {
        let header_size = self.underlay_header_size + underlay_l2_opt_size;
        let seq = arp.lookup_counter(&self.dst_ip);
        serialize_seq(
            &mut packet,
            seq,
            underlay_l2_opt_size,
            self.underlay_is_ipv6,
        );
        self.socket
            .send_to(&packet.as_slice()[header_size..], &self.remote)
    }

    fn close(&mut self) {}
}

#[derive(Debug)]
struct TcpSender {
    socket: Option<Socket>,
    underlay_is_ipv6: bool,

    overlay_packet_offset: usize,

    dst_ip: IpAddr,
    remote: SockAddr,
}

impl TcpSender {
    const CONNECT_TIMEOUT: u64 = 100;

    fn new(dst_ip: &IpAddr, dst_port: u16) -> Self {
        let overlay_packet_offset = if dst_ip.is_ipv6() {
            TCP6_PACKET_SIZE
        } else {
            TCP_PACKET_SIZE
        };
        Self {
            socket: None,
            underlay_is_ipv6: dst_ip.is_ipv6(),
            overlay_packet_offset,
            remote: match dst_ip {
                IpAddr::V4(ip) => SockAddr::from(SocketAddrV4::new(ip.clone(), dst_port)),
                IpAddr::V6(ip) => SockAddr::from(SocketAddrV6::new(ip.clone(), dst_port, 0, 0)),
            },
            dst_ip: dst_ip.clone(),
        }
    }

    fn connect_check(&mut self) -> IOResult<()> {
        if self.socket.is_some() {
            return Ok(());
        }
        let domain = if self.underlay_is_ipv6 {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        let socket = Socket::new(domain, Type::STREAM, None)?;
        socket.connect_timeout(&self.remote, Duration::from_millis(Self::CONNECT_TIMEOUT))?;
        socket.set_nonblocking(true)?;
        socket.set_keepalive(true)?;
        self.socket.replace(socket);
        info!("Npb TcpSender init with {}.", self.dst_ip);
        Ok(())
    }

    fn send(
        &mut self,
        underlay_l2_opt_size: usize,
        mut packet: Vec<u8>,
        arp: &Arc<NpbArpTable>,
    ) -> IOResult<usize> {
        self.connect_check()?;
        let seq = arp.lookup_counter(&self.dst_ip);
        serialize_seq(
            &mut packet,
            seq,
            underlay_l2_opt_size,
            self.underlay_is_ipv6,
        );
        let overlay_packet_offset = self.overlay_packet_offset + underlay_l2_opt_size;
        let packet = &mut packet.as_mut_slice()[overlay_packet_offset..];

        let mut header = NpbHeader::default();
        let _ = header.decode(packet);
        header.total_length = packet.len() as u16;
        let _ = header.encode(packet);
        let n = self.socket.as_ref().unwrap().send(packet);
        if n.is_err() {
            self.socket = None;
        }
        return n;
    }

    fn close(&mut self) {}
}

#[derive(Debug)]
enum NpbSender {
    IpSender(IpSender),
    #[cfg(unix)]
    RawSender(AfpacketSender),
    TcpSender(TcpSender),
}

impl NpbSender {
    fn send(
        &mut self,
        #[cfg(unix)] timestamp: u64,
        #[cfg(not(unix))] _: u64,
        underlay_l2_opt_size: usize,
        packet: Vec<u8>,
        arp: &Arc<NpbArpTable>,
    ) -> IOResult<usize> {
        match self {
            Self::IpSender(s) => s.send(underlay_l2_opt_size, packet, arp),
            #[cfg(unix)]
            Self::RawSender(s) => s.send(timestamp, underlay_l2_opt_size, packet, arp),
            Self::TcpSender(s) => s.send(underlay_l2_opt_size, packet, arp),
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

#[derive(Debug)]
pub struct ArpEntry {
    counter: AtomicU32,
    dst_mac: MacAddr,
    src_mac: MacAddr,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    if_name: String,

    aging: AtomicU64,
}

const ARP_STALE_TIME: u64 = 60;
const ARP_INTERVAL: u64 = 1;
const ARP_AGING_TIME: u64 = 300;

impl ArpEntry {
    fn update(&mut self, new_entry: Self) {
        self.aging = new_entry.aging;

        if self.dst_mac == new_entry.dst_mac
            && self.src_mac == new_entry.src_mac
            && self.src_ip == new_entry.src_ip
            && self.if_name == new_entry.if_name
        {
            return;
        }

        self.dst_mac = new_entry.dst_mac;
        self.src_mac = new_entry.src_mac;
        self.src_ip = new_entry.src_ip;
        self.if_name = new_entry.if_name;
        info!("Arp entry change to {}", self);
    }
}

impl Default for ArpEntry {
    fn default() -> Self {
        ArpEntry {
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            aging: AtomicU64::new(ARP_AGING_TIME),
            counter: AtomicU32::new(1),
            if_name: String::new(),
            dst_mac: MacAddr::ZERO,
            src_mac: MacAddr::ZERO,
        }
    }
}

impl std::fmt::Display for ArpEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Local: {} {} Remote: {} {} If: {} Aging: {}s Counter: {}",
            self.src_mac,
            self.src_ip,
            self.dst_mac,
            self.dst_ip,
            self.if_name,
            self.aging.load(Ordering::Relaxed),
            self.counter.load(Ordering::Relaxed)
        )
    }
}

impl TryFrom<&IpAddr> for ArpEntry {
    type Error = String;

    fn try_from(remote: &IpAddr) -> Result<Self, Self::Error> {
        let local_addr = get_route_src_ip_and_mac(remote);
        if local_addr.is_err() {
            return Err(format!("Route error: {:?}.", local_addr.unwrap_err()));
        }
        let if_name = get_route_src_ip_interface_name(remote);
        if if_name.is_err() {
            return Err(format!("Route error: {:?}.", if_name.unwrap_err()));
        }
        let neighbor = neighbor_lookup(remote.clone());
        if neighbor.is_err() {
            return Err(format!("Route error: {:?}.", neighbor.unwrap_err()));
        }
        let (src_ip, src_mac) = local_addr.unwrap();

        Ok(Self {
            counter: AtomicU32::new(1),
            dst_mac: neighbor.unwrap().dest_mac_addr,
            src_mac,
            src_ip,
            dst_ip: remote.clone(),
            if_name: if_name.unwrap(),
            ..Default::default()
        })
    }
}

// NPB ARP table has the following functions:
// 1. Provide npb packet counter
// 2. Provide mac address
pub struct NpbArpTable {
    table: Arc<RwLock<HashMap<IpAddr, ArpEntry>>>,
    is_running: Arc<AtomicBool>,
    need_resolve_mac: Arc<AtomicBool>,
    exception_handler: ExceptionHandler,

    thread_handler: Mutex<Option<JoinHandle<()>>>,
}

impl NpbArpTable {
    pub fn new(need_resolve_mac: bool, exception_handler: ExceptionHandler) -> Self {
        NpbArpTable {
            table: Arc::new(RwLock::new(HashMap::new())),
            thread_handler: Mutex::new(None),
            is_running: Arc::new(AtomicBool::new(false)),
            need_resolve_mac: Arc::new(AtomicBool::new(need_resolve_mac)),
            exception_handler,
        }
    }

    pub fn add(&self, remote: &IpAddr) {
        if self.table.read().unwrap().contains_key(remote) {
            return;
        }

        self.table.write().unwrap().insert(
            remote.clone(),
            ArpEntry {
                dst_ip: remote.clone(),
                aging: AtomicU64::new(ARP_STALE_TIME),
                ..Default::default()
            },
        );
    }

    pub fn lookup(&self, remote: &IpAddr) -> Option<(MacAddr, MacAddr, IpAddr, String)> {
        if let Some(entry) = self.table.read().unwrap().get(&remote) {
            if entry.if_name.is_empty() {
                return None;
            }
            return Some((
                entry.src_mac,
                entry.dst_mac,
                entry.src_ip,
                entry.if_name.clone(),
            ));
        }
        self.add(remote);
        return None;
    }

    pub fn lookup_counter(&self, remote: &IpAddr) -> u32 {
        let table = self.table.read().unwrap();
        return table
            .get(&remote)
            .unwrap()
            .counter
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_need_resolve_mac(&self, need_resolve_mac: bool) {
        self.need_resolve_mac
            .store(need_resolve_mac, Ordering::Relaxed);
    }

    fn run(
        table: Arc<RwLock<HashMap<IpAddr, ArpEntry>>>,
        is_running: Arc<AtomicBool>,
        need_resolve_mac: Arc<AtomicBool>,
        exception_handler: ExceptionHandler,
    ) {
        let mut lookup_ips = vec![];
        let mut timeout_ips = vec![];
        while is_running.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(ARP_INTERVAL));
            if !need_resolve_mac.load(Ordering::Relaxed) {
                continue;
            }

            for (dst_ip, entry) in table.read().unwrap().iter() {
                let aging = entry.aging.fetch_sub(ARP_INTERVAL, Ordering::Relaxed);
                if aging <= ARP_STALE_TIME {
                    if aging > ARP_INTERVAL {
                        lookup_ips.push((false, dst_ip.clone()));
                    } else if aging == ARP_INTERVAL {
                        lookup_ips.push((true, dst_ip.clone()));
                    } else {
                        timeout_ips.push(dst_ip.clone());
                    }
                }
            }

            // Remove all timeout entrys.
            for key in &timeout_ips {
                table.write().unwrap().remove(key);
            }

            // Lookup all stale entrys.
            for (last_lookup, key) in &lookup_ips {
                let entry = ArpEntry::try_from(key);
                if entry.is_ok() {
                    let entry = entry.unwrap();
                    table.write().unwrap().get_mut(key).unwrap().update(entry);
                } else {
                    exception_handler.set(Exception::NpbNoGwArp);
                    if *last_lookup {
                        warn!("Arp lookup {} error: {:?}.", key, entry.unwrap_err());
                    }
                }
            }

            timeout_ips.clear();
            lookup_ips.clear();
        }
    }

    pub fn start(&self) {
        if self.is_running.load(Ordering::Relaxed) || NOT_SUPPORT {
            return;
        }
        info!("Arp table starting...");
        self.is_running.store(true, Ordering::Relaxed);
        let table = self.table.clone();
        let is_running = self.is_running.clone();
        let need_resolve_mac = self.need_resolve_mac.clone();
        let exception_handler = self.exception_handler.clone();
        self.thread_handler.lock().unwrap().replace(
            thread::Builder::new()
                .name("npb-sender".to_owned())
                .spawn(move || {
                    Self::run(table, is_running, need_resolve_mac, exception_handler);
                })
                .unwrap(),
        );
    }

    pub fn stop(&self) {
        if !self.is_running.load(Ordering::Relaxed) || NOT_SUPPORT {
            return;
        }
        info!("Arp table stopping...");
        self.is_running.store(false, Ordering::Relaxed);
        if let Some(handler) = self.thread_handler.lock().unwrap().take() {
            let _ = handler.join();
        }
    }
}

pub struct NpbConnectionPool {
    connections: HashMap<(u128, u8), NpbSender>,
    socket_type: SocketType,
    npb_port: u16,
    underlay_is_ipv6: bool,

    counter: Arc<NpbSenderCounter>,

    arp: Arc<NpbArpTable>,
}

impl NpbConnectionPool {
    pub fn new(
        id: usize,
        underlay_is_ipv6: bool,
        socket_type: SocketType,
        npb_port: u16,
        arp: Arc<NpbArpTable>,
        stats_collector: Arc<stats::Collector>,
    ) -> Self {
        let counter = Arc::new(NpbSenderCounter::default());
        stats_collector.register_countable(
            "npb_packet_sender",
            Countable::Owned(Box::new(StatsNpbSenderCounter(Arc::downgrade(&counter)))),
            vec![StatsOption::Tag("id", id.to_string())],
        );

        #[cfg(windows)]
        let mut socket_type = socket_type;
        #[cfg(windows)]
        {
            if socket_type == SocketType::RawUdp {
                info!("Npb socket type is not support RawUDP change to udp.");
                socket_type = SocketType::Udp
            }
        }

        Self {
            connections: HashMap::new(),
            socket_type,
            npb_port,
            underlay_is_ipv6,
            counter,
            arp,
        }
    }

    fn create_sender(&self, remote: &IpAddr, protocol: u8) -> Result<NpbSender, String> {
        // Trigger to create ARP table entry.
        self.arp.add(remote);
        match self.socket_type {
            SocketType::Udp if protocol != IpProtocol::Tcp => {
                let sender = IpSender::new(remote, protocol);
                if sender.is_err() {
                    return Err(format!("IpSender error: {:?}.", sender.unwrap_err()));
                }
                Ok(NpbSender::IpSender(sender.unwrap()))
            }
            SocketType::Tcp if protocol == IpProtocol::Tcp => {
                Ok(NpbSender::TcpSender(TcpSender::new(remote, self.npb_port)))
            }
            #[cfg(unix)]
            SocketType::RawUdp if protocol != IpProtocol::Tcp => {
                Ok(NpbSender::RawSender(AfpacketSender::new(remote)))
            }
            _ => Err(format!(
                "NPB socket type {:?} not support tunnel ip {} and protocol {}.",
                self.socket_type, remote, protocol
            )),
        }
    }

    fn send_to(
        &mut self,
        timestamp: u64,
        underlay_l2_opt_size: usize,
        packet: Vec<u8>,
    ) -> IOResult<usize> {
        let (remote, key) = if self.underlay_is_ipv6 {
            let offset = IPV6_DST_OFFSET + underlay_l2_opt_size;
            let ip = Ipv6Addr::from(
                *<&[u8; 16]>::try_from(&packet[offset..offset + IPV6_ADDR_LEN]).unwrap(),
            );
            (
                IpAddr::from(ip),
                (
                    u128::from(ip),
                    packet[IPV6_PROTO_OFFSET + underlay_l2_opt_size],
                ),
            )
        } else {
            let offset = IPV4_DST_OFFSET + underlay_l2_opt_size;
            let ip = Ipv4Addr::from(
                *<&[u8; 4]>::try_from(&packet[offset..offset + IPV4_ADDR_LEN]).unwrap(),
            );
            (
                IpAddr::from(ip),
                (
                    u32::from(ip) as u128,
                    packet[IPV4_PROTO_OFFSET + underlay_l2_opt_size],
                ),
            )
        };

        let mut conn = self.connections.get_mut(&key);
        if conn.is_some() {
            return conn
                .as_mut()
                .unwrap()
                .send(timestamp, underlay_l2_opt_size, packet, &self.arp);
        }

        let conn = self.create_sender(&remote, key.1);
        if conn.is_err() {
            return Err(IOError::new(ErrorKind::Other, conn.unwrap_err()));
        }
        let mut conn = conn.unwrap();
        let ret = conn.send(timestamp, underlay_l2_opt_size, packet, &self.arp);
        self.connections.insert(key, conn);
        return ret;
    }

    pub fn send(
        &mut self,
        timestamp: u64,
        underlay_l2_opt_size: usize,
        packet: Vec<u8>,
    ) -> IOResult<usize> {
        let bytes = packet.len();
        let ret = self.send_to(timestamp, underlay_l2_opt_size, packet);
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
    receiver: Receiver<(u64, usize, Vec<u8>)>,
    disable: AtomicBool,
}

impl NpbPacketSender {
    const LOG_INTERVAL: u64 = 300 * 1000000000;
    pub fn new(
        id: usize,
        receiver: Receiver<(u64, usize, Vec<u8>)>,
        config: &NpbConfig,
        arp: Arc<NpbArpTable>,
        stats_collector: Arc<stats::Collector>,
    ) -> Self {
        NpbPacketSender {
            connections: Mutex::new(NpbConnectionPool::new(
                id,
                config.underlay_is_ipv6,
                config.socket_type,
                config.npb_port,
                arp.clone(),
                stats_collector,
            )),
            receiver,
            disable: AtomicBool::new(true),
        }
    }

    pub fn run(&self) {
        let mut last_timestamp = 0;
        let mut batch = Vec::with_capacity(QUEUE_BATCH_SIZE);
        while !self.disable.load(Ordering::Relaxed) {
            if self
                .receiver
                .recv_all(&mut batch, Some(Duration::from_secs(1)))
                .is_err()
            {
                continue;
            }
            for packet in batch.drain(..) {
                let (timestamp, underlay_l2_opt_size, packet) = packet;
                let ret =
                    self.connections
                        .lock()
                        .unwrap()
                        .send(timestamp, underlay_l2_opt_size, packet);
                if ret.is_err() && last_timestamp + Self::LOG_INTERVAL < timestamp {
                    last_timestamp = timestamp;
                    warn!("Npb packet sender error: {:?}.", ret);
                }
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
