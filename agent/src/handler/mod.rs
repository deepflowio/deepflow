use std::net::IpAddr;
use std::time::Duration;

use crate::common::meta_packet::MetaPacket;
use crate::pcap::PcapPacket;
use crate::utils::net::MacAddr;
use crate::utils::queue::DebugSender;

pub struct IpInfo {
    pub mac: MacAddr,
    pub ip: IpAddr,
    pub last_seen: Duration,
}
pub struct LldpInfo {
    pub lldp_du: LldpDuInfo,
    pub last_seen: Duration,
}

pub struct LldpDuInfo {
    pub port_id: String,
    pub port_description: String,
    pub system_name: String,
    pub management_address: Vec<String>,
    pub ttl: u32,
}

pub enum PacketHandler {
    Pcap(DebugSender<PcapPacket>),
}

impl PacketHandler {
    pub fn handle(&mut self, _overlay_packet: &[u8], _meta_packet: &MetaPacket) {
        // TODO
    }
}

pub enum PacketHandlerBuilder {
    Pcap(DebugSender<PcapPacket>),
}

impl PacketHandlerBuilder {
    pub fn build_with(&self, _id: usize, _if_index: u32, _mac: MacAddr) -> PacketHandler {
        match self {
            PacketHandlerBuilder::Pcap(s) => PacketHandler::Pcap(s.clone()),
        }
    }

    pub fn send_terminated(&self) {
        match self {
            PacketHandlerBuilder::Pcap(s) => {
                let _ = s.send(PcapPacket::Terminated);
            }
        }
    }
}
