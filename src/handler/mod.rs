use std::net::IpAddr;
use std::time::Duration;

use crate::common::endpoint::EndpointData;
use crate::common::meta_packet::MetaPacket;
use crate::common::policy::PolicyData;
use crate::utils::net::MacAddr;

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

pub enum PacketHandler {}

impl PacketHandler {
    pub fn handle(
        &mut self,
        _overlay_packet: &[u8],
        _meta_packet: &MetaPacket,
        _endpoint: Option<&EndpointData>,
        _policy: Option<&PolicyData>,
    ) {
        todo!()
    }
}

pub enum PacketHandlerBuilder {}

impl PacketHandlerBuilder {
    pub fn build_with(&self, _id: usize, _if_index: u32, _mac: MacAddr) -> PacketHandler {
        todo!()
    }
}
