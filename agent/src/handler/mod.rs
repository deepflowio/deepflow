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
