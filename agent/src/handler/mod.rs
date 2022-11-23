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

mod npb;
pub use npb::NpbBuilder;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::common::meta_packet::MetaPacket;
use npb_handler::{NpbHandler, NpbMode};
use npb_pcap_policy::PolicyData;
use public::{packet::MiniPacketEnum, queue::DebugSender, utils::net::MacAddr};

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

#[derive(Debug)]
pub struct MiniPacket<'a> {
    policy: Option<Arc<PolicyData>>,
    timestamp: u64,
    packet: &'a [u8],
    npb_mode: NpbMode,
    l2_opt_size: usize,
    l3_opt_size: usize,
    l4_opt_size: usize,
    packet_size: usize,
    // IPV6
    ipv6_last_option_offset: usize,
    ipv6_fragment_option_offset: usize,
}

impl<'a> MiniPacket<'a> {
    pub fn new(overlay_packet: &'a [u8], meta_packet: &MetaPacket) -> MiniPacket<'a> {
        MiniPacket {
            policy: meta_packet.policy_data.clone(),
            packet: overlay_packet,
            timestamp: meta_packet.lookup_key.timestamp.as_nanos() as u64,
            npb_mode: meta_packet.npb_mode(),
            l2_opt_size: meta_packet.vlan_tag_size,
            l3_opt_size: meta_packet.l2_l3_opt_size - meta_packet.vlan_tag_size,
            l4_opt_size: meta_packet.l4_opt_size,
            packet_size: if meta_packet.packet_len > overlay_packet.len() {
                overlay_packet.len()
            } else {
                meta_packet.packet_len
            },
            ipv6_last_option_offset: meta_packet.offset_ipv6_last_option,
            ipv6_fragment_option_offset: meta_packet.offset_ipv6_fragment_option,
        }
    }
}

pub enum PacketHandler {
    Pcap(DebugSender<MiniPacketEnum>),
    Npb(NpbHandler),
}

impl PacketHandler {
    pub fn handle(&mut self, packet: &MiniPacket) {
        match self {
            Self::Pcap(_) => {}
            Self::Npb(n) => n.handle(
                packet.policy.as_ref(),
                &packet.npb_mode,
                packet.timestamp,
                packet.packet,
                packet.packet_size,
                packet.l2_opt_size,
                packet.l3_opt_size,
                packet.l4_opt_size,
                packet.ipv6_last_option_offset,
                packet.ipv6_fragment_option_offset,
            ),
        }
    }
}

pub enum PacketHandlerBuilder {
    Pcap(DebugSender<MiniPacketEnum>),
    Npb(Box<NpbBuilder>),
}

impl PacketHandlerBuilder {
    pub fn build_with(&self, id: usize, if_index: u32, mac: MacAddr) -> PacketHandler {
        match self {
            PacketHandlerBuilder::Pcap(s) => PacketHandler::Pcap(s.clone()),
            PacketHandlerBuilder::Npb(b) => PacketHandler::Npb(b.build_with(id, if_index, mac)),
        }
    }

    pub fn stop(&mut self) {
        match self {
            PacketHandlerBuilder::Pcap(s) => {
                let _ = s.send(MiniPacketEnum::Terminated);
            }
            PacketHandlerBuilder::Npb(b) => {
                b.stop();
            }
        }
    }

    pub fn start(&mut self) {
        match self {
            PacketHandlerBuilder::Pcap(_s) => {}
            PacketHandlerBuilder::Npb(b) => {
                b.start();
            }
        }
    }
}
