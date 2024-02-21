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

mod npb;
pub use npb::NpbBuilder;

use std::net::IpAddr;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use log::debug;

use npb_handler::{NpbHandler, NpbMode};
use npb_pcap_policy::{NpbTunnelType, PolicyData};
use public::{enums::HeaderType, packet, queue::DebugSender, utils::net::MacAddr};

use crate::collector::acc_flow::U16Set;
use crate::common::meta_packet::{MetaPacket, RawPacket};

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
    packet: RawPacket<'a>,
    npb_mode: NpbMode,
    l2_opt_size: u8,
    l3_opt_size: u16,
    l4_opt_size: u32,
    packet_size: u32,
    // IPV6
    ipv6_last_option_offset: u16,
    ipv6_fragment_option_offset: u16,
    // RawPcap
    flow_id: u64,
    header_type: HeaderType,
    l2_l3_opt_size: u16,
    packet_len: u32,
    second_in_minute: u8,
    if_index: isize,
}

impl<'a> MiniPacket<'a> {
    pub fn new<P>(overlay_packet: P, meta_packet: &MetaPacket, if_index: isize) -> MiniPacket<'a>
    where
        P: Into<RawPacket<'a>>,
    {
        let overlay_packet = overlay_packet.into();
        MiniPacket {
            policy: meta_packet.policy_data.clone(),
            packet_size: if meta_packet.packet_len as usize > overlay_packet.len() {
                overlay_packet.len() as u32
            } else {
                meta_packet.packet_len as u32
            },
            packet: overlay_packet,
            timestamp: meta_packet.lookup_key.timestamp.as_nanos() as u64,
            npb_mode: meta_packet.npb_mode(),
            l2_opt_size: meta_packet.vlan_tag_size,
            l3_opt_size: meta_packet.l2_l3_opt_size - meta_packet.vlan_tag_size as u16,
            l4_opt_size: meta_packet.l4_opt_size,
            ipv6_last_option_offset: meta_packet.offset_ipv6_last_option,
            ipv6_fragment_option_offset: meta_packet.offset_ipv6_fragment_option,
            flow_id: meta_packet.flow_id,
            header_type: meta_packet.header_type,
            l2_l3_opt_size: meta_packet.l2_l3_opt_size,
            packet_len: meta_packet.packet_len,
            second_in_minute: meta_packet.second_in_minute,
            if_index,
        }
    }

    pub fn if_index(&self) -> isize {
        self.if_index
    }

    pub fn raw(&self) -> &[u8] {
        match &self.packet {
            RawPacket::Borrowed(r) => *r,
            RawPacket::Owned(r) => r.as_ref(),
        }
    }
}

pub enum PacketHandler {
    // pcap_assembler sender, use for send mini packet to assemble
    Pcap(DebugSender<packet::MiniPacket>),
    Npb(NpbHandler),
}

impl PacketHandler {
    pub fn handle(&mut self, packet: &MiniPacket) {
        match self {
            Self::Pcap(sender) => {
                let mut acl_gids = U16Set::new();
                if packet.policy.is_none()
                    || !packet.policy.as_ref().unwrap().contain_pcap()
                    || packet.flow_id == 0
                {
                    return;
                }
                let payload_offset = packet.header_type.min_packet_size()
                    + packet.l2_l3_opt_size as usize
                    + packet.l4_opt_size as usize;
                let policy = packet.policy.as_ref().unwrap();
                let mut max_raw_len = 0;
                // find longest payload
                for action in policy.npb_actions.iter() {
                    if action.tunnel_type() != NpbTunnelType::Pcap {
                        continue;
                    }
                    for gid in action.acl_gids().iter() {
                        acl_gids.add(*gid);
                    }
                    let mut raw_len = payload_offset + action.payload_slice();
                    if raw_len > packet.packet.len() {
                        raw_len = packet.packet.len();
                    }
                    if raw_len > packet.packet_len as usize {
                        // only get packet_size in padding situation
                        raw_len = packet.packet_len as usize;
                    }
                    if raw_len > max_raw_len {
                        max_raw_len = raw_len;
                    }
                }
                if max_raw_len == 0 {
                    return;
                }

                let mini_packet = packet::MiniPacket {
                    packet: packet.packet[..max_raw_len].to_vec(),
                    flow_id: packet.flow_id,
                    timestamp: Duration::from_nanos(packet.timestamp),
                    acl_gids: Vec::from(acl_gids.list()),
                    second_in_minute: packet.second_in_minute,
                };
                if let Err(e) = sender.send(mini_packet) {
                    debug!("send mini packet to pcap assembler error: {e:?}");
                }
            }
            Self::Npb(n) => n.handle(
                packet.policy.as_ref(),
                &packet.npb_mode,
                packet.timestamp,
                &packet.packet,
                packet.packet_size as usize,
                packet.l2_opt_size as usize,
                packet.l3_opt_size as usize,
                packet.l4_opt_size as usize,
                packet.ipv6_last_option_offset as usize,
                packet.ipv6_fragment_option_offset as usize,
            ),
        }
    }
}

pub enum PacketHandlerBuilder {
    Pcap(DebugSender<packet::MiniPacket>),
    Npb(Box<NpbBuilder>),
}

impl PacketHandlerBuilder {
    pub fn build_with(&self, id: usize, if_index: u32, mac: MacAddr) -> PacketHandler {
        match self {
            PacketHandlerBuilder::Pcap(s) => PacketHandler::Pcap(s.clone()),
            PacketHandlerBuilder::Npb(b) => PacketHandler::Npb(b.build_with(id, if_index, mac)),
        }
    }

    pub fn notify_stop(&mut self) -> Option<JoinHandle<()>> {
        match self {
            PacketHandlerBuilder::Pcap(_) => None,
            PacketHandlerBuilder::Npb(b) => b.notify_stop(),
        }
    }

    pub fn stop(&mut self) {
        match self {
            PacketHandlerBuilder::Pcap(_) => {}
            PacketHandlerBuilder::Npb(b) => {
                b.stop();
            }
        }
    }

    pub fn start(&mut self) {
        match self {
            PacketHandlerBuilder::Pcap(_) => {}
            PacketHandlerBuilder::Npb(b) => {
                b.start();
            }
        }
    }
}
