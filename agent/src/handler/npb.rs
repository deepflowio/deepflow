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

use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::vec;

use log::info;
use npb_pcap_policy::NpbTunnelType;
use pnet::packet::{
    ethernet::{EtherTypes, MutableEthernetPacket},
    gre::MutableGrePacket,
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::MutableIpv4Packet,
    ipv6::MutableIpv6Packet,
    udp::MutableUdpPacket,
    vlan::{ClassesOfService, MutableVlanPacket},
};
use public::enums::IpProtocol;

use crate::common::{
    erspan, vxlan, ERSPAN_HEADER_SIZE, ETH_HEADER_SIZE, GRE_HEADER_SIZE, IPV4_HEADER_SIZE,
    IPV6_HEADER_SIZE, TCP6_PACKET_SIZE, TCP_PACKET_SIZE, UDP_HEADER_SIZE, VLAN_HEADER_SIZE,
    VXLAN_HEADER_SIZE,
};
use crate::config::NpbConfig;
use crate::sender::npb_sender::{NpbArpTable, NpbPacketSender};
use crate::utils::stats::{self, StatsOption};
use npb_handler::{NpbHandler, NpbHandlerCounter, NpbHeader, StatsNpbHandlerCounter, NOT_SUPPORT};
use public::{
    counter::Countable,
    debug::QueueDebugger,
    leaky_bucket::LeakyBucket,
    proto::trident::VlanMode,
    queue::{bounded_with_debug, DebugSender},
    utils::net::MacAddr,
};

pub struct NpbBuilder {
    id: usize,
    mtu: usize,

    enable_qos_bypass: bool,
    underlay_is_ipv6: bool,
    underlay_has_vlan: bool,
    overlay_vlan_mode: VlanMode,

    sender: DebugSender<(u64, usize, Vec<u8>)>,

    npb_packet_sender: Option<Arc<NpbPacketSender>>,
    arp: Arc<NpbArpTable>,

    pseudo_tunnel_header: [Vec<u8>; NpbTunnelType::Max as usize],

    thread_handle: Mutex<Option<JoinHandle<()>>>,

    bps_limit: Arc<LeakyBucket>,
    stats_collector: Arc<stats::Collector>,
}

impl NpbBuilder {
    fn create_pseudo_ether_header(config: &NpbConfig) -> Vec<u8> {
        let mut buffer = [0u8; ETH_HEADER_SIZE + VLAN_HEADER_SIZE];
        let mut ethernet_header = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
        let ether_type = if config.underlay_is_ipv6 {
            EtherTypes::Ipv6
        } else {
            EtherTypes::Ipv4
        };
        if config.output_vlan > 0 {
            ethernet_header.set_ethertype(EtherTypes::Vlan);
            let mut vlan_header = MutableVlanPacket::new(&mut buffer[ETH_HEADER_SIZE..]).unwrap();
            vlan_header.set_ethertype(ether_type);
            vlan_header.set_priority_code_point(ClassesOfService::BE);
            vlan_header.set_vlan_identifier(config.output_vlan);
            return buffer.to_vec();
        } else {
            ethernet_header.set_ethertype(ether_type);
            return buffer[..ETH_HEADER_SIZE].to_vec();
        }
    }

    fn create_pseudo_ip_header(config: &NpbConfig, protocol: IpNextHeaderProtocol) -> Vec<u8> {
        if !config.underlay_is_ipv6 {
            let mut buffer = [0u8; IPV4_HEADER_SIZE];
            let mut ip_header = MutableIpv4Packet::new(&mut buffer).unwrap();
            ip_header.set_header_length(5);
            ip_header.set_next_level_protocol(protocol);
            ip_header.set_ttl(64);
            ip_header.set_version(4);
            return buffer.to_vec();
        } else {
            let mut buffer = [0u8; IPV6_HEADER_SIZE];
            let mut ip_header = MutableIpv6Packet::new(&mut buffer).unwrap();
            ip_header.set_next_header(protocol);
            ip_header.set_hop_limit(64);
            ip_header.set_version(6);
            return buffer.to_vec();
        }
    }

    fn create_pseudo_udp_header(config: &NpbConfig) -> Vec<u8> {
        let mut buffer = [0u8; UDP_HEADER_SIZE];
        let mut udp_header = MutableUdpPacket::new(&mut buffer).unwrap();
        udp_header.set_source(49152);
        udp_header.set_destination(config.npb_port);
        return buffer.to_vec();
    }

    fn create_pseudo_vxlan_header(config: &NpbConfig) -> Vec<u8> {
        let mut buffer = vec![0u8; VXLAN_HEADER_SIZE];
        buffer[vxlan::FLAGS_OFFSET] = config.vxlan_flags;
        return buffer;
    }

    fn create_pseudo_vxlan_packet(config: &NpbConfig) -> Vec<u8> {
        let mut l2 = Self::create_pseudo_ether_header(config);
        let mut l3 = Self::create_pseudo_ip_header(config, IpNextHeaderProtocols::Udp);
        let mut l4 = Self::create_pseudo_udp_header(config);
        let mut vxlan = Self::create_pseudo_vxlan_header(config);

        l2.append(&mut l3);
        l2.append(&mut l4);
        l2.append(&mut vxlan);
        return l2;
    }

    fn create_pseudo_gre_packet() -> Vec<u8> {
        let mut buffer = [0u8; GRE_HEADER_SIZE];
        let mut gre_header = MutableGrePacket::new(&mut buffer).unwrap();
        gre_header.set_key_present(1);
        gre_header.set_sequence_present(1);
        gre_header.set_protocol_type(erspan::GRE_PROTO_ERSPAN_III as u16);
        return buffer.to_vec();
    }

    fn create_pseudo_erspan_header() -> Vec<u8> {
        let mut buffer = [0u8; ERSPAN_HEADER_SIZE];
        buffer[erspan::TYPE3_VER_OFFSET] = 0x20;
        buffer[erspan::TYPE3_FLAGS_OFFSET] = 6;
        return buffer.to_vec();
    }

    fn create_pseudo_erspan_packet(config: &NpbConfig) -> Vec<u8> {
        let mut l2 = Self::create_pseudo_ether_header(config);
        let mut l3 = Self::create_pseudo_ip_header(config, IpNextHeaderProtocols::Gre);
        let mut gre = Self::create_pseudo_gre_packet();
        let mut erspan = Self::create_pseudo_erspan_header();

        l2.append(&mut l3);
        l2.append(&mut gre);
        l2.append(&mut erspan);
        return l2;
    }

    fn create_pseudo_tcp_packet(config: &NpbConfig) -> Vec<u8> {
        let mut packet_size = if !config.underlay_is_ipv6 {
            TCP_PACKET_SIZE + NpbHeader::SIZEOF
        } else {
            TCP6_PACKET_SIZE + NpbHeader::SIZEOF
        };
        if config.output_vlan > 0 {
            packet_size += VLAN_HEADER_SIZE;
        }

        vec![u8::from(IpProtocol::TCP); packet_size]
    }

    pub fn on_config_change(&mut self, config: &NpbConfig, queue_debugger: &QueueDebugger) {
        if self.npb_packet_sender.is_none() {
            return;
        }
        let is_running = self.npb_packet_sender.as_ref().unwrap().is_running();
        self.stop();
        self.npb_packet_sender = None;

        let (sender, receiver, _) =
            bounded_with_debug(4096, "1-packet-to-npb-sender", queue_debugger);
        let npb_packet_sender = Arc::new(NpbPacketSender::new(
            self.id,
            receiver,
            config,
            self.arp.clone(),
            self.stats_collector.clone(),
        ));

        self.mtu = config.mtu as usize;
        self.underlay_is_ipv6 = config.underlay_is_ipv6;
        self.underlay_has_vlan = config.output_vlan > 0;
        self.overlay_vlan_mode = config.vlan_mode;
        self.pseudo_tunnel_header = [
            Self::create_pseudo_vxlan_packet(config),
            Self::create_pseudo_erspan_packet(config),
            vec![],
            vec![],
            Self::create_pseudo_tcp_packet(config),
        ];
        self.npb_packet_sender = Some(npb_packet_sender);
        self.sender = sender;

        if is_running {
            self.start();
        }
    }

    pub fn new(
        id: usize,
        config: &NpbConfig,
        queue_debugger: &QueueDebugger,
        npb_bps_limit: Arc<LeakyBucket>,
        arp: Arc<NpbArpTable>,
        stats_collector: Arc<stats::Collector>,
    ) -> Box<Self> {
        let (sender, receiver, _) =
            bounded_with_debug(4096, "1-packet-to-npb-sender", queue_debugger);

        let builder = Box::new(Self {
            id,
            mtu: config.mtu as usize,
            enable_qos_bypass: config.enable_qos_bypass, // TODO
            underlay_is_ipv6: config.underlay_is_ipv6,
            underlay_has_vlan: config.output_vlan > 0,
            overlay_vlan_mode: config.vlan_mode,
            sender,
            npb_packet_sender: Some(Arc::new(NpbPacketSender::new(
                id,
                receiver,
                &config,
                arp.clone(),
                stats_collector.clone(),
            ))),
            pseudo_tunnel_header: [
                Self::create_pseudo_vxlan_packet(config),
                Self::create_pseudo_erspan_packet(config),
                vec![],
                vec![],
                Self::create_pseudo_tcp_packet(config),
            ],
            thread_handle: Mutex::new(None),
            arp,
            stats_collector,
            bps_limit: npb_bps_limit,
        });

        builder
    }

    pub fn build_with(&self, id: usize, if_index: u32, mac: MacAddr) -> NpbHandler {
        let counter = Arc::new(NpbHandlerCounter::default());

        if !NOT_SUPPORT {
            info!(
                "Build with npb packet handler with id: {} if_index: {} mac: {}",
                id, if_index, mac
            );

            self.stats_collector.register_countable(
                "fragmenter",
                Countable::Owned(Box::new(StatsNpbHandlerCounter(Arc::downgrade(&counter)))),
                vec![
                    StatsOption::Tag("index", id.to_string()),
                    StatsOption::Tag("mac", mac.to_string()),
                    StatsOption::Tag("ifIndex", if_index.to_string()),
                ],
            );
        }

        let mut underlay_vlan_header_size = 0;
        if self.underlay_has_vlan {
            underlay_vlan_header_size = VLAN_HEADER_SIZE
        }

        NpbHandler::new(
            id,
            self.mtu,
            self.pseudo_tunnel_header.clone(),
            underlay_vlan_header_size,
            self.overlay_vlan_mode,
            self.bps_limit.clone(),
            counter,
            self.sender.clone(),
        )
    }

    pub fn start(&mut self) {
        if self.npb_packet_sender.is_some() && self.npb_packet_sender.as_ref().unwrap().is_running()
        {
            return;
        }
        info!("Start npb packet sender {}.", self.id);
        self.npb_packet_sender.as_ref().unwrap().start();

        let sync_sender = self.npb_packet_sender.as_ref().unwrap().clone();
        *self.thread_handle.lock().unwrap() = Some(
            thread::Builder::new()
                .name("npb-packet-sender".to_owned())
                .spawn(move || sync_sender.run())
                .unwrap(),
        );
    }

    pub fn notify_stop(&self) -> Option<JoinHandle<()>> {
        if self.npb_packet_sender.is_none()
            || !self.npb_packet_sender.as_ref().unwrap().is_running()
        {
            return None;
        }
        self.npb_packet_sender.as_ref().unwrap().stop();

        info!("Notified stop npb packet sender {}.", self.id);
        self.thread_handle.lock().unwrap().take()
    }

    pub fn stop(&self) {
        if self.npb_packet_sender.is_none()
            || !self.npb_packet_sender.as_ref().unwrap().is_running()
        {
            return;
        }
        self.npb_packet_sender.as_ref().unwrap().stop();

        if let Some(handler) = self.thread_handle.lock().unwrap().take() {
            let _ = handler.join();
        }

        info!("Stop npb packet sender {}.", self.id);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use public::consts::NPB_DEFAULT_PORT;

    #[test]
    fn test_pseudo_vxlan() {
        let config = NpbConfig {
            npb_port: NPB_DEFAULT_PORT,
            vxlan_flags: 0x08,
            output_vlan: 0,
            enable_qos_bypass: false,
            underlay_is_ipv6: false,
            ..Default::default()
        };
        let vxlan_packet = NpbBuilder::create_pseudo_vxlan_packet(&config);
        assert_eq!(vxlan_packet.len(), 50);
        assert_eq!(
            vxlan_packet,
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 69, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 192, 0, 18, 181, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0
            ]
        );

        let config = NpbConfig {
            output_vlan: 4097,
            npb_port: NPB_DEFAULT_PORT,
            vxlan_flags: 0xff,
            enable_qos_bypass: false,
            underlay_is_ipv6: false,
            ..Default::default()
        };
        let vxlan_packet = NpbBuilder::create_pseudo_vxlan_packet(&config);
        assert_eq!(vxlan_packet.len(), 54);
        assert_eq!(
            vxlan_packet,
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 0, 0, 1, 8, 0, 69, 0, 0, 0, 0, 0, 0, 0,
                64, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 18, 181, 0, 0, 0, 0, 255, 0, 0, 0, 0,
                0, 0, 0
            ]
        );

        let config = NpbConfig {
            output_vlan: 4097,
            npb_port: NPB_DEFAULT_PORT,
            vxlan_flags: 0xff,
            underlay_is_ipv6: true,
            enable_qos_bypass: false,
            ..Default::default()
        };
        let vxlan_packet = NpbBuilder::create_pseudo_vxlan_packet(&config);
        assert_eq!(vxlan_packet.len(), 74);
        assert_eq!(
            vxlan_packet,
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 0, 0, 1, 134, 221, 96, 0, 0, 0, 0, 0, 17,
                64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 192, 0, 18, 181, 0, 0, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }
}
