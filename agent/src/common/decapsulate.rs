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

use std::fmt;
use std::net::Ipv4Addr;

use num_enum::TryFromPrimitive;

use super::consts::*;
use super::enums::{EthernetType, IpProtocol};

use crate::utils::bytes;
use serde::Serialize;

use public::proto::trident::DecapType;

#[derive(Serialize, Debug, Clone, Copy, PartialEq, PartialOrd, TryFromPrimitive)]
#[repr(u8)]
pub enum TunnelType {
    // The maximum value here is 15
    None = DecapType::None as u8,
    Vxlan = DecapType::Vxlan as u8,
    Ipip = DecapType::Ipip as u8,
    TencentGre = DecapType::Tencent as u8,
    Geneve = DecapType::Geneve as u8,
    ErspanOrTeb = DecapType::Geneve as u8 + 1,
}

impl From<DecapType> for TunnelType {
    fn from(t: DecapType) -> Self {
        match t {
            DecapType::None => TunnelType::None,
            DecapType::Vxlan => TunnelType::Vxlan,
            DecapType::Ipip => TunnelType::Ipip,
            DecapType::Tencent => TunnelType::TencentGre,
            DecapType::Geneve => TunnelType::Geneve,
        }
    }
}

impl fmt::Display for TunnelType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TunnelType::None => write!(f, "none"),
            TunnelType::Vxlan => write!(f, "VXLAN"),
            TunnelType::Ipip => write!(f, "IPIP"),
            TunnelType::TencentGre => write!(f, "GRE"),
            TunnelType::Geneve => write!(f, "Geneve"),
            TunnelType::ErspanOrTeb => write!(f, "ERSPAN_TEB"),
        }
    }
}

impl Default for TunnelType {
    fn default() -> Self {
        TunnelType::None
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TunnelTypeBitmap(u16);

impl TunnelTypeBitmap {
    pub fn new(tunnel_types: &Vec<TunnelType>) -> Self {
        let mut bitmap = TunnelTypeBitmap(0);
        for tunnel_type in tunnel_types.iter() {
            bitmap.0 |= 1 << *tunnel_type as u16;
        }
        bitmap
    }

    pub fn add(&mut self, tunnel_type: TunnelType) {
        self.0 |= 1 << tunnel_type as u16
    }

    pub fn has(&self, tunnel_type: TunnelType) -> bool {
        self.0 & (1 << tunnel_type as u16) != 0
    }

    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for TunnelTypeBitmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return write!(f, "{}", TunnelType::None);
        }
        let mut separation = "";
        if self.has(TunnelType::Vxlan) {
            write!(f, "{}", TunnelType::Vxlan)?;
            separation = " ";
        }
        if self.has(TunnelType::Ipip) {
            write!(f, "{}{}", separation, TunnelType::Ipip)?;
            separation = " ";
        }
        if self.has(TunnelType::TencentGre) {
            write!(f, "{}{}", separation, TunnelType::TencentGre)?;
            separation = " ";
        }
        if self.has(TunnelType::ErspanOrTeb) {
            write!(f, "{}{}", separation, TunnelType::ErspanOrTeb)?;
        }
        write!(f, "")
    }
}

const LE_IPV4_PROTO_TYPE_I: u16 = 0x0008; // 0x0008's LittleEndian
const LE_IPV6_PROTO_TYPE_I: u16 = 0xDD86; // 0x86dd's LittleEndian
const LE_ERSPAN_PROTO_TYPE_II: u16 = 0xBE88; // 0x88BE's LittleEndian
const LE_ERSPAN_PROTO_TYPE_III: u16 = 0xEB22; // 0x22EB's LittleEndian
const LE_VXLAN_PROTO_UDP_DPORT: u16 = 0xB512; // 0x12B5(4789)'s LittleEndian
const LE_VXLAN_PROTO_UDP_DPORT2: u16 = 0x1821; // 0x2118(8472)'s LittleEndian
const LE_VXLAN_PROTO_UDP_DPORT3: u16 = 0x801A; // 0x1A80(6784)'s LittleEndian
const LE_TRANSPARENT_ETHERNET_BRIDGEING: u16 = 0x5865; // 0x6558(25944)'s LittleEndian
const LE_GENEVE_PROTO_UDP_DPORT: u16 = 0xc117; // 0x17c1(6081)'s LittleEndian

const VXLAN_FLAGS: u8 = 8;
const TUNNEL_TIER_LIMIT: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TunnelInfo {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub mac_src: u32, // lowest 4B
    pub mac_dst: u32, // lowest 4B
    pub id: u32,
    pub tunnel_type: TunnelType,
    pub tier: u8,
    pub is_ipv6: bool,
}

impl Default for TunnelInfo {
    fn default() -> Self {
        TunnelInfo {
            src: Ipv4Addr::UNSPECIFIED,
            dst: Ipv4Addr::UNSPECIFIED,
            mac_src: 0,
            mac_dst: 0,
            id: 0,
            tunnel_type: TunnelType::default(),
            tier: 0,
            is_ipv6: false,
        }
    }
}

impl TunnelInfo {
    fn decapsulate_addr(&mut self, l3_packet: &[u8]) {
        self.src = Ipv4Addr::from(bytes::read_u32_be(
            &l3_packet[FIELD_OFFSET_SIP - ETH_HEADER_SIZE..],
        ));
        self.dst = Ipv4Addr::from(bytes::read_u32_be(
            &l3_packet[FIELD_OFFSET_DIP - ETH_HEADER_SIZE..],
        ));
    }

    fn decapsulate_mac(&mut self, packet: &[u8]) {
        self.mac_src = bytes::read_u32_be(&packet[FIELD_OFFSET_SA + 2..]); // MAC低4个字节
        self.mac_dst = bytes::read_u32_be(&packet[FIELD_OFFSET_DA + 2..]);
    }

    fn decapsulate_v6_addr(&mut self, l3_packet: &[u8]) {
        self.src = Ipv4Addr::from(bytes::read_u32_be(&l3_packet[IP6_SIP_OFFSET..]));
        self.dst = Ipv4Addr::from(bytes::read_u32_be(&l3_packet[IP6_DIP_OFFSET..]));
    }

    pub fn decapsulate_udp(
        &mut self,
        packet: &[u8],
        l2_len: usize,
        tunnel_types: &TunnelTypeBitmap,
    ) -> usize {
        let l3_packet = &packet[l2_len..];
        let dst_port_offset = FIELD_OFFSET_DPORT - ETH_HEADER_SIZE;
        if dst_port_offset + PORT_LEN > l3_packet.len() {
            return 0;
        }
        let dst_port = bytes::read_u16_le(&l3_packet[FIELD_OFFSET_DPORT - ETH_HEADER_SIZE..]);
        match dst_port {
            LE_VXLAN_PROTO_UDP_DPORT | LE_VXLAN_PROTO_UDP_DPORT2 | LE_VXLAN_PROTO_UDP_DPORT3
                if tunnel_types.has(TunnelType::Vxlan) =>
            {
                self.decapsulate_vxlan(packet, l2_len)
            }
            LE_GENEVE_PROTO_UDP_DPORT if tunnel_types.has(TunnelType::Geneve) => {
                self.decapsulate_geneve(packet, l2_len)
            }
            _ => 0,
        }
    }

    pub fn decapsulate_vxlan(&mut self, packet: &[u8], l2_len: usize) -> usize {
        let l3_packet = &packet[l2_len..];
        if l3_packet.len() < FIELD_OFFSET_VXLAN_FLAGS + VXLAN_HEADER_SIZE {
            return 0;
        }

        if l3_packet[FIELD_OFFSET_VXLAN_FLAGS - ETH_HEADER_SIZE] != VXLAN_FLAGS {
            return 0;
        }

        // 仅保存最外层的隧道信息
        if self.tier == 0 {
            self.decapsulate_addr(l3_packet);
            self.decapsulate_mac(packet);
            self.tunnel_type = TunnelType::Vxlan;
            self.id =
                bytes::read_u32_be(&l3_packet[FIELD_OFFSET_VXLAN_VNI - ETH_HEADER_SIZE..]) >> 8;
        }
        self.tier += 1;

        // return offset start from L3
        FIELD_OFFSET_VXLAN_FLAGS - ETH_HEADER_SIZE + VXLAN_HEADER_SIZE
    }

    fn calc_gre_option_size(flags: u16) -> usize {
        let mut size = 0;
        if flags & GRE_FLAGS_KEY_MASK != 0 {
            size += GRE_KEY_LEN;
        }
        if flags & GRE_FLAGS_SEQ_MASK != 0 {
            size += GRE_SEQ_LEN;
        }
        if flags & GRE_FLAGS_CSUM_MASK != 0 {
            size += GRE_CSUM_LEN;
        }
        size
    }

    pub fn decapsulate_erspan(
        &mut self,
        packet: &[u8],
        l2_len: usize,
        flags: u16,
        gre_protocol_type: u16,
        ip_header_size: usize,
    ) -> usize {
        let l3_packet = &packet[l2_len..];
        match gre_protocol_type {
            // ERSPAN I
            LE_ERSPAN_PROTO_TYPE_II if flags == 0 => {
                // 仅保存最外层的隧道信息
                if self.tier == 0 {
                    self.decapsulate_addr(l3_packet);
                    self.decapsulate_mac(packet);
                    self.tunnel_type = TunnelType::ErspanOrTeb;
                }
                self.tier += 1;
                ip_header_size + GRE_HEADER_SIZE_DECAP + ERSPAN_I_HEADER_SIZE
            }
            // ERSPAN II
            LE_ERSPAN_PROTO_TYPE_II => {
                let gre_header_size =
                    GRE_HEADER_SIZE_DECAP + TunnelInfo::calc_gre_option_size(flags);
                if self.tier == 0 {
                    self.decapsulate_addr(l3_packet);
                    self.decapsulate_mac(packet);
                    self.tunnel_type = TunnelType::ErspanOrTeb;
                    self.id = bytes::read_u32_be(
                        &l3_packet[ip_header_size + gre_header_size + ERSPAN_ID_OFFSET..],
                    ) & 0x3ff;
                }
                self.tier += 1;
                ip_header_size + gre_header_size + ERSPAN_II_HEADER_SIZE
            }
            LE_ERSPAN_PROTO_TYPE_III => {
                let gre_header_size =
                    GRE_HEADER_SIZE_DECAP + TunnelInfo::calc_gre_option_size(flags);
                // 仅保存最外层的隧道信息
                if self.tier == 0 {
                    self.decapsulate_addr(l3_packet);
                    self.decapsulate_mac(packet);
                    self.tunnel_type = TunnelType::ErspanOrTeb;
                    self.id = bytes::read_u32_be(
                        &l3_packet[ip_header_size + gre_header_size + ERSPAN_ID_OFFSET..],
                    ) & 0x3ff;
                }
                self.tier += 1;

                let flag =
                    l3_packet[ip_header_size + gre_header_size + ERSPAN_III_FLAGS_OFFSET] & 0x1;
                if flag == 0 {
                    return ip_header_size + gre_header_size + ERSPAN_III_HEADER_SIZE;
                }
                ip_header_size
                    + gre_header_size
                    + ERSPAN_III_HEADER_SIZE
                    + ERSPAN_III_SUBHEADER_SIZE
            }
            _ => 0,
        }
    }

    pub fn is_gre_pseudo_inner_mac(mac: u64) -> bool {
        mac >> 16 == 0
    }

    pub fn decapsulate_tencent_gre(
        &mut self,
        packet: &mut [u8],
        l2_len: usize,
        flags: u16,
        gre_protocol_type: u16,
        ip_header_size: usize,
    ) -> usize {
        // TCE GRE：Version 0、Version 1两种
        if flags & GRE_FLAGS_VER_MASK > 1 || flags & GRE_FLAGS_KEY_MASK == 0 {
            return 0;
        }

        let gre_header_size = GRE_HEADER_SIZE_DECAP + TunnelInfo::calc_gre_option_size(flags);
        let mut gre_key_offset = GRE_KEY_OFFSET;
        if flags & GRE_FLAGS_CSUM_MASK != 0 {
            gre_key_offset += GRE_CSUM_LEN;
        }

        if self.tier == 0 {
            self.decapsulate_mac(packet);
        }
        let l3_packet = &mut packet[l2_len..];
        // 仅保存最外层的隧道信息
        if self.tier == 0 {
            self.decapsulate_addr(l3_packet);
            self.tunnel_type = TunnelType::TencentGre;
            self.id = bytes::read_u32_be(&l3_packet[ip_header_size + gre_key_offset..]);
        }
        self.tier += 1;
        let overlay_offset = gre_header_size + ip_header_size - ETH_HEADER_SIZE; // 伪造L2层信息

        // NOTICE:
        //     这里需要将TunnelID封装为Mac Suffix，策略FastPath需要不同的MAC区分不同的VPC。
        // 腾讯GRE流量是通过TunnelID来确认其对应的EPC ID的，这个将TunnelID用作MAC后缀，同
        // 样能在FastPath里面区分不同的VPC。
        //     这样的伪造MAC可以通过IsGrePseudoInnerMac函数判断
        let mut macs = if gre_protocol_type == LE_IPV4_PROTO_TYPE_I {
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x8, 0]
        } else {
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x86, 0xdd]
        };
        macs[4..6].copy_from_slice(
            &l3_packet[ip_header_size + gre_key_offset + 2..ip_header_size + gre_key_offset + 4],
        );
        macs[10..12].copy_from_slice(
            &l3_packet[ip_header_size + gre_key_offset..ip_header_size + gre_key_offset + 2],
        );
        l3_packet[overlay_offset..overlay_offset + 14].copy_from_slice(&macs[..]);

        overlay_offset
    }

    pub fn decapsulate_teb(
        &mut self,
        packet: &[u8],
        l2_len: usize,
        flags: u16,
        ip_header_size: usize,
    ) -> usize {
        if flags & GRE_FLAGS_VER_MASK != 0 || flags & GRE_FLAGS_KEY_MASK == 0 {
            return 0;
        }

        let gre_header_size = GRE_HEADER_SIZE_DECAP + TunnelInfo::calc_gre_option_size(flags);
        let mut gre_key_offset = GRE_KEY_OFFSET;
        if flags & GRE_FLAGS_CSUM_MASK != 0 {
            gre_key_offset += GRE_CSUM_LEN;
        }

        let l3_packet = &packet[l2_len..];
        // 仅保存最外层的隧道信息
        if self.tier == 0 {
            self.decapsulate_addr(l3_packet);
            self.decapsulate_mac(packet);
            self.tunnel_type = TunnelType::ErspanOrTeb;
            self.id = bytes::read_u32_be(&l3_packet[ip_header_size + gre_key_offset..]);
        }
        self.tier += 1;
        gre_header_size + ip_header_size
    }

    pub fn decapsulate_gre(
        &mut self,
        packet: &mut [u8],
        l2_len: usize,
        tunnel_types: &TunnelTypeBitmap,
    ) -> usize {
        let l3_packet = &packet[l2_len..];
        let ip_header_size: usize = (l3_packet[IP_IHL_OFFSET] as usize & 0xf) << 2;
        let flags = bytes::read_u16_be(&l3_packet[ip_header_size + GRE_FLAGS_OFFSET..]);
        let gre_protocol_type =
            bytes::read_u16_le(&l3_packet[ip_header_size + GRE_PROTOCOL_OFFSET..]);

        match gre_protocol_type {
            // ERSPAN
            LE_ERSPAN_PROTO_TYPE_II | LE_ERSPAN_PROTO_TYPE_III
                if tunnel_types.has(TunnelType::ErspanOrTeb) =>
            {
                self.decapsulate_erspan(packet, l2_len, flags, gre_protocol_type, ip_header_size)
            }

            LE_IPV4_PROTO_TYPE_I | LE_IPV6_PROTO_TYPE_I
                if tunnel_types.has(TunnelType::TencentGre) =>
            {
                self.decapsulate_tencent_gre(
                    packet,
                    l2_len,
                    flags,
                    gre_protocol_type,
                    ip_header_size,
                )
            }
            LE_TRANSPARENT_ETHERNET_BRIDGEING if tunnel_types.has(TunnelType::ErspanOrTeb) => {
                self.decapsulate_teb(packet, l2_len, flags, ip_header_size)
            }
            _ => 0,
        }
    }

    pub fn decapsulate_geneve(&mut self, packet: &[u8], l2_len: usize) -> usize {
        let l3_packet = &packet[l2_len..];
        if l3_packet.len() < UDP_PACKET_SIZE + GENEVE_HEADER_SIZE {
            return 0;
        }

        let l4_payload = &l3_packet[IPV4_HEADER_SIZE + UDP_HEADER_SIZE..];
        let (tunnel_id, geneve_header_size) = Self::decapsulate_geneve_header(l4_payload);
        if geneve_header_size == 0 {
            return 0;
        }

        // 仅保存最外层的隧道信息
        if self.tier == 0 {
            self.decapsulate_addr(l3_packet);
            self.decapsulate_mac(packet);
            self.tunnel_type = TunnelType::Geneve;
            self.id = tunnel_id;
        }
        self.tier += 1;

        // return offset start from L3
        UDP_PACKET_SIZE - ETH_HEADER_SIZE + geneve_header_size
    }

    pub fn decapsulate(
        &mut self,
        packet: &mut [u8],
        l2_len: usize,
        tunnel_types: &TunnelTypeBitmap,
    ) -> usize {
        if tunnel_types.is_empty() || self.tier == TUNNEL_TIER_LIMIT {
            return 0;
        }

        // 通过ERSPAN_III_HEADER_SIZE(12 bytes)+ERSPAN_III_SUBHEADER_SIZE(8 bytes)判断，保证不会数组越界
        let l3_packet = &packet[l2_len..];
        if l3_packet.len()
            < IPV4_HEADER_SIZE
                + GRE_HEADER_SIZE_DECAP
                + ERSPAN_III_HEADER_SIZE
                + ERSPAN_III_SUBHEADER_SIZE
        {
            return 0;
        }

        let protocol: IpProtocol = l3_packet[FIELD_OFFSET_PROTO - ETH_HEADER_SIZE]
            .try_into()
            .unwrap_or_default();
        match protocol {
            IpProtocol::UDP => self.decapsulate_udp(packet, l2_len, tunnel_types),
            IpProtocol::GRE => self.decapsulate_gre(packet, l2_len, tunnel_types),
            IpProtocol::IPV4 if tunnel_types.has(TunnelType::Ipip) => {
                self.decapsulate_ipip(packet, l2_len, false, false)
            }
            IpProtocol::IPV6 if tunnel_types.has(TunnelType::Ipip) => {
                self.decapsulate_ipip(packet, l2_len, false, true)
            }
            _ => 0,
        }
    }

    fn decapsulate_geneve_header(l4_payload: &[u8]) -> (u32, usize) {
        if l4_payload.len() < GENEVE_HEADER_SIZE {
            return (0, 0);
        }

        let version_and_option_length = l4_payload[GENEVE_VERSION_OFFSET];
        if version_and_option_length >> GENEVE_VERSION_SHIFT != 0 {
            return (0, 0);
        }
        let option_length = ((version_and_option_length & GENEVE_OPTION_LENGTH_MASK) << 2) as usize;
        let geneve_header_size = option_length + GENEVE_HEADER_SIZE;
        if l4_payload.len() < geneve_header_size {
            return (0, 0);
        }

        let protocol_type = bytes::read_u16_le(&l4_payload[GENEVE_PROTOCOL_OFFSET..]);
        if protocol_type != LE_TRANSPARENT_ETHERNET_BRIDGEING {
            return (0, 0);
        }

        (
            bytes::read_u32_be(&l4_payload[GENEVE_VNI_OFFSET..]) >> GENEVE_VNI_SHIFT,
            geneve_header_size,
        )
    }

    pub fn decapsulate_v6_geneve(&mut self, packet: &[u8], l2_len: usize) -> usize {
        let l3_packet = &packet[l2_len..];
        if l3_packet.len() < UDP6_PACKET_SIZE + GENEVE_HEADER_SIZE {
            return 0;
        }

        let l4_payload = &l3_packet[IPV6_HEADER_SIZE + UDP_HEADER_SIZE..];
        let (tunnel_id, geneve_header_size) = Self::decapsulate_geneve_header(l4_payload);
        if geneve_header_size == 0 {
            return 0;
        }

        // 仅保存最外层的隧道信息
        if self.tier == 0 {
            self.decapsulate_v6_addr(l3_packet);
            self.decapsulate_mac(packet);
            self.tunnel_type = TunnelType::Geneve;
            self.id = tunnel_id;
            self.is_ipv6 = true;
        }
        self.tier += 1;

        // return offset start from L3
        UDP_PACKET_SIZE - ETH_HEADER_SIZE + geneve_header_size
    }

    pub fn decapsulate_v6_vxlan(&mut self, packet: &[u8], l2_len: usize) -> usize {
        let l3_packet = &packet[l2_len..];
        if l3_packet.len() < FIELD_OFFSET_VXLAN_FLAGS + VXLAN_HEADER_SIZE {
            return 0;
        }

        if l3_packet[IPV6_HEADER_SIZE + UDP_HEADER_SIZE + VXLAN_FLAGS_OFFSET_DECAP] != VXLAN_FLAGS {
            return 0;
        }

        // 仅保存最外层的隧道信息
        if self.tier == 0 {
            self.decapsulate_v6_addr(l3_packet);
            self.decapsulate_mac(packet);
            self.tunnel_type = TunnelType::Vxlan;
            self.id = bytes::read_u32_be(
                &l3_packet[IPV6_HEADER_SIZE + UDP_HEADER_SIZE + VXLAN_VNI_OFFSET_DECAP..],
            ) >> 8;
            self.is_ipv6 = true;
        }
        self.tier += 1;

        // return offset start from L3
        IPV6_HEADER_SIZE + UDP_HEADER_SIZE + VXLAN_HEADER_SIZE
    }

    pub fn decapsulate_v6_udp(
        &mut self,
        packet: &[u8],
        l2_len: usize,
        tunnel_types: &TunnelTypeBitmap,
    ) -> usize {
        let l3_packet = &packet[l2_len..];
        let dst_port_offset = IPV6_HEADER_SIZE + UDP_DPORT_OFFSET;
        if dst_port_offset + PORT_LEN > l3_packet.len() {
            return 0;
        }
        let dst_port = bytes::read_u16_le(&l3_packet[dst_port_offset..]);
        match dst_port {
            LE_VXLAN_PROTO_UDP_DPORT | LE_VXLAN_PROTO_UDP_DPORT2 | LE_VXLAN_PROTO_UDP_DPORT3
                if tunnel_types.has(TunnelType::Vxlan) =>
            {
                self.decapsulate_v6_vxlan(packet, l2_len)
            }
            LE_GENEVE_PROTO_UDP_DPORT if tunnel_types.has(TunnelType::Geneve) => {
                self.decapsulate_v6_geneve(packet, l2_len)
            }
            _ => 0,
        }
    }

    pub fn decapsulate_v6(
        &mut self,
        packet: &mut [u8],
        l2_len: usize,
        tunnel_types: &TunnelTypeBitmap,
    ) -> usize {
        if tunnel_types.is_empty() || self.tier == TUNNEL_TIER_LIMIT {
            return 0;
        }

        let l3_packet = &packet[l2_len..];
        // 通过ERSPAN_III_HEADER_SIZE(12 bytes)+ERSPAN_III_SUBHEADER_SIZE(8 bytes)判断，保证不会数组越界
        if l3_packet.len()
            < IPV6_HEADER_SIZE
                + GRE_HEADER_SIZE_DECAP
                + ERSPAN_III_HEADER_SIZE
                + ERSPAN_III_SUBHEADER_SIZE
        {
            return 0;
        }

        let protocol: IpProtocol = l3_packet[IP6_PROTO_OFFSET].try_into().unwrap_or_default();
        match protocol {
            IpProtocol::UDP => self.decapsulate_v6_udp(packet, l2_len, tunnel_types),
            IpProtocol::IPV4 if tunnel_types.has(TunnelType::Ipip) => {
                self.decapsulate_ipip(packet, l2_len, true, false)
            }
            IpProtocol::IPV6 if tunnel_types.has(TunnelType::Ipip) => {
                self.decapsulate_ipip(packet, l2_len, true, true)
            }
            _ => 0,
        }
    }

    pub fn is_valid(self) -> bool {
        self.tunnel_type != TunnelType::None
    }

    pub fn decapsulate_ipip(
        &mut self,
        packet: &mut [u8],
        l2_len: usize,
        underlay_ipv6: bool,
        overlay_ipv6: bool,
    ) -> usize {
        if self.tier == 0 {
            self.decapsulate_mac(packet);
        }

        let l3_packet = &mut packet[l2_len..];
        let underlay_ip_header_size = if underlay_ipv6 {
            // underlay网络为IPv6时不支持Options字段
            IPV6_HEADER_SIZE
        } else {
            ((l3_packet[IP_IHL_OFFSET] & 0xf) << 2) as usize
        };

        if self.tier == 0 {
            if underlay_ipv6 {
                self.decapsulate_v6_addr(l3_packet);
                self.is_ipv6 = true;
            } else {
                self.decapsulate_addr(l3_packet);
            }
            self.tunnel_type = TunnelType::Ipip;
            self.id = 0;
        }
        self.tier += 1;

        // 去除underlay ip头，将l2层头放在overlay ip头前

        // 偏移计算：overlay ip头开始位置(l2Len + underlayIpHeaderSize) - l2层长度(l2Len)
        let start = l2_len + underlay_ip_header_size - l2_len;

        packet.copy_within(0..l2_len, start);
        if !overlay_ipv6 {
            bytes::write_u16_be(
                &mut packet[start + l2_len - 2..],
                u16::from(EthernetType::IPV4),
            );
        } else {
            bytes::write_u16_be(
                &mut packet[start + l2_len - 2..],
                u16::from(EthernetType::IPV6),
            );
        }
        // l2已经做过解析，这个去除掉已经解析的l2长度
        start - l2_len
    }
}

impl fmt::Display for TunnelInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "type: {:?}, src: {} {:#010x}, dst: {} {:#010x}, id: {}, tier: {}",
            self.tunnel_type, self.src, self.mac_src, self.dst, self.mac_dst, self.id, self.tier
        )
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::path::Path;

    use super::*;

    use crate::utils::test::Capture;

    pub const PCAP_PATH_PREFIX: &str = "./resources/test/common";

    #[test]
    fn bitmap_new() {
        let tvec = vec![TunnelType::Ipip, TunnelType::TencentGre];
        let bitmap = TunnelTypeBitmap::new(&tvec);
        assert!(bitmap.has(TunnelType::TencentGre));
        assert!(bitmap.has(TunnelType::Ipip));
        assert!(!bitmap.has(TunnelType::Vxlan));
    }

    #[test]
    fn bitmap_add() {
        let mut bitmap = TunnelTypeBitmap(0);
        assert!(bitmap.is_empty());
        bitmap.add(TunnelType::Ipip);
        bitmap.add(TunnelType::Vxlan);
        assert!(bitmap.has(TunnelType::Ipip));
        assert!(bitmap.has(TunnelType::Vxlan));
        assert!(!bitmap.has(TunnelType::TencentGre));
    }

    #[test]
    fn test_decapsulate_erspan() {
        let bitmap = TunnelTypeBitmap::new(&vec![TunnelType::ErspanOrTeb]);
        let expected = TunnelInfo {
            src: Ipv4Addr::new(172, 28, 25, 108),
            dst: Ipv4Addr::new(172, 28, 28, 70),
            mac_src: 0xbdf819ff,
            mac_dst: 0x22222222,
            id: 0,
            tunnel_type: TunnelType::ErspanOrTeb,
            tier: 1,
            is_ipv6: false,
        };
        let mut packets: Vec<Vec<u8>> = Capture::load_pcap(
            Path::new(PCAP_PATH_PREFIX).join("decapsulate_erspan1.pcap"),
            None,
        )
        .into();
        let packet = packets[0].as_mut_slice();

        let l2_len = 18;
        let mut actual = TunnelInfo::default();
        let offset = actual.decapsulate(packet, l2_len, &bitmap);
        let expected_offset = IPV4_HEADER_SIZE + GRE_HEADER_SIZE_DECAP;

        assert_eq!(offset, expected_offset);
        assert_eq!(actual, expected);

        let packet = packets[1].as_mut_slice();
        let mut actual = TunnelInfo::default();
        let offset = actual.decapsulate(packet, l2_len, &bitmap);

        assert_eq!(offset, expected_offset);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_decapsulate_erspan_ii() {
        let bitmap = TunnelTypeBitmap::new(&vec![TunnelType::ErspanOrTeb]);
        let expected = TunnelInfo {
            src: Ipv4Addr::new(2, 2, 2, 2),
            dst: Ipv4Addr::new(1, 1, 1, 1),
            mac_src: 0xf1e20101,
            mac_dst: 0xf1e20112,
            id: 100,
            tunnel_type: TunnelType::ErspanOrTeb,
            tier: 1,
            is_ipv6: false,
        };
        let mut packets: Vec<Vec<u8>> = Capture::load_pcap(
            Path::new(PCAP_PATH_PREFIX).join("decapsulate_test.pcap"),
            None,
        )
        .into();
        let packet = packets[0].as_mut_slice();

        let l2_len = 14;
        let mut actual = TunnelInfo::default();
        let offset = actual.decapsulate(packet, l2_len, &bitmap);
        let expected_offset = 50 - l2_len;

        assert_eq!(offset, expected_offset);
        assert_eq!(actual, expected);

        let packet = packets[1].as_mut_slice();
        let mut actual = TunnelInfo::default();
        let offset = actual.decapsulate(packet, l2_len, &bitmap);

        assert_eq!(offset, expected_offset);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_decapsulate_erspan_iii() {
        let bitmap = TunnelTypeBitmap::new(&vec![TunnelType::ErspanOrTeb]);
        let expected = TunnelInfo {
            src: Ipv4Addr::new(172, 16, 1, 103),
            dst: Ipv4Addr::new(10, 30, 101, 132),
            mac_src: 0x60d19449,
            mac_dst: 0x3ee959f5,
            id: 0,
            tunnel_type: TunnelType::ErspanOrTeb,
            tier: 1,
            is_ipv6: false,
        };
        let mut packets: Vec<Vec<u8>> = Capture::load_pcap(
            Path::new(PCAP_PATH_PREFIX).join("decapsulate_test.pcap"),
            None,
        )
        .into();
        let packet = packets[3].as_mut_slice();

        let l2_len = 14;
        let mut actual = TunnelInfo::default();
        let offset = actual.decapsulate(packet, l2_len, &bitmap);
        let expected_offset = 54 - l2_len;

        assert_eq!(offset, expected_offset);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_decapsulate_vxlan() {
        let bitmap = TunnelTypeBitmap::new(&vec![TunnelType::Vxlan]);
        let expected = TunnelInfo {
            src: Ipv4Addr::new(172, 16, 1, 103),
            dst: Ipv4Addr::new(172, 20, 1, 171),
            mac_src: 0xafda7679,
            mac_dst: 0x3ddd88c3,
            id: 123,
            tunnel_type: TunnelType::Vxlan,
            tier: 1,
            is_ipv6: false,
        };
        let mut packets: Vec<Vec<u8>> = Capture::load_pcap(
            Path::new(PCAP_PATH_PREFIX).join("decapsulate_test.pcap"),
            None,
        )
        .into();
        let packet = packets[2].as_mut_slice();

        let l2_len = 14;
        let mut actual = TunnelInfo::default();
        let offset = actual.decapsulate(packet, l2_len, &bitmap);
        let expected_offset = 50 - l2_len;

        assert_eq!(offset, expected_offset);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_decapsulate_tencent_gre() {
        let bitmap = TunnelTypeBitmap::new(&vec![TunnelType::TencentGre]);
        let expected = TunnelInfo {
            src: Ipv4Addr::new(10, 19, 0, 21),
            dst: Ipv4Addr::new(10, 21, 64, 5),
            mac_src: 0xbffac801,
            mac_dst: 0x06246b71,
            id: 0x10285,
            tunnel_type: TunnelType::TencentGre,
            tier: 1,
            is_ipv6: false,
        };
        let expected_overlay = [
            0x00, 0x00, 0x00, 0x00, 0x02, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x28, 0x87, 0x93, 0x40, 0x00, 0x40, 0x06, 0xa8, 0xe7, 0x0a, 0x01,
            0xfb, 0x29, 0x0a, 0x01, 0xfb, 0x29,
        ];

        let mut packets: Vec<Vec<u8>> =
            Capture::load_pcap(Path::new(PCAP_PATH_PREFIX).join("tencent-gre.pcap"), None).into();
        let packet = packets[0].as_mut_slice();

        let l2_len = 14;
        let mut actual = TunnelInfo::default();
        let offset = actual.decapsulate(packet, l2_len, &bitmap);
        let expected_offset = 18;

        let actual_overlay: [u8; 34] = packet
            [l2_len + expected_offset..l2_len + expected_offset + 34]
            .try_into()
            .unwrap();
        assert_eq!(expected_overlay, actual_overlay);
        assert_eq!(offset, expected_offset);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_decapsulate_teb() {
        let bitmap = TunnelTypeBitmap::new(&vec![TunnelType::ErspanOrTeb]);
        let expected = TunnelInfo {
            src: Ipv4Addr::new(10, 25, 6, 6),
            dst: Ipv4Addr::new(10, 25, 59, 67),
            mac_src: 0x3503bca8,
            mac_dst: 0x56aefcc6,
            id: 0x2000000,
            tunnel_type: TunnelType::ErspanOrTeb,
            tier: 1,
            is_ipv6: false,
        };
        let mut packets: Vec<Vec<u8>> = Capture::load_pcap(
            Path::new(PCAP_PATH_PREFIX).join("vmware-gre-teb.pcap"),
            None,
        )
        .into();
        let packet = packets[2].as_mut_slice();

        let l2_len = 14;
        let mut actual = TunnelInfo::default();
        let offset = actual.decapsulate(packet, l2_len, &bitmap);
        let expected_offset = 28;

        assert_eq!(offset, expected_offset);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_decapsulate_ipv6_vxlan() {
        let bitmap = TunnelTypeBitmap::new(&vec![TunnelType::Vxlan]);
        let expected = TunnelInfo {
            src: Ipv4Addr::new(0, 0, 2, 63),
            dst: Ipv4Addr::new(0, 0, 2, 61),
            mac_src: 0x3e7eda7d,
            mac_dst: 0x3ebb1665,
            id: 27,
            tunnel_type: TunnelType::Vxlan,
            tier: 1,
            is_ipv6: true,
        };
        let mut packets: Vec<Vec<u8>> =
            Capture::load_pcap(Path::new(PCAP_PATH_PREFIX).join("ip6-vxlan.pcap"), None).into();
        let packet = packets[0].as_mut_slice();

        let l2_len = 14;
        let mut actual = TunnelInfo::default();
        let offset = actual.decapsulate_v6(packet, l2_len, &bitmap);
        let expected_offset = IPV6_HEADER_SIZE + UDP_HEADER_SIZE + VXLAN_HEADER_SIZE;

        assert_eq!(offset, expected_offset);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_decapsulate_ipip() {
        let bitmap = TunnelTypeBitmap::new(&vec![TunnelType::Ipip]);
        let expected = TunnelInfo {
            src: Ipv4Addr::new(10, 162, 42, 93),
            dst: Ipv4Addr::new(10, 162, 33, 164),
            mac_src: 0x027dc643,
            mac_dst: 0x0027e67d,
            id: 0,
            tunnel_type: TunnelType::Ipip,
            tier: 1,
            is_ipv6: false,
        };
        let mut packets: Vec<Vec<u8>> =
            Capture::load_pcap(Path::new(PCAP_PATH_PREFIX).join("ipip.pcap"), None).into();
        let packet = packets[0].as_mut_slice();

        let l2_len = 18;
        let mut actual = TunnelInfo::default();
        let offset = actual.decapsulate(packet, l2_len, &bitmap);
        let expected_offset = IPV4_HEADER_SIZE - l2_len;

        assert_eq!(offset, expected_offset);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_decapsulate_all() {
        let bitmap = TunnelTypeBitmap::new(&vec![TunnelType::Vxlan, TunnelType::ErspanOrTeb]);
        let mut actual_bitmap = TunnelTypeBitmap::new(&vec![TunnelType::None]);

        let mut packets: Vec<Vec<u8>> = Capture::load_pcap(
            Path::new(PCAP_PATH_PREFIX).join("decapsulate_test.pcap"),
            None,
        )
        .into();

        let l2_len = 14;

        for packet in packets.iter_mut() {
            let actual = &mut TunnelInfo::default();
            let _ = actual.decapsulate(packet, l2_len, &bitmap);
            actual_bitmap.add(actual.tunnel_type);
        }
        assert!(actual_bitmap.has(TunnelType::Vxlan));
        assert!(actual_bitmap.has(TunnelType::ErspanOrTeb));
    }

    #[test]
    fn test_decapsulate_geneve() {
        let bitmap = TunnelTypeBitmap::new(&vec![TunnelType::Geneve]);
        let expected = TunnelInfo {
            src: Ipv4Addr::new(158, 243, 143, 4),
            dst: Ipv4Addr::new(158, 243, 143, 3),
            mac_src: 0xd3ba6ec6,
            mac_dst: 0xae952396,
            id: 3,
            tunnel_type: TunnelType::Geneve,
            tier: 1,
            is_ipv6: false,
        };
        let mut packets: Vec<Vec<u8>> =
            Capture::load_pcap(Path::new(PCAP_PATH_PREFIX).join("geneve.pcap"), None).into();
        let packet = packets[0].as_mut_slice();

        let mut actual = TunnelInfo::default();
        let offset = actual.decapsulate(packet, 14, &bitmap);
        assert_eq!(offset, IPV4_HEADER_SIZE + 24);
        assert_eq!(actual, expected);
    }
}
