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

use std::fmt;
use std::mem::swap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use super::TapPort;
use super::{
    endpoint::FeatureFlags,
    enums::{EthernetType, IpProtocol, TapType},
    flow::PacketDirection,
    matched_field::{MatchedField, MatchedFieldv4, MatchedFieldv6, MatchedFlag},
};

use npb_pcap_policy::{DedupOperator, TapSide};
use public::utils::net::MacAddr;

#[derive(Clone, Debug)]
pub struct LookupKey {
    pub timestamp: Duration,
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub eth_type: EthernetType,
    pub l2_end_0: bool,
    pub l2_end_1: bool,
    pub l3_end_0: bool,
    pub l3_end_1: bool,
    pub is_vip_0: bool,
    pub is_vip_1: bool,
    pub l3_epc_id_0: u16,
    pub l3_epc_id_1: u16,
    pub proto: IpProtocol,
    pub tap_type: TapType,
    pub feature_flag: FeatureFlags,
    pub forward_matched: Option<MatchedField>,
    pub backward_matched: Option<MatchedField>,
    pub fast_index: usize,
    pub tunnel_id: u32,
    /********** For NAT (currently only TOA) ***********/
    pub dst_nat_port: u16,
    pub src_nat_port: u16,
    pub src_nat_ip: IpAddr,
    pub dst_nat_ip: IpAddr,
    pub dst_nat_source: u8,
    pub src_nat_source: u8,
    pub direction: PacketDirection,
}

impl DedupOperator for LookupKey {
    fn is_valid(&self, tap_side: TapSide) -> bool {
        match tap_side {
            TapSide::SRC => self.l2_end_0 && self.l3_end_0,
            TapSide::DST => self.l2_end_1 && self.l3_end_1,
            _ => false,
        }
    }

    fn is_tor(&self) -> bool {
        self.tap_type == TapType::Cloud
    }
}

impl Default for LookupKey {
    fn default() -> Self {
        LookupKey {
            timestamp: Duration::ZERO,
            src_mac: Default::default(),
            dst_mac: Default::default(),
            src_ip: Ipv4Addr::UNSPECIFIED.into(),
            dst_ip: Ipv4Addr::UNSPECIFIED.into(),
            src_port: 0,
            dst_port: 0,
            eth_type: Default::default(),
            l2_end_0: false,
            l2_end_1: false,
            l3_end_0: false,
            l3_end_1: false,
            is_vip_0: false,
            is_vip_1: false,
            l3_epc_id_0: 0,
            l3_epc_id_1: 0,
            proto: Default::default(),
            tap_type: Default::default(),
            feature_flag: FeatureFlags::NONE,
            forward_matched: None,
            backward_matched: None,
            fast_index: 0,
            tunnel_id: 0,
            src_nat_source: TapPort::NAT_SOURCE_NONE,
            src_nat_ip: Ipv4Addr::UNSPECIFIED.into(),
            src_nat_port: 0,
            dst_nat_source: TapPort::NAT_SOURCE_NONE,
            dst_nat_ip: Ipv4Addr::UNSPECIFIED.into(),
            dst_nat_port: 0,
            direction: PacketDirection::ClientToServer,
        }
    }
}

impl LookupKey {
    pub fn get_nat_source(&self) -> u8 {
        self.src_nat_source.max(self.dst_nat_source)
    }

    fn set_matched_field(
        f: &mut MatchedField,
        tap_type: TapType,
        proto: IpProtocol,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_epc: u16,
        dst_epc: u16,
        src_port: u16,
        dst_port: u16,
    ) {
        f.set(MatchedFlag::TapType, u16::from(tap_type));
        f.set(MatchedFlag::Proto, u8::from(proto) as u16);
        f.set_ip(MatchedFlag::SrcIp, src_ip);
        f.set_ip(MatchedFlag::DstIp, dst_ip);
        f.set(MatchedFlag::SrcEpc, src_epc);
        f.set(MatchedFlag::DstEpc, dst_epc);
        f.set(MatchedFlag::SrcPort, src_port);
        f.set(MatchedFlag::DstPort, dst_port);
    }

    pub fn generate_matched_field(&mut self, src_epc: u16, dst_epc: u16) {
        match self.src_ip {
            IpAddr::V4(_) => {
                self.forward_matched = Some(MatchedField::V4(MatchedFieldv4::default()));
                self.backward_matched = Some(MatchedField::V4(MatchedFieldv4::default()));
            }
            IpAddr::V6(_) => {
                self.forward_matched = Some(MatchedField::V6(MatchedFieldv6::default()));
                self.backward_matched = Some(MatchedField::V6(MatchedFieldv6::default()));
            }
        }
        Self::set_matched_field(
            self.forward_matched.as_mut().unwrap(),
            self.tap_type,
            self.proto,
            self.src_ip,
            self.dst_ip,
            src_epc,
            dst_epc,
            self.src_port,
            self.dst_port,
        );
        Self::set_matched_field(
            self.backward_matched.as_mut().unwrap(),
            self.tap_type,
            self.proto,
            self.dst_ip,
            self.src_ip,
            dst_epc,
            src_epc,
            self.dst_port,
            self.src_port,
        );
    }

    pub fn reverse(&mut self) {
        swap(&mut self.src_mac, &mut self.dst_mac);
        swap(&mut self.src_ip, &mut self.dst_ip);
        swap(&mut self.src_port, &mut self.dst_port);
        swap(&mut self.l2_end_0, &mut self.l2_end_1);
        swap(&mut self.l3_end_0, &mut self.l3_end_1);
        swap(&mut self.is_vip_0, &mut self.is_vip_1);
        swap(&mut self.l3_epc_id_0, &mut self.l3_epc_id_1);
    }

    pub fn fast_key(&self, src_masked_ip: u32, dst_masked_ip: u32) -> (u64, u64) {
        let src_port = self.src_port as u64;
        let dst_port = self.dst_port as u64;
        let src_mac_suffix = self.src_mac.get_suffix() as u64;
        let dst_mac_suffix = self.dst_mac.get_suffix() as u64;
        (
            (src_masked_ip as u64) | src_mac_suffix << 32 | src_port << 48,
            (dst_masked_ip as u64) | dst_mac_suffix << 32 | dst_port << 48,
        )
    }

    pub fn is_l2(&self) -> bool {
        self.eth_type != EthernetType::Ipv4 && self.eth_type != EthernetType::Ipv6
    }

    pub fn is_tcp(&self) -> bool {
        self.proto == IpProtocol::Tcp
    }

    pub fn is_ipv4(&self) -> bool {
        self.eth_type == EthernetType::Ipv4
    }
}

impl fmt::Display for LookupKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} {}:{} > {}:{}, eth_type: {:#06x}, {} {}.{}.{} > {}.{}.{}, nat: {}.{:?}.{} > {}.{:?}.{}, proto: {:?}, tap_type: {}, tunnel_id: {}",
            self.timestamp,
            self.src_mac,
            self.l2_end_0,
            self.dst_mac,
            self.l2_end_1,
            u16::from(self.eth_type),
            self.direction,
            self.src_ip,
            self.src_port,
            self.l3_end_0,
            self.dst_ip,
            self.dst_port,
            self.l3_end_1,
            self.src_nat_source,
            self.src_nat_ip,
            self.src_nat_port,
            self.dst_nat_source,
            self.dst_nat_ip,
            self.dst_nat_port,
            self.proto,
            self.tap_type,
            self.tunnel_id,
        )
    }
}
