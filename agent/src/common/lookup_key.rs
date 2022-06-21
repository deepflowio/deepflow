use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use super::{
    endpoint::FeatureFlags,
    enums::{EthernetType, IpProtocol, TapType},
    matched_field::{MatchedField, MatchedFieldv4, MatchedFieldv6, MatchedFlag},
};

use crate::utils::net::MacAddr;

#[derive(Debug)]
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
            feature_flag: FeatureFlags::NPB,
            forward_matched: None,
            backward_matched: None,
            fast_index: 0,
            tunnel_id: 0,
        }
    }
}

impl LookupKey {
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
        f.set(MatchedFlag::Proto, proto as u16);
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
            src_epc,
            dst_epc,
            self.dst_port,
            self.src_port,
        );
    }

    pub fn has_feature_flag(&self, feature_flag: FeatureFlags) -> bool {
        self.feature_flag & feature_flag == feature_flag
    }
}

impl fmt::Display for LookupKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} {}:{} > {}:{}, eth_type: {:#06x}, {}.{}.{} > {}.{}.{}, proto: {:?}, tap_type: {}, tunnel_id: {}",
            self.timestamp,
            self.src_mac,
            self.l2_end_0,
            self.dst_mac,
            self.l2_end_1,
            self.eth_type as u16,
            self.src_ip,
            self.src_port,
            self.l3_end_0,
            self.dst_ip,
            self.dst_port,
            self.l3_end_1,
            self.proto,
            self.tap_type,
            self.tunnel_id,
        )
    }
}
