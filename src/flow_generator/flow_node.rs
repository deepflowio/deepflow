use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    net::IpAddr,
    time::Duration,
};

use super::{perf::FlowPerf, FlowState, FLOW_METRICS_PEER_DST, FLOW_METRICS_PEER_SRC};
use crate::{
    common::{
        decapsulate::TunnelType,
        endpoint::EndpointData,
        enums::{EthernetType, PacketDirection, TapType},
        flow::FlowKey,
        meta_packet::MetaPacket,
        policy::PolicyData,
        tagged_flow::TaggedFlow,
    },
    proto::common::TridentType,
};

#[derive(PartialOrd, Debug, Default)]
pub(super) struct FlowMapKey {
    pub current_time_in_unit: u64,
    pub flow_key: FlowKey,
    pub eth_type: EthernetType,
    pub tunnel_info: (TunnelType, u8),
    // 读取Config.FlowGeneratorConfig.(ignore_l2_end, ignore_tor_mac)
    pub config_ignore: (bool, bool),
    // LookupKey.l2_end_0, LookupKey.l2_end_1
    pub lookup_key_enabled: (bool, bool),
    pub trident_type: TridentType,
}

impl Ord for FlowMapKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let time_unit_ordering = self.current_time_in_unit.cmp(&other.current_time_in_unit);
        if time_unit_ordering != Ordering::Equal {
            return time_unit_ordering;
        }
        let eth_ordering = self.eth_type.cmp(&other.eth_type);
        if eth_ordering != Ordering::Equal {
            return eth_ordering;
        }

        let flow_key_ordering = self.flow_key.cmp(&other.flow_key);
        if flow_key_ordering != Ordering::Equal {
            return flow_key_ordering;
        }
        let tunnel_ordering = self
            .tunnel_info
            .partial_cmp(&other.tunnel_info)
            .unwrap_or(Ordering::Equal);
        if tunnel_ordering != Ordering::Equal {
            return tunnel_ordering;
        }

        let config_ignore_ordering = self.config_ignore.cmp(&other.config_ignore);
        if config_ignore_ordering != Ordering::Equal {
            return config_ignore_ordering;
        }
        self.lookup_key_enabled.cmp(&other.lookup_key_enabled)
    }
}

#[repr(u8)]
enum MatchMac {
    None,
    Dst,
    Src,
    All,
}

impl FlowMapKey {
    pub fn new(
        time_in_unit: u64,
        meta_packet: &MetaPacket,
        config_ignore: (bool, bool),
        trident_type: TridentType,
    ) -> Self {
        let lookup_key = &meta_packet.lookup_key;

        Self {
            current_time_in_unit: time_in_unit,
            eth_type: lookup_key.eth_type,
            flow_key: FlowKey {
                vtap_id: meta_packet.vlan,
                tap_type: lookup_key.tap_type,
                tap_port: meta_packet.tap_port,
                mac_src: lookup_key.src_mac,
                mac_dst: lookup_key.dst_mac,
                ip_src: lookup_key.src_ip,
                ip_dst: lookup_key.dst_ip,
                port_src: lookup_key.src_port,
                port_dst: lookup_key.dst_port,
                proto: lookup_key.proto,
            },
            tunnel_info: if let Some(tunnel) = meta_packet.tunnel {
                (tunnel.tunnel_type, tunnel.tier)
            } else {
                (TunnelType::default(), 0)
            },
            config_ignore,
            lookup_key_enabled: (lookup_key.l2_end_0, lookup_key.l2_end_1),
            trident_type,
        }
    }

    fn is_hyper_v(&self) -> bool {
        self.trident_type == TridentType::TtHyperVCompute
            || self.trident_type == TridentType::TtHyperVNetwork
    }

    // 微软ACS：
    //   HyperVNetwork网关宿主机和HyperVCompute网关流量模型中，MAC地址不对称
    //   在浦发环境中，IP地址不存在相同的场景，所以流聚合可直接忽略MAC地址
    //   但注意：若K8s部署正在HyperV中流量为双层隧道，内部流量为K8s虚拟机的存在相同IP，流聚合不能忽略MAC
    // 腾讯TCE：
    //   GRE隧道流量中的mac地址为伪造，流聚合忽略MAC地址
    // IPIP隧道：
    //   在IPIP隧道封装场景下，外层MAC在腾讯TCE环境中存在不对称情况
    //   实际上IPIP没有隧道ID，因此可以肯定不存在IP冲突，忽略MAC也是合理的
    // TODO: maybe should consider L2End0 and L2End1 when InPort == 0x30000
    fn mac_match(&self, other: &Self) -> MatchMac {
        let ignore_mac = (self.is_hyper_v() && other.tunnel_info.1 < 2)
            || other.tunnel_info.0 == TunnelType::TencentGre
            || other.tunnel_info.0 == TunnelType::Ipip;

        let o_flow_key = &other.flow_key;
        let is_from_isp = o_flow_key.tap_type != TapType::Tor;
        if is_from_isp || ignore_mac || self.config_ignore.1 {
            return MatchMac::None;
        }

        let is_from_trident =
            o_flow_key.tap_type == TapType::Tor && o_flow_key.tap_port.split_fields().0 > 0;

        if !self.config_ignore.0 && is_from_trident {
            if !other.lookup_key_enabled.0 && !other.lookup_key_enabled.1 {
                return MatchMac::None;
            } else if !other.lookup_key_enabled.0 {
                return MatchMac::Dst;
            } else {
                return MatchMac::Src;
            }
        }
        MatchMac::All
    }

    fn mac_match_with_direction(
        &self,
        other: &Self,
        match_mac: MatchMac,
        direction: PacketDirection,
    ) -> bool {
        let (src_mac, dst_mac) = match direction {
            PacketDirection::ClientToServer => (self.flow_key.mac_src, self.flow_key.mac_dst),
            PacketDirection::ServerToClient => (self.flow_key.mac_dst, self.flow_key.mac_src),
        };

        match match_mac {
            MatchMac::Dst => dst_mac == other.flow_key.mac_dst,
            MatchMac::Src => src_mac == other.flow_key.mac_src,
            MatchMac::All => dst_mac == other.flow_key.mac_dst && src_mac == other.flow_key.mac_src,
            _ => true,
        }
    }

    fn endpoint_match_with_direction(&self, other: &Self, direction: PacketDirection) -> bool {
        if other.tunnel_info.0 == TunnelType::None {
            return true;
        }
        // 同一个TapPort上的流量，如果有隧道的话，当Port做发卡弯转发时，进出的内层流量完全一样
        // 此时需要额外比较L2End确定哪股是进入的哪股是出去的
        match direction {
            PacketDirection::ClientToServer => {
                other.lookup_key_enabled.0 == self.lookup_key_enabled.0
                    && other.lookup_key_enabled.1 == self.lookup_key_enabled.1
            }
            PacketDirection::ServerToClient => {
                other.lookup_key_enabled.0 == self.lookup_key_enabled.1
                    && other.lookup_key_enabled.1 == self.lookup_key_enabled.0
            }
        }
    }
}

impl PartialEq for FlowMapKey {
    fn eq(&self, other: &Self) -> bool {
        let flow_key = &self.flow_key;
        let o_flow_key = &other.flow_key;
        if self.eth_type.ne(&other.eth_type)
            || flow_key.tap_port.ne(&o_flow_key.tap_port)
            || flow_key.tap_type.ne(&o_flow_key.tap_type)
        {
            return false;
        }
        // other ethernet type
        if other.eth_type != EthernetType::Ipv4 && other.eth_type != EthernetType::Ipv6 {
            // direction = ClientToServer
            let eq = flow_key.mac_src.eq(&o_flow_key.mac_src)
                    && flow_key.mac_dst.eq(&o_flow_key.mac_dst)
                    && flow_key.ip_src.eq(&o_flow_key.ip_src)
                    && flow_key.ip_dst.eq(&o_flow_key.ip_dst)
                // direction = ServerToClient
                    || flow_key.mac_src.eq(&o_flow_key.mac_dst)
                        && flow_key.mac_dst.eq(&o_flow_key.mac_src)
                        && flow_key.ip_src.eq(&o_flow_key.ip_dst)
                        && flow_key.ip_dst.eq(&o_flow_key.ip_src);

            return eq;
        }

        if flow_key.proto.ne(&o_flow_key.proto) {
            return false;
        }

        if self.tunnel_info.0.ne(&other.tunnel_info.0) || self.tunnel_info.0.ne(&TunnelType::None) {
            // 微软ACS存在非对称隧道流量，需要排除
            if !self.is_hyper_v() {
                return false;
            }
        }

        // Ipv4/Ipv6 solve
        let mac_match = self.mac_match(other);
        if flow_key.ip_src == o_flow_key.ip_src
            && flow_key.ip_dst == o_flow_key.ip_dst
            && flow_key.port_src == o_flow_key.port_src
            && flow_key.port_dst == o_flow_key.port_dst
        {
            // direction = ClientToServer
            self.endpoint_match_with_direction(other, PacketDirection::ClientToServer)
                && self.mac_match_with_direction(other, mac_match, PacketDirection::ClientToServer)
        } else if flow_key.ip_src == o_flow_key.ip_dst
            && flow_key.ip_dst == o_flow_key.ip_src
            && flow_key.port_src == o_flow_key.port_dst
            && flow_key.port_dst == o_flow_key.port_src
        {
            // direction = ServerToClient
            self.endpoint_match_with_direction(other, PacketDirection::ServerToClient)
                && self.mac_match_with_direction(other, mac_match, PacketDirection::ServerToClient)
        } else {
            false
        }
    }
}

impl Eq for FlowMapKey {}

impl FlowMapKey {
    fn l3_hash(flow_key: &FlowKey) -> Option<u64> {
        let (src, dst) = match (flow_key.ip_src, flow_key.ip_dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => (
                u32::from_le_bytes(s.octets()),
                u32::from_le_bytes(d.octets()),
            ),
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                let (src, dst) = (s.octets(), d.octets());
                src.chunks(4)
                    .zip(dst.chunks(4))
                    .fold((0, 0), |(hash1, hash2), (b1, b2)| {
                        (
                            hash1 ^ u32::from_le_bytes(*<&[u8; 4]>::try_from(b1).unwrap()),
                            hash2 ^ u32::from_le_bytes(*<&[u8; 4]>::try_from(b2).unwrap()),
                        )
                    })
            }
            (_, _) => {
                return None;
            }
        };

        if src >= dst {
            Some((src as u64) << 32 | dst as u64)
        } else {
            Some((dst as u64) << 32 | src as u64)
        }
    }

    fn l4_hash(flow_key: &FlowKey) -> u64 {
        if flow_key.port_src >= flow_key.port_dst {
            (flow_key.port_src as u64) << 16 | flow_key.port_dst as u64
        } else {
            (flow_key.port_dst as u64) << 16 | flow_key.port_src as u64
        }
    }
}

impl Hash for FlowMapKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let flow_key = &self.flow_key;
        match self.eth_type {
            EthernetType::Ipv4 | EthernetType::Ipv6 => {
                if let Some(lhs) = Self::l3_hash(flow_key) {
                    let rhs = ((u16::from(flow_key.tap_type) as u64) << 24 | flow_key.tap_port.0)
                        << 32
                        | Self::l4_hash(flow_key);
                    lhs.hash(state);
                    rhs.hash(state);
                }
            }
            EthernetType::Arp => {
                if let Some(lhs) = Self::l3_hash(flow_key) {
                    let rhs = ((u16::from(flow_key.tap_type) as u64) << 24 | flow_key.tap_port.0)
                        << 32
                        | (u64::from(flow_key.mac_src) ^ u64::from(flow_key.mac_dst));
                    lhs.hash(state);
                    rhs.hash(state);
                }
            }
            _ => {
                let lhs = (u16::from(flow_key.tap_type) as u64) << 24 | flow_key.tap_port.0;
                let rhs = u64::from(flow_key.mac_src) ^ u64::from(flow_key.mac_dst);
                lhs.hash(state);
                rhs.hash(state);
            }
        }
    }
}

pub struct FlowNode {
    pub tagged_flow: TaggedFlow,
    pub min_arrived_time: Duration,
    pub recent_time: Duration, // 最近一个Packet的时间戳
    pub timeout: Duration,     // 相对超时时间
    pub flow_state: FlowState,
    pub meta_flow_perf: Option<FlowPerf>,

    pub policy_data_cache: [PolicyData; 2],
    pub endpoint_data_cache: EndpointData,

    pub next_tcp_seq0: u32,
    pub next_tcp_seq1: u32,
    pub policy_in_tick: [bool; 2], // 当前统计周期（目前是自然秒）是否更新策略
    pub packet_in_tick: bool,      // 当前统计周期（目前是自然秒）是否有包
}

impl FlowNode {
    fn reset_flow_stat_info(&mut self) {
        self.policy_in_tick = [false; 2];
        self.packet_in_tick = false;
        let flow = &mut self.tagged_flow.flow;
        flow.flow_start_time = Duration::ZERO;
        flow.is_new_flow = false;
        let flow_metrics_peer_src = &mut flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC];
        flow_metrics_peer_src.packet_count = 0;
        flow_metrics_peer_src.byte_count = 0;
        flow_metrics_peer_src.l3_byte_count = 0;
        flow_metrics_peer_src.l4_byte_count = 0;

        let flow_metrics_peer_dst = &mut flow.flow_metrics_peers[FLOW_METRICS_PEER_DST];
        flow_metrics_peer_dst.packet_count = 0;
        flow_metrics_peer_dst.byte_count = 0;
        flow_metrics_peer_dst.l3_byte_count = 0;
        flow_metrics_peer_dst.l4_byte_count = 0;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::mem;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use super::*;
    use crate::common::{enums::TapType, tap_port::TapPort};
    use crate::utils::hasher::Jenkins64Hasher;
    use crate::utils::net::MacAddr;

    // tap_type = TapType::ISP(7), tap_port = 2100, src_mac = B0-60-88-51-D7-54 dst_mac = 00-15-5D-70-01-03
    // src_ipv4addr = 192.168.66.1 dst_ipv4addr = 192.168.66.2 src_port = 19001, dst_port = 19002
    // src_ipv6addr =  fe80::88d3:f197:5843:f873 dst_ipv6addr = fe80::742a:d20d:8d45:56e6
    fn new_map_key(eth_type: EthernetType, src_addr: IpAddr, dst_addr: IpAddr) -> FlowMapKey {
        FlowMapKey {
            current_time_in_unit: 0,
            flow_key: FlowKey {
                tap_type: TapType::Isp(7),
                tap_port: TapPort(2100),
                mac_src: MacAddr::from([0xb0, 0x60, 0x88, 0x51, 0xd7, 0x54]),
                mac_dst: MacAddr::from([0x00, 0x15, 0x5d, 0x70, 0x01, 0x03]),
                ip_src: src_addr,
                ip_dst: dst_addr,
                port_src: 19001,
                port_dst: 19002,
                ..Default::default()
            },
            eth_type,
            tunnel_info: (TunnelType::default(), 0),
            config_ignore: (false, false),
            lookup_key_enabled: (false, false),
            trident_type: TridentType::TtHostPod,
        }
    }

    #[test]
    fn flow_map_key_server_to_client_eq() {
        let key1 = new_map_key(
            EthernetType::Ipv4,
            Ipv4Addr::new(192, 168, 66, 1).into(),
            Ipv4Addr::new(192, 168, 66, 2).into(),
        );
        let mut key2 = new_map_key(
            EthernetType::Ipv4,
            Ipv4Addr::new(192, 168, 66, 2).into(),
            Ipv4Addr::new(192, 168, 66, 1).into(),
        );
        let flow_key = &mut key2.flow_key;
        mem::swap(&mut flow_key.mac_dst, &mut flow_key.mac_src);
        mem::swap(&mut flow_key.port_dst, &mut flow_key.port_src);
        assert_eq!(key1, key2);
    }

    #[test]
    fn flow_map_key_other_eth_eq() {
        let key1 = new_map_key(
            EthernetType::Arp,
            Ipv4Addr::new(192, 168, 66, 1).into(),
            Ipv4Addr::new(192, 168, 66, 2).into(),
        );
        let mut key2 = new_map_key(
            EthernetType::Arp,
            Ipv4Addr::new(192, 168, 66, 2).into(),
            Ipv4Addr::new(192, 168, 66, 1).into(),
        );
        let flow_key = &mut key2.flow_key;
        mem::swap(&mut flow_key.mac_dst, &mut flow_key.mac_src);
        assert_eq!(key1, key2);
    }

    #[test]
    fn ipv4_node_hash() {
        let mut hasher = Jenkins64Hasher::default();
        let key = new_map_key(
            EthernetType::Ipv4,
            Ipv4Addr::new(192, 168, 66, 1).into(),
            Ipv4Addr::new(192, 168, 66, 2).into(),
        );
        let flow_key = &key.flow_key;
        // 右边是go 版本计算得出
        assert_eq!(FlowMapKey::l3_hash(flow_key), Some(0x242a8c00142a8c0));
        assert_eq!(FlowMapKey::l4_hash(flow_key), 0x4a3a4a39);
        key.hash(&mut hasher);
        assert_eq!(hasher.finish(), 0xecb912dddb15b140);
    }

    #[test]
    fn ipv6_node_hash() {
        let mut hasher = Jenkins64Hasher::default();
        let key = new_map_key(
            EthernetType::Ipv6,
            Ipv6Addr::from_str("fe80::88d3:f197:5843:f873")
                .unwrap()
                .into(),
            Ipv6Addr::from_str("fe80::742a:d20d:8d45:56e6")
                .unwrap()
                .into(),
        );
        let flow_key = &key.flow_key;
        // 右边是go 版本计算得出
        assert_eq!(FlowMapKey::l3_hash(flow_key), Some(0xeb84ef07e409102e));
        assert_eq!(FlowMapKey::l4_hash(flow_key), 0x4a3a4a39);
        key.hash(&mut hasher);
        assert_eq!(hasher.finish(), 0xe7f0aea2897fd9ad);
    }

    #[test]
    fn arp_node_hash() {
        let mut hasher = Jenkins64Hasher::default();
        let key = new_map_key(
            EthernetType::Arp,
            Ipv6Addr::from_str("fe80::88d3:f197:5843:f873")
                .unwrap()
                .into(),
            Ipv6Addr::from_str("fe80::742a:d20d:8d45:56e6")
                .unwrap()
                .into(),
        );
        // 右边是go 版本计算得出
        key.hash(&mut hasher);
        assert_eq!(hasher.finish(), 1098954493523811076);
    }

    #[test]
    fn other_node_hash() {
        let mut hasher = Jenkins64Hasher::default();
        let key = new_map_key(
            EthernetType::Dot1Q,
            Ipv6Addr::from_str("fe80::88d3:f197:5843:f873")
                .unwrap()
                .into(),
            Ipv6Addr::from_str("fe80::742a:d20d:8d45:56e6")
                .unwrap()
                .into(),
        );
        // 右边是go 版本计算得出
        key.hash(&mut hasher);
        assert_eq!(hasher.finish(), 4948968142922745785);
    }

    #[test]
    fn node_insert() {
        let hasher = Jenkins64Hasher::default();
        let mut set = HashSet::with_hasher(hasher);
        let key = new_map_key(
            EthernetType::Ipv4,
            Ipv4Addr::new(192, 168, 66, 1).into(),
            Ipv4Addr::new(192, 168, 66, 2).into(),
        );
        assert!(set.insert(key));
        let key = new_map_key(
            EthernetType::Ipv4,
            Ipv4Addr::new(192, 168, 66, 1).into(),
            Ipv4Addr::new(192, 168, 66, 2).into(),
        );
        assert!(!set.insert(key));
    }
}
