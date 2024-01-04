/*
 * Copyright (c) 2024 Yunshan Networks
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

use std::{net::IpAddr, sync::Arc};

use super::{perf::FlowLog, FlowState, FLOW_METRICS_PEER_DST, FLOW_METRICS_PEER_SRC};
use crate::common::{
    decapsulate::TunnelType,
    endpoint::EndpointDataPov,
    enums::{EthernetType, TapType, TcpFlags},
    flow::{FlowMetricsPeer, L7PerfStats, PacketDirection, SignalSource, TcpPerfStats},
    lookup_key::LookupKey,
    meta_packet::MetaPacket,
    tagged_flow::TaggedFlow,
    TapPort, Timestamp,
};
use public::{proto::common::TridentType, utils::net::MacAddr};

use npb_pcap_policy::PolicyData;
use packet_sequence_block::PacketSequenceBlock;

#[repr(u8)]
enum MatchMac {
    None,
    Dst,
    Src,
    All,
}

/*
    FlowMapKey是流节点映射表的唯一标识,由Jenkins64算法哈希得到，因为FlowMap处理复杂网络环境，
    所以有可能key对应多个流节点的情况，需要根据流节点的match_node方法在映射表唯一标识一条流。
*/
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy, Default)]
pub(super) struct FlowMapKey {
    lhs: u64,
    rhs: u64,
}

impl FlowMapKey {
    fn l3_hash(lookup_key: &LookupKey) -> u64 {
        let (src, dst) = match (lookup_key.src_ip, lookup_key.dst_ip) {
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
            _ => unreachable!(),
        };

        if src >= dst {
            (src as u64) << 32 | dst as u64
        } else {
            (dst as u64) << 32 | src as u64
        }
    }

    fn l4_hash(lookup_key: &LookupKey) -> u64 {
        if lookup_key.src_port >= lookup_key.dst_port {
            (lookup_key.src_port as u64) << 16 | lookup_key.dst_port as u64
        } else {
            (lookup_key.dst_port as u64) << 16 | lookup_key.src_port as u64
        }
    }

    pub(super) fn new(lookup_key: &LookupKey, tap_port: TapPort) -> Self {
        match lookup_key.eth_type {
            EthernetType::IPV4 | EthernetType::IPV6 => {
                let lhs = Self::l3_hash(lookup_key);
                let rhs = ((u16::from(lookup_key.tap_type) as u64) << 24
                    | tap_port.ignore_nat_source())
                    << 32
                    | Self::l4_hash(lookup_key);
                Self { lhs, rhs }
            }
            EthernetType::ARP => {
                let lhs = Self::l3_hash(lookup_key);
                let rhs = ((u16::from(lookup_key.tap_type) as u64) << 24
                    | tap_port.ignore_nat_source())
                    << 32
                    | (u64::from(lookup_key.src_mac) ^ u64::from(lookup_key.dst_mac));
                Self { lhs, rhs }
            }
            _ => {
                let lhs =
                    (u16::from(lookup_key.tap_type) as u64) << 24 | tap_port.ignore_nat_source();
                let rhs = u64::from(lookup_key.src_mac) ^ u64::from(lookup_key.dst_mac);
                Self { lhs, rhs }
            }
        }
    }
}

#[derive(Default)]
pub struct FlowNode {
    pub tagged_flow: TaggedFlow,
    pub min_arrived_time: Timestamp,
    // 最近一个Packet的时间戳
    pub recent_time: Timestamp,
    // 相对超时时间
    pub timeout: Timestamp,
    // 用作time_set比对的标识，等于FlowTimeKey的timestamp_key, 只有创建FlowNode和刷新更新流节点的超时才会更新
    pub timestamp_key: u64,

    pub meta_flow_log: Option<Box<FlowLog>>,
    pub policy_data_cache: [Option<Arc<PolicyData>>; 2],
    pub endpoint_data_cache: Option<EndpointDataPov>,

    // Only for eBPF TCP Flow, used to help confirm whether the Flow can be timed out.
    pub residual_request: i32,
    pub next_tcp_seq0: u32,
    pub next_tcp_seq1: u32,
    // 当前统计周期（目前是自然秒）是否更新策略
    pub policy_in_tick: [bool; 2],
    pub packet_in_tick: bool, // 当前统计周期（目前是自然秒）是否有包
    pub flow_state: FlowState,

    // Enterprise Edition Feature: packet-sequence
    pub packet_sequence_block: Option<Box<PacketSequenceBlock>>,
}

impl FlowNode {
    pub(super) fn reset_flow_stat_info(&mut self) {
        self.policy_in_tick = [false; 2];
        self.packet_in_tick = false;
        let flow = &mut self.tagged_flow.flow;
        flow.flow_stat_time = Default::default();
        flow.is_new_flow = false;
        let flow_metrics_peer_src = &mut flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC];
        flow_metrics_peer_src.packet_count = 0;
        flow_metrics_peer_src.byte_count = 0;
        flow_metrics_peer_src.l3_byte_count = 0;
        flow_metrics_peer_src.l4_byte_count = 0;
        flow_metrics_peer_src.tcp_flags = TcpFlags::empty();

        let flow_metrics_peer_dst = &mut flow.flow_metrics_peers[FLOW_METRICS_PEER_DST];
        flow_metrics_peer_dst.packet_count = 0;
        flow_metrics_peer_dst.byte_count = 0;
        flow_metrics_peer_dst.l3_byte_count = 0;
        flow_metrics_peer_dst.l4_byte_count = 0;
        flow_metrics_peer_dst.tcp_flags = TcpFlags::empty();

        if let Some(ref mut flow_perf_stats) = &mut flow.flow_perf_stats {
            flow_perf_stats.tcp = TcpPerfStats::default();
            flow_perf_stats.l7 = L7PerfStats::default();
        }
    }

    // reset l7 parser and l7 perf stats on plugin reload to avoid inconsistency
    pub fn reset_on_plugin_reload(&mut self) {
        if let Some(stats) = self.tagged_flow.flow.flow_perf_stats.as_mut() {
            stats.reset_on_plugin_reload();
        }
        if let Some(flow_log) = self.meta_flow_log.as_mut() {
            flow_log.reset_on_plugin_reload();
        }
    }

    pub fn match_node(
        &self,
        meta_packet: &mut MetaPacket,
        ignore_l2_end: bool,
        ignore_tor_mac: bool,
        ignore_idc_vlan: bool,
        trident_type: TridentType,
    ) -> bool {
        if meta_packet.signal_source == SignalSource::EBPF {
            if self.tagged_flow.flow.flow_id != meta_packet.socket_id {
                return false;
            }

            // After matching to the node, the packet needs to obtain the direction based on the IP and port
            if self.tagged_flow.flow.flow_key.ip_src == meta_packet.lookup_key.src_ip
                && self.tagged_flow.flow.flow_key.port_src == meta_packet.lookup_key.src_port
            {
                meta_packet.lookup_key.direction = PacketDirection::ClientToServer;
            } else {
                meta_packet.lookup_key.direction = PacketDirection::ServerToClient;
            }

            return true;
        }

        let flow = &self.tagged_flow.flow;
        let flow_key = &flow.flow_key;
        let meta_lookup_key = &meta_packet.lookup_key;
        if flow_key.tap_port.ignore_nat_source() != meta_packet.tap_port.ignore_nat_source()
            || flow_key.tap_type != meta_lookup_key.tap_type
        {
            return false;
        }

        if flow.eth_type != meta_lookup_key.eth_type {
            return false;
        }

        if flow.vlan != meta_packet.vlan
            && meta_lookup_key.tap_type != TapType::Cloud
            && !ignore_idc_vlan
        {
            return false;
        }

        // other ethernet type
        if flow.eth_type != EthernetType::IPV4 && meta_lookup_key.eth_type != EthernetType::IPV6 {
            // direction = ClientToServer
            if flow_key.mac_src == meta_lookup_key.src_mac
                && flow_key.mac_dst == meta_lookup_key.dst_mac
                && flow_key.ip_src == meta_lookup_key.src_ip
                && flow_key.ip_dst == meta_lookup_key.dst_ip
            {
                meta_packet.lookup_key.direction = PacketDirection::ClientToServer;
                return true;
            }
            // direction = ServerToClient
            if flow_key.mac_src == meta_lookup_key.dst_mac
                && flow_key.mac_dst == meta_lookup_key.src_mac
                && flow_key.ip_src == meta_lookup_key.dst_ip
                && flow_key.ip_dst == meta_lookup_key.src_ip
            {
                meta_packet.lookup_key.direction = PacketDirection::ServerToClient;
                return true;
            }

            return false;
        }

        if flow_key.proto != meta_lookup_key.proto {
            return false;
        }

        if (meta_packet.tunnel.is_some()
            && flow.tunnel.tunnel_type != meta_packet.tunnel.unwrap().tunnel_type)
            || (meta_packet.tunnel.is_none() && flow.tunnel.tunnel_type != TunnelType::None)
        {
            // 微软ACS存在非对称隧道流量，需要排除
            if !Self::is_hyper_v(trident_type) {
                return false;
            }
        }

        // Ipv4/Ipv6 solve
        let mac_match = Self::mac_match(meta_packet, ignore_l2_end, ignore_tor_mac, trident_type);
        if flow_key.ip_src == meta_lookup_key.src_ip
            && flow_key.ip_dst == meta_lookup_key.dst_ip
            && flow_key.port_src == meta_lookup_key.src_port
            && flow_key.port_dst == meta_lookup_key.dst_port
        {
            // l3 protocols, such as icmp, can determine the direction of packets according
            // to icmp type, so there is no need to correct the direction of packets
            if meta_lookup_key.is_tcp() || meta_lookup_key.is_udp() {
                meta_packet.lookup_key.direction = PacketDirection::ClientToServer;
            }
        } else if flow_key.ip_src == meta_lookup_key.dst_ip
            && flow_key.ip_dst == meta_lookup_key.src_ip
            && flow_key.port_src == meta_lookup_key.dst_port
            && flow_key.port_dst == meta_lookup_key.src_port
        {
            if meta_lookup_key.is_tcp() || meta_lookup_key.is_udp() {
                meta_packet.lookup_key.direction = PacketDirection::ServerToClient;
            }
        } else {
            return false;
        }
        Self::endpoint_match_with_direction(&flow.flow_metrics_peers, meta_packet)
            && Self::mac_match_with_direction(
                meta_packet,
                flow_key.mac_src,
                flow_key.mac_dst,
                mac_match,
            )
    }

    fn is_hyper_v(trident_type: TridentType) -> bool {
        trident_type == TridentType::TtHyperVCompute || trident_type == TridentType::TtHyperVNetwork
    }

    // Microsoft ACS：
    //   HyperVNetwork网关宿主机和HyperVCompute网关流量模型中，MAC地址不对称
    //   在部分微软ACS环境中，IP地址不存在相同的场景，所以流聚合可直接忽略MAC地址
    //   但注意：若K8s部署正在HyperV中流量为双层隧道，内部流量为K8s虚拟机的存在相同IP，流聚合不能忽略MAC
    // Tencent TCE：
    //   GRE隧道流量中的mac地址为伪造，流聚合忽略MAC地址
    // IPIP Tunnel：
    //   在IPIP隧道封装场景下，外层MAC在腾讯TCE环境中存在不对称情况
    //   实际上IPIP没有隧道ID，因此可以肯定不存在IP冲突，忽略MAC也是合理的
    fn mac_match(
        meta_packet: &MetaPacket,
        ignore_l2_end: bool,
        ignore_tor_mac: bool,
        trident_type: TridentType,
    ) -> MatchMac {
        let ignore_mac = meta_packet.tunnel.is_some()
            && ((Self::is_hyper_v(trident_type) && meta_packet.tunnel.unwrap().tier < 2)
                || meta_packet.tunnel.unwrap().tunnel_type == TunnelType::TencentGre
                || meta_packet.tunnel.unwrap().tunnel_type == TunnelType::Ipip);

        // return value stands different match type, defined by MAC_MATCH_*
        // TODO: maybe should consider L2End0 and L2End1 when InPort == 0x30000
        let is_from_isp = meta_packet.lookup_key.tap_type != TapType::Cloud;
        if is_from_isp || ignore_mac || (meta_packet.tunnel.is_none() && ignore_tor_mac) {
            return MatchMac::None;
        }

        let is_from_trident = meta_packet.lookup_key.tap_type == TapType::Cloud
            && meta_packet.tap_port.split_fields().0 > 0;

        if !ignore_l2_end && is_from_trident {
            if !meta_packet.lookup_key.l2_end_0 && !meta_packet.lookup_key.l2_end_1 {
                return MatchMac::None;
            } else if !meta_packet.lookup_key.l2_end_0 {
                return MatchMac::Dst;
            } else {
                return MatchMac::Src;
            }
        }
        MatchMac::All
    }

    fn mac_match_with_direction(
        meta_packet: &MetaPacket,
        flow_mac_src: MacAddr,
        flow_mac_dst: MacAddr,
        match_mac: MatchMac,
    ) -> bool {
        let (src_mac, dst_mac) = match meta_packet.lookup_key.direction {
            PacketDirection::ClientToServer => (flow_mac_src, flow_mac_dst),
            PacketDirection::ServerToClient => (flow_mac_dst, flow_mac_src),
        };

        match match_mac {
            MatchMac::Dst => dst_mac == meta_packet.lookup_key.dst_mac,
            MatchMac::Src => src_mac == meta_packet.lookup_key.src_mac,
            MatchMac::All => {
                dst_mac == meta_packet.lookup_key.dst_mac
                    && src_mac == meta_packet.lookup_key.src_mac
            }
            MatchMac::None => true,
        }
    }

    fn endpoint_match_with_direction(
        peers: &[FlowMetricsPeer; 2],
        meta_packet: &MetaPacket,
    ) -> bool {
        if meta_packet.tunnel.is_none() {
            return true;
        }

        // 同一个TapPort上的流量，如果有隧道的话，当Port做发卡弯转发时，进出的内层流量完全一样
        // 此时需要额外比较L2End确定哪股是进入的哪股是出去的
        let lookup_key = &meta_packet.lookup_key;
        match meta_packet.lookup_key.direction {
            PacketDirection::ClientToServer => {
                lookup_key.l2_end_0 == peers[0].is_l2_end
                    && lookup_key.l2_end_1 == peers[1].is_l2_end
            }
            PacketDirection::ServerToClient => {
                lookup_key.l2_end_0 == peers[1].is_l2_end
                    && lookup_key.l2_end_1 == peers[0].is_l2_end
            }
        }
    }
}
