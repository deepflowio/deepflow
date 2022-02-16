use std::sync::Arc;
use std::time::Duration;

use super::{
    consts::*, EndpointData, FlowMetricsPeer, HeaderType, LookupKey, PolicyData, TapPort,
    TunnelInfo,
};

#[derive(Default)]
pub struct MetaPacket {
    // 主机序, 不因L2End1而颠倒, 端口会在查询策略时被修改
    pub lookup_key: LookupKey,

    pub raw: Option<Arc<Vec<u8>>>,
    pub packet_len: usize,
    vlan_tag_size: usize,
    pub ttl: u8,
    pub reset_ttl: bool,
    pub endpoint_data: Option<EndpointData>,
    pub policy_data: Option<PolicyData>,

    offset_ip_0: usize,
    offset_ip_1: usize,
    offset_mac_0: usize,
    offset_mac_1: usize,
    offset_port_0: usize,
    offset_port_1: usize,
    offset_ipv6_last_option: usize,
    offset_ipv6_fragment_option: usize,

    pub header_type: HeaderType,
    // 读取时不要直接用这个字段，用MetaPacket.GetPktSize()
    // 注意：不含镜像外层VLAN的四个字节
    l2_l3_opt_size: usize, // 802.1Q + IPv4 optional fields
    l4_opt_size: usize,    // ICMP payload / TCP optional fields
    l3_payload_len: usize,
    l4_payload_len: usize,
    npb_ignore_l4: bool, // 对于IP分片或IP Options不全的情况，分发时不对l4进行解析
    nd_reply_or_arp_request: bool, // NDP request or ARP request

    tunnel: Option<Arc<TunnelInfo>>,

    data_offset_ihl_or_fl4b: u8,
    next_header: u8, // ipv6 header中的nextHeader字段，用于包头压缩等

    tcp_options_flag: u8,
    tcp_opt_win_scale_offset: usize,
    tcp_opt_mss_offset: usize,
    tcp_opt_sack_offset: usize,

    pub tcp_data: Option<MetaPacketTcpHeader>,
    pub tap_port: Option<TapPort>, // packet与xflow复用
    pub payload_len: u16,
    pub vlan: u16,
    pub direction: PacketDirection,
    pub is_active_service: bool,
    pub queue_hash: u8,

    // for xflow
    pub packet_count: u64,
    pub packet_bytes: u64,
    pub start_time: Duration,
    pub end_time: Duration,
    pub source_ip: u32,
}

impl MetaPacket {
    pub fn empty() -> MetaPacket {
        MetaPacket {
            offset_mac_0: FIELD_OFFSET_SA,
            offset_mac_1: FIELD_OFFSET_DA,
            offset_ip_0: FIELD_OFFSET_SIP,
            offset_ip_1: FIELD_OFFSET_DIP,
            offset_port_0: FIELD_OFFSET_SPORT,
            offset_port_1: FIELD_OFFSET_DPORT,
            ..Default::default()
        }
    }
}

pub struct MetaPacketTcpHeader {
    pub seq: u32,
    pub ack: u32,
    pub win_size: u16,
    pub mss: u16,
    pub flags: u8,
    pub data_offset: u8,
    pub win_scale: u8,
    pub sack_permitted: bool,
    pub sack: Vec<u8>, // sack value
}

#[repr(u8)]
pub enum PacketDirection {
    ClientToServer = FlowMetricsPeer::SRC,
    ServerToClient = FlowMetricsPeer::DST,
}

impl Default for PacketDirection {
    fn default() -> PacketDirection {
        PacketDirection::ClientToServer
    }
}
