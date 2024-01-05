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

use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub const PROCESS_NAME: &str = "deepflow-agent";
#[cfg(target_os = "windows")]
pub const PROCESS_NAME: &str = "deepflow-agent.exe";

pub const DEFAULT_INGESTER_PORT: u16 = 30033;
pub const DEFAULT_CONTROLLER_PORT: u16 = 30035;
pub const DEFAULT_CONTROLLER_TLS_PORT: u16 = 30135;

pub const NORMAL_EXIT_WITH_RESTART: i32 = 3;
pub const TRIDENT_MEMORY_LIMIT: u64 = 0;
pub const TRIDENT_PROCESS_LIMIT: u32 = 10;
pub const TRIDENT_THREAD_LIMIT: u32 = 100;
pub const FREE_SPACE_REQUIREMENT: u64 = 100 << 20;
pub const DEFAULT_MAX_CPUS: u32 = 1; // cpu限制默认值
pub const DEFAULT_CPU_CFS_PERIOD_US: u32 = 100000; // cfs_period_us默认值

pub const DEFAULT_LOG_RETENTION: u32 = 365;
pub const DEFAULT_LOG_FILE_SIZE_LIMIT: u32 = 10000; // 单位：M
pub const CGROUP_PROCS_PATH: &'static str = "cpu/deepflow-agent/cgroup.procs";
pub const CGROUP_TASKS_PATH: &'static str = "cpu/deepflow-agent/tasks";
pub const CGROUP_V2_PROCS_PATH: &'static str = "deepflow-agent/cgroup.procs";
pub const CGROUP_V2_THREADS_PATH: &'static str = "deepflow-agent/cgroup.threads";

#[cfg(target_os = "linux")]
mod platform_consts {
    pub const DEFAULT_LOG_FILE: &'static str = "/var/log/deepflow-agent/deepflow-agent.log";
    pub const DEFAULT_CONF_FILE: &'static str = "/etc/deepflow-agent.yaml";
    pub const DEFAULT_TRIDENT_CONF_FILE: &'static str = "/etc/trident.yaml";
    pub const COREFILE_FORMAT: &'static str = "core";
    pub const DEFAULT_COREFILE_PATH: &'static str = "/tmp";
    pub const DEFAULT_LIBVIRT_XML_PATH: &'static str = "/etc/libvirt/qemu";
}

/* TODO: fix constants for android */
#[cfg(target_os = "android")]
mod platform_consts {
    pub const DEFAULT_LOG_FILE: &'static str = "/var/log/deepflow-agent/deepflow-agent.log";
    pub const DEFAULT_CONF_FILE: &'static str = "/etc/deepflow-agent.yaml";
    pub const DEFAULT_TRIDENT_CONF_FILE: &'static str = "/etc/trident.yaml";
    pub const COREFILE_FORMAT: &'static str = "core";
    pub const DEFAULT_COREFILE_PATH: &'static str = "/tmp";
}

#[cfg(target_os = "windows")]
mod platform_consts {
    pub const DEFAULT_LOG_FILE: &'static str =
        "C:\\DeepFlow\\deepflow-agent\\log\\deepflow-agent.log";
    // NOTE yaml must be full path, otherwise service wouldn't start as you wish.
    pub const DEFAULT_CONF_FILE: &'static str =
        "C:\\DeepFlow\\deepflow-agent\\deepflow-agent-windows.yaml";
    pub const DEFAULT_TRIDENT_CONF_FILE: &'static str =
        "C:\\DeepFlow\\trident\\trident-windows.yaml";
    pub const DEFAULT_COREFILE_PATH: &'static str = "C:\\DeepFlow\\deepflow-agent";
    pub const COREFILE_FORMAT: &'static str = "dump";
}

pub use platform_consts::*;

pub const FIELD_OFFSET_DA: usize = 0;
pub const FIELD_OFFSET_SA: usize = 6;
pub const FIELD_OFFSET_VLANTAG: usize = 14;
// 在之后按需增加4B的DOT1Q偏移量
pub const FIELD_OFFSET_ETH_TYPE: usize = 12;
pub const FIELD_OFFSET_ARP: usize = 14;
pub const FIELD_OFFSET_PAYLOAD_LEN: usize = 18;
pub const FIELD_OFFSET_IPV6_SRC: usize = 22;
pub const FIELD_OFFSET_IPV6_DST: usize = 38;
pub const FIELD_OFFSET_IHL: usize = 14;
pub const FIELD_OFFSET_TOTAL_LEN: usize = 16;
pub const FIELD_OFFSET_ID: usize = 18;
pub const FIELD_OFFSET_FRAG: usize = 20;
pub const FIELD_OFFSET_TTL: usize = 22;
pub const FIELD_OFFSET_PROTO: usize = 23;
pub const FIELD_OFFSET_SIP: usize = 26;
pub const FIELD_OFFSET_DIP: usize = 30;
// 在之后按需增加(4+IHL*4-20)B的DOT1Q + IPv4 option偏移量;
pub const FIELD_OFFSET_ICMP_TYPE_CODE: usize = 34;
pub const FIELD_OFFSET_ICMP_ID_SEQ: usize = 38;
pub const FIELD_OFFSET_ICMP_REST: usize = 38;
pub const FIELD_OFFSET_SPORT: usize = 34;
pub const FIELD_OFFSET_DPORT: usize = 36;
pub const FIELD_OFFSET_IPV6_SPORT: usize = 54;
pub const FIELD_OFFSET_IPV6_DPORT: usize = 56;
pub const FIELD_OFFSET_TCP_SEQ: usize = 38;
pub const FIELD_OFFSET_TCPV6_SEQ: usize = 58;
pub const FIELD_OFFSET_TCP_ACK: usize = 42;
pub const FIELD_OFFSET_TCPV6_ACK: usize = 62;
pub const FIELD_OFFSET_TCP_DATAOFF: usize = 46;
pub const FIELD_OFFSET_TCPV6_DATAOFF: usize = 66;
pub const FIELD_OFFSET_TCP_FLAG: usize = 47;
pub const FIELD_OFFSET_TCPV6_FLAG: usize = 67;
pub const FIELD_OFFSET_TCP_WIN: usize = 48;
pub const FIELD_OFFSET_TCPV6_WIN: usize = 68;
pub const FIELD_OFFSET_VXLAN_FLAGS: usize = 42;
pub const FIELD_OFFSET_VXLAN_VNI: usize = 46;
pub const FIELD_OFFSET_GENEVE_VERSION: usize = 42;
pub const FIELD_OFFSET_GENEVE_PROTOCOL: usize = 44;
pub const FIELD_OFFSET_GENEVE_VNI: usize = 46;

pub const FIELD_LEN_DA: usize = 6;
pub const FIELD_LEN_SA: usize = 6;
pub const FIELD_LEN_VLANTAG: usize = 2;
pub const FIELD_LEN_ETH_TYPE: usize = 2;

pub const FIELD_LEN_ARP: usize = 28;

pub const FIELD_LEN_IP6_SRC: usize = 16;
pub const FIELD_LEN_IP6_DST: usize = 16;

pub const FIELD_LEN_IHL: usize = 1;
pub const FIELD_LEN_TOTAL_LEN: usize = 2;
pub const FIELD_LEN_ID: usize = 2;
pub const FIELD_LEN_FRAG: usize = 2;
pub const FIELD_LEN_TTL: usize = 1;
pub const FIELD_LEN_PROTO: usize = 1;
pub const FIELD_LEN_SIP: usize = 4;
pub const FIELD_LEN_DIP: usize = 4;

pub const FIELD_LEN_ICMP_TYPE_CODE: usize = 2;
pub const FIELD_LEN_ICMP_ID_SEQ: usize = 4;
pub const FIELD_LEN_ICMP_REST: usize = 28;

pub const FIELD_LEN_SPORT: usize = 2;
pub const FIELD_LEN_DPORT: usize = 2;

pub const FIELD_LEN_TCP_SEQ: usize = 4;
pub const FIELD_LEN_TCP_ACK: usize = 4;
pub const FIELD_LEN_TCP_DATAOFF: usize = 1;
pub const FIELD_LEN_TCP_FLAG: usize = 1;
pub const FIELD_LEN_TCP_WIN: usize = 2;

pub const FIELD_LEN_VXLAN_FLAGS: usize = 1;
pub const FIELD_LEN_VXLAN_VNI: usize = 3;

pub const MAC_ADDR_LEN: usize = 6;
pub const VLANTAG_LEN: usize = 2;
pub const HEADER_TYPE_LEN: usize = 1;
pub const EPC_ID_LEN: usize = 2;
pub const PORT_LEN: usize = 2;
pub const GRE_PROTO_LEN: usize = 2;
pub const IPV4_ADDR_LEN: usize = 4;
pub const IPV6_ADDR_LEN: usize = 16;
pub const ETH_TYPE_LEN: usize = 2;
pub const IPV4_TTL_LEN: usize = 1;
pub const IPV4_PROTO_LEN: usize = 1;
pub const IPV4_FLAGS_FRAG_OFFSET_LEN: usize = 2;
pub const TCP_WIN_LEN: usize = 2;
pub const IPV6_FRAGMENT_LEN: usize = 8;
pub const IPV6_PROTO_LEN: usize = 1;

pub const ETH_HEADER_SIZE: usize = MAC_ADDR_LEN * 2 + ETH_TYPE_LEN;
pub const VLAN_HEADER_SIZE: usize = 4;
pub const ARP_HEADER_SIZE: usize = 28;
pub const IPV4_HEADER_SIZE: usize = 20;
pub const IPV6_HEADER_SIZE: usize = 40;
pub const UDP_HEADER_SIZE: usize = 8;
pub const VXLAN_HEADER_SIZE: usize = 8;
pub const GRE_HEADER_SIZE: usize = 12;
pub const ERSPAN_HEADER_SIZE: usize = 12;
pub const ERSPAN_I_HEADER_SIZE: usize = 0;
pub const ERSPAN_II_HEADER_SIZE: usize = 8;
pub const ERSPAN_III_HEADER_SIZE: usize = 12;
pub const ERSPAN_III_SUBHEADER_SIZE: usize = 8;
pub const GENEVE_HEADER_SIZE: usize = 8;
pub const TCP_HEADER_SIZE: usize = 20;

// min packet size
pub const IPV4_PACKET_SIZE: usize = ETH_HEADER_SIZE + IPV4_HEADER_SIZE; // 34
pub const UDP_PACKET_SIZE: usize = IPV4_PACKET_SIZE + UDP_HEADER_SIZE; // 42
pub const VXLAN_PACKET_SIZE: usize = UDP_PACKET_SIZE + VXLAN_HEADER_SIZE; // 50
pub const GRE_PACKET_SIZE: usize = IPV4_PACKET_SIZE + GRE_HEADER_SIZE; // 42
pub const ERSPAN_PACKET_SIZE: usize = GRE_PACKET_SIZE + ERSPAN_HEADER_SIZE; // 54
pub const IPV6_PACKET_SIZE: usize = ETH_HEADER_SIZE + IPV6_HEADER_SIZE; // 54
pub const UDP6_PACKET_SIZE: usize = IPV6_PACKET_SIZE + UDP_HEADER_SIZE; // 62
pub const VXLAN6_PACKET_SIZE: usize = UDP6_PACKET_SIZE + VXLAN_HEADER_SIZE; // 70
pub const GRE6_PACKET_SIZE: usize = IPV6_PACKET_SIZE + GRE_HEADER_SIZE; // 42
pub const ERSPAN6_PACKET_SIZE: usize = GRE6_PACKET_SIZE + ERSPAN_HEADER_SIZE; // 74
pub const TCP_PACKET_SIZE: usize = IPV4_PACKET_SIZE + TCP_HEADER_SIZE; // 54
pub const TCP6_PACKET_SIZE: usize = IPV6_PACKET_SIZE + TCP_HEADER_SIZE; // 74

// other
pub const IPV6_HEADER_ADJUST: usize = IPV6_HEADER_SIZE - IPV4_HEADER_SIZE;

pub const NPB_VXLAN_FLAGS: u8 = 0xff;
pub const NPB_DEFAULT_PORT: u16 = 4789;

pub const TCP_OPT_FLAG_WIN_SCALE: u8 = 0b1;
pub const TCP_OPT_FLAG_MSS: u8 = 0b10;
pub const TCP_OPT_FLAG_SACK_PERMIT: u8 = 0b100;
pub const TCP_OPT_FLAG_SACK: u8 = 0x38; // 0011 1000, 同时也表示SACK的字节数，不要修改

pub const TCP_OPT_WIN_SCALE_LEN: usize = 3;
pub const TCP_OPT_MSS_LEN: usize = 4;

// IPVS: https://github.com/yubo/ip_vs_ca
pub const TCP_OPT_ADDRESS_IPVS: u8 = 200;
// HUAWEI & ALI: https://github.com/Huawei/TCP_option_address/blob/master/src/toa.h
pub const TCP_OPT_ADDRESS_HUAWEI: u8 = 254;
pub const TCP_TOA_LEN: usize = 8;
pub const TCP_TOA_PORT_OFFSET: usize = 2;
pub const TCP_TOA_IP_OFFSET: usize = 4;

pub const VLAN_ID_MASK: u16 = 0xfff;

pub mod arp {
    pub const OP_OFFSET: usize = 6;
    pub const SENDER_PROTO_ADDR_OFFSET: usize = 14;
    pub const TARGET_PROTO_ADDR_OFFSET: usize = 24;

    pub const OP_REQUEST: u16 = 1;
    pub const OP_REPLY: u16 = 2;
}

pub mod erspan {
    /*
    ERSPAN Type III header (12 octets)
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Ver  |          VLAN         | COS |BSO|T|     Session ID    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Timestamp                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |             SGT               |P|    FT   |   Hw ID   |D|Gra|O|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */
    pub const GRE_PROTO_ERSPAN_III: usize = 0x22eb;
    pub const GRE_PROTO_OFFSET: usize = 2;
    pub const GRE_KEY_OFFSET: usize = 4;
    pub const GRE_SEQUENCE_OFFSET: usize = 8; // 注意: 相对GRE头部开头位置的偏移量

    pub const TYPE3_VER_OFFSET: usize = 0;
    pub const TYPE3_SESSION_ID_OFFSET: usize = 2;
    pub const TYPE3_TIMESTAMP_HIGH_OFFSET: usize = 4;
    pub const TYPE3_TIMESTAMP_LOWER_OFFSET: usize = 8;
    pub const TYPE3_FLAGS_OFFSET: usize = 11;
}

pub mod icmpv6 {
    pub const TYPE_OFFSET: usize = 0;
}

pub mod ipv4 {
    pub const VERSION_IHL_OFFSET: usize = 0;
    pub const TOTAL_LENGTH_OFFSET: usize = 2;
    pub const FLAGS_OFFSET: usize = 6;
    pub const TTL_OFFSET: usize = 8;
    pub const PROTO_OFFSET: usize = 9;
    pub const CSUM_OFFSET: usize = 10;
    pub const SRC_OFFSET: usize = 12;
    pub const DST_OFFSET: usize = 16;
}

pub mod ipv6 {
    pub const FLOW_LABEL_OFFSET: usize = 0;
    pub const PROTO_OFFSET: usize = 6;
    pub const HOP_LIMIT_OFFSET: usize = 7;
    pub const PAYLOAD_LENGTH_OFFSET: usize = 4;
    pub const SRC_OFFSET: usize = 8;
    pub const DST_OFFSET: usize = 24;

    // options
    pub const FRAG_OFFSET: usize = 2;
    pub const FRAG_ID_OFFSET: usize = 4;
}

pub mod tcp {
    pub const SRC_OFFSET: usize = 0;
    pub const DST_OFFSET: usize = 2;
}

pub mod udp {
    pub const SRC_OFFSET: usize = 0;
    pub const DST_OFFSET: usize = 2;
    pub const LENGTH_OFFSET: usize = 4;
    pub const CHKSUM_OFFSET: usize = 6;
}

pub mod vxlan {
    // VXLAN Header:
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |R|R|R|R|I|R|R|R|            SEQUENCE                           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                VXLAN Network Identifier (VNI) |   Reserved  |D|
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    pub const FLAGS_OFFSET: usize = 0;
    pub const SEQUENCE_OFFSET: usize = 1; // NOTE: 使用24bit的Reserved作为sequece
    pub const VNI_OFFSET: usize = 4;
    pub const DIRECTION_OFFSET: usize = 7;
}

pub const ETH_ADDR_SIZE: usize = MAC_ADDR_LEN * 2;
pub const ETH_TYPE_OFFSET: usize = ETH_ADDR_SIZE;

pub const ARP_OP_OFFSET: usize = ETH_HEADER_SIZE + arp::OP_OFFSET; // 20
pub const ARP_SPA_OFFSET: usize = ETH_HEADER_SIZE + arp::SENDER_PROTO_ADDR_OFFSET; // 28
pub const ARP_TPA_OFFSET: usize = ETH_HEADER_SIZE + arp::TARGET_PROTO_ADDR_OFFSET; // 38

pub const IPV4_VERSION_IHL_OFFSET: usize = ETH_HEADER_SIZE + ipv4::VERSION_IHL_OFFSET; // 14
pub const IPV4_TOTAL_LENGTH_OFFSET: usize = ETH_HEADER_SIZE + ipv4::TOTAL_LENGTH_OFFSET; // 16
pub const IPV4_FLAGS_OFFSET: usize = ETH_HEADER_SIZE + ipv4::FLAGS_OFFSET; // 20
pub const IPV4_TTL_OFFSET: usize = ETH_HEADER_SIZE + ipv4::TTL_OFFSET; // 22
pub const IPV4_PROTO_OFFSET: usize = ETH_HEADER_SIZE + ipv4::PROTO_OFFSET; // 23
pub const IPV4_CSUM_OFFSET: usize = ETH_HEADER_SIZE + ipv4::CSUM_OFFSET; // 24
pub const IPV4_SRC_OFFSET: usize = ETH_HEADER_SIZE + ipv4::SRC_OFFSET; // 26
pub const IPV4_DST_OFFSET: usize = ETH_HEADER_SIZE + ipv4::DST_OFFSET; // 30

pub const IPV4_FRAG_DONT_FRAGMENT: u16 = 0x4000;
pub const IPV4_FRAG_MORE_FRAGMENT: u16 = 0x2000;
pub const IPV6_FRAG_MORE_FRAGMENT: u16 = 1;

pub const IPV6_PROTO_OFFSET: usize = ETH_HEADER_SIZE + ipv6::PROTO_OFFSET; // 20
pub const IPV6_FLOW_LABEL_OFFSET: usize = ETH_HEADER_SIZE + ipv6::FLOW_LABEL_OFFSET;
pub const IPV6_HOP_LIMIT_OFFSET: usize = ETH_HEADER_SIZE + ipv6::HOP_LIMIT_OFFSET;
pub const IPV6_PAYLOAD_LENGTH_OFFSET: usize = ETH_HEADER_SIZE + ipv6::PAYLOAD_LENGTH_OFFSET;
pub const IPV6_SRC_OFFSET: usize = ETH_HEADER_SIZE + ipv6::SRC_OFFSET;
pub const IPV6_DST_OFFSET: usize = ETH_HEADER_SIZE + ipv6::DST_OFFSET;
// ipv6 options
pub const IPV6_FRAG_OFFSET: usize = ipv6::FRAG_OFFSET;
pub const IPV6_FRAG_ID_OFFSET: usize = ipv6::FRAG_ID_OFFSET;

pub const ICMPV6_TYPE_OFFSET: usize = ETH_HEADER_SIZE + IPV6_HEADER_SIZE + icmpv6::TYPE_OFFSET;
pub const ICMPV6_TYPE_SIZE: usize = 1;

pub const UDP_SRC_OFFSET: usize = IPV4_PACKET_SIZE + udp::SRC_OFFSET; // 34
pub const UDP_DST_OFFSET: usize = IPV4_PACKET_SIZE + udp::DST_OFFSET; // 36
pub const UDP_LENGTH_OFFSET: usize = IPV4_PACKET_SIZE + udp::LENGTH_OFFSET; // 38
pub const UDP_CHKSUM_OFFSET: usize = IPV4_PACKET_SIZE + udp::CHKSUM_OFFSET; // 40
pub const UDP6_SRC_OFFSET: usize = IPV6_PACKET_SIZE + udp::SRC_OFFSET; // 54
pub const UDP6_DST_OFFSET: usize = IPV6_PACKET_SIZE + udp::DST_OFFSET; // 56
pub const UDP6_LENGTH_OFFSET: usize = IPV6_PACKET_SIZE + udp::LENGTH_OFFSET; // 58
pub const UDP6_CHKSUM_OFFSET: usize = IPV6_PACKET_SIZE + udp::CHKSUM_OFFSET; // 60

pub const TCP_SRC_OFFSET: usize = IPV4_PACKET_SIZE + tcp::SRC_OFFSET; // 34
pub const TCP_DST_OFFSET: usize = IPV4_PACKET_SIZE + tcp::DST_OFFSET; // 36
pub const TCP6_SRC_OFFSET: usize = IPV6_PACKET_SIZE + tcp::SRC_OFFSET; // 54
pub const TCP6_DST_OFFSET: usize = IPV6_PACKET_SIZE + tcp::DST_OFFSET; // 56

pub const VXLAN_FLAGS_OFFSET: usize = UDP_PACKET_SIZE + vxlan::FLAGS_OFFSET;
pub const VXLAN_SEQ_OFFSET: usize = UDP_PACKET_SIZE + vxlan::SEQUENCE_OFFSET;
pub const VXLAN_VNI_OFFSET: usize = UDP_PACKET_SIZE + vxlan::VNI_OFFSET;
pub const VXLAN_DIRECTION_OFFSET: usize = UDP_PACKET_SIZE + vxlan::DIRECTION_OFFSET;
pub const VXLAN6_FLAGS_OFFSET: usize = UDP6_PACKET_SIZE + vxlan::FLAGS_OFFSET;
pub const VXLAN6_SEQ_OFFSET: usize = UDP6_PACKET_SIZE + vxlan::SEQUENCE_OFFSET;
pub const VXLAN6_VNI_OFFSET: usize = UDP6_PACKET_SIZE + vxlan::VNI_OFFSET;
pub const VXLAN6_DIRECTION_OFFSET: usize = UDP6_PACKET_SIZE + vxlan::DIRECTION_OFFSET;

pub const GRE4_PROTO_OFFSET: usize = IPV4_PACKET_SIZE + erspan::GRE_PROTO_OFFSET;
pub const GRE6_PROTO_OFFSET: usize = IPV6_PACKET_SIZE + erspan::GRE_PROTO_OFFSET;

pub const ERSPAN_SEQ_OFFSET: usize = IPV4_PACKET_SIZE + erspan::GRE_SEQUENCE_OFFSET;
pub const ERSPAN_SESSION_ID_OFFSET: usize = GRE_PACKET_SIZE + erspan::TYPE3_SESSION_ID_OFFSET;
pub const ERSPAN_KEY_OFFSET: usize = IPV4_PACKET_SIZE + erspan::GRE_KEY_OFFSET;
pub const ERSPAN_TIMESTAMP_HIGH_OFFSET: usize =
    GRE_PACKET_SIZE + erspan::TYPE3_TIMESTAMP_HIGH_OFFSET;
pub const ERSPAN_TIMESTAMP_LOWER_OFFSET: usize =
    GRE_PACKET_SIZE + erspan::TYPE3_TIMESTAMP_LOWER_OFFSET;
pub const ERSPAN_FLAGS_OFFSET: usize = GRE_PACKET_SIZE + erspan::TYPE3_FLAGS_OFFSET;
pub const ERSPAN6_SEQ_OFFSET: usize = IPV6_PACKET_SIZE + erspan::GRE_SEQUENCE_OFFSET;
pub const ERSPAN6_SESSION_ID_OFFSET: usize = GRE6_PACKET_SIZE + erspan::TYPE3_SESSION_ID_OFFSET;
pub const ERSPAN6_KEY_OFFSET: usize = IPV6_PACKET_SIZE + erspan::GRE_KEY_OFFSET;
pub const ERSPAN6_TIMESTAMP_HIGH_OFFSET: usize =
    GRE6_PACKET_SIZE + erspan::TYPE3_TIMESTAMP_HIGH_OFFSET;
pub const ERSPAN6_TIMESTAMP_LOWER_OFFSET: usize =
    GRE6_PACKET_SIZE + erspan::TYPE3_TIMESTAMP_LOWER_OFFSET;
pub const ERSPAN6_FLAGS_OFFSET: usize = GRE6_PACKET_SIZE + erspan::TYPE3_FLAGS_OFFSET;

pub const GRE_HEADER_SIZE_DECAP: usize = 4;
pub const GRE_FLAGS_OFFSET: usize = 0;
pub const GRE_PROTOCOL_OFFSET: usize = 2;
pub const GRE_KEY_OFFSET: usize = 4;

pub const GRE_FLAGS_VER_MASK: u16 = 0x7;
pub const GRE_FLAGS_SEQ_MASK: u16 = 1 << 12;
pub const GRE_FLAGS_KEY_MASK: u16 = 1 << 13;
pub const GRE_FLAGS_CSUM_MASK: u16 = 1 << 15;

pub const GRE_SEQ_LEN: usize = 4;
pub const GRE_KEY_LEN: usize = 4;
pub const GRE_CSUM_LEN: usize = 4;

pub const GENEVE_VERSION_OFFSET: usize = 0;
pub const GENEVE_PROTOCOL_OFFSET: usize = 2;
pub const GENEVE_VNI_OFFSET: usize = 4;

pub const GENEVE_OPTION_LENGTH_MASK: u8 = 0x3f;

pub const GENEVE_VERSION_SHIFT: u8 = 6;
pub const GENEVE_VNI_SHIFT: u32 = 8;

pub const IP_IHL_OFFSET: usize = 0;
pub const IP6_PROTO_OFFSET: usize = 6;
pub const IP6_SIP_OFFSET: usize = 20; // 用于解析tunnel，仅使用后四个字节
pub const IP6_DIP_OFFSET: usize = 36; // 用于解析tunnel，仅使用后四个字节
pub const UDP_DPORT_OFFSET: usize = 2;
pub const VXLAN_FLAGS_OFFSET_DECAP: usize = 0;
pub const VXLAN_VNI_OFFSET_DECAP: usize = 4;
pub const ERSPAN_ID_OFFSET: usize = 0; // erspan2和3共用，4字节取0x3ff
pub const ERSPAN_III_FLAGS_OFFSET: usize = 11;

// IpAddr mask
pub const IPV6_MAX_MASK_LEN: u8 = 128;
pub const IPV4_MAX_MASK_LEN: u8 = 32;
pub const MIN_MASK_LEN: u8 = 0;

// 静态配置项默认值
pub const L7_PROTOCOL_INFERENCE_MAX_FAIL_COUNT: usize = 1000;
pub const L7_PROTOCOL_INFERENCE_TTL: usize = 60;

// RawPcap
pub const PCAP_MAGIC: u32 = 0xa1b2c3d4;
pub const RECORD_HEADER_LEN: usize = 16;

// GRPC
pub const GRPC_DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
pub const GRPC_SESSION_TIMEOUT: Duration = Duration::from_secs(30);
