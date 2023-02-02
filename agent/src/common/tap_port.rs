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
use std::net::Ipv4Addr;

use serde::Serialize;

use super::decapsulate::TunnelType;

// 64     60         40           36         32                                    0
// +------+----------+------------+----------+-------------------------------------+
// | from | RESERVED | NAT SOURCE | TUN_TYPE |   ip/mac/dispatcher_id/process_id   |
// +------+----------+------------+----------+-------------------------------------+
// 注意ip/id/mac不能超过32bit，否则数据存储、四元组聚合都会有歧义
#[derive(Serialize, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct TapPort(pub u64);

impl TapPort {
    pub const FROM_LOCAL_MAC: u8 = 0;
    pub const FROM_GATEWAY_MAC: u8 = 1;
    pub const FROM_TUNNEL_IPV4: u8 = 2;
    pub const FROM_TUNNEL_IPV6: u8 = 3;
    pub const FROM_ID: u8 = 4;
    pub const FROM_NETFLOW: u8 = 5;
    pub const FROM_SFLOW: u8 = 6;
    pub const FROM_EBPF: u8 = 7;
    pub const FROM_OTEL: u8 = 8;

    // The higher the nat source value, the higher the priority.
    // NAT_SOURCE_VIP and NAT_SOURCE_CONTROLLER is obtained through policy query,
    // NAT_SOURCE_TOA is obtained through TCP Options Address.
    pub const NAT_SOURCE_NONE: u8 = 0;
    pub const NAT_SOURCE_VIP: u8 = 2;
    pub const NAT_SOURCE_RTOA: u8 = 4;
    pub const NAT_SOURCE_TOA: u8 = 6;

    const TUNNEL_TYPE_OFFSET: u64 = 32;
    const TUNNEL_TYPE_MASK: u64 = 0xf;
    const FROM_OFFSET: u64 = 60;
    const NAT_SOURCE_OFFSET: u64 = 36;
    const NAT_SOURCE_MASK: u64 = 0xf;
    const RESERVED_OFFSET: u8 = 40;
    const RESERVED_MASK: u32 = 0xfffff;

    pub fn is_from(&self, w: u8) -> bool {
        (self.0 >> Self::FROM_OFFSET) as u8 == w
    }

    pub fn ignore_nat_source(&self) -> u64 {
        self.0 & !((Self::NAT_SOURCE_MASK as u64) << Self::NAT_SOURCE_OFFSET)
    }

    pub fn get_nat_source(&self) -> u8 {
        ((self.0 >> Self::NAT_SOURCE_OFFSET) & Self::NAT_SOURCE_MASK) as u8
    }

    pub fn set_nat_source(&mut self, w: u8) {
        self.0 &= !((Self::NAT_SOURCE_MASK as u64) << Self::NAT_SOURCE_OFFSET);
        self.0 |= (w as u64) << Self::NAT_SOURCE_OFFSET;
    }

    pub fn from_local_mac(nat_source: u8, tunnel_type: TunnelType, mac: u32) -> Self {
        Self(
            mac as u64
                | ((tunnel_type as u64 & Self::TUNNEL_TYPE_MASK) << Self::TUNNEL_TYPE_OFFSET)
                | ((nat_source as u64) << Self::NAT_SOURCE_OFFSET)
                | ((Self::FROM_LOCAL_MAC as u64) << Self::FROM_OFFSET),
        )
    }

    pub fn from_netflow(mac: u32) -> Self {
        Self(mac as u64 | ((Self::FROM_NETFLOW as u64) << Self::FROM_OFFSET))
    }

    pub fn from_sflow(mac: u32) -> Self {
        Self(mac as u64 | ((Self::FROM_SFLOW as u64) << Self::FROM_OFFSET))
    }

    pub fn from_gateway_mac(tunnel_type: TunnelType, mac: u32) -> Self {
        Self(
            mac as u64
                | ((tunnel_type as u64 & Self::TUNNEL_TYPE_MASK) << Self::TUNNEL_TYPE_OFFSET)
                | ((Self::FROM_GATEWAY_MAC as u64) << Self::FROM_OFFSET),
        )
    }

    pub fn from_tunnel_ip(ip: u32, is_ip_v6: bool) -> Self {
        Self(
            ip as u64
                | ((if is_ip_v6 {
                    Self::FROM_TUNNEL_IPV6
                } else {
                    Self::FROM_TUNNEL_IPV4
                } as u64)
                    << Self::FROM_OFFSET),
        )
    }

    pub fn from_id(tunnel_type: TunnelType, id: u32) -> Self {
        Self(
            id as u64
                | ((tunnel_type as u64 & Self::TUNNEL_TYPE_MASK) << Self::TUNNEL_TYPE_OFFSET)
                | ((Self::FROM_ID as u64) << Self::FROM_OFFSET),
        )
    }

    pub fn from_ebpf(process_id: u32) -> Self {
        Self(process_id as u64 | (Self::FROM_EBPF as u64) << Self::FROM_OFFSET)
    }

    pub fn split_fields(&self) -> (u32, u8, TunnelType) {
        (
            self.0 as u32,
            (self.0 >> Self::FROM_OFFSET) as u8,
            (((self.0 >> Self::TUNNEL_TYPE_OFFSET) & Self::TUNNEL_TYPE_MASK) as u8)
                .try_into()
                .unwrap_or(TunnelType::None),
        )
    }

    // 用于编码后做为Map Key
    // Used as Map Key after encoding
    pub fn set_reserved_bytes(&self, tap_type: u32) -> TapPort {
        TapPort(self.0 | ((tap_type & Self::RESERVED_MASK) as u64) << Self::RESERVED_OFFSET)
    }
}

impl fmt::Display for TapPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (p, t, tt) = self.split_fields();
        match t {
            TapPort::FROM_LOCAL_MAC => {
                let bs = p.to_be_bytes();
                write!(
                    f,
                    "LMAC@{}@{:02x}:{:02x}:{:02x}:{:02x}",
                    tt, bs[0], bs[1], bs[2], bs[3]
                )
            }
            TapPort::FROM_GATEWAY_MAC => {
                let bs = p.to_be_bytes();
                write!(
                    f,
                    "GMAC@{}@{:02x}:{:02x}:{:02x}:{:02x}",
                    tt, bs[0], bs[1], bs[2], bs[3]
                )
            }
            TapPort::FROM_TUNNEL_IPV4 => {
                write!(f, "IPv4@{}", Ipv4Addr::from(p))
            }
            TapPort::FROM_TUNNEL_IPV6 => {
                write!(f, "IPv6@{:#10x}", p)
            }
            TapPort::FROM_ID => {
                write!(f, "ID@{}@{}", tt, p)
            }
            TapPort::FROM_NETFLOW => {
                write!(f, "NetFlow@{}", p)
            }
            TapPort::FROM_SFLOW => {
                write!(f, "sFlow@{}", p)
            }
            TapPort::FROM_EBPF => {
                write!(f, "eBPF@{}", p)
            }
            _ => panic!("Invalid tap_port type {}.", t),
        }
    }
}

impl fmt::Debug for TapPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}
