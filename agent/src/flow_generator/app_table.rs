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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use lru::LruCache;

use crate::common::enums::PacketDirection;
use crate::common::flow::L7Protocol;
use crate::common::meta_packet::MetaPacket;
use crate::common::{L7_PROTOCOL_INFERENCE_MAX_FAIL_COUNT, L7_PROTOCOL_INFERENCE_TTL};

#[derive(Eq, Hash, PartialEq)]
struct AppTable4Key {
    ip: Ipv4Addr,
    epc: i32,
    port: u16,
}

#[derive(Eq, Hash, PartialEq)]
struct AppTable6Key {
    ip: Ipv6Addr,
    epc: i32,
    port: u16,
}

struct AppTableValue {
    unknown_count: usize,
    l7_protocol: L7Protocol,
    last: u64, // 单位秒
}

// 记录IP+EPC+PORT对应的应用协议
pub struct AppTable {
    ipv4: LruCache<AppTable4Key, AppTableValue>,
    ipv6: LruCache<AppTable6Key, AppTableValue>,

    l7_protocol_inference_max_fail_count: usize,
    l7_protocol_inference_ttl: u64,
}

impl Default for AppTable {
    fn default() -> Self {
        Self {
            ipv4: LruCache::new(Self::APP_LRU_SIZE),
            ipv6: LruCache::new(Self::APP_LRU_SIZE),
            l7_protocol_inference_max_fail_count: L7_PROTOCOL_INFERENCE_MAX_FAIL_COUNT,
            l7_protocol_inference_ttl: L7_PROTOCOL_INFERENCE_TTL as u64,
        }
    }
}

impl AppTable {
    const APP_LRU_SIZE: usize = 1 << 12;

    pub fn new(
        l7_protocol_inference_max_fail_count: usize,
        l7_protocol_inference_ttl: usize,
    ) -> Self {
        let l7_protocol_inference_ttl = l7_protocol_inference_ttl as u64;
        Self {
            l7_protocol_inference_max_fail_count,
            l7_protocol_inference_ttl,
            ..Default::default()
        }
    }

    fn get_ip_epc_port(packet: &MetaPacket, forward: bool) -> (IpAddr, i32, u16) {
        let (src_epc, dst_epc) = if let Some(endponints) = packet.endpoint_data.as_ref() {
            (endponints.src_info.l3_epc_id, endponints.dst_info.l3_epc_id)
        } else {
            (0, 0)
        };
        if forward {
            (
                packet.lookup_key.dst_ip,
                dst_epc,
                packet.lookup_key.dst_port,
            )
        } else {
            (
                packet.lookup_key.src_ip,
                src_epc,
                packet.lookup_key.src_port,
            )
        }
    }

    fn get_ipv4_protocol(
        &mut self,
        time_in_sec: u64,
        ip: Ipv4Addr,
        epc: i32,
        port: u16,
    ) -> Option<L7Protocol> {
        let key = AppTable4Key { ip, epc, port };
        if let Some(v) = self.ipv4.get_mut(&key) {
            if v.last + self.l7_protocol_inference_ttl < time_in_sec {
                self.ipv4.pop(&key);
                return None;
            }
            v.last = time_in_sec;
            return Some(v.l7_protocol);
        }
        return None;
    }

    fn get_ipv6_protocol(
        &mut self,
        time_in_sec: u64,
        ip: Ipv6Addr,
        epc: i32,
        port: u16,
    ) -> Option<L7Protocol> {
        let key = AppTable6Key { ip, epc, port };
        if let Some(v) = self.ipv6.get_mut(&key) {
            if v.last + self.l7_protocol_inference_ttl < time_in_sec {
                self.ipv6.pop(&key);
                return None;
            }
            v.last = time_in_sec;
            return Some(v.l7_protocol);
        }
        return None;
    }

    pub fn get_protocol(&mut self, packet: &MetaPacket) -> Option<L7Protocol> {
        let (ip, epc, port) =
            Self::get_ip_epc_port(packet, packet.direction == PacketDirection::ClientToServer);
        let time_in_sec = packet.lookup_key.timestamp.as_secs();
        match ip {
            IpAddr::V4(i) => self.get_ipv4_protocol(time_in_sec, i, epc, port),
            IpAddr::V6(i) => self.get_ipv6_protocol(time_in_sec, i, epc, port),
        }
    }

    // EBPF数据MetaPacket中direction未赋值
    pub fn get_protocol_from_ebpf(
        &mut self,
        packet: &MetaPacket,
        local_epc: i32,
        remote_epc: i32,
    ) -> Option<(L7Protocol, u16)> {
        if packet.lookup_key.is_loopback_packet() {
            return None;
        }
        let (ip, _, port) = Self::get_ip_epc_port(packet, true);
        let time_in_sec = packet.lookup_key.timestamp.as_secs();
        let epc = if packet.lookup_key.l2_end_0 {
            local_epc
        } else {
            remote_epc
        };
        let dst_protocol = match ip {
            IpAddr::V4(i) => self.get_ipv4_protocol(time_in_sec, i, epc, port),
            IpAddr::V6(i) => self.get_ipv6_protocol(time_in_sec, i, epc, port),
        };
        if dst_protocol.is_some() && dst_protocol.unwrap() != L7Protocol::Unknown {
            return Some((dst_protocol.unwrap(), packet.lookup_key.dst_port));
        }

        let (ip, _, port) = Self::get_ip_epc_port(packet, false);
        let epc = if packet.lookup_key.l2_end_1 {
            local_epc
        } else {
            remote_epc
        };
        let src_protocol = match ip {
            IpAddr::V4(i) => self.get_ipv4_protocol(time_in_sec, i, epc, port),
            IpAddr::V6(i) => self.get_ipv6_protocol(time_in_sec, i, epc, port),
        };
        if src_protocol.is_some() && src_protocol.unwrap() != L7Protocol::Unknown {
            return Some((src_protocol.unwrap(), packet.lookup_key.src_port));
        }
        if src_protocol.is_none() && dst_protocol.is_none() {
            return None;
        } else if src_protocol.is_none() {
            return Some((dst_protocol.unwrap(), packet.lookup_key.dst_port));
        }
        return Some((src_protocol.unwrap(), packet.lookup_key.src_port));
    }

    fn set_ipv4_protocol(
        &mut self,
        time_in_sec: u64,
        ip: Ipv4Addr,
        epc: i32,
        port: u16,
        protocol: L7Protocol,
    ) -> bool {
        let key = AppTable4Key { ip, epc, port };
        let value = self.ipv4.get_mut(&key);
        if let Some(value) = value {
            value.last = time_in_sec;
            if protocol == L7Protocol::Unknown {
                value.unknown_count += 1;
                if value.unknown_count > self.l7_protocol_inference_max_fail_count {
                    value.l7_protocol = protocol;
                    return true;
                }
            } else {
                value.unknown_count = 0;
                value.l7_protocol = protocol;
            }
        } else {
            self.ipv4.put(
                key,
                AppTableValue {
                    unknown_count: 0,
                    l7_protocol: protocol,
                    last: time_in_sec,
                },
            );
        }
        return false;
    }

    fn set_ipv6_protocol(
        &mut self,
        time_in_sec: u64,
        ip: Ipv6Addr,
        epc: i32,
        port: u16,
        protocol: L7Protocol,
    ) -> bool {
        let key = AppTable6Key { ip, epc, port };
        let value = self.ipv6.get_mut(&key);
        if let Some(value) = value {
            value.last = time_in_sec;
            if protocol == L7Protocol::Unknown {
                value.unknown_count += 1;
                if value.unknown_count > self.l7_protocol_inference_max_fail_count {
                    value.l7_protocol = protocol;
                    return true;
                }
            } else {
                value.unknown_count = 0;
                value.l7_protocol = protocol;
            }
        } else {
            self.ipv6.put(
                key,
                AppTableValue {
                    unknown_count: 0,
                    l7_protocol: protocol,
                    last: time_in_sec,
                },
            );
        }
        return false;
    }

    pub fn set_protocol(&mut self, packet: &MetaPacket, protocol: L7Protocol) -> bool {
        let (ip, epc, port) =
            Self::get_ip_epc_port(packet, packet.direction == PacketDirection::ClientToServer);
        let time_in_sec = packet.lookup_key.timestamp.as_secs();
        match ip {
            IpAddr::V4(i) => self.set_ipv4_protocol(time_in_sec, i, epc, port, protocol),
            IpAddr::V6(i) => self.set_ipv6_protocol(time_in_sec, i, epc, port, protocol),
        }
    }

    pub fn set_protocol_from_ebpf(
        &mut self,
        packet: &MetaPacket,
        protocol: L7Protocol,
        local_epc: i32,
        remote_epc: i32,
    ) -> bool {
        let is_c2s = packet.direction == PacketDirection::ClientToServer;
        let (ip, _, port) = Self::get_ip_epc_port(packet, is_c2s);
        // 在容器环境中相同回环地址和端口可能对应不同的应用，这里不做记录
        // ====================================================================================
        // In a container environment, the same loopback ip address and port may correspond to
        // different applications, which are not recorded here.
        if ip.is_loopback() {
            return false;
        }
        let time_in_sec = packet.lookup_key.timestamp.as_secs();
        let epc = if is_c2s == packet.lookup_key.l2_end_1 {
            local_epc
        } else {
            remote_epc
        };
        match ip {
            IpAddr::V4(i) => self.set_ipv4_protocol(time_in_sec, i, epc, port, protocol),
            IpAddr::V6(i) => self.set_ipv6_protocol(time_in_sec, i, epc, port, protocol),
        }
    }

    fn delete_ipv4(&mut self, ip: Ipv4Addr, epc: i32, port: u16) {
        let key = AppTable4Key { ip, epc, port };
        self.ipv4.pop(&key);
    }

    fn delete_ipv6(&mut self, ip: Ipv6Addr, epc: i32, port: u16) {
        let key = AppTable6Key { ip, epc, port };
        self.ipv6.pop(&key);
    }

    pub fn delete(&mut self, ip: IpAddr, epc: i32, port: u16) {
        match ip {
            IpAddr::V4(i) => self.delete_ipv4(i, epc, port),
            IpAddr::V6(i) => self.delete_ipv6(i, epc, port),
        }
    }
}
