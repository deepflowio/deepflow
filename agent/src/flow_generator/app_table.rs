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

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroUsize,
};

use lru::LruCache;
use public::l7_protocol::{L7Protocol, L7ProtocolEnum};

use crate::common::flow::PacketDirection;
use crate::common::meta_packet::MetaPacket;
use crate::common::{L7_PROTOCOL_INFERENCE_MAX_FAIL_COUNT, L7_PROTOCOL_INFERENCE_TTL};

#[derive(Eq, Hash, PartialEq)]
struct AppTable4Key {
    ip: Ipv4Addr,
    epc: i32,
    port: u16,
    // only ebpf and loopback addr will set pid
    // maybe remove in future
    pid: u32,
    // only ebpf
    source: u8,
}

#[derive(Eq, Hash, PartialEq)]
struct AppTable6Key {
    ip: Ipv6Addr,
    epc: i32,
    port: u16,
    // only ebpf and loopback addr will set pid
    // maybe remove in future
    pid: u32,
    // only ebpf
    source: u8,
}

struct AppTableValue {
    unknown_count: u32,
    l7_protocol_enum: L7ProtocolEnum,
    last: u64, // 单位秒
}

// 记录IP+EPC+PORT对应的应用协议
pub struct AppTable {
    ipv4: LruCache<AppTable4Key, AppTableValue>,
    ipv6: LruCache<AppTable6Key, AppTableValue>,

    l7_protocol_inference_max_fail_count: u32,
    l7_protocol_inference_ttl: u64,
}

impl Default for AppTable {
    fn default() -> Self {
        Self {
            ipv4: LruCache::new(Self::APP_LRU_SIZE),
            ipv6: LruCache::new(Self::APP_LRU_SIZE),
            l7_protocol_inference_max_fail_count: L7_PROTOCOL_INFERENCE_MAX_FAIL_COUNT as u32,
            l7_protocol_inference_ttl: L7_PROTOCOL_INFERENCE_TTL as u64,
        }
    }
}

impl AppTable {
    // safe because parameter to new_unchecked is not zero
    const APP_LRU_SIZE: NonZeroUsize = unsafe { NonZeroUsize::new_unchecked(1 << 12) };

    pub fn new(
        l7_protocol_inference_max_fail_count: usize,
        l7_protocol_inference_ttl: usize,
    ) -> Self {
        let l7_protocol_inference_ttl = l7_protocol_inference_ttl as u64;
        Self {
            l7_protocol_inference_max_fail_count: l7_protocol_inference_max_fail_count as u32,
            l7_protocol_inference_ttl,
            ..Default::default()
        }
    }

    fn get_ip_epc_port(packet: &MetaPacket, forward: bool) -> (IpAddr, i32, u16) {
        let (src_epc, dst_epc) = if let Some(endpoints) = packet.endpoint_data.as_ref() {
            (
                endpoints.src_info().l3_epc_id,
                endpoints.dst_info().l3_epc_id,
            )
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
        pid: u32,
        source: u8,
    ) -> Option<(L7ProtocolEnum, u32, u64)> {
        let key = AppTable4Key {
            ip,
            epc,
            port,
            pid,
            source,
        };
        if let Some(v) = self.ipv4.get_mut(&key) {
            if v.last + self.l7_protocol_inference_ttl < time_in_sec {
                self.ipv4.pop(&key);
                return None;
            }
            v.last = time_in_sec;
            // 如果第一次check就失败会设置为unknown，所以需要加上count判断
            // ====================================================
            // if first check fail will set to unknown, need to add count determine
            if v.l7_protocol_enum.get_l7_protocol() == L7Protocol::Unknown
                && v.unknown_count < self.l7_protocol_inference_max_fail_count
            {
                return None;
            } else {
                return Some((v.l7_protocol_enum.clone(), v.unknown_count, v.last));
            }
        }
        None
    }

    fn get_ipv6_protocol(
        &mut self,
        time_in_sec: u64,
        ip: Ipv6Addr,
        epc: i32,
        port: u16,
        pid: u32,
        source: u8,
    ) -> Option<(L7ProtocolEnum, u32, u64)> {
        let key = AppTable6Key {
            ip,
            epc,
            port,
            pid,
            source,
        };
        if let Some(v) = self.ipv6.get_mut(&key) {
            if v.last + self.l7_protocol_inference_ttl < time_in_sec {
                self.ipv6.pop(&key);
                return None;
            }
            v.last = time_in_sec;
            // 如果第一次check就失败会设置为unknown，所以需要加上count判断
            // ====================================================
            // if first check fail will set to unknown, need to add count determine
            if v.l7_protocol_enum.get_l7_protocol() == L7Protocol::Unknown
                && v.unknown_count < self.l7_protocol_inference_max_fail_count
            {
                return None;
            } else {
                return Some((v.l7_protocol_enum.clone(), v.unknown_count, v.last));
            }
        }
        None
    }

    // get protocol from non ebpf packet, return (proto, fail_count, last_time)
    pub fn get_protocol(&mut self, packet: &MetaPacket) -> Option<(L7ProtocolEnum, u32, u64)> {
        let (ip, epc, port) = Self::get_ip_epc_port(
            packet,
            packet.lookup_key.direction == PacketDirection::ClientToServer,
        );
        let time_in_sec = packet.lookup_key.timestamp.as_secs();
        match ip {
            IpAddr::V4(i) => self.get_ipv4_protocol(time_in_sec, i, epc, port, 0, 0),
            IpAddr::V6(i) => self.get_ipv6_protocol(time_in_sec, i, epc, port, 0, 0),
        }
    }

    // EBPF数据MetaPacket中direction未赋值
    // return (proto, port, fail_count, last_time)
    pub fn get_protocol_from_ebpf(
        &mut self,
        packet: &MetaPacket,
        local_epc: i32,
        remote_epc: i32,
    ) -> Option<(L7ProtocolEnum, u16, u32, u64)> {
        let (ip, _, dport) = Self::get_ip_epc_port(packet, true);
        let pid = if ip.is_loopback() {
            packet.process_id
        } else {
            0
        };
        let time_in_sec = packet.lookup_key.timestamp.as_secs();
        let epc = if packet.lookup_key.l2_end_0 {
            local_epc
        } else {
            remote_epc
        };
        let source = packet.ebpf_type.into();
        let dst_protocol = match ip {
            IpAddr::V4(i) => self.get_ipv4_protocol(time_in_sec, i, epc, dport, pid, source),
            IpAddr::V6(i) => self.get_ipv6_protocol(time_in_sec, i, epc, dport, pid, source),
        };
        match dst_protocol.as_ref() {
            Some((dst_protocol, _, last)) => {
                if dst_protocol.get_l7_protocol() != L7Protocol::Unknown {
                    return Some((dst_protocol.clone(), dport, 0, *last));
                }
            }
            _ => {}
        }

        let (ip, _, sport) = Self::get_ip_epc_port(packet, false);
        let pid = if ip.is_loopback() {
            packet.process_id
        } else {
            0
        };
        let epc = if packet.lookup_key.l2_end_1 {
            local_epc
        } else {
            remote_epc
        };
        let src_protocol = match ip {
            IpAddr::V4(i) => self.get_ipv4_protocol(time_in_sec, i, epc, sport, pid, source),
            IpAddr::V6(i) => self.get_ipv6_protocol(time_in_sec, i, epc, sport, pid, source),
        };
        match src_protocol.as_ref() {
            Some((src_protocol, _, last)) => {
                if src_protocol.get_l7_protocol() != L7Protocol::Unknown {
                    return Some((src_protocol.clone(), sport, 0, *last));
                }
            }
            _ => {}
        }

        if src_protocol.is_none() && dst_protocol.is_none() {
            return None;
        } else if src_protocol.is_none() {
            let (l7_protocol, l7_protocol_inference_max_fail_count, last) = dst_protocol.unwrap();
            return Some((
                l7_protocol,
                dport,
                l7_protocol_inference_max_fail_count,
                last,
            ));
        }
        let (l7_protocol, l7_protocol_inference_max_fail_count, last) = src_protocol.unwrap();
        return Some((
            l7_protocol,
            sport,
            l7_protocol_inference_max_fail_count,
            last,
        ));
    }

    fn set_ipv4_protocol(
        &mut self,
        time_in_sec: u64,
        ip: Ipv4Addr,
        epc: i32,
        port: u16,
        l7_protocol_enum: L7ProtocolEnum,
        pid: u32,
        source: u8,
    ) -> bool {
        let key = AppTable4Key {
            ip,
            epc,
            port,
            pid,
            source,
        };
        let value = self.ipv4.get_mut(&key);
        if let Some(value) = value {
            if l7_protocol_enum.get_l7_protocol() == L7Protocol::Unknown {
                if value.last + self.l7_protocol_inference_ttl < time_in_sec {
                    value.unknown_count = 0;
                }
                value.last = time_in_sec;

                value.unknown_count += 1;
                if value.unknown_count > self.l7_protocol_inference_max_fail_count {
                    value.l7_protocol_enum = l7_protocol_enum;
                    return true;
                }
            } else {
                value.last = time_in_sec;
                value.unknown_count = 0;
                value.l7_protocol_enum = l7_protocol_enum;
            }
        } else {
            self.ipv4.put(
                key,
                AppTableValue {
                    unknown_count: 0,
                    l7_protocol_enum,
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
        l7_protocol_enum: L7ProtocolEnum,
        pid: u32,
        source: u8,
    ) -> bool {
        let key = AppTable6Key {
            ip,
            epc,
            port,
            pid,
            source,
        };
        let value = self.ipv6.get_mut(&key);
        if let Some(value) = value {
            if l7_protocol_enum.get_l7_protocol() == L7Protocol::Unknown {
                if value.last + self.l7_protocol_inference_ttl < time_in_sec {
                    value.unknown_count = 0;
                }
                value.last = time_in_sec;

                value.unknown_count += 1;
                if value.unknown_count > self.l7_protocol_inference_max_fail_count {
                    value.l7_protocol_enum = l7_protocol_enum;
                    return true;
                }
            } else {
                value.last = time_in_sec;
                value.unknown_count = 0;
                value.l7_protocol_enum = l7_protocol_enum;
            }
        } else {
            self.ipv6.put(
                key,
                AppTableValue {
                    unknown_count: 0,
                    l7_protocol_enum,
                    last: time_in_sec,
                },
            );
        }
        return false;
    }

    pub fn clear(&mut self) {
        self.ipv4.clear();
        self.ipv6.clear();
    }

    // set protocol to app_table from non ebpf packet
    pub fn set_protocol(&mut self, packet: &MetaPacket, protocol: L7ProtocolEnum) -> bool {
        let (mut ip, epc, mut port) = Self::get_ip_epc_port(
            packet,
            packet.lookup_key.direction == PacketDirection::ClientToServer,
        );

        if protocol.get_l7_protocol() == L7Protocol::Redis {
            (ip, port) = packet.get_redis_server_addr();
        }
        let time_in_sec = packet.lookup_key.timestamp.as_secs();
        match ip {
            IpAddr::V4(i) => self.set_ipv4_protocol(time_in_sec, i, epc, port, protocol, 0, 0),
            IpAddr::V6(i) => self.set_ipv6_protocol(time_in_sec, i, epc, port, protocol, 0, 0),
        }
    }

    pub fn set_protocol_from_ebpf(
        &mut self,
        packet: &MetaPacket,
        protocol: L7ProtocolEnum,
        local_epc: i32,
        remote_epc: i32,
    ) -> bool {
        let is_c2s = packet.lookup_key.direction == PacketDirection::ClientToServer;

        let (ip, port);
        // redis can not determine dirction by RESP protocol when pakcet is from ebpf, special treatment
        if protocol.get_l7_protocol() == L7Protocol::Redis {
            (ip, port) = packet.get_redis_server_addr();
        } else {
            (ip, _, port) = Self::get_ip_epc_port(packet, is_c2s);
        }
        // due to loopback may be in different protocol in container, add pid as key
        // FIXME: istio (or the similar proxy use DNAT on loopback addr and port to hijack traffic) will have different protocol in same port,
        // save the protocol to apptable use loopback addr and port will lead to get incorrect protocol in those envrioment
        let pid = if ip.is_loopback() {
            packet.process_id
        } else {
            0
        };
        let time_in_sec = packet.lookup_key.timestamp.as_secs();
        let epc = if is_c2s == packet.lookup_key.l2_end_1 {
            local_epc
        } else {
            remote_epc
        };
        let source = packet.ebpf_type.into();
        match ip {
            IpAddr::V4(i) => {
                self.set_ipv4_protocol(time_in_sec, i, epc, port, protocol, pid, source)
            }
            IpAddr::V6(i) => {
                self.set_ipv6_protocol(time_in_sec, i, epc, port, protocol, pid, source)
            }
        }
    }
}
