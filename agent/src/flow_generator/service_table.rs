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

use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ahash::{HashSet, HashSetExt};
use lru::LruCache;

use crate::common::enums::TcpFlags;
use crate::common::flow::PacketDirection;

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum ServiceKey {
    V4(Ipv4Key),
    V6(Ipv6Key),
}

impl ServiceKey {
    pub fn new(addr: IpAddr, epc_id: i16, port: u16) -> Self {
        match addr {
            IpAddr::V4(v4) => Self::V4(Ipv4Key::new(v4, epc_id, port)),
            IpAddr::V6(v6) => Self::V6(Ipv6Key::new(v6, epc_id, port)),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct Ipv4Key {
    addr: Ipv4Addr,
    epc_id: i16,
    port: u16,
}

impl Ipv4Key {
    pub fn new(addr: Ipv4Addr, epc_id: i16, port: u16) -> Self {
        Self { addr, epc_id, port }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct Ipv6Key {
    addr: Ipv6Addr,
    epc_id: i16,
    port: u16,
}

impl Ipv6Key {
    pub fn new(addr: Ipv6Addr, epc_id: i16, port: u16) -> Self {
        Self { addr, epc_id, port }
    }
}

impl Hash for Ipv4Key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let key = (u32::from_le_bytes(self.addr.octets()) as u64) << 32
            | (self.port as u64) << 16
            | self.epc_id as u16 as u64;
        key.hash(state);
    }
}

impl Hash for Ipv6Key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr.octets().hash(state);
        ((self.epc_id as u16 as u64) << 16 | self.port as u64).hash(state);
    }
}

pub struct ServiceTable {
    ipv4: LruCache<Ipv4Key, u8>,
    ipv6: LruCache<Ipv6Key, u8>,

    port_map: HashSet<u16>,
}

impl ServiceTable {
    const MIN_SCORE: u8 = 0;
    pub const MAX_SCORE: u8 = 0xff;
    pub const MAX_SCORE_FROM_CONFIG: u8 = Self::MAX_SCORE - 1;
    const SCORE_DIFF_THRESHOLD: u8 = 8;
    const PORT_MSB: u16 = 1 << 15;

    pub fn new(ipv4_capacity: usize, ipv6_capacity: usize, server_ports: &Vec<u16>) -> Self {
        let mut port_map = HashSet::new();
        for port in server_ports {
            if *port != 0 {
                port_map.insert(*port);
            }
        }
        Self {
            ipv4: LruCache::new(ipv4_capacity.try_into().unwrap()),
            ipv6: LruCache::new(ipv6_capacity.try_into().unwrap()),
            port_map,
        }
    }

    // When the direction of the flow is incorrect, the L7 parser will obtain the correct direction
    // and synchronize it here, and after calling reset_score, adjust_score cannot modify direction
    pub fn reset_score(&mut self, flow_src_key: ServiceKey, flow_dst_key: ServiceKey) {
        // adjust_score
        match (flow_src_key, flow_dst_key) {
            (ServiceKey::V4(flow_src_key), ServiceKey::V4(flow_dst_key)) => {
                self.ipv4.put(flow_src_key, Self::MIN_SCORE);
                self.ipv4.put(
                    flow_dst_key,
                    Self::MIN_SCORE + Self::SCORE_DIFF_THRESHOLD + 1,
                );
            }
            (ServiceKey::V6(flow_src_key), ServiceKey::V6(flow_dst_key)) => {
                self.ipv6.put(flow_src_key, Self::MIN_SCORE);
                self.ipv6.put(
                    flow_dst_key,
                    Self::MIN_SCORE + Self::SCORE_DIFF_THRESHOLD + 1,
                );
            }
            _ => unimplemented!(),
        }
    }

    // At present, the function is called in update_l4_direction and update_flow_direction respectively,
    // where update_l4_direction uses the tcp flags and need_reverse_flow obtained from the packet to adjust the direction,
    // and update_flow_direction uses toa obtained from flow to adjust the direction
    pub fn get_tcp_score(
        &mut self,
        is_first_packet: bool,
        need_reverse_flow: bool,
        direction: PacketDirection,
        tcp_flags: TcpFlags,
        toa_sent_by_flow_src: bool,
        toa_sent_by_flow_dst: bool,
        flow_src_key: ServiceKey,
        flow_dst_key: ServiceKey,
    ) -> (u8, u8) {
        let (mut flow_src_score, mut flow_dst_score) = (Self::MIN_SCORE, Self::MIN_SCORE);

        if tcp_flags.contains(TcpFlags::SYN_ACK) || toa_sent_by_flow_dst {
            // 一旦发送SYN|ACK，即被认为是服务端，其对侧被认为不可能是服务端
            flow_src_score = Self::MAX_SCORE;
            flow_dst_score = Self::MIN_SCORE;
            match (flow_src_key, flow_dst_key) {
                (ServiceKey::V4(flow_src_key), ServiceKey::V4(flow_dst_key)) => {
                    self.ipv4.put(flow_src_key, flow_src_score);
                    self.ipv4.pop(&flow_dst_key);
                }
                (ServiceKey::V6(flow_src_key), ServiceKey::V6(flow_dst_key)) => {
                    self.ipv6.put(flow_src_key, flow_src_score);
                    self.ipv6.pop(&flow_dst_key);
                }
                _ => unimplemented!(),
            }
            (flow_src_score, flow_dst_score)
        } else if tcp_flags.contains(TcpFlags::SYN) || toa_sent_by_flow_src {
            // It must be the client when packet has SYN or TOA.
            flow_src_score = Self::MIN_SCORE;

            match (flow_src_key, flow_dst_key) {
                (ServiceKey::V4(flow_src_key), ServiceKey::V4(flow_dst_key)) => {
                    self.ipv4.pop(&flow_src_key);

                    if let Some(score) = self.ipv4.get(&flow_dst_key) {
                        flow_dst_score = *score;
                    }
                    if is_first_packet && flow_dst_score < Self::MAX_SCORE - 1 {
                        flow_dst_score += 1;
                        self.ipv4.put(flow_dst_key, flow_dst_score);
                    }
                }
                (ServiceKey::V6(flow_src_key), ServiceKey::V6(flow_dst_key)) => {
                    self.ipv6.pop(&flow_src_key);

                    if let Some(score) = self.ipv6.get(&flow_dst_key) {
                        flow_dst_score = *score;
                    }
                    if is_first_packet && flow_dst_score < Self::MAX_SCORE - 1 {
                        flow_dst_score += 1;
                        self.ipv6.put(flow_dst_key, flow_dst_score);
                    }
                }
                _ => unimplemented!(),
            }

            (flow_src_score, flow_dst_score)
        } else if is_first_packet {
            self.get_first_packet_score(flow_src_key, flow_dst_key)
        } else if need_reverse_flow {
            match direction {
                PacketDirection::ClientToServer => {
                    flow_src_score = Self::MAX_SCORE;
                    flow_dst_score = Self::MIN_SCORE;
                    match (flow_src_key, flow_dst_key) {
                        (ServiceKey::V4(flow_src_key), ServiceKey::V4(flow_dst_key)) => {
                            self.ipv4.put(flow_src_key, flow_src_score);
                            self.ipv4.pop(&flow_dst_key);
                        }
                        (ServiceKey::V6(flow_src_key), ServiceKey::V6(flow_dst_key)) => {
                            self.ipv6.put(flow_src_key, flow_src_score);
                            self.ipv6.pop(&flow_dst_key);
                        }
                        _ => unimplemented!(),
                    }
                    (flow_src_score, flow_dst_score)
                }
                PacketDirection::ServerToClient => {
                    flow_src_score = Self::MIN_SCORE;
                    flow_dst_score = Self::MAX_SCORE;
                    match (flow_src_key, flow_dst_key) {
                        (ServiceKey::V4(flow_src_key), ServiceKey::V4(flow_dst_key)) => {
                            self.ipv4.put(flow_src_key, flow_src_score);
                            self.ipv4.pop(&flow_dst_key);
                        }
                        (ServiceKey::V6(flow_src_key), ServiceKey::V6(flow_dst_key)) => {
                            self.ipv6.put(flow_src_key, flow_src_score);
                            self.ipv6.pop(&flow_dst_key);
                        }
                        _ => unimplemented!(),
                    }
                    (flow_src_score, flow_dst_score)
                }
            }
        } else {
            match (flow_src_key, flow_dst_key) {
                (ServiceKey::V4(flow_src_key), ServiceKey::V4(flow_dst_key)) => {
                    if let Some(score) = self.ipv4.get(&flow_src_key) {
                        flow_src_score = *score;
                    }
                    if let Some(score) = self.ipv4.get(&flow_dst_key) {
                        flow_dst_score = *score;
                    }

                    self.adjust_score(
                        flow_src_key.port,
                        flow_dst_key.port,
                        flow_src_score,
                        flow_dst_score,
                    )
                }
                (ServiceKey::V6(flow_src_key), ServiceKey::V6(flow_dst_key)) => {
                    if let Some(score) = self.ipv6.get(&flow_src_key) {
                        flow_src_score = *score;
                    }
                    if let Some(score) = self.ipv6.get(&flow_dst_key) {
                        flow_dst_score = *score;
                    }

                    (flow_src_score, flow_dst_score)
                }
                _ => unimplemented!(),
            }
        }
    }

    pub fn get_udp_score(
        &mut self,
        is_first_packet: bool,
        need_reverse_flow: bool,
        direction: PacketDirection,
        flow_src_key: ServiceKey,
        flow_dst_key: ServiceKey,
    ) -> (u8, u8) {
        if is_first_packet {
            return self.get_first_packet_score(flow_src_key, flow_dst_key);
        }

        let (mut flow_src_score, mut flow_dst_score) = (Self::MIN_SCORE, Self::MIN_SCORE);
        match (flow_src_key, flow_dst_key) {
            (ServiceKey::V4(flow_src_key), ServiceKey::V4(flow_dst_key)) => {
                if need_reverse_flow {
                    match direction {
                        PacketDirection::ClientToServer => {
                            flow_src_score = Self::MAX_SCORE;
                            self.ipv4.put(flow_src_key, flow_src_score);
                        }
                        PacketDirection::ServerToClient => {
                            flow_dst_score = Self::MAX_SCORE;
                            self.ipv4.put(flow_dst_key, flow_dst_score);
                        }
                    }
                    return (flow_src_score, flow_dst_score);
                }

                if let Some(score) = self.ipv4.get(&flow_src_key) {
                    flow_src_score = *score;
                }
                if let Some(score) = self.ipv4.get(&flow_dst_key) {
                    flow_dst_score = *score;
                }

                self.adjust_score(
                    flow_src_key.port,
                    flow_dst_key.port,
                    flow_src_score,
                    flow_dst_score,
                )
            }
            (ServiceKey::V6(flow_src_key), ServiceKey::V6(flow_dst_key)) => {
                if need_reverse_flow {
                    match direction {
                        PacketDirection::ClientToServer => {
                            flow_src_score = Self::MAX_SCORE;
                            self.ipv6.put(flow_src_key, flow_src_score);
                        }
                        PacketDirection::ServerToClient => {
                            flow_dst_score = Self::MAX_SCORE;
                            self.ipv6.put(flow_dst_key, flow_dst_score);
                        }
                    }
                    return (flow_src_score, flow_dst_score);
                }

                if let Some(score) = self.ipv6.get(&flow_src_key) {
                    flow_src_score = *score;
                }
                if let Some(score) = self.ipv6.get(&flow_dst_key) {
                    flow_dst_score = *score;
                }

                (flow_src_score, flow_dst_score)
            }
            _ => unimplemented!(),
        }
    }

    pub fn is_client_to_server(flow_src_score: u8, flow_dst_score: u8) -> bool {
        flow_src_score <= flow_dst_score // 分数相等也认为是C2S，避免reverse Flow
    }

    pub fn is_active_service(flow_dst_score: u8) -> bool {
        flow_dst_score == Self::MAX_SCORE
    }

    pub fn is_ebpf_active_udp_service(
        &mut self,
        flow_src_key: ServiceKey,
        flow_dst_key: ServiceKey,
        direction: PacketDirection,
    ) -> bool {
        if direction == PacketDirection::ClientToServer {
            // if direction is ClientToServer, use dst_key which contains server ip and server port
            return match flow_dst_key {
                ServiceKey::V4(flow_dst_key) => {
                    let mut flow_dst_score = 0;
                    if let Some(score) = self.ipv4.get(&flow_dst_key) {
                        flow_dst_score = *score;
                    }
                    flow_dst_score > 0
                }
                ServiceKey::V6(flow_dst_key) => {
                    let mut flow_dst_score = 0;
                    if let Some(score) = self.ipv6.get(&flow_dst_key) {
                        flow_dst_score = *score;
                    }
                    flow_dst_score > 0
                }
            };
        } else {
            match flow_src_key {
                ServiceKey::V4(flow_src_key) => {
                    self.ipv4.put(flow_src_key, 1);
                }
                ServiceKey::V6(flow_src_key) => {
                    self.ipv6.put(flow_src_key, 1);
                }
            }
            return true;
        }
    }

    fn get_first_packet_score(
        &mut self,
        flow_src_key: ServiceKey,
        flow_dst_key: ServiceKey,
    ) -> (u8, u8) {
        let (mut flow_src_score, mut flow_dst_score) = (Self::MIN_SCORE, Self::MIN_SCORE);

        match (flow_src_key, flow_dst_key) {
            (ServiceKey::V4(flow_src_key), ServiceKey::V4(flow_dst_key)) => {
                if self.port_map.contains(&flow_src_key.port) {
                    flow_src_score = Self::MAX_SCORE_FROM_CONFIG;
                } else if let Some(score) = self.ipv4.get(&flow_src_key) {
                    flow_src_score = *score;
                }
                if self.port_map.contains(&flow_dst_key.port) {
                    flow_dst_score = Self::MAX_SCORE_FROM_CONFIG;
                } else if let Some(score) = self.ipv4.get(&flow_dst_key) {
                    flow_dst_score = *score;
                }
                if flow_src_score == Self::MAX_SCORE || flow_dst_score == Self::MAX_SCORE {
                    // 一旦有一侧发送过SYN|ACK，无需更新
                    return (flow_src_score, flow_dst_score);
                }

                if flow_src_score > Self::MIN_SCORE {
                    flow_src_score -= 1;
                    if flow_src_score > Self::MIN_SCORE {
                        self.ipv4.put(flow_src_key, flow_src_score);
                    } else {
                        self.ipv4.pop(&flow_src_key);
                    }
                }

                if flow_dst_score < Self::MAX_SCORE - 1 {
                    flow_dst_score += 1;
                    self.ipv4.put(flow_dst_key, flow_dst_score);
                }

                self.adjust_score(
                    flow_src_key.port,
                    flow_dst_key.port,
                    flow_src_score,
                    flow_dst_score,
                )
            }
            (ServiceKey::V6(flow_src_key), ServiceKey::V6(flow_dst_key)) => {
                if self.port_map.contains(&flow_src_key.port) {
                    flow_src_score = Self::MAX_SCORE_FROM_CONFIG;
                } else if let Some(score) = self.ipv6.get(&flow_src_key) {
                    flow_src_score = *score;
                }
                if self.port_map.contains(&flow_dst_key.port) {
                    flow_dst_score = Self::MAX_SCORE_FROM_CONFIG;
                } else if let Some(score) = self.ipv6.get(&flow_dst_key) {
                    flow_dst_score = *score;
                }
                if flow_src_score == Self::MAX_SCORE || flow_dst_score == Self::MAX_SCORE {
                    // 一旦有一侧发送过SYN|ACK，无需更新
                    return (flow_src_score, flow_dst_score);
                }

                if flow_src_score > Self::MIN_SCORE {
                    flow_src_score -= 1;
                    if flow_src_score > Self::MIN_SCORE {
                        self.ipv6.put(flow_src_key, flow_src_score);
                    } else {
                        self.ipv6.pop(&flow_src_key);
                    }
                }

                if flow_dst_score < Self::MAX_SCORE - 1 {
                    flow_dst_score += 1;
                    self.ipv6.put(flow_dst_key, flow_dst_score);
                }

                (flow_src_score, flow_dst_score)
            }
            _ => unimplemented!(),
        }
    }

    fn adjust_score(
        &mut self,
        flow_src_port: u16,
        flow_dst_port: u16,
        flow_src_score: u8,
        flow_dst_score: u8,
    ) -> (u8, u8) {
        let diff_value = if flow_src_score > flow_dst_score {
            flow_src_score - flow_dst_score
        } else {
            flow_dst_score - flow_src_score
        };

        if diff_value < Self::SCORE_DIFF_THRESHOLD {
            // 两个端口一个小于32768，一个大于等于32768时进行校正
            // 参考：Many Linux kernels use the port range 32768–60999：https://en.wikipedia.org/wiki/Ephemeral_port
            if (flow_src_port ^ flow_dst_port) & Self::PORT_MSB != 0 {
                if flow_src_port & Self::PORT_MSB > 0 {
                    return (0, 1);
                } else {
                    return (1, 0);
                }
            }
        }

        (flow_src_score, flow_dst_score)
    }

    pub fn get_ebpf_tcp_score(
        &mut self,
        socket_role: u8,
        l2_end_0: bool,
        l2_end_1: bool,
        flow_src_key: ServiceKey,
        flow_dst_key: ServiceKey,
    ) -> (u8, bool) {
        let score;
        let mut need_reverse = false;
        match (flow_src_key, flow_dst_key) {
            (ServiceKey::V4(flow_src_key), ServiceKey::V4(flow_dst_key)) => {
                // socket_role: 0:unknown 1:client(connect) 2:server(accept)
                // if socket_role > 0, indicating that socket was established by connect
                // or accept, and we can determine the direction by l2_end_0 and l2_end_1
                if socket_role == 1 && l2_end_0 {
                    self.ipv4.put(flow_dst_key, Self::MAX_SCORE);
                    self.ipv4.pop(&flow_src_key);
                    score = Self::MAX_SCORE;
                } else if socket_role == 1 && l2_end_1 {
                    self.ipv4.put(flow_src_key, Self::MAX_SCORE);
                    self.ipv4.pop(&flow_dst_key);
                    score = Self::MAX_SCORE;
                    need_reverse = true;
                } else if socket_role == 2 && l2_end_1 {
                    self.ipv4.put(flow_dst_key, Self::MAX_SCORE);
                    self.ipv4.pop(&flow_src_key);
                    score = Self::MAX_SCORE;
                } else if socket_role == 2 && l2_end_0 {
                    self.ipv4.put(flow_src_key, Self::MAX_SCORE);
                    self.ipv4.pop(&flow_dst_key);
                    score = Self::MAX_SCORE;
                    need_reverse = true;
                } else {
                    let source_score = if self.port_map.contains(&flow_src_key.port) {
                        Self::MAX_SCORE_FROM_CONFIG
                    } else if let Some(s) = self.ipv4.get(&flow_src_key) {
                        *s
                    } else {
                        0
                    };

                    let dest_score = if self.port_map.contains(&flow_dst_key.port) {
                        Self::MAX_SCORE_FROM_CONFIG
                    } else if let Some(s) = self.ipv4.get(&flow_dst_key) {
                        *s
                    } else {
                        0
                    };

                    need_reverse = source_score > dest_score;
                    score = source_score.max(dest_score);
                }
            }
            (ServiceKey::V6(flow_src_key), ServiceKey::V6(flow_dst_key)) => {
                if socket_role == 1 && l2_end_0 {
                    self.ipv6.put(flow_dst_key, Self::MAX_SCORE);
                    self.ipv6.pop(&flow_src_key);
                    score = Self::MAX_SCORE;
                } else if socket_role == 1 && l2_end_1 {
                    self.ipv6.put(flow_src_key, Self::MAX_SCORE);
                    self.ipv6.pop(&flow_dst_key);
                    score = Self::MAX_SCORE;
                    need_reverse = true;
                } else if socket_role == 2 && l2_end_1 {
                    self.ipv6.put(flow_dst_key, Self::MAX_SCORE);
                    self.ipv6.pop(&flow_src_key);
                    score = Self::MAX_SCORE;
                } else if socket_role == 2 && l2_end_0 {
                    self.ipv6.put(flow_src_key, Self::MAX_SCORE);
                    self.ipv6.pop(&flow_dst_key);
                    score = Self::MAX_SCORE;
                    need_reverse = true;
                } else {
                    let source_score = if self.port_map.contains(&flow_src_key.port) {
                        Self::MAX_SCORE_FROM_CONFIG
                    } else if let Some(s) = self.ipv6.get(&flow_src_key) {
                        *s
                    } else {
                        0
                    };

                    let dest_score = if self.port_map.contains(&flow_dst_key.port) {
                        Self::MAX_SCORE_FROM_CONFIG
                    } else if let Some(s) = self.ipv6.get(&flow_dst_key) {
                        *s
                    } else {
                        0
                    };

                    need_reverse = source_score > dest_score;
                    score = source_score.max(dest_score);
                }
            }
            _ => unimplemented!(),
        }
        (score, need_reverse)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        str::FromStr,
    };

    use super::*;
    use crate::common::endpoint::EPC_DEEPFLOW;

    #[test]
    fn service_key() {
        let key1 = Ipv4Key::new(Ipv4Addr::new(192, 168, 1, 1), EPC_DEEPFLOW as i16, 80);
        let key2 = Ipv4Key::new(Ipv4Addr::new(192, 168, 1, 1), EPC_DEEPFLOW as i16, 8080);
        assert_ne!(key1, key2);
        let key1 = Ipv6Key::new(
            Ipv6Addr::from_str("1002:1003:4421:5566:7788:99aa:bbcc:ddee").unwrap(),
            EPC_DEEPFLOW as i16,
            80,
        );
        let key2 = Ipv6Key::new(
            Ipv6Addr::from_str("1002:1003:4421:5566:7788:99aa:bbcc:ddee").unwrap(),
            EPC_DEEPFLOW as i16,
            8080,
        );
        assert_ne!(key1, key2);
    }

    #[test]
    fn get_tcp_score() {
        let key_pairs = vec![
            (
                ServiceKey::new(
                    Ipv6Addr::from_str("1002:1003:4421:5566:7788:99aa:bbcc:ddee")
                        .unwrap()
                        .into(),
                    EPC_DEEPFLOW as i16,
                    1234,
                ),
                ServiceKey::new(
                    Ipv6Addr::from_str("1002:1003:4421:5566:7788:99aa:bbcc:ddee")
                        .unwrap()
                        .into(),
                    EPC_DEEPFLOW as i16,
                    80,
                ),
            ),
            (
                ServiceKey::new(
                    Ipv4Addr::new(192, 168, 1, 1).into(),
                    EPC_DEEPFLOW as i16,
                    1234,
                ),
                ServiceKey::new(
                    Ipv4Addr::new(192, 168, 1, 10).into(),
                    EPC_DEEPFLOW as i16,
                    80,
                ),
            ),
        ];

        let mut table = ServiceTable::new(10, 10, &vec![]);
        for (src_key, dst_key) in key_pairs {
            let (src_score, dst_score) = table.get_tcp_score(
                true,
                false,
                PacketDirection::ClientToServer,
                TcpFlags::SYN_ACK,
                false,
                false,
                src_key,
                dst_key,
            );
            assert!(
                src_score == ServiceTable::MAX_SCORE && dst_score == ServiceTable::MIN_SCORE,
                "对SYN|ACK判断不正确"
            );
            let (src_score, dst_score) = table.get_tcp_score(
                false,
                false,
                PacketDirection::ClientToServer,
                TcpFlags::SYN_ACK,
                false,
                false,
                src_key,
                dst_key,
            );
            assert!(
                src_score == ServiceTable::MAX_SCORE && dst_score == ServiceTable::MIN_SCORE,
                "对SYN|ACK判断不正确"
            );

            let (src_score, dst_score) = table.get_tcp_score(
                true,
                false,
                PacketDirection::ClientToServer,
                TcpFlags::empty(),
                false,
                false,
                src_key,
                dst_key,
            );
            assert!(
                src_score == ServiceTable::MAX_SCORE && dst_score == ServiceTable::MIN_SCORE,
                "其它Flag首包预期不能改变SYN|ACK的Score"
            );

            let (src_score, dst_score) = table.get_tcp_score(
                false,
                false,
                PacketDirection::ClientToServer,
                TcpFlags::empty(),
                false,
                false,
                src_key,
                dst_key,
            );
            assert!(
                src_score == ServiceTable::MAX_SCORE && dst_score == ServiceTable::MIN_SCORE,
                "其它Flag非首包预期不能改变SYN|ACK的Score"
            );

            let (src_score, dst_score) = table.get_tcp_score(
                true,
                false,
                PacketDirection::ClientToServer,
                TcpFlags::SYN,
                false,
                false,
                src_key,
                dst_key,
            );
            assert!(
                src_score == ServiceTable::MIN_SCORE && dst_score == ServiceTable::MIN_SCORE + 1,
                "对SYN判断不正确"
            );

            let (src_score, dst_score) = table.get_tcp_score(
                false,
                false,
                PacketDirection::ClientToServer,
                TcpFlags::SYN,
                false,
                false,
                src_key,
                dst_key,
            );
            assert!(
                src_score == ServiceTable::MIN_SCORE && dst_score == ServiceTable::MIN_SCORE + 1,
                "对SYN判断不正确"
            );
            let (src_score, dst_score) = table.get_tcp_score(
                true,
                false,
                PacketDirection::ClientToServer,
                TcpFlags::empty(),
                false,
                false,
                src_key,
                dst_key,
            );
            assert!(
                src_score == ServiceTable::MIN_SCORE && dst_score == ServiceTable::MIN_SCORE + 2,
                "对其它Flag首包的判断不正确"
            );

            let (src_score, dst_score) = table.get_tcp_score(
                false,
                false,
                PacketDirection::ClientToServer,
                TcpFlags::empty(),
                false,
                false,
                src_key,
                dst_key,
            );
            assert!(
                src_score == ServiceTable::MIN_SCORE && dst_score == ServiceTable::MIN_SCORE + 2,
                "对其它Flag非首包的判断不正确"
            );
        }
    }

    #[test]
    fn get_udp_score() {
        let key_pairs = vec![
            (
                ServiceKey::new(
                    Ipv6Addr::from_str("1002:1003:4421:5566:7788:99aa:bbcc:ddee")
                        .unwrap()
                        .into(),
                    EPC_DEEPFLOW as i16,
                    1234,
                ),
                ServiceKey::new(
                    Ipv6Addr::from_str("1002:1003:4421:5566:7788:99aa:bbcc:ddee")
                        .unwrap()
                        .into(),
                    EPC_DEEPFLOW as i16,
                    53,
                ),
            ),
            (
                ServiceKey::new(
                    Ipv4Addr::new(192, 168, 1, 1).into(),
                    EPC_DEEPFLOW as i16,
                    1234,
                ),
                ServiceKey::new(
                    Ipv4Addr::new(192, 168, 1, 10).into(),
                    EPC_DEEPFLOW as i16,
                    53,
                ),
            ),
        ];

        let mut table = ServiceTable::new(10, 10, &vec![]);
        for (src_key, dst_key) in key_pairs {
            let (src_score, dst_score) = table.get_udp_score(
                true,
                false,
                PacketDirection::ClientToServer,
                src_key,
                dst_key,
            );
            assert!(
                src_score == ServiceTable::MIN_SCORE && dst_score == ServiceTable::MIN_SCORE + 1,
                "对UDP首包的判断不正确"
            );
            let (src_score, dst_score) = table.get_udp_score(
                false,
                false,
                PacketDirection::ClientToServer,
                src_key,
                dst_key,
            );
            assert!(
                src_score == ServiceTable::MIN_SCORE && dst_score == ServiceTable::MIN_SCORE + 1,
                "对UDP非首包的判断不正确"
            );
            let (src_score, dst_score) = table.get_udp_score(
                true,
                false,
                PacketDirection::ClientToServer,
                src_key,
                dst_key,
            );
            assert!(
                src_score == ServiceTable::MIN_SCORE && dst_score == ServiceTable::MIN_SCORE + 2,
                "对UDP非首包累加的判断不正确"
            );
        }
    }

    #[test]
    fn port_map() {
        let server_port = vec![80];
        let mut table = ServiceTable::new(10, 10, &server_port);
        let flow_src_key = ServiceKey::new(
            Ipv6Addr::from_str("1002:1003:4421:5566:7788:99aa:bbcc:ddee")
                .unwrap()
                .into(),
            EPC_DEEPFLOW as i16,
            80,
        );
        let flow_dst_key = ServiceKey::new(
            Ipv6Addr::from_str("1002:1003:4421:5566:7788:99aa:bbcc:ddee")
                .unwrap()
                .into(),
            EPC_DEEPFLOW as i16,
            53,
        );

        let (src_score, _) = table.get_tcp_score(
            true,
            false,
            PacketDirection::ClientToServer,
            TcpFlags::PSH,
            false,
            false,
            flow_src_key,
            flow_dst_key,
        );
        assert_eq!(src_score, ServiceTable::MAX_SCORE_FROM_CONFIG - 1);
        let (src_score, dst_score) = table.get_tcp_score(
            false,
            false,
            PacketDirection::ClientToServer,
            TcpFlags::SYN_ACK,
            false,
            false,
            flow_dst_key,
            flow_src_key,
        );
        assert_eq!(src_score, ServiceTable::MAX_SCORE);
        assert_eq!(dst_score, 0);

        let (src_score, dst_score) = table.get_tcp_score(
            true,
            false,
            PacketDirection::ClientToServer,
            TcpFlags::PSH,
            false,
            false,
            flow_src_key,
            flow_dst_key,
        );
        assert_eq!(src_score, ServiceTable::MAX_SCORE_FROM_CONFIG);
        assert_eq!(dst_score, ServiceTable::MAX_SCORE);

        let (src_score, dst_score) = table.get_tcp_score(
            false,
            false,
            PacketDirection::ClientToServer,
            TcpFlags::PSH,
            false,
            false,
            flow_src_key,
            flow_dst_key,
        );
        assert_eq!(src_score, 0);
        assert_eq!(dst_score, ServiceTable::MAX_SCORE);

        let (score, reverse) = table.get_ebpf_tcp_score(0, true, false, flow_dst_key, flow_src_key);
        assert_eq!(score, ServiceTable::MAX_SCORE);
        assert_eq!(reverse, true);
    }
}
