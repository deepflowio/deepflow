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

use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
}

impl ServiceTable {
    const MIN_SCORE: u8 = 0;
    const MAX_SCORE: u8 = 0xff;
    const SCORE_DIFF_THRESHOLD: u8 = 8;
    const PORT_MSB: u16 = 1 << 15;

    pub fn new(ipv4_capacity: usize, ipv6_capacity: usize) -> Self {
        Self {
            ipv4: LruCache::new(ipv4_capacity),
            ipv6: LruCache::new(ipv6_capacity),
        }
    }

    pub fn get_tcp_score(
        &mut self,
        is_first_packet: bool,
        has_toa: bool,
        tcp_flags: TcpFlags,
        src_key: ServiceKey,
        dst_key: ServiceKey,
    ) -> (u8, u8) {
        let (mut src_score, mut dst_score) = (Self::MIN_SCORE, Self::MIN_SCORE);

        if tcp_flags.contains(TcpFlags::SYN_ACK) {
            // 一旦发送SYN|ACK，即被认为是服务端，其对侧被认为不可能是服务端
            src_score = Self::MAX_SCORE;
            dst_score = Self::MIN_SCORE;
            match (src_key, dst_key) {
                (ServiceKey::V4(src_key), ServiceKey::V4(dst_key)) => {
                    self.ipv4.put(src_key, src_score);
                    self.ipv4.pop(&dst_key);
                }
                (ServiceKey::V6(src_key), ServiceKey::V6(dst_key)) => {
                    self.ipv6.put(src_key, src_score);
                    self.ipv6.pop(&dst_key);
                }
                _ => unimplemented!(),
            }
            (src_score, dst_score)
        } else if tcp_flags.contains(TcpFlags::SYN) || has_toa {
            // It must be the client when packet has SYN or TOA.
            src_score = Self::MIN_SCORE;

            match (src_key, dst_key) {
                (ServiceKey::V4(src_key), ServiceKey::V4(dst_key)) => {
                    self.ipv4.pop(&src_key);

                    if let Some(score) = self.ipv4.get(&dst_key) {
                        dst_score = *score;
                    }
                    if is_first_packet && dst_score < Self::MAX_SCORE - 1 {
                        dst_score += 1;
                        self.ipv4.put(dst_key, dst_score);
                    }
                }
                (ServiceKey::V6(src_key), ServiceKey::V6(dst_key)) => {
                    self.ipv6.pop(&src_key);

                    if let Some(score) = self.ipv6.get(&dst_key) {
                        dst_score = *score;
                    }
                    if is_first_packet && dst_score < Self::MAX_SCORE - 1 {
                        dst_score += 1;
                        self.ipv6.put(dst_key, dst_score);
                    }
                }
                _ => unimplemented!(),
            }

            (src_score, dst_score)
        } else if is_first_packet {
            self.get_first_packet_score(src_key, dst_key)
        } else {
            match (src_key, dst_key) {
                (ServiceKey::V4(src_key), ServiceKey::V4(dst_key)) => {
                    if let Some(score) = self.ipv4.get(&src_key) {
                        src_score = *score;
                    }
                    if let Some(score) = self.ipv4.get(&dst_key) {
                        dst_score = *score;
                    }

                    self.adjust_score(src_key.port, dst_key.port, src_score, dst_score)
                }
                (ServiceKey::V6(src_key), ServiceKey::V6(dst_key)) => {
                    if let Some(score) = self.ipv6.get(&src_key) {
                        src_score = *score;
                    }
                    if let Some(score) = self.ipv6.get(&dst_key) {
                        dst_score = *score;
                    }

                    (src_score, dst_score)
                }
                _ => unimplemented!(),
            }
        }
    }

    pub fn get_udp_score(
        &mut self,
        is_first_packet: bool,
        src_key: ServiceKey,
        dst_key: ServiceKey,
    ) -> (u8, u8) {
        if is_first_packet {
            return self.get_first_packet_score(src_key, dst_key);
        }

        let (mut src_score, mut dst_score) = (Self::MIN_SCORE, Self::MIN_SCORE);
        match (src_key, dst_key) {
            (ServiceKey::V4(src_key), ServiceKey::V4(dst_key)) => {
                if let Some(score) = self.ipv4.get(&src_key) {
                    src_score = *score;
                }
                if let Some(score) = self.ipv4.get(&dst_key) {
                    dst_score = *score;
                }

                self.adjust_score(src_key.port, dst_key.port, src_score, dst_score)
            }
            (ServiceKey::V6(src_key), ServiceKey::V6(dst_key)) => {
                if let Some(score) = self.ipv6.get(&src_key) {
                    src_score = *score;
                }
                if let Some(score) = self.ipv6.get(&dst_key) {
                    dst_score = *score;
                }

                (src_score, dst_score)
            }
            _ => unimplemented!(),
        }
    }

    pub fn is_client_to_server(src_score: u8, dst_score: u8) -> bool {
        src_score <= dst_score // 分数相等也认为是C2S，避免reverse Flow
    }

    pub fn is_active_service(dst_score: u8) -> bool {
        dst_score == Self::MAX_SCORE
    }

    pub fn is_ebpf_active_udp_service(
        &mut self,
        src_key: ServiceKey,
        dst_key: ServiceKey,
        direction: PacketDirection,
    ) -> bool {
        if direction == PacketDirection::ClientToServer {
            // if direction is ClientToServer, use dst_key which contains server ip and server port
            return match dst_key {
                ServiceKey::V4(dst_key) => {
                    let mut dst_score = 0;
                    if let Some(score) = self.ipv4.get(&dst_key) {
                        dst_score = *score;
                    }
                    dst_score > 0
                }
                ServiceKey::V6(dst_key) => {
                    let mut dst_score = 0;
                    if let Some(score) = self.ipv6.get(&dst_key) {
                        dst_score = *score;
                    }
                    dst_score > 0
                }
            };
        } else {
            match src_key {
                ServiceKey::V4(src_key) => {
                    self.ipv4.put(src_key, 1);
                }
                ServiceKey::V6(src_key) => {
                    self.ipv6.put(src_key, 1);
                }
            }
            return true;
        }
    }

    fn get_first_packet_score(&mut self, src_key: ServiceKey, dst_key: ServiceKey) -> (u8, u8) {
        let (mut src_score, mut dst_score) = (Self::MIN_SCORE, Self::MIN_SCORE);

        match (src_key, dst_key) {
            (ServiceKey::V4(src_key), ServiceKey::V4(dst_key)) => {
                if let Some(score) = self.ipv4.get(&src_key) {
                    src_score = *score;
                }
                if let Some(score) = self.ipv4.get(&dst_key) {
                    dst_score = *score;
                }
                if src_score == Self::MAX_SCORE || dst_score == Self::MAX_SCORE {
                    // 一旦有一侧发送过SYN|ACK，无需更新
                    return (src_score, dst_score);
                }

                if src_score > Self::MIN_SCORE {
                    src_score -= 1;
                    if src_score > Self::MIN_SCORE {
                        self.ipv4.put(src_key, src_score);
                    } else {
                        self.ipv4.pop(&src_key);
                    }
                }

                if dst_score < Self::MAX_SCORE - 1 {
                    dst_score += 1;
                    self.ipv4.put(dst_key, dst_score);
                }

                self.adjust_score(src_key.port, dst_key.port, src_score, dst_score)
            }
            (ServiceKey::V6(src_key), ServiceKey::V6(dst_key)) => {
                if let Some(score) = self.ipv6.get(&src_key) {
                    src_score = *score;
                }
                if let Some(score) = self.ipv6.get(&dst_key) {
                    dst_score = *score;
                }
                if src_score == Self::MAX_SCORE || dst_score == Self::MAX_SCORE {
                    // 一旦有一侧发送过SYN|ACK，无需更新
                    return (src_score, dst_score);
                }

                if src_score > Self::MIN_SCORE {
                    src_score -= 1;
                    if src_score > Self::MIN_SCORE {
                        self.ipv6.put(src_key, src_score);
                    } else {
                        self.ipv6.pop(&src_key);
                    }
                }

                if dst_score < Self::MAX_SCORE - 1 {
                    dst_score += 1;
                    self.ipv6.put(dst_key, dst_score);
                }

                (src_score, dst_score)
            }
            _ => unimplemented!(),
        }
    }

    fn adjust_score(
        &mut self,
        src_port: u16,
        dst_port: u16,
        src_score: u8,
        dst_score: u8,
    ) -> (u8, u8) {
        let diff_value = if src_score > dst_score {
            src_score - dst_score
        } else {
            dst_score - src_score
        };

        if diff_value < Self::SCORE_DIFF_THRESHOLD {
            // 两个端口一个小于32768，一个大于等于32768时进行校正
            // 参考：Many Linux kernels use the port range 32768–60999：https://en.wikipedia.org/wiki/Ephemeral_port
            if (src_port ^ dst_port) & Self::PORT_MSB != 0 {
                if src_port & Self::PORT_MSB > 0 {
                    return (0, 1);
                } else {
                    return (1, 0);
                }
            }
        }

        (src_score, dst_score)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        str::FromStr,
    };

    use super::*;
    use crate::common::endpoint::EPC_FROM_DEEPFLOW;

    #[test]
    fn service_key() {
        let key1 = Ipv4Key::new(Ipv4Addr::new(192, 168, 1, 1), EPC_FROM_DEEPFLOW as i16, 80);
        let key2 = Ipv4Key::new(
            Ipv4Addr::new(192, 168, 1, 1),
            EPC_FROM_DEEPFLOW as i16,
            8080,
        );
        assert_ne!(key1, key2);
        let key1 = Ipv6Key::new(
            Ipv6Addr::from_str("1002:1003:4421:5566:7788:99aa:bbcc:ddee").unwrap(),
            EPC_FROM_DEEPFLOW as i16,
            80,
        );
        let key2 = Ipv6Key::new(
            Ipv6Addr::from_str("1002:1003:4421:5566:7788:99aa:bbcc:ddee").unwrap(),
            EPC_FROM_DEEPFLOW as i16,
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
                    EPC_FROM_DEEPFLOW as i16,
                    1234,
                ),
                ServiceKey::new(
                    Ipv6Addr::from_str("1002:1003:4421:5566:7788:99aa:bbcc:ddee")
                        .unwrap()
                        .into(),
                    EPC_FROM_DEEPFLOW as i16,
                    80,
                ),
            ),
            (
                ServiceKey::new(
                    Ipv4Addr::new(192, 168, 1, 1).into(),
                    EPC_FROM_DEEPFLOW as i16,
                    1234,
                ),
                ServiceKey::new(
                    Ipv4Addr::new(192, 168, 1, 10).into(),
                    EPC_FROM_DEEPFLOW as i16,
                    80,
                ),
            ),
        ];

        let mut table = ServiceTable::new(10, 10);
        for (src_key, dst_key) in key_pairs {
            let (src_score, dst_score) =
                table.get_tcp_score(true, false, TcpFlags::SYN_ACK, src_key, dst_key);
            assert!(
                src_score == ServiceTable::MAX_SCORE && dst_score == ServiceTable::MIN_SCORE,
                "对SYN|ACK判断不正确"
            );
            let (src_score, dst_score) =
                table.get_tcp_score(false, false, TcpFlags::SYN_ACK, src_key, dst_key);
            assert!(
                src_score == ServiceTable::MAX_SCORE && dst_score == ServiceTable::MIN_SCORE,
                "对SYN|ACK判断不正确"
            );

            let (src_score, dst_score) =
                table.get_tcp_score(true, false, TcpFlags::empty(), src_key, dst_key);
            assert!(
                src_score == ServiceTable::MAX_SCORE && dst_score == ServiceTable::MIN_SCORE,
                "其它Flag首包预期不能改变SYN|ACK的Score"
            );

            let (src_score, dst_score) =
                table.get_tcp_score(false, false, TcpFlags::empty(), src_key, dst_key);
            assert!(
                src_score == ServiceTable::MAX_SCORE && dst_score == ServiceTable::MIN_SCORE,
                "其它Flag非首包预期不能改变SYN|ACK的Score"
            );

            let (src_score, dst_score) =
                table.get_tcp_score(true, false, TcpFlags::SYN, src_key, dst_key);
            assert!(
                src_score == ServiceTable::MIN_SCORE && dst_score == ServiceTable::MIN_SCORE + 1,
                "对SYN判断不正确"
            );

            let (src_score, dst_score) =
                table.get_tcp_score(false, false, TcpFlags::SYN, src_key, dst_key);
            assert!(
                src_score == ServiceTable::MIN_SCORE && dst_score == ServiceTable::MIN_SCORE + 1,
                "对SYN判断不正确"
            );
            let (src_score, dst_score) =
                table.get_tcp_score(true, false, TcpFlags::empty(), src_key, dst_key);
            assert!(
                src_score == ServiceTable::MIN_SCORE && dst_score == ServiceTable::MIN_SCORE + 2,
                "对其它Flag首包的判断不正确"
            );

            let (src_score, dst_score) =
                table.get_tcp_score(false, false, TcpFlags::empty(), src_key, dst_key);
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
                    EPC_FROM_DEEPFLOW as i16,
                    1234,
                ),
                ServiceKey::new(
                    Ipv6Addr::from_str("1002:1003:4421:5566:7788:99aa:bbcc:ddee")
                        .unwrap()
                        .into(),
                    EPC_FROM_DEEPFLOW as i16,
                    53,
                ),
            ),
            (
                ServiceKey::new(
                    Ipv4Addr::new(192, 168, 1, 1).into(),
                    EPC_FROM_DEEPFLOW as i16,
                    1234,
                ),
                ServiceKey::new(
                    Ipv4Addr::new(192, 168, 1, 10).into(),
                    EPC_FROM_DEEPFLOW as i16,
                    53,
                ),
            ),
        ];

        let mut table = ServiceTable::new(10, 10);
        for (src_key, dst_key) in key_pairs {
            let (src_score, dst_score) = table.get_udp_score(true, src_key, dst_key);
            assert!(
                src_score == ServiceTable::MIN_SCORE && dst_score == ServiceTable::MIN_SCORE + 1,
                "对UDP首包的判断不正确"
            );
            let (src_score, dst_score) = table.get_udp_score(false, src_key, dst_key);
            assert!(
                src_score == ServiceTable::MIN_SCORE && dst_score == ServiceTable::MIN_SCORE + 1,
                "对UDP非首包的判断不正确"
            );
            let (src_score, dst_score) = table.get_udp_score(true, src_key, dst_key);
            assert!(
                src_score == ServiceTable::MIN_SCORE && dst_score == ServiceTable::MIN_SCORE + 2,
                "对UDP非首包累加的判断不正确"
            );
        }
    }
}
