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

use std::fmt;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, RwLock};

use ahash::AHashMap;
use ipnetwork::IpNetwork;
use log::{debug, error};
use lru::LruCache;
use pnet::datalink::NetworkInterface;

use crate::{
    common::{
        decapsulate::TunnelType, enums::TapType, lookup_key::LookupKey,
        platform_data::PlatformData, TapPort, Timestamp,
    },
    utils::environment::is_tt_workload,
};
use public::proto::common::TridentType;
use public::utils::net::MacAddr;

pub const FROM_CONTROLLER: u16 = 1;
pub const FROM_CONFIG: u16 = 2;
pub const FROM_TRAFFIC_TTL: u16 = 4;
pub const FROM_TRAFFIC_ARP: u16 = 8;
pub const FROM_MAX: u16 = 16;

#[derive(Clone, PartialEq, Eq, Hash)]
struct L3Key {
    ip: IpAddr,
    mac: MacAddr,
}

#[derive(Clone, Copy)]
struct L3Item {
    ip: IpAddr,
    mac: MacAddr,
    epc_id: i32,
    tap_type: TapType,
    tap_port: TapPort,

    last: Timestamp,
    from: u16,
}

impl L3Item {
    fn update(&mut self, other: &L3Item) {
        self.from |= other.from;

        if other.last > self.last {
            self.last = other.last;
        }

        if other.epc_id > 0 {
            self.epc_id = other.epc_id
        }
    }
}

impl fmt::Display for L3Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let from_to_str = [
            "nil",
            "controller",                                // FROM_CONTROLLER
            "config",                                    // FROM_CONFIG:
            "controller|config",                         // FROM_CONTROLLER | FROM_CONFIG:
            "traffic-ttl",                               // FROM_TRAFFIC_TTL:
            "controller|traffic-ttl",                    // FROM_CONTROLLER | FROM_TRAFFIC_TTL:
            "config|traffic-ttl",                        // FROM_CONFIG | FROM_TRAFFIC_TTL:
            "controller|config|traffic-ttl", // FROM_CONTROLLER | FROM_CONFIG | FROM_TRAFFIC_TTL:
            "traffic-arp",                   // FROM_TRAFFIC_ARP:
            "controller|traffic-arp",        // FROM_CONTROLLER | FROM_TRAFFIC_ARP:
            "config|traffic-arp",            // FROM_CONFIG | FROM_TRAFFIC_ARP:
            "controller|config|traffic-arp", // FROM_CONTROLLER | FROM_CONFIG | FROM_TRAFFIC_ARP:
            "traffic-ttl|traffic-arp",       // FROM_TRAFFIC_TTL | FROM_TRAFFIC_ARP:
            "controller|traffic-ttl|traffic-arp", // FROM_CONTROLLER | FROM_TRAFFIC_TTL | FROM_TRAFFIC_ARP:
            "config|traffic-ttl|traffic-arp", // FROM_CONFIG | FROM_TRAFFIC_TTL | FROM_TRAFFIC_ARP:
            "controller|config|traffic-ttl|traffic-arp", // FROM_CONTROLLER | FROM_CONFIG | FROM_TRAFFIC_TTL | FROM_TRAFFIC_ARP:
        ];

        write!(
            f,
            "TapType: {} TapPort: {} EPC: {} MAC: {} IP: {} FROM: {} LAST: {}",
            self.tap_type,
            self.tap_port,
            self.epc_id,
            self.mac,
            self.ip,
            from_to_str[self.from as usize],
            self.last.as_secs()
        )
    }
}

type TableLruCache = LruCache<L3Key, L3Item>;

pub struct Forward {
    mac_ip_tables: RwLock<TableLruCache>,
    vip_device_tables: RwLock<AHashMap<u64, bool>>,

    capacity: usize,
}

impl Forward {
    pub fn new(queue_count: usize, capacity: usize) -> Self {
        assert!(queue_count < super::MAX_QUEUE_COUNT && queue_count > 0);
        Self {
            mac_ip_tables: RwLock::new(TableLruCache::new(NonZeroUsize::new(capacity).unwrap())),
            vip_device_tables: RwLock::new(AHashMap::new()),
            capacity,
        }
    }

    fn update_vip_from_platforms(
        &self,
        table: &mut AHashMap<u64, bool>,
        platforms: &Vec<Arc<PlatformData>>,
    ) {
        for platform in platforms {
            if platform.mac == 0 || !platform.is_vip_interface {
                continue;
            }
            table.insert(platform.mac, true);
        }
    }

    fn update_l3_from_platforms(
        &self,
        table: &mut TableLruCache,
        platforms: &Vec<Arc<PlatformData>>,
    ) {
        debug!("Platform L3:");
        for platform in platforms {
            if platform.mac == 0 {
                continue;
            }
            let mac = MacAddr::try_from(platform.mac);
            if mac.is_err() {
                continue;
            }
            let mac = mac.unwrap();

            for ip in &platform.ips {
                let key = L3Key {
                    ip: ip.raw_ip,
                    mac: mac,
                };
                if let Some(value) = table.get_mut(&key) {
                    value.from |= FROM_CONTROLLER;
                    continue;
                }
                let value = L3Item {
                    epc_id: platform.epc_id,
                    tap_type: TapType::Cloud,
                    tap_port: TapPort::from_local_mac(
                        TapPort::NAT_SOURCE_NONE,
                        TunnelType::None,
                        0,
                    ),
                    last: Timestamp::ZERO,
                    from: FROM_CONTROLLER,
                    ip: ip.raw_ip,
                    mac,
                };
                debug!("\t{} {}", key.mac, key.ip);
                table.push(key, value);
            }
        }
    }

    fn is_link_local(ip_addr: IpAddr) -> bool {
        match ip_addr {
            IpAddr::V4(ip) => ip.is_link_local(),
            IpAddr::V6(ip) => (ip.segments()[0] & 0xffc0) == 0xfe80,
        }
    }

    fn get_ip_from_lookback(
        trident_type: TridentType,
        interfaces: &Vec<NetworkInterface>,
    ) -> Vec<IpNetwork> {
        let mut ips = Vec::new();
        if !is_tt_workload(trident_type) {
            return ips;
        }

        for interface in interfaces {
            if !interface.is_loopback() || !interface.is_up() {
                continue;
            }

            for ip in &interface.ips {
                let ip_addr = ip.ip();
                if ip_addr.is_unspecified() || ip_addr.is_loopback() || Self::is_link_local(ip_addr)
                {
                    continue;
                }
                ips.push(ip.clone())
            }
        }
        return ips;
    }

    fn update_l3_from_interfaces(
        &self,
        trident_type: TridentType,
        table: &mut TableLruCache,
        interfaces: &Vec<NetworkInterface>,
    ) {
        let ips = Self::get_ip_from_lookback(trident_type, interfaces);
        debug!("Interface L3:");
        for interface in interfaces {
            if interface.is_loopback() || !interface.is_up() || interface.mac.is_none() {
                continue;
            }

            let mac = MacAddr::from(interface.mac.unwrap().octets());
            let mut ips = ips.clone();
            interface.ips.iter().for_each(|v| ips.push(v.clone()));
            for ip in &ips {
                let key = L3Key { ip: ip.ip(), mac };
                if let Some(value) = table.get_mut(&key) {
                    value.from |= FROM_CONFIG;
                    continue;
                }
                let value = L3Item {
                    epc_id: 0,
                    tap_type: TapType::Cloud,
                    tap_port: TapPort::from_local_mac(
                        TapPort::NAT_SOURCE_NONE,
                        TunnelType::None,
                        0,
                    ),
                    last: Timestamp::ZERO,
                    from: FROM_CONFIG,
                    ip: ip.ip(),
                    mac,
                };
                debug!("\t{} {}", key.mac, key.ip);
                table.push(key, value);
            }
        }
    }

    pub fn update_from_config(
        &mut self,
        trident_type: TridentType,
        platforms: &Vec<Arc<PlatformData>>,
        interfaces: &Vec<NetworkInterface>,
    ) {
        if platforms.len() + interfaces.len() > self.capacity {
            error!("The capacity({}) of the Forward table will be exceeded, where platforms is {} and interfaces is {}. ",
                self.capacity, platforms.len(), interfaces.len());
        }
        let mut mac_ip_table = self.mac_ip_tables.write().unwrap();
        mac_ip_table.clear();
        self.update_l3_from_platforms(&mut mac_ip_table, platforms);
        self.update_l3_from_interfaces(trident_type, &mut mac_ip_table, interfaces);

        let mut vip_device_table = AHashMap::new();
        self.update_vip_from_platforms(&mut vip_device_table, platforms);
        *self.vip_device_tables.write().unwrap() = vip_device_table
    }

    fn query_vip(&self, mac: MacAddr) -> bool {
        let mac = u64::from(mac);
        return self.vip_device_tables.read().unwrap().get(&mac).is_some();
    }

    pub fn query(&mut self, _index: usize, mac: MacAddr, ip: IpAddr, l2_end: bool) -> bool {
        let key = L3Key { mac, ip };
        if self.mac_ip_tables.read().unwrap().peek(&key).is_none() {
            return l2_end && self.query_vip(mac);
        }

        return true;
    }

    pub fn add(&mut self, _index: usize, packet: &LookupKey, tap_port: TapPort, from: u16) {
        let key = L3Key {
            mac: packet.src_mac,
            ip: packet.src_ip,
        };
        if let Some(value) = self.mac_ip_tables.write().unwrap().get_mut(&key) {
            value.from |= from;
            value.last = packet.timestamp;
            value.tap_type = packet.tap_type;
            value.tap_port = tap_port;
            return;
        }

        let value = L3Item {
            epc_id: 0,
            tap_type: packet.tap_type,
            tap_port,
            last: packet.timestamp,
            from,
            ip: key.ip,
            mac: key.mac,
        };
        self.mac_ip_tables.write().unwrap().push(key, value);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use pnet::datalink;

    use crate::common::decapsulate::TunnelType;
    use crate::common::platform_data::IpSubnet;

    use super::*;

    #[test]
    fn test_forward() {
        let mut forward = Forward::new(3, 1024);
        let interfaces = datalink::interfaces();
        let mut platforms = Vec::new();
        platforms.push(Arc::new(PlatformData {
            mac: 0x112233445566,
            ips: vec![IpSubnet {
                raw_ip: IpAddr::from("10.0.0.10".parse::<Ipv4Addr>().unwrap()),
                ..Default::default()
            }],
            epc_id: 100,
            ..Default::default()
        }));
        platforms.push(Arc::new(PlatformData {
            mac: 0x665544332211,
            ips: vec![IpSubnet {
                raw_ip: IpAddr::from("20.0.0.20".parse::<Ipv4Addr>().unwrap()),
                ..Default::default()
            }],
            epc_id: 100,
            is_vip_interface: true,
            ..Default::default()
        }));

        forward.update_from_config(TridentType::TtHostPod, &platforms, &interfaces);

        // 平台数据查询
        assert_eq!(
            true,
            forward.query(
                0,
                MacAddr::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
                IpAddr::from("10.0.0.10".parse::<Ipv4Addr>().unwrap()),
                false
            )
        );
        // 平台数据VIP查询
        assert_eq!(
            true,
            forward.query(
                1,
                MacAddr::from([0x66, 0x55, 0x44, 0x33, 0x22, 0x11]),
                IpAddr::from("10.0.0.10".parse::<Ipv4Addr>().unwrap()),
                true
            )
        );
        assert_eq!(
            false,
            forward.query(
                2,
                MacAddr::from([0x66, 0x55, 0x44, 0x33, 0x22, 0x11]),
                IpAddr::from("10.0.0.10".parse::<Ipv4Addr>().unwrap()),
                false
            )
        );
        // 本地接口查询
        for i in interfaces {
            if i.is_loopback() || !i.is_up() || i.mac.is_none() || i.ips.len() == 0 {
                continue;
            }
            assert_eq!(
                true,
                forward.query(
                    0,
                    MacAddr::from(i.mac.unwrap().octets()),
                    i.ips.first().unwrap().ip(),
                    false
                )
            );
        }
        // 流量添加查询
        let key = LookupKey {
            src_mac: MacAddr::from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            src_ip: IpAddr::from("192.168.1.10".parse::<Ipv4Addr>().unwrap()),
            ..Default::default()
        };
        forward.add(
            0,
            &key,
            TapPort::from_local_mac(TapPort::NAT_SOURCE_NONE, TunnelType::None, 0xccddeeff),
            FROM_TRAFFIC_TTL,
        );

        assert_eq!(
            true,
            forward.query(
                0,
                MacAddr::from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
                IpAddr::from("192.168.1.10".parse::<Ipv4Addr>().unwrap()),
                false
            )
        );
    }
}
