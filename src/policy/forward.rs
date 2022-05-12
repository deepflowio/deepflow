use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use log::debug;
use lru::LruCache;
use pnet::datalink::NetworkInterface;

use crate::common::decapsulate::TunnelType;
use crate::common::enums::TapType;
use crate::common::lookup_key::LookupKey;
use crate::common::platform_data::PlatformData;
use crate::common::TapPort;
use crate::utils::net::MacAddr;

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

    last: Duration,
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

const MAX_QUEUE_COUNT: usize = 16;

pub struct Forward {
    mac_ip_tables: Vec<Option<Box<TableLruCache>>>,
    vip_device_tables: Option<Box<HashMap<u64, bool>>>,

    queue_count: usize,
}

impl Forward {
    pub fn new(queue_count: usize) -> Self {
        assert!(queue_count < MAX_QUEUE_COUNT && queue_count > 0);
        Self {
            mac_ip_tables: vec![
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None,
            ],
            vip_device_tables: Some(Box::new(HashMap::new())),
            queue_count,
        }
    }

    fn update_vip_from_platforms(
        &self,
        table: &mut HashMap<u64, bool>,
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
                    tap_type: TapType::Tor,
                    tap_port: TapPort::from_local_mac(TunnelType::None, 0),
                    last: Duration::from_secs(0),
                    from: FROM_CONTROLLER,
                    ip: ip.raw_ip,
                    mac,
                };
                debug!("\t{} {}", key.mac, key.ip);
                table.push(key, value);
            }
        }
    }

    fn update_l3_from_interfaces(
        &self,
        table: &mut TableLruCache,
        interfaces: &Vec<NetworkInterface>,
    ) {
        debug!("Interface L3:");
        for interface in interfaces {
            if interface.is_loopback() || !interface.is_up() || interface.mac.is_none() {
                continue;
            }

            let mac = MacAddr::from(interface.mac.unwrap().octets());
            for ip in &interface.ips {
                let key = L3Key { ip: ip.ip(), mac };
                if let Some(value) = table.get_mut(&key) {
                    value.from |= FROM_CONFIG;
                    continue;
                }
                let value = L3Item {
                    epc_id: 0,
                    tap_type: TapType::Tor,
                    tap_port: TapPort::from_local_mac(TunnelType::None, 0),
                    last: Duration::from_secs(0),
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
        platforms: &Vec<Arc<PlatformData>>,
        interfaces: &Vec<NetworkInterface>,
    ) {
        for i in 0..self.queue_count {
            let mut mac_ip_table = TableLruCache::new(1 << 14);
            self.update_l3_from_platforms(&mut mac_ip_table, platforms);
            self.update_l3_from_interfaces(&mut mac_ip_table, interfaces);

            self.mac_ip_tables[i].replace(Box::new(mac_ip_table));
        }

        let mut vip_device_table = HashMap::new();

        self.update_vip_from_platforms(&mut vip_device_table, platforms);
        self.vip_device_tables.replace(Box::new(vip_device_table));
    }

    fn query_vip(&self, mac: MacAddr) -> bool {
        if self.vip_device_tables.is_none() {
            false
        } else {
            let mac = u64::from(mac);
            self.vip_device_tables.as_ref().unwrap().get(&mac).is_some()
        }
    }

    pub fn query(&self, index: usize, mac: MacAddr, ip: IpAddr, l2_end: bool) -> bool {
        let key = L3Key { mac, ip };
        if self.mac_ip_tables[index].is_none() {
            return l2_end && self.query_vip(mac);
        }

        return self.mac_ip_tables[index]
            .as_ref()
            .unwrap()
            .peek(&key)
            .is_some()
            || (l2_end && self.query_vip(mac));
    }

    pub fn add(&mut self, index: usize, packet: &LookupKey, tap_port: TapPort, from: u16) {
        if self.mac_ip_tables[index].is_none() {
            self.mac_ip_tables[index] = Some(Box::new(TableLruCache::new(1 << 14)));
        }

        let key = L3Key {
            mac: packet.src_mac,
            ip: packet.src_ip,
        };
        if let Some(value) = self.mac_ip_tables[index].as_mut().unwrap().get_mut(&key) {
            value.from |= from;
            value.last = packet.timestamp;
            value.tap_type = packet.tap_type;
            value.tap_port = tap_port;
        } else {
            let value = L3Item {
                epc_id: 0,
                tap_type: packet.tap_type,
                tap_port,
                last: packet.timestamp,
                from,
                ip: key.ip,
                mac: key.mac,
            };
            self.mac_ip_tables[index].as_mut().unwrap().push(key, value);
        }
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
        let mut forward = Forward::new(3);
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

        forward.update_from_config(&platforms, &interfaces);

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
            TapPort::from_local_mac(TunnelType::None, 0xccddeeff),
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
