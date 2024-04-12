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

use std::cmp::max;
use std::net::IpAddr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};
use std::thread;
use std::time::Duration;

use ipnet::{IpNet, Ipv4Net};
use log::warn;
use lru::LruCache;

use crate::common::endpoint::{EndpointData, EndpointStore};
use crate::common::lookup_key::LookupKey;
use crate::common::platform_data::PlatformData as Interface;
use crate::common::policy::{Acl, Cidr, IpGroupData};
use crate::common::port_range::{PortRange, PortRangeList};
use npb_pcap_policy::PolicyData;

const MAX_ACL_PROTOCOL: usize = 255;
const MAX_TAP_TYPE: usize = 256;
const MAX_FAST_PATH: usize = MAX_TAP_TYPE * (super::MAX_QUEUE_COUNT + 1);
const NET_IP_MAX: u32 = 32;
const NET_IP_LEN: u32 = 16;
const NET_IP_MASK: u32 = u32::MAX << NET_IP_LEN;

type TableLruCache = LruCache<u128, PolicyTableItem>;

#[derive(Clone, Debug)]
struct PolicyTableItem {
    store: EndpointStore,
    protocol_table: [Option<Arc<PolicyData>>; MAX_ACL_PROTOCOL + 1],
}

pub struct FastPath {
    interest_table: RwLock<Vec<PortRange>>,
    policy_table: Vec<Option<TableLruCache>>,
    // Multi threaded access has thread safety issues, the ebpf
    // table must be accessed by an ebpf dispatcher thread.
    ebpf_table: LruCache<u128, Arc<EndpointData>>,

    // Use the first 16 bits of the IPv4 address to query the table and obtain the corresponding netmask.
    netmask_table: RwLock<Vec<u32>>,

    policy_table_flush_flags: [AtomicBool; super::MAX_QUEUE_COUNT + 1],
    ebpf_table_flush_flag: AtomicBool,

    mask_from_interface: RwLock<Vec<u32>>,
    mask_from_ipgroup: RwLock<Vec<u32>>,
    mask_from_cidr: RwLock<Vec<u32>>,

    map_size: usize,

    // 统计计数
    policy_count: usize,
}

const FLUSH_FLAGS: AtomicBool = AtomicBool::new(false);
impl FastPath {
    // 策略相关等内容更新后必须执行该函数以清空策略表
    pub fn flush(&mut self) {
        self.generate_mask_table();
        self.policy_table_flush_flags.iter_mut().for_each(|f| {
            f.store(true, Ordering::Relaxed);
        });
        self.ebpf_table_flush_flag.store(true, Ordering::Relaxed);
        self.policy_count = 0;
    }

    pub fn generate_mask_from_interface(&mut self, interfaces: &Vec<Arc<Interface>>) {
        let mut mask_table = vec![0; u16::MAX as usize + 1];

        for iface in interfaces {
            for ip in &iface.ips {
                match ip.raw_ip {
                    IpAddr::V4(ipv4) => {
                        let ip_int = u32::from_be_bytes(ipv4.octets());
                        let mask = u32::MAX << (NET_IP_MAX - ip.netmask);
                        let net_addr = ip_int & mask;

                        let mut start = net_addr >> NET_IP_LEN;
                        let mut end = start;
                        if ip.netmask < NET_IP_LEN {
                            end += (1 << (NET_IP_LEN - ip.netmask)) - 1;
                        }

                        while start <= end {
                            if mask > mask_table[start as usize] {
                                mask_table[start as usize] = mask
                            }
                            start += 1;
                        }
                    }
                    IpAddr::V6(_) => {
                        //TODO
                    }
                }
            }
        }
        *self.mask_from_interface.write().unwrap() = mask_table;
    }

    fn cidr_to_mask(addr: &Ipv4Net, epc_id: u16, table: &mut Vec<u32>) {
        let ipv4 = u32::from(addr.network());
        let mask_len = addr.prefix_len();
        if ipv4 == 0 && epc_id == 0 && mask_len == 0 {
            // internet资源因为匹配所有IP, 不需要加在这里
            return;
        }
        let mut start = ipv4 >> NET_IP_LEN;
        let mut end = start;
        let mask = u32::from(addr.netmask());
        if mask_len < NET_IP_LEN as u8 {
            end += (1 << (NET_IP_LEN as u8 - mask_len)) - 1;
        }

        while start <= end {
            if table[start as usize] < mask {
                table[start as usize] = mask;
            }
            start += 1;
        }
    }

    pub fn generate_mask_table_from_group(&mut self, groups: &Vec<Arc<IpGroupData>>) {
        let mut mask_from_ipgroup = vec![0; u16::MAX as usize + 1];

        for group in groups {
            for ip in &group.ips {
                match ip {
                    IpNet::V4(addr) => {
                        Self::cidr_to_mask(addr, group.epc_id, &mut mask_from_ipgroup);
                    }
                    _ => {
                        // TODO IPV6
                    }
                }
            }
        }
        *self.mask_from_ipgroup.write().unwrap() = mask_from_ipgroup;
    }

    pub fn generate_mask_table_from_cidr(&mut self, cidrs: &Vec<Arc<Cidr>>) {
        let mut mask_from_cidr = vec![0u32; u16::MAX as usize + 1];
        for cidr in cidrs {
            match cidr.ip {
                IpNet::V4(addr) => {
                    Self::cidr_to_mask(&addr, (cidr.epc_id & 0xffff) as u16, &mut mask_from_cidr);
                }
                _ => {
                    // TODO IPV6
                }
            }
        }
        *self.mask_from_cidr.write().unwrap() = mask_from_cidr;
    }

    // Interface、Cidr、IpGroup任何一个更新这里都需要更新
    pub fn generate_mask_table(&mut self) {
        let mut netmask_table = vec![0u32; u16::MAX as usize + 1];
        let mask_from_interface = self.mask_from_interface.read().unwrap();
        let mask_from_ipgroup = self.mask_from_ipgroup.read().unwrap();
        let mask_from_cidr = self.mask_from_cidr.read().unwrap();
        for i in 0..u16::MAX as usize + 1 {
            netmask_table[i] = max(
                mask_from_interface[i],
                max(mask_from_ipgroup[i], mask_from_cidr[i]),
            );
        }
        *self.netmask_table.write().unwrap() = netmask_table;
    }

    fn generate_mask_ip(&self, ip_src: IpAddr, ip_dst: IpAddr) -> (u32, u32) {
        match (ip_src, ip_dst) {
            (IpAddr::V4(src_addr), IpAddr::V4(dst_addr)) => {
                let src = u32::from_be_bytes(src_addr.octets());
                let dst = u32::from_be_bytes(dst_addr.octets());
                let netmask_table = self.netmask_table.read().unwrap();
                let mut src_mask = netmask_table[(src >> NET_IP_LEN) as usize];
                let mut dst_mask = netmask_table[(dst >> NET_IP_LEN) as usize];
                // The EPC of the local link IP and private IP is 0, which needs to be
                // distinguished from other internet IP to avoid querying incorrect EPC.
                // The longest netmask between local link IP and private IP is used to
                // ensure accurate queries.
                if src_addr.is_link_local() || src_addr.is_private() {
                    src_mask = src_mask.max(NET_IP_MASK);
                }
                if dst_addr.is_link_local() || dst_addr.is_private() {
                    dst_mask = dst_mask.max(NET_IP_MASK);
                }
                return (src & src_mask, dst & dst_mask);
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                let src = u128::from_be_bytes(src.octets());
                let dst = u128::from_be_bytes(dst.octets());
                return (
                    src as u32 ^ (src >> 32) as u32 ^ (src >> 64) as u32 ^ (src >> 96) as u32,
                    dst as u32 ^ (dst >> 32) as u32 ^ (dst >> 64) as u32 ^ (dst >> 96) as u32,
                );
            }
            _ => {
                warn!(
                    "IpAddr({:?} and {:?}) is invalid: ip address version is inconsistent, deepflow-agent restart...\n",
                    ip_src, ip_dst,
                );
                thread::sleep(Duration::from_secs(1));
                std::process::exit(-1);
            }
        }
    }

    pub fn generate_interest_table(&mut self, acls: &Vec<Arc<Acl>>) {
        let mut interest_table: Vec<PortRange> = std::iter::repeat(PortRange::new(0, 0))
            .take(u16::MAX as usize + 1)
            .collect();
        let mut list = Vec::new();

        for acl in acls.into_iter() {
            list.extend(&acl.src_port_ranges);
            list.extend(&acl.dst_port_ranges);
        }

        let list = PortRangeList::from(list).interest();
        let mut port_other = 0;
        for (i, item) in list.iter().enumerate() {
            if i == 0 {
                port_other = if item.min() == 0 { item.max() } else { 0 };
            } else if port_other >= item.min() - 1 {
                port_other = item.max();
            }

            for j in item.min() as usize..item.max() as usize + 1 {
                interest_table[j] = *item;
            }
        }
        if port_other != 0 && port_other < u16::MAX {
            port_other += 1;

            // port_other为非策略端口中的的第一个端口
            // 为了减少内存，减少fastPath项， 所有不在策略中的端口使用port_other来建立查询fastPath
            for i in 0..u16::MAX as usize + 1 {
                if interest_table[i] == PortRange::ZERO {
                    interest_table[i] = PortRange::new(port_other, port_other);
                }
            }
        }

        *self.interest_table.write().unwrap() = interest_table;
    }

    fn interest_table_map(&self, key: &mut LookupKey) {
        let table = &self.interest_table.read().unwrap();
        key.src_port = table[key.src_port as usize].min();
        key.dst_port = table[key.dst_port as usize].min();
    }

    fn table_flush_check(&mut self, key: &LookupKey) -> bool {
        let start_index = key.fast_index * MAX_TAP_TYPE;
        if self.policy_table_flush_flags[key.fast_index].load(Ordering::Relaxed) {
            for i in 0..MAX_TAP_TYPE {
                if let Some(t) = &mut self.policy_table[start_index + i] {
                    t.clear();
                }
            }
            self.policy_table_flush_flags[key.fast_index].store(false, Ordering::Relaxed);
        }

        if self.policy_table[start_index + u16::from(key.tap_type) as usize].is_none() {
            self.policy_table[start_index + u16::from(key.tap_type) as usize] =
                Some(LruCache::new(self.map_size.try_into().unwrap()));
            return true;
        }
        false
    }

    pub fn add_policy(
        &mut self,
        packet: &mut LookupKey,
        policy: &PolicyData,
        endpoints: EndpointData,
    ) -> (Arc<PolicyData>, Arc<EndpointData>) {
        self.table_flush_check(packet);
        self.interest_table_map(packet);

        let start_index = packet.fast_index * MAX_TAP_TYPE;
        let acl_id = policy.acl_id;
        let (key_0, key_1) = self.generate_map_key(packet);
        let proto = u8::from(packet.proto) as usize;
        let key = (key_0 as u128) << 64 | key_1 as u128;
        let table = self.policy_table[start_index + u16::from(packet.tap_type) as usize]
            .as_mut()
            .unwrap();

        let mut forward = PolicyData::default();
        if acl_id > 0 {
            forward.merge_and_dedup_npb_actions(&policy.npb_actions, acl_id, false);
            forward.format_npb_action();
        }

        let (forward_policy, forward_endpoints) = if let Some(item) = table.get_mut(&key) {
            let forward_policy = Arc::new(forward.clone());
            item.protocol_table[proto] = Some(forward_policy.clone());
            let forward_endpoints = item.store.get(
                packet.l2_end_0,
                packet.l2_end_1,
                packet.l3_end_0,
                packet.l3_end_1,
            );
            (forward_policy, forward_endpoints)
        } else {
            let mut item = PolicyTableItem {
                store: EndpointStore::from(endpoints),
                protocol_table: unsafe { std::mem::zeroed() },
            };
            let forward_policy = Arc::new(forward.clone());
            let forward_endpoints = item.store.get(
                packet.l2_end_0,
                packet.l2_end_1,
                packet.l3_end_0,
                packet.l3_end_1,
            );
            item.protocol_table[proto] = Some(forward_policy.clone());
            table.put(key, item);

            self.policy_count += 1;

            (forward_policy, forward_endpoints)
        };

        if key_0 == key_1 {
            return (forward_policy, forward_endpoints);
        }

        let mut backward = PolicyData::default();
        if acl_id > 0 {
            backward.merge_and_dedup_npb_actions(&policy.npb_actions, acl_id, true);
            backward.format_npb_action();
        }

        let (key_0, key_1) = (key_1, key_0);
        let key = (key_0 as u128) << 64 | key_1 as u128;
        if let Some(item) = table.get_mut(&key) {
            item.protocol_table[proto] = Some(Arc::new(backward.clone()));
        } else {
            let endpoints = EndpointData {
                src_info: endpoints.dst_info,
                dst_info: endpoints.src_info,
            };
            let mut item = PolicyTableItem {
                store: EndpointStore::from(endpoints),
                protocol_table: unsafe { std::mem::zeroed() },
            };

            item.protocol_table[proto] = Some(Arc::new(backward.clone()));
            table.put(key, item);

            self.policy_count += 1;
        }
        return (forward_policy, forward_endpoints);
    }

    pub fn get_policy(
        &mut self,
        packet: &mut LookupKey,
    ) -> Option<(Arc<PolicyData>, Arc<EndpointData>)> {
        if self.table_flush_check(packet) {
            return None;
        }
        self.interest_table_map(packet);

        let start_index = packet.fast_index * MAX_TAP_TYPE;
        let (key_0, key_1) = self.generate_map_key(packet);
        let key = (key_0 as u128) << 64 | key_1 as u128;
        let table = self.policy_table[start_index + u16::from(packet.tap_type) as usize]
            .as_mut()
            .unwrap();
        if let Some(item) = table.get(&key) {
            if let Some(policy) = &item.protocol_table[u8::from(packet.proto) as usize] {
                return Some((
                    Arc::clone(policy),
                    item.store.get(
                        packet.l2_end_0,
                        packet.l2_end_1,
                        packet.l3_end_0,
                        packet.l3_end_1,
                    ),
                ));
            }
        }
        return None;
    }

    // NOTE: Only one thread can access it at a time.
    pub fn ebpf_add_endpoints(
        &mut self,
        ip_src: IpAddr,
        ip_dst: IpAddr,
        l3_epc_id_src: i32,
        l3_epc_id_dst: i32,
        endpoints: EndpointData,
    ) -> Arc<EndpointData> {
        let (key_0, key_1) =
            self.generate_ebpf_map_key(ip_src, ip_dst, l3_epc_id_src, l3_epc_id_dst);
        let key = (key_0 as u128) << 64 | key_1 as u128;
        let endpoints = Arc::new(endpoints);

        self.ebpf_table.put(key, endpoints.clone());
        if key_0 == key_1 {
            return endpoints;
        }
        let key = (key_1 as u128) << 64 | key_0 as u128;

        self.ebpf_table.put(key, endpoints.clone());
        return endpoints;
    }

    pub fn ebpf_get_endpoints(
        &mut self,
        ip_src: IpAddr,
        ip_dst: IpAddr,
        l3_epc_id_src: i32,
        l3_epc_id_dst: i32,
    ) -> Option<Arc<EndpointData>> {
        if self.ebpf_table_flush_flag.load(Ordering::Relaxed) {
            self.ebpf_table.clear();
            self.ebpf_table_flush_flag.store(false, Ordering::Relaxed);
            return None;
        }

        let (key_0, key_1) =
            self.generate_ebpf_map_key(ip_src, ip_dst, l3_epc_id_src, l3_epc_id_dst);
        let key = (key_0 as u128) << 64 | key_1 as u128;

        self.ebpf_table.get(&key).and_then(|x| Some(x.clone()))
    }

    // 查询路径调用会影响性能
    fn generate_map_key(&self, key: &LookupKey) -> (u64, u64) {
        let (src_masked_ip, dst_masked_ip) = self.generate_mask_ip(key.src_ip, key.dst_ip);

        key.fast_key(src_masked_ip, dst_masked_ip)
    }

    fn generate_ebpf_map_key(
        &self,
        ip_src: IpAddr,
        ip_dst: IpAddr,
        l3_epc_id_src: i32,
        l3_epc_id_dst: i32,
    ) -> (u64, u64) {
        let (src_masked_ip, dst_masked_ip) = self.generate_mask_ip(ip_src, ip_dst);
        let l3_epc_id_src = l3_epc_id_src as u64;
        let l3_epc_id_dst = l3_epc_id_dst as u64;

        (
            (src_masked_ip as u64) | 0xffff << 32 | l3_epc_id_src << 48,
            (dst_masked_ip as u64) | 0xffff << 32 | l3_epc_id_dst << 48,
        )
    }

    pub fn new(queue_count: usize, map_size: usize) -> Self {
        assert!(
            queue_count <= super::MAX_QUEUE_COUNT,
            "Fastpath queue count over limit."
        );
        FastPath {
            map_size,

            mask_from_interface: RwLock::new(
                std::iter::repeat(0).take(u16::MAX as usize + 1).collect(),
            ),
            mask_from_ipgroup: RwLock::new(
                std::iter::repeat(0).take(u16::MAX as usize + 1).collect(),
            ),
            mask_from_cidr: RwLock::new(std::iter::repeat(0).take(u16::MAX as usize + 1).collect()),

            netmask_table: RwLock::new(std::iter::repeat(0).take(u16::MAX as usize + 1).collect()),

            interest_table: RwLock::new(
                std::iter::repeat(PortRange::new(0, 0))
                    .take(u16::MAX as usize + 1)
                    .collect::<Vec<PortRange>>(),
            ),
            policy_table: {
                let mut table = Vec::new();
                for _i in 0..MAX_FAST_PATH {
                    table.push(None);
                }
                table
            },
            ebpf_table: LruCache::new(map_size.try_into().unwrap()),

            policy_table_flush_flags: [FLUSH_FLAGS; super::MAX_QUEUE_COUNT + 1],
            ebpf_table_flush_flag: FLUSH_FLAGS,

            // 统计计数
            policy_count: 0,
        }
    }

    pub fn reset_queue_size(&mut self, queue_count: usize) {
        assert!(
            queue_count <= super::MAX_QUEUE_COUNT,
            "Fastpath queue count over limit."
        );
        self.policy_table_flush_flags.iter_mut().for_each(|f| {
            f.store(true, Ordering::Relaxed);
        });
        self.ebpf_table_flush_flag.store(true, Ordering::Relaxed)
    }
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use super::*;
    use crate::common::platform_data::{IpSubnet, PlatformData};
    use public::utils::net::MacAddr;

    #[test]
    fn test_fast_interest_1() {
        let mut table = FastPath::new(1, 1024);
        let acl = Acl {
            src_port_ranges: vec![PortRange::new(0, 10)],
            dst_port_ranges: vec![PortRange::new(5, 11)],
            ..Default::default()
        };
        table.generate_interest_table(&vec![Arc::new(acl)]);

        // 1-4 -> 1  5->10 -> 5 11->11 other->12
        let mut key = LookupKey {
            src_port: 1,
            dst_port: 9,
            ..Default::default()
        };
        table.interest_table_map(&mut key);
        assert_eq!(key.src_port, 0);
        assert_eq!(key.dst_port, 5);

        let mut key = LookupKey {
            src_port: 11,
            dst_port: 3000,
            ..Default::default()
        };
        table.interest_table_map(&mut key);
        assert_eq!(key.src_port, 11);
        assert_eq!(key.dst_port, 12)
    }

    #[test]
    fn test_fast_interest_2() {
        let mut table = FastPath::new(1, 1024);
        let acl = Acl {
            src_port_ranges: vec![PortRange::new(0, 10)],
            dst_port_ranges: vec![PortRange::new(13, 65535)],
            ..Default::default()
        };
        table.generate_interest_table(&vec![Arc::new(acl)]);

        // 0-10 -> 0  13->65535 -> 13 other->11
        let mut key = LookupKey {
            src_port: 1,
            dst_port: 65535,
            ..Default::default()
        };
        table.interest_table_map(&mut key);
        assert_eq!(key.src_port, 0);
        assert_eq!(key.dst_port, 13);

        let mut key = LookupKey {
            src_port: 11,
            dst_port: 12,
            ..Default::default()
        };
        table.interest_table_map(&mut key);
        assert_eq!(key.src_port, 11);
        assert_eq!(key.dst_port, 11);
    }

    #[test]
    fn test_fast_interest_3() {
        let mut table = FastPath::new(1, 1024);
        let acl = Acl {
            src_port_ranges: vec![PortRange::new(5, 10)],
            dst_port_ranges: vec![PortRange::new(13, 65535)],
            ..Default::default()
        };
        table.generate_interest_table(&vec![Arc::new(acl)]);

        // 5-10 -> 5  13->65535 -> 13 other->11
        let mut key = LookupKey {
            src_port: 8,
            dst_port: 65535,
            ..Default::default()
        };
        table.interest_table_map(&mut key);
        assert_eq!(key.src_port, 5);
        assert_eq!(key.dst_port, 13);

        let mut key = LookupKey {
            src_port: 11,
            dst_port: 3,
            ..Default::default()
        };
        table.interest_table_map(&mut key);
        assert_eq!(key.src_port, 0);
        assert_eq!(key.dst_port, 0);
    }

    #[test]
    fn test_fast_interest_4() {
        let mut table = FastPath::new(1, 1024);
        let acl = Acl {
            src_port_ranges: vec![PortRange::new(0, 10)],
            dst_port_ranges: vec![PortRange::new(100, 300), PortRange::new(500, 600)],
            ..Default::default()
        };
        table.generate_interest_table(&vec![Arc::new(acl)]);

        // other->11
        let mut key = LookupKey {
            src_port: 22,
            dst_port: 88,
            ..Default::default()
        };
        table.interest_table_map(&mut key);
        assert_eq!(key.src_port, 11);
        assert_eq!(key.dst_port, 11);
    }

    #[test]
    fn test_fast_normal() {
        let mut table = FastPath::new(1, 1024);
        let mut key = LookupKey {
            src_mac: MacAddr::try_from(0x112233445566 as u64).unwrap(),
            dst_mac: MacAddr::try_from(0x778899aabbcc as u64).unwrap(),
            src_ip: IpAddr::from("192.169.1.100".parse::<Ipv4Addr>().unwrap()),
            dst_ip: IpAddr::from("172.29.2.200".parse::<Ipv4Addr>().unwrap()),
            src_port: 22,
            dst_port: 88,
            ..Default::default()
        };
        let mut endpoints: EndpointData = Default::default();
        endpoints.src_info.l3_epc_id = 10;
        endpoints.dst_info.l3_epc_id = 20;
        let policy: PolicyData = Default::default();
        table.add_policy(&mut key, &policy, endpoints);

        let result = table.get_policy(&mut key);
        assert_eq!(result.is_some(), true);
        if let Some((p, e)) = result {
            assert_eq!(Arc::strong_count(&p), 2);
            assert_eq!(endpoints.src_info.l3_epc_id, e.src_info.l3_epc_id);
            assert_eq!(endpoints.dst_info.l3_epc_id, e.dst_info.l3_epc_id);
        }

        let mut key = LookupKey {
            src_mac: MacAddr::try_from(0x778899aabbcc as u64).unwrap(),
            dst_mac: MacAddr::try_from(0x112233445566 as u64).unwrap(),
            src_ip: IpAddr::from("172.29.2.200".parse::<Ipv4Addr>().unwrap()),
            dst_ip: IpAddr::from("192.169.1.100".parse::<Ipv4Addr>().unwrap()),
            src_port: 88,
            dst_port: 22,
            ..Default::default()
        };
        let result = table.get_policy(&mut key);
        assert_eq!(result.is_some(), true);
        if let Some((p, e)) = result {
            assert_eq!(Arc::strong_count(&p), 2);
            assert_eq!(endpoints.dst_info.l3_epc_id, e.src_info.l3_epc_id);
            assert_eq!(endpoints.src_info.l3_epc_id, e.dst_info.l3_epc_id);
        }
    }

    #[test]
    fn test_mask_table_from_interface() {
        let mut table = FastPath::new(1, 1024);
        let interface: PlatformData = PlatformData {
            ips: vec![IpSubnet {
                raw_ip: "192.168.10.100".parse().unwrap(),
                netmask: 14,
                ..Default::default()
            }],
            ..Default::default()
        };

        table.generate_mask_from_interface(&vec![Arc::new(interface.clone())]);
        for i in 0xc0a8..0xc0ac {
            assert_eq!(table.mask_from_interface.read().unwrap()[i], 0xfffc0000);
        }

        let interface1: PlatformData = PlatformData {
            ips: vec![IpSubnet {
                raw_ip: "192.168.10.100".parse().unwrap(),
                netmask: 23,
                ..Default::default()
            }],
            ..Default::default()
        };
        table.generate_mask_from_interface(&vec![Arc::new(interface), Arc::new(interface1)]);
        assert_eq!(
            table.mask_from_interface.read().unwrap()[0xc0a8],
            0xfffffe00
        );
        for i in 0xc0a9..0xc0ac {
            assert_eq!(table.mask_from_interface.read().unwrap()[i], 0xfffc0000);
        }
    }

    #[test]
    fn test_mask_table_from_cidr() {
        let mut table = FastPath::new(1, 1024);
        let cidr: Cidr = Cidr {
            ip: "192.168.10.100/13".parse::<IpNet>().unwrap(),
            ..Default::default()
        };
        table.generate_mask_table_from_cidr(&vec![Arc::new(cidr.clone())]);
        for i in 0xc0a8..0xc0b0 {
            assert_eq!(table.mask_from_cidr.read().unwrap()[i], 0xfff80000);
        }

        let cidr1: Cidr = Cidr {
            ip: "192.168.10.100/25".parse::<IpNet>().unwrap(),
            ..Default::default()
        };
        table.generate_mask_table_from_cidr(&vec![Arc::new(cidr), Arc::new(cidr1)]);
        assert_eq!(table.mask_from_cidr.read().unwrap()[0xc0a8], 0xffffff80);
        for i in 0xc0a9..0xc0b0 {
            assert_eq!(table.mask_from_cidr.read().unwrap()[i], 0xfff80000);
        }
    }

    #[test]
    fn test_mask_table_from_ip_group() {
        let mut table = FastPath::new(1, 1024);

        let group = IpGroupData {
            ips: vec!["192.168.10.100/13".parse::<IpNet>().unwrap()],
            ..Default::default()
        };

        table.generate_mask_table_from_group(&vec![Arc::new(group.clone())]);
        for i in 0xc0a8..0xc0b0 {
            assert_eq!(table.mask_from_ipgroup.read().unwrap()[i], 0xfff80000);
        }

        let group1 = IpGroupData {
            ips: vec!["192.168.10.100/25".parse::<IpNet>().unwrap()],
            ..Default::default()
        };
        table.generate_mask_table_from_group(&vec![Arc::new(group), Arc::new(group1)]);
        assert_eq!(table.mask_from_ipgroup.read().unwrap()[0xc0a8], 0xffffff80);
        for i in 0xc0a9..0xc0b0 {
            assert_eq!(table.mask_from_ipgroup.read().unwrap()[i], 0xfff80000);
        }
    }
}
