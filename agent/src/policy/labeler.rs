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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{
    atomic::{AtomicI32, Ordering},
    Arc, RwLock,
};

use ahash::AHashMap;
use log::warn;

use super::bit::count_trailing_zeros32;
use crate::common::decapsulate::TunnelInfo;
use crate::common::endpoint::{EndpointData, EndpointInfo, EPC_FROM_DEEPFLOW, EPC_FROM_INTERNET};
use crate::common::lookup_key::LookupKey;
use crate::common::platform_data::{IfType, PlatformData};
use crate::common::policy::{Cidr, CidrType, Container, PeerConnection};
use public::utils::net::is_unicast_link_local;

const BROADCAST_MAC: u64 = 0xffffffffffff;
const MULTICAST_MAC: u64 = 0x010000000000;

#[derive(Debug, Hash, std::cmp::Eq, PartialEq)]
struct EpcIpKey {
    ip: u128,
    epc_id: i32,
}

const IPV4_BITS: usize = 32;
const IPV6_BITS: usize = 128;

#[derive(Debug, Hash, std::cmp::Eq, PartialEq)]
struct EpcNetIpKey {
    ip: u128,
    masklen: u8,
    epc_id: i32,
}

impl EpcNetIpKey {
    fn new(ip: &IpAddr, masklen: u8, epc_id: i32) -> EpcNetIpKey {
        match ip {
            IpAddr::V4(i) => EpcNetIpKey {
                ip: u32::from_be_bytes(i.octets()) as u128,
                epc_id,
                masklen,
            },
            IpAddr::V6(i) => EpcNetIpKey {
                ip: u128::from_be_bytes(i.octets()),
                epc_id,
                masklen,
            },
        }
    }

    fn clone_by_masklen(&self, masklen: usize, is_ipv4: bool) -> Self {
        let max_prefix = if is_ipv4 { IPV4_BITS } else { IPV6_BITS };
        Self {
            ip: self.ip & (u128::MAX << (max_prefix - masklen)),
            epc_id: self.epc_id,
            masklen: masklen as u8,
        }
    }
}

pub struct Labeler {
    local_epc: AtomicI32,
    // Interface表
    mac_table: RwLock<AHashMap<u64, Arc<PlatformData>>>,
    epc_ip_table: RwLock<AHashMap<EpcIpKey, Arc<PlatformData>>>,
    // Interface WAN IP表
    ip_netmask_table: RwLock<AHashMap<u16, u32>>, // 仅用于IPv4, IPv6的掩码目前仅支持128不用计算
    ip_table: RwLock<AHashMap<u128, Arc<PlatformData>>>,
    // 对等连接表
    peer_table: RwLock<AHashMap<i32, Vec<i32>>>,
    // CIDR表
    epc_cidr_masklen_table: RwLock<AHashMap<i32, (u8, u8)>>,
    epc_cidr_table: RwLock<AHashMap<EpcNetIpKey, Arc<Cidr>>>,
    tunnel_cidr_table: RwLock<AHashMap<u32, Vec<Arc<Cidr>>>>,
    // Container
    container_table: RwLock<AHashMap<String, u32>>,
}

impl Default for Labeler {
    fn default() -> Self {
        Self {
            local_epc: AtomicI32::new(EPC_FROM_INTERNET),
            mac_table: RwLock::new(AHashMap::new()),
            epc_ip_table: RwLock::new(AHashMap::new()),
            ip_netmask_table: RwLock::new(AHashMap::new()),
            ip_table: RwLock::new(AHashMap::new()),
            peer_table: RwLock::new(AHashMap::new()),
            epc_cidr_masklen_table: RwLock::new(AHashMap::new()),
            epc_cidr_table: RwLock::new(AHashMap::new()),
            tunnel_cidr_table: RwLock::new(AHashMap::new()),
            container_table: RwLock::new(AHashMap::new()),
        }
    }
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => {
            return addr.is_link_local();
        }
        IpAddr::V6(addr) => {
            return is_unicast_link_local(&addr);
        }
    }
}

fn is_unicast_mac(mac: u64) -> bool {
    return mac != BROADCAST_MAC && mac & MULTICAST_MAC != MULTICAST_MAC;
}

impl Labeler {
    pub fn update_local_epc(&mut self, local_epc: i32) {
        self.local_epc.store(local_epc, Ordering::Relaxed);
    }

    fn update_mac_table(&mut self, interfaces: &Vec<Arc<PlatformData>>) {
        let mut mac_table = AHashMap::new();

        for interface in interfaces {
            let iface = Arc::clone(interface);
            if iface.skip_mac {
                continue;
            }
            if iface.mac != 0 {
                mac_table.insert(iface.mac, iface);
            }
        }

        *self.mac_table.write().unwrap() = mac_table;
    }

    fn get_real_ip_by_mac(&self, mac: u64, is_ipv6: bool) -> IpAddr {
        if let Some(interface) = self.mac_table.read().unwrap().get(&mac) {
            for ip in &(interface.ips) {
                if ip.raw_ip.is_ipv6() == is_ipv6 {
                    return ip.raw_ip;
                }
            }
        }
        if is_ipv6 {
            Ipv6Addr::UNSPECIFIED.into()
        } else {
            Ipv4Addr::UNSPECIFIED.into()
        }
    }

    fn get_interface_by_mac(&self, mac: u64) -> Option<PlatformData> {
        if let Some(platform) = self.mac_table.read().unwrap().get(&mac) {
            return Some(platform.as_ref().clone());
        }
        return None;
    }

    fn update_epc_ip_table(&mut self, interfaces: &Vec<Arc<PlatformData>>) {
        let mut epc_ip_table = AHashMap::new();

        for interface in interfaces {
            let mut epc_id = interface.epc_id;
            if epc_id == EPC_FROM_DEEPFLOW {
                epc_id = 0;
            }

            for ip in &interface.ips {
                epc_ip_table.insert(
                    EpcIpKey {
                        ip: match ip.raw_ip {
                            IpAddr::V4(ip) => u32::from_be_bytes(ip.octets()) as u128,
                            IpAddr::V6(ip) => u128::from_be_bytes(ip.octets()),
                        },
                        epc_id,
                    },
                    Arc::clone(interface),
                );
            }
        }

        *self.epc_ip_table.write().unwrap() = epc_ip_table;
    }

    fn get_interface_by_epc_ip(&self, ip: IpAddr, epc_id: i32) -> Option<PlatformData> {
        match ip {
            IpAddr::V4(ip) => {
                if let Some(platform) = self.epc_ip_table.read().unwrap().get(&EpcIpKey {
                    ip: u32::from_be_bytes(ip.octets()) as u128,
                    epc_id,
                }) {
                    Some(platform.as_ref().clone())
                } else {
                    None
                }
            }
            IpAddr::V6(ip) => {
                if let Some(platform) = self.epc_ip_table.read().unwrap().get(&EpcIpKey {
                    ip: u128::from_be_bytes(ip.octets()),
                    epc_id,
                }) {
                    Some(platform.as_ref().clone())
                } else {
                    None
                }
            }
        }
    }

    pub fn update_peer_table(&mut self, peers: &Vec<Arc<PeerConnection>>) {
        let mut peer_table: AHashMap<i32, Vec<i32>> = AHashMap::new();
        for peer in peers {
            peer_table
                .entry(peer.local_epc)
                .or_default()
                .push(peer.remote_epc);
            peer_table
                .entry(peer.remote_epc)
                .or_default()
                .push(peer.local_epc);
        }

        *self.peer_table.write().unwrap() = peer_table;
    }

    fn get_epc_by_peer(&self, ip: IpAddr, epc_id: i32, endpoint: &mut EndpointInfo) {
        if let Some(list) = self.peer_table.read().unwrap().get(&epc_id) {
            for peer_epc in list {
                if let Some(interface) = self.get_interface_by_epc_ip(ip, *peer_epc) {
                    endpoint.set_l3_data(&interface);
                    return;
                }
            }

            for peer_epc in list {
                if self.set_epc_by_cidr(ip, *peer_epc, endpoint) {
                    return;
                }
            }
        }
    }

    fn get_cidr_masklen_range(&self, epc_id: i32) -> (usize, usize) {
        if let Some((min, max)) = self.epc_cidr_masklen_table.read().unwrap().get(&epc_id) {
            return (*min as usize, *max as usize);
        }
        return (0, 0);
    }

    pub fn update_cidr_table(&mut self, cidrs: &Vec<Arc<Cidr>>) {
        let mut masklen_table: AHashMap<i32, (u8, u8)> = AHashMap::new();
        let mut epc_table: AHashMap<EpcNetIpKey, Arc<Cidr>> = AHashMap::new();
        let mut tunnel_table: AHashMap<u32, Vec<Arc<Cidr>>> = AHashMap::new();

        for item in cidrs {
            let mut epc_id = item.epc_id;
            if item.cidr_type == CidrType::Wan {
                epc_id = EPC_FROM_DEEPFLOW;
            }
            let key = EpcNetIpKey::new(&item.ip.network(), item.ip.prefix_len(), epc_id);

            if let Some(old) = epc_table.insert(key, item.clone()) {
                if (item.cidr_type == CidrType::Wan && item.epc_id != old.epc_id)
                    || item.is_vip != old.is_vip
                {
                    warn!(
                        "Found the same cidr, please check {:?} and {:?}.",
                        item, old
                    );
                }
            }
            masklen_table
                .entry(epc_id)
                .and_modify(|(min, max)| {
                    let netmask_len = item.netmask_len();
                    if *min > netmask_len {
                        *min = netmask_len
                    } else if *max < netmask_len {
                        *max = netmask_len
                    }
                })
                .or_insert((item.netmask_len(), item.netmask_len()));

            if item.tunnel_id > 0 {
                tunnel_table
                    .entry(item.tunnel_id)
                    .or_default()
                    .push(Arc::clone(item));
            }
        }

        // 排序使用降序是为了CIDR的最长前缀匹配
        for (_k, v) in &mut tunnel_table.iter_mut() {
            v.sort_by(|a, b| {
                b.netmask_len()
                    .partial_cmp(&Arc::clone(a).netmask_len())
                    .unwrap()
            });
        }

        *self.tunnel_cidr_table.write().unwrap() = tunnel_table;
        *self.epc_cidr_masklen_table.write().unwrap() = masklen_table;
        *self.epc_cidr_table.write().unwrap() = epc_table;
    }

    pub fn update_container(&mut self, containers: &Vec<Arc<Container>>) {
        let mut table = AHashMap::new();
        for item in containers {
            table.insert(item.container_id.clone(), item.pod_id);
        }
        *self.container_table.write().unwrap() = table;
    }

    pub fn lookup_pod_id(&self, container_id: &String) -> u32 {
        if let Some(pod_id) = self.container_table.read().unwrap().get(container_id) {
            return *pod_id;
        }

        0
    }

    // 函数通过EPC+IP查询对应的CIDR，获取EPC标记
    // 注意当查询外网时必须给epc参数传递EPC_FROM_DEEPFLOW值，表示在所有WAN CIDR范围内搜索，并返回该CIDR的真实EPC
    fn set_epc_by_cidr(&self, ip: IpAddr, epc_id: i32, endpoint: &mut EndpointInfo) -> bool {
        let (min, max) = self.get_cidr_masklen_range(epc_id);
        let cidr_key = EpcNetIpKey::new(&ip, max as u8, epc_id);
        let table = self.epc_cidr_table.read().unwrap();
        for i in (min..=max).rev() {
            let key = cidr_key.clone_by_masklen(i, ip.is_ipv4());
            if let Some(cidr) = table.get(&key) {
                endpoint.l3_epc_id = cidr.epc_id;
                endpoint.is_vip = cidr.is_vip;
                return true;
            }
        }

        false
    }

    // 函数通过EPC+IP查询对应的CIDR，获取EPC和VIP标记
    // 注意当查询外网时必须给epc参数传递EPC_FROM_DEEPFLOW值，表示在所有WAN CIDR范围内搜索，并返回该CIDR的真实EPC
    fn set_epc_vip_by_tunnel(
        &self,
        ip: IpAddr,
        tunnel_id: u32,
        endpoint: &mut EndpointInfo,
    ) -> bool {
        if let Some(list) = self.tunnel_cidr_table.read().unwrap().get(&tunnel_id) {
            for cidr in list.iter() {
                if cidr.ip.contains(&ip) {
                    endpoint.l3_epc_id = cidr.epc_id;
                    endpoint.is_vip = cidr.is_vip;
                    return cidr.cidr_type == CidrType::Wan;
                }
            }

            let mut last_epc_id: i32 = 0;
            for cidr in list.iter() {
                if cidr.epc_id == last_epc_id {
                    continue;
                }
                last_epc_id = cidr.epc_id;
                if self.set_epc_by_cidr(ip, cidr.epc_id, endpoint) {
                    return cidr.cidr_type == CidrType::Wan;
                }
            }
        }
        false
    }

    fn set_vip_by_cidr(&self, ip: IpAddr, epc_id: i32, info: &mut EndpointInfo) -> bool {
        let (min, max) = self.get_cidr_masklen_range(epc_id);
        let cidr_key = EpcNetIpKey::new(&ip, max as u8, epc_id);
        let table = self.epc_cidr_table.read().unwrap();
        for i in (min..=max).rev() {
            let key = cidr_key.clone_by_masklen(i, ip.is_ipv4());
            if let Some(cidr) = table.get(&key) {
                info.is_vip = cidr.is_vip;
                return true;
            }
        }

        return false;
    }

    fn update_ip_table(&mut self, interfaces: &Vec<Arc<PlatformData>>) {
        let mut ip_netmask_table = AHashMap::new();
        let mut ip_table = AHashMap::new();
        for interface in interfaces {
            if interface.if_type != IfType::WAN {
                continue;
            }
            for ip in &(interface.ips) {
                let net_addr = match ip.raw_ip {
                    IpAddr::V4(ipv4) => {
                        let ip_int = u32::from_be_bytes(ipv4.octets());
                        let net_addr = (ip_int & (0xffff_ffff << (32 - ip.netmask))) as u128;

                        let mut start = net_addr >> 16;
                        let mut end = start;
                        if ip.netmask < 16 {
                            end += (1 << (16 - ip.netmask)) - 1;
                        }

                        while start <= end {
                            let k = start as u16;
                            if let Some(v) = ip_netmask_table.get_mut(&k) {
                                *v |= 1 << (32 - ip.netmask);
                            } else {
                                ip_netmask_table.insert(k, 1 << (32 - ip.netmask));
                            }
                            start += 1;
                        }
                        // IPv4-mapped IPv6 addresses are defined in [IETF RFC 4291 Section 2.5.5.2]
                        net_addr | 0xffff_0000_0000
                    }
                    IpAddr::V6(ipv6) => {
                        u128::from_be_bytes(ipv6.octets())
                            & 0xffffffffffffffff_ffffffffffffffff << (128 - ip.netmask)
                    }
                };
                ip_table.insert(net_addr, Arc::clone(interface));
            }
        }

        *self.ip_netmask_table.write().unwrap() = ip_netmask_table;
        *self.ip_table.write().unwrap() = ip_table;
    }

    fn get_interface_by_ip(&self, ip: IpAddr) -> Option<PlatformData> {
        match ip {
            IpAddr::V4(ipv4) => {
                let ip_int = u32::from_be_bytes(ipv4.octets());
                if let Some(netmask) = self
                    .ip_netmask_table
                    .read()
                    .unwrap()
                    .get(&((ip_int >> 16) as u16))
                {
                    let mut netmask_temp = *netmask;
                    while netmask_temp > 0 {
                        let count = count_trailing_zeros32(netmask_temp);
                        netmask_temp ^= 1 << count;
                        let net_addr = (ip_int & (0xffff_ffff << count)) as u128;
                        if let Some(v) = self
                            .ip_table
                            .read()
                            .unwrap()
                            .get(&(net_addr | 0xffff_0000_0000))
                        {
                            return Some(v.as_ref().clone());
                        }
                    }
                }
                return None;
            }
            IpAddr::V6(ipv6) => {
                let net_addr = u128::from_be_bytes(ipv6.octets());
                if let Some(v) = self.ip_table.read().unwrap().get(&net_addr) {
                    Some(v.as_ref().clone())
                } else {
                    None
                }
            }
        }
    }

    pub fn update_interface_table(&mut self, interfaces: &Vec<Arc<PlatformData>>) {
        self.update_mac_table(interfaces);
        self.update_epc_ip_table(interfaces);
        self.update_ip_table(interfaces);
    }

    fn get_endpoint_info(
        &self,
        mac: u64,
        ip: IpAddr,
        l2_end: bool,
        l3_end: bool,
        tunnel_id: u32,
        is_loopback: bool,
    ) -> (EndpointInfo, bool) {
        let mut is_wan = false;
        let mut info: EndpointInfo = EndpointInfo {
            l2_end,
            l3_end,
            ..Default::default()
        };

        // The loopback packet epc id is local epc id, and no query is required.
        if is_loopback {
            info.set_loopback(self.local_epc.load(Ordering::Relaxed));
            return (info, false);
        }

        // 如下场景无法直接查询隧道内层的MAC地址确定EPC：
        // 1. 腾讯TCE：使用GRE做隧道封装，内层没有MAC
        // 2. 使用VXLAN隧道但内层MAC已无法识别
        //    目前发现青云私有云属于这种情况，VXLAN内层的MAC可能不是任何一个实际存在的虚拟网卡MAC
        // 采集器并不关心具体的云平台差异，只要控制器下发隧道ID，都会优先使用它进行查询

        if tunnel_id > 0 {
            // step 1: 查询tunnelID监控网段(cidr)
            is_wan = self.set_epc_vip_by_tunnel(ip, tunnel_id, &mut info);
            if TunnelInfo::is_gre_pseudo_inner_mac(mac) {
                // 腾讯TCE使用GRE封装场景下，此处拿到是伪造MAC，无法用于查询云平台信息，直接在此分支中返回即可
                if info.l3_epc_id == 0 {
                    // step 2: 查询平台数据WAN接口
                    if let Some(interface) = self.get_interface_by_ip(ip) {
                        info.set_l3_data(&interface);
                        is_wan = interface.if_type == IfType::WAN;
                    } else {
                        // step 3: 查询DEEPFLOW添加的WAN监控网段(cidr)
                        is_wan = self.set_epc_by_cidr(ip, EPC_FROM_DEEPFLOW, &mut info);
                    }
                    return (info, is_wan);
                }
            } else {
                // 其他云如果使用TunnelID没有查询到，还需要继续用MAC查询
            }
        }
        // step 1: 使用mac查询L2
        if let Some(interface) = self.get_interface_by_mac(mac) {
            info.set_l2_data(&interface);
            info.is_vip_interface = interface.is_vip_interface;
            // IP为0，则取MAC对应的二层数据作为三层数据
            if l3_end || ip.is_unspecified() || ip.is_loopback() || is_link_local(ip) {
                info.set_l3_data(&interface);
                is_wan = interface.if_type == IfType::WAN;
                return (info, is_wan);
            }
        }

        // step 2: 使用L2EpcId + IP查询L3，如果L2EpcId为0，会查询到DEEPFLOW添加的监控IP
        if let Some(interface) = self.get_interface_by_epc_ip(ip, info.l2_epc_id) {
            info.set_l3_data(&interface);
            is_wan = interface.if_type == IfType::WAN;
        }
        return (info, is_wan);
    }

    fn modify_endpoint_data(&self, endpoint: &mut EndpointData, key: &LookupKey) {
        let mut src_data = &mut endpoint.src_info;
        let mut dst_data = &mut endpoint.dst_info;
        if dst_data.l3_epc_id == 0 && src_data.l3_epc_id > 0 {
            if !is_unicast_mac(u64::from(key.dst_mac))
                || key.dst_ip.is_loopback()
                || key.dst_ip.is_multicast()
                || key.src_ip == key.dst_ip
            {
                dst_data.l3_epc_id = src_data.l3_epc_id;
                dst_data.l2_epc_id = src_data.l2_epc_id;
                dst_data.is_device = true;
            } else if let Some(interface) =
                self.get_interface_by_epc_ip(key.dst_ip, src_data.l3_epc_id)
            {
                // 本端IP + 对端EPC查询EPC-IP表
                dst_data.set_l3_data(&interface);
            } else {
                // 本端IP + 对端EPC查询CIDR表
                self.set_epc_by_cidr(key.dst_ip, src_data.l3_epc_id, &mut dst_data);
            }
        }
        if src_data.l3_epc_id == 0 && dst_data.l3_epc_id > 0 {
            if key.src_ip.is_loopback() || key.src_ip == key.dst_ip {
                src_data.l3_epc_id = dst_data.l3_epc_id;
                src_data.l2_epc_id = dst_data.l2_epc_id;
                src_data.is_device = true;
            } else if let Some(interface) =
                self.get_interface_by_epc_ip(key.src_ip, dst_data.l3_epc_id)
            {
                // 本端IP + 对端EPC查询EPC-IP表
                src_data.set_l3_data(&interface);
            } else {
                // 本端IP + 对端EPC查询CIDR表
                self.set_epc_by_cidr(key.src_ip, dst_data.l3_epc_id, &mut src_data);
            }
        }
    }

    fn get_l3_by_peer(&self, src: IpAddr, dst: IpAddr, endpoint: &mut EndpointData) {
        let src_data = &mut endpoint.src_info;
        let dst_data = &mut endpoint.dst_info;
        if src_data.l3_epc_id <= 0 && dst_data.l3_epc_id > 0 {
            self.get_epc_by_peer(src, dst_data.l3_epc_id, src_data);
        } else if dst_data.l3_epc_id <= 0 && src_data.l3_epc_id > 0 {
            self.get_epc_by_peer(dst, src_data.l3_epc_id, dst_data);
        }
    }

    fn get_l3_by_wan(&self, src: IpAddr, dst: IpAddr, endpoint: &mut EndpointData) -> (bool, bool) {
        let src_data = &mut endpoint.src_info;
        let dst_data = &mut endpoint.dst_info;

        let mut found_src = false;
        let mut fount_dst = false;

        if src_data.l3_epc_id == 0 {
            // step 1: 查询平台接口数据WAN IP
            if let Some(interface) = self.get_interface_by_ip(src) {
                src_data.set_l3_data(&interface);
                found_src = true;
            } else {
                // step 2: 查询DEEPFLOW添加的WAN监控网段(cidr)
                found_src = self.set_epc_by_cidr(src, EPC_FROM_DEEPFLOW, src_data);
            }
        }
        if dst_data.l3_epc_id == 0 {
            // step 1: 查询平台接口数据WAN IP
            if let Some(interface) = self.get_interface_by_ip(dst) {
                dst_data.set_l3_data(&interface);
                fount_dst = true;
            } else {
                // step 2: 查询DEEPFLOW添加的WAN监控网段(cidr)
                fount_dst = self.set_epc_by_cidr(dst, EPC_FROM_DEEPFLOW, dst_data);
            }
        }
        return (found_src, fount_dst);
    }

    fn get_vip(
        &self,
        key: &LookupKey,
        is_src_wan: bool,
        is_dst_wan: bool,
        endpoint: &mut EndpointData,
    ) {
        let mut src_data = &mut endpoint.src_info;
        let mut dst_data = &mut endpoint.dst_info;

        if !src_data.is_vip && src_data.l3_epc_id > 0 {
            if !is_src_wan {
                self.set_vip_by_cidr(key.src_ip, src_data.l3_epc_id, &mut src_data);
            } else {
                self.set_vip_by_cidr(key.src_ip, EPC_FROM_DEEPFLOW, &mut src_data);
            }
        }
        if src_data.is_vip {
            src_data.real_ip =
                self.get_real_ip_by_mac(u64::from(key.src_mac), key.src_ip.is_ipv6());
        }

        if !dst_data.is_vip && dst_data.l3_epc_id > 0 {
            if !is_dst_wan {
                self.set_vip_by_cidr(key.dst_ip, dst_data.l3_epc_id, &mut dst_data);
            } else {
                self.set_vip_by_cidr(key.dst_ip, EPC_FROM_DEEPFLOW, &mut dst_data);
            }
        }
        if dst_data.is_vip {
            dst_data.real_ip =
                self.get_real_ip_by_mac(u64::from(key.dst_mac), key.dst_ip.is_ipv6());
        }
    }

    fn modify_internet_epc(&self, endpoint: &mut EndpointData) {
        let src_data = &mut endpoint.src_info;
        let dst_data = &mut endpoint.dst_info;

        if src_data.l3_epc_id == 0 {
            src_data.l3_epc_id = EPC_FROM_INTERNET;
        }
        if dst_data.l3_epc_id == 0 {
            dst_data.l3_epc_id = EPC_FROM_INTERNET;
        }
    }

    pub fn get_endpoint_data(&self, key: &LookupKey) -> EndpointData {
        let is_loopback = key.src_mac == key.dst_mac;
        // l2: mac查询
        // l3: l2epc+ip查询
        let (src_info, mut is_src_wan) = self.get_endpoint_info(
            u64::from(key.src_mac),
            key.src_ip,
            key.l2_end_0,
            key.l3_end_0,
            key.tunnel_id,
            is_loopback,
        );
        let (dst_info, mut is_dst_wan) = self.get_endpoint_info(
            u64::from(key.dst_mac),
            key.dst_ip,
            key.l2_end_1,
            key.l3_end_1,
            key.tunnel_id,
            is_loopback,
        );
        let mut endpoint = EndpointData::new(src_info, dst_info);
        // l3: 私有网络 VPC内部路由
        // 1) 本端IP + 对端EPC查询EPC-IP表
        // 2) 本端IP + 对端EPC查询CIDR表
        self.modify_endpoint_data(&mut endpoint, key);
        // l3: 对等连接查询, 以下两种查询
        // 1) peer epc + ip查询对等连接表
        // 2) peer epc + ip查询CIDR表
        self.get_l3_by_peer(key.src_ip, key.dst_ip, &mut endpoint);
        // l3: WAN查询，包括以下两种查询
        // 1) ip查询平台数据WAN接口
        // 2) ip查询DEEPFLOW添加的WAN监控网段(cidr)
        let (found_src, found_dst) = self.get_l3_by_wan(key.src_ip, key.dst_ip, &mut endpoint);
        if found_src || found_dst {
            self.modify_endpoint_data(&mut endpoint, key);
            self.get_l3_by_peer(key.src_ip, key.dst_ip, &mut endpoint);
        }
        is_src_wan = is_src_wan || found_src;
        is_dst_wan = is_dst_wan || found_dst;
        // vip: vip查询，如果是VIP查询mac对应的实际IP
        //
        // XXX: VIP查询是否使用WAN的逻辑中：
        // 1. EPC通过另一端EPC查询时统一按照LAN处理
        self.get_vip(key, is_src_wan, is_dst_wan, &mut endpoint);
        self.modify_internet_epc(&mut endpoint);
        return endpoint;
    }

    pub fn get_endpoint_data_by_epc(
        &self,
        src: IpAddr,
        dst: IpAddr,
        l3_epc_id_src: i32,
        l3_epc_id_dst: i32,
    ) -> EndpointData {
        let src_info = EndpointInfo {
            is_device: l3_epc_id_src > 0,
            l3_epc_id: l3_epc_id_src,
            l2_end: l3_epc_id_src > 0,
            l3_end: l3_epc_id_src > 0,
            ..Default::default()
        };
        let dst_info = EndpointInfo {
            is_device: l3_epc_id_dst > 0,
            l3_epc_id: l3_epc_id_dst,
            l2_end: l3_epc_id_dst > 0,
            l3_end: l3_epc_id_dst > 0,
            ..Default::default()
        };
        let mut endpoint = EndpointData::new(src_info, dst_info);
        let key = &LookupKey {
            src_ip: src,
            dst_ip: dst,
            ..Default::default()
        };
        // l3: 私有网络 VPC内部路由
        // 1) 本端IP + 对端EPC查询EPC-IP表
        // 2) 本端IP + 对端EPC查询CIDR表
        self.modify_endpoint_data(&mut endpoint, key);
        // l3: 对等连接查询, 以下两种查询
        // 1) peer epc + ip查询对等连接表
        // 2) peer epc + ip查询CIDR表
        self.get_l3_by_peer(key.src_ip, key.dst_ip, &mut endpoint);
        // l3: WAN查询，包括以下两种查询
        // 1) ip查询平台数据WAN接口
        // 2) ip查询DEEPFLOW添加的WAN监控网段(cidr)
        let (found_src, found_dst) = self.get_l3_by_wan(key.src_ip, key.dst_ip, &mut endpoint);
        if found_src || found_dst {
            self.modify_endpoint_data(&mut endpoint, key);
            self.get_l3_by_peer(key.src_ip, key.dst_ip, &mut endpoint);
        }
        self.modify_internet_epc(&mut endpoint);
        return endpoint;
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv6Addr, str::FromStr};

    use ipnet::IpNet;

    use super::*;
    use crate::common::platform_data::IpSubnet;
    use public::utils::net::MacAddr;

    #[test]
    fn test_mac_normal() {
        let mut labeler: Labeler = Default::default();
        let ip4 = "192.168.10.100";
        let ip6 = "2002:2002::10";
        let interface: PlatformData = PlatformData {
            mac: 0x112233445566,
            ips: vec![
                IpSubnet {
                    raw_ip: ip4.parse().unwrap(),
                    ..Default::default()
                },
                IpSubnet {
                    raw_ip: ip6.parse().unwrap(),
                    netmask: 128,
                    ..Default::default()
                },
            ],
            epc_id: 1,
            ..Default::default()
        };
        labeler.update_mac_table(&vec![Arc::new(interface)]);

        let ret = labeler.get_interface_by_mac(0x112233445566);
        assert_eq!(ret.is_some(), true);

        let real_ip = labeler.get_real_ip_by_mac(0x112233445566, false);
        assert_eq!(real_ip, ip4.parse::<Ipv4Addr>().unwrap());

        let real_ip = labeler.get_real_ip_by_mac(0x112233445566, true);
        assert_eq!(real_ip, ip6.parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_epc_ip_normal() {
        let mut labeler: Labeler = Default::default();
        let interface1: PlatformData = PlatformData {
            mac: 0x112233445566,
            ips: vec![IpSubnet {
                raw_ip: "192.168.10.100".parse().unwrap(),
                ..Default::default()
            }],
            epc_id: 1,
            ..Default::default()
        };
        let interface2: PlatformData = PlatformData {
            mac: 0x112233445566,
            ips: vec![IpSubnet {
                raw_ip: "192.168.10.200".parse().unwrap(),
                ..Default::default()
            }],
            epc_id: EPC_FROM_DEEPFLOW,
            if_type: IfType::WAN,
            ..Default::default()
        };

        labeler.update_epc_ip_table(&vec![Arc::new(interface1), Arc::new(interface2)]);

        let ret = labeler.get_interface_by_epc_ip("192.168.10.100".parse().unwrap(), 1);
        assert_eq!(ret.is_some(), true);

        let ret =
            labeler.get_interface_by_epc_ip("192.168.10.200".parse().unwrap(), EPC_FROM_DEEPFLOW);
        assert_eq!(ret.is_some(), false);

        let ret = labeler.get_interface_by_epc_ip("192.168.10.200".parse().unwrap(), 0);
        assert_eq!(ret.is_some(), true);
    }

    #[test]
    fn test_ip_lan_wan() {
        let mut labeler: Labeler = Default::default();
        let interface1: PlatformData = PlatformData {
            ips: vec![IpSubnet {
                raw_ip: "192.168.10.100".parse().unwrap(),
                netmask: 29,
                ..Default::default()
            }],
            epc_id: 1,
            ..Default::default()
        };
        let interface2: PlatformData = PlatformData {
            ips: vec![IpSubnet {
                raw_ip: "192.168.10.100".parse().unwrap(),
                netmask: 28,
                ..Default::default()
            }],
            epc_id: 2,
            if_type: IfType::WAN,
            ..Default::default()
        };

        labeler.update_ip_table(&vec![Arc::new(interface1), Arc::new(interface2)]);

        let ret = labeler.get_interface_by_ip("192.168.10.100".parse().unwrap());
        assert_eq!(ret.is_some(), true);
        assert_eq!(ret.unwrap().epc_id, 2);
    }

    #[test]
    fn test_ip_netmask() {
        let mut labeler: Labeler = Default::default();
        let interface1: PlatformData = PlatformData {
            ips: vec![IpSubnet {
                raw_ip: "192.168.10.100".parse().unwrap(),
                netmask: 29,
                ..Default::default()
            }],
            epc_id: 1,
            if_type: IfType::WAN,
            ..Default::default()
        };
        let interface2: PlatformData = PlatformData {
            ips: vec![IpSubnet {
                raw_ip: "192.168.10.100".parse().unwrap(),
                netmask: 30,
                ..Default::default()
            }],
            epc_id: 2,
            if_type: IfType::WAN,
            ..Default::default()
        };

        labeler.update_ip_table(&vec![Arc::new(interface1), Arc::new(interface2)]);

        let ret = labeler.get_interface_by_ip("192.168.10.100".parse().unwrap());
        assert_eq!(ret.is_some(), true);
        assert_eq!(ret.unwrap().epc_id, 2);
    }

    #[test]
    fn test_ip_litte_netmask() {
        let mut labeler: Labeler = Default::default();
        let interface1: PlatformData = PlatformData {
            ips: vec![IpSubnet {
                raw_ip: "192.168.10.100".parse().unwrap(),
                netmask: 8,
                ..Default::default()
            }],
            epc_id: 1,
            if_type: IfType::WAN,
            ..Default::default()
        };
        let interface2: PlatformData = PlatformData {
            ips: vec![IpSubnet {
                raw_ip: "192.128.10.100".parse().unwrap(),
                netmask: 9,
                ..Default::default()
            }],
            epc_id: 2,
            if_type: IfType::WAN,
            ..Default::default()
        };

        labeler.update_ip_table(&vec![Arc::new(interface1), Arc::new(interface2)]);

        let ret = labeler.get_interface_by_ip("192.1.10.100".parse().unwrap());
        assert_eq!(ret.is_some(), true);
        assert_eq!(ret.unwrap().epc_id, 1);

        let ret = labeler.get_interface_by_ip("192.128.10.100".parse().unwrap());
        assert_eq!(ret.is_some(), true);
        assert_eq!(ret.unwrap().epc_id, 2);
    }

    #[test]
    fn test_ip6_netmask() {
        let mut labeler: Labeler = Default::default();
        let interface1: PlatformData = PlatformData {
            ips: vec![IpSubnet {
                raw_ip: "2200:3300:4400::10".parse().unwrap(),
                netmask: 127,
                ..Default::default()
            }],
            epc_id: 1,
            if_type: IfType::WAN,
            ..Default::default()
        };
        let interface2: PlatformData = PlatformData {
            ips: vec![IpSubnet {
                raw_ip: "2200:3300:4400::10".parse().unwrap(),
                netmask: 128,
                ..Default::default()
            }],
            epc_id: 2,
            if_type: IfType::WAN,
            ..Default::default()
        };

        labeler.update_ip_table(&vec![Arc::new(interface1), Arc::new(interface2)]);

        let ret = labeler.get_interface_by_ip("2200:3300:4400::10".parse().unwrap());
        assert_eq!(ret.is_some(), true);
        assert_eq!(ret.unwrap().epc_id, 2);
    }

    #[test]
    fn test_peer_normal() {
        let mut labeler: Labeler = Default::default();
        let peer: PeerConnection = PeerConnection {
            local_epc: 1,
            remote_epc: 2,
            ..Default::default()
        };
        let interface1: PlatformData = PlatformData {
            mac: 0x112233445566,
            ips: vec![IpSubnet {
                raw_ip: "192.168.10.100".parse().unwrap(),
                ..Default::default()
            }],
            epc_id: 1,
            ..Default::default()
        };
        let interface2: PlatformData = PlatformData {
            mac: 0x112233445566,
            ips: vec![IpSubnet {
                raw_ip: "192.168.10.200".parse().unwrap(),
                ..Default::default()
            }],
            epc_id: 2,
            if_type: IfType::WAN,
            ..Default::default()
        };

        labeler.update_peer_table(&vec![Arc::new(peer)]);
        labeler.update_epc_ip_table(&vec![Arc::new(interface1), Arc::new(interface2)]);

        let mut endpoint: EndpointInfo = Default::default();

        labeler.get_epc_by_peer("192.168.10.100".parse().unwrap(), 2, &mut endpoint);
        assert_eq!(endpoint.l3_epc_id, 1);

        labeler.get_epc_by_peer("192.168.10.200".parse().unwrap(), 1, &mut endpoint);
        assert_eq!(endpoint.l3_epc_id, 2);
    }

    #[test]
    fn test_cidr_order() {
        let mut labeler: Labeler = Default::default();
        let cidr1: Cidr = Cidr {
            ip: IpNet::from_str("192.168.10.100/26").unwrap(),
            epc_id: 10,
            ..Default::default()
        };
        let cidr2: Cidr = Cidr {
            ip: IpNet::from_str("192.168.10.100/27").unwrap(),
            epc_id: 10,
            is_vip: true,
            ..Default::default()
        };
        let cidr3: Cidr = Cidr {
            ip: IpNet::from_str("192.168.10.100/25").unwrap(),
            epc_id: 10,
            ..Default::default()
        };
        let cidrs = vec![Arc::new(cidr1), Arc::new(cidr2), Arc::new(cidr3)];
        let mut endpoint: EndpointInfo = Default::default();

        labeler.update_cidr_table(&cidrs);

        labeler.set_epc_by_cidr("192.168.10.100".parse().unwrap(), 10, &mut endpoint);
        assert_eq!(endpoint.is_vip, true);
    }

    #[test]
    fn test_cidr_match() {
        let mut labeler: Labeler = Default::default();
        let cidr1: Cidr = Cidr {
            ip: IpNet::from_str("10.0.0.0/24").unwrap(),
            epc_id: 10,
            is_vip: true,
            ..Default::default()
        };
        let cidr2: Cidr = Cidr {
            ip: IpNet::from_str("192.168.10.100/8").unwrap(),
            epc_id: 10,
            is_vip: true,
            ..Default::default()
        };
        let cidrs = vec![Arc::new(cidr1), Arc::new(cidr2)];
        labeler.update_cidr_table(&cidrs);

        let mut endpoint: EndpointInfo = Default::default();
        labeler.set_epc_by_cidr("10.1.2.3".parse().unwrap(), 10, &mut endpoint);
        assert_eq!(endpoint.is_vip, false);
    }

    #[test]
    fn test_cidr_wan() {
        let mut labeler: Labeler = Default::default();
        let cidr1: Cidr = Cidr {
            ip: IpNet::from_str("192.168.10.100/24").unwrap(),
            epc_id: 10,
            cidr_type: CidrType::Wan,
            ..Default::default()
        };

        let mut endpoint: EndpointInfo = Default::default();

        labeler.update_cidr_table(&vec![Arc::new(cidr1)]);
        labeler.set_epc_by_cidr("192.168.10.100".parse().unwrap(), 10, &mut endpoint);
        assert_eq!(endpoint.l3_epc_id, 0);

        labeler.set_epc_by_cidr(
            "192.168.10.100".parse().unwrap(),
            EPC_FROM_DEEPFLOW,
            &mut endpoint,
        );
        assert_eq!(endpoint.l3_epc_id, 10);
    }

    #[test]
    fn test_cidr_tunnel() {
        let mut labeler: Labeler = Default::default();
        let cidr1: Cidr = Cidr {
            ip: IpNet::from_str("192.168.10.100/24").unwrap(),
            epc_id: 10,
            tunnel_id: 10,
            ..Default::default()
        };

        let mut endpoint: EndpointInfo = Default::default();

        labeler.update_cidr_table(&vec![Arc::new(cidr1)]);

        labeler.set_epc_vip_by_tunnel("192.168.10.100".parse().unwrap(), 10, &mut endpoint);
        assert_eq!(endpoint.l3_epc_id, 10);
    }

    #[test]
    fn test_cidr_vip() {
        let mut labeler: Labeler = Default::default();
        let cidr1: Cidr = Cidr {
            ip: IpNet::from_str("192.168.10.100/24").unwrap(),
            epc_id: 10,
            is_vip: true,
            ..Default::default()
        };

        let mut endpoint: EndpointInfo = Default::default();

        labeler.update_cidr_table(&vec![Arc::new(cidr1)]);

        labeler.set_vip_by_cidr("192.168.10.100".parse().unwrap(), 10, &mut endpoint);
        assert_eq!(endpoint.is_vip, true);
    }

    #[test]
    fn test_get_endpoint_date() {
        let mut labeler: Labeler = Default::default();
        let peer: PeerConnection = PeerConnection {
            local_epc: 1,
            remote_epc: 2,
            ..Default::default()
        };
        let interface1: PlatformData = PlatformData {
            mac: 0x112233445566,
            ips: vec![IpSubnet {
                raw_ip: "192.168.10.100".parse().unwrap(),
                ..Default::default()
            }],
            epc_id: 1,
            ..Default::default()
        };
        let interface2: PlatformData = PlatformData {
            mac: 0x112233445577,
            ips: vec![IpSubnet {
                raw_ip: "192.168.10.200".parse().unwrap(),
                ..Default::default()
            }],
            epc_id: 2,
            ..Default::default()
        };
        let cidr1: Cidr = Cidr {
            ip: IpNet::from_str("192.168.10.200/32").unwrap(),
            epc_id: 10,
            cidr_type: CidrType::Wan,
            ..Default::default()
        };
        let list = vec![Arc::new(interface1), Arc::new(interface2)];

        labeler.update_mac_table(&list);
        labeler.update_epc_ip_table(&list);
        labeler.update_cidr_table(&vec![Arc::new(cidr1)]);

        let key: LookupKey = LookupKey {
            src_mac: MacAddr::from_str("11:22:33:44:55:66").unwrap(),
            src_ip: "192.168.10.100".parse().unwrap(),
            dst_ip: "192.168.10.200".parse().unwrap(),
            ..Default::default()
        };

        // 通过CIDR匹配到EPC_ID：10
        let endpoints = labeler.get_endpoint_data(&key);
        assert_eq!(endpoints.src_info.l3_epc_id, 1);
        assert_eq!(endpoints.dst_info.l3_epc_id, 10);

        // 加入对等连接
        labeler.update_peer_table(&vec![Arc::new(peer)]);

        // 加入对等连接后，对等连接优先级高于CIDR WAN
        let endpoints = labeler.get_endpoint_data(&key);
        assert_eq!(endpoints.src_info.l3_epc_id, 1);
        assert_eq!(endpoints.dst_info.l3_epc_id, 2);
    }
    #[test]
    fn test_modify_endpoint_date() {
        let mut labeler: Labeler = Default::default();
        let interface = PlatformData {
            mac: 0x112233445566,
            ips: vec![IpSubnet {
                raw_ip: "192.168.10.100".parse().unwrap(),
                ..Default::default()
            }],
            epc_id: 1,
            ..Default::default()
        };
        let cidr = Cidr {
            ip: IpNet::from_str("172.29.20.200/32").unwrap(),
            epc_id: 1,
            ..Default::default()
        };
        labeler.update_mac_table(&vec![Arc::new(interface)]);
        labeler.update_cidr_table(&vec![Arc::new(cidr)]);
        let mut endpoints: EndpointData = Default::default();
        endpoints.src_info.l3_epc_id = 1;

        let key: LookupKey = LookupKey {
            src_mac: MacAddr::from_str("11:22:33:44:55:66").unwrap(),
            src_ip: "192.168.10.100".parse().unwrap(),
            dst_ip: "172.29.20.200".parse().unwrap(),
            ..Default::default()
        };
        labeler.modify_endpoint_data(&mut endpoints, &key);
        assert_eq!(endpoints.dst_info.l3_epc_id, 1);
    }
    #[test]
    fn test_modify_internet_epc() {
        let labeler: Labeler = Default::default();
        let mut endpoints: EndpointData = Default::default();
        labeler.modify_internet_epc(&mut endpoints);
        assert_eq!(endpoints.dst_info.l3_epc_id, -2);
        assert_eq!(endpoints.src_info.l3_epc_id, -2);
    }

    #[test]
    fn test_get_vip() {
        let mut labeler: Labeler = Default::default();
        let cidr = Cidr {
            ip: IpNet::from_str("172.29.20.200/32").unwrap(),
            epc_id: 1,
            is_vip: true,
            ..Default::default()
        };
        labeler.update_cidr_table(&vec![Arc::new(cidr)]);

        let mut endpoints: EndpointData = Default::default();
        endpoints.dst_info.l3_epc_id = 1;
        let key: LookupKey = LookupKey {
            src_mac: MacAddr::from_str("11:22:33:44:55:66").unwrap(),
            src_ip: "192.168.10.100".parse().unwrap(),
            dst_ip: "172.29.20.200".parse().unwrap(),
            ..Default::default()
        };
        labeler.get_vip(&key, false, false, &mut endpoints);
        assert_eq!(endpoints.dst_info.is_vip, true);
    }
}
