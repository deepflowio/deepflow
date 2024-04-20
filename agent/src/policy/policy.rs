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

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};

use ahash::AHashMap;
use log::{debug, warn};
use pnet::datalink;
use public::enums::IpProtocol;

use super::{
    first_path::FirstPath,
    forward::{Forward, FROM_TRAFFIC_ARP},
    labeler::Labeler,
    Result as PResult,
};
use crate::common::endpoint::{EndpointData, EndpointDataPov};
use crate::common::enums::TapType;
use crate::common::flow::{PacketDirection, SignalSource};
use crate::common::lookup_key::LookupKey;
use crate::common::platform_data::PlatformData;
use crate::common::policy::{
    gpid_key, Acl, Cidr, Container, GpidEntry, GpidProtocol, IpGroupData, PeerConnection,
};
use crate::common::MetaPacket;
use crate::common::TapPort;
use crate::common::{FlowAclListener, FlowAclListenerId};
use npb_pcap_policy::PolicyData;
use public::proto::common::TridentType;
use public::proto::trident::RoleType;
use public::queue::Sender;

pub struct PolicyMonitor {
    sender: Arc<Sender<String>>,
    enabled: Arc<AtomicBool>,
}

impl PolicyMonitor {
    pub fn send(
        &self,
        key: &LookupKey,
        policy: &Arc<PolicyData>,
        endpoints: &Arc<EndpointData>,
        gpid_entries: &GpidEntry,
    ) {
        if self.enabled.load(Ordering::Relaxed) {
            let _ = self.sender.send(format!(
                "{}\n\t{:?}\n\t{}\n\tSOCKET: {:?}",
                key, endpoints, policy, gpid_entries,
            ));
        }
    }

    pub fn send_ebpf(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        src_epc: i32,
        dst_epc: i32,
        gpid_entries: &GpidEntry,
    ) {
        if self.enabled.load(Ordering::Relaxed) {
            let _ = self.sender.send(format!(
                "EBPF: IP {} > {} PORT {} > {} L3EPC {} > {} SOCKET: {:?} ",
                src_ip, dst_ip, src_port, dst_port, src_epc, dst_epc, gpid_entries,
            ));
        }
    }
}

pub struct Policy {
    labeler: Labeler,
    table: FirstPath,
    forward: Forward,

    nat: RwLock<Vec<AHashMap<u128, GpidEntry>>>,

    first_hit: usize,
    fast_hit: usize,

    monitor: Option<PolicyMonitor>,
    acls: Vec<Arc<Acl>>,
    groups: Vec<Arc<IpGroupData>>,
}

impl Policy {
    pub fn new(
        queue_count: usize,
        level: usize,
        map_size: usize,
        forward_capacity: usize,
        fast_disable: bool,
    ) -> (PolicySetter, PolicyGetter) {
        let policy = Box::into_raw(Box::new(Policy {
            labeler: Labeler::default(),
            table: FirstPath::new(queue_count, level, map_size, fast_disable),
            forward: Forward::new(queue_count, forward_capacity),
            nat: RwLock::new(vec![AHashMap::new(), AHashMap::new()]),
            first_hit: 0,
            fast_hit: 0,
            monitor: None,
            acls: vec![],
            groups: vec![],
        }));
        return (PolicySetter::from(policy), PolicyGetter::from(policy));
    }

    pub fn set_monitor(&mut self, sender: Arc<Sender<String>>, enabled: Arc<AtomicBool>) {
        self.monitor = Some(PolicyMonitor { sender, enabled });
    }

    pub fn lookup_l3(&mut self, packet: &mut MetaPacket) {
        let key = &mut packet.lookup_key;
        let index = key.fast_index;
        if key.tap_type != TapType::Cloud {
            return;
        }
        if key.src_ip.is_loopback() {
            key.l3_end_0 = true;
            key.l3_end_1 = true;
            return;
        }
        key.l3_end_0 = self
            .forward
            .query(index, key.src_mac, key.src_ip, key.l2_end_0);
        key.l3_end_1 = self
            .forward
            .query(index, key.dst_mac, key.dst_ip, key.l2_end_1);

        // 根据ARP和NDP添加forward表
        if packet.is_ndp_response() {
            if !packet.lookup_key.l3_end_0 {
                self.forward
                    .add(index, &packet.lookup_key, packet.tap_port, FROM_TRAFFIC_ARP);
                packet.lookup_key.l3_end_0 = true;
            }
        }
        // TODO: 根据TTL添加forward表
    }

    fn fill_gpid_entry(packet: &mut MetaPacket, gpid_entry: &GpidEntry) {
        if gpid_entry.port_1 == 0 && gpid_entry.port_0 == 0 {
            return;
        }

        let mut direction = packet.lookup_key.direction;

        // We consider the direction (role) in GpidEntry to be the ground truth because
        // it is taken from the socket information of the OS. Both meta_packet and flow need to
        // correct their direction based on this.
        packet.need_reverse_flow = match direction {
            PacketDirection::ServerToClient => {
                gpid_entry.port_1 != packet.lookup_key.src_port
                    || IpAddr::from(Ipv4Addr::from(gpid_entry.ip_1)) != packet.lookup_key.src_ip
            }
            PacketDirection::ClientToServer => {
                gpid_entry.port_1 != packet.lookup_key.dst_port
                    || IpAddr::from(Ipv4Addr::from(gpid_entry.ip_1)) != packet.lookup_key.dst_ip
            }
        };
        if packet.need_reverse_flow {
            direction = direction.reversed()
        }

        match direction {
            PacketDirection::ClientToServer => {
                if gpid_entry.port_real > 0 {
                    // 用于客户端处采集的流量，流量服务端IP为NAT IP，需要通过客户端信息查询流量真实的服务端IP
                    match gpid_entry.role_real {
                        RoleType::RoleServer => {
                            packet.gpid_0 = gpid_entry.pid_0;
                            packet.gpid_1 = gpid_entry.pid_real;
                            // NAT_SOURCE_RTOA高于当前优先级会更新数据
                            if TapPort::NAT_SOURCE_RTOA > packet.lookup_key.dst_nat_source {
                                packet.lookup_key.dst_nat_source = TapPort::NAT_SOURCE_RTOA;
                                packet.lookup_key.dst_nat_port = gpid_entry.port_real;
                                packet.lookup_key.dst_nat_ip =
                                    IpAddr::V4(Ipv4Addr::from(gpid_entry.ip_real));
                            }
                        }
                        RoleType::RoleClient => {
                            packet.gpid_0 = gpid_entry.pid_real;
                            // NAT_SOURCE_TOA高于当前优先级会更新数据
                            if TapPort::NAT_SOURCE_TOA > packet.lookup_key.src_nat_source {
                                packet.lookup_key.src_nat_source = TapPort::NAT_SOURCE_TOA;
                                packet.lookup_key.src_nat_port = gpid_entry.port_real;
                                packet.lookup_key.src_nat_ip =
                                    IpAddr::V4(Ipv4Addr::from(gpid_entry.ip_real));
                            }
                            packet.gpid_1 = gpid_entry.pid_1;
                        }
                        RoleType::RoleNone => {
                            packet.gpid_0 = gpid_entry.pid_0;
                            packet.gpid_1 = gpid_entry.pid_1;
                        }
                    }
                } else {
                    packet.gpid_0 = gpid_entry.pid_0;
                    packet.gpid_1 = gpid_entry.pid_1;
                }
            }
            PacketDirection::ServerToClient => {
                if gpid_entry.port_real > 0 {
                    // 用于客户端处采集的流量，流量服务端IP为NAT IP，需要通过客户端信息查询流量真实的服务端IP
                    match gpid_entry.role_real {
                        RoleType::RoleServer => {
                            packet.gpid_0 = gpid_entry.pid_real;
                            // NNAT_SOURCE_RTOA高于当前优先级会更新数据
                            if TapPort::NAT_SOURCE_RTOA > packet.lookup_key.src_nat_source {
                                packet.lookup_key.src_nat_source = TapPort::NAT_SOURCE_RTOA;
                                packet.lookup_key.src_nat_port = gpid_entry.port_real;
                                packet.lookup_key.src_nat_ip =
                                    IpAddr::V4(Ipv4Addr::from(gpid_entry.ip_real));
                            }
                            packet.gpid_1 = gpid_entry.pid_0;
                        }
                        RoleType::RoleClient => {
                            packet.gpid_0 = gpid_entry.pid_1;
                            packet.gpid_1 = gpid_entry.pid_real;
                            // NAT_SOURCE_RTOA高于当前优先级会更新数据
                            if TapPort::NAT_SOURCE_TOA > packet.lookup_key.dst_nat_source {
                                packet.lookup_key.dst_nat_source = TapPort::NAT_SOURCE_TOA;
                                packet.lookup_key.dst_nat_port = gpid_entry.port_real;
                                packet.lookup_key.dst_nat_ip =
                                    IpAddr::V4(Ipv4Addr::from(gpid_entry.ip_real));
                            }
                        }
                        RoleType::RoleNone => {
                            packet.gpid_0 = gpid_entry.pid_1;
                            packet.gpid_1 = gpid_entry.pid_0;
                        }
                    }
                } else {
                    packet.gpid_0 = gpid_entry.pid_1;
                    packet.gpid_1 = gpid_entry.pid_0;
                }
            }
        }
    }

    pub fn lookup(&mut self, packet: &mut MetaPacket, index: usize, local_epc_id: i32) {
        packet.lookup_key.fast_index = index;
        self.lookup_l3(packet);

        let key = &mut packet.lookup_key;

        if packet.signal_source == SignalSource::EBPF {
            let (endpoints, gpid_entries) = self.lookup_from_ebpf(key, local_epc_id);
            packet.endpoint_data = Some(EndpointDataPov::new(endpoints));
            packet.policy_data = Some(Arc::new(PolicyData::default())); // Only endpoint is required for ebpf data
            Self::fill_gpid_entry(packet, &gpid_entries);
            return;
        }

        // 策略查序会改变端口，为不影响后续业务， 这里保存
        if let Some((policy, endpoints, gpid_entries)) = self.lookup_all_by_key(key) {
            packet.policy_data = Some(policy);
            packet.endpoint_data = Some(EndpointDataPov::new(endpoints));
            Self::fill_gpid_entry(packet, &gpid_entries);
        }
    }

    fn send(
        &self,
        key: &LookupKey,
        policy: &Arc<PolicyData>,
        endpoints: &Arc<EndpointData>,
        gpid_entry: &GpidEntry,
    ) {
        if self.monitor.is_some() {
            self.monitor
                .as_ref()
                .unwrap()
                .send(key, policy, endpoints, gpid_entry);
        }
    }

    fn send_ebpf(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        src_epc: i32,
        dst_epc: i32,
        gpid_entry: &GpidEntry,
    ) {
        if self.monitor.is_some() {
            self.monitor.as_ref().unwrap().send_ebpf(
                src_ip, dst_ip, src_port, dst_port, src_epc, dst_epc, gpid_entry,
            );
        }
    }

    pub fn lookup_all_by_key(
        &mut self,
        key: &mut LookupKey,
    ) -> Option<(Arc<PolicyData>, Arc<EndpointData>, GpidEntry)> {
        let src_port = key.src_port;
        let dst_port = key.dst_port;
        if let Some(x) = self.table.fast_get(key) {
            key.src_port = src_port;
            key.dst_port = dst_port;
            self.fast_hit += 1;
            let entry = self.lookup_gpid_entry(key, &x.1);
            self.send(key, &x.0, &x.1, &entry);
            return Some((x.0, x.1, entry));
        }
        self.first_hit += 1;
        let endpoints = self.labeler.get_endpoint_data(key);
        let x = self.table.first_get(key, endpoints).unwrap();
        key.src_port = src_port;
        key.dst_port = dst_port;
        let entry = self.lookup_gpid_entry(key, &x.1);
        self.send(key, &x.0, &x.1, &entry);
        return Some((x.0, x.1, entry));
    }

    fn lookup_epc_by_epc(&mut self, src: IpAddr, dst: IpAddr, l3_epc_id_src: i32) -> i32 {
        // TODO：可能也需要走fast提升性能
        let endpoints = self
            .labeler
            .get_endpoint_data_by_epc(src, dst, l3_epc_id_src, 0);
        self.send_ebpf(
            src,
            dst,
            0,
            0,
            endpoints.src_info.l3_epc_id,
            endpoints.dst_info.l3_epc_id,
            &GpidEntry::default(),
        );

        endpoints.dst_info.l3_epc_id
    }

    // NOTE: This function has insufficient performance and is only used in low PPS scenarios.
    // Currently, only the Integration collector is calling this function.
    pub fn lookup_all_by_epc(
        &self,
        key: &mut LookupKey,
        local_epc_id: i32,
    ) -> (EndpointData, GpidEntry) {
        let (l3_epc_id_0, l3_epc_id_1) = if key.l2_end_0 {
            (local_epc_id, 0)
        } else {
            (0, local_epc_id)
        };
        let endpoints =
            self.labeler
                .get_endpoint_data_by_epc(key.src_ip, key.dst_ip, l3_epc_id_0, l3_epc_id_1);
        let entry = self.lookup_gpid_entry(key, &endpoints);
        self.send_ebpf(
            key.src_ip,
            key.dst_ip,
            key.src_port,
            key.dst_port,
            endpoints.src_info.l3_epc_id,
            endpoints.dst_info.l3_epc_id,
            &entry,
        );

        (endpoints, entry)
    }

    fn lookup_from_ebpf(
        &mut self,
        key: &mut LookupKey,
        local_epc_id: i32,
    ) -> (Arc<EndpointData>, GpidEntry) {
        let (l3_epc_id_0, l3_epc_id_1) = if key.l2_end_0 {
            (local_epc_id, 0)
        } else {
            (0, local_epc_id)
        };

        if let Some(endpoints) =
            self.table
                .ebpf_fast_get(key.src_ip, key.dst_ip, l3_epc_id_0, l3_epc_id_1)
        {
            let entry = self.lookup_gpid_entry(key, &endpoints);
            self.send_ebpf(
                key.src_ip,
                key.dst_ip,
                key.src_port,
                key.dst_port,
                endpoints.src_info.l3_epc_id,
                endpoints.dst_info.l3_epc_id,
                &entry,
            );
            return (endpoints, entry);
        }

        let endpoints =
            self.labeler
                .get_endpoint_data_by_epc(key.src_ip, key.dst_ip, l3_epc_id_0, l3_epc_id_1);
        let endpoints =
            self.table
                .ebpf_fast_add(key.src_ip, key.dst_ip, l3_epc_id_0, l3_epc_id_1, endpoints);
        let entry = self.lookup_gpid_entry(key, &endpoints);
        self.send_ebpf(
            key.src_ip,
            key.dst_ip,
            key.src_port,
            key.dst_port,
            endpoints.src_info.l3_epc_id,
            endpoints.dst_info.l3_epc_id,
            &entry,
        );

        (endpoints, entry)
    }

    pub fn lookup_pod_id(&self, container_id: &String) -> u32 {
        self.labeler.lookup_pod_id(container_id)
    }

    pub fn update_interfaces(
        &mut self,
        trident_type: TridentType,
        ifaces: &Vec<Arc<PlatformData>>,
    ) {
        self.labeler.update_interface_table(ifaces);
        self.table.update_interfaces(ifaces);

        // TODO: 后续需要添加监控本地网卡，如果网卡配置有变化应该也需要出发表更新
        let local_interfaces = datalink::interfaces();
        self.forward
            .update_from_config(trident_type, ifaces, &local_interfaces);
    }

    pub fn update_ip_group(&mut self, groups: &Vec<Arc<IpGroupData>>) {
        self.table.update_ip_group(groups);

        self.groups = groups.clone();
    }

    pub fn update_peer_connections(&mut self, peers: &Vec<Arc<PeerConnection>>) {
        self.labeler.update_peer_table(peers);
    }

    pub fn update_cidr(&mut self, cidrs: &Vec<Arc<Cidr>>) {
        self.table.update_cidr(cidrs);
        self.labeler.update_cidr_table(cidrs);
    }

    pub fn update_container(&mut self, cidrs: &Vec<Arc<Container>>) {
        self.labeler.update_container(cidrs);
    }

    pub fn update_acl(&mut self, acls: &Vec<Arc<Acl>>, check: bool) -> PResult<()> {
        self.table.update_acl(acls, check)?;

        self.acls = acls.clone();

        Ok(())
    }

    fn lookup_gpid_entry(&self, key: &mut LookupKey, _endpoints: &EndpointData) -> GpidEntry {
        if !key.is_ipv4() || (key.proto != IpProtocol::UDP && key.proto != IpProtocol::TCP) {
            return GpidEntry::default();
        }
        let protocol = u8::from(GpidProtocol::try_from(key.proto).unwrap()) as usize;
        // FIXME: Support epc id
        let epc_id_0 = 0;
        let epc_id_1 = 0;

        let (ip_0, port_0) = if TapPort::NAT_SOURCE_TOA == key.src_nat_source {
            if let IpAddr::V4(addr) = key.src_nat_ip {
                (u32::from(addr), key.src_nat_port)
            } else {
                (0, key.src_nat_port)
            }
        } else if let IpAddr::V4(addr) = key.src_ip {
            (u32::from(addr), key.src_port)
        } else {
            (0, 0)
        };
        let (ip_1, port_1) = if TapPort::NAT_SOURCE_TOA == key.dst_nat_source {
            if let IpAddr::V4(addr) = key.dst_nat_ip {
                (u32::from(addr), key.dst_nat_port)
            } else {
                (0, key.dst_nat_port)
            }
        } else if let IpAddr::V4(addr) = key.dst_ip {
            (u32::from(addr), key.dst_port)
        } else {
            (0, 0)
        };

        let key_0 = gpid_key(ip_0, epc_id_0, port_0);
        let key_1 = gpid_key(ip_1, epc_id_1, port_1);
        let key = (key_0 as u128) << 64 | key_1 as u128;
        *self.nat.read().unwrap()[protocol]
            .get(&key)
            .unwrap_or(&GpidEntry::default())
    }

    pub fn update_gpids(&mut self, gpid_entries: &Vec<GpidEntry>) {
        let mut table = vec![
            AHashMap::with_capacity(gpid_entries.len()),
            AHashMap::with_capacity(gpid_entries.len() >> 2),
        ];
        for gpid_entry in gpid_entries.iter() {
            let protocol = u8::from(gpid_entry.protocol) as usize;
            if protocol >= table.len() {
                warn!("Invalid protocol {:?} in {:?}", protocol, &gpid_entry);
                continue;
            }

            let (key_0, key_1) = (gpid_entry.client_key(), gpid_entry.server_key());
            debug!("key: 0x{:x} 0x{:x} value: {:?}", key_0, key_1, &gpid_entry);

            // Data in both directions will be stored for quick query
            let key = (key_0 as u128) << 64 | key_1 as u128;
            table[protocol].insert(key, gpid_entry.clone());
            let key = (key_1 as u128) << 64 | key_0 as u128;
            table[protocol].insert(key, gpid_entry.clone());
        }
        *self.nat.write().unwrap() = table;
    }

    pub fn get_acls(&self) -> &Vec<Arc<Acl>> {
        return &self.acls;
    }

    pub fn get_groups(&self) -> &Vec<Arc<IpGroupData>> {
        return &self.groups;
    }

    pub fn flush(&mut self) {
        self.table.flush();
    }

    pub fn get_hits(&self) -> (usize, usize) {
        (self.first_hit, self.fast_hit)
    }

    pub fn set_memory_limit(&self, limit: u64) {
        self.table.set_memory_limit(limit);
    }

    pub fn reset_queue_size(&mut self, queue_count: usize) {
        self.table.reset_queue_size(queue_count);
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PolicyGetter {
    policy: *mut Policy,
    switch: bool,
}

unsafe impl Send for PolicyGetter {}
unsafe impl Sync for PolicyGetter {}

impl PolicyGetter {
    pub fn policy(&self) -> &mut Policy {
        unsafe { &mut *self.policy }
    }

    pub fn disable(&mut self) {
        self.switch = false;
    }

    pub fn lookup(&mut self, packet: &mut MetaPacket, index: usize, local_epc_id: i32) {
        if !self.switch {
            return;
        }
        self.policy().lookup(packet, index, local_epc_id);
    }

    pub fn lookup_all_by_key(
        &mut self,
        key: &mut LookupKey,
    ) -> Option<(Arc<PolicyData>, Arc<EndpointData>, GpidEntry)> {
        self.policy().lookup_all_by_key(key)
    }

    pub fn lookup_epc_by_epc(&mut self, src: IpAddr, dst: IpAddr, l3_epc_id_src: i32) -> i32 {
        self.policy().lookup_epc_by_epc(src, dst, l3_epc_id_src)
    }

    pub fn lookup_pod_id(&self, container_id: &String) -> u32 {
        self.policy().lookup_pod_id(container_id)
    }
}

impl From<*mut Policy> for PolicyGetter {
    fn from(policy: *mut Policy) -> Self {
        PolicyGetter {
            policy,
            switch: true,
        }
    }
}

#[derive(Clone, Copy)]
pub struct PolicySetter {
    policy: *mut Policy,
}

unsafe impl Send for PolicySetter {}
unsafe impl Sync for PolicySetter {}

impl From<*mut Policy> for PolicySetter {
    fn from(policy: *mut Policy) -> Self {
        PolicySetter { policy }
    }
}

impl FlowAclListener for PolicySetter {
    fn flow_acl_change(
        &mut self,
        trident_type: TridentType,
        local_epc: i32,
        ip_groups: &Vec<Arc<IpGroupData>>,
        platform_data: &Vec<Arc<PlatformData>>,
        peers: &Vec<Arc<PeerConnection>>,
        cidrs: &Vec<Arc<Cidr>>,
        acls: &Vec<Arc<Acl>>,
    ) -> Result<(), String> {
        self.update_local_epc(local_epc);
        self.update_interfaces(trident_type, platform_data);
        self.update_ip_group(ip_groups);
        self.update_peer_connections(peers);
        self.update_cidr(cidrs);
        if let Err(e) = self.update_acl(acls, true) {
            return Err(format!("{}", e));
        }

        self.flush();
        Ok(())
    }

    fn containers_change(&mut self, containers: &Vec<Arc<Container>>) {
        self.update_container(containers);
    }

    fn id(&self) -> usize {
        u16::from(FlowAclListenerId::Policy) as usize
    }
}

impl PolicySetter {
    fn policy(&self) -> &mut Policy {
        unsafe { &mut *self.policy }
    }

    pub fn update_local_epc(&mut self, local_epc: i32) {
        self.policy().labeler.update_local_epc(local_epc);
    }

    pub fn update_interfaces(
        &mut self,
        trident_type: TridentType,
        ifaces: &Vec<Arc<PlatformData>>,
    ) {
        self.policy().update_interfaces(trident_type, ifaces);
    }

    pub fn update_ip_group(&mut self, groups: &Vec<Arc<IpGroupData>>) {
        self.policy().update_ip_group(groups);
    }

    pub fn update_peer_connections(&mut self, peers: &Vec<Arc<PeerConnection>>) {
        self.policy().update_peer_connections(peers);
    }

    pub fn update_cidr(&mut self, cidrs: &Vec<Arc<Cidr>>) {
        self.policy().update_cidr(cidrs);
    }

    pub fn update_container(&mut self, containers: &Vec<Arc<Container>>) {
        self.policy().update_container(containers);
    }

    pub fn update_acl(&mut self, acls: &Vec<Arc<Acl>>, check: bool) -> PResult<()> {
        self.policy().update_acl(acls, check)?;

        Ok(())
    }

    pub fn flush(&mut self) {
        self.policy().flush();
    }

    pub fn set_monitor(&mut self, sender: Arc<Sender<String>>, enabled: Arc<AtomicBool>) {
        self.policy().set_monitor(sender, enabled);
    }

    pub fn get_acls(&self) -> &Vec<Arc<Acl>> {
        self.policy().get_acls()
    }

    pub fn get_groups(&self) -> &Vec<Arc<IpGroupData>> {
        self.policy().get_groups()
    }

    pub fn get_hits(&self) -> (usize, usize) {
        return self.policy().get_hits();
    }

    pub fn update_gpids(&self, entrys: &Vec<GpidEntry>) {
        self.policy().update_gpids(entrys);
    }

    pub fn set_memory_limit(&self, limit: u64) {
        self.policy().set_memory_limit(limit)
    }

    pub fn reset_queue_size(&self, queue_count: usize) {
        self.policy().reset_queue_size(queue_count);
    }
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use ipnet::IpNet;

    use super::*;
    use crate::common::platform_data::IpSubnet;
    use crate::common::policy::{Cidr, CidrType};
    use public::utils::net::MacAddr;

    #[test]
    fn test_policy_normal() {
        let (mut setter, mut getter) = Policy::new(10, 0, 1024, 1024, false);
        let interface: PlatformData = PlatformData {
            mac: 0x002233445566,
            ips: vec![IpSubnet {
                raw_ip: "192.168.10.100".parse().unwrap(),
                ..Default::default()
            }],
            epc_id: 2,
            ..Default::default()
        };
        let cidr: Cidr = Cidr {
            ip: "172.29.20.200/32".parse::<IpNet>().unwrap(),
            epc_id: 10,
            cidr_type: CidrType::Wan,
            ..Default::default()
        };
        setter.update_interfaces(TridentType::TtHostPod, &vec![Arc::new(interface)]);
        setter.update_cidr(&vec![Arc::new(cidr)]);
        setter.flush();

        let mut key = LookupKey {
            src_mac: MacAddr::try_from(0x002233445566 as u64).unwrap(),
            dst_mac: MacAddr::try_from(0x008899aabbcc as u64).unwrap(),
            src_ip: IpAddr::from("192.168.10.100".parse::<Ipv4Addr>().unwrap()),
            dst_ip: IpAddr::from("172.29.20.200".parse::<Ipv4Addr>().unwrap()),
            src_port: 22,
            dst_port: 88,
            ..Default::default()
        };

        let result = getter.lookup_all_by_key(&mut key);
        assert_eq!(result.is_some(), true);
        if let Some((p, e, _)) = result {
            assert_eq!(Arc::strong_count(&p), 2);
            assert_eq!(2, e.src_info.l3_epc_id);
            assert_eq!(10, e.dst_info.l3_epc_id);
        }

        let result = getter.lookup_all_by_key(&mut key);
        assert_eq!(result.is_some(), true);
        if let Some((p, e, _)) = result {
            assert_eq!(Arc::strong_count(&p), 2);
            assert_eq!(2, e.src_info.l3_epc_id);
            assert_eq!(10, e.dst_info.l3_epc_id);
        }
    }
}
