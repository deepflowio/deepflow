use std::net::IpAddr;
use std::sync::Arc;

use log::debug;
use pnet::datalink;

use super::{
    first_path::FirstPath,
    forward::{Forward, FROM_TRAFFIC_ARP},
    labeler::Labeler,
};
use crate::common::endpoint::EndpointData;
use crate::common::enums::TapType;
use crate::common::lookup_key::LookupKey;
use crate::common::platform_data::PlatformData;
use crate::common::policy::{Acl, Cidr, IpGroupData, PeerConnection, PolicyData};
use crate::common::FlowAclListener;
use crate::common::MetaPacket;

pub struct Policy {
    labeler: Labeler,
    table: FirstPath,
    forward: Forward,

    queue_count: usize,
    first_hit: usize,
    fast_hit: usize,
}

impl Policy {
    pub fn new(
        queue_count: usize,
        level: usize,
        map_size: usize,
        fast_disable: bool,
    ) -> (PolicySetter, PolicyGetter) {
        let policy = Box::into_raw(Box::new(Policy {
            labeler: Labeler::default(),
            table: FirstPath::new(queue_count, level, map_size, fast_disable),
            forward: Forward::new(queue_count),
            queue_count,
            first_hit: 0,
            fast_hit: 0,
        }));
        return (PolicySetter::from(policy), PolicyGetter::from(policy));
    }

    pub fn lookup_l3(&mut self, packet: &mut MetaPacket) {
        let key = &mut packet.lookup_key;
        let index = key.fast_index;
        if key.tap_type != TapType::Tor {
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
            .query(index, key.src_mac, key.src_ip, key.l2_end_0);

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

    pub fn lookup(&mut self, packet: &mut MetaPacket, index: usize) {
        packet.lookup_key.fast_index = index;
        self.lookup_l3(packet);

        let key = &mut packet.lookup_key;

        // 策略查序会改变端口，为不影响后续业务， 这里保存
        let src_port = key.src_port;
        let dst_port = key.dst_port;
        if let Some((policy, endpoints)) = self.lookup_all_by_key(key) {
            packet.policy_data = Some(policy);
            packet.endpoint_data = Some(endpoints);
            debug!(
                "\n{}\n\t{:?}\n\t{:?}\n",
                key, packet.policy_data, packet.endpoint_data
            );
        }
        key.src_port = src_port;
        key.dst_port = dst_port;
    }

    pub fn lookup_all_by_key(
        &mut self,
        key: &mut LookupKey,
    ) -> Option<(Arc<PolicyData>, Arc<EndpointData>)> {
        if let Some(x) = self.table.fast_get(key) {
            self.fast_hit += 1;
            return Some(x);
        }
        self.first_hit += 1;
        let endpoints = self.labeler.get_endpoint_data(key);
        return self.table.first_get(key, endpoints);
    }

    pub fn lookup_all_by_epc(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        l3_epc_id_src: i32,
        l3_epc_id_dst: i32,
    ) -> i32 {
        // TODO：可能也需要走fast提升性能
        let endpoints =
            self.labeler
                .get_endpoint_data_by_epc(src, dst, l3_epc_id_src, l3_epc_id_dst);
        if l3_epc_id_src > 0 {
            endpoints.dst_info.l3_epc_id
        } else {
            endpoints.src_info.l3_epc_id
        }
    }

    pub fn update_interfaces(&mut self, ifaces: &Vec<Arc<PlatformData>>) {
        self.labeler.update_interface_table(ifaces);
        self.table.update_interfaces(ifaces);

        // TODO: 后续需要添加监控本地网卡，如果网卡配置有变化应该也需要出发表更新
        let local_interfaces = datalink::interfaces();
        self.forward.update_from_config(ifaces, &local_interfaces);
    }

    pub fn update_ip_group(&mut self, groups: &Vec<Arc<IpGroupData>>) {
        self.table.update_ip_group(groups);
    }

    pub fn update_peer_connections(&mut self, peers: &Vec<Arc<PeerConnection>>) {
        self.labeler.update_peer_table(peers);
    }

    pub fn update_cidr(&mut self, cidrs: &Vec<Arc<Cidr>>) {
        self.table.update_cidr(cidrs);
        self.labeler.update_cidr_table(cidrs);
    }

    pub fn update_acl(&mut self, acls: &Vec<Arc<Acl>>, check: bool) {
        self.table.update_acl(acls, check);
    }

    pub fn flush(&mut self) {
        self.table.flush();
    }

    pub fn hit_status(&self) -> (usize, usize) {
        (self.first_hit, self.fast_hit)
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
    fn policy(&self) -> &mut Policy {
        unsafe { &mut *self.policy }
    }

    pub fn disable(&mut self) {
        self.switch = false;
    }

    pub fn lookup(&mut self, packet: &mut MetaPacket, index: usize) {
        if !self.switch {
            return;
        }
        self.policy().lookup(packet, index);
    }

    pub fn lookup_all_by_key(
        &mut self,
        key: &mut LookupKey,
    ) -> Option<(Arc<PolicyData>, Arc<EndpointData>)> {
        self.policy().lookup_all_by_key(key)
    }

    pub fn lookup_all_by_epc(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        l3_epc_id_src: i32,
        l3_epc_id_dst: i32,
    ) -> i32 {
        self.policy()
            .lookup_all_by_epc(src, dst, l3_epc_id_src, l3_epc_id_dst)
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
        ip_groups: &Vec<Arc<IpGroupData>>,
        platform_data: &Vec<Arc<PlatformData>>,
        peers: &Vec<Arc<PeerConnection>>,
        cidrs: &Vec<Arc<Cidr>>,
    ) {
        self.update_interfaces(platform_data);
        self.update_ip_group(ip_groups);
        self.update_peer_connections(peers);
        self.update_cidr(cidrs);

        self.flush();
    }

    // TODO: 用于区别于不同的FlowAclListener
    fn id(&self) -> usize {
        return 0;
    }
}

impl PolicySetter {
    fn policy(&self) -> &mut Policy {
        unsafe { &mut *self.policy }
    }

    pub fn update_map_size(&mut self, map_size: usize) {
        self.policy().table.update_map_size(map_size);
    }

    pub fn update_interfaces(&mut self, ifaces: &Vec<Arc<PlatformData>>) {
        self.policy().update_interfaces(ifaces);
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

    pub fn update_acl(&mut self, acls: &Vec<Arc<Acl>>, check: bool) {
        self.policy().update_acl(acls, check);
    }

    pub fn flush(&mut self) {
        self.policy().flush();
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
    use crate::utils::net::MacAddr;

    #[test]
    fn test_policy_normal() {
        let (mut setter, mut getter) = Policy::new(10, 0, 1024, false);
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
        setter.update_interfaces(&vec![Arc::new(interface)]);
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
        if let Some((p, e)) = result {
            assert_eq!(Arc::strong_count(&p), 1);
            assert_eq!(2, e.src_info.l3_epc_id);
            assert_eq!(10, e.dst_info.l3_epc_id);
        }

        let result = getter.lookup_all_by_key(&mut key);
        assert_eq!(result.is_some(), true);
        if let Some((p, e)) = result {
            assert_eq!(Arc::strong_count(&p), 2);
            assert_eq!(2, e.src_info.l3_epc_id);
            assert_eq!(10, e.dst_info.l3_epc_id);
        }
    }
}
