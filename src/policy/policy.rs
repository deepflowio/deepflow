use std::net::IpAddr;
use std::rc::Rc;
use std::sync::Arc;

use super::ip_group::IpGroup;
use super::{first_path::FirstPath, labeler::Labeler};
use crate::common::endpoint::EndpointData;
use crate::common::lookup_key::LookupKey;
use crate::common::platform_data::PlatformData;
use crate::common::policy::{Acl, Cidr, PeerConnection, PolicyData};

pub struct Policy {
    labeler: Box<Labeler>,
    table: Box<FirstPath>,

    queue_count: usize,
    first_hit: usize,
    fast_hit: usize,
}

impl Policy {
    pub fn new(queue_count: usize, level: usize, map_size: usize, fast_disable: bool) -> Box<Self> {
        Box::new(Policy {
            labeler: Labeler::new(),
            table: FirstPath::new(queue_count, level, map_size, fast_disable),
            queue_count,
            first_hit: 0,
            fast_hit: 0,
        })
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

    pub fn update_interfaces(&mut self, ifaces: &Vec<Rc<PlatformData>>) {
        self.labeler.update_interface_table(ifaces);
        self.table.update_interfaces(ifaces);
    }

    pub fn update_ip_group(&mut self, groups: &Vec<Rc<IpGroup>>) {
        self.table.update_ip_group(groups);
    }

    pub fn update_peer_connections(&mut self, peers: &Vec<Rc<PeerConnection>>) {
        self.labeler.update_peer_table(peers);
    }

    pub fn update_cidr(&mut self, cidrs: &Vec<Rc<Cidr>>) {
        self.table.update_cidr(cidrs);
        self.labeler.update_cidr_table(cidrs);
    }

    pub fn update_acl(&mut self, acls: &Vec<Rc<Acl>>, check: bool) {
        self.table.update_acl(acls, check);
    }

    pub fn flush(&mut self) {
        self.table.flush();
    }

    pub fn hit_status(&self) -> (usize, usize) {
        (self.first_hit, self.fast_hit)
    }
}

#[derive(Clone, Copy)]
pub struct PolicyGetter {
    policy: *mut Policy,
}

unsafe impl Send for PolicyGetter {}
unsafe impl Sync for PolicyGetter {}

impl PolicyGetter {
    fn policy(&self) -> &mut Policy {
        unsafe { &mut *self.policy }
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
        PolicyGetter { policy }
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
        let mut table = Policy::new(10, 0, 1024, false);
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
        table.update_interfaces(&vec![Rc::new(interface)]);
        table.update_cidr(&vec![Rc::new(cidr)]);
        table.flush();

        let mut key = LookupKey {
            src_mac: MacAddr::try_from(0x002233445566 as u64).unwrap(),
            dst_mac: MacAddr::try_from(0x008899aabbcc as u64).unwrap(),
            src_ip: IpAddr::from("192.168.10.100".parse::<Ipv4Addr>().unwrap()),
            dst_ip: IpAddr::from("172.29.20.200".parse::<Ipv4Addr>().unwrap()),
            src_port: 22,
            dst_port: 88,
            ..Default::default()
        };

        let result = table.lookup_all_by_key(&mut key);
        assert_eq!(result.is_some(), true);
        if let Some((p, e)) = result {
            assert_eq!(Arc::strong_count(&p), 1);
            assert_eq!(2, e.src_info.l3_epc_id);
            assert_eq!(10, e.dst_info.l3_epc_id);
        }

        let result = table.lookup_all_by_key(&mut key);
        assert_eq!(result.is_some(), true);
        if let Some((p, e)) = result {
            assert_eq!(Arc::strong_count(&p), 2);
            assert_eq!(2, e.src_info.l3_epc_id);
            assert_eq!(10, e.dst_info.l3_epc_id);
        }
    }
}
