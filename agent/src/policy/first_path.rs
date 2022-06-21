use std::sync::Arc;

use super::fast_path::FastPath;
use crate::common::endpoint::EndpointData;
use crate::common::lookup_key::LookupKey;
use crate::common::platform_data::PlatformData;
use crate::common::policy::{Acl, Cidr, IpGroupData, PolicyData};

pub struct FirstPath {
    fast: FastPath,

    fast_disable: bool,
    queue_count: usize,
}

impl FirstPath {
    pub fn new(
        queue_count: usize,
        _level: usize,
        map_size: usize,
        fast_disable: bool,
    ) -> FirstPath {
        FirstPath {
            fast: FastPath::new(queue_count, map_size),
            queue_count,
            fast_disable,
        }
    }

    pub fn update_map_size(&mut self, map_size: usize) {
        self.fast.update_map_size(map_size)
    }

    pub fn update_interfaces(&mut self, ifaces: &Vec<Arc<PlatformData>>) {
        self.fast.generate_mask_from_interface(ifaces);
    }

    pub fn update_ip_group(&mut self, groups: &Vec<Arc<IpGroupData>>) {
        // TODO: first group id map
        self.fast.generate_mask_table_from_group(groups);
    }

    pub fn update_cidr(&mut self, cidrs: &Vec<Arc<Cidr>>) {
        self.fast.generate_mask_table_from_cidr(cidrs);
    }

    pub fn update_acl(&mut self, acls: &Vec<Arc<Acl>>, _check: bool) {
        // TODO: first

        // fast
        self.fast.generate_interest_table(acls);
    }

    pub fn flush(&mut self) {
        self.fast.flush();
    }

    pub fn first_get(
        &mut self,
        key: &mut LookupKey,
        endpoints: EndpointData,
    ) -> Option<(Arc<PolicyData>, Arc<EndpointData>)> {
        // TODO: first policy

        let policy = PolicyData::default();
        self.fast.add_policy(key, &policy, &policy, endpoints);

        return Some((Arc::new(policy), Arc::new(endpoints)));
    }

    pub fn fast_get(
        &mut self,
        key: &mut LookupKey,
    ) -> Option<(Arc<PolicyData>, Arc<EndpointData>)> {
        if self.fast_disable {
            return None;
        }
        if let Some(x) = self.fast.get_policy(key) {
            return Some(x);
        }
        return None;
    }
}
