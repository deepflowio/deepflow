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

use std::hash::Hasher;
use std::sync::Arc;

use ahash::AHasher;
use log::{debug, info, trace, warn};
use regex::Regex;

use crate::{
    config::handler::PlatformConfig,
    platform::{
        kubernetes::{InterfaceInfoStore, Poller},
        platform_synchronizer::{
            linux_process::get_all_process_in, process_info_enabled, ProcessData,
        },
        GenericPoller, InterfaceEntry, LibvirtXmlExtractor,
    },
    utils::command::{
        get_all_vm_xml, get_brctl_show, get_hostname, get_ip_address, get_ovs_interfaces,
        get_ovs_ports, get_vlan_config, get_vm_states,
    },
};

use public::{
    netns::{self, InterfaceInfo, NsFile},
    proto::trident as pb,
};

pub struct Querier {
    override_os_hostname: Option<String>,

    kubernetes_poller: Option<Arc<GenericPoller>>,
    libvirt_xml_extractor: Arc<LibvirtXmlExtractor>,

    netns_regex: Option<Regex>,

    digest: u64,

    raw_hostname: Option<String>,
    raw_all_vm_xml: Option<String>,
    raw_vm_states: Option<String>,
    raw_ovs_interfaces: Option<String>,
    raw_ovs_ports: Option<String>,
    raw_brctl_show: Option<String>,
    raw_vlan_config: Option<String>,
    raw_ip_netns: Vec<String>,
    raw_ip_addrs: Vec<String>,

    process_data: Vec<ProcessData>,

    kubernetes_version: u64,
    kubernetes_interfaces: Vec<InterfaceInfo>,
    kubeif_store: InterfaceInfoStore,

    xml_interfaces: Vec<InterfaceEntry>,
}

impl Querier {
    pub fn new(
        override_os_hostname: Option<String>,
        libvirt_xml_extractor: Arc<LibvirtXmlExtractor>,
    ) -> Self {
        Self {
            override_os_hostname,
            libvirt_xml_extractor,

            kubernetes_poller: None,
            netns_regex: Default::default(),

            digest: Default::default(),

            raw_hostname: Default::default(),
            raw_all_vm_xml: Default::default(),
            raw_vm_states: Default::default(),
            raw_ovs_interfaces: Default::default(),
            raw_ovs_ports: Default::default(),
            raw_brctl_show: Default::default(),
            raw_vlan_config: Default::default(),
            raw_ip_netns: Default::default(),
            raw_ip_addrs: Default::default(),

            process_data: Default::default(),

            kubernetes_version: Default::default(),
            kubernetes_interfaces: Default::default(),
            kubeif_store: Default::default(),

            xml_interfaces: Default::default(),
        }
    }

    pub fn digest(&self) -> u64 {
        self.digest
    }

    // returns digest
    pub fn update(&mut self, config: &PlatformConfig) -> u64 {
        // reconstruct regex if changed
        match self.netns_regex.as_ref() {
            Some(re) if re.as_str() != config.extra_netns_regex.as_str() => self.netns_regex = None,
            _ => (),
        }
        if self.netns_regex.is_none() && config.extra_netns_regex != "" {
            match Regex::new(config.extra_netns_regex.as_str()) {
                Ok(new_re) => {
                    info!("extra_netns_regex updated to /{}/", new_re.as_str());
                    self.netns_regex = Some(new_re);
                }
                Err(e) => {
                    warn!(
                        "extra_netns_regex /{}/ is invalid: {}",
                        config.extra_netns_regex.as_str(),
                        e
                    )
                }
            }
        }

        let mut netns = vec![NsFile::Root];
        if let Some(re) = self.netns_regex.as_ref() {
            let mut extra_ns = netns::find_ns_files_by_regex(re);
            extra_ns.sort_unstable();
            netns.extend(extra_ns);
        }
        debug!("query net namespace {:?}", netns);

        let mut hasher = AHasher::default();

        self.update_raw_hostname(&mut hasher);
        self.update_raw_ip_addr_and_netns(&netns, &mut hasher);

        if config.enabled {
            Self::update_simple_field(
                &mut self.raw_all_vm_xml,
                "all_vm_xml",
                || get_all_vm_xml(&config.libvirt_xml_path),
                &mut hasher,
            );
            Self::update_simple_field(
                &mut self.raw_vm_states,
                "vm_states",
                get_vm_states,
                &mut hasher,
            );
            Self::update_simple_field(
                &mut self.raw_ovs_interfaces,
                "ovs_interfaces",
                get_ovs_interfaces,
                &mut hasher,
            );
            Self::update_simple_field(
                &mut self.raw_ovs_ports,
                "ovs_ports",
                get_ovs_ports,
                &mut hasher,
            );
            Self::update_simple_field(
                &mut self.raw_brctl_show,
                "brctl_show",
                get_brctl_show,
                &mut hasher,
            );
            Self::update_simple_field(
                &mut self.raw_vlan_config,
                "vlan_config",
                get_vlan_config,
                &mut hasher,
            );
        }

        self.update_process_data(config, &mut hasher);
        self.update_kubernetes_interfaces(&netns, &mut hasher);
        self.update_xml_interfaces(&mut hasher);

        self.digest = hasher.finish();
        self.digest()
    }

    pub fn generate_message(&self, config: &PlatformConfig) -> pb::GenesisSyncRequest {
        let mut interfaces: Vec<_> = self
            .kubernetes_poller
            .as_ref()
            .map(|poller| {
                fn info_to_pb(info: &InterfaceInfo) -> pb::InterfaceInfo {
                    pb::InterfaceInfo {
                        mac: Some(info.mac.into()),
                        name: Some(info.name.to_string()),
                        device_id: Some(info.device_id.to_string()),
                        tap_index: Some(info.tap_idx),
                        ip: info.ips.iter().map(ToString::to_string).collect(),
                        netns: Some(info.tap_ns.to_string()),
                        netns_id: Some(info.ns_inode as u32),
                        if_type: info.if_type.clone(),
                        ..Default::default()
                    }
                }

                if matches!(poller.as_ref(), &GenericPoller::ActivePoller(_)) {
                    self.kubeif_store
                        .iter()
                        .map(|info| info_to_pb(info))
                        .collect()
                } else {
                    self.kubernetes_interfaces
                        .iter()
                        .map(|info| info_to_pb(info))
                        .collect()
                }
            })
            .unwrap_or_default();
        interfaces.extend(self.xml_interfaces.iter().map(|info| pb::InterfaceInfo {
            name: Some(info.name.clone()),
            mac: Some(info.mac.into()),
            device_id: Some(info.domain_uuid.clone()),
            device_name: Some(info.domain_name.clone()),
            ..Default::default()
        }));

        let mut platform_data = pb::GenesisPlatformData {
            platform_enabled: Some(config.enabled),
            raw_hostname: self.raw_hostname.clone(),
            raw_ip_netns: self.raw_ip_netns.clone(),
            raw_ip_addrs: self.raw_ip_addrs.clone(),
            interfaces,
            ..Default::default()
        };
        if config.enabled {
            platform_data.raw_all_vm_xml = self.raw_all_vm_xml.clone();
            platform_data.raw_vm_states = self.raw_vm_states.clone();
            platform_data.raw_ovs_interfaces = self.raw_ovs_interfaces.clone();
            platform_data.raw_ovs_ports = self.raw_ovs_ports.clone();
            platform_data.raw_brctl_show = self.raw_brctl_show.clone();
            platform_data.raw_vlan_config = self.raw_vlan_config.clone();
        }

        pb::GenesisSyncRequest {
            platform_data: Some(platform_data),
            process_data: Some(pb::GenesisProcessData {
                process_entries: self
                    .process_data
                    .iter()
                    .map(|data| pb::ProcessInfo::from(data))
                    .collect(),
            }),
            ..Default::default()
        }
    }

    pub fn set_kubernetes_poller(&mut self, poller: Arc<GenericPoller>) {
        self.kubernetes_poller.replace(poller);
    }

    fn update_raw_hostname(&mut self, hasher: &mut AHasher) {
        if let Some(hostname) = self.override_os_hostname.as_ref() {
            if self.raw_hostname.is_none() {
                self.raw_hostname = Some(hostname.clone());
            }
            return;
        }
        match get_hostname() {
            Ok(hostname) => {
                debug!("get_hostname() = {}", hostname);
                hasher.write(hostname.as_bytes());
                trace!("digest={:016x}", hasher.finish());
                self.raw_hostname = Some(hostname);
            }
            Err(e) => debug!("get_hostname failed: {}", e),
        }
    }

    fn update_raw_ip_addr_and_netns(&mut self, netns: &[NsFile], hasher: &mut AHasher) {
        self.raw_ip_addrs.clear();
        self.raw_ip_netns.clear();
        for ns in netns {
            if let Err(e) = netns::open_named_and_setns(&ns) {
                warn!("setns to {:?} failed: {}", ns, e);
                continue;
            }
            let raw_host_ip_addr = get_ip_address()
                .map_err(|err| debug!("get_ip_address error:{}", err))
                .ok();
            if let Some(ip_addr) = raw_host_ip_addr.as_ref() {
                for line in ip_addr.lines() {
                    // 忽略可能变化的行避免version频繁更新
                    if line.contains("valid_lft") {
                        continue;
                    }
                    hasher.write(line.as_bytes());
                }
            }
            self.raw_ip_netns.push(ns.to_string());
            self.raw_ip_addrs.push(raw_host_ip_addr.unwrap_or_default());
        }
        if let Err(e) = netns::reset_netns() {
            warn!("restore net namespace failed: {}", e);
        }
        debug!(
            "updated ip addresses in {} namespaces",
            self.raw_ip_netns.len()
        );
        trace!("digest={:016x}", hasher.finish());
    }

    fn update_simple_field<F>(
        field: &mut Option<String>,
        label: &str,
        func: F,
        hasher: &mut AHasher,
    ) where
        F: Fn() -> Result<String, std::io::Error>,
    {
        match func() {
            Ok(s) => {
                debug!("get {} result len {}", label, s.len());
                hasher.write(s.as_bytes());
                trace!("digest={:016x}", hasher.finish());
                field.replace(s);
            }
            Err(e) => debug!("get {} failed: {}", label, e),
        }
    }

    fn update_process_data(&mut self, config: &PlatformConfig, hasher: &mut AHasher) {
        if !(process_info_enabled(config.trident_type)
            && config.os_proc_scan_conf.os_proc_sync_enabled)
        {
            return;
        }
        trace!("get process data with {:?}", config.os_proc_scan_conf);
        self.process_data.clear();
        get_all_process_in(&config.os_proc_scan_conf, &mut self.process_data);
        // sort and use pid for digest
        self.process_data.sort_by_key(|p| p.pid);
        for p in self.process_data.iter() {
            hasher.write_u64(p.pid);
        }
        debug!(
            "updated process data returned {} entries",
            self.process_data.len()
        );
        trace!("digest={:016x}", hasher.finish());
    }

    fn update_kubernetes_interfaces(&mut self, netns: &[NsFile], hasher: &mut AHasher) {
        let Some(poller) = self.kubernetes_poller.as_ref() else {
            return;
        };
        trace!("get kubernetes interfaces");

        if matches!(poller.as_ref(), &GenericPoller::ActivePoller(_)) {
            // do not use poller in active mode for faster change detection
            let m = match netns::interfaces_linked_with(netns) {
                Ok(m) => m,
                Err(e) => {
                    warn!("query namespace interfaces failed: {:?}", e);
                    return;
                }
            };
            self.kubeif_store.merge(m);
            let mut n = 0;
            for item in self.kubeif_store.iter() {
                n += 1;
                hasher.write_u64(u64::from(item.mac));
            }
            debug!("updated kubernetes interfaces returned {} entries", n);
        } else {
            let version = poller.get_version();
            if version != self.kubernetes_version {
                let mut interfaces = poller.get_interface_info();
                interfaces.sort_unstable();
                std::mem::swap(&mut self.kubernetes_interfaces, &mut interfaces);
            }
            for item in self.kubernetes_interfaces.iter() {
                hasher.write_u64(u64::from(item.mac));
            }
            debug!(
                "updated kubernetes interfaces returned {} entries",
                self.kubernetes_interfaces.len()
            );
        }

        trace!("digest={:016x}", hasher.finish());
    }

    fn update_xml_interfaces(&mut self, hasher: &mut AHasher) {
        trace!("get xml interfaces");
        let Some(mut interfaces) = self.libvirt_xml_extractor.get_entries() else {
            return;
        };
        interfaces.sort_by_key(|f| f.mac);
        std::mem::swap(&mut self.xml_interfaces, &mut interfaces);
        for p in self.xml_interfaces.iter() {
            hasher.write_u64(u64::from(p.mac));
        }
        debug!(
            "updated libvirt xml interfaces returned {} entries",
            self.xml_interfaces.len()
        );
        trace!("digest={:016x}", hasher.finish());
    }
}
