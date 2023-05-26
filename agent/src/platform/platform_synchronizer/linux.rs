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

use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    thread,
    thread::JoinHandle,
    time::{Duration, SystemTime},
};

use arc_swap::access::Access;
use log::{debug, error, info, warn};
use regex::Regex;
use ring::digest;
use tokio::runtime::Runtime;

use crate::{
    config::{handler::PlatformAccess, KubernetesPollerType},
    exception::ExceptionHandler,
    handler,
    platform::{
        kubernetes::{
            check_read_link_ns, check_set_ns, ActivePoller, GenericPoller, PassivePoller, Poller,
        },
        InterfaceEntry, LibvirtXmlExtractor,
    },
    rpc::Session,
    utils::{
        command::{
            get_all_vm_xml, get_brctl_show, get_hostname, get_ip_address, get_ovs_interfaces,
            get_ovs_ports, get_vlan_config, get_vm_states,
        },
        environment::is_tt_pod,
    },
};

use public::{
    netns::{InterfaceInfo, NetNs, NsFile},
    proto::trident::{self, Exception},
};

const SHA1_DIGEST_LEN: usize = 20;

struct ProcessArgs {
    runtime: Arc<Runtime>,
    config: PlatformAccess,
    running: Arc<Mutex<bool>>,
    version: Arc<AtomicU64>,
    session: Arc<Session>,
    sniffer: Arc<sniffer_builder::Sniffer>,
    timer: Arc<Condvar>,
    xml_extractor: Arc<LibvirtXmlExtractor>,
    kubernetes_poller: Arc<GenericPoller>,
    exception_handler: ExceptionHandler,
    extra_netns_regex: Arc<Mutex<Option<Regex>>>,
}

#[derive(Default)]
struct PlatformArgs {
    raw_hostname: Option<String>,
    raw_all_vm_xml: Option<String>,
    raw_vm_states: Option<String>,
    raw_ovs_interfaces: Option<String>,
    raw_ovs_ports: Option<String>,
    raw_brctl_show: Option<String>,
    raw_vlan_config: Option<String>,
    raw_ip_netns: Vec<String>,
    raw_ip_addrs: Vec<String>,
    ips: Vec<handler::IpInfo>,
    lldps: Vec<handler::LldpInfo>,
}

#[derive(Default)]
struct HashArgs {
    raw_info_hash: [u8; SHA1_DIGEST_LEN],
    lldp_info_hash: [u8; SHA1_DIGEST_LEN],
    xml_interfaces_hash: [u8; SHA1_DIGEST_LEN],
}

pub struct PlatformSynchronizer {
    runtime: Arc<Runtime>,
    config: PlatformAccess,
    version: Arc<AtomicU64>,
    running: Arc<Mutex<bool>>,
    timer: Arc<Condvar>,
    kubernetes_poller: Arc<GenericPoller>,
    thread: Mutex<Option<JoinHandle<()>>>,
    session: Arc<Session>,
    xml_extractor: Arc<LibvirtXmlExtractor>,
    sniffer: Arc<sniffer_builder::Sniffer>,
    exception_handler: ExceptionHandler,
    extra_netns_regex: Arc<Mutex<Option<Regex>>>,
}

impl PlatformSynchronizer {
    pub fn new(
        runtime: Arc<Runtime>,
        config: PlatformAccess,
        session: Arc<Session>,
        xml_extractor: Arc<LibvirtXmlExtractor>,
        exception_handler: ExceptionHandler,
        extra_netns_regex: String,
    ) -> Self {
        let (can_set_ns, can_read_link_ns) = (check_set_ns(), check_read_link_ns());

        if !can_set_ns || !can_read_link_ns {
            warn!(
                "kubernetes poller privileges: set_ns={} read_link_ns={}",
                can_set_ns, can_read_link_ns
            );
        } else {
            info!(
                "kubernetes poller privileges: set_ns={} read_link_ns={}",
                can_set_ns, can_read_link_ns
            );
        }

        let extra_netns_regex = if extra_netns_regex != "" {
            info!("platform monitoring extra netns: /{}/", extra_netns_regex);
            Some(Regex::new(&extra_netns_regex).unwrap())
        } else {
            info!("platform monitoring no extra netns");
            None
        };

        let sync_interval = config.load().sync_interval;
        let kubernetes_poller_type = config.load().kubernetes_poller_type;
        let poller = match kubernetes_poller_type {
            KubernetesPollerType::Adaptive => {
                if can_set_ns && can_read_link_ns {
                    GenericPoller::from(ActivePoller::new(sync_interval, extra_netns_regex.clone()))
                } else {
                    GenericPoller::from(PassivePoller::new(sync_interval, config.clone()))
                }
            }
            KubernetesPollerType::Active => {
                GenericPoller::from(ActivePoller::new(sync_interval, extra_netns_regex.clone()))
            }
            KubernetesPollerType::Passive => {
                GenericPoller::from(PassivePoller::new(sync_interval, config.clone()))
            }
        };

        let kubernetes_poller = Arc::new(poller);
        let mappings = mappings::Mappings;
        mappings.set_kubernetes_poller(kubernetes_poller.clone());
        let sniffer = Arc::new(sniffer_builder::Sniffer);

        Self {
            runtime,
            config,
            version: Arc::new(AtomicU64::new(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )),
            kubernetes_poller,
            running: Arc::new(Mutex::new(false)),
            timer: Arc::new(Condvar::new()),
            thread: Mutex::new(None),
            session,
            xml_extractor,
            sniffer,
            exception_handler,
            extra_netns_regex: Arc::new(Mutex::new(extra_netns_regex)),
        }
    }

    pub fn start_kubernetes_poller(&self) {
        self.kubernetes_poller.start()
    }

    pub fn stop_kubernetes_poller(&self) {
        self.kubernetes_poller.stop()
    }

    pub fn set_netns_regex<S: AsRef<str>>(&self, regex: S) {
        let regex = if regex.as_ref() != "" {
            info!("platform monitoring extra netns: /{}/", regex.as_ref());
            Some(Regex::new(regex.as_ref()).unwrap())
        } else {
            info!("platform monitoring no extra netns");
            None
        };
        self.kubernetes_poller.set_netns_regex(regex.clone());
        *self.extra_netns_regex.lock().unwrap() = regex;
    }

    pub fn is_running(&self) -> bool {
        *self.running.lock().unwrap()
    }

    pub fn clone_poller(&self) -> Arc<GenericPoller> {
        self.kubernetes_poller.clone()
    }

    pub fn stop(&self) {
        let mut running_lock = self.running.lock().unwrap();
        if !*running_lock {
            let config_guard = self.config.load();
            let err = format!(
                "PlatformSynchronizer has already stopped with ctrl-ip:{} vtap-id:{}",
                config_guard.source_ip, config_guard.vtap_id
            );
            debug!("{}", err);
            return;
        }
        *running_lock = false;
        drop(running_lock);

        self.timer.notify_one();
        if let Some(handle) = self.thread.lock().unwrap().take() {
            let _ = handle.join();
        }

        self.stop_kubernetes_poller();
        info!("PlatformSynchronizer stopped");
    }

    pub fn start(&self) {
        let mut running_guard = self.running.lock().unwrap();
        if *running_guard {
            let config_guard = self.config.load();
            let err = format!(
                "PlatformSynchronizer has already running with ctrl-ip:{} vtap-id:{}",
                config_guard.source_ip, config_guard.vtap_id
            );
            debug!("{}", err);
            return;
        }
        *running_guard = true;
        drop(running_guard);

        let process_args = ProcessArgs {
            runtime: self.runtime.clone(),
            config: self.config.clone(),
            running: self.running.clone(),
            version: self.version.clone(),
            kubernetes_poller: self.kubernetes_poller.clone(),
            timer: self.timer.clone(),
            session: self.session.clone(),
            xml_extractor: self.xml_extractor.clone(),
            sniffer: self.sniffer.clone(),
            exception_handler: self.exception_handler.clone(),
            extra_netns_regex: self.extra_netns_regex.clone(),
        };

        let handle = thread::Builder::new()
            .name("platform-synchronizer".to_owned())
            .spawn(move || Self::process(process_args))
            .unwrap();
        *self.thread.lock().unwrap() = Some(handle);

        if is_tt_pod(self.config.load().trident_type) {
            self.kubernetes_poller.start();
        }
        info!("PlatformSynchronizer started");
    }

    fn query_platform(
        platform_args: &mut PlatformArgs,
        hash_args: &mut HashArgs,
        self_interface_infos: &mut Vec<InterfaceInfo>,
        self_xml_interfaces: &mut Vec<InterfaceEntry>,
        process_args: &ProcessArgs,
        self_kubernetes_version: &mut u64,
        self_last_ip_update_timestamp: &mut Duration,
        netns: &Vec<NsFile>,
    ) {
        let platform_enabled = process_args.config.load().enabled;

        let mut changed = 0;

        let mut hash_handle = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);

        let raw_hostname = get_hostname()
            .map_err(|err| debug!("get_hostname error:{}", err))
            .ok();
        if let Some(hostname) = raw_hostname.as_ref() {
            hash_handle.update(hostname.as_bytes());
        }

        let mut raw_ip_netns = vec![];
        let mut raw_ip_addrs = vec![];
        let current_ns = if netns.len() > 1 {
            // for restore
            let current_ns = NetNs::open_current_ns();
            if let Err(e) = current_ns {
                warn!("get self net namespace failed: {:?}", e);
                return;
            }
            current_ns.ok()
        } else {
            None
        };
        for ns in netns {
            if ns != &NsFile::Root {
                if let Err(e) = NetNs::open_named_and_setns(ns) {
                    warn!("setns to {:?} failed: {}", ns, e);
                    continue;
                }
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
                    hash_handle.update(line.as_bytes());
                }
            }
            raw_ip_netns.push(ns.to_string());
            raw_ip_addrs.push(raw_host_ip_addr.unwrap_or_default());
        }
        if let Some(ns) = current_ns {
            if let Err(e) = NetNs::setns(&ns, Some(NetNs::CURRENT_NS_PATH)) {
                warn!("restore net namespace failed: {}", e);
                return;
            }
        }

        let mut raw_all_vm_xml = None;
        let mut raw_vm_states = None;
        let mut raw_ovs_interfaces = None;
        let mut raw_ovs_ports = None;
        let mut raw_brctl_show = None;
        let mut raw_vlan_config = None;

        if platform_enabled {
            raw_all_vm_xml = get_all_vm_xml(process_args.config.load().libvirt_xml_path.as_path())
                .map_err(|err| debug!("get_all_vm_xml error:{}", err))
                .ok();

            if let Some(xml) = raw_all_vm_xml.as_ref() {
                hash_handle.update(xml.as_bytes());
            }

            raw_vm_states = get_vm_states()
                .map_err(|err| debug!("get_vm_states error:{}", err))
                .ok();
            if let Some(states) = raw_vm_states.as_ref() {
                hash_handle.update(states.as_bytes());
            }

            raw_ovs_interfaces = get_ovs_interfaces()
                .map_err(|err| debug!("get_ovs_interfaces error:{}", err))
                .ok();
            if let Some(ovs_interfaces) = raw_ovs_interfaces.as_ref() {
                hash_handle.update(ovs_interfaces.as_bytes());
            }

            raw_ovs_ports = get_ovs_ports()
                .map_err(|err| debug!("get_ovs_ports error:{}", err))
                .ok();
            if let Some(ovs_ports) = raw_ovs_ports.as_ref() {
                hash_handle.update(ovs_ports.as_bytes());
            }

            raw_brctl_show = get_brctl_show()
                .map_err(|err| debug!("get_brctl_show error:{}", err))
                .ok();
            if let Some(brctl_show) = raw_brctl_show.as_ref() {
                hash_handle.update(brctl_show.as_bytes());
            }

            raw_vlan_config = get_vlan_config()
                .map_err(|err| debug!("get_vlan_config error:{}", err))
                .ok();
            if let Some(vlan_config) = raw_vlan_config.as_ref() {
                hash_handle.update(vlan_config.as_bytes());
            }
        }

        let hash_sum = hash_handle.finish();
        let raw_info_hash = hash_sum.as_ref();
        if raw_info_hash != hash_args.raw_info_hash {
            debug!("raw info changed");
            changed += 1;
        }

        let mut lldp_info_hash = [0u8; SHA1_DIGEST_LEN];
        let mut ip_update_timestamp = Duration::default();
        let mut ip_records = vec![];
        let mut lldp_records = vec![];

        if platform_enabled {
            let records = process_args.sniffer.get_ip_records();
            ip_update_timestamp = records.0;
            ip_records = records.1;
            if ip_update_timestamp > *self_last_ip_update_timestamp {
                debug!("ip info changed");
                changed += 1;
            }

            lldp_records = process_args.sniffer.get_lldp_records();
            lldp_records.iter().for_each(|record| {
                let mut lldp_hash_handle = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
                lldp_hash_handle.update(record.lldp_du.port_id.as_bytes());
                lldp_hash_handle.update(record.lldp_du.port_description.as_bytes());
                lldp_hash_handle.update(record.lldp_du.system_name.as_bytes());
                record
                    .lldp_du
                    .management_address
                    .iter()
                    .for_each(|address| lldp_hash_handle.update(address.as_bytes()));
                lldp_hash_handle.update(&record.lldp_du.ttl.to_be_bytes());

                let lldp_digest = lldp_hash_handle.finish();
                for (i, &b) in lldp_digest.as_ref().into_iter().enumerate() {
                    lldp_info_hash[i] ^= b;
                }
            });

            if lldp_info_hash != hash_args.lldp_info_hash {
                debug!("lldp info changed");
                changed += 1;
            }
        }

        let new_kubernetes_version = process_args.kubernetes_poller.get_version();
        if new_kubernetes_version != *self_kubernetes_version {
            debug!("kubernetes info changed");
            changed += 1;
        }

        let xml_interfaces = process_args.xml_extractor.get_entries();
        let mut xml_interface_hash = [0u8; SHA1_DIGEST_LEN];
        if let Some(xml_interfaces) = xml_interfaces.as_ref() {
            xml_interfaces.iter().for_each(|interface| {
                let mut xml_info_handle = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
                xml_info_handle.update(interface.name.as_bytes());
                xml_info_handle.update(u64::from(interface.mac).to_string().as_bytes());
                xml_info_handle.update(interface.domain_name.as_bytes());

                let digest = xml_info_handle.finish();
                for (i, &b) in digest.as_ref().into_iter().enumerate() {
                    xml_interface_hash[i] ^= b;
                }
            });
        }
        if xml_interface_hash != hash_args.xml_interfaces_hash {
            debug!("xml interfaces info changed");
            changed += 1;
        }

        if changed > 0 {
            if raw_info_hash != hash_args.raw_info_hash {
                hash_args.raw_info_hash.copy_from_slice(raw_info_hash);
                platform_args.raw_hostname = raw_hostname;

                if platform_enabled {
                    platform_args.raw_all_vm_xml = raw_all_vm_xml;
                    platform_args.raw_vm_states = raw_vm_states;
                    platform_args.raw_ovs_interfaces = raw_ovs_interfaces;
                    platform_args.raw_ovs_ports = raw_ovs_ports;
                    platform_args.raw_brctl_show = raw_brctl_show;
                    platform_args.raw_vlan_config = raw_vlan_config;
                }
                platform_args.raw_ip_netns = raw_ip_netns;
                platform_args.raw_ip_addrs = raw_ip_addrs;
            }

            if platform_enabled {
                if ip_update_timestamp > *self_last_ip_update_timestamp {
                    platform_args.ips = ip_records;
                    *self_last_ip_update_timestamp = ip_update_timestamp;
                }
                if lldp_info_hash != hash_args.lldp_info_hash {
                    platform_args.lldps = lldp_records;
                    hash_args.lldp_info_hash.copy_from_slice(&lldp_info_hash);
                }
            }

            if new_kubernetes_version != *self_kubernetes_version {
                *self_interface_infos = process_args.kubernetes_poller.get_interface_info();
                *self_kubernetes_version = new_kubernetes_version;
            }

            if xml_interface_hash != hash_args.xml_interfaces_hash {
                if let Some(xml_interfaces) = xml_interfaces {
                    *self_xml_interfaces = xml_interfaces;
                    hash_args
                        .xml_interfaces_hash
                        .copy_from_slice(&xml_interface_hash);
                }
            }
            info!(
                "Platform information changed to version {}",
                process_args.version.fetch_add(1, Ordering::SeqCst) + 1
            );
        }
    }

    fn push_platform_message(
        platform_args: &PlatformArgs,
        process_args: &ProcessArgs,
        self_interface_infos: &Vec<InterfaceInfo>,
        self_xml_interfaces: &Vec<InterfaceEntry>,
        vtap_id: u16,
        version: u64,
    ) -> Result<u64, tonic::Status> {
        let config_guard = process_args.config.load();
        let trident_type = config_guard.trident_type;
        let ctrl_ip = config_guard.source_ip;
        let platform_enabled = config_guard.enabled;
        drop(config_guard);

        let (mut ips, mut lldp_infos) = (vec![], vec![]);

        let mut raw_all_vm_xml = None;
        let mut raw_vm_states = None;
        let mut raw_ovs_interfaces = None;
        let mut raw_ovs_ports = None;
        let mut raw_brctl_show = None;
        let mut raw_vlan_config = None;

        if platform_enabled {
            raw_all_vm_xml = platform_args.raw_all_vm_xml.clone();
            raw_vm_states = platform_args.raw_vm_states.clone();
            raw_ovs_interfaces = platform_args.raw_ovs_interfaces.clone();
            raw_ovs_ports = platform_args.raw_ovs_ports.clone();
            raw_brctl_show = platform_args.raw_brctl_show.clone();
            raw_vlan_config = platform_args.raw_vlan_config.clone();
            ips = platform_args
                .ips
                .iter()
                .map(|ip_info| {
                    let addr = match ip_info.ip {
                        IpAddr::V4(addr) => Vec::from(addr.octets()),
                        IpAddr::V6(addr) => Vec::from(addr.octets()),
                    };
                    trident::Ip {
                        last_seen: Some(ip_info.last_seen.as_secs() as u32),
                        mac: Some(ip_info.mac.into()),
                        ip: Some(addr),
                        port_uuid: None,
                    }
                })
                .collect();

            lldp_infos = platform_args
                .lldps
                .iter()
                .map(|lldp_info| trident::Lldp {
                    port_id: Some(lldp_info.lldp_du.port_id.to_string()),
                    interface: None,
                    system_name: Some(lldp_info.lldp_du.system_name.to_string()),
                    management_address: Some(lldp_info.lldp_du.management_address[0].to_string()),
                    port_description: Some(lldp_info.lldp_du.port_description.to_string()),
                })
                .collect();
        }

        let interfaces: Vec<trident::InterfaceInfo> = self_interface_infos
            .iter()
            .map(|interface_info| trident::InterfaceInfo {
                mac: Some(interface_info.mac.into()),
                name: Some(interface_info.name.to_string()),
                device_id: Some(interface_info.device_id.to_string()),
                tap_index: Some(interface_info.tap_idx),
                ip: interface_info.ips.iter().map(ToString::to_string).collect(),
                device_name: None,
                netns: Some(interface_info.tap_ns.to_string()),
            })
            .chain(
                self_xml_interfaces
                    .iter()
                    .map(|entry| trident::InterfaceInfo {
                        name: Some(entry.name.clone()),
                        mac: Some(entry.mac.into()),
                        device_id: Some(entry.domain_uuid.clone()),
                        device_name: Some(entry.domain_name.clone()),
                        ip: vec![],
                        tap_index: None,
                        netns: None,
                    }),
            )
            .collect();

        let platform_data = trident::GenesisPlatformData {
            ips,
            platform_enabled: Some(platform_enabled),
            raw_hostname: platform_args.raw_hostname.clone(),
            raw_all_vm_xml,
            raw_vm_states,
            raw_ovs_interfaces,
            raw_ovs_ports,
            raw_brctl_show,
            raw_vlan_config,
            lldp_info: lldp_infos,
            raw_ip_netns: platform_args.raw_ip_netns.clone(),
            raw_ip_addrs: platform_args.raw_ip_addrs.clone(),
            interfaces,
        };

        let msg = trident::GenesisSyncRequest {
            version: Some(version),
            trident_type: Some(trident_type as i32),
            platform_data: Some(platform_data),
            source_ip: Some(ctrl_ip.to_string()),
            vtap_id: Some(vtap_id as u32),
            kubernetes_cluster_id: Some(
                process_args.config.load().kubernetes_cluster_id.to_string(),
            ),
            nat_ip: None,
        };

        process_args
            .runtime
            .block_on(process_args.session.grpc_genesis_sync_with_statsd(msg))
            .map(|r| r.into_inner().version())
    }

    fn process(args: ProcessArgs) {
        let mut last_version = 0;
        let mut kubernetes_version = 0;
        let mut last_ip_update_timestamp = Duration::default();
        let init_version = args.version.load(Ordering::Relaxed);

        let mut hash_args = HashArgs::default();
        let mut platform_args = PlatformArgs::default();

        let mut interface_infos = vec![];
        let mut xml_interfaces = vec![];

        let mut netns = vec![];

        loop {
            let mut new_netns = vec![NsFile::Root];
            if let Some(re) = &*args.extra_netns_regex.lock().unwrap() {
                let mut extra_ns = NetNs::find_ns_files_by_regex(&re);
                extra_ns.sort_unstable();
                new_netns.extend(extra_ns);
            }
            if netns.is_empty() {
                netns = new_netns;
            } else if netns != new_netns {
                info!(
                    "query net namespaces changed from {:?} to {:?}",
                    netns, new_netns
                );
                netns = new_netns;
            }
            Self::query_platform(
                &mut platform_args,
                &mut hash_args,
                &mut interface_infos,
                &mut xml_interfaces,
                &args,
                &mut kubernetes_version,
                &mut last_ip_update_timestamp,
                &netns,
            );

            let cur_version = args.version.load(Ordering::SeqCst);

            let config_guard = args.config.load();
            let cur_vtap_id = config_guard.vtap_id;
            let trident_type = config_guard.trident_type;
            let ctrl_ip = config_guard.source_ip;
            let poll_interval = config_guard.sync_interval;
            drop(config_guard);

            if cur_version == init_version {
                // 避免信息同步先于信息采集
                // ====
                // wait 5 seconds to check version change
                if Self::wait_timeout(&args.running, &args.timer, Duration::from_secs(5)) {
                    break;
                }
                continue;
            }

            if last_version == cur_version {
                let msg = trident::GenesisSyncRequest {
                    version: Some(cur_version),
                    trident_type: Some(trident_type as i32),
                    source_ip: Some(ctrl_ip.to_string()),
                    vtap_id: Some(cur_vtap_id as u32),
                    kubernetes_cluster_id: Some(
                        args.config.load().kubernetes_cluster_id.to_string(),
                    ),
                    platform_data: None,
                    nat_ip: None,
                };

                match args
                    .runtime
                    .block_on(args.session.grpc_genesis_sync_with_statsd(msg))
                {
                    Ok(res) => {
                        let res = res.into_inner();
                        let remote_version = res.version();
                        if remote_version == cur_version {
                            if Self::wait_timeout(&args.running, &args.timer, poll_interval) {
                                break;
                            }
                            continue;
                        }
                        info!(
                            "local version {}, remote version {}",
                            cur_version, remote_version
                        );
                    }
                    Err(e) => {
                        args.exception_handler.set(Exception::ControllerSocketError);
                        error!(
                            "send platform heartbeat with genesis_sync grpc call failed: {}",
                            e
                        );
                        if Self::wait_timeout(&args.running, &args.timer, poll_interval) {
                            break;
                        }
                        continue;
                    }
                }
            } else {
                info!("local version changed to {}", cur_version);
            }

            match Self::push_platform_message(
                &platform_args,
                &args,
                &interface_infos,
                &xml_interfaces,
                cur_vtap_id,
                cur_version,
            ) {
                Ok(version) => last_version = version,
                Err(e) => {
                    args.exception_handler.set(Exception::ControllerSocketError);
                    error!(
                        "send platform information with genesis_sync grpc call failed: {}",
                        e
                    );
                    if Self::wait_timeout(&args.running, &args.timer, poll_interval) {
                        break;
                    }
                    continue;
                }
            }

            if Self::wait_timeout(&args.running, &args.timer, poll_interval) {
                break;
            }
        }
    }

    fn wait_timeout(running: &Arc<Mutex<bool>>, timer: &Arc<Condvar>, interval: Duration) -> bool {
        let guard = running.lock().unwrap();
        if !*guard {
            return true;
        }
        let (guard, _) = timer.wait_timeout(guard, interval).unwrap();
        if !*guard {
            return true;
        }
        false
    }
}

mod config {
    use public::proto::common;
    pub struct StaticConfig;
    impl StaticConfig {
        pub fn get_trident_type(&self) -> common::TridentType {
            todo!()
        }

        pub fn is_tt_pod(&self) -> bool {
            todo!()
        }
    }
}

mod sniffer_builder {
    use std::time::Duration;

    use crate::handler::{IpInfo, LldpInfo};

    pub struct Sniffer;

    impl Sniffer {
        pub fn get_ip_records(&self) -> (Duration, Vec<IpInfo>) {
            (Duration::ZERO, vec![])
        }

        pub fn get_lldp_records(&self) -> Vec<LldpInfo> {
            vec![]
        }
    }
}

mod mappings {
    use crate::platform::kubernetes::GenericPoller;
    use std::sync::Arc;
    pub struct Mappings;
    impl Mappings {
        pub fn set_kubernetes_poller(&self, _poller: Arc<GenericPoller>) {}
    }
}
//END
