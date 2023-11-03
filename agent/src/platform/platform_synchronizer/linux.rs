/*
 * Copyright (c) 2023 Yunshan Networks
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
    collections::HashMap,
    net::{IpAddr, SocketAddr, SocketAddrV4},
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Condvar, Mutex, MutexGuard,
    },
    thread,
    thread::JoinHandle,
    time::{Duration, SystemTime},
};

use arc_swap::access::Access;
use log::{debug, error, info, warn};
use parking_lot::RwLock;
use regex::Regex;
use ring::digest;
use tokio::runtime::Runtime;

use crate::{
    common::policy::GpidEntry,
    config::handler::{OsProcScanConfig, PlatformAccess},
    exception::ExceptionHandler,
    handler,
    platform::{
        kubernetes::{GenericPoller, Poller},
        InterfaceEntry, LibvirtXmlExtractor,
    },
    policy::{PolicyGetter, PolicySetter},
    rpc::Session,
    trident::AgentId,
    utils::{
        command::{
            get_all_vm_xml, get_brctl_show, get_hostname, get_ip_address, get_ovs_interfaces,
            get_ovs_ports, get_vlan_config, get_vm_states,
        },
        lru::Lru,
    },
};

use public::{
    netns::{self, InterfaceInfo, NsFile},
    proto::{
        common::TridentType,
        trident::{
            self, Exception, GenesisProcessData, GpidSyncRequest, GpidSyncResponse, ProcessInfo,
        },
    },
    queue::Receiver,
};

use super::{
    calc_process_datas_sha1, get_all_socket, linux_process::get_all_process, process_info_enabled,
    ProcessData, Role, SockAddrData,
};

pub const SHA1_DIGEST_LEN: usize = 20;

pub(super) struct ProcessArgs {
    pub(super) runtime: Arc<Runtime>,
    pub(super) config: PlatformAccess,
    pub(super) running: Arc<Mutex<bool>>,
    pub(super) version: Arc<AtomicU64>,
    pub(super) session: Arc<Session>,
    pub(super) sniffer: Arc<sniffer_builder::Sniffer>,
    pub(super) timer: Arc<Condvar>,
    pub(super) xml_extractor: Arc<LibvirtXmlExtractor>,
    pub(super) kubernetes_poller: Arc<Mutex<Option<Arc<GenericPoller>>>>,
    pub(super) exception_handler: ExceptionHandler,
    pub(super) extra_netns_regex: Arc<Mutex<Option<Regex>>>,
    pub(super) override_os_hostname: Arc<Option<String>>,
    pub(super) pid_netns_id_map: Arc<RwLock<HashMap<u32, u32>>>,
    pub(super) agent_id: Arc<RwLock<AgentId>>,
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
    process_data_hash: [u8; SHA1_DIGEST_LEN],
}

pub struct PlatformSynchronizer {
    runtime: Arc<Runtime>,
    config: PlatformAccess,
    version: Arc<AtomicU64>,
    running: Arc<Mutex<bool>>,
    timer: Arc<Condvar>,
    kubernetes_poller: Arc<Mutex<Option<Arc<GenericPoller>>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    session: Arc<Session>,
    xml_extractor: Arc<LibvirtXmlExtractor>,
    sniffer: Arc<sniffer_builder::Sniffer>,
    exception_handler: ExceptionHandler,
    extra_netns_regex: Arc<Mutex<Option<Regex>>>,
    override_os_hostname: Arc<Option<String>>,
    pid_netns_id_map: Arc<RwLock<HashMap<u32, u32>>>,
    agent_id: Arc<RwLock<AgentId>>,
}

impl PlatformSynchronizer {
    pub fn new(
        runtime: Arc<Runtime>,
        config: PlatformAccess,
        agent_id: Arc<RwLock<AgentId>>,
        session: Arc<Session>,
        xml_extractor: Arc<LibvirtXmlExtractor>,
        exception_handler: ExceptionHandler,
        extra_netns_regex: String,
        override_os_hostname: Option<String>,
        pid_netns_id_map: HashMap<u32, u32>,
    ) -> Self {
        let extra_netns_regex = if extra_netns_regex != "" {
            info!("platform monitoring extra netns: /{}/", extra_netns_regex);
            Some(Regex::new(&extra_netns_regex).unwrap())
        } else {
            info!("platform monitoring no extra netns");
            None
        };

        let sniffer = Arc::new(sniffer_builder::Sniffer);

        Self {
            runtime,
            config,
            agent_id,
            version: Arc::new(AtomicU64::new(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )),
            kubernetes_poller: Default::default(),
            running: Arc::new(Mutex::new(false)),
            timer: Arc::new(Condvar::new()),
            thread: Mutex::new(None),
            session,
            xml_extractor,
            sniffer,
            exception_handler,
            extra_netns_regex: Arc::new(Mutex::new(extra_netns_regex)),
            override_os_hostname: Arc::new(override_os_hostname),
            pid_netns_id_map: Arc::new(RwLock::new(pid_netns_id_map)),
        }
    }

    pub fn set_netns_regex(&self, regex: Option<Regex>) {
        *self.extra_netns_regex.lock().unwrap() = regex;
    }

    pub fn set_kubernetes_poller(&self, poller: Arc<GenericPoller>) {
        self.kubernetes_poller.lock().unwrap().replace(poller);
    }

    pub fn is_running(&self) -> bool {
        *self.running.lock().unwrap()
    }

    pub fn stop(&self) {
        let mut running_lock = self.running.lock().unwrap();
        if !*running_lock {
            let config_guard = self.config.load();
            let err = format!(
                "PlatformSynchronizer has already stopped with agent-id:{} vtap-id:{}",
                self.agent_id.read(),
                config_guard.vtap_id
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

        info!("PlatformSynchronizer stopped");
    }

    pub fn start(&self) {
        let mut running_guard = self.running.lock().unwrap();
        if *running_guard {
            let config_guard = self.config.load();
            let err = format!(
                "PlatformSynchronizer has already running with agent-id:{} vtap-id:{}",
                self.agent_id.read(),
                config_guard.vtap_id
            );
            debug!("{}", err);
            return;
        }
        *running_guard = true;
        drop(running_guard);

        let process_args = ProcessArgs {
            runtime: self.runtime.clone(),
            config: self.config.clone(),
            agent_id: self.agent_id.clone(),
            running: self.running.clone(),
            version: self.version.clone(),
            kubernetes_poller: self.kubernetes_poller.clone(),
            timer: self.timer.clone(),
            session: self.session.clone(),
            xml_extractor: self.xml_extractor.clone(),
            sniffer: self.sniffer.clone(),
            exception_handler: self.exception_handler.clone(),
            extra_netns_regex: self.extra_netns_regex.clone(),
            override_os_hostname: self.override_os_hostname.clone(),
            pid_netns_id_map: self.pid_netns_id_map.clone(),
        };

        let handle = thread::Builder::new()
            .name("platform-synchronizer".to_owned())
            .spawn(move || Self::process(process_args))
            .unwrap();
        *self.thread.lock().unwrap() = Some(handle);

        info!("PlatformSynchronizer started");
    }

    fn query_platform(
        platform_args: &mut PlatformArgs,
        hash_args: &mut HashArgs,
        self_interface_infos: &mut Vec<InterfaceInfo>,
        self_xml_interfaces: &mut Vec<InterfaceEntry>,
        process_info: &mut Vec<ProcessData>,
        process_info_enabled: bool,
        platform_enabled: bool,
        proc_scan_conf: &OsProcScanConfig,
        process_args: &ProcessArgs,
        self_kubernetes_version: &mut u64,
        self_last_ip_update_timestamp: &mut Duration,
        netns: &Vec<NsFile>,
        libvirt_xml_path: &Path,
    ) {
        let mut changed = 0;

        let mut hash_handle = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);

        let raw_hostname = process_args
            .override_os_hostname
            .as_ref()
            .clone()
            .or_else(|| match get_hostname() {
                Ok(name) => Some(name),
                Err(e) => {
                    debug!("get_hostname error: {}", e);
                    None
                }
            });
        if let Some(hostname) = raw_hostname.as_ref() {
            hash_handle.update(hostname.as_bytes());
        }

        let mut raw_ip_netns = vec![];
        let mut raw_ip_addrs = vec![];
        for ns in netns {
            if let Err(e) = netns::open_named_and_setns(ns) {
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
                    hash_handle.update(line.as_bytes());
                }
            }
            raw_ip_netns.push(ns.to_string());
            raw_ip_addrs.push(raw_host_ip_addr.unwrap_or_default());
        }
        if let Err(e) = netns::reset_netns() {
            warn!("restore net namespace failed: {}", e);
            return;
        }

        let mut raw_all_vm_xml = None;
        let mut raw_vm_states = None;
        let mut raw_ovs_interfaces = None;
        let mut raw_ovs_ports = None;
        let mut raw_brctl_show = None;
        let mut raw_vlan_config = None;

        if platform_enabled {
            raw_all_vm_xml = get_all_vm_xml(libvirt_xml_path)
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

        if process_info_enabled && proc_scan_conf.os_proc_sync_enabled {
            *process_info = get_all_process(proc_scan_conf);
            process_info.sort_by_key(|p| p.pid);
            let proc_sha1 = calc_process_datas_sha1(&*process_info);
            if proc_sha1 != hash_args.process_data_hash {
                debug!("proc info changed");
                hash_args.process_data_hash = proc_sha1;
                changed += 1;

                let mut w = process_args.pid_netns_id_map.write();
                w.clear();
                for p in process_info.iter() {
                    w.insert(p.pid as u32, p.netns_id);
                }
            }
        }

        let kubernetes_poller = process_args.kubernetes_poller.lock().unwrap();
        let mut new_kubernetes_version = *self_kubernetes_version;
        if let Some(poller) = kubernetes_poller.as_ref() {
            new_kubernetes_version = poller.get_version();
            if new_kubernetes_version != *self_kubernetes_version {
                debug!("kubernetes info changed");
                changed += 1;
            }
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
                *self_interface_infos = kubernetes_poller.as_ref().unwrap().get_interface_info();
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
        proc_data: &Vec<ProcessData>,
        vtap_id: u16,
        version: u64,
        ctrl_ip: String,
        trident_type: TridentType,
        platform_enabled: bool,
        kubernetes_cluster_id: String,
    ) -> Result<u64, tonic::Status> {
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
                netns_id: Some(interface_info.ns_inode as u32),
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
                        netns_id: None,
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

        let process_data = GenesisProcessData {
            process_entries: proc_data.iter().map(|p| ProcessInfo::from(p)).collect(),
        };

        let msg = trident::GenesisSyncRequest {
            version: Some(version),
            trident_type: Some(trident_type as i32),
            platform_data: Some(platform_data),
            process_data: Some(process_data),
            source_ip: Some(ctrl_ip),
            vtap_id: Some(vtap_id as u32),
            kubernetes_cluster_id: Some(kubernetes_cluster_id),
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
        let mut process_data = vec![];

        let mut netns = vec![];

        loop {
            let mut new_netns = vec![NsFile::Root];
            if let Some(re) = &*args.extra_netns_regex.lock().unwrap() {
                let mut extra_ns = netns::find_ns_files_by_regex(&re);
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

            let config_guard = args.config.load();
            let trident_type = config_guard.trident_type;
            let process_info_enabled = process_info_enabled(trident_type);
            let platform_enabled = config_guard.enabled;
            let proc_scan_conf = &config_guard.os_proc_scan_conf;
            let cur_vtap_id = config_guard.vtap_id;
            let trident_type = config_guard.trident_type;
            let ctrl_ip = args.agent_id.read().ip.to_string();
            let poll_interval = config_guard.sync_interval;
            let kubernetes_cluster_id = config_guard.kubernetes_cluster_id.clone();
            let libvirt_xml_path = config_guard.libvirt_xml_path.clone();

            Self::query_platform(
                &mut platform_args,
                &mut hash_args,
                &mut interface_infos,
                &mut xml_interfaces,
                &mut process_data,
                process_info_enabled,
                platform_enabled,
                proc_scan_conf,
                &args,
                &mut kubernetes_version,
                &mut last_ip_update_timestamp,
                &netns,
                libvirt_xml_path.as_path(),
            );

            let cur_version = args.version.load(Ordering::SeqCst);

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
                let process_data = GenesisProcessData {
                    process_entries: process_data.iter().map(|p| ProcessInfo::from(p)).collect(),
                };
                let msg = trident::GenesisSyncRequest {
                    version: Some(cur_version),
                    trident_type: Some(trident_type as i32),
                    source_ip: Some(ctrl_ip.clone()),
                    vtap_id: Some(cur_vtap_id as u32),
                    kubernetes_cluster_id: Some(kubernetes_cluster_id.clone()),
                    platform_data: None,
                    process_data: Some(process_data),
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
                &process_data,
                cur_vtap_id,
                cur_version,
                ctrl_ip,
                trident_type,
                platform_enabled,
                kubernetes_cluster_id.clone(),
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

    pub fn get_netns_id_by_pid(&self, pid: u32) -> Option<u32> {
        let r = self.pid_netns_id_map.read();
        r.get(&pid).and_then(|n| Some(*n))
    }
}

pub struct SocketSynchronizer {
    runtime: Arc<Runtime>,
    config: PlatformAccess,
    agent_id: Arc<RwLock<AgentId>>,
    stop_notify: Arc<Condvar>,
    session: Arc<Session>,
    running: Arc<Mutex<bool>>,
    policy_getter: Arc<Mutex<PolicyGetter>>,
    policy_setter: PolicySetter,
    lru_toa_info: Arc<Mutex<Lru<SocketAddr, SocketAddr>>>,
}

impl SocketSynchronizer {
    pub fn new(
        runtime: Arc<Runtime>,
        config: PlatformAccess,
        agent_id: Arc<RwLock<AgentId>>,
        policy_getter: Arc<Mutex<PolicyGetter>>,
        policy_setter: PolicySetter,
        session: Arc<Session>,
        // toa info, Receiver<Box< LocalAddr, RealAddr>>
        // receiver from SubQuadGen::inject_flow()
        receiver: Receiver<Box<(SocketAddr, SocketAddr)>>,
        // toa info cache, Lru<LocalAddr, RealAddr>
        lru_toa_info: Arc<Mutex<Lru<SocketAddr, SocketAddr>>>,
    ) -> Self {
        if process_info_enabled(config.load().trident_type) {
            let lru_toa_info_clone = lru_toa_info.clone();
            thread::Builder::new()
                .name("socket-synchronizer-toa-recv".to_string())
                .spawn(|| {
                    Self::sync_toa(lru_toa_info_clone, receiver);
                })
                .unwrap();
        }

        Self {
            runtime,
            config,
            agent_id,
            policy_getter,
            policy_setter,
            stop_notify: Arc::new(Condvar::new()),
            session,
            running: Arc::new(Mutex::new(false)),
            lru_toa_info,
        }
    }

    pub fn start(&mut self) {
        let conf_guard = self.config.load();
        if !process_info_enabled(conf_guard.trident_type) {
            return;
        }

        let mut running_guard = self.running.lock().unwrap();
        if *running_guard {
            warn!("socket sync is running");
            return;
        }

        let (
            runtime,
            running,
            config,
            agent_id,
            policy_getter,
            policy_setter,
            session,
            stop_notify,
            lru_toa_info,
        ) = (
            self.runtime.clone(),
            self.running.clone(),
            self.config.clone(),
            self.agent_id.clone(),
            self.policy_getter.clone(),
            self.policy_setter,
            self.session.clone(),
            self.stop_notify.clone(),
            self.lru_toa_info.clone(),
        );

        thread::Builder::new()
            .name("socket-synchronizer".to_string())
            .spawn(move || {
                Self::run(
                    runtime,
                    running,
                    config,
                    agent_id,
                    policy_getter,
                    policy_setter,
                    session,
                    stop_notify,
                    lru_toa_info,
                )
            })
            .unwrap();
        *running_guard = true;

        info!("socket info sync start");
    }

    fn run(
        runtime: Arc<Runtime>,
        running: Arc<Mutex<bool>>,
        config: PlatformAccess,
        agent_id: Arc<RwLock<AgentId>>,
        policy_getter: Arc<Mutex<PolicyGetter>>,
        policy_setter: PolicySetter,
        session: Arc<Session>,
        stop_notify: Arc<Condvar>,
        lru_toa_info: Arc<Mutex<Lru<SocketAddr, SocketAddr>>>,
    ) {
        let mut last_entries: Vec<GpidEntry> = vec![];

        loop {
            let running_guard = running.lock().unwrap();
            let sync_interval;

            {
                let conf_guard = config.load();
                sync_interval = Duration::from_secs(
                    conf_guard.os_proc_scan_conf.os_proc_socket_sync_interval as u64,
                );

                // wait for config from server
                if !conf_guard.os_proc_scan_conf.os_proc_sync_enabled {
                    if !Self::wait_timeout(running_guard, stop_notify.clone(), sync_interval) {
                        return;
                    }
                    continue;
                }

                let (ctrl_ip, ctrl_mac) = {
                    let id = agent_id.read();
                    (id.ip.to_string(), id.mac.to_string())
                };
                let mut policy_getter = policy_getter.lock().unwrap();

                let sock_entries = match get_all_socket(
                    &conf_guard.os_proc_scan_conf,
                    &mut policy_getter,
                    conf_guard.epc_id,
                ) {
                    Err(e) => {
                        error!("fetch socket info fail: {}", e);
                        if !Self::wait_timeout(running_guard, stop_notify.clone(), sync_interval) {
                            return;
                        }
                        continue;
                    }
                    Ok(mut res) => {
                        // fill toa
                        let mut lru_toa = lru_toa_info.lock().unwrap();
                        for se in res.iter_mut() {
                            if se.role == Role::Server {
                                // the client addr
                                let sa = match se.remote.ip {
                                    IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(
                                        v4.clone(),
                                        se.remote.port,
                                    )),
                                    _ => continue,
                                };
                                // get real addr by client addr from toa
                                if let Some(real_addr) = lru_toa.get_mut(&sa) {
                                    se.real_client = Some(SockAddrData {
                                        epc_id: 0,
                                        ip: real_addr.ip(),
                                        port: real_addr.port(),
                                    });
                                }
                            }
                        }
                        res
                    }
                };

                match runtime.block_on(
                    session.gpid_sync(GpidSyncRequest {
                        ctrl_ip: Some(ctrl_ip),
                        ctrl_mac: Some(ctrl_mac),
                        vtap_id: Some(conf_guard.vtap_id as u32),
                        entries: sock_entries
                            .into_iter()
                            .filter_map(|sock| {
                                if let Ok(e) = sock.try_into() {
                                    Some(e)
                                } else {
                                    None
                                }
                            })
                            .collect(),
                        // TODO compress_algorithm
                        ..Default::default()
                    }),
                ) {
                    Err(e) => error!("gpid sync fail: {}", e),
                    Ok(response) => {
                        let response: GpidSyncResponse = response.into_inner();
                        let mut current_entries = vec![];
                        for entry in response.entries.iter() {
                            let e = GpidEntry::try_from(entry);
                            if e.is_err() {
                                warn!("{:?}", e);
                                continue;
                            }
                            current_entries.push(e.unwrap());
                        }

                        if current_entries != last_entries {
                            policy_setter.update_gpids(&current_entries);
                            last_entries = current_entries
                        }
                    }
                }
            }

            if !Self::wait_timeout(running_guard, stop_notify.clone(), sync_interval) {
                return;
            }
        }
    }

    pub fn stop(&mut self) {
        let conf_guard = self.config.load();
        if !process_info_enabled(conf_guard.trident_type) {
            return;
        }

        let mut running_guard = self.running.lock().unwrap();
        if !*running_guard {
            warn!("socket info sync not running");
            return;
        }
        *running_guard = false;
        self.stop_notify.notify_one();
        info!("socket info sync stop");
    }

    fn wait_timeout(guard: MutexGuard<bool>, stop_notify: Arc<Condvar>, timeout: Duration) -> bool {
        *(stop_notify.wait_timeout(guard, timeout).unwrap().0)
    }

    fn sync_toa(
        lru_toa_info: Arc<Mutex<Lru<SocketAddr, SocketAddr>>>,
        receive: Receiver<Box<(SocketAddr, SocketAddr)>>,
    ) {
        while let Ok(toa_info) = receive.recv(None) {
            let (client, real) = (toa_info.0, toa_info.1);
            let mut lru_toa = lru_toa_info.lock().unwrap();
            lru_toa.put(client, real);
        }
        info!("toa sync queue close");
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
