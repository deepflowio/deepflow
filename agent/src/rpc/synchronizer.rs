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

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::mem;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{self, Command};
use std::str::FromStr;
use std::sync::{
    self,
    atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    Arc, Weak,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[cfg(unix)]
use std::{fs::Permissions, os::unix::fs::PermissionsExt};

use log::{debug, error, info, warn};
use md5::{Digest, Md5};
use parking_lot::{Mutex, RwLock, RwLockUpgradableReadGuard};
use prost::Message;
use rand::RngCore;
use sysinfo::{System, SystemExt};
use tokio::runtime::Runtime;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::task::JoinHandle;
use tokio::time;

use super::ntp::{NtpMode, NtpPacket, NtpTime};

use crate::common::endpoint::EPC_FROM_INTERNET;
use crate::common::policy::Acl;
use crate::common::policy::{Cidr, IpGroupData, PeerConnection};
use crate::common::NORMAL_EXIT_WITH_RESTART;
use crate::common::{FlowAclListener, PlatformData as VInterface, DEFAULT_CONTROLLER_PORT};
use crate::config::RuntimeConfig;
use crate::exception::ExceptionHandler;
use crate::rpc::session::Session;
use crate::trident::{self, ChangedConfig, RunningMode, TridentState, VersionInfo};
use crate::utils::{
    command::get_hostname,
    environment::{
        get_executable_path, is_tt_pod, running_in_container, running_in_only_watch_k8s_mode,
    },
    stats,
};
use public::proto::common::TridentType;
use public::proto::trident::{self as tp, Exception, TapMode};
use public::utils::net::{addr_list, is_unicast_link_local, MacAddr};

const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_secs(60);
const RPC_RETRY_INTERVAL: Duration = Duration::from_secs(60);
const NANOS_IN_SECOND: i64 = Duration::from_secs(1).as_nanos() as i64;
const SECOND: Duration = Duration::from_secs(1);

pub struct StaticConfig {
    pub version_info: &'static VersionInfo,
    pub boot_time: SystemTime,

    pub tap_mode: tp::TapMode,
    pub vtap_group_id_request: String,
    pub controller_ip: String,

    pub env: RuntimeEnvironment,
    pub kubernetes_cluster_id: String,
    pub kubernetes_cluster_name: Option<String>,

    pub override_os_hostname: Option<String>,
}

const EMPTY_VERSION_INFO: &'static trident::VersionInfo = &trident::VersionInfo {
    name: "",
    branch: "",
    commit_id: "",
    rev_count: "",
    compiler: "",
    compile_time: "",
    revision: "",
};

impl Default for StaticConfig {
    fn default() -> Self {
        Self {
            version_info: EMPTY_VERSION_INFO,
            boot_time: SystemTime::now(),
            tap_mode: Default::default(),
            vtap_group_id_request: Default::default(),
            controller_ip: Default::default(),
            env: Default::default(),
            kubernetes_cluster_id: Default::default(),
            kubernetes_cluster_name: Default::default(),
            override_os_hostname: None,
        }
    }
}

pub struct RunningConfig {
    pub ctrl_mac: String,
    pub ctrl_ip: String,
}

impl Default for RunningConfig {
    fn default() -> Self {
        Self {
            ctrl_ip: Default::default(),
            ctrl_mac: Default::default(),
        }
    }
}

pub struct Status {
    pub hostname: String,

    pub time_diff: i64,

    pub config_accepted: bool,
    pub new_revision: Option<String>,

    pub proxy_ip: Option<String>,
    pub proxy_port: u16,
    pub sync_interval: Duration,
    pub ntp_enabled: bool,

    // GRPC数据
    pub local_epc: i32,

    pub version_platform_data: u64,
    pub version_acls: u64,
    pub version_groups: u64,

    pub interfaces: Vec<Arc<VInterface>>,
    pub peers: Vec<Arc<PeerConnection>>,
    pub cidrs: Vec<Arc<Cidr>>,
    pub ip_groups: Vec<Arc<IpGroupData>>,
    pub acls: Vec<Arc<Acl>>,
}

impl Default for Status {
    fn default() -> Self {
        Self {
            hostname: "".into(),

            time_diff: 0,

            config_accepted: false,
            new_revision: None,

            proxy_ip: None,
            proxy_port: DEFAULT_CONTROLLER_PORT,
            sync_interval: DEFAULT_SYNC_INTERVAL,
            ntp_enabled: false,

            local_epc: EPC_FROM_INTERNET,
            version_platform_data: 0,
            version_acls: 0,
            version_groups: 0,
            interfaces: Default::default(),
            peers: Default::default(),
            cidrs: Default::default(),
            ip_groups: Default::default(),
            acls: Default::default(),
        }
    }
}

impl Status {
    fn update_platform_data(
        &mut self,
        version: u64,
        interfaces: Vec<Arc<VInterface>>,
        peers: Vec<Arc<PeerConnection>>,
        cidrs: Vec<Arc<Cidr>>,
    ) {
        info!(
            "Update PlatformData version {} to {}.",
            self.version_platform_data, version
        );

        self.version_platform_data = version;
        self.interfaces = interfaces;
        self.cidrs = cidrs;
        self.peers = peers;
    }

    fn update_ip_groups(&mut self, version: u64, ip_groups: Vec<Arc<IpGroupData>>) {
        info!(
            "Update IpGroups version {} to {}.",
            self.version_groups, version
        );

        self.version_groups = version;
        self.ip_groups = ip_groups;
    }

    fn update_flow_acl(&mut self, version: u64, flow_acls: Vec<Acl>) {
        info!(
            "Update FlowAcls version {} to {}.",
            self.version_acls, version
        );

        let acls = flow_acls
            .iter()
            .map(|x| Arc::new(x.clone()))
            .collect::<Vec<Arc<Acl>>>();

        self.version_acls = version;
        self.acls = acls;
    }

    pub fn get_platform_data(&mut self, resp: &tp::SyncResponse) -> bool {
        let current_version = self.version_platform_data;
        let version = resp.version_platform_data.unwrap_or(0);
        debug!(
            "get grpc PlatformData version: {} vs current version: {}.",
            version, current_version
        );
        if version == 0 {
            debug!("platform data in preparation.");
            return false;
        }
        if version == current_version {
            debug!("platform data same version.");
            return false;
        }

        if let Some(platform_compressed) = &resp.platform_data {
            let platform = tp::PlatformData::decode(platform_compressed.as_slice());
            if platform.is_ok() {
                let platform = platform.unwrap();
                let mut interfaces = Vec::new();
                let mut peers = Vec::new();
                let mut cidrs = Vec::new();
                for item in &platform.interfaces {
                    let result = VInterface::try_from(item);
                    if result.is_ok() {
                        interfaces.push(Arc::new(result.unwrap()));
                    } else {
                        warn!("{:?}: {}", item, result.unwrap_err());
                    }
                }
                for item in &platform.peer_connections {
                    peers.push(Arc::new(PeerConnection::from(item)));
                }
                for item in &platform.cidrs {
                    let result = Cidr::try_from(item);
                    if result.is_ok() {
                        cidrs.push(Arc::new(result.unwrap()));
                    } else {
                        warn!("{:?}: {}", item, result.unwrap_err());
                    }
                }

                self.update_platform_data(version, interfaces, peers, cidrs);
            } else {
                error!("Invalid platform data.");
                self.update_platform_data(version, vec![], vec![], vec![]);
            }
        } else {
            self.update_platform_data(version, vec![], vec![], vec![]);
        }
        return true;
    }

    fn modify_platform(&mut self, macs: &Vec<MacAddr>, config: &RuntimeConfig) {
        if config.tap_mode == TapMode::Analyzer {
            return;
        }
        let mut local_mac_map = HashSet::new();
        for mac in macs {
            let _ = local_mac_map.insert(u64::from(*mac));
        }

        let region_id = config.region_id;
        let pod_cluster_id = config.pod_cluster_id;
        let mut vinterfaces = Vec::new();
        for i in &self.interfaces {
            let mut viface = (*(i.clone())).clone();
            if !is_tt_pod(config.trident_type) {
                viface.skip_mac = viface.region_id != region_id;
            } else {
                let mut is_tap_interface = viface.pod_cluster_id == pod_cluster_id;
                is_tap_interface = is_tap_interface
                    || (viface.region_id == region_id
                        && viface.device_type != (tp::DeviceType::Pod as u8));
                viface.skip_mac = !is_tap_interface;
            }

            viface.is_local = local_mac_map.contains(&viface.mac);
            vinterfaces.push(Arc::new(viface));
        }

        self.interfaces = vinterfaces;
        // TODO：bridge fdb
    }

    pub fn get_flow_acls(&mut self, resp: &tp::SyncResponse) -> bool {
        let version = resp.version_acls.unwrap_or(0);
        debug!(
            "get grpc FlowAcls version: {} vs current version: {}.",
            version, self.version_acls
        );
        if version == 0 {
            debug!("FlowAcls data in preparation.");
            return false;
        }
        if version == self.version_acls {
            debug!("FlowAcls data same version.");
            return false;
        }

        if let Some(acls_commpressed) = &resp.flow_acls {
            let acls = tp::FlowAcls::decode(acls_commpressed.as_slice());
            if let Ok(acls) = acls {
                let flow_acls = acls
                    .flow_acl
                    .into_iter()
                    .filter_map(|a| match a.try_into() {
                        Err(e) => {
                            warn!("{}", e);
                            None
                        }
                        t => t.ok(),
                    })
                    .collect::<Vec<Acl>>();
                self.update_flow_acl(version, flow_acls);
            } else {
                error!("Invalid acls.");
                self.update_flow_acl(version, vec![]);
            }
        } else {
            self.update_flow_acl(version, vec![]);
        }
        return true;
    }

    pub fn get_ip_groups(&mut self, resp: &tp::SyncResponse) -> bool {
        let version = resp.version_groups.unwrap_or(0);
        debug!(
            "get grpc Groups version: {} vs current version: {}.",
            version, self.version_groups
        );
        if version == 0 {
            debug!("Groups data in preparation.");
            return false;
        }
        if self.version_groups == version {
            debug!("Groups data same version.");
            return false;
        }

        if let Some(groups_compressed) = &resp.groups {
            let groups = tp::Groups::decode(groups_compressed.as_slice());
            if groups.is_ok() {
                let groups = groups.unwrap();
                let mut ip_groups = Vec::new();
                for item in &groups.groups {
                    let result = IpGroupData::try_from(item);
                    if result.is_ok() {
                        ip_groups.push(Arc::new(result.unwrap()));
                    } else {
                        warn!("{}", result.unwrap_err());
                    }
                }
                self.update_ip_groups(version, ip_groups);
            } else {
                error!("Invalid ip groups.");
                self.update_ip_groups(version, vec![]);
            }
        } else {
            self.update_ip_groups(version, vec![]);
        }
        return true;
    }

    pub fn get_blacklist(&mut self, resp: &tp::SyncResponse) -> Vec<u64> {
        return resp.skip_interface.iter().map(|i| i.mac.unwrap()).collect();
    }

    pub fn get_local_epc(&mut self, config: &RuntimeConfig) -> bool {
        if config.epc_id as i32 != self.local_epc {
            self.local_epc = config.epc_id as i32;
            return true;
        }
        return false;
    }

    fn trigger_flow_acl(
        &self,
        trident_type: TridentType,
        listener: &mut Box<dyn FlowAclListener>,
    ) -> Result<(), String> {
        listener.flow_acl_change(
            trident_type,
            self.local_epc,
            &self.ip_groups,
            &self.interfaces,
            &self.peers,
            &self.cidrs,
            &self.acls,
        )
    }
}

pub struct Synchronizer {
    pub static_config: Arc<StaticConfig>,
    pub running_config: Arc<RwLock<RunningConfig>>,
    pub status: Arc<RwLock<Status>>,

    trident_state: TridentState,

    session: Arc<Session>,
    // 策略模块和NPB带宽检测会用到
    flow_acl_listener: Arc<sync::Mutex<Vec<Box<dyn FlowAclListener>>>>,
    exception_handler: ExceptionHandler,

    running: Arc<AtomicBool>,

    // threads
    runtime: Arc<Runtime>,
    threads: Mutex<Vec<JoinHandle<()>>>,

    max_memory: Arc<AtomicU64>,
    ntp_diff: Arc<AtomicI64>,
    agent_mode: RunningMode,
    standalone_runtime_config: Option<PathBuf>,
}

impl Synchronizer {
    const LOG_THRESHOLD: usize = 3;
    pub fn new(
        runtime: Arc<Runtime>,
        session: Arc<Session>,
        trident_state: TridentState,
        version_info: &'static VersionInfo,
        ctrl_ip: String,
        ctrl_mac: String,
        controller_ip: String,
        vtap_group_id_request: String,
        kubernetes_cluster_id: String,
        kubernetes_cluster_name: Option<String>,
        override_os_hostname: Option<String>,
        exception_handler: ExceptionHandler,
        agent_mode: RunningMode,
        standalone_runtime_config: Option<PathBuf>,
    ) -> Synchronizer {
        Synchronizer {
            static_config: Arc::new(StaticConfig {
                version_info,
                boot_time: SystemTime::now(),
                tap_mode: tp::TapMode::Local,
                vtap_group_id_request,
                controller_ip,
                env: RuntimeEnvironment::new(),
                kubernetes_cluster_id,
                kubernetes_cluster_name,
                override_os_hostname,
            }),
            running_config: Arc::new(RwLock::new(RunningConfig { ctrl_mac, ctrl_ip })),
            trident_state,
            status: Default::default(),
            session,
            running: Arc::new(AtomicBool::new(false)),
            runtime,
            threads: Default::default(),
            flow_acl_listener: Arc::new(sync::Mutex::new(vec![])),
            exception_handler,

            max_memory: Default::default(),
            ntp_diff: Default::default(),
            agent_mode,
            standalone_runtime_config,
        }
    }

    pub fn reset_session(&self, controller_ips: Vec<String>, ctrl_ip: String, ctrl_mac: String) {
        self.session.reset_server_ip(controller_ips);

        let mut running_config = self.running_config.write();
        running_config.ctrl_ip = ctrl_ip;
        running_config.ctrl_mac = ctrl_mac;

        self.status.write().proxy_ip = None;
        self.status.write().proxy_port = DEFAULT_CONTROLLER_PORT;
    }

    pub fn reset_version(&self) {
        let mut status = self.status.write();
        status.version_acls = 0;
        status.version_groups = 0;
        status.version_platform_data = 0;
        info!("Reset version of acls, groups and platform_data.");
    }

    pub fn add_flow_acl_listener(&self, module: Box<dyn FlowAclListener>) {
        let mut listeners = self.flow_acl_listener.lock().unwrap();
        for item in listeners.iter() {
            if item.id() == module.id() {
                return;
            }
        }
        listeners.push(module);
        // The lock must be immediately released, and holding both flow_acl_listener and status
        // simultaneously can cause a deadlock.
        drop(listeners);

        // make sure agent can get the latest policy data
        // ===============================================
        // 保证 Agent 可以获取最新策略
        self.reset_version();
    }

    pub fn max_memory(&self) -> Arc<AtomicU64> {
        self.max_memory.clone()
    }

    pub fn generate_sync_request(
        running_config: &Arc<RwLock<RunningConfig>>,
        static_config: &Arc<StaticConfig>,
        status: &Arc<RwLock<Status>>,
        time_diff: i64,
        exception_handler: &ExceptionHandler,
    ) -> tp::SyncRequest {
        let status = status.read();

        let boot_time = static_config
            .boot_time
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let boot_time = (boot_time as i64 + time_diff) / 1_000_000_000;

        fn is_excluded_ip_addr(ip_addr: IpAddr) -> bool {
            if ip_addr.is_loopback() || ip_addr.is_unspecified() || ip_addr.is_multicast() {
                return true;
            }
            match ip_addr {
                IpAddr::V4(addr) => addr.is_link_local(),
                // Ipv6Addr::is_unicast_link_local()是实验API无法使用
                IpAddr::V6(addr) => is_unicast_link_local(&addr),
            }
        }

        let running_config = running_config.read();

        tp::SyncRequest {
            boot_time: Some(boot_time as u32),
            config_accepted: Some(status.config_accepted),
            version_platform_data: Some(status.version_platform_data),
            version_acls: Some(status.version_acls),
            version_groups: Some(status.version_groups),
            state: Some(tp::State::Running.into()),
            revision: Some(static_config.version_info.revision.to_owned()),
            exception: Some(exception_handler.take()),
            process_name: Some(static_config.version_info.name.to_owned()),
            ctrl_mac: Some(running_config.ctrl_mac.clone()),
            ctrl_ip: Some(running_config.ctrl_ip.clone()),
            tap_mode: Some(static_config.tap_mode.into()),
            host: Some(status.hostname.clone()),
            host_ips: addr_list().map_or(vec![], |xs| {
                xs.into_iter()
                    .filter_map(|x| {
                        if is_excluded_ip_addr(x.ip_addr) {
                            None
                        } else {
                            Some(x.ip_addr.to_string())
                        }
                    })
                    .collect()
            }),
            cpu_num: Some(static_config.env.cpu_num),
            memory_size: Some(static_config.env.memory_size),
            arch: Some(static_config.env.arch.clone()),
            os: Some(static_config.env.os.clone()),
            kernel_version: Some(static_config.env.kernel_version.clone()),
            vtap_group_id_request: Some(static_config.vtap_group_id_request.clone()),
            kubernetes_cluster_id: Some(static_config.kubernetes_cluster_id.clone()),
            kubernetes_cluster_name: static_config.kubernetes_cluster_name.clone(),
            kubernetes_force_watch: Some(running_in_only_watch_k8s_mode()),

            ..Default::default()
        }
    }

    pub fn clone_session(&self) -> Arc<Session> {
        self.session.clone()
    }

    fn parse_upgrade(
        resp: &tp::SyncResponse,
        static_config: &Arc<StaticConfig>,
        status: &Arc<RwLock<Status>>,
    ) {
        match &resp.revision {
            // static_config.version_info.revision is: ${branch} ${rev_count}-${commit_id}
            // resp.revision is: ${rev_count}-${commit_id}
            Some(revision)
                if revision != "" && !static_config.version_info.revision.contains(revision) =>
            {
                if let Some(url) = &resp.self_update_url {
                    if url.trim().to_lowercase() != "grpc" {
                        warn!("error upgrade method, only support grpc: {}", url);
                        return;
                    }
                    info!(
                        "trigger upgrade as revision update from {} to {}",
                        &static_config.version_info.revision, revision
                    );
                    status.write().new_revision = Some(revision.clone());
                }
            }
            _ => (),
        }
    }

    fn parse_segment(
        tap_mode: tp::TapMode,
        resp: &tp::SyncResponse,
    ) -> (Vec<tp::Segment>, Vec<MacAddr>, Vec<MacAddr>) {
        let segments = if tap_mode == tp::TapMode::Analyzer {
            resp.remote_segments.clone()
        } else {
            resp.local_segments.clone()
        };

        if segments.len() == 0 && tap_mode != tp::TapMode::Local {
            warn!("Segment is empty, in {:?} mode.", tap_mode);
        }
        let mut macs = Vec::new();
        let mut gateway_vmacs = Vec::new();
        for segment in &segments {
            let vm_macs = &segment.mac;
            let vmacs = &segment.vmac;
            if vm_macs.len() != vmacs.len() {
                warn!(
                    "Invalid segment the length of vmMacs and vMacs is inconsistent: {:?}",
                    segment
                );
                continue;
            }
            for (mac_str, vmac_str) in vm_macs.iter().zip(vmacs) {
                let mac = MacAddr::from_str(mac_str.as_str());
                if mac.is_err() {
                    warn!(
                        "Malformed VM mac {}, response rejected: {}",
                        mac_str,
                        mac.unwrap_err()
                    );
                    continue;
                }

                let vmac = MacAddr::from_str(vmac_str.as_str());
                if vmac.is_err() {
                    warn!(
                        "Malformed VM vmac {}, response rejected: {}",
                        vmac_str,
                        vmac.unwrap_err()
                    );
                    continue;
                }
                macs.push(mac.unwrap());
                gateway_vmacs.push(vmac.unwrap());
            }
        }
        return (segments, macs, gateway_vmacs);
    }

    // Note that both 'status' and 'flow_acl_listener' will be locked here, and other places where 'status'
    // and 'flow_acl_listener' are used need to be careful to avoid deadlocks
    fn on_response(
        remote: (String, u16),
        mut resp: tp::SyncResponse,
        trident_state: &TridentState,
        static_config: &Arc<StaticConfig>,
        status: &Arc<RwLock<Status>>,
        flow_acl_listener: &Arc<sync::Mutex<Vec<Box<dyn FlowAclListener>>>>,
        max_memory: &Arc<AtomicU64>,
        exception_handler: &ExceptionHandler,
        escape_tx: &UnboundedSender<Duration>,
    ) {
        Self::parse_upgrade(&resp, static_config, status);

        match resp.status() {
            tp::Status::Failed => warn!(
                "server ({:?}) responded with {:?}",
                remote,
                tp::Status::Failed
            ),
            tp::Status::Heartbeat => return,
            _ => (),
        }

        let config = resp.config.take();
        if config.is_none() {
            warn!("invalid response from {:?} without config", remote);
            return;
        }
        let runtime_config = RuntimeConfig::try_from(config.unwrap());
        if let Err(e) = runtime_config {
            warn!(
                "invalid response from {:?} with invalid config: {}",
                remote, e
            );
            exception_handler.set(Exception::InvalidConfiguration);
            return;
        }
        let runtime_config = runtime_config.unwrap();
        // FIXME: Confirm the kvm resource classification and then cancel the comment
        // When the ee version compiles the ce crate, it will be false, only ce version
        // will be true
        /*
        if static_config.version_info.name == env!("AGENT_NAME") {
            runtime_config.platform_enabled = false;
        }
         */
        let _ = escape_tx.send(Duration::from_secs(runtime_config.max_escape));

        max_memory.store(runtime_config.max_memory, Ordering::Relaxed);

        let (_, macs, gateway_vmac_addrs) = Self::parse_segment(runtime_config.tap_mode, &resp);

        let mut status = status.write();
        status.proxy_ip = if runtime_config.proxy_controller_ip.len() > 0 {
            Some(runtime_config.proxy_controller_ip.clone())
        } else {
            Some(static_config.controller_ip.clone())
        };
        status.proxy_port = runtime_config.proxy_controller_port;
        status.sync_interval = Duration::from_secs(runtime_config.sync_interval);
        status.ntp_enabled = runtime_config.ntp_enabled;
        let updated_platform = status.get_platform_data(&resp);
        if updated_platform {
            status.modify_platform(&macs, &runtime_config);
        }
        let mut updated = status.get_ip_groups(&resp) || updated_platform;
        updated = status.get_flow_acls(&resp) || updated;
        updated = status.get_local_epc(&runtime_config) || updated;
        if updated {
            // 更新策略相关
            let last = SystemTime::now();
            info!("Grpc version ip-groups: {}, interfaces, peer-connections and cidrs: {}, flow-acls: {}",
            status.version_groups, status.version_platform_data, status.version_acls);
            let mut policy_error = false;
            for listener in flow_acl_listener.lock().unwrap().iter_mut() {
                if let Err(e) = status.trigger_flow_acl(runtime_config.trident_type, listener) {
                    warn!("OnPolicyChange: {}.", e);
                    policy_error = true;
                }
            }
            if policy_error {
                warn!("OnPolicyChange error, set exception TOO_MANY_POLICIES.");
                exception_handler.set(Exception::TooManyPolicies);
            } else {
                exception_handler.clear(Exception::TooManyPolicies);
            }
            let now = SystemTime::now();
            info!("Grpc finish update cost {:?} on {} listener, {} ip-groups, {} interfaces, {} peer-connections, {} cidrs, {} flow-acls",
                now.duration_since(last).unwrap_or(Duration::from_secs(0)),
                flow_acl_listener.lock().unwrap().len(),
                status.ip_groups.len(),
                status.interfaces.len(),
                status.peers.len(),
                status.cidrs.len(),
                status.acls.len(),
            );
        }
        let blacklist = status.get_blacklist(&resp);
        drop(status);

        let (trident_state, cvar) = &**trident_state;
        if !runtime_config.enabled {
            *trident_state.lock().unwrap() = trident::State::Disabled(Some(runtime_config));
        } else {
            *trident_state.lock().unwrap() = trident::State::ConfigChanged(ChangedConfig {
                runtime_config,
                blacklist,
                vm_mac_addrs: macs,
                gateway_vmac_addrs,
                tap_types: resp.tap_types,
            });
        }
        cvar.notify_one();
    }

    fn grpc_failed_log(grpc_failed_count: &mut usize, detail: String) {
        *grpc_failed_count += 1;
        if *grpc_failed_count > Self::LOG_THRESHOLD {
            error!("Grpc error {} count {}", detail, grpc_failed_count);
        } else {
            warn!("Grpc error {} count {}", detail, grpc_failed_count);
        }
    }

    fn run_triggered_session(&self, escape_tx: UnboundedSender<Duration>) {
        let session = self.session.clone();
        let trident_state = self.trident_state.clone();
        let static_config = self.static_config.clone();
        let running_config = self.running_config.clone();
        let status = self.status.clone();
        let running = self.running.clone();
        let max_memory = self.max_memory.clone();
        let flow_acl_listener = self.flow_acl_listener.clone();
        let exception_handler = self.exception_handler.clone();
        let ntp_diff = self.ntp_diff.clone();
        self.threads.lock().push(self.runtime.spawn(async move {
            let mut grpc_failed_count = 0;
            while running.load(Ordering::SeqCst) {
                let response = session
                    .grpc_push_with_statsd(Synchronizer::generate_sync_request(
                        &running_config,
                        &static_config,
                        &status,
                        ntp_diff.load(Ordering::Relaxed),
                        &exception_handler,
                    ))
                    .await;
                let version = session.get_version();

                if let Err(m) = response {
                    exception_handler.set(Exception::ControllerSocketError);
                    session.set_request_failed(true);
                    Self::grpc_failed_log(&mut grpc_failed_count, format!("from trigger {:?}", m));
                    time::sleep(RPC_RETRY_INTERVAL).await;
                    continue;
                }
                session.set_request_failed(false);
                grpc_failed_count = 0;

                let mut stream = response.unwrap().into_inner();
                while running.load(Ordering::SeqCst) {
                    let message = stream.message().await;
                    if session.get_version() != version {
                        info!("grpc server changed");
                        break;
                    }
                    if let Err(m) = message {
                        exception_handler.set(Exception::ControllerSocketError);
                        Self::grpc_failed_log(
                            &mut grpc_failed_count,
                            format!("from trigger {:?}", m),
                        );
                        break;
                    }
                    let message = message.unwrap();
                    if message.is_none() {
                        debug!("end of stream");
                        break;
                    }
                    let message = message.unwrap();
                    match message.status() {
                        tp::Status::Failed => {
                            exception_handler.set(Exception::ControllerSocketError);
                            let (ip, port) = session.get_current_server();
                            warn!(
                                "server (ip: {} port: {}) responded with {:?}",
                                ip,
                                port,
                                tp::Status::Failed
                            );
                            time::sleep(RPC_RETRY_INTERVAL).await;
                            continue;
                        }
                        tp::Status::Heartbeat => {
                            continue;
                        }
                        _ => (),
                    }

                    debug!("received realtime policy successfully");
                    {
                        let status = status.read();
                        if status.version_acls
                            + status.version_groups
                            + status.version_platform_data
                            == 0
                        {
                            // 如果没有同步过（agent重启），server下发的数据仅有版本号，此时应由agent主动请求
                            //If the data is not synchronized (the agent restarts), the server sends only
                            // the data version. In this case, the agent must actively request the data version
                            continue;
                        }
                    }

                    Self::on_response(
                        session.get_current_server(),
                        message,
                        &trident_state,
                        &static_config,
                        &status,
                        &flow_acl_listener,
                        &max_memory,
                        &exception_handler,
                        &escape_tx,
                    );
                }
            }
        }));
    }

    fn run_escape_timer(&self) -> UnboundedSender<Duration> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let trident_state = self.trident_state.clone();
        let running = self.running.clone();
        self.runtime.spawn(async move {
            // default escape time is 1h
            let mut escape_time = Duration::from_secs(3600);
            while running.load(Ordering::SeqCst) {
                match time::timeout(escape_time, rx.recv()).await {
                    Ok(Some(t)) => escape_time = t,
                    // channel closed
                    Ok(None) => return,
                    Err(_) => {
                        let (ts, cvar) = &*trident_state;
                        *ts.lock().unwrap() = trident::State::Disabled(None);
                        cvar.notify_one();
                        warn!("as max escape time expired, deepflow-agent restart...");
                        // 与控制器失联的时间超过设置的逃逸时间，这里直接重启主要有两个原因：
                        // 1. 如果仅是停用系统无法回收全部的内存资源
                        // 2. 控制器地址可能是通过域明解析的，如果域明解析发生变更需要重启来触发重新解析
                        time::sleep(Duration::from_secs(1)).await;
                        process::exit(NORMAL_EXIT_WITH_RESTART);
                    }
                }
            }
        });
        tx
    }

    pub fn ntp_diff(&self) -> Arc<AtomicI64> {
        self.ntp_diff.clone()
    }

    pub fn ntp_counter(&self) -> NtpCounter {
        NtpCounter(Arc::downgrade(&self.ntp_diff()))
    }

    fn run_ntp_sync(&self) {
        let running_config = self.running_config.clone();
        let session = self.session.clone();
        let status = self.status.clone();
        let running = self.running.clone();
        let ntp_diff = self.ntp_diff.clone();
        self.runtime.spawn(async move {
            while running.load(Ordering::SeqCst) {
                let (enabled, sync_interval) = {
                    let reader = status.read();
                    (reader.ntp_enabled, reader.sync_interval)
                };

                if !enabled {
                    ntp_diff.store(0, Ordering::Relaxed);
                    time::sleep(sync_interval).await;
                    continue;
                }

                let mut ntp_msg = NtpPacket::new();
                // To ensure privacy and prevent spoofing, try to use a random 64-bit
                // value for the TransmitTime. Keep track of when the messsage was
                // actually transmitted.
                ntp_msg.ts_xmit = rand::thread_rng().next_u64();
                let send_time = SystemTime::now();

                let ctrl_ip = running_config.read().ctrl_ip.clone();
                let response = session
                    .grpc_ntp_with_statsd(tp::NtpRequest {
                        ctrl_ip: Some(ctrl_ip),
                        request: Some(ntp_msg.to_vec()),
                    })
                    .await;

                if let Err(e) = response {
                    warn!("ntp request failed with: {:?}", e);
                    time::sleep(sync_interval).await;
                    continue;
                }
                let response = response.unwrap().into_inner();
                if response.response.is_none() {
                    warn!("ntp response empty");
                    time::sleep(sync_interval).await;
                    continue;
                }

                let resp_packet = NtpPacket::try_from(response.response.unwrap().as_ref());
                if let Err(e) = resp_packet {
                    warn!("parse ntp response failed: {:?}", e);
                    time::sleep(sync_interval).await;
                    continue;
                }
                let mut resp_packet = resp_packet.unwrap();

                if resp_packet.get_mode() != NtpMode::Server {
                    warn!("NTP: invalid mod in response");
                    time::sleep(sync_interval).await;
                    continue;
                }
                if resp_packet.ts_xmit == 0 {
                    warn!("NTP: invalid transmit time in response");
                    time::sleep(sync_interval).await;
                    continue;
                }
                if resp_packet.ts_orig != ntp_msg.ts_xmit {
                    warn!("NTP: server response mismatch");
                    time::sleep(sync_interval).await;
                    continue;
                }
                if resp_packet.ts_recv > resp_packet.ts_xmit {
                    warn!("NTP: server clock ticked backwards");
                    time::sleep(sync_interval).await;
                    continue;
                }
                let recv_time = SystemTime::now();
                if let Err(e) = recv_time.duration_since(send_time) {
                    warn!("system time err: {:?}", e);
                    time::sleep(sync_interval).await;
                    continue;
                }

                // Correct the received message's origin time using the actual
                // transmit time.
                resp_packet.ts_orig = NtpTime::from(&send_time).0;
                let offset = resp_packet.offset(&recv_time);
                ntp_diff.store(
                    offset / NANOS_IN_SECOND * NANOS_IN_SECOND,
                    Ordering::Relaxed,
                );

                time::sleep(sync_interval).await;
            }
        });
    }

    async fn upgrade(
        running: &AtomicBool,
        session: &Session,
        new_revision: &str,
        ctrl_ip: &str,
        ctrl_mac: &str,
    ) -> Result<(), String> {
        if running_in_container() {
            info!("running in a container, exit directly and try to recreate myself using a new version docker image...");
            return Ok(());
        }

        let response = session
            .grpc_upgrade_with_statsd(tp::UpgradeRequest {
                ctrl_ip: Some(ctrl_ip.to_owned()),
                ctrl_mac: Some(ctrl_mac.to_owned()),
            })
            .await;
        if let Err(m) = response {
            return Err(format!("rpc error {:?}", m));
        }

        let binary_path = get_executable_path()
            .map_err(|_| format!("Cannot get deepflow-agent path for this OS"))?;
        let mut temp_path = binary_path.clone();
        #[cfg(unix)]
        temp_path.set_extension("test");
        #[cfg(windows)]
        temp_path.set_extension("test.exe");
        let mut backup_path = binary_path.clone();
        backup_path.set_extension("bak");

        let mut first_message = true;
        let mut md5_sum = String::new();
        let mut bytes = 0;
        let mut total_bytes = 0;
        let mut count = 0usize;
        let mut total_count = 0;
        let fp = File::create(&temp_path)
            .map_err(|e| format!("File {} creation failed: {:?}", temp_path.display(), e))?;
        let mut writer = BufWriter::new(fp);
        let mut checksum = Md5::new();

        let mut stream = response.unwrap().into_inner();
        while let Some(message) = stream
            .message()
            .await
            .map_err(|e| format!("RPC error {:?}", e))?
        {
            if !running.load(Ordering::SeqCst) {
                return Err("Upgrade terminated".to_owned());
            }
            if message.status() != tp::Status::Success {
                return Err("Upgrade failed in server response".to_owned());
            }
            if first_message {
                first_message = false;
                md5_sum = message.md5().to_owned();
                total_bytes = message.total_len() as usize;
                total_count = message.pkt_count() as usize;
            }
            checksum.update(&message.content());
            if let Err(e) = writer.write_all(&message.content()) {
                return Err(format!(
                    "Write to file {} failed: {:?}",
                    temp_path.display(),
                    e
                ));
            }
            bytes += message.content().len() as usize;
            count += 1;
        }

        if bytes != total_bytes {
            return Err(format!(
                "Binary truncated, received {}/{} messages, {}/{} bytes",
                count, total_count, bytes, total_bytes
            ));
        }

        let checksum = checksum
            .finalize()
            .into_iter()
            .fold(String::new(), |s, c| s + &format!("{:02x}", c));
        if checksum != md5_sum {
            return Err(format!(
                "Binary checksum mismatch, expected: {}, received: {}",
                md5_sum, checksum
            ));
        }

        writer
            .flush()
            .map_err(|e| format!("Flush {} failed: {:?}", temp_path.display(), e))?;
        mem::drop(writer);

        #[cfg(unix)]
        if let Err(e) = fs::set_permissions(&temp_path, Permissions::from_mode(0o755)) {
            return Err(format!(
                "Set file {} permissions failed: {:?}",
                temp_path.display(),
                e
            ));
        }

        let version_info = Command::new(&temp_path)
            .arg("-v")
            .output()
            .map_err(|e| format!("Binary execution failed: {:?}", e))?
            .stdout;
        if !version_info.starts_with(new_revision.as_bytes()) {
            return Err("Binary version mismatch".to_owned());
        }

        // ignore file not exist and other errors
        let _ = fs::remove_file(&backup_path);

        if let Err(e) = fs::rename(&binary_path, &backup_path) {
            return Err(format!("Backup old binary failed: {:?}", e));
        }
        if let Err(e) = fs::rename(&temp_path, &binary_path) {
            let err_string = format!(
                "Copy new binary to {} failed: {:?}",
                &binary_path.display(),
                e
            );
            if let Err(ee) = fs::rename(&backup_path, &binary_path) {
                return Err(format!("{}, restoring backup failed: {:?}", err_string, ee));
            }
            return Err(err_string);
        }

        // ignore failure as upgrade succeeded anyway
        let _ = fs::remove_file(backup_path);

        Ok(())
    }

    fn run_standalone(&self) {
        let running = self.running.clone();
        let trident_state = self.trident_state.clone();
        let max_memory = self.max_memory.clone();
        let mut sync_interval = DEFAULT_SYNC_INTERVAL;
        let standalone_runtime_config = self.standalone_runtime_config.as_ref().unwrap().clone();
        self.threads.lock().push(self.runtime.spawn(async move {
            while running.load(Ordering::SeqCst) {
                let runtime_config =
                    match RuntimeConfig::load_from_file(standalone_runtime_config.as_path()) {
                        Ok(c) => c,
                        Err(e) => {
                            error!(
                                "load standalone runtime config from path={} failed: {}",
                                standalone_runtime_config.as_path().display(),
                                e
                            );
                            time::sleep(sync_interval).await;
                            continue;
                        }
                    };

                max_memory.store(runtime_config.max_memory, Ordering::Relaxed);
                let new_sync_interval = Duration::from_secs(runtime_config.sync_interval);
                let (trident_state, cvar) = &*trident_state;
                if !runtime_config.enabled {
                    *trident_state.lock().unwrap() = trident::State::Disabled(Some(runtime_config));
                } else {
                    *trident_state.lock().unwrap() = trident::State::ConfigChanged(ChangedConfig {
                        runtime_config,
                        ..Default::default()
                    });
                }
                cvar.notify_one();

                if sync_interval != new_sync_interval {
                    sync_interval = new_sync_interval;
                    info!("sync interval set to {:?}", sync_interval);
                }
                time::sleep(sync_interval).await;
            }
        }));
    }

    fn run(&self, escape_tx: UnboundedSender<Duration>) {
        let session = self.session.clone();
        let trident_state = self.trident_state.clone();
        let static_config = self.static_config.clone();
        let running_config = self.running_config.clone();
        let status = self.status.clone();
        let mut sync_interval = DEFAULT_SYNC_INTERVAL;
        let running = self.running.clone();
        let flow_acl_listener = self.flow_acl_listener.clone();
        let max_memory = self.max_memory.clone();
        let exception_handler = self.exception_handler.clone();
        let ntp_diff = self.ntp_diff.clone();
        self.threads.lock().push(self.runtime.spawn(async move {
            let mut grpc_failed_count = 0;
            while running.load(Ordering::SeqCst) {
                let upgrade_hostname = |s: &str| {
                    let r = status.upgradable_read();
                    if s.ne(&r.hostname) {
                        info!("hostname changed from \"{}\" to \"{}\"", r.hostname, s);
                        RwLockUpgradableReadGuard::upgrade(r).hostname = s.to_owned();
                    }
                };
                if let Some(name) = static_config.override_os_hostname.as_ref() {
                    upgrade_hostname(name);
                } else {
                    match get_hostname() {
                        Ok(name) => {
                            upgrade_hostname(&name);
                        }
                        Err(e) => warn!("refresh hostname failed: {}", e),
                    }
                };
                if session.get_request_failed() {
                    let running_config = running_config.read();
                    let status = status.read();
                    info!(
                        "TapMode: {:?}, CtrlMac: {}, CtrlIp: {}, Hostname: {}",
                        static_config.tap_mode,
                        running_config.ctrl_mac,
                        running_config.ctrl_ip,
                        status.hostname,
                    )
                }

                let request = Synchronizer::generate_sync_request(
                    &running_config,
                    &static_config,
                    &status,
                    ntp_diff.load(Ordering::Relaxed),
                    &exception_handler,
                );
                debug!("grpc sync request: {:?}", request);

                let response = session.grpc_sync_with_statsd(request).await;
                if let Err(m) = response {
                    exception_handler.set(Exception::ControllerSocketError);
                    let (ip, port) = session.get_current_server();
                    session.set_request_failed(true);
                    Self::grpc_failed_log(&mut grpc_failed_count,
                        format!("from sync server {} {} unavailable {:?}\"",
                                    ip, port, &m));
                    time::sleep(RPC_RETRY_INTERVAL).await;
                    continue;
                }
                session.set_request_failed(false);
                grpc_failed_count = 0;

                Self::on_response(
                    session.get_current_server(),
                    response.unwrap().into_inner(),
                    &trident_state,
                    &static_config,
                    &status,
                    &flow_acl_listener,
                    &max_memory,
                    &exception_handler,
                    &escape_tx,
                );
                let (new_revision, proxy_ip, proxy_port, new_sync_interval) = {
                    let status = status.read();
                    (
                        status.new_revision.clone(),
                        status.proxy_ip.clone(),
                        status.proxy_port,
                        status.sync_interval,
                    )
                };
                if let Some(revision) = new_revision {
                    let (ctrl_ip, ctrl_mac) = {
                        let running_config = running_config.read();
                        (running_config.ctrl_ip.clone(), running_config.ctrl_mac.clone())
                    };
                    match Self::upgrade(&running, &session, &revision, &ctrl_ip, &ctrl_mac).await {
                        Ok(_) => {
                            let (ts, cvar) = &*trident_state;
                            *ts.lock().unwrap() = trident::State::Terminated;
                            cvar.notify_one();
                            warn!("agent upgrade is successful and restarts normally, deepflow-agent restart...");
                            time::sleep(Duration::from_secs(1)).await;
                            process::exit(NORMAL_EXIT_WITH_RESTART);
                        },
                        Err(e) => {
                            exception_handler.set(Exception::ControllerSocketError);
                            error!("upgrade failed: {:?}", e);
                        },
                    }
                    status.write().new_revision = None;
                }
                let (current_proxy_ip, current_proxy_port) = session.get_proxy_server();
                if proxy_ip != current_proxy_ip || proxy_port != current_proxy_port {
                    info!("ProxyController update to {:?}:{:?}", proxy_ip, proxy_port);
                    session.set_proxy_server(proxy_ip, proxy_port);
                }

                if sync_interval != new_sync_interval {
                    sync_interval = new_sync_interval;
                    info!("sync interval set to {:?}", sync_interval);
                }

                time::sleep(sync_interval).await;
            }
        }));
    }

    pub fn start(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }
        match self.agent_mode {
            RunningMode::Managed => {
                self.run_ntp_sync();
                let esc_tx = self.run_escape_timer();
                self.run_triggered_session(esc_tx.clone());
                self.run(esc_tx);
            }
            RunningMode::Standalone => {
                self.run_standalone();
            }
        }
    }

    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return;
        }
        self.runtime.block_on(async move {
            for t in self.threads.lock().drain(..) {
                let _ = t.await;
            }
        });
    }
}

pub struct SynchronizerBuilder {
    port: Option<u16>,
    tls_port: Option<u16>,
    timeout: Duration,
    controller_cert_file_prefix: String,
    vtap_group_id_request: String,

    ctrl_ip: String,
    ctrl_mac: String,
    controller_ips: Vec<String>,
}

impl SynchronizerBuilder {
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }
}

#[derive(Debug, Default)]
pub struct RuntimeEnvironment {
    pub cpu_num: u32,
    pub memory_size: u64,

    pub arch: String,
    pub os: String,

    pub kernel_version: String,
}

impl RuntimeEnvironment {
    fn new() -> RuntimeEnvironment {
        let mut sys = System::new();
        sys.refresh_system();
        RuntimeEnvironment {
            cpu_num: sys.cpus().len() as u32,
            memory_size: sys.total_memory(),
            arch: std::env::consts::ARCH.into(),
            os: format!(
                "{} {}",
                sys.name().unwrap_or_default(),
                sys.os_version().unwrap_or_default()
            ),
            kernel_version: sys
                .kernel_version()
                .unwrap_or_default()
                .split('-')
                .next()
                .unwrap_or_default()
                .into(),
        }
    }
}

pub struct NtpCounter(Weak<AtomicI64>);

impl stats::OwnedCountable for NtpCounter {
    fn get_counters(&self) -> Vec<stats::Counter> {
        match self.0.upgrade() {
            Some(counter) => vec![(
                "time_diff",
                stats::CounterType::Counted,
                stats::CounterValue::Signed(counter.load(Ordering::Relaxed)),
            )],
            None => vec![],
        }
    }

    fn closed(&self) -> bool {
        self.0.strong_count() == 0
    }
}
