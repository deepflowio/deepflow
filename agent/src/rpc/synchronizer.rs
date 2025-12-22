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

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::mem;
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::sync::{
    self,
    atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    Arc, Weak,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[cfg(unix)]
use std::{fs::Permissions, os::unix::fs::PermissionsExt};

#[cfg(target_os = "linux")]
use k8s_openapi::api::apps::v1::DaemonSet;
#[cfg(target_os = "linux")]
use kube::{
    api::{Api, Patch, PatchParams},
    Client, Config,
};
use log::{debug, error, info, warn};
use md5::{Digest, Md5};
use parking_lot::{Mutex, RwLock, RwLockUpgradableReadGuard};
use prost::Message;
use rand::RngCore;
use sysinfo::{System, SystemExt};
use tokio::runtime::Runtime;
use tokio::sync::{
    broadcast,
    mpsc::{self, UnboundedSender},
    watch,
};
use tokio::task::JoinHandle;
use tokio::time;

use super::{
    ntp::{NtpMode, NtpPacket, NtpTime},
    RPC_RECONNECT_INTERVAL, RPC_RETRY_INTERVAL,
};

#[cfg(any(target_os = "linux"))]
use crate::utils::environment::{get_current_k8s_image, get_k8s_namespace};
use crate::{
    common::{
        endpoint::EPC_INTERNET,
        policy::{Acl, Cidr, Container, IpGroupData, PeerConnection},
        FlowAclListener, PlatformData as VInterface, DEFAULT_CONTROLLER_PORT,
        NORMAL_EXIT_WITH_RESTART,
    },
    config::UserConfig,
    exception::ExceptionHandler,
    platform,
    rpc::session::Session,
    trident::{self, AgentId, AgentState, ChangedConfig, RunningMode, State, VersionInfo},
    utils::{
        command::get_hostname,
        environment::{
            get_executable_path, is_tt_pod, running_in_container, running_in_k8s,
            running_in_only_watch_k8s_mode, KubeWatchPolicy,
        },
        stats,
    },
};

use public::{
    proto::agent::{
        self as pb, AgentIdentifier, AgentType, DynamicConfig, Exception, PacketCaptureType,
    },
    utils::net::{is_unicast_link_local, IpMacPair, MacAddr},
};

const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_secs(60);
const NANOS_IN_SECOND: i64 = Duration::from_secs(1).as_nanos() as i64;
const SECOND: Duration = Duration::from_secs(1);
const DEFAULT_NTP_MAX_INTERVAL: Duration = Duration::from_secs(60);

pub struct StaticConfig {
    pub version_info: &'static VersionInfo,
    pub boot_time: SystemTime,

    pub capture_mode: pb::PacketCaptureType,
    pub vtap_group_id_request: String,
    pub controller_ip: String,

    pub env: RuntimeEnvironment,
    pub kubernetes_cluster_id: String,
    pub kubernetes_cluster_name: Option<String>,
    pub kubernetes_cluster_opaque_id: Option<String>,

    pub override_os_hostname: Option<String>,
    pub agent_unique_identifier: AgentIdentifier,
    pub current_k8s_image: Option<String>,
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
            capture_mode: Default::default(),
            vtap_group_id_request: Default::default(),
            controller_ip: Default::default(),
            env: Default::default(),
            kubernetes_cluster_id: Default::default(),
            kubernetes_cluster_name: Default::default(),
            kubernetes_cluster_opaque_id: Default::default(),
            override_os_hostname: None,
            agent_unique_identifier: Default::default(),
            current_k8s_image: None,
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
    pub first: bool,
    pub ntp_max_interval: Duration,
    pub ntp_min_interval: Duration,

    // GRPC数据
    pub local_epc: i32,

    pub last_invalid_log: Duration,
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
            first: true,
            ntp_min_interval: Duration::from_secs(10),
            ntp_max_interval: Duration::from_secs(300),

            local_epc: EPC_INTERNET,
            last_invalid_log: Duration::ZERO,
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
    const INVALID_LOG_INTERVAL: Duration = Duration::from_secs(50);

    pub fn enabled_invalid_log(&mut self) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

        if self.last_invalid_log > now {
            self.last_invalid_log = now;
        }

        now - self.last_invalid_log >= Self::INVALID_LOG_INTERVAL
    }

    pub fn update_last_invalid_log(&mut self) {
        self.last_invalid_log = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    }

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

    pub fn get_platform_data(
        &mut self,
        resp: &pb::SyncResponse,
        enabled_invalid_log: bool,
    ) -> (bool, bool) {
        let current_version = self.version_platform_data;
        let version = resp.version_platform_data.unwrap_or(0);
        debug!(
            "get grpc PlatformData version: {} vs current version: {}.",
            version, current_version
        );
        if version == 0 {
            debug!("platform data in preparation.");
            return (false, false);
        }
        if version == current_version {
            debug!("platform data same version.");
            return (false, false);
        }

        let mut has_invalid_log = false;
        if let Some(platform_compressed) = &resp.platform_data {
            let platform = pb::PlatformData::decode(platform_compressed.as_slice());
            if platform.is_ok() {
                let platform = platform.unwrap();
                let mut interfaces = Vec::new();
                let mut peers = Vec::new();
                let mut cidrs = Vec::new();
                let mut invalid_interfaces = Vec::new();
                let mut invalid_cidrs = Vec::new();
                for item in &platform.interfaces {
                    let result = VInterface::try_from(item);
                    if result.is_ok() {
                        interfaces.push(Arc::new(result.unwrap()));
                    } else {
                        if enabled_invalid_log {
                            invalid_interfaces.push(item.id());
                        }
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
                        if enabled_invalid_log {
                            invalid_cidrs.push(item.prefix());
                        }
                    }
                }

                if enabled_invalid_log {
                    if !invalid_interfaces.is_empty() {
                        warn!("Invalid interfaces: {:?}, maybe it's caused by the wrong mac, ip_resource, if_type.", invalid_interfaces);
                        has_invalid_log = true;
                    }

                    if !invalid_cidrs.is_empty() {
                        warn!(
                            "Invalid cidrs: {:?}, maybe it's caused by the wrong prefix.",
                            invalid_cidrs
                        );
                        has_invalid_log = true;
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
        return (true, has_invalid_log);
    }

    fn modify_platform(
        &mut self,
        macs: &Vec<MacAddr>,
        config: &UserConfig,
        dynamic_config: &DynamicConfig,
    ) {
        if config.inputs.cbpf.common.capture_mode == PacketCaptureType::Analyzer {
            return;
        }
        let mut local_mac_map = HashSet::new();
        for mac in macs {
            let _ = local_mac_map.insert(u64::from(*mac));
        }

        let region_id = dynamic_config.region_id();
        let pod_cluster_id = dynamic_config.pod_cluster_id();
        let mut vinterfaces = Vec::new();
        for i in &self.interfaces {
            let mut viface = (*(i.clone())).clone();
            if !is_tt_pod(config.global.common.agent_type) {
                viface.skip_mac = viface.region_id != region_id;
            } else {
                let mut is_tap_interface = viface.pod_cluster_id == pod_cluster_id;
                is_tap_interface = is_tap_interface
                    || (viface.region_id == region_id
                        && viface.device_type != (pb::DeviceType::Pod as u8));
                viface.skip_mac = !is_tap_interface;
            }

            viface.is_local = local_mac_map.contains(&viface.mac);
            vinterfaces.push(Arc::new(viface));
        }

        self.interfaces = vinterfaces;
        // TODO：bridge fdb
    }

    pub fn get_flow_acls(
        &mut self,
        resp: &pb::SyncResponse,
        enabled_invalid_log: bool,
    ) -> (bool, bool) {
        let version = resp.version_acls.unwrap_or(0);
        debug!(
            "get grpc FlowAcls version: {} vs current version: {}.",
            version, self.version_acls
        );
        if version == 0 {
            debug!("FlowAcls data in preparation.");
            return (false, false);
        }
        if version == self.version_acls {
            debug!("FlowAcls data same version.");
            return (false, false);
        }

        let mut has_invalid_log = false;
        if let Some(acls_commpressed) = &resp.flow_acls {
            let acls = pb::FlowAcls::decode(acls_commpressed.as_slice());
            if let Ok(acls) = acls {
                let mut invalid_flow_acl = Vec::new();
                let flow_acls = acls
                    .flow_acl
                    .into_iter()
                    .filter_map(|a| {
                        let id = a.id();
                        match a.try_into() {
                            Err(_) => {
                                if enabled_invalid_log {
                                    invalid_flow_acl.push(id);
                                }
                                None
                            }
                            t => t.ok(),
                        }
                    })
                    .collect::<Vec<Acl>>();
                if enabled_invalid_log && !invalid_flow_acl.is_empty() {
                    warn!("Invalid flow acl: {:?}, maybe it's with the wrong port or capture_network_type.", invalid_flow_acl);
                    has_invalid_log = true;
                }
                self.update_flow_acl(version, flow_acls);
            } else {
                error!("Invalid acls.");
                self.update_flow_acl(version, vec![]);
            }
        } else {
            self.update_flow_acl(version, vec![]);
        }
        return (true, has_invalid_log);
    }

    pub fn get_ip_groups(
        &mut self,
        resp: &pb::SyncResponse,
        enabled_invalid_log: bool,
    ) -> (bool, bool) {
        let version = resp.version_groups.unwrap_or(0);
        debug!(
            "get grpc Groups version: {} vs current version: {}.",
            version, self.version_groups
        );
        if version == 0 {
            debug!("Groups data in preparation.");
            return (false, false);
        }
        if self.version_groups == version {
            debug!("Groups data same version.");
            return (false, false);
        }

        let mut has_invalid_log = false;
        if let Some(groups_compressed) = &resp.groups {
            let groups = pb::Groups::decode(groups_compressed.as_slice());
            if groups.is_ok() {
                let groups = groups.unwrap();
                let mut ip_groups = Vec::new();
                let mut invalid_ip_groups = Vec::new();
                for item in &groups.groups {
                    let result = IpGroupData::try_from(item);
                    if result.is_ok() {
                        ip_groups.push(Arc::new(result.unwrap()));
                    } else {
                        if enabled_invalid_log {
                            invalid_ip_groups.push(item.id())
                        }
                    }
                }

                if enabled_invalid_log && !invalid_ip_groups.is_empty() {
                    warn!(
                        "Invalid ip groups: {:?}, maybe it doesn't come with a valid IP address",
                        invalid_ip_groups
                    );
                    has_invalid_log = true;
                }

                self.update_ip_groups(version, ip_groups);
            } else {
                error!("Invalid ip groups.");
                self.update_ip_groups(version, vec![]);
            }
        } else {
            self.update_ip_groups(version, vec![]);
        }
        return (true, has_invalid_log);
    }

    pub fn get_blacklist(&mut self, resp: &pb::SyncResponse) -> Vec<u64> {
        return resp.skip_interface.iter().map(|i| i.mac.unwrap()).collect();
    }

    pub fn get_local_epc(&mut self, config: &DynamicConfig) -> bool {
        if config.vpc_id() as i32 != self.local_epc {
            self.local_epc = config.vpc_id() as i32;
            return true;
        }
        return false;
    }

    fn trigger_flow_acl(
        &self,
        agent_type: AgentType,
        listener: &mut Box<dyn FlowAclListener>,
        enabled_invalid_log: bool,
        has_invalid_log: &mut bool,
    ) -> Result<(), String> {
        listener.flow_acl_change(
            agent_type,
            self.local_epc,
            &self.ip_groups,
            &self.interfaces,
            &self.peers,
            &self.cidrs,
            &self.acls,
            enabled_invalid_log,
            has_invalid_log,
        )
    }

    pub fn update(
        &mut self,
        user_config: &UserConfig,
        static_config: &StaticConfig,
        resp: &pb::SyncResponse,
        macs: &Vec<MacAddr>,
        enabled_invalid_log: bool,
    ) -> (bool, bool, bool) {
        let mut has_invalid_log = false;

        self.proxy_ip = if user_config.global.communication.proxy_controller_ip.len() > 0 {
            Some(user_config.global.communication.proxy_controller_ip.clone())
        } else {
            Some(static_config.controller_ip.clone())
        };
        self.proxy_port = user_config.global.communication.proxy_controller_port;
        self.sync_interval = user_config.global.communication.proactive_request_interval;
        self.ntp_enabled = user_config.global.ntp.enabled;
        self.ntp_max_interval = user_config.global.ntp.max_drift;
        self.ntp_min_interval = user_config.global.ntp.min_drift;

        let wait_ntp = self.ntp_enabled && self.first;
        if resp.only_partial_fields() {
            return (false, wait_ntp, has_invalid_log);
        }

        let (updated_platform, invalid_log) = self.get_platform_data(resp, enabled_invalid_log);
        if updated_platform {
            self.modify_platform(
                macs,
                user_config,
                &resp.dynamic_config.clone().unwrap_or_default(),
            );
        }
        has_invalid_log |= invalid_log;

        let (mut updated, invalid_log) = self.get_ip_groups(resp, enabled_invalid_log);
        updated |= updated_platform;
        has_invalid_log |= invalid_log;

        let (updated_acl, invalid_log) = self.get_flow_acls(resp, enabled_invalid_log);
        updated |= updated_acl;
        has_invalid_log |= invalid_log;

        updated = self.get_local_epc(&resp.dynamic_config.clone().unwrap_or_default()) || updated;

        (updated, wait_ntp, has_invalid_log)
    }
}

pub struct Synchronizer {
    pub static_config: Arc<StaticConfig>,
    pub agent_id: Arc<RwLock<AgentId>>,
    pub status: Arc<RwLock<Status>>,

    agent_state: Arc<AgentState>,

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
    ipmac_tx: Arc<broadcast::Sender<IpMacPair>>,
}

impl Synchronizer {
    const LOG_THRESHOLD: usize = 3;

    pub fn new(
        runtime: Arc<Runtime>,
        session: Arc<Session>,
        agent_state: Arc<AgentState>,
        version_info: &'static VersionInfo,
        agent_id: AgentId,
        controller_ip: String,
        vtap_group_id_request: String,
        kubernetes_cluster_id: String,
        kubernetes_cluster_name: Option<String>,
        kubernetes_cluster_opaque_id: Option<String>,
        override_os_hostname: Option<String>,
        agent_unique_identifier: crate::config::AgentIdType,
        exception_handler: ExceptionHandler,
        agent_mode: RunningMode,
        standalone_runtime_config: Option<PathBuf>,
        ipmac_tx: Arc<broadcast::Sender<IpMacPair>>,
        ntp_diff: Arc<AtomicI64>,
    ) -> Synchronizer {
        Synchronizer {
            static_config: Arc::new(StaticConfig {
                version_info,
                boot_time: SystemTime::now(),
                capture_mode: pb::PacketCaptureType::Local,
                vtap_group_id_request,
                controller_ip,
                env: RuntimeEnvironment::new(),
                kubernetes_cluster_id,
                kubernetes_cluster_name,
                kubernetes_cluster_opaque_id,
                override_os_hostname,
                agent_unique_identifier: agent_unique_identifier.into(),
                #[cfg(any(target_os = "linux"))]
                current_k8s_image: runtime.block_on(get_current_k8s_image()),
                #[cfg(any(target_os = "windows", target_os = "android"))]
                current_k8s_image: None,
            }),
            agent_id: Arc::new(RwLock::new(agent_id)),
            agent_state,
            status: Default::default(),
            session,
            running: Arc::new(AtomicBool::new(false)),
            runtime,
            threads: Default::default(),
            flow_acl_listener: Arc::new(sync::Mutex::new(vec![])),
            exception_handler,

            max_memory: Default::default(),
            ntp_diff,
            agent_mode,
            standalone_runtime_config,
            ipmac_tx,
        }
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

    fn host_ips() -> Vec<String> {
        #[cfg(target_os = "linux")]
        let (links, addrs) = (
            public::netns::link_list_in_netns(&public::netns::NsFile::Root),
            public::netns::addr_list_in_netns(&public::netns::NsFile::Root),
        );
        #[cfg(any(target_os = "windows", target_os = "android"))]
        let (links, addrs) = (
            public::utils::net::link_list(),
            public::utils::net::addr_list(),
        );

        let (links, addrs) = match (links, addrs) {
            (Ok(links), Ok(addrs)) => (links, addrs),
            (Err(e), _) => {
                warn!("get links failed: {}", e);
                return vec![];
            }
            (_, Err(e)) => {
                warn!("get addrs failed: {}", e);
                return vec![];
            }
        };
        // find ignored interface indices
        let filtered_indices: HashSet<u32> = links
            .into_iter()
            .filter_map(|link| {
                if platform::IGNORED_INTERFACES.contains(&link.name.as_str()) {
                    Some(link.if_index)
                } else {
                    None
                }
            })
            .collect();
        addrs
            .into_iter()
            .filter_map(|addr| {
                if Self::is_excluded_ip_addr(addr.ip_addr)
                    || filtered_indices.contains(&addr.if_index)
                {
                    None
                } else {
                    Some(addr.ip_addr.to_string())
                }
            })
            .collect()
    }

    pub fn generate_sync_request(
        agent_id: &Arc<RwLock<AgentId>>,
        static_config: &Arc<StaticConfig>,
        status: &Arc<RwLock<Status>>,
        time_diff: i64,
        exception_handler: &ExceptionHandler,
        grpc_buffer_size: u64,
    ) -> pb::SyncRequest {
        let status = status.read();

        let boot_time = static_config
            .boot_time
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let boot_time = (boot_time as i64 + time_diff) / 1_000_000_000;

        let agent_id = agent_id.read();

        pb::SyncRequest {
            boot_time: Some(boot_time as u32),
            config_accepted: Some(status.config_accepted),
            version_platform_data: Some(status.version_platform_data),
            version_acls: Some(status.version_acls),
            version_groups: Some(status.version_groups),
            state: Some(pb::State::Running.into()),
            revision: Some(static_config.version_info.revision.to_owned()),
            current_k8s_image: static_config.current_k8s_image.clone(),
            exception: Some(exception_handler.take()),
            process_name: Some(static_config.version_info.name.to_owned()),
            ctrl_mac: Some(agent_id.ipmac.mac.to_string()),
            ctrl_ip: Some(agent_id.ipmac.ip.to_string()),
            team_id: Some(agent_id.team_id.clone()),
            host: Some(status.hostname.clone()),
            host_ips: Self::host_ips(),
            cpu_num: Some(static_config.env.cpu_num),
            memory_size: Some(static_config.env.memory_size),
            arch: Some(static_config.env.arch.clone()),
            os: Some(static_config.env.os.clone()),
            kernel_version: Some(static_config.env.kernel_version.clone()),
            agent_group_id_request: Some(static_config.vtap_group_id_request.clone()),
            kubernetes_cluster_id: Some(static_config.kubernetes_cluster_id.clone()),
            kubernetes_cluster_name: static_config.kubernetes_cluster_name.clone(),
            kubernetes_cluster_md5: static_config.kubernetes_cluster_opaque_id.clone(),
            kubernetes_force_watch: Some(running_in_only_watch_k8s_mode()),
            kubernetes_watch_policy: Some(
                pb::KubernetesWatchPolicy::from(KubeWatchPolicy::get()).into(),
            ),
            agent_unique_identifier: Some(pb::AgentIdentifier::from(
                static_config.agent_unique_identifier,
            ) as i32),
            current_grpc_buffer_size: Some(grpc_buffer_size),
            ..Default::default()
        }
    }

    pub fn clone_session(&self) -> Arc<Session> {
        self.session.clone()
    }

    fn parse_upgrade(
        resp: &pb::SyncResponse,
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

    fn parse_containers(resp: &pb::SyncResponse) -> Vec<Arc<Container>> {
        let mut containers = vec![];
        for item in &resp.containers {
            containers.push(Arc::new(Container::from(item)));
        }
        return containers;
    }

    fn parse_segment(
        capture_mode: PacketCaptureType,
        resp: &pb::SyncResponse,
        enabled_invalid_log: bool,
    ) -> (Vec<pb::Segment>, Vec<MacAddr>, Vec<MacAddr>, bool) {
        if resp.only_partial_fields() {
            return (vec![], vec![], vec![], false);
        }

        let segments = if capture_mode == PacketCaptureType::Analyzer {
            resp.remote_segments.clone()
        } else {
            resp.local_segments.clone()
        };

        let mut macs = Vec::new();
        let mut gateway_vmacs = Vec::new();
        let mut invalid_segment = Vec::new();
        let mut invalid_mac = Vec::new();
        let mut invalid_vmac = Vec::new();
        for segment in &segments {
            let vm_macs = &segment.mac;
            let vmacs = &segment.vmac;
            if vm_macs.len() != vmacs.len() {
                if enabled_invalid_log {
                    invalid_segment.push(segment.id());
                }
                continue;
            }
            for (mac_str, vmac_str) in vm_macs.iter().zip(vmacs) {
                let mac = MacAddr::from_str(mac_str.as_str());
                if mac.is_err() {
                    if enabled_invalid_log {
                        invalid_mac.push(mac_str.as_str());
                    }
                    continue;
                }

                let vmac = MacAddr::from_str(vmac_str.as_str());
                if vmac.is_err() {
                    if enabled_invalid_log {
                        invalid_vmac.push(vmac_str.as_str());
                    }
                    continue;
                }
                macs.push(mac.unwrap());
                gateway_vmacs.push(vmac.unwrap());
            }
        }

        let mut has_invalid_log = false;
        if enabled_invalid_log {
            if segments.len() == 0 && capture_mode != PacketCaptureType::Local {
                info!("Segment is empty, in {:?} mode.", capture_mode);
                has_invalid_log = true;
            }

            if !invalid_segment.is_empty() {
                warn!(
                    "Invalid segment {:?}, the length of vmMacs and vMacs is inconsistent.",
                    invalid_segment
                );
                has_invalid_log = true;
            }
            if !invalid_mac.is_empty() {
                warn!(
                    "Invalid mac {:?}, The mac address is invalid and cannot be resolved to MacAddr
    .",
                    invalid_mac
                );
                has_invalid_log = true;
            }
            if !invalid_vmac.is_empty() {
                warn!(
                    "Invalid vmac {:?}, The vmac address is invalid and cannot be resolved to MacAddr
    .",
                    invalid_vmac
                );
                has_invalid_log = true;
            }
        }

        return (segments, macs, gateway_vmacs, has_invalid_log);
    }

    // Note that both 'status' and 'flow_acl_listener' will be locked here, and other places where 'status'
    // and 'flow_acl_listener' are used need to be careful to avoid deadlocks
    async fn on_response(
        remote: (String, u16),
        mut resp: pb::SyncResponse,
        agent_id: &RwLock<AgentId>,
        agent_state: &AgentState,
        ntp_receiver: &mut watch::Receiver<u64>,
        static_config: &Arc<StaticConfig>,
        status: &Arc<RwLock<Status>>,
        flow_acl_listener: &Arc<sync::Mutex<Vec<Box<dyn FlowAclListener>>>>,
        max_memory: &Arc<AtomicU64>,
        exception_handler: &ExceptionHandler,
        escape_tx: &UnboundedSender<Duration>,
    ) {
        Self::parse_upgrade(&resp, static_config, status);

        match resp.status() {
            pb::Status::Failed => warn!(
                "server ({:?}) responded with {:?}",
                remote,
                pb::Status::Failed
            ),
            pb::Status::Heartbeat => return,
            _ => (),
        }

        let config = resp.user_config.take();
        if config.is_none() {
            warn!("invalid response from {:?} without config", remote);
            return;
        }
        let user_config = serde_yaml::from_str(&config.unwrap());
        if let Err(e) = user_config {
            warn!(
                "invalid response from {:?} with invalid config: {}",
                remote, e
            );
            exception_handler.set(Exception::InvalidConfiguration);
            return;
        }
        let mut user_config: UserConfig = user_config.unwrap();
        if let Some(dynamic_config) = resp.dynamic_config.as_ref() {
            user_config.set_dynamic_config_and_grpc_buffer_size(
                dynamic_config,
                resp.new_grpc_buffer_size(),
            );
            match &dynamic_config.group_id {
                Some(id) if !id.is_empty() => {
                    agent_id.write().group_id = id.to_owned();
                }
                _ => (),
            }
        }
        user_config.adjust();

        if resp.only_partial_fields() {
            info!(
                "Grpc recv only_partial_fields message and update grpc_buffer_size to {}.",
                user_config.global.communication.grpc_buffer_size
            );
        }

        // FIXME: Confirm the kvm resource classification and then cancel the comment
        // When the ee version compiles the ce crate, it will be false, only ce version
        // will be true
        /*
        if static_config.version_info.name == env!("AGENT_NAME") {
            user_config.platform_enabled = false;
        }
         */
        let _ = escape_tx.send(user_config.global.communication.max_escape_duration);

        max_memory.store(user_config.global.limits.max_memory, Ordering::Relaxed);

        let containers = Self::parse_containers(&resp);
        for listener in flow_acl_listener.lock().unwrap().iter_mut() {
            listener.containers_change(&containers);
        }

        let (updated, wait_ntp, macs, gateway_vmac_addrs, enabled_invalid_log, mut has_invalid_log) = {
            let mut status_guard = status.write();
            let enabled_invalid_log = status_guard.enabled_invalid_log();

            let (_, macs, gateway_vmac_addrs, has_invalid_log) = Self::parse_segment(
                user_config.inputs.cbpf.common.capture_mode,
                &resp,
                enabled_invalid_log,
            );
            let (updated, wait_ntp, invalid_log) = status_guard.update(
                &user_config,
                static_config,
                &resp,
                &macs,
                enabled_invalid_log,
            );

            (
                updated,
                wait_ntp,
                macs,
                gateway_vmac_addrs,
                enabled_invalid_log,
                has_invalid_log || invalid_log,
            )
        };
        if wait_ntp {
            // Here, it is necessary to wait for the NTP synchronization timestamp to start
            // collecting traffic and avoid using incorrect timestamps
            info!("Waiting for NTP synchronization to complete... The agent will remain temporarily disabled until synchronization is finished.");
            let _ = ntp_receiver.changed().await;
        }
        if updated {
            let status_guard = status.write();
            // 更新策略相关
            let last = SystemTime::now();
            info!("Grpc version ip-groups: {}, interfaces, peer-connections and cidrs: {}, flow-acls: {}",
            status_guard.version_groups, status_guard.version_platform_data, status_guard.version_acls);
            let mut policy_error = false;
            for listener in flow_acl_listener.lock().unwrap().iter_mut() {
                if let Err(e) = status_guard.trigger_flow_acl(
                    user_config.global.common.agent_type,
                    listener,
                    enabled_invalid_log,
                    &mut has_invalid_log,
                ) {
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
                status_guard.ip_groups.len(),
                status_guard.interfaces.len(),
                status_guard.peers.len(),
                status_guard.cidrs.len(),
                status_guard.acls.len(),
            );
        }

        if has_invalid_log {
            let mut status_guard = status.write();
            status_guard.update_last_invalid_log();
        }

        let mut status_guard = status.write();
        status_guard.first = false;
        if resp.only_partial_fields() {
            drop(status_guard);

            agent_state.update_partial_config(user_config);
        } else {
            let blacklist = status_guard.get_blacklist(&resp);
            drop(status_guard);

            agent_state.update_config(ChangedConfig {
                user_config,
                blacklist,
                vm_mac_addrs: macs,
                gateway_vmac_addrs,
                tap_types: resp.capture_network_types,
            });
        }
    }

    fn grpc_failed_log(grpc_failed_count: &mut usize, detail: String) {
        *grpc_failed_count += 1;
        if *grpc_failed_count > Self::LOG_THRESHOLD {
            error!("Grpc error {} count {}", detail, grpc_failed_count);
        } else {
            warn!("Grpc error {} count {}", detail, grpc_failed_count);
        }
    }

    fn run_triggered_session(
        &self,
        escape_tx: UnboundedSender<Duration>,
        mut ntp_receiver: Option<watch::Receiver<u64>>,
    ) {
        let session = self.session.clone();
        let agent_state = self.agent_state.clone();
        let static_config = self.static_config.clone();
        let agent_id = self.agent_id.clone();
        let status = self.status.clone();
        let running = self.running.clone();
        let max_memory = self.max_memory.clone();
        let flow_acl_listener = self.flow_acl_listener.clone();
        let exception_handler = self.exception_handler.clone();
        let ntp_diff = self.ntp_diff.clone();
        let mut ntp_receiver = ntp_receiver.take().unwrap();
        self.threads.lock().push(self.runtime.spawn(async move {
            let mut grpc_failed_count = 0;
            while running.load(Ordering::SeqCst) {
                let response = session
                    .grpc_push_with_statsd(Synchronizer::generate_sync_request(
                        &agent_id,
                        &static_config,
                        &status,
                        ntp_diff.load(Ordering::Relaxed),
                        &exception_handler,
                        session.get_rx_size(),
                    ))
                    .await;
                let version = session.get_version();

                if let Err(m) = response {
                    exception_handler.set(Exception::ControllerSocketError);
                    Self::grpc_failed_log(&mut grpc_failed_count, format!("from trigger {:?}", m));
                    time::sleep(RPC_RETRY_INTERVAL).await;
                    continue;
                }
                grpc_failed_count = 0;

                let mut stream = response.unwrap().into_inner();
                while running.load(Ordering::SeqCst) {
                    let message = stream.message().await;
                    if session.get_version() != version {
                        info!("grpc server or config changed");
                        time::sleep(RPC_RECONNECT_INTERVAL).await;
                        break;
                    }
                    if let Err(m) = message {
                        exception_handler.set(Exception::ControllerSocketError);
                        Self::grpc_failed_log(
                            &mut grpc_failed_count,
                            format!("from trigger {:?}", m),
                        );
                        time::sleep(RPC_RECONNECT_INTERVAL).await;
                        break;
                    }
                    let message = message.unwrap();
                    if message.is_none() {
                        debug!("end of stream");
                        time::sleep(RPC_RECONNECT_INTERVAL).await;
                        break;
                    }
                    let message = message.unwrap();

                    session.update_message_counter(message.encoded_len());

                    match message.status() {
                        pb::Status::Failed => {
                            exception_handler.set(Exception::ControllerSocketError);
                            let (ip, port) = session.get_current_server();
                            warn!(
                                "server (ip: {} port: {}) responded with {:?}",
                                ip,
                                port,
                                pb::Status::Failed
                            );
                            time::sleep(RPC_RETRY_INTERVAL).await;
                            continue;
                        }
                        pb::Status::Heartbeat => {
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
                        &agent_id,
                        &agent_state,
                        &mut ntp_receiver,
                        &static_config,
                        &status,
                        &flow_acl_listener,
                        &max_memory,
                        &exception_handler,
                        &escape_tx,
                    )
                    .await;
                }
            }
        }));
    }

    fn run_escape_timer(&self) -> UnboundedSender<Duration> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let agent_state = self.agent_state.clone();
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
                        agent_state.disable();
                        warn!("as max escape time expired, deepflow-agent restart...");
                        // 与控制器失联的时间超过设置的逃逸时间，这里直接重启主要有两个原因：
                        // 1. 如果仅是停用系统无法回收全部的内存资源
                        // 2. 控制器地址可能是通过域明解析的，如果域明解析发生变更需要重启来触发重新解析
                        crate::utils::clean_and_exit(NORMAL_EXIT_WITH_RESTART);
                        return;
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

    fn run_ntp_sync(&self, mut ntp_sender: Option<watch::Sender<u64>>) {
        let agent_id = self.agent_id.clone();
        let session = self.session.clone();
        let status = self.status.clone();
        let running = self.running.clone();
        let ntp_diff = self.ntp_diff.clone();
        let ntp_sender = ntp_sender.take().unwrap();
        self.runtime.spawn(async move {
            while running.load(Ordering::SeqCst) {
                let (enabled, sync_interval, max_interval, min_interval, first) = {
                    let reader = status.read();
                    (reader.ntp_enabled, reader.sync_interval, reader.ntp_max_interval.as_nanos() as i64, reader.ntp_min_interval.as_nanos() as i64, reader.first)
                };

                if !enabled {
                    let diff = ntp_diff.load(Ordering::Relaxed);
                    if diff > max_interval {
                        warn!("Closing NTP causes the timestamp to fall back by {}s, and the agent needs to be restarted.", diff/NANOS_IN_SECOND);
                        crate::utils::clean_and_exit(NORMAL_EXIT_WITH_RESTART);
                        return;
                    }
                    ntp_diff.store(0, Ordering::Relaxed);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }

                let mut ntp_msg = NtpPacket::new();
                // To ensure privacy and prevent spoofing, try to use a random 64-bit
                // value for the TransmitTime. Keep track of when the messsage was
                // actually transmitted.
                ntp_msg.ts_xmit = rand::thread_rng().next_u64();
                let send_time = SystemTime::now();

                let ctrl_ip = agent_id.read().ipmac.ip.to_string();
                let response = session
                    .grpc_ntp_with_statsd(pb::NtpRequest {
                        ctrl_ip: Some(ctrl_ip),
                        request: Some(ntp_msg.to_vec()),
                    })
                    .await;

                if let Err(e) = response {
                    warn!("NTP request failed with: {:?}, If NTP has never completed synchronization the agent will remain temporarily disabled until the initial NTP synchronization is completed.", e);
                    time::sleep(sync_interval).await;
                    continue;
                }
                let response = response.unwrap().into_inner();
                if response.response.is_none() {
                    warn!("NTP response is empty, please check the NTP service. If NTP has never completed synchronization the agent will remain temporarily disabled until the initial NTP synchronization is completed.");
                    time::sleep(sync_interval).await;
                    continue;
                }

                let resp_packet = NtpPacket::try_from(response.response.unwrap().as_ref());
                if let Err(e) = resp_packet {
                    warn!("Parse NTP response failed: {:?}, If NTP has never completed synchronization the agent will remain temporarily disabled until the initial NTP synchronization is completed.", e);
                    time::sleep(sync_interval).await;
                    continue;
                }
                let mut resp_packet = resp_packet.unwrap();

                if resp_packet.get_mode() != NtpMode::Server {
                    warn!("NTP: invalid mod in response, If NTP has never completed synchronization the agent will remain temporarily disabled until the initial NTP synchronization is completed.");
                    time::sleep(sync_interval).await;
                    continue;
                }
                if resp_packet.ts_xmit == 0 {
                    warn!("NTP: invalid transmit time in response, If NTP has never completed synchronization the agent will remain temporarily disabled until the initial NTP synchronization is completed.");
                    time::sleep(sync_interval).await;
                    continue;
                }
                if resp_packet.ts_orig != ntp_msg.ts_xmit {
                    warn!("NTP: server response mismatch, If NTP has never completed synchronization the agent will remain temporarily disabled until the initial NTP synchronization is completed.");
                    time::sleep(sync_interval).await;
                    continue;
                }
                if resp_packet.ts_recv > resp_packet.ts_xmit {
                    warn!("NTP: server clock ticked backwards, If NTP has never completed synchronization the agent will remain temporarily disabled until the initial NTP synchronization is completed.");
                    time::sleep(sync_interval).await;
                    continue;
                }
                let recv_time = SystemTime::now();
                if let Err(e) = recv_time.duration_since(send_time) {
                    warn!("System time err: {:?}, If NTP has never completed synchronization the agent will remain temporarily disabled until the initial NTP synchronization is completed.", e);
                    time::sleep(sync_interval).await;
                    continue;
                }

                // Correct the received message's origin time using the actual
                // transmit time.
                resp_packet.ts_orig = NtpTime::from(&send_time).0;
                let offset = resp_packet.offset(&recv_time) / NANOS_IN_SECOND * NANOS_IN_SECOND;
                match ntp_diff.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |x| {
                    if (x - offset).abs() >= min_interval {
                        info!("NTP Set time offset {}s.", offset / NANOS_IN_SECOND);
                        Some(offset)
                    } else {
                        None
                    }
                }) {
                    Ok(last_offset) => {
                        if !first && (last_offset - offset).abs() >= max_interval {
                            warn!("Openning NTP causes the timestamp to fall back by {}s, and the agent needs to be restarted.", offset/ NANOS_IN_SECOND);
                            crate::utils::clean_and_exit(NORMAL_EXIT_WITH_RESTART);
                            return;
                        }
                    }
                    _ =>{},
                }

                let _ = ntp_sender.send(send_time.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs());

                time::sleep(sync_interval).await;
            }
        });
    }

    #[cfg(target_os = "linux")]
    async fn upgrade_k8s_image(
        running: &AtomicBool,
        session: &Session,
        agent_id: &AgentId,
        current_k8s_image: &Option<String>,
    ) -> Result<bool, String> {
        let response = session
            .grpc_upgrade_with_statsd(pb::UpgradeRequest {
                ctrl_ip: Some(agent_id.ipmac.ip.to_string()),
                ctrl_mac: Some(agent_id.ipmac.mac.to_string()),
                team_id: Some(agent_id.team_id.clone()),
            })
            .await;
        let mut stream = match response {
            Ok(stream) => stream.into_inner(),
            Err(e) => return Err(format!("rpc error {:?}", e)),
        };
        while let Some(message) = stream
            .message()
            .await
            .map_err(|e| format!("rpc error {:?}", e))?
        {
            if !running.load(Ordering::SeqCst) {
                return Err("upgrade terminated".to_owned());
            }

            session.update_message_counter(message.encoded_len());

            if message.status() != pb::Status::Success {
                return Err("upgrade failed in server response".to_owned());
            }

            let new_k8s_image = message.k8s_image();
            match current_k8s_image {
                Some(image) if image == new_k8s_image => {
                    info!("k8s_image '{image}' has not changed, not upgraded");
                    return Ok(false);
                }
                _ => (),
            }
            info!(
                "upgrading k8s_image from '{}' to '{new_k8s_image}'",
                current_k8s_image
                    .as_ref()
                    .map(|s| s.as_str())
                    .unwrap_or_default(),
            );

            let Ok(mut config) = Config::infer().await else {
                return Err("failed to infer kubernetes config".to_owned());
            };
            config.accept_invalid_certs = true;

            let Ok(client) = Client::try_from(config) else {
                return Err("failed to create kubernetes client".to_owned());
            };

            let daemonsets: Api<DaemonSet> = Api::namespaced(client, &get_k8s_namespace());

            // Referer: https://kubernetes.io/zh-cn/docs/reference/kubernetes-api/workload-resources/pod-v1/#Container
            let patch = serde_json::json!({
                "apiVersion": "apps/v1",
                "kind": "DaemonSet",
                "spec": {
                    "template":{
                        "spec":{
                            "containers": [{
                                "name": public::consts::CONTAINER_NAME,
                                "image": new_k8s_image,
                            }],
                        }
                    }
                }
            });
            let params = PatchParams::default();
            let patch = Patch::Strategic(&patch);
            if let Err(e) = daemonsets
                .patch(public::consts::DAEMONSET_NAME, &params, &patch)
                .await
            {
                return Err(format!(
                    "patch deepflow-agent k8s image failed, current_k8s_image: {:?}, error: {:?}",
                    &current_k8s_image, e
                ));
            }
            return Ok(true);
        }
        Ok(false)
    }

    async fn upgrade(
        running: &AtomicBool,
        session: &Session,
        new_revision: &str,
        agent_id: &AgentId,
        agent_state: &AgentState,
    ) -> Result<bool, String> {
        if running_in_container() {
            info!("running in a non-k8s containter, exit directly and try to recreate myself using a new version docker image...");
            return Ok(true);
        }

        let response = session
            .grpc_upgrade_with_statsd(pb::UpgradeRequest {
                ctrl_ip: Some(agent_id.ipmac.ip.to_string()),
                ctrl_mac: Some(agent_id.ipmac.mac.to_string()),
                team_id: Some(agent_id.team_id.clone()),
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
            if agent_state.get() != State::Running {
                info!("Upgrade halted because agent is no longer in running state");
                return Ok(false);
            }
            if message.status() != pb::Status::Success {
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

        Ok(true)
    }

    fn run_standalone(&self) {
        let running = self.running.clone();
        let agent_state = self.agent_state.clone();
        let max_memory = self.max_memory.clone();
        let mut sync_interval = DEFAULT_SYNC_INTERVAL;
        let standalone_runtime_config = self.standalone_runtime_config.as_ref().unwrap().clone();
        let flow_acl_listener = self.flow_acl_listener.clone();
        self.threads.lock().push(self.runtime.spawn(async move {
            while running.load(Ordering::SeqCst) {
                let mut user_config =
                    match UserConfig::load_from_file(standalone_runtime_config.as_path()) {
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
                let dynamic_config = DynamicConfig {
                    enabled: Some(true),
                    vpc_id: Some(3302),
                    agent_id: Some(3302),
                    agent_type: Some(AgentType::TtProcess.into()),
                    ..Default::default()
                };
                user_config.set_dynamic_config_and_grpc_buffer_size(&dynamic_config, 5 << 20);

                for listener in flow_acl_listener.lock().unwrap().iter_mut() {
                    let _ = listener.flow_acl_change(
                        user_config.global.common.agent_type,
                        dynamic_config.vpc_id() as i32,
                        &vec![],
                        &vec![],
                        &vec![],
                        &vec![],
                        &vec![],
                        false,
                        &mut false,
                    );
                }

                max_memory.store(user_config.global.limits.max_memory, Ordering::Relaxed);
                let new_sync_interval = user_config.global.communication.proactive_request_interval;
                agent_state.update_config(ChangedConfig {
                    user_config,
                    ..Default::default()
                });

                if sync_interval != new_sync_interval {
                    sync_interval = new_sync_interval;
                    info!("sync interval set to {:?}", sync_interval);
                }
                time::sleep(sync_interval).await;
            }
        }));
    }

    fn run(
        &self,
        escape_tx: UnboundedSender<Duration>,
        mut ntp_receiver: Option<watch::Receiver<u64>>,
    ) {
        let session = self.session.clone();
        let agent_state = self.agent_state.clone();
        let static_config = self.static_config.clone();
        let agent_id = self.agent_id.clone();
        let status = self.status.clone();
        let mut sync_interval = DEFAULT_SYNC_INTERVAL;
        let running = self.running.clone();
        let flow_acl_listener = self.flow_acl_listener.clone();
        let max_memory = self.max_memory.clone();
        let exception_handler = self.exception_handler.clone();
        let ntp_diff = self.ntp_diff.clone();
        let mut ntp_receiver = ntp_receiver.take().unwrap();
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
                    let agent_id = agent_id.read();
                    let status = status.read();
                    info!(
                        "PacketCaptureType: {:?}, AgentId: {:?}, Hostname: {}",
                        static_config.capture_mode,
                        agent_id,
                        status.hostname,
                    )
                }
                let request = Synchronizer::generate_sync_request(
                    &agent_id,
                    &static_config,
                    &status,
                    ntp_diff.load(Ordering::Relaxed),
                    &exception_handler,
                    session.get_rx_size(),
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
                    &agent_id,
                    &agent_state,
                    &mut ntp_receiver,
                    &static_config,
                    &status,
                    &flow_acl_listener,
                    &max_memory,
                    &exception_handler,
                    &escape_tx,
                ).await;

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
                    let id = agent_id.read().clone();
                    if running_in_k8s() {
                        #[cfg(target_os = "linux")]
                        match Self::upgrade_k8s_image(&running, &session, &id, &static_config.current_k8s_image).await {
                            Ok(true) => {
                                warn!("agent upgrade is successful and don't ternimate or restart it, wait for the k8s to recreate it");
                            }
                            Ok(false) => (), // same version or no valid message
                            Err(e) => {
                                exception_handler.set(Exception::ControllerSocketError);
                                error!("upgrade failed: {:?}", e);
                            }
                        }
                        #[cfg(any(target_os = "windows", target_os = "android"))]
                        warn!("does not support upgrading environment");
                    } else {
                        match Self::upgrade(&running, &session, &revision, &id, &agent_state).await {
                            Ok(true) => {
                                warn!("agent upgrade is successful and restarts normally, deepflow-agent restart...");
                                crate::utils::clean_and_exit(NORMAL_EXIT_WITH_RESTART);
                                return;
                            },
                            Ok(false) => (), // upgrade terminated
                            Err(e) => {
                                exception_handler.set(Exception::ControllerSocketError);
                                error!("upgrade failed: {:?}", e);
                            },
                        }
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

    async fn watch_ipmac_pair(
        mut ipmac_rx: broadcast::Receiver<IpMacPair>,
        agent_id: Arc<RwLock<AgentId>>,
        status: Arc<RwLock<Status>>,
    ) {
        while let Ok(new_ipmac) = ipmac_rx.recv().await {
            {
                let mut old_id = agent_id.write();
                old_id.ipmac.ip = new_ipmac.ip;
                old_id.ipmac.mac = new_ipmac.mac;
            }
            {
                let mut sg = status.write();
                sg.proxy_ip = None;
                sg.proxy_port = DEFAULT_CONTROLLER_PORT;
            }
        }
    }

    pub fn start(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }
        let agent_id = self.agent_id.clone();
        let status = self.status.clone();
        let ipmac_rx = self.ipmac_tx.subscribe();
        self.runtime.spawn(async move {
            Self::watch_ipmac_pair(ipmac_rx, agent_id, status).await;
        });
        match self.agent_mode {
            RunningMode::Managed => {
                let (ntp_sender, ntp_receiver) = watch::channel(0);
                self.run_ntp_sync(Some(ntp_sender));
                let esc_tx = self.run_escape_timer();
                self.run_triggered_session(esc_tx.clone(), Some(ntp_receiver.clone()));
                self.run(esc_tx, Some(ntp_receiver));
            }
            RunningMode::Standalone => self.run_standalone(),
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

#[cfg(target_os = "linux")]
#[derive(PartialEq, Eq)]
enum InfoType {
    Name,
    OsVersion,
}

impl RuntimeEnvironment {
    fn new() -> RuntimeEnvironment {
        let mut sys = System::new();
        sys.refresh_system();
        RuntimeEnvironment {
            cpu_num: sys.cpus().len() as u32,
            memory_size: sys.total_memory(),
            arch: std::env::consts::ARCH.into(),
            #[cfg(target_os = "linux")]
            os: {
                let os_name = Self::get_system_info_linux(
                    InfoType::Name,
                    Path::new("/proc/1/root/etc/os-release"),
                    Path::new("/proc/1/root/etc/lsb-release"),
                );
                let os_version = Self::get_system_info_linux(
                    InfoType::OsVersion,
                    Path::new("/proc/1/root/etc/os-release"),
                    Path::new("/proc/1/root/etc/lsb-release"),
                );
                format!(
                    "{} {}",
                    os_name.unwrap_or_else(|| sys.name().unwrap_or_default()),
                    os_version.unwrap_or_else(|| sys.os_version().unwrap_or_default())
                )
            },
            #[cfg(not(target_os = "linux"))]
            os: format!(
                "{} {}",
                sys.name().unwrap_or_default(),
                sys.os_version().unwrap_or_default()
            ),
            kernel_version: sys.kernel_version().unwrap_or_default(),
        }
    }

    // Code is from https://github.com/GuillaumeGomez/sysinfo/blob/51b249e6e7e6e5ad0eb3f83a64f8a6505195e200/src/unix/linux/system.rs#L611
    // Agent in container does not have access to system files, neither can it set mount namespace
    // An alternative approach is to use `/proc/1/root/etc/os-release` and `/proc/1/root/etc/lsb-release`
    // files to get system info
    #[cfg(target_os = "linux")]
    fn get_system_info_linux(info: InfoType, path: &Path, fallback_path: &Path) -> Option<String> {
        if let Ok(buf) = fs::read_to_string(path) {
            let info_str = match info {
                InfoType::Name => "NAME=",
                InfoType::OsVersion => "VERSION_ID=",
            };

            for line in buf.lines() {
                if let Some(stripped) = line.strip_prefix(info_str) {
                    return Some(stripped.replace('"', ""));
                }
            }
        }

        // Fallback to `/etc/lsb-release` file for systems where VERSION_ID is not included.
        // VERSION_ID is not required in the `/etc/os-release` file
        // per https://www.linux.org/docs/man5/os-release.html
        // If this fails for some reason, fallback to None
        let buf = fs::read_to_string(fallback_path).ok()?;

        let info_str = match info {
            InfoType::OsVersion => "DISTRIB_RELEASE=",
            InfoType::Name => "DISTRIB_ID=",
        };
        for line in buf.lines() {
            if let Some(stripped) = line.strip_prefix(info_str) {
                return Some(stripped.replace('"', ""));
            }
        }
        None
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
