use std::collections::HashMap;
use std::convert::TryInto;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{self, Arc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use log::{debug, info, warn};
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

use crate::common::policy::{Cidr, IpGroupData, PeerConnection};
use crate::common::{FlowAclListener, PlatformData as VInterface};
use crate::common::{NORMAL_EXIT_WITH_RESTART, TEMP_STATIC_CONFIG_FILENAME};
use crate::config::{self, RuntimeConfig};
use crate::dispatcher::DispatcherListener;
use crate::exception::ExceptionHandler;
use crate::policy::PolicySetter;
use crate::proto::common::TridentType;
use crate::proto::trident::{self as tp, Exception, LocalConfigFile, TapMode};
use crate::rpc::session::Session;
use crate::trident::{self, TridentState};
use crate::utils::{
    self,
    environment::{is_tt_pod, is_tt_process},
    net::{is_unicast_link_local, MacAddr},
};

const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_secs(10);
const RPC_RETRY_INTERVAL: Duration = Duration::from_secs(60);
const NANOS_IN_SECOND: i64 = Duration::from_secs(1).as_nanos() as i64;
const SECOND: Duration = Duration::from_secs(1);

pub struct StaticConfig {
    pub revision: String,
    pub boot_time: SystemTime,

    pub tap_mode: tp::TapMode,
    pub vtap_group_id_request: String,
    pub kubernetes_cluster_id: String,
    pub ctrl_mac: String,
    pub ctrl_ip: String,
    pub controller_ip: String,
    pub analyzer_ip: String,

    pub env: RuntimeEnvironment,
}

impl Default for StaticConfig {
    fn default() -> Self {
        Self {
            revision: Default::default(),
            boot_time: SystemTime::now(),
            tap_mode: Default::default(),
            vtap_group_id_request: Default::default(),
            kubernetes_cluster_id: Default::default(),
            ctrl_ip: Default::default(),
            ctrl_mac: Default::default(),
            controller_ip: Default::default(),
            analyzer_ip: Default::default(),
            env: Default::default(),
        }
    }
}

#[derive(Default)]
pub struct Config {
    proxy_ip: String,
}

#[derive(Default)]
pub struct Status {
    pub hostname: String,

    pub time_diff: i64,

    pub config_accepted: bool,
    pub synced: bool,
    pub new_revision: Option<String>,

    pub proxy_ip: String,
    pub sync_interval: Duration,
    pub ntp_enabled: bool,

    // GRPC数据
    pub version_platform_data: u64,
    pub version_acls: u64,
    pub version_groups: u64,

    pub interfaces: Vec<Arc<VInterface>>,
    pub peers: Vec<Arc<PeerConnection>>,
    pub cidrs: Vec<Arc<Cidr>>,
    pub ip_groups: Vec<Arc<IpGroupData>>,
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

    fn update_flow_acl(&mut self, version: u64) {
        info!(
            "Update FlowAcls version {} to {}.",
            self.version_acls, version
        );

        self.version_acls = version;

        // TODO: add acl
    }

    fn get_platform_data(&mut self, resp: &tp::SyncResponse) -> bool {
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
                return true;
            }
        }
        return false;
    }

    fn modify_platform(
        &mut self,
        tap_mode: TapMode,
        macs: &Vec<MacAddr>,
        config: &RuntimeConfig,
    ) -> Vec<VInterface> {
        let mut black_list = Vec::new();
        if tap_mode == TapMode::Analyzer {
            return black_list;
        }
        let mut local_mac_map = HashMap::new();
        for mac in macs {
            let _ = local_mac_map.insert(u64::from(*mac), true);
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

            // vm为k8s node场景，k8s node流量由k8s内的采集器来采集，不在这里采集避免采集重复的流量
            if viface.skip_tap_interface
                && is_tt_process(config.trident_type)
                && viface.region_id == region_id
            {
                black_list.push(viface.clone());
            }
            if let Some(v) = local_mac_map.get(&viface.mac) {
                viface.is_local = *v;
            }
            vinterfaces.push(Arc::new(viface));
        }

        self.interfaces = vinterfaces;
        // TODO：bridge fdb
        return black_list;
    }

    fn get_flow_acls(&mut self, resp: &tp::SyncResponse) -> bool {
        let version = resp.version_platform_data.unwrap_or(0);
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
            if acls.is_ok() {
                // TODO: acl parse
                self.update_flow_acl(version);
                return true;
            }
        }
        return false;
    }

    fn get_ip_groups(&mut self, resp: &tp::SyncResponse) -> bool {
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
                return true;
            }
        }
        return false;
    }

    fn trigger_flow_acl(&self, trident_type: TridentType, listener: &mut Box<dyn FlowAclListener>) {
        listener.flow_acl_change(
            trident_type,
            &self.ip_groups,
            &self.interfaces,
            &self.peers,
            &self.cidrs,
        );
    }
}

pub struct Synchronizer {
    pub static_config: Arc<StaticConfig>,
    config: Arc<RwLock<Config>>,
    pub status: Arc<RwLock<Status>>,

    trident_state: TridentState,

    session: Arc<Session>,
    dispatcher_listener: Arc<Mutex<Option<DispatcherListener>>>,
    // 策略模块和NPB带宽检测会用到
    flow_acl_listener: Arc<sync::Mutex<Vec<Box<dyn FlowAclListener>>>>,
    exception_handler: ExceptionHandler,

    running: Arc<AtomicBool>,

    // threads
    rt: Runtime,
    threads: Mutex<Vec<JoinHandle<()>>>,

    max_memory: Arc<AtomicU64>,
    ntp_diff: Arc<AtomicI64>,

    // 本地配置文件
    pub local_config: Arc<LocalStaticConfig>,
}

pub struct LocalStaticConfig {
    pub local_config_str: String,
    pub revision: String,
    pub only_revison: AtomicBool,
    pub static_config_path: PathBuf,
}

impl Synchronizer {
    pub fn new(
        session: Arc<Session>,
        trident_state: TridentState,
        revision: String,
        ctrl_ip: String,
        ctrl_mac: String,
        controller_ip: String,
        analyzer_ip: String,
        vtap_group_id_request: String,
        kubernetes_cluster_id: String,
        policy_setter: PolicySetter,
        exception_handler: ExceptionHandler,
        static_config_path: PathBuf,
    ) -> Synchronizer {
        let local_config_str = fs::read_to_string(static_config_path.as_path()).unwrap_or_default();

        let mut static_config_md5_hasher = Md5::new();
        static_config_md5_hasher.update(local_config_str.as_bytes());
        let static_config_revision = static_config_md5_hasher
            .finalize_reset()
            .into_iter()
            .map(|c| format!("{:02x}", c))
            .collect::<Vec<_>>()
            .join("");

        let local_config = Arc::new(LocalStaticConfig {
            local_config_str,
            revision: static_config_revision,
            only_revison: AtomicBool::new(false),
            static_config_path,
        });

        Synchronizer {
            static_config: Arc::new(StaticConfig {
                revision,
                boot_time: SystemTime::now(),
                tap_mode: tp::TapMode::Local,
                vtap_group_id_request,
                kubernetes_cluster_id,
                ctrl_mac,
                ctrl_ip,
                controller_ip,
                analyzer_ip,
                env: RuntimeEnvironment::new(),
            }),
            trident_state,
            config: Default::default(),
            status: Default::default(),
            session,
            dispatcher_listener: Default::default(),
            running: Arc::new(AtomicBool::new(false)),
            rt: Runtime::new().unwrap(),
            threads: Default::default(),
            flow_acl_listener: Arc::new(sync::Mutex::new(vec![Box::new(policy_setter)])),
            exception_handler,

            max_memory: Default::default(),
            ntp_diff: Default::default(),
            local_config,
        }
    }

    pub fn add_flow_acl_listener(&mut self, module: Box<dyn FlowAclListener>) {
        let mut listeners = self.flow_acl_listener.lock().unwrap();
        for item in listeners.iter() {
            if item.id() == module.id() {
                return;
            }
        }
        listeners.push(module);
    }

    pub fn max_memory(&self) -> Arc<AtomicU64> {
        self.max_memory.clone()
    }

    pub fn generate_sync_request(
        static_config: &Arc<StaticConfig>,
        status: &Arc<RwLock<Status>>,
        time_diff: i64,
        exception_handler: &ExceptionHandler,
        local_config: LocalConfigFile,
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

        tp::SyncRequest {
            boot_time: Some(boot_time as u32),
            config_accepted: Some(status.config_accepted),
            version_platform_data: Some(status.version_platform_data),
            version_acls: Some(status.version_acls),
            version_groups: Some(status.version_groups),
            state: Some(tp::State::Running.into()),
            revision: Some(static_config.revision.clone()),
            exception: Some(exception_handler.take()),
            process_name: Some("trident".into()),
            ctrl_mac: Some(static_config.ctrl_mac.clone()),
            ctrl_ip: Some(static_config.ctrl_ip.clone()),
            tap_mode: Some(static_config.tap_mode.into()),
            host: Some(status.hostname.clone()),
            host_ips: utils::net::addr_list().map_or(vec![], |xs| {
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

            // not interested
            communication_vtaps: vec![],
            tsdb_report_info: None,
            local_config_file: Some(local_config),
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
            Some(revision) if revision != "" && revision != &static_config.revision => {
                if let Some(url) = &resp.self_update_url {
                    if url.trim().to_lowercase() != "grpc" {
                        warn!("error upgrade method, onlly support grpc: {}", url);
                        return;
                    }
                    info!(
                        "trigger upgrade as revision update from {} to {}",
                        &static_config.revision, revision
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
    ) -> (Vec<tp::Segment>, Vec<MacAddr>) {
        let segments = if tap_mode == tp::TapMode::Analyzer {
            resp.remote_segments.clone()
        } else {
            resp.local_segments.clone()
        };

        if segments.len() == 0 && tap_mode != tp::TapMode::Local {
            warn!("Segment is empty, in {:?} mode.", tap_mode);
        }
        let mut macs = Vec::new();
        for segment in &segments {
            for mac_str in &segment.mac {
                let mac = MacAddr::from_str(mac_str.as_str());
                if mac.is_err() {
                    warn!(
                        "Malformed VM mac {}, response rejected: {}",
                        mac_str,
                        mac.unwrap_err()
                    );
                    continue;
                }
                macs.push(mac.unwrap());
            }
        }
        return (segments, macs);
    }

    fn on_response(
        remote: &str,
        mut resp: tp::SyncResponse,
        trident_state: &TridentState,
        static_config: &Arc<StaticConfig>,
        status: &Arc<RwLock<Status>>,
        dispatcher_listener: &Arc<Mutex<Option<DispatcherListener>>>,
        flow_acl_listener: &Arc<sync::Mutex<Vec<Box<dyn FlowAclListener>>>>,
        max_memory: &Arc<AtomicU64>,
        exception_handler: &ExceptionHandler,
        escape_tx: &UnboundedSender<Duration>,
        local_config: &LocalStaticConfig,
    ) {
        // TODO: 把cleaner UpdatePcapDataRetention挪到别的地方
        Self::parse_upgrade(&resp, static_config, status);

        match resp.status() {
            tp::Status::Failed => warn!(
                "trisolaris (ip: {}) responded with {:?}",
                remote,
                tp::Status::Failed
            ),
            tp::Status::Heartbeat => return,
            _ => (),
        }

        let config = resp.config.take();
        if config.is_none() {
            warn!("invalid response from {} without config", remote);
            return;
        }
        let new_config = config.clone();
        let runtime_config: Result<RuntimeConfig, _> = config.unwrap().try_into();
        if let Err(e) = runtime_config {
            warn!(
                "invalid response from {} with invalid config: {}",
                remote, e
            );
            exception_handler.set(Exception::InvalidConfiguration);
            return;
        }
        let mut runtime_config = runtime_config.unwrap();
        if static_config.analyzer_ip != "" {
            // 配置文件配置analyzer-ip后，会使用配置文件中的controller-ips和analyzer-ip替换配置器下发的proxy-controller-ip和analyzer-ip
            runtime_config.proxy_controller_ip = static_config.controller_ip.clone();
            runtime_config.analyzer_ip = static_config.analyzer_ip.clone();
        }

        let _ = escape_tx.send(runtime_config.max_escape);

        max_memory.store(runtime_config.max_memory, Ordering::Relaxed);

        let mut dispatcher_listener = dispatcher_listener.lock();
        if let Some(listener) = (*dispatcher_listener).as_mut() {
            listener.on_config_change(&runtime_config);
        }

        let mut blacklist = vec![];
        let (_segments, macs) = Self::parse_segment(static_config.tap_mode, &resp);

        let mut status = status.write();
        status.proxy_ip = runtime_config.proxy_controller_ip.clone();
        status.sync_interval = runtime_config.sync_interval;
        status.ntp_enabled = runtime_config.ntp_enabled;
        let updated_platform = status.get_platform_data(&resp);
        if updated_platform {
            blacklist = status.modify_platform(static_config.tap_mode, &macs, &runtime_config);
        }
        let mut updated = status.get_ip_groups(&resp) || updated_platform;
        updated = status.get_flow_acls(&resp) || updated;
        if updated {
            // 更新策略相关
            let last = SystemTime::now();
            info!("Grpc version ip-groups: {}, interfaces, peer-connections and cidrs: {}, flow-acls: {}",
            status.version_groups, status.version_platform_data, status.version_acls);
            let policy_error = false;
            for listener in flow_acl_listener.lock().unwrap().iter_mut() {
                // TODO: error handling
                status.trigger_flow_acl(runtime_config.trident_type, listener);
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
                0,
            );
        }

        // TODO: bridge forward
        // TODO: check trisolaris
        // TODO: segments
        // TODO: modify platform
        match resp.local_config_file {
            Some(remote_local_config) => {
                if !remote_local_config.revision().is_empty() {
                    if let Err(e) = Self::update_local_config(
                        runtime_config.trident_type,
                        local_config,
                        remote_local_config,
                    ) {
                        warn!("update local config file failed, {}", e);
                        exception_handler.set(Exception::InvalidLocalConfigFile);
                    }
                }
            }
            // 当控制器删除采集器的时候local_config_file为空，此时需要重传本地配置
            None => local_config.only_revison.store(false, Ordering::Relaxed),
        }

        let (trident_state, cvar) = &**trident_state;
        if !runtime_config.enabled {
            *trident_state.lock().unwrap() = trident::State::Disabled;
        } else {
            *trident_state.lock().unwrap() =
                trident::State::ConfigChanged((runtime_config, new_config.unwrap(), blacklist));
        }
        cvar.notify_one();
    }

    fn run_triggered_session(&self, escape_tx: UnboundedSender<Duration>) {
        let session = self.session.clone();
        let trident_state = self.trident_state.clone();
        let static_config = self.static_config.clone();
        let status = self.status.clone();
        let running = self.running.clone();
        let dispatcher_listener = self.dispatcher_listener.clone();
        let max_memory = self.max_memory.clone();
        let flow_acl_listener = self.flow_acl_listener.clone();
        let exception_handler = self.exception_handler.clone();
        let ntp_diff = self.ntp_diff.clone();
        let local_config = self.local_config.clone();
        self.threads.lock().push(self.rt.spawn(async move {
            while running.load(Ordering::SeqCst) {
                session.update_current_server().await;
                let client = session.get_client();
                if client.is_none() {
                    info!("rpc trigger not running, client not connected");
                    time::sleep(Duration::new(1, 0)).await;
                    continue;
                }
                let mut client = tp::synchronizer_client::SynchronizerClient::new(client.unwrap());
                let version = session.get_version();

                let current_local_config = if local_config.only_revison.load(Ordering::Relaxed) {
                    LocalConfigFile {
                        local_config: None,
                        revision: Some(local_config.revision.clone()),
                    }
                } else {
                    LocalConfigFile {
                        local_config: Some(local_config.local_config_str.clone()),
                        revision: Some(local_config.revision.clone()),
                    }
                };
                let response = client
                    .push(Synchronizer::generate_sync_request(
                        &static_config,
                        &status,
                        ntp_diff.load(Ordering::Relaxed),
                        &exception_handler,
                        current_local_config,
                    ))
                    .await;
                if let Err(m) = response {
                    warn!("rpc error {:?}", m);
                    time::sleep(RPC_RETRY_INTERVAL).await;
                    continue;
                }
                let mut stream = response.unwrap().into_inner();
                while running.load(Ordering::SeqCst) {
                    let message = stream.message().await;
                    if session.get_version() != version {
                        info!("grpc server changed");
                        break;
                    }
                    if let Err(m) = message {
                        warn!("rpc error {:?}", m);
                        break;
                    }
                    let message = message.unwrap();
                    if message.is_none() {
                        debug!("end of stream");
                        break;
                    }
                    let message = message.unwrap();

                    debug!("received realtime policy successfully");
                    if !status.read().synced {
                        // 如果没有同步过（trident重启），trisolaris下发的数据仅有版本号，此时应由trident主动请求
                        continue;
                    }
                    Self::on_response(
                        &session.get_current_server(),
                        message,
                        &trident_state,
                        &static_config,
                        &status,
                        &dispatcher_listener,
                        &flow_acl_listener,
                        &max_memory,
                        &exception_handler,
                        &escape_tx,
                        &local_config,
                    );
                }
            }
        }));
    }

    fn run_escape_timer(&self) -> UnboundedSender<Duration> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let trident_state = self.trident_state.clone();
        let running = self.running.clone();
        self.rt.spawn(async move {
            // default escape time is 1h
            let mut escape_time = Duration::from_secs(3600);
            while running.load(Ordering::SeqCst) {
                match time::timeout(escape_time, rx.recv()).await {
                    Ok(Some(t)) => escape_time = t,
                    // channel closed
                    Ok(None) => return,
                    Err(_) => {
                        let (ts, cvar) = &*trident_state;
                        *ts.lock().unwrap() = trident::State::Disabled;
                        cvar.notify_one();
                        warn!("metaflow-agent restart, as max escape time expired");
                        // 与控制器失联的时间超过设置的逃逸时间，这里直接重启主要有两个原因：
                        // 1. 如果仅是停用系统无法回收全部的内存资源
                        // 2. 控制器地址可能是通过域明解析的，如果域明解析发生变更需要重启来触发重新解析
                        const NORMAL_EXIT_WITH_RESTART: i32 = 3;
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

    fn run_ntp_sync(&self) {
        let static_config = self.static_config.clone();
        let session = self.session.clone();
        let status = self.status.clone();
        let running = self.running.clone();
        let ntp_diff = self.ntp_diff.clone();
        self.rt.spawn(async move {
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

                let inner_client = session.get_client();
                if inner_client.is_none() {
                    info!("grpc sync client not connected");
                    time::sleep(Duration::new(1, 0)).await;
                    continue;
                }
                let mut client =
                    tp::synchronizer_client::SynchronizerClient::new(inner_client.unwrap());

                let mut ntp_msg = NtpPacket::new();
                // To ensure privacy and prevent spoofing, try to use a random 64-bit
                // value for the TransmitTime. Keep track of when the messsage was
                // actually transmitted.
                ntp_msg.ts_xmit = rand::thread_rng().next_u64();
                let send_time = SystemTime::now();

                let response = client
                    .query(tp::NtpRequest {
                        ctrl_ip: Some(static_config.ctrl_ip.clone()),
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

    fn run(&self, escape_tx: UnboundedSender<Duration>) {
        let session = self.session.clone();
        let trident_state = self.trident_state.clone();
        let static_config = self.static_config.clone();
        let _config = self.config.clone();
        let status = self.status.clone();
        let mut sync_interval = DEFAULT_SYNC_INTERVAL;
        let running = self.running.clone();
        let dispatcher_listener = self.dispatcher_listener.clone();
        let flow_acl_listener = self.flow_acl_listener.clone();
        let max_memory = self.max_memory.clone();
        let exception_handler = self.exception_handler.clone();
        let ntp_diff = self.ntp_diff.clone();
        let local_config = self.local_config.clone();
        self.threads.lock().push(self.rt.spawn(async move {
            let mut client = None;
            let version = session.get_version();
            while running.load(Ordering::SeqCst) {
                match hostname::get() {
                    Ok(hostname) => {
                        if let Ok(s) = hostname.into_string() {
                            let r = status.upgradable_read();
                            if s.ne(&r.hostname) {
                                info!("hostname changed from \"{}\" to \"{}\"", r.hostname, s);
                                RwLockUpgradableReadGuard::upgrade(r).hostname = s;
                            }
                        }
                    }
                    Err(e) => warn!("refresh hostname failed: {}", e),
                }
                if session.get_request_failed() {
                    let status = status.read();
                    info!(
                        "TapMode: {:?}, CtrlMac: {}, CtrlIp: {}, Hostname: {}",
                        static_config.tap_mode,
                        static_config.ctrl_mac,
                        static_config.ctrl_ip,
                        status.hostname,
                    )
                }

                let changed = session.update_current_server().await;

                let current_local_config = if local_config.only_revison.load(Ordering::Relaxed) {
                    LocalConfigFile {
                        local_config: None,
                        revision: Some(local_config.revision.clone()),
                    }
                } else {
                    LocalConfigFile {
                        local_config: Some(local_config.local_config_str.clone()),
                        revision: Some(local_config.revision.clone()),
                    }
                };

                let request = Synchronizer::generate_sync_request(
                    &static_config,
                    &status,
                    ntp_diff.load(Ordering::Relaxed),
                    &exception_handler,
                    current_local_config,
                );
                debug!("grpc sync request: {:?}", request);

                if client.is_none() || version != session.get_version() {
                    let inner_client = session.get_client();
                    if inner_client.is_none() {
                        session.set_request_failed(true);
                        info!("grpc sync client not connected");
                        time::sleep(Duration::new(1, 0)).await;
                        continue;
                    }
                    client = Some(tp::synchronizer_client::SynchronizerClient::new(
                        inner_client.unwrap(),
                    ));
                }
                let now = Instant::now();
                let response = client.as_mut().unwrap().sync(request).await;
                if let Err(m) = response {
                    warn!(
                        "grpc sync error, server {} unavailable, status-code {}, message: \"{}\"",
                        session.get_current_server(),
                        m.code(),
                        m.message()
                    );
                    session.set_request_failed(true);
                    time::sleep(RPC_RETRY_INTERVAL).await;
                    continue;
                }

                debug!("grpc sync took {:?}", now.elapsed());
                session.set_request_failed(false);

                if changed {
                    info!(
                        "grpc sync new rpc server {} available",
                        session.get_current_server()
                    );
                }

                Self::on_response(
                    &session.get_current_server(),
                    response.unwrap().into_inner(),
                    &trident_state,
                    &static_config,
                    &status,
                    &dispatcher_listener,
                    &flow_acl_listener,
                    &max_memory,
                    &exception_handler,
                    &escape_tx,
                    &local_config,
                );
                let (new_revision, proxy_ip, new_sync_interval) = {
                    let status = status.read();
                    (
                        status.new_revision.clone(),
                        status.proxy_ip.clone(),
                        status.sync_interval,
                    )
                };
                if new_revision.is_some() {
                    // TODO: upgrade
                }
                match session.get_proxy_server() {
                    Some(ip) if &ip == &proxy_ip => (),
                    _ => {
                        info!("proxy_controller_ip update to {}", proxy_ip);
                        session.set_proxy_server(proxy_ip);
                    }
                }
                if sync_interval != new_sync_interval {
                    sync_interval = new_sync_interval;
                    info!("sync interval set to {:?}", sync_interval);
                }

                time::sleep(sync_interval).await;
            }
        }));
    }

    fn update_local_config(
        trident_type: TridentType,
        local_config: &LocalStaticConfig,
        remote_local_config: LocalConfigFile,
    ) -> Result<(), io::Error> {
        // 容器/Exsi/Dedicate采集器只支持读取配置，不支持修改
        match trident_type {
            TridentType::TtHostPod
            | TridentType::TtVmPod
            | TridentType::TtVm
            | TridentType::TtDedicatedPhysicalMachine => {
                debug!(
                    "current trident-type {:?} do not support config file update",
                    trident_type
                );
                return Ok(());
            }
            _ => (),
        }

        if local_config.revision == remote_local_config.revision() {
            local_config.only_revison.swap(true, Ordering::Relaxed);
            debug!(
                "don't need update local static config, static config revision ({}) unchanged",
                local_config.revision
            );
            return Ok(());
        }

        info!("local static config revision ({}) is different from remote static config revision ({})", local_config.revision, remote_local_config.revision());

        // 检查metaflow-server下发的配置，校验通过则进行写入临时文件
        let static_config = config::Config::load(remote_local_config.local_config())?;
        let temp_filename =
            local_config.static_config_path
            .parent()
            .ok_or(io::Error::new(io::ErrorKind::Other, "can't create temporary static config file because static config path is root directory"))?
            .join(TEMP_STATIC_CONFIG_FILENAME);
        {
            debug!(
                "Create temporary static config file: {}",
                temp_filename.display()
            );
            fs::write(temp_filename.as_path(), remote_local_config.local_config())?;
        }
        // 读取临时文件，再次进行校验，校验通过写入static_config_path
        let temp_static_config =
            config::Config::load(fs::read_to_string(temp_filename.as_path())?)?;
        if static_config != temp_static_config {
            debug!("temporary static config file has unexpected change");
        }

        fs::write(
            local_config.static_config_path.as_path(),
            remote_local_config.local_config(),
        )?;

        fs::remove_file(temp_filename)?;

        info!("metaflow-agent local static config changed, restart metaflow-agent....");

        thread::sleep(SECOND);
        process::exit(NORMAL_EXIT_WITH_RESTART);
    }

    pub fn start(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }
        self.run_ntp_sync();
        let esc_tx = self.run_escape_timer();
        self.run_triggered_session(esc_tx.clone());
        self.run(esc_tx);
    }

    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return;
        }
        self.rt.block_on(async move {
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
    analyzer_ip: String,
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
        sys.refresh_memory();
        RuntimeEnvironment {
            cpu_num: sys.physical_core_count().unwrap_or_default() as u32,
            // 这里乘1000，因为库作者思路清奇换算成了10基底的KB
            memory_size: sys.total_memory() * 1000,
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
