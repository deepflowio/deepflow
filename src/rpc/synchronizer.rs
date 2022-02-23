use std::convert::TryInto;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use log::{debug, info, warn};
use parking_lot::{Mutex, RwLock, RwLockUpgradableReadGuard};
use sysinfo::{System, SystemExt};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tokio::time;

use crate::config::RuntimeConfig;
use crate::proto::trident;
use crate::rpc::session::Session;
use crate::utils::{
    self,
    net::is_unicast_link_local,
    stats::{Countable, Counter},
};

const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_secs(10);
const RPC_RETRY_INTERVAL: Duration = Duration::from_secs(60);

pub struct StaticConfig {
    revision: String,
    boot_time: SystemTime,

    tap_mode: trident::TapMode,
    vtap_group_id_request: String,
    kubernetes_cluster_id: String,
    ctrl_mac: String,
    ctrl_ip: String,

    env: RuntimeEnvironment,
}

#[derive(Default)]
pub struct Config {
    proxy_ip: String,
}

#[derive(Default)]
pub struct Status {
    hostname: String,

    time_diff: i64,

    config_accepted: bool,
    synced: bool,
    new_revision: Option<String>,

    version_platform_data: u64,
    version_acls: u64,
    version_groups: u64,
}

pub struct Synchronizer {
    static_config: Arc<StaticConfig>,
    config: Arc<RwLock<Config>>,
    status: Arc<RwLock<Status>>,

    sync_interval: Duration,

    session: Arc<Session>,

    running: Arc<AtomicBool>,

    // threads
    rt: Runtime,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl Synchronizer {
    pub fn new(
        session: Arc<Session>,
        revision: String,
        ctrl_ip: String,
        ctrl_mac: String,
        vtap_group_id_request: String,
        kubernetes_cluster_id: String,
    ) -> Synchronizer {
        Synchronizer {
            static_config: Arc::new(StaticConfig {
                revision,
                boot_time: SystemTime::now(),
                tap_mode: trident::TapMode::Local,
                vtap_group_id_request,
                kubernetes_cluster_id,
                ctrl_mac,
                ctrl_ip,
                env: RuntimeEnvironment::new(),
            }),
            config: Arc::new(RwLock::new(Config::default())),
            status: Arc::new(RwLock::new(Status::default())),
            sync_interval: DEFAULT_SYNC_INTERVAL,
            session,
            running: Arc::new(AtomicBool::new(false)),
            rt: Runtime::new().unwrap(),
            threads: Mutex::new(Vec::new()),
        }
    }

    fn generate_sync_request(
        static_config: &Arc<StaticConfig>,
        status: &Arc<RwLock<Status>>,
    ) -> trident::SyncRequest {
        let status = status.read();

        let boot_time = static_config
            .boot_time
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let boot_time = (boot_time as i64 + status.time_diff) / 1_000_000_000;

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

        trident::SyncRequest {
            boot_time: Some(boot_time as u32),
            config_accepted: Some(status.config_accepted),
            version_platform_data: Some(status.version_platform_data),
            version_acls: Some(status.version_acls),
            version_groups: Some(status.version_groups),
            state: Some(trident::State::Running.into()),
            revision: Some(static_config.revision.clone()),
            exception: None, // TBD
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
            // FIXME @xiangwang 后续增加配置文件处理业务逻辑
            local_config_file: None,
        }
    }

    fn parse_upgrade(
        resp: &trident::SyncResponse,
        static_config: &Arc<StaticConfig>,
        status: &Arc<RwLock<Status>>,
    ) {
        match &resp.revision {
            Some(revision) if revision != &static_config.revision => {
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

    fn on_config_change(_config: &RuntimeConfig) {
        todo!()
    }

    fn on_response(
        remote: &str,
        mut resp: trident::SyncResponse,
        static_config: &Arc<StaticConfig>,
        status: &Arc<RwLock<Status>>,
    ) {
        // TODO: reset escape timer
        // TODO: 把cleaner UpdatePcapDataRetention挪到别的地方
        Self::parse_upgrade(&resp, static_config, status);

        match resp.status() {
            trident::Status::Failed => warn!(
                "trisolaris (ip: {}) responded with {:?}",
                remote,
                trident::Status::Failed
            ),
            trident::Status::Heartbeat => return,
            _ => (),
        }

        let config = resp.config.take();
        if config.is_none() {
            warn!("invalid response from {} without config", remote);
            return;
        }
        let config = config.unwrap();
        let runtime_config = (&config).try_into();
        if let Err(e) = runtime_config {
            warn!(
                "invalid response from {} with invalid config: {}",
                remote, e
            );
            return;
        }
        let runtime_config = runtime_config.unwrap();
        Self::on_config_change(&runtime_config);

        // TODO: update platform, flow acls, groups, bridge forward
        // TODO: check trisolaris
        // TODO: segments
        // TODO: modify platform
        // TODO: trigger listener
    }

    fn run_triggered_session(&self) {
        let session = self.session.clone();
        let static_config = self.static_config.clone();
        let status = self.status.clone();
        let running = self.running.clone();
        self.threads.lock().push(self.rt.spawn(async move {
            while running.load(Ordering::SeqCst) {
                session.update_current_server().await;
                let client = session.get_client();
                if client.is_none() {
                    info!("rpc trigger not running, client not connected");
                    time::sleep(Duration::new(1, 0)).await;
                    continue;
                }
                let mut client =
                    trident::synchronizer_client::SynchronizerClient::new(client.unwrap());
                let version = session.get_version();
                let response = client
                    .push(Synchronizer::generate_sync_request(&static_config, &status))
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
                        &static_config,
                        &status,
                    );
                }
            }
        }));
    }

    fn run(&self) {
        let session = self.session.clone();
        let static_config = self.static_config.clone();
        let _config = self.config.clone();
        let status = self.status.clone();
        let sync_interval = self.sync_interval;
        let running = self.running.clone();
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
                        static_config.ctrl_ip,
                        static_config.ctrl_mac,
                        status.hostname,
                    )
                }

                let changed = session.update_current_server().await;
                let request = Synchronizer::generate_sync_request(&static_config, &status);
                debug!("grpc sync request: {:?}", request);

                if client.is_none() || version != session.get_version() {
                    let inner_client = session.get_client();
                    if inner_client.is_none() {
                        info!("grpc sync client not connected");
                        time::sleep(Duration::new(1, 0)).await;
                        continue;
                    }
                    client = Some(trident::synchronizer_client::SynchronizerClient::new(
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
                    &static_config,
                    &status,
                );
                if status.read().new_revision.is_some() {
                    // TODO: upgrade
                }

                time::sleep(sync_interval).await;
            }
        }));
    }

    pub fn start(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }
        self.run_triggered_session();
        self.run();
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

impl Countable for Synchronizer {
    fn get_counters(&self) -> Vec<Counter> {
        vec![]
    }

    fn closed(&self) -> bool {
        !self.running.load(Ordering::SeqCst)
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

#[derive(Debug)]
struct RuntimeEnvironment {
    cpu_num: u32,
    memory_size: u64,

    arch: String,
    os: String,

    kernel_version: String,
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
