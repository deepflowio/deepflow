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

use std::env;
use std::fmt;
use std::fs;
use std::mem;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::{
    atomic::{AtomicBool, AtomicI64, Ordering},
    Arc, Condvar, Mutex, Weak,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{anyhow, Result};
use arc_swap::access::Access;
use dns_lookup::lookup_host;
use flexi_logger::{colored_opt_format, Age, Cleanup, Criterion, FileSpec, Logger, Naming};
use log::{debug, info, warn};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::broadcast;

#[cfg(target_os = "linux")]
use crate::platform::{
    kubernetes::{GenericPoller, Poller, SidecarPoller},
    prometheus::targets::TargetsWatcher,
    ApiWatcher, LibvirtXmlExtractor,
};
use crate::{
    collector::{
        flow_aggr::FlowAggrThread, quadruple_generator::QuadrupleGeneratorThread, CollectorThread,
        MetricsType,
    },
    collector::{
        l7_quadruple_generator::L7QuadrupleGeneratorThread, Collector, L7Collector,
        L7CollectorThread,
    },
    common::{
        enums::TapType,
        flow::L7Stats,
        proc_event::BoxedProcEvents,
        tagged_flow::{BoxedTaggedFlow, TaggedFlow},
        tap_types::TapTyper,
        FeatureFlags, DEFAULT_LOG_RETENTION, DEFAULT_TRIDENT_CONF_FILE, FREE_SPACE_REQUIREMENT,
    },
    config::PcapConfig,
    config::{
        handler::{ConfigHandler, DispatcherConfig, ModuleConfig},
        Config, ConfigError, RuntimeConfig, YamlConfig,
    },
    debug::{ConstructDebugCtx, Debugger},
    dispatcher::{
        self, recv_engine::bpf, BpfOptions, Dispatcher, DispatcherBuilder, DispatcherListener,
    },
    exception::ExceptionHandler,
    flow_generator::{
        protocol_logs::BoxAppProtoLogsData, protocol_logs::SessionAggregator, PacketSequenceParser,
    },
    handler::{NpbBuilder, PacketHandlerBuilder},
    integration_collector::{
        BoxedPrometheusExtra, MetricServer, OpenTelemetry, OpenTelemetryCompressed, Profile,
        TelegrafMetric,
    },
    metric::document::BoxedDocument,
    monitor::Monitor,
    platform::synchronizer::Synchronizer as PlatformSynchronizer,
    policy::{Policy, PolicyGetter, PolicySetter},
    rpc::{Session, Synchronizer, DEFAULT_TIMEOUT},
    sender::{npb_sender::NpbArpTable, uniform_sender::UniformSenderThread},
    utils::{
        cgroups::{is_kernel_available_for_cgroups, Cgroups},
        command::get_hostname,
        environment::{
            check, controller_ip_check, free_memory_check, free_space_checker, get_ctrl_ip_and_mac,
            get_env, kernel_check, running_in_container, tap_interface_check,
            trident_process_check,
        },
        guard::Guard,
        logger::{LogLevelWriter, LogWriterAdapter, RemoteLogWriter},
        npb_bandwidth_watcher::NpbBandwidthWatcher,
        stats::{self, ArcBatch, Countable, RefCountable, StatsOption},
    },
};
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::{
    ebpf_dispatcher::EbpfCollector,
    platform::SocketSynchronizer,
    utils::{environment::core_file_check, lru::Lru},
};

use packet_sequence_block::BoxedPacketSequenceBlock;
use pcap_assembler::{BoxedPcapBatch, PcapAssembler};

#[cfg(target_os = "linux")]
use public::netns;
use public::{
    buffer::BatchedBox,
    debug::QueueDebugger,
    packet::MiniPacket,
    proto::trident::{self, Exception, SocketType, TapMode},
    queue::{self, DebugSender},
    utils::net::{get_route_src_ip, Link, MacAddr},
    LeakyBucket,
};

const MINUTE: Duration = Duration::from_secs(60);
const COMMON_DELAY: u32 = 5;

#[derive(Debug, Default)]
pub struct ChangedConfig {
    pub runtime_config: RuntimeConfig,
    pub blacklist: Vec<u64>,
    pub vm_mac_addrs: Vec<MacAddr>,
    pub gateway_vmac_addrs: Vec<MacAddr>,
    pub tap_types: Vec<trident::TapType>,
}

#[derive(Clone, Default, Copy, PartialEq, Eq, Debug)]
pub enum RunningMode {
    #[default]
    Managed,
    Standalone,
}

#[derive(Debug)]
pub enum State {
    Running,
    ConfigChanged(ChangedConfig),
    Terminated,
    Disabled(Option<RuntimeConfig>), // Requires runtime config to update platform config
}

impl State {
    fn unwrap_config(self) -> ChangedConfig {
        match self {
            Self::ConfigChanged(c) => c,
            _ => panic!("{:?} not config type", &self),
        }
    }
}

pub struct VersionInfo {
    pub name: &'static str,
    pub branch: &'static str,
    pub commit_id: &'static str,
    pub rev_count: &'static str,
    pub compiler: &'static str,
    pub compile_time: &'static str,

    pub revision: &'static str,
}

impl fmt::Display for VersionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}-{}
Name: {}
Branch: {}
CommitId: {}
RevCount: {}
Compiler: {}
CompileTime: {}",
            self.rev_count,
            self.commit_id,
            match self.name {
                "deepflow-agent-ce" => "deepflow-agent community edition",
                "deepflow-agent-ee" => "deepflow-agent enterprise edition",
                _ => panic!("{:?} unknown deepflow-agent edition", &self.name),
            },
            self.branch,
            self.commit_id,
            self.rev_count,
            self.compiler,
            self.compile_time
        )
    }
}

pub type TridentState = Arc<(Mutex<State>, Condvar)>;

#[derive(Clone, Debug)]
pub struct AgentId {
    pub ip: IpAddr,
    pub mac: MacAddr,
    pub team_id: String,
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.team_id.is_empty() {
            write!(f, "{}/{}", self.ip, self.mac)
        } else {
            write!(f, "{}/{}/{}", self.ip, self.mac, self.team_id)
        }
    }
}

pub struct Trident {
    state: TridentState,
    handle: Option<JoinHandle<()>>,
    #[cfg(target_os = "linux")]
    pid_file: Option<crate::utils::pid_file::PidFile>,
}

impl Trident {
    pub fn start<P: AsRef<Path>>(
        config_path: P,
        version_info: &'static VersionInfo,
        agent_mode: RunningMode,
        sidecar_mode: bool,
    ) -> Result<Trident> {
        let config = match agent_mode {
            RunningMode::Managed => {
                match Config::load_from_file(config_path.as_ref()) {
                    Ok(conf) => conf,
                    Err(e) => {
                        if let ConfigError::YamlConfigInvalid(_) = e {
                            // try to load config file from trident.yaml to support upgrading from trident
                            if let Ok(conf) = Config::load_from_file(DEFAULT_TRIDENT_CONF_FILE) {
                                conf
                            } else {
                                // return the original error instead of loading trident conf
                                return Err(e.into());
                            }
                        } else {
                            return Err(e.into());
                        }
                    }
                }
            }
            RunningMode::Standalone => {
                let rc = RuntimeConfig::load_from_file(config_path.as_ref())?;
                let mut conf = Config::default();
                conf.controller_ips = vec!["127.0.0.1".into()];
                conf.log_file = rc.yaml_config.log_file;
                conf.agent_mode = agent_mode;
                conf
            }
        };
        #[cfg(target_os = "linux")]
        let pid_file = if !config.pid_file.is_empty() {
            match crate::utils::pid_file::PidFile::open(&config.pid_file) {
                Ok(file) => Some(file),
                Err(e) => return Err(anyhow!("Create pid file {} failed: {}", config.pid_file, e)),
            }
        } else {
            None
        };

        let controller_ip: IpAddr = config.controller_ips[0].parse()?;
        let (ctrl_ip, ctrl_mac) = match get_ctrl_ip_and_mac(&controller_ip) {
            Ok(tuple) => tuple,
            Err(e) => return Err(anyhow!("get ctrl ip and mac failed: {}", e)),
        };
        let mut config_handler = ConfigHandler::new(config, ctrl_ip, ctrl_mac);

        let config = &config_handler.static_config;
        let hostname = match config.override_os_hostname.as_ref() {
            Some(name) => name.to_owned(),
            None => get_hostname().unwrap_or_default(),
        };

        let ntp_diff = Arc::new(AtomicI64::new(0));
        let stats_collector = Arc::new(stats::Collector::new(&hostname, ntp_diff.clone()));
        let exception_handler = ExceptionHandler::default();

        let base_name = Path::new(&env::args().next().unwrap())
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let remote_log_writer = RemoteLogWriter::new(
            base_name,
            hostname.clone(),
            config_handler.log(),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            ntp_diff.clone(),
        );

        let (log_level_writer, log_level_counter) = LogLevelWriter::new();
        let logger = Logger::try_with_env_or_str("info")
            .unwrap()
            .format(colored_opt_format);
        // check log folder permission
        let base_path = Path::new(&config.log_file).parent().unwrap();
        let write_to_file = if base_path.exists() {
            base_path
                .metadata()
                .ok()
                .map(|meta| !meta.permissions().readonly())
                .unwrap_or(false)
        } else {
            fs::create_dir_all(base_path).is_ok()
        };
        let logger = if write_to_file {
            logger
                .log_to_file_and_writer(
                    FileSpec::try_from(&config.log_file)?,
                    Box::new(LogWriterAdapter::new(vec![
                        Box::new(remote_log_writer),
                        Box::new(log_level_writer),
                    ])),
                )
                .rotate(
                    Criterion::Age(Age::Day),
                    Naming::Timestamps,
                    Cleanup::KeepLogFiles(DEFAULT_LOG_RETENTION as usize),
                )
                .create_symlink(&config.log_file)
                .append()
        } else {
            eprintln!(
                "Log file path '{}' access denied, logs will not be written to file",
                &config.log_file
            );
            logger.log_to_writer(Box::new(LogWriterAdapter::new(vec![
                Box::new(remote_log_writer),
                Box::new(log_level_writer),
            ])))
        };

        #[cfg(any(target_os = "linux", target_os = "android"))]
        let logger = if nix::unistd::getppid().as_raw() != 1 {
            logger.duplicate_to_stderr(flexi_logger::Duplicate::All)
        } else {
            logger
        };
        let logger_handle = logger.start()?;
        config_handler.set_logger_handle(logger_handle);

        let config = &config_handler.static_config;
        // Use controller ip to replace analyzer ip before obtaining configuration
        if matches!(config.agent_mode, RunningMode::Managed) {
            stats_collector.start();
        }

        stats_collector.register_countable(
            "log_counter",
            stats::Countable::Owned(Box::new(log_level_counter)),
            Default::default(),
        );

        info!("static_config {:#?}", config);
        let state = Arc::new((Mutex::new(State::Running), Condvar::new()));
        let state_thread = state.clone();
        let config_path = match agent_mode {
            RunningMode::Managed => None,
            RunningMode::Standalone => Some(config_path.as_ref().to_path_buf()),
        };
        let handle = Some(thread::spawn(move || {
            if let Err(e) = Self::run(
                state_thread,
                ctrl_ip,
                ctrl_mac,
                config_handler,
                version_info,
                stats_collector,
                exception_handler,
                config_path,
                sidecar_mode,
                ntp_diff,
            ) {
                warn!(
                    "Launching deepflow-agent failed: {}, deepflow-agent restart...",
                    e
                );
                crate::utils::notify_exit(1);
            }
        }));

        Ok(Trident {
            state,
            handle,
            #[cfg(target_os = "linux")]
            pid_file,
        })
    }

    fn run(
        state: TridentState,
        ctrl_ip: IpAddr,
        ctrl_mac: MacAddr,
        mut config_handler: ConfigHandler,
        version_info: &'static VersionInfo,
        stats_collector: Arc<stats::Collector>,
        exception_handler: ExceptionHandler,
        config_path: Option<PathBuf>,
        sidecar_mode: bool,
        ntp_diff: Arc<AtomicI64>,
    ) -> Result<()> {
        info!("==================== Launching DeepFlow-Agent ====================");
        info!("Environment variables: {:?}", get_env());

        if running_in_container() {
            info!(
                "use K8S_NODE_IP_FOR_DEEPFLOW env ip as destination_ip({})",
                ctrl_ip
            );
            warn!("When running in a container, the cpu and memory limits notified by deepflow-server will be ignored, please make sure to use K8s or docker for resource limits.");
        }

        #[cfg(target_os = "linux")]
        let agent_id = if sidecar_mode {
            AgentId {
                ip: ctrl_ip.clone(),
                mac: ctrl_mac,
                team_id: config_handler.static_config.team_id.clone(),
            }
        } else {
            // use host ip/mac as agent id if not in sidecar mode
            if let Err(e) = netns::open_named_and_setns(&netns::NsFile::Root) {
                return Err(anyhow!("agent must have CAP_SYS_ADMIN to run without 'hostNetwork: true'. setns error: {}", e));
            }
            let controller_ip: IpAddr = config_handler.static_config.controller_ips[0].parse()?;
            let (ip, mac) = match get_ctrl_ip_and_mac(&controller_ip) {
                Ok(tuple) => tuple,
                Err(e) => return Err(anyhow!("get ctrl ip and mac failed with error: {}", e)),
            };
            if let Err(e) = netns::reset_netns() {
                return Err(anyhow!("reset netns error: {}", e));
            };
            AgentId {
                ip,
                mac,
                team_id: config_handler.static_config.team_id.clone(),
            }
        };
        #[cfg(any(target_os = "windows", target_os = "android"))]
        let agent_id = AgentId {
            ip: ctrl_ip.clone(),
            mac: ctrl_mac,
            team_id: config_handler.static_config.team_id.clone(),
        };

        info!(
            "agent {} running in {:?} mode, ctrl_ip {} ctrl_mac {}",
            agent_id, config_handler.static_config.agent_mode, ctrl_ip, ctrl_mac
        );

        let session = Arc::new(Session::new(
            config_handler.static_config.controller_port,
            config_handler.static_config.controller_tls_port,
            DEFAULT_TIMEOUT,
            config_handler
                .static_config
                .controller_cert_file_prefix
                .clone(),
            config_handler.static_config.controller_ips.clone(),
            exception_handler.clone(),
            &stats_collector,
        ));

        let runtime = Arc::new(
            Builder::new_multi_thread()
                .worker_threads(
                    config_handler
                        .static_config
                        .async_worker_thread_number
                        .into(),
                )
                .enable_all()
                .build()
                .unwrap(),
        );

        if matches!(
            config_handler.static_config.agent_mode,
            RunningMode::Managed
        ) && running_in_container()
            && config_handler
                .static_config
                .kubernetes_cluster_id
                .is_empty()
        {
            config_handler.static_config.kubernetes_cluster_id =
                Config::get_k8s_cluster_id(&runtime, &session, &config_handler.static_config)
                    .unwrap_or_default();
        }

        let (agent_id_tx, _) = broadcast::channel::<AgentId>(1);
        let agent_id_tx = Arc::new(agent_id_tx);

        let synchronizer = Arc::new(Synchronizer::new(
            runtime.clone(),
            session.clone(),
            state.clone(),
            version_info,
            agent_id,
            config_handler.static_config.controller_ips[0].clone(),
            config_handler.static_config.vtap_group_id_request.clone(),
            config_handler.static_config.kubernetes_cluster_id.clone(),
            config_handler.static_config.kubernetes_cluster_name.clone(),
            config_handler.static_config.override_os_hostname.clone(),
            config_handler.static_config.agent_unique_identifier,
            exception_handler.clone(),
            config_handler.static_config.agent_mode,
            config_path,
            agent_id_tx.clone(),
            ntp_diff,
        ));
        stats_collector.register_countable(
            "ntp",
            stats::Countable::Owned(Box::new(synchronizer.ntp_counter())),
            Default::default(),
        );
        synchronizer.start();

        let mut domain_name_listener = DomainNameListener::new(
            stats_collector.clone(),
            session.clone(),
            config_handler.static_config.controller_domain_name.clone(),
            config_handler.static_config.controller_ips.clone(),
            config_handler.static_config.team_id.clone(),
            sidecar_mode,
            agent_id_tx,
        );
        domain_name_listener.start();

        let mut cgroup_mount_path = "".to_string();
        let mut is_cgroup_v2 = false;
        let mut cgroups_controller = None;
        if running_in_container() {
            info!("don't initialize cgroups controller, because agent is running in container");
        } else if !is_kernel_available_for_cgroups() {
            // fixme: Linux after kernel version 2.6.24 can use cgroups
            info!("don't initialize cgroups controller, because kernel version < 3 or agent is in Windows");
        } else {
            match Cgroups::new(process::id() as u64, config_handler.environment()) {
                Ok(cg_controller) => {
                    cg_controller.start();
                    cgroup_mount_path = cg_controller.get_mount_path();
                    is_cgroup_v2 = cg_controller.is_v2();
                    cgroups_controller = Some(cg_controller);
                }
                Err(e) => {
                    warn!("initialize cgroups controller failed: {}, resource utilization will be checked regularly to prevent resource usage from exceeding the limit.", e);
                    exception_handler.set(Exception::CgroupsConfigError);
                }
            }
        }

        let log_dir = Path::new(config_handler.static_config.log_file.as_str());
        let log_dir = log_dir.parent().unwrap().to_str().unwrap();
        let guard = match Guard::new(
            config_handler.environment(),
            log_dir.to_string(),
            config_handler.candidate_config.yaml_config.guard_interval,
            exception_handler.clone(),
            cgroup_mount_path,
            is_cgroup_v2,
            config_handler
                .candidate_config
                .yaml_config
                .memory_trim_disabled,
        ) {
            Ok(g) => g,
            Err(e) => {
                warn!("guard create failed");
                return Err(anyhow!(e));
            }
        };
        guard.start();

        let monitor = Monitor::new(
            stats_collector.clone(),
            log_dir.to_string(),
            config_handler.environment(),
        )?;
        monitor.start();

        #[cfg(target_os = "linux")]
        let (libvirt_xml_extractor, platform_synchronizer, sidecar_poller, api_watcher) = {
            let ext = Arc::new(LibvirtXmlExtractor::new());
            let syn = Arc::new(PlatformSynchronizer::new(
                runtime.clone(),
                config_handler.platform(),
                config_handler.static_config.override_os_hostname.clone(),
                synchronizer.agent_id.clone(),
                session.clone(),
                ext.clone(),
                exception_handler.clone(),
            ));
            ext.start();
            let poller = if sidecar_mode {
                let p = match SidecarPoller::new(
                    config_handler.static_config.controller_ips[0].parse()?,
                ) {
                    Ok(p) => p,
                    Err(e) => return Err(anyhow!(e)),
                };
                let p: Arc<GenericPoller> = Arc::new(p.into());
                syn.set_kubernetes_poller(p.clone());
                Some(p)
            } else {
                None
            };
            let watcher = Arc::new(ApiWatcher::new(
                runtime.clone(),
                config_handler.platform(),
                synchronizer.agent_id.clone(),
                session.clone(),
                exception_handler.clone(),
                stats_collector.clone(),
            ));
            (ext, syn, poller, watcher)
        };
        #[cfg(any(target_os = "windows", target_os = "android"))]
        let platform_synchronizer = Arc::new(PlatformSynchronizer::new(
            runtime.clone(),
            config_handler.platform(),
            config_handler.static_config.override_os_hostname.clone(),
            synchronizer.agent_id.clone(),
            session.clone(),
            exception_handler.clone(),
        ));
        if matches!(
            config_handler.static_config.agent_mode,
            RunningMode::Managed
        ) {
            platform_synchronizer.start();
        }

        let (state, cond) = &*state;
        let mut state_guard = state.lock().unwrap();
        let mut components: Option<Components> = None;
        let mut yaml_conf: Option<YamlConfig> = None;

        loop {
            match &mut *state_guard {
                State::Running => {
                    state_guard = cond.wait(state_guard).unwrap();
                    #[cfg(target_os = "linux")]
                    if config_handler
                        .candidate_config
                        .platform
                        .kubernetes_api_enabled
                    {
                        api_watcher.start();
                    } else {
                        api_watcher.stop();
                    }
                    continue;
                }
                State::Terminated => {
                    if let Some(mut c) = components {
                        c.stop();
                        guard.stop();
                        monitor.stop();
                        domain_name_listener.stop();
                        platform_synchronizer.stop();
                        #[cfg(target_os = "linux")]
                        {
                            api_watcher.stop();
                            libvirt_xml_extractor.stop();
                        }
                        if let Some(cg_controller) = cgroups_controller {
                            if let Err(e) = cg_controller.stop() {
                                info!("stop cgroups controller failed, {:?}", e);
                            }
                        }
                    }
                    return Ok(());
                }
                State::Disabled(config) => {
                    if let Some(ref mut c) = components {
                        c.stop();
                    }
                    if let Some(c) = config.take() {
                        let agent_id = synchronizer.agent_id.read().clone();
                        let callbacks = config_handler.on_config(
                            c,
                            &exception_handler,
                            None,
                            #[cfg(target_os = "linux")]
                            &api_watcher,
                            &runtime,
                            &session,
                            &agent_id,
                        );

                        #[cfg(target_os = "linux")]
                        if config_handler
                            .candidate_config
                            .platform
                            .kubernetes_api_enabled
                        {
                            api_watcher.start();
                        } else {
                            api_watcher.stop();
                        }

                        if let Some(Components::Agent(c)) = components.as_mut() {
                            for callback in callbacks {
                                callback(&config_handler, c);
                            }

                            for d in c.dispatcher_components.iter_mut() {
                                d.dispatcher_listener
                                    .on_config_change(&config_handler.candidate_config.dispatcher);
                            }
                        } else {
                            stats_collector
                                .set_hostname(config_handler.candidate_config.stats.host.clone());
                            stats_collector
                                .set_min_interval(config_handler.candidate_config.stats.interval);
                        }
                    }
                    state_guard = cond.wait(state_guard).unwrap();
                    continue;
                }
                _ => (),
            }
            let mut new_state = State::Running;
            mem::swap(&mut new_state, &mut *state_guard);
            mem::drop(state_guard);

            let ChangedConfig {
                runtime_config,
                blacklist,
                vm_mac_addrs,
                gateway_vmac_addrs,
                tap_types,
            } = new_state.unwrap_config();

            if let Some(old_yaml) = yaml_conf {
                if old_yaml != runtime_config.yaml_config {
                    if let Some(mut c) = components.take() {
                        c.stop();
                    }
                    // EbpfCollector does not support recreation because it calls bpf_tracer_init, which can only be called once in a process
                    // Work around this problem by exiting and restart trident
                    let info = "yaml_config updated, deepflow-agent restart...";
                    warn!("{}", info);
                    thread::sleep(Duration::from_secs(1));
                    return Err(anyhow!(info));
                }
            }
            yaml_conf = Some(runtime_config.yaml_config.clone());
            let agent_id = synchronizer.agent_id.read().clone();
            match components.as_mut() {
                None => {
                    let callbacks = config_handler.on_config(
                        runtime_config,
                        &exception_handler,
                        None,
                        #[cfg(target_os = "linux")]
                        &api_watcher,
                        &runtime,
                        &session,
                        &agent_id,
                    );

                    #[cfg(target_os = "linux")]
                    if config_handler
                        .candidate_config
                        .platform
                        .kubernetes_api_enabled
                    {
                        api_watcher.start();
                    } else {
                        api_watcher.stop();
                    }

                    let mut comp = Components::new(
                        &version_info,
                        &config_handler,
                        stats_collector.clone(),
                        &session,
                        &synchronizer,
                        exception_handler.clone(),
                        #[cfg(target_os = "linux")]
                        libvirt_xml_extractor.clone(),
                        platform_synchronizer.clone(),
                        #[cfg(target_os = "linux")]
                        sidecar_poller.clone(),
                        #[cfg(target_os = "linux")]
                        api_watcher.clone(),
                        vm_mac_addrs,
                        gateway_vmac_addrs,
                        config_handler.static_config.agent_mode,
                        runtime.clone(),
                    )?;

                    comp.start();

                    if let Components::Agent(components) = &mut comp {
                        if config_handler.candidate_config.dispatcher.tap_mode == TapMode::Analyzer
                        {
                            parse_tap_type(components, tap_types);
                        }

                        for callback in callbacks {
                            callback(&config_handler, components);
                        }
                    }

                    components.replace(comp);
                }
                Some(Components::Agent(components)) => {
                    let callbacks: Vec<fn(&ConfigHandler, &mut AgentComponents)> = config_handler
                        .on_config(
                            runtime_config,
                            &exception_handler,
                            Some(components),
                            #[cfg(target_os = "linux")]
                            &api_watcher,
                            &runtime,
                            &session,
                            &agent_id,
                        );

                    #[cfg(target_os = "linux")]
                    if config_handler
                        .candidate_config
                        .platform
                        .kubernetes_api_enabled
                    {
                        api_watcher.start();
                    } else {
                        api_watcher.stop();
                    }

                    components.config = config_handler.candidate_config.clone();
                    components.start();

                    component_on_config_change(
                        &config_handler,
                        components,
                        blacklist,
                        vm_mac_addrs,
                        gateway_vmac_addrs,
                        tap_types,
                        &synchronizer,
                        #[cfg(target_os = "linux")]
                        libvirt_xml_extractor.clone(),
                    );
                    for callback in callbacks {
                        callback(&config_handler, components);
                    }

                    for d in components.dispatcher_components.iter_mut() {
                        d.dispatcher_listener
                            .on_config_change(&config_handler.candidate_config.dispatcher);
                    }
                }
                _ => {
                    config_handler.on_config(
                        runtime_config,
                        &exception_handler,
                        None,
                        #[cfg(target_os = "linux")]
                        &api_watcher,
                        &runtime,
                        &session,
                        &agent_id,
                    );

                    #[cfg(target_os = "linux")]
                    if config_handler
                        .candidate_config
                        .platform
                        .kubernetes_api_enabled
                    {
                        api_watcher.start();
                    } else {
                        api_watcher.stop();
                    }
                }
            }
            state_guard = state.lock().unwrap();
        }
    }

    pub fn stop(&mut self) {
        info!("Gracefully stopping");
        let (state, cond) = &*self.state;

        let mut state_guard = state.lock().unwrap();
        *state_guard = State::Terminated;
        cond.notify_one();
        mem::drop(state_guard);
        self.handle.take().unwrap().join().unwrap();
        info!("Gracefully stopped");
    }
}

fn get_listener_links(
    conf: &DispatcherConfig,
    #[cfg(target_os = "linux")] netns: &netns::NsFile,
) -> Vec<Link> {
    #[cfg(target_os = "linux")]
    match netns::links_by_name_regex_in_netns(&conf.tap_interface_regex, netns) {
        Err(e) => {
            warn!("get interfaces by name regex in {:?} failed: {}", netns, e);
            vec![]
        }
        Ok(links) => {
            if links.is_empty() {
                info!(
                    "tap-interface-regex({}) do not match any interface in {:?}",
                    conf.tap_interface_regex, netns,
                );
            }
            debug!("tap interfaces in namespace {:?}: {:?}", netns, links);
            links
        }
    }

    #[cfg(any(target_os = "windows", target_os = "android"))]
    match public::utils::net::links_by_name_regex(&conf.tap_interface_regex) {
        Err(e) => {
            warn!("get interfaces by name regex failed: {}", e);
            vec![]
        }
        Ok(links) => {
            if links.is_empty() {
                warn!(
                    "tap-interface-regex({}) do not match any interface, in local mode",
                    conf.tap_interface_regex
                );
            }
            debug!("tap interfaces: {:?}", links);
            links
        }
    }
}

fn component_on_config_change(
    config_handler: &ConfigHandler,
    components: &mut AgentComponents,
    blacklist: Vec<u64>,
    vm_mac_addrs: Vec<MacAddr>,
    gateway_vmac_addrs: Vec<MacAddr>,
    tap_types: Vec<trident::TapType>,
    synchronizer: &Arc<Synchronizer>,
    #[cfg(target_os = "linux")] libvirt_xml_extractor: Arc<LibvirtXmlExtractor>,
) {
    let conf = &config_handler.candidate_config.dispatcher;
    match conf.tap_mode {
        TapMode::Local => {
            let if_mac_source = conf.if_mac_source;
            for d in components.dispatcher_components.iter() {
                let interfaces = get_listener_links(
                    conf,
                    #[cfg(target_os = "linux")]
                    d.dispatcher_listener.netns(),
                );
                d.dispatcher_listener.on_tap_interface_change(
                    &interfaces,
                    if_mac_source,
                    conf.trident_type,
                    &blacklist,
                );
                d.dispatcher_listener
                    .on_vm_change(&vm_mac_addrs, &gateway_vmac_addrs);
            }
        }
        TapMode::Mirror | TapMode::Analyzer => {
            // Obtain the currently configured network interfaces
            let mut current_interfaces = get_listener_links(
                conf,
                #[cfg(target_os = "linux")]
                &netns::NsFile::Root,
            );
            current_interfaces.sort();

            if current_interfaces == components.tap_interfaces {
                return;
            }

            // By comparing current_interfaces and components.tap_interfaces, we can determine which
            // dispatcher_components should be closed and which dispatcher_components should be built
            let interfaces_to_build: Vec<_> = current_interfaces
                .iter()
                .filter(|i| !components.tap_interfaces.contains(i))
                .cloned()
                .collect();

            components.dispatcher_components.retain_mut(|d| {
                let retain = current_interfaces.contains(&d.src_link);
                if !retain {
                    d.stop();
                }
                retain
            });

            let mut id = components.last_dispatcher_component_id;
            components
                .policy_setter
                .reset_queue_size(id + interfaces_to_build.len() + 1);
            let debugger_queue = components.debugger.clone_queue();
            for i in interfaces_to_build {
                id += 1;
                match build_dispatchers(
                    id,
                    vec![i],
                    components.stats_collector.clone(),
                    config_handler,
                    debugger_queue.clone(),
                    components.is_ce_version,
                    synchronizer,
                    components.npb_bps_limit.clone(),
                    components.npb_arp_table.clone(),
                    components.rx_leaky_bucket.clone(),
                    components.policy_getter,
                    components.exception_handler.clone(),
                    0,
                    components.bpf_options.clone(),
                    components.packet_sequence_uniform_output.clone(),
                    components.proto_log_sender.clone(),
                    components.pcap_batch_sender.clone(),
                    components.tap_typer.clone(),
                    vm_mac_addrs.clone(),
                    gateway_vmac_addrs.clone(),
                    components.toa_info_sender.clone(),
                    components.l4_flow_aggr_sender.clone(),
                    components.metrics_sender.clone(),
                    #[cfg(target_os = "linux")]
                    netns::NsFile::Root,
                    #[cfg(target_os = "linux")]
                    components.kubernetes_poller.clone(),
                    #[cfg(target_os = "linux")]
                    libvirt_xml_extractor.clone(),
                ) {
                    Ok(mut d) => {
                        d.start();
                        components.dispatcher_components.push(d);
                    }
                    Err(e) => {
                        warn!("build dispatcher_component failed: {}", e);
                        thread::sleep(Duration::from_secs(1));
                        crate::utils::notify_exit(1);
                    }
                }
            }
            components.last_dispatcher_component_id = id;
            if conf.tap_mode == TapMode::Analyzer {
                parse_tap_type(components, tap_types);
            }
            components.tap_interfaces = current_interfaces;
        }

        _ => {}
    }
}

fn parse_tap_type(components: &mut AgentComponents, tap_types: Vec<trident::TapType>) {
    let mut updated = false;
    if components.cur_tap_types.len() != tap_types.len() {
        updated = true;
    } else {
        for i in 0..tap_types.len() {
            if components.cur_tap_types[i] != tap_types[i] {
                updated = true;
                break;
            }
        }
    }
    if updated {
        components.tap_typer.on_tap_types_change(tap_types.clone());
        components.cur_tap_types.clear();
        components.cur_tap_types.clone_from(&tap_types);
    }
}

pub struct DomainNameListener {
    stats_collector: Arc<stats::Collector>,
    session: Arc<Session>,
    ips: Vec<String>,
    domain_names: Vec<String>,
    team_id: String,

    sidecar_mode: bool,

    thread_handler: Option<JoinHandle<()>>,
    stopped: Arc<AtomicBool>,
    agent_id_tx: Arc<broadcast::Sender<AgentId>>,
}

impl DomainNameListener {
    const INTERVAL: Duration = Duration::from_secs(5);

    fn new(
        stats_collector: Arc<stats::Collector>,
        session: Arc<Session>,
        domain_names: Vec<String>,
        ips: Vec<String>,
        team_id: String,
        sidecar_mode: bool,
        agent_id_tx: Arc<broadcast::Sender<AgentId>>,
    ) -> DomainNameListener {
        Self {
            stats_collector,
            session,
            domain_names,
            ips,
            team_id,
            sidecar_mode,
            thread_handler: None,
            stopped: Arc::new(AtomicBool::new(false)),
            agent_id_tx,
        }
    }

    fn start(&mut self) {
        if self.thread_handler.is_some() {
            return;
        }
        self.stopped.store(false, Ordering::Relaxed);
        self.run();
    }

    fn stop(&mut self) {
        if self.thread_handler.is_none() {
            return;
        }
        self.stopped.store(true, Ordering::Relaxed);
        if let Some(handler) = self.thread_handler.take() {
            let _ = handler.join();
        }
    }

    fn run(&mut self) {
        if self.domain_names.len() == 0 {
            return;
        }

        let mut ips = self.ips.clone();
        let domain_names = self.domain_names.clone();
        let team_id = self.team_id.clone();
        let stopped = self.stopped.clone();
        let agent_id_tx = self.agent_id_tx.clone();
        let session = self.session.clone();

        #[cfg(target_os = "linux")]
        let sidecar_mode = self.sidecar_mode;

        info!(
            "Resolve controller domain name {} {}",
            domain_names[0], ips[0]
        );

        self.thread_handler = Some(
            thread::Builder::new()
                .name("domain-name-listener".to_owned())
                .spawn(move || {
                    while !stopped.swap(false, Ordering::Relaxed) {
                        thread::sleep(Self::INTERVAL);

                        let mut changed = false;
                        for i in 0..domain_names.len() {
                            let current = lookup_host(domain_names[i].as_str());
                            if current.is_err() {
                                continue;
                            }
                            let current = current.unwrap();

                            changed = current.iter().find(|&&x| x.to_string() == ips[i]).is_none();
                            if changed {
                                info!(
                                    "Domain name {} ip {} change to {}",
                                    domain_names[i], ips[i], current[0]
                                );
                                ips[i] = current[0].to_string();
                            }
                        }

                        if changed {
                            let (ctrl_ip, ctrl_mac) = match get_ctrl_ip_and_mac(&ips[0].parse().unwrap()) {
                                Ok(tuple) => tuple,
                                Err(e) => {
                                    warn!("get ctrl ip and mac failed with error: {}", e);
                                    crate::utils::notify_exit(1);
                                    thread::sleep(Duration::from_secs(1));
                                    continue;
                                }
                            };
                            info!(
                                "use K8S_NODE_IP_FOR_DEEPFLOW env ip as destination_ip({})",
                                ctrl_ip
                            );
                            #[cfg(target_os = "linux")]
                            let agent_id = if sidecar_mode {
                                AgentId { ip: ctrl_ip.clone(), mac: ctrl_mac, team_id: team_id.clone() }
                            } else {
                                // use host ip/mac as agent id if not in sidecar mode
                                if let Err(e) = netns::open_named_and_setns(&netns::NsFile::Root) {
                                    warn!("agent must have CAP_SYS_ADMIN to run without 'hostNetwork: true'.");
                                    warn!("setns error: {}", e);
                                    crate::utils::notify_exit(1);
                                    thread::sleep(Duration::from_secs(1));
                                    continue;
                                }
                                let (ip, mac) = match get_ctrl_ip_and_mac(&ips[0].parse().unwrap()) {
                                    Ok(tuple) => tuple,
                                    Err(e) => {
                                        warn!("get ctrl ip and mac failed with error: {}", e);
                                        crate::utils::notify_exit(1);
                                        thread::sleep(Duration::from_secs(1));
                                        continue;
                                    }
                                };
                                if let Err(e) = netns::reset_netns() {
                                    warn!("reset setns error: {}", e);
                                    crate::utils::notify_exit(1);
                                    thread::sleep(Duration::from_secs(1));
                                    continue;
                                }
                                AgentId { ip, mac, team_id: team_id.clone() }
                            };
                            #[cfg(any(target_os = "windows", target_os = "android"))]
                            let agent_id = AgentId { ip: ctrl_ip.clone(), mac: ctrl_mac, team_id: team_id.clone() };

                            session.reset_server_ip(ips.clone());
                            let _ = agent_id_tx.send(agent_id);
                        }
                    }
                })
                .unwrap(),
        );
    }
}

pub enum Components {
    Agent(AgentComponents),
    #[cfg(target_os = "linux")]
    Watcher(WatcherComponents),
    Other,
}

#[cfg(target_os = "linux")]
pub struct WatcherComponents {
    pub running: AtomicBool,
    tap_mode: TapMode,
    agent_mode: RunningMode,
    runtime: Arc<Runtime>,
}

#[cfg(target_os = "linux")]
impl WatcherComponents {
    fn new(
        config_handler: &ConfigHandler,
        agent_mode: RunningMode,
        runtime: Arc<Runtime>,
    ) -> Result<Self> {
        let candidate_config = &config_handler.candidate_config;
        info!("With ONLY_WATCH_K8S_RESOURCE and IN_CONTAINER environment variables set, the agent will only watch K8s resource");
        Ok(WatcherComponents {
            running: AtomicBool::new(false),
            tap_mode: candidate_config.tap_mode,
            agent_mode,
            runtime,
        })
    }

    fn start(&mut self) {
        if self.running.swap(true, Ordering::Relaxed) {
            return;
        }
        info!("Started watcher components.");
    }

    fn stop(&mut self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            return;
        }
        info!("Stopped watcher components.")
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub struct EbpfDispatcherComponent {
    pub ebpf_collector: Box<EbpfCollector>,
    pub session_aggregator: SessionAggregator,
    pub collector: CollectorThread,
    pub l7_collector: L7CollectorThread,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl EbpfDispatcherComponent {
    pub fn start(&mut self) {
        self.session_aggregator.start();
        self.collector.start();
        self.l7_collector.start();
        self.ebpf_collector.start();
    }

    pub fn stop(&mut self) {
        self.session_aggregator.stop();
        self.collector.stop();
        self.l7_collector.stop();
        self.ebpf_collector.notify_stop();
    }
}

pub struct MetricsServerComponent {
    pub external_metrics_server: MetricServer,
    pub l7_collector: L7CollectorThread,
}

impl MetricsServerComponent {
    pub fn start(&mut self) {
        self.external_metrics_server.start();
        self.l7_collector.start();
    }

    pub fn stop(&mut self) {
        self.external_metrics_server.stop();
        self.l7_collector.stop();
    }
}

pub struct DispatcherComponent {
    pub id: usize,
    pub dispatcher: Dispatcher,
    pub dispatcher_listener: DispatcherListener,
    pub session_aggregator: SessionAggregator,
    pub collector: CollectorThread,
    pub l7_collector: L7CollectorThread,
    pub packet_sequence_parser: PacketSequenceParser,
    pub pcap_assembler: PcapAssembler,
    pub handler_builders: Arc<Mutex<Vec<PacketHandlerBuilder>>>,
    pub src_link: Link, // The original src_interface
}

impl DispatcherComponent {
    pub fn start(&mut self) {
        self.dispatcher.start();
        self.session_aggregator.start();
        self.collector.start();
        self.l7_collector.start();
        self.packet_sequence_parser.start();
        self.pcap_assembler.start();
        self.handler_builders
            .lock()
            .unwrap()
            .iter_mut()
            .for_each(|y| {
                y.start();
            });
    }
    pub fn stop(&mut self) {
        self.dispatcher.stop();
        self.session_aggregator.stop();
        self.collector.stop();
        self.l7_collector.stop();
        self.packet_sequence_parser.stop();
        self.pcap_assembler.stop();
        self.handler_builders
            .lock()
            .unwrap()
            .iter_mut()
            .for_each(|y| {
                y.stop();
            });
    }
}

pub struct AgentComponents {
    pub config: ModuleConfig,
    pub rx_leaky_bucket: Arc<LeakyBucket>,
    pub tap_typer: Arc<TapTyper>,
    pub cur_tap_types: Vec<trident::TapType>,
    pub dispatcher_components: Vec<DispatcherComponent>,
    pub l4_flow_uniform_sender: UniformSenderThread<BoxedTaggedFlow>,
    pub metrics_uniform_sender: UniformSenderThread<BoxedDocument>,
    pub l7_flow_uniform_sender: UniformSenderThread<BoxAppProtoLogsData>,
    pub stats_sender: UniformSenderThread<ArcBatch>,
    pub platform_synchronizer: Arc<PlatformSynchronizer>,
    #[cfg(target_os = "linux")]
    pub kubernetes_poller: Arc<GenericPoller>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub socket_synchronizer: SocketSynchronizer,
    #[cfg(target_os = "linux")]
    pub prometheus_targets_watcher: Arc<TargetsWatcher>,
    pub debugger: Debugger,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub ebpf_dispatcher_component: Option<EbpfDispatcherComponent>,
    pub running: AtomicBool,
    pub stats_collector: Arc<stats::Collector>,
    pub metrics_server_component: MetricsServerComponent,
    pub otel_uniform_sender: UniformSenderThread<OpenTelemetry>,
    pub prometheus_uniform_sender: UniformSenderThread<BoxedPrometheusExtra>,
    pub telegraf_uniform_sender: UniformSenderThread<TelegrafMetric>,
    pub profile_uniform_sender: UniformSenderThread<Profile>,
    pub packet_sequence_uniform_output: DebugSender<BoxedPacketSequenceBlock>, // Enterprise Edition Feature: packet-sequence
    pub packet_sequence_uniform_sender: UniformSenderThread<BoxedPacketSequenceBlock>, // Enterprise Edition Feature: packet-sequence
    pub proc_event_uniform_sender: UniformSenderThread<BoxedProcEvents>,
    pub exception_handler: ExceptionHandler,
    pub proto_log_sender: DebugSender<BoxAppProtoLogsData>,
    pub pcap_batch_sender: DebugSender<BoxedPcapBatch>,
    pub toa_info_sender: DebugSender<Box<(SocketAddr, SocketAddr)>>,
    pub l4_flow_aggr_sender: DebugSender<BoxedTaggedFlow>,
    pub metrics_sender: DebugSender<BoxedDocument>,
    pub npb_bps_limit: Arc<LeakyBucket>,
    pub compressed_otel_uniform_sender: UniformSenderThread<OpenTelemetryCompressed>,
    pub pcap_batch_uniform_sender: UniformSenderThread<BoxedPcapBatch>,
    pub policy_setter: PolicySetter,
    pub policy_getter: PolicyGetter,
    pub npb_bandwidth_watcher: Box<Arc<NpbBandwidthWatcher>>,
    pub npb_arp_table: Arc<NpbArpTable>,
    pub is_ce_version: bool, // Determine whether the current version is a ce version, CE-AGENT always set pcap-assembler disabled
    pub tap_interfaces: Vec<Link>,
    pub bpf_options: Arc<Mutex<BpfOptions>>,
    pub last_dispatcher_component_id: usize,

    max_memory: u64,
    tap_mode: TapMode,
    agent_mode: RunningMode,

    runtime: Arc<Runtime>,
}

impl AgentComponents {
    fn new_collector(
        id: usize,
        stats_collector: Arc<stats::Collector>,
        flow_receiver: queue::Receiver<Arc<BatchedBox<TaggedFlow>>>,
        toa_info_sender: DebugSender<Box<(SocketAddr, SocketAddr)>>,
        l4_flow_aggr_sender: Option<DebugSender<BoxedTaggedFlow>>,
        metrics_sender: DebugSender<BoxedDocument>,
        metrics_type: MetricsType,
        config_handler: &ConfigHandler,
        queue_debugger: &QueueDebugger,
        synchronizer: &Arc<Synchronizer>,
        agent_mode: RunningMode,
    ) -> CollectorThread {
        let yaml_config = &config_handler.candidate_config.yaml_config;

        let mut l4_flow_aggr_outer = None;
        let mut l4_log_sender_outer = None;
        if l4_flow_aggr_sender.is_some() {
            let (l4_log_sender, l4_log_receiver, counter) = queue::bounded_with_debug(
                yaml_config.flow.aggr_queue_size as usize,
                "2-second-flow-to-minute-aggrer",
                queue_debugger,
            );
            l4_log_sender_outer = Some(l4_log_sender);
            stats_collector.register_countable(
                "queue",
                Countable::Owned(Box::new(counter)),
                vec![
                    StatsOption::Tag("module", "2-second-flow-to-minute-aggrer".to_string()),
                    StatsOption::Tag("index", id.to_string()),
                ],
            );
            let (l4_flow_aggr, flow_aggr_counter) = FlowAggrThread::new(
                id,                                   // id
                l4_log_receiver,                      // input
                l4_flow_aggr_sender.unwrap().clone(), // output
                config_handler.collector(),
                synchronizer.ntp_diff(),
            );
            l4_flow_aggr_outer = Some(l4_flow_aggr);
            stats_collector.register_countable(
                "flow_aggr",
                Countable::Ref(Arc::downgrade(&flow_aggr_counter) as Weak<dyn RefCountable>),
                vec![StatsOption::Tag("index", id.to_string())],
            );
        }

        let (second_sender, second_receiver, counter) = queue::bounded_with_debug(
            yaml_config.quadruple_queue_size,
            "2-flow-with-meter-to-second-collector",
            queue_debugger,
        );
        stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag(
                    "module",
                    "2-flow-with-meter-to-second-collector".to_string(),
                ),
                StatsOption::Tag("index", id.to_string()),
            ],
        );
        let (minute_sender, minute_receiver, counter) = queue::bounded_with_debug(
            yaml_config.quadruple_queue_size,
            "2-flow-with-meter-to-minute-collector",
            queue_debugger,
        );
        stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag(
                    "module",
                    "2-flow-with-meter-to-minute-collector".to_string(),
                ),
                StatsOption::Tag("index", id.to_string()),
            ],
        );

        // FIXME: 应该让flowgenerator和dispatcher解耦，并提供Delay函数用于此处
        // QuadrupleGenerator的Delay组成部分：
        //   FlowGen中流统计数据固有的Delay：_FLOW_STAT_INTERVAL + packetDelay
        //   FlowGen中InjectFlushTicker的额外Delay：_TIME_SLOT_UNIT
        //   FlowGen中输出队列Flush的Delay：flushInterval
        //   FlowGen中其它处理流程可能产生的Delay: 5s
        let second_quadruple_tolerable_delay = (yaml_config.packet_delay.as_secs()
            + 1
            + yaml_config.flow.flush_interval.as_secs()
            + COMMON_DELAY as u64)
            + yaml_config.second_flow_extra_delay.as_secs();
        // minute QG window is also pushed forward by flow stat time,
        // therefore its delay should be 60 + second delay (including extra flow delay)
        let minute_quadruple_tolerable_delay = 60 + second_quadruple_tolerable_delay;

        let quadruple_generator = QuadrupleGeneratorThread::new(
            id,
            flow_receiver,
            second_sender,
            minute_sender,
            toa_info_sender,
            l4_log_sender_outer,
            (yaml_config.flow.hash_slots << 3) as usize, // connection_lru_capacity
            metrics_type,
            second_quadruple_tolerable_delay,
            minute_quadruple_tolerable_delay,
            1 << 18, // possible_host_size
            config_handler.collector(),
            synchronizer.ntp_diff(),
            stats_collector.clone(),
        );

        let (mut second_collector, mut minute_collector) = (None, None);
        if metrics_type.contains(MetricsType::SECOND) {
            second_collector = Some(Collector::new(
                id as u32,
                second_receiver,
                metrics_sender.clone(),
                MetricsType::SECOND,
                second_quadruple_tolerable_delay as u32 + COMMON_DELAY, // qg processing is delayed and requires the collector component to increase the window size
                &stats_collector,
                config_handler.collector(),
                synchronizer.ntp_diff(),
                agent_mode,
            ));
        }
        if metrics_type.contains(MetricsType::MINUTE) {
            minute_collector = Some(Collector::new(
                id as u32,
                minute_receiver,
                metrics_sender,
                MetricsType::MINUTE,
                minute_quadruple_tolerable_delay as u32 + COMMON_DELAY, // qg processing is delayed and requires the collector component to increase the window size
                &stats_collector,
                config_handler.collector(),
                synchronizer.ntp_diff(),
                agent_mode,
            ));
        }

        CollectorThread::new(
            quadruple_generator,
            l4_flow_aggr_outer,
            second_collector,
            minute_collector,
        )
    }

    fn new_l7_collector(
        id: usize,
        stats_collector: Arc<stats::Collector>,
        l7_stats_receiver: queue::Receiver<BatchedBox<L7Stats>>,
        metrics_sender: DebugSender<BoxedDocument>,
        metrics_type: MetricsType,
        config_handler: &ConfigHandler,
        queue_debugger: &QueueDebugger,
        synchronizer: &Arc<Synchronizer>,
        agent_mode: RunningMode,
    ) -> L7CollectorThread {
        let yaml_config = &config_handler.candidate_config.yaml_config;

        let (l7_second_sender, l7_second_receiver, counter) = queue::bounded_with_debug(
            yaml_config.quadruple_queue_size,
            "2-flow-with-meter-to-l7-second-collector",
            queue_debugger,
        );
        stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag(
                    "module",
                    "2-flow-with-meter-to-l7-second-collector".to_string(),
                ),
                StatsOption::Tag("index", id.to_string()),
            ],
        );
        let (l7_minute_sender, l7_minute_receiver, counter) = queue::bounded_with_debug(
            yaml_config.quadruple_queue_size,
            "2-flow-with-meter-to-l7-minute-collector",
            queue_debugger,
        );
        stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag(
                    "module",
                    "2-flow-with-meter-to-l7-minute-collector".to_string(),
                ),
                StatsOption::Tag("index", id.to_string()),
            ],
        );

        // FIXME: 应该让flowgenerator和dispatcher解耦，并提供Delay函数用于此处
        // QuadrupleGenerator的Delay组成部分：
        //   FlowGen中流统计数据固有的Delay：_FLOW_STAT_INTERVAL + packetDelay
        //   FlowGen中InjectFlushTicker的额外Delay：_TIME_SLOT_UNIT
        //   FlowGen中输出队列Flush的Delay：flushInterval
        //   FlowGen中其它处理流程可能产生的Delay: 5s
        let second_quadruple_tolerable_delay = (yaml_config.packet_delay.as_secs()
            + 1
            + yaml_config.flow.flush_interval.as_secs()
            + COMMON_DELAY as u64)
            + yaml_config.second_flow_extra_delay.as_secs();
        // minute QG window is also pushed forward by flow stat time,
        // therefore its delay should be 60 + second delay (including extra flow delay)
        let minute_quadruple_tolerable_delay = 60 + second_quadruple_tolerable_delay;

        let quadruple_generator = L7QuadrupleGeneratorThread::new(
            id,
            l7_stats_receiver,
            l7_second_sender,
            l7_minute_sender,
            metrics_type,
            second_quadruple_tolerable_delay,
            minute_quadruple_tolerable_delay,
            1 << 18, // possible_host_size
            config_handler.collector(),
            synchronizer.ntp_diff(),
            stats_collector.clone(),
        );

        let (mut second_collector, mut minute_collector) = (None, None);
        if metrics_type.contains(MetricsType::SECOND) {
            second_collector = Some(L7Collector::new(
                id as u32,
                l7_second_receiver,
                metrics_sender.clone(),
                MetricsType::SECOND,
                second_quadruple_tolerable_delay as u32 + COMMON_DELAY, // qg processing is delayed and requires the collector component to increase the window size
                &stats_collector,
                config_handler.collector(),
                synchronizer.ntp_diff(),
                agent_mode,
            ));
        }
        if metrics_type.contains(MetricsType::MINUTE) {
            minute_collector = Some(L7Collector::new(
                id as u32,
                l7_minute_receiver,
                metrics_sender,
                MetricsType::MINUTE,
                minute_quadruple_tolerable_delay as u32 + COMMON_DELAY, // qg processing is delayed and requires the collector component to increase the window size
                &stats_collector,
                config_handler.collector(),
                synchronizer.ntp_diff(),
                agent_mode,
            ));
        }

        L7CollectorThread::new(quadruple_generator, second_collector, minute_collector)
    }

    fn new(
        version_info: &VersionInfo,
        config_handler: &ConfigHandler,
        stats_collector: Arc<stats::Collector>,
        session: &Arc<Session>,
        synchronizer: &Arc<Synchronizer>,
        exception_handler: ExceptionHandler,
        #[cfg(target_os = "linux")] libvirt_xml_extractor: Arc<LibvirtXmlExtractor>,
        platform_synchronizer: Arc<PlatformSynchronizer>,
        #[cfg(target_os = "linux")] sidecar_poller: Option<Arc<GenericPoller>>,
        #[cfg(target_os = "linux")] api_watcher: Arc<ApiWatcher>,
        vm_mac_addrs: Vec<MacAddr>,
        gateway_vmac_addrs: Vec<MacAddr>,
        agent_mode: RunningMode,
        runtime: Arc<Runtime>,
    ) -> Result<Self> {
        let static_config = &config_handler.static_config;
        let candidate_config = &config_handler.candidate_config;
        let yaml_config = &candidate_config.yaml_config;
        let ctrl_ip = config_handler.ctrl_ip;
        let max_memory = config_handler.candidate_config.environment.max_memory;
        let process_threshold = config_handler
            .candidate_config
            .environment
            .process_threshold;
        let feature_flags = FeatureFlags::from(&yaml_config.feature_flags);

        if !yaml_config.src_interfaces.is_empty() {
            warn!("src_interfaces is not empty, but this has already been deprecated, instead, the tap_interface_regex should be set");
        }

        let mut stats_sender = UniformSenderThread::new(
            "stats",
            stats_collector.get_receiver(),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            true,
        );
        stats_sender.start();

        info!("Start check process...");
        trident_process_check(process_threshold);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if !yaml_config.check_core_file_disabled {
            info!("Start check core file...");
            core_file_check();
        }
        info!("Start check controller ip...");
        controller_ip_check(&static_config.controller_ips);
        info!("Start check free space...");
        check(free_space_checker(
            &static_config.log_file,
            FREE_SPACE_REQUIREMENT,
            exception_handler.clone(),
        ));

        #[cfg(target_os = "linux")]
        let mut interfaces_and_ns: Vec<(Vec<Link>, netns::NsFile)> = vec![];
        #[cfg(any(target_os = "windows", target_os = "android"))]
        let mut interfaces_and_ns: Vec<Vec<Link>> = vec![];

        #[cfg(target_os = "linux")]
        if candidate_config.dispatcher.extra_netns_regex != "" {
            if candidate_config.tap_mode == TapMode::Local {
                let re = regex::Regex::new(&candidate_config.dispatcher.extra_netns_regex).unwrap();
                let mut nss = netns::find_ns_files_by_regex(&re);
                nss.sort_unstable();
                for ns in nss.into_iter() {
                    interfaces_and_ns
                        .push((get_listener_links(&candidate_config.dispatcher, &ns), ns));
                }
            } else {
                log::error!("When the TapMode is not Local, it does not support extra_netns_regex, other modes only support interfaces under the root network namespace");
            }
        }

        #[cfg(target_os = "linux")]
        let local_dispatcher_count = if candidate_config.tap_mode == TapMode::Local
            && candidate_config.dispatcher.extra_netns_regex == ""
        {
            yaml_config.local_dispatcher_count
        } else {
            1
        };
        #[cfg(any(target_os = "windows", target_os = "android"))]
        let local_dispatcher_count = 1;

        if interfaces_and_ns.is_empty() {
            let links = get_listener_links(
                &candidate_config.dispatcher,
                #[cfg(target_os = "linux")]
                &netns::NsFile::Root,
            );
            if candidate_config.tap_mode != TapMode::Local {
                for l in links {
                    #[cfg(target_os = "linux")]
                    interfaces_and_ns.push((vec![l], netns::NsFile::Root));
                    #[cfg(any(target_os = "windows", target_os = "android"))]
                    interfaces_and_ns.push(vec![l]);
                }
            } else {
                for _ in 0..local_dispatcher_count {
                    #[cfg(target_os = "linux")]
                    interfaces_and_ns.push((links.clone(), netns::NsFile::Root));
                    #[cfg(any(target_os = "windows", target_os = "android"))]
                    interfaces_and_ns.push(links.clone());
                }
            }
        }

        match candidate_config.tap_mode {
            TapMode::Analyzer => {
                info!("Start check kernel...");
                kernel_check();
                info!("Start check tap interface...");
                #[cfg(target_os = "linux")]
                let tap_interfaces: Vec<_> = interfaces_and_ns
                    .iter()
                    .filter_map(|i| i.0.get(0).map(|l| l.name.clone()))
                    .collect();
                #[cfg(any(target_os = "windows", target_os = "android"))]
                let tap_interfaces: Vec<_> = interfaces_and_ns
                    .iter()
                    .filter_map(|i| i.get(0).map(|l| l.name.clone()))
                    .collect();

                tap_interface_check(&tap_interfaces);
            }
            _ => {
                // NPF服务检查
                // TODO: npf (only on windows)
                if candidate_config.tap_mode == TapMode::Mirror {
                    info!("Start check kernel...");
                    kernel_check();
                }
            }
        }

        info!("Agent run with feature-flags: {:?}.", feature_flags);
        // Currently, only loca-mode + ebpf collector is supported, and ebpf collector is not
        // applicable to fastpath, so the number of queues is 1
        // =================================================================================
        // 目前仅支持local-mode + ebpf-collector，ebpf-collector不适用fastpath, 所以队列数为1
        let (policy_setter, policy_getter) = Policy::new(
            1.max(if candidate_config.tap_mode != TapMode::Local {
                interfaces_and_ns.len()
            } else {
                1
            }),
            yaml_config.first_path_level as usize,
            yaml_config.fast_path_map_size,
            yaml_config.forward_capacity,
            yaml_config.fast_path_disabled,
        );
        synchronizer.add_flow_acl_listener(Box::new(policy_setter));
        policy_setter.set_memory_limit(max_memory);

        // TODO: collector enabled
        // TODO: packet handler builders

        #[cfg(target_os = "linux")]
        // sidecar poller is created before agent start to provide pod interface info for server
        let kubernetes_poller = sidecar_poller.unwrap_or_else(|| {
            let poller = Arc::new(GenericPoller::new(
                config_handler.platform(),
                config_handler
                    .candidate_config
                    .dispatcher
                    .extra_netns_regex
                    .clone(),
            ));
            platform_synchronizer.set_kubernetes_poller(poller.clone());
            poller
        });

        #[cfg(target_os = "linux")]
        let prometheus_targets_watcher = Arc::new(TargetsWatcher::new(
            runtime.clone(),
            config_handler.platform(),
            synchronizer.agent_id.clone(),
            session.clone(),
            exception_handler.clone(),
            stats_collector.clone(),
        ));

        let context = ConstructDebugCtx {
            runtime: runtime.clone(),
            #[cfg(target_os = "linux")]
            api_watcher: api_watcher.clone(),
            #[cfg(target_os = "linux")]
            poller: kubernetes_poller.clone(),
            session: session.clone(),
            static_config: synchronizer.static_config.clone(),
            agent_id: synchronizer.agent_id.clone(),
            status: synchronizer.status.clone(),
            config: config_handler.debug(),
            policy_setter,
        };
        let debugger = Debugger::new(context);
        let queue_debugger = debugger.clone_queue();

        #[cfg(any(target_os = "linux", target_os = "android"))]
        let (toa_sender, toa_recv, _) = queue::bounded_with_debug(
            yaml_config.toa_sender_queue_size,
            "1-socket-sync-toa-info-queue",
            &queue_debugger,
        );
        #[cfg(target_os = "windows")]
        let (toa_sender, _, _) = queue::bounded_with_debug(
            yaml_config.toa_sender_queue_size,
            "1-socket-sync-toa-info-queue",
            &queue_debugger,
        );
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let socket_synchronizer = SocketSynchronizer::new(
            runtime.clone(),
            config_handler.platform(),
            synchronizer.agent_id.clone(),
            Arc::new(Mutex::new(policy_getter)),
            policy_setter,
            session.clone(),
            toa_recv,
            Arc::new(Mutex::new(Lru::with_capacity(
                yaml_config.toa_lru_cache_size >> 5,
                yaml_config.toa_lru_cache_size,
            ))),
        );

        let rx_leaky_bucket = Arc::new(LeakyBucket::new(match candidate_config.tap_mode {
            TapMode::Analyzer => None,
            _ => Some(
                config_handler
                    .candidate_config
                    .dispatcher
                    .global_pps_threshold,
            ),
        }));

        let tap_typer = Arc::new(TapTyper::new());

        // TODO: collector enabled
        let mut dispatcher_components = vec![];

        // Sender/Collector
        info!(
            "static analyzer ip: '{}' actual analyzer ip '{}'",
            yaml_config.analyzer_ip, candidate_config.sender.dest_ip
        );
        let l4_flow_aggr_queue_name = "3-flowlog-to-collector-sender";
        let (l4_flow_aggr_sender, l4_flow_aggr_receiver, counter) = queue::bounded_with_debug(
            yaml_config.flow_sender_queue_size as usize,
            l4_flow_aggr_queue_name,
            &queue_debugger,
        );
        stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag("module", l4_flow_aggr_queue_name.to_string()),
                StatsOption::Tag("index", "0".to_string()),
            ],
        );
        let l4_flow_uniform_sender = UniformSenderThread::new(
            l4_flow_aggr_queue_name,
            Arc::new(l4_flow_aggr_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            true,
        );

        let metrics_queue_name = "3-doc-to-collector-sender";
        let (metrics_sender, metrics_receiver, counter) = queue::bounded_with_debug(
            yaml_config.collector_sender_queue_size,
            metrics_queue_name,
            &queue_debugger,
        );
        stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag("module", metrics_queue_name.to_string()),
                StatsOption::Tag("index", "0".to_string()),
            ],
        );
        let metrics_uniform_sender = UniformSenderThread::new(
            metrics_queue_name,
            Arc::new(metrics_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            true,
        );

        let proto_log_queue_name = "2-protolog-to-collector-sender";
        let (proto_log_sender, proto_log_receiver, counter) = queue::bounded_with_debug(
            yaml_config.flow_sender_queue_size,
            proto_log_queue_name,
            &queue_debugger,
        );
        stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag("module", proto_log_queue_name.to_string()),
                StatsOption::Tag("index", "0".to_string()),
            ],
        );
        let l7_flow_uniform_sender = UniformSenderThread::new(
            proto_log_queue_name,
            Arc::new(proto_log_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            true,
        );

        let analyzer_ip = if candidate_config
            .dispatcher
            .analyzer_ip
            .parse::<IpAddr>()
            .is_ok()
        {
            candidate_config
                .dispatcher
                .analyzer_ip
                .parse::<IpAddr>()
                .unwrap()
        } else {
            let ips = lookup_host(&candidate_config.dispatcher.analyzer_ip)?;
            ips[0]
        };

        // Dispatcher
        let source_ip = match get_route_src_ip(&analyzer_ip) {
            Ok(ip) => ip,
            Err(e) => {
                warn!("get route to '{}' failed: {:?}", &analyzer_ip, e);
                if ctrl_ip.is_ipv6() {
                    Ipv6Addr::UNSPECIFIED.into()
                } else {
                    Ipv4Addr::UNSPECIFIED.into()
                }
            }
        };

        let npb_bps_limit = Arc::new(LeakyBucket::new(Some(
            config_handler.candidate_config.sender.npb_bps_threshold,
        )));
        let npb_arp_table = Arc::new(NpbArpTable::new(
            config_handler.candidate_config.npb.socket_type == SocketType::RawUdp,
            exception_handler.clone(),
        ));

        let pcap_batch_queue = "2-pcap-batch-to-sender";
        let (pcap_batch_sender, pcap_batch_receiver, pcap_batch_counter) =
            queue::bounded_with_debug(
                yaml_config.pcap.queue_size as usize,
                pcap_batch_queue,
                &queue_debugger,
            );
        stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(pcap_batch_counter)),
            vec![
                StatsOption::Tag("module", pcap_batch_queue.to_string()),
                StatsOption::Tag("index", "0".to_string()),
            ],
        );
        let pcap_batch_uniform_sender = UniformSenderThread::new(
            pcap_batch_queue,
            Arc::new(pcap_batch_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            false,
        );
        // Enterprise Edition Feature: packet-sequence
        let packet_sequence_queue_name = "2-packet-sequence-block-to-sender";
        let (packet_sequence_uniform_output, packet_sequence_uniform_input, counter) =
            queue::bounded_with_debug(
                yaml_config.packet_sequence_queue_size,
                packet_sequence_queue_name,
                &queue_debugger,
            );

        stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag("module", packet_sequence_queue_name.to_string()),
                StatsOption::Tag("index", "0".to_string()),
            ],
        );

        let packet_sequence_uniform_sender = UniformSenderThread::new(
            packet_sequence_queue_name,
            Arc::new(packet_sequence_uniform_input),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            true,
        );

        let bpf_builder = bpf::Builder {
            is_ipv6: ctrl_ip.is_ipv6(),
            vxlan_flags: yaml_config.vxlan_flags,
            npb_port: yaml_config.npb_port,
            controller_port: static_config.controller_port,
            controller_tls_port: static_config.controller_tls_port,
            proxy_controller_port: candidate_config.dispatcher.proxy_controller_port,
            analyzer_source_ip: source_ip,
            analyzer_port: candidate_config.dispatcher.analyzer_port,
        };
        let bpf_syntax_str = bpf_builder.build_pcap_syntax_to_str();
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let bpf_syntax = bpf_builder.build_pcap_syntax();

        let bpf_options = Arc::new(Mutex::new(BpfOptions {
            capture_bpf: candidate_config.dispatcher.capture_bpf.clone(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            bpf_syntax,
            bpf_syntax_str,
        }));

        let mut tap_interfaces = vec![];
        for (i, entry) in interfaces_and_ns.into_iter().enumerate() {
            #[cfg(target_os = "linux")]
            let links = entry.0;
            #[cfg(any(target_os = "windows", target_os = "android"))]
            let links = entry;
            tap_interfaces.extend(links.clone());
            #[cfg(target_os = "linux")]
            let netns = entry.1;
            let dispatcher_component = build_dispatchers(
                i,
                links,
                stats_collector.clone(),
                config_handler,
                queue_debugger.clone(),
                version_info.name != env!("AGENT_NAME"),
                synchronizer,
                npb_bps_limit.clone(),
                npb_arp_table.clone(),
                rx_leaky_bucket.clone(),
                policy_getter,
                exception_handler.clone(),
                local_dispatcher_count,
                bpf_options.clone(),
                packet_sequence_uniform_output.clone(),
                proto_log_sender.clone(),
                pcap_batch_sender.clone(),
                tap_typer.clone(),
                vm_mac_addrs.clone(),
                gateway_vmac_addrs.clone(),
                toa_sender.clone(),
                l4_flow_aggr_sender.clone(),
                metrics_sender.clone(),
                #[cfg(target_os = "linux")]
                netns,
                #[cfg(target_os = "linux")]
                kubernetes_poller.clone(),
                #[cfg(target_os = "linux")]
                libvirt_xml_extractor.clone(),
            )?;
            dispatcher_components.push(dispatcher_component);
        }
        tap_interfaces.sort();
        let proc_event_queue_name = "1-proc-event-to-sender";
        #[allow(unused)]
        let (proc_event_sender, proc_event_receiver, counter) = queue::bounded_with_debug(
            yaml_config.external_metrics_sender_queue_size,
            proc_event_queue_name,
            &queue_debugger,
        );
        stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag("module", proc_event_queue_name.to_string()),
                StatsOption::Tag("index", "0".to_string()),
            ],
        );
        let proc_event_uniform_sender = UniformSenderThread::new(
            proc_event_queue_name,
            Arc::new(proc_event_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            true,
        );

        let profile_queue_name = "1-profile-to-sender";
        let (profile_sender, profile_receiver, counter) = queue::bounded_with_debug(
            yaml_config.external_metrics_sender_queue_size,
            profile_queue_name,
            &queue_debugger,
        );
        stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag("module", profile_queue_name.to_string()),
                StatsOption::Tag("index", "0".to_string()),
            ],
        );
        let profile_uniform_sender = UniformSenderThread::new(
            profile_queue_name,
            Arc::new(profile_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            true,
        );

        let ebpf_dispatcher_id = dispatcher_components.len();
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let mut ebpf_dispatcher_component = None;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if !config_handler.ebpf().load().ebpf.disabled
            && candidate_config.tap_mode != TapMode::Analyzer
        {
            let (flow_sender, flow_receiver, counter) = queue::bounded_with_debug(
                yaml_config.flow_queue_size,
                "1-tagged-flow-to-quadruple-generator",
                &queue_debugger,
            );
            stats_collector.register_countable(
                "queue",
                Countable::Owned(Box::new(counter)),
                vec![
                    StatsOption::Tag("module", "1-tagged-flow-to-quadruple-generator".to_string()),
                    StatsOption::Tag("index", ebpf_dispatcher_id.to_string()),
                ],
            );

            let (l7_stats_sender, l7_stats_receiver, counter) = queue::bounded_with_debug(
                yaml_config.flow_queue_size,
                "1-l7-stats-to-quadruple-generator",
                &queue_debugger,
            );
            stats_collector.register_countable(
                "queue",
                Countable::Owned(Box::new(counter)),
                vec![
                    StatsOption::Tag("module", "1-l7-stats-to-quadruple-generator".to_string()),
                    StatsOption::Tag("index", ebpf_dispatcher_id.to_string()),
                ],
            );
            let collector = Self::new_collector(
                ebpf_dispatcher_id,
                stats_collector.clone(),
                flow_receiver,
                toa_sender.clone(),
                None,
                metrics_sender.clone(),
                MetricsType::SECOND | MetricsType::MINUTE,
                config_handler,
                &queue_debugger,
                &synchronizer,
                agent_mode,
            );
            let (log_sender, log_receiver, counter) = queue::bounded_with_debug(
                yaml_config.flow_queue_size,
                "1-tagged-flow-to-app-protocol-logs",
                &queue_debugger,
            );
            stats_collector.register_countable(
                "queue",
                Countable::Owned(Box::new(counter)),
                vec![
                    StatsOption::Tag("module", "1-tagged-flow-to-app-protocol-logs".to_string()),
                    StatsOption::Tag("index", ebpf_dispatcher_id.to_string()),
                ],
            );
            let (session_aggregator, counter) = SessionAggregator::new(
                log_receiver,
                proto_log_sender.clone(),
                ebpf_dispatcher_id as u32,
                config_handler.log_parser(),
                synchronizer.ntp_diff(),
            );
            stats_collector.register_countable(
                "l7_session_aggr",
                Countable::Ref(Arc::downgrade(&counter) as Weak<dyn RefCountable>),
                vec![StatsOption::Tag("index", ebpf_dispatcher_id.to_string())],
            );
            let l7_collector = Self::new_l7_collector(
                ebpf_dispatcher_id,
                stats_collector.clone(),
                l7_stats_receiver,
                metrics_sender.clone(),
                MetricsType::SECOND | MetricsType::MINUTE,
                config_handler,
                &queue_debugger,
                &synchronizer,
                agent_mode,
            );
            match EbpfCollector::new(
                ebpf_dispatcher_id,
                synchronizer.ntp_diff(),
                config_handler.ebpf(),
                config_handler.log_parser(),
                config_handler.flow(),
                config_handler.collector(),
                policy_getter,
                log_sender,
                flow_sender,
                l7_stats_sender,
                proc_event_sender,
                profile_sender.clone(),
                &queue_debugger,
                stats_collector.clone(),
            ) {
                Ok(ebpf_collector) => {
                    synchronizer
                        .add_flow_acl_listener(Box::new(ebpf_collector.get_sync_dispatcher()));
                    stats_collector.register_countable(
                        "ebpf-collector",
                        Countable::Owned(Box::new(ebpf_collector.get_sync_counter())),
                        vec![],
                    );
                    ebpf_dispatcher_component = Some(EbpfDispatcherComponent {
                        ebpf_collector,
                        session_aggregator,
                        collector,
                        l7_collector,
                    });
                }
                Err(e) => {
                    log::error!("ebpf collector error: {:?}", e);
                }
            };
        }

        let otel_queue_name = "1-otel-to-sender";
        let (otel_sender, otel_receiver, counter) = queue::bounded_with_debug(
            yaml_config.external_metrics_sender_queue_size,
            otel_queue_name,
            &queue_debugger,
        );
        stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag("module", otel_queue_name.to_string()),
                StatsOption::Tag("index", "0".to_string()),
            ],
        );
        let otel_uniform_sender = UniformSenderThread::new(
            otel_queue_name,
            Arc::new(otel_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            true,
        );

        let otel_dispatcher_id = ebpf_dispatcher_id + 1;

        let (l7_stats_sender, l7_stats_receiver, counter) = queue::bounded_with_debug(
            yaml_config.flow_queue_size,
            "1-l7-stats-to-quadruple-generator",
            &queue_debugger,
        );
        stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag("module", "1-l7-stats-to-quadruple-generator".to_string()),
                StatsOption::Tag("index", otel_dispatcher_id.to_string()),
            ],
        );
        let l7_collector = Self::new_l7_collector(
            otel_dispatcher_id,
            stats_collector.clone(),
            l7_stats_receiver,
            metrics_sender.clone(),
            MetricsType::SECOND | MetricsType::MINUTE,
            config_handler,
            &queue_debugger,
            &synchronizer,
            agent_mode,
        );

        let prometheus_queue_name = "1-prometheus-to-sender";
        let (prometheus_sender, prometheus_receiver, counter) = queue::bounded_with_debug(
            yaml_config.external_metrics_sender_queue_size,
            prometheus_queue_name,
            &queue_debugger,
        );
        stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag("module", prometheus_queue_name.to_string()),
                StatsOption::Tag("index", "0".to_string()),
            ],
        );
        let prometheus_uniform_sender = UniformSenderThread::new(
            prometheus_queue_name,
            Arc::new(prometheus_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            true,
        );

        let telegraf_queue_name = "1-telegraf-to-sender";
        let (telegraf_sender, telegraf_receiver, counter) = queue::bounded_with_debug(
            yaml_config.external_metrics_sender_queue_size,
            telegraf_queue_name,
            &queue_debugger,
        );
        stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag("module", telegraf_queue_name.to_string()),
                StatsOption::Tag("index", "0".to_string()),
            ],
        );
        let telegraf_uniform_sender = UniformSenderThread::new(
            telegraf_queue_name,
            Arc::new(telegraf_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            true,
        );

        let compressed_otel_queue_name = "1-compressed-otel-to-sender";
        let (compressed_otel_sender, compressed_otel_receiver, counter) = queue::bounded_with_debug(
            yaml_config.external_metrics_sender_queue_size,
            compressed_otel_queue_name,
            &queue_debugger,
        );
        stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag("module", compressed_otel_queue_name.to_string()),
                StatsOption::Tag("index", "0".to_string()),
            ],
        );
        let compressed_otel_uniform_sender = UniformSenderThread::new(
            compressed_otel_queue_name,
            Arc::new(compressed_otel_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
            true,
        );

        let (external_metrics_server, external_metrics_counter) = MetricServer::new(
            runtime.clone(),
            otel_sender,
            compressed_otel_sender,
            l7_stats_sender,
            prometheus_sender,
            telegraf_sender,
            profile_sender,
            candidate_config.metric_server.port,
            exception_handler.clone(),
            candidate_config.metric_server.compressed,
            candidate_config.platform.epc_id,
            policy_getter,
            synchronizer.ntp_diff(),
            candidate_config.yaml_config.prometheus_extra_config.clone(),
            candidate_config.log_parser.clone(),
            candidate_config
                .yaml_config
                .external_profile_integration_disabled,
            candidate_config
                .yaml_config
                .external_trace_integration_disabled,
            candidate_config
                .yaml_config
                .external_metric_integration_disabled,
        );

        stats_collector.register_countable(
            "integration_collector",
            Countable::Owned(Box::new(external_metrics_counter)),
            Default::default(),
        );

        let sender_config = config_handler.sender().load();
        let (npb_bandwidth_watcher, npb_bandwidth_watcher_counter) = NpbBandwidthWatcher::new(
            sender_config.bandwidth_probe_interval.as_secs(),
            sender_config.npb_bps_threshold,
            sender_config.server_tx_bandwidth_threshold,
            npb_bps_limit.clone(),
            exception_handler.clone(),
        );
        synchronizer.add_flow_acl_listener(npb_bandwidth_watcher.clone());
        stats_collector.register_countable(
            "npb_bandwidth_watcher",
            Countable::Ref(Arc::downgrade(&npb_bandwidth_watcher_counter) as Weak<dyn RefCountable>),
            Default::default(),
        );

        Ok(AgentComponents {
            config: candidate_config.clone(),
            rx_leaky_bucket,
            tap_typer,
            cur_tap_types: vec![],
            l4_flow_uniform_sender,
            metrics_uniform_sender,
            l7_flow_uniform_sender,
            stats_sender,
            platform_synchronizer,
            #[cfg(target_os = "linux")]
            kubernetes_poller,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            socket_synchronizer,
            #[cfg(target_os = "linux")]
            prometheus_targets_watcher,
            debugger,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            ebpf_dispatcher_component,
            stats_collector,
            running: AtomicBool::new(false),
            metrics_server_component: MetricsServerComponent {
                external_metrics_server,
                l7_collector,
            },
            exception_handler,
            max_memory,
            otel_uniform_sender,
            prometheus_uniform_sender,
            telegraf_uniform_sender,
            profile_uniform_sender,
            proc_event_uniform_sender,
            tap_mode: candidate_config.tap_mode,
            packet_sequence_uniform_output, // Enterprise Edition Feature: packet-sequence
            packet_sequence_uniform_sender, // Enterprise Edition Feature: packet-sequence
            npb_bps_limit,
            compressed_otel_uniform_sender,
            pcap_batch_uniform_sender,
            proto_log_sender,
            pcap_batch_sender,
            toa_info_sender: toa_sender,
            l4_flow_aggr_sender,
            metrics_sender,
            agent_mode,
            policy_setter,
            policy_getter,
            npb_bandwidth_watcher,
            npb_arp_table,
            runtime,
            dispatcher_components,
            is_ce_version: version_info.name != env!("AGENT_NAME"),
            tap_interfaces,
            last_dispatcher_component_id: otel_dispatcher_id,
            bpf_options,
        })
    }

    pub fn clear_dispatcher_components(&mut self) {
        self.dispatcher_components.iter_mut().for_each(|d| d.stop());
        self.dispatcher_components.clear();
        self.tap_interfaces.clear();
    }

    fn start(&mut self) {
        if self.running.swap(true, Ordering::Relaxed) {
            return;
        }
        info!("Staring agent components.");
        self.stats_collector.start();

        #[cfg(any(target_os = "linux", target_os = "android"))]
        self.socket_synchronizer.start();
        #[cfg(target_os = "linux")]
        {
            if crate::utils::environment::is_tt_pod(self.config.trident_type) {
                self.kubernetes_poller.start();
            }
            if matches!(self.agent_mode, RunningMode::Managed) && running_in_container() {
                self.prometheus_targets_watcher.start();
            }
        }
        self.debugger.start();
        self.metrics_uniform_sender.start();
        self.l7_flow_uniform_sender.start();
        self.l4_flow_uniform_sender.start();

        // Enterprise Edition Feature: packet-sequence
        self.packet_sequence_uniform_sender.start();

        // When tap_mode is Analyzer mode and agent is not running in container and agent
        // in the environment where cgroup is not supported, we need to check free memory
        if self.tap_mode != TapMode::Analyzer
            && !running_in_container()
            && !is_kernel_available_for_cgroups()
        {
            match free_memory_check(self.max_memory, &self.exception_handler) {
                Ok(()) => {
                    for d in self.dispatcher_components.iter_mut() {
                        d.start();
                    }
                }
                Err(e) => {
                    warn!("{}", e);
                }
            }
        } else {
            for d in self.dispatcher_components.iter_mut() {
                d.start();
            }
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(ebpf_dispatcher_component) = self.ebpf_dispatcher_component.as_mut() {
            ebpf_dispatcher_component.start();
        }
        if matches!(self.agent_mode, RunningMode::Managed) {
            self.otel_uniform_sender.start();
            self.compressed_otel_uniform_sender.start();
            self.prometheus_uniform_sender.start();
            self.telegraf_uniform_sender.start();
            self.profile_uniform_sender.start();
            self.proc_event_uniform_sender.start();
            if self.config.metric_server.enabled {
                self.metrics_server_component.start();
            }
            self.pcap_batch_uniform_sender.start();
        }

        self.npb_bandwidth_watcher.start();
        self.npb_arp_table.start();
        info!("Started agent components.");
    }

    fn stop(&mut self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            return;
        }

        let mut join_handles = vec![];

        self.policy_setter.reset_queue_size(0);
        for d in self.dispatcher_components.iter_mut() {
            d.stop();
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        self.socket_synchronizer.stop();
        #[cfg(target_os = "linux")]
        {
            self.kubernetes_poller.stop();
            self.prometheus_targets_watcher.stop();
        }

        if let Some(h) = self.l4_flow_uniform_sender.notify_stop() {
            join_handles.push(h);
        }
        if let Some(h) = self.metrics_uniform_sender.notify_stop() {
            join_handles.push(h);
        }
        if let Some(h) = self.l7_flow_uniform_sender.notify_stop() {
            join_handles.push(h);
        }

        self.debugger.stop();

        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(d) = self.ebpf_dispatcher_component.as_mut() {
            d.stop();
        }

        self.metrics_server_component.stop();
        if let Some(h) = self.otel_uniform_sender.notify_stop() {
            join_handles.push(h);
        }
        if let Some(h) = self.compressed_otel_uniform_sender.notify_stop() {
            join_handles.push(h);
        }
        if let Some(h) = self.prometheus_uniform_sender.notify_stop() {
            join_handles.push(h);
        }
        if let Some(h) = self.telegraf_uniform_sender.notify_stop() {
            join_handles.push(h);
        }
        if let Some(h) = self.profile_uniform_sender.notify_stop() {
            join_handles.push(h);
        }
        if let Some(h) = self.proc_event_uniform_sender.notify_stop() {
            join_handles.push(h);
        }
        if let Some(h) = self.pcap_batch_uniform_sender.notify_stop() {
            join_handles.push(h);
        }
        // Enterprise Edition Feature: packet-sequence
        if let Some(h) = self.packet_sequence_uniform_sender.notify_stop() {
            join_handles.push(h);
        }

        if let Some(h) = self.npb_bandwidth_watcher.notify_stop() {
            join_handles.push(h);
        }

        if let Some(h) = self.npb_arp_table.notify_stop() {
            join_handles.push(h);
        }
        if let Some(h) = self.stats_collector.notify_stop() {
            join_handles.push(h);
        }

        for handle in join_handles {
            if !handle.is_finished() {
                info!(
                    "wait for {} to fully stop",
                    handle.thread().name().unwrap_or("unnamed thread")
                );
            }
            let _ = handle.join();
        }

        info!("Stopped agent components.")
    }
}

impl Components {
    fn start(&mut self) {
        match self {
            Self::Agent(a) => a.start(),
            #[cfg(target_os = "linux")]
            Self::Watcher(w) => w.start(),
            _ => {}
        }
    }

    fn new(
        version_info: &VersionInfo,
        config_handler: &ConfigHandler,
        stats_collector: Arc<stats::Collector>,
        session: &Arc<Session>,
        synchronizer: &Arc<Synchronizer>,
        exception_handler: ExceptionHandler,
        #[cfg(target_os = "linux")] libvirt_xml_extractor: Arc<LibvirtXmlExtractor>,
        platform_synchronizer: Arc<PlatformSynchronizer>,
        #[cfg(target_os = "linux")] sidecar_poller: Option<Arc<GenericPoller>>,
        #[cfg(target_os = "linux")] api_watcher: Arc<ApiWatcher>,
        vm_mac_addrs: Vec<MacAddr>,
        gateway_vmac_addrs: Vec<MacAddr>,
        agent_mode: RunningMode,
        runtime: Arc<Runtime>,
    ) -> Result<Self> {
        #[cfg(target_os = "linux")]
        if crate::utils::environment::running_in_only_watch_k8s_mode() {
            let components = WatcherComponents::new(config_handler, agent_mode, runtime)?;
            return Ok(Components::Watcher(components));
        }
        let components = AgentComponents::new(
            version_info,
            config_handler,
            stats_collector,
            session,
            synchronizer,
            exception_handler,
            #[cfg(target_os = "linux")]
            libvirt_xml_extractor,
            platform_synchronizer,
            #[cfg(target_os = "linux")]
            sidecar_poller,
            #[cfg(target_os = "linux")]
            api_watcher,
            vm_mac_addrs,
            gateway_vmac_addrs,
            agent_mode,
            runtime,
        )?;
        return Ok(Components::Agent(components));
    }

    fn stop(&mut self) {
        match self {
            Self::Agent(a) => a.stop(),
            #[cfg(target_os = "linux")]
            Self::Watcher(w) => w.stop(),
            _ => {}
        }
    }
}

fn build_pcap_assembler(
    enabled: bool,
    config: &PcapConfig,
    stats_collector: &stats::Collector,
    pcap_batch_sender: DebugSender<BoxedPcapBatch>,
    queue_debugger: &QueueDebugger,
    ntp_diff: Arc<AtomicI64>,
    id: usize,
) -> (PcapAssembler, DebugSender<MiniPacket>) {
    let mini_packet_queue = "1-mini-meta-packet-to-pcap-handler";
    let (mini_packet_sender, mini_packet_receiver, mini_packet_counter) = queue::bounded_with_debug(
        config.queue_size as usize,
        mini_packet_queue,
        &queue_debugger,
    );
    let pcap_assembler = PcapAssembler::new(
        id as u32,
        enabled,
        config.buffer_size,
        config.flow_buffer_size,
        config.flush_interval,
        pcap_batch_sender,
        mini_packet_receiver,
        ntp_diff,
    );
    stats_collector.register_countable(
        "pcap_assembler",
        Countable::Ref(Arc::downgrade(&pcap_assembler.counter) as Weak<dyn RefCountable>),
        vec![StatsOption::Tag("id", id.to_string())],
    );
    stats_collector.register_countable(
        "queue",
        Countable::Owned(Box::new(mini_packet_counter)),
        vec![
            StatsOption::Tag("module", mini_packet_queue.to_string()),
            StatsOption::Tag("index", id.to_string()),
        ],
    );
    (pcap_assembler, mini_packet_sender)
}

fn build_dispatchers(
    id: usize,
    links: Vec<Link>,
    stats_collector: Arc<stats::Collector>,
    config_handler: &ConfigHandler,
    queue_debugger: Arc<QueueDebugger>,
    is_ce_version: bool,
    synchronizer: &Arc<Synchronizer>,
    npb_bps_limit: Arc<LeakyBucket>,
    npb_arp_table: Arc<NpbArpTable>,
    rx_leaky_bucket: Arc<LeakyBucket>,
    policy_getter: PolicyGetter,
    exception_handler: ExceptionHandler,
    local_dispatcher_count: usize,
    bpf_options: Arc<Mutex<BpfOptions>>,
    packet_sequence_uniform_output: DebugSender<BoxedPacketSequenceBlock>,
    proto_log_sender: DebugSender<BoxAppProtoLogsData>,
    pcap_batch_sender: DebugSender<BoxedPcapBatch>,
    tap_typer: Arc<TapTyper>,
    vm_mac_addrs: Vec<MacAddr>,
    gateway_vmac_addrs: Vec<MacAddr>,
    toa_info_sender: DebugSender<Box<(SocketAddr, SocketAddr)>>,
    l4_flow_aggr_sender: DebugSender<BoxedTaggedFlow>,
    metrics_sender: DebugSender<BoxedDocument>,
    #[cfg(target_os = "linux")] netns: netns::NsFile,
    #[cfg(target_os = "linux")] kubernetes_poller: Arc<GenericPoller>,
    #[cfg(target_os = "linux")] libvirt_xml_extractor: Arc<LibvirtXmlExtractor>,
) -> Result<DispatcherComponent> {
    let candidate_config = &config_handler.candidate_config;
    let yaml_config = &candidate_config.yaml_config;
    let dispatcher_config = &candidate_config.dispatcher;
    let static_config = &config_handler.static_config;
    let agent_mode = static_config.agent_mode;
    let ctrl_ip = config_handler.ctrl_ip;
    let ctrl_mac = config_handler.ctrl_mac;
    let src_link = links.get(0).map(|l| l.to_owned()).unwrap_or_default();

    let (flow_sender, flow_receiver, counter) = queue::bounded_with_debug(
        yaml_config.flow_queue_size,
        "1-tagged-flow-to-quadruple-generator",
        &queue_debugger,
    );
    stats_collector.register_countable(
        "queue",
        Countable::Owned(Box::new(counter)),
        vec![
            StatsOption::Tag("module", "1-tagged-flow-to-quadruple-generator".to_string()),
            StatsOption::Tag("index", id.to_string()),
        ],
    );

    let (l7_stats_sender, l7_stats_receiver, counter) = queue::bounded_with_debug(
        yaml_config.flow_queue_size,
        "1-l7-stats-to-quadruple-generator",
        &queue_debugger,
    );
    stats_collector.register_countable(
        "queue",
        Countable::Owned(Box::new(counter)),
        vec![
            StatsOption::Tag("module", "1-l7-stats-to-quadruple-generator".to_string()),
            StatsOption::Tag("index", id.to_string()),
        ],
    );

    // create and start app proto logs
    let (log_sender, log_receiver, counter) = queue::bounded_with_debug(
        yaml_config.flow_queue_size,
        "1-tagged-flow-to-app-protocol-logs",
        &queue_debugger,
    );
    stats_collector.register_countable(
        "queue",
        Countable::Owned(Box::new(counter)),
        vec![
            StatsOption::Tag("module", "1-tagged-flow-to-app-protocol-logs".to_string()),
            StatsOption::Tag("index", id.to_string()),
        ],
    );

    let (session_aggr, counter) = SessionAggregator::new(
        log_receiver,
        proto_log_sender.clone(),
        id as u32,
        config_handler.log_parser(),
        synchronizer.ntp_diff(),
    );
    stats_collector.register_countable(
        "l7_session_aggr",
        Countable::Ref(Arc::downgrade(&counter) as Weak<dyn RefCountable>),
        vec![StatsOption::Tag("index", id.to_string())],
    );

    // Enterprise Edition Feature: packet-sequence
    // create and start packet sequence
    let (packet_sequence_sender, packet_sequence_receiver, counter) = queue::bounded_with_debug(
        yaml_config.packet_sequence_queue_size,
        "1-packet-sequence-block-to-parser",
        &queue_debugger,
    );
    stats_collector.register_countable(
        "queue",
        Countable::Owned(Box::new(counter)),
        vec![
            StatsOption::Tag("module", "1-packet-sequence-block-to-parser".to_string()),
            StatsOption::Tag("index", id.to_string()),
        ],
    );

    let packet_sequence_parser = PacketSequenceParser::new(
        packet_sequence_receiver,
        packet_sequence_uniform_output,
        id as u32,
    );
    let (pcap_assembler, mini_packet_sender) = build_pcap_assembler(
        is_ce_version,
        &yaml_config.pcap,
        &stats_collector,
        pcap_batch_sender.clone(),
        &queue_debugger,
        synchronizer.ntp_diff(),
        id,
    );

    let handler_builders = Arc::new(Mutex::new(vec![
        PacketHandlerBuilder::Pcap(mini_packet_sender),
        PacketHandlerBuilder::Npb(NpbBuilder::new(
            id,
            &candidate_config.npb,
            &queue_debugger,
            npb_bps_limit.clone(),
            npb_arp_table.clone(),
            stats_collector.clone(),
        )),
    ]));

    let pcap_interfaces =
        if candidate_config.tap_mode == TapMode::Mirror && yaml_config.dpdk_enabled {
            vec![]
        } else {
            links.clone()
        };

    let dispatcher_builder = DispatcherBuilder::new()
        .id(id)
        .pause(agent_mode == RunningMode::Managed)
        .handler_builders(handler_builders.clone())
        .ctrl_mac(ctrl_mac)
        .leaky_bucket(rx_leaky_bucket.clone())
        .options(Arc::new(Mutex::new(dispatcher::Options {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            af_packet_version: dispatcher_config.af_packet_version,
            packet_blocks: dispatcher_config.af_packet_blocks,
            tap_mode: candidate_config.tap_mode,
            tap_mac_script: yaml_config.tap_mac_script.clone(),
            is_ipv6: ctrl_ip.is_ipv6(),
            npb_port: yaml_config.npb_port,
            vxlan_flags: yaml_config.vxlan_flags,
            controller_port: static_config.controller_port,
            controller_tls_port: static_config.controller_tls_port,
            libpcap_enabled: yaml_config.libpcap_enabled,
            snap_len: dispatcher_config.capture_packet_size as usize,
            dpdk_enabled: dispatcher_config.dpdk_enabled,
            dispatcher_queue: dispatcher_config.dispatcher_queue,
            ..Default::default()
        })))
        .bpf_options(bpf_options)
        .default_tap_type(
            (yaml_config.default_tap_type as u16)
                .try_into()
                .unwrap_or(TapType::Cloud),
        )
        .mirror_traffic_pcp(yaml_config.mirror_traffic_pcp)
        .tap_typer(tap_typer.clone())
        .analyzer_dedup_disabled(yaml_config.analyzer_dedup_disabled)
        .flow_output_queue(flow_sender.clone())
        .l7_stats_output_queue(l7_stats_sender.clone())
        .log_output_queue(log_sender.clone())
        .packet_sequence_output_queue(packet_sequence_sender) // Enterprise Edition Feature: packet-sequence
        .stats_collector(stats_collector.clone())
        .flow_map_config(config_handler.flow())
        .log_parse_config(config_handler.log_parser())
        .collector_config(config_handler.collector())
        .policy_getter(policy_getter)
        .exception_handler(exception_handler.clone())
        .ntp_diff(synchronizer.ntp_diff())
        .src_interface(if candidate_config.tap_mode != TapMode::Local {
            src_link.name.clone()
        } else {
            "".into()
        })
        .trident_type(dispatcher_config.trident_type)
        .queue_debugger(queue_debugger.clone())
        .analyzer_queue_size(yaml_config.analyzer_queue_size as usize)
        .pcap_interfaces(pcap_interfaces.clone())
        .local_dispatcher_count(local_dispatcher_count)
        .analyzer_raw_packet_block_size(yaml_config.analyzer_raw_packet_block_size as usize);
    #[cfg(target_os = "linux")]
    let dispatcher_builder = dispatcher_builder
        .netns(netns)
        .libvirt_xml_extractor(libvirt_xml_extractor.clone())
        .platform_poller(kubernetes_poller.clone());
    let dispatcher = match dispatcher_builder.build() {
        Ok(d) => d,
        Err(e) => {
            warn!(
                "dispatcher creation failed: {}, deepflow-agent restart...",
                e
            );
            thread::sleep(Duration::from_secs(1));
            return Err(e.into());
        }
    };
    let mut dispatcher_listener = dispatcher.listener();
    dispatcher_listener.on_config_change(dispatcher_config);
    dispatcher_listener.on_tap_interface_change(
        &links,
        dispatcher_config.if_mac_source,
        dispatcher_config.trident_type,
        &vec![],
    );
    dispatcher_listener.on_vm_change(&vm_mac_addrs, &gateway_vmac_addrs);
    synchronizer.add_flow_acl_listener(Box::new(dispatcher_listener.clone()));

    // create and start collector
    let collector = AgentComponents::new_collector(
        id,
        stats_collector.clone(),
        flow_receiver,
        toa_info_sender.clone(),
        Some(l4_flow_aggr_sender.clone()),
        metrics_sender.clone(),
        MetricsType::SECOND | MetricsType::MINUTE,
        config_handler,
        &queue_debugger,
        &synchronizer,
        agent_mode,
    );

    let l7_collector = AgentComponents::new_l7_collector(
        id,
        stats_collector.clone(),
        l7_stats_receiver,
        metrics_sender.clone(),
        MetricsType::SECOND | MetricsType::MINUTE,
        config_handler,
        &queue_debugger,
        &synchronizer,
        agent_mode,
    );
    Ok(DispatcherComponent {
        id,
        dispatcher,
        dispatcher_listener,
        session_aggregator: session_aggr,
        collector,
        l7_collector,
        packet_sequence_parser,
        pcap_assembler,
        handler_builders,
        src_link,
    })
}
