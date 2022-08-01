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

use std::env;
use std::mem;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::process;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Condvar, Mutex, Weak,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::Result;
use arc_swap::access::Access;
use dns_lookup::lookup_host;
use flexi_logger::{
    colored_opt_format, Age, Cleanup, Criterion, Duplicate, FileSpec, Logger, LoggerHandle, Naming,
};
use log::{info, warn};

use crate::{
    collector::Collector,
    collector::{
        flow_aggr::FlowAggrThread, quadruple_generator::QuadrupleGeneratorThread, CollectorThread,
        MetricsType,
    },
    common::{
        enums::TapType, tagged_flow::TaggedFlow, tap_types::TapTyper, DropletMessageType,
        DEFAULT_INGESTER_PORT, DEFAULT_LOG_RETENTION, FREE_SPACE_REQUIREMENT,
    },
    config::{
        handler::{ConfigHandler, DispatcherConfig, PortAccess},
        Config, ConfigError, RuntimeConfig, YamlConfig,
    },
    debug::{ConstructDebugCtx, Debugger, QueueDebugger},
    dispatcher::{
        self, recv_engine::bpf, BpfOptions, Dispatcher, DispatcherBuilder, DispatcherListener,
    },
    ebpf_collector::EbpfCollector,
    exception::ExceptionHandler,
    flow_generator::{AppProtoLogsParser, PacketSequenceParser},
    handler::PacketHandlerBuilder,
    integration_collector::MetricServer,
    monitor::Monitor,
    pcap::WorkerManager,
    platform::{ApiWatcher, LibvirtXmlExtractor, PlatformSynchronizer},
    policy::{Policy, PolicyGetter},
    proto::trident::TapMode,
    rpc::{Session, Synchronizer, DEFAULT_TIMEOUT},
    sender::{uniform_sender::UniformSenderThread, SendItem},
    utils::{
        cgroups::Cgroups,
        environment::{
            check, controller_ip_check, free_memory_check, free_space_checker, kernel_check,
            running_in_container, trident_process_check,
        },
        guard::Guard,
        logger::{LogLevelWriter, LogWriterAdapter, RemoteLogConfig, RemoteLogWriter},
        net::{get_ctrl_ip_and_mac, get_route_src_ip, links_by_name_regex},
        queue,
        stats::{self, Countable, RefCountable, StatsOption},
        LeakyBucket,
    },
};

const MINUTE: Duration = Duration::from_secs(60);

pub enum State {
    Running,
    ConfigChanged((RuntimeConfig, Vec<u64>)),
    Terminated,
    Disabled, // 禁用状态
}

impl State {
    fn unwrap_config(self) -> (RuntimeConfig, Vec<u64>) {
        match self {
            Self::ConfigChanged(c) => c,
            _ => panic!("not config type"),
        }
    }
}

pub type TridentState = Arc<(Mutex<State>, Condvar)>;

pub struct Trident {
    state: TridentState,
    handle: Option<JoinHandle<()>>,
}

#[cfg(unix)]
pub const DEFAULT_TRIDENT_CONF_FILE: &'static str = "/etc/trident.yaml";
#[cfg(windows)]
pub const DEFAULT_TRIDENT_CONF_FILE: &'static str = "C:\\DeepFlow\\trident\\trident-windows.yaml";

impl Trident {
    pub fn start<P: AsRef<Path>>(
        config_path: P,
        agent_ident: &'static str,
        revision: &'static str,
    ) -> Result<Trident> {
        let state = Arc::new((Mutex::new(State::Running), Condvar::new()));
        let state_thread = state.clone();

        let config = match Config::load_from_file(config_path.as_ref()) {
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
        };
        let base_name = Path::new(&env::args().next().unwrap())
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let (remote_log_writer, remote_log_config) = RemoteLogWriter::new(
            &config.controller_ips,
            DEFAULT_INGESTER_PORT,
            base_name,
            vec![0, 0, 0, 0, DropletMessageType::Syslog as u8],
        );

        let (log_level_writer, log_level_counter) = LogLevelWriter::new();
        let mut logger = Logger::try_with_str("info")
            .unwrap()
            .format(colored_opt_format)
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
            .append();
        if nix::unistd::getppid().as_raw() != 1 {
            logger = logger.duplicate_to_stderr(Duplicate::All);
        }
        let logger_handle = logger.start()?;

        let stats_collector = Arc::new(stats::Collector::new(&config.controller_ips));
        stats_collector.start();
        stats_collector.register_countable(
            "log_counter",
            stats::Countable::Owned(Box::new(log_level_counter)),
            Default::default(),
        );

        info!("static_config {:#?}", config);
        let handle = Some(thread::spawn(move || {
            if let Err(e) = Self::run(
                state_thread,
                config,
                agent_ident,
                revision,
                logger_handle,
                remote_log_config,
                stats_collector,
            ) {
                warn!("deepflow-agent exited: {}", e);
                process::exit(1);
            }
        }));

        Ok(Trident { state, handle })
    }

    fn run(
        state: TridentState,
        mut config: Config,
        agent_ident: &'static str,
        revision: &'static str,
        logger_handle: LoggerHandle,
        remote_log_config: RemoteLogConfig,
        stats_collector: Arc<stats::Collector>,
    ) -> Result<()> {
        info!("========== DeepFlow Agent start! ==========");

        let (ctrl_ip, ctrl_mac) = get_ctrl_ip_and_mac(config.controller_ips[0].parse()?);
        info!("ctrl_ip {} ctrl_mac {}", ctrl_ip, ctrl_mac);

        let exception_handler = ExceptionHandler::default();
        let session = Arc::new(Session::new(
            config.controller_port,
            config.controller_tls_port,
            DEFAULT_TIMEOUT,
            config.controller_cert_file_prefix.clone(),
            config.controller_ips.clone(),
            exception_handler.clone(),
        ));

        if running_in_container() && config.kubernetes_cluster_id.is_empty() {
            config.kubernetes_cluster_id = Config::get_k8s_cluster_id(&session);
        }

        let default_runtime_config = RuntimeConfig::default();
        // 目前仅支持local-mod + ebpf-collector，ebpf-collector不适用fast, 所以队列数为1
        let (policy_setter, policy_getter) = Policy::new(
            1,
            default_runtime_config.yaml_config.first_path_level as usize,
            default_runtime_config.yaml_config.fast_path_map_size,
            false,
        );

        let mut config_handler = ConfigHandler::new(
            config,
            ctrl_ip,
            ctrl_mac,
            logger_handle,
            remote_log_config.clone(),
        );

        let mut stats_sender = UniformSenderThread::new(
            stats::DFSTATS_SENDER_ID,
            stats_collector.get_receiver(),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
        );
        stats_sender.start();

        let synchronizer = Arc::new(Synchronizer::new(
            session.clone(),
            state.clone(),
            agent_ident,
            revision,
            ctrl_ip.to_string(),
            ctrl_mac.to_string(),
            config_handler.static_config.controller_ips[0].clone(),
            config_handler.static_config.vtap_group_id_request.clone(),
            config_handler.static_config.kubernetes_cluster_id.clone(),
            policy_setter,
            exception_handler.clone(),
        ));
        synchronizer.start();

        let log_dir = Path::new(config_handler.static_config.log_file.as_str());
        let log_dir = log_dir.parent().unwrap().to_str().unwrap();
        let guard = Guard::new(
            config_handler.environment(),
            log_dir.to_string(),
            exception_handler.clone(),
        );
        guard.start();

        let monitor = Monitor::new(stats_collector.clone(), log_dir.to_string())?;
        monitor.start();

        let (state, cond) = &*state;
        let mut state_guard = state.lock().unwrap();
        let mut components: Option<Components> = None;
        let mut yaml_conf: Option<YamlConfig> = None;

        loop {
            match &*state_guard {
                State::Running => {
                    state_guard = cond.wait(state_guard).unwrap();
                    continue;
                }
                State::Terminated => {
                    if let Some(mut c) = components {
                        c.stop();
                        guard.stop();
                        monitor.stop();
                    }
                    return Ok(());
                }
                State::Disabled => {
                    if let Some(ref mut c) = components {
                        c.stop();
                    }
                    state_guard = cond.wait(state_guard).unwrap();
                    continue;
                }
                _ => (),
            }
            let mut new_state = State::Running;
            mem::swap(&mut new_state, &mut *state_guard);
            mem::drop(state_guard);

            let (new_conf, blacklist) = new_state.unwrap_config();
            if let Some(old_yaml) = yaml_conf {
                if old_yaml != new_conf.yaml_config {
                    if let Some(mut c) = components.take() {
                        c.stop();
                    }
                }
            }
            yaml_conf = Some(new_conf.yaml_config.clone());
            let callbacks = config_handler.on_config(new_conf, &exception_handler);
            match components.as_mut() {
                None => {
                    let mut comp = Components::new(
                        &config_handler,
                        stats_collector.clone(),
                        &session,
                        &synchronizer,
                        policy_getter,
                        exception_handler.clone(),
                        remote_log_config.clone(),
                    )?;
                    comp.start();
                    for callback in callbacks {
                        callback(&config_handler, &mut comp);
                    }
                    dispatcher_listener_callback(
                        &config_handler.candidate_config.dispatcher,
                        &comp,
                        blacklist,
                    );
                    components.replace(comp);
                }
                Some(components) => {
                    dispatcher_listener_callback(
                        &config_handler.candidate_config.dispatcher,
                        &components,
                        blacklist,
                    );
                    for callback in callbacks {
                        callback(&config_handler, components);
                    }
                    for listener in components.dispatcher_listeners.iter_mut() {
                        listener.on_config_change(&config_handler.candidate_config.dispatcher);
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

fn dispatcher_listener_callback(
    conf: &DispatcherConfig,
    components: &Components,
    blacklist: Vec<u64>,
) {
    if conf.tap_mode == TapMode::Local {
        let if_mac_source = conf.if_mac_source;
        let links = match links_by_name_regex(&conf.tap_interface_regex) {
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
                links
            }
        };
        for listener in components.dispatcher_listeners.iter() {
            listener.on_tap_interface_change(&links, if_mac_source, conf.trident_type, &blacklist);
        }
    } else {
        todo!()
    }
}

pub struct DomainNameListener {
    stats_collector: Arc<stats::Collector>,
    synchronizer: Arc<Synchronizer>,
    remote_log_config: RemoteLogConfig,

    ips: Vec<String>,
    domain_names: Vec<String>,
    port_config: PortAccess,

    thread_handler: Option<JoinHandle<()>>,
    stopped: Arc<AtomicBool>,
}

impl DomainNameListener {
    const INTERVAL: u64 = 5;

    fn new(
        stats_collector: Arc<stats::Collector>,
        synchronizer: Arc<Synchronizer>,
        remote_log_config: RemoteLogConfig,
        domain_names: Vec<String>,
        ips: Vec<String>,
        port_config: PortAccess,
    ) -> DomainNameListener {
        Self {
            stats_collector: stats_collector.clone(),
            synchronizer: synchronizer.clone(),
            remote_log_config,

            domain_names: domain_names.clone(),
            ips: ips.clone(),
            port_config,

            thread_handler: None,
            stopped: Arc::new(AtomicBool::new(false)),
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
        let stats_collector = self.stats_collector.clone();
        let synchronizer = self.synchronizer.clone();

        let mut ips = self.ips.clone();
        let domain_names = self.domain_names.clone();
        let stopped = self.stopped.clone();
        let remote_log_config = self.remote_log_config.clone();
        let port_config = self.port_config.clone();

        info!(
            "Resolve controller domain name {} {}",
            domain_names[0], ips[0]
        );

        self.thread_handler = Some(thread::spawn(move || {
            while !stopped.swap(false, Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(Self::INTERVAL));

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
                    let (ctrl_ip, ctrl_mac) = get_ctrl_ip_and_mac(ips[0].parse().unwrap());

                    synchronizer.reset_session(
                        ips.clone(),
                        ctrl_ip.to_string(),
                        ctrl_mac.to_string(),
                    );
                    stats_collector.set_remotes(
                        ips.iter()
                            .map(|item| item.parse::<IpAddr>().unwrap())
                            .collect(),
                    );

                    remote_log_config.set_remotes(&ips, port_config.load().analyzer_port);
                }
            }
        }));
    }
}

pub struct Components {
    pub rx_leaky_bucket: Arc<LeakyBucket>,
    pub l7_log_rate: Arc<LeakyBucket>,
    pub libvirt_xml_extractor: Arc<LibvirtXmlExtractor>,
    pub tap_typer: Arc<TapTyper>,
    pub dispatchers: Vec<Dispatcher>,
    pub dispatcher_listeners: Vec<DispatcherListener>,
    pub log_parsers: Vec<AppProtoLogsParser>,
    pub collectors: Vec<CollectorThread>,
    pub l4_flow_uniform_sender: Option<UniformSenderThread>,
    pub metrics_uniform_sender: UniformSenderThread,
    pub l7_flow_uniform_sender: UniformSenderThread,
    pub platform_synchronizer: PlatformSynchronizer,
    pub api_watcher: Arc<ApiWatcher>,
    pub debugger: Debugger,
    pub pcap_manager: WorkerManager,
    pub ebpf_collector: Option<Box<EbpfCollector>>,
    pub running: AtomicBool,
    pub stats_collector: Arc<stats::Collector>,
    pub cgroups_controller: Arc<Cgroups>,
    pub external_metrics_server: MetricServer,
    pub otel_uniform_sender: UniformSenderThread,
    pub prometheus_uniform_sender: UniformSenderThread,
    pub telegraf_uniform_sender: UniformSenderThread,
    pub packet_sequence_parsers: Vec<PacketSequenceParser>, // Enterprise Edition Feature: packet-sequence
    pub packet_sequence_uniform_sender: UniformSenderThread, // Enterprise Edition Feature: packet-sequence
    pub exception_handler: ExceptionHandler,
    pub domain_name_listener: DomainNameListener,
    max_memory: u64,
    tap_mode: TapMode,
}

impl Components {
    fn start(&mut self) {
        info!("Staring components.");
        if self.running.swap(true, Ordering::Relaxed) {
            return;
        }
        self.libvirt_xml_extractor.start();
        self.pcap_manager.start();
        self.platform_synchronizer.start();
        self.api_watcher.start();
        self.debugger.start();
        self.metrics_uniform_sender.start();
        self.l7_flow_uniform_sender.start();

        if let Some(l4_sender) = self.l4_flow_uniform_sender.as_mut() {
            l4_sender.start();
        }

        // Enterprise Edition Feature: packet-sequence
        self.packet_sequence_uniform_sender.start();
        for packet_sequence_parser in self.packet_sequence_parsers.iter() {
            packet_sequence_parser.start();
        }

        match self.tap_mode {
            TapMode::Analyzer => (),
            _ => match free_memory_check(self.max_memory, &self.exception_handler) {
                Ok(()) => {
                    for dispatcher in self.dispatchers.iter() {
                        dispatcher.start();
                    }
                }
                Err(e) => {
                    warn!("{}", e);
                }
            },
        }

        for log_parser in self.log_parsers.iter() {
            log_parser.start();
        }

        for collector in self.collectors.iter_mut() {
            collector.start();
        }
        if let Some(ebpf_collector) = self.ebpf_collector.as_mut() {
            ebpf_collector.start();
        }

        self.otel_uniform_sender.start();
        self.prometheus_uniform_sender.start();
        self.telegraf_uniform_sender.start();
        self.external_metrics_server.start();
        self.domain_name_listener.start();

        info!("Started components.");
    }

    fn new(
        config_handler: &ConfigHandler,
        stats_collector: Arc<stats::Collector>,
        session: &Arc<Session>,
        synchronizer: &Arc<Synchronizer>,
        policy_getter: PolicyGetter,
        exception_handler: ExceptionHandler,
        remote_log_config: RemoteLogConfig,
    ) -> Result<Self> {
        let static_config = &config_handler.static_config;
        let candidate_config = &config_handler.candidate_config;
        let yaml_config = &candidate_config.yaml_config;
        let ctrl_ip = config_handler.ctrl_ip;
        let ctrl_mac = config_handler.ctrl_mac;
        let max_memory = config_handler.candidate_config.environment.max_memory;
        let tap_mode = config_handler.candidate_config.yaml_config.tap_mode;

        trident_process_check();
        controller_ip_check(&static_config.controller_ips);
        check(free_space_checker(
            &static_config.log_file,
            FREE_SPACE_REQUIREMENT,
            exception_handler.clone(),
        ));

        match yaml_config.tap_mode {
            TapMode::Analyzer => todo!(),
            _ => {
                // NPF服务检查
                // TODO: npf (only on windows)
                if yaml_config.tap_mode == TapMode::Mirror {
                    kernel_check();
                }
            }
        }

        // TODO: collector enabled
        // TODO: packet handler builders

        let libvirt_xml_extractor = Arc::new(LibvirtXmlExtractor::new());
        let platform_synchronizer = PlatformSynchronizer::new(
            config_handler.platform(),
            session.clone(),
            libvirt_xml_extractor.clone(),
            exception_handler.clone(),
        );

        let api_watcher = Arc::new(ApiWatcher::new(
            config_handler.platform(),
            session.clone(),
            exception_handler.clone(),
        ));

        let context = ConstructDebugCtx {
            api_watcher: api_watcher.clone(),
            poller: platform_synchronizer.clone_poller(),
            session: session.clone(),
            static_config: synchronizer.static_config.clone(),
            running_config: synchronizer.running_config.clone(),
            status: synchronizer.status.clone(),
            config: config_handler.debug(),
        };
        let debugger = Debugger::new(context);
        let queue_debugger = debugger.clone_queue();

        let (pcap_sender, pcap_receiver, _) = queue::bounded_with_debug(
            config_handler.candidate_config.pcap.queue_size as usize,
            "1-mini-meta-packet-to-pcap",
            &queue_debugger,
        );

        let pcap_manager = WorkerManager::new(
            config_handler.pcap(),
            vec![pcap_receiver],
            stats_collector.clone(),
            synchronizer.ntp_diff(),
        );

        let rx_leaky_bucket = Arc::new(LeakyBucket::new(match yaml_config.tap_mode {
            TapMode::Analyzer => None,
            _ => Some(
                config_handler
                    .candidate_config
                    .dispatcher
                    .global_pps_threshold,
            ),
        }));

        let tap_typer = Arc::new(TapTyper::new());

        let tap_interfaces = match links_by_name_regex(
            &config_handler
                .candidate_config
                .dispatcher
                .tap_interface_regex,
        ) {
            Err(e) => {
                warn!("get interfaces by name regex failed: {}", e);
                vec![]
            }
            Ok(links) if links.is_empty() => {
                warn!(
                    "tap-interface-regex({}) do not match any interface, in local mode",
                    config_handler
                        .candidate_config
                        .dispatcher
                        .tap_interface_regex
                );
                vec![]
            }
            Ok(links) => links,
        };

        // TODO: collector enabled
        let dispatcher_num = yaml_config.src_interfaces.len().max(1);
        let mut dispatchers = vec![];
        let mut dispatcher_listeners = vec![];
        let mut collectors = vec![];
        let mut log_parsers = vec![];
        let mut packet_sequence_parsers = vec![]; // Enterprise Edition Feature: packet-sequence

        // Sender/Collector
        info!(
            "static analyzer ip: {} actual analyzer ip {}",
            yaml_config.analyzer_ip, candidate_config.sender.dest_ip
        );
        let sender_id = 0usize;
        let mut l4_flow_aggr_sender = None;
        let mut l4_flow_uniform_sender = None;
        if config_handler
            .candidate_config
            .collector
            .l4_log_store_tap_types
            .iter()
            .any(|&t| t)
        {
            let (sender, l4_flow_aggr_receiver, counter) = queue::bounded_with_debug(
                yaml_config.flow_sender_queue_size as usize,
                "3-flow-to-collector-sender",
                &queue_debugger,
            );
            stats_collector.register_countable(
                "queue",
                Countable::Owned(Box::new(counter)),
                vec![
                    StatsOption::Tag("module", "3-flow-to-collector-sender".to_string()),
                    StatsOption::Tag("index", sender_id.to_string()),
                ],
            );
            l4_flow_aggr_sender = Some(sender);
            l4_flow_uniform_sender = Some(UniformSenderThread::new(
                sender_id,
                Arc::new(l4_flow_aggr_receiver),
                config_handler.sender(),
                stats_collector.clone(),
                exception_handler.clone(),
            ));
        }

        let sender_id = 1usize;
        let (metrics_sender, metrics_receiver, counter) = queue::bounded_with_debug(
            yaml_config.collector_sender_queue_size,
            "2-doc-to-collector-sender",
            &queue_debugger,
        );
        stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag("module", "2-doc-to-collector-sender".to_string()),
                StatsOption::Tag("index", sender_id.to_string()),
            ],
        );
        let metrics_uniform_sender = UniformSenderThread::new(
            sender_id,
            Arc::new(metrics_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
        );

        let sender_id = 2usize;
        let (proto_log_sender, proto_log_receiver, counter) = queue::bounded_with_debug(
            yaml_config.flow_sender_queue_size,
            "3-protolog-to-collector-sender",
            &queue_debugger,
        );
        stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag("module", "3-protolog-to-collector-sender".to_string()),
                StatsOption::Tag("index", "0".to_string()),
            ],
        );
        let l7_flow_uniform_sender = UniformSenderThread::new(
            sender_id,
            Arc::new(proto_log_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
        );

        // Dispatcher
        let bpf_syntax = if candidate_config.dispatcher.capture_bpf != "" {
            candidate_config.dispatcher.capture_bpf.clone()
        } else {
            let source_ip = match get_route_src_ip(&candidate_config.dispatcher.analyzer_ip) {
                Ok(ip) => ip,
                Err(e) => {
                    warn!(
                        "get route to {} failed: {:?}",
                        candidate_config.dispatcher.analyzer_ip, e
                    );
                    Ipv4Addr::UNSPECIFIED.into()
                }
            };
            bpf::Builder {
                is_ipv6: ctrl_ip.is_ipv6(),
                vxlan_port: yaml_config.vxlan_port,
                controller_port: static_config.controller_port,
                controller_tls_port: static_config.controller_tls_port,
                proxy_controller_ip: candidate_config.dispatcher.proxy_controller_ip,
                analyzer_source_ip: source_ip,
            }
            .build_pcap_syntax()
        };

        let l7_log_rate = Arc::new(LeakyBucket::new(Some(
            candidate_config.log_parser.l7_log_collect_nps_threshold,
        )));

        // Enterprise Edition Feature: packet-sequence
        let sender_id = 6; // TODO sender_id should be generated automatically
        let (packet_sequence_uniform_output, packet_sequence_uniform_input, counter) =
            queue::bounded_with_debug(
                yaml_config.packet_sequence_queue_size,
                "packet_sequence_block-to-sender",
                &queue_debugger,
            );

        stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag("module", "packet_sequence_block-to-sender".to_string()),
                StatsOption::Tag("index", sender_id.to_string()),
            ],
        );
        let packet_sequence_uniform_sender = UniformSenderThread::new(
            sender_id,
            Arc::new(packet_sequence_uniform_input),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
        );

        let bpf_options = Arc::new(Mutex::new(BpfOptions { bpf_syntax }));
        for i in 0..dispatcher_num {
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
                    StatsOption::Tag("index", i.to_string()),
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
                    StatsOption::Tag("index", i.to_string()),
                ],
            );

            let (app_proto_log_parser, counter) = AppProtoLogsParser::new(
                log_receiver,
                proto_log_sender.clone(),
                i as u32,
                config_handler.log_parser(),
                l7_log_rate.clone(),
            );
            stats_collector.register_countable(
                "l7_session_aggr",
                Countable::Ref(Arc::downgrade(&counter) as Weak<dyn RefCountable>),
                vec![StatsOption::Tag("index", i.to_string())],
            );
            log_parsers.push(app_proto_log_parser);

            // Enterprise Edition Feature: packet-sequence
            // create and start packet sequence
            let (packet_sequence_sender, packet_sequence_receiver, counter) =
                queue::bounded_with_debug(
                    yaml_config.packet_sequence_queue_size,
                    "1-packet-sequence-block-to-uniform-collect-sender",
                    &queue_debugger,
                );
            stats_collector.register_countable(
                "queue",
                Countable::Owned(Box::new(counter)),
                vec![
                    StatsOption::Tag(
                        "module",
                        "1-packet-sequence-block-to-uniform-collect-sender".to_string(),
                    ),
                    StatsOption::Tag("index", i.to_string()),
                ],
            );

            let packet_sequence_parser = PacketSequenceParser::new(
                packet_sequence_receiver,
                packet_sequence_uniform_output.clone(),
                i as u32,
            );
            packet_sequence_parsers.push(packet_sequence_parser);

            let dispatcher = DispatcherBuilder::new()
                .id(i)
                .ctrl_mac(ctrl_mac)
                .leaky_bucket(rx_leaky_bucket.clone())
                .options(Arc::new(dispatcher::Options {
                    af_packet_blocks: config_handler.candidate_config.dispatcher.af_packet_blocks,
                    af_packet_version: config_handler.candidate_config.dispatcher.af_packet_version,
                    tap_mode: yaml_config.tap_mode,
                    tap_mac_script: yaml_config.tap_mac_script.clone(),
                    is_ipv6: ctrl_ip.is_ipv6(),
                    vxlan_port: yaml_config.vxlan_port,
                    controller_port: static_config.controller_port,
                    controller_tls_port: static_config.controller_tls_port,
                    handler_builders: vec![PacketHandlerBuilder::Pcap(pcap_sender.clone())],
                    ..Default::default()
                }))
                .bpf_options(bpf_options.clone())
                .default_tap_type(
                    (yaml_config.default_tap_type as u16)
                        .try_into()
                        .unwrap_or(TapType::Tor),
                )
                .mirror_traffic_pcp(yaml_config.mirror_traffic_pcp)
                .tap_typer(tap_typer.clone())
                .analyzer_dedup_disabled(yaml_config.analyzer_dedup_disabled)
                .libvirt_xml_extractor(libvirt_xml_extractor.clone())
                .flow_output_queue(flow_sender)
                .log_output_queue(log_sender)
                .packet_sequence_output_queue(packet_sequence_sender) // Enterprise Edition Feature: packet-sequence
                .stats_collector(stats_collector.clone())
                .flow_map_config(config_handler.flow())
                .policy_getter(policy_getter)
                .platform_poller(platform_synchronizer.clone_poller())
                .exception_handler(exception_handler.clone())
                .ntp_diff(synchronizer.ntp_diff())
                .build()
                .unwrap();

            // TODO: 创建dispatcher的时候处理这些
            let mut dispatcher_listener = dispatcher.listener();
            dispatcher_listener.on_config_change(&candidate_config.dispatcher);
            dispatcher_listener.on_tap_interface_change(
                &tap_interfaces,
                candidate_config.dispatcher.if_mac_source,
                candidate_config.dispatcher.trident_type,
                &vec![],
            );

            dispatchers.push(dispatcher);
            dispatcher_listeners.push(dispatcher_listener);

            // create and start collector
            let collector = Self::new_collector(
                i,
                &stats_collector,
                flow_receiver,
                l4_flow_aggr_sender.clone(),
                metrics_sender.clone(),
                MetricsType::SECOND | MetricsType::MINUTE,
                config_handler,
                &queue_debugger,
                &synchronizer,
            );
            collectors.push(collector);
        }

        let ebpf_collector = EbpfCollector::new(
            synchronizer.ntp_diff(),
            &config_handler.candidate_config.ebpf,
            config_handler.log_parser(),
            policy_getter,
            l7_log_rate.clone(),
            proto_log_sender,
        )
        .ok();
        if let Some(collector) = &ebpf_collector {
            stats_collector.register_countable(
                "ebpf-collector",
                Countable::Owned(Box::new(collector.get_sync_counter())),
                vec![],
            );
        }
        let cgroups_controller: Arc<Cgroups> = Arc::new(Cgroups { cgroup: None });

        let sender_id = 3;
        let (otel_sender, otel_receiver, counter) = queue::bounded_with_debug(
            yaml_config.external_metrics_sender_queue_size,
            "otel-to-sender",
            &queue_debugger,
        );
        stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag("module", "otel-to-sender".to_string()),
                StatsOption::Tag("index", sender_id.to_string()),
            ],
        );
        let otel_uniform_sender = UniformSenderThread::new(
            sender_id,
            Arc::new(otel_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
        );

        let sender_id = 4;
        let (prometheus_sender, prometheus_receiver, counter) = queue::bounded_with_debug(
            yaml_config.external_metrics_sender_queue_size,
            "prometheus-to-sender",
            &queue_debugger,
        );
        stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag("module", "prometheus-to-sender".to_string()),
                StatsOption::Tag("index", sender_id.to_string()),
            ],
        );
        let prometheus_uniform_sender = UniformSenderThread::new(
            sender_id,
            Arc::new(prometheus_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
        );

        let sender_id = 5;
        let (telegraf_sender, telegraf_receiver, counter) = queue::bounded_with_debug(
            yaml_config.external_metrics_sender_queue_size,
            "telegraf-to-sender",
            &queue_debugger,
        );
        stats_collector.register_countable(
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag("module", "telegraf-to-sender".to_string()),
                StatsOption::Tag("index", sender_id.to_string()),
            ],
        );
        let telegraf_uniform_sender = UniformSenderThread::new(
            sender_id,
            Arc::new(telegraf_receiver),
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
        );

        let external_metrics_server = MetricServer::new(
            otel_sender,
            prometheus_sender,
            telegraf_sender,
            config_handler.metric_server(),
            exception_handler.clone(),
        );

        let domain_name_listener = DomainNameListener::new(
            stats_collector.clone(),
            synchronizer.clone(),
            remote_log_config,
            config_handler.static_config.controller_domain_name.clone(),
            config_handler.static_config.controller_ips.clone(),
            config_handler.port(),
        );

        Ok(Components {
            rx_leaky_bucket,
            l7_log_rate,
            libvirt_xml_extractor,
            tap_typer,
            dispatchers,
            dispatcher_listeners,
            collectors,
            l4_flow_uniform_sender,
            metrics_uniform_sender,
            l7_flow_uniform_sender,
            platform_synchronizer,
            api_watcher,
            debugger,
            pcap_manager,
            log_parsers,
            ebpf_collector,
            stats_collector,
            running: AtomicBool::new(false),
            cgroups_controller,
            external_metrics_server,
            exception_handler,
            max_memory,
            otel_uniform_sender,
            prometheus_uniform_sender,
            telegraf_uniform_sender,
            tap_mode,
            packet_sequence_uniform_sender, // Enterprise Edition Feature: packet-sequence
            packet_sequence_parsers,        // Enterprise Edition Feature: packet-sequence
            domain_name_listener,
        })
    }

    fn new_collector(
        id: usize,
        stats_collector: &Arc<stats::Collector>,
        flow_receiver: queue::Receiver<Box<TaggedFlow>>,
        l4_flow_aggr_sender: Option<queue::DebugSender<SendItem>>,
        metrics_sender: queue::DebugSender<SendItem>,
        metrics_type: MetricsType,
        config_handler: &ConfigHandler,
        queue_debugger: &QueueDebugger,
        synchronizer: &Arc<Synchronizer>,
    ) -> CollectorThread {
        let yaml_config = &config_handler.candidate_config.yaml_config;
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

        let (mut l4_log_sender, mut l4_log_receiver) = (None, None);
        if l4_flow_aggr_sender.is_some() {
            let (l4_flow_sender, l4_flow_receiver, counter) = queue::bounded_with_debug(
                yaml_config.flow.aggr_queue_size as usize,
                "2-second-flow-to-minute-aggrer",
                queue_debugger,
            );
            stats_collector.register_countable(
                "queue",
                Countable::Owned(Box::new(counter)),
                vec![
                    StatsOption::Tag("module", "2-second-flow-to-minute-aggrer".to_string()),
                    StatsOption::Tag("index", id.to_string()),
                ],
            );
            l4_log_sender = Some(l4_flow_sender);
            l4_log_receiver = Some(l4_flow_receiver);
        }

        // FIXME: 应该让flowgenerator和dispatcher解耦，并提供Delay函数用于此处
        // QuadrupleGenerator的Delay组成部分：
        //   FlowGen中流统计数据固有的Delay：_FLOW_STAT_INTERVAL + packetDelay
        //   FlowGen中InjectFlushTicker的额外Delay：_TIME_SLOT_UNIT
        //   FlowGen中输出队列Flush的Delay：flushInterval
        //   FlowGen中其它处理流程可能产生的Delay: 5s
        let second_quadruple_tolerable_delay = (yaml_config.packet_delay.as_secs()
            + 1
            + yaml_config.flow.flush_interval.as_secs()
            + 5)
            + yaml_config.second_flow_extra_delay.as_secs();
        let minute_quadruple_tolerable_delay = (60 + yaml_config.packet_delay.as_secs())
            + 1
            + yaml_config.flow.flush_interval.as_secs()
            + 5;

        let quadruple_generator = QuadrupleGeneratorThread::new(
            id,
            flow_receiver,
            second_sender,
            minute_sender,
            l4_log_sender,
            (yaml_config.flow.hash_slots << 3) as usize, // connection_lru_capacity
            metrics_type,
            second_quadruple_tolerable_delay,
            minute_quadruple_tolerable_delay,
            1 << 18, // possible_host_size
            config_handler.collector(),
            synchronizer.ntp_diff(),
        );

        let mut l4_flow_aggr = None;
        if let Some(l4_log_receiver) = l4_log_receiver {
            l4_flow_aggr = Some(FlowAggrThread::new(
                id,                                   // id
                l4_log_receiver,                      // input
                l4_flow_aggr_sender.unwrap().clone(), // output
                config_handler.collector(),
            ));
        }

        let (mut second_collector, mut minute_collector) = (None, None);
        if metrics_type.contains(MetricsType::SECOND) {
            second_collector = Some(Collector::new(
                id as u32,
                second_receiver,
                metrics_sender.clone(),
                MetricsType::SECOND,
                second_quadruple_tolerable_delay as u32,
                stats_collector,
                config_handler.collector(),
                synchronizer.ntp_diff(),
            ));
        }
        if metrics_type.contains(MetricsType::MINUTE) {
            minute_collector = Some(Collector::new(
                id as u32,
                minute_receiver,
                metrics_sender,
                MetricsType::MINUTE,
                minute_quadruple_tolerable_delay as u32,
                stats_collector,
                config_handler.collector(),
                synchronizer.ntp_diff(),
            ));
        }

        CollectorThread::new(
            quadruple_generator,
            l4_flow_aggr,
            second_collector,
            minute_collector,
        )
    }

    fn stop(&mut self) {
        info!("Stopping components.");

        if !self.running.swap(false, Ordering::Relaxed) {
            return;
        }

        for d in self.dispatchers.iter_mut() {
            d.stop();
        }
        self.platform_synchronizer.stop();
        self.api_watcher.stop();

        // TODO: collector
        for q in self.collectors.iter_mut() {
            q.stop();
        }

        for p in self.log_parsers.iter() {
            p.stop();
        }

        if let Some(l4_flow_uniform_sender) = self.l4_flow_uniform_sender.as_mut() {
            l4_flow_uniform_sender.stop();
        }
        self.metrics_uniform_sender.stop();
        self.l7_flow_uniform_sender.stop();

        self.libvirt_xml_extractor.stop();
        self.pcap_manager.stop();
        self.debugger.stop();
        if let Some(ebpf_collector) = self.ebpf_collector.as_mut() {
            ebpf_collector.stop();
        }
        match self.cgroups_controller.stop() {
            Ok(_) => {
                info!("stopped cgroups_controller");
            }
            Err(e) => {
                warn!("stop cgroups_controller failed: {}", e);
            }
        }

        self.external_metrics_server.stop();
        self.otel_uniform_sender.stop();
        self.prometheus_uniform_sender.stop();
        self.telegraf_uniform_sender.stop();
        self.packet_sequence_uniform_sender.stop(); // Enterprise Edition Feature: packet-sequence
        self.domain_name_listener.stop();

        info!("Stopped components.")
    }
}
