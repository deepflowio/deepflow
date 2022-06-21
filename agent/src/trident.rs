use std::env;
use std::mem;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Condvar, Mutex, Weak,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use flexi_logger::{
    colored_opt_format, Age, Cleanup, Criterion, Duplicate, FileSpec, Logger, LoggerHandle, Naming,
};
use log::{info, warn};

use crate::common::DropletMessageType;
use crate::debug::QueueDebugger;
use crate::exception::ExceptionHandler;
use crate::external_metrics::MetricServer;
use crate::handler::PacketHandlerBuilder;
use crate::pcap::WorkerManager;
use crate::utils::cgroups::Cgroups;
use crate::utils::guard::Guard;
use crate::{
    collector::Collector,
    collector::{
        flow_aggr::FlowAggrThread, quadruple_generator::QuadrupleGeneratorThread, CollectorThread,
        MetricsType,
    },
    common::{
        enums::TapType, platform_data::PlatformData, tagged_flow::TaggedFlow, tap_types::TapTyper,
        DEFAULT_LOG_RETENTION, DROPLET_PORT, FREE_SPACE_REQUIREMENT,
    },
    config::{
        handler::{ConfigHandler, DispatcherConfig},
        Config, RuntimeConfig, YamlConfig,
    },
    debug::{ConstructDebugCtx, Debugger},
    dispatcher::{
        self, recv_engine::bpf, BpfOptions, Dispatcher, DispatcherBuilder, DispatcherListener,
    },
    ebpf_collector::EbpfCollector,
    flow_generator::AppProtoLogsParser,
    monitor::Monitor,
    platform::{ApiWatcher, LibvirtXmlExtractor, PlatformSynchronizer},
    policy::{Policy, PolicyGetter},
    proto::trident::TapMode,
    rpc::{Session, Synchronizer, DEFAULT_TIMEOUT},
    sender::{uniform_sender::UniformSenderThread, SendItem},
    utils::{
        environment::{
            check, controller_ip_check, free_memory_checker, free_space_checker, kernel_check,
            trident_process_check,
        },
        logger::{RemoteLogConfig, RemoteLogWriter},
        net::{get_route_src_ip, get_route_src_ip_and_mac, links_by_name_regex},
        queue,
        stats::{self, Countable, RefCountable, StatsOption},
        LeakyBucket,
    },
};

const MINUTE: Duration = Duration::from_secs(60);

pub enum State {
    Running,
    ConfigChanged((RuntimeConfig, Vec<PlatformData>)),
    Terminated,
    Disabled, // 禁用状态
}

impl State {
    fn unwrap_config(self) -> (RuntimeConfig, Vec<PlatformData>) {
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

impl Trident {
    pub fn start<P: AsRef<Path>>(config_path: P, revision: String) -> Result<Trident> {
        let state = Arc::new((Mutex::new(State::Running), Condvar::new()));
        let state_thread = state.clone();

        let config = Config::load_from_file(config_path.as_ref())?;
        let base_name = Path::new(&env::args().next().unwrap())
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let (remote_log_writer, remote_log_config) = RemoteLogWriter::new(
            &config.controller_ips,
            DROPLET_PORT,
            base_name,
            vec![0, 0, 0, 0, DropletMessageType::Syslog as u8],
        );

        let mut logger = Logger::try_with_str("info")
            .unwrap()
            .format(colored_opt_format)
            .log_to_file_and_writer(
                FileSpec::try_from(&config.log_file)?,
                Box::new(remote_log_writer),
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

        info!("static_config {:#?}", config);
        let handle = Some(thread::spawn(move || {
            if let Err(e) = Self::run(
                state_thread,
                config,
                revision,
                logger_handle,
                remote_log_config,
            ) {
                warn!("metaflow-agent exited: {}", e);
                process::exit(1);
            }
        }));

        Ok(Trident { state, handle })
    }

    fn run(
        state: TridentState,
        config: Config,
        revision: String,
        logger_handle: LoggerHandle,
        remote_log_config: RemoteLogConfig,
    ) -> Result<()> {
        info!("========== MetaFlowAgent start! ==========");

        let (ctrl_ip, ctrl_mac) = get_route_src_ip_and_mac(&config.controller_ips[0].parse()?)
            .context("failed getting control ip and mac")?;
        let stats_collector = Arc::new(stats::Collector::new(&config.controller_ips));
        stats_collector.start();

        let exception_handler = ExceptionHandler::default();
        let session = Arc::new(Session::new(
            config.controller_port,
            config.controller_tls_port,
            DEFAULT_TIMEOUT,
            config.controller_cert_file_prefix.clone(),
            config.controller_ips.clone(),
            exception_handler.clone(),
        ));

        let default_runtime_config = RuntimeConfig::default();
        // 目前仅支持local-mod + ebpf-collector，ebpf-collector不适用fast, 所以队列数为1
        let (policy_setter, policy_getter) = Policy::new(
            1,
            default_runtime_config.yaml_config.first_path_level as usize,
            default_runtime_config.yaml_config.fast_path_map_size,
            false,
        );

        let mut config_handler =
            ConfigHandler::new(config, ctrl_ip, ctrl_mac, logger_handle, remote_log_config);

        let synchronizer = Arc::new(Synchronizer::new(
            session.clone(),
            state.clone(),
            revision.clone(),
            ctrl_ip.to_string(),
            ctrl_mac.to_string(),
            config_handler.static_config.controller_ips[0].clone(),
            config_handler.static_config.vtap_group_id_request.clone(),
            config_handler.static_config.kubernetes_cluster_id.clone(),
            policy_setter,
            exception_handler.clone(),
        ));
        synchronizer.start();

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
    blacklist: Vec<PlatformData>,
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
    pub monitor: Monitor,
    pub platform_synchronizer: PlatformSynchronizer,
    pub api_watcher: Arc<ApiWatcher>,
    pub debugger: Debugger,
    pub pcap_manager: WorkerManager,
    pub guard: Guard,
    pub ebpf_collector: Option<Box<EbpfCollector>>,
    pub running: AtomicBool,
    pub stats_collector: Arc<stats::Collector>,
    pub cgroups_controller: Arc<Cgroups>,
    pub external_metrics_server: MetricServer,
    pub otel_uniform_sender: UniformSenderThread,
    pub prometheus_uniform_sender: UniformSenderThread,
    pub telegraf_uniform_sender: UniformSenderThread,
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

        for dispatcher in self.dispatchers.iter() {
            dispatcher.start();
        }

        for log_parser in self.log_parsers.iter() {
            log_parser.start();
        }

        for collector in self.collectors.iter_mut() {
            collector.start();
        }
        self.monitor.start();
        self.guard.start();
        if let Some(ebpf_collector) = self.ebpf_collector.as_mut() {
            ebpf_collector.start();
        }

        self.otel_uniform_sender.start();
        self.prometheus_uniform_sender.start();
        self.telegraf_uniform_sender.start();
        self.external_metrics_server.start();

        info!("Started components.");
    }

    fn new(
        config_handler: &ConfigHandler,
        stats_collector: Arc<stats::Collector>,
        session: &Arc<Session>,
        synchronizer: &Arc<Synchronizer>,
        policy_getter: PolicyGetter,
        exception_handler: ExceptionHandler,
    ) -> Result<Self> {
        let static_config = &config_handler.static_config;
        let candidate_config = &config_handler.candidate_config;
        let yaml_config = &candidate_config.yaml_config;
        let ctrl_ip = config_handler.ctrl_ip;
        let ctrl_mac = config_handler.ctrl_mac;

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
                check(free_memory_checker(
                    config_handler.candidate_config.environment.max_memory,
                    exception_handler.clone(),
                ));
                info!("Complete memory check");

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
        );

        let api_watcher = Arc::new(ApiWatcher::new(config_handler.platform(), session.clone()));

        let context = ConstructDebugCtx {
            api_watcher: api_watcher.clone(),
            poller: platform_synchronizer.clone_poller(),
            session: session.clone(),
            static_config: synchronizer.static_config.clone(),
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
                l4_flow_aggr_receiver,
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
            metrics_receiver,
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
            proto_log_receiver,
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
                synchronizer,
            );
            collectors.push(collector);
        }

        let log_dir = Path::new(static_config.log_file.as_str());
        let log_dir = log_dir.parent().unwrap().to_str().unwrap();
        let monitor = Monitor::new(stats_collector.clone(), log_dir.to_string())?;
        let guard = Guard::new(
            config_handler.environment(),
            log_dir.to_string(),
            exception_handler.clone(),
        );

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
            otel_receiver,
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
            prometheus_receiver,
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
            telegraf_receiver,
            config_handler.sender(),
            stats_collector.clone(),
            exception_handler.clone(),
        );

        let external_metrics_server = MetricServer::new(
            otel_sender,
            prometheus_sender,
            telegraf_sender,
            config_handler.metric_server(),
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
            monitor,
            platform_synchronizer,
            api_watcher,
            debugger,
            pcap_manager,
            log_parsers,
            guard,
            ebpf_collector,
            stats_collector,
            running: AtomicBool::new(false),
            cgroups_controller,
            external_metrics_server,
            otel_uniform_sender,
            prometheus_uniform_sender,
            telegraf_uniform_sender,
        })
    }

    fn new_collector(
        id: usize,
        stats_collector: &Arc<stats::Collector>,
        flow_receiver: queue::Receiver<TaggedFlow>,
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
        self.monitor.stop();
        self.guard.stop();
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

        info!("Stopped components.")
    }
}
