use std::mem;
use std::net::IpAddr;
use std::path::Path;
use std::process;
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    Arc, Condvar, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use flexi_logger::{
    colored_opt_format, Age, Cleanup, Criterion, Duplicate, FileSpec, Logger, Naming,
};
use log::{info, warn};

use crate::handler::PacketHandlerBuilder;
use crate::pcap::WorkerManager;
use crate::{
    collector::Collector,
    collector::{
        flow_aggr::FlowAggrThread, quadruple_generator::QuadrupleGeneratorThread, CollectorThread,
        MetricsType,
    },
    common::{
        enums::TapType, tagged_flow::TaggedFlow, tap_types::TapTyper, DEFAULT_LIBVIRT_XML_PATH,
        FREE_SPACE_REQUIREMENT,
    },
    config::{Config, RuntimeConfig},
    debug::{ConstructDebugCtx, Debugger},
    dispatcher::{
        self,
        recv_engine::{self, bpf},
        BpfOptions, Dispatcher, DispatcherBuilder, DispatcherListener,
    },
    flow_generator::{
        AppProtoLogsParser, FlowMapConfig, FlowMapRuntimeConfig, FlowTimeout, TcpTimeout,
    },
    monitor::Monitor,
    platform::{ApiWatcher, LibvirtXmlExtractor, PlatformSynchronizer},
    proto::trident::TapMode,
    rpc::{Session, Synchronizer, DEFAULT_TIMEOUT},
    sender::{uniform_sender::UniformSenderThread, SendItem},
    utils::{
        environment::{
            check, controller_ip_check, free_memory_checker, free_space_checker, kernel_check,
            trident_process_check,
        },
        net::{get_route_src_ip, get_route_src_ip_and_mac, links_by_name_regex, MacAddr},
        queue,
        stats::{self, StatsOption},
        LeakyBucket,
    },
};

const MINUTE: Duration = Duration::from_secs(60);

pub enum State {
    Running,
    ConfigChanged(RuntimeConfig),
    Terminated,
}

impl State {
    fn unwrap_config(self) -> RuntimeConfig {
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

        let config = Config::load_from_file(config_path)?;

        let mut logger = Logger::try_with_str("info")?
            .format_for_files(colored_opt_format)
            .log_to_file(FileSpec::try_from(&config.log_file)?)
            .rotate(Criterion::Age(Age::Day), Naming::Timestamps, Cleanup::Never)
            .create_symlink(&config.log_file)
            .append();
        if nix::unistd::getppid().as_raw() != 1 {
            logger = logger.duplicate_to_stderr(Duplicate::All);
        }
        logger.start()?;

        let handle = Some(thread::spawn(move || {
            if let Err(e) = Self::run(state_thread, config, revision) {
                warn!("trident exited: {}", e);
                process::exit(1);
            }
        }));

        Ok(Trident { state, handle })
    }

    fn run(state: TridentState, config: Config, revision: String) -> Result<()> {
        info!("========== MetaFlowAgent start! ==========");

        let (ctrl_ip, ctrl_mac) = get_route_src_ip_and_mac(&config.controller_ips[0].parse()?)
            .context("failed getting control ip and mac")?;

        let stats_collector = Arc::new(stats::Collector::new(&config.controller_ips));
        stats_collector.start();

        let session = Arc::new(Session::new(
            config.controller_port,
            config.controller_tls_port,
            DEFAULT_TIMEOUT,
            config.controller_cert_file_prefix.clone(),
            config.controller_ips.clone(),
        ));
        let synchronizer = Arc::new(Synchronizer::new(
            session.clone(),
            state.clone(),
            revision.clone(),
            ctrl_ip.to_string(),
            ctrl_mac.to_string(),
            config.vtap_group_id_request.clone(),
            config.kubernetes_cluster_id.clone(),
        ));
        stats_collector.register_countable("synchronizer", synchronizer.clone(), vec![]);
        synchronizer.start();

        let (state, cond) = &*state;
        let mut state_guard = state.lock().unwrap();
        let mut components = None;
        let mut config_handler = ConfigHandler::new(&synchronizer, ctrl_ip, ctrl_mac, config);

        loop {
            match &*state_guard {
                State::Running => {
                    state_guard = cond.wait(state_guard).unwrap();
                    continue;
                }
                State::Terminated => return Ok(()),
                _ => (),
            }
            let mut new_state = State::Running;
            mem::swap(&mut new_state, &mut *state_guard);
            mem::drop(state_guard);

            let new_config = new_state.unwrap_config();
            let restart_dispatcher =
                Self::update_config(&mut config_handler, new_config, &mut components);

            if restart_dispatcher {
                if let Some(c) = components.take() {
                    c.stop();
                    // TODO: reset fast path
                }
            }
            if config_handler.runtime_config.enabled != components.is_some() {
                if config_handler.runtime_config.enabled {
                    info!("Current Revision: {}", &revision);
                    match Components::start(
                        &config_handler,
                        &stats_collector,
                        &session,
                        &synchronizer,
                    ) {
                        Ok(c) => components = Some(c),
                        Err(e) => warn!("start dispatcher failed: {}", e),
                    }
                } else {
                    components.take().unwrap().stop();
                }
            }

            state_guard = state.lock().unwrap();
        }
    }

    // returns dispatcher need restart
    fn update_config(
        config_handler: &mut ConfigHandler,
        new_config: RuntimeConfig,
        components: &mut Option<Components>,
    ) -> bool {
        let static_config = &config_handler.static_config;
        let runtime_config = &mut config_handler.runtime_config;

        let mut restart_dispatcher = false;
        if runtime_config.enabled != new_config.enabled {
            runtime_config.enabled = new_config.enabled;
            info!("Enabled set to {}", new_config.enabled);
        }
        if runtime_config.global_pps_threshold != new_config.global_pps_threshold {
            runtime_config.global_pps_threshold = new_config.global_pps_threshold;
            if let Some(components) = components.as_mut() {
                match static_config.tap_mode {
                    TapMode::Analyzer => {
                        components.rx_leaky_bucket.set_rate(None);
                        info!("Global pps set unlimit when tap_mode=analyzer");
                    }
                    _ => {
                        components
                            .rx_leaky_bucket
                            .set_rate(Some(runtime_config.global_pps_threshold));
                        info!(
                            "Global pps threshold change to {}",
                            runtime_config.global_pps_threshold
                        );
                    }
                }
            }
        }

        if runtime_config.inactive_server_port_enabled != new_config.inactive_server_port_enabled {
            config_handler
                .collector
                .inactive_server_port_enabled
                .store(new_config.inactive_server_port_enabled, Ordering::Relaxed);
            info!(
                "inactive_server_port_enabled set to {}",
                new_config.inactive_server_port_enabled
            );
        }

        // TODO: update other configs and remove the next line
        *runtime_config = new_config;
        restart_dispatcher
    }

    pub fn stop(&mut self) {
        info!("Gracefully stopping");
        let (state, cond) = &*self.state;

        let mut state_guard = state.lock().unwrap();
        *state_guard = State::Terminated;
        cond.notify_one();
        mem::drop(state_guard);
        self.handle.take().unwrap().join().unwrap();
    }

    fn get_af_packet_blocks(config: &Config, mem_size: u64) -> usize {
        if config.tap_mode == TapMode::Analyzer || config.af_packet_blocks_enabled {
            config.af_packet_blocks.max(8)
        } else {
            (mem_size as usize / recv_engine::DEFAULT_BLOCK_SIZE / 16).min(128)
        }
    }
}

struct Components {
    source_ip: IpAddr,
    rx_leaky_bucket: Arc<LeakyBucket>,
    libvirt_xml_extractor: Arc<LibvirtXmlExtractor>,
    tap_typer: Arc<TapTyper>,
    dispatchers: Vec<Dispatcher>,
    dispatcher_listeners: Vec<DispatcherListener>,
    log_parsers: Vec<AppProtoLogsParser>,
    collectors: Vec<CollectorThread>,
    l4_flow_uniform_sender: Option<UniformSenderThread>,
    metrics_uniform_sender: UniformSenderThread,
    l7_flow_uniform_sender: UniformSenderThread,
    monitor: Monitor,
    platform_synchronizer: PlatformSynchronizer,
    api_watcher: Arc<ApiWatcher>,
    debugger: Debugger,
    pcap_manager: WorkerManager,
}

impl Components {
    fn start(
        config_handler: &ConfigHandler,
        stats_collector: &Arc<stats::Collector>,
        session: &Arc<Session>,
        synchronizer: &Arc<Synchronizer>,
    ) -> Result<Self> {
        let static_config = &config_handler.static_config;
        let runtime_config = &config_handler.runtime_config;
        let ctrl_ip = config_handler.ctrl_ip;
        let ctrl_mac = config_handler.ctrl_mac;

        info!("start dispatcher");
        trident_process_check();
        controller_ip_check(&static_config.controller_ips);
        check(free_space_checker(
            &static_config.log_file,
            FREE_SPACE_REQUIREMENT,
        ));

        if !static_config.controller_ips.is_empty() && static_config.analyzer_ip != "" {
            warn!("Static config controller-ips({}) and analyzer-ip({}) will replace proxy-controller-ip and analyzer-ip.",
                static_config.controller_ips[0], static_config.analyzer_ip);
        }
        let analyzer_ip = runtime_config
            .analyzer_ip
            .parse()
            .with_context(|| format!("parse analyzer_ip {} failed", runtime_config.analyzer_ip))?;
        let source_ip = get_route_src_ip(&analyzer_ip)?;

        match static_config.tap_mode {
            TapMode::Analyzer => todo!(),
            _ => {
                check(free_memory_checker(
                    config_handler.environment.max_memory.clone(),
                ));
                info!("Complete memory check");

                // NPF服务检查
                // TODO: npf (only on windows)
                if static_config.tap_mode == TapMode::Mirror {
                    kernel_check();
                }
            }
        }

        // TODO: collector enabled
        // TODO: packet handler builders
        let libvirt_xml_extractor = Arc::new(LibvirtXmlExtractor::new());
        libvirt_xml_extractor.start();

        let pcap_config = &static_config.pcap;
        let (pcap_sender, pcap_receiver, _) =
            queue::bounded(static_config.pcap.queue_size as usize);

        let pcap_manager = WorkerManager::new(
            pcap_config.block_size_kb,
            pcap_config.max_concurrent_files,
            pcap_config.max_file_size_mb,
            pcap_config.max_file_period,
            &pcap_config.file_directory,
            pcap_config.max_file_period,
            vec![pcap_receiver],
            stats_collector.clone(),
        );
        pcap_manager.start();

        let platform_synchronizer = PlatformSynchronizer::new(
            MINUTE,
            static_config.kubernetes_poller_type,
            static_config
                .controller_ips
                .first()
                .unwrap()
                .parse::<IpAddr>()
                .unwrap(),
            DEFAULT_LIBVIRT_XML_PATH,
            static_config.kubernetes_cluster_id.clone(),
            runtime_config.trident_type,
            session.clone(),
            libvirt_xml_extractor.clone(),
        );

        platform_synchronizer.start();

        let api_watcher = Arc::new(ApiWatcher::new(
            static_config
                .controller_ips
                .first()
                .unwrap()
                .parse::<IpAddr>()
                .unwrap(),
            static_config.kubernetes_cluster_id.clone(),
            static_config.ingress_flavour,
            MINUTE,
            session.clone(),
        ));

        api_watcher.start();

        let context = ConstructDebugCtx {
            vtap_id: runtime_config.vtap_id,
            api_watcher: api_watcher.clone(),
            poller: platform_synchronizer.clone_poller(),
            session: session.clone(),
            static_config: synchronizer.static_config.clone(),
            status: synchronizer.status.clone(),
            controller_ips: static_config
                .controller_ips
                .iter()
                .map(|c| c.parse::<IpAddr>().unwrap())
                .collect(),
        };
        let debugger = Debugger::new(context);
        debugger.start();

        let bpf_syntax = bpf::Builder {
            is_ipv6: ctrl_ip.is_ipv6(),
            vxlan_port: static_config.vxlan_port,
            controller_port: static_config.controller_port,
            controller_tls_port: static_config.controller_tls_port,
            proxy_controller_ip: runtime_config.proxy_controller_ip.parse()?,
            analyzer_source_ip: source_ip,
        }
        .build_pcap_syntax();

        let bpf_options = Arc::new(Mutex::new(BpfOptions { bpf_syntax }));

        let rx_leaky_bucket = Arc::new(LeakyBucket::new(match static_config.tap_mode {
            TapMode::Analyzer => None,
            _ => Some(runtime_config.global_pps_threshold),
        }));

        let flow_map_config = {
            let flow_config = &static_config.flow;

            let mut l7_log_tap_types = [false; 256];
            for &tap in runtime_config.l7_log_store_tap_types.iter() {
                if tap < 256 {
                    l7_log_tap_types[tap as usize] = true;
                }
            }

            FlowMapConfig {
                tap_types: l7_log_tap_types,
                vtap_id: runtime_config.vtap_id,
                trident_type: runtime_config.trident_type,
                collector_enabled: runtime_config.collector_enabled,
                packet_delay: static_config.packet_delay,
                flush_interval: flow_config.flush_interval,
                ignore_l2_end: flow_config.ignore_l2_end,
                ignore_tor_mac: flow_config.ignore_tor_mac,
                cloud_gateway_traffic: static_config.cloud_gateway_traffic,
                flow_timeout: FlowTimeout::from(TcpTimeout {
                    established: flow_config.established_timeout,
                    closing_rst: flow_config.closing_rst_timeout,
                    others: flow_config.others_timeout,
                }),
                runtime_config: Arc::new(FlowMapRuntimeConfig {
                    l7_metrics_enabled: AtomicBool::new(runtime_config.l7_metrics_enabled),
                    l4_performance_enabled: AtomicBool::new(runtime_config.l4_performance_enabled),
                    app_proto_log_enabled: AtomicBool::new(
                        runtime_config.l7_log_store_tap_types.is_empty(),
                    ),
                    l7_log_packet_size: AtomicU32::new(runtime_config.l7_log_packet_size),
                }),
            }
        };

        let tap_typer = Arc::new(TapTyper::new());

        let tap_interfaces = match links_by_name_regex(&runtime_config.tap_interface_regex) {
            Err(e) => {
                warn!("get interfaces by name regex failed: {}", e);
                vec![]
            }
            Ok(links) if links.is_empty() => {
                warn!(
                    "tap-interface-regex({}) do not match any interface, in local mode",
                    runtime_config.tap_interface_regex
                );
                vec![]
            }
            Ok(links) => links,
        };

        // TODO: collector enabled
        let dispatcher_num = static_config.src_interfaces.len().max(1);
        let mut dispatchers = vec![];
        let mut dispatcher_listeners = vec![];
        let mut collectors = vec![];
        let mut log_parsers = vec![];
        let queue_debugger = debugger.clone_queue();

        let dst_ip = Arc::new(Mutex::new(
            IpAddr::from_str(&runtime_config.analyzer_ip).unwrap(),
        ));
        info!("analyzer_ip: {}", *dst_ip.lock().unwrap());
        let sender_id = 0usize;
        let mut l4_flow_aggr_sender = None;
        let mut l4_flow_uniform_sender = None;
        if runtime_config.l4_log_store_tap_types.len() > 0 {
            let (sender, l4_flow_aggr_receiver, counter) =
                queue::bounded(static_config.flow.aggr_queue_size as usize);
            stats_collector.register_countable(
                "3-flow-to-collector-sender",
                Arc::new(counter),
                vec![StatsOption::Tag("index", sender_id.to_string())],
            );
            l4_flow_aggr_sender = Some(sender);
            l4_flow_uniform_sender = Some(UniformSenderThread::new(
                sender_id,
                runtime_config.vtap_id,
                l4_flow_aggr_receiver,
                dst_ip.clone(),
            ));
            l4_flow_uniform_sender.as_mut().unwrap().start();
        }

        let sender_id = 1usize;
        let (metrics_sender, metrics_receiver, counter) =
            queue::bounded(static_config.collector_sender_queue_size);
        stats_collector.register_countable(
            "2-doc-to-collector-sender",
            Arc::new(counter),
            vec![StatsOption::Tag("index", sender_id.to_string())],
        );
        let mut metrics_uniform_sender = UniformSenderThread::new(
            sender_id,
            runtime_config.vtap_id,
            metrics_receiver,
            dst_ip.clone(),
        );
        metrics_uniform_sender.start();

        let sender_id = 2usize;
        let (proto_log_sender, proto_log_receiver, counter) = queue::bounded_with_debug(
            static_config.flow_sender_queue_size,
            "3-protolog-to-collector-sender",
            &queue_debugger,
        );
        stats_collector.register_countable(
            "3-protolog-to-collector-sender",
            Arc::new(counter),
            vec![],
        );
        let mut l7_flow_uniform_sender = UniformSenderThread::new(
            sender_id,
            runtime_config.vtap_id,
            proto_log_receiver,
            dst_ip,
        );
        l7_flow_uniform_sender.start();

        for i in 0..dispatcher_num {
            let (flow_sender, flow_receiver, counter) =
                queue::bounded(static_config.flow_queue_size);
            stats_collector.register_countable(
                "1-tagged-flow-to-quadruple-generator",
                Arc::new(counter),
                vec![StatsOption::Tag("index", i.to_string())],
            );

            // create and start app proto logs
            let (log_sender, log_receiver, counter) = queue::bounded(static_config.flow_queue_size);
            stats_collector.register_countable(
                "1-tagged-flow-to-app-protocol-logs",
                Arc::new(counter),
                vec![StatsOption::Tag("index", i.to_string())],
            );

            let (app_proto_log_parser, counter) = AppProtoLogsParser::new(
                log_receiver,
                runtime_config.l7_log_collect_nps_threshold as usize,
                static_config.l7_log_session_aggr_timeout,
                proto_log_sender.clone(),
                i as u32,
                synchronizer.clone_http_config(),
            );
            stats_collector.register_countable(
                "l7_session_aggr",
                counter,
                vec![StatsOption::Tag("index", i.to_string())],
            );
            app_proto_log_parser.start();
            log_parsers.push(app_proto_log_parser);

            let dispatcher = DispatcherBuilder::new()
                .id(i)
                .ctrl_mac(ctrl_mac)
                .leaky_bucket(rx_leaky_bucket.clone())
                .options(Arc::new(dispatcher::Options {
                    af_packet_blocks: Trident::get_af_packet_blocks(
                        &static_config,
                        runtime_config.max_memory,
                    ),
                    af_packet_version: runtime_config.capture_socket_type.into(),
                    tap_mode: static_config.tap_mode,
                    tap_mac_script: static_config.tap_mac_script.clone(),
                    is_ipv6: ctrl_ip.is_ipv6(),
                    vxlan_port: static_config.vxlan_port,
                    controller_port: static_config.controller_port,
                    controller_tls_port: static_config.controller_tls_port,
                    handler_builders: vec![PacketHandlerBuilder::Pcap(pcap_sender.clone())],
                    ..Default::default()
                }))
                .bpf_options(bpf_options.clone())
                .default_tap_type(
                    (static_config.default_tap_type as u16)
                        .try_into()
                        .unwrap_or(TapType::Tor),
                )
                .mirror_traffic_pcp(static_config.mirror_traffic_pcp)
                .tap_typer(tap_typer.clone())
                .analyzer_dedup_disabled(static_config.analyzer_dedup_disabled)
                .libvirt_xml_extractor(libvirt_xml_extractor.clone())
                .flow_output_queue(flow_sender)
                .log_output_queue(log_sender)
                .flow_map_config(flow_map_config.clone())
                .stats_collector(stats_collector.clone())
                .build()
                .unwrap();

            // TODO: 创建dispatcher的时候处理这些
            let mut dispatcher_listener = dispatcher.listener();
            dispatcher_listener.on_config_change(&runtime_config);
            dispatcher_listener.on_tap_interface_change(
                &tap_interfaces,
                runtime_config.if_mac_source,
                runtime_config.trident_type,
                &vec![],
            );

            dispatcher.start();
            dispatchers.push(dispatcher);
            dispatcher_listeners.push(dispatcher_listener);

            // create and start collector
            let mut collector = Self::new_collector(
                i,
                stats_collector,
                static_config,
                runtime_config,
                flow_receiver,
                l4_flow_aggr_sender.clone(),
                metrics_sender.clone(),
                MetricsType::SECOND | MetricsType::MINUTE,
                config_handler
                    .collector
                    .inactive_server_port_enabled
                    .clone(),
            );
            collector.start();
            collectors.push(collector);
        }

        let monitor = Monitor::new(stats_collector.clone())?;
        monitor.start();

        Ok(Components {
            source_ip,
            rx_leaky_bucket,
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
        })
    }

    fn new_collector(
        id: usize,
        stats_collector: &Arc<stats::Collector>,
        static_config: &Config,
        runtime_config: &RuntimeConfig,
        flow_receiver: queue::Receiver<TaggedFlow>,
        l4_flow_aggr_sender: Option<queue::Sender<SendItem>>,
        metrics_sender: queue::Sender<SendItem>,
        metrics_type: MetricsType,
        inactive_server_port_enabled: Arc<AtomicBool>,
    ) -> CollectorThread {
        let (second_sender, second_receiver, counter) =
            queue::bounded(static_config.quadruple_queue_size);
        stats_collector.register_countable(
            "2-flow-with-meter-to-second-collector",
            Arc::new(counter),
            vec![StatsOption::Tag("index", id.to_string())],
        );
        let (minute_sender, minute_receiver, counter) =
            queue::bounded(static_config.quadruple_queue_size);
        stats_collector.register_countable(
            "2-flow-with-meter-to-minute-collector",
            Arc::new(counter),
            vec![StatsOption::Tag("index", id.to_string())],
        );

        let (mut l4_log_sender, mut l4_log_receiver) = (None, None);
        if l4_flow_aggr_sender.is_some() {
            let (l4_flow_sender, l4_flow_receiver, counter) =
                queue::bounded(static_config.flow.aggr_queue_size as usize);
            stats_collector.register_countable(
                "2-second-flow-to-minute-aggrer",
                Arc::new(counter),
                vec![StatsOption::Tag("index", id.to_string())],
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
        let second_quadruple_tolerable_delay = (static_config.packet_delay.as_secs()
            + 1
            + static_config.flow.flush_interval.as_secs()
            + 5)
            + static_config.second_flow_extra_delay.as_secs();
        let minute_quadruple_tolerable_delay = (60 + static_config.packet_delay.as_secs())
            + 1
            + static_config.flow.flush_interval.as_secs()
            + 5;

        let vtap_flow_1s_enabled = Arc::new(AtomicBool::new(runtime_config.vtap_flow_1s_enabled));
        let quadruple_generator = QuadrupleGeneratorThread::new(
            id,
            flow_receiver,
            second_sender,
            minute_sender,
            l4_log_sender,
            (static_config.flow.hash_slots << 3) as usize, // connection_lru_capacity
            metrics_type,
            second_quadruple_tolerable_delay,
            minute_quadruple_tolerable_delay,
            1 << 18, // possible_host_size
            runtime_config.l7_metrics_enabled,
            vtap_flow_1s_enabled,
        );

        let mut l4_flow_aggr = None;
        if let Some(l4_log_receiver) = l4_log_receiver {
            let throttle = Arc::new(AtomicU64::new(runtime_config.l4_log_collect_nps_threshold));
            l4_flow_aggr = Some(FlowAggrThread::new(
                id,                                   // id
                l4_log_receiver,                      // input
                l4_flow_aggr_sender.unwrap().clone(), // output
                runtime_config.l4_log_store_tap_types.as_slice(),
                throttle,
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
                runtime_config.vtap_id,
                inactive_server_port_enabled.clone(),
                static_config.cloud_gateway_traffic,
                runtime_config.trident_type,
                stats_collector,
            ));
        }
        if metrics_type.contains(MetricsType::MINUTE) {
            minute_collector = Some(Collector::new(
                id as u32,
                minute_receiver,
                metrics_sender,
                MetricsType::MINUTE,
                minute_quadruple_tolerable_delay as u32,
                runtime_config.vtap_id,
                inactive_server_port_enabled,
                static_config.cloud_gateway_traffic,
                runtime_config.trident_type,
                stats_collector,
            ));
        }

        CollectorThread::new(
            quadruple_generator,
            l4_flow_aggr,
            second_collector,
            minute_collector,
        )
    }

    fn stop(mut self) {
        info!("stop dispatcher");

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

        // TODO: app proto logs handler

        self.libvirt_xml_extractor.stop();
        self.pcap_manager.stop();

        self.debugger.stop();
        self.monitor.stop();
    }
}

struct CollectorConfig {
    inactive_server_port_enabled: Arc<AtomicBool>,
}

struct EnvironmentConfig {
    max_memory: Arc<AtomicU64>,
}

struct ConfigHandler {
    static_config: Config,
    runtime_config: RuntimeConfig,
    ctrl_ip: IpAddr,
    ctrl_mac: MacAddr,
    // need update
    collector: CollectorConfig,
    environment: EnvironmentConfig,
}

impl ConfigHandler {
    fn new(
        synchronizer: &Synchronizer,
        ctrl_ip: IpAddr,
        ctrl_mac: MacAddr,
        config: Config,
    ) -> Self {
        ConfigHandler {
            static_config: config,
            runtime_config: RuntimeConfig::default(),
            ctrl_ip,
            ctrl_mac,
            collector: CollectorConfig {
                inactive_server_port_enabled: Arc::new(AtomicBool::new(false)),
            },
            environment: EnvironmentConfig {
                max_memory: synchronizer.max_memory(),
            },
        }
    }
}
