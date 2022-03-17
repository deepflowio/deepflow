use std::mem;
use std::net::IpAddr;
use std::path::Path;
use std::process;
use std::sync::{
    atomic::{AtomicBool, AtomicU32, AtomicU64},
    Arc, Condvar, Mutex,
};
use std::thread::{self, JoinHandle};

use anyhow::{Context, Result};
use flexi_logger::{
    colored_opt_format, Age, Cleanup, Criterion, Duplicate, FileSpec, Logger, Naming,
};
use log::{info, warn};

use crate::{
    collector::{quadruple_generator::QuadrupleGeneratorThread, MetricsType},
    common::{
        enums::TapType, tagged_flow::TaggedFlow, tap_types::TapTyper, FREE_SPACE_REQUIREMENT,
    },
    config::{Config, RuntimeConfig},
    dispatcher::{
        self,
        recv_engine::{self, bpf},
        BpfOptions, Dispatcher, DispatcherBuilder,
    },
    flow_generator::{FlowMapConfig, FlowMapRuntimeConfig, FlowTimeout, TcpTimeout},
    monitor::Monitor,
    platform::LibvirtXmlExtractor,
    proto::trident::TapMode,
    rpc::{Session, Synchronizer, DEFAULT_TIMEOUT},
    utils::{
        environment::{
            check, controller_ip_check, free_memory_checker, free_space_checker, kernel_check,
            trident_process_check,
        },
        net::{get_route_src_ip, get_route_src_ip_and_mac, MacAddr},
        queue,
        stats::{self, StatsOption},
        LeakyBucket,
    },
};

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
        info!("========== Trident start! ==========");

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
        let mut running_config = RuntimeConfig::default();
        let mut components = None;
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
                Self::update_config(&config, &mut running_config, new_config, &mut components);

            if restart_dispatcher {
                if let Some(c) = components.take() {
                    c.stop();
                    // TODO: reset fast path
                }
            }
            if running_config.enabled != components.is_some() {
                if running_config.enabled {
                    info!("Current Revision: {}", &revision);
                    match Components::start(
                        &config,
                        &running_config,
                        &synchronizer.max_memory(),
                        ctrl_ip,
                        ctrl_mac,
                        &stats_collector,
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
        static_config: &Config,
        running_config: &mut RuntimeConfig,
        new_config: RuntimeConfig,
        components: &mut Option<Components>,
    ) -> bool {
        let mut restart_dispatcher = false;
        if running_config.enabled != new_config.enabled {
            running_config.enabled = new_config.enabled;
            info!("Enabled set to {}", new_config.enabled);
        }
        if running_config.global_pps_threshold != new_config.global_pps_threshold {
            running_config.global_pps_threshold = new_config.global_pps_threshold;
            if let Some(components) = components.as_mut() {
                match static_config.tap_mode {
                    TapMode::Analyzer => {
                        components.rx_leaky_bucket.set_rate(None);
                        info!("Global pps set unlimit when tap_mode=analyzer");
                    }
                    _ => {
                        components
                            .rx_leaky_bucket
                            .set_rate(Some(running_config.global_pps_threshold));
                        info!(
                            "Global pps threshold change to {}",
                            running_config.global_pps_threshold
                        );
                    }
                }
            }
        }
        // TODO: update other configs and remove the next line
        *running_config = new_config;
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
    quadruple_generators: Vec<QuadrupleGeneratorThread>,
    monitor: Monitor,
}

impl Components {
    fn start(
        static_config: &Config,
        runtime_config: &RuntimeConfig,
        max_memory: &Arc<AtomicU64>,
        ctrl_ip: IpAddr,
        ctrl_mac: MacAddr,
        stats_collector: &Arc<stats::Collector>,
    ) -> Result<Self> {
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
                check(free_memory_checker(max_memory.clone()));
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
        let libvirt_xml_extractor = Arc::new(LibvirtXmlExtractor::new());
        libvirt_xml_extractor.start();

        let flow_config = &static_config.flow;
        let flow_map_config = FlowMapConfig {
            vtap_id: runtime_config.vtap_id,
            trident_type: runtime_config.trident_type,
            collector_enabled: runtime_config.collector_enabled,
            packet_delay: static_config.packet_delay,
            flush_interval: flow_config.flush_interval,
            ignore_l2_end: flow_config.ignore_l2_end,
            ignore_tor_mac: flow_config.ignore_tor_mac,
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
        };

        let tap_typer = Arc::new(TapTyper::new());

        // TODO: collector enabled
        let dispatcher_num = static_config.src_interfaces.len().max(1);
        let mut dispatchers = vec![];
        let mut quadruple_generators = vec![];

        for i in 0..dispatcher_num {
            // TODO: create and start collector
            let (flow_sender, flow_receiver, counter) =
                queue::bounded(static_config.flow_queue_size);
            stats_collector.register_countable(
                "1-tagged-flow-to-quadruple-generator",
                Arc::new(counter),
                vec![],
            );

            // TODO: create and start app proto logs
            let (log_sender, log_receiver, counter) = queue::bounded(static_config.flow_queue_size);
            stats_collector.register_countable(
                "1-tagged-flow-to-app-protocol-logs",
                Arc::new(counter),
                vec![],
            );
            thread::spawn(|| for _ in log_receiver {});

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
            dispatcher.start();
            dispatchers.push(dispatcher);

            let mut quadruple_generator = Self::new_collector(
                i,
                stats_collector,
                static_config,
                runtime_config,
                flow_receiver,
                MetricsType::SECOND | MetricsType::MINUTE,
            );
            quadruple_generator.start();
            quadruple_generators.push(quadruple_generator);
        }

        // TODO: platform synchronizer

        // TODO: kubernetes api watcher

        let monitor = Monitor::new(stats_collector.clone())?;
        monitor.start();

        Ok(Components {
            source_ip,
            rx_leaky_bucket,
            libvirt_xml_extractor,
            tap_typer,
            dispatchers,
            quadruple_generators,
            monitor,
        })
    }

    // TODO: collector...
    fn new_collector(
        id: usize,
        stats_collector: &Arc<stats::Collector>,
        static_config: &Config,
        runtime_config: &RuntimeConfig,
        flow_receiver: queue::Receiver<TaggedFlow>,
        metrics_type: MetricsType,
    ) -> QuadrupleGeneratorThread {
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
        if runtime_config.l4_log_store_tap_types.len() > 0 {
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
            (static_config.flow.hash_slots << 8) as usize, // connection_lru_capacity
            metrics_type,
            second_quadruple_tolerable_delay,
            minute_quadruple_tolerable_delay,
            1 << 18, // possible_host_size
            runtime_config.l7_metrics_enabled,
            vtap_flow_1s_enabled,
        );

        thread::spawn(move || {
            for flow in second_receiver {
                info!("second: {}", flow);
            }
        });
        thread::spawn(move || {
            for flow in minute_receiver {
                info!("minute: {}", flow);
            }
        });
        if let Some(l4_flow_receiver) = l4_log_receiver {
            thread::spawn(move || {
                for flow in l4_flow_receiver {
                    info!("l4_flow: {}", flow);
                }
            });
        }
        quadruple_generator
    }

    fn stop(mut self) {
        info!("stop dispatcher");

        for d in self.dispatchers.iter_mut() {
            d.stop();
        }
        // TODO: platform synchronizer

        // TODO: collector
        for q in self.quadruple_generators.iter_mut() {
            q.stop();
        }

        // TODO: app proto logs handler

        self.libvirt_xml_extractor.stop();

        // TODO: kubernetes api watcher

        self.monitor.stop();
    }
}
