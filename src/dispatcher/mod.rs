mod error;
pub(crate) mod recv_engine;

mod base_dispatcher;

mod analyzer_mode_dispatcher;
mod local_mode_dispatcher;
mod mirror_mode_dispatcher;

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use log::warn;

use analyzer_mode_dispatcher::AnalyzerModeDispatcher;
use base_dispatcher::{BaseDispatcher, TapTypeHandler};
use error::{Error, Result};
use local_mode_dispatcher::LocalModeDispatcher;
use mirror_mode_dispatcher::MirrorModeDispatcher;
use recv_engine::{
    af_packet::{self, OptTpacketVersion, Tpacket},
    Counter as ReCounter, RecvEngine, DEFAULT_BLOCK_SIZE, FRAME_SIZE_MAX, FRAME_SIZE_MIN,
    POLL_TIMEOUT,
};

use crate::{
    common::{enums::TapType, PlatformData, TaggedFlow, TapTyper},
    config::RuntimeConfig,
    flow_generator::{FlowMapConfig, MetaAppProto},
    handler::{PacketHandler, PacketHandlerBuilder},
    platform::LibvirtXmlExtractor,
    proto::{
        common::TridentType,
        trident::{IfMacSource, TapMode},
    },
    utils::{
        net::{Link, MacAddr},
        queue::Sender,
        stats::{self, Collector},
        LeakyBucket,
    },
};

use self::local_mode_dispatcher::LocalModeDispatcherListener;

enum DispatcherFlavor {
    Analyzer(AnalyzerModeDispatcher),
    Local(LocalModeDispatcher),
    Mirror(MirrorModeDispatcher),
}

impl DispatcherFlavor {
    fn init(&mut self) {
        match self {
            DispatcherFlavor::Analyzer(d) => d.init(),
            DispatcherFlavor::Local(d) => d.base.init(),
            DispatcherFlavor::Mirror(d) => d.init(),
        }
    }

    fn run(&mut self) {
        match self {
            DispatcherFlavor::Analyzer(d) => d.run(),
            DispatcherFlavor::Local(d) => d.run(),
            DispatcherFlavor::Mirror(d) => d.run(),
        }
    }

    fn listener(&self) -> DispatcherListener {
        match self {
            DispatcherFlavor::Local(d) => DispatcherListener::Local(d.listener()),
            _ => todo!(),
        }
    }
}

pub struct Dispatcher {
    flavor: Mutex<Option<DispatcherFlavor>>,
    terminated: Arc<AtomicBool>,
    running: AtomicBool,
    handle: Mutex<Option<JoinHandle<DispatcherFlavor>>>,
}

impl Dispatcher {
    pub fn listener(&self) -> DispatcherListener {
        self.flavor
            .lock()
            .unwrap()
            .as_ref()
            .expect("Cannot get dispatcher listener after start")
            .listener()
    }

    pub fn start(&self) {
        if self.running.swap(true, Ordering::Relaxed) {
            return;
        }
        let mut flavor = self.flavor.lock().unwrap().take().unwrap();
        self.handle.lock().unwrap().replace(thread::spawn(move || {
            flavor.run();
            flavor
        }));
    }

    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            return;
        }
        self.terminated.store(true, Ordering::Relaxed);
        let handle = self.handle.lock().unwrap().take().unwrap();
        handle.thread().unpark();
        self.flavor.lock().unwrap().replace(handle.join().unwrap());
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}

#[derive(Clone)]
pub enum DispatcherListener {
    Local(LocalModeDispatcherListener),
}

impl DispatcherListener {
    pub(super) fn on_config_change(&mut self, config: &RuntimeConfig) {
        match self {
            Self::Local(l) => l.on_config_change(config),
        }
    }

    pub fn on_vm_change(&self, _: &[MacAddr]) {
        todo!()
    }

    pub fn on_tap_interface_change(
        &self,
        interfaces: &Vec<Link>,
        if_mac_source: IfMacSource,
        trident_type: TridentType,
        blacklist: &Vec<PlatformData>,
    ) {
        match self {
            Self::Local(l) => {
                l.on_tap_interface_change(interfaces, if_mac_source, trident_type, blacklist)
            }
        }
    }
}

#[derive(Default)]
pub struct DpdkRingPortConf {
    pub enabled: bool,
    pub core_id: u32,
    pub port_name: String,
}

#[derive(Default)]
pub struct BpfOptions {
    // bpf_instructions
    pub bpf_syntax: String,
}

#[derive(Default)]
pub struct Options {
    pub handler_builders: Vec<PacketHandlerBuilder>,
    pub af_packet_blocks: usize,
    pub af_packet_version: OptTpacketVersion,
    pub snap_len: usize,
    pub tap_mode: TapMode,
    pub dpdk_conf: DpdkRingPortConf,
    pub tap_mac_script: String,
    pub is_ipv6: bool,
    pub vxlan_port: u16,
    pub controller_port: u16,
    pub controller_tls_port: u16,
}

struct Pipeline {
    vm_mac: MacAddr,
    handlers: Vec<PacketHandler>,
    timestamp: Duration,
}

#[derive(Default)]
struct PacketCounter {
    terminated: Arc<AtomicBool>,

    rx: AtomicU64,
    rx_bytes: AtomicU64,
    err: AtomicU64,

    invalid_packets: AtomicU64,
    get_token_failed: AtomicU64,

    kernel_counter: Arc<ReCounter>,
}

impl PacketCounter {
    fn new(terminated: Arc<AtomicBool>, kernel_counter: Arc<ReCounter>) -> Self {
        Self {
            terminated,

            rx: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            err: AtomicU64::new(0),

            invalid_packets: AtomicU64::new(0),
            get_token_failed: AtomicU64::new(0),

            kernel_counter,
        }
    }
}

impl stats::Countable for PacketCounter {
    fn get_counters(&self) -> Vec<stats::Counter> {
        let kc = &self.kernel_counter;
        let get_token_failed = self.get_token_failed.swap(0, Ordering::Relaxed);
        if get_token_failed > 0 {
            warn!("rx rate limit hit {}", get_token_failed);
        }
        vec![
            (
                "rx",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(self.rx.swap(0, Ordering::Relaxed)),
            ),
            (
                "rx_bytes",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(self.rx_bytes.swap(0, Ordering::Relaxed)),
            ),
            (
                "err",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(self.err.swap(0, Ordering::Relaxed)),
            ),
            (
                "invalid_packets",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(self.invalid_packets.swap(0, Ordering::Relaxed)),
            ),
            (
                "get_token_failed",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(get_token_failed),
            ),
            (
                "retired",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(kc.retired.swap(0, Ordering::Relaxed)),
            ),
            (
                "kernel_packets",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(kc.kernel_packets.swap(0, Ordering::Relaxed)),
            ),
            (
                "kernel_drops",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(kc.kernel_drops.swap(0, Ordering::Relaxed)),
            ),
            (
                "kernel_freezes",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(kc.kernel_freezes.swap(0, Ordering::Relaxed)),
            ),
        ]
    }

    fn closed(&self) -> bool {
        self.terminated.load(Ordering::Relaxed)
    }
}

#[derive(Default)]
pub struct DispatcherBuilder {
    id: Option<usize>,
    src_interface: Option<String>,
    ctrl_mac: Option<MacAddr>,
    leaky_bucket: Option<Arc<LeakyBucket>>,
    options: Option<Arc<Options>>,
    bpf_options: Option<Arc<Mutex<BpfOptions>>>,
    default_tap_type: Option<TapType>,
    mirror_traffic_pcp: Option<u16>,
    tap_typer: Option<Arc<TapTyper>>,
    analyzer_dedup_disabled: Option<bool>,
    libvirt_xml_extractor: Option<Arc<LibvirtXmlExtractor>>,
    flow_output_queue: Option<Sender<TaggedFlow>>,
    log_output_queue: Option<Sender<MetaAppProto>>,
    flow_map_config: Option<FlowMapConfig>,
    stats_collector: Option<Arc<Collector>>,
}

impl DispatcherBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn id(mut self, v: usize) -> Self {
        self.id = Some(v);
        self
    }

    pub fn src_interface(mut self, v: String) -> Self {
        self.src_interface = Some(v);
        self
    }

    pub fn ctrl_mac(mut self, v: MacAddr) -> Self {
        self.ctrl_mac = Some(v);
        self
    }

    pub fn leaky_bucket(mut self, v: Arc<LeakyBucket>) -> Self {
        self.leaky_bucket = Some(v);
        self
    }

    pub fn options(mut self, v: Arc<Options>) -> Self {
        self.options = Some(v);
        self
    }

    pub fn bpf_options(mut self, v: Arc<Mutex<BpfOptions>>) -> Self {
        self.bpf_options = Some(v);
        self
    }

    pub fn default_tap_type(mut self, v: TapType) -> Self {
        self.default_tap_type = Some(v);
        self
    }

    pub fn mirror_traffic_pcp(mut self, v: u16) -> Self {
        self.mirror_traffic_pcp = Some(v);
        self
    }

    pub fn tap_typer(mut self, v: Arc<TapTyper>) -> Self {
        self.tap_typer = Some(v);
        self
    }

    pub fn analyzer_dedup_disabled(mut self, v: bool) -> Self {
        self.analyzer_dedup_disabled = Some(v);
        self
    }

    pub fn libvirt_xml_extractor(mut self, v: Arc<LibvirtXmlExtractor>) -> Self {
        self.libvirt_xml_extractor = Some(v);
        self
    }

    pub fn flow_output_queue(mut self, v: Sender<TaggedFlow>) -> Self {
        self.flow_output_queue = Some(v);
        self
    }

    pub fn log_output_queue(mut self, v: Sender<MetaAppProto>) -> Self {
        self.log_output_queue = Some(v);
        self
    }

    pub fn flow_map_config(mut self, v: FlowMapConfig) -> Self {
        self.flow_map_config = Some(v);
        self
    }

    pub fn stats_collector(mut self, v: Arc<Collector>) -> Self {
        self.stats_collector = Some(v);
        self
    }

    pub fn build(mut self) -> Result<Dispatcher> {
        let options = self
            .options
            .ok_or(Error::ConfigIncomplete("no options".into()))?;
        let kernel_counter = Arc::new(ReCounter::default());
        let tap_mode = options.tap_mode;
        let engine = if tap_mode == TapMode::Mirror && options.dpdk_conf.enabled {
            #[cfg(all(target_os = "linux", not(target_arch = "s390x")))]
            {
                RecvEngine::Dpdk(kernel_counter.clone())
            }
            #[cfg(target_os = "windows")]
            return Err(Error::ConfigInvalid(
                "windows does not support DPDK!".into(),
            ));
            #[cfg(target_arch = "s390x")]
            return Err(Error::ConfigInvalid(
                "cpu arch s390x does not support DPDK!".into(),
            ));
        } else {
            let afp = af_packet::Options {
                frame_size: if options.tap_mode == TapMode::Analyzer {
                    FRAME_SIZE_MIN as u32
                } else {
                    FRAME_SIZE_MAX as u32
                },
                block_size: DEFAULT_BLOCK_SIZE as u32,
                num_blocks: options.af_packet_blocks as u32,
                poll_timeout: POLL_TIMEOUT.as_nanos() as isize,
                version: options.af_packet_version,
                iface: self.src_interface.take().unwrap_or("".to_string()),
                ..Default::default()
            };
            RecvEngine::AfPacket(Tpacket::new(afp).unwrap())
        };
        let id = self.id.ok_or(Error::ConfigIncomplete("no id".into()))?;
        let terminated = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(PacketCounter::new(terminated.clone(), kernel_counter));
        let collector = self
            .stats_collector
            .ok_or(Error::StatsCollector("no stats collector"))?;

        let base = BaseDispatcher {
            engine,

            id,
            src_interface: if tap_mode == TapMode::Local {
                "".to_string()
            } else {
                self.src_interface.unwrap_or("".to_string())
            },
            src_interface_index: 0,
            ctrl_mac: self
                .ctrl_mac
                .ok_or(Error::ConfigIncomplete("no ctrl_mac".into()))?,

            options,
            bpf_options: self.bpf_options.unwrap_or_default(),

            leaky_bucket: self
                .leaky_bucket
                .ok_or(Error::ConfigIncomplete("no leaky_bucket".into()))?,
            pipelines: Default::default(),
            tap_interfaces: Default::default(),
            tunnel_type_bitmap: Default::default(),
            tunnel_info: Default::default(),

            tap_type_handler: TapTypeHandler {
                tap_typer: self
                    .tap_typer
                    .ok_or(Error::ConfigIncomplete("no tap_typer".into()))?,
                default_tap_type: self
                    .default_tap_type
                    .ok_or(Error::ConfigIncomplete("no default_tap_type".into()))?,
                mirror_traffic_pcp: self
                    .mirror_traffic_pcp
                    .ok_or(Error::ConfigIncomplete("no mirror_traffic_pcp".into()))?,
                tap_mode,
            },

            need_update_ebpf: Arc::new(AtomicBool::new(true)),
            reset_whitelist: Default::default(),
            tap_interface_whitelist: Default::default(),

            analyzer_dedup_disabled: self
                .analyzer_dedup_disabled
                .ok_or(Error::ConfigIncomplete("no analyzer_dedup_disabled".into()))?,

            flow_output_queue: self
                .flow_output_queue
                .take()
                .ok_or(Error::ConfigIncomplete("no flow_output_queue".into()))?,
            log_output_queue: self
                .log_output_queue
                .take()
                .ok_or(Error::ConfigIncomplete("no log_output_queue".into()))?,

            counter: counter.clone(),
            terminated: terminated.clone(),
            flow_map_config: self
                .flow_map_config
                .take()
                .ok_or(Error::ConfigIncomplete("no flow_map_config".into()))?,
            stats: collector.clone(),
        };
        collector.register_countable(
            "dispatcher",
            counter,
            vec![stats::StatsOption::Tag("id", base.id.to_string())],
        );
        let mut dispatcher = match tap_mode {
            TapMode::Local => {
                let extractor = self
                    .libvirt_xml_extractor
                    .ok_or(Error::ConfigIncomplete("no libvirt xml extractor".into()))?;
                DispatcherFlavor::Local(LocalModeDispatcher { base, extractor })
            }
            TapMode::Mirror => DispatcherFlavor::Mirror(MirrorModeDispatcher { base }),
            TapMode::Analyzer => DispatcherFlavor::Analyzer(AnalyzerModeDispatcher { base }),
            _ => {
                return Err(Error::ConfigInvalid(format!(
                    "invalid tap mode {:?}",
                    &base.options.tap_mode
                )))
            }
        };
        dispatcher.init();
        Ok(Dispatcher {
            flavor: Mutex::new(Some(dispatcher)),
            terminated,
            running: AtomicBool::new(false),
            handle: Mutex::new(None),
        })
    }
}
