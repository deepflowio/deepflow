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

mod error;
pub(crate) mod recv_engine;

mod base_dispatcher;

mod analyzer_mode_dispatcher;
mod local_mode_dispatcher;
mod mirror_mode_dispatcher;

use std::sync::{
    atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    Arc, Mutex, Weak,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use libc::c_int;
use log::{debug, error, info, warn};
use pcap_sys::{bpf_program, pcap_compile_nopcap};

use analyzer_mode_dispatcher::AnalyzerModeDispatcher;
use base_dispatcher::{BaseDispatcher, TapTypeHandler};
use error::{Error, Result};
use local_mode_dispatcher::LocalModeDispatcher;
use mirror_mode_dispatcher::MirrorModeDispatcher;
use recv_engine::{
    af_packet::{self, bpf, BpfSyntax, OptTpacketVersion, Tpacket},
    RecvEngine, DEFAULT_BLOCK_SIZE, FRAME_SIZE_MAX, FRAME_SIZE_MIN, POLL_TIMEOUT,
};

use crate::{
    common::{enums::TapType, TaggedFlow, TapTyper},
    config::{handler::FlowAccess, DispatcherConfig},
    exception::ExceptionHandler,
    flow_generator::MetaAppProto,
    handler::{PacketHandler, PacketHandlerBuilder},
    platform::{GenericPoller, LibvirtXmlExtractor},
    policy::PolicyGetter,
    proto::{
        common::TridentType,
        trident::{IfMacSource, TapMode},
    },
    utils::{
        net::{Link, MacAddr},
        queue::DebugSender,
        stats::{self, Collector},
        LeakyBucket,
    },
};

use self::{
    local_mode_dispatcher::LocalModeDispatcherListener, recv_engine::af_packet::RawInstruction,
};

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
        self.terminated.store(false, Ordering::Relaxed);
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
    pub(super) fn on_config_change(&mut self, config: &DispatcherConfig) {
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
        blacklist: &Vec<u64>,
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

pub struct BpfOptions {
    pub capture_bpf: String,
    pub bpf_syntax: Vec<BpfSyntax>,
}

impl Default for BpfOptions {
    fn default() -> Self {
        Self {
            capture_bpf: "".to_string(),
            bpf_syntax: Vec::new(),
        }
    }
}

impl BpfOptions {
    fn skip_tap_interface(&self, tap_interfaces: &Vec<Link>) -> Vec<BpfSyntax> {
        let mut bpf_syntax = self.bpf_syntax.clone();

        bpf_syntax.push(BpfSyntax::LoadExtension(bpf::LoadExtension {
            num: bpf::Extension::ExtInterfaceIndex,
        }));

        let total = tap_interfaces.len();
        for (i, iface) in tap_interfaces.iter().enumerate() {
            bpf_syntax.push(BpfSyntax::JumpIf(bpf::JumpIf {
                cond: bpf::JumpTest::JumpEqual,
                val: iface.if_index,
                skip_true: (total - i) as u8,
                ..Default::default()
            }));
        }

        bpf_syntax.push(BpfSyntax::RetConstant(bpf::RetConstant { val: 0 }));
        bpf_syntax.push(BpfSyntax::RetConstant(bpf::RetConstant { val: 65535 }));

        return bpf_syntax;
    }

    fn to_pcap_bpf_prog(&self) -> Option<bpf_program> {
        let mut prog: bpf_program = bpf_program {
            bf_len: 0,
            bf_insns: std::ptr::null_mut(),
        };
        unsafe {
            let ret = pcap_compile_nopcap(
                0xffff as c_int,
                1,
                &mut prog,
                self.capture_bpf.as_ptr() as *const i8,
                1,
                0xffffffff,
            );

            if ret != 0 {
                return None;
            }
        }
        return Some(prog);
    }

    pub fn get_bpf_instructions(&self, tap_interfaces: &Vec<Link>) -> Vec<RawInstruction> {
        if self.capture_bpf.len() == 0 {
            let syntaxs = self.skip_tap_interface(tap_interfaces);
            debug!("Capture bpf set to:");
            for (i, syntax) in syntaxs.iter().enumerate() {
                debug!("{:3}: {}", i + 1, syntax);
            }
            return syntaxs.iter().map(|x| x.to_instruction()).collect();
        }

        let prog = self.to_pcap_bpf_prog();
        if prog.is_none() {
            error!("Capture bpf {} error.", self.capture_bpf);
            return vec![];
        }
        debug!("Capture bpf set to: {}", self.capture_bpf);

        let prog = prog.unwrap();
        unsafe {
            let pcap_ins =
                Vec::from_raw_parts(prog.bf_insns, prog.bf_len as usize, prog.bf_len as usize);
            return pcap_ins
                .iter()
                .map(|&x| bpf::RawInstruction::from(x))
                .collect();
        }
    }
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

struct PacketCounter {
    terminated: Arc<AtomicBool>,

    rx: AtomicU64,
    rx_all: AtomicU64,
    rx_bytes: AtomicU64,
    rx_all_bytes: AtomicU64,
    err: AtomicU64,

    invalid_packets: AtomicU64,
    get_token_failed: AtomicU64,

    retired: AtomicU64,
    kernel_counter: Arc<dyn stats::RefCountable>,
}

impl PacketCounter {
    fn new(terminated: Arc<AtomicBool>, kernel_counter: Arc<dyn stats::RefCountable>) -> Self {
        Self {
            terminated,

            rx: AtomicU64::new(0),
            rx_all: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            rx_all_bytes: AtomicU64::new(0),
            err: AtomicU64::new(0),

            invalid_packets: AtomicU64::new(0),
            get_token_failed: AtomicU64::new(0),

            retired: AtomicU64::new(0),
            kernel_counter,
        }
    }
}

impl stats::RefCountable for PacketCounter {
    fn get_counters(&self) -> Vec<stats::Counter> {
        let mut counters = self.kernel_counter.get_counters();
        let get_token_failed = self.get_token_failed.swap(0, Ordering::Relaxed);
        if get_token_failed > 0 {
            warn!("rx rate limit hit {}", get_token_failed);
        }
        counters.extend(vec![
            (
                "rx",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(self.rx.swap(0, Ordering::Relaxed)),
            ),
            (
                "rx_all",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(self.rx_all.swap(0, Ordering::Relaxed)),
            ),
            (
                "rx_bytes",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(self.rx_bytes.swap(0, Ordering::Relaxed)),
            ),
            (
                "rx_all_bytes",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(self.rx_all_bytes.swap(0, Ordering::Relaxed)),
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
                stats::CounterValue::Unsigned(self.retired.swap(0, Ordering::Relaxed)),
            ),
        ]);
        counters
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
    flow_output_queue: Option<DebugSender<TaggedFlow>>,
    log_output_queue: Option<DebugSender<MetaAppProto>>,
    packet_sequence_output_queue:
        Option<DebugSender<Box<packet_sequence_block::PacketSequenceBlock>>>, // Enterprise Edition Feature: packet-sequence
    stats_collector: Option<Arc<Collector>>,
    flow_map_config: Option<FlowAccess>,
    policy_getter: Option<PolicyGetter>,
    platform_poller: Option<Arc<GenericPoller>>,
    exception_handler: Option<ExceptionHandler>,
    ntp_diff: Option<Arc<AtomicI64>>,
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

    pub fn flow_output_queue(mut self, v: DebugSender<TaggedFlow>) -> Self {
        self.flow_output_queue = Some(v);
        self
    }

    pub fn log_output_queue(mut self, v: DebugSender<MetaAppProto>) -> Self {
        self.log_output_queue = Some(v);
        self
    }

    // Enterprise Edition Feature: packet-sequence
    pub fn packet_sequence_output_queue(
        mut self,
        v: DebugSender<Box<packet_sequence_block::PacketSequenceBlock>>,
    ) -> Self {
        self.packet_sequence_output_queue = Some(v);
        self
    }

    pub fn stats_collector(mut self, v: Arc<Collector>) -> Self {
        self.stats_collector = Some(v);
        self
    }

    pub fn flow_map_config(mut self, v: FlowAccess) -> Self {
        self.flow_map_config = Some(v);
        self
    }

    pub fn policy_getter(mut self, v: PolicyGetter) -> Self {
        self.policy_getter = Some(v);
        self
    }

    pub fn platform_poller(mut self, v: Arc<GenericPoller>) -> Self {
        self.platform_poller = Some(v);
        self
    }

    pub fn exception_handler(mut self, v: ExceptionHandler) -> Self {
        self.exception_handler = Some(v);
        self
    }

    pub fn ntp_diff(mut self, v: Arc<AtomicI64>) -> Self {
        self.ntp_diff = Some(v);
        self
    }

    pub fn build(mut self) -> Result<Dispatcher> {
        let options = self
            .options
            .ok_or(Error::ConfigIncomplete("no options".into()))?;
        let tap_mode = options.tap_mode;
        let engine = if tap_mode == TapMode::Mirror && options.dpdk_conf.enabled {
            #[cfg(all(target_os = "linux", not(target_arch = "s390x")))]
            {
                RecvEngine::Dpdk()
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
            info!("Afpacket init with {:?}", afp);
            RecvEngine::AfPacket(Tpacket::new(afp).unwrap())
        };
        let kernel_counter = engine.get_counter_handle();
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

            need_update_bpf: Arc::new(AtomicBool::new(true)),
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
            stats: collector.clone(),
            flow_map_config: self
                .flow_map_config
                .take()
                .ok_or(Error::ConfigIncomplete("no flow map config".into()))?,
            policy_getter: self
                .policy_getter
                .ok_or(Error::ConfigIncomplete("no policy".into()))?,
            platform_poller: self
                .platform_poller
                .take()
                .ok_or(Error::ConfigIncomplete("no platform poller".into()))?,
            exception_handler: self
                .exception_handler
                .take()
                .ok_or(Error::ConfigIncomplete("no exception handler".into()))?,
            ntp_diff: self
                .ntp_diff
                .take()
                .ok_or(Error::ConfigIncomplete("no ntp_diff".into()))?,
            // Enterprise Edition Feature: packet-sequence
            packet_sequence_output_queue: self
                .packet_sequence_output_queue
                .take()
                .ok_or(Error::ConfigIncomplete("no packet_sequence_block".into()))?,
        };
        collector.register_countable(
            "dispatcher",
            stats::Countable::Ref(Arc::downgrade(&counter) as Weak<dyn stats::RefCountable>),
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
