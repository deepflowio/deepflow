/*
 * Copyright (c) 2023 Yunshan Networks
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

#[cfg(target_os = "windows")]
use std::process;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
        Arc, Mutex, RwLock, Weak,
    },
};

#[cfg(target_os = "linux")]
use libc::c_int;
use log::{debug, error, info, warn};
use packet_dedup::*;
#[cfg(target_os = "linux")]
use pcap_sys::bpf_insn;
#[cfg(target_os = "linux")]
use pcap_sys::{bpf_program, pcap_compile_nopcap};
use public::debug::QueueDebugger;
#[cfg(target_os = "linux")]
use public::enums::LinuxSllPacketType::Outgoing;
#[cfg(target_os = "windows")]
use windows_recv_engine::WinPacket;

use analyzer_mode_dispatcher::{AnalyzerModeDispatcher, AnalyzerModeDispatcherListener}; // Enterprise Edition Feature: analyzer_mode
use base_dispatcher::{BaseDispatcher, TapTypeHandler};
use error::{Error, Result};
use local_mode_dispatcher::{LocalModeDispatcher, LocalModeDispatcherListener};
use mirror_mode_dispatcher::{MirrorModeDispatcher, MirrorModeDispatcherListener};
pub use recv_engine::RecvEngine;
#[cfg(target_os = "linux")]
pub use recv_engine::{
    af_packet::{self, bpf::*, BpfSyntax, OptTpacketVersion, RawInstruction, Tpacket},
    DEFAULT_BLOCK_SIZE, FRAME_SIZE_MAX, FRAME_SIZE_MIN, POLL_TIMEOUT,
};

#[cfg(target_os = "linux")]
use self::base_dispatcher::TapInterfaceWhitelist;
#[cfg(target_os = "linux")]
use crate::platform::GenericPoller;
use crate::utils::environment::get_mac_by_name;
use crate::{
    common::{enums::TapType, FlowAclListener, TaggedFlow, TapTyper},
    config::{
        handler::{FlowAccess, LogParserAccess},
        DispatcherConfig,
    },
    exception::ExceptionHandler,
    flow_generator::MetaAppProto,
    handler::{PacketHandler, PacketHandlerBuilder},
    platform::LibvirtXmlExtractor,
    policy::PolicyGetter,
    utils::stats::{self, Collector},
};
#[cfg(target_os = "linux")]
use public::netns::NetNs;
use public::{
    netns::NsFile,
    proto::{
        common::TridentType,
        trident::{IfMacSource, TapMode},
    },
    queue::DebugSender,
    utils::net::{Link, MacAddr},
    LeakyBucket,
};

enum DispatcherFlavor {
    Analyzer(AnalyzerModeDispatcher), // Enterprise Edition Feature: analyzer_mode
    Local(LocalModeDispatcher),
    Mirror(MirrorModeDispatcher),
}

impl DispatcherFlavor {
    fn init(&mut self) {
        match self {
            DispatcherFlavor::Analyzer(d) => d.base.init(), // Enterprise Edition Feature: analyzer_mode
            DispatcherFlavor::Local(d) => d.base.init(),
            DispatcherFlavor::Mirror(d) => d.init(),
        }
    }

    fn run(&mut self) {
        match self {
            DispatcherFlavor::Analyzer(d) => d.run(), // Enterprise Edition Feature: analyzer_mode
            DispatcherFlavor::Local(d) => d.run(),
            DispatcherFlavor::Mirror(d) => d.run(),
        }
    }

    fn listener(&self) -> DispatcherListener {
        match self {
            // Enterprise Edition Feature: analyzer_mode
            DispatcherFlavor::Analyzer(d) => DispatcherListener::Analyzer(d.listener()),
            DispatcherFlavor::Local(d) => DispatcherListener::Local(d.listener()),
            DispatcherFlavor::Mirror(d) => DispatcherListener::Mirror(d.listener()),
        }
    }

    #[cfg(target_os = "windows")]
    fn switch_recv_engine(&mut self, pcap_interfaces: Vec<Link>) -> Result<()> {
        match self {
            DispatcherFlavor::Local(d) => d.switch_recv_engine(pcap_interfaces),
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
        self.handle.lock().unwrap().replace(
            thread::Builder::new()
                .name("dispatcher".to_owned())
                .spawn(move || {
                    flavor.run();
                    flavor
                })
                .unwrap(),
        );
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

#[cfg(target_os = "windows")]
impl Dispatcher {
    pub fn switch_recv_engine(&self, pcap_interfaces: Vec<Link>) {
        self.stop();
        if let Err(e) = self
            .flavor
            .lock()
            .unwrap()
            .as_mut()
            .ok_or(Error::DispatcherFlavorEmpty)
            .and_then(|d| d.switch_recv_engine(pcap_interfaces))
        {
            error!("switch RecvEngine error: {}, deepflow-agent restart...", e);
            thread::sleep(Duration::from_secs(1));
            process::exit(-1);
        }
        self.start();
    }
}

#[derive(Clone)]
pub enum DispatcherListener {
    Analyzer(AnalyzerModeDispatcherListener), // Enterprise Edition Feature: analyzer_mode
    Local(LocalModeDispatcherListener),
    Mirror(MirrorModeDispatcherListener),
}

impl FlowAclListener for DispatcherListener {
    fn flow_acl_change(
        &mut self,
        _: TridentType,
        _: i32,
        _: &Vec<Arc<crate::_IpGroupData>>,
        _: &Vec<Arc<crate::_PlatformData>>,
        _: &Vec<Arc<crate::common::policy::PeerConnection>>,
        _: &Vec<Arc<crate::_Cidr>>,
        _: &Vec<Arc<crate::_Acl>>,
    ) -> Result<(), String> {
        match self {
            DispatcherListener::Local(a) => a.flow_acl_change(),
            DispatcherListener::Mirror(a) => a.flow_acl_change(),
            DispatcherListener::Analyzer(a) => a.flow_acl_change(),
        }
        Ok(())
    }

    fn id(&self) -> usize {
        let id = match self {
            DispatcherListener::Local(a) => a.id(),
            DispatcherListener::Mirror(a) => a.id(),
            DispatcherListener::Analyzer(a) => a.id(),
        };
        2 + id
    }
}

impl DispatcherListener {
    pub(super) fn netns(&self) -> NsFile {
        match self {
            Self::Local(l) => l.netns(),
            _ => NsFile::Root,
        }
    }

    pub(super) fn on_config_change(&mut self, config: &DispatcherConfig) {
        match self {
            Self::Local(l) => l.on_config_change(config),
            Self::Analyzer(l) => l.on_config_change(config), // Enterprise Edition Feature: analyzer_mode
            Self::Mirror(l) => l.on_config_change(config),
        }
    }

    pub fn on_vm_change(&self, vm_mac_addrs: &[MacAddr], gateway_vmac_addrs: &[MacAddr]) {
        match self {
            // Enterprise Edition Feature: analyzer_mode
            Self::Analyzer(l) => {
                l.on_vm_change(vm_mac_addrs, gateway_vmac_addrs);
            }
            Self::Mirror(l) => {
                l.on_vm_change(vm_mac_addrs);
            }
            _ => {}
        }
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
            // Enterprise Edition Feature: analyzer_mode
            Self::Analyzer(l) => {
                l.on_tap_interface_change(interfaces, if_mac_source);
            }
            Self::Mirror(l) => {
                l.on_tap_interface_change(interfaces, if_mac_source, trident_type);
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
    #[cfg(target_os = "linux")]
    pub bpf_syntax: Vec<BpfSyntax>,
    #[cfg(target_os = "windows")]
    pub bpf_syntax_str: String,
}

impl Default for BpfOptions {
    fn default() -> Self {
        Self {
            capture_bpf: "".to_string(),
            #[cfg(target_os = "linux")]
            bpf_syntax: Vec::new(),
            #[cfg(target_os = "windows")]
            bpf_syntax_str: "".to_string(),
        }
    }
}

#[cfg(target_os = "linux")]
impl BpfOptions {
    // When using the default BPF filtering rules, it can support collecting traffic
    // from up to 254 network ports simultaneously.
    #[cfg(target_os = "linux")]
    const MAX_TAP_INTERFACES: usize = 254;

    fn skip_tap_interface(
        &self,
        tap_interfaces: &Vec<Link>,
        white_list: &TapInterfaceWhitelist,
        snap_len: usize,
    ) -> Vec<BpfSyntax> {
        let mut bpf_syntax = self.bpf_syntax.clone();

        bpf_syntax.push(BpfSyntax::LoadExtension(LoadExtension {
            num: Extension::ExtInterfaceIndex,
        }));

        if tap_interfaces.len() > Self::MAX_TAP_INTERFACES {
            error!(
                "Tap_interfaces.len() exceeds {}, use only the top {} of tap_interfaces.",
                Self::MAX_TAP_INTERFACES,
                Self::MAX_TAP_INTERFACES
            )
        }

        let total = tap_interfaces.len().min(Self::MAX_TAP_INTERFACES);
        for (i, iface) in tap_interfaces[..total].iter().enumerate() {
            let mut skip_true = (total - i) as u8;
            if white_list.has(iface.if_index as usize) {
                skip_true += 1;
            }
            bpf_syntax.push(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpEqual,
                val: iface.if_index,
                skip_true,
                ..Default::default()
            }));
        }

        bpf_syntax.push(BpfSyntax::RetConstant(RetConstant { val: 0 }));
        bpf_syntax.push(BpfSyntax::RetConstant(RetConstant {
            val: snap_len as u32,
        }));
        bpf_syntax.push(BpfSyntax::RetConstant(RetConstant { val: 65535 }));

        return bpf_syntax;
    }

    fn to_pcap_bpf_prog(&self) -> Option<bpf_program> {
        let mut prog: bpf_program = bpf_program {
            bf_len: 0,
            bf_insns: std::ptr::null_mut(),
        };
        unsafe {
            #[cfg(target_arch = "x86_64")]
            let ret = pcap_compile_nopcap(
                0xffff as c_int,
                1,
                &mut prog,
                self.capture_bpf.as_ptr() as *const i8,
                1,
                0xffffffff,
            );
            #[cfg(target_arch = "aarch64")]
            let ret = pcap_compile_nopcap(
                0xffff as c_int,
                1,
                &mut prog,
                self.capture_bpf.as_ptr() as *const u8,
                1,
                0xffffffff,
            );

            if ret != 0 {
                return None;
            }
        }
        return Some(prog);
    }

    pub fn get_bpf_instructions(
        &self,
        tap_interfaces: &Vec<Link>,
        white_list: &TapInterfaceWhitelist,
        snap_len: usize,
    ) -> Vec<RawInstruction> {
        let mut syntaxs = vec![];
        debug!("Capture bpf set to:");
        if self.capture_bpf.len() != 0 {
            let prog = self.to_pcap_bpf_prog();
            if !prog.is_none() && prog.unwrap().bf_len > 0 {
                let prog = prog.unwrap();
                unsafe {
                    let mut pcap_ins = Vec::from_raw_parts(
                        prog.bf_insns,
                        prog.bf_len as usize,
                        prog.bf_len as usize,
                    );
                    let bf_len = prog.bf_len as usize;
                    if pcap_ins[bf_len - 1].code & OP_CLS_RETURN == OP_CLS_RETURN {
                        if pcap_ins[bf_len - 1].k != 0 {
                            // RetConstant 0
                            // RetConstant 65535
                            for i in 0..pcap_ins.len() - 1 {
                                debug!("Bpf custom {:?}", pcap_ins[i]);
                                syntaxs.push(RawInstruction::from(pcap_ins[i]));
                            }
                        } else if pcap_ins[bf_len - 2].code & OP_CLS_RETURN == OP_CLS_RETURN {
                            // RetConstant 65535
                            // RetConstant 0
                            pcap_ins[bf_len - 2] = bpf_insn {
                                code: OP_CLS_JUMP | OP_JUMP_EQUAL,
                                jt: 1,
                                jf: 1,
                                k: 0,
                            };
                            for i in 0..pcap_ins.len() {
                                debug!("Bpf custom {:?}", pcap_ins[i]);
                                syntaxs.push(RawInstruction::from(pcap_ins[i]));
                            }
                        } else {
                            error!(
                                "Capture customized bpf({}) error, use default only.",
                                self.capture_bpf
                            );
                        }
                    } else {
                        error!(
                            "Capture customized bpf({}) error, use default only.",
                            self.capture_bpf
                        );
                    }
                }
            } else {
                error!(
                    "Capture customized bpf({}) error, use default only.",
                    self.capture_bpf
                );
            }
        }

        let default_syntaxs = self.skip_tap_interface(tap_interfaces, white_list, snap_len);
        for (i, syntax) in default_syntaxs.iter().enumerate() {
            debug!("Bpf default {:3}: {}", i + 1, syntax);
            syntaxs.push(syntax.to_instruction());
        }
        return syntaxs;
    }
}

#[cfg(target_os = "windows")]
impl BpfOptions {
    pub fn get_bpf_instructions(&self) -> String {
        if self.capture_bpf.len() > 0 {
            let syntax = format!("({}) and ({})", self.capture_bpf, self.bpf_syntax_str);
            debug!("Capture bpf set to: {}", syntax);
            return syntax;
        }
        debug!("Capture bpf set to: {}", self.bpf_syntax_str);
        return self.bpf_syntax_str.clone();
    }
}

#[derive(Default)]
pub struct Options {
    #[cfg(target_os = "windows")]
    pub win_packet_blocks: usize,
    #[cfg(target_os = "linux")]
    pub af_packet_blocks: usize,
    #[cfg(target_os = "linux")]
    pub af_packet_version: OptTpacketVersion,
    pub snap_len: usize,
    pub tap_mode: TapMode,
    pub dpdk_conf: DpdkRingPortConf,
    pub tap_mac_script: String,
    pub is_ipv6: bool,
    pub vxlan_flags: u8,
    pub npb_port: u16,
    pub controller_port: u16,
    pub controller_tls_port: u16,
}

pub struct Pipeline {
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
    options: Option<Arc<Mutex<Options>>>,
    handler_builders: Arc<Mutex<Vec<PacketHandlerBuilder>>>,
    bpf_options: Option<Arc<Mutex<BpfOptions>>>,
    default_tap_type: Option<TapType>,
    mirror_traffic_pcp: Option<u16>,
    tap_typer: Option<Arc<TapTyper>>,
    analyzer_dedup_disabled: Option<bool>,
    libvirt_xml_extractor: Option<Arc<LibvirtXmlExtractor>>,
    flow_output_queue: Option<DebugSender<Box<TaggedFlow>>>,
    log_output_queue: Option<DebugSender<Box<MetaAppProto>>>,
    packet_sequence_output_queue:
        Option<DebugSender<Box<packet_sequence_block::PacketSequenceBlock>>>, // Enterprise Edition Feature: packet-sequence
    stats_collector: Option<Arc<Collector>>,
    flow_map_config: Option<FlowAccess>,
    log_parse_config: Option<LogParserAccess>,
    policy_getter: Option<PolicyGetter>,
    #[cfg(target_os = "linux")]
    platform_poller: Option<Arc<GenericPoller>>,
    exception_handler: Option<ExceptionHandler>,
    ntp_diff: Option<Arc<AtomicI64>>,
    #[cfg(target_os = "windows")]
    pcap_interfaces: Option<Vec<Link>>,
    netns: Option<NsFile>,
    trident_type: Option<TridentType>,
    queue_debugger: Option<Arc<QueueDebugger>>,
    analyzer_queue_size: Option<usize>,
    analyzer_raw_packet_block_size: Option<usize>,
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

    pub fn options(mut self, v: Arc<Mutex<Options>>) -> Self {
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

    pub fn flow_output_queue(mut self, v: DebugSender<Box<TaggedFlow>>) -> Self {
        self.flow_output_queue = Some(v);
        self
    }

    pub fn log_output_queue(mut self, v: DebugSender<Box<MetaAppProto>>) -> Self {
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

    pub fn log_parse_config(mut self, v: LogParserAccess) -> Self {
        self.log_parse_config = Some(v);
        self
    }

    pub fn policy_getter(mut self, v: PolicyGetter) -> Self {
        self.policy_getter = Some(v);
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

    pub fn handler_builders(mut self, v: Arc<Mutex<Vec<PacketHandlerBuilder>>>) -> Self {
        self.handler_builders = v.clone();
        self
    }

    pub fn netns(mut self, v: NsFile) -> Self {
        self.netns = Some(v);
        self
    }

    pub fn trident_type(mut self, v: TridentType) -> Self {
        self.trident_type = Some(v);
        self
    }

    pub fn queue_debugger(mut self, v: Arc<QueueDebugger>) -> Self {
        self.queue_debugger = Some(v);
        self
    }

    pub fn analyzer_queue_size(mut self, v: usize) -> Self {
        self.analyzer_queue_size = Some(v);
        self
    }

    pub fn analyzer_raw_packet_block_size(mut self, v: usize) -> Self {
        self.analyzer_raw_packet_block_size = Some(v);
        self
    }

    pub fn build(mut self) -> Result<Dispatcher> {
        let netns = self.netns.unwrap_or_default();
        #[cfg(target_os = "linux")]
        let mut current_ns = None;
        #[cfg(target_os = "linux")]
        if netns != NsFile::Root {
            current_ns = Some(NetNs::open_current_ns()?);
            // set ns before creating af packet socket
            let _ = NetNs::open_named_and_setns(&netns)?;
        };
        let options = self
            .options
            .ok_or(Error::ConfigIncomplete("no options".into()))?;
        let tap_mode = options.lock().unwrap().tap_mode;
        let snap_len = options.lock().unwrap().snap_len;
        #[cfg(target_os = "windows")]
        let engine = Self::get_engine(&self.pcap_interfaces, tap_mode, &options)?;
        #[cfg(target_os = "linux")]
        let engine = Self::get_engine(&mut self.src_interface, tap_mode, &options)?;

        let kernel_counter = engine.get_counter_handle();
        let id = self.id.ok_or(Error::ConfigIncomplete("no id".into()))?;
        let terminated = Arc::new(AtomicBool::new(false));
        let stat_counter = Arc::new(PacketCounter::new(terminated.clone(), kernel_counter));
        let collector = self
            .stats_collector
            .ok_or(Error::StatsCollector("no stats collector"))?;
        let src_interface = if tap_mode == TapMode::Local {
            "".to_string()
        } else {
            self.src_interface.unwrap_or("".to_string())
        };

        #[cfg(target_os = "linux")]
        let platform_poller = self
            .platform_poller
            .take()
            .ok_or(Error::ConfigIncomplete("no platform poller".into()))?;

        let base = BaseDispatcher {
            log_id: {
                let mut lid = vec![id.to_string()];
                if &src_interface != "" {
                    lid.push(src_interface.clone());
                } else if netns != NsFile::Root {
                    lid.push(netns.to_string());
                }
                format!("({})", lid.join(", "))
            },
            engine,

            id,
            src_interface: src_interface.clone(),
            src_interface_index: 0,
            ctrl_mac: self
                .ctrl_mac
                .ok_or(Error::ConfigIncomplete("no ctrl_mac".into()))?,

            options,
            bpf_options: self.bpf_options.unwrap_or_default(),

            leaky_bucket: self
                .leaky_bucket
                .ok_or(Error::ConfigIncomplete("no leaky_bucket".into()))?,
            handler_builder: self.handler_builders.clone(),
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

            counter: stat_counter.clone(),
            terminated: terminated.clone(),
            stats: collector.clone(),
            flow_map_config: self
                .flow_map_config
                .take()
                .ok_or(Error::ConfigIncomplete("no flow map config".into()))?,
            log_parse_config: self
                .log_parse_config
                .take()
                .ok_or(Error::ConfigIncomplete("no log parse config".into()))?,
            policy_getter: self
                .policy_getter
                .ok_or(Error::ConfigIncomplete("no policy".into()))?,
            #[cfg(target_os = "linux")]
            platform_poller: platform_poller.clone(),
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
            netns,
            npb_dedup_enabled: Arc::new(AtomicBool::new(false)),
            pause: Arc::new(AtomicBool::new(true)),
        };
        collector.register_countable(
            "dispatcher",
            stats::Countable::Ref(Arc::downgrade(&stat_counter) as Weak<dyn stats::RefCountable>),
            vec![stats::StatsOption::Tag("id", base.id.to_string())],
        );
        let mut dispatcher = match tap_mode {
            TapMode::Local => {
                #[cfg(target_os = "linux")]
                let extractor = self
                    .libvirt_xml_extractor
                    .ok_or(Error::ConfigIncomplete("no libvirt xml extractor".into()))?;
                DispatcherFlavor::Local(LocalModeDispatcher {
                    base,
                    #[cfg(target_os = "linux")]
                    extractor,
                })
            }
            TapMode::Mirror => DispatcherFlavor::Mirror(MirrorModeDispatcher {
                base,
                dedup: PacketDedupMap::new(),
                local_vm_mac_set: Arc::new(Mutex::new(HashMap::new())),
                local_segment_macs: vec![],
                tap_bridge_macs: vec![],
                pipelines: HashMap::new(),
                #[cfg(target_os = "linux")]
                poller: Some(platform_poller),
                updated: Arc::new(AtomicBool::new(false)),
                trident_type: Arc::new(Mutex::new(
                    self.trident_type
                        .ok_or(Error::ConfigIncomplete("no trident_type".into()))?,
                )),
                mac: get_mac_by_name(src_interface),
                last_timestamp_array: vec![],
            }),
            TapMode::Analyzer => {
                #[cfg(target_os = "linux")]
                {
                    base.bpf_options
                        .lock()
                        .unwrap()
                        .bpf_syntax
                        .push(BpfSyntax::LoadExtension(LoadExtension {
                            num: Extension::ExtType,
                        }));
                    base.bpf_options
                        .lock()
                        .unwrap()
                        .bpf_syntax
                        .push(BpfSyntax::JumpIf(JumpIf {
                            cond: JumpTest::JumpNotEqual,
                            val: Outgoing as u32,
                            skip_true: 1,
                            ..Default::default()
                        }));
                    base.bpf_options
                        .lock()
                        .unwrap()
                        .bpf_syntax
                        .push(BpfSyntax::RetConstant(RetConstant { val: 0 })); // Do not capture tx direction traffic
                }
                #[cfg(target_os = "windows")]
                {
                    // TODO fill bpf_syntax_str
                }

                DispatcherFlavor::Analyzer(AnalyzerModeDispatcher {
                    base,
                    vm_mac_addrs: Arc::new(RwLock::new(Default::default())),
                    pool_raw_size: snap_len,
                    flow_generator_thread_handler: None,
                    pipeline_thread_handler: None,
                    stats_collector: collector.clone(),
                    queue_debugger: self.queue_debugger.as_ref().unwrap().clone(),
                    inner_queue_size: self
                        .analyzer_queue_size
                        .take()
                        .ok_or(Error::ConfigIncomplete("no analyzer-queue-size".into()))?,
                    raw_packet_block_size: self.analyzer_raw_packet_block_size.take().ok_or(
                        Error::ConfigIncomplete("no analyzer-raw-packet-block-size".into()),
                    )?,
                })
            }
            _ => {
                return Err(Error::ConfigInvalid(format!(
                    "invalid tap mode {:?}",
                    &base.options.lock().unwrap().tap_mode
                )))
            }
        };
        dispatcher.init();
        #[cfg(target_os = "linux")]
        if let Some(ns) = current_ns {
            let _ = NetNs::setns(&ns, Some(NetNs::CURRENT_NS_PATH))?;
        }
        Ok(Dispatcher {
            flavor: Mutex::new(Some(dispatcher)),
            terminated,
            running: AtomicBool::new(false),
            handle: Mutex::new(None),
        })
    }
}

#[cfg(target_os = "windows")]
impl DispatcherBuilder {
    fn get_engine(
        pcap_interfaces: &Option<Vec<Link>>,
        tap_mode: TapMode,
        options: &Arc<Mutex<Options>>,
    ) -> Result<RecvEngine> {
        match tap_mode {
            TapMode::Mirror | TapMode::Local => {
                if pcap_interfaces.is_none() || pcap_interfaces.as_ref().unwrap().is_empty() {
                    return Err(error::Error::WinPcap(
                        "windows pcap capture must give interface to capture packet".into(),
                    ));
                }
                let src_ifaces = pcap_interfaces
                    .as_ref()
                    .unwrap()
                    .iter()
                    .map(|src_iface| (src_iface.device_name.as_str(), src_iface.if_index as isize))
                    .collect();
                let options = options.lock().unwrap();
                let win_packet =
                    WinPacket::new(src_ifaces, options.win_packet_blocks, options.snap_len)
                        .map_err(|e| error::Error::WinPcap(e.to_string()))?;
                info!("WinPacket init");
                Ok(RecvEngine::WinPcap(Some(win_packet)))
            }
            _ => {
                return Err(Error::ConfigInvalid("Tap-mode not support.".into()));
            }
        }
    }

    pub fn pcap_interfaces(mut self, v: Vec<Link>) -> Self {
        self.pcap_interfaces = Some(v);
        self
    }
}

#[cfg(target_os = "linux")]
impl DispatcherBuilder {
    pub fn platform_poller(mut self, v: Arc<GenericPoller>) -> Self {
        self.platform_poller = Some(v);
        self
    }

    fn get_engine(
        src_interface: &mut Option<String>,
        tap_mode: TapMode,
        options: &Arc<Mutex<Options>>,
    ) -> Result<RecvEngine> {
        let options = options.lock().unwrap();
        match tap_mode {
            TapMode::Mirror if options.dpdk_conf.enabled => {
                #[cfg(target_arch = "s390x")]
                return Err(Error::ConfigInvalid(
                    "cpu arch s390x does not support DPDK!".into(),
                ));
                #[cfg(not(target_arch = "s390x"))]
                {
                    Ok(RecvEngine::Dpdk())
                }
            }
            TapMode::Local | TapMode::Mirror | TapMode::Analyzer => {
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
                    iface: src_interface.as_ref().unwrap_or(&"".to_string()).clone(),
                    ..Default::default()
                };
                info!("Afpacket init with {:?}", afp);
                Ok(RecvEngine::AfPacket(Tpacket::new(afp)?))
            }
            _ => {
                return Err(Error::ConfigInvalid("Tap-mode not support.".into()));
            }
        }
    }
}

const L2_MAC_ADDR_OFFSET: usize = 12;
