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

use std::ffi::{CStr, CString};
use std::ptr::{self, null_mut};
use std::slice;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ahash::HashSet;
use arc_swap::access::Access;
use libc::{c_int, c_ulonglong};
use log::{debug, error, info, warn};

use super::{Error, Result};
use crate::common::flow::L7Stats;
use crate::common::l7_protocol_log::{
    get_all_protocol, L7ProtocolBitmap, L7ProtocolParserInterface,
};
use crate::common::meta_packet::MetaPacket;
use crate::common::proc_event::{BoxedProcEvents, EventType, ProcEvent};
use crate::common::{FlowAclListener, FlowAclListenerId, TaggedFlow};
use crate::config::handler::{CollectorAccess, EbpfAccess, EbpfConfig, LogParserAccess};
use crate::config::FlowAccess;
use crate::ebpf;
use crate::exception::ExceptionHandler;
use crate::flow_generator::{flow_map::Config, AppProto, FlowMap};
use crate::integration_collector::Profile;
use crate::policy::PolicyGetter;
use crate::utils::stats;

use public::{
    buffer::BatchedBox,
    counter::{Countable, Counter, CounterType, CounterValue, OwnedCountable},
    debug::QueueDebugger,
    l7_protocol::L7Protocol,
    leaky_bucket::LeakyBucket,
    proto::{common::TridentType, metric, trident::Exception},
    queue::{bounded_with_debug, DebugSender, Receiver},
    utils::bitmap::parse_u16_range_list_to_bitmap,
};

pub struct EbpfCounter {
    rx: AtomicU64,
    get_token_failed: AtomicU64,
}

pub struct SyncEbpfCounter {
    counter: Arc<EbpfCounter>,
}

impl OwnedCountable for SyncEbpfCounter {
    fn get_counters(&self) -> Vec<Counter> {
        let rx = self.counter.rx.swap(0, Ordering::Relaxed);
        let get_token_failed = self.counter.get_token_failed.swap(0, Ordering::Relaxed);
        let ebpf_counter = unsafe { ebpf::socket_tracer_stats() };

        vec![
            (
                "collector_in",
                CounterType::Counted,
                CounterValue::Unsigned(rx),
            ),
            (
                "get_token_failed",
                CounterType::Counted,
                CounterValue::Unsigned(get_token_failed),
            ),
            (
                "perf_pages_count",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.perf_pages_count as u64),
            ),
            (
                "kern_lost",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.kern_lost),
            ),
            (
                "kern_socket_map_max",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.kern_socket_map_max as u64),
            ),
            (
                "kern_socket_map_used",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.kern_socket_map_used as u64),
            ),
            (
                "kern_trace_map_max",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.kern_trace_map_max as u64),
            ),
            (
                "kern_trace_map_used",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.kern_trace_map_used as u64),
            ),
            (
                "socket_map_max_reclaim",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.socket_map_max_reclaim as u64),
            ),
            (
                "worker_num",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.worker_num as u64),
            ),
            (
                "queue_capacity",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.queue_capacity as u64),
            ),
            (
                "user_enqueue_count",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.user_enqueue_count),
            ),
            (
                "user_dequeue_count",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.user_dequeue_count),
            ),
            (
                "user_enqueue_lost",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.user_enqueue_lost),
            ),
            (
                "queue_burst_count",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.queue_burst_count),
            ),
            (
                "is_adapt_success",
                CounterType::Counted,
                CounterValue::Unsigned(if ebpf_counter.is_adapt_success { 1 } else { 0 }),
            ),
            (
                "tracer_state",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.tracer_state as u64),
            ),
            (
                "boot_time_update_diff",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.boot_time_update_diff as u64),
            ),
            (
                "probes_count",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.probes_count as u64),
            ),
        ]
    }
    // EbpfCollector不会重复创建，这里都是false
    fn closed(&self) -> bool {
        false
    }
}

#[derive(Clone)]
struct EbpfDispatcher {
    dispatcher_id: usize,
    time_diff: Arc<AtomicI64>,

    receiver: Arc<Receiver<Box<MetaPacket<'static>>>>,

    pause: Arc<AtomicBool>,

    // 策略查询
    policy_getter: PolicyGetter,

    // GRPC配置
    log_parser_config: LogParserAccess,
    flow_map_config: FlowAccess,
    collector_config: CollectorAccess,

    config: EbpfAccess,
    output: DebugSender<Box<AppProto>>, // Send AppProtos to the AppProtoLogsParser
    flow_output: DebugSender<Arc<BatchedBox<TaggedFlow>>>, // Send TaggedFlows to the QuadrupleGenerator
    l7_stats_output: DebugSender<BatchedBox<L7Stats>>,     // Send L7Stats to the QuadrupleGenerator
    stats_collector: Arc<stats::Collector>,
}

impl EbpfDispatcher {
    const FLOW_MAP_SIZE: usize = 1 << 14;

    fn run(&self, counter: Arc<EbpfCounter>, exception_handler: ExceptionHandler) {
        let mut flow_map = FlowMap::new(
            self.dispatcher_id as u32,
            self.flow_output.clone(),
            self.l7_stats_output.clone(),
            self.policy_getter,
            self.output.clone(),
            self.time_diff.clone(),
            &self.flow_map_config.load(),
            None, // Enterprise Edition Feature: packet-sequence
            self.stats_collector.clone(),
            true, // from_ebpf
        );
        let ebpf_config = self.config.load();
        let leaky_bucket = LeakyBucket::new(Some(ebpf_config.ebpf.global_ebpf_pps_threshold));
        const QUEUE_BATCH_SIZE: usize = 1024;
        let mut batch = Vec::with_capacity(QUEUE_BATCH_SIZE);
        while unsafe { SWITCH } {
            let config = Config {
                flow: &self.flow_map_config.load(),
                log_parser: &self.log_parser_config.load(),
                collector: &self.collector_config.load(),
                ebpf: Some(&ebpf_config),
            };

            if self
                .receiver
                .recv_all(&mut batch, Some(Duration::from_secs(1)))
                .is_err()
            {
                flow_map.inject_flush_ticker(&config, Duration::ZERO);
                continue;
            }

            if self.pause.load(Ordering::Relaxed) {
                continue;
            }

            for mut packet in batch.drain(..) {
                if !leaky_bucket.acquire(1) {
                    counter.get_token_failed.fetch_add(1, Ordering::Relaxed);
                    exception_handler.set(Exception::RxPpsThresholdExceeded);
                    continue;
                }

                counter.rx.fetch_add(1, Ordering::Relaxed);

                packet.timestamp_adjust(self.time_diff.load(Ordering::Relaxed));
                packet.set_loopback_mac(ebpf_config.ctrl_mac);
                flow_map.inject_meta_packet(&config, &mut packet);
            }
        }
    }
}

pub struct SyncEbpfDispatcher {
    pause: Arc<AtomicBool>,
}

impl FlowAclListener for SyncEbpfDispatcher {
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
        self.pause.store(false, Ordering::Relaxed);
        Ok(())
    }

    fn id(&self) -> usize {
        u16::from(FlowAclListenerId::EbpfDispatcher) as usize
    }
}

pub struct EbpfCollector {
    thread_dispatcher: EbpfDispatcher,
    thread_handle: Option<JoinHandle<()>>,

    counter: Arc<EbpfCounter>,

    exception_handler: ExceptionHandler,
}

static mut SWITCH: bool = false;
static mut SENDER: Option<DebugSender<Box<MetaPacket>>> = None;
static mut PROC_EVENT_SENDER: Option<DebugSender<BoxedProcEvents>> = None;
static mut EBPF_PROFILE_SENDER: Option<DebugSender<Profile>> = None;
static mut POLICY_GETTER: Option<PolicyGetter> = None;
static mut ON_CPU_PROFILE_FREQUENCY: u32 = 0;
static mut TIME_DIFF: Option<Arc<AtomicI64>> = None;

impl EbpfCollector {
    #[cfg(target_arch = "x86_64")]
    unsafe fn convert_to_string(ptr: *const u8) -> String {
        CStr::from_ptr(ptr as *const i8)
            .to_string_lossy()
            .into_owned()
    }

    #[cfg(target_arch = "aarch64")]
    unsafe fn convert_to_string(ptr: *const u8) -> String {
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }

    extern "C" fn ebpf_l7_callback(sd: *mut ebpf::SK_BPF_DATA) {
        unsafe {
            if !SWITCH || SENDER.is_none() {
                return;
            }

            let container_id =
                Self::convert_to_string(ptr::addr_of!((*sd).container_id) as *const u8);
            let event_type = EventType::from(ptr::addr_of!((*sd).source).read_unaligned());
            if event_type != EventType::OtherEvent {
                // EbpfType like TracePoint, TlsUprobe, GoHttp2Uprobe belong to other events
                let event = ProcEvent::from_ebpf(sd, event_type);
                if event.is_err() {
                    warn!("proc event parse from ebpf error: {}", event.unwrap_err());
                    return;
                }
                let mut event = event.unwrap();
                if let Some(policy) = POLICY_GETTER.as_ref() {
                    event.0.pod_id = policy.lookup_pod_id(&container_id);
                }
                if let Err(e) = PROC_EVENT_SENDER.as_mut().unwrap().send(event) {
                    warn!("event send ebpf error: {:?}", e);
                }
                return;
            }
            let packet = MetaPacket::from_ebpf(sd);
            if packet.is_err() {
                warn!("meta packet parse from ebpf error: {}", packet.unwrap_err());
                return;
            }
            let mut packet = packet.unwrap();
            if let Some(policy) = POLICY_GETTER.as_ref() {
                packet.pod_id = policy.lookup_pod_id(&container_id);
            }
            if let Err(e) = SENDER.as_mut().unwrap().send(Box::new(packet)) {
                warn!("meta packet send ebpf error: {:?}", e);
            }
        }
    }

    #[cfg(not(feature = "off_cpu"))]
    fn get_event_type(_: u8) -> i32 {
        metric::ProfileEventType::EbpfOnCpu.into()
    }

    #[cfg(feature = "off_cpu")]
    fn get_event_type(profiler_type: u8) -> i32 {
        match profiler_type {
            ebpf::PROFILER_TYPE_ONCPU => metric::ProfileEventType::EbpfOnCpu.into(),
            ebpf::PROFILER_TYPE_OFFCPU => metric::ProfileEventType::EbpfOffCpu.into(),
            _ => {
                warn!(
                    "ebpf profile data with invalid event type: {}",
                    profiler_type
                );
                metric::ProfileEventType::EbpfOnCpu.into()
            }
        }
    }

    extern "C" fn ebpf_profiler_callback(data: *mut ebpf::stack_profile_data) {
        unsafe {
            if !SWITCH || EBPF_PROFILE_SENDER.is_none() {
                return;
            }
            let mut profile = metric::Profile::default();
            let data = &mut *data;
            profile.sample_rate = ON_CPU_PROFILE_FREQUENCY;
            profile.timestamp = data.timestamp;
            profile.event_type = Self::get_event_type(data.profiler_type);
            profile.stime = data.stime;
            profile.pid = data.pid;
            profile.tid = data.tid;
            profile.thread_name = Self::convert_to_string(data.comm.as_ptr());
            profile.process_name = Self::convert_to_string(data.process_name.as_ptr());
            profile.u_stack_id = data.u_stack_id;
            profile.k_stack_id = data.k_stack_id;
            profile.cpu = data.cpu;
            profile.count = data.count;
            profile.data =
                slice::from_raw_parts(data.stack_data as *mut u8, data.stack_data_len as usize)
                    .to_vec();
            let container_id = Self::convert_to_string(data.container_id.as_ptr());
            if let Some(policy_getter) = POLICY_GETTER.as_ref() {
                profile.pod_id = policy_getter.lookup_pod_id(&container_id);
            }
            if let Err(e) = EBPF_PROFILE_SENDER.as_mut().unwrap().send(Profile(profile)) {
                warn!("ebpf profile send error: {:?}", e);
            }
        }
    }

    fn ebpf_init(
        config: &EbpfConfig,
        sender: DebugSender<Box<MetaPacket<'static>>>,
        proc_event_sender: DebugSender<BoxedProcEvents>,
        ebpf_profile_sender: DebugSender<Profile>,
        l7_protocol_enabled_bitmap: L7ProtocolBitmap,
        policy_getter: PolicyGetter,
        time_diff: Arc<AtomicI64>,
    ) -> Result<()> {
        // ebpf内核模块初始化
        unsafe {
            if !config.ebpf.uprobe_proc_regexp.golang.is_empty() {
                info!(
                    "ebpf set golang uprobe proc regexp: {}",
                    config.ebpf.uprobe_proc_regexp.golang.as_str()
                );
                ebpf::set_feature_regex(
                    ebpf::FEATURE_UPROBE_GOLANG,
                    CString::new(config.ebpf.uprobe_proc_regexp.golang.as_str().as_bytes())
                        .unwrap()
                        .as_c_str()
                        .as_ptr(),
                );
            } else {
                info!("ebpf golang uprobe proc regexp is empty, skip set")
            }

            if !config.ebpf.uprobe_proc_regexp.openssl.is_empty() {
                info!(
                    "ebpf set openssl uprobe proc regexp: {}",
                    config.ebpf.uprobe_proc_regexp.openssl.as_str()
                );
                ebpf::set_feature_regex(
                    ebpf::FEATURE_UPROBE_OPENSSL,
                    CString::new(config.ebpf.uprobe_proc_regexp.openssl.as_str().as_bytes())
                        .unwrap()
                        .as_c_str()
                        .as_ptr(),
                );
            } else {
                info!("ebpf openssl uprobe proc regexp is empty, skip set")
            }

            if !config.ebpf.uprobe_proc_regexp.golang_symbol.is_empty() {
                info!(
                    "ebpf set golang symbol uprobe proc regexp: {}",
                    config.ebpf.uprobe_proc_regexp.golang_symbol.as_str()
                );
                ebpf::set_feature_regex(
                    ebpf::FEATURE_UPROBE_GOLANG_SYMBOL,
                    CString::new(
                        config
                            .ebpf
                            .uprobe_proc_regexp
                            .golang_symbol
                            .as_str()
                            .as_bytes(),
                    )
                    .unwrap()
                    .as_c_str()
                    .as_ptr(),
                );
            } else {
                info!("ebpf golang symbol proc regexp is empty, skip set")
            }

            for i in get_all_protocol().into_iter() {
                if l7_protocol_enabled_bitmap.is_enabled(i.protocol()) {
                    info!("l7 protocol {:?} parse enabled", i.protocol());
                    ebpf::enable_ebpf_protocol(i.protocol() as ebpf::c_int);
                }
            }

            let white_list = &config.ebpf.kprobe_whitelist;
            if !white_list.port_list.is_empty() {
                if let Some(b) = parse_u16_range_list_to_bitmap(&white_list.port_list, false) {
                    ebpf::set_allow_port_bitmap(b.get_raw_ptr());
                }
            }

            let black_list = &config.ebpf.kprobe_blacklist;
            if !black_list.port_list.is_empty() {
                if let Some(b) = parse_u16_range_list_to_bitmap(&black_list.port_list, false) {
                    ebpf::set_bypass_port_bitmap(b.get_raw_ptr());
                }
            }

            if ebpf::bpf_tracer_init(null_mut(), true) != 0 {
                info!("ebpf bpf_tracer_init error.");
                return Err(Error::EbpfInitError);
            }

            if ebpf::set_go_tracing_timeout(config.ebpf.go_tracing_timeout as c_int) != 0 {
                info!("ebpf set_go_tracing_timeout error.",);
                return Err(Error::EbpfInitError);
            }

            if ebpf::set_io_event_collect_mode(config.ebpf.io_event_collect_mode as c_int) != 0 {
                info!(
                    "ebpf set_io_event_collect_mode error: {}",
                    config.ebpf.io_event_collect_mode
                );
                return Err(Error::EbpfInitError);
            }

            if ebpf::set_io_event_minimal_duration(
                config.ebpf.io_event_minimal_duration.as_nanos() as c_ulonglong
            ) != 0
            {
                info!(
                    "ebpf set_io_event_minimal_duration error: {:?}",
                    config.ebpf.io_event_minimal_duration
                );
                return Err(Error::EbpfInitError);
            }

            let mut all_proto_map = get_all_protocol()
                .iter()
                .map(|p| p.as_str().to_lowercase())
                .collect::<HashSet<String>>();
            for (protocol, port_range) in &config.l7_protocol_ports {
                all_proto_map.remove(&protocol.to_lowercase());
                let l7_protocol = L7Protocol::from(protocol.clone());
                let ports = CString::new(port_range.as_str()).unwrap();
                if ebpf::set_protocol_ports_bitmap(u8::from(l7_protocol) as i32, ports.as_ptr())
                    != 0
                {
                    warn!(
                        "Ebpf set_protocol_ports_bitmap error: {} {}",
                        protocol, port_range
                    );
                }
            }

            // if not config the port range, default is parse in all port
            let all_port = "1-65535".to_string();
            for protocol in all_proto_map.iter() {
                let l7_protocol = L7Protocol::from(protocol.clone());
                let ports = CString::new(all_port.as_str()).unwrap();
                if ebpf::set_protocol_ports_bitmap(u8::from(l7_protocol) as i32, ports.as_ptr())
                    != 0
                {
                    warn!(
                        "Ebpf set_protocol_ports_bitmap error: {} {}",
                        protocol, all_port
                    );
                }
            }

            if ebpf::running_socket_tracer(
                Self::ebpf_l7_callback,                    /* 回调接口 rust -> C */
                config.ebpf.thread_num as i32, /* 工作线程数，是指用户态有多少线程参与数据处理 */
                config.ebpf.perf_pages_count as u32, /* 内核共享内存占用的页框数量, 值为2的次幂。用于perf数据传递 */
                config.ebpf.ring_size as u32, /* 环形缓存队列大小，值为2的次幂。e.g: 2,4,8,16,32,64,128 */
                config.ebpf.max_socket_entries as u32, /* 设置用于socket追踪的hash表项最大值，取决于实际场景中并发请求数量 */
                config.ebpf.max_trace_entries as u32, /* 设置用于线程追踪会话的hash表项最大值，SK_BPF_DATA结构的syscall_trace_id_session关联这个哈希表 */
                config.ebpf.socket_map_max_reclaim as u32, /* socket map表项进行清理的最大阈值，当前map的表项数量超过这个值进行map清理操作 */
            ) != 0
            {
                return Err(Error::EbpfRunningError);
            }

            let ebpf_conf = &config.ebpf;
            let on_cpu = &ebpf_conf.on_cpu_profile;
            let off_cpu = &ebpf_conf.off_cpu_profile;

            let profiler_enabled =
                !on_cpu.disabled || (cfg!(feature = "off_cpu") && !off_cpu.disabled);
            if profiler_enabled {
                if !on_cpu.disabled {
                    ebpf::enable_oncpu_profiler();
                } else {
                    ebpf::disable_oncpu_profiler();
                }

                #[cfg(feature = "off_cpu")]
                if !off_cpu.disabled {
                    ebpf::enable_offcpu_profiler();
                } else {
                    ebpf::disable_offcpu_profiler();
                }

                if ebpf::start_continuous_profiler(
                    on_cpu.frequency as i32,
                    ebpf_conf.java_symbol_file_max_space_limit as i32,
                    ebpf_conf.java_symbol_file_refresh_defer_interval.as_secs() as i32,
                    Self::ebpf_profiler_callback,
                ) != 0
                {
                    info!("ebpf start_continuous_profiler error.");
                    return Err(Error::EbpfInitError);
                }

                if !on_cpu.disabled {
                    ebpf::set_profiler_regex(
                        CString::new(on_cpu.regex.as_bytes())
                            .unwrap()
                            .as_c_str()
                            .as_ptr(),
                    );

                    // CPUID will not be included in the aggregation of stack trace data.
                    ebpf::set_profiler_cpu_aggregation(on_cpu.cpu as i32);
                }

                #[cfg(feature = "off_cpu")]
                if !off_cpu.disabled {
                    ebpf::set_offcpu_profiler_regex(
                        CString::new(off_cpu.regex.as_bytes())
                            .unwrap()
                            .as_c_str()
                            .as_ptr(),
                    );

                    ebpf::set_offcpu_cpuid_aggregation(off_cpu.cpu as i32);
                    ebpf::set_offcpu_minblock_time(off_cpu.min_block.as_micros() as u32);
                }
            }

            ebpf::bpf_tracer_finish();
        }
        // ebpf和ebpf collector通信配置初始化
        unsafe {
            SWITCH = false;
            SENDER = Some(sender);
            PROC_EVENT_SENDER = Some(proc_event_sender);
            EBPF_PROFILE_SENDER = Some(ebpf_profile_sender);
            POLICY_GETTER = Some(policy_getter);
            ON_CPU_PROFILE_FREQUENCY = config.ebpf.on_cpu_profile.frequency as u32;
            TIME_DIFF = Some(time_diff);
        }

        Ok(())
    }

    fn ebpf_on_config_change(l7_log_packet_size: usize) {
        unsafe {
            let n = ebpf::set_data_limit_max(l7_log_packet_size as c_int);
            if n < 0 {
                warn!(
                    "ebpf set l7_log_packet_size({}) failed.",
                    l7_log_packet_size
                );
            } else if n != l7_log_packet_size as c_int {
                info!(
                    "ebpf set l7_log_packet_size to {}, actual effective configuration is {}.",
                    l7_log_packet_size, n
                );
            }
        }
    }

    fn ebpf_start() {
        debug!("ebpf collector starting ebpf-kernel.");
        unsafe {
            const RETRY_MAX: i32 = 50;
            let mut retry_count = 0;
            /*
             * The eBPF socket_tracer_start() can be executed successfully only after the eBPF
             * initialization is complete and the eBPF is in the STOP state.Need to wait
             * for the initialization of tracer and the state transition to complete.
             * The maximum waiting time is 100 seconds, more than this will throw an error.
             */
            while ebpf::socket_tracer_start() != 0 && retry_count < RETRY_MAX {
                std::thread::sleep(Duration::from_secs(2));
                retry_count = retry_count + 1;
                if retry_count >= RETRY_MAX {
                    error!(
                        "[eBPF Kernel Adapt] The socket_tracer_start() \
                            error. Kernel offset adapt failed. \
                            Please ensure that BTF is enabled (kernel built \
                            with CONFIG_DEBUG_INFO_BTF=y option). If the current \
                            kernel version is low (<5.2), upgrading the Linux kernel \
                            to 5.2+ (kernel built with CONFIG_DEBUG_INFO_BTF=y option) \
                            can solve the problem. If it is not possible to upgrade \
                            the kernel, the kernel-devel package can be provided for \
                            developers to adapt and solve the problem."
                    );
                }
            }
        }
    }

    fn ebpf_stop() {
        info!("ebpf collector stopping ebpf-kernel.");
        unsafe {
            ebpf::socket_tracer_stop();
        }
    }

    pub fn new(
        dispatcher_id: usize,
        time_diff: Arc<AtomicI64>,
        config: EbpfAccess,
        log_parser_config: LogParserAccess,
        flow_map_config: FlowAccess,
        collector_config: CollectorAccess,
        policy_getter: PolicyGetter,
        output: DebugSender<Box<AppProto>>,
        flow_output: DebugSender<Arc<BatchedBox<TaggedFlow>>>,
        l7_stats_output: DebugSender<BatchedBox<L7Stats>>,
        proc_event_output: DebugSender<BoxedProcEvents>,
        ebpf_profile_sender: DebugSender<Profile>,
        queue_debugger: &QueueDebugger,
        stats_collector: Arc<stats::Collector>,
        exception_handler: ExceptionHandler,
    ) -> Result<Box<Self>> {
        let ebpf_config = config.load();
        if ebpf_config.ebpf.disabled {
            info!("ebpf collector disabled.");
            return Err(Error::EbpfDisabled);
        }
        info!("ebpf collector init...");
        let queue_name = "0-ebpf-to-ebpf-collector";
        let (sender, receiver, counter) =
            bounded_with_debug(ebpf_config.queue_size, queue_name, queue_debugger);
        stats_collector.register_countable(
            &stats::QueueStats {
                id: 0,
                module: queue_name,
            },
            Countable::Owned(Box::new(counter)),
        );

        Self::ebpf_init(
            &ebpf_config,
            sender,
            proc_event_output,
            ebpf_profile_sender,
            ebpf_config.l7_protocol_enabled_bitmap,
            policy_getter,
            time_diff.clone(),
        )?;
        Self::ebpf_on_config_change(ebpf::CAP_LEN_MAX);

        info!("ebpf collector initialized.");
        Ok(Box::new(EbpfCollector {
            thread_dispatcher: EbpfDispatcher {
                dispatcher_id,
                time_diff,
                receiver: Arc::new(receiver),
                policy_getter,
                config,
                log_parser_config,
                output,
                flow_output,
                l7_stats_output,
                flow_map_config,
                stats_collector,
                collector_config,
                pause: Arc::new(AtomicBool::new(true)),
            },
            thread_handle: None,
            counter: Arc::new(EbpfCounter {
                rx: AtomicU64::new(0),
                get_token_failed: AtomicU64::new(0),
            }),
            exception_handler,
        }))
    }

    pub fn get_sync_counter(&self) -> SyncEbpfCounter {
        SyncEbpfCounter {
            counter: self.counter.clone(),
        }
    }

    pub fn get_sync_dispatcher(&self) -> SyncEbpfDispatcher {
        SyncEbpfDispatcher {
            pause: self.thread_dispatcher.pause.clone(),
        }
    }

    pub fn on_config_change(&mut self, config: &EbpfConfig) {
        if config.l7_log_enabled() {
            unsafe {
                if SWITCH {
                    self.stop();
                }
            }
            self.start();
            Self::ebpf_on_config_change(config.l7_log_packet_size);
        } else {
            self.stop();
        }
    }

    pub fn start(&mut self) {
        unsafe {
            if SWITCH {
                info!("ebpf collector started");
                return;
            }
            SWITCH = true;
        }

        let sync_counter = self.counter.clone();
        let exception_handler = self.exception_handler.clone();
        let dispatcher = self.thread_dispatcher.clone();
        self.thread_handle = Some(
            thread::Builder::new()
                .name("ebpf-collector".to_owned())
                .spawn(move || dispatcher.run(sync_counter, exception_handler))
                .unwrap(),
        );

        debug!("ebpf collector starting ebpf-kernel.");
        Self::ebpf_start();
        info!("ebpf collector started");
    }

    pub fn notify_stop(&mut self) -> Option<JoinHandle<()>> {
        unsafe {
            if !SWITCH {
                info!("ebpf collector stopped.");
                return None;
            }
            SWITCH = false;
        }
        Self::ebpf_stop();

        info!("notified ebpf collector stopping thread.");
        self.thread_handle.take()
    }

    pub fn stop(&mut self) {
        unsafe {
            if !SWITCH {
                info!("ebpf collector stopped.");
                return;
            }
            SWITCH = false;
        }
        Self::ebpf_stop();

        info!("ebpf collector stopping thread.");
        if let Some(handler) = self.thread_handle.take() {
            let _ = handler.join();
        }
        info!("ebpf collector stopped.");
    }
}

impl Drop for EbpfCollector {
    fn drop(&mut self) {
        self.stop();
    }
}
