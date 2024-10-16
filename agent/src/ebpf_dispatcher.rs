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

/* example

```
use trident::common::protocol_logs::AppProtoLogsData;
use trident::ebpf_collector::ebpf_collector::EbpfCollector;
use trident::utils::queue::bounded;

fn main() {
    let (s, r, _) = bounded::<Box<AppProtoLogsData>>(1024);
    let mut collector = EbpfCollector::new(s).unwrap();

    collector.start();

    loop {
        if let Ok(msg) = r.recv(None) {
            println!("{}", msg);
        }
    }
}
```

 */

#[cfg(feature = "extended_profile")]
pub mod memory_profile;

use std::ffi::{CStr, CString};
use std::ptr::{self, null_mut};
use std::slice;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ahash::HashSet;
use arc_swap::access::Access;
use libc::{c_int, c_ulonglong, c_void};
use log::{debug, error, info, warn};
use thiserror::Error;
use zstd::bulk::compress;

use crate::common::ebpf::EbpfType;
use crate::common::flow::L7Stats;
use crate::common::l7_protocol_log::{
    get_all_protocol, L7ProtocolBitmap, L7ProtocolParserInterface,
};
use crate::common::meta_packet::{MetaPacket, SegmentFlags};
use crate::common::proc_event::{BoxedProcEvents, EventType, ProcEvent};
use crate::common::{FlowAclListener, FlowAclListenerId};
use crate::config::handler::{CollectorAccess, EbpfAccess, EbpfConfig, LogParserAccess};
use crate::config::FlowAccess;
use crate::ebpf;
use crate::exception::ExceptionHandler;
use crate::flow_generator::{flow_map::Config, AppProto, FlowMap};
use crate::integration_collector::Profile;
use crate::platform::ProcessData;
use crate::policy::PolicyGetter;
use crate::rpc::get_timestamp;
use crate::utils::{process::ProcessListener, stats};

use public::{
    buffer::BatchedBox,
    counter::{Countable, Counter, CounterType, CounterValue, OwnedCountable},
    debug::QueueDebugger,
    l7_protocol::{L7Protocol, L7ProtocolChecker},
    leaky_bucket::LeakyBucket,
    proto::{
        agent::{AgentType, Exception},
        metric,
    },
    queue::{bounded_with_debug, DebugSender, Receiver},
    utils::bitmap::parse_u16_range_list_to_bitmap,
};
use reorder::{Reorder, ReorderCounter, StatsReorderCounter};

#[derive(Debug, Error)]
pub enum Error {
    #[error("ebpf init error.")]
    EbpfInitError,
    #[error("ebpf running error.")]
    EbpfRunningError,
    #[error("l7 parse error.")]
    EbpfL7ParseError,
    #[error("l7 get log info error.")]
    EbpfL7GetLogInfoError,
    #[error("ebpf disabled.")]
    EbpfDisabled,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

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
            (
                "period_push_conflict_count",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.period_push_conflict_count as u64),
            ),
            (
                "period_push_max_delay",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.period_push_max_delay as u64),
            ),
            (
                "period_push_avg_delay",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.period_push_avg_delay as u64),
            ),
            (
                "proc_exec_event_count",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.proc_exec_event_count as u64),
            ),
            (
                "proc_exit_event_count",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.proc_exit_event_count as u64),
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
    l7_stats_output: DebugSender<BatchedBox<L7Stats>>, // Send L7Stats to the QuadrupleGenerator
    stats_collector: Arc<stats::Collector>,
}

impl EbpfDispatcher {
    fn segmentation_reassembly<'a>(
        packets: &'a mut Vec<Box<MetaPacket<'a>>>,
    ) -> Vec<Box<MetaPacket<'a>>> {
        let mut merge_packets: Vec<Box<MetaPacket<'a>>> = vec![];
        for mut p in packets.drain(..) {
            if p.segment_flags != SegmentFlags::Seg {
                merge_packets.push(p);
                continue;
            }

            let Some(last) = merge_packets.last_mut() else {
                merge_packets.push(p);
                continue;
            };

            if last.generate_ebpf_flow_id() == p.generate_ebpf_flow_id()
                && last.segment_flags == SegmentFlags::Start
                && last.cap_end_seq + 1 == p.cap_start_seq
            {
                last.merge(&mut p);
            } else {
                merge_packets.push(p);
            }
        }

        merge_packets
    }

    fn inject_flush_ticker(
        timestamp: Duration,
        flow_map: &mut FlowMap,
        config: &Config,
        reorder: &mut Reorder,
    ) {
        let mut packets = reorder.flush(timestamp.as_millis() as u64);
        let mut packets = packets
            .drain(..)
            .map(|x| x.into_any().downcast::<MetaPacket>().unwrap())
            .collect::<Vec<Box<MetaPacket>>>();
        let packets = Self::segmentation_reassembly(&mut packets);
        let need_flush = packets.is_empty();
        for mut packet in packets {
            flow_map.inject_meta_packet(&config, &mut packet);
        }
        if need_flush {
            flow_map.inject_flush_ticker(config, timestamp);
        }
    }

    fn inject_meta_packet(
        mut packet: Box<MetaPacket<'static>>,
        flow_map: &mut FlowMap,
        config: &Config,
        reorder: &mut Reorder,
    ) {
        let mut packets = match packet.ebpf_type {
            EbpfType::GoHttp2Uprobe | EbpfType::GoHttp2UprobeData => {
                flow_map.inject_meta_packet(config, &mut packet);
                reorder.flush(packet.lookup_key.timestamp.as_millis() as u64)
            }
            _ => reorder.inject_item(packet),
        };
        let mut packets = packets
            .drain(..)
            .map(|x| x.into_any().downcast::<MetaPacket>().unwrap())
            .collect::<Vec<Box<MetaPacket>>>();
        let packets = Self::segmentation_reassembly(&mut packets);
        for mut packet in packets {
            flow_map.inject_meta_packet(config, &mut packet);
        }
    }

    fn run(&self, counter: Arc<EbpfCounter>, exception_handler: ExceptionHandler) {
        let ebpf_config = self.config.load();
        let out_of_order_reassembly_bitmap = L7ProtocolBitmap::from(
            ebpf_config
                .ebpf
                .socket
                .preprocess
                .out_of_order_reassembly_protocols
                .as_slice(),
        );
        let reorder_counter = Arc::new(ReorderCounter::default());
        self.stats_collector.register_countable(
            &stats::NoTagModule("ebpf-collector-reorder"),
            Countable::Owned(Box::new(StatsReorderCounter::new(reorder_counter.clone()))),
        );
        let mut reorder = Reorder::new(
            Box::new(out_of_order_reassembly_bitmap),
            reorder_counter,
            ebpf_config
                .ebpf
                .socket
                .preprocess
                .out_of_order_reassembly_cache_size,
        );
        let mut flow_map = FlowMap::new(
            self.dispatcher_id as u32,
            None,
            self.l7_stats_output.clone(),
            self.policy_getter,
            self.output.clone(),
            self.time_diff.clone(),
            &self.flow_map_config.load(),
            None, // Enterprise Edition Feature: packet-sequence
            self.stats_collector.clone(),
            true, // from_ebpf
        );
        let leaky_bucket = LeakyBucket::new(Some(ebpf_config.ebpf.socket.tunning.max_capture_rate));
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
                Self::inject_flush_ticker(
                    get_timestamp(self.time_diff.load(Ordering::Relaxed)),
                    &mut flow_map,
                    &config,
                    &mut reorder,
                );
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
                Self::inject_meta_packet(packet, &mut flow_map, &config, &mut reorder);
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
        _: AgentType,
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

#[derive(Default)]
struct ConfigHandle {
    #[cfg(feature = "extended_profile")]
    memory_profile_settings: Option<memory_profile::MemoryContextSettings>,
}

pub struct EbpfCollector {
    thread_dispatcher: EbpfDispatcher,
    thread_handle: Option<JoinHandle<()>>,

    config_handle: ConfigHandle,

    counter: Arc<EbpfCounter>,

    exception_handler: ExceptionHandler,
    process_listener: Arc<ProcessListener>,
}

static mut SWITCH: bool = false;
static mut SENDER: Option<DebugSender<Box<MetaPacket>>> = None;
static mut PROC_EVENT_SENDER: Option<DebugSender<BoxedProcEvents>> = None;
static mut EBPF_PROFILE_SENDER: Option<DebugSender<Profile>> = None;
static mut POLICY_GETTER: Option<PolicyGetter> = None;
static mut ON_CPU_PROFILE_FREQUENCY: u32 = 0;
static mut PROFILE_STACK_COMPRESSION: bool = true;
static mut TIME_DIFF: Option<Arc<AtomicI64>> = None;

pub unsafe fn string_from_null_terminated_c_str(ptr: *const u8) -> String {
    CStr::from_ptr(ptr as *const libc::c_char)
        .to_string_lossy()
        .into_owned()
}

impl EbpfCollector {
    extern "C" fn ebpf_l7_callback(_: *mut c_void, sd: *mut ebpf::SK_BPF_DATA) {
        unsafe {
            if !SWITCH || SENDER.is_none() {
                return;
            }

            let container_id =
                CStr::from_ptr(ptr::addr_of!((*sd).container_id) as *const libc::c_char)
                    .to_string_lossy();
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

    extern "C" fn ebpf_profiler_callback(
        #[allow(unused)] ctx: *mut c_void,
        data: *mut ebpf::stack_profile_data,
    ) {
        unsafe {
            if !SWITCH || EBPF_PROFILE_SENDER.is_none() {
                return;
            }
            let data = &mut *data;

            #[cfg(feature = "extended_profile")]
            if data.profiler_type == ebpf::PROFILER_TYPE_MEMORY {
                let mut ts_nanos = data.timestamp;
                if let Some(time_diff) = TIME_DIFF.as_ref() {
                    let diff = time_diff.load(Ordering::Relaxed);
                    if diff > 0 {
                        ts_nanos += diff as u64;
                    } else {
                        ts_nanos -= (-diff) as u64;
                    }
                }
                let Some(m_ctx) = (ctx as *mut memory_profile::MemoryContext).as_mut() else {
                    return;
                };
                m_ctx.update(data);
                m_ctx.report(
                    Duration::from_nanos(ts_nanos),
                    EBPF_PROFILE_SENDER.as_mut().unwrap(),
                );
                return;
            }

            let mut profile = metric::Profile::default();
            profile.sample_rate = ON_CPU_PROFILE_FREQUENCY;
            profile.timestamp = data.timestamp;
            if let Some(time_diff) = TIME_DIFF.as_ref() {
                let diff = time_diff.load(Ordering::Relaxed);
                if diff > 0 {
                    profile.timestamp += diff as u64;
                } else {
                    profile.timestamp -= (-diff) as u64;
                }
            }
            profile.event_type = match data.profiler_type {
                #[cfg(feature = "extended_profile")]
                ebpf::PROFILER_TYPE_OFFCPU => metric::ProfileEventType::EbpfOffCpu.into(),
                _ => metric::ProfileEventType::EbpfOnCpu.into(),
            };
            profile.stime = data.stime;
            profile.pid = data.pid;
            profile.tid = data.tid;
            profile.thread_name = string_from_null_terminated_c_str(data.comm.as_ptr());
            profile.process_name = string_from_null_terminated_c_str(data.process_name.as_ptr());
            profile.u_stack_id = data.u_stack_id;
            profile.k_stack_id = data.k_stack_id;
            profile.cpu = data.cpu;
            profile.count = data.count as u32;
            profile.wide_count = data.count;
            let profile_data =
                slice::from_raw_parts(data.stack_data as *mut u8, data.stack_data_len as usize);
            if PROFILE_STACK_COMPRESSION {
                match compress(&profile_data, 0) {
                    Ok(compressed_data) => {
                        profile.data_compressed = true;
                        profile.data = compressed_data;
                    }
                    Err(e) => {
                        profile.data = profile_data.to_vec();
                        debug!("failed to compress ebpf profile: {:?}", e);
                    }
                }
            } else {
                profile.data = profile_data.to_vec();
            }
            let container_id =
                CStr::from_ptr(data.container_id.as_ptr() as *const libc::c_char).to_string_lossy();
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
        policy_getter: PolicyGetter,
        time_diff: Arc<AtomicI64>,
        process_listener: &ProcessListener,
    ) -> Result<ConfigHandle> {
        // ebpf和ebpf collector通信配置初始化
        unsafe {
            let handle = Self::ebpf_core_init(process_listener, config);
            // initialize communication between core and ebpf collector
            SWITCH = false;
            SENDER = Some(sender);
            PROC_EVENT_SENDER = Some(proc_event_sender);
            EBPF_PROFILE_SENDER = Some(ebpf_profile_sender);
            POLICY_GETTER = Some(policy_getter);
            ON_CPU_PROFILE_FREQUENCY = config.ebpf.profile.on_cpu.sampling_frequency as u32;
            PROFILE_STACK_COMPRESSION = config.ebpf.profile.preprocess.stack_compression;
            TIME_DIFF = Some(time_diff);
            handle
        }
    }

    unsafe fn ebpf_core_init(
        process_listener: &ProcessListener,
        config: &EbpfConfig,
    ) -> Result<ConfigHandle> {
        // ebpf core modules init
        #[allow(unused_mut)]
        let mut handle = ConfigHandle::default();
        ebpf::set_uprobe_golang_enabled(config.ebpf.socket.uprobe.golang.enabled);
        if config.ebpf.socket.uprobe.golang.enabled {
            let feature = "ebpf.socket.uprobe.golang";
            process_listener.register(feature, set_feature_uprobe_golang);

            let uprobe_proc_regexp = config
                .process_matcher
                .iter()
                .find(|p| {
                    p.enabled_features
                        .iter()
                        .find(|f| f.eq_ignore_ascii_case(feature))
                        .is_some()
                })
                .map(|p| p.match_regex.as_str())
                .unwrap_or_default();
            info!("ebpf set golang uprobe proc regexp: {}", uprobe_proc_regexp);
            ebpf::set_feature_regex(
                ebpf::FEATURE_UPROBE_GOLANG,
                CString::new(uprobe_proc_regexp.as_bytes())
                    .unwrap()
                    .as_c_str()
                    .as_ptr(),
            );
        } else {
            info!("ebpf golang uprobe proc regexp is empty, skip set")
        }

        ebpf::set_uprobe_openssl_enabled(config.ebpf.socket.uprobe.tls.enabled);
        if config.ebpf.socket.uprobe.tls.enabled {
            let feature = "ebpf.socket.uprobe.tls";
            process_listener.register(feature, set_feature_uprobe_tls);

            let uprobe_proc_regexp = config
                .process_matcher
                .iter()
                .find(|p| {
                    p.enabled_features
                        .iter()
                        .find(|f| f.eq_ignore_ascii_case(feature))
                        .is_some()
                })
                .map(|p| p.match_regex.as_str())
                .unwrap_or_default();
            info!(
                "ebpf set openssl uprobe proc regexp: {}",
                uprobe_proc_regexp
            );
            ebpf::set_feature_regex(
                ebpf::FEATURE_UPROBE_OPENSSL,
                CString::new(uprobe_proc_regexp.as_bytes())
                    .unwrap()
                    .as_c_str()
                    .as_ptr(),
            );
        } else {
            info!("ebpf openssl uprobe proc regexp is empty, skip set")
        }

        if config.symbol_table.golang_specific.enabled {
            let feature = "proc.golang_symbol_table";
            process_listener.register(feature, set_feature_uprobe_golang_symbol);

            let uprobe_proc_regexp = config
                .process_matcher
                .iter()
                .find(|p| {
                    p.enabled_features
                        .iter()
                        .find(|f| f.eq_ignore_ascii_case(feature))
                        .is_some()
                })
                .map(|p| p.match_regex.as_str())
                .unwrap_or_default();
            info!(
                "ebpf set golang symbol uprobe proc regexp: {}",
                uprobe_proc_regexp
            );
            ebpf::set_feature_regex(
                ebpf::FEATURE_UPROBE_GOLANG_SYMBOL,
                CString::new(uprobe_proc_regexp.as_bytes())
                    .unwrap()
                    .as_c_str()
                    .as_ptr(),
            );
        } else {
            info!("ebpf golang symbol proc regexp is empty, skip set")
        }

        for i in get_all_protocol().into_iter() {
            if config.l7_protocol_enabled_bitmap.is_enabled(i.protocol()) {
                info!("l7 protocol {:?} parse enabled", i.protocol());
                ebpf::enable_ebpf_protocol(i.protocol() as ebpf::c_int);
            }
        }

        let segmentation_reassembly_bitmap = L7ProtocolBitmap::from(
            config
                .ebpf
                .socket
                .preprocess
                .segmentation_reassembly_protocols
                .as_slice(),
        );
        for i in get_all_protocol().into_iter() {
            if segmentation_reassembly_bitmap.is_enabled(i.protocol()) {
                info!(
                    "l7 protocol {:?} segmentation reassembly enabled",
                    i.protocol()
                );
                ebpf::enable_ebpf_seg_reasm_protocol(i.protocol() as ebpf::c_int);
            }
        }

        let white_list = &config.ebpf.socket.kprobe.whitelist;
        if !white_list.ports.is_empty() {
            if let Some(b) = parse_u16_range_list_to_bitmap(&white_list.ports, false) {
                ebpf::set_allow_port_bitmap(b.get_raw_ptr());
            }
        }

        let black_list = &config.ebpf.socket.kprobe.blacklist;
        if !black_list.ports.is_empty() {
            if let Some(b) = parse_u16_range_list_to_bitmap(&black_list.ports, false) {
                ebpf::set_bypass_port_bitmap(b.get_raw_ptr());
            }
        }

        if ebpf::bpf_tracer_init(null_mut(), true) != 0 {
            info!("ebpf bpf_tracer_init error.");
            return Err(Error::EbpfInitError);
        }

        if ebpf::set_go_tracing_timeout(
            config.ebpf.socket.uprobe.golang.tracing_timeout.as_secs() as c_int
        ) != 0
        {
            info!("ebpf set_go_tracing_timeout error.",);
            return Err(Error::EbpfInitError);
        }

        if ebpf::set_io_event_collect_mode(config.ebpf.file.io_event.collect_mode as c_int) != 0 {
            info!(
                "ebpf set_io_event_collect_mode error: {}",
                config.ebpf.file.io_event.collect_mode
            );
            return Err(Error::EbpfInitError);
        }

        if ebpf::set_io_event_minimal_duration(
            config.ebpf.file.io_event.minimal_duration.as_nanos() as c_ulonglong,
        ) != 0
        {
            info!(
                "ebpf set_io_event_minimal_duration error: {:?}",
                config.ebpf.file.io_event.minimal_duration
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
            if ebpf::set_protocol_ports_bitmap(u8::from(l7_protocol) as i32, ports.as_ptr()) != 0 {
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
            if ebpf::set_protocol_ports_bitmap(u8::from(l7_protocol) as i32, ports.as_ptr()) != 0 {
                warn!(
                    "Ebpf set_protocol_ports_bitmap error: {} {}",
                    protocol, all_port
                );
            }
        }

        if config.ebpf.socket.tunning.syscall_trace_id_disabled {
            ebpf::disable_syscall_trace_id();
        }

        ebpf::set_bpf_map_prealloc(!config.ebpf.socket.tunning.map_prealloc_disabled);

        if ebpf::running_socket_tracer(
            Self::ebpf_l7_callback,                              /* 回调接口 rust -> C */
            config.ebpf.tunning.userspace_worker_threads as i32, /* 工作线程数，是指用户态有多少线程参与数据处理 */
            config.ebpf.tunning.perf_pages_count as u32, /* 内核共享内存占用的页框数量, 值为2的次幂。用于perf数据传递 */
            config.ebpf.tunning.kernel_ring_size as u32, /* 环形缓存队列大小，值为2的次幂。e.g: 2,4,8,16,32,64,128 */
            config.ebpf.tunning.max_socket_entries as u32, /* 设置用于socket追踪的hash表项最大值，取决于实际场景中并发请求数量 */
            config.ebpf.tunning.max_trace_entries as u32, /* 设置用于线程追踪会话的hash表项最大值，SK_BPF_DATA结构的syscall_trace_id_session关联这个哈希表 */
            config.ebpf.tunning.socket_map_reclaim_threshold as u32, /* socket map表项进行清理的最大阈值，当前map的表项数量超过这个值进行map清理操作 */
        ) != 0
        {
            return Err(Error::EbpfRunningError);
        }

        let ebpf_conf = &config.ebpf;
        let on_cpu = &ebpf_conf.profile.on_cpu;
        let off_cpu = &ebpf_conf.profile.off_cpu;
        let memory = &ebpf_conf.profile.memory;

        let profiler_enabled = !on_cpu.disabled
            || (cfg!(feature = "extended_profile") && (!off_cpu.disabled || !memory.disabled));
        if profiler_enabled {
            if !on_cpu.disabled {
                ebpf::enable_oncpu_profiler();
            } else {
                ebpf::disable_oncpu_profiler();
            }
            ebpf::set_dwarf_enabled(!config.ebpf.profile.unwinding.dwarf_disabled);
            ebpf::set_dwarf_regex(
                CString::new(config.ebpf.profile.unwinding.dwarf_regex.as_bytes())
                    .unwrap()
                    .as_c_str()
                    .as_ptr(),
            );
            ebpf::set_dwarf_process_map_size(
                config.ebpf.profile.unwinding.dwarf_process_map_size as i32,
            );
            ebpf::set_dwarf_shard_map_size(
                config.ebpf.profile.unwinding.dwarf_shard_map_size as i32,
            );

            #[cfg(feature = "extended_profile")]
            {
                if !off_cpu.disabled {
                    ebpf::enable_offcpu_profiler();
                } else {
                    ebpf::disable_offcpu_profiler();
                }

                if !memory.disabled {
                    ebpf::enable_memory_profiler();
                } else {
                    ebpf::disable_memory_profiler();
                }
            }

            #[allow(unused_mut)]
            let mut contexts: [*mut c_void; 3] = [ptr::null_mut(); 3];
            #[cfg(feature = "extended_profile")]
            {
                let mp_ctx = memory_profile::MemoryContext::new(
                    memory.report_interval,
                    ebpf_conf.profile.preprocess.stack_compression,
                );
                handle.memory_profile_settings = Some(mp_ctx.settings());
                contexts[ebpf::PROFILER_CTX_MEMORY_IDX] =
                    Box::into_raw(Box::new(mp_ctx)) as *mut c_void;
            }

            if ebpf::start_continuous_profiler(
                on_cpu.sampling_frequency as i32,
                ebpf_conf.java_symbol_file_refresh_defer_interval,
                Self::ebpf_profiler_callback,
                &contexts as *const [*mut c_void; ebpf::PROFILER_CTX_NUM],
            ) != 0
            {
                warn!("ebpf start_continuous_profiler error.");
                return Err(Error::EbpfInitError);
            }

            if !on_cpu.disabled {
                let feature = "ebpf.profile.on_cpu";
                process_listener.register(feature, set_feature_on_cpu);

                let on_cpu_regexp = config
                    .process_matcher
                    .iter()
                    .find(|p| {
                        p.enabled_features
                            .iter()
                            .find(|f| f.eq_ignore_ascii_case(feature))
                            .is_some()
                    })
                    .map(|p| p.match_regex.as_str())
                    .unwrap_or_default();
                ebpf::set_feature_regex(
                    ebpf::FEATURE_PROFILE_ONCPU,
                    CString::new(on_cpu_regexp.as_bytes())
                        .unwrap()
                        .as_c_str()
                        .as_ptr(),
                );

                // CPUID will not be included in the aggregation of stack trace data.
                ebpf::set_profiler_cpu_aggregation(on_cpu.aggregate_by_cpu as i32);
            }

            #[cfg(feature = "extended_profile")]
            {
                let feature = "ebpf.profile.off_cpu";
                let off_cpu_regexp = config
                    .process_matcher
                    .iter()
                    .find(|p| {
                        p.enabled_features
                            .iter()
                            .find(|f| f.eq_ignore_ascii_case(feature))
                            .is_some()
                    })
                    .map(|p| p.match_regex.as_str())
                    .unwrap_or_default();
                if !off_cpu.disabled {
                    process_listener.register(feature, set_feature_off_cpu);

                    ebpf::set_feature_regex(
                        ebpf::FEATURE_PROFILE_ONCPU,
                        CString::new(off_cpu_regexp.as_bytes())
                            .unwrap()
                            .as_c_str()
                            .as_ptr(),
                    );

                    ebpf::set_offcpu_cpuid_aggregation(off_cpu.aggregate_by_cpu as i32);
                    ebpf::set_offcpu_minblock_time(off_cpu.min_blocking_time.as_micros() as u32);
                }

                if !memory.disabled {
                    let feature = "ebpf.profile.memory";
                    process_listener.register(feature, set_feature_memory);

                    let memory_cpu_regexp = config
                        .process_matcher
                        .iter()
                        .find(|p| {
                            p.enabled_features
                                .iter()
                                .find(|f| f.eq_ignore_ascii_case("ebpf.profile.memory"))
                                .is_some()
                        })
                        .map(|p| p.match_regex.as_str())
                        .unwrap_or_default();
                    ebpf::set_feature_regex(
                        ebpf::FEATURE_PROFILE_MEMORY,
                        CString::new(memory_cpu_regexp.as_bytes())
                            .unwrap()
                            .as_c_str()
                            .as_ptr(),
                    );
                }
            }
        }

        ebpf::bpf_tracer_finish();

        Ok(handle)
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
        l7_stats_output: DebugSender<BatchedBox<L7Stats>>,
        proc_event_output: DebugSender<BoxedProcEvents>,
        ebpf_profile_sender: DebugSender<Profile>,
        queue_debugger: &QueueDebugger,
        stats_collector: Arc<stats::Collector>,
        exception_handler: ExceptionHandler,
        process_listener: &Arc<ProcessListener>,
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

        let config_handle = Self::ebpf_init(
            &ebpf_config,
            sender,
            proc_event_output,
            ebpf_profile_sender,
            policy_getter,
            time_diff.clone(),
            process_listener,
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
                l7_stats_output,
                flow_map_config,
                stats_collector,
                collector_config,
                pause: Arc::new(AtomicBool::new(true)),
            },
            thread_handle: None,
            config_handle,
            counter: Arc::new(EbpfCounter {
                rx: AtomicU64::new(0),
                get_token_failed: AtomicU64::new(0),
            }),
            exception_handler,
            process_listener: process_listener.clone(),
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
        unsafe {
            let ecfg = &config.ebpf.profile;
            let restart_cprofiler = ebpf::dwarf_available()
                && ebpf::continuous_profiler_running()
                && (ebpf::get_dwarf_enabled() != !ecfg.unwinding.dwarf_disabled
                    || ebpf::get_dwarf_process_map_size() as u32
                        != ecfg.unwinding.dwarf_process_map_size
                    || ebpf::get_dwarf_shard_map_size() as u32
                        != ecfg.unwinding.dwarf_shard_map_size);
            ebpf::set_dwarf_enabled(!ecfg.unwinding.dwarf_disabled);
            ebpf::set_dwarf_regex(
                CString::new(ecfg.unwinding.dwarf_regex.as_bytes())
                    .unwrap()
                    .as_c_str()
                    .as_ptr(),
            );
            ebpf::set_dwarf_process_map_size(ecfg.unwinding.dwarf_process_map_size as i32);
            ebpf::set_dwarf_shard_map_size(ecfg.unwinding.dwarf_shard_map_size as i32);
            if restart_cprofiler {
                let mut contexts: [*mut c_void; 3] = [ptr::null_mut(); 3];
                ebpf::stop_continuous_profiler(
                    &mut contexts as *mut [*mut c_void; ebpf::PROFILER_CTX_NUM],
                );
                #[cfg(feature = "extended_profile")]
                {
                    std::mem::drop(Box::from_raw(
                        contexts[ebpf::PROFILER_CTX_MEMORY_IDX]
                            as *mut memory_profile::MemoryContext,
                    ));
                }
                if let Ok(handle) = Self::ebpf_core_init(&self.process_listener, config) {
                    self.config_handle = handle;
                } else {
                    warn!("ebpf start_continuous_profiler error.");
                    self.config_handle = Default::default();
                    return;
                }
            }
            #[cfg(feature = "extended_profile")]
            if let Some(s) = self.config_handle.memory_profile_settings.as_ref() {
                s.set_report_interval(ecfg.memory.report_interval);
            }
        }
        if config.l7_log_enabled() {
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

pub fn set_feature_uprobe_golang(pids: &Vec<u32>, _: &Vec<ProcessData>) {
    unsafe {
        ebpf::set_feature_pids(
            ebpf::FEATURE_UPROBE_GOLANG,
            pids.as_ptr() as *const i32,
            pids.len() as i32,
        );
    }
}

pub fn set_feature_uprobe_golang_symbol(pids: &Vec<u32>, _: &Vec<ProcessData>) {
    unsafe {
        ebpf::set_feature_pids(
            ebpf::FEATURE_UPROBE_GOLANG_SYMBOL,
            pids.as_ptr() as *const i32,
            pids.len() as i32,
        );
    }
}

pub fn set_feature_uprobe_tls(pids: &Vec<u32>, _: &Vec<ProcessData>) {
    unsafe {
        ebpf::set_feature_pids(
            ebpf::FEATURE_UPROBE_OPENSSL,
            pids.as_ptr() as *const i32,
            pids.len() as i32,
        );
    }
}

pub fn set_feature_on_cpu(pids: &Vec<u32>, _: &Vec<ProcessData>) {
    unsafe {
        ebpf::set_feature_pids(
            ebpf::FEATURE_PROFILE_ONCPU,
            pids.as_ptr() as *const i32,
            pids.len() as i32,
        );
    }
}

pub fn set_feature_off_cpu(pids: &Vec<u32>, _: &Vec<ProcessData>) {
    unsafe {
        ebpf::set_feature_pids(
            ebpf::FEATURE_PROFILE_OFFCPU,
            pids.as_ptr() as *const i32,
            pids.len() as i32,
        );
    }
}

pub fn set_feature_memory(pids: &Vec<u32>, _: &Vec<ProcessData>) {
    unsafe {
        ebpf::set_feature_pids(
            ebpf::FEATURE_PROFILE_MEMORY,
            pids.as_ptr() as *const i32,
            pids.len() as i32,
        );
    }
}
