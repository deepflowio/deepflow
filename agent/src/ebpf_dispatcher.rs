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

#[cfg(feature = "extended_observability")]
pub mod memory_profile;

#[cfg(feature = "enterprise")]
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::ptr::{self, null_mut};
use std::slice;
#[cfg(feature = "enterprise")]
use std::sync::atomic::AtomicI32;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
#[cfg(feature = "enterprise")]
use std::sync::{Mutex, OnceLock};
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
#[cfg(feature = "enterprise")]
use crate::common::kernel_capability::KernelCapability;
use crate::common::l7_protocol_log::{
    get_all_protocol, L7ProtocolBitmap, L7ProtocolParserInterface,
};
use crate::common::meta_packet::{MetaPacket, SegmentFlags};
#[cfg(feature = "enterprise")]
use crate::common::proc_event::PROC_LIFECYCLE_FORK;
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

#[cfg(feature = "extended_observability")]
use public::queue::Error::Terminated;
use public::{
    buffer::BatchedBox,
    counter::{Countable, Counter, CounterType, CounterValue, OwnedCountable},
    debug::QueueDebugger,
    l7_protocol::{L7Protocol, L7ProtocolChecker},
    leaky_bucket::LeakyBucket,
    packet,
    proto::{
        agent::{AgentType, Exception},
        metric,
    },
    queue::{bounded_with_debug, DebugSender, Receiver},
    utils::bitmap::parse_u16_range_list_to_bitmap,
};
use reorder::{Reorder, ReorderCounter, StatsReorderCounter};

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct HookedSocketSyscallBitmap(c_ulonglong);

impl HookedSocketSyscallBitmap {
    fn set_enabled(&mut self, bit: c_ulonglong) {
        self.0 |= bit;
    }
}

impl<T: AsRef<str>> From<&[T]> for HookedSocketSyscallBitmap {
    fn from(vs: &[T]) -> Self {
        let mut bitmap = HookedSocketSyscallBitmap(0);
        for v in vs.iter() {
            match v.as_ref() {
                "read" => bitmap.set_enabled(HOOKED_SOCKET_SYSCALL_READ),
                "readv" => bitmap.set_enabled(HOOKED_SOCKET_SYSCALL_READV),
                "recvfrom" => bitmap.set_enabled(HOOKED_SOCKET_SYSCALL_RECVFROM),
                "recvmsg" => bitmap.set_enabled(HOOKED_SOCKET_SYSCALL_RECVMSG),
                "recvmmsg" => bitmap.set_enabled(HOOKED_SOCKET_SYSCALL_RECVMMSG),
                "sendmsg" => bitmap.set_enabled(HOOKED_SOCKET_SYSCALL_SENDMSG),
                "sendmmsg" => bitmap.set_enabled(HOOKED_SOCKET_SYSCALL_SENDMMSG),
                "sendto" => bitmap.set_enabled(HOOKED_SOCKET_SYSCALL_SENDTO),
                "write" => bitmap.set_enabled(HOOKED_SOCKET_SYSCALL_WRITE),
                "writev" => bitmap.set_enabled(HOOKED_SOCKET_SYSCALL_WRITEV),
                _ => {}
            }
        }
        bitmap
    }
}

const HOOKED_SOCKET_SYSCALL_READ: c_ulonglong = 1 << 0;
const HOOKED_SOCKET_SYSCALL_READV: c_ulonglong = 1 << 1;
const HOOKED_SOCKET_SYSCALL_RECVFROM: c_ulonglong = 1 << 2;
const HOOKED_SOCKET_SYSCALL_RECVMSG: c_ulonglong = 1 << 3;
const HOOKED_SOCKET_SYSCALL_RECVMMSG: c_ulonglong = 1 << 4;
const HOOKED_SOCKET_SYSCALL_SENDMSG: c_ulonglong = 1 << 5;
const HOOKED_SOCKET_SYSCALL_SENDMMSG: c_ulonglong = 1 << 6;
const HOOKED_SOCKET_SYSCALL_SENDTO: c_ulonglong = 1 << 7;
const HOOKED_SOCKET_SYSCALL_WRITE: c_ulonglong = 1 << 8;
const HOOKED_SOCKET_SYSCALL_WRITEV: c_ulonglong = 1 << 9;

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
    time_backtrack_max: AtomicU64,
    get_token_failed: AtomicU64,
}

pub struct SyncEbpfCounter {
    counter: Arc<EbpfCounter>,
}

#[cfg(feature = "enterprise")]
fn register_ai_agent_child(event: &BoxedProcEvents) {
    if let Some(info) = event.0.proc_lifecycle_info() {
        if info.lifecycle_type != PROC_LIFECYCLE_FORK {
            return;
        }
        if let Some(registry) = enterprise_utils::ai_agent::global_registry() {
            let now = Duration::from_nanos(event.0.start_time());
            registry.register_child(info.parent_pid, info.pid, now);
        }
    }
}

#[cfg(feature = "enterprise")]
fn fill_ai_agent_root_pid(event: &mut BoxedProcEvents) {
    if let Some(registry) = enterprise_utils::ai_agent::global_registry() {
        let root_pid = registry.get_root_pid(event.0.pid);
        if root_pid != 0 {
            event.0.ai_agent_root_pid = root_pid;
        }
    }
}

#[cfg(feature = "enterprise")]
#[allow(static_mut_refs)]
fn emit_ai_agent_enforcement_audit_event(event: &BoxedProcEvents) {
    use enterprise_utils::ai_agent_enforcement::{EnforcementMode, KernelEventSource};

    if event.0.ai_agent_root_pid == 0 {
        return;
    }
    let Some(exec_info) = event.0.proc_lifecycle_exec_info() else {
        return;
    };
    if exec_info.exec_path.is_empty() {
        return;
    }
    let Some(policy) = enterprise_utils::ai_agent_enforcement::global_exec_policy() else {
        return;
    };
    let exec_path = String::from_utf8_lossy(exec_info.exec_path);
    let cmdline = String::from_utf8_lossy(exec_info.cmdline);
    let Some(hit) = policy.match_exec(&exec_path, &cmdline) else {
        return;
    };
    if hit.mode != EnforcementMode::AuditOnly {
        return;
    }
    match hit.kernel_event_source {
        KernelEventSource::Lsm if AI_AGENT_EXEC_LSM_EVENTS_ACTIVE.load(Ordering::Relaxed) => {
            return;
        }
        KernelEventSource::KprobeOverride
            if AI_AGENT_EXEC_KPROBE_EVENTS_ACTIVE.load(Ordering::Relaxed) =>
        {
            return;
        }
        _ => {}
    }
    let Some(audit_event) = event
        .0
        .new_proc_block_event_for_audit(&hit.rule_id, policy.epoch)
    else {
        return;
    };

    unsafe {
        if let Some(sender) = PROC_EVENT_SENDER.as_mut() {
            if let Err(e) = sender.send(audit_event) {
                warn!("ai agent enforcement audit event send error: {:?}", e);
            }
        }
    }
}

#[cfg(feature = "enterprise")]
fn kernel_block_event_cache() -> &'static Mutex<HashMap<KernelBlockMarkerKey, u64>> {
    RECENT_KERNEL_BLOCK_EVENTS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(feature = "enterprise")]
fn prune_kernel_block_event_cache(cache: &mut HashMap<KernelBlockMarkerKey, u64>, now: u64) {
    cache.retain(|_, ts| now.saturating_sub(*ts) <= KERNEL_BLOCK_EVENT_CACHE_WINDOW_NS);
}

#[cfg(feature = "enterprise")]
fn record_kernel_block_event(event: &BoxedProcEvents) {
    let Some(info) = event.0.proc_block_info() else {
        return;
    };
    if info.action != metric::EnforcementAction::Deny as u8 || info.exec_path.is_empty() {
        return;
    }
    let mut cache = kernel_block_event_cache().lock().unwrap();
    prune_kernel_block_event_cache(&mut cache, info.timestamp);
    cache.insert(
        KernelBlockMarkerKey {
            pid: info.pid,
            rule_id: info.rule_id.to_string(),
            exec_path: info.exec_path.to_vec(),
        },
        info.timestamp,
    );
}

#[cfg(feature = "enterprise")]
fn consume_recent_kernel_block_event(pid: u32, rule_id: &str, exec_path: &[u8], now: u64) -> bool {
    let mut cache = kernel_block_event_cache().lock().unwrap();
    prune_kernel_block_event_cache(&mut cache, now);
    cache
        .remove(&KernelBlockMarkerKey {
            pid,
            rule_id: rule_id.to_string(),
            exec_path: exec_path.to_vec(),
        })
        .map(|ts| now.saturating_sub(ts) <= KERNEL_BLOCK_EVENT_CACHE_WINDOW_NS)
        .unwrap_or(false)
}

#[cfg(feature = "enterprise")]
#[allow(static_mut_refs)]
fn emit_ai_agent_enforcement_best_effort_event(event: &BoxedProcEvents) {
    use enterprise_utils::ai_agent_enforcement::EnforcementMode;

    if event.0.ai_agent_root_pid == 0 {
        return;
    }
    let Some(exec_info) = event.0.proc_lifecycle_exec_info() else {
        return;
    };
    if exec_info.exec_path.is_empty() {
        return;
    }
    let Some(policy) = enterprise_utils::ai_agent_enforcement::global_exec_policy() else {
        return;
    };
    let exec_path = String::from_utf8_lossy(exec_info.exec_path);
    let cmdline = String::from_utf8_lossy(exec_info.cmdline);
    let Some(hit) = policy.match_exec(&exec_path, &cmdline) else {
        return;
    };
    if hit.mode != EnforcementMode::Block {
        return;
    }
    if consume_recent_kernel_block_event(
        exec_info.pid,
        &hit.rule_id,
        exec_info.exec_path,
        exec_info.timestamp,
    ) {
        return;
    }
    let Some(best_effort_event) = event
        .0
        .new_proc_block_event_for_best_effort(&hit.rule_id, policy.epoch)
    else {
        return;
    };
    unsafe {
        if let Some(sender) = PROC_EVENT_SENDER.as_mut() {
            if let Err(e) = sender.send(best_effort_event) {
                warn!("ai agent enforcement best_effort event send error: {:?}", e);
            }
        }
    }
}

impl OwnedCountable for SyncEbpfCounter {
    fn get_counters(&self) -> Vec<Counter> {
        let rx = self.counter.rx.swap(0, Ordering::Relaxed);
        let get_token_failed = self.counter.get_token_failed.swap(0, Ordering::Relaxed);
        let time_backtrack_max = self.counter.time_backtrack_max.swap(0, Ordering::Relaxed);
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
                "time_backtrack_max",
                CounterType::Counted,
                CounterValue::Unsigned(time_backtrack_max),
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
            (
                "rx_packets",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.rx_packets as u64),
            ),
            (
                "tx_packets",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.tx_packets as u64),
            ),
            (
                "rx_bytes",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.rx_bytes as u64),
            ),
            (
                "tx_bytes",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.tx_bytes as u64),
            ),
            (
                "dropped_packets",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.dropped_packets as u64),
            ),
            (
                "kern_missed_packets",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.kern_missed_packets as u64),
            ),
            (
                "invalid_packets",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.invalid_packets as u64),
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
    output: DebugSender<AppProto>, // Send AppProtos to the AppProtoLogsParser
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

    fn run(
        &self,
        counter: Arc<EbpfCounter>,
        exception_handler: ExceptionHandler,
        need_reload_config: Arc<AtomicBool>,
    ) {
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
            ebpf_config
                .ebpf
                .socket
                .preprocess
                .out_of_order_reassembly_timeout,
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

        let mut flow_config = self.flow_map_config.load().clone();
        let mut log_parser_config = self.log_parser_config.load().clone();
        let mut collector_config = self.collector_config.load().clone();
        let mut ebpf_config = self.config.load().clone();
        let mut last_packet_timestamp = 0;

        while unsafe { SWITCH } {
            if need_reload_config.swap(false, Ordering::Relaxed) {
                info!("ebpf dispatcher reload config");
                flow_config = self.flow_map_config.load().clone();
                log_parser_config = self.log_parser_config.load().clone();
                collector_config = self.collector_config.load().clone();
                ebpf_config = self.config.load().clone();
            }
            let config = Config {
                flow: &flow_config,
                log_parser: &log_parser_config,
                collector: &collector_config,
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
                if packet.lookup_key.timestamp.as_nanos() < last_packet_timestamp {
                    counter.time_backtrack_max.fetch_max(
                        last_packet_timestamp - packet.lookup_key.timestamp.as_nanos(),
                        Ordering::Relaxed,
                    );
                }
                last_packet_timestamp = packet.lookup_key.timestamp.as_nanos();

                if !leaky_bucket.acquire(1) {
                    counter.get_token_failed.fetch_add(1, Ordering::Relaxed);
                    exception_handler.set(Exception::RxPpsThresholdExceeded, None);
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
        _: bool,
        _: &mut bool,
    ) -> Result<(), String> {
        self.pause.store(false, Ordering::Relaxed);
        Ok(())
    }

    fn id(&self) -> usize {
        u16::from(FlowAclListenerId::EbpfDispatcher) as usize
    }
}

#[derive(Default)]
struct ConfigHandle;

pub struct EbpfCollector {
    thread_dispatcher: EbpfDispatcher,
    thread_handle: Option<JoinHandle<()>>,

    config_handle: ConfigHandle,

    counter: Arc<EbpfCounter>,
    stats_collector: Arc<stats::Collector>,
    need_reload_config: Arc<AtomicBool>,

    exception_handler: ExceptionHandler,
    process_listener: Arc<ProcessListener>,

    #[cfg(feature = "extended_observability")]
    memory_profiler: memory_profile::MemoryProfiler,
}

const BATCH_SIZE: usize = 64;

#[allow(static_mut_refs)]
static mut SWITCH: bool = false;
#[allow(static_mut_refs)]
static mut SENDER: Option<DebugSender<Box<MetaPacket>>> = None;
#[allow(static_mut_refs)]
static mut DPDK_SENDERS: Option<Vec<DebugSender<Box<packet::Packet>>>> = None;
#[allow(static_mut_refs)]
static mut DPDK_SENDER_BUFFERS: Vec<Vec<Box<packet::Packet>>> = vec![];
#[allow(static_mut_refs)]
static mut PROC_EVENT_SENDER: Option<DebugSender<BoxedProcEvents>> = None;
#[allow(static_mut_refs)]
static mut EBPF_PROFILE_SENDER: Option<DebugSender<Profile>> = None;
#[allow(static_mut_refs)]
static mut POLICY_GETTER: Option<PolicyGetter> = None;
#[allow(static_mut_refs)]
static mut ON_CPU_PROFILE_FREQUENCY: u32 = 0;
#[allow(static_mut_refs)]
static mut PROFILE_STACK_COMPRESSION: bool = true;
#[allow(static_mut_refs)]
static mut TIME_DIFF: Option<Arc<AtomicI64>> = None;
#[cfg(feature = "enterprise")]
static AI_AGENT_EXEC_RULES_MAP_FD: AtomicI32 = AtomicI32::new(-1);
#[cfg(feature = "enterprise")]
static AI_AGENT_SYSCALL_RULES_MAP_FD: AtomicI32 = AtomicI32::new(-1);
#[cfg(feature = "enterprise")]
static AI_AGENT_POLICY_EPOCH_MAP_FD: AtomicI32 = AtomicI32::new(-1);
#[cfg(feature = "enterprise")]
static AI_AGENT_EXEC_LSM_EVENTS_ACTIVE: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "enterprise")]
static AI_AGENT_EXEC_KPROBE_EVENTS_ACTIVE: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "enterprise")]
static RECENT_KERNEL_BLOCK_EVENTS: OnceLock<Mutex<HashMap<KernelBlockMarkerKey, u64>>> =
    OnceLock::new();
#[cfg(feature = "enterprise")]
const AI_AGENT_EXEC_RULES_BPF_MAX: usize = 256;
#[cfg(feature = "enterprise")]
const AI_AGENT_SYSCALL_RULES_BPF_MAX: usize = 32;
#[cfg(feature = "enterprise")]
const KERNEL_BLOCK_EVENT_CACHE_WINDOW_NS: u64 = 5_000_000_000;

#[cfg(feature = "enterprise")]
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct KernelBlockMarkerKey {
    pid: u32,
    rule_id: String,
    exec_path: Vec<u8>,
}

#[cfg(feature = "enterprise")]
fn ai_agent_enforcement_mode_eq(value: &str, expected: &str) -> bool {
    value.trim().eq_ignore_ascii_case(expected)
}

#[cfg(feature = "enterprise")]
fn ai_agent_enforcement_lsm_allowed(
    config: &crate::config::config::AiAgentEnforcementConfig,
) -> bool {
    let mechanism_allowed = config
        .allowed_mechanisms
        .iter()
        .any(|m| ai_agent_enforcement_mode_eq(m, "lsm"));
    let strategy_allows_lsm = matches!(
        config.strategy.trim().to_ascii_lowercase().as_str(),
        "auto" | "lsm_only"
    );
    mechanism_allowed && strategy_allows_lsm
}

#[cfg(feature = "enterprise")]
fn ai_agent_enforcement_kprobe_override_allowed(
    config: &crate::config::config::AiAgentEnforcementConfig,
) -> bool {
    let mechanism_allowed = config
        .allowed_mechanisms
        .iter()
        .any(|m| ai_agent_enforcement_mode_eq(m, "kprobe_override"));
    let strategy_allows_override = matches!(
        config.syscall_strategy.trim().to_ascii_lowercase().as_str(),
        "auto" | "override_only"
    );
    mechanism_allowed && strategy_allows_override
}

#[cfg(feature = "enterprise")]
fn ai_agent_exec_argv_match_op(
    op: &str,
) -> enterprise_utils::ai_agent_enforcement::ExecArgvMatchOp {
    match op.trim().to_ascii_lowercase().as_str() {
        "prefix" => enterprise_utils::ai_agent_enforcement::ExecArgvMatchOp::Prefix,
        "suffix" => enterprise_utils::ai_agent_enforcement::ExecArgvMatchOp::Suffix,
        _ => enterprise_utils::ai_agent_enforcement::ExecArgvMatchOp::Exact,
    }
}

#[cfg(feature = "enterprise")]
fn ai_agent_exec_enforcement_inputs(
    config: &crate::config::config::AiAgentEnforcementConfig,
    mode: enterprise_utils::ai_agent_enforcement::EnforcementMode,
) -> Vec<enterprise_utils::ai_agent_enforcement::ExecRuleInput> {
    config
        .rules
        .iter()
        .filter(|rule| {
            ai_agent_enforcement_mode_eq(&rule.scope, "ai_agent_tree")
                && ai_agent_enforcement_mode_eq(&rule.target_type, "exec")
        })
        .map(|rule| {
            let rule_mode = if mode
                == enterprise_utils::ai_agent_enforcement::EnforcementMode::Block
                && ai_agent_enforcement_mode_eq(&rule.action.action_type, "deny")
            {
                enterprise_utils::ai_agent_enforcement::EnforcementMode::Block
            } else {
                enterprise_utils::ai_agent_enforcement::EnforcementMode::AuditOnly
            };
            enterprise_utils::ai_agent_enforcement::ExecRuleInput {
                id: rule.id.clone(),
                mode: rule_mode,
                exact: rule.exec.exact.clone(),
                prefix: rule.exec.prefix.clone(),
                suffix: rule.exec.suffix.clone(),
                argv_matches: rule
                    .exec
                    .argv_matches
                    .iter()
                    .map(
                        |m| enterprise_utils::ai_agent_enforcement::ExecArgvMatchInput {
                            index: m.index,
                            op: ai_agent_exec_argv_match_op(&m.op),
                            value: m.value.clone(),
                        },
                    )
                    .collect(),
                argv_contains_any: rule.exec.argv_contains_any.clone(),
            }
        })
        .collect()
}

#[cfg(feature = "enterprise")]
fn ai_agent_syscall_enforcement_inputs(
    config: &crate::config::config::AiAgentEnforcementConfig,
    mode: enterprise_utils::ai_agent_enforcement::EnforcementMode,
) -> Vec<enterprise_utils::ai_agent_enforcement::SyscallRuleInput> {
    config
        .rules
        .iter()
        .filter(|rule| {
            ai_agent_enforcement_mode_eq(&rule.scope, "ai_agent_tree")
                && ai_agent_enforcement_mode_eq(&rule.target_type, "syscall")
        })
        .map(|rule| {
            let rule_mode = if mode
                == enterprise_utils::ai_agent_enforcement::EnforcementMode::Block
                && ai_agent_enforcement_mode_eq(&rule.action.action_type, "deny")
            {
                enterprise_utils::ai_agent_enforcement::EnforcementMode::Block
            } else {
                enterprise_utils::ai_agent_enforcement::EnforcementMode::AuditOnly
            };
            enterprise_utils::ai_agent_enforcement::SyscallRuleInput {
                id: rule.id.clone(),
                mode: rule_mode,
                names: rule.syscall.names.clone(),
                symbols: rule.syscall.symbols.clone(),
            }
        })
        .collect()
}

#[cfg(feature = "enterprise")]
fn ai_agent_syscall_policy_supported_by_kernel(
    policy: &enterprise_utils::ai_agent_enforcement::CompiledSyscallPolicy,
    capability: &KernelCapability,
) -> bool {
    let records = policy.to_bpf_records();
    !records.is_empty()
        && records.iter().all(|record| {
            enterprise_utils::ai_agent_enforcement::syscall_override_symbols(record.syscall_key)
                .iter()
                .any(|symbol| capability.supports_kprobe_override_symbol(symbol))
        })
}

pub unsafe fn string_from_null_terminated_c_str(ptr: *const u8) -> String {
    CStr::from_ptr(ptr as *const libc::c_char)
        .to_string_lossy()
        .into_owned()
}

impl EbpfCollector {
    extern "C" fn ebpf_l7_callback(
        _: *mut c_void,
        #[allow(unused)] queue_id: c_int,
        sd: *mut ebpf::SK_BPF_DATA,
    ) -> c_int {
        #[allow(static_mut_refs)]
        unsafe {
            if !SWITCH || SENDER.is_none() {
                return 0;
            }

            let sd = &mut sd.read_unaligned();
            #[cfg(feature = "extended_observability")]
            if sd.source == ebpf::DATA_SOURCE_DPDK {
                let queue_id = queue_id as usize;
                let mut temp =
                    slice::from_raw_parts_mut(sd.cap_data as *mut u8, sd.cap_len as usize).to_vec();
                let ptr = temp.as_mut_ptr();
                std::mem::forget(temp);

                let packet = packet::Packet {
                    timestamp: Duration::from_nanos(sd.timestamp),
                    capture_length: sd.syscall_len as isize,
                    if_index: 0,
                    data: slice::from_raw_parts_mut(ptr, sd.cap_len as usize),
                    raw: Some(ptr),
                };

                if queue_id >= DPDK_SENDER_BUFFERS.len() {
                    error!("dpdk is not initialized, deepflow-agent restart...");
                    crate::utils::clean_and_exit(1);
                }

                DPDK_SENDER_BUFFERS[queue_id].push(Box::new(packet));
                if DPDK_SENDER_BUFFERS[queue_id].len() == BATCH_SIZE || sd.batch_last_data {
                    match DPDK_SENDERS.as_mut().unwrap()[queue_id]
                        .send_all(&mut DPDK_SENDER_BUFFERS[queue_id])
                    {
                        Err(Terminated(a, b)) => {
                            error!("dpdk init error: {:?}, deepflow-agent restart...", (a, b));
                            crate::utils::clean_and_exit(1);
                        }
                        Err(e) => {
                            warn!("meta packet send ebpf error: {:?}", e);
                        }
                        _ => {}
                    }
                }
                return 0;
            }

            let container_id =
                CStr::from_ptr(sd.container_id.as_ptr() as *const libc::c_char).to_string_lossy();
            let event_type = EventType::from(sd.source);
            if event_type != EventType::OtherEvent {
                // EbpfType like TracePoint, TlsUprobe, GoHttp2Uprobe belong to other events
                let event = ProcEvent::from_ebpf(sd, event_type);
                if event.is_err() {
                    warn!("proc event parse from ebpf error: {}", event.unwrap_err());
                    return 0;
                }
                let mut event = event.unwrap();
                if let Some(policy) = POLICY_GETTER.as_ref() {
                    event.0.pod_id = policy.lookup_pod_id(&container_id);
                }
                #[cfg(feature = "enterprise")]
                register_ai_agent_child(&event);
                #[cfg(feature = "enterprise")]
                fill_ai_agent_root_pid(&mut event);
                #[cfg(feature = "enterprise")]
                record_kernel_block_event(&event);
                #[cfg(feature = "enterprise")]
                emit_ai_agent_enforcement_audit_event(&event);
                #[cfg(feature = "enterprise")]
                emit_ai_agent_enforcement_best_effort_event(&event);
                if let Err(e) = PROC_EVENT_SENDER.as_mut().unwrap().send(event) {
                    warn!("event send ebpf error: {:?}", e);
                }
                return 0;
            }
            let packet = MetaPacket::from_ebpf(sd);
            if packet.is_err() {
                warn!("meta packet parse from ebpf error: {}", packet.unwrap_err());
                return 0;
            }
            let mut packet = packet.unwrap();
            if let Some(policy) = POLICY_GETTER.as_ref() {
                packet.pod_id = policy.lookup_pod_id(&container_id);
            }
            if let Err(e) = SENDER.as_mut().unwrap().send(Box::new(packet)) {
                warn!("meta packet send ebpf error: {:?}", e);
            }
        }

        0
    }

    extern "C" fn ebpf_profiler_callback(
        #[allow(unused)] ctx: *mut c_void,
        _queue_id: c_int,
        data: *mut ebpf::stack_profile_data,
    ) -> c_int {
        #[allow(static_mut_refs)]
        unsafe {
            if !SWITCH || EBPF_PROFILE_SENDER.is_none() {
                return 0;
            }

            let time_diff = TIME_DIFF
                .as_ref()
                .map(|t| t.load(Ordering::Relaxed))
                .unwrap_or(0);

            #[cfg(feature = "extended_observability")]
            if (*data).profiler_type == ebpf::PROFILER_TYPE_MEMORY {
                let Some(m_ctx) = (ctx as *mut memory_profile::MemoryContext).as_mut() else {
                    return 0;
                };
                m_ctx.update(data);
                return ebpf::TRACER_CALLBACK_FLAG_KEEP_DATA as c_int;
            }

            let data = &mut *data;

            let mut profile = metric::Profile::default();
            profile.sample_rate = ON_CPU_PROFILE_FREQUENCY;
            profile.timestamp = if time_diff > 0 {
                data.timestamp + time_diff as u64
            } else {
                data.timestamp - time_diff.abs() as u64
            };
            profile.event_type = match data.profiler_type {
                #[cfg(feature = "extended_observability")]
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

        0
    }

    fn ebpf_init(
        config: &EbpfConfig,
        sender: DebugSender<Box<MetaPacket<'static>>>,
        dpdk_senders: Vec<DebugSender<Box<packet::Packet<'static>>>>,
        proc_event_sender: DebugSender<BoxedProcEvents>,
        ebpf_profile_sender: DebugSender<Profile>,
        policy_getter: PolicyGetter,
        time_diff: Arc<AtomicI64>,
        stats_collector: &stats::Collector,
        process_listener: &ProcessListener,
        #[cfg(feature = "extended_observability")] memory_context: memory_profile::MemoryContext,
    ) -> Result<ConfigHandle> {
        // ebpf和ebpf collector通信配置初始化
        #[allow(static_mut_refs)]
        unsafe {
            let dpdk_sender_count = dpdk_senders.len();
            let handle = Self::ebpf_core_init(
                process_listener,
                #[cfg(feature = "extended_observability")]
                memory_context,
                config,
                stats_collector,
            );
            // initialize communication between core and ebpf collector
            SWITCH = false;
            SENDER = Some(sender);
            DPDK_SENDERS = Some(dpdk_senders);
            DPDK_SENDER_BUFFERS = Vec::with_capacity(dpdk_sender_count);
            for _ in 0..dpdk_sender_count {
                DPDK_SENDER_BUFFERS.push(Vec::with_capacity(BATCH_SIZE));
            }
            PROC_EVENT_SENDER = Some(proc_event_sender);
            EBPF_PROFILE_SENDER = Some(ebpf_profile_sender);
            POLICY_GETTER = Some(policy_getter);
            ON_CPU_PROFILE_FREQUENCY = config.ebpf.profile.on_cpu.sampling_frequency as u32;
            PROFILE_STACK_COMPRESSION = config.ebpf.profile.preprocess.stack_compression;
            TIME_DIFF = Some(time_diff);
            handle
        }
    }

    #[allow(unused)]
    unsafe fn ebpf_core_init(
        process_listener: &ProcessListener,
        #[cfg(feature = "extended_observability")] memory_context: memory_profile::MemoryContext,
        config: &EbpfConfig,
        stats_collector: &stats::Collector,
    ) -> Result<ConfigHandle> {
        // ebpf core modules init
        let mut handle = ConfigHandle::default();
        let is_uprobe_meltdown = crate::utils::guard::is_kernel_ebpf_uprobe_meltdown();
        ebpf::set_uprobe_golang_enabled(
            !is_uprobe_meltdown && config.ebpf.socket.uprobe.golang.enabled,
        );
        if !is_uprobe_meltdown && config.ebpf.socket.uprobe.golang.enabled {
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

        ebpf::set_uprobe_openssl_enabled(
            !is_uprobe_meltdown && config.ebpf.socket.uprobe.tls.enabled,
        );
        if !is_uprobe_meltdown && config.ebpf.socket.uprobe.tls.enabled {
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

        if config.ebpf.socket.kprobe.disabled {
            info!("ebpf kprobe disabled");
            ebpf::disable_kprobe_feature();
        } else {
            info!("ebpf kprobe enabled");
            ebpf::enable_kprobe_feature();
        }

        if config.ebpf.socket.kprobe.enable_unix_socket {
            info!("ebpf unix socket tracing enabled");
            ebpf::enable_unix_socket_feature();
        } else {
            info!("ebpf unix socket tracing disabled");
            ebpf::disable_unix_socket_feature();
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

        if let Err(e) = config.ebpf.tunning.validate() {
            warn!(
                "skip setting kick thread nice value to {}: {}",
                config.ebpf.tunning.kick_kern_nice, e
            );
        } else if ebpf::set_kick_kern_nice(config.ebpf.tunning.kick_kern_nice) != 0 {
            warn!(
                "failed to set kick thread nice value to {}",
                config.ebpf.tunning.kick_kern_nice
            );
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

        if ebpf::set_virtual_file_collect(config.ebpf.file.io_event.enable_virtual_file_collect)
            != 0
        {
            info!(
                "ebpf set_virtual_file_collect error: {}",
                config.ebpf.file.io_event.enable_virtual_file_collect
            );
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
            let l7_protocol = L7Protocol::from(protocol);
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
            let l7_protocol = L7Protocol::from(protocol);
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

        ebpf::set_hooked_socket_syscalls(
            HookedSocketSyscallBitmap::from(
                config.ebpf.socket.tunning.hooked_socket_syscalls.as_slice(),
            )
            .0,
        );

        ebpf::set_bpf_map_prealloc(!config.ebpf.socket.tunning.map_prealloc_disabled);

        if config.ebpf.socket.tunning.fentry_enabled {
            ebpf::enable_fentry();
        } else {
            ebpf::disable_fentry();
        }

        // set ebpf dpdk enabled
        #[cfg(feature = "extended_observability")]
        ebpf::set_dpdk_trace_enabled(config.dpdk_enabled);

        #[cfg(feature = "extended_observability")]
        {
            let tcp_option_trace = &config.ebpf.socket.sock_ops.tcp_option_trace;

            if ebpf::set_tcp_option_tracing_sample_window(
                tcp_option_trace.sampling_window_bytes as u32,
            ) != 0
            {
                warn!(
                    "failed to set tcp option tracing sampling window to {}",
                    tcp_option_trace.sampling_window_bytes
                );
            }

            if ebpf::set_tcp_option_tracing_enabled(tcp_option_trace.enabled) != 0 {
                warn!(
                    "tcp option tracing enable failed (set enabled = {})",
                    tcp_option_trace.enabled
                );
            }

            // NicOptimize
            if ebpf::set_nic_optimization(config.ebpf.network.nic_opt_enabled) != 0 {
                warn!(
                    "Failed to apply NIC optimization setting (enabled: {})",
                    config.ebpf.network.nic_opt_enabled
                );
            }

            for nic in &config.ebpf.network.nic_optimize {
                nic.apply();
            }
        }

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

        Self::ebpf_on_config_change(config.l7_log_packet_size, config.ai_agent_max_payload_size);

        let ebpf_conf = &config.ebpf;
        let on_cpu = &ebpf_conf.profile.on_cpu;
        let off_cpu = &ebpf_conf.profile.off_cpu;
        let memory = &ebpf_conf.profile.memory;

        let profiler_enabled = (!is_uprobe_meltdown && !on_cpu.disabled)
            || (cfg!(feature = "extended_observability")
                && (!off_cpu.disabled || (!is_uprobe_meltdown && !memory.disabled)));
        if profiler_enabled {
            if !is_uprobe_meltdown && !on_cpu.disabled {
                ebpf::enable_oncpu_profiler();
            } else {
                ebpf::disable_oncpu_profiler();
            }
            ebpf::set_dwarf_enabled(
                !is_uprobe_meltdown && !config.ebpf.profile.unwinding.dwarf_disabled,
            );
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

            // Language-specific profiling configuration
            // Set feature regex for each language profiler based on configuration
            // When xxx_disabled is false, set regex to ".*" to enable the feature
            // When xxx_disabled is true, don't set regex (feature remains disabled)
            let languages = &config.ebpf.profile.languages;
            if !languages.python_disabled {
                ebpf::set_feature_regex(
                    ebpf::FEATURE_PROFILE_PYTHON,
                    CString::new(".*").unwrap().as_c_str().as_ptr(),
                );
            }
            if !languages.php_disabled {
                ebpf::set_feature_regex(
                    ebpf::FEATURE_PROFILE_PHP,
                    CString::new(".*").unwrap().as_c_str().as_ptr(),
                );
            }
            if !languages.nodejs_disabled {
                ebpf::set_feature_regex(
                    ebpf::FEATURE_PROFILE_V8,
                    CString::new(".*").unwrap().as_c_str().as_ptr(),
                );
            }
            if !languages.lua_disabled {
                ebpf::set_feature_regex(
                    ebpf::FEATURE_PROFILE_LUA,
                    CString::new(".*").unwrap().as_c_str().as_ptr(),
                );
            }

            #[cfg(feature = "extended_observability")]
            {
                if !off_cpu.disabled {
                    ebpf::enable_offcpu_profiler();
                } else {
                    ebpf::disable_offcpu_profiler();
                }

                if !is_uprobe_meltdown && !memory.disabled {
                    ebpf::enable_memory_profiler();
                } else {
                    ebpf::disable_memory_profiler();
                }
            }

            #[allow(unused_mut)]
            let mut contexts: [*mut c_void; 3] = [ptr::null_mut(); 3];
            #[cfg(feature = "extended_observability")]
            {
                contexts[ebpf::PROFILER_CTX_MEMORY_IDX] =
                    Box::into_raw(Box::new(memory_context)) as *mut c_void;
            }

            if ebpf::start_continuous_profiler(
                on_cpu.sampling_frequency as i32,
                ebpf_conf.java_symbol_file_refresh_defer_interval,
                Self::ebpf_profiler_callback,
                &contexts as *const [*mut c_void; ebpf::PROFILER_CTX_NUM],
            ) != 0
            {
                warn!("ebpf start_continuous_profiler error.");
            }

            if !is_uprobe_meltdown && !on_cpu.disabled {
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

            #[cfg(feature = "extended_observability")]
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

                if !is_uprobe_meltdown && !memory.disabled {
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

        // ebpf dpdk init
        #[cfg(feature = "extended_observability")]
        if config.dpdk_enabled {
            let dpdk = &config.ebpf.socket.uprobe.dpdk;

            if !is_uprobe_meltdown && !dpdk.command.is_empty() {
                ebpf::set_dpdk_cmd_name(
                    CString::new(dpdk.command.as_bytes())
                        .unwrap()
                        .as_c_str()
                        .as_ptr(),
                );
            }

            if !dpdk.rx_hooks.is_empty() {
                ebpf::set_dpdk_hooks(
                    ebpf::DPDK_HOOK_TYPE_RECV as c_int,
                    CString::new(dpdk.rx_hooks.join(",").as_bytes())
                        .unwrap()
                        .as_c_str()
                        .as_ptr(),
                );
            }
            if !dpdk.tx_hooks.is_empty() {
                ebpf::set_dpdk_hooks(
                    ebpf::DPDK_HOOK_TYPE_XMIT as c_int,
                    CString::new(dpdk.tx_hooks.join(",").as_bytes())
                        .unwrap()
                        .as_c_str()
                        .as_ptr(),
                );
            }

            ebpf::dpdk_trace_start();
        }

        // Istio envoy mtls
        #[cfg(feature = "extended_observability")]
        if !is_uprobe_meltdown && config.ebpf.socket.uprobe.tls.enabled {
            ebpf::envoy_trace_start();
        }

        ebpf::bpf_tracer_finish();

        // Wire AI Agent PID → BPF map fd after all tracers are loaded
        #[cfg(feature = "enterprise")]
        {
            use enterprise_utils::ai_agent::global_registry;
            let fd = unsafe {
                ebpf::bpf_table_get_map_fd(c"socket-trace".as_ptr(), c"__ai_agent_pids".as_ptr())
            };
            if fd >= 0 {
                if let Some(registry) = global_registry() {
                    registry.set_bpf_map_fd(fd);
                }
            } else {
                warn!("AI Agent: could not find __ai_agent_pids BPF map (fd={}), file I/O monitoring will not work", fd);
            }

            let exec_rules_fd = unsafe {
                ebpf::bpf_table_get_map_fd(
                    c"socket-trace".as_ptr(),
                    c"__ai_agent_exec_rules".as_ptr(),
                )
            };
            AI_AGENT_EXEC_RULES_MAP_FD.store(exec_rules_fd, Ordering::Relaxed);
            let syscall_rules_fd = unsafe {
                ebpf::bpf_table_get_map_fd(
                    c"socket-trace".as_ptr(),
                    c"__ai_agent_syscall_rules".as_ptr(),
                )
            };
            AI_AGENT_SYSCALL_RULES_MAP_FD.store(syscall_rules_fd, Ordering::Relaxed);
            let policy_epoch_fd = unsafe {
                ebpf::bpf_table_get_map_fd(
                    c"socket-trace".as_ptr(),
                    c"__ai_agent_policy_epoch".as_ptr(),
                )
            };
            AI_AGENT_POLICY_EPOCH_MAP_FD.store(policy_epoch_fd, Ordering::Relaxed);
            if exec_rules_fd < 0 || syscall_rules_fd < 0 || policy_epoch_fd < 0 {
                warn!(
                    "AI Agent enforcement: BPF maps unavailable (__ai_agent_exec_rules={}, __ai_agent_syscall_rules={}, __ai_agent_policy_epoch={}), block mode will downgrade to audit-only for unavailable mechanisms",
                    exec_rules_fd, syscall_rules_fd, policy_epoch_fd
                );
            }
            Self::sync_ai_agent_enforcement_policy(&config.ai_agent_enforcement);
        }

        Ok(handle)
    }

    fn ebpf_on_config_change(l7_log_packet_size: usize, ai_agent_max_payload_size: usize) {
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

            let ai_agent_limit = if ai_agent_max_payload_size == 0 {
                0
            } else {
                ai_agent_max_payload_size.min(i32::MAX as usize) as c_int
            };
            let n = ebpf::set_ai_agent_data_limit_max(ai_agent_limit);
            if n < 0 {
                warn!(
                    "ebpf set ai_agent_max_payload_size({}) failed.",
                    ai_agent_max_payload_size
                );
            } else if ai_agent_limit != 0 && n != ai_agent_limit {
                info!(
                    "ebpf set ai_agent_max_payload_size to {}, actual effective configuration is {}.",
                    ai_agent_max_payload_size, n
                );
            }
        }
    }

    #[cfg(feature = "enterprise")]
    fn clear_ai_agent_exec_enforcement_bpf_maps(max_records: usize) {
        let exec_rules_fd = AI_AGENT_EXEC_RULES_MAP_FD.load(Ordering::Relaxed);
        let policy_epoch_fd = AI_AGENT_POLICY_EPOCH_MAP_FD.load(Ordering::Relaxed);
        if exec_rules_fd < 0 || policy_epoch_fd < 0 {
            return;
        }
        match enterprise_utils::ai_agent_enforcement::compile_exec_rules(&[]) {
            Ok(policy) => {
                if let Err(e) = policy.sync_to_bpf_maps(exec_rules_fd, policy_epoch_fd, max_records)
                {
                    warn!("AI Agent enforcement: failed to clear BPF maps: {}", e);
                }
            }
            Err(e) => warn!("AI Agent enforcement: failed to build empty policy: {}", e),
        }
    }

    #[cfg(feature = "enterprise")]
    fn clear_ai_agent_syscall_enforcement_bpf_maps(max_records: usize) {
        let syscall_rules_fd = AI_AGENT_SYSCALL_RULES_MAP_FD.load(Ordering::Relaxed);
        let policy_epoch_fd = AI_AGENT_POLICY_EPOCH_MAP_FD.load(Ordering::Relaxed);
        if syscall_rules_fd < 0 || policy_epoch_fd < 0 {
            return;
        }
        match enterprise_utils::ai_agent_enforcement::compile_syscall_rules(&[]) {
            Ok(policy) => {
                if let Err(e) =
                    policy.sync_to_bpf_maps(syscall_rules_fd, policy_epoch_fd, max_records)
                {
                    warn!(
                        "AI Agent enforcement: failed to clear syscall BPF maps: {}",
                        e
                    );
                }
            }
            Err(e) => warn!(
                "AI Agent enforcement: failed to build empty syscall policy: {}",
                e
            ),
        }
    }

    #[cfg(feature = "enterprise")]
    fn sync_ai_agent_enforcement_policy(config: &crate::config::config::AiAgentEnforcementConfig) {
        use enterprise_utils::ai_agent_enforcement::{
            compile_exec_rules, compile_syscall_rules, set_global_exec_policy, EnforcementMode,
        };

        let max_exec_records = config.max_rules.min(AI_AGENT_EXEC_RULES_BPF_MAX);
        let max_syscall_records = config.max_rules.min(AI_AGENT_SYSCALL_RULES_BPF_MAX);
        if !config.enabled {
            set_global_exec_policy(None);
            AI_AGENT_EXEC_LSM_EVENTS_ACTIVE.store(false, Ordering::Relaxed);
            AI_AGENT_EXEC_KPROBE_EVENTS_ACTIVE.store(false, Ordering::Relaxed);
            Self::clear_ai_agent_exec_enforcement_bpf_maps(max_exec_records);
            Self::clear_ai_agent_syscall_enforcement_bpf_maps(max_syscall_records);
            return;
        }

        let exec_rules_fd = AI_AGENT_EXEC_RULES_MAP_FD.load(Ordering::Relaxed);
        let syscall_rules_fd = AI_AGENT_SYSCALL_RULES_MAP_FD.load(Ordering::Relaxed);
        let policy_epoch_fd = AI_AGENT_POLICY_EPOCH_MAP_FD.load(Ordering::Relaxed);
        let exec_bpf_maps_available = exec_rules_fd >= 0 && policy_epoch_fd >= 0;
        let syscall_bpf_maps_available = syscall_rules_fd >= 0 && policy_epoch_fd >= 0;
        let lsm_allowed = ai_agent_enforcement_lsm_allowed(config);
        let kprobe_override_allowed = ai_agent_enforcement_kprobe_override_allowed(config);
        let requested_block = ai_agent_enforcement_mode_eq(&config.mode, "block");
        let exec_effective_mode = if requested_block
            && exec_bpf_maps_available
            && (lsm_allowed || kprobe_override_allowed)
        {
            EnforcementMode::Block
        } else {
            if requested_block {
                warn!(
                    "AI Agent enforcement: block mode requested but no exec blocking mechanism is available or allowed; downgrade to audit-only (maps_available={}, lsm_allowed={}, kprobe_override_allowed={})",
                    exec_bpf_maps_available, lsm_allowed, kprobe_override_allowed
                );
            }
            EnforcementMode::AuditOnly
        };

        let inputs = ai_agent_exec_enforcement_inputs(config, exec_effective_mode);
        let policy = match compile_exec_rules(&inputs) {
            Ok(policy) => policy,
            Err(e) => {
                warn!("AI Agent enforcement: failed to compile policy: {}", e);
                set_global_exec_policy(None);
                AI_AGENT_EXEC_LSM_EVENTS_ACTIVE.store(false, Ordering::Relaxed);
                AI_AGENT_EXEC_KPROBE_EVENTS_ACTIVE.store(false, Ordering::Relaxed);
                Self::clear_ai_agent_exec_enforcement_bpf_maps(max_exec_records);
                return;
            }
        };

        if exec_effective_mode == EnforcementMode::Block {
            if let Err(e) =
                policy.sync_to_bpf_maps(exec_rules_fd, policy_epoch_fd, max_exec_records)
            {
                warn!(
                    "AI Agent enforcement: failed to sync BPF policy, downgrade to audit-only: {}",
                    e
                );
                let audit_inputs =
                    ai_agent_exec_enforcement_inputs(config, EnforcementMode::AuditOnly);
                match compile_exec_rules(&audit_inputs) {
                    Ok(audit_policy) => set_global_exec_policy(Some(audit_policy)),
                    Err(e) => {
                        warn!(
                            "AI Agent enforcement: failed to compile audit policy: {}",
                            e
                        );
                        set_global_exec_policy(None);
                    }
                }
                AI_AGENT_EXEC_LSM_EVENTS_ACTIVE.store(false, Ordering::Relaxed);
                AI_AGENT_EXEC_KPROBE_EVENTS_ACTIVE.store(false, Ordering::Relaxed);
                Self::clear_ai_agent_exec_enforcement_bpf_maps(max_exec_records);
                return;
            }
            AI_AGENT_EXEC_LSM_EVENTS_ACTIVE.store(lsm_allowed, Ordering::Relaxed);
            AI_AGENT_EXEC_KPROBE_EVENTS_ACTIVE.store(kprobe_override_allowed, Ordering::Relaxed);
        } else {
            AI_AGENT_EXEC_LSM_EVENTS_ACTIVE.store(false, Ordering::Relaxed);
            AI_AGENT_EXEC_KPROBE_EVENTS_ACTIVE.store(false, Ordering::Relaxed);
            Self::clear_ai_agent_exec_enforcement_bpf_maps(max_exec_records);
        }

        set_global_exec_policy(Some(policy));

        if !syscall_bpf_maps_available || !kprobe_override_allowed {
            if requested_block && !kprobe_override_allowed {
                warn!(
                    "AI Agent enforcement: syscall block requested but kprobe_override is disallowed by config; syscall enforcement disabled"
                );
            }
            Self::clear_ai_agent_syscall_enforcement_bpf_maps(max_syscall_records);
            return;
        }

        let syscall_inputs =
            ai_agent_syscall_enforcement_inputs(config, EnforcementMode::AuditOnly);
        if syscall_inputs.is_empty() {
            Self::clear_ai_agent_syscall_enforcement_bpf_maps(max_syscall_records);
            return;
        }

        let audit_syscall_policy = match compile_syscall_rules(&syscall_inputs) {
            Ok(policy) => policy,
            Err(e) => {
                warn!(
                    "AI Agent enforcement: failed to compile syscall policy: {}",
                    e
                );
                Self::clear_ai_agent_syscall_enforcement_bpf_maps(max_syscall_records);
                return;
            }
        };

        let syscall_effective_mode = if requested_block {
            let block_inputs = ai_agent_syscall_enforcement_inputs(config, EnforcementMode::Block);
            match compile_syscall_rules(&block_inputs) {
                Ok(block_policy) => {
                    let capability = KernelCapability::detect();
                    if ai_agent_syscall_policy_supported_by_kernel(&block_policy, &capability) {
                        Some(block_policy)
                    } else {
                        warn!(
                            "AI Agent enforcement: syscall block requested but kprobe override allowlist does not cover all configured syscall rules; downgrade to audit-only (capability={:?})",
                            capability
                        );
                        None
                    }
                }
                Err(e) => {
                    warn!(
                        "AI Agent enforcement: failed to compile blocking syscall policy: {}",
                        e
                    );
                    None
                }
            }
        } else {
            None
        };

        let syscall_policy = syscall_effective_mode
            .as_ref()
            .unwrap_or(&audit_syscall_policy);
        if let Err(e) =
            syscall_policy.sync_to_bpf_maps(syscall_rules_fd, policy_epoch_fd, max_syscall_records)
        {
            warn!(
                "AI Agent enforcement: failed to sync syscall BPF policy: {}",
                e
            );
            Self::clear_ai_agent_syscall_enforcement_bpf_maps(max_syscall_records);
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
            #[cfg(feature = "extended_observability")]
            {
                if ebpf::set_tcp_option_tracing_enabled(false) != 0 {
                    warn!("failed to disable tcp option tracing while stopping");
                }
            }
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
        dpdk_senders: Vec<DebugSender<Box<packet::Packet<'static>>>>,
        output: DebugSender<AppProto>,
        l7_stats_output: DebugSender<BatchedBox<L7Stats>>,
        proc_event_output: DebugSender<BoxedProcEvents>,
        ebpf_profile_sender: DebugSender<Profile>,
        queue_debugger: &QueueDebugger,
        stats_collector: Arc<stats::Collector>,
        exception_handler: ExceptionHandler,
        process_listener: &Arc<ProcessListener>,
    ) -> Result<Box<Self>> {
        let ebpf_config = config.load();
        let is_ebpf_meltdown = crate::utils::guard::is_kernel_ebpf_meltdown();
        let is_uprobe_meltdown = crate::utils::guard::is_kernel_ebpf_uprobe_meltdown();

        if ebpf_config.ebpf.disabled || is_ebpf_meltdown {
            info!("ebpf collector disabled.");
            return Err(Error::EbpfDisabled);
        }
        info!(
            "ebpf collector init... uprobe_meltdown: {}",
            is_uprobe_meltdown
        );
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

        #[cfg(feature = "extended_observability")]
        let memory_profiler = memory_profile::MemoryProfiler::new(
            config.clone(),
            ebpf_profile_sender.clone(),
            time_diff.clone(),
            policy_getter,
            queue_debugger,
            &stats_collector,
        );

        let config_handle = Self::ebpf_init(
            &ebpf_config,
            sender,
            dpdk_senders,
            proc_event_output,
            ebpf_profile_sender,
            policy_getter,
            time_diff.clone(),
            &stats_collector,
            process_listener,
            #[cfg(feature = "extended_observability")]
            memory_profiler.context(),
        )?;

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
                stats_collector: stats_collector.clone(),
                collector_config,
                pause: Arc::new(AtomicBool::new(true)),
            },
            thread_handle: None,
            config_handle,
            counter: Arc::new(EbpfCounter {
                rx: AtomicU64::new(0),
                time_backtrack_max: AtomicU64::new(0),
                get_token_failed: AtomicU64::new(0),
            }),
            need_reload_config: Default::default(),
            stats_collector,
            exception_handler,
            process_listener: process_listener.clone(),
            #[cfg(feature = "extended_observability")]
            memory_profiler,
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

    pub fn notify_reload_config(&self) {
        self.need_reload_config.store(true, Ordering::Relaxed);
    }

    pub fn on_config_change(&mut self, config: &EbpfConfig) {
        unsafe {
            let ecfg = &config.ebpf.profile;
            let is_uprobe_meltdown = crate::utils::guard::is_kernel_ebpf_uprobe_meltdown();
            let restart_cprofiler = ebpf::dwarf_available()
                && ebpf::continuous_profiler_running()
                && ((!is_uprobe_meltdown
                    && ebpf::get_dwarf_enabled() != !ecfg.unwinding.dwarf_disabled)
                    || ebpf::get_dwarf_process_map_size() as u32
                        != ecfg.unwinding.dwarf_process_map_size
                    || ebpf::get_dwarf_shard_map_size() as u32
                        != ecfg.unwinding.dwarf_shard_map_size);
            ebpf::set_dwarf_enabled(!is_uprobe_meltdown && !ecfg.unwinding.dwarf_disabled);
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
                #[cfg(feature = "extended_observability")]
                {
                    std::mem::drop(Box::from_raw(
                        contexts[ebpf::PROFILER_CTX_MEMORY_IDX]
                            as *mut memory_profile::MemoryContext,
                    ));
                }
                if let Ok(handle) = Self::ebpf_core_init(
                    &self.process_listener,
                    #[cfg(feature = "extended_observability")]
                    self.memory_profiler.context(),
                    config,
                    &self.stats_collector,
                ) {
                    self.config_handle = handle;
                } else {
                    warn!("ebpf start_continuous_profiler error.");
                    self.config_handle = Default::default();
                    return;
                }
            }

            Self::ebpf_on_config_change(
                config.l7_log_packet_size,
                config.ai_agent_max_payload_size,
            );
            #[cfg(feature = "enterprise")]
            Self::sync_ai_agent_enforcement_policy(&config.ai_agent_enforcement);

            #[cfg(feature = "extended_observability")]
            {
                let tcp_option_trace = &config.ebpf.socket.sock_ops.tcp_option_trace;

                if ebpf::set_tcp_option_tracing_sample_window(
                    tcp_option_trace.sampling_window_bytes as u32,
                ) != 0
                {
                    warn!(
                        "failed to set tcp option tracing sampling window to {}",
                        tcp_option_trace.sampling_window_bytes
                    );
                }

                if ebpf::set_tcp_option_tracing_enabled(tcp_option_trace.enabled) != 0 {
                    warn!(
                        "tcp option tracing enable failed (set enabled = {})",
                        tcp_option_trace.enabled
                    );
                }

                // NicOptimize
                if ebpf::set_nic_optimization(config.ebpf.network.nic_opt_enabled) != 0 {
                    warn!(
                        "Failed to apply NIC optimization setting (enabled: {})",
                        config.ebpf.network.nic_opt_enabled
                    );
                }

                for nic in &config.ebpf.network.nic_optimize {
                    nic.apply();
                }
            }
        }

        if config.l7_log_enabled() || config.dpdk_enabled {
            self.start();
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
        let need_reload_config = self.need_reload_config.clone();
        let dispatcher = self.thread_dispatcher.clone();
        self.thread_handle = Some(
            thread::Builder::new()
                .name("ebpf-collector".to_owned())
                .spawn(move || dispatcher.run(sync_counter, exception_handler, need_reload_config))
                .unwrap(),
        );

        #[cfg(feature = "extended_observability")]
        self.memory_profiler.start();

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

        #[cfg(feature = "extended_observability")]
        self.memory_profiler.stop();

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

        #[cfg(feature = "extended_observability")]
        self.memory_profiler.stop();

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
