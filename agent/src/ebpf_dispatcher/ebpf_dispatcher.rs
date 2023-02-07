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

use std::ffi::CString;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use arc_swap::access::Access;
use libc::c_int;
use log::{debug, error, info, warn};

use super::{Error, Result};
use crate::common::ebpf::EbpfType;
use crate::common::l7_protocol_log::{
    get_all_protocol, L7ProtocolBitmap, L7ProtocolParserInterface,
};
use crate::common::meta_packet::MetaPacket;
use crate::common::TaggedFlow;
use crate::config::handler::{EbpfAccess, EbpfConfig, LogParserAccess};
use crate::config::FlowAccess;
use crate::ebpf::{self, set_allow_port_bitmap};
use crate::flow_generator::{FlowMap, MetaAppProto};
use crate::policy::PolicyGetter;
use crate::utils::stats;
use public::counter::{Counter, CounterType, CounterValue, OwnedCountable};
use public::{
    debug::QueueDebugger,
    queue::{bounded_with_debug, DebugSender, Receiver},
    utils::bitmap::parse_u16_range_list_to_bitmap,
};

pub struct EbpfCounter {
    rx: u64,
}

impl EbpfCounter {
    fn reset(&mut self) {
        self.rx = 0;
    }
}

#[derive(Clone, Copy)]
pub struct SyncEbpfCounter {
    counter: *mut EbpfCounter,
}

impl SyncEbpfCounter {
    fn counter(&self) -> &mut EbpfCounter {
        unsafe { &mut *self.counter }
    }
}

unsafe impl Send for SyncEbpfCounter {}
unsafe impl Sync for SyncEbpfCounter {}

impl OwnedCountable for SyncEbpfCounter {
    fn get_counters(&self) -> Vec<Counter> {
        let rx = self.counter().rx;
        self.counter().reset();

        let ebpf_counter = unsafe { ebpf::socket_tracer_stats() };

        vec![
            (
                "collector_in",
                CounterType::Counted,
                CounterValue::Unsigned(rx),
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

struct EbpfDispatcher {
    dispatcher_id: usize,
    time_diff: Arc<AtomicI64>,

    receiver: Receiver<Box<MetaPacket<'static>>>,

    // 策略查询
    policy_getter: PolicyGetter,

    // GRPC配置
    log_parser_config: LogParserAccess,
    flow_map_config: FlowAccess,

    config: EbpfAccess,
    output: DebugSender<Box<MetaAppProto>>, // Send MetaAppProtos to the AppProtoLogsParser
    flow_output: DebugSender<Box<TaggedFlow>>, // Send TaggedFlows to the QuadrupleGenerator
    stats_collector: Arc<stats::Collector>,
}

impl EbpfDispatcher {
    const FLOW_MAP_SIZE: usize = 1 << 14;

    fn run(&mut self, sync_counter: SyncEbpfCounter) {
        let mut flow_map = FlowMap::new(
            self.dispatcher_id as u32,
            self.flow_output.clone(),
            self.policy_getter,
            self.output.clone(),
            self.time_diff.clone(),
            self.flow_map_config.clone(),
            self.log_parser_config.clone(),
            Some(self.config.clone()),
            None, // Enterprise Edition Feature: packet-sequence
            &self.stats_collector,
            true, // from_ebpf
        );
        let ebpf_config = self.config.load();
        const QUEUE_BATCH_SIZE: usize = 1024;
        let mut batch = Vec::with_capacity(QUEUE_BATCH_SIZE);
        while unsafe { SWITCH } {
            if self
                .receiver
                .recv_all(&mut batch, Some(Duration::from_secs(1)))
                .is_err()
            {
                continue;
            }

            for mut packet in batch.drain(..) {
                sync_counter.counter().rx += 1;

                packet.timestamp_adjust(self.time_diff.load(Ordering::Relaxed));
                packet.set_loopback_mac(ebpf_config.ctrl_mac);
                flow_map.inject_meta_packet(&mut packet);
            }
        }
    }
}

struct SyncEbpfDispatcher {
    dispatcher: *mut EbpfDispatcher,
}

unsafe impl Sync for SyncEbpfDispatcher {}
unsafe impl Send for SyncEbpfDispatcher {}

impl SyncEbpfDispatcher {
    fn dispatcher(&self) -> &mut EbpfDispatcher {
        unsafe { &mut *self.dispatcher }
    }
}

pub struct EbpfCollector {
    thread_dispatcher: EbpfDispatcher,
    thread_handle: Option<JoinHandle<()>>,

    counter: EbpfCounter,
}

static mut SWITCH: bool = false;
static mut SENDER: Option<DebugSender<Box<MetaPacket>>> = None;

impl EbpfCollector {
    extern "C" fn ebpf_callback(sd: *mut ebpf::SK_BPF_DATA) {
        unsafe {
            if !SWITCH || SENDER.is_none() {
                return;
            }
            let packet = MetaPacket::from_ebpf(sd);
            if packet.is_err() {
                warn!("meta packet parse from ebpf error: {}", packet.unwrap_err());
                return;
            }
            let packet = packet.unwrap();
            if packet.ebpf_type == EbpfType::IOEvent {
                // FIXME: Remove this code when the feature is stable
                return;
            }
            if let Err(e) = SENDER.as_mut().unwrap().send(Box::new(packet)) {
                warn!("meta packet send ebpf error: {:?}", e);
            }
        }
    }

    fn ebpf_init(
        config: &EbpfConfig,
        sender: DebugSender<Box<MetaPacket<'static>>>,
        l7_protocol_enabled_bitmap: L7ProtocolBitmap,
    ) -> Result<()> {
        // ebpf内核模块初始化
        unsafe {
            let log_file = config.ebpf.log_file.clone();
            let log_file = if !log_file.is_empty() {
                CString::new(log_file.as_bytes())
                    .unwrap()
                    .as_c_str()
                    .as_ptr()
            } else {
                std::ptr::null()
            };

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
                    set_allow_port_bitmap(b.get_raw_ptr());
                }
            }

            if ebpf::bpf_tracer_init(log_file, true) != 0 {
                info!("ebpf bpf_tracer_init error: {}", config.ebpf.log_file);
                return Err(Error::EbpfInitError);
            }

            if ebpf::set_go_tracing_timeout(config.ebpf.go_tracing_timeout as c_int) != 0 {
                info!(
                    "ebpf set_go_tracing_timeout error: {}",
                    config.ebpf.log_file
                );
                return Err(Error::EbpfInitError);
            }

            if ebpf::running_socket_tracer(
                Self::ebpf_callback,                       /* 回调接口 rust -> C */
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
            ebpf::bpf_tracer_finish();
        }
        // ebpf和ebpf collector通信配置初始化
        unsafe {
            SWITCH = false;
            SENDER = Some(sender);
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
             * The eBPF tracer_start() can be executed successfully only after the eBPF
             * initialization is complete and the eBPF is in the STOP state.Need to wait
             * for the initialization of tracer and the state transition to complete.
             * The maximum waiting time is 100 seconds, more than this will throw an error.
             */
            while ebpf::tracer_start() != 0 && retry_count < RETRY_MAX {
                std::thread::sleep(Duration::from_secs(2));
                retry_count = retry_count + 1;
                if retry_count >= RETRY_MAX {
                    error!(
                        "The tracer_start() error. Kernel offset adapt failed. \
                            Provide the operating system name and the \
                            'kernel-devel' package for developers to adapt."
                    );
                }
            }
        }
    }

    fn ebpf_stop() {
        info!("ebpf collector stopping ebpf-kernel.");
        unsafe {
            ebpf::tracer_stop();
        }
    }

    pub fn new(
        dispatcher_id: usize,
        time_diff: Arc<AtomicI64>,
        config: EbpfAccess,
        log_parser_config: LogParserAccess,
        flow_map_config: FlowAccess,
        policy_getter: PolicyGetter,
        output: DebugSender<Box<MetaAppProto>>,
        flow_output: DebugSender<Box<TaggedFlow>>,
        queue_debugger: &QueueDebugger,
        stats_collector: Arc<stats::Collector>,
    ) -> Result<Box<Self>> {
        let ebpf_config = config.load();
        if ebpf_config.ebpf.disabled {
            info!("ebpf collector disabled.");
            return Err(Error::EbpfDisabled);
        }
        info!("ebpf collector init...");
        let (sender, receiver, _) =
            bounded_with_debug(4096, "0-ebpf-packet-to-ebpf-dispatcher", queue_debugger);

        Self::ebpf_init(&ebpf_config, sender, ebpf_config.l7_protocol_enabled_bitmap)?;
        Self::ebpf_on_config_change(ebpf::CAP_LEN_MAX);

        info!("ebpf collector initialized.");
        return Ok(Box::new(EbpfCollector {
            thread_dispatcher: EbpfDispatcher {
                dispatcher_id,
                time_diff,
                receiver,
                policy_getter,
                config,
                log_parser_config,
                output,
                flow_output,
                flow_map_config,
                stats_collector,
            },
            thread_handle: None,
            counter: EbpfCounter { rx: 0 },
        }));
    }

    pub fn get_sync_counter(&self) -> SyncEbpfCounter {
        SyncEbpfCounter {
            counter: &self.counter as *const EbpfCounter as *mut EbpfCounter,
        }
    }

    fn get_sync_dispatcher(&self) -> SyncEbpfDispatcher {
        SyncEbpfDispatcher {
            dispatcher: &self.thread_dispatcher as *const EbpfDispatcher as *mut EbpfDispatcher,
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

        let sync_dispatcher = self.get_sync_dispatcher();
        let sync_counter = self.get_sync_counter();
        self.thread_handle = Some(
            thread::Builder::new()
                .name("ebpf-collector".to_owned())
                .spawn(move || sync_dispatcher.dispatcher().run(sync_counter))
                .unwrap(),
        );

        debug!("ebpf collector starting ebpf-kernel.");
        Self::ebpf_start();
        info!("ebpf collector started");
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
