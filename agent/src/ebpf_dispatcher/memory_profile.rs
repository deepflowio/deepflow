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

use std::{
    cell::RefCell,
    collections::{hash_map, HashMap, HashSet},
    ffi::CStr,
    num::NonZeroUsize,
    ptr::NonNull,
    rc::Rc,
    slice,
    sync::{
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
        Arc, Weak,
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime},
    vec,
};

use arc_swap::access::Access;
use log::{debug, info, warn};
use lru::LruCache;
use procfs::process::Process;
use sysinfo::{ProcessExt, SystemExt};

use public::{
    counter::{Counter, OwnedCountable, RefCountable},
    debug::QueueDebugger,
    proto::metric,
    queue::{self, bounded_with_debug, BufferedSender, DebugSender, Receiver, StatsHandle},
};

use super::string_from_null_terminated_c_str;

use crate::{
    config::{config::EbpfProfileMemory, handler::EbpfAccess},
    ebpf,
    integration_collector::Profile,
    policy::PolicyGetter,
    utils::stats::{self, Countable},
};

const ADDRESS_LRU_LEN_MIN: usize = 1024;
const ADDRESS_LRU_LEN_MAX: usize = 4194704;
const QUEUE_BATCH_SIZE: usize = 4096;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
struct AddrKey {
    pid: u32,
    mem_addr: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
struct StackKey {
    pid: u32,
    stack_id: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct AllocInfo {
    stack_id: u32,
    size: u64,
}

struct Processor {
    allocated_addrs: LruCache<AddrKey, AllocInfo>,

    initial_memory: u64,

    allocs: HashMap<StackKey, Rc<RefCell<Data>>>,
    in_use: HashMap<StackKey, Rc<RefCell<Data>>>,

    latest_epoch: u64, // latest epoch of input data in nanos

    counter: Arc<MemoryCounter>,
}

impl Processor {
    pub fn new(config: &EbpfProfileMemory, counter: Arc<MemoryCounter>) -> Self {
        let lru_len = (config.allocated_addresses_lru_len as usize)
            .clamp(ADDRESS_LRU_LEN_MIN, ADDRESS_LRU_LEN_MAX);
        Self {
            allocated_addrs: LruCache::new(NonZeroUsize::new(lru_len).unwrap()),
            initial_memory: {
                let s = sysinfo::System::new_with_specifics(
                    sysinfo::RefreshKind::new().with_processes(sysinfo::ProcessRefreshKind::new()),
                );
                s.process(sysinfo::Pid::from(std::process::id() as i32))
                    .map(|p| p.memory())
                    .unwrap_or(0)
            },
            allocs: Default::default(),
            in_use: Default::default(),
            latest_epoch: 0,
            counter,
        }
    }

    fn update_allocs(stacks: &mut HashMap<StackKey, Rc<RefCell<Data>>>, data: Rc<RefCell<Data>>) {
        let borrowed = data.borrow();
        let profile = borrowed.as_ref();
        match stacks.entry(StackKey {
            pid: profile.pid,
            stack_id: profile.u_stack_id,
        }) {
            hash_map::Entry::Occupied(mut entry) => {
                let mut borrowed = entry.get_mut().borrow_mut();
                borrowed.as_mut().count += profile.count;
            }
            hash_map::Entry::Vacant(entry) => {
                std::mem::drop(borrowed);
                entry.insert(data);
            }
        }
    }

    fn update_frees(
        stacks: &mut HashMap<StackKey, Rc<RefCell<Data>>>,
        pid: u32,
        stack_id: u32,
        size: u64,
    ) {
        let stack_key = StackKey { pid, stack_id };
        if let Some(data) = stacks.get_mut(&stack_key) {
            let mut borrowed = data.borrow_mut();
            let p = borrowed.as_mut();
            if p.count > size {
                p.count -= size;
            } else {
                std::mem::drop(borrowed);
                stacks.remove(&stack_key);
            }
        }
    }

    pub fn update_config(&mut self, config: &EbpfProfileMemory) {
        let lru_len = (config.allocated_addresses_lru_len as usize)
            .clamp(ADDRESS_LRU_LEN_MIN, ADDRESS_LRU_LEN_MAX);

        // no need to resize
        if lru_len == self.allocated_addrs.cap().get() {
            return;
        }

        // remove entries until len <= lru_len
        while self.allocated_addrs.len() > lru_len {
            self.counter.lru_overflow.fetch_add(1, Ordering::Relaxed);
            let (AddrKey { pid, .. }, AllocInfo { stack_id, size }) =
                self.allocated_addrs.pop_lru().unwrap();
            Self::update_frees(&mut self.in_use, pid, stack_id, size);
        }

        self.allocated_addrs
            .resize(NonZeroUsize::new(lru_len).unwrap());
    }

    pub fn process(&mut self, data: vec::Drain<Data>) {
        for datum in data {
            let profile = datum.as_ref();

            if profile.timestamp < self.latest_epoch {
                self.counter.time_backtrack.fetch_add(1, Ordering::Relaxed);
            } else {
                self.latest_epoch = profile.timestamp;
            }

            let addr_key = AddrKey {
                pid: profile.pid,
                mem_addr: profile.mem_addr,
            };

            if profile.count as i64 <= 0 {
                // frees
                if let Some(AllocInfo { stack_id, size }) = self.allocated_addrs.pop(&addr_key) {
                    Self::update_frees(&mut self.in_use, profile.pid, stack_id, size);
                } else {
                    // lru overflow may also cause this
                    self.counter
                        .free_without_alloc
                        .fetch_add(1, Ordering::Relaxed);
                    // also reduces initial memory estimation
                    self.initial_memory = self
                        .initial_memory
                        .saturating_sub((profile.count as i64).abs() as u64);
                }
            } else {
                // data will reside in both allocs and in_use hashmaps
                let rc_data = Rc::new(RefCell::new(datum));

                // allocs
                Self::update_allocs(&mut self.allocs, rc_data.clone());

                let borrowed = rc_data.borrow();
                let profile = borrowed.as_ref();
                // for languages without free (i.e. JAVA), not recording in_use info, only allocs
                if profile.mem_addr == 0 {
                    continue;
                }

                if let Some((old_key, record)) = self.allocated_addrs.push(
                    addr_key,
                    AllocInfo {
                        stack_id: profile.u_stack_id,
                        size: profile.count,
                    },
                ) {
                    // alloc entry replaced, remove the old from self.in_use
                    if old_key == addr_key {
                        // consecutive allocs on same address
                        self.counter
                            .alloc_without_free
                            .fetch_add(1, Ordering::Relaxed);
                    } else {
                        // LRU full
                        self.counter.lru_overflow.fetch_add(1, Ordering::Relaxed);
                    }
                    Self::update_frees(&mut self.in_use, profile.pid, record.stack_id, record.size);
                }
                std::mem::drop(borrowed);
                Self::update_allocs(&mut self.in_use, rc_data);
            }
        }
    }
}

// DO NOT impl Copy/Clone for this type
#[derive(Debug)]
struct Data {
    ptr: NonNull<ebpf::stack_profile_data>,
}

unsafe impl Send for Data {}

impl AsRef<ebpf::stack_profile_data> for Data {
    fn as_ref(&self) -> &ebpf::stack_profile_data {
        unsafe { self.ptr.as_ref() }
    }
}

impl AsMut<ebpf::stack_profile_data> for Data {
    fn as_mut(&mut self) -> &mut ebpf::stack_profile_data {
        unsafe { self.ptr.as_mut() }
    }
}

impl Drop for Data {
    fn drop(&mut self) {
        let p = self.ptr.as_ptr();
        unsafe {
            ebpf::clib_mem_free(p as *mut libc::c_void);
        }
    }
}

pub struct MemoryContext {
    queue: DebugSender<Data>,
}

impl MemoryContext {
    pub unsafe fn update(&self, data: *mut ebpf::stack_profile_data) {
        assert_eq!((*data).profiler_type, ebpf::PROFILER_TYPE_MEMORY);

        let data = Data {
            ptr: NonNull::new_unchecked(data),
        };

        // struct Data is reponsible for freeing the data
        if let Err(e) = self.queue.send(data) {
            warn!("memory profiler send failed: {e}");
        }
    }
}

struct Interior {
    input: Receiver<Data>,
    output: BufferedSender<Profile>,

    config: EbpfAccess,
    time_diff: Arc<AtomicI64>,
    policy_getter: PolicyGetter,

    last_report: Duration,

    counter: Arc<MemoryCounter>,
    running: Arc<AtomicBool>,
}

impl Interior {
    // There's a small difference (less than 1s) between start time from profiler and from procfs rust lib.
    // If cached stime from profiler plus THRESHOLD is smaller than start time from procfs, it's a process restart
    const PROCESS_RESTART_THRESHOLD: Duration = Duration::from_secs(3);

    fn process_stime_millis(pid: u32) -> Option<u64> {
        Process::new(pid as i32)
            .and_then(|p| p.stat())
            .and_then(|s| s.starttime())
            .map(|s| s.timestamp_millis() as u64)
            .ok()
    }

    fn generate_profile(
        compress: bool,
        policy_getter: &PolicyGetter,
        data: &ebpf::stack_profile_data,
    ) -> metric::Profile {
        let mut profile = metric::Profile {
            stime: data.stime,
            pid: data.pid,
            tid: data.tid,
            thread_name: unsafe { string_from_null_terminated_c_str(data.comm.as_ptr()) },
            process_name: unsafe { string_from_null_terminated_c_str(data.process_name.as_ptr()) },
            u_stack_id: data.u_stack_id,
            cpu: data.cpu,
            count: data.count as u32,
            wide_count: data.count,
            pod_id: unsafe {
                let container_id =
                    CStr::from_ptr(data.container_id.as_ptr() as *const libc::c_char)
                        .to_string_lossy();
                policy_getter.lookup_pod_id(&container_id)
            },
            ..Default::default()
        };

        unsafe {
            let stack =
                slice::from_raw_parts(data.stack_data as *mut u8, data.stack_data_len as usize);
            if compress {
                match zstd::bulk::compress(&stack, 0) {
                    Ok(compressed_data) => {
                        profile.data_compressed = true;
                        profile.data = compressed_data;
                    }
                    Err(e) => {
                        profile.data = stack.to_vec();
                        debug!("failed to compress ebpf profile: {:?}", e);
                    }
                }
            } else {
                profile.data = stack.to_vec();
            }
        }

        profile
    }

    fn report(
        &mut self,
        cache: &mut Vec<Data>,
        processor: &mut Processor,
        config: &EbpfProfileMemory,
        compress: bool,
        timestamp: Duration,
    ) {
        if self.last_report.is_zero() {
            self.last_report = timestamp;
            return;
        }
        if timestamp < self.last_report + config.report_interval {
            return;
        }
        self.last_report = timestamp;

        let doc_timestamp = (timestamp.as_nanos() as i64 - config.report_interval.as_nanos() as i64
            + self.time_diff.load(Ordering::Relaxed)) as u64;

        for (_, data) in processor.allocs.drain() {
            let profile = metric::Profile {
                timestamp: doc_timestamp,
                event_type: metric::ProfileEventType::EbpfMemAlloc.into(),
                ..Self::generate_profile(compress, &self.policy_getter, data.borrow().as_ref())
            };
            if let Err(e) = self.output.send(Profile(profile)) {
                warn!("memory profiler send failed: {e}");
                self.output.clear();
            }
        }

        let mut process_addrs_and_stime: HashMap<u32, (Vec<u64>, Option<u64>)> = HashMap::new();
        let mut dead_pids = HashSet::new();
        for (key, _) in processor.allocated_addrs.iter() {
            match process_addrs_and_stime.entry(key.pid) {
                hash_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().0.push(key.mem_addr);
                }
                hash_map::Entry::Vacant(entry) => {
                    let stime = Self::process_stime_millis(key.pid);
                    if stime.is_none() {
                        dead_pids.insert(key.pid);
                    }
                    entry.insert((vec![key.mem_addr], stime));
                }
            }
        }

        let agent_pid = std::process::id() as u32;
        let mut agent_initial_memory: Option<metric::Profile> = None;

        processor.in_use.retain(|StackKey { pid, .. }, data| {
            let borrowed = data.borrow();
            let data = borrowed.as_ref();

            match process_addrs_and_stime.get(pid) {
                Some((_, Some(stime)))
                    if (*stime as i64 - data.stime as i64).abs()
                        < Self::PROCESS_RESTART_THRESHOLD.as_nanos() as i64 =>
                {
                    ()
                }
                _ => {
                    dead_pids.insert(*pid);
                    return false;
                }
            }

            let profile = metric::Profile {
                timestamp: doc_timestamp,
                event_type: metric::ProfileEventType::EbpfMemInUse.into(),
                ..Self::generate_profile(compress, &self.policy_getter, data)
            };

            // pseudo initial memory before agent attach memory uprobes
            if processor.initial_memory > 0 && *pid == agent_pid && agent_initial_memory.is_none() {
                agent_initial_memory = Some(metric::Profile {
                    tid: 0,
                    thread_name: String::new(),
                    u_stack_id: 0,
                    cpu: 0,
                    count: processor.initial_memory as u32,
                    wide_count: processor.initial_memory,
                    data: String::from("[initial_memory]").into_bytes(),
                    data_compressed: false,
                    ..profile.clone()
                });
            }

            if let Err(e) = self.output.send(Profile(profile)) {
                warn!("memory profiler send failed: {e}");
                self.output.clear();
            }
            true
        });

        if let Some(p) = agent_initial_memory {
            if let Err(e) = self.output.send(Profile(p)) {
                warn!("memory profiler send failed: {e}");
                self.output.clear();
            }
        }

        if !dead_pids.is_empty() {
            cache.retain(|it| !dead_pids.contains(&it.as_ref().pid));
            for pid in dead_pids {
                let Some((addrs, _)) = process_addrs_and_stime.get(&pid) else {
                    continue;
                };
                for addr in addrs {
                    processor.allocated_addrs.pop(&AddrKey {
                        pid,
                        mem_addr: *addr,
                    });
                }
            }
        }

        if let Err(e) = self.output.flush() {
            warn!("memory profiler flush failed: {e}");
            self.output.clear();
        }
    }

    const QUEUE_RECV_TIMEOUT: Duration = Duration::from_secs(1);

    pub fn process(mut self) -> Receiver<Data> {
        let mut batch = Vec::with_capacity(QUEUE_BATCH_SIZE);

        let config = self.config.load();
        let memory_config = &config.ebpf.profile.memory;
        // items are pushed into cache in batches, so the capacity is the sum of sort_length and QUEUE_BATCH_SIZE
        let mut cache = Vec::with_capacity(memory_config.sort_length as usize + QUEUE_BATCH_SIZE);
        let mut processor = Processor::new(memory_config, self.counter.clone());
        std::mem::drop(config);

        while self.running.load(Ordering::Relaxed) {
            let mut ts_nanos: Option<u64> = None;
            match self
                .input
                .recv_all(&mut batch, Some(Self::QUEUE_RECV_TIMEOUT))
            {
                Ok(_) => {
                    cache.append(&mut batch);
                    cache.sort_unstable_by_key(|it| it.as_ref().timestamp);
                    ts_nanos = cache.last().map(|it| it.as_ref().timestamp);
                }
                Err(queue::Error::Timeout) => (),
                Err(queue::Error::Terminated(_, _)) => self.running.store(false, Ordering::Relaxed),
                Err(queue::Error::BatchTooLarge(_)) => unreachable!(),
            }

            let config = self.config.load();
            let memory_config = &config.ebpf.profile.memory;
            processor.update_config(memory_config);

            // use max timestamp in cache if the result of `recv_all` is not timeout,
            // otherwise use current time
            let now = match ts_nanos {
                Some(ts) => Duration::from_nanos(ts),
                None => SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap(),
            };
            let ts_nanos = now.as_nanos() as u64;
            let dequeue_before =
                ts_nanos.saturating_sub(memory_config.sort_interval.as_nanos() as u64);
            // interval limit
            let interval_dequeue_idx =
                cache.partition_point(|it| it.as_ref().timestamp <= dequeue_before);
            self.counter
                .dequeued_by_interval
                .fetch_add(interval_dequeue_idx as u64, Ordering::Relaxed);
            // length limit
            let length_dequeue_idx = cache
                .len()
                .saturating_sub(memory_config.sort_length as usize);
            self.counter
                .dequeued_by_length
                .fetch_add(length_dequeue_idx as u64, Ordering::Relaxed);

            let dequeue_idx = interval_dequeue_idx.max(length_dequeue_idx);
            processor.process(cache.drain(..dequeue_idx));

            self.report(
                &mut cache,
                &mut processor,
                memory_config,
                config.ebpf.profile.preprocess.stack_compression,
                now,
            );
        }

        // return the receiver queue
        self.input
    }
}

pub struct MemoryProfiler {
    input: DebugSender<Data>,
    inner_recv: Option<Receiver<Data>>,
    output: DebugSender<Profile>,

    config: EbpfAccess,
    time_diff: Arc<AtomicI64>,
    policy_getter: PolicyGetter,

    counter: Arc<MemoryCounter>,
    running: Arc<AtomicBool>,
    thread_handle: Option<JoinHandle<Receiver<Data>>>,
}

impl MemoryProfiler {
    pub fn new(
        config: EbpfAccess,
        output: DebugSender<Profile>,
        time_diff: Arc<AtomicI64>,
        policy_getter: PolicyGetter,
        queue_debugger: &QueueDebugger,
        stats_collector: &stats::Collector,
    ) -> Self {
        let cfg = config.load();

        let (input, inner_recv, stats) = bounded_with_debug(
            cfg.ebpf.profile.memory.queue_size,
            "0-ebpf-to-memory-profiler",
            queue_debugger,
        );

        let counter = Arc::new(MemoryCounter::new(stats));
        stats_collector.register_countable(
            &stats::NoTagModule("ebpf-memory-profiler"),
            Countable::Ref(Arc::downgrade(&counter) as Weak<dyn RefCountable>),
        );

        Self {
            input,
            inner_recv: Some(inner_recv),
            output,
            config,
            time_diff,
            policy_getter,
            counter,
            running: Default::default(),
            thread_handle: None,
        }
    }

    pub fn context(&self) -> MemoryContext {
        MemoryContext {
            queue: self.input.clone(),
        }
    }

    pub fn start(&mut self) {
        if self.running.swap(true, Ordering::Relaxed) {
            info!("memory profiler already started");
            return;
        }
        if self.inner_recv.is_none() || self.thread_handle.is_some() {
            warn!("memory profiler is in invalid state, terminating agent");
            crate::utils::clean_and_exit(1);
        }

        info!("memory profiler starting");
        let interior = Interior {
            input: self.inner_recv.take().unwrap(),
            output: BufferedSender::from(self.output.clone()),
            config: self.config.clone(),
            time_diff: self.time_diff.clone(),
            policy_getter: self.policy_getter,
            last_report: Duration::ZERO,
            counter: self.counter.clone(),
            running: self.running.clone(),
        };
        self.thread_handle = Some(
            thread::Builder::new()
                .name("memory-profiler".to_owned())
                .spawn(move || interior.process())
                .unwrap(),
        );
        info!("memory profiler started");
    }

    pub fn stop(&mut self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            warn!("memory profiler already stopped");
            return;
        }

        info!("stopping memory profiler");
        self.inner_recv
            .replace(self.thread_handle.take().unwrap().join().unwrap());
        info!("stopped memory profiler");
    }
}

pub struct MemoryCounter {
    queue_counter: StatsHandle<Data>,

    dequeued_by_interval: AtomicU64,
    dequeued_by_length: AtomicU64,
    time_backtrack: AtomicU64,
    free_without_alloc: AtomicU64,
    alloc_without_free: AtomicU64,
    lru_overflow: AtomicU64,
}

impl MemoryCounter {
    fn new(queue_stats: StatsHandle<Data>) -> Self {
        Self {
            queue_counter: queue_stats,
            dequeued_by_interval: Default::default(),
            dequeued_by_length: Default::default(),
            time_backtrack: Default::default(),
            free_without_alloc: Default::default(),
            alloc_without_free: Default::default(),
            lru_overflow: Default::default(),
        }
    }
}

impl RefCountable for MemoryCounter {
    fn get_counters(&self) -> Vec<Counter> {
        let mut counters = self.queue_counter.get_counters();
        counters.extend_from_slice(&[
            (
                "dequeued_by_interval",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(self.dequeued_by_interval.swap(0, Ordering::Relaxed)),
            ),
            (
                "dequeued_by_length",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(self.dequeued_by_length.swap(0, Ordering::Relaxed)),
            ),
            (
                "time_backtrack",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(self.time_backtrack.swap(0, Ordering::Relaxed)),
            ),
            (
                "free_without_alloc",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(self.free_without_alloc.swap(0, Ordering::Relaxed)),
            ),
            (
                "alloc_without_free",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(self.alloc_without_free.swap(0, Ordering::Relaxed)),
            ),
            (
                "lru_overflow",
                stats::CounterType::Counted,
                stats::CounterValue::Unsigned(self.lru_overflow.swap(0, Ordering::Relaxed)),
            ),
        ]);
        counters
    }
}
