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
    collections::{hash_map, HashMap, HashSet},
    ffi::CStr,
    num::NonZeroUsize,
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

use public::{
    counter::{Counter, OwnedCountable, RefCountable},
    debug::QueueDebugger,
    proto::metric,
    queue::{self, bounded_with_debug, BufferedSender, DebugSender, Receiver, StatsHandle},
};

use super::string_from_null_terminated_c_str;

use crate::{
    config::{
        config::EbpfProfileMemory,
        handler::EbpfAccess,
    },
    ebpf,
    integration_collector::Profile,
    policy::PolicyGetter,
    utils::stats::{self, Countable},
};

const ADDRESS_LRU_LEN_MIN: usize = 1024;
const ADDRESS_LRU_LEN_MAX: usize = 4194704;
const QUEUE_BATCH_SIZE: usize = 1024;

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

    allocs: HashMap<StackKey, metric::Profile>,
    in_use: HashMap<StackKey, metric::Profile>,

    counter: Arc<MemoryCounter>,
}

impl Processor {
    pub fn new(config: &EbpfProfileMemory, counter: Arc<MemoryCounter>) -> Self {
        let lru_len = (config.allocated_addresses_lru_len as usize)
            .clamp(ADDRESS_LRU_LEN_MIN, ADDRESS_LRU_LEN_MAX);
        Self {
            allocated_addrs: LruCache::new(NonZeroUsize::new(lru_len).unwrap()),
            allocs: Default::default(),
            in_use: Default::default(),
            counter,
        }
    }

    fn update_allocs(stacks: &mut HashMap<StackKey, metric::Profile>, data: metric::Profile) {
        match stacks.entry(StackKey {
            pid: data.pid,
            stack_id: data.u_stack_id,
        }) {
            hash_map::Entry::Occupied(mut entry) => {
                entry.get_mut().wide_count += data.wide_count;
            }
            hash_map::Entry::Vacant(entry) => {
                entry.insert(data);
            }
        }
    }

    fn update_frees(
        stacks: &mut HashMap<StackKey, metric::Profile>,
        pid: u32,
        stack_id: u32,
        size: u64,
    ) {
        let stack_key = StackKey { pid, stack_id };
        if let Some(p) = stacks.get_mut(&stack_key) {
            if p.wide_count > size {
                p.wide_count -= size;
            } else {
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

    pub fn process(&mut self, data: vec::Drain<Box<Data>>) {
        let mut ts = 0;
        for d in data {
            let Data { profile, mem_addr } = *d;

            if profile.timestamp < ts {
                self.counter.time_backtrack.fetch_add(1, Ordering::Relaxed);
            }
            ts = profile.timestamp;

            if profile.wide_count == 0 {
                // frees
                if let Some(AllocInfo { stack_id, size }) = self.allocated_addrs.pop(&AddrKey {
                    pid: profile.pid,
                    mem_addr,
                }) {
                    Self::update_frees(&mut self.in_use, profile.pid, stack_id, size);
                } else {
                    // lru overflow may also cause this
                    self.counter
                        .free_without_alloc
                        .fetch_add(1, Ordering::Relaxed);
                }
            } else {
                // allocs
                Self::update_allocs(&mut self.allocs, profile.clone());
                // for languages without free (i.e. JAVA), not recording in_use info, only allocs
                if mem_addr == 0 {
                    continue;
                }

                let addr_key = AddrKey {
                    pid: profile.pid,
                    mem_addr,
                };
                if let Some((old_key, record)) = self.allocated_addrs.push(
                    addr_key,
                    AllocInfo {
                        stack_id: profile.u_stack_id,
                        size: profile.wide_count,
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
                Self::update_allocs(&mut self.in_use, profile);
            }
        }
    }
}

#[derive(Debug)]
struct Data {
    profile: metric::Profile,
    mem_addr: u64,
}

pub struct MemoryContext {
    queue: DebugSender<Box<Data>>,
}

impl MemoryContext {
    pub unsafe fn update(
        &self,
        data: &ebpf::stack_profile_data,
        compress: bool,
        policy_getter: Option<&PolicyGetter>,
    ) {
        assert_eq!(data.profiler_type, ebpf::PROFILER_TYPE_MEMORY);

        if let Err(e) = self.queue.send(Box::new(if data.count == 0 {
            // frees
            Data {
                profile: metric::Profile {
                    timestamp: data.timestamp,
                    pid: data.pid,
                    ..Default::default()
                },
                mem_addr: data.mem_addr,
            }
        } else {
            // allocs
            let mut profile = metric::Profile {
                timestamp: data.timestamp,
                stime: data.stime,
                pid: data.pid,
                tid: data.tid,
                thread_name: string_from_null_terminated_c_str(data.comm.as_ptr()),
                process_name: string_from_null_terminated_c_str(data.process_name.as_ptr()),
                u_stack_id: data.u_stack_id,
                cpu: data.cpu,
                wide_count: data.count,
                ..Default::default()
            };
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
            if let Some(policy_getter) = policy_getter {
                let container_id =
                    CStr::from_ptr(data.container_id.as_ptr() as *const libc::c_char)
                        .to_string_lossy();
                profile.pod_id = policy_getter.lookup_pod_id(&container_id);
            }
            Data {
                profile,
                mem_addr: data.mem_addr,
            }
        })) {
            warn!("memory profiler send failed: {e}");
        }
    }
}

struct Interior {
    input: Receiver<Box<Data>>,
    output: BufferedSender<Profile>,

    config: EbpfAccess,
    time_diff: Arc<AtomicI64>,

    cache: Vec<Box<Data>>,
    processor: Processor,

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

    fn report(&mut self, config: &EbpfProfileMemory, timestamp: Duration) {
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

        for (_, mut profile) in self.processor.allocs.drain() {
            profile.timestamp = doc_timestamp;
            profile.event_type = metric::ProfileEventType::EbpfMemAlloc.into();
            profile.count = profile.wide_count as u32;
            if let Err(e) = self.output.send(Profile(profile)) {
                warn!("memory profiler send failed: {e}");
                self.output.clear();
            }
        }

        let mut process_addrs_and_stime = HashMap::new();
        let mut dead_pids = HashSet::new();
        for (key, _) in self.processor.allocated_addrs.iter() {
            let stime = Self::process_stime_millis(key.pid);
            if stime.is_none() {
                dead_pids.insert(key.pid);
            }
            process_addrs_and_stime
                .entry(key.pid)
                .or_insert((vec![], stime))
                .0
                .push(key.mem_addr);
        }

        self.processor
            .in_use
            .retain(|StackKey { pid, .. }, profile| {
                match process_addrs_and_stime.get(pid) {
                    Some((_, Some(stime)))
                        if (*stime as i64 - profile.stime as i64).abs()
                            < Self::PROCESS_RESTART_THRESHOLD.as_nanos() as i64 =>
                    {
                        ()
                    }
                    _ => {
                        dead_pids.insert(*pid);
                        return false;
                    }
                }
                let mut p = profile.clone();
                p.timestamp = doc_timestamp;
                p.event_type = metric::ProfileEventType::EbpfMemInUse.into();
                p.count = p.wide_count as u32;
                if let Err(e) = self.output.send(Profile(p)) {
                    warn!("memory profiler send failed: {e}");
                    self.output.clear();
                }
                true
            });

        if !dead_pids.is_empty() {
            self.cache.retain(|it| !dead_pids.contains(&it.profile.pid));
            for pid in dead_pids {
                let Some((addrs, _)) = process_addrs_and_stime.get(&pid) else {
                    continue;
                };
                for addr in addrs {
                    self.processor.allocated_addrs.pop(&AddrKey {
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

    pub fn process(mut self) -> Receiver<Box<Data>> {
        let mut batch = Vec::with_capacity(QUEUE_BATCH_SIZE);

        while self.running.load(Ordering::Relaxed) {
            match self
                .input
                .recv_all(&mut batch, Some(Self::QUEUE_RECV_TIMEOUT))
            {
                Ok(_) => {
                    self.cache.append(&mut batch);
                    self.cache.sort_unstable_by_key(|it| it.profile.timestamp);
                }
                Err(queue::Error::Timeout) => (),
                Err(queue::Error::Terminated(_, _)) => self.running.store(false, Ordering::Relaxed),
                Err(queue::Error::BatchTooLarge(_)) => unreachable!(),
            }

            let config = self.config.load();
            let memory_config = &config.ebpf.profile.memory;
            self.processor.update_config(memory_config);

            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap();
            let ts_nanos = now.as_nanos() as u64;
            let dequeue_before =
                ts_nanos.saturating_sub(memory_config.sort_interval.as_nanos() as u64);
            // interval limit
            let dequeue_idx = self
                .cache
                .partition_point(|it| it.profile.timestamp <= dequeue_before);
            // length limit
            let dequeue_idx = self
                .cache
                .len()
                .saturating_sub(memory_config.sort_length as usize)
                .max(dequeue_idx);

            self.processor.process(self.cache.drain(..dequeue_idx));

            self.report(memory_config, now);
        }

        // return the receiver queue
        self.input
    }
}

pub struct MemoryProfiler {
    input: DebugSender<Box<Data>>,
    inner_recv: Option<Receiver<Box<Data>>>,
    output: DebugSender<Profile>,

    config: EbpfAccess,
    time_diff: Arc<AtomicI64>,

    counter: Arc<MemoryCounter>,
    running: Arc<AtomicBool>,
    thread_handle: Option<JoinHandle<Receiver<Box<Data>>>>,
}

impl MemoryProfiler {
    pub fn new(
        config: EbpfAccess,
        output: DebugSender<Profile>,
        time_diff: Arc<AtomicI64>,
        queue_debugger: &QueueDebugger,
        stats_collector: &stats::Collector,
    ) -> Self {
        let cfg = config.load();

        let (input, inner_recv, stats) =
            bounded_with_debug(cfg.ebpf.profile.memory.queue_size, "0-ebpf-to-memory-profiler", queue_debugger);

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
        let cfg = self.config.load();
        let memory_config = &cfg.ebpf.profile.memory;
        let interior = Interior {
            input: self.inner_recv.take().unwrap(),
            output: BufferedSender::from(self.output.clone()),
            config: self.config.clone(),
            time_diff: self.time_diff.clone(),
            // items are pushed into cache in batches, so the capacity is the sum of sort_length and QUEUE_BATCH_SIZE
            cache: Vec::with_capacity(memory_config.sort_length as usize + QUEUE_BATCH_SIZE),
            processor: Processor::new(memory_config, self.counter.clone()),
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
    queue_counter: StatsHandle<Box<Data>>,

    time_backtrack: AtomicU64,
    free_without_alloc: AtomicU64,
    alloc_without_free: AtomicU64,
    lru_overflow: AtomicU64,
}

impl MemoryCounter {
    fn new(queue_stats: StatsHandle<Box<Data>>) -> Self {
        Self {
            queue_counter: queue_stats,
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
