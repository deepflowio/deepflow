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
        atomic::{AtomicU64, Ordering},
        Arc, Weak,
    },
    time::Duration,
    vec,
};

use arc_swap::access::Access;
use log::{debug, warn};
use lru::LruCache;
use procfs::process::Process;
use zstd::bulk::compress;

use public::{
    counter::{Counter, CounterType, CounterValue, RefCountable},
    proto::metric,
    queue::DebugSender,
};

use super::string_from_null_terminated_c_str;

use crate::{
    config::{
        config::{EbpfProfile, EbpfProfileMemory},
        handler::EbpfAccess,
    },
    ebpf,
    integration_collector::Profile,
    policy::PolicyGetter,
};

const QUEUE_BATCH_SIZE: usize = 1024;

// (profile, mem_addr)
type CachedItem = (metric::Profile, u64);

#[derive(Default)]
struct SortedCache {
    items: Vec<CachedItem>,
}

impl SortedCache {
    unsafe fn enqueue<'a>(
        &mut self,
        config: &EbpfProfile,
        data: &'a ebpf::stack_profile_data,
        policy_getter: Option<&PolicyGetter>,
    ) -> vec::Drain<CachedItem> {
        assert_eq!(data.profiler_type, ebpf::PROFILER_TYPE_MEMORY);

        let idx = self
            .items
            .partition_point(|it| it.0.timestamp <= data.timestamp);
        if data.count == 0 {
            // frees
            self.items.insert(
                idx,
                (
                    metric::Profile {
                        timestamp: data.timestamp,
                        pid: data.pid,
                        ..Default::default()
                    },
                    data.mem_addr,
                ),
            );
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
            if config.preprocess.stack_compression {
                match compress(&stack, 0) {
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
            self.items.insert(idx, (profile, data.mem_addr));
        }
        let dequeue_before = data
            .timestamp
            .saturating_sub(config.memory.sort_interval.as_nanos() as u64);

        // interval limit
        let dequeue_idx = self
            .items
            .partition_point(|it| it.0.timestamp <= dequeue_before);
        // length limit
        let dequeue_idx = dequeue_idx.max(
            self.items
                .len()
                .saturating_sub(config.memory.sort_length as usize),
        );

        self.items.drain(..dequeue_idx)
    }
}

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
        let lru_len = (config.allocated_addresses_lru_len as usize).clamp(
            MemoryContext::ADDRESS_LRU_LEN_MIN,
            MemoryContext::ADDRESS_LRU_LEN_MAX,
        );
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
        let lru_len = (config.allocated_addresses_lru_len as usize).clamp(
            MemoryContext::ADDRESS_LRU_LEN_MIN,
            MemoryContext::ADDRESS_LRU_LEN_MAX,
        );

        // no need to resize
        if lru_len == self.allocated_addrs.cap().get() {
            return;
        }

        // remove entries until len <= lru_len
        while self.allocated_addrs.len() > lru_len {
            // TODO: update lru overflow counter
            let (AddrKey { pid, .. }, AllocInfo { stack_id, size }) =
                self.allocated_addrs.pop_lru().unwrap();
            Self::update_frees(&mut self.in_use, pid, stack_id, size);
        }

        self.allocated_addrs
            .resize(NonZeroUsize::new(lru_len).unwrap());
    }

    pub fn process(&mut self, data: vec::Drain<CachedItem>) {
        for (profile, mem_addr) in data {
            // TODO: update timestamp backtracking counter here
            if profile.wide_count == 0 {
                // frees
                if let Some(AllocInfo { stack_id, size }) = self.allocated_addrs.pop(&AddrKey {
                    pid: profile.pid,
                    mem_addr,
                }) {
                    Self::update_frees(&mut self.in_use, profile.pid, stack_id, size);
                } else {
                    // TODO: update free without alloc counter
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
                        // TODO: update alloc without free counter
                    } else {
                        // LRU full
                        // TODO: update LRU full counter
                    }
                    Self::update_frees(&mut self.in_use, profile.pid, record.stack_id, record.size);
                }
                Self::update_allocs(&mut self.in_use, profile);
            }
        }
    }
}

pub struct MemoryContext {
    config: EbpfAccess,

    process_stime: LruCache<u32, u64>,
    cache: SortedCache,
    processor: Processor,

    last_report: Duration,

    counter: Arc<MemoryCounter>,
}

impl MemoryContext {
    // There's a small difference (less than 1s) between start time from profiler and from procfs rust lib.
    // If cached stime from profiler plus THRESHOLD is smaller than start time from procfs, it's a process restart
    const PROCESS_RESTART_THRESHOLD: Duration = Duration::from_secs(3);

    const ADDRESS_LRU_LEN_MIN: usize = 1024;
    const ADDRESS_LRU_LEN_MAX: usize = 4194704;

    pub fn new(config: EbpfAccess) -> Self {
        let cfg = config.load();
        let counter = Arc::new(MemoryCounter::default());
        Self {
            process_stime: LruCache::new(NonZeroUsize::new(1024).unwrap()),
            cache: Default::default(),
            processor: Processor::new(&cfg.ebpf.profile.memory, counter.clone()),

            last_report: Duration::ZERO,

            counter,

            config,
        }
    }

    pub fn counters(&self) -> Weak<MemoryCounter> {
        Arc::downgrade(&self.counter)
    }

    fn send_with_buffer(
        sender: &mut DebugSender<Profile>,
        buffer: &mut Vec<Profile>,
        item: Profile,
    ) {
        if buffer.len() >= QUEUE_BATCH_SIZE {
            Self::flush_buffer(sender, buffer);
        }
        buffer.push(item);
    }

    fn flush_buffer(sender: &mut DebugSender<Profile>, buffer: &mut Vec<Profile>) {
        if buffer.is_empty() {
            return;
        }
        if let Err(e) = sender.send_all(buffer) {
            warn!("output queue failed to send data: {e}");
            buffer.clear();
        }
    }

    fn process_stime_millis(pid: u32) -> Option<u64> {
        Process::new(pid as i32)
            .and_then(|p| p.stat())
            .and_then(|s| s.starttime())
            .map(|s| s.timestamp_millis() as u64)
            .ok()
    }

    fn report_data(
        &mut self,
        config: &EbpfProfileMemory,
        timestamp: Duration,
        time_diff: i64,
        sender: &mut DebugSender<Profile>,
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
            + time_diff) as u64;

        let mut batch_buffer = Vec::with_capacity(QUEUE_BATCH_SIZE);

        for (_, mut profile) in self.processor.allocs.drain() {
            profile.timestamp = doc_timestamp;
            profile.event_type = metric::ProfileEventType::EbpfMemAlloc.into();
            profile.count = profile.wide_count as u32;
            Self::send_with_buffer(sender, &mut batch_buffer, Profile(profile));
        }

        // TODO: fix capacity
        let mut process_addrs_and_stime = HashMap::with_capacity(16384);
        let mut dead_pids = HashSet::with_capacity(16384);
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
                Self::send_with_buffer(sender, &mut batch_buffer, Profile(p));
                true
            });

        if !dead_pids.is_empty() {
            self.cache
                .items
                .retain(|(profile, _)| !dead_pids.contains(&profile.pid));
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

        Self::flush_buffer(sender, &mut batch_buffer);
    }

    pub unsafe fn process(
        &mut self,
        data: &ebpf::stack_profile_data,
        time_diff: i64,
        policy_getter: Option<&PolicyGetter>,
        sender: &mut DebugSender<Profile>,
    ) {
        let config = self.config.load();

        let items = self
            .cache
            .enqueue(&config.ebpf.profile, data, policy_getter);

        self.processor.update_config(&config.ebpf.profile.memory);
        self.processor.process(items);

        self.report_data(
            &config.ebpf.profile.memory,
            Duration::from_nanos(data.timestamp),
            time_diff,
            sender,
        );
    }
}

#[derive(Debug, Default)]
pub struct MemoryCounter {
    process_count: AtomicU64,

    address_count_max: AtomicU64,
    address_count_sum: AtomicU64,

    in_use_max: AtomicU64,
    in_use_sum: AtomicU64,

    purged_address_max: AtomicU64,
    purged_address_sum: AtomicU64,
    purged_alloc_max: AtomicU64,
    purged_alloc_sum: AtomicU64,
}

impl RefCountable for MemoryCounter {
    fn get_counters(&self) -> Vec<Counter> {
        vec![
            (
                "process_count",
                CounterType::Gauged,
                CounterValue::Unsigned(self.process_count.load(Ordering::Relaxed)),
            ),
            (
                "address_count_max",
                CounterType::Gauged,
                CounterValue::Unsigned(self.address_count_max.load(Ordering::Relaxed)),
            ),
            (
                "address_count_sum",
                CounterType::Gauged,
                CounterValue::Unsigned(self.address_count_sum.load(Ordering::Relaxed)),
            ),
            (
                "in_use_max",
                CounterType::Gauged,
                CounterValue::Unsigned(self.in_use_max.load(Ordering::Relaxed)),
            ),
            (
                "in_use_sum",
                CounterType::Gauged,
                CounterValue::Unsigned(self.in_use_sum.load(Ordering::Relaxed)),
            ),
            (
                "purged_address_max",
                CounterType::Counted,
                CounterValue::Unsigned(self.purged_address_max.swap(0, Ordering::Relaxed)),
            ),
            (
                "purged_address_sum",
                CounterType::Counted,
                CounterValue::Unsigned(self.purged_address_sum.swap(0, Ordering::Relaxed)),
            ),
            (
                "purged_alloc_max",
                CounterType::Counted,
                CounterValue::Unsigned(self.purged_alloc_max.swap(0, Ordering::Relaxed)),
            ),
            (
                "purged_alloc_sum",
                CounterType::Counted,
                CounterValue::Unsigned(self.purged_alloc_sum.swap(0, Ordering::Relaxed)),
            ),
        ]
    }
}
