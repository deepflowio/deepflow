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
    collections::{HashMap, HashSet},
    ffi::CStr,
    num::NonZeroUsize,
    slice,
    sync::{
        atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering},
        Arc, Weak,
    },
    time::Duration,
};

use log::{debug, trace, warn};
use lru::LruCache;
use procfs::process::Process;
use zstd::bulk::compress;

use public::{
    counter::{Counter, CounterType, CounterValue, RefCountable},
    proto::metric,
    queue::DebugSender,
};

use super::{string_from_null_terminated_c_str, POLICY_GETTER};

use crate::ebpf;
use crate::integration_collector::Profile;

const QUEUE_BATCH_SIZE: usize = 1024;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct AllocInfo {
    stack_id: u32,
    size: u64,
}

const ALLOC_INFO_QUEUE_SIZE: usize = 4;

#[derive(Debug, Default)]
struct AllocInfoQueue {
    info: [AllocInfo; ALLOC_INFO_QUEUE_SIZE],
    head: usize,
    len: usize,
}

impl AllocInfoQueue {
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn len(&self) -> usize {
        self.len
    }

    fn pop(&mut self) -> Option<AllocInfo> {
        if self.is_empty() {
            return None;
        }
        let info = self.info[self.head];
        self.head = (self.head + 1) % ALLOC_INFO_QUEUE_SIZE;
        self.len -= 1;
        Some(info)
    }

    fn push(&mut self, info: AllocInfo) -> Option<AllocInfo> {
        let tail = (self.head + self.len) % ALLOC_INFO_QUEUE_SIZE;
        let ret = if self.len == ALLOC_INFO_QUEUE_SIZE {
            let r = self.info[self.head];
            self.head = (self.head + 1) % ALLOC_INFO_QUEUE_SIZE;
            Some(r)
        } else {
            self.len += 1;
            None
        };
        self.info[tail] = info;
        ret
    }

    fn iter(&self) -> AllocInfoQueueIter {
        AllocInfoQueueIter {
            queue: self,
            pos: 0,
        }
    }
}

struct AllocInfoQueueIter<'a> {
    queue: &'a AllocInfoQueue,
    pos: usize,
}

impl<'a> Iterator for AllocInfoQueueIter<'a> {
    type Item = &'a AllocInfo;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.queue.len {
            None
        } else {
            let index = (self.queue.head + self.pos) % ALLOC_INFO_QUEUE_SIZE;
            self.pos += 1;
            Some(&self.queue.info[index])
        }
    }
}

#[derive(Debug, Default)]
struct AddressRecord {
    allocs: AllocInfoQueue,
    frees: usize,
}

#[derive(Debug)]
struct ProcessAllocInfo {
    allocated_addrs: LruCache<u64, AddressRecord>,

    alloc: HashMap<u32, metric::Profile>, // allocs between report interval
    in_use: HashMap<u32, metric::Profile>,

    stime: u64,

    purged_address: u64,
    purged_alloc: u64,
}

impl ProcessAllocInfo {
    pub fn new(lru_len: NonZeroUsize, stime: u64) -> Self {
        Self {
            allocated_addrs: LruCache::new(lru_len),
            alloc: Default::default(),
            in_use: Default::default(),
            stime,
            purged_address: 0,
            purged_alloc: 0,
        }
    }

    unsafe fn update_stack(
        stacks: &mut HashMap<u32, metric::Profile>,
        data: &ebpf::stack_profile_data,
        update_trace_str: bool,
    ) {
        let entry = stacks.entry(data.u_stack_id).or_insert_with(|| {
            let mut profile = metric::Profile::default();
            profile.sample_rate = 1; // reported every second
            profile.stime = data.stime;
            profile.pid = data.pid;
            profile.tid = data.tid;
            profile.thread_name = string_from_null_terminated_c_str(data.comm.as_ptr());
            profile.process_name = string_from_null_terminated_c_str(data.process_name.as_ptr());
            profile.u_stack_id = data.u_stack_id;
            profile.cpu = data.cpu;
            profile.wide_count = 0;
            let profile_data =
                slice::from_raw_parts(data.stack_data as *mut u8, data.stack_data_len as usize);
            profile.data = profile_data.to_vec();

            let container_id =
                CStr::from_ptr(data.container_id.as_ptr() as *const libc::c_char).to_string_lossy();
            if let Some(policy_getter) = POLICY_GETTER.as_ref() {
                profile.pod_id = policy_getter.lookup_pod_id(&container_id);
            }
            profile
        });
        entry.wide_count += data.count;
        if update_trace_str {
            let trace_str =
                slice::from_raw_parts(data.stack_data as *mut u8, data.stack_data_len as usize);
            if trace_str != &entry.data {
                entry.data = trace_str.to_vec();
            }
        }
    }

    unsafe fn update(&mut self, data: &ebpf::stack_profile_data) {
        // Memory allocations and frees may come in any order in a multi-core envrionment.
        // Make best effort to handle such situation.
        if data.count == 0 {
            // frees
            if let Some(info) = self.allocated_addrs.get_mut(&data.mem_addr) {
                if let Some(allocated) = info.allocs.pop() {
                    if let Some(p) = self.in_use.get_mut(&allocated.stack_id) {
                        if p.wide_count > allocated.size as u64 {
                            p.wide_count -= allocated.size as u64;
                        } else {
                            self.in_use.remove(&allocated.stack_id);
                        }
                    }
                    if info.allocs.is_empty() {
                        assert_eq!(info.frees, 0);
                        self.allocated_addrs.pop(&data.mem_addr);
                    }
                } else {
                    // out of order free without corresponding alloc, add free count
                    info.frees += 1;
                }
            } else {
                let old = self.allocated_addrs.push(
                    data.mem_addr,
                    AddressRecord {
                        allocs: Default::default(),
                        frees: 1,
                    },
                );
                // remove allocs record from in_use if the address is purged from lru
                if let Some((_, record)) = old {
                    self.purged_address += 1;
                    self.purged_alloc += record.allocs.len() as u64;
                }
            }
        } else {
            // allocs
            Self::update_stack(&mut self.alloc, data, false);
            // for languages without free (i.e. JAVA), not recording in_use info, only allocs
            if data.mem_addr == 0 {
                return;
            }

            if let Some(info) = self.allocated_addrs.get_mut(&data.mem_addr) {
                if info.frees != 0 {
                    // recorded free before any allocs, decrease free count
                    info.frees -= 1;
                    if info.frees == 0 {
                        assert!(info.allocs.is_empty());
                        self.allocated_addrs.pop(&data.mem_addr);
                    }
                } else {
                    // multiple allocs without frees
                    // unordered allocations will make in_use value inaccurate, but there's no easy fix at the moment
                    let old_info = info.allocs.push(AllocInfo {
                        stack_id: data.u_stack_id,
                        size: data.count,
                    });
                    if old_info.is_some() {
                        self.purged_alloc += 1;
                    }
                    Self::update_stack(&mut self.in_use, data, true);
                }
            } else {
                let old = self.allocated_addrs.push(data.mem_addr, {
                    let mut allocs = AllocInfoQueue::default();
                    allocs.push(AllocInfo {
                        stack_id: data.u_stack_id,
                        size: data.count,
                    });
                    AddressRecord {
                        allocs,
                        ..Default::default()
                    }
                });
                // remove allocs record from in_use if the address is purged from lru
                if let Some((_, record)) = old {
                    self.purged_address += 1;
                    self.purged_alloc += record.allocs.len() as u64;
                }
                Self::update_stack(&mut self.in_use, data, true);
            }
        }
    }
}

pub struct MemoryContext {
    processes: HashMap<u32, ProcessAllocInfo>,

    last_report: Duration,
    stack_compression: bool,

    report_interval_secs: Arc<AtomicU8>,
    address_lru_len: NonZeroUsize,
    updated_address_lru_len: Arc<AtomicU32>,

    memory_counter: Arc<MemoryCounter>,
}

impl MemoryContext {
    // There's a small difference (less than 1s) between start time from profiler and from procfs rust lib.
    // If cached stime from profiler plus THRESHOLD is smaller than start time from procfs, it's a process restart
    const PROCESS_RESTART_THRESHOLD: Duration = Duration::from_secs(3);

    pub fn new(report_interval: Duration, address_lru_len: u32, stack_compression: bool) -> Self {
        if address_lru_len == 0 {
            warn!("lru cannot have length 0, use 1 instead");
        }
        let address_lru_len = address_lru_len.max(1);
        Self {
            processes: Default::default(),
            report_interval_secs: Arc::new(AtomicU8::new(report_interval.as_secs() as u8)),
            address_lru_len: NonZeroUsize::new(address_lru_len as usize).unwrap(),
            updated_address_lru_len: Arc::new(AtomicU32::new(address_lru_len)),
            last_report: Default::default(),
            stack_compression: stack_compression,
            memory_counter: Arc::new(MemoryCounter::default()),
        }
    }

    pub fn counters(&self) -> Weak<MemoryCounter> {
        Arc::downgrade(&self.memory_counter)
    }

    pub fn settings(&self) -> MemoryContextSettings {
        MemoryContextSettings {
            report_interval_secs: self.report_interval_secs.clone(),
            address_lru_len: self.updated_address_lru_len.clone(),
        }
    }

    pub unsafe fn update(&mut self, data: &ebpf::stack_profile_data) {
        assert_eq!(data.profiler_type, ebpf::PROFILER_TYPE_MEMORY);
        // LRU length change will clear all records
        let len = self.updated_address_lru_len.load(Ordering::Relaxed) as usize;
        if len != self.address_lru_len.get() {
            self.processes.clear();
            self.address_lru_len = NonZeroUsize::new(len).unwrap();
        }
        self.processes
            .entry(data.pid)
            .or_insert_with(|| ProcessAllocInfo::new(self.address_lru_len, data.stime))
            .update(data);
    }

    fn collect_counters(&mut self) {
        let mut address_count_max = 0;
        let mut address_count_sum = 0;
        let mut in_use_max = 0;
        let mut in_use_sum = 0;
        let mut purged_address_max = 0;
        let mut purged_address_sum = 0;
        let mut purged_alloc_max = 0;
        let mut purged_alloc_sum = 0;
        for (_, info) in self.processes.iter_mut() {
            let address_count = info.allocated_addrs.len() as u64;
            address_count_max = address_count_max.max(address_count);
            address_count_sum += address_count;

            let in_use_count = info.in_use.len() as u64;
            in_use_max = in_use_max.max(in_use_count);
            in_use_sum += in_use_count;

            let purged_address_count = info.purged_address;
            purged_address_max = purged_address_max.max(purged_address_count);
            purged_address_sum += purged_address_count;
            info.purged_address = 0;

            let purged_alloc_count = info.purged_alloc;
            purged_alloc_max = purged_alloc_max.max(purged_alloc_count);
            purged_alloc_sum += purged_alloc_count;
            info.purged_alloc = 0;
        }

        let counter = &self.memory_counter;
        counter
            .process_count
            .store(self.processes.len() as u64, Ordering::Relaxed);
        counter
            .address_count_max
            .store(address_count_max, Ordering::Relaxed);
        counter
            .address_count_sum
            .store(address_count_sum, Ordering::Relaxed);
        counter.in_use_max.store(in_use_max, Ordering::Relaxed);
        counter.in_use_sum.store(in_use_sum, Ordering::Relaxed);
        counter
            .purged_address_max
            .store(purged_address_max, Ordering::Relaxed);
        counter
            .purged_address_sum
            .store(purged_address_sum, Ordering::Relaxed);
        counter
            .purged_alloc_max
            .store(purged_alloc_max, Ordering::Relaxed);
        counter
            .purged_alloc_sum
            .store(purged_alloc_sum, Ordering::Relaxed);
    }

    pub fn report(&mut self, timestamp: Duration, sender: &mut DebugSender<Profile>) {
        if self.last_report.is_zero() {
            self.last_report = timestamp;
            return;
        }
        let report_interval =
            Duration::from_secs(self.report_interval_secs.load(Ordering::Relaxed) as u64);
        if timestamp < self.last_report + report_interval {
            return;
        }
        self.last_report = timestamp;

        self.collect_counters();

        let mut batch = Vec::with_capacity(QUEUE_BATCH_SIZE);
        let mut dead_pids = vec![];

        'outer: for (pid, info) in self.processes.iter_mut() {
            let process_info = match Process::new(*pid as i32) {
                Ok(p) => p,
                Err(e) => {
                    trace!("process #{pid} likely exited: {e}");
                    dead_pids.push(*pid);
                    continue;
                }
            };
            let stime = match process_info.stat().and_then(|s| s.starttime()) {
                Ok(s) => s.timestamp_millis() as u64,
                Err(e) => {
                    debug!("process #{pid} get start time failed: {e}");
                    dead_pids.push(*pid);
                    continue;
                }
            } - Self::PROCESS_RESTART_THRESHOLD.as_millis() as u64;

            if info.stime < stime {
                trace!("process #{pid} restarted");
                dead_pids.push(*pid);
                continue;
            }

            // clean up alloc map every report
            for (_, mut p) in info.alloc.drain() {
                if batch.len() >= QUEUE_BATCH_SIZE {
                    if let Err(e) = sender.send_all(&mut batch) {
                        warn!("output queue failed to send data: {e}");
                        batch.clear();
                        break 'outer;
                    }
                }
                p.event_type = metric::ProfileEventType::EbpfMemAlloc.into();
                p.timestamp = (timestamp - report_interval).as_nanos() as u64;
                p.count = p.wide_count as u32;
                if self.stack_compression {
                    match compress(&p.data, 0) {
                        Ok(compressed_data) => {
                            p.data_compressed = true;
                            p.data = compressed_data;
                        }
                        Err(e) => {
                            debug!("failed to compress ebpf memory profile: {:?}", e);
                        }
                    }
                }
                batch.push(Profile(p));
            }

            // keep in_use map but remove inconsistent records
            let mut alive = HashSet::new();
            for (_, r) in info.allocated_addrs.iter() {
                for alloc in r.allocs.iter() {
                    alive.insert(alloc.stack_id);
                }
            }
            info.in_use.retain(|stack_id, _| alive.contains(stack_id));

            for rp in info.in_use.values() {
                if batch.len() >= QUEUE_BATCH_SIZE {
                    if let Err(e) = sender.send_all(&mut batch) {
                        warn!("output queue failed to send data: {e}");
                        batch.clear();
                        break 'outer;
                    }
                }
                let mut p = rp.clone();
                p.event_type = metric::ProfileEventType::EbpfMemInUse.into();
                p.timestamp = (timestamp - report_interval).as_nanos() as u64;
                p.count = p.wide_count as u32;
                if self.stack_compression {
                    match compress(&p.data, 0) {
                        Ok(compressed_data) => {
                            p.data_compressed = true;
                            p.data = compressed_data;
                        }
                        Err(e) => {
                            debug!("failed to compress ebpf memory profile: {:?}", e);
                        }
                    }
                }
                batch.push(Profile(p));
            }
        }

        if !batch.is_empty() {
            if let Err(e) = sender.send_all(&mut batch) {
                warn!("output queue failed to send data: {e}");
                batch.clear();
            }
        }

        for pid in dead_pids {
            self.processes.remove(&pid);
        }
    }
}

pub struct MemoryContextSettings {
    report_interval_secs: Arc<AtomicU8>,
    address_lru_len: Arc<AtomicU32>,
}

impl MemoryContextSettings {
    pub fn set_report_interval(&self, interval: Duration) {
        self.report_interval_secs
            .store(interval.as_secs() as u8, Ordering::Relaxed);
    }

    pub fn set_address_lru_len(&self, len: u32) {
        // length == 0 will effectively set address_lru_len to 1
        // so if it is already 1, do not print this warning
        if len == 0 && self.address_lru_len.load(Ordering::Relaxed) != 1 {
            warn!("lru cannot have length 0, use 1 instead");
            return;
        }
        self.address_lru_len.store(len, Ordering::Relaxed);
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ebpf;

    struct AllocData {
        stack_id: u32,
        addr: u64,
        size: u64,
    }

    impl ProcessAllocInfo {
        fn update_alloc_data(&mut self, data: AllocData) {
            let mut buf = [0u8; 0];
            unsafe {
                self.update(&ebpf::stack_profile_data {
                    u_stack_id: data.stack_id,
                    mem_addr: data.addr,
                    count: data.size,

                    profiler_type: 0,
                    timestamp: 0,
                    pid: 0,
                    tid: 0,
                    stime: 0,
                    netns_id: 0,
                    k_stack_id: 0,
                    cpu: 0,
                    comm: [0; ebpf::PACKET_KNAME_MAX_PADDING + 1],
                    process_name: [0; ebpf::PACKET_KNAME_MAX_PADDING + 1],
                    container_id: [0; ebpf::CONTAINER_ID_SIZE],
                    stack_data_len: 0,
                    stack_data: buf.as_mut_ptr() as *mut libc::c_char,
                });
            }
        }
    }

    impl AllocInfoQueue {
        fn get(&self, index: usize) -> Option<&AllocInfo> {
            if index >= self.len {
                return None;
            }
            let index = (self.head + index) % ALLOC_INFO_QUEUE_SIZE;
            Some(&self.info[index])
        }
    }

    #[test]
    fn normal_alloc_free() {
        let mut info = ProcessAllocInfo::new(NonZeroUsize::new(10).unwrap(), 0);
        info.update_alloc_data(AllocData {
            stack_id: 0x1234,
            addr: 0xdead,
            size: 0xc0de,
        });
        info.update_alloc_data(AllocData {
            stack_id: 0x1234,
            addr: 0xbeef,
            size: 0xc0de,
        });

        assert_eq!(
            info.allocated_addrs
                .get(&0xdead)
                .and_then(|r| r.allocs.get(0))
                .unwrap(),
            &AllocInfo {
                stack_id: 0x1234,
                size: 0xc0de
            }
        );
        assert_eq!(info.in_use.get(&0x1234).unwrap().wide_count, 2 * 0xc0de);

        info.update_alloc_data(AllocData {
            stack_id: 0x1234,
            addr: 0xdead,
            size: 0,
        });

        assert!(info.allocated_addrs.get(&0xdead).is_none());
        assert_eq!(info.in_use.get(&0x1234).unwrap().wide_count, 0xc0de);

        info.update_alloc_data(AllocData {
            stack_id: 0x4321,
            addr: 0xbeef,
            size: 0,
        });

        assert!(info.allocated_addrs.get(&0xbeef).is_none());
        assert_eq!(info.in_use.get(&0x1234), None);
    }

    #[test]
    fn unordered_alloc_free() {
        let mut info = ProcessAllocInfo::new(NonZeroUsize::new(10).unwrap(), 0);
        info.update_alloc_data(AllocData {
            stack_id: 0x1234,
            addr: 0xdeadbeef,
            size: 0xc0de,
        });
        // alloc at same address
        info.update_alloc_data(AllocData {
            stack_id: 0x1234,
            addr: 0xdeadbeef,
            size: 0xc0dec0de,
        });

        assert_eq!(
            info.allocated_addrs
                .get(&0xdeadbeef)
                .and_then(|r| r.allocs.get(0))
                .unwrap(),
            &AllocInfo {
                stack_id: 0x1234,
                size: 0xc0de
            }
        );
        assert_eq!(
            info.allocated_addrs
                .get(&0xdeadbeef)
                .and_then(|r| r.allocs.get(1))
                .unwrap(),
            &AllocInfo {
                stack_id: 0x1234,
                size: 0xc0dec0de
            }
        );
        assert_eq!(
            info.in_use.get(&0x1234).unwrap().wide_count,
            0xc0de + 0xc0dec0de
        );

        info.update_alloc_data(AllocData {
            stack_id: 0x1234,
            addr: 0xdeadbeef,
            size: 0,
        });

        assert_eq!(
            info.allocated_addrs
                .get(&0xdeadbeef)
                .and_then(|r| r.allocs.get(0))
                .unwrap(),
            &AllocInfo {
                stack_id: 0x1234,
                size: 0xc0dec0de
            }
        );
        assert_eq!(info.in_use.get(&0x1234).unwrap().wide_count, 0xc0dec0de);

        info.update_alloc_data(AllocData {
            stack_id: 0x1234,
            addr: 0xdeadbeef,
            size: 0,
        });
        // one more free
        info.update_alloc_data(AllocData {
            stack_id: 0x1234,
            addr: 0xdeadbeef,
            size: 0,
        });

        assert!(info
            .allocated_addrs
            .get(&0xdeadbeef)
            .unwrap()
            .allocs
            .is_empty());
        assert_eq!(info.allocated_addrs.get(&0xdeadbeef).unwrap().frees, 1);
        assert_eq!(info.in_use.get(&0x1234), None);

        info.update_alloc_data(AllocData {
            stack_id: 0x1234,
            addr: 0xdeadbeef,
            size: 0xc0dec0de,
        });

        assert!(info.allocated_addrs.get(&0xdeadbeef).is_none());
        assert_eq!(info.in_use.get(&0x1234), None);
    }

    #[test]
    fn alloc_info_queue() {
        let mut queue = AllocInfoQueue::default();
        assert!(queue.is_empty());
        assert_eq!(queue.pop(), None);

        // Test pushing elements
        let info1 = AllocInfo {
            stack_id: 1,
            size: 100,
        };
        assert_eq!(queue.push(info1), None);
        assert_eq!(queue.len, 1);

        let info2 = AllocInfo {
            stack_id: 2,
            size: 200,
        };
        assert_eq!(queue.push(info2), None);
        assert_eq!(queue.len, 2);

        // Test popping elements
        assert_eq!(queue.pop(), Some(info1));
        assert_eq!(queue.len, 1);
        assert_eq!(queue.pop(), Some(info2));
        assert_eq!(queue.len, 0);
        assert!(queue.is_empty());

        // Test queue overflow
        for i in 0..ALLOC_INFO_QUEUE_SIZE {
            queue.push(AllocInfo {
                stack_id: 100 + i as u32,
                size: 1000 + i as u64,
            });
        }

        // Next push should return oldest element
        let overflow = queue.push(AllocInfo {
            stack_id: 100,
            size: 1000,
        });
        assert_eq!(
            overflow,
            Some(AllocInfo {
                stack_id: 100,
                size: 1000
            })
        );
    }

    #[test]
    fn alloc_info_queue_iter() {
        let mut queue = AllocInfoQueue::default();

        // Push some elements
        for i in 0..3 {
            queue.push(AllocInfo {
                stack_id: i,
                size: i as u64 * 100,
            });
        }

        // Test iterator
        let mut iter = queue.iter();
        assert_eq!(
            iter.next(),
            Some(&AllocInfo {
                stack_id: 0,
                size: 0
            })
        );
        assert_eq!(
            iter.next(),
            Some(&AllocInfo {
                stack_id: 1,
                size: 100
            })
        );
        assert_eq!(
            iter.next(),
            Some(&AllocInfo {
                stack_id: 2,
                size: 200
            })
        );
        assert_eq!(iter.next(), None);

        // Test iterator after wrapping around
        queue.pop();
        queue.push(AllocInfo {
            stack_id: 3,
            size: 300,
        });
        queue.push(AllocInfo {
            stack_id: 4,
            size: 400,
        });
        queue.push(AllocInfo {
            stack_id: 5,
            size: 500,
        });

        let collected: Vec<_> = queue.iter().collect();
        assert_eq!(
            collected,
            vec![
                &AllocInfo {
                    stack_id: 2,
                    size: 200
                },
                &AllocInfo {
                    stack_id: 3,
                    size: 300
                },
                &AllocInfo {
                    stack_id: 4,
                    size: 400
                },
                &AllocInfo {
                    stack_id: 5,
                    size: 500
                }
            ]
        );
    }
}
