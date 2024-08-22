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

use std::{collections::HashMap, ffi::CStr, slice, time::Duration};

use log::{debug, trace, warn};
use procfs::process::Process;

use public::{proto::metric, queue::DebugSender};

use super::{string_from_null_terminated_c_str, POLICY_GETTER};

use crate::ebpf;
use crate::integration_collector::Profile;

const QUEUE_BATCH_SIZE: usize = 1024;

#[derive(Debug, Default)]
struct AllocInfo {
    stack_id: u32,
    size: u64,
}

#[derive(Debug, Default)]
struct ProcessAllocInfo {
    allocated_addrs: HashMap<u64, AllocInfo>, // map of allocated address and stack id

    alloc: HashMap<u32, metric::Profile>, // allocs between report interval
    in_use: HashMap<u32, metric::Profile>,
}

impl ProcessAllocInfo {
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
            profile.wide_count = data.count;
            profile.data =
                slice::from_raw_parts(data.stack_data as *mut u8, data.stack_data_len as usize)
                    .to_vec();
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
        if data.count == 0 {
            // frees
            if let Some(info) = self.allocated_addrs.remove(&data.mem_addr) {
                if let Some(p) = self.in_use.get_mut(&info.stack_id) {
                    if p.wide_count > info.size as u64 {
                        p.wide_count -= info.size as u64;
                    } else {
                        self.in_use.remove(&info.stack_id);
                    }
                }
            } else {
                debug!("allocated addr {} not found, ignored", data.mem_addr);
            }
        } else {
            // allocs
            if self.allocated_addrs.get(&data.mem_addr).is_some() {
                debug!("allocated addr {} already exists, ignored", data.mem_addr);
                return;
            }
            // for languages without free (i.e. JAVA), not recording in_use info, only allocs
            if data.mem_addr != 0 {
                self.allocated_addrs.insert(
                    data.mem_addr,
                    AllocInfo {
                        stack_id: data.u_stack_id,
                        size: data.count,
                    },
                );
                Self::update_stack(&mut self.in_use, data, true);
            }
            Self::update_stack(&mut self.alloc, data, false);
        }
    }
}

#[derive(Default)]
pub struct MemoryContext {
    processes: HashMap<u32, ProcessAllocInfo>,

    last_report: Duration,
}

impl MemoryContext {
    const REPORT_INTERVAL: Duration = Duration::from_secs(1);

    // There's a small difference (less than 1s) between start time from profiler and from procfs rust lib.
    // If cached stime from profiler plus THRESHOLD is smaller than start time from procfs, it's a process restart
    const PROCESS_RESTART_THRESHOLD: Duration = Duration::from_secs(3);

    pub unsafe fn update(&mut self, data: &ebpf::stack_profile_data) {
        assert_eq!(data.profiler_type, ebpf::PROFILER_TYPE_MEMORY);
        self.processes
            .entry(data.pid)
            .or_insert(Default::default())
            .update(data);
    }

    pub fn report(&mut self, timestamp: Duration, sender: &mut DebugSender<Profile>) {
        if self.last_report.is_zero() {
            self.last_report = timestamp;
            return;
        }
        if timestamp < self.last_report + Self::REPORT_INTERVAL {
            return;
        }
        self.last_report = timestamp;

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

            let exited = info.alloc.values().any(|p| p.stime < stime)
                || info.in_use.values().any(|p| p.stime < stime);
            if exited {
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
                p.timestamp = (timestamp - Self::REPORT_INTERVAL).as_millis() as u64;
                p.count = p.wide_count as u32;
                batch.push(Profile(p));
            }

            // keep in_use map
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
                p.timestamp = (timestamp - Self::REPORT_INTERVAL).as_millis() as u64;
                p.count = p.wide_count as u32;
                batch.push(Profile(p));
            }
        }

        for pid in dead_pids {
            self.processes.remove(&pid);
        }
    }
}
