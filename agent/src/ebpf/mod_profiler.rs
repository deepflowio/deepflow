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

extern crate libc;

pub use libc::c_char;
pub use libc::c_int;
pub use libc::c_uchar; // u8
pub use libc::c_uint;  // u32
pub use libc::c_ulonglong;
pub use std::ffi::{CStr, CString};
//use std::fmt;

// process_kname is up to 16 bytes, if the length of process_kname exceeds 15, the ending char is '\0'
pub const PACKET_KNAME_MAX_PADDING: usize = 15;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct stack_profile_data {
    pub timestamp: u64, // Timestamp of the stack trace data(unit: nanoseconds).
    pub pid: u32,       // User-space process-ID.
    /*
     * Identified within the eBPF program in kernel space.
     * If the current is a process and not a thread this field(tid) is filled
     * with the ID of the process.
     */
    pub tid: u32,
    pub stime: u64,      // The start time of the process is measured in milliseconds.
    pub u_stack_id: u32, // User space stackID.
    pub k_stack_id: u32, // Kernel space stackID.
    pub cpu: u32,        // The captured stack trace data is generated on which CPU?
    /*
     * The profiler captures the number of occurrences of the same
     * data by querying with the quadruple
     * "<pid + stime + u_stack_id + k_stack_id + tid + cpu>" as the key.
     */
    pub count: u32,
    /*
     * comm in task_struct(linux kernel), always 16 bytes
     * If the capture is a process, fill in the process name here.
     * If the capture is a thread, fill in the thread name.
     */
    pub comm: [u8; PACKET_KNAME_MAX_PADDING + 1],
    pub process_name: [u8; PACKET_KNAME_MAX_PADDING + 1], // process name
    pub stack_data_len: u32,                              // stack data length
    
    /*
     * Example of a folded stack trace string (taken from a perf profiler test):
     * main;xxx();yyy()
     * It is a list of symbols corresponding to addresses in the underlying stack trace,
     * separated by ';'.
     *
     * The merged folded stack trace string style for user space and kernel space would be:
     * <user space folded stack trace string> + ";" + <kernel space folded stack trace string>
     */
    pub stack_data: *mut c_char,
}

extern "C" {
    #[cfg(target_arch = "x86_64")]
    pub fn bpf_tracer_init(log_file: *const i8, is_stdout: bool) -> c_int;
    #[cfg(target_arch = "aarch64")]
    pub fn bpf_tracer_init(log_file: *const u8, is_stdout: bool) -> c_int;
    pub fn bpf_tracer_finish();

    /*
     * start continuous profiler
     * @freq sample frequency, Hertz. (e.g. 99 profile stack traces at 99 Hertz)
     * @callback Profile data processing callback interface
     * @returns 0 on success, < 0 on error
     */
    pub fn start_continuous_profiler(
        freq: c_int,
        callback: extern "C" fn(_data: *mut stack_profile_data),
    ) -> c_int;

    /*
     * stop continuous profiler
     * @returns 0 on success, < 0 on error
     */
    pub fn stop_continuous_profiler()-> c_int;

    /*
     * test flame graph
     */
    pub fn process_stack_trace_data_for_flame_graph(_data: *mut stack_profile_data);
    pub fn release_flame_graph_hash();

    /*
     * To set the regex matching for the profiler.
     *
     * Perform regular expression matching on process names.
     * Processes that successfully match the regular expression are
     * aggregated using the key:
     *     `{pid + stime + u_stack_id + k_stack_id + tid + cpu}`.
     *
     * For processes that do not match, they are aggregated using the
     * key:
     *     `<process name + u_stack_id + k_stack_id + cpu>`.
     *
     * The profiler startup will be set to ".*" by default.
     *
     * @pattern : Regular expression pattern. e.g. "^(java|nginx|.*ser.*)$"
     * @returns 0 on success, < 0 on error
     */
    pub fn set_profiler_regex(pattern: *const c_char) -> c_int;

    /*
     * This interface is used to set whether CPUID should be included in the
     * aggregation of stack trace data.
     *
     * @flag:
     *   If the flag is set to 1, CPUID will be included in the aggregation
     *   of stack trace data. If the flag is set to 0, it will not be incl-
     *   uded in the aggregation. Any other value is considered invalid.
     *
     * The profiler startup will be set to 0 by default.
     * 
     * @returns 0 on success, < 0 on error
     *
     * Note:
     *   If flag=0, the CPU value for stack trace data reporting is a special
     *   value (CPU_INVALID:0xfff) used to indicate that it is an invalid value.
     */
    pub fn set_profiler_cpu_aggregation(flag: c_int) -> c_int;
}
