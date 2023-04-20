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
pub use libc::c_uint; // u32
pub use libc::c_ulonglong;
pub use std::ffi::{CStr, CString};
use std::fmt;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct stack_profile_data {
    pub data_bytes: u32,
    pub sample_count: u32,
    pub data: *mut c_char,
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
 * @report_period How often is the data reported.
 * @callback Profile data processing callback interface
 * @returns 0 on success, < 0 on error
 */
pub fn start_continuous_profiler(
        freq: c_int,
        report_period: c_int,
        callback: extern "C" fn(_data: *mut stack_profile_data),
) -> c_int;

/*
 * stop continuous profiler
 * @returns 0 on success, < 0 on error
 */
pub fn stop_continuous_profiler()-> c_int;

}
