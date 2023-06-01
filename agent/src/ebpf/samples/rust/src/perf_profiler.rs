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

use chrono::prelude::DateTime;
use chrono::FixedOffset;
use chrono::Utc;
use perf_profiler::ebpf::*;
use std::convert::TryInto;
use std::fmt::Write;
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

fn date_time(ts: u64) -> String {
    // Creates a new SystemTime from the specified number of whole seconds
    let d = UNIX_EPOCH + Duration::from_micros(ts);
    // Create DateTime from SystemTime
    let time = DateTime::<Utc>::from(d);
    let china_timezone = FixedOffset::east(8 * 3600);
    // Formats the combined date and time with the specified format string.
    time.with_timezone(&china_timezone)
        .format("%Y-%m-%d %H:%M:%S.%6f")
        .to_string()
}

fn sk_str_safe(data: *mut c_char) -> String {
    unsafe { CStr::from_ptr(data).to_string_lossy().into_owned() }
}

fn sk_data_str_safe(sd: *mut stack_profile_data) -> String {
    unsafe { sk_str_safe((*sd).stack_data) }
}

fn cp_process_name_safe(cp: *mut stack_profile_data) -> String {
    unsafe {
        let v = &(*cp).comm;
        String::from_utf8_lossy(v).to_string()
    }
}

extern "C" fn continuous_profiler_callback(cp: *mut stack_profile_data) {
    unsafe {
          let data = sk_data_str_safe(cp);
          println!("{} PID {} START-TIME {} U-STACKID {} K-STACKID {} COMM {} CPU {} COUNT {} LEN {} \n  - {}\n",
                   date_time((*cp).timestamp),
                   (*cp).pid,
                   (*cp).stime,
                   (*cp).u_stack_id,
                   (*cp).k_stack_id,
                   cp_process_name_safe(cp),
                   (*cp).cpu,
                   (*cp).count,
                   (*cp).stack_data_len, data);
    }
}

fn main() {
    let log_file = CString::new("/var/log/deepflow-ebpf.log".as_bytes()).unwrap();
    let log_file_c = log_file.as_c_str();
    unsafe {
        // The first parameter passed by a null pointer can be
        // filled with std::ptr::null()
        if bpf_tracer_init(log_file_c.as_ptr(), true) != 0 {
            println!("bpf_tracer_init() file:{:?} error", log_file);
            ::std::process::exit(1);
        }

        if start_continuous_profiler(
            99,
            30,
            continuous_profiler_callback,
        ) != 0
        {
            println!("start_continuous_profiler() error.");
            ::std::process::exit(1);
        }

        
        bpf_tracer_finish();

        print!("test OK\n");
        thread::sleep(Duration::from_secs(20));
        stop_continuous_profiler();
    }

    loop {
        thread::sleep(Duration::from_secs(5));
    }
}
