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

//use chrono::prelude::DateTime;
use chrono::FixedOffset;
use chrono::Utc;
use perf_profiler::ebpf::*;
use std::convert::TryInto;
use std::fmt::Write;
//use std::net::IpAddr;
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

extern "C" fn continuous_profiler_callback(_data: *mut stack_profile_data) {
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
