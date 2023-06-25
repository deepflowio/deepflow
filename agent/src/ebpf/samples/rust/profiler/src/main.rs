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
use profiler::ebpf::*;
use std::thread;
use std::time::{Duration, UNIX_EPOCH};
use std::sync::Mutex;

lazy_static::lazy_static! {
    static ref COUNTER: Mutex<u32> = Mutex::new(0);
}

#[allow(dead_code)]
fn date_time(ts: u64) -> String {
    // Creates a new SystemTime from the specified number of whole seconds
    let d = UNIX_EPOCH + Duration::from_nanos(ts);
    // Create DateTime from SystemTime
    let time = DateTime::<Utc>::from(d);
    let china_timezone = FixedOffset::east(8 * 3600);
    // Formats the combined date and time with the specified format string.
    time.with_timezone(&china_timezone)
        .format("%Y-%m-%d %H:%M:%S.%6f")
        .to_string()
}

#[allow(dead_code)]
fn sk_str_safe(data: *mut c_char) -> String {
    unsafe { CStr::from_ptr(data).to_string_lossy().into_owned() }
}

#[allow(dead_code)]
fn sk_data_str_safe(sd: *mut stack_profile_data) -> String {
    unsafe { sk_str_safe((*sd).stack_data) }
}

#[allow(dead_code)]
fn cp_process_name_safe(cp: *mut stack_profile_data) -> String {
    unsafe {
        let v = &(*cp).comm;
        String::from_utf8_lossy(v).to_string()
    }
}

fn increment_counter(num: u32) {
    let mut counter = COUNTER.lock().unwrap();
    *counter += num;
}

extern "C" fn continuous_profiler_callback(cp: *mut stack_profile_data) {
    unsafe {
          process_stack_trace_data_for_flame_graph(cp);
          increment_counter((*cp).count);
          //let data = sk_data_str_safe(cp);
          //println!("\n+ --------------------------------- +");
          //println!("{} PID {} START-TIME {} U-STACKID {} K-STACKID {} COMM {} CPU {} COUNT {} LEN {} \n  - {}",
          //         date_time((*cp).timestamp),
          //         (*cp).pid,
          //         (*cp).stime,
          //         (*cp).u_stack_id,
          //         (*cp).k_stack_id,
          //         cp_process_name_safe(cp),
          //         (*cp).cpu,
          //         (*cp).count,
          //         (*cp).stack_data_len, data);
          //println!("+ --------------------------------- +");
    }
}

fn get_counter() -> u32 {
    *COUNTER.lock().unwrap()
}

fn main() {
    // cat ./.profiler.folded |./flamegraph.pl --color=io --countname=ms > profiler-test.svg
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
            continuous_profiler_callback,
        ) != 0
        {
            println!("start_continuous_profiler() error.");
            ::std::process::exit(1);
        }

        
        bpf_tracer_finish();

        thread::sleep(Duration::from_secs(65));
        stop_continuous_profiler();
        print!("====== capture count {}\n", get_counter());
        release_flame_graph_hash();
    }

    loop {
        thread::sleep(Duration::from_secs(5));
    }
}
