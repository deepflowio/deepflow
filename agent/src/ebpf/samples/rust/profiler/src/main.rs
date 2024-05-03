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
use std::ffi::CString;
use profiler::ebpf::*;
use std::env::set_var;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

lazy_static::lazy_static! {
    static ref SUM: Mutex<u32> = Mutex::new(0);
}

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
fn cp_comm_safe(cp: *mut stack_profile_data) -> String {
    unsafe {
        let v = &(*cp).comm;
        String::from_utf8_lossy(v).to_string()
    }
}

#[allow(dead_code)]
fn cp_process_name_safe(cp: *mut stack_profile_data) -> String {
    unsafe {
        let v = &(*cp).process_name;
        String::from_utf8_lossy(v).to_string()
    }
}

#[allow(dead_code)]
fn cp_container_id_safe(cp: *mut stack_profile_data) -> String {
    unsafe {
        let v = &(*cp).container_id;
        String::from_utf8_lossy(v).to_string()
    }
}

fn increment_counter(num: u32, counter_type: u32) {
    if counter_type == 0 {
        let mut counter = COUNTER.lock().unwrap();
        *counter += num;
    } else {
        let mut counter = SUM.lock().unwrap();
        *counter += num;
    }
}

#[allow(dead_code)]
extern "C" fn debug_callback(_data: *mut c_char, len: c_int) {
    // Ensure the input data is not null
    if _data.is_null() {
        return;
    }

    // Convert the C string to a Rust string
    unsafe {
        // Create a slice of the data with the specified length
        let data_slice = std::slice::from_raw_parts(_data as *const u8, len as usize);

        // Convert the slice to a CStr
        let c_str: &CStr = CStr::from_bytes_with_nul_unchecked(data_slice);

        // Convert the CStr to a Rust string
        if let Ok(rust_str) = c_str.to_str() {
            println!("+ --------------------------------- +");
            // Print the string to the standard output
            println!("{}", rust_str);
            println!("+ --------------------------------- +");
        } else {
            // Handle the case where conversion to a Rust string fails
            eprintln!("Error: Unable to convert C string to Rust string");
        }
    }
}

extern "C" fn socket_trace_callback(_sd: *mut SK_BPF_DATA) {}

extern "C" fn continuous_profiler_callback(cp: *mut stack_profile_data) {
    unsafe {
        process_stack_trace_data_for_flame_graph(cp);
        increment_counter((*cp).count, 1);
        increment_counter(1, 0);
        //let data = sk_data_str_safe(cp);
        //println!("\n+ --------------------------------- +");
        //println!("{} PID {} START-TIME {} NETNS-ID {} U-STACKID {} K-STACKID {} PROCESS_NAME {} COMM {} CONTAINER {} CPU {} COUNT {} LEN {} \n  - {}",
        //         date_time((*cp).timestamp),
        //         (*cp).pid,
        //         (*cp).stime,
        //         (*cp).netns_id,
        //         (*cp).u_stack_id,
        //         (*cp).k_stack_id,
        //         cp_process_name_safe(cp),
        //         cp_comm_safe(cp),
        //         cp_container_id_safe(cp),
        //         (*cp).cpu,
        //         (*cp).count,
        //         (*cp).stack_data_len, data);
        //println!("+ --------------------------------- +");
    }
}

fn get_counter(counter_type: u32) -> u32 {
    if counter_type == 0 {
        *COUNTER.lock().unwrap()
    } else {
        *SUM.lock().unwrap()
    }
}

fn main() {
    set_var("RUST_LOG", "info");
    env_logger::builder()
      .format_timestamp(Some(env_logger::TimestampPrecision::Millis))
      .init();

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

        if running_socket_tracer(
            socket_trace_callback, /* Callback interface rust -> C */
            1, /* Number of worker threads, indicating how many user-space threads participate in data processing */
            64, /* Number of page frames occupied by kernel-shared memory, must be a power of 2. Used for perf data transfer */
            65536, /* Size of the circular buffer queue, must be a power of 2. e.g: 2, 4, 8, 16, 32, 64, 128 */
            524288, /* Maximum number of hash table entries for socket tracing, depends on the actual number of concurrent requests in the scenario */
            524288, /* Maximum number of hash table entries for thread/coroutine tracing sessions */
            520000, /* Maximum threshold for cleaning socket map entries. If the current number of map entries exceeds this value, map cleaning operation is performed */
        ) != 0
        {
            println!("running_socket_tracer() error.");
            ::std::process::exit(1);
        }

        // Used to test our DeepFlow products, written as 97 frequency, so that
        // it will not affect the sampling test of deepflow agent (using 99Hz).
        if start_continuous_profiler(97, 10, 300, continuous_profiler_callback) != 0 {
            println!("start_continuous_profiler() error.");
            ::std::process::exit(1);
        }

        set_profiler_regex(
            CString::new("^(socket_tracer|java|deepflow-.*)$".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );

        // CPUID will not be included in the aggregation of stack trace data.
        set_profiler_cpu_aggregation(0);

        bpf_tracer_finish();

        if cpdbg_set_config(60, debug_callback) != 0 {
            println!("cpdbg_set_config() error");
            ::std::process::exit(1);
        }

        let stats = socket_tracer_stats();
        print!("{:#?}\n", stats);

        print!("start start ...\n");
        while socket_tracer_start() != 0 {
            print!("socket_tracer_start() error, sleep 1s retry.\n");
            std::thread::sleep(Duration::from_secs(1));
        }

        thread::sleep(Duration::from_secs(150));
        stop_continuous_profiler();
        print!(
            "====== capture count {}, sum {}\n",
            get_counter(0),
            get_counter(1)
        );
        release_flame_graph_hash();
    }

    loop {
        thread::sleep(Duration::from_secs(5));
    }
}
