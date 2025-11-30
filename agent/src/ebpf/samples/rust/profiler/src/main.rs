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
use std::env;
use std::ffi::CString;
use std::ptr;
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

#[allow(dead_code)]
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

extern "C" fn socket_trace_callback(_: *mut c_void, _queue_id: c_int, _sd: *mut SK_BPF_DATA) -> c_int { 0 }

extern "C" fn continuous_profiler_callback(
    _: *mut c_void,
    _queue_id: c_int,
    cp: *mut stack_profile_data,
) -> c_int {
    unsafe {
        process_stack_trace_data_for_flame_graph(cp);
        increment_counter((*cp).count as u32, 1);
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

    0
}

#[allow(dead_code)]
fn get_counter(counter_type: u32) -> u32 {
    if counter_type == 0 {
        *COUNTER.lock().unwrap()
    } else {
        *SUM.lock().unwrap()
    }
}

fn print_help(program_name: &str) {
    println!("DeepFlow eBPF Profiler - Continuous CPU Profiling Tool");
    println!();
    println!("USAGE:");
    println!("    {} <pid1> [pid2] [pid3] ...", program_name);
    println!("    {} --help | -h", program_name);
    println!();
    println!("ARGUMENTS:");
    println!("    <pid1> [pid2] ...    Process IDs to profile (must be positive integers)");
    println!();
    println!("OPTIONS:");
    println!("    -h, --help          Show this help message and exit");
    println!();
    println!("DESCRIPTION:");
    println!("    This tool performs continuous CPU profiling of specified processes using eBPF.");
    println!(
        "    It captures stack traces at 97Hz frequency and supports multi-language profiling"
    );
    println!("    for Python, PHP, and Node.js applications with DWARF unwinding.");
    println!();
    println!("    The profiler will:");
    println!("    - Run for 150 seconds by default");
    println!("    - Generate flame graph data suitable for visualization");
    println!("    - Support both kernel and user-space stack unwinding");
    println!("    - Automatically detect and profile Python, PHP, and Node.js processes");
    println!();
    println!("EXAMPLES:");
    println!(
        "    {}  1234                    # Profile single process",
        program_name
    );
    println!(
        "    {}  1234 5678              # Profile multiple processes",
        program_name
    );
    println!(
        "    {}  1234 5678 9012         # Profile three processes",
        program_name
    );
    println!();
    println!("NOTE:");
    println!("    - Requires root privileges to load eBPF programs");
    println!("    - Target processes should be running when profiler starts");
    println!("    - Output suitable for flame graph generation:");
    println!(
        "      cat ./.profiler.folded | ./flamegraph.pl --color=io --countname=ms > profiler.svg"
    );
}

fn main() {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info")
    }
    env_logger::builder()
        .format_timestamp(Some(env_logger::TimestampPrecision::Millis))
        .init();

    let args: Vec<String> = env::args().collect();

    // Check for help flags
    if args.len() > 1 && (args[1] == "--help" || args[1] == "-h") {
        print_help(&args[0]);
        ::std::process::exit(0);
    }

    // Parse PIDs from command line arguments
    let pids: Vec<c_int> = if args.len() > 1 {
        let mut parsed_pids = Vec::new();
        let mut invalid_args = Vec::new();

        for arg in &args[1..] {
            match arg.parse::<c_int>() {
                Ok(pid) if pid > 0 => parsed_pids.push(pid),
                Ok(pid) => {
                    eprintln!("Warning: Invalid PID '{}' (must be > 0), ignoring", pid);
                    invalid_args.push(arg.clone());
                }
                Err(_) => {
                    eprintln!("Warning: '{}' is not a valid PID, ignoring", arg);
                    invalid_args.push(arg.clone());
                }
            }
        }

        if !invalid_args.is_empty() && parsed_pids.is_empty() {
            eprintln!("Error: No valid PIDs provided");
            print_help(&args[0]);
            ::std::process::exit(1);
        }

        parsed_pids
    } else {
        eprintln!("Error: No PIDs provided");
        print_help(&args[0]);
        ::std::process::exit(1);
    };

    if pids.is_empty() {
        eprintln!("Error: No valid PIDs provided");
        print_help(&args[0]);
        ::std::process::exit(1);
    }

    println!("Profiling PIDs: {:?}", pids);

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

        set_bpf_map_prealloc(false);

        if running_socket_tracer(
            socket_trace_callback, /* Callback interface rust -> C */
            1, /* Number of worker threads, indicating how many user-space threads participate in data processing */
            64, /* Number of page frames occupied by kernel-shared memory, must be a power of 2. Used for perf data transfer */
            65536, /* Size of the circular buffer queue, must be a power of 2. e.g: 2, 4, 8, 16, 32, 64, 128 */
            131072, /* Maximum number of hash table entries for socket tracing, depends on the actual number of concurrent requests in the scenario */
            131072, /* Maximum number of hash table entries for thread/coroutine tracing sessions */
            120000, /* Maximum threshold for cleaning socket map entries. If the current number of map entries exceeds this value, map cleaning operation is performed */
        ) != 0
        {
            println!("running_socket_tracer() error.");
            ::std::process::exit(1);
        }

        set_dwarf_enabled(true);

        let mut contexts = [ptr::null_mut(), ptr::null_mut(), ptr::null_mut()];

        // Used to test our DeepFlow products, written as 97 frequency, so that
        // it will not affect the sampling test of deepflow agent (using 99Hz).
        if start_continuous_profiler(
            97,
            60,
            continuous_profiler_callback,
            &contexts as *const [*mut c_void; PROFILER_CTX_NUM],
        ) != 0
        {
            println!("start_continuous_profiler() error.");
            ::std::process::exit(1);
        }

        let pids_array: Vec<c_int> = pids.clone();
        let num: c_int = pids_array.len() as c_int;
        let result = set_feature_pids(FEATURE_PROFILE_ONCPU, pids_array.as_ptr(), num);
        println!("Result {}", result);
        let result = set_feature_pids(FEATURE_DWARF_UNWINDING, pids_array.as_ptr(), num);
        println!("Result {}", result);

        // No need for set_dwarf_regex() when using set_feature_pids(FEATURE_DWARF_UNWINDING)
        // The explicit PID list takes precedence and skips regex matching

        // CPUID will not be included in the aggregation of stack trace data.
        set_profiler_cpu_aggregation(0);

        bpf_tracer_finish();

        //if cpdbg_set_config(600, debug_callback) != 0 {
        //    println!("cpdbg_set_config() error");
        //    ::std::process::exit(1);
        //}

        let stats = socket_tracer_stats();
        print!("{:#?}\n", stats);

        print!("start start ...\n");
        while socket_tracer_start() != 0 {
            print!("socket_tracer_start() error, sleep 1s retry.\n");
            std::thread::sleep(Duration::from_secs(1));
        }

        thread::sleep(Duration::from_secs(300));
        stop_continuous_profiler(&mut contexts as *mut [*mut c_void; PROFILER_CTX_NUM]);
        print!(
            "====== capture count {}, sum {}\n",
            get_counter(0),
            get_counter(1)
        );
        release_flame_graph_hash();
    }

    loop {
        thread::sleep(Duration::from_secs(30));
        // unsafe {
        //     show_collect_pool();
        // }
    }
}
