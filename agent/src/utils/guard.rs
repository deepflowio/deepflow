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

use std::io::Read;
use std::path::Path;
use std::{
    fs::{self, File},
    process::exit,
    string::String,
    sync::{Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, UNIX_EPOCH},
};

use arc_swap::access::Access;
#[cfg(target_os = "windows")]
use bytesize::ByteSize;
use chrono::prelude::*;
use log::{debug, error, info, warn};

#[cfg(target_os = "windows")]
use super::process::get_memory_rss;
use super::process::{
    get_current_sys_free_memory_percentage, get_file_and_size_sum, get_thread_num, FileAndSizeSum,
};
use crate::common::{
    CGROUP_PROCS_PATH, CGROUP_TASKS_PATH, CGROUP_V2_PROCS_PATH, CGROUP_V2_THREADS_PATH,
    NORMAL_EXIT_WITH_RESTART,
};
use crate::config::handler::EnvironmentAccess;
use crate::exception::ExceptionHandler;
use crate::utils::{cgroups::is_kernel_available_for_cgroup, environment::running_in_container};

use public::proto::trident::{Exception, TapMode};

pub struct Guard {
    config: EnvironmentAccess,
    log_dir: String,
    interval: Duration,
    tap_mode: TapMode,
    thread: Mutex<Option<JoinHandle<()>>>,
    running: Arc<(Mutex<bool>, Condvar)>,
    exception_handler: ExceptionHandler,
    cgroup_mount_path: String,
    is_cgroup_v2: bool,
}

impl Guard {
    pub fn new(
        config: EnvironmentAccess,
        log_dir: String,
        interval: Duration,
        tap_mode: TapMode,
        exception_handler: ExceptionHandler,
        cgroup_mount_path: String,
        is_cgroup_v2: bool,
    ) -> Self {
        Self {
            config,
            log_dir,
            interval,
            tap_mode,
            thread: Mutex::new(None),
            running: Arc::new((Mutex::new(false), Condvar::new())),
            exception_handler,
            cgroup_mount_path,
            is_cgroup_v2,
        }
    }

    fn release_log_files(file_and_size_sum: FileAndSizeSum, log_file_size: u64) {
        let zero_o_clock = Local::today().and_hms_milli(0, 0, 0, 0).timestamp_millis() as u64; // 当天零点时间
        let mut file_sizes_sum = file_and_size_sum.file_sizes_sum.clone();
        // 从旧到新删除日志文件直到低于限制值
        for file_info in file_and_size_sum.file_infos.iter() {
            if file_sizes_sum < (log_file_size << 20) {
                break;
            }
            let file_mt = file_info
                .file_modified_time
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(); // 文件修改时间
            if file_mt >= zero_o_clock.into() {
                // 当天的文件清空
                match File::create(Path::new(file_info.file_path.as_str()))
                    .unwrap()
                    .set_len(0)
                {
                    Ok(_) => {
                        file_sizes_sum -= file_info.file_size;
                        warn!("truncate log file: {}", file_info.file_path.as_str());
                    }
                    Err(e) => {
                        error!("truncate log file failed: {}", e);
                    }
                }
            } else {
                // 非当天的文件删除
                match fs::remove_file(Path::new(file_info.file_path.as_str())) {
                    Ok(_) => {
                        file_sizes_sum -= file_info.file_size;
                        warn!("remove log file: {}", file_info.file_path.as_str());
                    }
                    Err(e) => {
                        error!("remove log file failed: {}", e);
                    }
                }
            }
        }
    }

    fn check_cgroup<P: AsRef<Path>>(cgroup_mount_path: P, is_cgroup_v2: bool) {
        fn check_file(path: &str) -> bool {
            match File::open(path) {
                Ok(mut file) => {
                    let mut buf: Vec<u8> = Vec::new();
                    // Because the cgroup file system is vfs, it is necessary to determine
                    // whether the file is empty by reading the contents of the file
                    file.read_to_end(&mut buf).unwrap_or_default();
                    if buf.len() == 0 {
                        warn!("check cgroup file failed: {} is empty", path);
                        return false;
                    }
                    return true;
                }
                Err(e) => {
                    warn!(
                        "check cgroup file failed, cannot open file: {}, {}",
                        path, e
                    );
                    return false;
                }
            }
        }
        let (proc_path, task_path) = if is_cgroup_v2 {
            (CGROUP_V2_PROCS_PATH, CGROUP_V2_THREADS_PATH)
        } else {
            (CGROUP_PROCS_PATH, CGROUP_TASKS_PATH)
        };
        let cgroup_proc_path = cgroup_mount_path.as_ref().join(proc_path).to_owned();
        let cgroup_task_path = cgroup_mount_path.as_ref().join(task_path).to_owned();
        if !check_file(cgroup_proc_path.to_str().unwrap())
            || !check_file(cgroup_task_path.to_str().unwrap())
        {
            error!("check cgroup file failed, deepflow-agent restart...");
            thread::sleep(Duration::from_secs(1));
            exit(-1);
        }
    }

    pub fn start(&self) {
        {
            let (started, _) = &*self.running;
            let mut started = started.lock().unwrap();
            if *started {
                return;
            }
            *started = true;
        }

        let limit = self.config.clone();
        let running = self.running.clone();
        let exception_handler = self.exception_handler.clone();
        let log_dir = self.log_dir.clone();
        let interval = self.interval;
        let tap_mode = self.tap_mode;
        #[cfg(target_os = "windows")]
        let mut over_memory_limit = false; // Higher than the limit does not meet expectations, just for Windows, Linux will use cgroup to limit memory
        let mut under_sys_free_memory_limit = false; // Below the limit, it does not meet expectations
        let cgroup_mount_path = self.cgroup_mount_path.clone();
        let is_cgroup_v2 = self.is_cgroup_v2;
        let thread = thread::Builder::new().name("guard".to_owned()).spawn(move || {
            loop {
                // If it is in a container or tap_mode is Analyzer, there is no need to limit resource, so there is no need to check cgroup
                if !running_in_container() && tap_mode != TapMode::Analyzer && is_kernel_available_for_cgroup() {
                    Self::check_cgroup(cgroup_mount_path.clone(), is_cgroup_v2);
                }
                #[cfg(target_os = "windows")]
                {
                    let memory_limit = limit.load().max_memory;
                    if memory_limit != 0 {
                        match get_memory_rss() {
                            Ok(memory_usage) => {
                                if memory_usage >= memory_limit {
                                    if over_memory_limit {
                                        error!(
                                    "memory usage over memory limit twice, current={}, memory_limit={}, deepflow-agent restart...",
                                    ByteSize::b(memory_usage).to_string_as(true), ByteSize::b(memory_limit).to_string_as(true)
                                    );
                                        thread::sleep(Duration::from_secs(1));
                                        exit(-1);
                                    } else {
                                        warn!(
                                    "memory usage over memory limit, current={}, memory_limit={}",
                                    ByteSize::b(memory_usage).to_string_as(true), ByteSize::b(memory_limit).to_string_as(true)
                                    );
                                        over_memory_limit = true;
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("{}", e);
                            }
                        }
                    }
                }

                let sys_free_memory_limit = limit.load().sys_free_memory_limit;
                let current_sys_free_memory_percentage = get_current_sys_free_memory_percentage();
                debug!(
                    "current_sys_free_memory_percentage: {}, sys_free_memory_limit: {}",
                    current_sys_free_memory_percentage, sys_free_memory_limit
                );
                if sys_free_memory_limit != 0 {
                    if current_sys_free_memory_percentage < sys_free_memory_limit {
                        if under_sys_free_memory_limit {
                            error!(
                                    "current system free memory percentage is less than sys_free_memory_limit twice, current system free memory percentage={}%, sys_free_memory_limit={}%, deepflow-agent restart...",
                                    current_sys_free_memory_percentage, sys_free_memory_limit
                                    );
                            thread::sleep(Duration::from_secs(1));
                            exit(-1);
                        } else {
                            warn!(
                                    "current system free memory percentage is less than sys_free_memory_limit, current system free memory percentage={}%, sys_free_memory_limit={}%",
                                    current_sys_free_memory_percentage, sys_free_memory_limit
                                    );
                            under_sys_free_memory_limit = true;
                        }
                    }
                }

                match get_thread_num() {
                    Ok(thread_num) => {
                        let thread_limit = limit.load().thread_threshold;
                        if thread_num > thread_limit {
                            warn!(
                                "the number of thread exceeds the limit({} > {})",
                                thread_num, thread_limit
                            );
                            if thread_num > thread_limit * 2 {
                                error!("the number of thread exceeds the limit by 2 times, trident restart...");
                                thread::sleep(Duration::from_secs(1));
                                exit(NORMAL_EXIT_WITH_RESTART);
                            }
                            exception_handler.set(Exception::ThreadThresholdExceeded);
                        } else {
                            exception_handler.clear(Exception::ThreadThresholdExceeded);
                        }
                    }
                    Err(e) => {
                        warn!("{}", e);
                    }
                }

                match get_file_and_size_sum(log_dir.clone()) {
                    Ok(file_and_size_sum) => {
                        let log_file_size = limit.load().log_file_size; // 日志文件大小限制值，单位：M
                        let file_sizes_sum = file_and_size_sum.file_sizes_sum.clone(); // 当前日志文件大小总和，单位：B
                        debug!(
                            "current log files' size: {}B, log_file_size_limit: {}B",
                            file_sizes_sum,
                            (log_file_size << 20)
                        );
                        if file_sizes_sum > (log_file_size as u64) << 20 {
                            error!("log files' size is over log_file_size_limit, current: {}B, log_file_size_limit: {}B",
                               file_sizes_sum, (log_file_size << 20));
                            Self::release_log_files(file_and_size_sum, log_file_size as u64);
                            exception_handler.set(Exception::LogFileExceeded);
                        } else {
                            exception_handler.clear(Exception::LogFileExceeded);
                        }
                    }
                    Err(e) => {
                        warn!("{}", e);
                    }
                }

                let (running, timer) = &*running;
                let mut running = running.lock().unwrap();
                if !*running {
                    break;
                }
                running = timer.wait_timeout(running, interval).unwrap().0;
                if !*running {
                    break;
                }
            }
            info!("guard exited");
        }).unwrap();

        self.thread.lock().unwrap().replace(thread);
        info!("guard started");
    }

    pub fn stop(&self) {
        let (stopped, timer) = &*self.running;
        {
            let mut stopped = stopped.lock().unwrap();
            if !*stopped {
                return;
            }
            *stopped = false;
        }
        timer.notify_one();

        if let Some(thread) = self.thread.lock().unwrap().take() {
            let _ = thread.join();
        }
    }
}
