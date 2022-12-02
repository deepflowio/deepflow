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

use std::path::Path;
use std::{
    fs::{self, File},
    process::exit,
    sync::{Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, UNIX_EPOCH},
};

use arc_swap::access::Access;
use bytesize::ByteSize;
use chrono::prelude::*;
use log::{debug, error, info, warn};

use super::process::{
    get_current_sys_free_memory_percentage, get_file_and_size_sum, get_memory_rss, get_process_num,
    get_thread_num, FileAndSizeSum,
};
use crate::common::NORMAL_EXIT_WITH_RESTART;
use crate::config::handler::EnvironmentAccess;
use crate::exception::ExceptionHandler;
use public::proto::trident::Exception;

const CHECK_INTERVAL: Duration = Duration::from_secs(1);

pub struct Guard {
    config: EnvironmentAccess,
    log_dir: String,
    thread: Mutex<Option<JoinHandle<()>>>,
    running: Arc<(Mutex<bool>, Condvar)>,
    exception_handler: ExceptionHandler,
}

impl Guard {
    pub fn new(
        config: EnvironmentAccess,
        log_dir: String,
        exception_handler: ExceptionHandler,
    ) -> Self {
        Self {
            config,
            log_dir,
            thread: Mutex::new(None),
            running: Arc::new((Mutex::new(false), Condvar::new())),
            exception_handler,
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
        let mut over_memory_limit = false; // 是否高于内存限制，高于则不符合预期
        let mut under_sys_free_memory_limit = false; // 是否低于空闲内存限制，低于则不符合预期
        let thread = thread::spawn(move || {
            loop {
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

                match get_process_num() {
                    Ok(process_num) => {
                        let process_limit = limit.load().process_threshold;
                        if process_num > process_limit {
                            warn!(
                                "the number of process exceeds the limit({} > {})",
                                process_num, process_limit
                            );
                            if process_num > process_limit * 2 {
                                error!("the number of process exceeds the limit by 2 times, deepflow-agent restart...");
                                thread::sleep(Duration::from_secs(1));
                                exit(NORMAL_EXIT_WITH_RESTART);
                            }
                            exception_handler.set(Exception::ProcessThresholdExceeded);
                        } else {
                            exception_handler.clear(Exception::ProcessThresholdExceeded);
                        }
                    }
                    Err(e) => {
                        warn!("{}", e);
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
                running = timer.wait_timeout(running, CHECK_INTERVAL).unwrap().0;
                if !*running {
                    break;
                }
            }
            info!("guard exited");
        });

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
