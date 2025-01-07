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

use std::io::Read;
use std::path::Path;
use std::{
    fs::{self, File},
    string::String,
    sync::{Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant, UNIX_EPOCH},
};

use arc_swap::access::Access;
use bytesize::ByteSize;
use chrono::prelude::*;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use libc::malloc_trim;
use log::{debug, error, info, warn};
use sysinfo::{get_current_pid, Pid, ProcessExt, ProcessRefreshKind, System, SystemExt};

use super::process::{
    get_current_sys_memory_percentage, get_file_and_size_sum, get_memory_rss, get_thread_num,
    FileAndSizeSum,
};
use crate::common::{
    CGROUP_PROCS_PATH, CGROUP_TASKS_PATH, CGROUP_V2_PROCS_PATH, CGROUP_V2_THREADS_PATH,
    NORMAL_EXIT_WITH_RESTART,
};
use crate::config::handler::EnvironmentAccess;
use crate::exception::ExceptionHandler;
use crate::rpc::get_timestamp;
use crate::trident::AgentState;
#[cfg(target_os = "linux")]
use crate::utils::environment::SocketInfo;
use crate::utils::{cgroups::is_kernel_available_for_cgroups, environment::running_in_container};

use public::proto::agent::{Exception, PacketCaptureType, SysMemoryMetric, SystemLoadMetric};

struct SystemLoadGuard {
    system: Arc<Mutex<System>>,

    exception_handler: ExceptionHandler,

    last_exceeded: Duration,
    last_exceeded_metric: SystemLoadMetric,
}

const CONTINUOUS_SAFETY_TIME: Duration = Duration::from_secs(300);

impl SystemLoadGuard {
    fn new(system: Arc<Mutex<System>>, exception_handler: ExceptionHandler) -> Self {
        Self {
            system,
            exception_handler,
            last_exceeded: Duration::ZERO,
            last_exceeded_metric: SystemLoadMetric::Load15,
        }
    }

    fn check(
        &mut self,
        system_load_circuit_breaker_threshold: f32,
        system_load_circuit_breaker_recover: f32,
        system_load_circuit_breaker_metric: SystemLoadMetric,
    ) {
        if system_load_circuit_breaker_threshold == 0.0
            || system_load_circuit_breaker_recover == 0.0
        {
            self.last_exceeded = Duration::ZERO;
            self.exception_handler
                .clear(Exception::SystemLoadCircuitBreaker);
            return;
        }
        if system_load_circuit_breaker_metric != self.last_exceeded_metric {
            self.last_exceeded_metric = system_load_circuit_breaker_metric;
            self.last_exceeded = Duration::ZERO;
        }

        let system = self.system.lock().unwrap();

        let cpu_count = system.cpus().len() as f32;
        let system_load = match system_load_circuit_breaker_metric {
            SystemLoadMetric::Load1 => system.load_average().one,
            SystemLoadMetric::Load5 => system.load_average().five,
            SystemLoadMetric::Load15 => system.load_average().fifteen,
        } as f32;

        if self
            .exception_handler
            .has(Exception::SystemLoadCircuitBreaker)
        {
            let has_exceeded = system_load / cpu_count >= system_load_circuit_breaker_recover;
            if has_exceeded {
                self.last_exceeded = get_timestamp(0);
            } else {
                let now = get_timestamp(0);
                if now > self.last_exceeded + CONTINUOUS_SAFETY_TIME {
                    info!(
                        "Current load {:?} is below the recover threshold({:?}), set the agent to enabled.",
                        system_load_circuit_breaker_metric, system_load_circuit_breaker_recover
                    );
                    self.exception_handler
                        .clear(Exception::SystemLoadCircuitBreaker);
                }
            }
        } else {
            let has_exceeded = system_load / cpu_count >= system_load_circuit_breaker_threshold;
            if has_exceeded {
                error!(
                    "Current load {:?} exceeds the threshold({:?}), set the agent to disabled.",
                    system_load_circuit_breaker_metric, system_load_circuit_breaker_threshold
                );
                self.last_exceeded = get_timestamp(0);
                self.exception_handler
                    .set(Exception::SystemLoadCircuitBreaker);
            }
        }
    }
}

pub struct Guard {
    config: EnvironmentAccess,
    state: Arc<AgentState>,
    log_dir: String,
    thread: Mutex<Option<JoinHandle<()>>>,
    running: Arc<(Mutex<bool>, Condvar)>,
    exception_handler: ExceptionHandler,
    cgroup_mount_path: String,
    is_cgroup_v2: bool,
    memory_trim_disabled: bool,
    system: Arc<Mutex<System>>,
    pid: Pid,
    cgroups_disabled: bool,
}

impl Guard {
    pub fn new(
        config: EnvironmentAccess,
        state: Arc<AgentState>,
        log_dir: String,
        exception_handler: ExceptionHandler,
        cgroup_mount_path: String,
        is_cgroup_v2: bool,
        memory_trim_enabled: bool,
        cgroups_disabled: bool,
    ) -> Result<Self, &'static str> {
        let Ok(pid) = get_current_pid() else {
            return Err("get the process' pid failed: {}, deepflow-agent restart...");
        };
        Ok(Self {
            config,
            state,
            log_dir,
            thread: Mutex::new(None),
            running: Arc::new((Mutex::new(false), Condvar::new())),
            exception_handler,
            cgroup_mount_path,
            is_cgroup_v2,
            memory_trim_disabled: !memory_trim_enabled,
            system: Arc::new(Mutex::new(System::new())),
            pid,
            cgroups_disabled,
        })
    }

    fn release_log_files(file_and_size_sum: FileAndSizeSum, log_file_size: u64) {
        let today = Utc::now()
            .date_naive()
            .and_hms_milli_opt(0, 0, 0, 0)
            .unwrap();
        let zero_o_clock = Local
            .from_local_datetime(&today)
            .unwrap()
            .timestamp_millis() as u128; // 当天零点时间
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
            if file_mt >= zero_o_clock {
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

    fn check_cgroups<P: AsRef<Path>>(cgroup_mount_path: P, is_cgroup_v2: bool) -> bool {
        fn check_file(path: &str) -> bool {
            match File::open(path) {
                Ok(mut file) => {
                    let mut buf: Vec<u8> = Vec::new();
                    // Because the cgroups file system is vfs, it is necessary to determine
                    // whether the file is empty by reading the contents of the file
                    file.read_to_end(&mut buf).unwrap_or_default();
                    if buf.len() == 0 {
                        warn!("check cgroups file failed: {} is empty", path);
                        return false;
                    }
                    return true;
                }
                Err(e) => {
                    warn!(
                        "check cgroups file failed, cannot open file: {}, {}",
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
        check_file(cgroup_proc_path.to_str().unwrap())
            && check_file(cgroup_task_path.to_str().unwrap())
    }

    fn check_cpu(system: Arc<Mutex<System>>, pid: Pid, cpu_limit: u32) -> bool {
        let system_guard = system.lock().unwrap();

        let cpu_usage = match system_guard.process(pid) {
            Some(process) => process.cpu_usage(),
            None => {
                warn!("get the process' cpu_usage failed");
                return false;
            }
        };
        (cpu_limit / 10) as f32 > cpu_usage // The cpu_usage is in percentage, and the unit of cpu_limit is milli-cores. Divide cpu_limit by 10 to align the units
    }

    fn check_sys_memory(
        sys_memory_limit: f64,
        sys_memory_metric: SysMemoryMetric,
        under_sys_memory_limit: &mut bool,
        last_exceeded: &mut Duration,
        exception_handler: &ExceptionHandler,
    ) {
        let (current_sys_free_memory_percentage, current_sys_available_memory_percentage) =
            get_current_sys_memory_percentage();
        debug!(
            "current_sys_memory_percentage: [ free: {}, available: {} ], sys_memory_metric: {:?} sys_memory_limit: {}",
            current_sys_free_memory_percentage, current_sys_available_memory_percentage, sys_memory_metric, sys_memory_limit
        );
        let current_memory_percentage = if sys_memory_metric == SysMemoryMetric::Free {
            current_sys_free_memory_percentage as f64
        } else {
            current_sys_available_memory_percentage as f64
        };

        if sys_memory_limit != 0.0 {
            if current_memory_percentage < sys_memory_limit * 0.7 {
                *last_exceeded = get_timestamp(0);
                exception_handler.set(Exception::FreeMemExceeded);
                *under_sys_memory_limit = true;
                error!(
                    "current system {:?} memory percentage is less than the 70% of sys_memory_limit, current system memory percentage={}%, sys_memory_limit={}%, deepflow-agent restart...",
                    sys_memory_metric, current_memory_percentage, sys_memory_limit
                );
                crate::utils::notify_exit(-1);
            } else if current_memory_percentage < sys_memory_limit {
                *last_exceeded = get_timestamp(0);
                exception_handler.set(Exception::FreeMemExceeded);
                *under_sys_memory_limit = true;
                error!(
                    "current system {:?} memory percentage is less than sys_memory_limit, current system memory percentage={}%, sys_memory_limit={}%, set the agent to disabled",
                    sys_memory_metric, current_memory_percentage, sys_memory_limit
                );
            } else if current_memory_percentage >= sys_memory_limit * 1.1 {
                let now = get_timestamp(0);
                if *under_sys_memory_limit && now > *last_exceeded + CONTINUOUS_SAFETY_TIME {
                    exception_handler.clear(Exception::FreeMemExceeded);
                    *under_sys_memory_limit = false;
                    info!(
                        "current system {:?} memory percentage: {}% remains above sys_memory_limit: {} * 110%, set the agent to enabled.",
                        sys_memory_metric, current_memory_percentage, sys_memory_limit
                    );
                }
            }
        } else {
            exception_handler.clear(Exception::FreeMemExceeded);
        }
    }

    pub fn start(&self) {
        {
            let (running, _) = &*self.running;
            let mut running = running.lock().unwrap();
            if *running {
                return;
            }
            *running = true;
        }

        let config = self.config.clone();
        let running_state = self.running.clone();
        let state = self.state.clone();
        let exception_handler = self.exception_handler.clone();
        let log_dir = self.log_dir.clone();
        let mut over_memory_limit = false; // Higher than the limit does not meet expectations
        let mut over_cpu_limit = false; // Higher than the limit does not meet expectations
        let mut under_sys_free_memory_limit = false; // Below the limit, it does not meet expectations
        let cgroup_mount_path = self.cgroup_mount_path.clone();
        let is_cgroup_v2 = self.is_cgroup_v2;
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        let memory_trim_disabled = self.memory_trim_disabled;
        let mut check_cgroup_result = true; // It is used to determine whether subsequent checks are required. If the first check fails, the check is stopped
        let system = self.system.clone();
        let pid: Pid = self.pid.clone();
        let cgroups_available = is_kernel_available_for_cgroups();
        let in_container = running_in_container();
        let cgroups_disabled = self.cgroups_disabled;
        let mut last_exceeded = get_timestamp(0);

        let thread = thread::Builder::new().name("guard".to_owned()).spawn(move || {
            let mut system_load = SystemLoadGuard::new(system.clone(), exception_handler.clone());
            #[cfg(target_os = "linux")]
            let mut last_over_max_sockets_limit = None;
            loop {
                let config = config.load();
                let capture_mode = config.capture_mode;
                let cpu_limit = config.max_millicpus;
                let mut system_guard = system.lock().unwrap();
                if !system_guard.refresh_process_specifics(pid, ProcessRefreshKind::new().with_cpu()) {
                    warn!("refresh process with cpu failed");
                }
                drop(system_guard);
                system_load.check(config.system_load_circuit_breaker_threshold, config.system_load_circuit_breaker_recover, config.system_load_circuit_breaker_metric);
                match get_file_and_size_sum(&log_dir) {
                    Ok(file_and_size_sum) => {
                        let log_file_size = config.log_file_size; // Log file size limit (unit: M)
                        let file_sizes_sum = file_and_size_sum.file_sizes_sum; // Total size of current log files (unit: B)
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
                            // exception_handler.clear(Exception::LogFileExceeded);
                        }
                    }
                    Err(e) => {
                        warn!("{}", e);
                    }
                }
                // If it is in a container or capture_mode is Analyzer, there is no need to limit resource, so there is no need to check cgroups
                if !in_container && config.capture_mode != PacketCaptureType::Analyzer {
                    if cgroups_available && !cgroups_disabled {
                        if check_cgroup_result {
                            check_cgroup_result = Self::check_cgroups(cgroup_mount_path.clone(), is_cgroup_v2);
                            if !check_cgroup_result {
                                warn!("check cgroups failed, limit cpu or memory without cgroups");
                            }
                        }
                        if !check_cgroup_result {
                            if !Self::check_cpu(system.clone(), pid.clone(), cpu_limit) {
                                if over_cpu_limit {
                                    error!("cpu usage over cpu limit twice, deepflow-agent restart...");
                                    crate::utils::notify_exit(-1);
                                    break;
                                } else {
                                    warn!("cpu usage over cpu limit");
                                    over_cpu_limit = true;
                                }
                            } else {
                                over_cpu_limit = false;
                            }
                        }
                    } else {
                        if !Self::check_cpu(system.clone(), pid.clone(), cpu_limit) {
                            if over_cpu_limit {
                                error!("cpu usage over cpu limit twice, deepflow-agent restart...");
                                crate::utils::notify_exit(-1);
                                break;
                            } else {
                                warn!("cpu usage over cpu limit");
                                over_cpu_limit = true;
                            }
                        } else {
                            over_cpu_limit = false;
                        }
                    }
                }

                #[cfg(all(target_os = "linux", target_env = "gnu"))]
                if !memory_trim_disabled {
                    unsafe { let _ = malloc_trim(0); }
                }

                // Periodic memory checks are necessary:
                // Cgroups does not count the memory of RssFile, and AF_PACKET Block occupies RssFile.
                // Therefore, using Cgroups to limit the memory usage may not be accurate in some scenarios.
                // Periodically checking the memory usage can determine whether the memory exceeds the limit.
                // Reference: https://unix.stackexchange.com/questions/686814/cgroup-and-process-memory-statistics-mismatch
                if capture_mode != PacketCaptureType::Analyzer {
                    let memory_limit = config.max_memory;
                    if memory_limit != 0 {
                        match get_memory_rss() {
                            Ok(memory_usage) => {
                                if memory_usage >= memory_limit {
                                    if over_memory_limit {
                                        error!(
                                    "memory usage over memory limit twice, current={}, memory_limit={}, deepflow-agent restart...",
                                    ByteSize::b(memory_usage).to_string_as(true), ByteSize::b(memory_limit).to_string_as(true)
                                    );
                                        crate::utils::notify_exit(-1);
                                        break;
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

                Self::check_sys_memory(config.sys_memory_limit as f64, config.sys_memory_metric, &mut under_sys_free_memory_limit, &mut last_exceeded, &exception_handler);

                match get_thread_num() {
                    Ok(thread_num) => {
                        let thread_limit = config.thread_threshold;
                        if thread_num > thread_limit {
                            warn!(
                                "the number of thread exceeds the limit({} > {})",
                                thread_num, thread_limit
                            );
                            if thread_num > thread_limit * 2 {
                                error!("the number of thread exceeds the limit by 2 times, deepflow-agent restart...");
                                crate::utils::notify_exit(NORMAL_EXIT_WITH_RESTART);
                                break;
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

                if exception_handler.has(Exception::SystemLoadCircuitBreaker) {
                    info!("Set the state to melt_down when the system load exceeds the threshold.");
                    state.melt_down();
                } else if exception_handler.has(Exception::FreeMemExceeded) {
                    info!("Set the state to melt_down when the free memory exceeds the threshold.");
                    state.melt_down();
                } else {
                    state.recover();
                }

                #[cfg(target_os = "linux")]
                match SocketInfo::get() {
                    Ok(SocketInfo { tcp, tcp6, udp, udp6 }) => {
                        let (n_tcp, n_tcp6, n_udp, n_udp6) = (tcp.len(), tcp6.len(), udp.len(), udp6.len());
                        if n_tcp + n_tcp6 + n_udp + n_udp6 <= config.max_sockets {
                            debug!("socket count check passed: {n_tcp}(tcp) + {n_tcp6}(tcp6) + {n_udp}(udp) + {n_udp6}(udp6) <= {}", config.max_sockets);
                            last_over_max_sockets_limit = None;
                        } else {
                            match last_over_max_sockets_limit {
                                None => {
                                    last_over_max_sockets_limit = Some(Instant::now());
                                    warn!("the number of socket exceeds the limit: {n_tcp}(tcp) + {n_tcp6}(tcp6) + {n_udp}(udp) + {n_udp6}(udp6) > {}", config.max_sockets);
                                    warn!("opened sockets:\n{}", SocketInfo { tcp, tcp6, udp, udp6 });
                                }
                                Some(last) if last.elapsed() > config.max_sockets_tolerate_interval => {
                                    warn!("the number of socket exceeds the limit longer than {:?}, deepflow-agent restart...", config.max_sockets_tolerate_interval);
                                    warn!("opened sockets:\n{}", SocketInfo { tcp, tcp6, udp, udp6 });
                                    crate::utils::notify_exit(NORMAL_EXIT_WITH_RESTART);
                                    break;
                                }
                                Some(last) => {
                                    debug!("the number of socket exceeds the limit for {:?}", last.elapsed());
                                    debug!("opened sockets:\n{}", SocketInfo { tcp, tcp6, udp, udp6 });
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Check agent sockets failed: {e}");
                        last_over_max_sockets_limit = None;
                    }
                }

                let (running, notifier) = &*running_state;
                let mut rg = running.lock().unwrap();
                if !*rg {
                    break;
                }
                rg = notifier.wait_timeout(rg, config.guard_interval).unwrap().0;
                if !*rg {
                    break;
                }
            }
            info!("guard exited");
        }).unwrap();

        self.thread.lock().unwrap().replace(thread);
        info!("guard started");
    }

    pub fn stop(&self) {
        let (running, notifier) = &*self.running;
        {
            let mut running = running.lock().unwrap();
            if !*running {
                return;
            }
            *running = false;
        }
        notifier.notify_one();

        if let Some(thread) = self.thread.lock().unwrap().take() {
            let _ = thread.join();
        }
    }
}
