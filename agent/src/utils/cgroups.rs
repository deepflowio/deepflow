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

use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use std::{fs, process, thread};

use crate::config::handler::EnvironmentAccess;

use arc_swap::access::Access;
use cgroups_rs::cgroup_builder::*;
use cgroups_rs::*;
use log::{error, info, warn};
use public::consts::{DEFAULT_CPU_CFS_PERIOD_US, PROCESS_NAME};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("cgroup is not supported: {0}")]
    CgroupNotSupported(String),
    #[error("set cpu controller failed: {0}")]
    CpuControllerSetFailed(String),
    #[error("set mem controller failed: {0}")]
    MemControllerSetFailed(String),
    #[error("apply resources failed: {0}")]
    ApplyResourcesFailed(String),
    #[error("delete cgroup failed: {0}")]
    DeleteCgroupFailed(String),
}

pub struct Cgroups {
    config: EnvironmentAccess,
    thread: Mutex<Option<JoinHandle<()>>>,
    running: Arc<(Mutex<bool>, Condvar)>,
    cgroup: Cgroup,
}

const CHECK_INTERVAL: Duration = Duration::from_secs(1);

impl Cgroups {
    /// 创建cgroup hierarchy
    pub fn new(pid: u64, config: EnvironmentAccess) -> Result<Self, Error> {
        let contents = match fs::read_to_string("/proc/filesystems") {
            Ok(file_contents) => file_contents,
            Err(e) => {
                return Err(Error::CgroupNotSupported(e.to_string()));
            }
        };
        let mut cgroup_supported = false;
        for line in contents.lines() {
            // 检查系统是否支持cgroup
            if line.to_lowercase().contains("cgroup") {
                cgroup_supported = true;
                break;
            }
        }
        if !cgroup_supported {
            return Err(Error::CgroupNotSupported(format!(
                "cgroup v1 or v2 is not found."
            )));
        }
        let hier = hierarchies::auto();
        let cg: Cgroup = CgroupBuilder::new(PROCESS_NAME).build(hier);
        let cpus: &cpu::CpuController = cg.controller_of().unwrap();
        if let Err(e) = cpus.add_task_by_tgid(&CgroupPid::from(pid)) {
            return Err(Error::CpuControllerSetFailed(e.to_string()));
        }
        let mem: &memory::MemController = cg.controller_of().unwrap();
        if let Err(e) = mem.add_task_by_tgid(&CgroupPid::from(pid)) {
            return Err(Error::MemControllerSetFailed(e.to_string()));
        }
        Ok(Cgroups {
            config,
            thread: Mutex::new(None),
            running: Arc::new((Mutex::new(false), Condvar::new())),
            cgroup: cg,
        })
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

        let environment_config = self.config.clone();
        let running = self.running.clone();
        let mut last_cpu = 0;
        let mut last_memory = 0;
        let cgroup = self.cgroup.clone();
        let thread = thread::spawn(move || {
            loop {
                let environment = environment_config.load();
                let max_cpus = environment.max_cpus;
                let max_memory = environment.max_memory;
                if max_cpus != last_cpu || max_memory != last_memory {
                    if let Err(e) = Self::apply(cgroup.clone(), max_cpus, max_memory) {
                        warn!("apply cgroup resource failed, {:?}, agent restart...", e);
                        thread::sleep(Duration::from_secs(1));
                        process::exit(1);
                    }
                }
                last_cpu = max_cpus;
                last_memory = max_memory;

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
            info!("cgroup controller exited");
        });

        self.thread.lock().unwrap().replace(thread);
        info!("cgroup controller started");
    }

    /// 更改资源限制
    pub fn apply(cgroup: Cgroup, max_cpus: u32, max_memory: u64) -> Result<(), Error> {
        let mut resources = Resources::default();
        let cpu_quota = max_cpus * DEFAULT_CPU_CFS_PERIOD_US;
        let cpu_resources = CpuResources {
            quota: Some(cpu_quota as i64),
            period: Some(DEFAULT_CPU_CFS_PERIOD_US as u64),
            ..Default::default()
        };
        resources.cpu = cpu_resources;

        let memory_resources = MemoryResources {
            memory_hard_limit: Some(max_memory as i64),
            ..Default::default()
        };
        resources.memory = memory_resources;
        if let Err(e) = cgroup.apply(&resources) {
            return Err(Error::ApplyResourcesFailed(e.to_string()));
        }
        Ok(())
    }

    /// 结束cgroup资源限制
    pub fn stop(&self) -> Result<(), Error> {
        let (stopped, timer) = &*self.running;
        {
            let mut stopped = stopped.lock().unwrap();
            if !*stopped {
                return Ok(());
            }
            *stopped = false;
        }
        timer.notify_one();

        if let Some(thread) = self.thread.lock().unwrap().take() {
            let _ = thread.join();
        }
        if let Err(e) = self.cgroup.delete() {
            return Err(Error::DeleteCgroupFailed(e.to_string()));
        }
        info!("cgroup controller stopped");
        Ok(())
    }
}
