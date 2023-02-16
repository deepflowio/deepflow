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

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, Weak,
    },
    time::Duration,
};

use arc_swap::access::Access;
use log::{debug, info, warn};
use sysinfo::{
    get_current_pid, NetworkExt, Pid, ProcessExt, ProcessRefreshKind, System, SystemExt,
};

use crate::config::handler::EnvironmentAccess;
use crate::{
    error::{Error, Result},
    utils::{
        process::{get_current_sys_free_memory_percentage, get_file_and_size_sum},
        stats::{
            Collector, Countable, Counter, CounterType, CounterValue, RefCountable, StatsOption,
        },
    },
};
use public::utils::net::link_list;

#[derive(Default)]
struct NetMetricArg {
    pub rx: u64,
    pub tx: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub drop_in: u64,
    pub drop_out: u64,
}

#[derive(Default)]
struct NetMetric {
    rx: AtomicU64,
    tx: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    drop_in: AtomicU64,
    drop_out: AtomicU64,
}

struct LinkStatusBroker {
    running: AtomicBool,
    old: NetMetric,
    new: NetMetric,
}

impl LinkStatusBroker {
    pub fn new() -> Self {
        Self {
            running: AtomicBool::new(true),
            old: NetMetric::default(),
            new: NetMetric::default(),
        }
    }

    pub fn close(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub fn closed(&self) -> bool {
        !self.running.load(Ordering::Relaxed)
    }

    pub fn update(&self, new_metric: NetMetricArg) {
        let NetMetricArg {
            rx,
            tx,
            tx_bytes,
            rx_bytes,
            drop_in,
            drop_out,
        } = new_metric;
        self.new.rx.store(rx, Ordering::Relaxed);
        self.new.tx.store(tx, Ordering::Relaxed);
        self.new.rx_bytes.store(rx_bytes, Ordering::Relaxed);
        self.new.tx_bytes.store(tx_bytes, Ordering::Relaxed);
        self.new.drop_in.store(drop_in, Ordering::Relaxed);
        self.new.drop_out.store(drop_out, Ordering::Relaxed);
    }
}

impl RefCountable for LinkStatusBroker {
    fn get_counters(&self) -> Vec<Counter> {
        if !self.running.load(Ordering::SeqCst) {
            return vec![];
        }

        let mut metrics = vec![];
        let new_rx = self.new.rx.load(Ordering::Relaxed);
        let old_rx = self.old.rx.swap(new_rx, Ordering::Relaxed);
        metrics.push((
            "rx",
            CounterType::Counted,
            CounterValue::Unsigned(new_rx.overflowing_sub(old_rx).0),
        ));
        let new_tx = self.new.tx.load(Ordering::Relaxed);
        let old_tx = self.old.tx.swap(new_tx, Ordering::Relaxed);
        metrics.push((
            "tx",
            CounterType::Counted,
            CounterValue::Unsigned(new_tx.overflowing_sub(old_tx).0),
        ));
        let new_tx_bytes = self.new.tx_bytes.load(Ordering::Relaxed);
        let old_tx_bytes = self.old.tx_bytes.swap(new_tx_bytes, Ordering::Relaxed);
        metrics.push((
            "tx_bytes",
            CounterType::Counted,
            CounterValue::Unsigned(new_tx_bytes.overflowing_sub(old_tx_bytes).0),
        ));
        let new_rx_bytes = self.new.rx_bytes.load(Ordering::Relaxed);
        let old_rx_bytes = self.old.rx_bytes.swap(new_rx_bytes, Ordering::Relaxed);
        metrics.push((
            "rx_bytes",
            CounterType::Counted,
            CounterValue::Unsigned(new_rx_bytes.overflowing_sub(old_rx_bytes).0),
        ));
        let new_drop_in = self.new.drop_in.load(Ordering::Relaxed);
        let old_drop_in = self.old.drop_in.swap(new_drop_in, Ordering::Relaxed);
        metrics.push((
            "drop_in",
            CounterType::Counted,
            CounterValue::Unsigned(new_drop_in.overflowing_sub(old_drop_in).0),
        ));
        let new_drop_out = self.new.drop_out.load(Ordering::Relaxed);
        let old_drop_out = self.old.drop_out.swap(new_drop_out, Ordering::Relaxed);
        metrics.push((
            "drop_out",
            CounterType::Counted,
            CounterValue::Unsigned(new_drop_out.overflowing_sub(old_drop_out).0),
        ));

        metrics
    }
}

struct SysStatusBroker {
    system: Arc<Mutex<System>>,
    pid: Pid,
    create_time: Duration,
    log_dir: String,
    config: EnvironmentAccess,
}

impl SysStatusBroker {
    pub fn new(
        system: Arc<Mutex<System>>,
        log_dir: String,
        config: EnvironmentAccess,
    ) -> Result<Self> {
        let pid = get_current_pid().map_err(|e| Error::SysMonitor(String::from(e)))?;

        let create_time = {
            let mut system_guard = system.lock().unwrap();
            if !system_guard.refresh_process_specifics(pid, ProcessRefreshKind::new().with_cpu()) {
                return Err(Error::SysMonitor(format!(
                    "couldn't refresh process with pid({})",
                    pid
                )));
            }
            system_guard
                .process(pid)
                .map(|p| Duration::from_secs(p.start_time()))
                .ok_or(Error::SysMonitor(format!(
                    "couldn't get process start time with pid({})",
                    pid
                )))?
        };
        Ok(Self {
            system,
            pid,
            create_time,
            log_dir,
            config,
        })
    }
}

impl RefCountable for SysStatusBroker {
    fn get_counters(&self) -> Vec<Counter> {
        let mut system_guard = self.system.lock().unwrap();
        // 只有在进程不存在的时候会返回false，基本不会报错
        if !system_guard.refresh_process_specifics(self.pid, ProcessRefreshKind::new().with_cpu()) {
            warn!("refresh process failed, system status monitor has stopped");
            return vec![];
        }

        let mut metrics = vec![];
        let current_sys_free_memory_percentage = get_current_sys_free_memory_percentage();
        metrics.push((
            "sys_free_memory",
            CounterType::Gauged,
            CounterValue::Unsigned(current_sys_free_memory_percentage as u64),
        ));

        metrics.push((
            "max_memory",
            CounterType::Gauged,
            CounterValue::Unsigned(self.config.load().max_memory as u64),
        ));
        metrics.push((
            "max_cpus",
            CounterType::Gauged,
            CounterValue::Unsigned(self.config.load().max_cpus as u64),
        ));
        metrics.push((
            "system_free_memory_limit",
            CounterType::Gauged,
            CounterValue::Unsigned(self.config.load().sys_free_memory_limit as u64),
        ));

        match get_file_and_size_sum(self.log_dir.clone()) {
            Ok(file_and_size_sum) => {
                metrics.push((
                    "log_file_size_sum",
                    CounterType::Gauged,
                    CounterValue::Unsigned(file_and_size_sum.file_sizes_sum),
                ));
                metrics.push((
                    "log_file_amount",
                    CounterType::Gauged,
                    CounterValue::Unsigned(file_and_size_sum.file_infos.len() as u64),
                ));
            }
            Err(e) => {
                warn!("get file and size sum failed: {:?}", e);
            }
        }
        match system_guard.process(self.pid) {
            Some(process) => {
                let cpu_usage = process.cpu_usage() as f64;
                let mem_used = process.memory(); // in bytes

                metrics.push((
                    "cpu_percent",
                    CounterType::Gauged,
                    CounterValue::Float(cpu_usage),
                ));
                metrics.push((
                    "memory",
                    CounterType::Gauged,
                    CounterValue::Unsigned(mem_used),
                ));
                metrics.push((
                    "create_time",
                    CounterType::Gauged,
                    CounterValue::Unsigned(self.create_time.as_millis() as u64),
                ));
            }
            None => {
                warn!("get process data failed, system status monitor has stopped");
            }
        }
        metrics
    }
}

struct SysLoad(Arc<Mutex<System>>);

impl RefCountable for SysLoad {
    fn get_counters(&self) -> Vec<Counter> {
        let mut sys = self.0.lock().unwrap();
        sys.refresh_cpu();
        vec![(
            "load1",
            CounterType::Gauged,
            CounterValue::Float(sys.load_average().one),
        )]
    }
}

pub struct Monitor {
    stats: Arc<Collector>,
    running: AtomicBool,
    sys_monitor: Arc<SysStatusBroker>,
    sys_load: Arc<SysLoad>,
    link_map: Arc<Mutex<HashMap<String, Arc<LinkStatusBroker>>>>,
    system: Arc<Mutex<System>>,
}

impl Monitor {
    pub fn new(stats: Arc<Collector>, log_dir: String, config: EnvironmentAccess) -> Result<Self> {
        let mut system = System::new();
        system.refresh_cpu();
        let system = Arc::new(Mutex::new(system));

        Ok(Self {
            stats,
            running: AtomicBool::new(false),
            sys_monitor: Arc::new(SysStatusBroker::new(
                system.clone(),
                log_dir,
                config.clone(),
            )?),
            sys_load: Arc::new(SysLoad(system.clone())),
            link_map: Arc::new(Mutex::new(HashMap::new())),
            system,
        })
    }

    pub fn start(&self) {
        if self.running.swap(true, Ordering::Relaxed) {
            debug!("monitor has already started");
            return;
        }

        // register network hook
        let stats = self.stats.clone();
        let system = self.system.clone();
        let link_map = self.link_map.clone();
        self.stats.register_pre_hook(Box::new(move || {
            let mut link_map_guard = link_map.lock().unwrap();

            // resolve network interface update
            let links = match link_list() {
                Ok(links) => links,
                Err(e) => {
                    warn!("get interface list error: {}", e);
                    return;
                }
            };

            let mut system_guard = system.lock().unwrap();
            let mut del_monitor_list = vec![];
            link_map_guard.retain(|name, broker| {
                let exist = links.iter().any(|link| link.name == name.as_str());
                if !exist {
                    // 通知 stats模块Collector关闭对应broker
                    broker.close();
                }
                let is_retain = exist && !broker.closed();
                if !is_retain {
                    del_monitor_list.push(name.clone());
                }
                is_retain
            });
            if !del_monitor_list.is_empty() {
                debug!("removing monitor interface list: {:?}", del_monitor_list);
            }

            let mut monitor_list = vec![];
            for link in links {
                if link_map_guard.contains_key(&link.name) {
                    continue;
                }
                let link_broker = Arc::new(LinkStatusBroker::new());
                let mut options = vec![];
                options.push(StatsOption::Tag("name", link.name.clone()));
                options.push(StatsOption::Tag("mac", link.mac_addr.to_string()));
                stats.register_countable(
                    "net",
                    Countable::Ref(Arc::downgrade(&link_broker) as Weak<dyn RefCountable>),
                    options,
                );
                link_map_guard.insert(link.name.clone(), link_broker);
                monitor_list.push(link.name);
            }

            if !monitor_list.is_empty() {
                debug!("adding new monitor interface list: {:?}", monitor_list);
            }

            system_guard.refresh_networks_list();
            for (interface, net_data) in system_guard.networks() {
                if let Some(broker) = link_map_guard.get(interface) {
                    let metric = NetMetricArg {
                        rx: net_data.total_packets_received(),
                        tx: net_data.total_packets_transmitted(),
                        rx_bytes: net_data.total_received(),
                        tx_bytes: net_data.total_transmitted(),
                        drop_in: net_data.total_errors_on_received(),
                        drop_out: net_data.total_errors_on_transmitted(),
                    };
                    broker.update(metric);
                }
            }
        }));

        self.stats.register_countable(
            "monitor",
            Countable::Ref(Arc::downgrade(&self.sys_monitor) as Weak<dyn RefCountable>),
            vec![],
        );

        self.stats.register_countable(
            "system",
            Countable::Ref(Arc::downgrade(&self.sys_load) as Weak<dyn RefCountable>),
            vec![],
        );

        info!("monitor started");
    }

    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            debug!("monitor has already stopped");
            return;
        }
        // tear down
        self.link_map
            .lock()
            .unwrap()
            .drain()
            .for_each(|(_, broker)| broker.close());
        info!("monitor stopped");
    }
}
