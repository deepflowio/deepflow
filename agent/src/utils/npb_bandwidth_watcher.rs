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

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{
    atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering::Relaxed},
    Arc, Mutex, RwLock,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use log::{error, info, warn};
use strum::{Display, EnumString};
use sysinfo::{NetworkExt, Pid, PidExt, ProcessExt, ProcessRefreshKind, System, SystemExt};

use crate::common::platform_data::PlatformData;
use crate::common::policy::{Acl, Cidr, IpGroupData, PeerConnection};
use crate::common::{FlowAclListener, FlowAclListenerId};
use crate::config::SelfLoadCircuitBreaker;
use crate::exception::ExceptionHandler;
use crate::utils::stats::{Counter, CounterType, CounterValue, RefCountable};
use npb_pcap_policy::{NpbTunnelType, NOT_SUPPORT};
use public::proto::agent::{AgentType, Exception};
use public::utils::net::get_route_src_ip_interface_name;
use public::LeakyBucket;

#[derive(Default)]
pub struct InterfaceTraffic {
    tx_bps: AtomicU64,
    cpu_percent: AtomicU8,
    memory_percent: AtomicU8,
    queue_percent: AtomicU8,
    fuse_count: AtomicU64,
}

impl RefCountable for InterfaceTraffic {
    fn get_counters(&self) -> Vec<Counter> {
        vec![
            (
                "tx_bps",
                CounterType::Counted,
                CounterValue::Unsigned(self.tx_bps.swap(0, Relaxed)),
            ),
            (
                "cpu_percent",
                CounterType::Gauged,
                CounterValue::Unsigned(self.cpu_percent.load(Relaxed) as u64),
            ),
            (
                "memory_percent",
                CounterType::Gauged,
                CounterValue::Unsigned(self.memory_percent.load(Relaxed) as u64),
            ),
            (
                "queue_percent",
                CounterType::Gauged,
                CounterValue::Unsigned(self.queue_percent.load(Relaxed) as u64),
            ),
            (
                "fuse_count",
                CounterType::Counted,
                CounterValue::Unsigned(self.fuse_count.swap(0, Relaxed)),
            ),
        ]
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, Display, EnumString)]
enum Reason {
    Bandwidth,
    Cpu,
    Memory,
    Queue,
}
struct Watcher {
    // the unit is bites per secend
    nic_bps_threshold: AtomicU64,
    npb_bps_threshold: AtomicU64,
    // the unit is second
    interval: AtomicU64,

    traffic_count: Arc<InterfaceTraffic>,

    nic_name: RwLock<String>,
    ips: RwLock<Vec<IpAddr>>,

    lock: Arc<Mutex<()>>,
    npb_leaky_bucket: Arc<LeakyBucket>,
    exception_handler: ExceptionHandler,
    is_running: AtomicBool,

    messages: Arc<Mutex<HashMap<Reason, String>>>,
    system: Arc<Mutex<System>>,
    self_load: Arc<RwLock<SelfLoadCircuitBreaker>>,
    memory_limit: AtomicU64,
    cpu_limit: AtomicU32,

    npb_queues: Arc<RwLock<HashMap<usize, Arc<dyn Fn() -> u8 + Send + Sync>>>>,
}

impl Watcher {
    const CHECK_CYCLES: usize = 5;

    fn get_nic_name(&self) -> String {
        let ips = self.ips.read().unwrap().clone();
        let mut last_nic_name = self.nic_name.write().unwrap();
        if !last_nic_name.to_string().is_empty() {
            return last_nic_name.to_string();
        }
        for remote in &ips {
            if let Ok(nic_name) = get_route_src_ip_interface_name(remote) {
                *last_nic_name = nic_name.clone();
                info!(
                    "Npb bandwidth watcher is monitoring {} by {}.",
                    &nic_name, remote
                );
                return nic_name;
            }
        }

        String::new()
    }

    fn get_nic_tx_bytes(&self, nic_name: String) -> Result<u64, bool> {
        let mut system = self.system.lock().unwrap();
        system.refresh_networks_list();
        for (iface_name, stats) in system.networks() {
            if *iface_name == nic_name {
                return Ok(stats.total_transmitted() as u64);
            }
        }
        Err(false)
    }

    fn get_nic_bps(&self, last_tx_bytes: &mut u64, interval: u64) -> Result<u64, bool> {
        let nic_name = self.get_nic_name();
        if nic_name.is_empty() {
            *last_tx_bytes = 0;
            return Err(false);
        }
        let Ok(tx_bytes) = self.get_nic_tx_bytes(nic_name) else {
            error!("Npb bandwidth watcher get tx bytes failed.");
            *last_tx_bytes = 0;
            return Err(false);
        };

        let tx_bps = if tx_bytes >= *last_tx_bytes && *last_tx_bytes != 0 {
            ((tx_bytes - *last_tx_bytes) * 8) / interval
        } else {
            0
        };
        *last_tx_bytes = tx_bytes;
        return Ok(tx_bps);
    }

    fn joined_messages(&self) -> String {
        let messages = self.messages.lock().unwrap();
        messages
            .values()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn stop_npb(&self, reason: Reason, description: String) {
        let _lock = self.lock.lock().unwrap();
        let result = {
            let mut messages = self.messages.lock().unwrap();
            if messages.contains_key(&reason) {
                return;
            }
            messages.insert(reason, description);
            messages
                .values()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        self.npb_leaky_bucket.set_rate(Some(1));
        self.traffic_count.fuse_count.fetch_add(1, Relaxed);
        self.exception_handler.set(Exception::NpbFuse, Some(result));
    }

    fn try_start_npb(&self, reason: Reason) {
        let _lock = self.lock.lock().unwrap();
        let reopened = {
            let mut messages = self.messages.lock().unwrap();
            if messages.remove(&reason).is_none() {
                return;
            }
            messages.is_empty()
        };

        info!("Npb try to reopened due to {} recovery.", reason);
        if reopened {
            self.exception_handler.clear(Exception::NpbFuse);
            self.npb_leaky_bucket
                .set_rate(Some(self.npb_bps_threshold.load(Relaxed)));
        } else {
            self.exception_handler
                .set(Exception::NpbFuse, Some(self.joined_messages()));
        }
    }

    fn get_cpu_percentage(&self) -> Option<u8> {
        let mut system = self.system.lock().unwrap();
        let current_pid = std::process::id();
        let pid = Pid::from_u32(current_pid);
        if !system.refresh_process_specifics(pid, ProcessRefreshKind::everything()) {
            return None;
        }
        let Some(process) = system.process(pid) else {
            return None;
        };
        let cpu_usage = process.cpu_usage();
        let cpu_limit = self.cpu_limit.load(Relaxed);

        Some((cpu_usage as f64 * 10.0 / cpu_limit as f64 * 100.0).min(100.0) as u8)
    }

    fn get_memory_percentage(&self) -> Option<u8> {
        let mut system = self.system.lock().unwrap();
        let current_pid = std::process::id();
        let pid = Pid::from_u32(current_pid);
        if !system.refresh_process_specifics(pid, ProcessRefreshKind::everything()) {
            return None;
        }
        let Some(process) = system.process(pid) else {
            return None;
        };
        let used_memory = process.memory();
        let memory_limit = self.memory_limit.load(Relaxed);

        Some(((used_memory as f64 / memory_limit as f64) * 100.0).min(100.0) as u8)
    }

    fn get_npb_queue_usage(&self) -> u8 {
        let npb_queues = self.npb_queues.read().unwrap();
        let mut max_usage = 0;
        for f in npb_queues.values() {
            let usage = f();
            if usage > max_usage {
                max_usage = usage;
            }
        }
        max_usage
    }

    fn run_self_load(&self) {
        let mut cpu_trigger_counter = 0u8;
        let mut cpu_recover_counter = 0u8;
        let mut mem_trigger_counter = 0u8;
        let mut mem_recover_counter = 0u8;
        let mut queue_trigger_counter = 0u8;
        let mut queue_recover_counter = 0u8;
        let mut last_config = self.self_load.read().unwrap().clone();

        while self.is_running.load(Relaxed) {
            let config = {
                let config = self.self_load.read().unwrap().clone();
                if config != last_config {
                    cpu_trigger_counter = 0;
                    cpu_recover_counter = 0;
                    mem_trigger_counter = 0;
                    mem_recover_counter = 0;
                    queue_trigger_counter = 0;
                    queue_recover_counter = 0;
                    last_config = config.clone();
                }

                config
            };

            thread::sleep(config.monitoring_interval);

            if !config.enabled {
                self.try_start_npb(Reason::Cpu);
                self.try_start_npb(Reason::Memory);
                self.try_start_npb(Reason::Queue);
                continue;
            }

            if config.cpu.enabled {
                let Some(cpu) = self.get_cpu_percentage() else {
                    info!("Npb watcher get cpu percentage failed.");
                    continue;
                };
                self.traffic_count.cpu_percent.store(cpu, Relaxed);
                if cpu >= config.cpu.trigger_threshold {
                    cpu_trigger_counter = cpu_trigger_counter.saturating_add(1);
                    cpu_recover_counter = 0;
                    if cpu_trigger_counter == config.trigger_times {
                        self.stop_npb(
                            Reason::Cpu,
                            format!("CPU({} > {})", cpu, config.cpu.trigger_threshold),
                        );
                        warn!(
                            "Npb watcher cpu usage is {}%, which exceeds the threshold of {}%.",
                            cpu, config.cpu.trigger_threshold
                        );
                    }
                } else if cpu < config.cpu.recovery_threshold {
                    cpu_recover_counter = cpu_recover_counter.saturating_add(1);
                    cpu_trigger_counter = 0;
                    if cpu_recover_counter >= config.recovery_times {
                        self.try_start_npb(Reason::Cpu);
                    }
                } else {
                    cpu_recover_counter = 0;
                    cpu_trigger_counter = 0;
                }
            } else {
                self.try_start_npb(Reason::Cpu);
            }

            if config.memory.enabled {
                let Some(memory) = self.get_memory_percentage() else {
                    info!("Npb watcher get memory percentage failed.");
                    continue;
                };
                self.traffic_count.memory_percent.store(memory, Relaxed);
                if memory >= config.memory.trigger_threshold {
                    mem_trigger_counter = mem_trigger_counter.saturating_add(1);
                    mem_recover_counter = 0;
                    if mem_trigger_counter == config.trigger_times {
                        self.stop_npb(
                            Reason::Memory,
                            format!("Memory({} > {})", memory, config.memory.trigger_threshold),
                        );
                        warn!(
                            "Npb watcher memory usage is {}%, which exceeds the threshold of {}%.",
                            memory, config.memory.trigger_threshold
                        );
                    }
                } else if memory < config.memory.recovery_threshold {
                    mem_recover_counter = mem_recover_counter.saturating_add(1);
                    mem_trigger_counter = 0;
                    if mem_recover_counter >= config.recovery_times {
                        self.try_start_npb(Reason::Memory);
                    }
                } else {
                    mem_recover_counter = 0;
                    mem_trigger_counter = 0;
                }
            } else {
                self.try_start_npb(Reason::Memory);
            }

            if config.queue.enabled {
                let queue_usage = self.get_npb_queue_usage();
                self.traffic_count.queue_percent.store(queue_usage, Relaxed);
                if queue_usage >= config.queue.trigger_threshold {
                    queue_trigger_counter = queue_trigger_counter.saturating_add(1);
                    queue_recover_counter = 0;
                    if queue_trigger_counter == config.trigger_times {
                        self.stop_npb(
                            Reason::Queue,
                            format!(
                                "Queue({}% > {}%)",
                                queue_usage, config.queue.trigger_threshold
                            ),
                        );
                        warn!(
                            "Npb watcher queue usage is {}%, which exceeds the threshold of {}%.",
                            queue_usage, config.queue.trigger_threshold
                        );
                    }
                } else if queue_usage < config.queue.recovery_threshold {
                    queue_recover_counter = queue_recover_counter.saturating_add(1);
                    queue_trigger_counter = 0;
                    if queue_recover_counter >= config.recovery_times {
                        self.try_start_npb(Reason::Queue);
                    }
                } else {
                    queue_recover_counter = 0;
                    queue_trigger_counter = 0;
                }
            } else {
                self.try_start_npb(Reason::Queue);
            }
        }
    }

    fn run(&self) {
        let mut last_tx_bytes = 0;
        let mut npb_is_closed = false;
        let mut cycles = 0;
        let mut first = true;
        while self.is_running.load(Relaxed) {
            thread::sleep(Duration::from_secs(self.interval.load(Relaxed)));

            let interval = self.interval.load(Relaxed);
            let nic_bps_threshold = self.nic_bps_threshold.load(Relaxed);
            let Ok(tx_bps) = self.get_nic_bps(&mut last_tx_bytes, interval) else {
                self.traffic_count.tx_bps.store(0, Relaxed);
                continue;
            };
            if first && last_tx_bytes != 0 {
                first = false;
                continue;
            }
            self.traffic_count.tx_bps.store(tx_bps, Relaxed);

            if nic_bps_threshold == 0 {
                if npb_is_closed {
                    self.try_start_npb(Reason::Bandwidth);
                    npb_is_closed = false;
                }
                continue;
            }

            if tx_bps > nic_bps_threshold {
                if !npb_is_closed {
                    self.stop_npb(
                        Reason::Bandwidth,
                        format!("Bandwidth({} > {})", tx_bps, nic_bps_threshold),
                    );
                    warn!(
                        "Npb had fused {} tx bandwidth is {} bps.",
                        self.get_nic_name(),
                        tx_bps
                    );
                    npb_is_closed = true;
                }
            } else {
                let npb_bps_threshold = self.npb_bps_threshold.load(Relaxed);
                if nic_bps_threshold <= npb_bps_threshold {
                    continue;
                }
                if tx_bps < (nic_bps_threshold - npb_bps_threshold) * 90 / 100 {
                    if npb_is_closed {
                        cycles += 1;
                        if cycles >= Self::CHECK_CYCLES {
                            self.try_start_npb(Reason::Bandwidth);
                            npb_is_closed = false;
                            cycles = 0;
                        }
                    } else {
                        cycles = 0;
                    }
                } else {
                    cycles = 0;
                }
            }
        }
    }
}

pub struct NpbBandwidthWatcher {
    watcher: Arc<Watcher>,
    thread_handlers: Mutex<Option<Vec<JoinHandle<()>>>>,
    exception_handler: ExceptionHandler,
}

impl NpbBandwidthWatcher {
    const BANDWIDTH_DEFAULT: u64 = 0;
    const BANDWIDTH_MAX: u64 = 100_000_000_000; // 100 Gbps
    const INTERVAL_DEFAULT: u64 = 10;
    const INTERVAL_MIN: u64 = 1;
    const INTERVAL_MAX: u64 = 60;

    pub fn new(
        interval: u64,
        npb_bps_threshold: u64,
        nic_bps_threshold: u64,
        cpu_limit: u32,
        memory_limit: u64,
        self_load: SelfLoadCircuitBreaker,
        npb_leaky_bucket: Arc<LeakyBucket>,
        exception_handler: ExceptionHandler,
    ) -> (Arc<Self>, Arc<InterfaceTraffic>) {
        let traffic_count = Arc::new(InterfaceTraffic::default());

        (
            Arc::new(Self {
                watcher: Arc::new(Watcher {
                    nic_bps_threshold: AtomicU64::new(nic_bps_threshold),
                    npb_bps_threshold: AtomicU64::new(npb_bps_threshold),
                    interval: AtomicU64::new(interval),
                    ips: RwLock::new(vec![]),
                    npb_leaky_bucket,
                    nic_name: RwLock::new("".to_string()),
                    is_running: AtomicBool::new(false),
                    traffic_count: traffic_count.clone(),
                    exception_handler: exception_handler.clone(),
                    self_load: Arc::new(RwLock::new(self_load)),
                    system: Arc::new(Mutex::new(System::new())),
                    memory_limit: AtomicU64::new(memory_limit),
                    cpu_limit: AtomicU32::new(cpu_limit),
                    messages: Arc::new(Mutex::new(HashMap::new())),
                    npb_queues: Arc::new(RwLock::new(HashMap::new())),
                    lock: Arc::new(Mutex::new(())),
                }),
                thread_handlers: Mutex::new(None),
                exception_handler,
            }),
            traffic_count,
        )
    }

    pub fn set_npb_rate(&self, threshold: u64) {
        self.watcher.npb_bps_threshold.store(threshold, Relaxed);
        // When there is Exception::NpbFuse, npb_leaky_bucket cannot be
        // set in order to not distribute traffic packet.
        if !self.exception_handler.has(Exception::NpbFuse) {
            self.watcher.npb_leaky_bucket.set_rate(Some(threshold));
        }
    }

    pub fn set_nic_rate(&self, mut threshold: u64) {
        if threshold > Self::BANDWIDTH_MAX {
            info!(
                "Invalid npb bandwidth threshold {} set to default value {}",
                threshold,
                Self::BANDWIDTH_DEFAULT
            );
            threshold = Self::BANDWIDTH_DEFAULT
        }

        self.watcher.nic_bps_threshold.store(threshold, Relaxed);
    }

    pub fn set_interval(&self, mut interval: u64) {
        if interval < Self::INTERVAL_MIN || interval > Self::INTERVAL_MAX {
            info!(
                "Invalid interval {} set to default value {}",
                interval,
                Self::INTERVAL_DEFAULT
            );
            interval = Self::INTERVAL_DEFAULT;
        }
        self.watcher.interval.store(interval, Relaxed);
    }

    pub fn set_cpu_limit(&self, limit: u32) {
        self.watcher.cpu_limit.store(limit, Relaxed);
    }

    pub fn set_memory_limit(&self, limit: u64) {
        self.watcher.memory_limit.store(limit, Relaxed);
    }

    pub fn set_self_load_circuit_breaker(&self, self_load: SelfLoadCircuitBreaker) {
        *self.watcher.self_load.write().unwrap() = self_load;
    }

    pub fn add_npb_queue(&self, id: usize, f: Arc<dyn Fn() -> u8 + Send + Sync>) {
        self.watcher.npb_queues.write().unwrap().insert(id, f);
    }

    pub fn remove_npb_queue(&self, id: usize) {
        self.watcher.npb_queues.write().unwrap().remove(&id);
    }

    pub fn start(&self) {
        if self.watcher.is_running.load(Relaxed) || NOT_SUPPORT {
            return;
        }
        let watcher = self.watcher.clone();
        watcher.is_running.store(true, Relaxed);
        info!("Npb bandwidth watcher start with: npb bandwidth {}, npb nic bandwidth {}, interval {}, self_load {:?}.",
            watcher.npb_bps_threshold.load(Relaxed),
            watcher.nic_bps_threshold.load(Relaxed),
            watcher.interval.load(Relaxed),
            watcher.self_load,
        );

        let mut thread_handlers = vec![];
        thread_handlers.push(
            thread::Builder::new()
                .name("npb-bandwidth-watcher".to_owned())
                .spawn(move || {
                    watcher.run();
                })
                .unwrap(),
        );
        let watcher = self.watcher.clone();
        thread_handlers.push(
            thread::Builder::new()
                .name("npb-bandwidth-watcher-self-load".to_owned())
                .spawn(move || {
                    watcher.run_self_load();
                })
                .unwrap(),
        );
        self.thread_handlers
            .lock()
            .unwrap()
            .replace(thread_handlers);
    }

    pub fn notify_stop(&self) -> Option<Vec<JoinHandle<()>>> {
        if !self.watcher.is_running.load(Relaxed) || NOT_SUPPORT {
            return None;
        }
        self.watcher.is_running.store(false, Relaxed);
        info!("Notify npb bandwidth watcher stop.");
        self.thread_handlers.lock().unwrap().take()
    }

    pub fn stop(&self) {
        if !self.watcher.is_running.load(Relaxed) || NOT_SUPPORT {
            return;
        }
        self.watcher.is_running.store(false, Relaxed);
        if let Some(handlers) = self.thread_handlers.lock().unwrap().take() {
            for handler in handlers {
                let _ = handler.join();
            }
        }
        info!("Npb bandwidth watcher stop.");
    }
}

impl FlowAclListener for Arc<NpbBandwidthWatcher> {
    fn flow_acl_change(
        &mut self,
        _agent_type: AgentType,
        _local_epc: i32,
        _ip_groups: &Vec<Arc<IpGroupData>>,
        _platform_data: &Vec<Arc<PlatformData>>,
        _peers: &Vec<Arc<PeerConnection>>,
        _cidrs: &Vec<Arc<Cidr>>,
        acls: &Vec<Arc<Acl>>,
        _: bool,
        _: &mut bool,
    ) -> Result<(), String> {
        if NOT_SUPPORT {
            return Ok(());
        }

        let mut ips = vec![];
        acls.iter().for_each(|x| {
            for action in &x.npb_actions {
                if action.tunnel_type() == NpbTunnelType::GreErspan
                    || action.tunnel_type() == NpbTunnelType::VxLan
                {
                    ips.push(action.tunnel_ip());
                }
            }
        });
        ips.sort();
        ips.dedup();
        let mut last_ips = self.watcher.ips.write().unwrap();
        if last_ips.len() != ips.len() || !ips.iter().zip(last_ips.iter()).all(|x| x.0 == x.1) {
            *last_ips = ips;
            *self.watcher.nic_name.write().unwrap() = "".to_string();
        }
        Ok(())
    }

    fn id(&self) -> usize {
        u16::from(FlowAclListenerId::NpbBandWatcher) as usize
    }
}
