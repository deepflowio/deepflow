use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use log::{debug, info, warn};
use sysinfo::{
    get_current_pid, NetworkExt, Pid, ProcessExt, ProcessRefreshKind, System, SystemExt,
};

use crate::{
    error::{Error, Result},
    utils::{
        net::link_list,
        stats::{Collector, Countable, Counter, CounterType, CounterValue, StatsOption},
    },
};

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

impl Countable for LinkStatusBroker {
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

    fn closed(&self) -> bool {
        !self.running.load(Ordering::Relaxed)
    }
}

struct SysStatusBroker {
    running: AtomicBool,
    system: Arc<Mutex<System>>,
    pid: Pid,
    create_time: Duration,
    core_count: usize,
}

impl SysStatusBroker {
    pub fn new(system: Arc<Mutex<System>>) -> Result<Self> {
        let pid = get_current_pid().map_err(|e| Error::SysMonitor(String::from(e)))?;
        let core_count = system
            .lock()
            .unwrap()
            .physical_core_count()
            .ok_or(Error::SysMonitor(format!(
                "couldn't get physical core count with pid({})",
                pid
            )))?;

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
            core_count,
            create_time,
            running: AtomicBool::new(false),
        })
    }

    pub fn close(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

impl Countable for SysStatusBroker {
    fn get_counters(&self) -> Vec<Counter> {
        if !self.running.load(Ordering::Relaxed) {
            return vec![];
        }
        let mut system_guard = self.system.lock().unwrap();
        // 只有在进程不存在的时候会返回false，基本不会报错
        if !system_guard.refresh_process_specifics(self.pid, ProcessRefreshKind::new().with_cpu()) {
            self.running.store(false, Ordering::Relaxed);
            warn!("refresh process failed, system status monitor has stopped");
            return vec![];
        }

        match system_guard.process(self.pid) {
            Some(process) => {
                let cpu_usage = process.cpu_usage() as f64 / self.core_count as f64;
                let mem_used = process.memory() << 10;

                let mut metrics = vec![];
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
                metrics
            }
            None => {
                self.running.store(false, Ordering::SeqCst);
                warn!("get process data failed, system status monitor has stopped");
                vec![]
            }
        }
    }

    fn closed(&self) -> bool {
        !self.running.load(Ordering::Relaxed)
    }
}

pub struct Monitor {
    stats: Arc<Collector>,
    running: AtomicBool,
    sys_monitor: Arc<SysStatusBroker>,
    link_map: Arc<Mutex<HashMap<String, Arc<LinkStatusBroker>>>>,
    system: Arc<Mutex<System>>,
}

impl Monitor {
    pub fn new(stats: Arc<Collector>) -> Result<Self> {
        let system = Arc::new(Mutex::new(System::new()));

        Ok(Self {
            stats,
            running: AtomicBool::new(false),
            sys_monitor: Arc::new(SysStatusBroker::new(system.clone())?),
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
            if link_map_guard.is_empty() {
                return;
            }

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
                stats.register_countable("net", link_broker.clone(), options);
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

        self.stats
            .register_countable("monitor", self.sys_monitor.clone(), vec![]);

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
        self.sys_monitor.close();
        info!("monitor stopped");
    }
}
