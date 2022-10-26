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
        atomic::{AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use log::{debug, info, log_enabled, warn, Level};

use super::Poller;
use public::netns::{InterfaceInfo, NetNs, NsFile};

#[derive(Debug, Default)]
pub struct ActivePoller {
    interval: Duration,
    version: Arc<AtomicU64>,
    entries: Arc<Mutex<HashMap<NsFile, Vec<InterfaceInfo>>>>,
    netns: Arc<Mutex<Vec<NsFile>>>,
    running: Arc<Mutex<bool>>,
    timer: Arc<Condvar>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl ActivePoller {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            version: Default::default(),
            entries: Default::default(),
            netns: Default::default(),
            running: Default::default(),
            timer: Default::default(),
            thread: Default::default(),
        }
    }

    fn query(ns: &Vec<NsFile>) -> HashMap<NsFile, Vec<InterfaceInfo>> {
        let mut net_ns = NetNs::default();
        let mut map = HashMap::new();

        // always query root ns (/proc/1/ns/net)
        let mut ns_files = vec![&NsFile::Root];
        ns_files.extend(ns);

        // for restore
        let current_ns = NetNs::open_current_ns();
        if let Err(e) = current_ns {
            warn!("get self net namespace failed: {:?}", e);
            return map;
        }
        let current_ns = current_ns.unwrap();

        for ns in ns_files {
            match net_ns.get_ns_interfaces(ns) {
                Ok(mut ifs) => {
                    ifs.sort_unstable();
                    map.insert(ns.clone(), ifs);
                }
                Err(e) => warn!("get interfaces failed for {:?}: {:?}", ns, e),
            }
        }

        if let Err(e) = NetNs::setns(&current_ns) {
            warn!("restore net namespace failed: {}", e);
        }
        map
    }

    fn process(
        timer: Arc<Condvar>,
        running: Arc<Mutex<bool>>,
        version: Arc<AtomicU64>,
        entries: Arc<Mutex<HashMap<NsFile, Vec<InterfaceInfo>>>>,
        netns: Arc<Mutex<Vec<NsFile>>>,
        timeout: Duration,
    ) {
        // 初始化
        let re = netns.lock().unwrap();
        *entries.lock().unwrap() = Self::query(&re);
        drop(re);
        version.store(1, Ordering::SeqCst);

        loop {
            let guard = running.lock().unwrap();
            if !*guard {
                break;
            }
            let (guard, _) = timer.wait_timeout(guard, timeout).unwrap();
            if !*guard {
                break;
            }
            drop(guard);

            let re = netns.lock().unwrap().clone();
            let new_interface_info = Self::query(&re);
            // compare two lists
            let mut old_interface_info = entries.lock().unwrap();
            if old_interface_info.eq(&new_interface_info) {
                continue;
            }

            *old_interface_info = new_interface_info;
            version.fetch_add(1, Ordering::SeqCst);
            info!(
                "kubernetes poller updated to version ({})",
                version.load(Ordering::SeqCst)
            );
            if log_enabled!(Level::Debug) {
                for ns in old_interface_info.values() {
                    for entry in ns {
                        debug!("{}", entry);
                    }
                }
            }
        }
    }
}

impl Poller for ActivePoller {
    fn get_version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }

    fn get_interface_info_in(&self, ns: &NsFile) -> Option<Vec<InterfaceInfo>> {
        self.entries.lock().unwrap().get(&ns).map(|e| e.clone())
    }

    fn get_interface_info(&self) -> Vec<InterfaceInfo> {
        let mut info = vec![];
        for v in self.entries.lock().unwrap().values() {
            info.extend(v.clone());
        }
        info
    }

    fn set_netns(&self, ns: Vec<NsFile>) {
        info!("poller monitoring netns: {:?}", ns);
        *self.netns.lock().unwrap() = ns;
    }

    fn start(&self) {
        {
            let mut running_guard = self.running.lock().unwrap();
            if *running_guard {
                debug!("ActivePoller has already running");
                return;
            }
            *running_guard = true;
        }

        info!("starts kubernetes active poller");
        let entries = self.entries.clone();
        let netns = self.netns.clone();
        let running = self.running.clone();
        let version = self.version.clone();
        let timeout = self.interval;
        let timer = self.timer.clone();

        let handle =
            thread::spawn(move || Self::process(timer, running, version, entries, netns, timeout));
        self.thread.lock().unwrap().replace(handle);
    }

    fn stop(&self) {
        {
            let mut running_lock = self.running.lock().unwrap();
            if !*running_lock {
                debug!("ActivePoller has already stopped");
                return;
            }
            *running_lock = false;
        }

        self.timer.notify_one();
        if let Some(handle) = self.thread.lock().unwrap().take() {
            handle.join().expect("cannot wait thread");
        }
        info!("stops kubernetes poller");
    }
}
