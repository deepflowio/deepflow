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
    collections::{hash_map::Entry, HashMap},
    process,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use log::{debug, info, log_enabled, trace, warn, Level};
use regex::Regex;

use super::Poller;
use public::{
    consts::NORMAL_EXIT_WITH_RESTART,
    netns::{InterfaceInfo, NetNs, NsFile},
};

const ENTRY_EXPIRE_COUNT: u8 = 3;

#[derive(Debug, Default)]
pub struct ActivePoller {
    interval: Duration,
    version: Arc<AtomicU64>,
    entries: Arc<Mutex<HashMap<NsFile, Vec<InterfaceInfo>>>>,
    netns_regex: Arc<Mutex<Option<Regex>>>,
    running: Arc<Mutex<bool>>,
    timer: Arc<Condvar>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl ActivePoller {
    pub fn new(interval: Duration, netns_regex: Option<Regex>) -> Self {
        Self {
            interval,
            version: Default::default(),
            entries: Default::default(),
            netns_regex: Arc::new(Mutex::new(netns_regex)),
            running: Default::default(),
            timer: Default::default(),
            thread: Default::default(),
        }
    }

    fn query(ns: &Vec<NsFile>) -> HashMap<NsFile, Vec<InterfaceInfo>> {
        // always query root ns (/proc/1/ns/net)
        let mut ns_files = vec![NsFile::Root];
        ns_files.extend(ns.clone());

        match NetNs::interfaces_linked_with(&ns_files) {
            Ok(mut map) => {
                for (_, v) in map.iter_mut() {
                    v.sort_unstable();
                }
                map
            }
            Err(e) => {
                warn!("query namespace interfaces failed: {:?}", e);
                HashMap::new()
            }
        }
    }

    fn process(
        timer: Arc<Condvar>,
        running: Arc<Mutex<bool>>,
        version: Arc<AtomicU64>,
        entries: Arc<Mutex<HashMap<NsFile, Vec<InterfaceInfo>>>>,
        netns_regex: Arc<Mutex<Option<Regex>>>,
        timeout: Duration,
    ) {
        // 初始化
        let mut nss = vec![NsFile::Root];
        if let Some(re) = &*netns_regex.lock().unwrap() {
            let mut extra_ns = NetNs::find_ns_files_by_regex(&re);
            extra_ns.sort_unstable();
            nss.extend(extra_ns);
        }
        let new_entries = Self::query(&nss);
        *entries.lock().unwrap() = new_entries;
        version.store(1, Ordering::SeqCst);
        info!("kubernetes poller updated to version (1)");

        // counter for entries in interface_info
        // if a namespace or a piece of interface info is missing in ENTRY_EXPIRE_COUNT consecutive queries
        // it will be removed from interface_info
        let mut absent_count = HashMap::new();

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

            let mut new_nss = vec![NsFile::Root];
            if let Some(re) = &*netns_regex.lock().unwrap() {
                let mut extra_ns = NetNs::find_ns_files_by_regex(&re);
                extra_ns.sort_unstable();
                new_nss.extend(extra_ns);
            }
            if nss != new_nss {
                info!("query net namespaces changed from {:?} to {:?}, restart agent to create dispatcher for extra namespaces", nss, new_nss);
                thread::sleep(Duration::from_secs(1));
                process::exit(NORMAL_EXIT_WITH_RESTART);
            }
            let mut new_interface_info = Self::query(&nss);
            // compare two lists
            let mut old_interface_info = entries.lock().unwrap();
            if old_interface_info.eq(&new_interface_info) {
                // everything refreshed, clear absent map
                absent_count.clear();
                continue;
            }

            // use old_interface_info to supply new info in case of query failure
            for (k, old_vs) in old_interface_info.iter() {
                match new_interface_info.entry(k.clone()) {
                    Entry::Vacant(v) => {
                        let retain = match absent_count.entry(k.clone()) {
                            Entry::Vacant(v) => {
                                v.insert((1, HashMap::new()));
                                trace!("interfaces in {:?} expire count is 1", k);
                                true
                            }
                            Entry::Occupied(o) => {
                                let r = o.into_mut();
                                r.0 += 1;
                                trace!("interfaces in {:?} expire count is {}", k, r.0);
                                r.0 < ENTRY_EXPIRE_COUNT
                            }
                        };
                        if retain {
                            v.insert(old_vs.to_vec());
                        } else {
                            debug!("interfaces in {:?} expired", k);
                        }
                    }
                    Entry::Occupied(o) => {
                        let new_vs = o.into_mut();

                        let mut absent =
                            absent_count.entry(k.clone()).or_insert((0, HashMap::new()));
                        absent.0 = 0;
                        // reset new interface absent count
                        for vs in new_vs.iter() {
                            absent.1.remove(&vs.tap_idx);
                        }

                        let mut to_insert = vec![];
                        for toi in old_vs.into_iter() {
                            let contains = new_vs
                                .binary_search_by_key(&toi.tap_idx, |v| v.tap_idx)
                                .is_ok();
                            if !contains {
                                let retain = match absent.1.entry(toi.tap_idx) {
                                    Entry::Vacant(v) => {
                                        v.insert(1);
                                        trace!("interfaces {:?} in {:?} expire count is 1", toi, k);
                                        true
                                    }
                                    Entry::Occupied(o) => {
                                        let r = o.into_mut();
                                        *r += 1;
                                        trace!(
                                            "interfaces {:?} in {:?} expire count is {}",
                                            toi,
                                            k,
                                            r
                                        );
                                        *r < ENTRY_EXPIRE_COUNT
                                    }
                                };
                                if retain {
                                    to_insert.push(toi.clone());
                                } else {
                                    debug!("interfaces {:?} in {:?} expired", toi, k);
                                }
                            }
                        }
                        new_vs.extend(to_insert);
                        new_vs.sort_unstable();
                    }
                }
            }

            // may be equal if merged
            if !old_interface_info.eq(&new_interface_info) {
                *old_interface_info = new_interface_info;
                version.fetch_add(1, Ordering::SeqCst);
                info!(
                    "kubernetes poller updated to version ({})",
                    version.load(Ordering::SeqCst)
                );
            }
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

    fn set_netns_regex(&self, ns: Option<Regex>) {
        *self.netns_regex.lock().unwrap() = ns;
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
        let netns_regex = self.netns_regex.clone();
        let running = self.running.clone();
        let version = self.version.clone();
        let timeout = self.interval;
        let timer = self.timer.clone();

        let handle = thread::Builder::new()
            .name("kubernetes-poller".to_owned())
            .spawn(move || Self::process(timer, running, version, entries, netns_regex, timeout))
            .unwrap();
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
