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

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use log::{debug, info, warn};
use regex::Regex;

use super::Poller;
use public::netns::{self, InterfaceInfo, NsFile};

const ENTRY_EXPIRE_COUNT: u8 = 3;

#[derive(Debug, Default)]
pub struct ActivePoller {
    interval: Duration,
    version: Arc<AtomicU64>,
    entries: Arc<Mutex<InterfaceInfoStore>>,
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
        let m = netns::interfaces_linked_with(&ns);
        if let Err(e) = m.as_ref() {
            warn!("query namespace interfaces failed: {:?}", e);
        }
        m.unwrap_or_default()
    }

    fn process(
        timer: Arc<Condvar>,
        running: Arc<Mutex<bool>>,
        version: Arc<AtomicU64>,
        entries: Arc<Mutex<InterfaceInfoStore>>,
        netns_regex: Arc<Mutex<Option<Regex>>>,
        timeout: Duration,
    ) {
        // 初始化
        // always query root ns (/proc/1/ns/net)
        let mut nss = vec![NsFile::Root];
        if let Some(re) = &*netns_regex.lock().unwrap() {
            let mut extra_ns = netns::find_ns_files_by_regex(&re);
            extra_ns.sort_unstable();
            nss.extend(extra_ns);
        }
        let new_entries = Self::query(&nss);
        entries.lock().unwrap().merge(new_entries);
        version.store(1, Ordering::SeqCst);
        info!("kubernetes poller updated to version (1)");

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

            // always query root ns (/proc/1/ns/net)
            let mut new_nss = vec![NsFile::Root];
            if let Some(re) = &*netns_regex.lock().unwrap() {
                let mut extra_ns = netns::find_ns_files_by_regex(&re);
                extra_ns.sort_unstable();
                new_nss.extend(extra_ns);
            }
            if nss != new_nss {
                info!(
                    "query net namespaces changed from {:?} to {:?}",
                    nss, new_nss
                );
                nss = new_nss;
            }
            let new_interface_info = Self::query(&nss);

            if entries.lock().unwrap().merge(new_interface_info) {
                version.fetch_add(1, Ordering::SeqCst);
                info!(
                    "kubernetes poller updated to version ({})",
                    version.load(Ordering::SeqCst)
                );
            }
        }
    }
}

impl Poller for ActivePoller {
    fn get_version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }

    fn get_interface_info_in(&self, ns: &NsFile) -> Option<Vec<InterfaceInfo>> {
        self.entries.lock().unwrap().get(&ns)
    }

    fn get_interface_info(&self) -> Vec<InterfaceInfo> {
        self.entries.lock().unwrap().get_all()
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

#[derive(Debug)]
struct NsEntry {
    // field.1 of info and expire_count are expiring counter for entries in interface_info
    // if a namespace or a piece of interface info is missing in ENTRY_EXPIRE_COUNT consecutive queries
    // it will be removed from interface_info
    info: Vec<(InterfaceInfo, u8)>,
    expire_count: u8,
}

impl NsEntry {
    fn age(&mut self) {
        self.expire_count += 1;
        self.info.iter_mut().for_each(|(_, e)| *e += 1);
    }

    fn expire(&mut self, limit: u8) -> bool {
        if self.expire_count >= limit {
            self.info.clear();
            return true;
        }

        let mut changed = false;
        self.info.retain(|(info, e)| {
            if *e < limit {
                true
            } else {
                debug!("interface {:?} expired", info);
                changed = true;
                false
            }
        });

        changed
    }

    fn renew(&mut self) {
        self.expire_count = 0;
        self.info.iter_mut().for_each(|(_, e)| *e = 0);
    }

    fn merge(&mut self, rhs: Vec<InterfaceInfo>) -> bool {
        let mut changed = false;
        self.expire_count = 0;
        for info in rhs.into_iter() {
            match self
                .info
                .binary_search_by(|(probe, _)| probe.tap_idx.cmp(&info.tap_idx))
            {
                Ok(replace_idx) => {
                    let old_info = &mut self.info[replace_idx];
                    if old_info.0 != info {
                        old_info.0 = info;
                        changed = true;
                    }
                    old_info.1 = 0;
                }
                Err(insert_idx) => {
                    debug!("interface {:?} added", info);
                    self.info.insert(insert_idx, (info, 0));
                    changed = true;
                }
            }
        }
        changed
    }
}

type InterfaceInfoMap = HashMap<NsFile, Vec<InterfaceInfo>>;

impl PartialEq<Vec<InterfaceInfo>> for NsEntry {
    fn eq(&self, rhs: &Vec<InterfaceInfo>) -> bool {
        self.info.iter().map(|(info, _)| info).eq(rhs.iter())
    }
}

impl From<Vec<InterfaceInfo>> for NsEntry {
    fn from(mut info: Vec<InterfaceInfo>) -> Self {
        info.sort_unstable_by_key(|iface| iface.tap_idx);
        Self {
            info: info.into_iter().map(|iface| (iface, 0)).collect(),
            expire_count: 0,
        }
    }
}

#[derive(Debug)]
pub struct InterfaceInfoStore {
    m: HashMap<NsFile, NsEntry>,

    expire_limit: u8,
}

impl Default for InterfaceInfoStore {
    fn default() -> Self {
        Self {
            m: Default::default(),
            expire_limit: ENTRY_EXPIRE_COUNT,
        }
    }
}

impl InterfaceInfoStore {
    fn eq(&mut self, new_map: &InterfaceInfoMap) -> bool {
        if self.m.len() != new_map.len() {
            return false;
        }
        self.m
            .iter()
            .all(|(ns, entry)| new_map.get(ns).map_or(false, |v| *entry == *v))
    }

    // returns true if updated
    pub fn merge(&mut self, mut new_map: InterfaceInfoMap) -> bool {
        for vs in new_map.values_mut() {
            vs.sort_unstable();
        }
        if self.eq(&new_map) {
            self.m.values_mut().for_each(|entry| entry.renew());
            return false;
        }

        for (_, old_entry) in self.m.iter_mut() {
            old_entry.age();
        }

        let mut changed = false;

        for (ns, new_info) in new_map.into_iter() {
            if let Some(old_entry) = self.m.get_mut(&ns) {
                changed |= old_entry.merge(new_info);
            } else {
                debug!("interfaces {:?} added", new_info);
                self.m.insert(ns, new_info.into());
                changed = true;
            }
        }

        self.m.retain(|ns, entry| {
            changed |= entry.expire(self.expire_limit);
            if entry.expire_count >= self.expire_limit {
                debug!("interfaces in {:?} expired", ns);
                false
            } else {
                true
            }
        });

        changed
    }

    pub fn get(&self, ns: &NsFile) -> Option<Vec<InterfaceInfo>> {
        self.m
            .get(ns)
            .map(|entry| entry.info.iter().map(|(info, _)| info.clone()).collect())
    }

    pub fn get_all(&self) -> Vec<InterfaceInfo> {
        let mut ret = vec![];
        for entry in self.m.values() {
            ret.extend(entry.info.iter().map(|(info, _)| info.clone()));
        }
        ret
    }

    pub fn iter(&self) -> StoreIter<'_> {
        StoreIter {
            map_iter: self.m.values(),
            vec_iter: None,
        }
    }
}

pub struct StoreIter<'a> {
    map_iter: std::collections::hash_map::Values<'a, NsFile, NsEntry>,
    vec_iter: Option<std::slice::Iter<'a, (InterfaceInfo, u8)>>,
}

impl<'a> Iterator for StoreIter<'a> {
    type Item = &'a InterfaceInfo;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(vs) = self.vec_iter.as_mut() {
            if let Some(n) = vs.next() {
                return Some(&n.0);
            }
            self.vec_iter = None;
        }
        while let Some(entry) = self.map_iter.next() {
            let mut vs = entry.info.iter();
            if let Some(n) = vs.next() {
                self.vec_iter = Some(vs);
                return Some(&n.0);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_info_store() {
        flexi_logger::Logger::try_with_env()
            .unwrap()
            .start()
            .unwrap();

        let mut input = HashMap::from([
            (
                NsFile::Root,
                vec![
                    InterfaceInfo {
                        tap_idx: 3,
                        ..Default::default()
                    },
                    InterfaceInfo {
                        tap_idx: 2,
                        ..Default::default()
                    },
                    InterfaceInfo {
                        tap_idx: 1,
                        ..Default::default()
                    },
                ],
            ),
            (
                NsFile::Proc(42),
                vec![InterfaceInfo {
                    tap_idx: 1,
                    ..Default::default()
                }],
            ),
        ]);

        let mut store = InterfaceInfoStore::default();
        assert_eq!(store.get_all().len(), 0);

        assert!(store.merge(input.clone()));
        assert_eq!(store.get(&NsFile::Root).map(|info| info.len()), Some(3));
        assert_eq!(store.get_all().len(), 4);

        input.get_mut(&NsFile::Root).unwrap().remove(1);
        for _ in 0..(ENTRY_EXPIRE_COUNT - 1) {
            assert!(!store.merge(input.clone()));
            assert_eq!(store.get(&NsFile::Root).map(|info| info.len()), Some(3));
        }

        // tap_idx: 2 in Root should expire
        assert!(store.merge(input.clone()));
        let info = store.get(&NsFile::Root).unwrap();
        assert_eq!(info.len(), 2);
        assert_eq!(info.get(1).map(|i| i.tap_idx), Some(3));

        input.remove(&NsFile::Proc(42));
        input.get_mut(&NsFile::Root).unwrap().push(InterfaceInfo {
            tap_idx: 42,
            ..Default::default()
        });
        for i in 0..(ENTRY_EXPIRE_COUNT - 1) {
            if i == 0 {
                // first merge adds tap_idx: 42 in Root
                assert!(store.merge(input.clone()));
            } else {
                assert!(!store.merge(input.clone()));
            }
            assert!(store.get(&NsFile::Proc(42)).is_some());
            assert_eq!(store.get(&NsFile::Root).map(|info| info.len()), Some(3));
        }
        assert!(store.merge(input.clone()));
        assert!(store.get(&NsFile::Proc(42)).is_none());
    }

    #[test]
    fn store_iter() {
        let input = HashMap::from([
            (
                NsFile::Root,
                vec![
                    InterfaceInfo {
                        tap_idx: 2,
                        ..Default::default()
                    },
                    InterfaceInfo {
                        tap_idx: 1,
                        ..Default::default()
                    },
                    InterfaceInfo {
                        tap_idx: 3,
                        ..Default::default()
                    },
                ],
            ),
            (
                NsFile::Proc(42),
                vec![InterfaceInfo {
                    tap_idx: 4,
                    ..Default::default()
                }],
            ),
        ]);

        let mut store = InterfaceInfoStore::default();
        store.merge(input);
        let indices = store.iter().map(|info| info.tap_idx).collect::<Vec<_>>();
        // hashmap iter order is arbitrary
        assert!(indices == vec![1, 2, 3, 4] || indices == vec![4, 1, 2, 3]);
    }
}
