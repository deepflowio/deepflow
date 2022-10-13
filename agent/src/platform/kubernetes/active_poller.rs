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
    fs,
    os::unix::io::AsRawFd,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use log::{debug, info, log_enabled, warn, Level};
use nix::errno::Errno;
use nix::sched::{setns, CloneFlags};

use super::{ls_ns_net, Poller};
use crate::platform::InterfaceInfo;
use public::utils::net::{addr_list, link_list};

#[derive(Debug)]
pub struct ActivePoller {
    interval: Duration,
    version: Arc<AtomicU64>,
    entries: Arc<Mutex<Option<Vec<InterfaceInfo>>>>,
    running: Arc<Mutex<bool>>,
    timer: Arc<Condvar>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl ActivePoller {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            version: Arc::new(AtomicU64::new(0)),
            entries: Arc::new(Mutex::new(None)),
            running: Arc::new(Mutex::new(false)),
            timer: Arc::new(Condvar::new()),
            thread: Mutex::new(None),
        }
    }

    fn query(priv_logged: &mut bool) -> Option<Vec<InterfaceInfo>> {
        let netns = fs::File::open("/proc/self/ns/net");
        if netns.is_err() {
            warn!("get self net namespace failed: {:?}", netns.unwrap_err());
            return None;
        }
        let netns = netns.unwrap();

        let net_nss = ls_ns_net();
        if net_nss.is_err() {
            warn!("get net namespaces failed: {:?}", net_nss.unwrap_err());
            return None;
        }
        let net_nss = net_nss.unwrap();

        if net_nss.len() <= 1 {
            if !*priv_logged {
                // 只能拿到global namespace的时候，可能权限配置不对，也有可能节点上没有容器
                warn!("no net namespaces found, check trident container privileges if this is not the expected behaviour");
                *priv_logged = true;
            }
        } else {
            *priv_logged = false;
        }

        let mut new_interface_info = vec![];

        for nss in net_nss.into_iter() {
            if nss.len() > 0 && nss[0] == 1 {
                // skip global namespace
                continue;
            }

            let mut current_ns_found = false;
            for &pid in nss.iter() {
                let ns_id = Self::get_net_ns_by(pid);
                if ns_id.is_none() {
                    continue;
                }

                if Self::set_net_ns_by(pid).is_err() {
                    continue;
                }

                let links = link_list();
                if links.is_err() {
                    continue;
                }

                let addrs = addr_list();
                if addrs.is_err() {
                    continue;
                }

                let mut addr_map =
                    addrs
                        .unwrap()
                        .into_iter()
                        .fold(HashMap::new(), |mut map, addr| {
                            map.entry(addr.if_index)
                                .or_insert(vec![])
                                .push(addr.ip_addr);

                            map
                        });

                for link in links.unwrap() {
                    let link_type = link
                        .if_type
                        .as_ref()
                        .map(|t| t.as_str())
                        .unwrap_or_default();
                    match link_type {
                        "veth" | "macvlan" | "ipvlan" => (),
                        _ => continue,
                    }

                    if !addr_map.contains_key(&link.if_index) {
                        // 忽略没有IP的接口
                        continue;
                    }

                    let info = InterfaceInfo {
                        tap_idx: link.parent_index.unwrap_or_else(|| {
                            todo!("如果没有找到parent index 就要使用ioctl 查询")
                        }),
                        mac: link.mac_addr,
                        ips: addr_map.remove(&link.if_index).unwrap(),
                        name: link.name,
                        device_id: ns_id
                            .as_ref()
                            .and_then(|p| p.to_str())
                            .map(|s| s.to_string())
                            .unwrap(),
                    };
                    new_interface_info.push(info);
                }
                // 当前命名空间正常查询完毕
                current_ns_found = true;
                break;
            }
            if !current_ns_found {
                warn!("failed getting ips for namespace group: {:?}", nss);
            }
        }

        if let Err(e) = setns(netns.as_raw_fd(), CloneFlags::CLONE_NEWNET) {
            warn!("restore net namespace failed: {}", e);
        }

        new_interface_info.sort_unstable();
        Some(new_interface_info)
    }

    fn get_net_ns_by(pid: u32) -> Option<PathBuf> {
        match fs::read_link(format!("/proc/{}/ns/net", pid)) {
            Ok(p) => Some(p),
            Err(e) => {
                warn!("get net namespace ({}) failed: {:?}", pid, e);
                None
            }
        }
    }

    fn set_net_ns_by(pid: u32) -> nix::Result<()> {
        match fs::OpenOptions::new()
            .read(true)
            .open(format!("/proc/{}/ns/net", pid))
        {
            Ok(file) => setns(file.as_raw_fd(), CloneFlags::CLONE_NEWNET),
            Err(e) => {
                warn!("set net namespace ({}) failed: {:?}", pid, e);
                Err(Errno::EACCES)
            }
        }
    }

    fn process(
        timer: Arc<Condvar>,
        running: Arc<Mutex<bool>>,
        version: Arc<AtomicU64>,
        entries: Arc<Mutex<Option<Vec<InterfaceInfo>>>>,
        timeout: Duration,
    ) {
        let mut priv_logged = false;
        // 初始化
        *entries.lock().unwrap() = Self::query(&mut priv_logged);
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

            let new_interface_info = Self::query(&mut priv_logged);
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
                if let Some(old) = old_interface_info.as_ref() {
                    for entry in old {
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

    fn get_interface_info(&self) -> Option<Vec<InterfaceInfo>> {
        self.entries.lock().unwrap().as_ref().map(|e| e.clone())
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
        let running = self.running.clone();
        let version = self.version.clone();
        let timeout = self.interval;
        let timer = self.timer.clone();

        let handle =
            thread::spawn(move || Self::process(timer, running, version, entries, timeout));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_poller_query() {
        let mut priv_logged = false;
        if let Some(infos) = ActivePoller::query(&mut priv_logged) {
            println!("result interface infos: {:?}", infos);
        }
    }

    #[test]
    fn assert_poller() {
        let poller = ActivePoller::new(Duration::from_secs(30));
        poller.start();
        thread::sleep(Duration::from_secs(1));
        if let Some(infos) = poller.get_interface_info() {
            println!("interface infos from active poller: {:?}", infos);
        }
        poller.stop();
    }
}
