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

use std::{collections::HashMap, fmt, fs, io, net::IpAddr, os::unix::io::AsRawFd, time::Duration};

use enum_dispatch::enum_dispatch;
use nix::sched::{setns, CloneFlags};

use crate::utils::net::MacAddr;

mod active_poller;
mod api_watcher;
mod resource_watcher;
pub use active_poller::ActivePoller;
pub use api_watcher::ApiWatcher;

use super::InterfaceInfo;

#[enum_dispatch]
pub enum GenericPoller {
    ActivePoller,
    PassivePoller,
}

#[enum_dispatch(GenericPoller)]
pub trait Poller {
    fn get_version(&self) -> u64;
    fn get_interface_info(&self) -> Option<Vec<InterfaceInfo>>;
    fn start(&self);
    fn stop(&self);
}

//TODO
pub struct PassivePoller;

impl PassivePoller {
    pub fn new(_interval: Duration) -> Self {
        todo!()
    }
}

impl Poller for PassivePoller {
    fn get_version(&self) -> u64 {
        0
    }
    fn get_interface_info(&self) -> Option<Vec<InterfaceInfo>> {
        None
    }
    fn start(&self) {}
    fn stop(&self) {}
}
//END

fn ls_ns_net() -> io::Result<Vec<Vec<u32>>> {
    let mut seen = HashMap::new();

    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }

        let pid = entry
            .file_name()
            .to_str()
            .and_then(|pid| pid.parse::<u32>().ok());
        if pid.is_none() {
            continue;
        }
        let pid = pid.unwrap();

        let linked = fs::read_link(format!("/proc/{}/ns/net", pid));
        if linked.is_err() {
            continue;
        }

        seen.entry(linked.unwrap()).or_insert(vec![]).push(pid);
    }

    let mut ret: Vec<Vec<u32>> = seen
        .into_values()
        .map(|mut v| {
            v.sort_unstable();
            v
        })
        .collect();

    ret.sort_unstable_by(|a, b| a[0].cmp(&b[0]));

    Ok(ret)
}

pub fn check_set_ns() -> bool {
    match fs::File::open("/proc/self/ns/net") {
        Ok(f) => setns(f.as_raw_fd(), CloneFlags::CLONE_NEWNET).is_ok(),
        Err(_) => false,
    }
}

pub fn check_read_link_ns() -> bool {
    fs::read_link("/proc/1/ns/net").is_ok()
}
