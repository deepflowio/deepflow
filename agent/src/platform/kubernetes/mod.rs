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

use std::{fs, os::unix::io::AsRawFd, time::Duration};

use enum_dispatch::enum_dispatch;
use nix::sched::{setns, CloneFlags};

mod active_poller;
mod api_watcher;
mod resource_watcher;
pub use active_poller::ActivePoller;
pub use api_watcher::ApiWatcher;

use public::netns::{InterfaceInfo, NsFile};

#[enum_dispatch]
pub enum GenericPoller {
    ActivePoller,
    PassivePoller,
}

#[enum_dispatch(GenericPoller)]
pub trait Poller {
    fn get_version(&self) -> u64;
    fn get_interface_info_in(&self, ns: &NsFile) -> Option<Vec<InterfaceInfo>>;
    fn get_interface_info(&self) -> Vec<InterfaceInfo>;
    fn set_netns(&self, ns: Vec<NsFile>);
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
    fn get_interface_info_in(&self, _: &NsFile) -> Option<Vec<InterfaceInfo>> {
        None
    }
    fn get_interface_info(&self) -> Vec<InterfaceInfo> {
        vec![]
    }
    fn set_netns(&self, _: Vec<NsFile>) {}
    fn start(&self) {}
    fn stop(&self) {}
}
//END

pub fn check_set_ns() -> bool {
    match fs::File::open("/proc/self/ns/net") {
        Ok(f) => setns(f.as_raw_fd(), CloneFlags::CLONE_NEWNET).is_ok(),
        Err(_) => false,
    }
}

pub fn check_read_link_ns() -> bool {
    fs::read_link("/proc/1/ns/net").is_ok()
}
