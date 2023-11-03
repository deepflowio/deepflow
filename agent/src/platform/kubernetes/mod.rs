/*
 * Copyright (c) 2023 Yunshan Networks
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

use std::{fs, os::unix::io::AsRawFd};

use arc_swap::access::Access;
use enum_dispatch::enum_dispatch;
use log::{info, warn};
use nix::sched::{setns, CloneFlags};
use regex::Regex;

mod active_poller;
mod api_watcher;
mod crd;
mod passive_poller;
mod sidecar_poller;
pub use active_poller::ActivePoller;
pub use api_watcher::ApiWatcher;
pub use passive_poller::PassivePoller;
pub use sidecar_poller::SidecarPoller;

mod resource_watcher;

use public::netns::{self, InterfaceInfo, NsFile};

use crate::config::{handler::PlatformAccess, KubernetesPollerType};

#[enum_dispatch(Poller)]
pub enum GenericPoller {
    ActivePoller,
    PassivePoller,
    SidecarPoller,
}

#[enum_dispatch]
pub trait Poller {
    fn get_version(&self) -> u64;
    fn get_interface_info_in(&self, ns: &NsFile) -> Option<Vec<InterfaceInfo>>;
    fn get_interface_info(&self) -> Vec<InterfaceInfo>;
    fn set_netns_regex(&self, ns: Option<Regex>);
    fn start(&self);
    fn stop(&self);
}

pub fn check_set_ns() -> bool {
    netns::supported()
        && match fs::File::open("/proc/self/ns/net") {
            Ok(f) => setns(f.as_raw_fd(), CloneFlags::CLONE_NEWNET).is_ok(),
            Err(_) => false,
        }
}

pub fn check_read_link_ns() -> bool {
    netns::supported() && fs::read_link("/proc/1/ns/net").is_ok()
}

impl GenericPoller {
    pub fn new(config: PlatformAccess, extra_netns_regex: String) -> Self {
        let (can_set_ns, can_read_link_ns) = (check_set_ns(), check_read_link_ns());

        if !can_set_ns || !can_read_link_ns {
            warn!(
                "kubernetes poller privileges: set_ns={} read_link_ns={}",
                can_set_ns, can_read_link_ns
            );
        } else {
            info!(
                "kubernetes poller privileges: set_ns={} read_link_ns={}",
                can_set_ns, can_read_link_ns
            );
        }

        let extra_netns_regex = if extra_netns_regex != "" {
            info!("platform monitoring extra netns: /{}/", extra_netns_regex);
            Some(Regex::new(&extra_netns_regex).unwrap())
        } else {
            info!("platform monitoring no extra netns");
            None
        };

        let sync_interval = config.load().sync_interval;
        let kubernetes_poller_type = config.load().kubernetes_poller_type;
        match kubernetes_poller_type {
            KubernetesPollerType::Adaptive => {
                if can_set_ns && can_read_link_ns {
                    ActivePoller::new(sync_interval, extra_netns_regex.clone()).into()
                } else {
                    PassivePoller::new(sync_interval, config.clone()).into()
                }
            }
            KubernetesPollerType::Active => {
                ActivePoller::new(sync_interval, extra_netns_regex.clone()).into()
            }
            KubernetesPollerType::Passive => {
                PassivePoller::new(sync_interval, config.clone()).into()
            }
        }
    }
}
