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

use std::{net::IpAddr, path::Path, process, thread, time::Duration};

use log::{info, warn};
use regex::Regex;

use super::Poller;
use crate::utils::environment::get_ctrl_ip_and_mac;

use public::{
    netns::{self, InterfaceInfo, NsFile},
    utils::net::link_list,
};

pub struct SidecarPoller(InterfaceInfo);

impl SidecarPoller {
    pub fn new(dest: IpAddr) -> Self {
        let (ctrl_ip, ctrl_mac) = get_ctrl_ip_and_mac(dest);
        let Ok(links) = link_list() else {
            warn!("call link_list() failed");
            thread::sleep(Duration::from_secs(1));
            process::exit(-1);
        };
        let Some(link) = links.into_iter().filter(|link| link.mac_addr == ctrl_mac).next() else {
            warn!("cannot find ctrl interface with mac {}", ctrl_mac);
            thread::sleep(Duration::from_secs(1));
            process::exit(-1);
        };
        let Ok(ns): Result<NsFile, _> = Path::new(netns::CURRENT_NS_PATH).try_into() else {
            warn!("cannot open ns file {}", netns::CURRENT_NS_PATH);
            thread::sleep(Duration::from_secs(1));
            process::exit(-1);
        };
        let info = InterfaceInfo {
            tap_idx: link.if_index,
            mac: ctrl_mac,
            ips: vec![ctrl_ip],
            name: link.name,
            device_id: ns.to_string(),
            tap_ns: ns,
            ..Default::default()
        };
        info!("Sidecar poller: {:?}", info);
        Self(info)
    }
}

impl Poller for SidecarPoller {
    fn get_version(&self) -> u64 {
        1
    }

    fn get_interface_info_in(&self, _: &NsFile) -> Option<Vec<InterfaceInfo>> {
        Some(self.get_interface_info())
    }

    fn get_interface_info(&self) -> Vec<InterfaceInfo> {
        vec![self.0.clone()]
    }

    fn set_netns_regex(&self, _: Option<Regex>) {}

    fn start(&self) {}

    fn stop(&self) {}
}
