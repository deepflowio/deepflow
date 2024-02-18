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

use std::net::IpAddr;

use log::info;
use regex::Regex;

use super::Poller;
use crate::utils::environment::get_ctrl_ip_and_mac;

use public::{
    netns::{self, InterfaceInfo, NsFile},
    utils::net::link_list,
};

pub struct SidecarPoller(InterfaceInfo);

impl SidecarPoller {
    pub fn new(dest: IpAddr) -> Result<Self, String> {
        let (ctrl_ip, ctrl_mac) = match get_ctrl_ip_and_mac(&dest) {
            Ok(tuple) => tuple,
            Err(e) => return Err(format!("call get_ctrl_ip_and_mac() failed: {}", e)),
        };
        let Ok(links) = link_list() else {
            return Err("call link_list() failed".to_owned());
        };
        let Some(link) = links
            .into_iter()
            .filter(|link| link.mac_addr == ctrl_mac)
            .next()
        else {
            return Err(format!("cannot find ctrl interface with mac {}", ctrl_mac));
        };
        let path = netns::current_netns_path();
        let Ok(ns): Result<NsFile, _> = path.as_path().try_into() else {
            return Err(format!("cannot open ns file {}", path.display()));
        };
        let info = InterfaceInfo {
            tap_idx: link.if_index,
            mac: ctrl_mac,
            ips: vec![ctrl_ip.into()],
            name: link.name,
            device_id: ns.to_string(),
            tap_ns: ns,
            ..Default::default()
        };
        info!("Sidecar poller: {:?}", info);
        Ok(Self(info))
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
