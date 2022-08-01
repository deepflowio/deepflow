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

#[cfg(target_os = "linux")]
mod kubernetes;
mod libvirt_xml_extractor;
#[cfg(target_os = "linux")]
mod platform_synchronizer;

use std::fmt;
use std::net::IpAddr;

#[cfg(target_os = "linux")]
pub use kubernetes::{ActivePoller, ApiWatcher, GenericPoller, Poller};
pub use libvirt_xml_extractor::LibvirtXmlExtractor;
#[cfg(target_os = "linux")]
pub use platform_synchronizer::PlatformSynchronizer;

use crate::utils::net::MacAddr;

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct InterfaceEntry {
    pub name: String,
    pub mac: MacAddr,
    pub domain_uuid: String,
    pub domain_name: String,
}

#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub tap_idx: u32,
    pub mac: MacAddr,
    pub ips: Vec<IpAddr>,
    pub name: String,
    pub device_id: String,
}

impl fmt::Display for InterfaceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ips_str = self
            .ips
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<String>>()
            .as_slice()
            .join(",");
        write!(
            f,
            "{}: {}: {} [{}] device {}",
            self.tap_idx, self.name, self.mac, ips_str, self.device_id
        )
    }
}

impl PartialEq for InterfaceInfo {
    fn eq(&self, other: &Self) -> bool {
        self.tap_idx.eq(&other.tap_idx) && self.mac.eq(&other.mac)
    }
}

impl Eq for InterfaceInfo {}

impl PartialOrd for InterfaceInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match (
            self.tap_idx.partial_cmp(&other.tap_idx),
            self.mac.partial_cmp(&other.mac),
        ) {
            (Some(std::cmp::Ordering::Equal), mac) => mac,
            (tap, _) => tap,
        }
    }
}

impl Ord for InterfaceInfo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap_or(std::cmp::Ordering::Equal)
    }
}
