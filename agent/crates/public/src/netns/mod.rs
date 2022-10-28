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
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{link_list_in_netns, links_by_name_regex_in_netns, NetNs, NsFile};

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use self::windows::{NetNs, NsFile};

use std::cmp::Ordering;
use std::fmt::{self, Debug};
use std::net::IpAddr;

#[cfg(target_os = "linux")]
use neli::err::{NlError, SerError};
use thiserror::Error;

use super::utils::net::{self, MacAddr};

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[cfg(target_os = "linux")]
    #[error("neli error: {0}")]
    NeliError(String),
    #[error("net error: {0}")]
    NetError(#[from] net::Error),
    #[error("netns not found")]
    NotFound,
    #[cfg(target_os = "linux")]
    #[error("syscall error: {0}")]
    Syscall(#[from] nix::Error),
}

#[cfg(target_os = "linux")]
impl<T: Debug, P: Debug> From<NlError<T, P>> for Error {
    fn from(e: NlError<T, P>) -> Self {
        Self::NeliError(format!("{}", e))
    }
}

#[cfg(target_os = "linux")]
impl From<SerError> for Error {
    fn from(e: SerError) -> Self {
        Self::NeliError(format!("{}", e))
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub tap_ns: NsFile,
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
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for InterfaceInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.tap_idx.cmp(&other.tap_idx), self.mac.cmp(&other.mac)) {
            (Ordering::Equal, mac) => mac,
            (tap, _) => tap,
        }
    }
}
