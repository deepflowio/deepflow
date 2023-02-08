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
mod linux_process;
#[cfg(target_os = "linux")]
mod linux_socket;
mod proc_scan_hook;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
mod windows_process;

#[cfg(target_os = "linux")]
use std::{
    fs::{metadata, symlink_metadata},
    os::linux::fs::MetadataExt,
    path::PathBuf,
};

#[cfg(target_os = "windows")]
pub use self::windows::*;
#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(target_os = "linux")]
pub use linux_process::*;
#[cfg(target_os = "linux")]
pub use linux_socket::*;
use public::proto::common::TridentType;
#[cfg(target_os = "windows")]
pub use windows_process::*;

#[cfg(target_os = "linux")]
// return the (now_sec - sym_change_time) second
pub(super) fn sym_uptime(now_sec: u64, path: &PathBuf) -> Result<u64, &'static str> {
    // linux default not record the file birth time, use the change time instead of the birth time.
    let s = symlink_metadata(path)
        .map_err(|_| "get symlink metadate fail")?
        .st_ctime() as u64;
    if now_sec >= s {
        Ok(now_sec - s)
    } else {
        Err("sym up time after current")
    }
}

#[cfg(target_os = "linux")]
pub fn dir_inode(path: &str) -> std::io::Result<u64> {
    let m = metadata(path)?;
    Ok(m.st_ino())
}

// whether need to scan the process info
pub fn process_info_enabled(t: TridentType) -> bool {
    match t {
        TridentType::TtPublicCloud
        | TridentType::TtPhysicalMachine
        | TridentType::TtHostPod
        | TridentType::TtVmPod => true,
        _ => false,
    }
}
