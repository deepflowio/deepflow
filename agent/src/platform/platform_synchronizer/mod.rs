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

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux_process;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux_socket;
mod proc_scan_hook;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
mod windows_process;

#[cfg(target_os = "android")]
use std::os::android::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::{
    fs::{metadata, symlink_metadata},
    path::PathBuf,
};

#[cfg(target_os = "windows")]
pub use self::windows::*;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::*;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux_process::*;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux_socket::*;
use public::proto::common::TridentType;
#[cfg(target_os = "windows")]
pub use windows_process::*;

use crate::utils::environment::{is_tt_pod, is_tt_workload};

#[cfg(any(target_os = "linux", target_os = "android"))]
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

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn dir_inode(path: &str) -> std::io::Result<u64> {
    let m = metadata(path)?;
    Ok(m.st_ino())
}

// whether need to scan the process info
pub fn process_info_enabled(t: TridentType) -> bool {
    is_tt_workload(t) || is_tt_pod(t)
}
