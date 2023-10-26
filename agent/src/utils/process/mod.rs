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

mod process;
pub use process::*;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::*;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use self::windows::*;

use sysinfo::{System, SystemExt};

/// 返回当前系统的空闲内存数目，单位：%
pub fn get_current_sys_free_memory_percentage() -> u32 {
    // don't use new_all(), we only need meminfo, new_all() will refresh all things(include cpu, users, etc).
    // It could be problematic for processes using a lot of files and using sysinfo at the same time.
    // https://github.com/GuillaumeGomez/sysinfo/blob/master/src/linux/system.rs#L21
    let mut s = System::new();
    s.refresh_memory();
    let total_memory = s.total_memory();
    if total_memory > 0 {
        (s.free_memory() * 100 / total_memory) as u32
    } else {
        0
    }
}
