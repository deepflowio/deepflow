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

pub(crate) mod cgroups;
pub(crate) mod command;
pub(crate) mod environment;
pub(crate) mod guard;
pub(crate) mod hasher;
pub(crate) mod logger;
pub(crate) mod lru;
pub(crate) mod npb_bandwidth_watcher;
pub(crate) mod possible_host;
pub(crate) mod process;
pub mod stats;

#[cfg(target_os = "linux")]
pub(crate) mod pid_file;

pub use public::bytes;

pub mod test;

const WIN_ERROR_CODE_STR: &str = "please browse website(https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes) to get more detail";

pub fn notify_exit(code: i32) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Err(_) =
        nix::sys::signal::kill(nix::unistd::Pid::this(), nix::sys::signal::Signal::SIGTERM)
    {
        std::process::exit(code);
    }
    #[cfg(target_os = "windows")]
    std::process::exit(code);
}
