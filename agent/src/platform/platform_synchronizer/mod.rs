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

mod proc_scan_hook;

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "linux", target_os = "android"))] {
        mod linux;
        pub(crate) mod linux_process;
        mod linux_socket;

        pub use linux::SocketSynchronizer;
        pub use linux_process::{ProcessData, ProcRegRewrite};
    } else if #[cfg(target_os = "windows")] {
        pub struct ProcessData {}
    }
}

use public::proto::common::TridentType;

use crate::utils::environment::{is_tt_pod, is_tt_workload};

// whether need to scan the process info
pub fn process_info_enabled(t: TridentType) -> bool {
    is_tt_workload(t) || is_tt_pod(t)
}
