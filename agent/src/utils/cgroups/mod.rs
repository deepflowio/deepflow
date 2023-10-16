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

use thiserror::Error;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::*;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use self::windows::*;

#[derive(Debug, Error)]
pub enum Error {
    #[error("cgroups is not supported: {0}")]
    CgroupsNotSupported(String),
    #[error("set cpu controller failed: {0}")]
    CpuControllerSetFailed(String),
    #[error("set mem controller failed: {0}")]
    MemControllerSetFailed(String),
    #[error("apply resources failed: {0}")]
    ApplyResourcesFailed(String),
    #[error("delete cgroups failed: {0}")]
    DeleteCgroupsFailed(String),
}
