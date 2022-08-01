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

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("parse mac address failed from: {0}")]
    ParseMacFailed(String),
    #[error("call try_from() failed from {0}")]
    TryFromFailed(String),
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    KubeWatcher(#[from] kube::runtime::watcher::Error),
    #[error(transparent)]
    ParseUtf8(#[from] std::string::FromUtf8Error),
    #[error("PlatformSynchronizer failed: {0} ")]
    PlatformSynchronizer(String),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("data not found: {0}")]
    NotFound(String),
    #[error("Kubernetes ApiWatcher error: {0}")]
    KubernetesApiWatcher(String),
    #[error("system: {0}")]
    SysMonitor(String),
    #[error("environment error: {0}")]
    Environment(String),
    #[error("parse packet failed from: {0}")]
    ParsePacketFailed(String),
    #[error("invalid tpacket version: {0}")]
    InvalidTpVersion(isize),
    #[error("windows error: {0}")]
    Windows(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
