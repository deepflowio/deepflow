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

use num_enum::{TryFromPrimitive, TryFromPrimitiveError};
use thiserror::Error;

use public::error;
#[cfg(target_os = "linux")]
use public::netns;

#[derive(Debug, Error)]
pub enum Error {
    #[error("dispatcher config incomplete: {0}")]
    ConfigIncomplete(String),
    #[error("dispatcher config invalid: {0}")]
    ConfigInvalid(String),
    #[error("packet parse failed: {0}")]
    PacketInvalid(String),
    #[error("dispatcher stats collector: {0}")]
    StatsCollector(&'static str),
    #[error("recv engine failure: {0}")]
    RecvEngineFailure(String),
    #[error("dispatcher winpcap: {0}")]
    Libpcap(String), // Enterprise Edition Feature: windows-dispatcher
    #[error("flavor dispatcher is empty")]
    DispatcherFlavorEmpty, // Enterprise Edition Feature: windows-dispatcher
    #[cfg(target_os = "linux")]
    #[error("netns failure: {0}")]
    NetNs(String), // Enterprise Edition Feature: network-namespace
}

impl<T: TryFromPrimitive> From<TryFromPrimitiveError<T>> for Error {
    fn from(e: TryFromPrimitiveError<T>) -> Self {
        Error::PacketInvalid(e.to_string())
    }
}

#[cfg(target_os = "linux")]
impl From<netns::Error> for Error {
    fn from(e: netns::Error) -> Self {
        Error::NetNs(e.to_string())
    }
}

impl From<error::Error> for Error {
    fn from(e: error::Error) -> Self {
        Error::RecvEngineFailure(e.to_string())
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
