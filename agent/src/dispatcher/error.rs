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

use num_enum::{TryFromPrimitive, TryFromPrimitiveError};
use thiserror::Error;

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
    #[error("dispatcher winpcap: {0}")]
    WinPcap(String), // Enterprise Edition Feature: windows-dispatcher
    #[error("flavor dispatcher is empty")]
    DispatcherFlavorEmpty, // Enterprise Edition Feature: windows-dispatcher
}

impl<T: TryFromPrimitive> From<TryFromPrimitiveError<T>> for Error {
    fn from(e: TryFromPrimitiveError<T>) -> Self {
        Error::PacketInvalid(e.to_string())
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
