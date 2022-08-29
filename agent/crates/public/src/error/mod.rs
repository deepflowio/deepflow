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

pub mod af_packet;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("timeout")]
    Timeout,
    #[cfg(target_os = "linux")]
    #[error("afpacket error")]
    AfPacketError(#[from] af_packet::Error),
    #[cfg(target_os = "linux")]
    #[error("create raw socket error")]
    CreateRawSocketError(#[from] std::io::Error),
    #[cfg(target_os = "windows")]
    #[error("winpcap error {0}")]
    WinpcapError(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
