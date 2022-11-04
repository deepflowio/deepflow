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
pub(crate) mod bpf;

#[cfg(target_os = "windows")]
use std::ffi::CStr;
use std::sync::{atomic::AtomicU64, Arc};
use std::time::Duration;

#[cfg(target_os = "linux")]
use af_packet::{options::Options, tpacket::Tpacket};
pub use public::error::{Error, Result};
use public::packet;

use crate::utils::stats;

#[cfg(target_os = "windows")]
pub use windows_recv_engine::{WinPacket, WinPcapCounter};

pub const DEFAULT_BLOCK_SIZE: usize = 1 << 20;
pub const FRAME_SIZE_MAX: usize = 1 << 16; // local and mirror
pub const FRAME_SIZE_MIN: usize = 1 << 11; // analyzer
pub const POLL_TIMEOUT: Duration = Duration::from_millis(100);

pub enum RecvEngine {
    #[cfg(target_os = "linux")]
    AfPacket(Tpacket),
    Dpdk(),
    #[cfg(target_os = "windows")]
    WinPcap(Option<WinPacket>),
}

impl RecvEngine {
    const WIN_PCAP_NONE: &'static str = "windows packet capture is none";

    pub fn init(&mut self) -> Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            Self::AfPacket(_) => Ok(()),
            Self::Dpdk() => todo!(),
            #[cfg(target_os = "windows")]
            Self::WinPcap(_) => Ok(()),
        }
    }

    pub fn close(&mut self) {
        match self {
            #[cfg(target_os = "windows")]
            Self::WinPcap(w) => {
                let _ = w.take();
            }
            _ => (),
        }
    }

    pub fn recv(&mut self) -> Result<packet::Packet> {
        match self {
            #[cfg(target_os = "linux")]
            Self::AfPacket(e) => match e.read() {
                Some(p) => Ok(p),
                None => Err(Error::Timeout),
            },
            Self::Dpdk() => todo!(),
            // Enterprise Edition Feature: windows-dispatcher
            #[cfg(target_os = "windows")]
            Self::WinPcap(w) => w
                .as_mut()
                .ok_or(Error::WinpcapError(Self::WIN_PCAP_NONE.to_string()))
                .and_then(|e| e.read()),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn set_bpf(&mut self, s: Vec<af_packet::RawInstruction>) -> Result<()> {
        match self {
            Self::AfPacket(e) => e.set_bpf(s).map_err(|e| e.into()),
            Self::Dpdk() => todo!(),
        }
    }

    #[cfg(target_os = "windows")]
    pub fn set_bpf(&mut self, s: &CStr) -> Result<()> {
        match self {
            Self::WinPcap(w) => w
                .as_mut()
                .ok_or(Error::WinpcapError(Self::WIN_PCAP_NONE.to_string()))
                .and_then(|e| e.set_bpf(s.to_str().unwrap())),
            _ => todo!(),
        }
    }

    pub fn get_counter_handle(&self) -> Arc<dyn stats::RefCountable> {
        match self {
            #[cfg(target_os = "linux")]
            Self::AfPacket(e) => Arc::new(e.get_counter_handle()),
            Self::Dpdk() => todo!(),
            #[cfg(target_os = "windows")]
            Self::WinPcap(w) => match w {
                Some(w) => w.get_counter_handle(),
                None => Arc::new(WinPcapCounter::default()),
            },
        }
    }
}

#[cfg(target_os = "linux")]
impl Default for RecvEngine {
    fn default() -> Self {
        Self::AfPacket(Tpacket::new(Options::default()).unwrap())
    }
}

#[cfg(target_os = "windows")]
impl Default for RecvEngine {
    fn default() -> Self {
        Self::WinPcap(None)
    }
}

#[derive(Default)]
pub(super) struct Counter {
    pub(super) retired: AtomicU64,
    pub(super) kernel_packets: AtomicU64,
    pub(super) kernel_drops: AtomicU64,
    pub(super) kernel_freezes: AtomicU64,

    pub(super) poll_error: AtomicU64,
    pub(super) intr_error: AtomicU64,
}
