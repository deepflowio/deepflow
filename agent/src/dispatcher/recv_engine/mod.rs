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

pub(crate) mod af_packet;
pub(crate) mod bpf;

use std::sync::{atomic::AtomicU64, Arc};
use std::time::Duration;

use thiserror::Error;

pub use af_packet::OptTpacketVersion;
use af_packet::{
    options::Options,
    tpacket::{Packet, Tpacket},
};

use crate::utils::stats;

pub const DEFAULT_BLOCK_SIZE: usize = 1 << 20;
pub const FRAME_SIZE_MAX: usize = 1 << 16; // local and mirror
pub const FRAME_SIZE_MIN: usize = 1 << 11; // analyzer
pub const POLL_TIMEOUT: Duration = Duration::from_millis(100);

pub(super) enum RecvEngine {
    AfPacket(Tpacket),
    Dpdk(),
}

impl RecvEngine {
    pub fn init(&mut self) -> Result<()> {
        match self {
            Self::AfPacket(_) => Ok(()),
            Self::Dpdk() => todo!(),
        }
    }

    pub fn close(&mut self) {
        todo!()
    }

    pub fn recv(&mut self) -> Result<Packet> {
        match self {
            Self::AfPacket(e) => match e.read() {
                Some(p) => Ok(p),
                None => Err(Error::Timeout),
            },
            Self::Dpdk() => todo!(),
        }
    }

    pub fn set_bpf(&mut self, s: Vec<af_packet::RawInstruction>) -> Result<()> {
        match self {
            Self::AfPacket(e) => e.set_bpf(s).map_err(|e| e.into()),
            Self::Dpdk() => todo!(),
        }
    }

    pub fn get_counter_handle(&self) -> Arc<dyn stats::RefCountable> {
        match self {
            Self::AfPacket(e) => Arc::new(e.get_counter_handle()),
            Self::Dpdk() => todo!(),
        }
    }
}

impl Default for RecvEngine {
    fn default() -> Self {
        Self::AfPacket(Tpacket::new(Options::default()).unwrap())
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

#[derive(Debug, Error)]
pub enum Error {
    #[error("timeout")]
    Timeout,
    #[error("afpacket error")]
    AfPacketError(#[from] af_packet::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
