pub(crate) mod af_packet;
pub(crate) mod bpf;

use std::ffi::CStr;
use std::sync::{atomic::AtomicU64, Arc};
use std::time::Duration;

use thiserror::Error;

pub use af_packet::OptTpacketVersion;
use af_packet::{
    options::Options,
    tpacket::{Packet, Tpacket},
};

pub const DEFAULT_BLOCK_SIZE: usize = 1 << 20;
pub const FRAME_SIZE_MAX: usize = 1 << 16; // local and mirror
pub const FRAME_SIZE_MIN: usize = 1 << 11; // analyzer
pub const POLL_TIMEOUT: Duration = Duration::from_millis(100);

pub(super) enum RecvEngine {
    AfPacket(Tpacket),
    Dpdk(Arc<Counter>),
}

impl RecvEngine {
    pub fn init(&mut self) -> Result<()> {
        match self {
            Self::AfPacket(_) => Ok(()),
            Self::Dpdk(_) => todo!(),
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
            Self::Dpdk(_) => todo!(),
        }
    }

    pub fn set_bpf(&mut self, s: &CStr) -> Result<()> {
        match self {
            Self::AfPacket(e) => e.set_bpf(s).map_err(|e| e.into()),
            Self::Dpdk(_) => todo!(),
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
