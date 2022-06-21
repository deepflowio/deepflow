use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use chrono::{DateTime, Utc};

use crate::common::enums::TapType;

mod manager;
mod worker;
mod writer;

pub use manager::WorkerManager;

const GLOBAL_HEADER_LEN: usize = 24;
const RECORD_HEADER_LEN: usize = 16;
const TS_SEC_OFFSET: usize = 0;
const INCL_LEN_OFFSET: usize = 8;
const PCAP_MAGIC: u32 = 0xa1b2c3d4;
const VERSION_MAJOR: u16 = 2;
const VERSION_MINOR: u16 = 2;
const SNAP_LEN: u32 = 65535;

// strtime format
const TIME_FORMAT: &str = "%y%m%d%H%M%S";

#[derive(Debug)]
pub struct Packet {
    timestamp: Duration,
    tap_type: TapType,
    acl_gid: u16,
    pkt_len: u16,
    vtap_id: u16,
    dispatcher_id: u32,
    raw_pkt: Vec<u8>,
}

#[derive(Debug)]
pub enum PcapPacket {
    Packet(Packet),
    Terminated,
}

impl Packet {
    pub fn bytes(&self) -> &[u8] {
        &self.raw_pkt
    }

    pub fn timestamp(&self) -> Duration {
        self.timestamp
    }

    pub fn pkt_len(&self) -> u16 {
        self.pkt_len
    }
}

fn format_time(dur: Duration) -> String {
    let time_point = SystemTime::UNIX_EPOCH
        .checked_add(dur)
        .expect("Failed to parse timestamp");
    DateTime::<Utc>::from(time_point)
        .format(TIME_FORMAT)
        .to_string()
}

fn get_temp_filename(
    base: &Path,
    acl_gid: u16,
    tap_type: TapType,
    dispatcher_id: u32,
    timestamp: Duration,
    vtap_id: u16,
) -> PathBuf {
    let formatted_time = format_time(timestamp);
    let mut filename = base.to_path_buf();
    filename.push(format!("{}", acl_gid));
    filename.push(format!(
        "{}_{:012x}_0_{}_.{}.pcap.temp",
        tap_type, dispatcher_id, formatted_time, vtap_id
    ));

    filename
}
