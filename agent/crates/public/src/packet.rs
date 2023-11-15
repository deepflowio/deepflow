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

use std::fmt;
use std::io::{Result, Write};
use std::time::Duration;

use crate::consts::RECORD_HEADER_LEN;

pub const SECONDS_IN_MINUTE: u64 = 60;

#[derive(Debug, Default)]
pub struct Packet<'a> {
    pub timestamp: Duration,
    pub if_index: isize,
    pub capture_length: isize,
    pub data: &'a mut [u8],
    // Some scene packet will be copied and stored in raw, and referenced by data
    pub raw: Option<*mut u8>,
}

unsafe impl Send for Packet<'_> {}
unsafe impl Sync for Packet<'_> {}

impl Drop for Packet<'_> {
    fn drop(&mut self) {
        if let Some(p) = self.raw {
            unsafe {
                Vec::from_raw_parts(p, 0, self.data.len());
            }
        }
    }
}

pub struct MiniPacket {
    pub packet: Vec<u8>,
    pub timestamp: Duration,
    pub flow_id: u64,
    pub acl_gids: Vec<u16>,
    pub second_in_minute: u8,
}

impl fmt::Debug for MiniPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MiniPacket")
            .field("packet_len", &self.packet.len())
            .field("timestamp", &self.timestamp)
            .field("second_in_minute", &self.second_in_minute)
            .field("flow_id", &self.flow_id)
            .field("acl_gids", &self.flow_id)
            .finish()
    }
}

impl MiniPacket {
    pub fn record_len(&self) -> usize {
        self.packet.len() + RECORD_HEADER_LEN
    }

    pub fn start_time_in_minute(&self) -> Duration {
        let second_in_minute = self.second_in_minute as u64;
        Duration::from_secs(
            (self.timestamp.as_secs() - second_in_minute) / SECONDS_IN_MINUTE * SECONDS_IN_MINUTE
                + second_in_minute,
        )
    }
}

pub fn write_record_header(
    writer: &mut impl Write,
    ts: Duration,
    raw_pkt_len: u32,
    pkt_len: u32,
) -> Result<()> {
    writer.write((ts.as_secs() as u32).to_le_bytes().as_slice())?;
    writer.write((ts.subsec_micros() as u32).to_le_bytes().as_slice())?;
    writer.write(raw_pkt_len.to_le_bytes().as_slice())?;
    writer.write(pkt_len.to_le_bytes().as_slice())?;
    Ok(())
}
