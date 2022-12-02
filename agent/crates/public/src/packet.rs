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

use std::fmt;
use std::io::{Result, Write};
use std::time::Duration;

use crate::consts::RECORD_HEADER_LEN;

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct Packet<'a> {
    pub timestamp: Duration,
    pub if_index: isize,
    pub capture_length: isize,
    pub data: &'a mut [u8],
}

#[cfg(target_os = "windows")]
#[derive(Debug)]
pub struct Packet {
    pub timestamp: Duration,
    pub if_index: isize,
    pub capture_length: isize,
    pub data: Vec<u8>,
}

pub struct MiniPacket {
    pub packet: Vec<u8>,
    pub timestamp: Duration,
    pub flow_id: u64,
}

impl fmt::Debug for MiniPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MiniPacket")
            .field("packet_len", &self.packet.len())
            .field("timestamp", &self.timestamp)
            .field("flow_id", &self.flow_id)
            .finish()
    }
}

impl MiniPacket {
    pub fn record_len(&self) -> usize {
        self.packet.len() + RECORD_HEADER_LEN
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
