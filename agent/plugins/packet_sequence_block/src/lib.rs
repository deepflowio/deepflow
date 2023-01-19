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

//! Enterprise Edition Feature: packet-sequence
use std::time::Duration;

use public::sender::{SendMessageType, Sendable};

#[derive(Debug, Default, PartialEq)]
pub struct PacketData {}

#[derive(Debug, Default, PartialEq)]
pub struct PacketSequenceBlock {}

impl PacketSequenceBlock {
    pub fn new(_: u32) -> Self {
        unimplemented!();
    }

    pub fn is_available(&self, _: usize, _: u32) -> bool {
        unimplemented!();
    }

    pub fn convert_duration_to_timestamp(_: usize, _: Duration) -> u64 {
        unimplemented!();
    }

    pub fn append_packet(&self, _: MiniMetaPacket, _: u8) {
        unimplemented!();
    }

    pub fn reverse_needed_for_new_packet(&mut self) {
        unimplemented!();
    }
}

#[derive(Debug)]
pub struct BoxedPacketSequenceBlock(pub Box<PacketSequenceBlock>);

impl Sendable for BoxedPacketSequenceBlock {
    fn encode(self, _: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        Ok(0)
    }

    fn message_type(&self) -> SendMessageType {
        SendMessageType::PacketSequenceBlock
    }
}

pub struct MiniMetaPacket<'a> {
    _foo: &'a Option<Vec<u8>>,
}

impl<'a> MiniMetaPacket<'a> {
    pub fn new(
        _: u64,
        _: u8,
        _: Duration,
        _: u16,
        _: u32,
        _: u32,
        _: u16,
        _: u16,
        _: u8,
        _: u8,
        _: bool,
        _: &'a Option<Vec<u8>>,
    ) -> Self {
        MiniMetaPacket { _foo: &None }
    }
}
