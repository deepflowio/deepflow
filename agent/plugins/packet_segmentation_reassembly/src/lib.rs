/*
 * Copyright (c) 2024 Yunshan Networks
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

use public::packet::Downcast;

pub trait Segment: Downcast {
    fn is_c2s(&self) -> bool;
    fn get_tcp_seq(&self) -> u32;
    fn next_tcp_seq(&self) -> u32;
    fn merge_segments(&mut self, other: &[u8]);
    fn get_payload(&self) -> &[u8];
    fn get_payload_length(&self) -> u16;
}

#[derive(Default)]
pub struct PacketSegmentationReassembly {}

impl PacketSegmentationReassembly {
    pub fn does_support() -> bool {
        false
    }

    pub fn reverse(&mut self) {}

    pub fn flush(&mut self) -> Option<Vec<Box<dyn Segment>>> {
        None
    }

    pub fn inject(&mut self, _: Box<dyn Segment>) -> Option<Vec<Box<dyn Segment>>> {
        None
    }
}
