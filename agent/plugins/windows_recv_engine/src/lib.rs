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

//! Enterprise Edition Feature: windows-dispatcher

use std::sync::Arc;

use public::counter;
use public::error::Result;
use public::packet;

#[derive(Default)]
pub struct WinPcapCounter;

impl counter::RefCountable for WinPcapCounter {
    fn get_counters(&self) -> Vec<counter::Counter> {
        unimplemented!();
    }
}

pub struct WinPacket;

impl WinPacket {
    pub fn new(_: Vec<(&str, isize)>, _: usize, _: usize) -> Result<Self> {
        unimplemented!();
    }

    pub fn read(&mut self) -> Result<packet::Packet> {
        unimplemented!();
    }

    pub fn set_bpf(&mut self, _: &str) -> Result<()> {
        unimplemented!();
    }

    pub fn get_counter_handle(&self) -> Arc<dyn counter::RefCountable> {
        unimplemented!();
    }
}
