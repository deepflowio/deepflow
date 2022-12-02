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

//! Enterprise Edition Feature: RawPcap Assembler

use std::sync::atomic::AtomicI64;
use std::sync::Arc;
use std::time::Duration;

use public::counter::{Counter, RefCountable};
use public::packet::MiniPacket;
use public::proto::trident::PcapBatch;
use public::queue::{DebugSender, Receiver};
use public::sender::{SendMessageType, Sendable};

pub struct PcapAssembler {
    pub counter: Arc<AssemblerCounter>,
}

pub struct AssemblerCounter;

impl RefCountable for AssemblerCounter {
    fn get_counters(&self) -> Vec<Counter> {
        vec![]
    }
}

#[derive(Debug)]
pub struct BoxedPcapBatch(pub Box<PcapBatch>);

impl Sendable for BoxedPcapBatch {
    fn encode(self, _: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        Ok(0)
    }

    fn message_type(&self) -> SendMessageType {
        SendMessageType::RawPcap
    }
}

impl PcapAssembler {
    pub fn new(
        _: u32,
        _: bool,
        _: u64,
        _: u32,
        _: Duration,
        _: DebugSender<BoxedPcapBatch>,
        _: Receiver<MiniPacket>,
        _: Arc<AtomicI64>,
    ) -> Self {
        PcapAssembler {
            counter: Arc::new(AssemblerCounter),
        }
    }

    pub fn start(&self) {}

    pub fn stop(&self) {}
}
