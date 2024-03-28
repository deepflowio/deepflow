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

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
};

use log::{info, warn};
use packet_sequence_block::BoxedPacketSequenceBlock;

// Enterprise Edition Feature: packet-sequence
use super::consts;

use public::queue::{DebugSender, Error, Receiver};

pub struct PacketSequenceParser {
    input_queue: Arc<Receiver<Box<packet_sequence_block::PacketSequenceBlock>>>,
    output_queue: DebugSender<BoxedPacketSequenceBlock>,
    id: u32,
    running: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl PacketSequenceParser {
    pub fn new(
        input_queue: Receiver<Box<packet_sequence_block::PacketSequenceBlock>>,
        output_queue: DebugSender<BoxedPacketSequenceBlock>,
        id: u32,
    ) -> Self {
        PacketSequenceParser {
            input_queue: Arc::new(input_queue),
            output_queue,
            id,
            running: Default::default(),
            thread: Mutex::new(None),
        }
    }

    pub fn start(&self) {
        if self.running.swap(true, Ordering::Relaxed) {
            return;
        }

        let running = self.running.clone();
        let input_queue = self.input_queue.clone();
        let output_queue = self.output_queue.clone();

        let thread = thread::Builder::new()
            .name("packet-sequence-parser".to_owned())
            .spawn(move || {
                let mut blocks = Vec::with_capacity(consts::QUEUE_BATCH_SIZE);
                let mut batch = Vec::new();
                while running.load(Ordering::Relaxed) {
                    match input_queue.recv_all(&mut blocks, Some(consts::RCV_TIMEOUT)) {
                        Ok(_) => {
                            batch.reserve(blocks.len());
                            batch.extend(blocks.drain(..).map(|f| BoxedPacketSequenceBlock(f)));
                            if let Err(_) = output_queue.send_all(&mut batch) {
                                warn!(
                                    "packet sequence block to queue failed maybe queue have terminated"
                                );
                                batch.clear();
                            }
                        }
                        Err(Error::Timeout) => continue,
                        Err(Error::Terminated(..)) => break,
                        Err(Error::BatchTooLarge(_)) => unreachable!(),
                    };
                }
            })
            .unwrap();
        self.thread.lock().unwrap().replace(thread);
        info!("packet sequence parser (id={}) started", self.id);
    }

    pub fn stop(&mut self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            warn!(
                "packet sequence parser id: {} already stopped, do nothing.",
                self.id
            );
            return;
        }
        info!("stopping packet sequence parser: {}", self.id);
        if let Some(t) = self.thread.lock().unwrap().take() {
            let _ = t.join();
        }
        info!("stopped packet sequence parser: {}", self.id);
    }
}
