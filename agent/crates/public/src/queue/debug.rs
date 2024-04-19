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

use std::{
    fmt::Debug,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use log::debug;

use super::{bounded, Error, Receiver, Sender, StatsHandle};

use crate::debug::{QueueDebugger, QUEUE_LEN};

pub struct DebugSender<T> {
    debug: (Sender<String>, Arc<AtomicBool>),
    sender: Sender<T>,
}

impl<T: Debug> DebugSender<T> {
    pub fn send(&self, msg: T) -> Result<(), Error<T>> {
        if self.debug.1.load(Ordering::Relaxed) {
            if let Err(e) = self.debug.0.send(format!("{:?}", msg)) {
                debug!("failed to send: {:?}", e);
            }
        }
        self.sender.send(msg)
    }

    fn send_debug(&self, msgs: &Vec<T>) {
        if self.debug.1.load(Ordering::Relaxed) {
            let mut batch = Vec::with_capacity(QUEUE_LEN);
            for chunk in msgs.chunks(QUEUE_LEN) {
                batch.extend(chunk.iter().map(|msg| format!("{:?}", msg)));
                if let Err(e) = self.debug.0.send_all(&mut batch) {
                    debug!("failed to send_all: {:?}", e);
                    batch.clear();
                }
            }
        }
    }

    pub fn send_all(&self, msgs: &mut Vec<T>) -> Result<(), Error<T>> {
        self.send_debug(&msgs);
        self.sender.send_all(msgs)
    }
}

impl<T> Clone for DebugSender<T> {
    fn clone(&self) -> Self {
        Self {
            debug: self.debug.clone(),
            sender: self.sender.clone(),
        }
    }
}

pub fn bounded_with_debug<T>(
    size: usize,
    name: &'static str,
    debugger: &QueueDebugger,
) -> (DebugSender<T>, Receiver<T>, StatsHandle<T>) {
    let (sender, receiver, handle) = bounded(size);

    let (debug_sender, debug_receiver, _) = bounded(QUEUE_LEN);
    let enabled = Arc::new(AtomicBool::new(false));
    debugger.append_queue(name, debug_receiver, enabled.clone());

    let sender = DebugSender {
        debug: (debug_sender, enabled),
        sender,
    };

    (sender, receiver, handle)
}
