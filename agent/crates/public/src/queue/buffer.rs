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

use super::{DebugSender, Error, Sender};

enum SenderFlavor<T> {
    Sender(Sender<T>),
    DebugSender(DebugSender<T>),
}

pub const DEFAULT_BUFFER_SIZE: usize = 1024;

pub struct BufferedSender<T> {
    s: SenderFlavor<T>,

    buffer: Vec<T>,
    size: usize,
}

impl<T> From<Sender<T>> for BufferedSender<T> {
    fn from(s: Sender<T>) -> Self {
        Self {
            s: SenderFlavor::Sender(s),
            buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
            size: DEFAULT_BUFFER_SIZE,
        }
    }
}

impl<T: std::fmt::Debug> From<DebugSender<T>> for BufferedSender<T> {
    fn from(s: DebugSender<T>) -> Self {
        Self {
            s: SenderFlavor::DebugSender(s),
            buffer: Vec::with_capacity(DEFAULT_BUFFER_SIZE),
            size: DEFAULT_BUFFER_SIZE,
        }
    }
}

impl<T: std::fmt::Debug> BufferedSender<T> {
    pub fn resize(&mut self, size: usize) -> Result<(), Error<T>> {
        if size < self.buffer.len() {
            self.flush()?;
        }
        self.buffer.shrink_to(size);
        self.size = size;
        Ok(())
    }

    pub fn send(&mut self, msg: T) -> Result<(), Error<T>> {
        if self.buffer.len() >= self.size {
            self.flush()?;
        }
        self.buffer.push(msg);
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), Error<T>> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        match &self.s {
            SenderFlavor::Sender(s) => s.send_all(&mut self.buffer),
            SenderFlavor::DebugSender(s) => s.send_all(&mut self.buffer),
        }
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}
