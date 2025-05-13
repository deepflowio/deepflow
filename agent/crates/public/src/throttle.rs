/*
 * Copyright (c) 2025 Yunshan Networks
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

use crate::queue::DebugSender;
use crate::LeakyBucket;
use log::warn;
use rand::prelude::{Rng, SeedableRng, SmallRng};
use std::fmt::Debug;
use std::sync::Arc;

pub trait ThrottleCounter {
    fn throttle_dropped(&self);
}

const BUFFER_SIZE: usize = 1024;
pub struct Throttle<T: Debug, C: ThrottleCounter> {
    leaky_bucket: LeakyBucket,
    tick_counter: u64,
    period_count: u32,
    buffer: Vec<T>,
    output_queue: DebugSender<T>,
    small_rng: SmallRng,
    counter: Arc<C>,
}

impl<T: Debug, C: ThrottleCounter> Throttle<T, C> {
    pub fn new(rate: u64, output_queue: DebugSender<T>, counter: Arc<C>) -> Self {
        Throttle {
            leaky_bucket: LeakyBucket::new(Some(rate)),
            tick_counter: 0,
            buffer: Vec::with_capacity(BUFFER_SIZE),
            output_queue,
            small_rng: SmallRng::from_entropy(),
            period_count: 0,
            counter,
        }
    }

    pub fn put(&mut self, item: T) {
        let leaky_tick_counter = self.leaky_bucket.tick_counter();
        if self.tick_counter < leaky_tick_counter {
            self.period_count = 0;
            self.tick_counter = leaky_tick_counter;
            if !self.buffer.is_empty(){
                if let Err(e) = self.output_queue.send_all(&mut self.buffer) {
                    warn!(
                        "throttle push {} items to queue failed, because {:?}",
                        self.buffer.len(),
                        e
                    );
                    self.buffer.clear();
                }
            }
        }

        self.period_count += 1;
        if self.leaky_bucket.acquire(1) {
            self.buffer.push(item);
        } else {
            let index = self.small_rng.gen_range(0..self.period_count) as usize;
            if index < self.buffer.len() {
                self.buffer[index] = item;
            }
            self.counter.throttle_dropped();
        }
    }

    pub fn flush(&mut self) {
        if !self.buffer.is_empty() {
            if let Err(e) = self.output_queue.send_all(&mut self.buffer) {
                warn!(
                    "throttle push {} items to queue failed, because {:?}",
                    self.buffer.len(),
                    e
                );
                self.buffer.clear();
            }
        }
    }

    pub fn set_rate(&mut self, rate: u64) {
        self.leaky_bucket.set_rate(Some(rate));
    }
}
