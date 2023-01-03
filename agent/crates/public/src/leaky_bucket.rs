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

use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const TICK_INTERVAL: Duration = Duration::from_millis(100);
const TICK_PER_SECOND: u64 =
    (Duration::from_secs(1).as_millis() / TICK_INTERVAL.as_millis()) as u64;
const BURST_MULTIPLE: u64 = 10;

pub struct LeakyBucket {
    rate: Arc<AtomicU64>,
    token: Arc<AtomicU64>,
    running: Arc<AtomicBool>,

    handle: JoinHandle<()>,
}

impl LeakyBucket {
    pub fn new(rate: Option<u64>) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let rate = Arc::new(AtomicU64::new(rate.unwrap_or(0)));
        let token = Arc::new(AtomicU64::new(0));

        let t_running = running.clone();
        let t_rate = rate.clone();
        let t_token = token.clone();
        let handle = thread::Builder::new()
            .name("leaky-bucket".to_owned())
            .spawn(move || {
                let mut rate = 0;
                let mut quantity_per_tick = 0;
                let mut full = 0;
                let token = t_token;
                while t_running.load(Ordering::Relaxed) {
                    let new_rate = t_rate.load(Ordering::Relaxed);
                    if new_rate == 0 || new_rate != rate {
                        rate = new_rate;
                        if rate == 0 {
                            thread::park();
                            continue;
                        }
                        quantity_per_tick = 1.max(rate / TICK_PER_SECOND);
                        full = quantity_per_tick * BURST_MULTIPLE;
                        token.store(full, Ordering::Release);
                    }

                    let _ = token.fetch_update(Ordering::Release, Ordering::Relaxed, |t| {
                        if t + quantity_per_tick > full {
                            None
                        } else {
                            Some(t + quantity_per_tick)
                        }
                    });

                    thread::park_timeout(TICK_INTERVAL);
                }
            })
            .unwrap();

        LeakyBucket {
            rate,
            token,
            running,
            handle,
        }
    }

    pub fn set_rate(&self, rate: Option<u64>) {
        self.rate.store(rate.unwrap_or(0), Ordering::Relaxed);
        self.handle.thread().unpark();
    }

    pub fn acquire(&self, size: u64) -> bool {
        if self.rate.load(Ordering::Relaxed) == 0 {
            return true;
        }

        self.token
            .fetch_update(Ordering::Release, Ordering::Relaxed, |t| {
                if t < size {
                    None
                } else {
                    Some(t - size)
                }
            })
            .is_ok()
    }
}

impl Default for LeakyBucket {
    fn default() -> Self {
        Self::new(None)
    }
}

impl Drop for LeakyBucket {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        self.handle.thread().unpark();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate() {
        for (i, rate) in vec![1000, 10000000].into_iter().enumerate() {
            let bucket = if i % 2 == 0 {
                let bucket = LeakyBucket::new(None);
                bucket.set_rate(Some(rate));
                bucket
            } else {
                LeakyBucket::new(Some(rate))
            };
            thread::sleep(TICK_INTERVAL / 10);
            assert!(
                bucket.acquire(BURST_MULTIPLE * rate / TICK_PER_SECOND),
                "failed acquiring for rate {}",
                rate
            );
            assert!(!bucket.acquire(1), "failed leaking for rate {}", rate);
            thread::sleep(TICK_INTERVAL + TICK_INTERVAL / 10);
            for _ in 0..10 {
                assert!(
                    bucket.acquire(rate / 10 / TICK_PER_SECOND),
                    "failed acquiring for rate {}",
                    rate
                );
            }
            assert!(
                !bucket.acquire(rate / 10 / TICK_PER_SECOND),
                "failed leaking for rate {}",
                rate
            );
        }

        let unlimited = LeakyBucket::new(None);
        for _ in 0..1000 {
            assert!(
                unlimited.acquire(u64::MAX),
                "failed acquiring for unlimited rate"
            );
        }
    }
}
