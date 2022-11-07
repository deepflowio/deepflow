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
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
    time::Duration,
};

const NANOS_PER_SEC: u32 = 1_000_000_000;
const NANOS_PER_MILLI: u32 = 1_000_000;
const NANOS_PER_MICRO: u32 = 1_000;
const MILLIS_PER_SEC: u64 = 1_000;
const MICROS_PER_SEC: u64 = 1_000_000;

#[derive(Default)]
pub struct AtomicDuration {
    secs: AtomicU64,
    nanos: AtomicU32, // Always 0 <= nanos < NANOS_PER_SEC
}

impl AtomicDuration {
    pub fn new(secs: u64, nanos: u32) -> Self {
        Self {
            secs: AtomicU64::new(secs),
            nanos: AtomicU32::new(nanos),
        }
    }

    pub fn from_nanos(nanos: u64) -> Self {
        Self {
            secs: AtomicU64::new(nanos / (NANOS_PER_SEC as u64)),
            nanos: AtomicU32::new((nanos % (NANOS_PER_SEC as u64)) as u32),
        }
    }

    pub fn swap(&self, duration: Duration) -> Duration {
        let nanos = duration.as_nanos();
        let secs = nanos / (NANOS_PER_SEC as u128);
        let nanos = nanos % (NANOS_PER_SEC as u128);
        let prev_secs = self.secs.swap(secs as u64, Ordering::Relaxed);
        let prev_nanos = self.nanos.swap(nanos as u32, Ordering::Relaxed);

        Duration::new(prev_secs, prev_nanos)
    }

    pub fn as_nanos(&self) -> u128 {
        self.secs.load(Ordering::Relaxed) as u128 * NANOS_PER_SEC as u128
            + self.nanos.load(Ordering::Relaxed) as u128
    }

    pub fn as_millis(&self) -> u128 {
        self.secs.load(Ordering::Relaxed) as u128 * MILLIS_PER_SEC as u128
            + (self.nanos.load(Ordering::Relaxed) / NANOS_PER_MILLI) as u128
    }

    pub fn as_micros(&self) -> u128 {
        self.secs.load(Ordering::Relaxed) as u128 * MICROS_PER_SEC as u128
            + (self.nanos.load(Ordering::Relaxed) / NANOS_PER_MICRO) as u128
    }

    pub fn checked_add(&self, rhs: Duration) -> bool {
        let mut result = true;

        let rhs_nanos = rhs.as_nanos();
        let rhs_secs = (rhs_nanos / (NANOS_PER_SEC as u128)) as u64;
        let rhs_nanos = (rhs_nanos % (NANOS_PER_SEC as u128)) as u32;

        let _ = self
            .secs
            .fetch_update(Ordering::Release, Ordering::Acquire, |secs| {
                if let Some(mut secs) = secs.checked_add(rhs_secs) {
                    let _ =
                        self.nanos
                            .fetch_update(Ordering::Release, Ordering::Acquire, |nanos| {
                                let mut nanos = nanos + rhs_nanos;
                                if nanos >= NANOS_PER_SEC {
                                    nanos -= NANOS_PER_SEC;
                                    if let Some(new_secs) = secs.checked_add(1) {
                                        secs = new_secs;
                                    } else {
                                        result = false;
                                        return None;
                                    }
                                }
                                debug_assert!(nanos < NANOS_PER_SEC);
                                Some(nanos)
                            });
                    Some(secs)
                } else {
                    result = false;
                    None
                }
            });

        result
    }

    pub fn checked_div(self, rhs: u32) -> bool {
        if rhs == 0 {
            return false;
        }
        let _ = self
            .secs
            .fetch_update(Ordering::Release, Ordering::Acquire, |secs| {
                let div_secs = secs / (rhs as u64);
                let carry = secs - div_secs * (rhs as u64);
                let extra_nanos = carry * (NANOS_PER_SEC as u64) / (rhs as u64);
                let _ = self
                    .nanos
                    .fetch_update(Ordering::Release, Ordering::Acquire, |nanos| {
                        let nanos = nanos / rhs + (extra_nanos as u32);
                        debug_assert!(nanos < NANOS_PER_SEC);
                        Some(nanos)
                    });
                Some(div_secs)
            });

        true
    }
}

impl PartialEq<Duration> for AtomicDuration {
    fn eq(&self, other: &Duration) -> bool {
        self.as_nanos().eq(&other.as_nanos())
    }
}

impl PartialOrd<Duration> for AtomicDuration {
    fn partial_cmp(&self, other: &Duration) -> Option<std::cmp::Ordering> {
        self.as_nanos().partial_cmp(&other.as_nanos())
    }
}

#[derive(Default)]
pub struct AtomicTimeStats {
    pub count: AtomicU32,
    pub sum: AtomicDuration,
    pub max: AtomicDuration,
}

impl AtomicTimeStats {
    pub fn update(&self, duration: Duration) {
        if !self.sum.checked_add(duration) {
            return;
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        if self.max < duration {
            self.max.swap(duration);
        }
    }
}
