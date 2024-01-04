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

// This module provides a 8B timestamp struct for memory-sensitive structs
// std::time::Duration is 16B

use std::cmp::Ordering;
use std::fmt;
use std::ops::{Add, AddAssign, Sub, SubAssign};
use std::time::Duration;

use serde::Serializer;

#[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(u64);

impl From<Duration> for Timestamp {
    fn from(d: Duration) -> Self {
        Self(d.as_nanos() as u64)
    }
}

impl From<Timestamp> for Duration {
    fn from(t: Timestamp) -> Self {
        Self::from_nanos(t.as_nanos())
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Duration::from(*self).fmt(f)
    }
}

impl Timestamp {
    const NANOS_IN_SECOND: u64 = Duration::from_secs(1).as_nanos() as u64;
    const NANOS_IN_MILLIS: u64 = Duration::from_millis(1).as_nanos() as u64;
    const NANOS_IN_MICROS: u64 = Duration::from_micros(1).as_nanos() as u64;

    pub const ZERO: Self = Self(0);

    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    pub const fn as_nanos(&self) -> u64 {
        self.0
    }

    pub const fn from_micros(micros: u64) -> Self {
        Self(micros * Self::NANOS_IN_MICROS)
    }

    pub const fn as_micros(&self) -> u64 {
        self.0 / Self::NANOS_IN_MICROS
    }

    pub const fn from_millis(millis: u64) -> Self {
        Self(millis * Self::NANOS_IN_MILLIS)
    }

    pub const fn as_millis(&self) -> u64 {
        self.0 / Self::NANOS_IN_MILLIS
    }

    pub const fn from_secs(secs: u64) -> Self {
        Self(secs * Self::NANOS_IN_SECOND)
    }

    pub const fn as_secs(&self) -> u64 {
        self.0 / Self::NANOS_IN_SECOND
    }

    pub const fn is_zero(&self) -> bool {
        self.0 == 0
    }

    pub const fn round_to(&self, rhs: Self) -> Self {
        Self(self.0 / rhs.0 * rhs.0)
    }

    pub const fn round_to_minute(&self) -> Self {
        self.round_to(Timestamp::from_secs(60))
    }
}

impl PartialEq<Duration> for Timestamp {
    fn eq(&self, other: &Duration) -> bool {
        self.0.eq(&(other.as_nanos() as u64))
    }
}

impl PartialEq<Timestamp> for Duration {
    fn eq(&self, other: &Timestamp) -> bool {
        other.eq(self)
    }
}

impl PartialOrd<Duration> for Timestamp {
    fn partial_cmp(&self, other: &Duration) -> Option<Ordering> {
        Some(self.0.cmp(&(other.as_nanos() as u64)))
    }
}

impl PartialOrd<Timestamp> for Duration {
    fn partial_cmp(&self, other: &Timestamp) -> Option<Ordering> {
        other.partial_cmp(self).map(Ordering::reverse)
    }
}

impl Add for Timestamp {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Add<Duration> for Timestamp {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        self + Self::from(rhs)
    }
}

impl AddAssign for Timestamp {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl Sub for Timestamp {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        if self.0 < rhs.0 {
            panic!("overflow when subtracting timestamp")
        }
        Self(self.0 - rhs.0)
    }
}

impl Sub<Timestamp> for Duration {
    type Output = Self;

    fn sub(self, rhs: Timestamp) -> Self::Output {
        self - Self::from(rhs)
    }
}

impl Sub<Duration> for Timestamp {
    type Output = Self;

    fn sub(self, rhs: Duration) -> Self::Output {
        self - Self::from(rhs)
    }
}

impl SubAssign for Timestamp {
    fn sub_assign(&mut self, rhs: Self) {
        if self.0 < rhs.0 {
            panic!("overflow when subtracting timestamp")
        }
        self.0 -= rhs.0;
    }
}

pub fn timestamp_to_micros<S>(d: &Timestamp, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u64(d.as_micros())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion() {
        let d = Duration::from_secs(123);
        assert_eq!(d, Duration::from(Timestamp::from(d)));
    }

    #[test]
    fn comparison() {
        assert_eq!(
            Timestamp::from_secs(123),
            Timestamp::from(Duration::from_secs(123))
        );
        assert_eq!(Timestamp::from_nanos(123), Duration::from_nanos(123));
        assert_eq!(Timestamp::from_micros(123), Duration::from_micros(123));
        assert_eq!(Timestamp::from_secs(123), Duration::from_secs(123));
        assert_eq!(
            Timestamp::from_secs(123).as_nanos(),
            Duration::from_secs(123).as_nanos() as u64
        );
        assert_eq!(
            Timestamp::from_secs(123).as_micros(),
            Duration::from_secs(123).as_micros() as u64
        );
        assert_eq!(
            Timestamp::from_secs(123).as_secs(),
            Duration::from_secs(123).as_secs()
        );

        assert!(Timestamp::from_nanos(123) < Timestamp::from_secs(123));
        assert!(Timestamp::from_micros(123) < Timestamp::from_secs(123));
        assert!(Timestamp::from_secs(124) > Timestamp::from_secs(123));

        assert!(Duration::new(1571105646, 245884000) > Timestamp::ZERO);
        assert!(Duration::from_secs(124) > Timestamp::from_secs(123));
        assert!(Timestamp::from_micros(123) < Duration::from_secs(123));
    }

    #[test]
    fn arithmetics() {
        assert_eq!(
            Timestamp::from_micros(123) + Timestamp::from_micros(456),
            Duration::from_micros(579)
        );
        assert_eq!(
            Timestamp::from_nanos(123) + Duration::from_nanos(456),
            Duration::from_nanos(579)
        );
        assert_eq!(
            Duration::from_secs(987) - Timestamp::from_secs(654),
            Duration::from_secs(333)
        );
        assert_eq!(
            Timestamp::from_micros(987) - Duration::from_micros(654),
            Duration::from_micros(333)
        );
    }
}
