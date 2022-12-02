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

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use public::proto::trident::Exception;

#[derive(Clone, Debug, Default)]
pub struct ExceptionHandler(Arc<AtomicU64>);

impl ExceptionHandler {
    pub fn set(&self, e: Exception) {
        self.0.fetch_or(e as u64, Ordering::SeqCst);
    }

    pub fn clear(&self, e: Exception) {
        self.0.fetch_and(!(e as u64), Ordering::SeqCst);
    }

    pub fn take(&self) -> u64 {
        self.0.swap(0, Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exceptions() {
        let mut expected = 0u64;
        let h = ExceptionHandler::default();

        h.set(Exception::DiskNotEnough);
        expected |= Exception::DiskNotEnough as u64;
        assert_eq!(h.take(), expected);

        let exceptions = vec![
            Exception::DiskNotEnough,
            Exception::MemNotEnough,
            Exception::CorefileTooMany,
            Exception::NpbFuse,
            Exception::NpbNoGwArp,
            Exception::AnalyzerNoGwArp,
        ];
        expected = 0;
        for e in exceptions {
            h.set(e);
            expected |= e as u64;
            assert_eq!(h.0.load(Ordering::Relaxed), expected);
        }

        h.clear(Exception::DiskNotEnough);
        expected &= !(Exception::DiskNotEnough as u64);
        assert_eq!(h.0.load(Ordering::Relaxed), expected);

        assert_eq!(h.take(), expected);
        assert_eq!(h.0.load(Ordering::Relaxed), 0);
    }
}
