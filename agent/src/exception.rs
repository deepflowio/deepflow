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

use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

use public::proto::agent::Exception;

#[derive(Clone, Debug, Default)]
pub struct ExceptionHandler {
    exception: Arc<AtomicU64>,
    descriptions: Arc<Mutex<HashMap<u64, String>>>,
}

impl ExceptionHandler {
    const AUTO_CLEAR_BITS: u64 = Exception::NpbNoGwArp as u64
        | Exception::AnalyzerNoGwArp as u64
        | Exception::NpbBpsThresholdExceeded as u64
        | Exception::RxPpsThresholdExceeded as u64
        | Exception::ProcessThresholdExceeded as u64
        | Exception::ThreadThresholdExceeded as u64
        | Exception::LogFileExceeded as u64
        | Exception::ControllerSocketError as u64
        | Exception::AnalyzerSocketError as u64
        | Exception::IntegrationSocketError as u64
        | Exception::NpbSocketError as u64
        | Exception::DataBpsThresholdExceeded as u64;

    pub fn set(&self, e: Exception, description: Option<String>) {
        self.exception.fetch_or(e as u64, Ordering::SeqCst);
        if let Some(d) = description {
            self.descriptions.lock().unwrap().insert(e as u64, d);
        }
    }

    pub fn has(&self, e: Exception) -> bool {
        let e = e as u64;
        self.exception.load(Ordering::Relaxed) & e == e
    }

    pub fn clear(&self, e: Exception) {
        self.exception.fetch_and(!(e as u64), Ordering::SeqCst);
        self.descriptions.lock().unwrap().remove(&(e as u64));
    }

    pub fn take(&self) -> (u64, Option<String>) {
        let bits = self
            .exception
            .fetch_and(!Self::AUTO_CLEAR_BITS, Ordering::SeqCst);
        let mut descriptions = self.descriptions.lock().unwrap();
        let mut result = vec![];
        for i in 0..64 {
            let bit = 1u64 << i;
            if bits & bit == bit {
                let mut description = if bit & Self::AUTO_CLEAR_BITS == bit {
                    descriptions.remove(&bit)
                } else {
                    descriptions.get(&bit).cloned()
                };

                if let Some(d) = description.take() {
                    result.push(d);
                }
            }
        }

        (
            bits,
            if result.is_empty() {
                None
            } else {
                Some(result.join(";"))
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exceptions() {
        let mut expected = 0u64;
        let h = ExceptionHandler::default();

        h.set(Exception::DiskNotEnough, None);
        expected |= Exception::DiskNotEnough as u64;
        assert_eq!(h.take().0, expected);

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
            h.set(e, None);
            expected |= e as u64;
            assert_eq!(h.exception.load(Ordering::Relaxed), expected);
        }

        h.clear(Exception::DiskNotEnough);
        expected &= !(Exception::DiskNotEnough as u64);
        assert_eq!(h.exception.load(Ordering::Relaxed), expected);

        assert_eq!(h.take().0, expected);
        expected &= !(ExceptionHandler::AUTO_CLEAR_BITS);
        assert_eq!(h.exception.load(Ordering::Relaxed), expected);

        let h = ExceptionHandler::default();
        h.set(
            Exception::ControllerSocketError,
            Some("controller socket error".to_string()),
        );
        h.set(
            Exception::MemNotEnough,
            Some("memory not enough".to_string()),
        );
        let (bits, descriptions) = h.take();
        assert_eq!(
            bits,
            (Exception::ControllerSocketError as u64) | (Exception::MemNotEnough as u64)
        );
        assert_eq!(
            descriptions,
            Some("memory not enough;controller socket error".to_string())
        );
        let (bits, descriptions) = h.take();
        assert_eq!(bits, Exception::MemNotEnough as u64);
        assert_eq!(descriptions, Some("memory not enough".to_string()));
    }
}
