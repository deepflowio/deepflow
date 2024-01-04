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

use std::sync::Weak;

use cadence::{
    ext::{MetricValue, ToCounterValue, ToGaugeValue},
    MetricResult,
};

#[derive(Clone, Copy, Debug)]
pub enum CounterType {
    Counted,
    Gauged,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CounterValue {
    Signed(i64),
    Unsigned(u64),
    Float(f64),
}

impl ToCounterValue for CounterValue {
    fn try_to_value(self) -> MetricResult<MetricValue> {
        Ok(match self {
            CounterValue::Signed(v) => MetricValue::Signed(v),
            // convert unsigned and float to signed for compatibility
            CounterValue::Unsigned(v) => MetricValue::Signed(v as i64),
            CounterValue::Float(v) => MetricValue::Signed(v as i64),
        })
    }
}

impl ToGaugeValue for CounterValue {
    fn try_to_value(self) -> MetricResult<MetricValue> {
        Ok(match self {
            CounterValue::Signed(v) => MetricValue::Signed(v),
            // convert unsigned and float to signed for compatibility
            CounterValue::Unsigned(v) => MetricValue::Signed(v as i64),
            CounterValue::Float(v) => MetricValue::Signed(v as i64),
        })
    }
}

pub type Counter = (&'static str, CounterType, CounterValue);

pub trait RefCountable: Send + Sync {
    fn get_counters(&self) -> Vec<Counter>;
}

pub trait OwnedCountable: Send + Sync {
    fn get_counters(&self) -> Vec<Counter>;
    fn closed(&self) -> bool;
}

pub enum Countable {
    Owned(Box<dyn OwnedCountable>),
    Ref(Weak<dyn RefCountable>),
}

impl Countable {
    pub fn get_counters(&self) -> Vec<Counter> {
        match self {
            Countable::Owned(c) => c.get_counters(),
            Countable::Ref(c) => c.upgrade().map(|c| c.get_counters()).unwrap_or_default(),
        }
    }

    pub fn closed(&self) -> bool {
        match self {
            Countable::Owned(c) => c.closed(),
            Countable::Ref(c) => c.strong_count() == 0,
        }
    }
}
