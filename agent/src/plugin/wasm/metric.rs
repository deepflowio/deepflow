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
    collections::HashMap,
    sync::{atomic::AtomicU64, Arc},
};

use public::counter::{CounterType, CounterValue, RefCountable};

#[derive(Debug, Default)]
pub struct WasmCounter {
    pub(super) mem_size: AtomicU64,
    pub(super) exe_duration: AtomicU64,
    pub(super) fail_cnt: AtomicU64,
}
impl RefCountable for WasmCounter {
    fn get_counters(&self) -> Vec<public::counter::Counter> {
        vec![
            (
                "mem_size",
                CounterType::Gauged,
                CounterValue::Unsigned(self.mem_size.swap(0, std::sync::atomic::Ordering::Relaxed)),
            ),
            (
                "exe_dur",
                CounterType::Gauged,
                CounterValue::Unsigned(
                    self.exe_duration
                        .swap(0, std::sync::atomic::Ordering::Relaxed),
                ),
            ),
            (
                "fail_cnt",
                CounterType::Counted,
                CounterValue::Unsigned(self.fail_cnt.swap(0, std::sync::atomic::Ordering::Relaxed)),
            ),
        ]
    }
}

#[derive(Debug)]
pub struct WasmCounterMap {
    pub wasm_mertic: HashMap<String, Arc<WasmCounter>>,
}

pub fn get_wasm_metric_counter_map_key(name: &str, func_name: &str) -> String {
    format!("{}:{}", name, func_name)
}
