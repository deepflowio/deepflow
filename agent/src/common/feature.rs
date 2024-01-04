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

use bitflags::bitflags;

bitflags! {
    pub struct FeatureFlags: u64 {
        const NONE = 0;
        // add a new feature flag like:
        // const OTEL_METRICS = 1<<1;
   }
}

impl From<&Vec<String>> for FeatureFlags {
    fn from(flags: &Vec<String>) -> Self {
        let features = FeatureFlags::NONE;
        for flag in flags {
            match flag.to_lowercase().as_str() {
                // match a new feature flag like:
                // "otel_metrics" => features.set(FeatureFlags::OTEL_METRICS, true),
                _ => {}
            }
        }

        features
    }
}
