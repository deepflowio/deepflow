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

use bitflags::bitflags;

bitflags! {
    pub struct FeatureFlags: u64 {
        const NONE = 0;
        const OTEL_METRICS = 1<<3;
   }
}

impl From<&Vec<String>> for FeatureFlags {
    fn from(flags: &Vec<String>) -> Self {
        let mut features = FeatureFlags::NONE;
        for flag in flags {
            match flag.to_lowercase().as_str() {
                "otel_metrics" => features.set(FeatureFlags::OTEL_METRICS, true),
                _ => {}
            }
        }

        features
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_feature_flags() {
        let flags = vec!["otel_metrics".to_string()];
        let feature = FeatureFlags::from(&flags);
        assert_eq!(feature.contains(FeatureFlags::OTEL_METRICS), true);
    }
}
