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

cfg_if::cfg_if! {
    if #[cfg(target_os = "android")] {
        mod android;
        pub use android::Querier;
    } else if #[cfg(target_os = "linux")] {
        mod linux;
        pub use linux::Querier;
    } else if #[cfg(target_os = "windows")] {
        mod windows;
        pub use windows::Querier;
    }
}
