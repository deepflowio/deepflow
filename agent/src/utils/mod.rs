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

pub(crate) mod bytes;
#[cfg(target_os = "linux")]
pub(crate) mod cgroups;
pub(crate) mod command;
pub(crate) mod environment;
pub(crate) mod guard;
pub(crate) mod hasher;
pub(crate) mod leaky_bucket;
pub(crate) mod logger;
pub(crate) mod lru;
pub(crate) mod net;
pub(crate) mod possible_host;
pub(crate) mod process;
pub(crate) mod queue;
pub(crate) mod stats;

pub use leaky_bucket::LeakyBucket;

#[cfg(test)]
pub mod test;

const WIN_ERROR_CODE_STR: &str = "please browse website(https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes) to get more detail";
