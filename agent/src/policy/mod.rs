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

mod bit;
pub mod fast_path;
pub mod first_path;
mod forward;
pub mod labeler;
pub mod policy;

pub use policy::{Policy, PolicyGetter, PolicySetter};

use thiserror::Error;

const MAX_QUEUE_COUNT: usize = 128;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    CustomError(String),
    #[error(
        "DDBS memory limit will be exceed, please enlarge total memory limit or optimize policy."
    )]
    ExceedMemoryLimit,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
