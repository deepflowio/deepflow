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

use semver::Version;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    FileReadError(#[from] std::io::Error),
    #[error(transparent)]
    ElfReadError(#[from] object::Error),
    #[error(transparent)]
    ElfParseError(#[from] gimli::Error),
    #[error(".eh_frame section not found in object file")]
    NoEhFrame,
    #[error("Process#{0} is not `{1}`")]
    BadInterpreterType(u32, &'static str),
    #[error("Process#{0} {1} v{2} not supported")]
    BadInterpreterVersion(u32, &'static str, Version),
    #[error("Process#{0} not found or not accessible")]
    ProcessNotFound(u32),
    #[error("Invalid pointer address: 0x{0:x}")]
    InvalidPointer(u64),
    #[error("Invalid or corrupted data")]
    InvalidData,
}

pub type Result<T> = std::result::Result<T, Error>;
