/*
 * Copyright (c) 2025 Yunshan Networks
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

use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(
    Serialize, Deserialize, Debug, Default, PartialEq, Copy, Clone, Eq, num_enum::TryFromPrimitive,
)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum L7ResponseStatus {
    Ok = 0,
    Timeout = 2,
    ServerError = 3,
    ClientError = 4,
    #[default]
    Unknown = 5,
    ParseFailed = 6,
}

impl fmt::Display for L7ResponseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl L7ResponseStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Timeout => "timeout",
            Self::ServerError => "server_error",
            Self::ClientError => "client_error",
            Self::ParseFailed => "parse_failed",
            Self::Unknown => "unknown",
        }
    }
}

impl From<&str> for L7ResponseStatus {
    fn from(s: &str) -> Self {
        match s {
            "ok" => L7ResponseStatus::Ok,
            "timeout" => L7ResponseStatus::Timeout,
            "server_error" => L7ResponseStatus::ServerError,
            "client_error" => L7ResponseStatus::ClientError,
            "parse_failed" => L7ResponseStatus::ParseFailed,
            "unknown" => L7ResponseStatus::Unknown,
            _ => L7ResponseStatus::Unknown,
        }
    }
}
