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

use std::fmt;

use bitflags::bitflags;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum TnsPacketType {
    Unknown,
}

impl TnsPacketType {
    pub fn as_str(&self) -> &'static str {
        ""
    }
}

impl Default for TnsPacketType {
    fn default() -> Self {
        Self::Unknown
    }
}

impl TryFrom<u8> for TnsPacketType {
    type Error = &'static str;

    fn try_from(_: u8) -> Result<Self, Self::Error> {
        Ok(Self::default())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataId {
    Unknown,
}

impl DataId {
    pub fn as_str(&self) -> &'static str {
        ""
    }
}

impl Default for DataId {
    fn default() -> Self {
        Self::Unknown
    }
}

impl TryFrom<u8> for DataId {
    type Error = &'static str;

    fn try_from(_: u8) -> Result<Self, Self::Error> {
        Ok(Self::default())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallId {
    Unknown,
}

impl CallId {
    pub fn as_str(&self) -> &'static str {
        ""
    }
}

impl Default for CallId {
    fn default() -> Self {
        Self::Unknown
    }
}

impl TryFrom<u8> for CallId {
    type Error = &'static str;

    fn try_from(_: u8) -> Result<Self, Self::Error> {
        Ok(Self::default())
    }
}

bitflags! {
    #[derive(Default)]
    pub struct DataFlags: u16 {}
}

impl fmt::Display for DataFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}

pub struct OracleParseConfig {
    pub is_be: bool,
    pub int_compress: bool,
    pub resp_0x04_extra_byte: bool,
    pub buf_size: u16,
}

#[derive(Default, PartialEq, Debug)]
pub struct OracleParser {
    pub packet_type: TnsPacketType,

    //request
    pub sql: String,
    pub req_data_flags: DataFlags,
    pub req_data_id: Option<DataId>,
    pub req_call_id: Option<CallId>,

    // response
    pub ret_code: u16,
    pub affected_rows: Option<u32>,
    pub error_message: String,
    pub resp_data_flags: DataFlags,
    pub resp_data_id: Option<DataId>,
}

impl OracleParser {
    pub fn check_payload(&mut self, _: &[u8], _: &OracleParseConfig) -> bool {
        false
    }

    pub fn parse_payload(&mut self, _: &[u8], _: bool, _: &OracleParseConfig) -> bool {
        unreachable!();
    }
}
