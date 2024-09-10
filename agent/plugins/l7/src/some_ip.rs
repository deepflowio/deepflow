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

pub struct SomeIpHeader {
    pub service_id: u16,
    pub method_id: u16,
    pub length: u32,
    pub client_id: u16,
    pub session_id: u16,
    pub protocol_version: u8,
    pub interface_version: u8,
    pub message_type: u8,
    pub return_code: u8,
    pub packet_length: u32,
}

pub const E_OK: u8 = 0x0;
pub const E_NOT_OK: u8 = 0x1;
pub const E_UNKNOWN_SERVICE: u8 = 0x2;
pub const E_UNKNOWN_METHOD: u8 = 0x3;
pub const E_NOT_READY: u8 = 0x4;
pub const E_NOT_REACHABLE: u8 = 0x5;
pub const E_TIMEOUT: u8 = 0x6;
pub const E_WRONG_PROTOCOL_VERSION: u8 = 0x7;
pub const E_WRONG_INTERFACE_VERSION: u8 = 0x8;
pub const E_MALFORMED_MESSAGE: u8 = 0x9;
pub const E_WRONG_MESSAGE_TYPE: u8 = 0xa;
pub const E_E2E_REPEATED: u8 = 0xb;
pub const E_E2E_WRONG_SEQUENCE: u8 = 0xc;
pub const E_E2E: u8 = 0xd;
pub const E_E2E_NOT_AVAILABLE: u8 = 0xe;
pub const E_E2E_NO_NEW_DATA: u8 = 0xf;

impl TryFrom<&[u8]> for SomeIpHeader {
    type Error = &'static str;

    fn try_from(_: &[u8]) -> std::result::Result<Self, Self::Error> {
        Err("Not supported")
    }
}

impl SomeIpHeader {
    pub fn check(&self) -> bool {
        false
    }

    pub fn does_supported(&self) -> bool {
        false
    }

    pub fn to_version(&self) -> String {
        "Not supported".to_string()
    }

    pub fn to_message_type(&self) -> String {
        "Not supported".to_string()
    }

    pub fn to_exception(&self) -> String {
        "Not supported".to_string()
    }
}
