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

use std::fmt::Display;
use std::time::Duration;

pub struct HandshakeHeader {}

impl Display for HandshakeHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Unsupport")
    }
}

pub struct TlsHeader {
    pub handshake_headers: Vec<HandshakeHeader>,
}

impl Display for TlsHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Unsupport")
    }
}

impl TlsHeader {
    pub const HEADER_LEN: usize = 5;
    pub fn new(_: &[u8]) -> Self {
        Self {
            handshake_headers: vec![],
        }
    }

    pub fn is_unsupport_content_type(&self) -> bool {
        true
    }

    pub fn is_handshake(&self) -> bool {
        false
    }

    pub fn is_client_hello(&self) -> bool {
        false
    }

    pub fn is_last(&self) -> bool {
        true
    }

    pub fn content_type(&self) -> u8 {
        0
    }

    pub fn version(&self) -> u16 {
        0
    }

    pub fn next(&self) -> usize {
        0
    }

    pub fn supported_version(&self) -> Option<u16> {
        None
    }

    pub fn is_change_cipher_spec(&self) -> bool {
        false
    }

    pub fn domain_name(&self) -> Option<String> {
        None
    }

    pub fn validity(&self) -> Option<(Duration, Duration)> {
        None
    }

    pub fn is_alert(&self) -> bool {
        false
    }

    pub fn cipher_suite(&self) -> Option<u16> {
        None
    }
}
