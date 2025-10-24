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

pub mod json;
pub mod xml;

use std::str::from_utf8;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SearchError {
    KeyNotFound,
    InvalidUTF8String,
    InvalidInputFormat,
}

fn find_bytes_case_sensitive(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn find_bytes_ignore_case(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

fn find_byte(haystack: &[u8], needle: u8) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

pub fn skip_whitespace(s: &str) -> &str {
    s.trim_start_matches(|c: char| matches!(c, ' ' | '\t' | '\n' | '\r'))
}

fn skip_whitespace_from_bytes(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
        .unwrap_or(bytes.len());
    &bytes[start..]
}

fn bytes_to_string(payload: &[u8], start: usize, end: usize) -> Result<String, SearchError> {
    match from_utf8(&payload[start..end]) {
        Ok(s) => Ok(s.to_string()),
        Err(_) => Err(SearchError::InvalidUTF8String),
    }
}
