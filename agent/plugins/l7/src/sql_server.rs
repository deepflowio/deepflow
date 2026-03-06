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

#[derive(Debug, Default)]
pub struct TdsParser {
    pub sql: Option<String>,
    pub status_code: Option<i32>,
    pub error_message: Option<String>,
    pub affected_row: Option<u64>,
}

impl TdsParser {
    pub fn new(_: &[u8]) -> Self {
        TdsParser::default()
    }

    pub fn parse(&mut self) -> Result<(), ParserError> {
        Err(ParserError::InvalidData)
    }
}

#[derive(Debug)]
pub enum ParserError {
    IoError(std::io::Error),
    UnknownToken(u8),
    UnknownEnvType(u8),
    InvalidData,
    InsufficientData,
    Utf8Error(std::string::FromUtf8Error),
    Utf16Error(std::string::FromUtf16Error),
    UnsupportedDataType,
}

impl From<std::io::Error> for ParserError {
    fn from(err: std::io::Error) -> Self {
        ParserError::IoError(err)
    }
}

impl From<std::string::FromUtf8Error> for ParserError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        ParserError::Utf8Error(err)
    }
}

impl From<std::string::FromUtf16Error> for ParserError {
    fn from(err: std::string::FromUtf16Error) -> Self {
        ParserError::Utf16Error(err)
    }
}
