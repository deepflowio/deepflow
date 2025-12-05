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

use std::fmt::Write;

use public::bytes::{
    read_f32_le, read_f64_le, read_i16_le, read_i32_le, read_i64_le, read_u16_le, read_u32_le,
};

pub const PROTOCOL_VERSION: u8 = 10;

// Compressed Header
pub const COMPRESS_HEADER_LEN: usize = 7;
pub const COMPRESS_HEADER_UNCOMPRESS_OFFSET: usize = 4;

// Header
pub const HEADER_LEN: usize = 4;

pub const HEADER_OFFSET: usize = 0;
pub const NUMBER_OFFSET: usize = 3;

// Greeting
pub const SERVER_VERSION_EOF: u8 = 0;

pub const PROTOCOL_VERSION_LEN: usize = 1;
pub const THREAD_ID_LEN: usize = 4;

pub const PROTOCOL_VERSION_OFFSET: usize = 0;
pub const SERVER_VERSION_OFFSET: usize = PROTOCOL_VERSION_OFFSET + PROTOCOL_VERSION_LEN;
pub const THREAD_ID_OFFSET_B: usize = SERVER_VERSION_OFFSET;

// Request
pub const COMMAND_OFFSET: usize = 0;
pub const COMMAND_LEN: usize = 1;

pub const PARAMETER_TYPE_LEN: usize = 2;

#[derive(Debug, Clone, Copy)]
pub enum FieldType {
    Tiny,
    Short,
    Long,
    Float,
    Double,
    Null,
    Timestamp,
    Longlong,
    Int24,
    Date,
    Time,
    Datetime,
    Year,
    String,
    Unknown(u8),
}

impl From<u8> for FieldType {
    fn from(tag: u8) -> Self {
        match tag {
            1 => Self::Tiny,
            2 => Self::Short,
            3 => Self::Long,
            4 => Self::Float,
            5 => Self::Double,
            6 => Self::Null,
            7 => Self::Timestamp,
            8 => Self::Longlong,
            9 => Self::Int24,
            10 => Self::Date,
            11 => Self::Time,
            12 => Self::Datetime,
            13 => Self::Year,
            254 => Self::String,
            _ => Self::Unknown(tag),
        }
    }
}

impl FieldType {
    fn header_length(&self) -> usize {
        match self {
            FieldType::Tiny
            | FieldType::String
            | FieldType::Date
            | FieldType::Time
            | FieldType::Timestamp
            | FieldType::Datetime => 1,
            FieldType::Short | FieldType::Year => 2,
            FieldType::Long | FieldType::Float | FieldType::Int24 => 4,
            FieldType::Double | FieldType::Longlong => 8,
            _ => 8,
        }
    }

    pub fn decode(self, payload: &[u8], output: &mut String) -> Option<usize> {
        let header_length = self.header_length();
        if header_length > payload.len() {
            return None;
        }
        let mut offset = 0;
        match self {
            FieldType::String => {
                let len = payload[offset] as usize;
                offset += header_length;

                if offset + len > payload.len() {
                    return None;
                }

                output.push_str(&String::from_utf8_lossy(&payload[offset..offset + len]));
                offset += len;
            }
            FieldType::Longlong => {
                let n = read_i64_le(&payload[offset..]);

                let _ = write!(output, "LongLong({})", n);
                offset += header_length;
            }
            FieldType::Long => {
                let n = read_i32_le(&payload[offset..]);

                let _ = write!(output, "Long({})", n);
                offset += header_length;
            }
            FieldType::Int24 => {
                let n = read_i32_le(&payload[offset..]);

                let _ = write!(output, "Int24({})", n);
                offset += header_length;
            }
            FieldType::Short => {
                let n = read_i16_le(&payload[offset..]);

                let _ = write!(output, "Short({})", n);
                offset += header_length;
            }
            FieldType::Year => {
                let n = read_i16_le(&payload[offset..]);

                let _ = write!(output, "Years({})", n);
                offset += header_length;
            }
            FieldType::Tiny => {
                let n = payload[offset] as i8;

                let _ = write!(output, "Tiny({})", n);
                offset += header_length;
            }
            FieldType::Double => {
                let n = read_f64_le(&payload[offset..]);

                let _ = write!(output, "Double({})", n);
                offset += header_length;
            }
            FieldType::Float => {
                let n = read_f32_le(&payload[offset..]);

                let _ = write!(output, "Float({})", n);
                offset += header_length;
            }
            FieldType::Date | FieldType::Datetime | FieldType::Timestamp => {
                let len = payload[offset] as usize;
                offset += header_length;
                if offset + len > payload.len() {
                    return None;
                }

                // To save space the packet can be compressed:
                match len {
                    // if year, month, day, hour, minutes, seconds and microseconds are all 0, length is 0 and no other field is sent.
                    0 => output.push_str("datetime 0000-00-00 00:00:00.000000"),
                    // if hour, seconds and microseconds are all 0, length is 4 and no other field is sent.
                    4 => {
                        let year = read_u16_le(&payload[offset..]);
                        let month = payload[offset + 2];
                        let day = payload[offset + 3];
                        offset += len;
                        let _ = write!(output, "datetime {:04}-{:02}-{:02}", year, month, day);
                    }
                    // if microseconds is 0, length is 7 and micro_seconds is not sent.
                    7 => {
                        let year = read_u16_le(&payload[offset..]);
                        let month = payload[offset + 2];
                        let day = payload[offset + 3];
                        let hour = payload[offset + 4];
                        let minute = payload[offset + 5];
                        let second = payload[offset + 6];
                        offset += len;
                        let _ = write!(
                            output,
                            "datetime {:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                            year, month, day, hour, minute, second
                        );
                    }
                    // otherwise the length is 11
                    11 => {
                        let year = read_u16_le(&payload[offset..]);
                        let month = payload[offset + 2];
                        let day = payload[offset + 3];
                        let hour = payload[offset + 4];
                        let minute = payload[offset + 5];
                        let second = payload[offset + 6];
                        let microsecond = read_u32_le(&payload[offset + 7..]);
                        offset += len;
                        let _ = write!(
                            output,
                            "datetime {:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}",
                            year, month, day, hour, minute, second, microsecond
                        );
                    }
                    _ => offset += len,
                }
            }
            FieldType::Time => {
                let len = payload[offset] as usize;
                offset += header_length;
                // To save space the packet can be compressed:
                match len {
                    // if day, hour, minutes, seconds and microseconds are all 0, length is 0 and no other field is sent.
                    1 => output.push_str("time 0d 00:00:00.000000"),
                    8 => {
                        if offset + len > payload.len() {
                            return None;
                        }
                        let is_negative = payload[offset] == 1;
                        offset += 1;

                        let days = read_u32_le(&payload[offset..]);
                        let hour = payload[offset + 4];
                        let minute = payload[offset + 5];
                        let second = payload[offset + 6];
                        if is_negative {
                            let _ = write!(
                                output,
                                "time -{}d {:02}:{:02}:{:02}",
                                days, hour, minute, second
                            );
                        } else {
                            let _ = write!(
                                output,
                                "time {}d {:02}:{:02}:{:02}",
                                days, hour, minute, second
                            );
                        }
                    }
                    12 => {
                        if offset + len > payload.len() {
                            return None;
                        }
                        let is_negative = payload[offset] == 1;
                        offset += 1;

                        let days = read_u32_le(&payload[offset..]);
                        let hour = payload[offset + 4];
                        let minute = payload[offset + 5];
                        let second = payload[offset + 6];
                        let microsecond = read_u32_le(&payload[offset + 7..]);
                        if is_negative {
                            let _ = write!(
                                output,
                                "time -{}d {:02}:{:02}:{:02}.{:06}",
                                days, hour, minute, second, microsecond
                            );
                        } else {
                            let _ = write!(
                                output,
                                "time {}d {:02}:{:02}:{:02}.{:06}",
                                days, hour, minute, second, microsecond
                            );
                        }
                    }
                    _ => offset += len,
                }
            }
            FieldType::Null => output.push_str("NULL"),
            FieldType::Unknown(_) => return None,
        }
        return Some(offset);
    }
}

// Response
pub const RESPONSE_CODE_LEN: usize = 1;
pub const ERROR_CODE_LEN: usize = 2;
pub const AFFECTED_ROWS_LEN: usize = 1;
pub const SQL_STATE_LEN: usize = 6;
pub const SQL_STATE_MARKER: u8 = b'#';
pub const STATEMENT_ID_LEN: usize = 4;

pub const RESPONSE_CODE_OFFSET: usize = 0;
pub const ERROR_CODE_OFFSET: usize = RESPONSE_CODE_OFFSET + RESPONSE_CODE_LEN;
pub const AFFECTED_ROWS_OFFSET: usize = RESPONSE_CODE_OFFSET + RESPONSE_CODE_LEN;
pub const SQL_STATE_OFFSET: usize = ERROR_CODE_OFFSET + ERROR_CODE_LEN;
pub const STATEMENT_ID_OFFSET: usize = RESPONSE_CODE_OFFSET + RESPONSE_CODE_LEN;
pub const EXECUTE_STATEMENT_PARAMS_OFFSET: usize = STATEMENT_ID_OFFSET + STATEMENT_ID_LEN + 5;

// Login

// Client Capabilities
pub const CLIENT_PROTOCOL_41: u16 = 512;
pub const CONNECT_WITH_DB: u16 = 1 << 3;
// Extended Client Capabilities
pub const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u16 = 1 << 5;

pub const CLIENT_CAPABILITIES_FLAGS_OFFSET: usize = 0;
pub const EXTENDED_CLIENT_CAPABILITIES_FLAGS_OFFSET: usize = 2;
pub const FILTER_OFFSET: usize = 9;
pub const FILTER_SIZE: usize = 23;
pub const LOGIN_USERNAME_OFFSET: usize = 32;

pub const LOGIN_RESPONSE_HEADER_SIZE: usize = 3;

// int
pub const INT_FLAGS_2: u8 = 0xfc;
pub const INT_FLAGS_3: u8 = 0xfd;
pub const INT_FLAGS_8: u8 = 0xfe;

pub const INT_BASE_LEN: usize = 1;

pub const MYSQL_RESPONSE_CODE_OK: u8 = 0;
pub const MYSQL_RESPONSE_CODE_ERR: u8 = 0xff;
pub const MYSQL_RESPONSE_CODE_EOF: u8 = 0xfe;

pub const COM_QUIT: u8 = 1;
pub const COM_INIT_DB: u8 = 2;
pub const COM_QUERY: u8 = 3;
pub const COM_FIELD_LIST: u8 = 4;
pub const COM_PING: u8 = 14;
pub const COM_STMT_PREPARE: u8 = 22;
pub const COM_STMT_EXECUTE: u8 = 23;
pub const COM_STMT_CLOSE: u8 = 25;
pub const COM_STMT_FETCH: u8 = 28;
pub const COM_MAX: u8 = 26;
