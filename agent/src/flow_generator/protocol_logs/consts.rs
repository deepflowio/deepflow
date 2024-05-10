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

/// HTTP constants
pub const HTTP_RESP_MAX_LINE: usize = 40;
pub const H2C_HEADER_SIZE: usize = 9;

pub const FRAME_HEADERS: u8 = 0x1;
pub const FLAG_HEADERS_PADDED: u8 = 0x8;
pub const FLAG_HEADERS_PRIORITY: u8 = 0x20;

pub const HTTP_METHOD_AND_SPACE_MAX_OFFSET: usize = 9; // Method：OPTIONS
pub const HTTP_V1_0_VERSION: &str = "HTTP/1.0";
pub const HTTP_V1_1_VERSION: &str = "HTTP/1.1";
pub const HTTP_V1_VERSION_LEN: usize = 8;
pub const HTTP_STATUS_CODE_MIN: u16 = 100;
pub const HTTP_STATUS_CODE_MAX: u16 = 600;
pub const HTTP_STATUS_CLIENT_ERROR_MIN: u16 = 400;
pub const HTTP_STATUS_CLIENT_ERROR_MAX: u16 = 499;
pub const HTTP_STATUS_SERVER_ERROR_MIN: u16 = 500;
pub const HTTP_STATUS_SERVER_ERROR_MAX: u16 = 600;
pub const HTTP_RESP_MIN_LEN: usize = 13; // 响应行："HTTP/1.1 200 "

pub const HTTP_HOST_OFFSET: usize = 6;
pub const HTTP_CONTENT_LENGTH_OFFSET: usize = 16;

pub const HTTPV2_CUSTOM_DATA_MIN_LENGTH: usize = 16;

pub const HTTPV2_FRAME_HEADER_LENGTH: usize = 9;
pub const HTTPV2_MAGIC_LENGTH: usize = 24;
pub const HTTPV2_MAGIC_PREFIX: [u8; 10] =
    [b'P', b'R', b'I', b' ', b'*', b' ', b'H', b'T', b'T', b'P'];

pub const HTTPV2_FRAME_DATA_TYPE: u8 = 0x00;
pub const HTTPV2_FRAME_HEADERS_TYPE: u8 = 0x01;

pub const HTTPV2_FRAME_TYPE_MIN: u8 = 0x00;
pub const HTTPV2_FRAME_TYPE_MAX: u8 = 0x09;

pub const TRACE_ID_TYPE: usize = 0;
pub const SPAN_ID_TYPE: usize = 1;

// 参考：https://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html

// Kafka constants
pub const KAFKA_REQ_HEADER_LEN: usize = 14;
pub const KAFKA_RESP_HEADER_LEN: usize = 8;

// dubbo constants
pub const DUBBO_MAGIC_HIGH: u8 = 0xda;
pub const DUBBO_MAGIC_LOW: u8 = 0xbb;
pub const DUBBO_HEADER_LEN: usize = 16;

// response status code
// 参考：https://dubbo.apache.org/zh/blog/2018/10/05/dubbo-%E5%8D%8F%E8%AE%AE%E8%AF%A6%E8%A7%A3/#%E5%8D%8F%E8%AE%AE%E8%AF%A6%E6%83%85
pub const OK: u8 = 20;
// client error
pub const CLIENT_TIMEOUT: u8 = 30;
pub const BAD_REQUEST: u8 = 40;
pub const CLIENT_ERROR: u8 = 90;
// server error
pub const SERVER_TIMEOUT: u8 = 31;
pub const BAD_RESPONSE: u8 = 50;
pub const SERVICE_NOT_FOUND: u8 = 60;
pub const SERVICE_ERROR: u8 = 70;
pub const SERVER_ERROR: u8 = 80;
pub const SERVER_THREADPOOL_EXHAUSTED_ERROR: u8 = 100;

pub const BC_STRING: u8 = 0x73;
pub const BC_STRING_CHUNK: u8 = 0x72;
pub const BC_STRING_DIRECT: u8 = 0x00;
pub const STRING_DIRECT_MAX: u8 = 0x1f;
pub const BC_STRING_SHORT: u8 = 0x30;
pub const BC_STRING_SHORT_MAX: u8 = 0x33; // STRING_SHORT_MAX >> 8 | BC_STRING_SHORT
pub const STRING_SHORT_MAX: u16 = 0x3ff;

// 参考：https://dubbo.apache.org/zh/docs/concepts/rpc-protocol/#protocol-spec
// Dubbo Request Body
pub const BODY_PARAM_MIN: u8 = 1;
pub const BODY_PARAM_DUBBO_VERSION: u8 = 1;
pub const BODY_PARAM_SERVICE_NAME: u8 = 2;
pub const BODY_PARAM_SERVICE_VERSION: u8 = 3;
pub const BODY_PARAM_METHOD_NAME: u8 = 4;
pub const BODY_PARAM_MAX: u8 = 5;

// Mysql constants
pub const PROTOCOL_VERSION: u8 = 10;

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

// dns constants
use std::time::Duration;

pub const PORT: u16 = 53;

pub const DNS_TCP_PAYLOAD_OFFSET: usize = 2;

pub const DNS_HEADER_SIZE: usize = 12;
pub const DNS_HEADER_FLAGS_OFFSET: usize = 2;
pub const DNS_HEADER_QR_MASK: u8 = 0x80;
pub const DNS_HEADER_RESPCODE_MASK: u8 = 0x0f;
pub const DNS_OPCODE_REQUEST: u8 = 0x00;
pub const DNS_OPCODE_RESPONSE: u8 = 0x80;

pub const DNS_RESPCODE_SUCCESS: u8 = 0x00;
pub const DNS_RESPCODE_FORMAT: u8 = 0x01;
pub const DNS_RESPCODE_NXDOMAIN: u8 = 0x03;

// Linux和Windows环境默认DNS超时时间均为10s，Linux最大可设置为30s*5=150s
// https://man7.org/linux/man-pages/man5/resolv.conf.5.html
// https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-client-resolution-timeouts
pub const DNS_RRT_MAX: Duration = Duration::from_secs(150);
pub const DNS_RRT_MIN: Duration = Duration::from_secs(0);

pub const DNS_REQUEST: u8 = 0x00;
pub const DNS_RESPONSE: u8 = 0x80;
pub const DNS_NAME_COMPRESS_POINTER: u8 = 0xc0;
pub const DNS_NAME_TAIL: u8 = 0x00;
pub const DNS_NAME_RESERVERD_40: u8 = 0x40;
pub const DNS_NAME_RESERVERD_80: u8 = 0x80;
pub const DNS_NAME_MAX_SIZE: usize = 255;
pub const DNS_HEADER_QDCOUNT_OFFSET: usize = 4;
pub const DNS_HEADER_ANCOUNT_OFFSET: usize = 6;
pub const DNS_HEADER_NSCOUNT_OFFSET: usize = 8;
pub const QUESTION_CLASS_OFFSET: usize = 2;
pub const QUESTION_CLASS_TYPE_SIZE: usize = 4;
pub const RR_CLASS_OFFSET: usize = 2;
pub const RR_DATALENGTH_OFFSET: usize = 8;
pub const RR_RDATA_OFFSET: usize = 10;
pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_NS: u16 = 2;
pub const DNS_TYPE_CNAME: u16 = 5;
pub const DNS_TYPE_SOA: u16 = 6;
pub const DNS_TYPE_WKS: u16 = 11;
pub const DNS_TYPE_PTR: u16 = 12;
pub const DNS_TYPE_AAAA: u16 = 28;
pub const DNS_TYPE_DNAME: u16 = 39;
pub const DNS_TYPE_WKS_LENGTH: usize = 5;
pub const DNS_TYPE_PTR_LENGTH: usize = 2;
pub const DOMAIN_NAME_SPLIT: char = ';';
