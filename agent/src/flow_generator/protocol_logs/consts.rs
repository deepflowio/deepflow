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
pub const HTTP_STATUS_OK: u16 = 200;
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

// GRPC
pub const GRPC_HEADER_SIZE: u32 = 5;
pub const GRPC_MESSAGE_LENGTH_OFFSET: usize = 1;
pub const GRPC_STATUS_OK: u16 = 0;
pub const GRPC_STATUS_CANCELLED: u16 = 1;
pub const GRPC_STATUS_INVALID_ARGUMENT: u16 = 3;
pub const GRPC_STATUS_NOT_FOUND: u16 = 5;
pub const GRPC_STATUS_ALREADY_EXISTS: u16 = 6;
pub const GRPC_STATUS_PERMISSION_DENIED: u16 = 7;
pub const GRPC_STATUS_FAILED_PRECONDITION: u16 = 9;
pub const GRPC_STATUS_OUT_OF_RANGE: u16 = 11;
pub const GRPC_STATUS_UNAUTHENTICATED: u16 = 16;

pub const TRACE_ID_TYPE: usize = 0;
pub const SPAN_ID_TYPE: usize = 1;

// 参考：https://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html

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

pub const APM_TRACE_ID_ATTR: &str = "apm_trace_id";
pub const APM_SPAN_ID_ATTR: &str = "apm_span_id";

pub const SYS_RESPONSE_CODE_ATTR: &str = "sys_response_code";
