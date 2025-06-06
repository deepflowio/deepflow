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

// hessian2 constants
pub const BC_END: u8 = b'Z';
pub const BC_NULL: u8 = b'N'; // x4e
pub const BC_REF: u8 = 0x51;
pub const BC_TRUE: u8 = b'T';
pub const BC_FALSE: u8 = b'F'; // boolean false

pub const BC_STRING: u8 = b'S'; // final string
pub const BC_STRING_CHUNK: u8 = b'R'; // non-final string
pub const BC_STRING_DIRECT: u8 = 0x00;
pub const STRING_DIRECT_MAX: u8 = 0x1f;
pub const BC_STRING_SHORT: u8 = 0x30;
pub const BC_STRING_SHORT_MAX: u8 = 0x33; // STRING_SHORT_MAX >> 8 | BC_STRING_SHORT

pub const BC_MAP: u8 = 0x4d;
pub const BC_MAP_UNTYPED: u8 = 0x48;

pub const BC_OBJECT: u8 = b'O';
pub const BC_OBJECT_DEF: u8 = b'C';
pub const BC_OBJECT_DIRECT: u8 = 0x60;
pub const OBJECT_DIRECT_MAX: u8 = 0x0f;
// only for BC_OBJECT match
pub const BC_OBJECT_DIRECT_MAX: u8 = BC_OBJECT_DIRECT + OBJECT_DIRECT_MAX;

pub const BC_BINARY: u8 = b'B';
pub const BC_BINARY_CHUNK: u8 = b'A';
pub const BC_BINARY_DIRECT: u8 = 0x20; // 1-byte length binary
pub const BINARY_DIRECT_MAX: u8 = 0x0f;
pub const BC_BINARY_SHORT: u8 = 0x34; // 2-byte length binary
pub const BINARY_SHORT_MAX: u16 = 0x3ff; // 0-1023 binary

pub const BC_DATE: u8 = 0x4a; // 64-bit millisecond UTC date
pub const BC_DATE_MINUTE: u8 = 0x4b; // 32-bit minute UTC date

pub const BC_DOUBLE: u8 = b'D'; // IEEE 64-bit double
pub const BC_DOUBLE_ZERO: u8 = 0x5b;
pub const BC_DOUBLE_ONE: u8 = 0x5c;
pub const BC_DOUBLE_BYTE: u8 = 0x5d;
pub const BC_DOUBLE_SHORT: u8 = 0x5e;
pub const BC_DOUBLE_MILL: u8 = 0x5f;

pub const BC_INT: u8 = b'I'; // 32-bit int
pub const BC_INT_ZERO: u8 = 0x90;
pub const BC_INT_BYTE_ZERO: u8 = 0xc8;
pub const BC_INT_SHORT_ZERO: u8 = 0xd4;
pub const INT_DIRECT_MIN: i8 = -0x10;
pub const INT_DIRECT_MAX: u8 = 0x2f;
pub const INT_BYTE_MIN: i16 = -0x800;
pub const INT_BYTE_MAX: u16 = 0x7ff;
pub const INT_SHORT_MIN: i32 = -0x40000;
pub const INT_SHORT_MAX: u32 = 0x3ffff;

pub const BC_LIST_FIXED: u8 = b'V';
pub const BC_LIST_VARIABLE: u8 = 0x55;
pub const BC_LIST_VARIABLE_UNTYPED: u8 = 0x57;
pub const BC_LIST_FIXED_UNTYPED: u8 = 0x58;
pub const BC_LIST_FIXED_TYPED_LEN_TAG_MIN: u8 = 0x70; // _listFixedTypedLenTagMin
pub const BC_LIST_FIXED_TYPED_LEN_TAG_MAX: u8 = 0x77; // _listFixedTypedLenTagMax
pub const BC_LIST_FIXED_UNTYPED_LEN_TAG_MIN: u8 = 0x78; // _listFixedUntypedLenTagMin
pub const BC_LIST_FIXED_UNTYPED_LEN_TAG_MAX: u8 = 0x7f; // _listFixedUntypedLenTagMax
pub const BC_LIST_DIRECT: u8 = 0x70;
pub const BC_LIST_DIRECT_UNTYPED: u8 = 0x78;
pub const LIST_DIRECT_MAX: u8 = 0x7;

pub const BC_LONG: u8 = b'L'; // 64-bit signed integer
pub const BC_LONG_ZERO: u8 = 0xe0;
pub const LONG_DIRECT_MIN: i8 = -0x08;
pub const LONG_DIRECT_MAX: u8 = 0x0f;
pub const BC_LONG_BYTE_ZERO: u8 = 0xf8;
pub const LONG_BYTE_MIN: i16 = -0x800;
pub const LONG_BYTE_MAX: u16 = 0x7ff;
pub const BC_LONG_SHORT_ZERO: u8 = 0x3c;
pub const LONG_SHORT_MIN: i32 = -0x40000;
pub const LONG_SHORT_MAX: u32 = 0x3ffff;
pub const BC_LONG_INT: u8 = 0x59;

// 参考：https://dubbo.apache.org/zh/docs/concepts/rpc-protocol/#protocol-spec
// Dubbo Request Body
pub const BODY_PARAM_MIN: u8 = 1;
pub const BODY_PARAM_DUBBO_VERSION: u8 = 1;
pub const BODY_PARAM_SERVICE_NAME: u8 = 2;
pub const BODY_PARAM_SERVICE_VERSION: u8 = 3;
pub const BODY_PARAM_METHOD_NAME: u8 = 4;
pub const BODY_PARAM_MAX: u8 = 5;

// ref: https://github.com/apache/dubbo-go-hessian2/blob/v2.0.0/const.go#L218
pub const REGEX_ARG_TYPES: &str = r#"(?:(?:[VZBCDFIJS])|(?:L(?:[_$a-zA-Z][_$a-zA-Z0-9]*)(?:\/(?:[_$a-zA-Z][_$a-zA-Z0-9]*))*;)|(?:\[+(?:(?:[VZBCDFIJS])|(?:L(?:[_$a-zA-Z][_$a-zA-Z0-9]*)(?:\/(?:[_$a-zA-Z][_$a-zA-Z0-9]*))*;))))"#;
