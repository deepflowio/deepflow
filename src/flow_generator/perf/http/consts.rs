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
pub const HTTP_RESP_MIN_LEN: usize = 15; // 响应行："HTTP/1.1 200 OK"

pub const HTTP_HOST_OFFSET: usize = 6;
pub const HTTP_CONTENT_LENGTH_OFFSET: usize = 16;

pub const HTTPV2_FRAME_HEADER_LENGTH: usize = 9;

pub const HTTPV2_FRAME_DATA_TYPE: u8 = 0x00;
pub const HTTPV2_FRAME_HEADERS_TYPE: u8 = 0x01;

pub const HTTPV2_FRAME_TYPE_MIN: u8 = 0x00;
pub const HTTPV2_FRAME_TYPE_MAX: u8 = 0x09;

pub const TRACE_ID_TYPE: usize = 0;
pub const SPAN_ID_TYPE: usize = 1;

// 参考：https://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html
