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

// 参考：https://dubbo.apache.org/zh/docs/concepts/rpc-protocol/#protocol-spec
// Dubbo Request Body
pub const BODY_PARAM_MIN: u8 = 1;
pub const BODY_PARAM_DUBBO_VERSION: u8 = 1;
pub const BODY_PARAM_SERVICE_NAME: u8 = 2;
pub const BODY_PARAM_SERVICE_VERSION: u8 = 3;
pub const BODY_PARAM_METHOD_NAME: u8 = 4;
pub const BODY_PARAM_MAX: u8 = 5;
