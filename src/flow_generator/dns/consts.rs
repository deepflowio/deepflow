use std::time::Duration;

pub const DNS_PORT: u16 = 53;

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
pub const DNS_TYPE_WKS: u16 = 11;
pub const DNS_TYPE_PTR: u16 = 12;
pub const DNS_TYPE_AAAA: u16 = 28;
pub const DNS_TYPE_DNAME: u16 = 39;
pub const DNS_TYPE_WKS_LENGTH: usize = 5;
pub const DNS_TYPE_PTR_LENGTH: usize = 2;
pub const DOMAIN_NAME_SPLIT: char = ';';
