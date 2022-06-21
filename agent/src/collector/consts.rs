use std::time::Duration;

// 注意总长度4字节对齐
pub const L3_EPC_ID_SIZE: usize = 2;
pub const TAP_PORT_SIZE: usize = 8; // tap_port(4B), type_type_type(1B), tap_type(1B), tunnel_type(1B), tap_side(1B)
pub const CLOSE_TYPE_SIZE: usize = 1;
pub const PROTOCOL_SIZE: usize = 1;
pub const PORT_SIZE: usize = 2;
pub const IPV4_PATH_SIZE: usize = 4 << 1; // ip4len << 1
pub const IPV6_PATH_SIZE: usize = 16 << 1; // ip6len << 1

pub const CONCURRENT_TIMEOUT: Duration = Duration::from_secs(300); // 单位：秒

pub const OFFSET_L3_EPC_ID_0: usize = 0;
pub const OFFSET_L3_EPC_ID_1: usize = OFFSET_L3_EPC_ID_0 + L3_EPC_ID_SIZE;
pub const OFFSET_TAP_PORT: usize = OFFSET_L3_EPC_ID_1 + L3_EPC_ID_SIZE;
pub const OFFSET_CLOSE_TYPE: usize = OFFSET_TAP_PORT + TAP_PORT_SIZE;
pub const OFFSET_PROTOCOL: usize = OFFSET_CLOSE_TYPE + CLOSE_TYPE_SIZE;
pub const OFFSET_PORT: usize = OFFSET_PROTOCOL + PROTOCOL_SIZE;
pub const OFFSET_IP: usize = OFFSET_PORT + PORT_SIZE;

pub const IPV4_LRU_KEY_SIZE: usize = OFFSET_IP + IPV4_PATH_SIZE; // 192b, 24B
pub const IPV6_LRU_KEY_SIZE: usize = OFFSET_IP + IPV6_PATH_SIZE; // 384b, 48B

pub const QUEUE_BATCH_SIZE: usize = 1024;

pub const SECONDS_IN_MINUTE: u64 = 60;
pub const NANOS_IN_SECOND: u64 = 1_000_000_000;
