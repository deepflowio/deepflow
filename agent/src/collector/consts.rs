/*
 * Copyright (c) 2022 Yunshan Networks
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

use std::time::Duration;

// 注意总长度4字节对齐
pub const L3_EPC_ID_SIZE: usize = 2;
pub const TAP_PORT_SIZE: usize = 8; // tap_port(4B), type_type_type(1B), tap_type(1B), tunnel_type(1B), tap_side(1B)
pub const CLOSE_TYPE_SIZE: usize = 1;
pub const PROTOCOL_SIZE: usize = 1;
pub const PORT_SIZE: usize = 2;
pub const IPV4_PATH_SIZE: usize = 4 << 1; // ip4len << 1
pub const IPV6_PATH_SIZE: usize = 16 << 1; // ip6len << 1
pub const GPID_SIZE: usize = 4;

pub const CONCURRENT_TIMEOUT: Duration = Duration::from_secs(300); // 单位：秒

pub const OFFSET_L3_EPC_ID_0: usize = 0;
pub const OFFSET_L3_EPC_ID_1: usize = OFFSET_L3_EPC_ID_0 + L3_EPC_ID_SIZE;
pub const OFFSET_TAP_PORT: usize = OFFSET_L3_EPC_ID_1 + L3_EPC_ID_SIZE;
pub const OFFSET_RESERVED: usize = OFFSET_TAP_PORT + TAP_PORT_SIZE;
pub const OFFSET_PROTOCOL: usize = OFFSET_RESERVED + CLOSE_TYPE_SIZE;
pub const OFFSET_PORT: usize = OFFSET_PROTOCOL + PROTOCOL_SIZE;
pub const OFFSET_GPID_0: usize = OFFSET_PORT + PORT_SIZE;
pub const OFFSET_GPID_1: usize = OFFSET_GPID_0 + GPID_SIZE;
pub const OFFSET_IP: usize = OFFSET_GPID_1 + GPID_SIZE;

pub const IPV4_LRU_KEY_SIZE: usize = OFFSET_IP + IPV4_PATH_SIZE; // 256b, 32B
pub const IPV6_LRU_KEY_SIZE: usize = OFFSET_IP + IPV6_PATH_SIZE; // 448b, 56B

pub const QUEUE_BATCH_SIZE: usize = 1024;
pub const RCV_TIMEOUT: Duration = Duration::from_secs(1);

pub const SECONDS_IN_MINUTE: u64 = 60;
pub const NANOS_IN_SECOND: u64 = 1_000_000_000;
