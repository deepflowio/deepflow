/*
 * Copyright (c) 2023 Yunshan Networks
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

mod app_table;
mod error;
mod flow_config;
pub mod flow_map;
pub(crate) mod flow_node;
pub(crate) mod flow_state;
mod packet_sequence; // Enterprise Edition Feature: packet-sequence
pub mod perf;
mod pool;
pub mod protocol_logs;
mod service_table;

pub use app_table::AppTable;
pub use error::{Error, Result};
pub use flow_config::{FlowMapConfig, FlowMapRuntimeConfig, FlowTimeout, TcpTimeout};
pub use flow_map::FlowMap;
use flow_node::{FlowMapKey, FlowNode};
pub use flow_state::FlowState;
pub use packet_sequence::PacketSequenceParser; // Enterprise Edition Feature: packet-sequence
pub use protocol_logs::L7ProtoRawDataType;
pub use protocol_logs::{
    AppProtoHead, AppProtoLogsBaseInfo, AppProtoLogsData, DnsLog, DubboLog, HttpLog, KafkaLog,
    LogMessageType, MetaAppProto, MqttLog, MysqlLog, RedisLog,
};

use std::time::Duration;

const FLOW_METRICS_PEER_SRC: usize = 0;
const FLOW_METRICS_PEER_DST: usize = 1;
const TIME_UNIT: Duration = Duration::from_secs(1);
const QUEUE_BATCH_SIZE: usize = 1024;
const STATISTICAL_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_L7_LOG_PACKET_SIZE: u32 = 256;
const THREAD_FLOW_ID_MASK: u64 = 0xFF;
const TIMER_FLOW_ID_MASK: u64 = 0xFFFFFFFF;
const COUNTER_FLOW_ID_MASK: u64 = 0xFFFFFF;
// 暂定的Ipv4 ServiceTable LRU cache 容量
const SERVICE_TABLE_IPV4_CAPACITY: usize = 2048;
// 暂定的Ipv6 ServiceTable LRU cache 容量
const SERVICE_TABLE_IPV6_CAPACITY: usize = 256;
const L7_RRT_CACHE_CAPACITY: usize = 8192;
