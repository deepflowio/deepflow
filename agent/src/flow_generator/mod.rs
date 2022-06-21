mod app_table;
mod error;
mod flow_config;
pub mod flow_map;
mod flow_node;
mod flow_state;
pub mod perf;
mod protocol_logs;
mod service_table;

pub use app_table::AppTable;
pub use error::{Error, Result};
pub use flow_config::{FlowMapConfig, FlowMapRuntimeConfig, FlowTimeout, TcpTimeout};
pub use flow_map::FlowMap;
use flow_node::{FlowMapKey, FlowNode, FlowTimeKey};
pub use flow_state::FlowState;
pub use perf::L7RrtCache;
pub use protocol_logs::{
    dns_check_protocol, dubbo_check_protocol, http1_check_protocol, http2_check_protocol,
    kafka_check_protocol, mqtt_check_protocol, mysql_check_protocol, redis_check_protocol,
};
pub use protocol_logs::{
    AppProtoHead, AppProtoLogsBaseInfo, AppProtoLogsData, AppProtoLogsInfo, AppProtoLogsParser,
    DnsLog, DubboLog, HttpLog, KafkaLog, L7LogParse, LogMessageType, MetaAppProto, MqttLog,
    MysqlLog, RedisLog,
};

use std::time::Duration;

const FLOW_METRICS_PEER_SRC: usize = 0;
const FLOW_METRICS_PEER_DST: usize = 1;
const TIME_UNIT: Duration = Duration::from_secs(1);
const TIME_MAX_INTERVAL: Duration = Duration::from_secs(5);
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
const L7_RRT_CACHE_CAPACITY: usize = 4096;
const L7_PROTOCOL_UNKNOWN_LIMIT: Duration = Duration::from_secs(60);
