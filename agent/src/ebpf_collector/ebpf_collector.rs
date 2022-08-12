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

use std::collections::HashMap;
use std::ffi::CString;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use log::{debug, error, info, warn};
use lru::LruCache;

use super::{Error, Result};
use crate::common::enums::{IpProtocol, PacketDirection};
use crate::common::flow::L7Protocol;
use crate::common::meta_packet::MetaPacket;
use crate::config::handler::{EbpfConfig, LogParserAccess};
use crate::ebpf;
use crate::flow_generator::{
    dns_check_protocol, dubbo_check_protocol, http1_check_protocol, http2_check_protocol,
    kafka_check_protocol, mqtt_check_protocol, mysql_check_protocol, redis_check_protocol,
    AppProtoHead, AppProtoLogsBaseInfo, AppProtoLogsData, AppProtoLogsInfo, AppTable, DnsLog,
    DubboLog, Error as LogError, HttpLog, KafkaLog, L7LogParse, LogMessageType, MqttLog, MysqlLog,
    RedisLog, Result as LogResult,
};
use crate::policy::PolicyGetter;
use crate::sender::SendItem;
use crate::utils::{
    queue::{bounded, DebugSender, Receiver, Sender},
    stats::{Counter, CounterType, CounterValue, OwnedCountable},
    LeakyBucket,
};

type LoggerItem = (L7Protocol, Box<dyn L7LogParse>);

struct SessionAggr {
    maps: [Option<HashMap<u64, AppProtoLogsData>>; 16],
    start_time: u64, // 秒级时间
    cache_count: u64,
    last_flush_time: u64, // 秒级时间
    slot_count: u64,

    counter: SyncEbpfCounter,

    log_rate: Arc<LeakyBucket>,
    output: DebugSender<SendItem>,
}

impl SessionAggr {
    // 尽力而为的聚合默认120秒(AppProtoLogs.aggr*SLOT_WIDTH)内的请求和响应
    const SLOT_WIDTH: u64 = 60; // 每个slot存60秒
    const SLOT_CACHED_COUNT: u64 = 300000; // 每个slot平均缓存的FLOW数

    pub fn new(
        l7_log_session_timeout: Duration,
        counter: SyncEbpfCounter,
        log_rate: Arc<LeakyBucket>,
        output: DebugSender<SendItem>,
    ) -> Self {
        let slot_count = l7_log_session_timeout.as_secs() / Self::SLOT_WIDTH;
        let slot_count = slot_count.min(16).max(1) as usize;
        Self {
            slot_count: slot_count as u64,
            output,
            start_time: 0,
            cache_count: 0,
            last_flush_time: 0,
            counter,
            log_rate,
            maps: [
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
                Some(HashMap::new()),
            ],
        }
    }

    fn send(&self, log: AppProtoLogsData) {
        debug!("ebpf_collector out: {}", log);
        if !self.log_rate.acquire(1) {
            self.counter.counter().throttle_drop += 1;
            return;
        }
        let _ = self.output.send(SendItem::L7FlowLog(Box::new(log)));
        self.counter.counter().tx += 1;
    }

    fn flush(&mut self, count: u64) -> u64 {
        let n = count.min(self.slot_count);
        for i in 0..n as usize {
            let mut map = self.maps[i].take().unwrap();
            for (_, log) in map.drain() {
                self.cache_count -= 1;
                self.send(log);
            }
            self.maps[i].replace(map);
        }

        if n != self.slot_count {
            for i in n..self.slot_count {
                let temp_back = self.maps[i as usize].take().unwrap();
                let temp_front = self.maps[(i - n) as usize].take().unwrap();
                self.maps[(i - n) as usize].replace(temp_back);
                self.maps[i as usize].replace(temp_front);
            }
        }
        self.start_time += count * Self::SLOT_WIDTH;

        self.slot_count - 1
    }

    fn slot_handle(&mut self, mut log: AppProtoLogsData, slot_index: usize, key: u64, ttl: usize) {
        let mut map = self.maps[slot_index as usize].take().unwrap();

        match log.base_info.head.msg_type {
            LogMessageType::Request => {
                let value = map.remove(&key);
                if value.is_none() {
                    // 防止缓存过多的log
                    if self.cache_count >= self.slot_count * Self::SLOT_CACHED_COUNT {
                        self.send(log);
                        self.maps[slot_index as usize].replace(map);
                        return;
                    }

                    map.insert(key, log);
                    self.cache_count += 1;
                    self.maps[slot_index as usize].replace(map);
                    return;
                }
                let item = value.unwrap();
                // 若乱序，已存在响应，则可以匹配为会话，则聚合响应发送
                if item.base_info.head.msg_type == LogMessageType::Response {
                    let rrt = if item.base_info.start_time > log.base_info.start_time {
                        item.base_info.start_time - log.base_info.start_time
                    } else {
                        Duration::ZERO
                    };
                    log.session_merge(item);
                    log.base_info.head.rrt = rrt.as_micros() as u64;
                    self.cache_count -= 1;
                    self.send(log);
                } else {
                    // 对于HTTPV1, requestID总为0, 连续出现多个request时，response匹配最后一个request为session
                    map.insert(key, log);
                    self.send(item);
                }
            }
            LogMessageType::Response => {
                let mut item = map.remove(&key);
                if item.is_none() {
                    if ttl > 0 && slot_index != 0 {
                        // 响应和请求时间差长的话，不在同一个时间槽里,或者此时请求还未到达，这里继续查询小的时间槽
                        let mut pre_map = self.maps[slot_index - 1 as usize].take();
                        let pre_map_mut = pre_map.as_mut().unwrap();
                        item = pre_map_mut.remove(&key);
                        if item.is_none() {
                            self.maps[slot_index - 1 as usize].replace(pre_map.unwrap());
                            // ebpf的数据存在乱序，回应比请求先到的情况
                            map.insert(key, log);
                            self.cache_count += 1;
                            self.maps[slot_index as usize].replace(map);
                            return;
                        }
                        self.maps[slot_index - 1 as usize].replace(pre_map.unwrap());
                    } else {
                        // ebpf的数据存在乱序，回应比请求先到的情况
                        map.insert(key, log);
                        self.cache_count += 1;
                        self.maps[slot_index as usize].replace(map);
                        return;
                    }
                }
                let mut item = item.unwrap();

                let rrt = if log.base_info.start_time > item.base_info.start_time {
                    log.base_info.start_time - item.base_info.start_time
                } else {
                    Duration::ZERO
                };
                // 若乱序导致map中的也是响应, 则发送响应,继续缓存新的响应
                if item.base_info.head.msg_type == LogMessageType::Response {
                    map.insert(key, log);
                    self.send(item);
                } else {
                    item.session_merge(log);
                    item.base_info.head.rrt = rrt.as_micros() as u64;
                    self.cache_count -= 1;
                    self.send(item);
                }
            }
            _ => {}
        }
        self.maps[slot_index as usize].replace(map);
    }

    fn handle(&mut self, log: AppProtoLogsData) {
        let solt_time = log.base_info.start_time.as_secs();
        if solt_time < self.start_time {
            self.send(log);
            return;
        }
        if self.start_time == 0 {
            self.start_time = solt_time / Self::SLOT_WIDTH * Self::SLOT_WIDTH;
        }

        let mut slot_index = (solt_time - self.start_time) / Self::SLOT_WIDTH;
        if slot_index >= self.slot_count {
            slot_index = self.flush(slot_index - self.slot_count + 1);
        }

        let key = log.ebpf_flow_session_id();
        self.slot_handle(log, slot_index as usize, key, 1);
    }
}

struct FlowItem {
    last_policy: u64, // 秒级
    last_packet: u64, // 秒级
    remote_epc: i32,

    // 应用识别
    protocol_bitmap_image: u128,
    protocol_bitmap: u128,
    l4_protocol: IpProtocol,
    l7_protocol: L7Protocol,

    is_from_app: bool,
    is_success: bool,
    is_local_service: bool,
    is_skip: bool,

    parser: Option<Box<dyn L7LogParse>>,
}

impl From<IpProtocol> for u128 {
    fn from(protocol: IpProtocol) -> Self {
        let bitmap = if protocol == IpProtocol::Tcp {
            1 << u8::from(L7Protocol::Http1)
                | 1 << u8::from(L7Protocol::Http2)
                | 1 << u8::from(L7Protocol::Dns)
                | 1 << u8::from(L7Protocol::Mysql)
                | 1 << u8::from(L7Protocol::Redis)
                | 1 << u8::from(L7Protocol::Dubbo)
                | 1 << u8::from(L7Protocol::Kafka)
                | 1 << u8::from(L7Protocol::Mqtt)
        } else {
            1 << u8::from(L7Protocol::Dns)
        };
        return bitmap;
    }
}

impl FlowItem {
    const POLICY_INTERVAL: u64 = 10;
    const PROTOCOL_CHECK_LIMIT: usize = 2;
    const FLOW_ITEM_TIMEOUT: u64 = 60;

    fn get_parser(
        protocol: L7Protocol,
        log_parser_config: &LogParserAccess,
    ) -> Option<Box<dyn L7LogParse>> {
        match protocol {
            L7Protocol::Dns => Some(Box::from(DnsLog::default())),
            L7Protocol::Http1 => Some(Box::from(HttpLog::new(log_parser_config, false))),
            L7Protocol::Http2 => Some(Box::from(HttpLog::new(log_parser_config, false))),
            L7Protocol::Http1TLS => Some(Box::from(HttpLog::new(log_parser_config, true))),
            L7Protocol::Mysql => Some(Box::from(MysqlLog::default())),
            L7Protocol::Redis => Some(Box::from(RedisLog::default())),
            L7Protocol::Kafka => Some(Box::from(KafkaLog::default())),
            L7Protocol::Dubbo => Some(Box::from(DubboLog::new(log_parser_config))),
            L7Protocol::Mqtt => Some(Box::from(MqttLog::default())),
            _ => None,
        }
    }

    fn new(
        app_table: &mut AppTable,
        packet: &MetaPacket,
        local_epc: i32,
        remote_epc: i32,
        log_parser_config: &LogParserAccess,
    ) -> Self {
        let time_in_sec = packet.lookup_key.timestamp.as_secs();
        let l4_protocol = packet.lookup_key.proto;
        let l7_protocol = app_table.get_protocol_from_ebpf(packet, local_epc, remote_epc);
        let mut is_from_app = l7_protocol.is_some();
        let (mut l7_protocol, is_local_service) =
            l7_protocol.unwrap_or((L7Protocol::Unknown, false));
        let mut protocol_bitmap = u128::from(l4_protocol);
        if packet.l7_protocol_from_ebpf == L7Protocol::Http1TLS {
            protocol_bitmap |= 1 << u8::from(L7Protocol::Http1TLS);
            protocol_bitmap &= !(1 << u8::from(L7Protocol::Http1));
        }

        if packet.lookup_key.is_loopback_packet() {
            is_from_app = true;
            l7_protocol = packet.l7_protocol_from_ebpf;
        }

        FlowItem {
            last_policy: time_in_sec,
            last_packet: time_in_sec,
            remote_epc,
            l4_protocol,
            l7_protocol,
            is_success: false,
            is_local_service,
            is_from_app,
            is_skip: false,
            protocol_bitmap,
            protocol_bitmap_image: protocol_bitmap,
            parser: Self::get_parser(l7_protocol, log_parser_config),
        }
    }

    fn _check(&mut self, protocol: L7Protocol, packet: &MetaPacket) -> bool {
        match protocol {
            L7Protocol::Dns => dns_check_protocol(&mut self.protocol_bitmap, packet),
            L7Protocol::Dubbo => dubbo_check_protocol(&mut self.protocol_bitmap, packet),
            L7Protocol::Kafka => kafka_check_protocol(&mut self.protocol_bitmap, packet),
            L7Protocol::Mqtt => mqtt_check_protocol(&mut self.protocol_bitmap, packet),
            L7Protocol::Mysql => mysql_check_protocol(&mut self.protocol_bitmap, packet),
            L7Protocol::Redis => redis_check_protocol(&mut self.protocol_bitmap, packet),
            L7Protocol::Http1 => http1_check_protocol(&mut self.protocol_bitmap, packet),
            L7Protocol::Http2 => http2_check_protocol(&mut self.protocol_bitmap, packet),
            L7Protocol::Http1TLS => http1_check_protocol(&mut self.protocol_bitmap, packet),
            _ => false,
        }
    }

    fn check(
        &mut self,
        packet: &MetaPacket,
        local_epc: i32,
        app_table: &mut AppTable,
        log_parser_config: &LogParserAccess,
    ) -> LogResult<AppProtoHead> {
        if self.is_skip {
            return Err(LogError::L7ProtocolCheckLimit);
        }

        let protocols = [
            L7Protocol::Http1TLS,
            L7Protocol::Http1,
            L7Protocol::Http2,
            L7Protocol::Dubbo,
            L7Protocol::Mysql,
            L7Protocol::Redis,
            L7Protocol::Kafka,
            L7Protocol::Mqtt,
            L7Protocol::Dns,
        ];

        for i in protocols {
            if self.protocol_bitmap & 1 << u8::from(i) == 0 {
                continue;
            }
            if self._check(i, packet) {
                self.l7_protocol = i;
                self.parser = Self::get_parser(i, log_parser_config);
                return self._parse(packet, local_epc, app_table);
            }
        }
        self.is_skip = app_table.set_protocol_from_ebpf(
            packet,
            L7Protocol::Unknown,
            local_epc,
            self.remote_epc,
        );

        Err(LogError::L7ProtocolUnknown)
    }

    fn _parse(
        &mut self,
        packet: &MetaPacket,
        local_epc: i32,
        app_table: &mut AppTable,
    ) -> LogResult<AppProtoHead> {
        if !self.is_success && self.is_skip {
            return Err(LogError::L7ProtocolParseLimit);
        }

        let direction = if !self.is_success && !self.is_from_app {
            PacketDirection::ClientToServer
        } else {
            packet.direction
        };

        let ret = self.parser.as_mut().unwrap().parse(
            packet.raw_from_ebpf.as_ref(),
            packet.lookup_key.proto,
            direction,
        );

        if !self.is_success {
            if ret.is_ok() {
                app_table.set_protocol_from_ebpf(
                    packet,
                    self.l7_protocol,
                    local_epc,
                    self.remote_epc,
                );
                self.is_success = true;
                if !self.is_from_app {
                    self.is_local_service = packet.lookup_key.l2_end_1;
                }
            } else {
                self.is_skip = app_table.set_protocol_from_ebpf(
                    packet,
                    L7Protocol::Unknown,
                    local_epc,
                    self.remote_epc,
                );
            }
        }
        return ret;
    }

    fn reset(&mut self, l4_protocol: IpProtocol) {
        self.last_packet = 0;
        self.last_policy = 0;
        self.l7_protocol = L7Protocol::Unknown;
        self.is_skip = false;
        self.is_success = false;
        self.is_local_service = false;
        self.is_from_app = false;
        self.protocol_bitmap = if self.l4_protocol == l4_protocol {
            self.protocol_bitmap_image
        } else {
            u128::from(l4_protocol)
        };
        self.l4_protocol = l4_protocol;
        self.parser = None;
    }

    fn parse(
        &mut self,
        packet: &MetaPacket,
        local_epc: i32,
        app_table: &mut AppTable,
        log_parser_config: &LogParserAccess,
    ) -> LogResult<AppProtoHead> {
        let time_in_sec = packet.lookup_key.timestamp.as_secs();
        if self.last_packet + Self::FLOW_ITEM_TIMEOUT < time_in_sec {
            self.reset(packet.lookup_key.proto);
        }
        self.last_packet = time_in_sec;

        if self.parser.is_some() {
            return self._parse(packet, local_epc, app_table);
        }

        if self.is_from_app {
            return Err(LogError::L7ProtocolUnknown);
        }

        if packet.l4_payload_len() <= 1 {
            return Err(LogError::L7ProtocolUnknown);
        }

        return self.check(packet, local_epc, app_table, log_parser_config);
    }

    fn get_info(&mut self) -> AppProtoLogsInfo {
        self.parser.as_ref().unwrap().info()
    }

    fn lookup_epc(&mut self, packet: &MetaPacket, mut policy_getter: PolicyGetter, local_epc: i32) {
        let key = &packet.lookup_key;
        if key.timestamp.as_secs() > self.last_policy + Self::POLICY_INTERVAL {
            self.last_policy = key.timestamp.as_secs();
            self.remote_epc = if key.l2_end_0 {
                policy_getter.lookup_all_by_epc(key.src_ip, key.dst_ip, local_epc, 0)
            } else {
                policy_getter.lookup_all_by_epc(key.src_ip, key.dst_ip, 0, local_epc)
            };
        }
    }

    fn handle(
        &mut self,
        packet: &mut MetaPacket,
        policy_getter: PolicyGetter,
        app_table: &mut AppTable,
        log_parser_config: &LogParserAccess,
        local_epc: i32,
        vtap_id: u16,
    ) -> Option<AppProtoLogsData> {
        // 策略EPC
        self.lookup_epc(packet, policy_getter, local_epc);
        // 应用解析
        if let Ok(head) = self.parse(packet, local_epc, app_table, log_parser_config) {
            // 获取日志信息
            let info = self.get_info();
            let base =
                AppProtoLogsBaseInfo::from_ebpf(&packet, head, vtap_id, local_epc, self.remote_epc);
            return Some(AppProtoLogsData {
                base_info: base,
                special_info: info,
            });
        }
        return None;
    }
}

pub struct EbpfCounter {
    rx: u64,
    tx: u64,
    unknown_protocol: u64,
    throttle_drop: u64,
}

impl EbpfCounter {
    fn reset(&mut self) {
        self.rx = 0;
        self.tx = 0;
        self.unknown_protocol = 0;
        self.throttle_drop = 0;
    }
}

#[derive(Clone, Copy)]
pub struct SyncEbpfCounter {
    counter: *mut EbpfCounter,
}

impl SyncEbpfCounter {
    fn counter(&self) -> &mut EbpfCounter {
        unsafe { &mut *self.counter }
    }
}

unsafe impl Send for SyncEbpfCounter {}
unsafe impl Sync for SyncEbpfCounter {}

impl OwnedCountable for SyncEbpfCounter {
    fn get_counters(&self) -> Vec<Counter> {
        let (rx, tx, unknow, drop) = (
            self.counter().rx,
            self.counter().tx,
            self.counter().unknown_protocol,
            self.counter().throttle_drop,
        );
        self.counter().reset();

        let ebpf_counter = unsafe { ebpf::socket_tracer_stats() };

        vec![
            (
                "collector_in",
                CounterType::Counted,
                CounterValue::Unsigned(rx),
            ),
            (
                "collector_out",
                CounterType::Counted,
                CounterValue::Unsigned(tx),
            ),
            (
                "collector_unknown_protocol",
                CounterType::Counted,
                CounterValue::Unsigned(unknow),
            ),
            (
                "throttle_drop",
                CounterType::Counted,
                CounterValue::Unsigned(drop),
            ),
            (
                "perf_pages_count",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.perf_pages_count as u64),
            ),
            (
                "kern_lost",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.kern_lost),
            ),
            (
                "kern_socket_map_max",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.kern_socket_map_max as u64),
            ),
            (
                "kern_socket_map_used",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.kern_socket_map_used as u64),
            ),
            (
                "kern_trace_map_max",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.kern_trace_map_max as u64),
            ),
            (
                "kern_trace_map_used",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.kern_trace_map_used as u64),
            ),
            (
                "socket_map_max_reclaim",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.socket_map_max_reclaim as u64),
            ),
            (
                "worker_num",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.worker_num as u64),
            ),
            (
                "queue_capacity",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.queue_capacity as u64),
            ),
            (
                "user_enqueue_count",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.user_enqueue_count),
            ),
            (
                "user_dequeue_count",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.user_dequeue_count),
            ),
            (
                "user_enqueue_lost",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.user_enqueue_lost),
            ),
            (
                "queue_burst_count",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.queue_burst_count),
            ),
            (
                "is_adapt_success",
                CounterType::Counted,
                CounterValue::Unsigned(if ebpf_counter.is_adapt_success { 1 } else { 0 }),
            ),
            (
                "tracer_state",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.tracer_state as u64),
            ),
            (
                "boot_time_update_diff",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.boot_time_update_diff as u64),
            ),
            (
                "probes_count",
                CounterType::Counted,
                CounterValue::Unsigned(ebpf_counter.probes_count as u64),
            ),
        ]
    }
    // EbpfCollector不会重复创建，这里都是false
    fn closed(&self) -> bool {
        false
    }
}

struct EbpfRunner {
    time_diff: Arc<AtomicI64>,

    receiver: Receiver<Box<MetaPacket<'static>>>,

    // 应用识别
    app_table: AppTable,

    // 策略查询
    policy_getter: PolicyGetter,

    // GRPC配置
    log_parser_config: LogParserAccess,
    l7_log_dynamic_is_updated: bool,

    config: EbpfConfig,

    log_rate: Arc<LeakyBucket>,
    output: DebugSender<SendItem>,
}

fn lookup_epc(packet: &MetaPacket, mut policy_getter: PolicyGetter, local_epc: i32) -> i32 {
    let key = &packet.lookup_key;
    if key.l2_end_0 {
        policy_getter.lookup_all_by_epc(key.src_ip, key.dst_ip, local_epc, 0)
    } else {
        policy_getter.lookup_all_by_epc(key.src_ip, key.dst_ip, 0, local_epc)
    }
}

impl EbpfRunner {
    const FLOW_MAP_SIZE: usize = 1 << 14;

    fn on_config_change(&mut self, config: &EbpfConfig) {
        info!(
            "ebpf collector config change from {:#?} to {:#?}.",
            self.config, config
        );
        self.config = config.clone();
        unsafe { CAPTURE_SIZE = config.l7_log_packet_size }
    }

    fn l7_log_dynamic_config_updated(&mut self) {
        debug!("ebpf l7 log config updated.");
        self.l7_log_dynamic_is_updated = true;
    }

    fn run(&mut self, sync_counter: SyncEbpfCounter) {
        let mut aggr = SessionAggr::new(
            self.config.l7_log_session_timeout,
            sync_counter,
            self.log_rate.clone(),
            self.output.clone(),
        );
        let mut flow_map: LruCache<u64, FlowItem> = LruCache::new(Self::FLOW_MAP_SIZE);

        while unsafe { SWITCH } {
            let mut packet = self.receiver.recv(Some(Duration::from_millis(1)));
            if packet.is_err() {
                continue;
            }

            // 应用解析配置发生变更清空数据
            if self.l7_log_dynamic_is_updated {
                flow_map.clear();
                self.l7_log_dynamic_is_updated = false;
            }

            sync_counter.counter().rx += 1;

            let packet = packet.as_mut().unwrap();
            packet.timestamp_adjust(self.time_diff.load(Ordering::Relaxed));
            packet.set_loopback_mac(self.config.ctrl_mac);

            let key = packet.ebpf_flow_id();

            // 流聚合
            let mut flow_item = flow_map.get_mut(&key);
            if flow_item.is_none() {
                let remote_epc = lookup_epc(packet, self.policy_getter, self.config.epc_id as i32);
                flow_map.put(
                    key,
                    FlowItem::new(
                        &mut self.app_table,
                        packet,
                        self.config.epc_id as i32,
                        remote_epc,
                        &self.log_parser_config,
                    ),
                );
                flow_item = flow_map.get_mut(&key);
            }

            if self.config.epc_id == 0 {
                continue;
            }

            flow_item.and_then(|flow_item| {
                // 应用解析
                if let Some(data) = flow_item.handle(
                    packet,
                    self.policy_getter,
                    &mut self.app_table,
                    &self.log_parser_config,
                    self.config.epc_id as i32,
                    self.config.vtap_id,
                ) {
                    // 应用日志聚合
                    aggr.handle(data);
                }
                Some(())
            });
        }
    }
}

struct SyncEbpfRunner {
    runner: *mut EbpfRunner,
}

unsafe impl Sync for SyncEbpfRunner {}
unsafe impl Send for SyncEbpfRunner {}

impl SyncEbpfRunner {
    fn runner(&self) -> &mut EbpfRunner {
        unsafe { &mut *self.runner }
    }
}

pub struct EbpfCollector {
    thread_runner: EbpfRunner,
    thread_handle: Option<JoinHandle<()>>,

    counter: EbpfCounter,
}

static mut SWITCH: bool = false;
static mut SENDER: Option<Sender<Box<MetaPacket>>> = None;
static mut CAPTURE_SIZE: usize = ebpf::CAP_LEN_MAX as usize;

impl EbpfCollector {
    extern "C" fn ebpf_callback(sd: *mut ebpf::SK_BPF_DATA) {
        unsafe {
            if !SWITCH || SENDER.is_none() {
                return;
            }
            debug!("ebpf collector in:\n{}", *sd);

            let packet = MetaPacket::from_ebpf(sd, CAPTURE_SIZE);
            if packet.is_err() {
                warn!("meta packet parse from ebpf error: {}", packet.unwrap_err());
                return;
            }
            if let Err(e) = SENDER.as_mut().unwrap().send(Box::new(packet.unwrap())) {
                warn!("meta packet send ebpf error: {:?}", e);
            }
        }
    }

    fn ebpf_init(config: &EbpfConfig, sender: Sender<Box<MetaPacket<'static>>>) -> Result<()> {
        // ebpf内核模块初始化
        unsafe {
            let log_file = config.log_path.clone();
            let log_file = if !log_file.is_empty() {
                CString::new(log_file.as_bytes())
                    .unwrap()
                    .as_c_str()
                    .as_ptr()
            } else {
                std::ptr::null()
            };

            if ebpf::bpf_tracer_init(log_file, true) != 0 {
                info!("ebpf bpf_tracer_init error: {}", config.log_path);
                return Err(Error::EbpfInitError);
            }

            if ebpf::running_socket_tracer(
                Self::ebpf_callback, /* 回调接口 rust -> C */
                1,                   /* 工作线程数，是指用户态有多少线程参与数据处理 */
                128,                 /* 内核共享内存占用的页框数量, 值为2的次幂。用于perf数据传递 */
                65536,               /* 环形缓存队列大小，值为2的次幂。e.g: 2,4,8,16,32,64,128 */
                524288, /* 设置用于socket追踪的hash表项最大值，取决于实际场景中并发请求数量 */
                524288, /* 设置用于线程追踪会话的hash表项最大值，SK_BPF_DATA结构的syscall_trace_id_session关联这个哈希表 */
                520000, /* socket map表项进行清理的最大阈值，当前map的表项数量超过这个值进行map清理操作 */
            ) != 0
            {
                return Err(Error::EbpfRunningError);
            }
            ebpf::bpf_tracer_finish();
        }
        // ebpf和ebpf collector通信配置初始化
        unsafe {
            SWITCH = false;
            SENDER = Some(sender);
            CAPTURE_SIZE = config.l7_log_packet_size;
        }

        Ok(())
    }

    fn ebpf_start() {
        debug!("ebpf collector starting ebpf-kernel.");
        unsafe {
            const RETRY_MAX: i32 = 50;
            let mut retry_count = 0;
            /*
             * The eBPF tracer_start() can be executed successfully only after the eBPF
             * initialization is complete and the eBPF is in the STOP state.Need to wait
             * for the initialization of tracer and the state transition to complete.
             * The maximum waiting time is 100 seconds, more than this will throw an error.
             */
            while ebpf::tracer_start() != 0 && retry_count < RETRY_MAX {
                std::thread::sleep(Duration::from_secs(2));
                retry_count = retry_count + 1;
                if retry_count >= RETRY_MAX {
                    error!("The tracer_start() error. Kernel offset adapt failed.\n");
                }
            }
        }
    }

    fn ebpf_stop() {
        info!("ebpf collector stopping ebpf-kernel.");
        unsafe {
            ebpf::tracer_stop();
        }
    }

    pub fn new(
        time_diff: Arc<AtomicI64>,
        config: &EbpfConfig,
        log_parser_config: LogParserAccess,
        policy_getter: PolicyGetter,
        l7_log_rate: Arc<LeakyBucket>,
        output: DebugSender<SendItem>,
    ) -> Result<Box<Self>> {
        info!("ebpf collector init...");
        let (sender, receiver, _) = bounded(1024);

        Self::ebpf_init(config, sender)?;
        info!("ebpf collector initialized.");
        return Ok(Box::new(EbpfCollector {
            thread_runner: EbpfRunner {
                time_diff,
                receiver,
                app_table: AppTable::new(
                    config.l7_protocol_inference_max_fail_count,
                    config.l7_protocol_inference_ttl,
                ),
                policy_getter,
                config: config.clone(),
                log_parser_config,
                output,
                log_rate: l7_log_rate,
                l7_log_dynamic_is_updated: false,
            },
            thread_handle: None,
            counter: EbpfCounter {
                rx: 0,
                tx: 0,
                unknown_protocol: 0,
                throttle_drop: 0,
            },
        }));
    }

    pub fn l7_log_dynamic_config_updated(&mut self) {
        self.thread_runner.l7_log_dynamic_config_updated();
    }

    pub fn get_sync_counter(&self) -> SyncEbpfCounter {
        SyncEbpfCounter {
            counter: &self.counter as *const EbpfCounter as *mut EbpfCounter,
        }
    }

    fn get_sync_runner(&self) -> SyncEbpfRunner {
        SyncEbpfRunner {
            runner: &self.thread_runner as *const EbpfRunner as *mut EbpfRunner,
        }
    }

    pub fn on_config_change(&mut self, config: &EbpfConfig) {
        if config.l7_log_enabled() {
            self.start();
        } else {
            self.stop();
        }

        self.thread_runner.on_config_change(config);
    }

    pub fn start(&mut self) {
        unsafe {
            if SWITCH {
                info!("ebpf collector started");
                return;
            }
            SWITCH = true;
        }

        let sync_runner = self.get_sync_runner();
        let sync_counter = self.get_sync_counter();
        self.thread_handle = Some(thread::spawn(move || {
            sync_runner.runner().run(sync_counter)
        }));

        debug!("ebpf collector starting ebpf-kernel.");
        Self::ebpf_start();
        info!("ebpf collector started");
    }

    pub fn stop(&mut self) {
        unsafe {
            if !SWITCH {
                info!("ebpf collector stopped.");
                return;
            }
            SWITCH = false;
        }
        Self::ebpf_stop();

        info!("ebpf collector stopping thread.");
        if let Some(handler) = self.thread_handle.take() {
            let _ = handler.join();
        }
        info!("ebpf collector stopped.");
    }
}

impl Drop for EbpfCollector {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_ebpf_collector() {}
}
