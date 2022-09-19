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

use crate::common::ebpf::{get_all_protocols_by_ebpf_type, EbpfType};
use crate::common::enums::{IpProtocol, PacketDirection};
use crate::common::flow::L7Protocol;
use crate::common::meta_packet::MetaPacket;
use crate::config::handler::{EbpfConfig, LogParserAccess};
use crate::debug::QueueDebugger;
use crate::ebpf;
use crate::flow_generator::{
    dns_check_protocol, dubbo_check_protocol, http1_check_protocol, http2_check_protocol,
    kafka_check_protocol, mqtt_check_protocol, mysql_check_protocol, redis_check_protocol,
    AppProtoHeadEnum, AppProtoLogsBaseInfo, AppProtoLogsData, AppProtoLogsInfoEnum, AppTable,
    DnsLog, DubboLog, Error as LogError, HttpLog, KafkaLog, L7LogParse, L7ProtoRawDataType,
    MqttLog, MysqlLog, RedisLog, Result as LogResult,
};
use crate::policy::PolicyGetter;
use crate::sender::SendItem;
use crate::utils::{
    queue::{bounded_with_debug, DebugSender, Receiver},
    LeakyBucket,
};
use public::counter::{Counter, CounterType, CounterValue, OwnedCountable};

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
        if log.omit_send() {
            debug!("ebpf_collector out omit: {}", log);
            return;
        }
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

    // slot_range 最多往前多少个slot找. 返回data和对应的slot_index
    fn remove(
        &mut self,
        slot_idx: usize,
        key: u64,
        slot_range: usize,
    ) -> (Option<AppProtoLogsData>, Option<usize>) {
        for off in 0..=slot_range {
            let idx = slot_idx as i32 - off as i32;
            if idx < 0 {
                return (None, None);
            }
            let mut map = self.maps[idx as usize].take().unwrap();
            let data = map.remove(&key);
            self.maps[idx as usize] = Some(map);
            if data.is_some() {
                return (data, Some(idx as usize));
            }
        }
        return (None, None);
    }

    fn insert(
        &mut self,
        slot_idx: usize,
        key: u64,
        data: AppProtoLogsData,
    ) -> Option<AppProtoLogsData> {
        let mut map = self.maps[slot_idx].take().unwrap();
        let old = map.insert(key, data);
        self.maps[slot_idx] = Some(map);
        return old;
    }

    fn log_exceed(&self) -> bool {
        return self.cache_count >= self.slot_count * Self::SLOT_CACHED_COUNT;
    }

    /*
     SessionAggr 主要用于匹配请求和响应,目前在 go http2 uprobe 也用于聚合请求.
     SessionAggr 本质是一个 数组+map的结构 数组是一个长度为 最大超时时间/slot时间间隔(最大16最小1)  的时序slot,每个slot时间间隔目前是60s.
     map 是一个session_id(AppProtoLogsData::ebpf_flow_session_id()) 为key 的字典.
     一个AppProtoLogsData 的 slot index 等于 (AppProtoLogsData.base_info.start_time - solt.start_time) / 每个slot时间间隔.
     ebpf提交的请求和响应有可能乱序,另也有可能没有响应导致同一个key收到重复的请求,目前主要处理策略如下:
     情况1: 收到响应,
        1.1: 当前slot有对应请求,取出对应请求然后和响应聚合,然后send.
        1.2: 当前slot没有对应请求,往前一个找,目前只会找前一个slot,所以两个请求时间相隔超过120s必然不能聚合.
        1.2.1: 找到,取出对应请求然后和响应聚合,然后send.
        1.2.2: 找不到,由于ebpf可能响应比请求早,先存下来,等待请求到达.
     情况2: 收到请求
        2.1: 当前solt找响应
        2.1.1: 找到,聚合发送.
        2.1.2: 找不到, 先存下来,等待响应.

     对于go http2 uprobe 来说,不管收到请求还是响应,都会和现有的数据数据聚合,直到收到请求结束标志和响应结束标志再发送

     slot有flush机制,目前只有当收到新的AppProtoLogsData,  slot index >= slot的长度, 才会触发.
     flush会强制发送前面的slot,然后将后面slot的map搬上来,空出slot.
    */
    fn slot_handle(&mut self, log: AppProtoLogsData, slot_index: usize, key: u64) {
        if log.is_request() {
            if log.need_protocol_merge() {
                self.on_merge_request_log(log, slot_index, key);
            } else {
                self.on_non_merge_request_log(log, slot_index, key);
            }
        } else {
            if log.need_protocol_merge() {
                self.on_merge_response_log(log, slot_index, key);
            } else {
                self.on_non_merge_response_log(log, slot_index, key);
            }
        }
    }

    // 处理非聚合日志
    fn on_non_merge_request_log(&mut self, mut log: AppProtoLogsData, slot_index: usize, key: u64) {
        let (value, _) = self.remove(slot_index, key, 0);
        if value.is_none() {
            // 防止缓存过多的log
            if self.log_exceed() {
                self.send(log);
            } else {
                self.insert(slot_index, key, log);
                self.cache_count += 1;
            }
            return;
        }
        let item = value.unwrap();
        // 若乱序，已存在响应，则可以匹配为会话，则聚合响应发送
        if item.is_response() {
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
            self.insert(slot_index, key, log);
            self.send(item);
        }
    }

    // 处理聚合日志, 目前只有 http2 go uprobe 需要聚合
    fn on_merge_request_log(&mut self, log: AppProtoLogsData, slot_index: usize, key: u64) {
        let (value, _) = self.remove(slot_index, key, 1);
        if value.is_none() {
            // 防止缓存过多的log
            if self.log_exceed() {
                self.send(log);
            } else {
                self.insert(slot_index, key, log);
                self.cache_count += 1;
            }
            return;
        }
        let mut item = value.unwrap();
        item.protocol_merge(log.special_info);

        if item.is_end() {
            self.cache_count -= 1;
            self.send(item);
        } else {
            if !log.base_info.start_time.is_zero()
                && log.base_info.start_time < item.base_info.start_time
            {
                item.base_info.start_time = log.base_info.start_time;
            }
            self.insert(slot_index, key, item);
        }
    }

    fn on_non_merge_response_log(&mut self, log: AppProtoLogsData, slot_index: usize, key: u64) {
        let (item, _) = self.remove(slot_index, key, 1);
        if item.is_none() {
            // ebpf的数据存在乱序，回应比请求先到的情况
            if self.log_exceed() {
                self.send(log);
            } else {
                self.insert(slot_index, key, log);
                self.cache_count += 1;
            }
            return;
        }
        let mut item = item.unwrap();

        let rrt = if log.base_info.start_time > item.base_info.start_time {
            log.base_info.start_time - item.base_info.start_time
        } else {
            Duration::ZERO
        };
        // 若乱序导致map中的也是响应, 则发送响应,继续缓存新的响应
        if item.is_response() {
            self.insert(slot_index, key, log);
            self.send(item);
        } else {
            item.session_merge(log);
            item.base_info.head.rrt = rrt.as_micros() as u64;
            self.cache_count -= 1;
            self.send(item);
        }
    }

    fn on_merge_response_log(&mut self, log: AppProtoLogsData, slot_index: usize, key: u64) {
        let (value, _) = self.remove(slot_index, key, 1);
        if value.is_none() {
            if self.log_exceed() {
                self.send(log);
            } else {
                self.insert(slot_index, key, log);
                self.cache_count += 1;
            }
            return;
        }
        let mut item = value.unwrap();
        item.session_merge(log);

        if item.is_end() {
            self.cache_count -= 1;
            self.send(item);
        } else {
            self.insert(slot_index, key, item);
        }
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
        self.slot_handle(log, slot_index as usize, key);
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

    server_port: u16,

    is_from_app: bool,
    is_success: bool,
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
        ebpf_type: EbpfType,
        log_parser_config: &LogParserAccess,
    ) -> Option<Box<dyn L7LogParse>> {
        let raw_data_type = L7ProtoRawDataType::from_ebpf_type(ebpf_type);

        match protocol {
            L7Protocol::Dns => Some(Box::from(DnsLog::default())),
            L7Protocol::Http1 => Some(Box::from(HttpLog::new(
                log_parser_config,
                false,
                raw_data_type,
            ))),
            L7Protocol::Http2 => Some(Box::from(HttpLog::new(
                log_parser_config,
                false,
                raw_data_type,
            ))),
            L7Protocol::Http1TLS => Some(Box::from(HttpLog::new(
                log_parser_config,
                true,
                raw_data_type,
            ))),
            L7Protocol::Http2TLS => Some(Box::from(HttpLog::new(
                log_parser_config,
                true,
                raw_data_type,
            ))),
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
        let is_from_app = l7_protocol.is_some();
        let (l7_protocol, server_port) = l7_protocol.unwrap_or((L7Protocol::Unknown, 0));
        let mut protocol_bitmap = u128::from(l4_protocol);
        match packet.l7_protocol_from_ebpf {
            L7Protocol::Http1TLS => {
                protocol_bitmap |= 1 << u8::from(L7Protocol::Http1TLS);
                protocol_bitmap &= !(1 << u8::from(L7Protocol::Http1));
            }
            L7Protocol::Http2TLS => {
                protocol_bitmap |= 1 << u8::from(L7Protocol::Http2TLS);
                protocol_bitmap &= !(1 << u8::from(L7Protocol::Http2));
            }
            _ => {}
        }

        FlowItem {
            last_policy: time_in_sec,
            last_packet: time_in_sec,
            remote_epc,
            l4_protocol,
            l7_protocol,
            is_success: false,
            is_from_app,
            is_skip: false,
            server_port,
            protocol_bitmap,
            protocol_bitmap_image: protocol_bitmap,
            parser: Self::get_parser(l7_protocol, packet.ebpf_type, log_parser_config),
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
            L7Protocol::Http1 | L7Protocol::Http1TLS => {
                http1_check_protocol(&mut self.protocol_bitmap, packet)
            }
            L7Protocol::Http2 | L7Protocol::Http2TLS => {
                http2_check_protocol(&mut self.protocol_bitmap, packet)
            }
            _ => false,
        }
    }

    fn check(
        &mut self,
        packet: &mut MetaPacket,
        local_epc: i32,
        app_table: &mut AppTable,
        log_parser_config: &LogParserAccess,
    ) -> LogResult<AppProtoHeadEnum> {
        if self.is_skip {
            return Err(LogError::L7ProtocolCheckLimit);
        }
        let protocols = get_all_protocols_by_ebpf_type(packet.ebpf_type, packet.is_tls());

        for i in protocols {
            if self.protocol_bitmap & 1 << u8::from(i) == 0 {
                continue;
            }
            if self._check(i, packet) {
                self.l7_protocol = i;
                self.server_port = packet.lookup_key.dst_port;
                self.parser = Self::get_parser(i, packet.ebpf_type, log_parser_config);
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
        packet: &mut MetaPacket,
        local_epc: i32,
        app_table: &mut AppTable,
    ) -> LogResult<AppProtoHeadEnum> {
        if !self.is_success && self.is_skip {
            return Err(LogError::L7ProtocolParseLimit);
        }

        packet.direction = if self.server_port == packet.lookup_key.dst_port {
            PacketDirection::ClientToServer
        } else {
            PacketDirection::ServerToClient
        };

        let ret = self.parser.as_mut().unwrap().parse(
            packet.raw_from_ebpf.as_ref(),
            packet.lookup_key.proto,
            packet.direction,
            Some(packet.is_request_end),
            Some(packet.is_response_end),
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
        packet: &mut MetaPacket,
        local_epc: i32,
        app_table: &mut AppTable,
        log_parser_config: &LogParserAccess,
    ) -> LogResult<AppProtoHeadEnum> {
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

    fn get_info(&mut self) -> AppProtoLogsInfoEnum {
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
    ) -> Option<Vec<AppProtoLogsData>> {
        // 策略EPC
        self.lookup_epc(packet, policy_getter, local_epc);
        // 应用解析, 获取日志信息
        let result = self
            .parse(packet, local_epc, app_table, log_parser_config)
            .ok()?
            .into_iter()
            .zip(self.get_info().into_iter())
            .map(|(h, i)| {
                let base = AppProtoLogsBaseInfo::from_ebpf(
                    &packet,
                    h,
                    vtap_id,
                    local_epc,
                    self.remote_epc,
                );
                AppProtoLogsData {
                    base_info: base,
                    special_info: i,
                }
            })
            .collect();
        Some(result)
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
        let mut flow_map: LruCache<u128, FlowItem> = LruCache::new(Self::FLOW_MAP_SIZE);

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
                    for d in data {
                        // 应用日志聚合
                        aggr.handle(d);
                    }
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
static mut SENDER: Option<DebugSender<Box<MetaPacket>>> = None;
static mut CAPTURE_SIZE: usize = ebpf::CAP_LEN_MAX as usize;

impl EbpfCollector {
    extern "C" fn ebpf_callback(sd: *mut ebpf::SK_BPF_DATA) {
        unsafe {
            if !SWITCH || SENDER.is_none() {
                return;
            }

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

    fn ebpf_init(config: &EbpfConfig, sender: DebugSender<Box<MetaPacket<'static>>>) -> Result<()> {
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
        queue_debugger: &QueueDebugger,
    ) -> Result<Box<Self>> {
        info!("ebpf collector init...");
        let (sender, receiver, _) =
            bounded_with_debug(4096, "1-ebpf-packet-to-ebpf-collector", queue_debugger);

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
