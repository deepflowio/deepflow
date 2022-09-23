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

use std::{
    cmp::min,
    collections::HashMap,
    mem::swap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    thread::JoinHandle,
    time::{Duration, SystemTime},
};

use arc_swap::access::Access;
use log::{debug, info, warn};

use super::{
    AppProtoHead, AppProtoLogsBaseInfo, AppProtoLogsData, AppProtoLogsInfo, DnsLog, DubboLog,
    KafkaLog, LogMessageType, MqttLog, MysqlLog, RedisLog,
};

use crate::{common::ebpf::EbpfType, flow_generator::protocol_logs::L7ProtoRawDataType};
use crate::{
    common::{
        enums::EthernetType,
        flow::{get_uniq_flow_id_in_one_minute, L7Protocol, PacketDirection},
        MetaPacket, TaggedFlow,
    },
    config::handler::LogParserAccess,
    flow_generator::{
        error::Result,
        protocol_logs::{HttpLog, L7LogParse},
        FLOW_METRICS_PEER_DST, FLOW_METRICS_PEER_SRC,
    },
    metric::document::TapSide,
    sender::SendItem,
    utils::{
        net::MacAddr,
        queue::{DebugSender, Error, Receiver},
        stats::{Counter, CounterType, CounterValue, RefCountable},
        LeakyBucket,
    },
};

const QUEUE_BATCH_SIZE: usize = 1024;
const RCV_TIMEOUT: Duration = Duration::from_secs(1);
// 尽力而为的聚合默认120秒(AppProtoLogs.aggr*SLOT_WIDTH)内的请求和响应
const SLOT_WIDTH: u64 = 10; // 每个slot存10秒
const SLOT_CACHED_COUNT: u64 = 100000; // 每个slot平均缓存的FLOW数

const THROTTLE_BUCKET_BITS: u8 = 2;
const THROTTLE_BUCKET: usize = 1 << THROTTLE_BUCKET_BITS; // 2^N。由于发送方是有突发的，需要累积一定时间做采样

#[derive(Debug)]
pub struct MetaAppProto {
    base_info: AppProtoLogsBaseInfo,
    direction: PacketDirection,
    raw_proto_payload: Vec<u8>,
}

impl MetaAppProto {
    pub fn new(
        flow: &TaggedFlow,
        meta_packet: &MetaPacket,
        head: AppProtoHead,
        offset: u16,
        packet_size: u16,
    ) -> Option<Self> {
        // 因metaPacket在logs处理时可能已经释放，需要copy metaPacket
        // 此处，只拷贝待解析的协议payload部分, offset表示相对于协议payload的偏移
        let raw_proto_payload = {
            let payload = meta_packet.get_l4_payload()?;
            let (offset, packet_size) = (offset as usize, packet_size as usize);
            let max_payload_len = payload.len() - offset;
            if max_payload_len > packet_size {
                (&payload[offset..offset + packet_size]).to_vec()
            } else {
                (&payload[offset..offset + max_payload_len]).to_vec()
            }
        };
        let mut base_info = AppProtoLogsBaseInfo {
            start_time: meta_packet.lookup_key.timestamp,
            end_time: meta_packet.lookup_key.timestamp,
            flow_id: flow.flow.flow_id,
            vtap_id: flow.flow.flow_key.vtap_id,
            tap_type: flow.flow.flow_key.tap_type,
            tap_port: flow.flow.flow_key.tap_port,
            tap_side: flow.flow.tap_side,
            head,
            protocol: meta_packet.lookup_key.proto,
            is_vip_interface_src: flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC]
                .is_vip_interface,
            is_vip_interface_dst: flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_DST]
                .is_vip_interface,
            mac_src: MacAddr::ZERO,
            mac_dst: MacAddr::ZERO,
            ip_src: meta_packet.lookup_key.src_ip,
            ip_dst: meta_packet.lookup_key.dst_ip,
            is_ipv6: meta_packet.lookup_key.eth_type == EthernetType::Ipv6,
            port_src: meta_packet.lookup_key.src_port,
            port_dst: meta_packet.lookup_key.dst_port,
            l3_epc_id_src: 0,
            l3_epc_id_dst: 0,
            req_tcp_seq: 0,
            resp_tcp_seq: 0,
            process_id_0: 0,
            process_id_1: 0,
            process_kname_0: "".to_string(),
            process_kname_1: "".to_string(),
            syscall_trace_id_request: 0,
            syscall_trace_id_response: 0,
            syscall_trace_id_thread_0: 0,
            syscall_trace_id_thread_1: 0,
            syscall_cap_seq_0: 0,
            syscall_cap_seq_1: 0,
            ebpf_type: EbpfType::None,
        };
        if flow.flow.tap_side == TapSide::Local {
            base_info.mac_src = flow.flow.flow_key.mac_src;
            base_info.mac_dst = flow.flow.flow_key.mac_dst;
        } else {
            if base_info.is_vip_interface_src {
                base_info.mac_src = flow.flow.flow_key.mac_src;
            }
            if base_info.is_vip_interface_dst {
                base_info.mac_dst = flow.flow.flow_key.mac_dst;
            }
        }

        if meta_packet.direction == PacketDirection::ClientToServer {
            base_info.l3_epc_id_src = flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC].l3_epc_id;
            base_info.l3_epc_id_dst = flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_DST].l3_epc_id;
            base_info.req_tcp_seq = meta_packet.tcp_data.seq;
        } else {
            base_info.l3_epc_id_src = flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_DST].l3_epc_id;
            base_info.l3_epc_id_dst = flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC].l3_epc_id;
            base_info.resp_tcp_seq = meta_packet.tcp_data.seq;
        }

        Some(Self {
            base_info,
            direction: meta_packet.direction,
            raw_proto_payload,
        })
    }
}

#[derive(Default)]
pub struct SessionAggrCounter {
    send_before_window: AtomicU64,
    receive: AtomicU64,
    merge: AtomicU64,
    cached: AtomicU64,
    throttle_drop: AtomicU64,
}

// FIXME: counter not registered
impl RefCountable for SessionAggrCounter {
    fn get_counters(&self) -> Vec<Counter> {
        vec![
            (
                "send-before-window",
                CounterType::Counted,
                CounterValue::Unsigned(self.send_before_window.swap(0, Ordering::Relaxed)),
            ),
            (
                "receive",
                CounterType::Counted,
                CounterValue::Unsigned(self.receive.swap(0, Ordering::Relaxed)),
            ),
            (
                "merge",
                CounterType::Counted,
                CounterValue::Unsigned(self.merge.swap(0, Ordering::Relaxed)),
            ),
            (
                "cached",
                CounterType::Counted,
                CounterValue::Unsigned(self.cached.load(Ordering::Relaxed)),
            ),
            (
                "throttle-drop",
                CounterType::Counted,
                CounterValue::Unsigned(self.throttle_drop.swap(0, Ordering::Relaxed)),
            ),
        ]
    }
}

struct SessionQueue {
    aggregate_start_time: Duration,
    last_flush_time: Duration,

    window_size: usize,
    time_window: Option<Vec<HashMap<u64, AppProtoLogsData>>>,

    log_rate: Arc<LeakyBucket>,

    counter: Arc<SessionAggrCounter>,
    output_queue: DebugSender<SendItem>,
    config: LogParserAccess,
}

impl SessionQueue {
    fn new(
        counter: Arc<SessionAggrCounter>,
        output_queue: DebugSender<SendItem>,
        config: LogParserAccess,
        log_rate: Arc<LeakyBucket>,
    ) -> Self {
        //l7_log_session_timeout 20s-300s ，window_size = 2-30，所以 SessionQueue.time_window 预分配内存
        let window_size =
            (config.load().l7_log_session_aggr_timeout.as_secs() / SLOT_WIDTH) as usize;
        let time_window = vec![HashMap::new(); window_size];

        Self {
            aggregate_start_time: Duration::ZERO,
            last_flush_time: Duration::ZERO,
            time_window: Some(time_window),
            config,
            window_size,

            log_rate,

            counter,
            output_queue,
        }
    }

    fn flush_one_slot(&mut self) {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        // 每秒检测是否flush, 若超过2倍slot时间未收到数据，则发送1个slot的数据
        if (now - self.last_flush_time).as_secs() < 2 * SLOT_WIDTH {
            return;
        }
        let mut time_window = match self.time_window.take() {
            Some(t) => t,
            None => return,
        };
        self.last_flush_time = now;
        // flush 1个slot的数据
        self.flush_window(1, &mut time_window);
        self.time_window.replace(time_window);
    }

    // 按时间窗口(6*10秒)聚合HTTP,DNS的请求和响应流程:
    //   - 收到请求，根据报文时间找到对应的时间窗口的缓存数据(若小于时间窗口的最小时间，则直接发送，若大于时间窗口的最大时间，则依次移动窗口，直到时间处于窗口内)
    //      - 若已缓存了(HTTPV1.1或重传时，存在一条流连续发送多个请求，且无法通过StreamID区分，则缓存最后一次的请求), 则发送旧的请求，存储当前请求
    //      - 若未缓存，则判断是否达到最大缓存数量
    //        - 未达到，则缓存
    //        - 达到， 则直接发送
    //   - 收到响应，根据报文时间-RRT时间，找到对应的时间窗口，查找是否有匹配的请求
    //      - 若有， 则合并请求和响应(将响应的数据填入请求中，并修改请求的类型为会话)，释放当前响应，发送会话
    //      - 若没有, 则直接发送当前响应
    fn aggregate_session_and_send(&mut self, item: AppProtoLogsData) {
        self.counter.receive.fetch_add(1, Ordering::Relaxed);

        let slot_time = if item.base_info.head.msg_type == LogMessageType::Response {
            // request = response - RRT
            (item.base_info.start_time - Duration::from_micros(item.base_info.head.rrt)).as_secs()
        } else {
            item.base_info.start_time.as_secs()
        };
        if slot_time < self.aggregate_start_time.as_secs() {
            if self
                .counter
                .send_before_window
                .fetch_add(1, Ordering::Relaxed)
                == 0
            {
                info!("l7 log {:?} (slot timestamp {:?}, start time: {:?}, rrt: {:?}) out of session aggregate window({:?}), will be sent without merge.",
                    item.base_info.head.proto,
                    Duration::from_secs(slot_time),
                    item.base_info.start_time,
                    Duration::from_micros(item.base_info.head.rrt),
                    self.aggregate_start_time
                );
            }
            self.send(item);
            return;
        }

        let mut slot = ((slot_time - self.aggregate_start_time.as_secs()) / SLOT_WIDTH) as usize;
        let mut time_window = match self.time_window.take() {
            Some(t) => t,
            None => return,
        };
        // 使time window维持在固定的长度
        if slot >= self.window_size {
            // flush过期的几个slot的数据
            self.flush_window(slot - self.window_size + 1, &mut time_window);
            slot = self.window_size - 1;
        }

        // 因为数组提前分配hashmap, slot < self.window_size 所以必然存在
        let map = time_window.get_mut(slot).unwrap();
        let key = Self::calc_key(&item);
        match item.base_info.head.msg_type {
            LogMessageType::Request => {
                // request，放入map
                if let Some(p) = map.remove(&key) {
                    // 对于HTTPV1, requestID总为0, 连续出现多个request时，response匹配最后一个request为session
                    self.send(p);
                    map.insert(key, item);
                } else if self.counter.cached.load(Ordering::Relaxed)
                    >= self.window_size as u64 * SLOT_CACHED_COUNT
                {
                    // 防止缓存过多的log
                    self.send(item);
                } else {
                    map.insert(key, item);
                    self.counter.cached.fetch_add(1, Ordering::Relaxed);
                }
            }
            LogMessageType::Response => {
                // response, 需要找到request并merge
                if let Some(mut request) = map.remove(&key) {
                    if request.base_info.head.proto == item.base_info.head.proto {
                        self.counter.cached.fetch_sub(1, Ordering::Relaxed);
                        self.counter.merge.fetch_add(1, Ordering::Relaxed);
                        request.session_merge(item);
                        self.send(request);
                    } else {
                        map.insert(key, request);
                        self.send(item);
                    }
                } else {
                    self.send(item);
                }
            }
            LogMessageType::Session => self.send(item),
            _ => (),
        }

        self.time_window.replace(time_window);
    }

    fn clear(&mut self) {
        let mut time_window = match self.time_window.take() {
            Some(t) => t,
            None => return,
        };
        for map in time_window.drain(..) {
            self.counter
                .cached
                .fetch_sub(map.len() as u64, Ordering::Relaxed);
            let v = map
                .into_values()
                .map(|item| SendItem::L7FlowLog(Box::new(item)))
                .collect();
            if let Err(Error::Terminated(..)) = self.output_queue.send_all(v) {
                warn!("output queue terminated");
                break;
            }
        }
        self.time_window.replace(time_window);
    }

    fn calc_key(item: &AppProtoLogsData) -> u64 {
        if let AppProtoLogsInfo::Mqtt(_) = item.special_info {
            return item.base_info.flow_id;
        }
        let request_id = match &item.special_info {
            AppProtoLogsInfo::Dns(d) => d.trans_id as u32,
            AppProtoLogsInfo::Dubbo(d) => d.serial_id as u32,
            AppProtoLogsInfo::HttpV1(h) => h.stream_id,
            AppProtoLogsInfo::HttpV2(h) => h.stream_id,
            AppProtoLogsInfo::Kafka(k) => k.correlation_id,
            _ => 0,
        };
        // key需保证流日志1分钟内唯一，由1分钟内唯一的flow_id和request_id组成
        get_uniq_flow_id_in_one_minute(item.base_info.flow_id) << 32 | (request_id as u64)
    }

    fn flush_window(&mut self, n: usize, time_window: &mut Vec<HashMap<u64, AppProtoLogsData>>) {
        let delete_num = min(n, self.window_size);
        for i in 0..delete_num {
            let map = time_window.get_mut(i).unwrap();
            self.counter
                .cached
                .fetch_sub(map.len() as u64, Ordering::Relaxed);
            self.send_all(map.drain().map(|(_, item)| item).collect());
        }
        let mut maps = time_window.drain(0..delete_num).collect();
        time_window.append(&mut maps);

        // update timestamp
        self.aggregate_start_time =
            Duration::from_secs(self.aggregate_start_time.as_secs() + n as u64 * SLOT_WIDTH);
    }

    fn send(&mut self, item: AppProtoLogsData) {
        if !self.log_rate.acquire(1) {
            self.counter.throttle_drop.fetch_add(1, Ordering::Relaxed);
            return;
        }

        if let Err(Error::Terminated(..)) =
            self.output_queue.send(SendItem::L7FlowLog(Box::new(item)))
        {
            warn!("output queue terminated");
        }
    }

    fn send_all(&mut self, items: Vec<AppProtoLogsData>) {
        for item in items {
            self.send(item);
        }
    }
}

#[derive(Default)]
struct AppLogs {
    dns: DnsLog,
    http: HttpLog,
    mysql: MysqlLog,
    redis: RedisLog,
    dubbo: DubboLog,
    kafka: KafkaLog,
    mqtt: MqttLog,
}

impl AppLogs {
    pub fn new(config: &LogParserAccess) -> Self {
        Self {
            http: HttpLog::new(config, false, L7ProtoRawDataType::RawProtocol),
            dubbo: DubboLog::new(config),
            ..Default::default()
        }
    }
}

pub struct AppProtoLogsParser {
    input_queue: Arc<Receiver<Box<MetaAppProto>>>,
    output_queue: DebugSender<SendItem>,
    id: u32,
    running: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
    counter: Arc<SessionAggrCounter>,
    l7_log_dynamic_is_updated: Arc<AtomicBool>,
    config: LogParserAccess,

    log_rate: Arc<LeakyBucket>,
}

impl AppProtoLogsParser {
    pub fn new(
        input_queue: Receiver<Box<MetaAppProto>>,
        output_queue: DebugSender<SendItem>,
        id: u32,
        config: LogParserAccess,
        log_rate: Arc<LeakyBucket>,
    ) -> (Self, Arc<SessionAggrCounter>) {
        let counter: Arc<SessionAggrCounter> = Default::default();
        (
            Self {
                input_queue: Arc::new(input_queue),
                output_queue,
                id,
                running: Default::default(),
                thread: Mutex::new(None),
                counter: counter.clone(),
                l7_log_dynamic_is_updated: Arc::new(AtomicBool::new(false)),
                config,
                log_rate,
            },
            counter,
        )
    }

    pub fn l7_log_dynamic_config_updated(&self) {
        self.l7_log_dynamic_is_updated
            .store(true, Ordering::Relaxed);
    }

    fn update_l7_log_dynamic_config(
        l7_log_dynamic_is_updated: Arc<AtomicBool>,
        config: &LogParserAccess,
        app_logs: &mut AppLogs,
    ) {
        if l7_log_dynamic_is_updated.swap(false, Ordering::Relaxed) {
            app_logs.http.update_config(config);
            app_logs.dubbo.update_config(config);
        }
    }

    pub fn start(&self) {
        if self.running.swap(true, Ordering::Relaxed) {
            return;
        }

        let running = self.running.clone();
        let counter = self.counter.clone();
        let input_queue = self.input_queue.clone();
        let output_queue = self.output_queue.clone();

        let config = self.config.clone();
        let l7_log_dynamic_is_updated = self.l7_log_dynamic_is_updated.clone();
        let log_rate = self.log_rate.clone();

        let thread = thread::spawn(move || {
            let mut session_queue =
                SessionQueue::new(counter, output_queue, config.clone(), log_rate);
            let mut app_logs = AppLogs::new(&config);

            while running.load(Ordering::Relaxed) {
                match input_queue.recv_n(QUEUE_BATCH_SIZE, Some(RCV_TIMEOUT)) {
                    Ok(app_protos) => {
                        Self::update_l7_log_dynamic_config(
                            l7_log_dynamic_is_updated.clone(),
                            &config,
                            &mut app_logs,
                        );
                        for app_proto in app_protos {
                            let proto_logs = match Self::parse_log(*app_proto, &mut app_logs) {
                                Ok(a) => a,
                                Err(e) => {
                                    debug!("{}", e);
                                    continue;
                                }
                            };

                            for proto_log in proto_logs {
                                session_queue.aggregate_session_and_send(proto_log);
                            }
                        }
                    }
                    Err(Error::Timeout) => {
                        session_queue.flush_one_slot();
                        continue;
                    }
                    Err(Error::Terminated(..)) => break,
                };
            }
            session_queue.clear();
        });
        self.thread.lock().unwrap().replace(thread);
        info!("app protocol logs parser (id={}) started", self.id);
    }

    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return;
        }
        if let Some(thread) = self.thread.lock().unwrap().take() {
            let _ = thread.join();
        }
        info!("app protocol logs parser (id={}) stopped", self.id);
    }

    fn parse_log(
        mut app_proto: MetaAppProto,
        app_logs: &mut AppLogs,
    ) -> Result<Vec<AppProtoLogsData>> {
        // 应用流日志只存C2S方向,所以非C2S方向需要转换方向
        if app_proto.base_info.head.msg_type != LogMessageType::Request {
            let base_info = &mut app_proto.base_info;
            swap(&mut base_info.port_dst, &mut base_info.port_src);
            swap(&mut base_info.ip_src, &mut base_info.ip_dst);
            swap(&mut base_info.l3_epc_id_src, &mut base_info.l3_epc_id_dst);
        }
        let proto_log = match app_proto.base_info.head.proto {
            L7Protocol::Dns => {
                app_logs.dns.parse(
                    app_proto.raw_proto_payload.as_slice(),
                    app_proto.base_info.protocol,
                    app_proto.direction,
                    None,
                    None,
                )?;
                let special_info = app_logs.dns.info();
                let base_info = app_proto.base_info;
                vec![AppProtoLogsData::new(base_info, special_info.into_inner())]
            }
            L7Protocol::Http1 | L7Protocol::Http2 => {
                app_logs.http.parse(
                    app_proto.raw_proto_payload.as_slice(),
                    app_proto.base_info.protocol,
                    app_proto.direction,
                    None,
                    None,
                )?;
                let special_info = app_logs.http.info();
                let base_info = app_proto.base_info;

                vec![AppProtoLogsData::new(base_info, special_info.into_inner())]
            }
            L7Protocol::Dubbo => {
                app_logs.dubbo.parse(
                    app_proto.raw_proto_payload.as_slice(),
                    app_proto.base_info.protocol,
                    app_proto.direction,
                    None,
                    None,
                )?;
                let special_info = app_logs.dubbo.info();
                let base_info = app_proto.base_info;

                vec![AppProtoLogsData::new(base_info, special_info.into_inner())]
            }
            L7Protocol::Kafka => {
                app_logs.kafka.parse(
                    app_proto.raw_proto_payload.as_slice(),
                    app_proto.base_info.protocol,
                    app_proto.direction,
                    None,
                    None,
                )?;
                let special_info = app_logs.kafka.info();
                let base_info = app_proto.base_info;

                vec![AppProtoLogsData::new(base_info, special_info.into_inner())]
            }
            L7Protocol::Mqtt => {
                let heads = app_logs.mqtt.parse(
                    app_proto.raw_proto_payload.as_slice(),
                    app_proto.base_info.protocol,
                    app_proto.direction,
                    None,
                    None,
                )?;

                let special_info = app_logs.mqtt.info();
                let base_info = app_proto.base_info;

                let result = special_info
                    .into_iter()
                    .zip(heads.into_iter())
                    .map(|(v, head)| {
                        let mut mqtt_base_info = base_info.clone();
                        mqtt_base_info.head.msg_type = head.msg_type;
                        app_logs
                            .mqtt
                            .amend_mqtt_proto_log_and_generate_log_data(v, mqtt_base_info)
                    })
                    .collect::<Result<Vec<_>>>()?;

                result
            }
            L7Protocol::Redis => {
                app_logs.redis.parse(
                    app_proto.raw_proto_payload.as_slice(),
                    app_proto.base_info.protocol,
                    app_proto.direction,
                    None,
                    None,
                )?;
                let special_info = app_logs.redis.info();
                let base_info = app_proto.base_info;

                vec![AppProtoLogsData::new(base_info, special_info.into_inner())]
            }
            L7Protocol::Mysql => {
                app_logs.mysql.parse(
                    app_proto.raw_proto_payload.as_slice(),
                    app_proto.base_info.protocol,
                    app_proto.direction,
                    None,
                    None,
                )?;
                let special_info = app_logs.mysql.info();
                let base_info = app_proto.base_info;

                vec![AppProtoLogsData::new(base_info, special_info.into_inner())]
            }
            _ => unreachable!(),
        };

        Ok(proto_log)
    }
}
