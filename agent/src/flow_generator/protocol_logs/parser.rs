/*
 * Copyright (c) 2024 Yunshan Networks
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
    fmt,
    sync::{
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    thread::JoinHandle,
    time::Duration,
};

use arc_swap::access::Access;
use log::{debug, info};
use serde::Serialize;

use super::{AppProtoHead, AppProtoLogsBaseInfo, BoxAppProtoLogsData};

use crate::{
    common::{
        ebpf::EbpfType,
        flow::{L7Protocol, PacketDirection, SignalSource},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        meta_packet::ProtocolData,
        MetaPacket, TaggedFlow, Timestamp,
    },
    config::handler::{LogParserAccess, LogParserConfig},
    flow_generator::{
        error::Result, protocol_logs::L7ResponseStatus, FLOW_METRICS_PEER_DST,
        FLOW_METRICS_PEER_SRC,
    },
    rpc::get_timestamp,
    utils::stats::{Counter, CounterType, CounterValue, RefCountable},
};
#[cfg(any(target_os = "linux", target_os = "android"))]
use public::utils::string::get_string_from_chars;
use public::{
    chrono_map::ChronoMap,
    l7_protocol::LogMessageType,
    queue::{self, DebugSender, Receiver},
    throttle::Throttle,
    utils::net::MacAddr,
};

const QUEUE_BATCH_SIZE: usize = 1024;
const RCV_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub enum AppProto {
    SocketClosed(u128),
    MetaAppProto(Box<MetaAppProto>),
}

#[derive(Clone, Debug, Serialize)]
pub struct MetaAppProto {
    #[serde(flatten)]
    pub base_info: AppProtoLogsBaseInfo,
    #[serde(skip)]
    pub direction: PacketDirection,
    pub direction_score: u8,
    #[serde(flatten)]
    pub l7_info: L7ProtocolInfo,
}

impl fmt::Display for MetaAppProto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} direction_score: {}\n",
            self.base_info, self.direction_score
        )?;
        write!(f, "\t{:?}", self.l7_info)
    }
}

impl MetaAppProto {
    pub fn new(
        flow: &TaggedFlow,
        meta_packet: &MetaPacket,
        l7_info: L7ProtocolInfo,
        head: AppProtoHead,
    ) -> Option<Self> {
        let mut base_info = AppProtoLogsBaseInfo {
            start_time: meta_packet.lookup_key.timestamp,
            end_time: meta_packet.lookup_key.timestamp,
            flow_id: flow.flow.flow_id,
            agent_id: flow.flow.flow_key.agent_id,
            tap_type: flow.flow.flow_key.tap_type,
            tap_port: flow.flow.flow_key.tap_port,
            signal_source: flow.flow.signal_source,
            tap_side: flow.flow.tap_side,
            head,
            protocol: meta_packet.lookup_key.proto,
            is_vip_interface_src: flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC]
                .is_vip_interface,
            is_vip_interface_dst: flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_DST]
                .is_vip_interface,
            gpid_0: flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC].gpid,
            gpid_1: flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_DST].gpid,
            mac_src: MacAddr::ZERO,
            mac_dst: MacAddr::ZERO,
            ip_src: flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC].nat_real_ip,
            ip_dst: flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_DST].nat_real_ip,
            port_src: flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC].nat_real_port,
            port_dst: flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_DST].nat_real_port,
            l3_epc_id_src: flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC].l3_epc_id,
            l3_epc_id_dst: flow.flow.flow_metrics_peers[FLOW_METRICS_PEER_DST].l3_epc_id,
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
            syscall_coroutine_0: 0,
            syscall_coroutine_1: 0,
            syscall_cap_seq_0: 0,
            syscall_cap_seq_1: 0,
            ebpf_type: meta_packet.ebpf_type,
            pod_id_0: 0,
            pod_id_1: 0,
            biz_type: l7_info.get_biz_type(),
        };

        #[cfg(any(target_os = "linux", target_os = "android"))]
        if meta_packet.signal_source == SignalSource::EBPF {
            let is_src = meta_packet.lookup_key.l2_end_0;
            let process_name = get_string_from_chars(&meta_packet.process_kname);
            match (is_src, meta_packet.lookup_key.direction) {
                (true, PacketDirection::ClientToServer)
                | (false, PacketDirection::ServerToClient) => {
                    base_info.process_id_0 = meta_packet.process_id;
                    base_info.process_kname_0 = process_name;
                    base_info.syscall_coroutine_0 = meta_packet.coroutine_id;
                    base_info.pod_id_0 = meta_packet.pod_id;
                }
                (false, PacketDirection::ClientToServer)
                | (true, PacketDirection::ServerToClient) => {
                    base_info.process_id_1 = meta_packet.process_id;
                    base_info.process_kname_1 = process_name;
                    base_info.syscall_coroutine_1 = meta_packet.coroutine_id;
                    base_info.pod_id_1 = meta_packet.pod_id;
                }
            }
        }

        if base_info.is_vip_interface_src {
            base_info.mac_src = flow.flow.flow_key.mac_src;
        }
        if base_info.is_vip_interface_dst {
            base_info.mac_dst = flow.flow.flow_key.mac_dst;
        }

        let seq = if let ProtocolData::TcpHeader(tcp_data) = &meta_packet.protocol_data {
            if meta_packet.ebpf_type != EbpfType::UnixSocket {
                tcp_data.seq + l7_info.tcp_seq_offset()
            } else {
                tcp_data.seq
            }
        } else {
            0
        };

        if meta_packet.lookup_key.direction == PacketDirection::ClientToServer {
            base_info.req_tcp_seq = seq;

            // ebpf info
            base_info.syscall_trace_id_request = meta_packet.syscall_trace_id;
            base_info.syscall_trace_id_thread_0 = meta_packet.thread_id;
            base_info.syscall_cap_seq_0 = meta_packet.cap_end_seq as u32;
        } else {
            base_info.resp_tcp_seq = seq;

            // ebpf info
            base_info.syscall_trace_id_response = meta_packet.syscall_trace_id;
            base_info.syscall_trace_id_thread_1 = meta_packet.thread_id;
            base_info.syscall_cap_seq_1 = meta_packet.cap_start_seq as u32;
        }

        if l7_info.is_reversed() {
            base_info.reverse()
        }

        Some(Self {
            base_info,
            direction: meta_packet.lookup_key.direction,
            direction_score: flow.flow.direction_score,
            l7_info,
        })
    }

    pub fn is_request(&self) -> bool {
        self.base_info.head.msg_type == LogMessageType::Request
    }

    pub fn is_response(&self) -> bool {
        self.base_info.head.msg_type == LogMessageType::Response
    }

    fn calc_cbpf_key(flow_id: u64, session_id: Option<u32>) -> u128 {
        // Packet key with session_id:
        //     | 64b flow_id | 32b 0 | 32b session_id |
        // Packet key without session_id:
        //     | 64b flow_id | 64b 0 |
        (flow_id as u128) << 64 | (session_id.unwrap_or_default() as u128)
    }

    fn calc_ebpf_key(
        flow_id: u64,
        mut proto: L7Protocol,
        session_id: Option<u32>,
        cap_seq: u32,
    ) -> u128 {
        // eBPF key with session_id:
        //     | 64b flow_id | 24b 0 | 8b proto | 32b session_id |
        // eBPF key without session_id:
        //     | 64b flow_id | 24b 0 | 8b proto | 32b cap_seq |
        let mut key = (flow_id as u128) << 64;

        if proto == L7Protocol::Grpc || proto == L7Protocol::Triple {
            proto = L7Protocol::Http2;
        }
        key |= (proto as u128) << 32;

        if let Some(session_id) = session_id {
            key |= session_id as u128;
        } else {
            key |= cap_seq as u128;
        }

        key
    }

    fn calc_key(&self) -> u128 {
        let mut cap_seq = self
            .base_info
            .syscall_cap_seq_0
            .max(self.base_info.syscall_cap_seq_1);
        if self.base_info.head.msg_type == LogMessageType::Request {
            cap_seq += 1;
        }
        Self::session_key(
            self.base_info.signal_source,
            self.base_info.flow_id,
            self.base_info.head.proto,
            self.l7_info.session_id(),
            cap_seq,
        )
    }

    pub fn session_key(
        signal_source: SignalSource,
        flow_id: u64,
        l7_protocol: L7Protocol,
        session_id: Option<u32>,
        cap_seq: u32,
    ) -> u128 {
        match signal_source {
            SignalSource::EBPF => Self::calc_ebpf_key(flow_id, l7_protocol, session_id, cap_seq),
            _ => Self::calc_cbpf_key(flow_id, session_id),
        }
    }

    pub fn session_merge(&mut self, log: &mut Self) -> Result<()> {
        // merge will fail under the following circumstances:
        //     when ebpf disorder, http1 can not match req/resp.
        let _ = self.l7_info.merge_log(&mut log.l7_info)?;
        self.base_info.merge(&mut log.base_info);
        Ok(())
    }

    // 是否需要进一步聚合
    // 目前仅http2 uprobe 需要聚合多个请求
    pub fn need_protocol_merge(&self) -> bool {
        self.l7_info.need_merge()
    }
}

#[derive(Default)]
pub struct SessionAggrCounter {
    send_before_window: AtomicU64,
    receive: AtomicU64,
    merge: AtomicU64,
    cached: AtomicU64, // It is used to record the number of logs that exist in session queue
    cached_request_resource: AtomicU64, // It is used to record the cache request-resource occupation space, the unit is B
    throttle_drop: AtomicU64,
    over_limit: AtomicU64, // It is used to record the number of logs that exceed the limit to the forced flush
}

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
                "cached-request-resource",
                CounterType::Counted,
                CounterValue::Unsigned(self.cached_request_resource.load(Ordering::Relaxed)),
            ),
            (
                "throttle-drop",
                CounterType::Counted,
                CounterValue::Unsigned(self.throttle_drop.swap(0, Ordering::Relaxed)),
            ),
            (
                "over-limit",
                CounterType::Counted,
                CounterValue::Unsigned(self.over_limit.swap(0, Ordering::Relaxed)),
            ),
        ]
    }
}

struct ThrottleSender {
    throttle: Throttle<BoxAppProtoLogsData>,
    counter: Arc<SessionAggrCounter>,
}

impl ThrottleSender {
    fn send(&mut self, data: Box<MetaAppProto>, override_resp_status: Option<L7ResponseStatus>) {
        if data.l7_info.skip_send() || data.l7_info.is_on_blacklist() {
            return;
        }
        if !self
            .throttle
            .send(BoxAppProtoLogsData::new(data, override_resp_status))
        {
            self.counter.throttle_drop.fetch_add(1, Ordering::Relaxed);
        }
    }
}

struct SessionQueue {
    config: LogParserAccess,

    window_start: Timestamp,
    max_timelines: usize,
    max_entries: usize,
    entries: ChronoMap<Timestamp, u128, Box<MetaAppProto>>,

    counter: Arc<SessionAggrCounter>,

    throttle_sender: ThrottleSender,
    l7_log_collect_nps_threshold: u64,
}

impl SessionQueue {
    fn new(
        counter: Arc<SessionAggrCounter>,
        output_queue: DebugSender<BoxAppProtoLogsData>,
        config: LogParserAccess,
    ) -> Self {
        let conf = config.load();
        let max_timelines = conf.l7_log_session_aggr_max_timeout.as_secs() as usize;
        let max_entries = conf.l7_log_session_aggr_max_entries;
        Self {
            config: config.clone(),

            window_start: Timestamp::ZERO,
            max_timelines,
            max_entries,
            entries: ChronoMap::with_capacity(max_entries, max_timelines),

            counter: counter.clone(),

            throttle_sender: ThrottleSender {
                throttle: Throttle::new(conf.l7_log_collect_nps_threshold, output_queue),
                counter: counter.clone(),
            },
            l7_log_collect_nps_threshold: conf.l7_log_collect_nps_threshold,
        }
    }

    fn aggregate_session_and_send(&mut self, config: &LogParserConfig, item: AppProto) {
        if let AppProto::SocketClosed(s) = item {
            if let Some(p) = self.entries.remove(&s) {
                self.counter.cached.fetch_sub(1, Ordering::Relaxed);
                self.counter.cached_request_resource.fetch_sub(
                    p.l7_info.get_request_resource_length() as u64,
                    Ordering::Relaxed,
                );
                self.throttle_sender.send(p, None);
            }
            self.counter.receive.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let mut item = match item {
            AppProto::MetaAppProto(m) => m,
            _ => unreachable!(),
        };

        if config.l7_log_ignore_tap_sides[item.base_info.tap_side as usize] {
            return;
        }
        self.counter.receive.fetch_add(1, Ordering::Relaxed);

        if !item.l7_info.needs_session_aggregation()
            || matches!(item.base_info.head.msg_type, LogMessageType::Session)
        {
            if item.base_info.start_time.is_zero() {
                item.base_info.start_time = item.base_info.end_time;
            }
            if item.base_info.end_time.is_zero() {
                item.base_info.end_time = item.base_info.start_time;
            }
            self.throttle_sender.send(item, None);
            return;
        }

        let timeout_time =
            item.base_info.start_time + config.get_l7_timeout(item.base_info.head.proto);
        if timeout_time <= self.window_start {
            self.counter
                .send_before_window
                .fetch_add(1, Ordering::Relaxed);
            debug!(
                "l7 log {:?} time {:?} timeout {:?} sent before aggregate start time {:?}",
                item.base_info.head.proto,
                item.base_info.start_time,
                timeout_time,
                self.window_start
            );
            self.throttle_sender.send(item, None);
            return;
        }

        let key = item.calc_key();
        if let Some(v) = self.entries.get_mut(&key) {
            if item.need_protocol_merge() {
                let _ = v.session_merge(&mut item);
                if v.l7_info.is_session_end() {
                    self.counter.cached.fetch_sub(1, Ordering::Relaxed);
                    self.counter.cached_request_resource.fetch_sub(
                        v.l7_info.get_request_resource_length() as u64,
                        Ordering::Relaxed,
                    );
                    self.throttle_sender
                        .send(self.entries.remove(&key).unwrap(), None);
                }
            } else {
                match item.base_info.head.msg_type {
                    // normal order, but if can not merge, send req and resp directly.
                    LogMessageType::Response
                        if v.is_request() && item.base_info.start_time > v.base_info.start_time =>
                    {
                        if let Err(_) = v.session_merge(&mut item) {
                            self.throttle_sender.send(item, None);
                        }
                        self.counter.cached.fetch_sub(1, Ordering::Relaxed);
                        self.counter.cached_request_resource.fetch_sub(
                            v.l7_info.get_request_resource_length() as u64,
                            Ordering::Relaxed,
                        );
                        self.counter.merge.fetch_add(1, Ordering::Relaxed);
                        self.throttle_sender
                            .send(self.entries.remove(&key).unwrap(), None);
                    }
                    // If the order is out of order and there is a response, it can be matched as a session, and the aggregated response is sent
                    LogMessageType::Request
                        if v.is_response()
                            && v.base_info.start_time > item.base_info.start_time =>
                    {
                        // if can not merge, send req and resp directly.
                        self.counter.cached_request_resource.fetch_sub(
                            v.l7_info.get_request_resource_length() as u64,
                            Ordering::Relaxed,
                        );
                        let mut v = self.entries.remove(&key).unwrap();
                        if let Err(_) = item.session_merge(&mut v) {
                            self.throttle_sender.send(v, None);
                        }
                        self.counter.cached.fetch_sub(1, Ordering::Relaxed);
                        self.counter.merge.fetch_add(1, Ordering::Relaxed);
                        self.throttle_sender.send(item, None);
                    }
                    // if entry and item cannot merge, send the early one and cache the other
                    _ => {
                        if v.base_info.start_time > item.base_info.start_time {
                            self.throttle_sender.send(item, None);
                        } else {
                            // swap out old item and send
                            self.counter.cached_request_resource.fetch_sub(
                                v.l7_info.get_request_resource_length() as u64,
                                Ordering::Relaxed,
                            );
                            self.throttle_sender
                                .send(self.entries.remove(&key).unwrap(), None);
                            self.counter.cached_request_resource.fetch_add(
                                item.l7_info.get_request_resource_length() as u64,
                                Ordering::Relaxed,
                            );
                            self.entries.insert(timeout_time, key, item);
                        }
                    }
                }
            }
            return;
        }

        if item.need_protocol_merge() {
            let (req_end, resp_end) = item.l7_info.is_req_resp_end();
            // http2 uprobe 有可能会重复收到resp_end, 直接忽略，防止堆积
            // http2 uprobe may receive resp_end repeatedly, ignore it directly to prevent accumulation
            if req_end || resp_end {
                return;
            }
        }

        if self.entries.len() >= self.max_entries {
            self.counter.over_limit.fetch_add(1, Ordering::Relaxed);
            if let Some(v) = self.entries.remove_oldest() {
                self.counter.cached_request_resource.fetch_sub(
                    v.l7_info.get_request_resource_length() as u64,
                    Ordering::Relaxed,
                );
                self.throttle_sender.send(v, None);
            }
            return;
        }

        self.counter.cached.fetch_add(1, Ordering::Relaxed);
        self.counter.cached_request_resource.fetch_add(
            item.l7_info.get_request_resource_length() as u64,
            Ordering::Relaxed,
        );
        self.entries.insert(timeout_time, key, item);
    }

    fn flush(&mut self) {
        for item in self.entries.drain(..) {
            self.throttle_sender.send(item, None);
        }
        self.throttle_sender.throttle.flush();
        self.counter.cached.store(0, Ordering::Relaxed);
        self.counter
            .cached_request_resource
            .store(0, Ordering::Relaxed);
        // shrink
        self.entries.shrink_to(self.max_entries, self.max_timelines);
    }

    fn flush_till(&mut self, time: Timestamp) {
        self.entries.forward_time(time, |item| {
            self.counter.cached.fetch_sub(1, Ordering::Relaxed);
            self.counter.cached_request_resource.fetch_sub(
                item.l7_info.get_request_resource_length() as u64,
                Ordering::Relaxed,
            );

            self.throttle_sender
                .send(item.clone(), Some(L7ResponseStatus::Timeout));
            None
        });
        self.throttle_sender.throttle.flush();
        // update timestamp
        self.window_start = time;
    }
}

pub struct SessionAggregator {
    input_queue: Arc<Receiver<AppProto>>,
    output_queue: DebugSender<BoxAppProtoLogsData>,
    id: u32,
    running: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
    counter: Arc<SessionAggrCounter>,
    config: LogParserAccess,
    ntp_diff: Arc<AtomicI64>,
}

impl SessionAggregator {
    pub fn new(
        input_queue: Receiver<AppProto>,
        output_queue: DebugSender<BoxAppProtoLogsData>,
        id: u32,
        config: LogParserAccess,
        ntp_diff: Arc<AtomicI64>,
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
                config,
                ntp_diff,
            },
            counter,
        )
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
        let ntp_diff = self.ntp_diff.clone();

        let thread = thread::Builder::new()
            .name("protocol-logs-parser".to_owned())
            .spawn(move || {
                let mut session_queue = SessionQueue::new(counter, output_queue, config.clone());
                let mut batch_buffer = Vec::with_capacity(QUEUE_BATCH_SIZE);
                // estimated lag from app proto start time to current time
                let mut lag_second = 0i64;

                while running.load(Ordering::Relaxed) {
                    let mut batch_time: Option<Timestamp> = None;
                    let result = input_queue.recv_all(&mut batch_buffer, Some(RCV_TIMEOUT));
                    let config = config.load();
                    match result {
                        Ok(_) => {
                            for app_proto in batch_buffer.drain(..) {
                                match app_proto {
                                    AppProto::MetaAppProto(ref m) => match batch_time {
                                        Some(time) if time >= m.base_info.start_time => (),
                                        _ => batch_time = Some(m.base_info.start_time),
                                    },
                                    _ => (),
                                }
                                session_queue.aggregate_session_and_send(&config, app_proto);
                            }
                        }
                        Err(queue::Error::Timeout) => (),
                        Err(queue::Error::Terminated(..)) => break,
                        Err(queue::Error::BatchTooLarge(_)) => unreachable!(),
                    };
                    let now: Timestamp = get_timestamp(ntp_diff.load(Ordering::Relaxed)).into();
                    let flush_timestamp = match batch_time {
                        Some(time) => {
                            lag_second = now.as_secs() as i64 - time.as_secs() as i64;
                            time
                        }
                        None => {
                            // no valid batch time from app proto, use current time with estimated lag
                            if lag_second > 0 {
                                now - Duration::from_secs(lag_second as u64)
                            } else {
                                now + Duration::from_secs((-lag_second) as u64)
                            }
                        }
                    };
                    session_queue.flush_till(flush_timestamp);
                    if config.l7_log_session_aggr_max_timeout.as_secs() as usize
                        != session_queue.max_timelines
                    {
                        session_queue.max_timelines =
                            config.l7_log_session_aggr_max_timeout.as_secs() as usize;
                    }
                    if config.l7_log_session_aggr_max_entries != session_queue.max_entries {
                        session_queue.max_entries = config.l7_log_session_aggr_max_entries;
                        session_queue.flush();
                    }
                    if config.l7_log_collect_nps_threshold
                        != session_queue.l7_log_collect_nps_threshold
                    {
                        info!(
                            "update l7_log_collect_nps_threshold from {} to {}",
                            session_queue.l7_log_collect_nps_threshold,
                            config.l7_log_collect_nps_threshold
                        );
                        session_queue.l7_log_collect_nps_threshold =
                            config.l7_log_collect_nps_threshold;
                        session_queue
                            .throttle_sender
                            .throttle
                            .set_rate(config.l7_log_collect_nps_threshold);
                    }
                }
                session_queue.flush();
            })
            .unwrap();
        self.thread.lock().unwrap().replace(thread);
        info!("app protocol logs parser (id={}) started", self.id);
    }

    pub fn notify_stop(&self) -> Option<JoinHandle<()>> {
        if !self.running.swap(false, Ordering::SeqCst) {
            return None;
        }
        info!("notified app protocol logs parser (id={}) to stop", self.id);
        self.thread.lock().unwrap().take()
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
}
