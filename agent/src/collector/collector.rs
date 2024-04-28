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
    collections::{hash_map::Entry, HashMap, VecDeque},
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
        Arc, Mutex, Weak,
    },
    thread,
    thread::JoinHandle,
    time::Duration,
};

use arc_swap::access::Access;
use log::{debug, info, warn};

use super::{
    consts::{QUEUE_BATCH_SIZE, RCV_TIMEOUT},
    types::{AppMeterWithFlow, FlowMeterWithFlow, MiniFlow},
    MetricsType, FLOW_METRICS_PEER_DST, FLOW_METRICS_PEER_SRC,
};
use crate::{
    common::{
        endpoint::EPC_INTERNET,
        enums::{EthernetType, IpProtocol},
        flow::{CloseType, L7Protocol, SignalSource},
    },
    config::handler::{CollectorAccess, CollectorConfig},
    metric::{
        document::{BoxedDocument, Code, Direction, Document, DocumentFlag, Tagger, TapSide},
        meter::{AppMeter, FlowMeter, Meter, UsageMeter},
    },
    rpc::get_timestamp,
    trident::RunningMode,
    utils::stats::{
        self, Countable, Counter, CounterType, CounterValue, RefCountable, StatsOption,
    },
};
use public::{
    queue::{DebugSender, Error, Receiver},
    utils::net::MacAddr,
};

const MINUTE: u64 = 60;

#[derive(Default)]
pub struct CollectorCounter {
    window_delay: AtomicI64,
    flow_delay: AtomicI64,
    out: AtomicU64,
    drop_before_window: AtomicU64,
    drop_inactive: AtomicU64,
    no_endpoint: AtomicU64,
    stash_len: AtomicU64,
    stash_capacity: AtomicU64,
    stash_shrinks: AtomicU64,
    running: Arc<AtomicBool>,
}

impl RefCountable for CollectorCounter {
    fn get_counters(&self) -> Vec<Counter> {
        vec![
            (
                "window-delay",
                CounterType::Counted,
                CounterValue::Signed(self.window_delay.swap(0, Ordering::Relaxed)),
            ),
            (
                "flow-delay",
                CounterType::Counted,
                CounterValue::Signed(self.flow_delay.swap(0, Ordering::Relaxed)),
            ),
            (
                "out",
                CounterType::Counted,
                CounterValue::Unsigned(self.out.swap(0, Ordering::Relaxed)),
            ),
            (
                "drop-before-window",
                CounterType::Counted,
                CounterValue::Unsigned(self.drop_before_window.swap(0, Ordering::Relaxed)),
            ),
            (
                "drop-inactive",
                CounterType::Counted,
                CounterValue::Unsigned(self.drop_inactive.swap(0, Ordering::Relaxed)),
            ),
            (
                "no-endpoint",
                CounterType::Counted,
                CounterValue::Unsigned(self.no_endpoint.swap(0, Ordering::Relaxed)),
            ),
            (
                "stash-len",
                CounterType::Counted,
                CounterValue::Unsigned(self.stash_len.load(Ordering::Relaxed)),
            ),
            (
                "stash-capacity",
                CounterType::Counted,
                CounterValue::Unsigned(self.stash_capacity.load(Ordering::Relaxed)),
            ),
            (
                "stash-shrinks",
                CounterType::Counted,
                CounterValue::Unsigned(self.stash_shrinks.swap(0, Ordering::Relaxed)),
            ),
        ]
    }
}

#[derive(Hash, PartialEq, Eq)]
struct StashKey {
    fast_id: u128,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_gpid: u32,
    dst_gpid: u32,
    endpoint_hash: u32,
    biz_type: u8,
}

impl Default for StashKey {
    fn default() -> Self {
        Self {
            fast_id: 0,
            src_ip: Ipv4Addr::UNSPECIFIED.into(),
            dst_ip: Ipv4Addr::UNSPECIFIED.into(),
            src_gpid: 0,
            dst_gpid: 0,
            endpoint_hash: 0,
            biz_type: 0,
        }
    }
}

impl StashKey {
    const SINGLE_IP: Code = Code::IP
        .union(Code::L3_EPC_ID)
        .union(Code::GPID)
        .union(Code::VTAP_ID)
        .union(Code::PROTOCOL)
        .union(Code::DIRECTION)
        .union(Code::TAP_TYPE);
    const SINGLE_IP_PORT: Code = Self::SINGLE_IP.union(Code::SERVER_PORT);
    const SINGLE_MAC_IP_PORT: Code = Self::SINGLE_IP.union(Code::MAC).union(Code::SERVER_PORT);

    const SINGLE_IP_PORT_APP: Code = Self::SINGLE_IP
        .union(Code::SERVER_PORT)
        .union(Code::L7_PROTOCOL);
    const SINGLE_MAC_IP_PORT_APP: Code = Self::SINGLE_IP
        .union(Code::SERVER_PORT)
        .union(Code::MAC)
        .union(Code::L7_PROTOCOL);

    const EDGE_IP: Code = Code::IP_PATH
        .union(Code::L3_EPC_PATH)
        .union(Code::GPID_PATH)
        .union(Code::VTAP_ID)
        .union(Code::PROTOCOL)
        .union(Code::DIRECTION)
        .union(Code::TAP_TYPE)
        .union(Code::TAP_PORT);
    const EDGE_IP_PORT: Code = Self::EDGE_IP.union(Code::SERVER_PORT);
    const EDGE_MAC_IP_PORT: Code = Self::EDGE_IP.union(Code::MAC_PATH).union(Code::SERVER_PORT);

    const EDGE_IP_PORT_APP: Code = Self::EDGE_IP
        .union(Code::SERVER_PORT)
        .union(Code::L7_PROTOCOL);
    const EDGE_MAC_IP_PORT_APP: Code = Self::EDGE_IP
        .union(Code::MAC_PATH)
        .union(Code::SERVER_PORT)
        .union(Code::L7_PROTOCOL);

    const ACL: Code = Code::ACL_GID.union(Code::TUNNEL_IP_ID).union(Code::VTAP_ID);

    fn new(tagger: &Tagger, src_ip: IpAddr, dst_ip: Option<IpAddr>, endpoint_hash: u32) -> Self {
        let mut fast_id = 0;
        match tagger.code {
            // single point
            // fast_id
            // 128          72        64    59       56        48           32          24         16        0
            // +-------------+---------+-----+--------+---------+------------+-----------+----------+---------+
            // |             | L7Proto | MAC | CodeID | TapType | ServerPort | Direction | Protocol | L3EpcId |
            // +-------------+---------+-----+--------+---------+------------+-----------+----------+---------+
            Self::SINGLE_MAC_IP_PORT_APP => {
                fast_id |= (tagger.l7_protocol as u128) << 64;
                fast_id |= 1 << 59;
                fast_id |= (tagger.l3_epc_id as u16 as u128)
                    | (u8::from(tagger.protocol) as u128) << 16
                    | (tagger.direction as u128) << 24
                    | (tagger.server_port as u128) << 32
                    | (u16::from(tagger.tap_type) as u128) << 48
                    | 3 << 56;
            }
            Self::SINGLE_MAC_IP_PORT => {
                fast_id |= 1 << 59;
                fast_id |= (tagger.l3_epc_id as u16 as u128)
                    | (u8::from(tagger.protocol) as u128) << 16
                    | (tagger.direction as u128) << 24
                    | (tagger.server_port as u128) << 32
                    | (u16::from(tagger.tap_type) as u128) << 48
                    | 2 << 56;
            }
            Self::SINGLE_IP_PORT => {
                fast_id |= (tagger.l3_epc_id as u16 as u128)
                    | (u8::from(tagger.protocol) as u128) << 16
                    | (tagger.direction as u128) << 24
                    | (tagger.server_port as u128) << 32
                    | (u16::from(tagger.tap_type) as u128) << 48
                    | 1 << 56;
            }
            Self::SINGLE_IP_PORT_APP => {
                fast_id |= (tagger.l3_epc_id as u16 as u128)
                    | (u8::from(tagger.protocol) as u128) << 16
                    | (tagger.direction as u128) << 24
                    | (tagger.server_port as u128) << 32
                    | (u16::from(tagger.tap_type) as u128) << 48
                    | 4 << 56;

                fast_id |= (tagger.l7_protocol as u128) << 64;
            }
            // edge data
            // fast_id
            //
            // 128    124        104          100        96          64          56           40         32         16        0
            // +------+----------+------------+----------+-----------+-----------+------------+----------+----------+---------+
            // | from | RESERVED | NAT SOURCE | TUN_TYPE | ip/id/mac | Direction | ServerPort | Protocol | L3EpcID1 | L3EpcId |
            // +------+----------+------------+----------+-----------+-----------+------------+----------+----------+---------+
            //          /
            //         /
            //        /
            // RESERVED
            // 20    19       16        8         0
            // ------------------------------------
            // | MAC | CodeID | L7Proto | TapType |
            // ------------------------------------
            Self::EDGE_MAC_IP_PORT_APP => {
                let tap_port_reserve = (tagger.l7_protocol as u32) << 8 | 3 << 16 | 1 << 19;
                fast_id |= (tagger.l3_epc_id as u16 as u128)
                    | (tagger.l3_epc_id1 as u16 as u128) << 16
                    | (u8::from(tagger.protocol) as u128) << 32
                    | (tagger.server_port as u128) << 40
                    | (tagger.direction as u128) << 56;
                fast_id |= (tagger
                    .tap_port
                    .set_reserved_bytes((u16::from(tagger.tap_type) as u32) | tap_port_reserve)
                    .0 as u128)
                    << 64;
            }
            Self::EDGE_MAC_IP_PORT => {
                let tap_port_reserve = 2 << 16 | 1 << 19;
                fast_id |= (tagger.l3_epc_id as u16 as u128)
                    | (tagger.l3_epc_id1 as u16 as u128) << 16
                    | (u8::from(tagger.protocol) as u128) << 32
                    | (tagger.server_port as u128) << 40
                    | (tagger.direction as u128) << 56;
                fast_id |= (tagger
                    .tap_port
                    .set_reserved_bytes((u16::from(tagger.tap_type) as u32) | tap_port_reserve)
                    .0 as u128)
                    << 64;
            }
            Self::EDGE_IP_PORT => {
                let tap_port_reserve = 1 << 16;
                fast_id |= (tagger.l3_epc_id as u16 as u128)
                    | (tagger.l3_epc_id1 as u16 as u128) << 16
                    | (u8::from(tagger.protocol) as u128) << 32
                    | (tagger.server_port as u128) << 40
                    | (tagger.direction as u128) << 56;
                fast_id |= (tagger
                    .tap_port
                    .set_reserved_bytes((u16::from(tagger.tap_type) as u32) | tap_port_reserve)
                    .0 as u128)
                    << 64;
            }
            Self::EDGE_IP_PORT_APP => {
                let tap_port_reserve = 4 << 16;
                fast_id |= (tagger.l3_epc_id as u16 as u128)
                    | (tagger.l3_epc_id1 as u16 as u128) << 16
                    | (u8::from(tagger.protocol) as u128) << 32
                    | (tagger.server_port as u128) << 40
                    | (tagger.direction as u128) << 56;
                fast_id |= (tagger
                    .tap_port
                    .set_reserved_bytes((u16::from(tagger.tap_type) as u32) | tap_port_reserve)
                    .0 as u128)
                    << 64;
            }
            Self::ACL => fast_id |= tagger.acl_gid as u128 | (tagger.server_port as u128) << 16,
            _ => panic!(
                "There is no matching code. You need to update the tagger.code: {:?}",
                tagger.code
            ),
        };

        Self {
            fast_id,
            src_ip,
            dst_ip: dst_ip.unwrap_or(Ipv4Addr::UNSPECIFIED.into()),
            src_gpid: tagger.gpid,
            dst_gpid: tagger.gpid_1,
            endpoint_hash,
            biz_type: tagger.biz_type,
        }
    }
}

struct Stash {
    sender: DebugSender<BoxedDocument>,
    closed_docs: Vec<BoxedDocument>,
    counter: Arc<CollectorCounter>,
    start_time: Duration,
    slot_interval: u64,
    inner: HashMap<StashKey, Document>,
    history_length: VecDeque<usize>,
    stash_init_capacity: usize,
    global_thread_id: u8,
    doc_flag: DocumentFlag,
    context: Context,
}

impl Stash {
    // record stash size in last N flushes to determine shrinking size
    const HISTORY_RECORD_COUNT: usize = 10;
    const MIN_STASH_CAPACITY: usize = 1024;

    fn new(
        ctx: Context,
        sender: DebugSender<BoxedDocument>,
        counter: Arc<CollectorCounter>,
    ) -> Self {
        let (slot_interval, doc_flag) = match ctx.metric_type {
            MetricsType::SECOND => (1, DocumentFlag::PER_SECOND_METRICS),
            _ => (60, DocumentFlag::NONE),
        };

        let start_time = Duration::from_secs(
            get_timestamp(ctx.ntp_diff.load(Ordering::Relaxed)).as_secs() / MINUTE * MINUTE
                - 2 * MINUTE,
        );
        let inner = HashMap::with_capacity(Self::MIN_STASH_CAPACITY);
        let stash_init_capacity = inner.capacity();
        Self {
            sender,
            closed_docs: Vec::with_capacity(QUEUE_BATCH_SIZE),
            counter,
            start_time,
            global_thread_id: ctx.id as u8 + 1,
            slot_interval,
            inner,
            history_length: [0; Self::HISTORY_RECORD_COUNT].into(),
            stash_init_capacity,
            doc_flag,
            context: ctx,
        }
    }

    fn collect_l4(
        &mut self,
        acc_flow: Option<FlowMeterWithFlow>,
        mut time_in_second: u64,
        config: &CollectorConfig,
    ) {
        if time_in_second < self.start_time.as_secs() {
            self.counter
                .drop_before_window
                .fetch_add(1, Ordering::Relaxed);
            return;
        }

        // time_in_second needs to be corrected here. because doc time is used to push the time window,
        // no correction is made to the timestamp in doc. for tick in queue (that is, accFlow == nil),
        // the time is modified to time_in_second - delay_seconds. for minute collector, minus 60s
        if acc_flow.is_none() && time_in_second >= self.context.delay_seconds {
            match self.context.metric_type {
                MetricsType::SECOND => time_in_second -= self.context.delay_seconds,
                _ => time_in_second -= self.context.delay_seconds - MINUTE,
            }
        }

        time_in_second = time_in_second / self.slot_interval * self.slot_interval;
        let timestamp = get_timestamp(self.context.ntp_diff.load(Ordering::Relaxed));

        let start_time = self.start_time.as_secs();
        if time_in_second > start_time {
            let delay = (timestamp.as_nanos() as i128 - self.start_time.as_nanos() as i128) as i64;
            let _ =
                self.counter
                    .window_delay
                    .fetch_update(Ordering::Acquire, Ordering::Relaxed, |x| {
                        if delay > x {
                            Some(delay)
                        } else {
                            None
                        }
                    });
            self.flush_stats();
            debug!("collector window moved interval={:?} is_tick={} sys_ts={:?} flow_ts={} window={:?}", self.slot_interval, false, timestamp, time_in_second, self.start_time);
            self.start_time = Duration::from_secs(time_in_second);
        }
        let delay = (timestamp.as_nanos() - Duration::from_secs(time_in_second).as_nanos()) as i64;
        let _ = self
            .counter
            .flow_delay
            .fetch_update(Ordering::Acquire, Ordering::Relaxed, |x| {
                if delay > x {
                    Some(delay)
                } else {
                    None
                }
            });
        let acc_flow = match acc_flow {
            Some(f) => f,
            None => return,
        };
        let flow = &acc_flow.flow;

        // PCAP and Distribution Policy Statistics
        if self.context.metric_type == MetricsType::MINUTE
            && flow.signal_source == SignalSource::Packet
        {
            let id_map = &acc_flow.id_maps[0];
            for (&acl_gid, &ip_id) in id_map.iter() {
                let tagger = Tagger {
                    code: StashKey::ACL,
                    acl_gid,
                    server_port: ip_id,
                    signal_source: flow.signal_source,
                    vtap_id: config.vtap_id,
                    ..Default::default()
                };
                let meter = &acc_flow.flow_meter;
                let usage_meter = UsageMeter {
                    packet_tx: meter.traffic.packet_tx,
                    byte_tx: meter.traffic.byte_tx,
                    l3_byte_tx: meter.traffic.l3_byte_tx,
                    l4_byte_tx: meter.traffic.l4_byte_tx,
                    ..Default::default()
                };
                let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None, 0);
                self.add(key, tagger, Meter::Usage(usage_meter), flow.close_type);
            }
            let id_map = &acc_flow.id_maps[1];
            for (&acl_gid, &ip_id) in id_map.iter() {
                let tagger = Tagger {
                    code: StashKey::ACL,
                    acl_gid,
                    server_port: ip_id,
                    signal_source: flow.signal_source,
                    vtap_id: config.vtap_id,
                    ..Default::default()
                };

                let meter = &acc_flow.flow_meter;
                let usage_meter = UsageMeter {
                    packet_rx: meter.traffic.packet_rx,
                    byte_rx: meter.traffic.byte_rx,
                    l3_byte_rx: meter.traffic.l3_byte_rx,
                    l4_byte_rx: meter.traffic.l4_byte_rx,
                    ..Default::default()
                };
                let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None, 0);
                self.add(key, tagger, Meter::Usage(usage_meter), flow.close_type);
            }
        }

        if !acc_flow.is_active_host0 && !acc_flow.is_active_host1 && !config.inactive_ip_enabled {
            self.counter.drop_inactive.fetch_add(1, Ordering::Relaxed);
            return;
        }

        self.fill_l4_stats(&acc_flow, &acc_flow.flow.directions, config);
    }

    fn fill_l4_stats(
        &mut self,
        acc_flow: &FlowMeterWithFlow,
        directions: &[Direction; 2],
        config: &CollectorConfig,
    ) {
        for ep in 0..2 {
            // Do not count the data of None direction
            if directions[ep] == Direction::None {
                continue;
            }
            let is_active_host = if ep == 0 {
                acc_flow.is_active_host0
            } else {
                acc_flow.is_active_host1
            };
            // single_stats: Do not count the inactive end (Internet/private network IP with no response packet)
            if config.inactive_ip_enabled || is_active_host {
                let flow_meter = if ep == FLOW_METRICS_PEER_DST {
                    acc_flow.flow_meter.to_reversed()
                } else {
                    acc_flow.flow_meter
                };
                let tagger = get_single_tagger(
                    self.global_thread_id,
                    &acc_flow.flow,
                    ep,
                    directions[ep],
                    is_active_host,
                    config,
                    None,
                    0,
                    acc_flow.l7_protocol,
                    self.context.agent_mode,
                );
                self.fill_single_l4_stats(tagger, flow_meter, acc_flow.flow.close_type);
            }
            let tagger = get_edge_tagger(
                self.global_thread_id,
                &acc_flow.flow,
                directions[ep],
                acc_flow.is_active_host0,
                acc_flow.is_active_host1,
                config,
                None,
                0,
                acc_flow.l7_protocol,
                self.context.agent_mode,
            );
            // edge_stats: If the direction of a certain end is known, the statistical data
            // will be recorded with the direction (corresponding tap-side), up to two times
            self.fill_edge_l4_stats(tagger, acc_flow.flow_meter, acc_flow.flow.close_type);
        }
        // edge_stats: If both ends of direction are None, record the
        // statistical data with direction=0 (corresponding tap-side=rest)
        if directions[0] == Direction::None && directions[1] == Direction::None {
            // if otel data's directions are unknown, set direction =  Direction::App
            let direction = if acc_flow.flow.signal_source == SignalSource::OTel {
                Direction::App
            } else {
                Direction::None
            };
            let tagger = get_edge_tagger(
                self.global_thread_id,
                &acc_flow.flow,
                direction,
                acc_flow.is_active_host0,
                acc_flow.is_active_host1,
                config,
                None,
                0,
                acc_flow.l7_protocol,
                self.context.agent_mode,
            );
            self.fill_edge_l4_stats(tagger, acc_flow.flow_meter, acc_flow.flow.close_type);
        }
    }

    fn fill_single_l4_stats(
        &mut self,
        tagger: Tagger,
        flow_meter: FlowMeter,
        close_type: CloseType,
    ) {
        // We collect the single-ended metrics data from Packet, XFlow, EBPF, Otel to the table (vtap_app_port).
        // In the case of signal_source grouping, the single_stats data is not duplicate.
        // Only data whose direction is c|s|local has flow_meter.
        if tagger.direction == Direction::ServerToClient
            || tagger.direction == Direction::ClientToServer
            || tagger.direction == Direction::LocalToLocal
        {
            let key = StashKey::new(&tagger, tagger.ip, None, 0);
            self.add(key, tagger, Meter::Flow(flow_meter), close_type);
        }
    }

    fn fill_edge_l4_stats(&mut self, tagger: Tagger, flow_meter: FlowMeter, close_type: CloseType) {
        // network metrics (vtap_flow_edge_port)
        // Packet data and XFlow data have L4 info
        if tagger.signal_source == SignalSource::Packet
            || tagger.signal_source == SignalSource::XFlow
        {
            let key = StashKey::new(&tagger, tagger.ip, Some(tagger.ip1), 0);
            self.add(key, tagger, Meter::Flow(flow_meter), close_type);
        }
    }

    fn collect_l7(
        &mut self,
        meter: Option<AppMeterWithFlow>,
        mut time_in_second: u64,
        config: &CollectorConfig,
    ) {
        if time_in_second < self.start_time.as_secs() {
            self.counter
                .drop_before_window
                .fetch_add(1, Ordering::Relaxed);
            return;
        }

        // if the flow is closed, fill and send the stats data as soon as possible, and do not push the time window
        if let Some(m) = meter.as_ref() {
            if m.flow.close_type != CloseType::Unknown
                && m.flow.close_type != CloseType::ForcedReport
            {
                if !m.is_active_host0 && !m.is_active_host1 && !config.inactive_ip_enabled {
                    self.counter.drop_inactive.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                self.fill_l7_stats(m, &m.flow.directions, &config);
                return;
            }
        }

        // time_in_second needs to be corrected here, because doc time is used to push the time window,
        // no correction is made to the timestamp in doc, for tick in queue (that is, meter == nil),
        // the time is modified to time_in_second - delay_seconds, for minute collector, minus 60s
        if meter.is_none() && time_in_second >= self.context.delay_seconds {
            match self.context.metric_type {
                MetricsType::SECOND => time_in_second -= self.context.delay_seconds,
                _ => time_in_second -= self.context.delay_seconds - MINUTE,
            }
        }

        time_in_second = time_in_second / self.slot_interval * self.slot_interval;
        let timestamp = get_timestamp(self.context.ntp_diff.load(Ordering::Relaxed));

        let start_time = self.start_time.as_secs();
        if time_in_second > start_time {
            let delay = (timestamp.as_nanos() as i128 - self.start_time.as_nanos() as i128) as i64;
            let _ =
                self.counter
                    .window_delay
                    .fetch_update(Ordering::Acquire, Ordering::Relaxed, |x| {
                        if delay > x {
                            Some(delay)
                        } else {
                            None
                        }
                    });
            self.flush_stats();
            debug!("l7 collector window moved interval={:?} is_tick={} sys_ts={:?} flow_ts={} window={:?}", self.slot_interval, false, timestamp, time_in_second, self.start_time);
            self.start_time = Duration::from_secs(time_in_second);
        }
        let delay = (timestamp.as_nanos() - Duration::from_secs(time_in_second).as_nanos()) as i64;
        let _ = self
            .counter
            .flow_delay
            .fetch_update(Ordering::Acquire, Ordering::Relaxed, |x| {
                if delay > x {
                    Some(delay)
                } else {
                    None
                }
            });
        let meter = match meter {
            Some(m) => m,
            None => return,
        };

        if !meter.is_active_host0 && !meter.is_active_host1 && !config.inactive_ip_enabled {
            self.counter.drop_inactive.fetch_add(1, Ordering::Relaxed);
            return;
        }

        self.fill_l7_stats(&meter, &meter.flow.directions, &config);
    }

    // When generating doc data, use flow.peers[x].nat_real_ip/port,
    // The tag is to use the real client before NAT and the real server after NAT
    fn fill_l7_stats(
        &mut self,
        meter: &AppMeterWithFlow,
        directions: &[Direction; 2],
        config: &CollectorConfig,
    ) {
        let flow = &meter.flow;
        for ep in 0..2 {
            // Do not count the data of None direction
            if directions[ep] == Direction::None {
                continue;
            }
            let is_active_host = if ep == 0 {
                meter.is_active_host0
            } else {
                meter.is_active_host1
            };
            // single_stats: Do not count the inactive end (Internet/private network IP with no response packet)
            if config.inactive_ip_enabled || is_active_host {
                let mut tagger = get_single_tagger(
                    self.global_thread_id,
                    &flow,
                    ep,
                    directions[ep],
                    is_active_host,
                    config,
                    meter.endpoint.clone(),
                    meter.biz_type,
                    meter.l7_protocol,
                    self.context.agent_mode,
                );
                tagger.code |= Code::L7_PROTOCOL;
                self.fill_single_l7_stats(
                    tagger,
                    meter.endpoint_hash,
                    meter.app_meter,
                    flow.close_type,
                );
            }
            let mut tagger = get_edge_tagger(
                self.global_thread_id,
                &flow,
                directions[ep],
                meter.is_active_host0,
                meter.is_active_host1,
                config,
                meter.endpoint.clone(),
                meter.biz_type,
                meter.l7_protocol,
                self.context.agent_mode,
            );
            tagger.code |= Code::L7_PROTOCOL;
            // edge_stats: If the direction of a certain end is known, the statistical data
            // will be recorded with the direction (corresponding tap-side), up to two times
            self.fill_edge_l7_stats(
                tagger,
                meter.endpoint_hash,
                meter.app_meter,
                flow.close_type,
            );
        }
        // edge_stats: If both ends of direction are None, record the
        // statistical data with direction=0 (corresponding tap-side=rest)
        if directions[0] == Direction::None && directions[1] == Direction::None {
            // if otel data's directions are unknown, set direction =  Direction::App
            let direction = if flow.signal_source == SignalSource::OTel {
                Direction::App
            } else {
                Direction::None
            };
            let mut tagger = get_edge_tagger(
                self.global_thread_id,
                &flow,
                direction,
                meter.is_active_host0,
                meter.is_active_host1,
                config,
                meter.endpoint.clone(),
                meter.biz_type,
                meter.l7_protocol,
                self.context.agent_mode,
            );
            tagger.code |= Code::L7_PROTOCOL;
            self.fill_edge_l7_stats(
                tagger,
                meter.endpoint_hash,
                meter.app_meter,
                flow.close_type,
            );
        }
    }

    fn fill_single_l7_stats(
        &mut self,
        tagger: Tagger,
        endpoint_hash: u32,
        app_meter: AppMeter,
        close_type: CloseType,
    ) {
        // The l7_protocol of otel data may not be available, so report all otel data metrics.
        if tagger.l7_protocol != L7Protocol::Unknown || tagger.signal_source == SignalSource::OTel {
            // Only data whose direction is c|s|local|c-p|s-p|c-app|s-app|app has app_meter.
            // The data of XFlow itself will not be duplicated.
            // The tagger.signal_source != SignalSource::Packet which represents these directions: c-p|s-p|c-app|s-app|app
            if tagger.direction == Direction::ClientToServer
                || tagger.direction == Direction::ServerToClient
                || tagger.direction == Direction::LocalToLocal
                || tagger.signal_source != SignalSource::Packet
            {
                let key = StashKey::new(&tagger, tagger.ip, None, endpoint_hash);
                self.add(key, tagger, Meter::App(app_meter), close_type);
            }
        }
    }

    fn fill_edge_l7_stats(
        &mut self,
        tagger: Tagger,
        endpoint_hash: u32,
        app_meter: AppMeter,
        close_type: CloseType,
    ) {
        // The l7_protocol of otel data may not be available, so report all otel data metrics.
        // application metrics (vtap_app_edge_port)
        if tagger.l7_protocol != L7Protocol::Unknown || tagger.signal_source == SignalSource::OTel {
            let key = StashKey::new(&tagger, tagger.ip, Some(tagger.ip1), endpoint_hash);
            self.add(key, tagger, Meter::App(app_meter), close_type);
        }
    }

    fn push_closed_doc(&mut self, closed_doc: BoxedDocument) {
        self.closed_docs.push(closed_doc);
        if self.closed_docs.len() >= QUEUE_BATCH_SIZE {
            if let Err(e) = self.sender.send_all(&mut self.closed_docs) {
                warn!("queue failed to send Document data, because {:?}", e);
                self.closed_docs.clear();
            }
        }
    }

    fn add(&mut self, key: StashKey, tagger: Tagger, meter: Meter, close_type: CloseType) {
        if close_type != CloseType::Unknown && close_type != CloseType::ForcedReport {
            match self.inner.entry(key) {
                Entry::Occupied(o) => {
                    let mut doc = o.remove();
                    doc.meter.sequential_merge(&meter);
                    self.push_closed_doc(BoxedDocument(Box::new(doc)));
                }
                Entry::Vacant(_) => {
                    let mut doc = Document::new(meter);
                    doc.tagger = tagger;
                    self.push_closed_doc(BoxedDocument(Box::new(doc)));
                }
            }
        } else {
            match self.inner.entry(key) {
                Entry::Occupied(mut o) => {
                    let doc = o.get_mut();
                    doc.meter.sequential_merge(&meter);
                }
                Entry::Vacant(o) => {
                    let mut doc = Document::new(meter);
                    doc.tagger = tagger;
                    o.insert(doc);
                }
            }
        }
    }

    fn flush_stats(&mut self) {
        self.history_length.rotate_right(1);
        self.history_length[0] = self.inner.len();

        let mut batch = Vec::with_capacity(QUEUE_BATCH_SIZE);
        for (_, mut doc) in self.inner.drain() {
            if batch.len() >= QUEUE_BATCH_SIZE {
                if let Err(e) = self.sender.send_all(&mut batch) {
                    warn!(
                        "{} queue failed to send data, because {:?}",
                        self.context.name, e
                    );
                    return;
                }
            }
            doc.timestamp = self.start_time.as_secs() as u32;
            doc.flags |= self.doc_flag;
            batch.push(BoxedDocument(Box::new(doc)))
        }
        if batch.len() > 0 {
            if let Err(e) = self.sender.send_all(&mut batch) {
                warn!(
                    "{} queue failed to send data, because {:?}",
                    self.context.name, e
                );
            }
        }

        let stash_cap = self.inner.capacity();
        if stash_cap > self.stash_init_capacity {
            let max_history = self.history_length.iter().fold(0, |acc, n| acc.max(*n));
            if stash_cap > 2 * max_history {
                // shrink stash if its capacity is larger than 2 times of the max stash length in the past HISTORY_RECORD_COUNT flushes
                self.counter.stash_shrinks.fetch_add(1, Ordering::Relaxed);
                self.inner
                    .shrink_to(self.stash_init_capacity.max(2 * max_history));
            }
        }
    }

    fn calc_stash_counters(&self) {
        self.counter
            .stash_len
            .store(self.history_length[0] as u64, Ordering::Relaxed);
        self.counter
            .stash_capacity
            .store(self.inner.capacity() as u64, Ordering::Relaxed);
    }
}

// server_port is ignored when is_active_service and inactive_server_port_enabled is turned off
// is_active_service and SFlow,NetFlow data, ignoring service port
// ignore the server for non-TCP/UDP traffic
fn ignore_server_port(flow: &MiniFlow, inactive_server_port_enabled: bool) -> bool {
    (!flow.is_active_service && !inactive_server_port_enabled)
        || (flow.flow_key.proto != IpProtocol::TCP && flow.flow_key.proto != IpProtocol::UDP)
}

fn get_single_tagger(
    global_thread_id: u8,
    flow: &MiniFlow,
    ep: usize,
    direction: Direction,
    is_active_host: bool,
    config: &CollectorConfig,
    endpoint: Option<String>,
    biz_type: u8,
    l7_protocol: L7Protocol,
    agent_mode: RunningMode,
) -> Tagger {
    let flow_key = &flow.flow_key;
    let side = &flow.peers[ep];
    let has_mac = side.is_vip_interface || direction == Direction::LocalToLocal;
    let is_ipv6 = flow.eth_type == EthernetType::IPV6;

    // In standalone mode, we don't relay on any extra information to rewrite ip
    let ip = match agent_mode {
        RunningMode::Standalone => {
            if ep == FLOW_METRICS_PEER_SRC {
                flow.peers[0].nat_real_ip
            } else {
                flow.peers[1].nat_real_ip
            }
        }
        RunningMode::Managed => {
            if !config.inactive_ip_enabled {
                if !is_active_host {
                    unspecified_ip(is_ipv6)
                } else {
                    side.nat_real_ip
                }
            } else if ep == FLOW_METRICS_PEER_SRC {
                if flow.peers[0].l3_epc_id != EPC_INTERNET
                    || flow.signal_source == SignalSource::OTel
                {
                    flow.peers[0].nat_real_ip
                } else {
                    unspecified_ip(is_ipv6)
                }
            } else {
                flow.peers[1].nat_real_ip
            }
        }
    };

    Tagger {
        global_thread_id,
        vtap_id: config.vtap_id,
        mac: if !has_mac {
            MacAddr::ZERO
        } else if ep == FLOW_METRICS_PEER_SRC {
            flow_key.mac_src
        } else {
            flow_key.mac_dst
        },
        ip,
        l3_epc_id: get_l3_epc_id(side.l3_epc_id, flow.signal_source),
        gpid: side.gpid,
        protocol: flow_key.proto,
        direction,
        tap_side: TapSide::from(direction),
        tap_port: flow_key.tap_port,
        tap_type: flow_key.tap_type,
        // If the resource is located on the client, the service port is ignored
        server_port: if ep == FLOW_METRICS_PEER_SRC
            || ignore_server_port(flow, config.inactive_server_port_enabled)
        {
            0
        } else {
            flow.peers[1].nat_real_port
        },
        is_ipv6,
        code: {
            let mut code = Code::IP
                | Code::L3_EPC_ID
                | Code::GPID
                | Code::VTAP_ID
                | Code::PROTOCOL
                | Code::SERVER_PORT
                | Code::DIRECTION
                | Code::TAP_TYPE;
            if has_mac {
                code |= Code::MAC;
            }

            code
        },
        l7_protocol,
        signal_source: flow.signal_source,
        otel_service: flow.otel_service.clone(),
        otel_instance: flow.otel_instance.clone(),
        endpoint,
        biz_type,
        pod_id: flow.pod_id,
        ..Default::default()
    }
}

fn get_edge_tagger(
    global_thread_id: u8,
    flow: &MiniFlow,
    direction: Direction,
    is_active_host0: bool,
    is_active_host1: bool,
    config: &CollectorConfig,
    endpoint: Option<String>,
    biz_type: u8,
    l7_protocol: L7Protocol,
    agent_mode: RunningMode,
) -> Tagger {
    let flow_key = &flow.flow_key;
    let src_ep = &flow.peers[FLOW_METRICS_PEER_SRC];
    let dst_ep = &flow.peers[FLOW_METRICS_PEER_DST];

    let is_ipv6 = flow.eth_type == EthernetType::IPV6;

    // In standalone mode, we don't relay on any extra information to rewrite src and dst ip
    let (src_ip, dst_ip) = match agent_mode {
        RunningMode::Standalone => (flow.peers[0].nat_real_ip, flow.peers[1].nat_real_ip),
        RunningMode::Managed => {
            let (mut src_ip, mut dst_ip) = (flow.peers[0].nat_real_ip, flow.peers[1].nat_real_ip);
            if !config.inactive_ip_enabled {
                if !is_active_host0 {
                    src_ip = unspecified_ip(is_ipv6);
                }
                if !is_active_host1 {
                    dst_ip = unspecified_ip(is_ipv6);
                }
            } else {
                // After enabling the storage of inactive IP addresses,
                // the Internet IP address also needs to be saved as 0,
                // except for otel data
                // =======================================
                // 开启存储非活跃IP后，Internet IP也需要存0, otel数据除外
                if flow.peers[0].l3_epc_id == EPC_INTERNET
                    && flow.signal_source != SignalSource::OTel
                {
                    src_ip = unspecified_ip(is_ipv6);
                }
            }

            (src_ip, dst_ip)
        }
    };

    let (src_mac, dst_mac) = {
        let (mut src_mac, mut dst_mac) = (flow.flow_key.mac_src, flow.flow_key.mac_dst);
        // Only is_vip_interface devices send MAC addresses
        if direction != Direction::LocalToLocal {
            if !src_ep.is_vip_interface {
                src_mac = MacAddr::ZERO;
            }
            if !dst_ep.is_vip_interface {
                dst_mac = MacAddr::ZERO;
            }
        }

        (src_mac, dst_mac)
    };

    Tagger {
        global_thread_id,
        vtap_id: config.vtap_id,
        mac: src_mac,
        mac1: dst_mac,
        ip: src_ip,
        ip1: dst_ip,
        l3_epc_id: get_l3_epc_id(src_ep.l3_epc_id, flow.signal_source),
        l3_epc_id1: get_l3_epc_id(dst_ep.l3_epc_id, flow.signal_source),
        gpid: src_ep.gpid,
        gpid_1: dst_ep.gpid,
        protocol: flow_key.proto,
        direction,
        tap_side: TapSide::from(direction),
        tap_port: flow_key.tap_port,
        tap_type: flow_key.tap_type,
        server_port: if ignore_server_port(flow, config.inactive_server_port_enabled) {
            0
        } else {
            dst_ep.nat_real_port
        },
        code: {
            let mut code = Code::IP_PATH
                | Code::L3_EPC_PATH
                | Code::GPID_PATH
                | Code::VTAP_ID
                | Code::PROTOCOL
                | Code::SERVER_PORT
                | Code::DIRECTION
                | Code::TAP_TYPE
                | Code::TAP_PORT;

            if src_mac != MacAddr::ZERO || dst_mac != MacAddr::ZERO {
                code |= Code::MAC_PATH;
            }
            code
        },
        l7_protocol,
        is_ipv6,
        signal_source: flow.signal_source,
        otel_service: flow.otel_service.clone(),
        otel_instance: flow.otel_instance.clone(),
        endpoint,
        pod_id: flow.pod_id,
        biz_type,
        ..Default::default()
    }
}

fn get_l3_epc_id(l3_epc_id: i32, signal_source: SignalSource) -> i16 {
    if l3_epc_id < 0 && signal_source == SignalSource::OTel {
        0 // OTel data l3_epc_id always not from internet
    } else {
        l3_epc_id as i16
    }
}

struct CollectorStats {
    id: u32,
    kind: &'static str,
    layer7: bool,
}

impl stats::Module for CollectorStats {
    fn name(&self) -> &'static str {
        "collector"
    }

    fn tags(&self) -> Vec<StatsOption> {
        vec![
            StatsOption::Tag("index", self.id.to_string()),
            if self.layer7 {
                StatsOption::Tag("kind", format!("l7_{}", self.kind))
            } else {
                StatsOption::Tag("kind", self.kind.to_owned())
            },
        ]
    }
}

#[derive(Clone)]
struct Context {
    id: u32,
    name: &'static str,
    delay_seconds: u64,
    metric_type: MetricsType,
    ntp_diff: Arc<AtomicI64>,
    agent_mode: RunningMode,
}

pub struct Collector {
    counter: Arc<CollectorCounter>,
    running: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
    receiver: Arc<Receiver<Box<FlowMeterWithFlow>>>,
    sender: DebugSender<BoxedDocument>,
    config: CollectorAccess,
    context: Context,
}

impl Collector {
    pub fn new(
        id: u32,
        receiver: Receiver<Box<FlowMeterWithFlow>>,
        sender: DebugSender<BoxedDocument>,
        metric_type: MetricsType,
        delay_seconds: u32,
        stats: &Arc<stats::Collector>,
        config: CollectorAccess,
        ntp_diff: Arc<AtomicI64>,
        agent_mode: RunningMode,
    ) -> Self {
        let delay_seconds = delay_seconds as u64;
        let (kind, name) = match metric_type {
            MetricsType::MINUTE => {
                if delay_seconds < MINUTE || delay_seconds >= MINUTE * 2 {
                    panic!("delay_seconds必须在[60, 120)秒内");
                }
                ("minute", "minute_collector")
            }
            _ => ("second", "second_collector"),
        };

        let running = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(CollectorCounter {
            running: running.clone(),
            ..Default::default()
        });

        stats.register_countable(
            &CollectorStats {
                id,
                kind,
                layer7: false,
            },
            Countable::Ref(Arc::downgrade(&counter) as Weak<dyn RefCountable>),
        );

        Self {
            counter,
            running,
            thread: Mutex::new(None),
            receiver: Arc::new(receiver),
            sender,
            config,
            context: Context {
                id,
                name,
                delay_seconds,
                metric_type,
                ntp_diff,
                agent_mode,
            },
        }
    }

    pub fn start(&self) {
        if self.running.swap(true, Ordering::Relaxed) {
            return;
        }

        let running = self.running.clone();
        let counter = self.counter.clone();
        let receiver = self.receiver.clone();
        let sender = self.sender.clone();
        let ctx = self.context.clone();
        let config = self.config.clone();
        let thread = thread::Builder::new()
            .name("collector".to_owned())
            .spawn(move || {
                let mut stash = Stash::new(ctx, sender, counter);
                let mut batch = Vec::with_capacity(QUEUE_BATCH_SIZE);
                while running.load(Ordering::Relaxed) {
                    let config = config.load();
                    match receiver.recv_all(&mut batch, Some(RCV_TIMEOUT)) {
                        Ok(_) => {
                            for flow in batch.drain(..) {
                                let time_in_second = flow.time_in_second.as_secs();
                                stash.collect_l4(Some(*flow), time_in_second, &config);
                            }
                            if let Err(e) = stash.sender.send_all(&mut stash.closed_docs) {
                                warn!("queue failed to send l4 Document data, because {:?}", e);
                                stash.closed_docs.clear();
                            }
                            stash.calc_stash_counters();
                        }
                        Err(Error::Timeout) => {
                            stash.collect_l4(
                                None,
                                get_timestamp(stash.context.ntp_diff.load(Ordering::Relaxed))
                                    .as_secs(),
                                &config,
                            );
                            if let Err(e) = stash.sender.send_all(&mut stash.closed_docs) {
                                warn!("queue failed to send l4 Document data, because {:?}", e);
                                stash.closed_docs.clear();
                            }
                        }
                        Err(Error::Terminated(..)) => break,
                        Err(Error::BatchTooLarge(_)) => unreachable!(),
                    }
                }
                stash.flush_stats();
            })
            .unwrap();

        self.thread.lock().unwrap().replace(thread);
        info!("{} id=({}) started", self.context.name, self.context.id);
    }

    pub fn notify_stop(&self) -> Option<JoinHandle<()>> {
        if !self.running.swap(false, Ordering::Relaxed) {
            return None;
        }
        info!(
            "{} id=({}) notified stop",
            self.context.name, self.context.id
        );
        self.thread.lock().unwrap().take()
    }

    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            return;
        }
        if let Some(t) = self.thread.lock().unwrap().take() {
            let _ = t.join();
        }
        info!("{} id=({}) stopped", self.context.name, self.context.id);
    }
}

pub struct L7Collector {
    counter: Arc<CollectorCounter>,
    running: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
    l7_receiver: Arc<Receiver<Box<AppMeterWithFlow>>>,
    sender: DebugSender<BoxedDocument>,
    config: CollectorAccess,
    context: Context,
}

impl L7Collector {
    pub fn new(
        id: u32,
        l7_receiver: Receiver<Box<AppMeterWithFlow>>,
        sender: DebugSender<BoxedDocument>,
        metric_type: MetricsType,
        delay_seconds: u32,
        stats: &Arc<stats::Collector>,
        config: CollectorAccess,
        ntp_diff: Arc<AtomicI64>,
        agent_mode: RunningMode,
    ) -> Self {
        let delay_seconds = delay_seconds as u64;
        let (kind, name) = match metric_type {
            MetricsType::MINUTE => {
                if delay_seconds < MINUTE || delay_seconds >= MINUTE * 2 {
                    panic!("delay_seconds必须在[60, 120)秒内");
                }
                ("minute", "minute_collector")
            }
            _ => ("second", "second_collector"),
        };

        let running = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(CollectorCounter {
            running: running.clone(),
            ..Default::default()
        });

        stats.register_countable(
            &CollectorStats {
                id,
                kind,
                layer7: true,
            },
            Countable::Ref(Arc::downgrade(&counter) as Weak<dyn RefCountable>),
        );

        Self {
            counter,
            running,
            thread: Mutex::new(None),
            l7_receiver: Arc::new(l7_receiver),
            sender,
            config,
            context: Context {
                id,
                name,
                delay_seconds,
                metric_type,
                ntp_diff,
                agent_mode,
            },
        }
    }

    pub fn start(&self) {
        if self.running.swap(true, Ordering::Relaxed) {
            return;
        }

        let running = self.running.clone();
        let counter = self.counter.clone();
        let l7_receiver = self.l7_receiver.clone();
        let sender = self.sender.clone();
        let ctx = self.context.clone();
        let config = self.config.clone();
        let thread = thread::Builder::new()
            .name("l7_collector".to_owned())
            .spawn(move || {
                let mut stash = Stash::new(ctx, sender, counter);
                let mut l7_batch = Vec::with_capacity(QUEUE_BATCH_SIZE);
                while running.load(Ordering::Relaxed) {
                    let config = config.load();
                    match l7_receiver.recv_all(&mut l7_batch, Some(RCV_TIMEOUT)) {
                        Ok(_) => {
                            for meter in l7_batch.drain(..) {
                                let ts = meter.time_in_second.as_secs();
                                stash.collect_l7(Some(*meter), ts, &config);
                            }
                            if let Err(e) = stash.sender.send_all(&mut stash.closed_docs) {
                                warn!("queue failed to send l7 Document data, because {:?}", e);
                                stash.closed_docs.clear();
                            }
                            stash.calc_stash_counters();
                        }
                        Err(Error::Timeout) => {
                            stash.collect_l7(
                                None,
                                get_timestamp(stash.context.ntp_diff.load(Ordering::Relaxed))
                                    .as_secs(),
                                &config,
                            );
                            if let Err(e) = stash.sender.send_all(&mut stash.closed_docs) {
                                warn!("queue failed to send l7 Document data, because {:?}", e);
                                stash.closed_docs.clear();
                            }
                        }
                        Err(Error::Terminated(..)) => break,
                        Err(Error::BatchTooLarge(_)) => unreachable!(),
                    }
                }
                stash.flush_stats();
            })
            .unwrap();

        self.thread.lock().unwrap().replace(thread);
        info!("{} id=({}) started", self.context.name, self.context.id);
    }

    pub fn notify_stop(&self) -> Option<JoinHandle<()>> {
        if !self.running.swap(false, Ordering::Relaxed) {
            return None;
        }
        info!(
            "{} id=({}) notified stop",
            self.context.name, self.context.id
        );
        self.thread.lock().unwrap().take()
    }

    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            return;
        }
        if let Some(t) = self.thread.lock().unwrap().take() {
            let _ = t.join();
        }
        info!("{} id=({}) stopped", self.context.name, self.context.id);
    }
}

#[inline(always)]
fn unspecified_ip(is_ipv6: bool) -> IpAddr {
    if is_ipv6 {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    }
}

#[cfg(test)]
mod tests {

    use std::collections::HashSet;

    use crate::common::enums::TapType;

    use super::*;

    //TODO TestIncorrectIPv6Key
    #[test]
    fn fast_id() {
        let (l3_epc_id, port) = (0xdeadu16, 0xbeef);
        let mut map = HashSet::new();
        let mut tagger = Tagger {
            l3_epc_id: l3_epc_id as i16,
            l3_epc_id1: l3_epc_id as i16,
            protocol: IpProtocol::TCP,
            server_port: port,
            direction: Direction::ClientToServer,
            code: Code::IP
                | Code::L3_EPC_ID
                | Code::GPID
                | Code::VTAP_ID
                | Code::PROTOCOL
                | Code::SERVER_PORT
                | Code::DIRECTION
                | Code::TAP_TYPE,
            ..Default::default()
        };
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None, 0);
        assert_eq!(map.insert(key), true);
        tagger.server_port ^= 0x1;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None, 0);
        assert_eq!(map.insert(key), true);
        tagger.server_port ^= 0x8000;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None, 0);
        assert_eq!(map.insert(key), true);
        tagger.l3_epc_id ^= 0x1;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None, 0);
        assert_eq!(map.insert(key), true);
        tagger.l3_epc_id = (tagger.l3_epc_id as u16 ^ 0x8000) as i16;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None, 0);
        assert_eq!(map.insert(key), true);
        tagger.tap_type = TapType::Idc(255);
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None, 0);
        assert_eq!(map.insert(key), true);
        tagger.direction = Direction::ServerToClient;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None, 0);
        assert_eq!(map.insert(key), true);

        tagger.code = Code::IP_PATH
            | Code::L3_EPC_PATH
            | Code::GPID_PATH
            | Code::VTAP_ID
            | Code::PROTOCOL
            | Code::SERVER_PORT
            | Code::DIRECTION
            | Code::TAP_TYPE
            | Code::TAP_PORT;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None, 0);
        assert_eq!(map.insert(key), true);
        tagger.server_port ^= 0x1;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None, 0);
        assert_eq!(map.insert(key), true);
        tagger.server_port ^= 0x8000;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None, 0);
        assert_eq!(map.insert(key), true);
        tagger.protocol = IpProtocol::ICMPV6;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None, 0);
        assert_eq!(map.insert(key), true);
        tagger.l3_epc_id ^= 0x1;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None, 0);
        assert_eq!(map.insert(key), true);
        tagger.l3_epc_id = (tagger.l3_epc_id as u16 ^ 0x8000) as i16;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None, 0);
        assert_eq!(map.insert(key), true);
        tagger.l3_epc_id1 ^= 0x1;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None, 0);
        assert_eq!(map.insert(key), true);
        tagger.l3_epc_id1 = (tagger.l3_epc_id as u16 ^ 0x8000) as i16;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None, 0);
        assert_eq!(map.insert(key), true);
        tagger.tap_type = TapType::Idc(200);
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None, 0);
        assert_eq!(map.insert(key), true);
        tagger.direction = Direction::ClientToServer;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None, 0);
        assert_eq!(map.insert(key), true);
        tagger.tap_port.0 ^= 1;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None, 0);
        assert_eq!(map.insert(key), true);

        tagger.code = Code::ACL_GID | Code::TUNNEL_IP_ID | Code::VTAP_ID;
        tagger.server_port = 0xffff;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None, 0);
        assert_eq!(map.insert(key), true);
        tagger.server_port = 0x7fff;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None, 0);
        assert_eq!(map.insert(key), true);
    }
}
