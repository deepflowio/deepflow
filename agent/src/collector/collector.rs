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
    collections::HashMap,
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
    acc_flow::AccumulatedFlow,
    consts::{QUEUE_BATCH_SIZE, RCV_TIMEOUT},
    MetricsType, FLOW_METRICS_PEER_DST, FLOW_METRICS_PEER_SRC,
};
use crate::{
    common::{
        enums::{EthernetType, IpProtocol},
        flow::{get_direction, Flow, L7Protocol, SignalSource},
    },
    config::handler::CollectorAccess,
    metric::{
        document::{
            BoxedDocument, Code, Direction, Document, DocumentFlag, TagType, Tagger, TapSide,
        },
        meter::{FlowMeter, Meter, UsageMeter},
    },
    rpc::get_timestamp,
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
}

impl Default for StashKey {
    fn default() -> Self {
        Self {
            fast_id: 0,
            src_ip: Ipv4Addr::UNSPECIFIED.into(),
            dst_ip: Ipv4Addr::UNSPECIFIED.into(),
            src_gpid: 0,
            dst_gpid: 0,
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

    const ACL: Code = Code::ACL_GID
        .union(Code::TAG_TYPE)
        .union(Code::TAG_VALUE)
        .union(Code::VTAP_ID);

    fn new(tagger: &Tagger, src_ip: IpAddr, dst_ip: Option<IpAddr>) -> Self {
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
            Self::ACL => {
                fast_id |= tagger.acl_gid as u128
                    | (tagger.tag_type as u128) << 16
                    | (tagger.tag_value as u128) << 24;
            }
            _ => panic!("没有符合，需要更新tagger.code: {:?}", tagger.code),
        };

        Self {
            fast_id,
            src_ip,
            dst_ip: dst_ip.unwrap_or(Ipv4Addr::UNSPECIFIED.into()),
            src_gpid: tagger.gpid,
            dst_gpid: tagger.gpid_1,
        }
    }
}

struct Stash {
    sender: DebugSender<BoxedDocument>,
    counter: Arc<CollectorCounter>,
    start_time: Duration,
    slot_interval: u64,
    inner: HashMap<StashKey, Document>,
    global_thread_id: u8,
    doc_flag: DocumentFlag,
    context: Context,
}

impl Stash {
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
        Self {
            sender,
            counter,
            start_time,
            global_thread_id: ctx.id as u8 + 1,
            slot_interval,
            inner: HashMap::new(),
            doc_flag,
            context: ctx,
        }
    }

    fn collect(&mut self, acc_flow: Option<AccumulatedFlow>, mut time_in_second: u64) {
        if time_in_second < self.start_time.as_secs() {
            self.counter
                .drop_before_window
                .fetch_add(1, Ordering::Relaxed);
            return;
        }

        // 这里需要修正一下timeInSecond
        // 因为要使用doc time来推动时间窗口，所以对于doc中的timestamp不做修正
        // 对于queue中的tick（即accFlow == nil），时间修正为timeInSecond - delaySeconds
        // 对于分钟collector，少减去60s
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
        let delay = (timestamp.as_nanos() as i128 - 1000_000_000 * (time_in_second as i128)) as i64;
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
        let flow = &acc_flow.tagged_flow.flow;

        // PCAP和分发策略统计
        if self.context.metric_type == MetricsType::MINUTE
            && flow.signal_source == SignalSource::Packet
        {
            let id_map = &acc_flow.id_maps[0];
            for (&acl_gid, &ip_id) in id_map.iter() {
                let tagger = Tagger {
                    code: Code::ACL_GID | Code::TAG_TYPE | Code::TAG_VALUE | Code::VTAP_ID,
                    acl_gid,
                    tag_value: ip_id,
                    tag_type: TagType::TunnelIpId,
                    signal_source: flow.signal_source,
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
                let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None);
                self.add(key, tagger, Meter::Usage(usage_meter));
            }
            let id_map = &acc_flow.id_maps[1];
            for (&acl_gid, &ip_id) in id_map.iter() {
                let tagger = Tagger {
                    code: Code::ACL_GID | Code::TAG_TYPE | Code::TAG_VALUE | Code::VTAP_ID,
                    acl_gid,
                    tag_value: ip_id,
                    tag_type: TagType::TunnelIpId,
                    signal_source: flow.signal_source,
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
                let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None);
                self.add(key, tagger, Meter::Usage(usage_meter));
            }
        }

        let inactive_ip_enabled = self.context.config.load().inactive_ip_enabled;
        if !acc_flow.is_active_host0 && !acc_flow.is_active_host1 && !inactive_ip_enabled {
            self.counter.drop_inactive.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // 全景图统计
        let directions = get_direction(
            flow,
            self.context.config.load().trident_type,
            self.context.config.load().cloud_gateway_traffic,
        );
        self.fill_stats(&acc_flow, directions, inactive_ip_enabled);
    }

    // When generating doc data, use flow.flow_metrics_peers[x].nat_real_ip/port,
    // The tag is to use the real client before NAT and the real server after NAT
    fn fill_stats(
        &mut self,
        acc_flow: &AccumulatedFlow,
        directions: [Direction; 2],
        inactive_ip_enabled: bool,
    ) {
        for ep in 0..2 {
            // 不统计未知direction的数据
            if directions[ep] == Direction::None {
                continue;
            }
            let is_active_host = if ep == 0 {
                acc_flow.is_active_host0
            } else {
                acc_flow.is_active_host1
            };
            // 单端统计量：不统计非活跃的一端（Internet/不回包的内网IP）
            if inactive_ip_enabled || is_active_host {
                if ep == FLOW_METRICS_PEER_DST {
                    let reversed_meter = acc_flow.flow_meter.to_reversed();
                    self.fill_single_stats(
                        acc_flow,
                        reversed_meter,
                        ep,
                        directions[ep],
                        inactive_ip_enabled,
                    );
                } else {
                    self.fill_single_stats(
                        acc_flow,
                        acc_flow.flow_meter.clone(),
                        ep,
                        directions[ep],
                        inactive_ip_enabled,
                    );
                }
            }
            // 双端统计量：若某端direction已知，则以该direction（对应的tap-side）记录统计数据，最多记录两次
            self.fill_edge_stats(acc_flow, directions[ep], inactive_ip_enabled);
        }
        // 双端统计量：若双端direction都未知，则以direction=0（对应tap-side=rest）记录一次统计数据
        if directions[0] == Direction::None && directions[1] == Direction::None {
            self.fill_edge_stats(acc_flow, Direction::None, inactive_ip_enabled);
        }
    }

    // 非活跃服务并且非活跃端口指标数据关闭时，忽略服务端口
    // 非活跃的服务并且是SFlow，NetFlow的数据，忽略服务端口
    // 非TCP/UDP的流量时，忽略服务端
    fn ignore_server_port(flow: &Flow, inactive_server_port_enabled: bool) -> bool {
        if (!flow.is_active_service && !inactive_server_port_enabled)
            || (flow.flow_key.proto != IpProtocol::Tcp && flow.flow_key.proto != IpProtocol::Udp)
        {
            return true;
        }
        false
    }

    fn fill_single_stats(
        &mut self,
        acc_flow: &AccumulatedFlow,
        flow_meter: FlowMeter,
        ep: usize,
        direction: Direction,
        inactive_ip_enabled: bool,
    ) {
        let flow = &acc_flow.tagged_flow.flow;
        let flow_key = &flow.flow_key;
        let side = &flow.flow_metrics_peers[ep];
        let is_active_host = if ep == 0 {
            acc_flow.is_active_host0
        } else {
            acc_flow.is_active_host1
        };
        let has_mac = side.is_vip_interface || direction == Direction::LocalToLocal;
        let is_ipv6 = flow.eth_type == EthernetType::Ipv6;

        let ip = if !is_active_host && !inactive_ip_enabled {
            if is_ipv6 {
                Ipv6Addr::UNSPECIFIED.into()
            } else {
                Ipv4Addr::UNSPECIFIED.into()
            }
        } else if ep == FLOW_METRICS_PEER_SRC {
            if flow.flow_metrics_peers[0].l3_epc_id > 0 {
                flow.flow_metrics_peers[0].nat_real_ip
            } else {
                if is_ipv6 {
                    Ipv6Addr::UNSPECIFIED.into()
                } else {
                    Ipv4Addr::UNSPECIFIED.into()
                }
            }
        } else {
            if flow.flow_metrics_peers[1].l3_epc_id > 0 {
                flow.flow_metrics_peers[1].nat_real_ip
            } else {
                if is_ipv6 {
                    Ipv6Addr::UNSPECIFIED.into()
                } else {
                    Ipv4Addr::UNSPECIFIED.into()
                }
            }
        };
        let mut tagger = Tagger {
            global_thread_id: self.global_thread_id,
            vtap_id: self.context.config.load().vtap_id,
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
            // 资源位于客户端时，忽略服务端口
            server_port: if ep == 0
                || Self::ignore_server_port(
                    flow,
                    self.context.config.load().inactive_server_port_enabled,
                ) {
                0
            } else {
                flow.flow_metrics_peers[1].nat_real_port
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
            l7_protocol: acc_flow.l7_protocol,
            signal_source: flow.signal_source,
            otel_service: flow.otel_service.clone(),
            otel_instance: flow.otel_instance.clone(),
            endpoint: flow.endpoint.clone(),
            ..Default::default()
        };
        let l7_metrics_enabled = self.context.config.load().l7_metrics_enabled;
        let key = StashKey::new(&tagger, ip, None);
        // We collect the single-ended metrics data from Packet, XFlow, EBPF, Otel to the table (vtap_app_port).
        // In the case of signal_source grouping, the single_stats data is not duplicate.
        // Only data whose direction is c|s|local has flow_meter.
        if tagger.direction == Direction::ServerToClient
            || tagger.direction == Direction::ClientToServer
            || tagger.direction == Direction::LocalToLocal
        {
            self.add(key, tagger.clone(), Meter::Flow(flow_meter));
        }

        if tagger.l7_protocol != L7Protocol::Unknown && l7_metrics_enabled {
            // Only data whose direction is c|s|local|c-p|s-p|c-app|s-app|app has app_meter.
            // The data of XFlow itself will not be duplicated.
            if tagger.direction == Direction::ClientToServer
                || tagger.direction == Direction::ServerToClient
                || tagger.direction == Direction::LocalToLocal
                || tagger.signal_source != SignalSource::Packet
            {
                tagger.code |= Code::L7_PROTOCOL;
                let key = StashKey::new(&tagger, ip, None);
                self.add(key, tagger, Meter::App(acc_flow.app_meter.clone()));
            }
        }
    }

    fn fill_edge_stats(
        &mut self,
        acc_flow: &AccumulatedFlow,
        direction: Direction,
        inactive_ip_enabled: bool,
    ) {
        let flow = &acc_flow.tagged_flow.flow;
        let flow_key = &flow.flow_key;
        let src_ep = &flow.flow_metrics_peers[FLOW_METRICS_PEER_SRC];
        let dst_ep = &flow.flow_metrics_peers[FLOW_METRICS_PEER_DST];

        let is_ipv6 = flow.eth_type == EthernetType::Ipv6;

        let (src_ip, dst_ip) = {
            let (mut src_ip, mut dst_ip) = (acc_flow.nat_real_ip_0, acc_flow.nat_real_ip_1);
            if !inactive_ip_enabled {
                if !acc_flow.is_active_host0 {
                    src_ip = if is_ipv6 {
                        Ipv6Addr::UNSPECIFIED.into()
                    } else {
                        Ipv4Addr::UNSPECIFIED.into()
                    };
                }
                if !acc_flow.is_active_host1 {
                    dst_ip = if is_ipv6 {
                        Ipv6Addr::UNSPECIFIED.into()
                    } else {
                        Ipv4Addr::UNSPECIFIED.into()
                    };
                }
            } else {
                // After enabling the storage of inactive IP addresses,
                // the Internet IP address also needs to be saved as 0
                // =======================================
                // 开启存储非活跃IP后，Internet IP也需要存0
                if flow.flow_metrics_peers[0].l3_epc_id <= 0 {
                    src_ip = if is_ipv6 {
                        Ipv6Addr::UNSPECIFIED.into()
                    } else {
                        Ipv4Addr::UNSPECIFIED.into()
                    };
                }
                if flow.flow_metrics_peers[1].l3_epc_id <= 0 {
                    dst_ip = if is_ipv6 {
                        Ipv6Addr::UNSPECIFIED.into()
                    } else {
                        Ipv4Addr::UNSPECIFIED.into()
                    };
                }
            }

            (src_ip, dst_ip)
        };

        let (src_mac, dst_mac) = {
            let (mut src_mac, mut dst_mac) = (flow.flow_key.mac_src, flow.flow_key.mac_dst);
            // 仅VIPInterface设备发送MAC地址
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

        let mut tagger = Tagger {
            global_thread_id: self.global_thread_id,
            vtap_id: self.context.config.load().vtap_id,
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
            server_port: if Self::ignore_server_port(
                flow,
                self.context.config.load().inactive_server_port_enabled,
            ) {
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
            l7_protocol: acc_flow.l7_protocol,
            is_ipv6,
            signal_source: flow.signal_source,
            otel_service: flow.otel_service.clone(),
            otel_instance: flow.otel_instance.clone(),
            endpoint: flow.endpoint.clone(),
            ..Default::default()
        };

        // network metrics (vtap_flow_edge_port)
        // Packet data and XFlow data have L4 info
        if flow.signal_source == SignalSource::Packet || flow.signal_source == SignalSource::XFlow {
            let key = StashKey::new(&tagger, src_ip, Some(dst_ip));
            self.add(
                key,
                tagger.clone(),
                Meter::Flow(acc_flow.flow_meter.clone()),
            );
        }

        // application metrics (vtap_app_edge_port)
        if tagger.l7_protocol != L7Protocol::Unknown
            && self.context.config.load().l7_metrics_enabled
        {
            tagger.code |= Code::L7_PROTOCOL;
            let key = StashKey::new(&tagger, src_ip, Some(dst_ip));
            self.add(key, tagger, Meter::App(acc_flow.app_meter.clone()));
        }
    }

    fn add(&mut self, key: StashKey, tagger: Tagger, meter: Meter) {
        if let Some(doc) = self.inner.get_mut(&key) {
            doc.meter.sequential_merge(&meter);
            return;
        }
        let mut doc = Document::new(meter);
        doc.tagger = tagger;
        self.inner.insert(key, doc);
    }

    fn flush_stats(&mut self) {
        let mut batch = Vec::with_capacity(QUEUE_BATCH_SIZE);
        for (_, mut doc) in self.inner.drain() {
            if batch.len() >= QUEUE_BATCH_SIZE {
                if let Err(Error::Terminated(..)) = self.sender.send_all(&mut batch) {
                    warn!("{} queue terminated", self.context.name);
                    return;
                }
            }
            doc.timestamp = self.start_time.as_secs() as u32;
            doc.flags |= self.doc_flag;
            batch.push(BoxedDocument(Box::new(doc)))
        }
        if batch.len() > 0 {
            if let Err(Error::Terminated(..)) = self.sender.send_all(&mut batch) {
                warn!("{} queue terminated", self.context.name);
            }
        }
    }
}

fn get_l3_epc_id(l3_epc_id: i32, signal_source: SignalSource) -> i16 {
    if l3_epc_id < 0 && signal_source == SignalSource::OTel {
        0 // OTel data l3_epc_id always not from internet
    } else {
        l3_epc_id as i16
    }
}

#[derive(Clone)]
struct Context {
    id: u32,
    name: &'static str,
    delay_seconds: u64,
    metric_type: MetricsType,
    config: CollectorAccess,
    ntp_diff: Arc<AtomicI64>,
}

pub struct Collector {
    counter: Arc<CollectorCounter>,
    running: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
    receiver: Arc<Receiver<Box<AccumulatedFlow>>>,
    sender: DebugSender<BoxedDocument>,

    context: Context,
}

impl Collector {
    pub fn new(
        id: u32,
        receiver: Receiver<Box<AccumulatedFlow>>,
        sender: DebugSender<BoxedDocument>,
        metric_type: MetricsType,
        delay_seconds: u32,
        stats: &Arc<stats::Collector>,
        config: CollectorAccess,
        ntp_diff: Arc<AtomicI64>,
    ) -> Self {
        let delay_seconds = delay_seconds as u64;
        let name = match metric_type {
            MetricsType::MINUTE => {
                if delay_seconds < MINUTE || delay_seconds >= MINUTE * 2 {
                    panic!("delay_seconds必须在[60, 120)秒内");
                }
                "minute_collector"
            }
            _ => "second_collector",
        };

        let running = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(CollectorCounter {
            running: running.clone(),
            ..Default::default()
        });

        stats.register_countable(
            name,
            Countable::Ref(Arc::downgrade(&counter) as Weak<dyn RefCountable>),
            vec![StatsOption::Tag("index", id.to_string())],
        );

        Self {
            counter,
            running,
            thread: Mutex::new(None),
            receiver: Arc::new(receiver),
            sender,
            context: Context {
                id,
                name,
                delay_seconds,
                metric_type,
                config,
                ntp_diff,
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

        let thread = thread::Builder::new()
            .name("collector".to_owned())
            .spawn(move || {
                let mut stash = Stash::new(ctx, sender, counter);
                let mut batch = Vec::with_capacity(QUEUE_BATCH_SIZE);
                while running.load(Ordering::Relaxed) {
                    match receiver.recv_all(&mut batch, Some(RCV_TIMEOUT)) {
                        Ok(_) => {
                            for flow in batch.drain(..) {
                                let time_in_second = flow.tagged_flow.flow.flow_stat_time.as_secs();
                                stash.collect(Some(*flow), time_in_second);
                            }
                        }
                        Err(Error::Timeout) => stash.collect(
                            None,
                            get_timestamp(stash.context.ntp_diff.load(Ordering::Relaxed)).as_secs(),
                        ),
                        Err(Error::Terminated(..)) => break,
                    }
                }
                stash.flush_stats();
            })
            .unwrap();

        self.thread.lock().unwrap().replace(thread);
        info!("{} id=({}) started", self.context.name, self.context.id);
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
            protocol: IpProtocol::Tcp,
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
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None);
        assert_eq!(map.insert(key), true);
        tagger.server_port ^= 0x1;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None);
        assert_eq!(map.insert(key), true);
        tagger.server_port ^= 0x8000;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None);
        assert_eq!(map.insert(key), true);
        tagger.l3_epc_id ^= 0x1;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None);
        assert_eq!(map.insert(key), true);
        tagger.l3_epc_id = (tagger.l3_epc_id as u16 ^ 0x8000) as i16;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None);
        assert_eq!(map.insert(key), true);
        tagger.tap_type = TapType::Idc(255);
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None);
        assert_eq!(map.insert(key), true);
        tagger.direction = Direction::ServerToClient;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None);
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
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None);
        assert_eq!(map.insert(key), true);
        tagger.server_port ^= 0x1;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None);
        assert_eq!(map.insert(key), true);
        tagger.server_port ^= 0x8000;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None);
        assert_eq!(map.insert(key), true);
        tagger.protocol = IpProtocol::Icmpv6;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None);
        assert_eq!(map.insert(key), true);
        tagger.l3_epc_id ^= 0x1;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None);
        assert_eq!(map.insert(key), true);
        tagger.l3_epc_id = (tagger.l3_epc_id as u16 ^ 0x8000) as i16;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None);
        assert_eq!(map.insert(key), true);
        tagger.l3_epc_id1 ^= 0x1;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None);
        assert_eq!(map.insert(key), true);
        tagger.l3_epc_id1 = (tagger.l3_epc_id as u16 ^ 0x8000) as i16;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None);
        assert_eq!(map.insert(key), true);
        tagger.tap_type = TapType::Idc(200);
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None);
        assert_eq!(map.insert(key), true);
        tagger.direction = Direction::ClientToServer;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None);
        assert_eq!(map.insert(key), true);
        tagger.tap_port.0 ^= 1;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None);
        assert_eq!(map.insert(key), true);

        tagger.code = Code::ACL_GID | Code::TAG_TYPE | Code::TAG_VALUE | Code::VTAP_ID;
        tagger.tag_type = TagType::TunnelIpId;
        tagger.tag_value = 0xffff;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None);
        assert_eq!(map.insert(key), true);
        tagger.tag_value = 0x7fff;
        let key = StashKey::new(&tagger, Ipv4Addr::UNSPECIFIED.into(), None);
        assert_eq!(map.insert(key), true);
    }
}
