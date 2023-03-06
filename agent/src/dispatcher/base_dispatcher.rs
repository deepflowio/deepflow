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

use std::collections::{HashMap, HashSet};
#[cfg(target_os = "windows")]
use std::ffi::CString;
use std::mem;
use std::net::IpAddr;
use std::process;
use std::sync::{
    atomic::{AtomicBool, AtomicI64, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::Duration;

use dns_lookup::lookup_host;
use log::{error, info, warn};

use super::{
    error::{Error, Result},
    recv_engine::{self, bpf, RecvEngine},
    BpfOptions, Options, PacketCounter, Pipeline,
};

#[cfg(target_os = "windows")]
use windows_recv_engine::WinPacket;

use crate::config::handler::LogParserAccess;
#[cfg(target_os = "linux")]
use crate::platform::GenericPoller;
use crate::{
    common::{
        decapsulate::{TunnelInfo, TunnelType, TunnelTypeBitmap},
        endpoint::FeatureFlags,
        enums::{EthernetType, TapType},
        MetaPacket, TaggedFlow, TapTyper, DEFAULT_CONTROLLER_PORT, DEFAULT_INGESTER_PORT,
        ETH_HEADER_SIZE, FIELD_OFFSET_ETH_TYPE, VLAN_HEADER_SIZE, VLAN_ID_MASK,
    },
    config::{handler::FlowAccess, DispatcherConfig},
    exception::ExceptionHandler,
    flow_generator::MetaAppProto,
    handler::PacketHandlerBuilder,
    policy::PolicyGetter,
    rpc::get_timestamp,
    utils::{bytes::read_u16_be, stats::Collector},
};

use public::{
    netns::NsFile,
    packet::Packet,
    proto::trident::{Exception, IfMacSource, TapMode},
    queue::DebugSender,
    utils::net::{self, get_route_src_ip, Link, MacAddr},
    LeakyBucket,
};

pub(super) struct BaseDispatcher {
    pub(super) engine: RecvEngine,

    pub(super) id: usize,
    pub(super) src_interface_index: u32,
    pub(super) src_interface: String,
    pub(super) ctrl_mac: MacAddr,

    pub(super) options: Arc<Mutex<Options>>,
    pub(super) bpf_options: Arc<Mutex<BpfOptions>>,

    pub(super) leaky_bucket: Arc<LeakyBucket>,
    pub(super) handler_builder: Arc<Mutex<Vec<PacketHandlerBuilder>>>,
    pub(super) pipelines: Arc<Mutex<HashMap<u32, Arc<Mutex<Pipeline>>>>>,
    pub(super) tap_interfaces: Arc<Mutex<Vec<Link>>>,
    pub(super) flow_map_config: FlowAccess,
    pub(super) log_parse_config: LogParserAccess,

    pub(super) tunnel_type_bitmap: Arc<Mutex<TunnelTypeBitmap>>,
    pub(super) tunnel_info: TunnelInfo,

    pub(super) tap_type_handler: TapTypeHandler,

    pub(super) need_update_bpf: Arc<AtomicBool>,
    // 该表中的tap接口采集包长不截断
    pub(super) reset_whitelist: Arc<AtomicBool>,
    pub(super) tap_interface_whitelist: TapInterfaceWhitelist,

    pub(super) analyzer_dedup_disabled: bool,

    pub(super) flow_output_queue: DebugSender<Box<TaggedFlow>>,
    pub(super) log_output_queue: DebugSender<Box<MetaAppProto>>,

    pub(super) counter: Arc<PacketCounter>,
    pub(super) terminated: Arc<AtomicBool>,
    pub(super) stats: Arc<Collector>,
    #[cfg(target_os = "linux")]
    pub(super) platform_poller: Arc<GenericPoller>,

    pub(super) policy_getter: PolicyGetter,
    pub(super) exception_handler: ExceptionHandler,
    pub(super) ntp_diff: Arc<AtomicI64>,

    pub(super) npb_dedup_enabled: Arc<AtomicBool>,

    // Enterprise Edition Feature: packet-sequence
    pub(super) packet_sequence_output_queue:
        DebugSender<Box<packet_sequence_block::PacketSequenceBlock>>,

    pub(super) netns: NsFile,

    // dispatcher id for easy debugging
    pub log_id: String,
}

impl BaseDispatcher {
    pub(super) fn prepare_flow(
        meta_packet: &mut MetaPacket,
        tap_type: TapType,
        reset_ttl: bool,
        queue_hash: u8,
        npb_dedup_enabled: bool,
    ) {
        meta_packet
            .lookup_key
            .feature_flag
            .set(FeatureFlags::DEDUP, npb_dedup_enabled);
        meta_packet.lookup_key.tap_type = tap_type;
        meta_packet.reset_ttl = reset_ttl;
        meta_packet.queue_hash = queue_hash;
    }

    pub(super) fn listener(&self) -> BaseDispatcherListener {
        BaseDispatcherListener {
            id: self.id,
            src_interface: self.src_interface.clone(),
            src_interface_index: self.src_interface_index as usize,
            options: self.options.clone(),
            bpf_options: self.bpf_options.clone(),
            pipelines: self.pipelines.clone(),
            tap_interfaces: self.tap_interfaces.clone(),
            need_update_bpf: self.need_update_bpf.clone(),
            #[cfg(target_os = "linux")]
            platform_poller: self.platform_poller.clone(),
            capture_bpf: "".into(),
            proxy_controller_ip: "0.0.0.0".into(),
            proxy_controller_port: DEFAULT_CONTROLLER_PORT,
            analyzer_ip: "0.0.0.0".into(),
            analyzer_port: DEFAULT_INGESTER_PORT,
            tunnel_type_bitmap: self.tunnel_type_bitmap.clone(),
            handler_builders: self.handler_builder.clone(),
            netns: self.netns.clone(),
            npb_dedup_enabled: self.npb_dedup_enabled.clone(),
            log_id: self.log_id.clone(),
            reset_whitelist: self.reset_whitelist.clone(),
        }
    }

    pub fn terminate_handler(&mut self) {
        self.pipelines.lock().unwrap().clear();
    }

    pub(super) fn check_and_update_bpf(&mut self) {
        if !self.need_update_bpf.swap(false, Ordering::Relaxed) {
            return;
        }

        #[cfg(target_os = "linux")]
        let tap_interfaces = self.tap_interfaces.lock().unwrap();
        #[cfg(target_os = "linux")]
        if tap_interfaces.len() == 0 {
            return;
        }

        let bpf_options = self.bpf_options.lock().unwrap();
        #[cfg(target_os = "linux")]
        if let Err(e) = self.engine.set_bpf(bpf_options.get_bpf_instructions(
            &tap_interfaces,
            &self.tap_interface_whitelist,
            self.options.lock().unwrap().snap_len,
        )) {
            warn!("set_bpf failed: {}", e);
        }
        #[cfg(target_os = "windows")]
        if let Err(e) = self
            .engine
            .set_bpf(&CString::new(bpf_options.get_bpf_instructions()).unwrap())
        {
            warn!("set_bpf failed: {}", e);
        }
    }
}

#[cfg(target_os = "windows")]
impl BaseDispatcher {
    pub(super) fn init(&mut self) {
        if let Err(e) = self.engine.init() {
            error!(
                "dispatcher recv_engine init error: {:?}, deepflow-agent restart...",
                e
            );
            thread::sleep(Duration::from_secs(1));
            process::exit(1);
        }
    }

    pub(super) fn switch_recv_engine(&mut self, pcap_interfaces: Vec<Link>) -> Result<()> {
        let options = self.options.lock().unwrap();
        self.engine = if options.tap_mode == TapMode::Local {
            if pcap_interfaces.is_empty() {
                return Err(Error::WinPcap(
                    "windows pcap capture must give interface to capture packet".into(),
                ));
            }
            let src_ifaces = pcap_interfaces
                .iter()
                .map(|src_iface| (src_iface.device_name.as_str(), src_iface.if_index as isize))
                .collect();
            let win_packet =
                WinPacket::new(src_ifaces, options.win_packet_blocks, options.snap_len)
                    .map_err(|e| Error::WinPcap(e.to_string()))?;
            info!("WinPacket init");
            self.need_update_bpf.store(true, Ordering::Relaxed);
            RecvEngine::WinPcap(Some(win_packet))
        } else {
            todo!()
        };

        Ok(())
    }

    pub(super) fn recv(
        engine: &mut RecvEngine,
        leaky_bucket: &LeakyBucket,
        exception_handler: &ExceptionHandler,
        prev_timestamp: &mut Duration,
        counter: &PacketCounter,
        ntp_diff: &AtomicI64,
    ) -> Option<(Packet, Duration)> {
        let packet = engine.recv();
        if packet.is_err() {
            if let recv_engine::Error::Timeout = packet.unwrap_err() {
                return None;
            }
            counter.err.fetch_add(1, Ordering::Relaxed);
            // Sleep to avoid wasting cpu during consequential errors
            thread::sleep(Duration::from_millis(1));
            return None;
        }
        let packet = packet.unwrap();
        // Receiving incomplete eth header under some environments, unlikely to happen
        if packet.data.len() < ETH_HEADER_SIZE + VLAN_HEADER_SIZE {
            counter.invalid_packets.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let mut timestamp = packet.timestamp;
        let time_diff = ntp_diff.load(Ordering::Relaxed);
        if time_diff >= 0 {
            timestamp += Duration::from_nanos(time_diff as u64);
        } else {
            timestamp -= Duration::from_nanos(-time_diff as u64);
        }
        if timestamp > *prev_timestamp {
            if timestamp - *prev_timestamp > Duration::from_secs(60) {
                // Correct invalid timestamp under some environments. Root cause unclear.
                // A large timestamp will lead to discarding of following packets, correct
                // this by setting it to present time
                let now = get_timestamp(time_diff);
                if timestamp > now && timestamp - now > Duration::from_secs(60) {
                    timestamp = now;
                }
            }
            *prev_timestamp = timestamp;
        }
        while !leaky_bucket.acquire(1) {
            counter.get_token_failed.fetch_add(1, Ordering::Relaxed);
            exception_handler.set(Exception::RxPpsThresholdExceeded);
            thread::sleep(Duration::from_millis(1));
        }

        counter.rx_all.fetch_add(1, Ordering::Relaxed);
        counter
            .rx_all_bytes
            .fetch_add(packet.data.len() as u64, Ordering::Relaxed);

        Some((packet, timestamp))
    }

    pub(super) fn decapsulate(
        packet: &mut [u8],
        tap_type_handler: &TapTypeHandler,
        tunnel_info: &mut TunnelInfo,
        bitmap: &TunnelTypeBitmap,
    ) -> Result<(usize, TapType)> {
        if packet.len() < ETH_HEADER_SIZE {
            return Err(Error::PacketInvalid(
                "packet.len() < ETH_HEADER_SIZE".to_string(),
            ));
        }

        let (tap_type, eth_type, l2_len) = tap_type_handler.get_l2_info(packet)?;
        let offset = match eth_type {
            // 最外层隧道封装，可能是ERSPAN或VXLAN
            EthernetType::Ipv4 => tunnel_info.decapsulate(packet, l2_len, bitmap),
            EthernetType::Ipv6 => tunnel_info.decapsulate_v6(packet, l2_len, bitmap),
            _ => 0,
        };
        if offset == 0 {
            Ok((0, tap_type))
        } else {
            Ok((l2_len + offset, tap_type))
        }
    }

    pub(super) fn decap_tunnel_with_erspan(
        packet: &mut [u8],
        tap_type_handler: &TapTypeHandler,
        tunnel_info: &mut TunnelInfo,
        bitmap: &TunnelTypeBitmap,
    ) -> Result<(usize, TapType)> {
        let mut decap_len = 0;
        let mut tap_type = TapType::Any;
        // 仅解析两层隧道
        for i in 0..2 {
            let (offset, t) = Self::decapsulate(
                &mut packet[decap_len..],
                tap_type_handler,
                tunnel_info,
                bitmap,
            )?;
            if i == 0 {
                tap_type = t;
            }
            if tunnel_info.tunnel_type == TunnelType::None {
                break;
            }
            if tunnel_info.tunnel_type == TunnelType::ErspanOrTeb {
                // 包括ERSPAN或TEB隧道前的所有隧道信息不保留，例如：
                // vxlan-erspan：隧道信息为空
                // erspan-vxlan；隧道信息为vxlan，隧道层数为1
                // erspan-vxlan-erspan；隧道信息为空
                *tunnel_info = Default::default();
            }
            decap_len += offset;
        }
        Ok((decap_len, tap_type))
    }

    pub(super) fn decap_tunnel(
        packet: &mut [u8],
        tap_type_handler: &TapTypeHandler,
        tunnel_info: &mut TunnelInfo,
        bitmap: TunnelTypeBitmap,
    ) -> Result<(usize, TapType)> {
        *tunnel_info = Default::default();
        Self::decap_tunnel_with_erspan(packet, tap_type_handler, tunnel_info, &bitmap)
    }
}

#[cfg(target_os = "linux")]
impl BaseDispatcher {
    #[cfg(not(target_arch = "s390x"))]
    fn is_engine_dpdk(&self) -> bool {
        match &self.engine {
            RecvEngine::Dpdk(..) => true,
            _ => false,
        }
    }

    #[cfg(target_arch = "s390x")]
    fn is_engine_dpdk(&self) -> bool {
        false
    }

    pub(super) fn init(&mut self) {
        match self.engine.init() {
            Ok(_) => {
                if &self.src_interface != "" {
                    if let Ok(link) = net::link_by_name(&self.src_interface) {
                        self.src_interface_index = link.if_index;
                    }
                }
            }
            Err(e) => {
                error!(
                    "dispatcher recv_engine init error: {:?}, deepflow-agent restart...",
                    e
                );
                thread::sleep(Duration::from_secs(1));
                process::exit(1);
            }
        }
    }

    pub(super) fn recv<'a>(
        engine: &'a mut RecvEngine,
        leaky_bucket: &LeakyBucket,
        exception_handler: &ExceptionHandler,
        prev_timestamp: &mut Duration,
        counter: &PacketCounter,
        ntp_diff: &AtomicI64,
    ) -> Option<(Packet<'a>, Duration)> {
        let packet = engine.recv();
        if packet.is_err() {
            if let recv_engine::Error::Timeout = packet.unwrap_err() {
                return None;
            }
            counter.err.fetch_add(1, Ordering::Relaxed);
            // Sleep to avoid wasting cpu during consequential errors
            thread::sleep(Duration::from_millis(1));
            return None;
        }
        let packet = packet.unwrap();
        // Receiving incomplete eth header under some environments, unlikely to happen
        if packet.data.len() < ETH_HEADER_SIZE + VLAN_HEADER_SIZE {
            counter.invalid_packets.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let mut timestamp = packet.timestamp;
        let time_diff = ntp_diff.load(Ordering::Relaxed);
        if time_diff >= 0 {
            timestamp += Duration::from_nanos(time_diff as u64);
        } else {
            timestamp -= Duration::from_nanos(-time_diff as u64);
        }
        if timestamp > *prev_timestamp {
            if timestamp - *prev_timestamp > Duration::from_secs(60) {
                // Correct invalid timestamp under some environments. Root cause unclear.
                // A large timestamp will lead to discarding of following packets, correct
                // this by setting it to present time
                let now = get_timestamp(time_diff);
                if timestamp > now && timestamp - now > Duration::from_secs(60) {
                    timestamp = now;
                }
            }
            *prev_timestamp = timestamp;
        }
        while !leaky_bucket.acquire(1) {
            counter.get_token_failed.fetch_add(1, Ordering::Relaxed);
            exception_handler.set(Exception::RxPpsThresholdExceeded);
            thread::sleep(Duration::from_millis(1));
        }

        counter.rx_all.fetch_add(1, Ordering::Relaxed);
        counter
            .rx_all_bytes
            .fetch_add(packet.data.len() as u64, Ordering::Relaxed);

        Some((packet, timestamp))
    }

    pub(super) fn decapsulate(
        packet: &mut [u8],
        tap_type_handler: &TapTypeHandler,
        tunnel_info: &mut TunnelInfo,
        bitmap: &TunnelTypeBitmap,
    ) -> Result<(usize, TapType)> {
        if packet.len() < ETH_HEADER_SIZE {
            return Err(Error::PacketInvalid(
                "packet.len() < ETH_HEADER_SIZE".to_string(),
            ));
        }

        let (tap_type, eth_type, l2_len) = tap_type_handler.get_l2_info(packet)?;
        let offset = match eth_type {
            // 最外层隧道封装，可能是ERSPAN或VXLAN
            EthernetType::Ipv4 => tunnel_info.decapsulate(packet, l2_len, bitmap),
            EthernetType::Ipv6 => tunnel_info.decapsulate_v6(packet, l2_len, bitmap),
            _ => 0,
        };
        if offset == 0 {
            Ok((0, tap_type))
        } else {
            Ok((l2_len + offset, tap_type))
        }
    }

    pub(super) fn decap_tunnel_with_erspan(
        packet: &mut [u8],
        tap_type_handler: &TapTypeHandler,
        tunnel_info: &mut TunnelInfo,
        bitmap: &TunnelTypeBitmap,
    ) -> Result<(usize, TapType)> {
        let mut decap_len = 0;
        let mut tap_type = TapType::Any;
        // 仅解析两层隧道
        for i in 0..2 {
            let (offset, t) = Self::decapsulate(
                &mut packet[decap_len..],
                tap_type_handler,
                tunnel_info,
                bitmap,
            )?;
            if i == 0 {
                tap_type = t;
            }
            if tunnel_info.tunnel_type == TunnelType::None {
                break;
            }
            if tunnel_info.tunnel_type == TunnelType::ErspanOrTeb {
                // 包括ERSPAN或TEB隧道前的所有隧道信息不保留，例如：
                // vxlan-erspan：隧道信息为空
                // erspan-vxlan；隧道信息为vxlan，隧道层数为1
                // erspan-vxlan-erspan；隧道信息为空
                *tunnel_info = Default::default();
            }
            decap_len += offset;
        }
        Ok((decap_len, tap_type))
    }

    pub(super) fn decap_tunnel(
        packet: &mut [u8],
        tap_type_handler: &TapTypeHandler,
        tunnel_info: &mut TunnelInfo,
        bitmap: TunnelTypeBitmap,
    ) -> Result<(usize, TapType)> {
        *tunnel_info = Default::default();
        Self::decap_tunnel_with_erspan(packet, tap_type_handler, tunnel_info, &bitmap)
    }
}

#[derive(Clone, Default)]
pub(super) struct TapTypeHandler {
    pub(super) tap_typer: Arc<TapTyper>,
    pub(super) default_tap_type: TapType,
    pub(super) mirror_traffic_pcp: u16,
    pub(super) tap_mode: TapMode,
}

impl TapTypeHandler {
    // returns tap_type, ethernet_type and l2_len
    pub(super) fn get_l2_info(&self, packet: &[u8]) -> Result<(TapType, EthernetType, usize)> {
        let mut eth_type = read_u16_be(&packet[FIELD_OFFSET_ETH_TYPE..]);
        let mut tap_type = self.default_tap_type;
        let mut l2_len = ETH_HEADER_SIZE;
        if eth_type == EthernetType::Dot1Q && packet.len() >= ETH_HEADER_SIZE + VLAN_HEADER_SIZE {
            let vlan_tag = read_u16_be(&packet[ETH_HEADER_SIZE..]);
            eth_type = read_u16_be(&packet[FIELD_OFFSET_ETH_TYPE + VLAN_HEADER_SIZE..]);
            // tap_type从qinq外层的vlan获取
            let pcp = (vlan_tag >> 13) & 0x7;
            if pcp == self.mirror_traffic_pcp && self.tap_mode == TapMode::Analyzer {
                let vid = vlan_tag & VLAN_ID_MASK;
                if let Some(t) = self.tap_typer.get_tap_type_by_vlan(vid) {
                    if t != TapType::Unknown {
                        tap_type = t;
                    }
                }
            }
            l2_len += VLAN_HEADER_SIZE;
            if eth_type == EthernetType::Dot1Q
                && packet.len() >= ETH_HEADER_SIZE + 2 * VLAN_HEADER_SIZE
            {
                eth_type = read_u16_be(&packet[FIELD_OFFSET_ETH_TYPE + 2 * VLAN_HEADER_SIZE..]);
                l2_len += VLAN_HEADER_SIZE;
            }
        } else if self.tap_mode == TapMode::Analyzer {
            if let Some(t) = self.tap_typer.get_tap_type_by_vlan(0) {
                if t != TapType::Unknown {
                    tap_type = t;
                }
            }
        }
        Ok((tap_type, EthernetType::from(eth_type), l2_len))
    }
}

#[derive(Default)]
pub struct TapInterfaceWhitelist {
    whitelist: HashSet<usize>,
    updated: bool,
    last_sync: Duration,
    ntp_diff: Arc<AtomicI64>,
}

impl TapInterfaceWhitelist {
    const SYNC_INTERVAL: Duration = Duration::from_secs(1);

    pub fn add(&mut self, index: usize) {
        if self.whitelist.insert(index) {
            self.updated = true;
        }
    }

    pub fn has(&self, index: usize) -> bool {
        self.whitelist.contains(&index)
    }

    pub fn reset(&mut self) {
        self.updated = self.whitelist.is_empty();
        self.whitelist.clear();
    }

    pub fn next_sync(&mut self, mut now: Duration) -> bool {
        if !self.updated {
            return false;
        }
        if now.is_zero() {
            now = get_timestamp(self.ntp_diff.load(Ordering::Relaxed));
        }
        if now > self.last_sync && now - self.last_sync > Self::SYNC_INTERVAL {
            self.updated = false;
            self.last_sync = now;
            true
        } else {
            false
        }
    }
}

#[derive(Clone)]
pub struct BaseDispatcherListener {
    pub id: usize,
    pub src_interface: String,
    pub src_interface_index: usize,
    pub options: Arc<Mutex<Options>>,
    pub bpf_options: Arc<Mutex<BpfOptions>>,
    pub handler_builders: Arc<Mutex<Vec<PacketHandlerBuilder>>>,
    pub pipelines: Arc<Mutex<HashMap<u32, Arc<Mutex<Pipeline>>>>>,
    pub tap_interfaces: Arc<Mutex<Vec<Link>>>,
    pub need_update_bpf: Arc<AtomicBool>,
    #[cfg(target_os = "linux")]
    pub platform_poller: Arc<GenericPoller>,
    pub tunnel_type_bitmap: Arc<Mutex<TunnelTypeBitmap>>,
    pub npb_dedup_enabled: Arc<AtomicBool>,
    pub reset_whitelist: Arc<AtomicBool>,
    capture_bpf: String,
    proxy_controller_ip: String,
    analyzer_ip: String,
    proxy_controller_port: u16,
    analyzer_port: u16,
    pub netns: NsFile,

    // dispatcher id for easy debugging
    pub log_id: String,
}

impl BaseDispatcherListener {
    fn on_decap_type_change(&mut self, config: &DispatcherConfig) {
        let mut old_map = self.tunnel_type_bitmap.lock().unwrap();
        if *old_map != config.tunnel_type_bitmap {
            info!("Decap tunnel type change to {}", config.tunnel_type_bitmap);
            *old_map = config.tunnel_type_bitmap;
        }
    }

    fn on_bpf_change(&mut self, config: &DispatcherConfig) {
        if self.capture_bpf == config.capture_bpf
            && self.proxy_controller_ip == config.proxy_controller_ip
            && self.proxy_controller_port == config.proxy_controller_port
            && self.analyzer_ip == config.analyzer_ip
            && self.analyzer_port == config.analyzer_port
            && self.options.lock().unwrap().snap_len == config.capture_packet_size as usize
        {
            return;
        }
        self.capture_bpf = config.capture_bpf.clone();
        self.proxy_controller_ip = config.proxy_controller_ip.clone();
        self.proxy_controller_port = config.proxy_controller_port;
        self.analyzer_ip = config.analyzer_ip.clone();
        self.analyzer_port = config.analyzer_port;
        self.options.lock().unwrap().snap_len = config.capture_packet_size as usize;

        let analyzer_ip = if self.analyzer_ip.parse::<IpAddr>().is_ok() {
            self.analyzer_ip.parse::<IpAddr>().unwrap()
        } else {
            let ips = lookup_host(&self.analyzer_ip);
            if ips.is_err() {
                warn!("Dns lookup {} error: {:?}", self.analyzer_ip, ips);
                return;
            }
            ips.unwrap()[0]
        };

        let source_ip = get_route_src_ip(&analyzer_ip);
        if source_ip.is_err() {
            warn!("get route to {} failed", analyzer_ip);
            return;
        }

        let options = self.options.lock().unwrap();
        let bpf_builder = bpf::Builder {
            is_ipv6: options.is_ipv6,
            vxlan_flags: options.vxlan_flags,
            npb_port: options.npb_port,
            controller_port: options.controller_port,
            controller_tls_port: options.controller_tls_port,
            proxy_controller_port: self.proxy_controller_port,
            analyzer_source_ip: source_ip.unwrap(),
            analyzer_port: self.analyzer_port,
        };

        let mut bpf_options = self.bpf_options.lock().unwrap();
        bpf_options.capture_bpf = config.capture_bpf.clone();
        #[cfg(target_os = "linux")]
        {
            bpf_options.bpf_syntax = bpf_builder.build_pcap_syntax();
        }
        #[cfg(target_os = "windows")]
        {
            bpf_options.bpf_syntax_str = bpf_builder.build_pcap_syntax_to_str();
        }
        self.need_update_bpf.store(true, Ordering::Release);

        mem::drop(bpf_options);
    }

    fn on_npb_dedup_change(&mut self, config: &DispatcherConfig) {
        if config.npb_dedup_enabled != self.npb_dedup_enabled.load(Ordering::Relaxed) {
            info!("Npb dedup change to {}", config.npb_dedup_enabled);
            self.npb_dedup_enabled
                .store(config.npb_dedup_enabled, Ordering::Relaxed)
        }
    }

    pub(super) fn on_config_change(&mut self, config: &DispatcherConfig) {
        #[cfg(target_os = "linux")]
        self.on_afpacket_change(config);
        self.on_decap_type_change(config);
        self.on_bpf_change(config);
        self.on_npb_dedup_change(config);
    }

    pub(super) fn on_vm_change(&self, keys: &[u32], vm_macs: &[MacAddr]) {
        assert_eq!(keys.len(), vm_macs.len());
        // assert keys in assending order for bsearch
        assert!(keys.windows(2).all(|w| w[0] <= w[1]));
        let mut pipelines = self.pipelines.lock().unwrap();

        let mut deleted = Vec::new();
        pipelines.retain(|k, v| {
            match keys.binary_search(k) {
                // 在POD和修改ifMacSource场景下，网卡对应的mac地址也会改变，这里需要比较mac
                Ok(id) if vm_macs[id] == v.lock().unwrap().vm_mac => true,
                _ => {
                    deleted.push(v.lock().unwrap().vm_mac);
                    false
                }
            }
        });
        if deleted.len() > 0 {
            info!("Dispatcher{} Removing VMs: {:?}", self.log_id, deleted);
        }
        if pipelines.len() == keys.len() {
            return;
        }

        let mut added = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            if pipelines.contains_key(key)
                && pipelines.get(key).unwrap().lock().unwrap().vm_mac == vm_macs[i]
            {
                // vm mac already checked
                continue;
            }
            let vm_mac = vm_macs[i];
            added.push(vm_mac);
            let handlers = self
                .handler_builders
                .lock()
                .unwrap()
                .iter()
                .map(|b| b.build_with(self.id, *key, vm_mac))
                .collect();
            pipelines.insert(
                *key,
                Arc::new(Mutex::new(Pipeline {
                    vm_mac,
                    handlers,
                    timestamp: Duration::ZERO,
                })),
            );
        }
        if added.len() > 0 {
            info!("Dispatcher{} Adding VMs: {:?}", self.log_id, added);
        }
    }

    pub(super) fn on_tap_interface_change(&self, mut interfaces: Vec<Link>, _: IfMacSource) {
        if &self.src_interface != "" {
            match net::link_by_name(&self.src_interface) {
                Ok(link) => interfaces = vec![link],
                Err(e) => warn!("link_by_name failed: {:?}", e),
            }
        }

        interfaces.sort();
        let mut tap_interfaces = self.tap_interfaces.lock().unwrap();
        // both tap_interfaces and interfaces are sorted
        if *tap_interfaces == interfaces {
            return;
        }
        *tap_interfaces = interfaces;
        self.need_update_bpf.store(true, Ordering::Release);
    }
}

#[cfg(target_os = "linux")]
impl BaseDispatcherListener {
    fn on_afpacket_change(&mut self, config: &DispatcherConfig) {
        if self.options.lock().unwrap().af_packet_version != config.capture_socket_type.into() {
            // TODO：目前通过进程退出的方式修改AfPacket版本，后面需要支持动态修改
            info!("Afpacket version update, deepflow-agent restart...");
            process::exit(1);
        }
    }
}
