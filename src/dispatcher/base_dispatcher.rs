use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use log::{debug, error, info, warn};

use super::{
    error::Result,
    recv_engine::{self, af_packet::Packet, bpf, RecvEngine},
    BpfOptions, Options, PacketCounter, Pipeline,
};

use crate::{
    common::{
        decapsulate::{TunnelInfo, TunnelType, TunnelTypeBitmap},
        enums::{EthernetType, TapType},
        MetaPacket, TaggedFlow, TapTyper, ETH_HEADER_SIZE, FIELD_OFFSET_ETH_TYPE, VLAN_HEADER_SIZE,
        VLAN_ID_MASK,
    },
    config::{handler::FlowAccess, RuntimeConfig},
    flow_generator::MetaAppProto,
    platform::GenericPoller,
    policy::PolicyGetter,
    proto::trident::{IfMacSource, TapMode},
    utils::{
        bytes::read_u16_be,
        net::{self, get_route_src_ip, Link, MacAddr},
        queue::Sender,
        stats::Collector,
        LeakyBucket,
    },
};

pub(super) struct BaseDispatcher {
    pub(super) engine: RecvEngine,

    pub(super) id: usize,
    pub(super) src_interface_index: u32,
    pub(super) src_interface: String,
    pub(super) ctrl_mac: MacAddr,

    pub(super) options: Arc<Options>,
    pub(super) bpf_options: Arc<Mutex<BpfOptions>>,

    pub(super) leaky_bucket: Arc<LeakyBucket>,
    pub(super) pipelines: Arc<Mutex<HashMap<u32, Arc<Mutex<Pipeline>>>>>,
    pub(super) tap_interfaces: Arc<Mutex<Vec<Link>>>,
    pub(super) flow_map_config: FlowAccess,

    pub(super) tunnel_type_bitmap: Arc<Mutex<TunnelTypeBitmap>>,
    pub(super) tunnel_info: TunnelInfo,

    pub(super) tap_type_handler: TapTypeHandler,

    pub(super) need_update_ebpf: Arc<AtomicBool>,
    // 该表中的tap接口采集包长不截断
    pub(super) reset_whitelist: Arc<AtomicBool>,
    pub(super) tap_interface_whitelist: TapInterfaceWhitelist,

    pub(super) analyzer_dedup_disabled: bool,

    pub(super) flow_output_queue: Sender<TaggedFlow>,
    pub(super) log_output_queue: Sender<MetaAppProto>,

    pub(super) counter: Arc<PacketCounter>,
    pub(super) terminated: Arc<AtomicBool>,
    pub(super) stats: Arc<Collector>,
    pub(super) platform_poller: Arc<GenericPoller>,

    pub(super) policy_getter: PolicyGetter,
}

impl BaseDispatcher {
    #[cfg(all(target_os = "linux", not(target_arch = "s390x")))]
    fn is_engine_dpdk(&self) -> bool {
        match &self.engine {
            RecvEngine::Dpdk(..) => true,
            _ => false,
        }
    }

    #[cfg(any(not(target_os = "linux"), target_arch = "s390x"))]
    fn is_engine_dpdk(&self) -> bool {
        false
    }

    pub(super) fn recv<'a>(
        engine: &'a mut RecvEngine,
        leaky_bucket: &LeakyBucket,
        prev_timestamp: &mut Duration,
        counter: &PacketCounter,
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
        if timestamp > *prev_timestamp {
            if timestamp - *prev_timestamp > Duration::from_secs(60) {
                // Correct invalid timestamp under some environments. Root cause unclear.
                // A large timestamp will lead to discarding of following packets, correct
                // this by setting it to present time
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                if timestamp > now && timestamp - now > Duration::from_secs(60) {
                    timestamp = now;
                }
            }
            *prev_timestamp = timestamp;
        }
        while !leaky_bucket.acquire(1) {
            counter.get_token_failed.fetch_add(1, Ordering::Relaxed);
            // TODO: SetAnException
            thread::sleep(Duration::from_millis(1));
        }

        counter.rx.fetch_add(1, Ordering::Relaxed);
        counter
            .rx_bytes
            .fetch_add(packet.data.len() as u64, Ordering::Relaxed);

        Some((packet, timestamp))
    }

    pub(super) fn decapsulate(
        packet: &mut [u8],
        tap_type_handler: &TapTypeHandler,
        tunnel_info: &mut TunnelInfo,
        bitmap: &TunnelTypeBitmap,
    ) -> Result<(usize, TapType)> {
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

    pub(super) fn prepare_flow(
        meta_packet: &mut MetaPacket,
        tap_type: TapType,
        reset_ttl: bool,
        queue_hash: u8,
    ) {
        meta_packet.lookup_key.tap_type = tap_type;
        meta_packet.reset_ttl = reset_ttl;
        meta_packet.queue_hash = queue_hash;
    }

    pub(super) fn listener(&self) -> BaseDispatcherListener {
        BaseDispatcherListener {
            id: self.id,
            src_interface: self.src_interface.clone(),
            options: self.options.clone(),
            bpf_options: self.bpf_options.clone(),
            pipelines: self.pipelines.clone(),
            tap_interfaces: self.tap_interfaces.clone(),
            need_update_ebpf: self.need_update_ebpf.clone(),
            platform_poller: self.platform_poller.clone(),
            proxy_controller_ip: Ipv4Addr::UNSPECIFIED.into(),
            analyzer_ip: Ipv4Addr::UNSPECIFIED.into(),
            tunnel_type_bitmap: self.tunnel_type_bitmap.clone(),
        }
    }

    pub fn terminate_queue(&self) {
        for sender in self.options.handler_builders.iter() {
            sender.send_terminated();
        }
    }
}

#[cfg(target_os = "linux")]
impl BaseDispatcher {
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
                    "dispatcher recv_engine init error: {:?}, trident restart...",
                    e
                );
                thread::sleep(Duration::from_secs(1));
                std::process::exit(1);
            }
        }
    }

    pub(super) fn check_and_update_ebpf(&mut self) {
        if !self.need_update_ebpf.swap(false, Ordering::Relaxed) {
            return;
        }
        let tap_interfaces = self.tap_interfaces.lock().unwrap();
        if tap_interfaces.len() == 0 {
            return;
        }
        let bpf_options = self.bpf_options.lock().unwrap();
        if let Err(e) = self
            .engine
            .set_bpf(&CString::new(&*bpf_options.bpf_syntax).unwrap())
        {
            warn!("set_bpf failed: {}", e);
        }
    }
}

#[derive(Default)]
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
                    tap_type = t;
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
                tap_type = t;
            }
        }
        Ok((tap_type, eth_type.try_into()?, l2_len))
    }
}

#[derive(Default)]
pub(super) struct TapInterfaceWhitelist {
    whitelist: HashSet<usize>,
    updated: bool,
    last_sync: Duration,
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
            // TODO: use ntp time
            now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
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
pub(super) struct BaseDispatcherListener {
    pub id: usize,
    pub src_interface: String,
    pub options: Arc<Options>,
    pub bpf_options: Arc<Mutex<BpfOptions>>,
    pub pipelines: Arc<Mutex<HashMap<u32, Arc<Mutex<Pipeline>>>>>,
    pub tap_interfaces: Arc<Mutex<Vec<Link>>>,
    pub need_update_ebpf: Arc<AtomicBool>,
    pub platform_poller: Arc<GenericPoller>,
    pub tunnel_type_bitmap: Arc<Mutex<TunnelTypeBitmap>>,

    proxy_controller_ip: IpAddr,
    analyzer_ip: IpAddr,
}

impl BaseDispatcherListener {
    pub(super) fn on_config_change(&mut self, config: &RuntimeConfig) {
        if self.proxy_controller_ip.to_string() == config.proxy_controller_ip
            && self.analyzer_ip.to_string() == config.analyzer_ip
        {
            return;
        }

        match (
            config.proxy_controller_ip.parse(),
            config.analyzer_ip.parse(),
        ) {
            (Ok(pc_ip), Ok(a_ip)) => {
                self.proxy_controller_ip = pc_ip;
                self.analyzer_ip = a_ip;
            }
            _ => {
                warn!(
                    "Invalid proxy_controller_ip {} or ananlyzer_ip {}",
                    config.proxy_controller_ip, config.analyzer_ip
                );
                return;
            }
        }

        let source_ip = get_route_src_ip(&self.analyzer_ip);
        if source_ip.is_err() {
            warn!("get route to {} failed", self.analyzer_ip);
            return;
        }

        let bpf_syntax = bpf::Builder {
            is_ipv6: self.options.is_ipv6,
            vxlan_port: self.options.vxlan_port,
            controller_port: self.options.controller_port,
            controller_tls_port: self.options.controller_tls_port,
            proxy_controller_ip: self.proxy_controller_ip,
            analyzer_source_ip: source_ip.unwrap(),
        }
        .build_pcap_syntax();

        debug!("PcapBpf: {}", bpf_syntax);
        self.bpf_options.lock().unwrap().bpf_syntax = bpf_syntax;
        self.need_update_ebpf.store(true, Ordering::Release);

        let mut tunnel_types = Vec::new();
        for decap_type in &config.decap_type {
            tunnel_types.push(TunnelType::try_from(*decap_type as u8).unwrap());
        }
        let bitmaps = TunnelTypeBitmap::new(&tunnel_types);
        *self.tunnel_type_bitmap.lock().unwrap() = bitmaps;
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
            info!("Removing VMs: {:?}", deleted);
        }
        if pipelines.len() == keys.len() {
            return;
        }

        let mut added = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            if pipelines.contains_key(key)
                && pipelines.get(key).unwrap().lock().unwrap().vm_mac != vm_macs[i]
            {
                // vm mac already checked
                continue;
            }
            let vm_mac = vm_macs[i];
            added.push(vm_mac);
            let handlers = self
                .options
                .handler_builders
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
            info!("Adding VMs: {:?}", added);
        }
    }
}

#[cfg(target_os = "linux")]
impl BaseDispatcherListener {
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
        self.need_update_ebpf.store(true, Ordering::Release);
    }
}
