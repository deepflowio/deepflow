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

use std::{
    cmp,
    collections::HashSet,
    ffi::CString,
    fmt,
    net::{IpAddr, Ipv4Addr},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime},
};

use arc_swap::access::Access;
use log::{debug, error, info, log_enabled, warn, Level};
use regex::Regex;

use super::Poller;
use crate::{
    common::{
        ARP_SPA_OFFSET, ETH_HEADER_SIZE, ETH_TYPE_LEN, ETH_TYPE_OFFSET, FIELD_OFFSET_SA,
        IPV4_ADDR_LEN, IPV4_SRC_OFFSET, IPV6_ADDR_LEN, IPV6_SRC_OFFSET, MAC_ADDR_LEN,
        VLAN_HEADER_SIZE,
    },
    config::handler::PlatformAccess,
    dispatcher::{
        af_packet::{bpf::*, Options, Tpacket},
        recv_engine::{RecvEngine, POLL_TIMEOUT},
    },
};

use public::{
    bytes::read_u16_be,
    consts::{IPV4_PACKET_SIZE, IPV6_PACKET_SIZE},
    enums::EthernetType,
    error::Error,
    netns::{InterfaceInfo, NsFile},
    packet::Packet,
    proto::trident::TapMode,
    utils::net::{links_by_name_regex, MacAddr},
};

const LINUX_SLL_PACKET_TYPE_OUT_GONING: u32 = 4;
const MINUTE: Duration = Duration::from_secs(60);

pub struct PassivePoller {
    expire_timeout: Duration,
    version: Arc<AtomicU64>,
    entries: Arc<Mutex<Vec<PassiveEntry>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    running: Arc<AtomicBool>,
    config: PlatformAccess,
}

impl PassivePoller {
    const TAP_INTERFACE_MAX: usize = 950;
    const CAPTURE_PACKET_SIZE: usize = IPV6_PACKET_SIZE + VLAN_HEADER_SIZE * 2;
    pub fn new(interval: Duration, config: PlatformAccess) -> Self {
        Self {
            config,
            expire_timeout: interval,
            version: Default::default(),
            running: Default::default(),
            thread: Default::default(),
            entries: Default::default(),
        }
    }

    fn update_bpf(engine: &mut RecvEngine, white_list: &HashSet<u32>) {
        let white_list = white_list.iter().map(|x| *x).collect::<Vec<u32>>();
        let mut bpf = vec![
            // From the perspective of the interface of the host namespace, the traffic sent by the container is inbound
            BpfSyntax::LoadExtension(LoadExtension {
                num: Extension::ExtType,
            }),
            BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpEqual,
                val: LINUX_SLL_PACKET_TYPE_OUT_GONING,
                skip_false: 1,
                skip_true: 0,
            }),
            BpfSyntax::RetConstant(RetConstant { val: 0 }),
            // Skip vlan header
            BpfSyntax::LoadAbsolute(LoadAbsolute {
                off: ETH_TYPE_OFFSET as u32,
                size: ETH_TYPE_LEN as u32,
            }),
            BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpNotEqual,
                val: u16::from(EthernetType::Dot1Q) as u32,
                skip_false: 0,
                skip_true: 2,
            }),
            BpfSyntax::LoadConstant(LoadConstant {
                dst: Register::RegX,
                val: VLAN_HEADER_SIZE as u32,
            }),
            BpfSyntax::LoadIndirect(LoadIndirect {
                off: ETH_TYPE_OFFSET as u32,
                size: ETH_TYPE_LEN as u32,
            }),
            // ARP
            BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpEqual,
                val: u16::from(EthernetType::Arp) as u32,
                skip_true: 3,
                skip_false: 0,
            }),
            // IPv4
            BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpEqual,
                val: u16::from(EthernetType::Ipv4) as u32,
                skip_true: 2,
                skip_false: 0,
            }),
            // IPv6
            BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpEqual,
                val: u16::from(EthernetType::Ipv6) as u32,
                skip_true: 1,
                skip_false: 0,
            }),
            BpfSyntax::RetConstant(RetConstant { val: 0 }),
            BpfSyntax::LoadExtension(LoadExtension {
                num: Extension::ExtInterfaceIndex,
            }),
        ];
        let total = white_list.len();
        for (i, if_index) in white_list.iter().enumerate() {
            bpf.push(BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpEqual,
                val: *if_index,
                skip_true: (total - i) as u8,
                skip_false: 0,
            }));
        }
        bpf.push(BpfSyntax::RetConstant(RetConstant { val: 0 }));
        bpf.push(BpfSyntax::RetConstant(RetConstant {
            val: Self::CAPTURE_PACKET_SIZE as u32,
        }));

        let ins = bpf.into_iter().map(|ins| ins.to_instruction()).collect();
        if let Err(e) = engine.set_bpf(ins, &CString::new("").unwrap()) {
            error!("RecvEngine set bpf error: {e}");
        }
    }

    fn generate_white_list(tap_interface_regex: &String) -> HashSet<u32> {
        let links = match links_by_name_regex(tap_interface_regex) {
            Err(e) => {
                warn!("get interfaces by name regex failed: {}", e);
                vec![]
            }
            Ok(links) => {
                if links.is_empty() {
                    warn!(
                        "tap-interface-regex({}) do not match any interface, in passive poller.",
                        tap_interface_regex
                    );
                }
                links
            }
        };
        let mut if_indices = links.iter().map(|x| x.if_index).collect::<Vec<u32>>();
        if_indices.sort();
        let limit = if_indices.len().min(Self::TAP_INTERFACE_MAX);
        if_indices[..limit]
            .iter()
            .map(|x| *x)
            .collect::<HashSet<u32>>()
    }

    fn flush_timeout(
        now: &SystemTime,
        expire_timeout: Duration,
        last_expire: &mut SystemTime,
        entries: &Arc<Mutex<Vec<PassiveEntry>>>,
        version: &Arc<AtomicU64>,
        white_list: &mut HashSet<u32>,
    ) {
        // 每分钟移除超时的记录
        // Remove timed out records every minute
        if now.duration_since(*last_expire).unwrap() > MINUTE {
            let mut entries_gurad = entries.lock().unwrap();
            let old_len: usize = entries_gurad.len();
            entries_gurad.retain_mut(|e| {
                let mut is_not_timeout = now.duration_since(e.last_seen).unwrap() <= expire_timeout;
                if !is_not_timeout {
                    white_list.insert(e.tap_index);
                    e.retry_count += 1;
                    if e.retry_count < PassiveEntry::RETRY_COUNT_LIMIT {
                        debug!("Capture pod timeout {}, try {}", e, e.retry_count);
                        e.last_seen = *now;
                        is_not_timeout = true
                    } else {
                        debug!("Capture remote pod {} {}", e, e.retry_count);
                    }
                }
                is_not_timeout
            });

            if entries_gurad.len() != old_len {
                version.fetch_add(1, Ordering::Relaxed);
            }
            *last_expire = *now;
        }
    }

    fn log_version(
        now: &SystemTime,
        last_version_log: &mut SystemTime,
        version: &Arc<AtomicU64>,
        last_version: &mut u64,
        entries: &Arc<Mutex<Vec<PassiveEntry>>>,
    ) {
        let new_version = version.load(Ordering::Relaxed);
        if *last_version != new_version {
            if now.duration_since(*last_version_log).unwrap() > MINUTE {
                info!("kubernetes poller updated to version {new_version}");
                *last_version_log = *now;
                if log_enabled!(Level::Debug) {
                    for entry in entries.lock().unwrap().iter() {
                        debug!("{entry}");
                    }
                }
            }
            *last_version = new_version;
        }
    }

    fn update_entries(
        entries: &Arc<Mutex<Vec<PassiveEntry>>>,
        version: &Arc<AtomicU64>,
        entry: PassiveEntry,
    ) {
        let mut entries = entries.lock().unwrap();
        let index = entries.partition_point(|x| x < &entry);
        if index >= entries.len() || !entries[index].eq(&entry) {
            debug!("Capture add pod {}", &entry);
            entries.insert(index, entry);
            version.fetch_add(1, Ordering::Relaxed);
        } else {
            entries[index].last_seen = entry.last_seen;
            entries[index].retry_count = 0;
        }
    }

    fn process(
        running: Arc<AtomicBool>,
        expire_timeout: Duration,
        version: Arc<AtomicU64>,
        entries: Arc<Mutex<Vec<PassiveEntry>>>,
        config: PlatformAccess,
    ) {
        let tap_mode = config.load().tap_mode;
        let mut engine = match tap_mode {
            TapMode::Local | TapMode::Mirror | TapMode::Analyzer => {
                let afp = Options {
                    frame_size: 256,
                    num_blocks: 1,
                    poll_timeout: POLL_TIMEOUT.as_nanos() as isize,
                    ..Default::default()
                };
                info!("Afpacket init with {afp:?}");
                RecvEngine::AfPacket(Tpacket::new(afp).unwrap())
            }
            _ => {
                error!("construct RecvEngine error: TapMode({tap_mode:?}) not support");
                return;
            }
        };

        let mut white_list = HashSet::new();
        let mut tap_interface_regex = String::new();
        let mut last_version = version.load(Ordering::Relaxed);
        let mut last_version_log = SystemTime::now();
        let mut last_expire = SystemTime::now();
        while running.load(Ordering::Relaxed) {
            if config.load().tap_interface_regex != tap_interface_regex {
                info!(
                    "Passive poller tap interface regex change from {} to {}.",
                    tap_interface_regex,
                    config.load().tap_interface_regex
                );

                tap_interface_regex = config.load().tap_interface_regex.clone();
                white_list = Self::generate_white_list(&tap_interface_regex);
                entries.lock().unwrap().clear();
                Self::update_bpf(&mut engine, &white_list);
            }

            let now = SystemTime::now();
            Self::flush_timeout(
                &now,
                expire_timeout,
                &mut last_expire,
                &entries,
                &version,
                &mut white_list,
            );
            Self::log_version(
                &now,
                &mut last_version_log,
                &version,
                &mut last_version,
                &entries,
            );

            Self::update_bpf(&mut engine, &white_list);

            // The lifecycle of the packet will end before the next call to recv.
            let packet = match unsafe { engine.recv() } {
                Ok(p) => p,
                Err(Error::Timeout) => continue,
                Err(e) => {
                    warn!("capture packet failed: {}", e);
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }
            };

            let if_index = packet.if_index as u32;
            if !white_list.contains(&if_index) {
                drop(packet);
                continue;
            }

            let entry = match PassiveEntry::new(&packet) {
                Ok(mut e) => {
                    e.last_seen = now;
                    e
                }
                Err(e) => {
                    error!("{:?}", e);
                    continue;
                }
            };
            drop(packet);
            Self::update_entries(&entries, &version, entry);
            Self::log_version(
                &now,
                &mut last_version_log,
                &version,
                &mut last_version,
                &entries,
            );

            white_list.remove(&if_index);
        }
    }
}

impl Poller for PassivePoller {
    fn get_version(&self) -> u64 {
        self.version.load(Ordering::Relaxed)
    }

    fn get_interface_info_in(&self, _: &NsFile) -> Option<Vec<InterfaceInfo>> {
        Some(self.get_interface_info())
    }

    fn get_interface_info(&self) -> Vec<InterfaceInfo> {
        let entries = self.entries.lock().unwrap();
        if entries.is_empty() {
            return vec![];
        }

        let mut info_slice = vec![];
        let mut info = InterfaceInfo {
            tap_idx: entries[0].tap_index,
            mac: entries[0].mac,
            ips: vec![entries[0].ip],
            device_id: "1".to_string(),
            ..Default::default()
        };
        for entry in entries.iter().skip(1) {
            if entry.tap_index == info.tap_idx && entry.mac == info.mac {
                info.ips.push(entry.ip);
            } else {
                info_slice.push(info.clone());
                info = InterfaceInfo {
                    tap_idx: entry.tap_index,
                    mac: entry.mac,
                    ips: vec![entry.ip],
                    device_id: "1".to_string(),
                    ..Default::default()
                };
            }
        }

        info_slice.push(info);
        info_slice
    }

    fn set_netns_regex(&self, _: Option<Regex>) {}

    fn start(&self) {
        if self.running.swap(true, Ordering::Relaxed) {
            return;
        }

        let expire_timeout = self.expire_timeout;
        let running = self.running.clone();
        let version = self.version.clone();
        let entries = self.entries.clone();
        let config = self.config.clone();
        let handle = thread::Builder::new()
            .name("kubernetes-poller".to_owned())
            .spawn(move || Self::process(running, expire_timeout, version, entries, config))
            .unwrap();
        self.thread.lock().unwrap().replace(handle);
        info!("kubernetes passive poller started");
    }

    fn stop(&self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            return;
        }

        if let Some(handle) = self.thread.lock().unwrap().take() {
            let _ = handle.join();
        }

        info!("kubernetes passive poller stopped");
    }
}

#[derive(Debug)]
struct PassiveEntry {
    tap_index: u32,
    mac: MacAddr,
    ip: IpAddr,
    last_seen: SystemTime,
    retry_count: u8,
}

impl Default for PassiveEntry {
    fn default() -> Self {
        PassiveEntry {
            last_seen: SystemTime::UNIX_EPOCH,
            tap_index: 0,
            ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            mac: MacAddr::ZERO,
            retry_count: 0,
        }
    }
}

impl PassiveEntry {
    const RETRY_COUNT_LIMIT: u8 = 3;

    fn new(packet: &Packet) -> Result<Self, String> {
        let packet_len = packet.data.len();
        let packet_data = &packet.data;
        if packet_len < ETH_HEADER_SIZE {
            debug!("ignore short packet, size={packet_len}");
            return Err("Invalid packet length.".to_string());
        }

        let mut eth_type = read_u16_be(&packet_data[ETH_TYPE_OFFSET..]);
        let mut extra_offset = 0;
        if eth_type == EthernetType::Dot1Q {
            extra_offset += VLAN_HEADER_SIZE;
            eth_type = read_u16_be(&packet_data[ETH_TYPE_OFFSET + extra_offset..]);
            if eth_type == EthernetType::Dot1Q {
                extra_offset += VLAN_HEADER_SIZE;
                eth_type = read_u16_be(&packet_data[ETH_TYPE_OFFSET + extra_offset..]);
            }
        }

        let eth_type = match EthernetType::try_from(eth_type) {
            Ok(e) => e,
            Err(e) => {
                debug!("parse packet eth_type failed: {e}");
                return Err("Unsupport ether type.".to_string());
            }
        };

        let entry = match eth_type {
            EthernetType::Ipv4 => {
                if packet_len < IPV4_PACKET_SIZE + extra_offset {
                    debug!("ignore short ipv4 packet, size={packet_len}");
                    return Err("Invalid ipv4 packet length.".to_string());
                }
                let so = IPV4_SRC_OFFSET + extra_offset;
                PassiveEntry {
                    tap_index: packet.if_index as u32,
                    mac: MacAddr::try_from(
                        &packet_data[FIELD_OFFSET_SA..FIELD_OFFSET_SA + MAC_ADDR_LEN],
                    )
                    .unwrap(),
                    ip: IpAddr::from(
                        *<&[u8; 4]>::try_from(&packet_data[so..so + IPV4_ADDR_LEN]).unwrap(),
                    ),
                    ..Default::default()
                }
            }
            EthernetType::Arp => {
                if packet_len < ARP_SPA_OFFSET + extra_offset + 4 {
                    debug!("ignore short arp packet, size={packet_len}");
                    return Err("Invalid arp packet length.".to_string());
                }

                let so = ARP_SPA_OFFSET + extra_offset;
                PassiveEntry {
                    tap_index: packet.if_index as u32,
                    mac: MacAddr::try_from(
                        &packet_data[FIELD_OFFSET_SA..FIELD_OFFSET_SA + MAC_ADDR_LEN],
                    )
                    .unwrap(),
                    ip: IpAddr::from(
                        *<&[u8; 4]>::try_from(&packet_data[so..so + IPV4_ADDR_LEN]).unwrap(),
                    ),
                    ..Default::default()
                }
            }
            EthernetType::Ipv6 => {
                if packet_len < IPV6_PACKET_SIZE + extra_offset {
                    debug!("ignore short ipv6 packet, size={packet_len}");
                    return Err("Invalid ipv6 packet length.".to_string());
                }

                let so = IPV6_SRC_OFFSET + extra_offset;
                PassiveEntry {
                    tap_index: packet.if_index as u32,
                    mac: MacAddr::try_from(
                        &packet_data[FIELD_OFFSET_SA..FIELD_OFFSET_SA + MAC_ADDR_LEN],
                    )
                    .unwrap(),
                    ip: IpAddr::from(
                        *<&[u8; 16]>::try_from(&packet_data[so..so + IPV6_ADDR_LEN]).unwrap(),
                    ),
                    ..Default::default()
                }
            }
            _ => return Err("Unsupport ether type.".to_string()),
        };

        Ok(entry)
    }
}

impl fmt::Display for PassiveEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IfIndex: {} MAC: {} IP: {}",
            self.tap_index, self.mac, self.ip
        )
    }
}

impl PartialEq for PassiveEntry {
    fn eq(&self, other: &Self) -> bool {
        self.tap_index.eq(&other.tap_index) && self.mac.eq(&other.mac) && self.ip.eq(&other.ip)
    }
}

impl Eq for PassiveEntry {}

impl PartialOrd for PassiveEntry {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PassiveEntry {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        let tap_index_ordering = self.tap_index.cmp(&other.tap_index);
        if tap_index_ordering != cmp::Ordering::Equal {
            return tap_index_ordering;
        }

        let mac_ordering = self.mac.cmp(&other.mac);
        if mac_ordering != cmp::Ordering::Equal {
            return mac_ordering;
        }

        self.ip.cmp(&other.ip)
    }
}
