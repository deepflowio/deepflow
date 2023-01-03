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
    cmp,
    collections::HashSet,
    fmt,
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime},
};

use arc_swap::access::Access;
use libc::RT_SCOPE_LINK;
use log::{debug, error, info, log_enabled, warn, Level};
use pnet::packet::icmpv6::Icmpv6Types;
use regex::Regex;

use super::Poller;
use crate::{
    common::{
        ARP_SPA_OFFSET, ETH_TYPE_LEN, ETH_TYPE_OFFSET, FIELD_OFFSET_SA, ICMPV6_TYPE_OFFSET,
        ICMPV6_TYPE_SIZE, IPV4_ADDR_LEN, IPV6_ADDR_LEN, IPV6_FRAGMENT_LEN, IPV6_PROTO_LEN,
        IPV6_PROTO_OFFSET, IPV6_SRC_OFFSET, MAC_ADDR_LEN, VLAN_HEADER_SIZE,
    },
    config::handler::PlatformAccess,
    dispatcher::{
        af_packet::{bpf::*, Options, Tpacket},
        recv_engine::{
            RecvEngine, DEFAULT_BLOCK_SIZE, FRAME_SIZE_MAX, FRAME_SIZE_MIN, POLL_TIMEOUT,
        },
    },
};

use public::{
    bytes::read_u16_be,
    enums::{EthernetType, IpProtocol},
    error::Error,
    netns::{InterfaceInfo, NsFile},
    proto::trident::TapMode,
    utils::net::{addr_list, MacAddr},
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

    // 排除掉有非link类型IP的接口，这些不会作为tap interface
    // Exclude interfaces with non-link type IPs, these will not be used as tap interfaces
    fn get_ignored_interface_indice() -> HashSet<u32> {
        let mut ignored = HashSet::new();

        let Ok(addrs) = addr_list() else { return ignored; };
        for addr in addrs {
            if addr.scope != RT_SCOPE_LINK {
                ignored.insert(addr.if_index);
            }
        }

        // HashSet Debug trait is {a, b, c, d} better than handwrite formatted string
        debug!("ignore tap interfaces with id in {ignored:?}");

        ignored
    }

    fn get_bpf() -> Vec<RawInstruction> {
        let bpf = vec![
            // 对于宿主命名空间的接口来看，容器发出来的流量是inbound
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
            // 跳过VLAN
            // skip VLAN packet
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
                skip_false: 1,
                skip_true: 0,
            }),
            BpfSyntax::RetConstant(RetConstant { val: 64 }),
            // IPv6
            BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpEqual,
                val: u16::from(EthernetType::Ipv6) as u32,
                skip_true: 1,
                skip_false: 0,
            }),
            BpfSyntax::RetConstant(RetConstant { val: 0 }),
            // IPv6 next header
            BpfSyntax::LoadIndirect(LoadIndirect {
                off: IPV6_PROTO_OFFSET as u32,
                size: IPV6_PROTO_LEN as u32,
            }),
            BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpEqual,
                val: u8::from(IpProtocol::Icmpv6) as u32,
                skip_true: 8,
                skip_false: 0,
            }),
            BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpEqual,
                val: u8::from(IpProtocol::Ipv6Fragment) as u32,
                skip_true: 1,
                skip_false: 0,
            }),
            BpfSyntax::RetConstant(RetConstant { val: 0 }),
            // skip fragment header
            BpfSyntax::Txa(Txa),
            BpfSyntax::ALUOpConstant(ALUOpConstant {
                op: ALU_OP_ADD,
                val: IPV6_FRAGMENT_LEN as u32,
            }),
            BpfSyntax::Txa(Txa),
            BpfSyntax::LoadIndirect(LoadIndirect {
                off: IPV6_PROTO_OFFSET as u32,
                size: IPV6_PROTO_LEN as u32,
            }),
            BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpEqual,
                val: u8::from(IpProtocol::Icmpv6) as u32,
                skip_true: 1,
                skip_false: 0,
            }),
            BpfSyntax::RetConstant(RetConstant { val: 0 }),
            // neighbour advertisement
            BpfSyntax::LoadIndirect(LoadIndirect {
                off: ICMPV6_TYPE_OFFSET as u32,
                size: ICMPV6_TYPE_SIZE as u32,
            }),
            BpfSyntax::JumpIf(JumpIf {
                cond: JumpTest::JumpEqual,
                val: Icmpv6Types::NeighborAdvert.0 as u32,
                skip_true: 0,
                skip_false: 1,
            }),
            BpfSyntax::RetConstant(RetConstant { val: 128 }),
            BpfSyntax::RetConstant(RetConstant { val: 0 }),
        ];

        bpf.into_iter().map(|ins| ins.to_instruction()).collect()
    }

    fn process(
        running: Arc<AtomicBool>,
        expire_timeout: Duration,
        version: Arc<AtomicU64>,
        entries: Arc<Mutex<Vec<PassiveEntry>>>,
        tap_mode: TapMode,
    ) {
        let mut engine = match tap_mode {
            TapMode::Local | TapMode::Mirror | TapMode::Analyzer => {
                let afp = Options {
                    frame_size: if tap_mode == TapMode::Analyzer {
                        FRAME_SIZE_MIN as u32
                    } else {
                        FRAME_SIZE_MAX as u32
                    },
                    block_size: DEFAULT_BLOCK_SIZE as u32,
                    num_blocks: 128,
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
        if let Err(e) = engine.set_bpf(Self::get_bpf()) {
            error!("RecvEngine set bpf error: {e}");
            return;
        }

        let mut last_version = version.load(Ordering::Relaxed);
        let mut last_version_log = SystemTime::now();
        let mut last_expire = SystemTime::now();
        let mut ignored_indice = Self::get_ignored_interface_indice();
        while running.load(Ordering::Relaxed) {
            let packet = match engine.recv() {
                Ok(p) => p,
                Err(Error::Timeout) => continue,
                Err(e) => {
                    warn!("capture packet failed: {}", e);
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }
            };
            let now = SystemTime::now();
            // 每分钟移除超时的记录
            // Remove timed out records every minute
            if now.duration_since(last_expire).unwrap() > MINUTE {
                ignored_indice = Self::get_ignored_interface_indice();
                let mut entries_gurad = entries.lock().unwrap();
                let old_len = entries_gurad.len();
                entries_gurad
                    .retain(|e| now.duration_since(e.last_seen).unwrap() <= expire_timeout);

                if entries_gurad.len() != old_len {
                    version.fetch_add(1, Ordering::Relaxed);
                }
                last_expire = now;
            }

            if ignored_indice.contains(&(packet.if_index as u32)) {
                continue;
            }

            let packet_len = packet.data.len();
            let packet_data = packet.data;
            if packet_len < ETH_TYPE_OFFSET + 2 * VLAN_HEADER_SIZE + 2 {
                // 22
                debug!("ignore short packet, size={packet_len}");
                continue;
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
                    continue;
                }
            };

            let entry = match eth_type {
                EthernetType::Arp => {
                    if packet_len < ARP_SPA_OFFSET + extra_offset + 4 {
                        debug!("ignore short arp packet, size={packet_len}");
                        continue;
                    }

                    let so = ARP_SPA_OFFSET + extra_offset;
                    PassiveEntry {
                        last_seen: now,
                        tap_index: packet.if_index as u32,
                        mac: MacAddr::try_from(
                            &packet_data[FIELD_OFFSET_SA..FIELD_OFFSET_SA + MAC_ADDR_LEN],
                        )
                        .unwrap(),
                        ip: IpAddr::from(
                            *<&[u8; 4]>::try_from(&packet_data[so..so + IPV4_ADDR_LEN]).unwrap(),
                        ),
                    }
                }
                EthernetType::Ipv6 => {
                    if packet_len < IPV6_PROTO_OFFSET + extra_offset + 1 {
                        debug!("ignore short ipv6 packet, size={packet_len}");
                        continue;
                    }

                    let mut protocol = packet_data[IPV6_PROTO_OFFSET + extra_offset];
                    if protocol == IpProtocol::Ipv6 {
                        extra_offset += IPV6_FRAGMENT_LEN;
                        protocol = packet_data[IPV6_PROTO_OFFSET + extra_offset];
                    }
                    if packet_len < ICMPV6_TYPE_OFFSET + extra_offset + 1 {
                        debug!("ignore short icmpv6 packet, size={packet_len}");
                        continue;
                    }
                    if protocol != IpProtocol::Icmpv6
                        || packet_data[ICMPV6_TYPE_OFFSET + extra_offset]
                            != Icmpv6Types::NeighborAdvert.0
                    {
                        continue;
                    }

                    let so = IPV6_SRC_OFFSET + extra_offset;
                    PassiveEntry {
                        last_seen: now,
                        tap_index: packet.if_index as u32,
                        mac: MacAddr::try_from(
                            &packet_data[FIELD_OFFSET_SA..FIELD_OFFSET_SA + MAC_ADDR_LEN],
                        )
                        .unwrap(),
                        ip: IpAddr::from(
                            *<&[u8; 16]>::try_from(&packet_data[so..so + IPV6_ADDR_LEN]).unwrap(),
                        ),
                    }
                }
                _ => continue,
            };

            {
                let mut entries = entries.lock().unwrap();
                let index = entries.partition_point(|x| x < &entry);
                if index >= entries.len() || !entries[index].eq(&entry) {
                    entries.insert(index, entry);
                    version.fetch_add(1, Ordering::Relaxed);
                } else {
                    entries[index].last_seen = entry.last_seen;
                }
            }
            let new_version = version.load(Ordering::Relaxed);
            if last_version != new_version {
                if now.duration_since(last_version_log).unwrap() > MINUTE {
                    info!("kubernetes poller updated to version {new_version}");
                    last_version_log = now;
                    if log_enabled!(Level::Debug) {
                        for entry in entries.lock().unwrap().iter() {
                            debug!("{entry}");
                        }
                    }
                }
                last_version = new_version;
            }
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
            tap_ns: Default::default(),
            name: Default::default(),
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
                    tap_ns: Default::default(),
                    name: Default::default(),
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
        let tap_mode = self.config.load().tap_mode;
        let handle = thread::Builder::new()
            .name("kubernetes-poller".to_owned())
            .spawn(move || Self::process(running, expire_timeout, version, entries, tap_mode))
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

struct PassiveEntry {
    tap_index: u32,
    mac: MacAddr,
    ip: IpAddr,
    last_seen: SystemTime,
}

impl fmt::Display for PassiveEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} {}", self.tap_index, self.mac, self.ip)
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
