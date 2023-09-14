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

use std::net::IpAddr;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
    Arc, Mutex, RwLock,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use log::{error, info, warn};
use sysinfo::{NetworkExt, System, SystemExt};

use crate::common::platform_data::PlatformData;
use crate::common::policy::{Acl, Cidr, IpGroupData, PeerConnection};
use crate::common::FlowAclListener;
use crate::exception::ExceptionHandler;
use crate::utils::stats::{Counter, CounterType, CounterValue, RefCountable};
use npb_pcap_policy::{NpbTunnelType, NOT_SUPPORT};
use public::proto::{common::TridentType, trident::Exception};
use public::utils::net::get_route_src_ip_interface_name;
use public::LeakyBucket;

#[derive(Default)]
pub struct InterfaceTraffic {
    tx_bps: AtomicU64,
    fuse_count: AtomicU64,
}

impl RefCountable for InterfaceTraffic {
    fn get_counters(&self) -> Vec<Counter> {
        vec![
            (
                "tx_bps",
                CounterType::Counted,
                CounterValue::Unsigned(self.tx_bps.swap(0, Relaxed)),
            ),
            (
                "fuse_count",
                CounterType::Counted,
                CounterValue::Unsigned(self.fuse_count.swap(0, Relaxed)),
            ),
        ]
    }
}

struct Watcher {
    // the unit is bites per secend
    nic_bps_threshold: AtomicU64,
    npb_bps_threshold: AtomicU64,
    // the unit is second
    interval: AtomicU64,

    traffic_count: Arc<InterfaceTraffic>,

    nic_name: RwLock<String>,
    ips: RwLock<Vec<IpAddr>>,

    npb_leaky_bucket: Arc<LeakyBucket>,
    exception_handler: ExceptionHandler,
    is_running: AtomicBool,
}

impl Watcher {
    const CHECK_CYCLES: usize = 5;

    fn get_nic_name(&self) -> String {
        let ips = self.ips.read().unwrap().clone();
        let mut last_nic_name = self.nic_name.write().unwrap();
        if !last_nic_name.to_string().is_empty() {
            return last_nic_name.to_string();
        }
        for remote in &ips {
            if let Ok(nic_name) = get_route_src_ip_interface_name(remote) {
                *last_nic_name = nic_name.clone();
                info!(
                    "Npb bandwidth watcher is monitoring {} by {}.",
                    &nic_name, remote
                );
                return nic_name;
            }
        }

        String::new()
    }

    fn get_nic_tx_bytes(&self, nic_name: String) -> Result<u64, bool> {
        let mut system = System::new();
        system.refresh_networks_list();
        for (iface_name, stats) in system.networks() {
            if *iface_name == nic_name {
                return Ok(stats.total_transmitted() as u64);
            }
        }
        Err(false)
    }

    fn get_nic_bps(&self, last_tx_bytes: &mut u64, interval: u64) -> Result<u64, bool> {
        let nic_name = self.get_nic_name();
        if nic_name.is_empty() {
            *last_tx_bytes = 0;
            return Err(false);
        }
        let Ok(tx_bytes) = self.get_nic_tx_bytes(nic_name) else {
            error!("Npb bandwidth watcher get tx bytes failed.");
            *last_tx_bytes = 0;
            return Err(false);
        };

        let tx_bps = if tx_bytes >= *last_tx_bytes && *last_tx_bytes != 0 {
            ((tx_bytes - *last_tx_bytes) * 8) / interval
        } else {
            0
        };
        *last_tx_bytes = tx_bytes;
        return Ok(tx_bps);
    }

    fn npb_stop(&self, nic_name: &str, tx_bps: u64) -> bool {
        self.npb_leaky_bucket.set_rate(Some(1));
        self.traffic_count.fuse_count.fetch_add(1, Relaxed);
        self.exception_handler.set(Exception::NpbFuse);
        warn!("Npb had fused {} tx bandwidth is {} bps.", nic_name, tx_bps);

        true
    }

    fn npb_start(&self, tx_bps: u64) -> bool {
        self.npb_leaky_bucket
            .set_rate(Some(self.npb_bps_threshold.load(Relaxed) / 8));
        self.exception_handler.clear(Exception::NpbFuse);
        info!("Npb reopen, tx bandwidth is {} bps.", tx_bps);

        false
    }

    fn run(&self) {
        let mut last_tx_bytes = 0;
        let mut npb_is_closed = false;
        let mut cycles = 0;
        let mut first = true;
        while self.is_running.load(Relaxed) {
            thread::sleep(Duration::from_secs(self.interval.load(Relaxed)));

            let interval = self.interval.load(Relaxed);
            let nic_bps_threshold = self.nic_bps_threshold.load(Relaxed);
            let Ok(tx_bps) = self.get_nic_bps(&mut last_tx_bytes, interval) else {
                self.traffic_count.tx_bps.store(0, Relaxed);
                continue;
            };
            if first && last_tx_bytes != 0 {
                first = false;
                continue;
            }
            self.traffic_count.tx_bps.store(tx_bps, Relaxed);

            if nic_bps_threshold == 0 {
                if npb_is_closed {
                    npb_is_closed = self.npb_start(tx_bps);
                }
                continue;
            }

            if tx_bps > nic_bps_threshold {
                if !npb_is_closed {
                    npb_is_closed = self.npb_stop(self.nic_name.read().unwrap().as_str(), tx_bps);
                }
            } else {
                let npb_bps_threshold = self.npb_bps_threshold.load(Relaxed);
                if nic_bps_threshold <= npb_bps_threshold {
                    continue;
                }
                if tx_bps < (nic_bps_threshold - npb_bps_threshold) * 90 / 100 {
                    if npb_is_closed {
                        cycles += 1;
                        if cycles >= Self::CHECK_CYCLES {
                            npb_is_closed = self.npb_start(tx_bps);
                            cycles = 0;
                        }
                    } else {
                        cycles = 0;
                    }
                } else {
                    cycles = 0;
                }
            }
        }
    }
}

pub struct NpbBandwidthWatcher {
    watcher: Arc<Watcher>,
    thread_handler: Mutex<Option<JoinHandle<()>>>,
}

impl NpbBandwidthWatcher {
    const BANDWIDTH_DEFAULT: u64 = 0;
    const BANDWIDTH_MAX: u64 = 100_000_000_000; // 100 Gbps
    const INTERVAL_DEFAULT: u64 = 10;
    const INTERVAL_MIN: u64 = 1;
    const INTERVAL_MAX: u64 = 60;

    pub fn new(
        interval: u64,
        npb_bps_threshold: u64,
        nic_bps_threshold: u64,
        npb_leaky_bucket: Arc<LeakyBucket>,
        exception_handler: ExceptionHandler,
    ) -> (Box<Arc<Self>>, Arc<InterfaceTraffic>) {
        let traffic_count = Arc::new(InterfaceTraffic::default());

        (
            Box::new(Arc::new(Self {
                watcher: Arc::new(Watcher {
                    nic_bps_threshold: AtomicU64::new(nic_bps_threshold),
                    npb_bps_threshold: AtomicU64::new(npb_bps_threshold),
                    interval: AtomicU64::new(interval),
                    ips: RwLock::new(vec![]),
                    npb_leaky_bucket,
                    nic_name: RwLock::new("".to_string()),
                    is_running: AtomicBool::new(false),
                    traffic_count: traffic_count.clone(),
                    exception_handler,
                }),
                thread_handler: Mutex::new(None),
            })),
            traffic_count,
        )
    }

    pub fn set_npb_rate(&self, threshold: u64) {
        self.watcher.npb_bps_threshold.store(threshold, Relaxed);
        self.watcher.npb_leaky_bucket.set_rate(Some(threshold));
    }

    pub fn set_nic_rate(&self, mut threshold: u64) {
        if threshold > Self::BANDWIDTH_MAX {
            info!(
                "Invalid npb bandwidth threshold {} set to default value {}",
                threshold,
                Self::BANDWIDTH_DEFAULT
            );
            threshold = Self::BANDWIDTH_DEFAULT
        }

        self.watcher.nic_bps_threshold.store(threshold, Relaxed);
    }

    pub fn set_interval(&self, mut interval: u64) {
        if interval < Self::INTERVAL_MIN || interval > Self::INTERVAL_MAX {
            info!(
                "Invalid interval {} set to default value {}",
                interval,
                Self::INTERVAL_DEFAULT
            );
            interval = Self::INTERVAL_DEFAULT;
        }
        self.watcher.interval.store(interval, Relaxed);
    }

    pub fn start(&self) {
        if self.watcher.is_running.load(Relaxed) || NOT_SUPPORT {
            return;
        }
        let watcher = self.watcher.clone();
        watcher.is_running.store(true, Relaxed);
        info!("Npb bandwidth watcher start with: npb bandwidth {}, npb nic bandwidth {}, interval {}.",
            watcher.npb_bps_threshold.load(Relaxed),
            watcher.nic_bps_threshold.load(Relaxed),
            watcher.interval.load(Relaxed),
        );
        self.thread_handler.lock().unwrap().replace(
            thread::Builder::new()
                .name("npb-bandwidth-watcher".to_owned())
                .spawn(move || {
                    watcher.run();
                })
                .unwrap(),
        );
    }

    pub fn notify_stop(&self) -> Option<JoinHandle<()>> {
        if !self.watcher.is_running.load(Relaxed) || NOT_SUPPORT {
            return None;
        }
        self.watcher.is_running.store(false, Relaxed);
        info!("Notify npb bandwidth watcher stop.");
        self.thread_handler.lock().unwrap().take()
    }

    pub fn stop(&self) {
        if !self.watcher.is_running.load(Relaxed) || NOT_SUPPORT {
            return;
        }
        self.watcher.is_running.store(false, Relaxed);
        if let Some(handler) = self.thread_handler.lock().unwrap().take() {
            let _ = handler.join();
        }
        info!("Npb bandwidth watcher stop.");
    }
}

impl FlowAclListener for Arc<NpbBandwidthWatcher> {
    fn flow_acl_change(
        &mut self,
        _trident_type: TridentType,
        _local_epc: i32,
        _ip_groups: &Vec<Arc<IpGroupData>>,
        _platform_data: &Vec<Arc<PlatformData>>,
        _peers: &Vec<Arc<PeerConnection>>,
        _cidrs: &Vec<Arc<Cidr>>,
        acls: &Vec<Arc<Acl>>,
    ) -> Result<(), String> {
        if NOT_SUPPORT {
            return Ok(());
        }

        let mut ips = vec![];
        acls.iter().for_each(|x| {
            for action in &x.npb_actions {
                if action.tunnel_type() == NpbTunnelType::GreErspan
                    || action.tunnel_type() == NpbTunnelType::VxLan
                {
                    ips.push(action.tunnel_ip());
                }
            }
        });
        ips.sort();
        ips.dedup();
        let mut last_ips = self.watcher.ips.write().unwrap();
        if last_ips.len() != ips.len() || !ips.iter().zip(last_ips.iter()).all(|x| x.0 == x.1) {
            *last_ips = ips;
            *self.watcher.nic_name.write().unwrap() = "".to_string();
        }
        Ok(())
    }

    fn id(&self) -> usize {
        1
    }
}
