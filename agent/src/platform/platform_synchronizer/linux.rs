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
    net::{IpAddr, SocketAddr, SocketAddrV4},
    sync::{Arc, Condvar, Mutex, MutexGuard},
    thread,
    time::Duration,
};

use arc_swap::access::Access;
use log::{error, info, warn};
use parking_lot::RwLock;
use tokio::runtime::Runtime;

use crate::{
    common::policy::GpidEntry,
    config::handler::PlatformAccess,
    policy::{PolicyGetter, PolicySetter},
    rpc::Session,
    trident::AgentId,
    utils::lru::Lru,
};
use public::{
    proto::trident::{GpidSyncRequest, GpidSyncResponse},
    queue::Receiver,
};

use super::{
    linux_socket::{get_all_socket, Role, SockAddrData},
    process_info_enabled,
};

pub struct SocketSynchronizer {
    runtime: Arc<Runtime>,
    config: PlatformAccess,
    agent_id: Arc<RwLock<AgentId>>,
    stop_notify: Arc<Condvar>,
    session: Arc<Session>,
    running: Arc<Mutex<bool>>,
    policy_getter: Arc<Mutex<PolicyGetter>>,
    policy_setter: PolicySetter,
    lru_toa_info: Arc<Mutex<Lru<SocketAddr, SocketAddr>>>,
}

impl SocketSynchronizer {
    pub fn new(
        runtime: Arc<Runtime>,
        config: PlatformAccess,
        agent_id: Arc<RwLock<AgentId>>,
        policy_getter: Arc<Mutex<PolicyGetter>>,
        policy_setter: PolicySetter,
        session: Arc<Session>,
        // toa info, Receiver<Box<LocalAddr, RealAddr>>
        // receiver from SubQuadGen::inject_flow()
        receiver: Receiver<Box<(SocketAddr, SocketAddr)>>,
        // toa info cache, Lru<LocalAddr, RealAddr>
        lru_toa_info: Arc<Mutex<Lru<SocketAddr, SocketAddr>>>,
    ) -> Self {
        if process_info_enabled(config.load().trident_type) {
            let lru_toa_info_clone = lru_toa_info.clone();
            thread::Builder::new()
                .name("socket-synchronizer-toa-recv".to_string())
                .spawn(|| {
                    Self::sync_toa(lru_toa_info_clone, receiver);
                })
                .unwrap();
        }

        Self {
            runtime,
            config,
            agent_id,
            policy_getter,
            policy_setter,
            stop_notify: Arc::new(Condvar::new()),
            session,
            running: Arc::new(Mutex::new(false)),
            lru_toa_info,
        }
    }

    pub fn start(&mut self) {
        let conf_guard = self.config.load();
        if !process_info_enabled(conf_guard.trident_type) {
            return;
        }

        let mut running_guard = self.running.lock().unwrap();
        if *running_guard {
            warn!("socket sync is running");
            return;
        }

        let (
            runtime,
            running,
            config,
            agent_id,
            policy_getter,
            policy_setter,
            session,
            stop_notify,
            lru_toa_info,
        ) = (
            self.runtime.clone(),
            self.running.clone(),
            self.config.clone(),
            self.agent_id.clone(),
            self.policy_getter.clone(),
            self.policy_setter,
            self.session.clone(),
            self.stop_notify.clone(),
            self.lru_toa_info.clone(),
        );

        thread::Builder::new()
            .name("socket-synchronizer".to_string())
            .spawn(move || {
                Self::run(
                    runtime,
                    running,
                    config,
                    agent_id,
                    policy_getter,
                    policy_setter,
                    session,
                    stop_notify,
                    lru_toa_info,
                )
            })
            .unwrap();
        *running_guard = true;

        info!("socket info sync start");
    }

    fn run(
        runtime: Arc<Runtime>,
        running: Arc<Mutex<bool>>,
        config: PlatformAccess,
        agent_id: Arc<RwLock<AgentId>>,
        policy_getter: Arc<Mutex<PolicyGetter>>,
        policy_setter: PolicySetter,
        session: Arc<Session>,
        stop_notify: Arc<Condvar>,
        lru_toa_info: Arc<Mutex<Lru<SocketAddr, SocketAddr>>>,
    ) {
        let mut last_entries: Vec<GpidEntry> = vec![];

        loop {
            let running_guard = running.lock().unwrap();
            let sync_interval;

            {
                let conf_guard = config.load();
                sync_interval = Duration::from_secs(
                    conf_guard.os_proc_scan_conf.os_proc_socket_sync_interval as u64,
                );

                // wait for config from server
                if !conf_guard.os_proc_scan_conf.os_proc_sync_enabled {
                    if !Self::wait_timeout(running_guard, stop_notify.clone(), sync_interval) {
                        return;
                    }
                    continue;
                }

                let (ctrl_ip, ctrl_mac, team_id) = {
                    let id = agent_id.read();
                    (id.ip.to_string(), id.mac.to_string(), id.team_id.clone())
                };
                let mut policy_getter = policy_getter.lock().unwrap();

                let sock_entries = match get_all_socket(
                    &conf_guard.os_proc_scan_conf,
                    &mut policy_getter,
                    conf_guard.epc_id,
                ) {
                    Err(e) => {
                        error!("fetch socket info fail: {}", e);
                        if !Self::wait_timeout(running_guard, stop_notify.clone(), sync_interval) {
                            return;
                        }
                        continue;
                    }
                    Ok(mut res) => {
                        // fill toa
                        let mut lru_toa = lru_toa_info.lock().unwrap();
                        for se in res.iter_mut() {
                            if se.role == Role::Server {
                                // the client addr
                                let sa = match se.remote.ip {
                                    IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(
                                        v4.clone(),
                                        se.remote.port,
                                    )),
                                    _ => continue,
                                };
                                // get real addr by client addr from toa
                                if let Some(real_addr) = lru_toa.get_mut(&sa) {
                                    se.real_client = Some(SockAddrData {
                                        epc_id: 0,
                                        ip: real_addr.ip(),
                                        port: real_addr.port(),
                                    });
                                }
                            }
                        }
                        res
                    }
                };

                match runtime.block_on(
                    session.gpid_sync(GpidSyncRequest {
                        ctrl_ip: Some(ctrl_ip),
                        ctrl_mac: Some(ctrl_mac),
                        team_id: Some(team_id),
                        vtap_id: Some(conf_guard.vtap_id as u32),
                        entries: sock_entries
                            .into_iter()
                            .filter_map(|sock| {
                                if let Ok(e) = sock.try_into() {
                                    Some(e)
                                } else {
                                    None
                                }
                            })
                            .collect(),
                        // TODO compress_algorithm
                        ..Default::default()
                    }),
                ) {
                    Err(e) => error!("gpid sync fail: {}", e),
                    Ok(response) => {
                        let response: GpidSyncResponse = response.into_inner();
                        let mut current_entries = vec![];
                        for entry in response.entries.iter() {
                            let e = GpidEntry::try_from(entry);
                            if e.is_err() {
                                warn!("{:?}", e);
                                continue;
                            }
                            current_entries.push(e.unwrap());
                        }

                        if current_entries != last_entries {
                            policy_setter.update_gpids(&current_entries);
                            last_entries = current_entries
                        }
                    }
                }
            }

            if !Self::wait_timeout(running_guard, stop_notify.clone(), sync_interval) {
                return;
            }
        }
    }

    pub fn stop(&mut self) {
        let conf_guard = self.config.load();
        if !process_info_enabled(conf_guard.trident_type) {
            return;
        }

        let mut running_guard = self.running.lock().unwrap();
        if !*running_guard {
            warn!("socket info sync not running");
            return;
        }
        *running_guard = false;
        self.stop_notify.notify_one();
        info!("socket info sync stop");
    }

    fn wait_timeout(guard: MutexGuard<bool>, stop_notify: Arc<Condvar>, timeout: Duration) -> bool {
        *(stop_notify.wait_timeout(guard, timeout).unwrap().0)
    }

    fn sync_toa(
        lru_toa_info: Arc<Mutex<Lru<SocketAddr, SocketAddr>>>,
        receive: Receiver<Box<(SocketAddr, SocketAddr)>>,
    ) {
        while let Ok(toa_info) = receive.recv(None) {
            let (client, real) = (toa_info.0, toa_info.1);
            let mut lru_toa = lru_toa_info.lock().unwrap();
            lru_toa.put(client, real);
        }
        info!("toa sync queue close");
    }
}

mod config {
    use public::proto::common;
    pub struct StaticConfig;
    impl StaticConfig {
        pub fn get_trident_type(&self) -> common::TridentType {
            todo!()
        }

        pub fn is_tt_pod(&self) -> bool {
            todo!()
        }
    }
}

mod sniffer_builder {
    use std::time::Duration;

    use crate::handler::{IpInfo, LldpInfo};

    pub struct Sniffer;

    impl Sniffer {
        pub fn get_ip_records(&self) -> (Duration, Vec<IpInfo>) {
            (Duration::ZERO, vec![])
        }

        pub fn get_lldp_records(&self) -> Vec<LldpInfo> {
            vec![]
        }
    }
}
