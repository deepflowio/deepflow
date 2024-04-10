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

#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    sync::{Arc, Condvar, Mutex},
    thread,
    thread::JoinHandle,
    time::{Duration, SystemTime},
};

use arc_swap::access::Access;
use log::{debug, error, info};
use parking_lot::RwLock;

use tokio::runtime::Runtime;

#[cfg(target_os = "linux")]
use crate::platform::{kubernetes::GenericPoller, LibvirtXmlExtractor};
use crate::{
    config::handler::PlatformAccess, exception::ExceptionHandler, rpc::Session, trident::AgentId,
};

use public::proto::trident::{self, Exception};

use super::querier::Querier;

struct Interior {
    running: Arc<Mutex<bool>>,
    timer: Arc<Condvar>,

    config: PlatformAccess,
    override_os_hostname: Option<String>,
    agent_id: Arc<RwLock<AgentId>>,
    runtime: Arc<Runtime>,
    session: Arc<Session>,
    exception_handler: ExceptionHandler,

    #[cfg(target_os = "linux")]
    kubernetes_poller_updated: Arc<AtomicBool>,
    #[cfg(target_os = "linux")]
    kubernetes_poller: Arc<Mutex<Option<Arc<GenericPoller>>>>,

    #[cfg(target_os = "linux")]
    xml_extractor: Arc<LibvirtXmlExtractor>,

    version: u64,
    peer_version: u64,
    digest: u64,
}

pub struct Synchronizer {
    running: Arc<Mutex<bool>>,
    timer: Arc<Condvar>,
    thread: Mutex<Option<JoinHandle<()>>>,

    config: PlatformAccess,
    override_os_hostname: Option<String>,
    agent_id: Arc<RwLock<AgentId>>,
    runtime: Arc<Runtime>,
    exception_handler: ExceptionHandler,
    session: Arc<Session>,

    #[cfg(target_os = "linux")]
    kubernetes_poller_updated: Arc<AtomicBool>,
    #[cfg(target_os = "linux")]
    kubernetes_poller: Arc<Mutex<Option<Arc<GenericPoller>>>>,

    #[cfg(target_os = "linux")]
    xml_extractor: Arc<LibvirtXmlExtractor>,
}

impl Synchronizer {
    pub fn new(
        runtime: Arc<Runtime>,
        config: PlatformAccess,
        override_os_hostname: Option<String>,
        agent_id: Arc<RwLock<AgentId>>,
        session: Arc<Session>,
        #[cfg(target_os = "linux")] xml_extractor: Arc<LibvirtXmlExtractor>,
        exception_handler: ExceptionHandler,
    ) -> Self {
        Self {
            running: Arc::new(Mutex::new(false)),
            timer: Arc::new(Condvar::new()),
            thread: Mutex::new(None),

            config,
            override_os_hostname,
            agent_id,
            session,
            exception_handler,
            runtime,

            #[cfg(target_os = "linux")]
            kubernetes_poller_updated: Default::default(),
            #[cfg(target_os = "linux")]
            kubernetes_poller: Default::default(),
            #[cfg(target_os = "linux")]
            xml_extractor,
        }
    }

    #[cfg(target_os = "linux")]
    pub fn set_kubernetes_poller(&self, poller: Arc<GenericPoller>) {
        info!("updating kubernetes poller");
        self.kubernetes_poller.lock().unwrap().replace(poller);
        self.kubernetes_poller_updated
            .store(true, Ordering::Release);
    }

    pub fn is_running(&self) -> bool {
        *self.running.lock().unwrap()
    }

    pub fn stop(&self) {
        let mut running_lock = self.running.lock().unwrap();
        if !*running_lock {
            let config_guard = self.config.load();
            let err = format!(
                "PlatformSynchronizer has already stopped with agent-id:{} vtap-id:{}",
                self.agent_id.read(),
                config_guard.vtap_id
            );
            debug!("{}", err);
            return;
        }
        *running_lock = false;
        drop(running_lock);

        self.timer.notify_one();
        if let Some(handle) = self.thread.lock().unwrap().take() {
            let _ = handle.join();
        }

        info!("PlatformSynchronizer stopped");
    }

    pub fn start(&self) {
        let mut running_guard = self.running.lock().unwrap();
        if *running_guard {
            let config_guard = self.config.load();
            let err = format!(
                "PlatformSynchronizer has already running with agent-id:{} vtap-id:{}",
                self.agent_id.read(),
                config_guard.vtap_id
            );
            debug!("{}", err);
            return;
        }
        *running_guard = true;
        drop(running_guard);

        let interior = Interior {
            running: self.running.clone(),
            timer: self.timer.clone(),

            config: self.config.clone(),
            override_os_hostname: self.override_os_hostname.clone(),
            agent_id: self.agent_id.clone(),
            runtime: self.runtime.clone(),
            session: self.session.clone(),
            exception_handler: self.exception_handler.clone(),

            #[cfg(target_os = "linux")]
            kubernetes_poller_updated: self.kubernetes_poller_updated.clone(),
            #[cfg(target_os = "linux")]
            kubernetes_poller: self.kubernetes_poller.clone(),

            #[cfg(target_os = "linux")]
            xml_extractor: self.xml_extractor.clone(),

            version: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            peer_version: 0,
            digest: 0,
        };

        let handle = thread::Builder::new()
            .name("platform-synchronizer".to_owned())
            .spawn(move || Self::process(interior))
            .unwrap();
        *self.thread.lock().unwrap() = Some(handle);

        info!("PlatformSynchronizer started");
    }

    fn process(mut args: Interior) {
        let init_version = args.version;

        let mut querier = Querier::new(
            args.override_os_hostname.clone(),
            #[cfg(target_os = "linux")]
            args.xml_extractor.clone(),
        );

        'outer: loop {
            let config = args.config.load();
            let (ctrl_ip, team_id) = {
                let id = args.agent_id.read();
                (id.ip.to_string(), id.team_id.clone())
            };

            #[cfg(target_os = "linux")]
            if args
                .kubernetes_poller_updated
                .swap(false, Ordering::Acquire)
            {
                if let Some(poller) = args.kubernetes_poller.lock().unwrap().clone() {
                    info!("updated kubernetes poller");
                    querier.set_kubernetes_poller(poller);
                }
            }

            let digest = querier.update(&config);
            if args.digest != digest {
                args.digest = digest;
                args.version += 1;
                info!("Platform information changed to version {}", args.version);
            }

            if args.version == init_version {
                // 避免信息同步先于信息采集
                // ====
                // wait 5 seconds to check version change
                if Self::wait_timeout(&args.running, &args.timer, Duration::from_secs(5)) {
                    break;
                }
                continue;
            }

            loop {
                let msg = if args.version == args.peer_version {
                    trident::GenesisSyncRequest {
                        version: Some(args.version),
                        trident_type: Some(config.trident_type as i32),
                        source_ip: Some(ctrl_ip.clone()),
                        vtap_id: Some(config.vtap_id as u32),
                        kubernetes_cluster_id: Some(config.kubernetes_cluster_id.clone()),
                        team_id: Some(team_id.clone()),
                        ..Default::default()
                    }
                } else {
                    info!("local version is {}, will send whole message", args.version);
                    trident::GenesisSyncRequest {
                        version: Some(args.version),
                        trident_type: Some(config.trident_type as i32),
                        source_ip: Some(ctrl_ip.clone()),
                        vtap_id: Some(config.vtap_id as u32),
                        kubernetes_cluster_id: Some(config.kubernetes_cluster_id.clone()),
                        team_id: Some(team_id.clone()),
                        ..querier.generate_message(&config)
                    }
                };

                debug!(
                    "syncing version {} -> {} to remote",
                    args.version, args.peer_version
                );
                match args
                    .runtime
                    .block_on(args.session.grpc_genesis_sync_with_statsd(msg))
                {
                    Ok(res) => {
                        let res = res.into_inner();
                        args.peer_version = res.version();
                        if args.version != args.peer_version {
                            // resync when versions mismatch
                            info!(
                                "local version {}, remote version {}, about to resync",
                                args.version, args.peer_version
                            );
                            continue;
                        } else {
                            if Self::wait_timeout(&args.running, &args.timer, config.sync_interval)
                            {
                                break 'outer;
                            }
                            continue 'outer;
                        }
                    }
                    Err(e) => {
                        args.exception_handler.set(Exception::ControllerSocketError);
                        error!(
                            "send platform {} with genesis_sync grpc call failed: {}",
                            if args.version == args.peer_version {
                                "heartbeat"
                            } else {
                                "information"
                            },
                            e
                        );
                        if Self::wait_timeout(&args.running, &args.timer, config.sync_interval) {
                            break 'outer;
                        }
                        continue 'outer;
                    }
                }
            }
        }
    }

    fn wait_timeout(running: &Arc<Mutex<bool>>, timer: &Arc<Condvar>, interval: Duration) -> bool {
        let guard = running.lock().unwrap();
        if !*guard {
            return true;
        }
        let (guard, _) = timer.wait_timeout(guard, interval).unwrap();
        if !*guard {
            return true;
        }
        false
    }
}
