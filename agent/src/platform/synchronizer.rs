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

use crate::{
    config::handler::PlatformAccess, exception::ExceptionHandler, rpc::Session, trident::AgentId,
};
#[cfg(target_os = "linux")]
use crate::{
    platform::{
        kubernetes::GenericPoller,
        platform_synchronizer::linux_process::set_proc_scan_process_datas, LibvirtXmlExtractor,
    },
    utils::process::ProcessListener,
};

use public::proto::agent::{self, Exception};

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
    #[cfg(any(target_os = "linux", target_os = "android"))]
    process_listener: Option<Arc<ProcessListener>>,
}

impl Synchronizer {
    const VERSION_CHANGE_RESYNC_INTERVAL: Duration = Duration::from_secs(1);

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
            #[cfg(any(target_os = "linux", target_os = "android"))]
            process_listener: None,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn set_process_listener(&self, process_listener: &Arc<ProcessListener>) {
        process_listener.register("proc.gprocess_info", set_proc_scan_process_datas);
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
        debug!("PlatformSynchronizer stopping");

        let mut running_lock = self.running.lock().unwrap();
        if !*running_lock {
            let config_guard = self.config.load();
            let err = format!(
                "PlatformSynchronizer has already stopped with agent-id:{} vtap-id:{}",
                self.agent_id.read(),
                config_guard.agent_id
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
                config_guard.agent_id
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
            let agent_id: agent::AgentId = (&*args.agent_id.read()).into();

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
                if !Self::wait_for_running(&args.running, &args.timer, Duration::from_secs(5)) {
                    break;
                }
                continue;
            }

            loop {
                let msg = agent::GenesisSyncRequest {
                    version: Some(args.version),
                    agent_type: Some(config.agent_type as i32),
                    source_ip: agent_id.ip.clone(),
                    agent_id: Some(config.agent_id as u32),
                    kubernetes_cluster_id: Some(config.kubernetes_cluster_id.clone()),
                    team_id: agent_id.team_id.clone(),
                    agent_info: Some(agent_id.clone()),
                    ..if args.version == args.peer_version {
                        Default::default()
                    } else {
                        info!("local version is {}, will send whole message", args.version);
                        querier.generate_message(&config)
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
                            // server in initial state will return version 0, wait longer in this situation
                            // otherwise (maybe a server switch), wait for a short time to avoid too frequent resync
                            let wait_interval = if args.peer_version == 0 {
                                config.sync_interval
                            } else {
                                Self::VERSION_CHANGE_RESYNC_INTERVAL
                            };
                            if !Self::wait_for_running(&args.running, &args.timer, wait_interval) {
                                break 'outer;
                            }
                            // resync when versions mismatch
                            info!(
                                "local version {}, remote version {}, about to resync",
                                args.version, args.peer_version
                            );
                            continue;
                        } else {
                            if !Self::wait_for_running(
                                &args.running,
                                &args.timer,
                                config.sync_interval,
                            ) {
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
                        if !Self::wait_for_running(&args.running, &args.timer, config.sync_interval)
                        {
                            break 'outer;
                        }
                        continue 'outer;
                    }
                }
            }
        }
    }

    // returns running status
    fn wait_for_running(running: &Mutex<bool>, timer: &Condvar, interval: Duration) -> bool {
        let guard = running.lock().unwrap();
        if !*guard {
            return *guard;
        }
        *timer.wait_timeout(guard, interval).unwrap().0
    }
}
