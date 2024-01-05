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
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    thread,
    thread::JoinHandle,
    time::{Duration, SystemTime},
};

use arc_swap::access::Access;
use log::{debug, error, info};
use parking_lot::RwLock;
use ring::digest;
use tokio::runtime::Runtime;

use crate::{
    config::handler::PlatformAccess,
    exception::ExceptionHandler,
    rpc::Session,
    trident::AgentId,
    utils::command::{get_hostname, get_ip_address},
};
use public::proto::trident::{self, Exception};

const SHA1_DIGEST_LEN: usize = 20;

struct ProcessArgs {
    runtime: Arc<Runtime>,
    config: PlatformAccess,
    running: Arc<Mutex<bool>>,
    version: Arc<AtomicU64>,
    session: Arc<Session>,
    timer: Arc<Condvar>,
    exception_handler: ExceptionHandler,
    override_os_hostname: Arc<Option<String>>,
    agent_id: Arc<RwLock<AgentId>>,
}

#[derive(Default)]
struct PlatformArgs {
    raw_hostname: Option<String>,
    raw_ip_addr: Option<String>,
}

#[derive(Default)]
struct HashArgs {
    raw_info_hash: [u8; SHA1_DIGEST_LEN],
}

pub struct PlatformSynchronizer {
    runtime: Arc<Runtime>,
    config: PlatformAccess,
    agent_id: Arc<RwLock<AgentId>>,
    version: Arc<AtomicU64>,
    running: Arc<Mutex<bool>>,
    timer: Arc<Condvar>,
    thread: Mutex<Option<JoinHandle<()>>>,
    session: Arc<Session>,
    exception_handler: ExceptionHandler,
    override_os_hostname: Arc<Option<String>>,
}

impl PlatformSynchronizer {
    pub fn new(
        runtime: Arc<Runtime>,
        config: PlatformAccess,
        agent_id: Arc<RwLock<AgentId>>,
        session: Arc<Session>,
        exception_handler: ExceptionHandler,
        override_os_hostname: Option<String>,
    ) -> Self {
        Self {
            runtime,
            config,
            agent_id,
            version: Arc::new(AtomicU64::new(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )),
            running: Arc::new(Mutex::new(false)),
            timer: Arc::new(Condvar::new()),
            thread: Mutex::new(None),
            session,
            exception_handler,
            override_os_hostname: Arc::new(override_os_hostname),
        }
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
                "PlatformSynchronizer has already stopped with agent-id:{} vtap-id:{}",
                self.agent_id.read(),
                config_guard.vtap_id
            );
            debug!("{}", err);
            return;
        }
        *running_guard = true;
        drop(running_guard);

        let process_args = ProcessArgs {
            runtime: self.runtime.clone(),
            config: self.config.clone(),
            agent_id: self.agent_id.clone(),
            running: self.running.clone(),
            version: self.version.clone(),
            timer: self.timer.clone(),
            session: self.session.clone(),
            exception_handler: self.exception_handler.clone(),
            override_os_hostname: self.override_os_hostname.clone(),
        };

        let handle = thread::Builder::new()
            .name("platform-synchronizer".to_owned())
            .spawn(move || Self::process(process_args))
            .unwrap();
        *self.thread.lock().unwrap() = Some(handle);

        info!("PlatformSynchronizer started");
    }

    fn query_platform(
        platform_args: &mut PlatformArgs,
        hash_args: &mut HashArgs,
        process_args: &ProcessArgs,
    ) {
        let mut changed = 0;

        let mut hash_handle = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);

        let raw_hostname = process_args
            .override_os_hostname
            .as_ref()
            .clone()
            .or_else(|| match get_hostname() {
                Ok(name) => Some(name),
                Err(e) => {
                    debug!("get_hostname error: {}", e);
                    None
                }
            });
        if let Some(hostname) = raw_hostname.as_ref() {
            hash_handle.update(hostname.as_bytes());
        }

        let raw_host_ip_addr = get_ip_address()
            .map_err(|err| debug!("get_ip_address error:{}", err))
            .ok();

        if let Some(ip_addr) = raw_host_ip_addr.as_ref() {
            for line in ip_addr.lines() {
                // 忽略可能变化的行避免version频繁更新
                if line.contains("valid_lft") {
                    continue;
                }
                hash_handle.update(line.as_bytes());
            }
        }

        let hash_sum = hash_handle.finish();
        let raw_info_hash = hash_sum.as_ref();
        if raw_info_hash != hash_args.raw_info_hash {
            debug!("raw info changed");
            changed += 1;
        }

        if changed > 0 {
            if raw_info_hash != hash_args.raw_info_hash {
                hash_args.raw_info_hash.copy_from_slice(raw_info_hash);
                platform_args.raw_hostname = raw_hostname;
                platform_args.raw_ip_addr = raw_host_ip_addr;
            }

            info!(
                "Platform information changed to version {}",
                process_args.version.fetch_add(1, Ordering::SeqCst) + 1
            );
        }
    }

    fn push_platform_message(
        platform_args: &PlatformArgs,
        process_args: &ProcessArgs,
        vtap_id: u16,
        version: u64,
    ) -> Result<u64, tonic::Status> {
        let config_guard = process_args.config.load();
        let trident_type = config_guard.trident_type;
        let ctrl_ip = process_args.agent_id.read().ip.to_string();
        let platform_enabled = config_guard.enabled;
        drop(config_guard);

        let platform_data = trident::GenesisPlatformData {
            platform_enabled: Some(platform_enabled),
            raw_hostname: platform_args.raw_hostname.clone(),
            raw_ip_addrs: vec![platform_args.raw_ip_addr.clone().unwrap_or_default()],
            ..Default::default()
        };

        let msg = trident::GenesisSyncRequest {
            version: Some(version),
            trident_type: Some(trident_type as i32),
            platform_data: Some(platform_data),
            source_ip: Some(ctrl_ip),
            vtap_id: Some(vtap_id as u32),
            kubernetes_cluster_id: Some(
                process_args.config.load().kubernetes_cluster_id.to_string(),
            ),
            ..Default::default()
        };

        process_args
            .runtime
            .block_on(process_args.session.grpc_genesis_sync_with_statsd(msg))
            .map(|r| r.into_inner().version())
    }

    fn process(args: ProcessArgs) {
        let mut last_version = 0;
        let init_version = args.version.load(Ordering::Relaxed);

        let mut hash_args = HashArgs::default();
        let mut platform_args = PlatformArgs::default();

        loop {
            Self::query_platform(&mut platform_args, &mut hash_args, &args);

            let cur_version = args.version.load(Ordering::SeqCst);

            let config_guard = args.config.load();
            let cur_vtap_id = config_guard.vtap_id;
            let trident_type = config_guard.trident_type;
            let ctrl_ip = args.agent_id.read().ip.to_string();
            let poll_interval = config_guard.sync_interval;
            drop(config_guard);

            if cur_version == init_version {
                // 避免信息同步先于信息采集
                // ====
                // wait 5 seconds to check version change
                if Self::wait_timeout(&args.running, &args.timer, Duration::from_secs(5)) {
                    break;
                }
                continue;
            }

            if last_version == cur_version {
                let msg = trident::GenesisSyncRequest {
                    version: Some(cur_version),
                    trident_type: Some(trident_type as i32),
                    source_ip: Some(ctrl_ip),
                    vtap_id: Some(cur_vtap_id as u32),
                    kubernetes_cluster_id: Some(
                        args.config.load().kubernetes_cluster_id.to_string(),
                    ),
                    ..Default::default()
                };

                match args
                    .runtime
                    .block_on(args.session.grpc_genesis_sync_with_statsd(msg))
                {
                    Ok(res) => {
                        let res = res.into_inner();
                        let remote_version = res.version();
                        if remote_version == cur_version {
                            if Self::wait_timeout(&args.running, &args.timer, poll_interval) {
                                break;
                            }
                            continue;
                        }
                        info!(
                            "local version {}, remote version {}",
                            cur_version, remote_version
                        );
                    }
                    Err(e) => {
                        args.exception_handler.set(Exception::ControllerSocketError);
                        error!(
                            "send platform heartbeat with genesis_sync grpc call failed: {}",
                            e
                        );
                        if Self::wait_timeout(&args.running, &args.timer, poll_interval) {
                            break;
                        }
                        continue;
                    }
                }
            } else {
                info!("local version changed to {}", cur_version);
            }

            match Self::push_platform_message(&platform_args, &args, cur_vtap_id, cur_version) {
                Ok(version) => last_version = version,
                Err(e) => {
                    args.exception_handler.set(Exception::ControllerSocketError);
                    error!(
                        "send platform information with genesis_sync grpc call failed: {}",
                        e
                    );
                    if Self::wait_timeout(&args.running, &args.timer, poll_interval) {
                        break;
                    }
                    continue;
                }
            }

            if Self::wait_timeout(&args.running, &args.timer, poll_interval) {
                break;
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
