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
    io::Error,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
        Arc, Mutex, Weak,
    },
    thread,
    time::SystemTime,
};

use arc_swap::access::Access;
use flate2::{write::ZlibEncoder, Compression};
use log::{error, info, warn};
use parking_lot::RwLock;
use reqwest;
use tokio::runtime::Runtime;

use crate::{
    config::handler::PlatformAccess,
    exception::ExceptionHandler,
    rpc::Session,
    trident::AgentId,
    utils::{
        environment::{running_in_container, running_in_only_watch_k8s_mode},
        stats::{self, Countable, Counter, CounterType, CounterValue, RefCountable, StatsOption},
    },
};

use public::{
    bytes::compress_entry,
    proto::{
        common::PrometheusApiInfo,
        trident::{Exception, PrometheusApiSyncRequest},
    },
};

const API_TARGETS_ENDPOINT: &str = "/api/v1/targets?state=active";
const API_CONFIG_ENDPOINT: &str = "/api/v1/status/config";

#[derive(Default)]
pub struct TargetsCounter {
    target_compressed_length: AtomicU32,
    config_compressed_length: AtomicU32,
}
impl RefCountable for TargetsCounter {
    fn get_counters(&self) -> Vec<Counter> {
        let target_compressed_length = self.target_compressed_length.swap(0, Ordering::Relaxed);
        let config_compressed_length = self.config_compressed_length.swap(0, Ordering::Relaxed);
        vec![
            (
                "target_compressed_length",
                CounterType::Gauged,
                CounterValue::Unsigned(target_compressed_length as u64),
            ),
            (
                "config_compressed_length",
                CounterType::Gauged,
                CounterValue::Unsigned(config_compressed_length as u64),
            ),
        ]
    }
}

struct Context {
    config: PlatformAccess,
    runtime: Arc<Runtime>,
    version: AtomicU64,
    client: Arc<reqwest::Client>,
}

pub struct TargetsWatcher {
    context: Arc<Context>,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
    running: Arc<AtomicBool>,
    session: Arc<Session>,
    exception_handler: ExceptionHandler,
    stats_collector: Arc<stats::Collector>,
    agent_id: Arc<RwLock<AgentId>>,
}

impl TargetsWatcher {
    pub fn new(
        runtime: Arc<Runtime>,
        config: PlatformAccess,
        agent_id: Arc<RwLock<AgentId>>,
        session: Arc<Session>,
        exception_handler: ExceptionHandler,
        stats_collector: Arc<stats::Collector>,
    ) -> Self {
        Self {
            context: Arc::new(Context {
                config,
                version: AtomicU64::new(
                    SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                ),
                runtime,
                client: Arc::new(reqwest::Client::new()),
            }),
            thread: Mutex::new(None),
            session,
            running: Arc::new(AtomicBool::new(false)),
            agent_id,
            exception_handler,
            stats_collector,
        }
    }

    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            info!("prometheus watcher has already stopped");
            return;
        }

        if let Some(handle) = self.thread.lock().unwrap().take() {
            let _ = handle.join();
        }
        info!("prometheus watcher is stopped");
    }

    pub fn start(&self) {
        info!("prometheus watcher is starting");
        let config_guard = self.context.config.load();
        // FIXME: The current default Prometheus deployed in k8s cluster, and shared kubernetes_api_enabled apiWatcher switches
        if (!config_guard.kubernetes_api_enabled && !running_in_only_watch_k8s_mode())
            || !running_in_container()
        {
            info!("did not turn on the kubernetes_api_enabled switch, or the environment is not suitable for the prometheus collection");
            return;
        }

        if config_guard.prometheus_http_api_addresses.is_empty() {
            info!(
                "prometheus watcher failed to start because prometheus_http_api_addresses are empty"
            );
            return;
        }

        if self.running.swap(true, Ordering::Relaxed) {
            info!("prometheus watcher has already running");
            return;
        }
        let mut context = self.context.clone();
        let counter = Arc::new(TargetsCounter::default());
        self.stats_collector.register_countable(
            "prometheus_targets_watcher",
            Countable::Ref(Arc::downgrade(&counter) as Weak<dyn RefCountable>),
            vec![StatsOption::Tag("kind", "prometheus_api".to_string())],
        );
        let session = self.session.clone();
        let running = self.running.clone();

        let agent_id = self.agent_id.clone();
        let exception_handler = self.exception_handler.clone();
        let interval = config_guard.sync_interval;
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());

        let handle = thread::Builder::new()
            .name("prometheus-target-watcher".to_owned())
            .spawn(move || {
                while running.load(Ordering::Relaxed) {
                    Self::process(
                        &mut context,
                        &mut counter.clone(),
                        &session,
                        &exception_handler,
                        &mut encoder,
                        &agent_id,
                    );
                    thread::sleep(interval);
                }
            })
            .unwrap();
        self.thread.lock().unwrap().replace(handle);
        info!("prometheus watcher is running");
    }

    fn process(
        context: &mut Arc<Context>,
        counter: &mut Arc<TargetsCounter>,
        session: &Arc<Session>,
        exception_handler: &ExceptionHandler,
        encoder: &mut ZlibEncoder<Vec<u8>>,
        agent_id: &Arc<RwLock<AgentId>>,
    ) {
        let config_guard = context.config.load();
        let api_addresses = config_guard.prometheus_http_api_addresses.clone();
        let mut total_entries = vec![];
        let mut err_msgs = vec![];
        for api in api_addresses {
            if api.is_empty() {
                continue;
            }
            let mut entry = PrometheusApiInfo::default();
            match Self::get_prometheus_api_info(
                context,
                api.clone() + API_TARGETS_ENDPOINT,
                encoder,
            ) {
                Ok(data) => {
                    counter
                        .target_compressed_length
                        .fetch_add(data.len() as u32, Ordering::Relaxed);
                    entry.target_compressed_info = Some(data);
                }
                Err(e) => {
                    warn!("get prometheus target info failed: {}", e);
                    err_msgs.push(e.to_string());
                    continue;
                }
            }
            match Self::get_prometheus_api_info(context, api + API_CONFIG_ENDPOINT, encoder) {
                Ok(data) => {
                    counter
                        .config_compressed_length
                        .fetch_add(data.len() as u32, Ordering::Relaxed);
                    entry.config_compressed_info = Some(data);
                }
                Err(e) => {
                    warn!("get prometheus config info failed: {}", e);
                    err_msgs.push(e.to_string());
                    continue;
                }
            }
            total_entries.push(entry);
        }

        if total_entries.is_empty() {
            info!("there has no prometheus target info or config info");
            return;
        }

        let version = &context.version;
        let pb_version = Some(version.load(Ordering::SeqCst));

        let msg = PrometheusApiSyncRequest {
            cluster_id: Some(config_guard.kubernetes_cluster_id.to_string()),
            version: pb_version,
            vtap_id: Some(config_guard.vtap_id as u32),
            source_ip: Some(agent_id.read().ip.to_string()),
            team_id: Some(String::new()),
            error_msg: Some(err_msgs.join(";")),
            entries: total_entries,
        };

        match context
            .runtime
            .block_on(session.grpc_prometheus_api_sync(msg))
        {
            Ok(_) => {
                version.fetch_add(1, Ordering::SeqCst);
            }
            Err(e) => {
                let err = format!("prometheus_api_sync grpc call failed: {}", e);
                exception_handler.set(Exception::ControllerSocketError);
                error!("{}", err);
            }
        }
    }

    fn get_prometheus_api_info(
        context: &mut Arc<Context>,
        api: String,
        encoder: &mut ZlibEncoder<Vec<u8>>,
    ) -> Result<Vec<u8>, Error> {
        context.runtime.block_on(async {
            compress_entry(
                encoder,
                context
                    .client
                    .get(api)
                    .send()
                    .await
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?
                    .text()
                    .await
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?
                    .as_bytes(),
            )
        })
    }
}
