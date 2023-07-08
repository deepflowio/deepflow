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
    rpc::{RunningConfig, Session},
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

#[derive(Default)]
pub struct TargetsCounter {
    compressed_length: AtomicU32,
}
impl RefCountable for TargetsCounter {
    fn get_counters(&self) -> Vec<Counter> {
        let compressed_length = self.compressed_length.swap(0, Ordering::Relaxed);
        vec![(
            "compressed_length",
            CounterType::Gauged,
            CounterValue::Unsigned(compressed_length as u64),
        )]
    }
}

struct Context {
    config: PlatformAccess,
    runtime: Arc<Runtime>,
    version: AtomicU64,
    client: Arc<reqwest::Client>,
    stats_counter: Arc<TargetsCounter>,
}

pub struct TargetsWatcher {
    context: Arc<Context>,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
    running: Arc<AtomicBool>,
    session: Arc<Session>,
    exception_handler: ExceptionHandler,
    stats_collector: Arc<stats::Collector>,
    running_config: Arc<RwLock<RunningConfig>>,
}

impl TargetsWatcher {
    pub fn new(
        runtime: Arc<Runtime>,
        config: PlatformAccess,
        running_config: Arc<RwLock<RunningConfig>>,
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
                stats_counter: Default::default(),
            }),
            thread: Mutex::new(None),
            session,
            running: Arc::new(AtomicBool::new(false)),
            running_config,
            exception_handler,
            stats_collector,
        }
    }

    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            info!("prometheus watcher  has already stopped");
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

        if config_guard.prometheus_http_api_address.is_empty() {
            info!(
                "prometheus watcher failed to start because prometheus_http_api_address is empty"
            );
            return;
        }

        if self.running.swap(true, Ordering::Relaxed) {
            info!("prometheus watcher has already running");
            return;
        }
        let mut context = self.context.clone();
        self.stats_collector.register_countable(
            "prometheus_targets_watcher",
            Countable::Ref(Arc::downgrade(&context.stats_counter) as Weak<dyn RefCountable>),
            vec![StatsOption::Tag("kind", API_TARGETS_ENDPOINT.to_string())],
        );
        let session = self.session.clone();
        let running = self.running.clone();

        let running_config = self.running_config.clone();
        let exception_handler = self.exception_handler.clone();
        let interval = config_guard.sync_interval;
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());

        let handle = thread::Builder::new()
            .name("prometheus-target-watcher".to_owned())
            .spawn(move || {
                while running.load(Ordering::Relaxed) {
                    Self::process(
                        &mut context,
                        &session,
                        &exception_handler,
                        &mut encoder,
                        &running_config,
                    );
                    thread::sleep(interval);
                }
            })
            .unwrap();
        self.thread.lock().unwrap().replace(handle);
        info!("prometheus watcher is running");
    }

    pub fn reset_session(&self, controller_ips: Vec<String>) {
        self.session.reset_server_ip(controller_ips);
    }

    fn process(
        context: &mut Arc<Context>,
        session: &Arc<Session>,
        exception_handler: &ExceptionHandler,
        encoder: &mut ZlibEncoder<Vec<u8>>,
        running_config: &Arc<RwLock<RunningConfig>>,
    ) {
        let config_guard = context.config.load();
        let api = config_guard.prometheus_http_api_address.clone() + API_TARGETS_ENDPOINT;

        let mut total_entries = vec![];
        let mut err_msgs = vec![];

        context.runtime.block_on(async {
            match context.client.get(api).send().await {
                Ok(resp) => {
                    match resp.text().await {
                        Ok(body) => {
                            match compress_entry(encoder, body.trim().as_bytes()) {
                                Ok(data) => {
                                    context
                                        .stats_counter
                                        .compressed_length
                                        .fetch_add(data.len() as u32, Ordering::Relaxed);
                                    let entry = PrometheusApiInfo {
                                        r#type: Some(API_TARGETS_ENDPOINT.to_string()),
                                        compressed_info: Some(data),
                                    };
                                    total_entries.push(entry);
                                }
                                Err(e) => {
                                    warn!("{}", e);
                                    err_msgs.push(e.to_string());
                                }
                            };
                        }
                        Err(e) => {
                            warn!("{}", e);
                            err_msgs.push(e.to_string());
                        }
                    };
                }
                Err(e) => {
                    warn!("{}", e);
                    err_msgs.push(e.to_string());
                }
            }
        });

        let version = &context.version;
        let pb_version = Some(version.load(Ordering::SeqCst));

        let msg = PrometheusApiSyncRequest {
            cluster_id: Some(config_guard.kubernetes_cluster_id.to_string()),
            version: pb_version,
            vtap_id: Some(config_guard.vtap_id as u32),
            source_ip: Some(running_config.read().ctrl_ip.clone()),
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
}
