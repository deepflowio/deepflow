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

use std::net::IpAddr;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Weak,
};
use std::time::{Duration, Instant};

use log::{debug, error, info};
use parking_lot::RwLock;
use rand::Rng;
use tokio::sync::Semaphore;
use tonic::transport::{Channel, Endpoint};

use crate::common::{DEFAULT_CONTROLLER_PORT, DEFAULT_CONTROLLER_TLS_PORT};
use crate::exception::ExceptionHandler;
use crate::proto::trident::{self, Exception};
use crate::utils::stats::{self, AtomicTimeStats, StatsOption};

use public::counter::{Countable, Counter, CounterType, CounterValue, RefCountable};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
// Sessions in use occasionally timeout for 60 seconds, The
// timeout should be adjusted to be greater than 60 seconds.
// ==========================================================
// 使用中会话偶尔会超时60秒，这里调整超时时间需要大于60秒
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(120);

const GRPC_CALL_ENDPOINTS: [&str; 7] = [
    "push",
    "query",
    "upgrade",
    "sync",
    "genesis_sync",
    "kubernetes_api_sync",
    "get_kubernetes_cluster_id",
];

const PUSH_ENDPOINT: usize = 0;
const QUERY_ENDPOINT: usize = 1;
const UPGRADE_ENDPOINT: usize = 2;
const SYNC_ENDPOINT: usize = 3;
const GENESIS_SYNC_ENDPOINT: usize = 4;
const KUBERNETES_API_SYNC_ENDPOINT: usize = 5;
const GET_KUBERNETES_CLUSTER_ID_ENDPOINT: usize = 6;

struct Config {
    port: u16,
    tls_port: u16,
    proxy_port: u16,
    timeout: Duration,
    controller_cert_file_prefix: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            port: DEFAULT_CONTROLLER_PORT,
            tls_port: DEFAULT_CONTROLLER_TLS_PORT,
            proxy_port: DEFAULT_CONTROLLER_PORT,
            timeout: DEFAULT_TIMEOUT,
            controller_cert_file_prefix: "".to_string(),
        }
    }
}

impl Config {
    fn get_port(&self, is_proxy: bool) -> u16 {
        if is_proxy {
            return self.proxy_port;
        }
        if self.controller_cert_file_prefix.len() > 0 {
            return self.tls_port;
        }
        return self.port;
    }

    pub fn set_proxy_port(&mut self, port: u16) {
        self.proxy_port = port;
    }

    fn get_proxy_port(&self) -> u16 {
        return self.proxy_port;
    }
}

pub struct Session {
    config: RwLock<Config>,

    server_ip: RwLock<ServerIp>,

    reset_session: AtomicBool,
    version: AtomicU64,
    client: RwLock<Option<Channel>>,
    exception_handler: ExceptionHandler,
    counters: Vec<Arc<GrpcCallCounter>>,

    // sharing tonic grpc channel sometimes suffers from high latency
    // using semaphore to force serialized grpc calls to
    // reduce the probability
    in_use: Semaphore,
}

impl Session {
    pub fn new(
        port: u16,
        tls_port: u16,
        timeout: Duration,
        controller_cert_file_prefix: String,
        controller_ips: Vec<String>,
        exception_handler: ExceptionHandler,
        stats_collector: &stats::Collector,
    ) -> Session {
        let counters = (0..GRPC_CALL_ENDPOINTS.len())
            .into_iter()
            .map(|_| Arc::new(GrpcCallCounter::default()))
            .collect::<Vec<_>>();

        for (endpoint, counter) in counters.iter().enumerate() {
            stats_collector.register_countable(
                "grpc_call",
                Countable::Ref(Arc::downgrade(&counter) as Weak<dyn RefCountable>),
                vec![StatsOption::Tag(
                    "endpoint",
                    GRPC_CALL_ENDPOINTS[endpoint].to_string(),
                )],
            );
        }

        Session {
            config: RwLock::new(Config {
                port,
                tls_port,
                timeout,
                controller_cert_file_prefix,
                ..Default::default()
            }),
            server_ip: RwLock::new(ServerIp::new(
                controller_ips
                    .into_iter()
                    .map(|x| x.parse().unwrap())
                    .collect(),
            )),
            version: AtomicU64::new(0),
            reset_session: Default::default(),
            client: RwLock::new(None),
            exception_handler,
            counters,

            in_use: Semaphore::new(1),
        }
    }

    pub fn reset_server_ip(&self, controller_ips: Vec<String>) {
        self.server_ip.write().update_controller_ips(
            controller_ips
                .into_iter()
                .map(|x| x.parse().unwrap())
                .collect(),
        );

        self.reset_session.store(true, Ordering::Relaxed);
    }

    pub fn reset(&self) {
        *self.client.write() = None;
        self.reset_session.store(true, Ordering::Relaxed);
        self.server_ip.write().reset();
    }

    async fn dial(&self, remote: &IpAddr) {
        let is_proxy = self.server_ip.read().is_proxy_ip();
        let remote_port = self.config.read().get_port(is_proxy);
        // TODO: 错误处理和tls
        match Endpoint::from_shared(format!("http://{}:{}", remote, remote_port))
            .unwrap()
            .connect_timeout(DEFAULT_TIMEOUT)
            .timeout(SESSION_TIMEOUT)
            .connect()
            .await
        {
            Ok(channel) => *self.client.write() = Some(channel),
            Err(e) => {
                self.exception_handler.set(Exception::ControllerSocketError);
                error!("dial server({}) failed {}", remote, e);
            }
        }
    }

    pub fn get_client(&self) -> Option<Channel> {
        self.client.read().clone()
    }

    pub fn get_current_server(&self) -> IpAddr {
        self.server_ip.read().get_current_ip()
    }

    async fn update_current_server(&self) -> bool {
        let changed = self.server_ip.write().update_current_ip();
        if changed {
            let ip = self.server_ip.read().get_current_ip();
            self.dial(&ip).await;
            self.version.fetch_add(1, Ordering::SeqCst);
        }
        changed
    }

    pub fn get_version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }

    pub fn close(&self) {
        *self.client.write() = None;
    }

    pub fn get_request_failed(&self) -> bool {
        self.server_ip.read().get_request_failed()
    }

    pub fn set_request_failed(&self, failed: bool) {
        self.server_ip.write().set_request_failed(failed);
    }

    pub fn get_proxy_server(&self) -> (Option<IpAddr>, u16) {
        (
            self.server_ip.read().get_proxy_ip(),
            self.config.read().get_proxy_port(),
        )
    }

    pub fn set_proxy_server(&self, ip: Option<IpAddr>, port: u16) {
        self.server_ip.write().set_proxy_ip(ip);
        self.config.write().set_proxy_port(port);

        self.reset_session.store(true, Ordering::Relaxed);
    }

    pub async fn grpc_push_with_statsd(
        &self,
        request: trident::SyncRequest,
    ) -> Result<tonic::Response<tonic::codec::Streaming<trident::SyncResponse>>, tonic::Status>
    {
        let _lock = self.in_use.acquire().await.unwrap();
        self.update_current_server().await;
        let client = match self.get_client() {
            Some(c) => c,
            None => {
                self.set_request_failed(true);
                return Err(tonic::Status::cancelled("grpc client not connected"));
            }
        };
        let mut client = trident::synchronizer_client::SynchronizerClient::new(client);

        let now = Instant::now();
        let response = client.push(request).await;
        let now_elapsed = now.elapsed();
        self.counters[PUSH_ENDPOINT].delay.update(now_elapsed);
        debug!("grpc push latency {:?}ms", now_elapsed.as_millis());
        response
    }

    async fn grpc_sync_inner(
        &self,
        request: trident::SyncRequest,
        with_statsd: bool,
    ) -> Result<tonic::Response<trident::SyncResponse>, tonic::Status> {
        let _lock = self.in_use.acquire().await.unwrap();
        self.update_current_server().await;
        let client = match self.get_client() {
            Some(c) => c,
            None => {
                self.set_request_failed(true);
                return Err(tonic::Status::cancelled("grpc client not connected"));
            }
        };
        let mut client = trident::synchronizer_client::SynchronizerClient::new(client);

        if with_statsd {
            client.sync(request).await
        } else {
            let now = Instant::now();
            let response = client.sync(request).await;
            let now_elapsed = now.elapsed();
            self.counters[SYNC_ENDPOINT].delay.update(now_elapsed);
            debug!("grpc sync latency {:?}ms", now_elapsed.as_millis());
            response
        }
    }

    // Not recommended, only used by debugger
    pub async fn grpc_sync(
        &self,
        request: trident::SyncRequest,
    ) -> Result<tonic::Response<trident::SyncResponse>, tonic::Status> {
        self.grpc_sync_inner(request, false).await
    }

    pub async fn grpc_sync_with_statsd(
        &self,
        request: trident::SyncRequest,
    ) -> Result<tonic::Response<trident::SyncResponse>, tonic::Status> {
        self.grpc_sync_inner(request, true).await
    }

    pub async fn grpc_upgrade_with_statsd(
        &self,
        request: trident::UpgradeRequest,
    ) -> Result<tonic::Response<tonic::codec::Streaming<trident::UpgradeResponse>>, tonic::Status>
    {
        let _lock = self.in_use.acquire().await.unwrap();
        self.update_current_server().await;
        let client = match self.get_client() {
            Some(c) => c,
            None => {
                self.set_request_failed(true);
                return Err(tonic::Status::cancelled("grpc client not connected"));
            }
        };
        let mut client = trident::synchronizer_client::SynchronizerClient::new(client);

        let now = Instant::now();
        let response = client.upgrade(request).await;
        let now_elapsed = now.elapsed();
        self.counters[UPGRADE_ENDPOINT].delay.update(now_elapsed);
        debug!("grpc upgrade latency {:?}ms", now_elapsed.as_millis());
        response
    }

    pub async fn grpc_query_with_statsd(
        &self,
        request: trident::NtpRequest,
    ) -> Result<tonic::Response<trident::NtpResponse>, tonic::Status> {
        let _lock = self.in_use.acquire().await.unwrap();
        self.update_current_server().await;
        let client = match self.get_client() {
            Some(c) => c,
            None => {
                self.set_request_failed(true);
                return Err(tonic::Status::cancelled("grpc client not connected"));
            }
        };
        let mut client = trident::synchronizer_client::SynchronizerClient::new(client);

        let now = Instant::now();
        let response = client.query(request).await;
        let now_elapsed = now.elapsed();
        self.counters[QUERY_ENDPOINT].delay.update(now_elapsed);
        debug!("grpc query latency {:?}ms", now_elapsed.as_millis());
        response
    }

    pub async fn grpc_genesis_sync_with_statsd(
        &self,
        request: trident::GenesisSyncRequest,
    ) -> Result<tonic::Response<trident::GenesisSyncResponse>, tonic::Status> {
        let _lock = self.in_use.acquire().await.unwrap();
        self.update_current_server().await;
        let client = match self.get_client() {
            Some(c) => c,
            None => {
                self.set_request_failed(true);
                return Err(tonic::Status::cancelled("grpc client not connected"));
            }
        };
        let mut client = trident::synchronizer_client::SynchronizerClient::new(client);

        let now = Instant::now();
        let response = client.genesis_sync(request).await;
        let now_elapsed = now.elapsed();
        self.counters[GENESIS_SYNC_ENDPOINT]
            .delay
            .update(now_elapsed);
        debug!("grpc genesis_sync latency {:?}ms", now_elapsed.as_millis());
        response
    }

    pub async fn grpc_kubernetes_api_sync_with_statsd(
        &self,
        request: trident::KubernetesApiSyncRequest,
    ) -> Result<tonic::Response<trident::KubernetesApiSyncResponse>, tonic::Status> {
        let _lock = self.in_use.acquire().await.unwrap();
        self.update_current_server().await;
        let client = match self.get_client() {
            Some(c) => c,
            None => {
                self.set_request_failed(true);
                return Err(tonic::Status::cancelled("grpc client not connected"));
            }
        };
        let mut client = trident::synchronizer_client::SynchronizerClient::new(client);

        let now = Instant::now();
        let response = client.kubernetes_api_sync(request).await;
        let now_elapsed = now.elapsed();
        self.counters[KUBERNETES_API_SYNC_ENDPOINT]
            .delay
            .update(now_elapsed);
        debug!("grpc kubernetes_api_sync latency {:?}ms", now_elapsed.as_millis());
        response
    }

    pub async fn grpc_get_kubernetes_cluster_id_with_statsd(
        &self,
        request: trident::KubernetesClusterIdRequest,
    ) -> Result<tonic::Response<trident::KubernetesClusterIdResponse>, tonic::Status> {
        let _lock = self.in_use.acquire().await.unwrap();
        self.update_current_server().await;
        let client = match self.get_client() {
            Some(c) => c,
            None => {
                self.set_request_failed(true);
                return Err(tonic::Status::cancelled("grpc client not connected"));
            }
        };
        let mut client = trident::synchronizer_client::SynchronizerClient::new(client);

        let now = Instant::now();
        let response = client.get_kubernetes_cluster_id(request).await;
        let now_elapsed = now.elapsed();
        self.counters[GET_KUBERNETES_CLUSTER_ID_ENDPOINT]
            .delay
            .update(now_elapsed);
        debug!("grpc get_kubernetes_cluster_id latency {:?}ms", now_elapsed.as_millis());
        response
    }
}

struct ServerIp {
    controller_ips: Vec<IpAddr>,
    this_controller: usize,

    current_ip: IpAddr,
    proxy_ip: Option<IpAddr>,
    proxied: bool,
    request_failed: bool,

    initialized: bool,
}

impl ServerIp {
    fn new(controller_ips: Vec<IpAddr>) -> ServerIp {
        if controller_ips.is_empty() {
            panic!("no controller IP set");
        }

        // Prevent multiple agents from reporting data to the same server and cause avalanches
        let mut rng = rand::thread_rng();
        let this_controller = rng.gen_range(0..controller_ips.len());
        ServerIp {
            current_ip: controller_ips[this_controller],

            controller_ips,
            this_controller,

            proxy_ip: None,
            proxied: false,
            request_failed: false,

            initialized: false,
        }
    }

    fn reset(&mut self) {
        self.this_controller = 0;
        self.current_ip = self.controller_ips[self.this_controller];
        self.proxied = false;
        self.initialized = false;
        self.proxy_ip = None;
        self.request_failed = false;
    }

    fn update_controller_ips(&mut self, controller_ips: Vec<IpAddr>) {
        self.proxied = false;
        self.this_controller = 0;
        self.controller_ips = controller_ips;
        self.current_ip = self.controller_ips[self.this_controller];
        self.initialized = false;
        self.request_failed = false;
    }

    fn get_current_ip(&self) -> IpAddr {
        self.current_ip
    }

    fn set_current_ip(&mut self, ip: IpAddr) {
        self.current_ip = ip;
    }

    fn get_proxy_ip(&self) -> Option<IpAddr> {
        self.proxy_ip
    }

    fn set_proxy_ip(&mut self, ip: Option<IpAddr>) {
        self.proxy_ip = ip;
    }

    fn is_proxy_ip(&self) -> bool {
        return self.proxied;
    }

    fn get_request_failed(&self) -> bool {
        self.request_failed
    }

    fn set_request_failed(&mut self, failed: bool) {
        self.request_failed = failed;
    }

    fn get_current_controller_ip(&self) -> IpAddr {
        // controller_ips一定不为空
        self.controller_ips[self.this_controller]
    }

    fn next_controller_ip(&mut self) {
        self.this_controller += 1;
        if self.this_controller >= self.controller_ips.len() {
            self.this_controller = 0;
        }
    }

    fn update_current_ip(&mut self) -> bool {
        if !self.initialized {
            // 第一次访问，直接返回
            self.initialized = true;
            return true;
        }
        if self.request_failed {
            // 上一次rpc请求失败
            if self.proxied {
                let new_ip = self.get_current_controller_ip();
                info!(
                    "rpc IP changed to controller {} from unavailable proxy {}",
                    new_ip, self.current_ip
                );
                self.current_ip = new_ip.into();
                self.proxied = false;
            } else {
                self.next_controller_ip();
                let new_ip = self.get_current_controller_ip();
                info!(
                    "rpc IP changed to controller {} from unavailable controller {}",
                    new_ip, self.current_ip
                );
                self.current_ip = new_ip.into();
            }
            return true;
        }
        if !self.proxied {
            // 请求controller成功，改为请求proxy
            if let Some(new_ip) = self.get_proxy_ip() {
                if new_ip == self.current_ip {
                    info!(
                        "proxy {} same as controller {}, nothing to do",
                        new_ip, self.current_ip
                    );
                    self.proxied = true;
                    return false;
                }
                info!(
                    "rpc IP changed to proxy {} from controller {}",
                    new_ip, self.current_ip
                );
                self.current_ip = new_ip.into();
                self.proxied = true;
                true
            } else {
                info!("rpc IP not changed, no valid proxy IP provided");
                false
            }
        } else {
            // 这里proxy_ip一定有
            let new_ip = self.get_proxy_ip().unwrap();
            if new_ip.ne(&self.current_ip) {
                // proxy改变
                info!(
                    "rpc IP changed to proxy {} from proxy {}",
                    new_ip, self.current_ip
                );
                self.current_ip = new_ip.into();
                true
            } else {
                false
            }
        }
    }
}

#[derive(Default)]
pub struct GrpcCallCounter {
    pub delay: AtomicTimeStats,
}

impl RefCountable for GrpcCallCounter {
    fn get_counters(&self) -> Vec<Counter> {
        let max_delay = self.delay.max_ns.swap(0, Ordering::Relaxed) / 1000;
        let delay_count = self.delay.count.swap(0, Ordering::Relaxed) as u64;
        let sum = self.delay.sum_ns.swap(0, Ordering::Relaxed) / 1000;
        let avg_delay = if delay_count == 0 {
            0
        } else {
            sum / delay_count
        };
        vec![
            (
                "max_delay",
                CounterType::Gauged,
                CounterValue::Unsigned(max_delay),
            ),
            (
                "avg_delay",
                CounterType::Gauged,
                CounterValue::Unsigned(avg_delay),
            ),
            (
                "delay_count",
                CounterType::Gauged,
                CounterValue::Unsigned(delay_count),
            ),
        ]
    }
}
