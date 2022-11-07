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
use std::time::Duration;

use log::{error, info};
use parking_lot::RwLock;
use rand::Rng;
use tonic::transport::{Channel, Endpoint};

use super::{GrpcCallCounter, GrpcWrapper};

use crate::common::{DEFAULT_CONTROLLER_PORT, DEFAULT_CONTROLLER_TLS_PORT};
use crate::exception::ExceptionHandler;
use crate::proto::trident::{self, Exception};
use crate::utils::stats::{self, StatsOption};

use public::counter::{Countable, RefCountable};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
// Sessions in use occasionally timeout for 60 seconds, The
// timeout should be adjusted to be greater than 60 seconds.
// ==========================================================
// 使用中会话偶尔会超时60秒，这里调整超时时间需要大于60秒
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(120);

const GRPC_CALL_NAMES: [&str; 7] = [
    "push",
    "query",
    "upgrade",
    "sync",
    "genesis_sync",
    "kubernetes_api_sync",
    "get_kubernetes_cluster_id",
];

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
    counters: Vec<(&'static str, Arc<GrpcCallCounter>)>,
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
        let counters = GRPC_CALL_NAMES
            .iter()
            .map(|&grpc| (grpc, Arc::new(GrpcCallCounter::default())))
            .collect::<Vec<_>>();

        for (name, counter) in counters.iter() {
            stats_collector.register_countable(
                "grpc_call",
                Countable::Ref(Arc::downgrade(&counter) as Weak<dyn RefCountable>),
                vec![StatsOption::Tag("name", name.to_string())],
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

    pub async fn call_with_statsd<Response, Request: GrpcWrapper<Response>>(
        &self,
        request: Request,
    ) -> Result<tonic::Response<Response>, tonic::Status> {
        self.update_current_server().await;
        let client = match self.get_client() {
            Some(c) => c,
            None => {
                self.set_request_failed(true);
                return Err(tonic::Status::cancelled("grpc client not connected"));
            }
        };
        let client = trident::synchronizer_client::SynchronizerClient::new(client);
        request.call_with_statsd(client, &self.counters).await
    }

    pub async fn call<Response, Request: GrpcWrapper<Response>>(
        &self,
        request: Request,
    ) -> Result<tonic::Response<Response>, tonic::Status> {
        self.update_current_server().await;
        let client = match self.get_client() {
            Some(c) => c,
            None => {
                self.set_request_failed(true);
                return Err(tonic::Status::cancelled("grpc client not connected"));
            }
        };
        let client = trident::synchronizer_client::SynchronizerClient::new(client);
        request.call(client).await
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
