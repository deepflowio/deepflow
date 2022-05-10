use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::RwLock;

use log::{info, warn};
use tonic::transport::{Channel, Endpoint};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

struct Config {
    port: u16,
    tls_port: u16,
    timeout: Duration,
    controller_cert_file_prefix: String,
}

pub struct Session {
    config: Config,

    server_ip: RwLock<ServerIp>,

    version: AtomicU64,
    client: RwLock<Option<Channel>>,
}

impl Session {
    pub fn new(
        port: u16,
        tls_port: u16,
        timeout: Duration,
        controller_cert_file_prefix: String,
        controller_ips: Vec<String>,
    ) -> Session {
        Session {
            config: Config {
                port,
                tls_port,
                timeout,
                controller_cert_file_prefix,
            },
            server_ip: RwLock::new(ServerIp::new(controller_ips)),
            version: AtomicU64::new(0),
            client: RwLock::new(None),
        }
    }

    async fn dial(&self, remote: &str) {
        // TODO: 错误处理和tls
        match Endpoint::from_shared(format!("http://{}:{}", remote, self.config.port))
            .unwrap()
            .connect()
            .await
        {
            Ok(channel) => *self.client.write() = Some(channel),
            Err(e) => warn!("dial server({}) failed {}", remote, e),
        }
    }

    pub fn get_client(&self) -> Option<Channel> {
        self.client.read().clone()
    }

    pub fn get_current_server(&self) -> String {
        self.server_ip.read().get_current_ip()
    }

    pub async fn update_current_server(&self) -> bool {
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

    pub fn set_proxy_server(&self, ip: &str) {
        self.server_ip.write().set_proxy_ip(ip);
    }
}

struct ServerIp {
    controller_ips: Vec<String>,
    this_controller: usize,

    current_ip: String,
    proxy_ip: Option<String>,
    proxied: bool,
    request_failed: bool,

    initialized: bool,
}

impl ServerIp {
    fn new(controller_ips: Vec<String>) -> ServerIp {
        if controller_ips.is_empty() {
            panic!("no controller IP set");
        }
        ServerIp {
            current_ip: controller_ips[0].clone(),

            controller_ips,
            this_controller: 0,

            proxy_ip: None,
            proxied: false,
            request_failed: false,

            initialized: false,
        }
    }

    fn get_current_ip(&self) -> String {
        self.current_ip.clone()
    }

    fn set_current_ip(&mut self, ip: &str) {
        self.current_ip = ip.into();
    }

    fn get_proxy_ip(&self) -> Option<&str> {
        self.proxy_ip.as_ref().map(|x| x.as_str())
    }

    fn set_proxy_ip(&mut self, ip: &str) {
        self.proxy_ip = Some(ip.into());
    }

    fn get_request_failed(&self) -> bool {
        self.request_failed
    }

    fn set_request_failed(&mut self, failed: bool) {
        self.request_failed = failed;
    }

    fn get_current_controller_ip(&self) -> &str {
        // controller_ips一定不为空
        &self.controller_ips[self.this_controller]
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
                info!(
                    "rpc IP changed to proxy {} from controller {}",
                    new_ip, self.current_ip
                );
                self.current_ip = new_ip.into();
                self.proxied = true;
                true
            } else {
                info!("rpc IP not changed, proxy unavailable");
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
