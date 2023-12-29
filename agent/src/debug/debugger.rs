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
    io::{self, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
};

use arc_swap::access::Access;
use bincode::{
    config::{self, Configuration},
    decode_from_std_read, encode_to_vec, Decode, Encode,
};
use log::{error, info, warn};
use parking_lot::RwLock;
use tokio::runtime::Runtime;

#[cfg(target_os = "linux")]
use super::{
    ebpf::{EbpfDebugger, EbpfMessage},
    platform::{PlatformDebugger, PlatformMessage},
};
use super::{
    policy::{PolicyDebugger, PolicyMessage},
    rpc::{RpcDebugger, RpcMessage},
    Beacon, Message, Module, BEACON_INTERVAL, DEEPFLOW_AGENT_BEACON,
};
#[cfg(target_os = "linux")]
use crate::platform::{ApiWatcher, GenericPoller};
use crate::{
    config::handler::DebugAccess,
    policy::PolicySetter,
    rpc::{Session, StaticConfig, Status},
    trident::AgentId,
    utils::command::get_hostname,
};
use public::debug::{send_to, Error, QueueDebugger, QueueMessage, Result, MAX_BUF_SIZE};

struct ModuleDebuggers {
    #[cfg(target_os = "linux")]
    pub platform: PlatformDebugger,
    pub rpc: RpcDebugger,
    pub queue: Arc<QueueDebugger>,
    pub policy: PolicyDebugger,
    #[cfg(target_os = "linux")]
    pub ebpf: EbpfDebugger,
}

pub struct Debugger {
    thread: Mutex<Option<JoinHandle<()>>>,
    running: Arc<AtomicBool>,
    debuggers: Arc<ModuleDebuggers>,
    config: DebugAccess,
    override_os_hostname: Arc<Option<String>>,
}

pub struct ConstructDebugCtx {
    pub runtime: Arc<Runtime>,
    pub config: DebugAccess,
    #[cfg(target_os = "linux")]
    pub api_watcher: Arc<ApiWatcher>,
    #[cfg(target_os = "linux")]
    pub poller: Arc<GenericPoller>,
    pub session: Arc<Session>,
    pub static_config: Arc<StaticConfig>,
    pub agent_id: Arc<RwLock<AgentId>>,
    pub status: Arc<RwLock<Status>>,
    pub policy_setter: PolicySetter,
}

impl Debugger {
    pub fn start(&self) {
        if self.running.swap(true, Ordering::Relaxed) {
            return;
        }

        let running = self.running.clone();
        let debuggers = self.debuggers.clone();
        let conf = self.config.clone();
        let override_os_hostname = self.override_os_hostname.clone();

        #[cfg(any(target_os = "linux", target_os = "android"))]
        let thread = thread::Builder::new()
            .name("debugger".to_owned())
            .spawn(move || {
                let addr: SocketAddr =
                    (IpAddr::from(Ipv6Addr::UNSPECIFIED), conf.load().listen_port).into();
                let sock = match UdpSocket::bind(addr) {
                    Ok(s) => Arc::new(s),
                    Err(_) => {
                        let ipv4_addr: SocketAddr =
                            (IpAddr::from(Ipv4Addr::UNSPECIFIED), conf.load().listen_port).into();
                        match UdpSocket::bind(ipv4_addr) {
                            Ok(s) => Arc::new(s),
                            Err(e) => {
                                error!(
                                    "failed to create debugger socket with addr={:?} error: {}",
                                    ipv4_addr, e
                                );
                                return;
                            }
                        }
                    }
                };
                info!("debugger listening on: {:?}", sock.local_addr().unwrap());

                let sock_clone = sock.clone();
                let running_clone = running.clone();
                let serialize_conf = config::standard();
                #[cfg(target_os = "linux")]
                let agent_mode = conf.load().agent_mode;
                let beacon_port = conf.load().controller_port;
                thread::Builder::new()
                    .name("debugger-beacon".to_owned())
                    .spawn(move || {
                        while running_clone.load(Ordering::Relaxed) {
                            thread::sleep(BEACON_INTERVAL);
                            let Some(hostname) = override_os_hostname.as_ref().clone().or_else(
                                || match get_hostname() {
                                    Ok(hostname) => Some(hostname),
                                    Err(e) => {
                                        warn!("get hostname failed: {}", e);
                                        None
                                    }
                                },
                            ) else {
                                continue;
                            };

                            let beacon = Beacon {
                                vtap_id: conf.load().vtap_id,
                                hostname,
                            };

                            let serialized_beacon = match encode_to_vec(beacon, serialize_conf) {
                                Ok(v) => v,
                                Err(_) => continue,
                            };
                            for &ip in conf.load().controller_ips.iter() {
                                if let Err(e) = sock_clone.send_to(
                                    [
                                        DEEPFLOW_AGENT_BEACON.as_bytes(),
                                        serialized_beacon.as_slice(),
                                    ]
                                    .concat()
                                    .as_slice(),
                                    (ip, beacon_port),
                                ) {
                                    warn!("write beacon to client error: {}", e);
                                }
                            }
                        }
                    })
                    .unwrap();

                while running.load(Ordering::Relaxed) {
                    let mut buf = [0u8; MAX_BUF_SIZE];
                    let mut addr = None;
                    match sock.recv_from(&mut buf) {
                        Ok((n, a)) => {
                            if n == 0 {
                                continue;
                            }
                            if addr.is_none() {
                                addr.replace(a);
                            }
                            Self::dispatch(
                                (&sock, addr.unwrap()),
                                &buf,
                                &debuggers,
                                serialize_conf,
                                #[cfg(target_os = "linux")]
                                agent_mode,
                            )
                            .unwrap_or_else(|e| warn!("handle client request error: {}", e));
                        }
                        Err(e) => {
                            warn!(
                                "receive udp packet error: kind=({:?}) detail={}",
                                e.kind(),
                                e
                            );
                            continue;
                        }
                    }
                }
            })
            .unwrap();

        #[cfg(target_os = "windows")]
        let thread = thread::Builder::new()
            .name("debugger".to_owned())
            .spawn(move || {
                let (mut has_ipv4, mut has_ipv6) = (false, false);
                for &ip in conf.load().controller_ips.iter() {
                    if ip.is_ipv4() {
                        has_ipv4 = true;
                    } else if ip.is_ipv6() {
                        has_ipv6 = true;
                    }
                }

                // [Issue #34202]: https://github.com/rust-lang/rust/issues/34202
                // This will return an error when the IP version of the local socket does not match that returned from [`ToSocketAddrs`]
                // So it needs to bind to ipv4 addr's socket and ipv6 addr's socket on Windows
                let addr_v4: SocketAddr =
                    (IpAddr::from(Ipv4Addr::UNSPECIFIED), conf.load().listen_port).into();
                let addr_v6: SocketAddr =
                    (IpAddr::from(Ipv6Addr::UNSPECIFIED), conf.load().listen_port).into();
                let sock_v4 = match UdpSocket::bind(addr_v4) {
                    Ok(s) => Arc::new(s),
                    Err(e) => {
                        error!(
                            "failed to create debugger socket with addr_v4={:?} error: {}",
                            addr_v4, e
                        );
                        return;
                    }
                };

                let sock_v6 = match UdpSocket::bind(addr_v6) {
                    Ok(s) => Arc::new(s),
                    Err(e) => {
                        error!(
                            "failed to create debugger socket with addr_v6={:?} error: {}",
                            addr_v6, e
                        );
                        return;
                    }
                };
                info!(
                    "debugger listening on: {:?} and {:?}",
                    sock_v4.local_addr().unwrap(),
                    sock_v6.local_addr().unwrap()
                );

                let sock_v4_clone = sock_v4.clone();
                let sock_v6_clone = sock_v6.clone();
                let running_clone = running.clone();
                let serialize_conf = config::standard();
                let beacon_port = conf.load().controller_port;
                thread::Builder::new()
                    .name("debugger-beacon".to_owned())
                    .spawn(move || {
                        while running_clone.load(Ordering::Relaxed) {
                            thread::sleep(BEACON_INTERVAL);
                            let Some(hostname) = override_os_hostname.as_ref().clone().or_else(
                                || match get_hostname() {
                                    Ok(hostname) => Some(hostname),
                                    Err(e) => {
                                        warn!("get hostname failed: {}", e);
                                        None
                                    }
                                },
                            ) else {
                                continue;
                            };

                            let beacon = Beacon {
                                vtap_id: conf.load().vtap_id,
                                hostname,
                            };

                            let serialized_beacon = match encode_to_vec(beacon, serialize_conf) {
                                Ok(v) => v,
                                Err(_) => continue,
                            };
                            for &ip in conf.load().controller_ips.iter() {
                                if has_ipv4 {
                                    if let Err(e) = sock_v4_clone.send_to(
                                        [
                                            DEEPFLOW_AGENT_BEACON.as_bytes(),
                                            serialized_beacon.as_slice(),
                                        ]
                                        .concat()
                                        .as_slice(),
                                        (ip, beacon_port),
                                    ) {
                                        warn!("write beacon to client error: {}", e);
                                    }
                                } else if has_ipv6 {
                                    if let Err(e) = sock_v6_clone.send_to(
                                        [
                                            DEEPFLOW_AGENT_BEACON.as_bytes(),
                                            serialized_beacon.as_slice(),
                                        ]
                                        .concat()
                                        .as_slice(),
                                        (ip, beacon_port),
                                    ) {
                                        warn!("write beacon to client error: {}", e);
                                    }
                                }
                            }
                        }
                    })
                    .unwrap();

                while running.load(Ordering::Relaxed) {
                    if has_ipv4 {
                        let mut buf_v4 = [0u8; MAX_BUF_SIZE];
                        let mut addr_v4 = None;
                        match sock_v4.recv_from(&mut buf_v4) {
                            Ok((n, a)) => {
                                if n == 0 {
                                    continue;
                                }
                                if addr_v4.is_none() {
                                    addr_v4.replace(a);
                                }
                                Self::dispatch(
                                    (&sock_v4, addr_v4.unwrap()),
                                    &buf_v4,
                                    &debuggers,
                                    serialize_conf,
                                )
                                .unwrap_or_else(|e| warn!("handle client request error: {}", e));
                            }
                            Err(e) => {
                                match e.kind() {
                                    ErrorKind::ConnectionReset => {} // It's a bug of Windows, https://stackoverflow.com/questions/34242622/windows-udp-sockets-recvfrom-fails-with-error-10054
                                    _ => {
                                        warn!(
                                            "receive udp packet error: kind=({:?}) detail={}",
                                            e.kind(),
                                            e
                                        );
                                    }
                                }
                                continue;
                            }
                        }
                    }
                    if has_ipv6 {
                        let mut buf_v6 = [0u8; MAX_BUF_SIZE];
                        let mut addr_v6 = None;
                        match sock_v6.recv_from(&mut buf_v6) {
                            Ok((n, a)) => {
                                if n == 0 {
                                    continue;
                                }
                                if addr_v6.is_none() {
                                    addr_v6.replace(a);
                                }
                                Self::dispatch(
                                    (&sock_v6, addr_v6.unwrap()),
                                    &buf_v6,
                                    &debuggers,
                                    serialize_conf,
                                )
                                .unwrap_or_else(|e| warn!("handle client request error: {}", e));
                            }
                            Err(e) => {
                                match e.kind() {
                                    ErrorKind::ConnectionReset => {} // It's a bug of Windows, https://stackoverflow.com/questions/34242622/windows-udp-sockets-recvfrom-fails-with-error-10054
                                    _ => {
                                        warn!(
                                            "receive udp packet error: kind=({:?}) detail={}",
                                            e.kind(),
                                            e
                                        );
                                    }
                                }
                                continue;
                            }
                        }
                    }
                }
            })
            .unwrap();
        self.thread.lock().unwrap().replace(thread);
        info!("debugger started");
    }

    fn dispatch(
        conn: (&Arc<UdpSocket>, SocketAddr),
        mut payload: &[u8],
        debuggers: &ModuleDebuggers,
        serialize_conf: Configuration,
        #[cfg(target_os = "linux")] agent_mode: crate::trident::RunningMode,
    ) -> Result<()> {
        let m = *payload.first().unwrap();
        let module = Module::try_from(m).unwrap_or_default();

        match module {
            #[cfg(target_os = "linux")]
            Module::Platform => {
                if matches!(agent_mode, crate::trident::RunningMode::Standalone) {
                    let msg = PlatformMessage::Fin;
                    send_to(conn.0, conn.1, msg, serialize_conf)?;
                }
                let req: Message<PlatformMessage> =
                    decode_from_std_read(&mut payload, serialize_conf)?;
                let debugger = &debuggers.platform;
                let resp = match req.into_inner() {
                    PlatformMessage::Version(_) => debugger.api_version(),
                    PlatformMessage::Watcher(w) => debugger
                        .watcher(String::from_utf8(w).map_err(|e| Error::FromUtf8(e.to_string()))?),
                    PlatformMessage::MacMappings(_) => debugger.mac_mapping(),
                    _ => unreachable!(),
                };
                iter_send_to(conn.0, conn.1, resp.iter(), serialize_conf)?;
            }
            Module::Rpc => {
                let req: Message<RpcMessage> = decode_from_std_read(&mut payload, serialize_conf)?;
                let debugger = &debuggers.rpc;
                let resp_result = match req.into_inner() {
                    RpcMessage::Acls(_) => debugger.flow_acls(),
                    RpcMessage::Cidr(_) => debugger.cidrs(),
                    RpcMessage::Config(_) => debugger.basic_config(),
                    RpcMessage::Groups(_) => debugger.ip_groups(),
                    RpcMessage::Segments(_) => debugger.local_segments(),
                    RpcMessage::TapTypes(_) => debugger.tap_types(),
                    RpcMessage::Version(_) => debugger.current_version(),
                    RpcMessage::PlatformData(_) => debugger.platform_data(),
                    _ => unreachable!(),
                };

                let resp = match resp_result {
                    Ok(m) => m,
                    Err(e) => vec![RpcMessage::Err(e.to_string())],
                };
                iter_send_to(conn.0, conn.1, resp.iter(), serialize_conf)?;
            }
            Module::Queue => {
                let req: Message<QueueMessage> =
                    decode_from_std_read(&mut payload, serialize_conf)?;
                let debugger = &debuggers.queue;
                match req.into_inner() {
                    QueueMessage::Clear => {
                        let msg = debugger.turn_off_all_queue();
                        send_to(conn.0, conn.1, msg, serialize_conf)?;
                    }
                    QueueMessage::Off(v) => {
                        let msg = debugger.turn_off_queue(v);
                        send_to(conn.0, conn.1, msg, serialize_conf)?;
                    }
                    QueueMessage::Names(_) => {
                        let msgs = debugger.queue_names();
                        iter_send_to(conn.0, conn.1, msgs.iter(), serialize_conf)?;
                    }
                    QueueMessage::On((name, duration)) => {
                        let msg = debugger.turn_on_queue(name.as_str());
                        send_to(conn.0, conn.1, msg, serialize_conf)?;
                        debugger.send(name, conn.1, serialize_conf, duration);
                    }
                    _ => unreachable!(),
                }
            }
            Module::Policy => {
                let req: Message<PolicyMessage> =
                    decode_from_std_read(&mut payload, serialize_conf)?;
                let debugger = &debuggers.policy;
                match req.into_inner() {
                    PolicyMessage::On => debugger.send(conn.0, conn.1, serialize_conf),
                    PolicyMessage::Off => {
                        debugger.turn_off();
                    }
                    PolicyMessage::Show => {
                        debugger.show(conn.0, conn.1, serialize_conf);
                    }
                    PolicyMessage::Analyzing(id) => {
                        debugger.analyzing(conn.0, conn.1, id, serialize_conf);
                    }
                    _ => unreachable!(),
                }
            }
            #[cfg(target_os = "linux")]
            Module::Ebpf => {
                let ebpf = &debuggers.ebpf;
                let req: Message<EbpfMessage> = decode_from_std_read(&mut payload, serialize_conf)?;
                let req = req.into_inner();
                match req {
                    EbpfMessage::DataDump(_) => {
                        ebpf.datadump(conn.0, conn.1, serialize_conf, &req);
                    }
                    EbpfMessage::Cpdbg(_) => {
                        ebpf.cpdbg(conn.0, conn.1, serialize_conf, &req);
                    }
                    _ => unreachable!(),
                }
            }
            _ => warn!("invalid module or invalid request, skip it"),
        }

        Ok(())
    }
}

impl Debugger {
    /// 传入构造上下文
    pub fn new(context: ConstructDebugCtx) -> Self {
        let override_os_hostname = Arc::new(context.static_config.override_os_hostname.clone());
        let debuggers = ModuleDebuggers {
            #[cfg(target_os = "linux")]
            platform: PlatformDebugger::new(context.api_watcher, context.poller),
            rpc: RpcDebugger::new(
                context.runtime.clone(),
                context.session,
                context.static_config,
                context.agent_id,
                context.status,
            ),
            queue: Arc::new(QueueDebugger::new()),
            policy: PolicyDebugger::new(context.policy_setter),
            #[cfg(target_os = "linux")]
            ebpf: EbpfDebugger::new(),
        };

        Self {
            thread: Mutex::new(None),
            running: Arc::new(AtomicBool::new(false)),
            debuggers: Arc::new(debuggers),
            config: context.config,
            override_os_hostname,
        }
    }

    pub fn clone_queue(&self) -> Arc<QueueDebugger> {
        self.debuggers.queue.clone()
    }

    pub fn notify_stop(&self) -> Option<JoinHandle<()>> {
        if !self.running.swap(false, Ordering::Relaxed) {
            return None;
        }

        info!("notified debugger exit");
        self.thread.lock().unwrap().take()
    }

    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            return;
        }

        let _ = self.thread.lock().unwrap().take();
        info!("debugger exited");
    }
}

pub struct Client {
    sock: UdpSocket,
    conf: Configuration,
    addr: SocketAddr,
}

impl Client {
    pub fn new(addr: SocketAddr) -> Result<Self> {
        let sock = if addr.is_ipv4() {
            UdpSocket::bind((IpAddr::from(Ipv4Addr::UNSPECIFIED), 0))?
        } else {
            UdpSocket::bind((IpAddr::from(Ipv6Addr::UNSPECIFIED), 0))?
        };
        Ok(Self {
            sock,
            conf: config::standard(),
            addr,
        })
    }

    /// 消息结构，msg_type占1字节，1个字节构成头部，后面存放序列化的消息
    /// 仅在client -> server发送的消息使用，server->client使用message
    /// 0          1               N 单位(字节)
    /// +----------+---------------+
    /// | msg_type |   message     |
    /// +----------+---------------+
    pub fn send_to(&mut self, msg: impl Encode) -> Result<()> {
        send_to(&self.sock, self.addr, msg, self.conf)?;
        Ok(())
    }

    pub fn recv<D: Decode>(&mut self) -> Result<D> {
        let mut buf = [0u8; MAX_BUF_SIZE];
        match self.sock.recv(&mut buf) {
            Ok(n) => {
                if n == 0 {
                    return Err(Error::IoError(io::Error::new(
                        ErrorKind::Other,
                        "receive zero byte",
                    )));
                }
                let d = decode_from_std_read(&mut buf.as_slice(), self.conf)?;
                Ok(d)
            }
            Err(e) => Err(Error::IoError(e)),
        }
    }
}

pub(super) fn iter_send_to<I: Iterator>(
    sock: &UdpSocket,
    addr: impl ToSocketAddrs + Clone,
    msgs: I,
    conf: Configuration,
) -> Result<()>
where
    I::Item: Encode,
{
    for msg in msgs {
        send_to(sock, addr.clone(), msg, conf)?
    }
    Ok(())
}
