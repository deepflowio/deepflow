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
    time::Duration,
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
    Beacon, Message, Module, BEACON_INTERVAL, BEACON_INTERVAL_MIN, DEEPFLOW_AGENT_BEACON,
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
use public::{
    consts::DEFAULT_CONTROLLER_PORT,
    debug::{send_to, Error, QueueDebugger, QueueMessage, Result, MAX_BUF_SIZE},
};

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

#[derive(Clone)]
struct DebugSockets {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    socket: Arc<UdpSocket>,
    #[cfg(target_os = "windows")]
    ipv4: Arc<UdpSocket>,
    #[cfg(target_os = "windows")]
    ipv6: Arc<UdpSocket>,
}

impl DebugSockets {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn bind(listen_port: u16) -> io::Result<Self> {
        let ipv6_addr: SocketAddr = (IpAddr::from(Ipv6Addr::UNSPECIFIED), listen_port).into();
        let socket = UdpSocket::bind(ipv6_addr).or_else(|_| {
            let ipv4_addr: SocketAddr = (IpAddr::from(Ipv4Addr::UNSPECIFIED), listen_port).into();
            UdpSocket::bind(ipv4_addr)
        })?;
        Ok(Self {
            socket: Arc::new(socket),
        })
    }

    #[cfg(target_os = "windows")]
    fn bind(listen_port: u16) -> io::Result<Self> {
        // [Issue #34202]: https://github.com/rust-lang/rust/issues/34202
        // A socket cannot send to an address returned by ToSocketAddrs when their IP
        // versions differ, so Windows needs separate IPv4 and IPv6 sockets.
        let ipv4_addr: SocketAddr = (IpAddr::from(Ipv4Addr::UNSPECIFIED), listen_port).into();
        let ipv6_addr: SocketAddr = (IpAddr::from(Ipv6Addr::UNSPECIFIED), listen_port).into();
        Ok(Self {
            ipv4: Arc::new(UdpSocket::bind(ipv4_addr)?),
            ipv6: Arc::new(UdpSocket::bind(ipv6_addr)?),
        })
    }

    fn set_timeouts(&self, timeout: Duration) {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Self::set_socket_timeouts(&self.socket, "", timeout);
        #[cfg(target_os = "windows")]
        {
            Self::set_socket_timeouts(&self.ipv4, " ipv4", timeout);
            Self::set_socket_timeouts(&self.ipv6, " ipv6", timeout);
        }
    }

    fn set_socket_timeouts(socket: &UdpSocket, label: &str, timeout: Duration) {
        if let Err(e) = socket.set_read_timeout(Some(timeout)) {
            warn!("debugger{} set read timeout error: {:?}", label, e);
        }
        if let Err(e) = socket.set_write_timeout(Some(timeout)) {
            warn!("debugger{} set write timeout error: {:?}", label, e);
        }
    }

    fn local_addrs(&self) -> Vec<SocketAddr> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        return self.socket.local_addr().into_iter().collect();
        #[cfg(target_os = "windows")]
        return [self.ipv4.local_addr(), self.ipv6.local_addr()]
            .into_iter()
            .filter_map(Result::ok)
            .collect();
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn receive_sockets(&self, _controller_ips: &[IpAddr]) -> Vec<Arc<UdpSocket>> {
        vec![self.socket.clone()]
    }

    #[cfg(target_os = "windows")]
    fn receive_sockets(&self, controller_ips: &[IpAddr]) -> Vec<Arc<UdpSocket>> {
        let mut sockets = Vec::with_capacity(2);
        if controller_ips.iter().any(IpAddr::is_ipv4) {
            sockets.push(self.ipv4.clone());
        }
        if controller_ips.iter().any(IpAddr::is_ipv6) {
            sockets.push(self.ipv6.clone());
        }
        sockets
    }

    fn send_to(&self, payload: &[u8], ip: IpAddr, port: u16) -> io::Result<usize> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        return self.socket.send_to(payload, (ip, port));
        #[cfg(target_os = "windows")]
        if ip.is_ipv4() {
            self.ipv4.send_to(payload, (ip, port))
        } else {
            self.ipv6.send_to(payload, (ip, port))
        }
    }
}

impl Debugger {
    const TIMEOUT: Duration = Duration::from_millis(500);

    pub fn start(&self) {
        if self.running.swap(true, Ordering::Relaxed) {
            return;
        }

        let running = self.running.clone();
        let debuggers = self.debuggers.clone();
        let conf = self.config.clone();
        let override_os_hostname = self.override_os_hostname.clone();

        let thread = thread::Builder::new()
            .name("debugger".to_owned())
            .spawn(move || {
                let sockets = match DebugSockets::bind(conf.load().listen_port) {
                    Ok(sockets) => sockets,
                    Err(e) => {
                        error!("failed to create debugger socket: {}", e);
                        return;
                    }
                };
                info!("debugger listening on: {:?}", sockets.local_addrs());
                sockets.set_timeouts(Self::TIMEOUT);

                let serialize_conf = config::standard();
                #[cfg(target_os = "linux")]
                let agent_mode = conf.load().agent_mode;
                let receive_sockets = sockets.receive_sockets(&conf.load().controller_ips);
                let beacon_thread =
                    Self::spawn_beacon_thread(running.clone(), conf, override_os_hostname, sockets);

                while running.load(Ordering::Relaxed) {
                    for socket in receive_sockets.iter() {
                        Self::receive_and_dispatch(
                            socket,
                            &debuggers,
                            serialize_conf,
                            #[cfg(target_os = "linux")]
                            agent_mode,
                        );
                    }
                }
                let _ = beacon_thread.join();
            })
            .unwrap();
        self.thread.lock().unwrap().replace(thread);
        info!("debugger started");
    }

    fn spawn_beacon_thread(
        running: Arc<AtomicBool>,
        conf: DebugAccess,
        override_os_hostname: Arc<Option<String>>,
        sockets: DebugSockets,
    ) -> JoinHandle<()> {
        thread::Builder::new()
            .name("debugger-beacon".to_owned())
            .spawn(move || {
                let interval_counter_max =
                    BEACON_INTERVAL.as_secs() / BEACON_INTERVAL_MIN.as_secs();
                let mut interval_counter = 0;
                let serialize_conf = config::standard();
                while running.load(Ordering::Relaxed) {
                    thread::sleep(BEACON_INTERVAL_MIN);
                    interval_counter += 1;
                    if interval_counter < interval_counter_max {
                        continue;
                    }
                    interval_counter = 0;

                    let (agent_id, controller_ips, controller_port) = {
                        let conf = conf.load();
                        if !conf.beacon_enabled {
                            continue;
                        }
                        (
                            conf.agent_id,
                            conf.controller_ips.clone(),
                            conf.controller_port,
                        )
                    };
                    let Some(hostname) =
                        override_os_hostname
                            .as_ref()
                            .clone()
                            .or_else(|| match get_hostname() {
                                Ok(hostname) => Some(hostname),
                                Err(e) => {
                                    warn!("get hostname failed: {}", e);
                                    None
                                }
                            })
                    else {
                        continue;
                    };
                    let beacon = Beacon { agent_id, hostname };
                    let serialized_beacon = match encode_to_vec(beacon, serialize_conf) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let payload = [
                        DEEPFLOW_AGENT_BEACON.as_bytes(),
                        serialized_beacon.as_slice(),
                    ]
                    .concat();
                    for ip in controller_ips {
                        if let Err(e) = sockets.send_to(&payload, ip, controller_port) {
                            warn!("write beacon to client error: {}", e);
                        }
                    }
                }
            })
            .unwrap()
    }

    fn receive_and_dispatch(
        socket: &Arc<UdpSocket>,
        debuggers: &ModuleDebuggers,
        serialize_conf: Configuration,
        #[cfg(target_os = "linux")] agent_mode: crate::trident::RunningMode,
    ) {
        let mut buf = [0u8; MAX_BUF_SIZE];
        match socket.recv_from(&mut buf) {
            Ok((0, _)) => {}
            Ok((_, addr)) => Self::dispatch(
                (socket, addr),
                &buf,
                debuggers,
                serialize_conf,
                #[cfg(target_os = "linux")]
                agent_mode,
            )
            .unwrap_or_else(|e| warn!("handle client request error: {}", e)),
            Err(e) => {
                if e.kind() == ErrorKind::WouldBlock {
                    return;
                }
                #[cfg(target_os = "windows")]
                // Windows may report WSAECONNRESET after receiving an ICMP port-unreachable
                // response for an earlier UDP packet.
                if matches!(e.kind(), ErrorKind::ConnectionReset | ErrorKind::TimedOut) {
                    return;
                }
                warn!(
                    "receive udp packet error: kind=({:?}) detail={}",
                    e.kind(),
                    e
                );
            }
        }
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
                    RpcMessage::CaptureNetworkTypes(_) => debugger.tap_types(),
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
            UdpSocket::bind((IpAddr::from(Ipv4Addr::UNSPECIFIED), DEFAULT_CONTROLLER_PORT))?
        } else {
            UdpSocket::bind((IpAddr::from(Ipv6Addr::UNSPECIFIED), DEFAULT_CONTROLLER_PORT))?
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
