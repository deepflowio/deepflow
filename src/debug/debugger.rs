use std::{
    io::{self, ErrorKind},
    mem,
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
    time::Instant,
};

use arc_swap::access::Access;
use log::{info, warn};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use super::{
    error::{Error, Result},
    platform::{PlatformDebugger, PlatformMessage},
    queue::{QueueDebugger, QueueMessage},
    rpc::{RpcDebugger, RpcMessage},
    Beacon, Message, Module, TestMessage, BEACON_INTERVAL, MAX_BUF_SIZE, SESSION_TIMEOUT,
};

use crate::{
    config::handler::DebugAccess,
    platform::{ApiWatcher, GenericPoller},
    rpc::{Session, StaticConfig, Status},
};

// 如果结构体长度大于此值就切片分包发送
const MAX_PKT_SIZE: usize = 540;
const LISTENED_IP: &str = "::";
const LISTENED_PORT: u16 = 0;
const BEACON_PORT: u16 = 20035;
// PktNum(u8)
const MAX_CHUNK_SIZE: usize = MAX_PKT_SIZE - mem::size_of::<u8>();
const SER_BUF_SIZE: usize = 1024;

struct ModuleDebuggers {
    pub platform: PlatformDebugger,
    pub rpc: RpcDebugger,
    pub queue: Arc<QueueDebugger>,
}

pub struct Debugger {
    udp_options: (Duration, Option<SocketAddr>, Duration),
    thread: Mutex<Option<JoinHandle<Result<()>>>>,
    running: Arc<AtomicBool>,
    debuggers: Arc<ModuleDebuggers>,
    config: DebugAccess,
}

pub struct ConstructDebugCtx {
    pub config: DebugAccess,
    pub api_watcher: Arc<ApiWatcher>,
    pub poller: Arc<GenericPoller>,
    pub session: Arc<Session>,
    pub static_config: Arc<StaticConfig>,
    pub status: Arc<RwLock<Status>>,
}

impl Debugger {
    pub fn start(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }

        let running = self.running.clone();
        let read_timeout = self.udp_options.0;
        let addr = self.udp_options.1;
        let debuggers = self.debuggers.clone();
        let config = self.config.clone();

        let beacon_interval = self.udp_options.2;

        let thread = thread::spawn(move || -> Result<()> {
            let sock = match addr {
                Some(a) => Arc::new(UdpSocket::bind(a)?),
                None => Arc::new(UdpSocket::bind((LISTENED_IP, LISTENED_PORT))?),
            };
            sock.set_read_timeout(Some(read_timeout))?;
            let sock_clone = sock.clone();
            let running_clone = running.clone();
            let beacon_handle = thread::spawn(move || -> Result<()> {
                while running_clone.load(Ordering::SeqCst) {
                    let hostname = match hostname::get() {
                        Ok(hostname) => match hostname.into_string() {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("get hostname failed: {:?}", e);
                                continue;
                            }
                        },
                        Err(e) => {
                            warn!("get hostname failed: {}", e);
                            continue;
                        }
                    };

                    let beacon = Beacon {
                        vtap_id: config.load().vtap_id,
                        hostname,
                    };
                    let serialized_beacon = bincode::serialize(&beacon)?;
                    for &ip in config.load().controller_ips.iter() {
                        sock_clone.send_to(serialized_beacon.as_slice(), (ip, BEACON_PORT))?;
                    }
                    thread::sleep(beacon_interval);
                }
                Ok(())
            });

            'SERVER: while running.load(Ordering::SeqCst) {
                let mut buf = [0u8; SER_BUF_SIZE];
                let mut addr = None;
                let (mut len, mut count, mut need_num) = (0, 0, 0);
                while running.load(Ordering::SeqCst) {
                    let start = Instant::now();
                    match sock.recv_from(&mut buf[len..]) {
                        Ok((n, a)) => {
                            if n == 0 {
                                break;
                            }
                            if addr.is_none() {
                                addr.replace(a);
                            }
                            len += n - 1;
                            count += 1;
                            if need_num == 0 {
                                need_num = buf[len];
                            }
                            //结束就退出,免得等待TIMEOUT
                            if need_num == count {
                                break;
                            }
                        }
                        Err(e)
                            if start.elapsed() >= read_timeout
                                && (cfg!(target_os = "windows")
                                    && e.kind() == ErrorKind::TimedOut
                                    || cfg!(target_os = "linux")
                                        && e.kind() == ErrorKind::WouldBlock) =>
                        {
                            // normal timeout, Window=TimedOut UNIX=WouldBlock
                            break;
                        }
                        Err(e) => {
                            warn!("{}", e);
                            continue 'SERVER;
                        }
                    };
                }
                if addr.is_none() || len == 0 {
                    continue;
                }
                Self::dispatch((&sock, addr.unwrap()), &buf[..len], &debuggers)?;
            }
            if let Err(e) = beacon_handle.join().unwrap() {
                warn!("{}", e);
            }
            Ok(())
        });
        self.thread.lock().unwrap().replace(thread);
        info!("debugger started");
    }
}

impl Debugger {
    /// 传入(read_timeout, bind地址), 构造上下文
    pub fn new(context: ConstructDebugCtx) -> Self {
        let debuggers = ModuleDebuggers {
            platform: PlatformDebugger::new(context.api_watcher, context.poller),
            rpc: RpcDebugger::new(context.session, context.static_config, context.status),
            queue: Arc::new(QueueDebugger::new()),
        };

        Self {
            udp_options: (SESSION_TIMEOUT, None, BEACON_INTERVAL),
            thread: Mutex::new(None),
            running: Arc::new(AtomicBool::new(false)),
            debuggers: Arc::new(debuggers),
            config: context.config,
        }
    }

    pub fn clone_queue(&self) -> Arc<QueueDebugger> {
        self.debuggers.queue.clone()
    }

    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return;
        }

        if let Some(t) = self.thread.lock().unwrap().take() {
            match t.join() {
                Ok(r) => {
                    if let Err(e) = r {
                        warn!("{}", e);
                    }
                }
                Err(e) => {
                    warn!("{:?}", e);
                }
            };
        }
        info!("debugger exited");
    }

    fn dispatch(
        conn: (&Arc<UdpSocket>, SocketAddr),
        payload: impl AsRef<[u8]>,
        debuggers: &ModuleDebuggers,
    ) -> Result<()> {
        let payload = payload.as_ref();
        let m = *payload.first().unwrap();
        let module = Module::try_from(m).unwrap_or_default();
        match module {
            Module::Platform => {
                let req = bincode::deserialize::<Message<PlatformMessage>>(payload)?.into_inner();
                let debugger = &debuggers.platform;
                let resp = match req {
                    PlatformMessage::Version(_) => debugger.api_version(),
                    PlatformMessage::WatcherReq(w) => debugger.watcher(w),
                    PlatformMessage::MacMappings(_) => debugger.mac_mapping(),
                    _ => unreachable!(),
                };
                iter_send_to(conn.0, conn.1, resp.iter())?;
            }
            Module::Rpc => {
                let req = bincode::deserialize::<Message<RpcMessage>>(payload)?.into_inner();
                let debugger = &debuggers.rpc;
                if let RpcMessage::PlatformData(_) = req {
                    let r = debugger.platform_data()?;
                    iter_send_to(conn.0, conn.1, r.iter())?;
                }
                let resp_result = match req {
                    RpcMessage::Acls(_) => debugger.flow_acls(),
                    RpcMessage::Cidr(_) => debugger.cidrs(),
                    RpcMessage::Config(_) => debugger.basic_config(),
                    RpcMessage::Groups(_) => debugger.ip_groups(),
                    RpcMessage::Segments(_) => debugger.local_segments(),
                    RpcMessage::TapTypes(_) => debugger.tap_types(),
                    RpcMessage::Version(_) => debugger.current_version(),
                    _ => unreachable!(),
                };

                let resp = match resp_result {
                    Ok(m) => m,
                    Err(e) => vec![Message {
                        module: Module::Rpc,
                        msg: RpcMessage::Err(e.to_string()),
                    }],
                };
                iter_send_to(conn.0, conn.1, resp.iter())?;
            }
            Module::Queue => {
                let req = bincode::deserialize::<Message<QueueMessage>>(payload)?.into_inner();
                let debugger = &debuggers.queue;
                match req {
                    QueueMessage::Clear => {
                        let msg = debugger.turn_off_all_queue();
                        send_to(conn.0, conn.1, &msg)?;
                    }
                    QueueMessage::Off(v) => {
                        let msg = debugger.turn_off_queue(v);
                        send_to(conn.0, conn.1, &msg)?;
                    }
                    QueueMessage::Names(_) => {
                        let msgs = debugger.queue_names();
                        iter_send_to(conn.0, conn.1, msgs.iter())?;
                    }
                    QueueMessage::On((name, duration)) => {
                        let msg = debugger.turn_on_queue(name.as_str());
                        send_to(conn.0, conn.1, &msg)?;
                        debugger.send(name, conn.1, duration);
                    }
                    _ => unreachable!(),
                }
            }
            Module::_Test => {
                let msg = bincode::deserialize::<Message<TestMessage>>(payload)?.into_inner();
                match msg {
                    TestMessage::Huge => {
                        let resp = Message {
                            module: Module::_Test,
                            msg: TestMessage::HugeResp(vec![1; 700]),
                        };
                        send_to(conn.0, conn.1, &resp)?;
                    }
                    _ => {
                        let resp = Message {
                            module: Module::_Test,
                            msg,
                        };
                        send_to(conn.0, conn.1, &resp)?
                    }
                }
            }
            _ => unreachable!(),
        }

        Ok(())
    }
}

pub struct Client {
    timeout: Duration,
    sock: UdpSocket,
}

impl Client {
    pub fn new(read_timeout: Option<Duration>, addr: impl ToSocketAddrs) -> Result<Self> {
        let read_timeout = read_timeout.or(Some(SESSION_TIMEOUT));
        let s = UdpSocket::bind(addr)?;
        s.set_read_timeout(read_timeout)?;
        Ok(Self {
            timeout: read_timeout.unwrap(),
            sock: s,
        })
    }

    pub fn send_to(&self, msg: &impl Serialize, addr: impl ToSocketAddrs + Clone) -> Result<()> {
        send_to(&self.sock, addr, msg)
    }

    pub fn recv<'de, D: Deserialize<'de>>(&self, buf: &'de mut [u8]) -> Result<D> {
        let (mut len, mut count, mut need_num) = (0, 0, 0);
        loop {
            let start = Instant::now();
            match self.sock.recv(&mut buf[len..]) {
                Ok(n) => {
                    if n == 0 {
                        break;
                    }
                    len += n - 1;
                    count += 1;
                    if need_num == 0 {
                        need_num = buf[len];
                    }
                    //结束就退出,免得等待TIMEOUT
                    if need_num == count {
                        break;
                    }
                }
                Err(e)
                    if start.elapsed() >= self.timeout
                        && (cfg!(target_os = "windows") && e.kind() == ErrorKind::TimedOut
                            || cfg!(target_os = "linux") && e.kind() == ErrorKind::WouldBlock) =>
                {
                    // normal timeout, Window=TimedOut UNIX=WouldBlock
                    break;
                }

                Err(e) => return Err(Error::IoError(e)),
            }
        }

        bincode::deserialize(&buf[..len]).map_err(|e| Error::BinCode(e))
    }
}

pub(super) fn send_to(
    sock: &UdpSocket,
    addr: impl ToSocketAddrs + Clone,
    msg: &impl Serialize,
) -> Result<()> {
    let encoded: Vec<u8> = bincode::serialize(msg)?;
    let pkt_len = (encoded.len() as f32 / MAX_CHUNK_SIZE as f32).ceil() as u8;
    if encoded.len() + pkt_len as usize > MAX_BUF_SIZE {
        return Err(Error::IoError(io::Error::new(
            ErrorKind::Other,
            "message length too large",
        )));
    }
    for chunk in encoded.chunks(MAX_CHUNK_SIZE) {
        sock.send_to([chunk, &[pkt_len]].concat().as_slice(), addr.clone())?;
    }
    Ok(())
}

pub(super) fn iter_send_to<I: Iterator>(
    sock: &UdpSocket,
    addr: impl ToSocketAddrs + Clone,
    msgs: I,
) -> Result<()>
where
    I::Item: Serialize,
{
    for msg in msgs {
        send_to(sock, addr.clone(), &msg)?
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv6Addr};

    use arc_swap::{access::Map, ArcSwap};
    use rand::random;

    use crate::config::handler::{DebugConfig, NewRuntimeConfig, PlatformConfig};
    use crate::platform::ActivePoller;
    use crate::{debug::Message, rpc::Session};

    use super::*;

    fn new_default_debug_ctx() -> ConstructDebugCtx {
        let s = String::from("yunshan");
        let session = Arc::new(Session::new(
            20035,
            0,
            Duration::from_secs(5),
            s.clone(),
            vec![String::from("10.1.20.21")],
        ));

        let current_config = Arc::new(ArcSwap::from_pointee(NewRuntimeConfig::default()));

        let static_config = Arc::new(StaticConfig::default());
        let status = Arc::new(RwLock::new(Status::default()));

        ConstructDebugCtx {
            api_watcher: Arc::new(ApiWatcher::new(
                Map::new(current_config.clone(), |config| -> &PlatformConfig {
                    &config.platform
                }),
                session.clone(),
            )),
            poller: Arc::new(GenericPoller::from(ActivePoller::new(Duration::from_secs(
                60,
            )))),
            session,
            static_config,
            status,
            config: Map::new(current_config.clone(), |config| -> &DebugConfig {
                &config.debug
            }),
        }
    }

    #[test]
    fn one_packet() {
        let timeout = Duration::from_secs(1);
        let port = 34444 + random::<u16>() % 1000;
        let ctx = new_default_debug_ctx();
        let mut server = Debugger::new(ctx);
        server.udp_options = (
            timeout,
            Some((IpAddr::from(LISTENED_IP.parse::<Ipv6Addr>().unwrap()), port).into()),
            timeout,
        );
        let client = Client::new(Some(timeout), (LISTENED_IP, 0)).unwrap();

        server.start();
        std::thread::sleep(Duration::from_secs(1));
        let mut buf = [0u8; 256];
        let msg = Message {
            module: Module::_Test,
            msg: TestMessage::new_small(),
        };
        client.send_to(&msg, ("127.0.0.1", port)).unwrap();
        let res: Message<TestMessage> = client.recv(&mut buf).unwrap();
        assert_eq!(msg, res);
        client.send_to(&msg, ("127.0.0.1", port)).unwrap();
        let res: Message<TestMessage> = client.recv(&mut buf).unwrap();
        assert_eq!(msg, res);
        client.send_to(&msg, ("127.0.0.1", port)).unwrap();
        let res: Message<TestMessage> = client.recv(&mut buf).unwrap();
        assert_eq!(msg, res);
        server.stop();
    }

    #[test]
    fn multi_packet() {
        let timeout = Duration::from_secs(1);
        let port = 34444 + random::<u16>() % 1000;
        let ctx = new_default_debug_ctx();
        let mut server = Debugger::new(ctx);
        server.udp_options = (
            timeout,
            Some((IpAddr::from(LISTENED_IP.parse::<Ipv6Addr>().unwrap()), port).into()),
            timeout,
        );
        let client = Client::new(Some(timeout), (LISTENED_IP, 0)).unwrap();
        server.start();
        std::thread::sleep(Duration::from_secs(1));
        let mut buf = [0u8; MAX_BUF_SIZE];
        let msg = Message {
            module: Module::_Test,
            msg: TestMessage::new_huge(),
        };
        client.send_to(&msg, ("127.0.0.1", port)).unwrap();
        let res = client
            .recv::<Message<TestMessage>>(&mut buf)
            .unwrap()
            .into_inner();
        if let TestMessage::HugeResp(v) = res {
            assert_eq!(v, vec![1; 700]);
        } else {
            assert_eq!(1, 2);
        }

        client.send_to(&msg, ("127.0.0.1", port)).unwrap();
        let res = client
            .recv::<Message<TestMessage>>(&mut buf)
            .unwrap()
            .into_inner();
        if let TestMessage::HugeResp(v) = res {
            assert_eq!(v, vec![1; 700]);
        } else {
            assert_eq!(1, 2);
        }

        server.stop();
    }

    #[test]
    #[ignore = "用于和trident-ctl调试"]
    fn list() {
        let timeout = Duration::from_secs(1);
        let ctx = new_default_debug_ctx();
        let mut server = Debugger::new(ctx);
        server.udp_options = (timeout, None, Duration::ZERO);
        server.start();
        std::thread::sleep(Duration::from_secs(10000));
    }
}
