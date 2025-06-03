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

use std::fs::{create_dir_all, rename, File, OpenOptions};
use std::io::{BufWriter, ErrorKind, Write};
use std::marker::PhantomData;
use std::net::{Shutdown, TcpStream};
use std::path::Path;
use std::sync::Mutex;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Weak,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use arc_swap::access::Access;
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use public::sender::{SendMessageType, Sendable};
use rand::{thread_rng, RngCore};

use super::{get_sender_id, QUEUE_BATCH_SIZE};

use crate::config::handler::{SenderAccess, SenderConfig};
use crate::exception::ExceptionHandler;
use crate::trident::SenderEncoder;
use crate::utils::stats::{
    self, Collector, Countable, Counter, CounterType, CounterValue, RefCountable,
};
use public::proto::agent::{Exception, SocketType};
use public::queue::{Error, Receiver};

const PRE_FILE_SUFFIX: &str = ".pre";

#[derive(Debug, Default)]
pub struct SenderCounter {
    pub rx: AtomicU64,
    pub tx: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub dropped: AtomicU64,
}

impl RefCountable for SenderCounter {
    fn get_counters(&self) -> Vec<Counter> {
        vec![
            (
                "rx",
                CounterType::Counted,
                CounterValue::Unsigned(self.rx.swap(0, Ordering::Relaxed)),
            ),
            (
                "tx",
                CounterType::Counted,
                CounterValue::Unsigned(self.tx.swap(0, Ordering::Relaxed)),
            ),
            (
                "tx-bytes",
                CounterType::Counted,
                CounterValue::Unsigned(self.tx_bytes.swap(0, Ordering::Relaxed)),
            ),
            (
                "dropped",
                CounterType::Counted,
                CounterValue::Unsigned(self.dropped.swap(0, Ordering::Relaxed)),
            ),
        ]
    }
}

//
// 0          8          16         24         32         40         48         56         64
// +----------+--------------------------------+----------+----------+----------+----------+
// | frame_size                                | msg_type | version             | encoder  |
// +----------+--------------------------------+----------+----------+----------+----------+
// | team_id                                   | orgnization_id      | rsvd_1              |
// +---------------------+----------+----------+---------------------+---------------------+
// | agent_id            | rsvd_2   |
// +--------------------------------+
//
const HEADER_VESION: u16 = 0x8000;

#[derive(Debug)]
struct Header {
    frame_size: u32,
    msg_type: SendMessageType,
    version: u16, // 从 0x8000 开始
    encoder: u8,
    team_id: u32,
    organization_id: u16,
    reserved_1: u16,
    agent_id: u16,
    reserved_2: u8,
}

impl Header {
    const HEADER_LEN: usize = 19;
    fn encode(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.frame_size.to_be_bytes().as_slice());
        buffer.push(self.msg_type.into());
        buffer.extend_from_slice(self.version.to_le_bytes().as_slice());
        buffer.push(self.encoder.into());
        buffer.extend_from_slice(self.team_id.to_le_bytes().as_slice());
        buffer.extend_from_slice(self.organization_id.to_le_bytes().as_slice());
        buffer.extend_from_slice(self.reserved_1.to_le_bytes().as_slice());
        buffer.extend_from_slice(self.agent_id.to_le_bytes().as_slice());
        buffer.push(self.reserved_2.into());
    }
}

struct Encoder<T> {
    id: usize,
    header: Header,

    buffer: Vec<u8>,
    _marker: PhantomData<T>,
}

impl<T: Sendable> Encoder<T> {
    const BUFFER_LEN: usize = 256 << 10;
    pub fn new(id: usize, msg_type: SendMessageType, agent_id: u16, encoder: u8) -> Self {
        Self {
            id,
            buffer: Vec::with_capacity(Self::BUFFER_LEN),
            header: Header {
                msg_type,
                frame_size: 0,
                version: HEADER_VESION,
                team_id: 0,
                organization_id: 0,
                agent_id: agent_id,
                reserved_1: 0,
                reserved_2: 0,
                encoder: encoder,
            },
            _marker: PhantomData,
        }
    }

    fn set_msg_type(&mut self, s: &T) {
        self.header.msg_type = s.message_type();
    }

    pub fn cache_to_sender(&mut self, s: T) {
        if self.buffer.is_empty() {
            self.set_msg_type(&s);
            self.add_header();
        }

        // Reserve 4 bytes pb length
        let offset = self.buffer.len();
        self.buffer.extend_from_slice([0u8; 4].as_slice());
        match s.encode(&mut self.buffer) {
            Ok(size) => self.buffer[offset..offset + 4]
                .copy_from_slice((size as u32).to_le_bytes().as_slice()),
            Err(e) => debug!("encode failed {}", e),
        };
    }

    fn add_header(&mut self) {
        self.header.encode(&mut self.buffer);
    }

    pub fn set_header_frame_size(&mut self) {
        let frame_size = self.buffer.len() as u32;
        self.buffer[0..4].copy_from_slice(frame_size.to_be_bytes().as_slice());
    }

    pub fn update_header(&mut self, name: &str, id: usize, config: &SenderAccess) {
        let config = config.load();
        if self.header.agent_id != config.agent_id
            || self.header.team_id != config.team_id
            || self.header.organization_id != config.organize_id as u16
        {
            info!(
                "{} id {} update agent id from {:?} to {:?}, team id from {:?} to {:?}, organization id from {:?} to {:?}.",
                name, id,
                self.header.agent_id, config.agent_id,
                self.header.team_id, config.team_id,
                self.header.organization_id, config.organize_id,
            );
            self.header.agent_id = config.agent_id;
            self.header.team_id = config.team_id;
            self.header.organization_id = config.organize_id as u16;
        }
    }

    pub fn compress_buffer(&mut self) {
        let buffer_len = self.buffer_len();
        match SenderEncoder::from(self.header.encoder).encode(&self.buffer[Header::HEADER_LEN..]) {
            Ok(result) => {
                if let Some(data) = result {
                    self.buffer.truncate(Header::HEADER_LEN);
                    self.buffer.extend_from_slice(&data);
                    debug!("compressed from {} to {}", buffer_len, data.len());
                }
            }
            Err(e) => {
                error!("compression failed {}", e);
            }
        };
    }

    pub fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    pub fn get_buffer(&self) -> &[u8] {
        &self.buffer[..]
    }

    pub fn reset_buffer(&mut self) {
        self.buffer.clear();
    }
}

pub struct UniformSenderThread<T> {
    id: usize,
    name: &'static str,
    input: Arc<Receiver<T>>,
    config: SenderAccess,

    thread_handle: Option<JoinHandle<()>>,

    running: Arc<AtomicBool>,
    stats: Arc<Collector>,
    exception_handler: ExceptionHandler,

    private_shared_conn: Option<Arc<Mutex<Connection>>>,
    sender_encoder: SenderEncoder,
}

impl<T: Sendable> UniformSenderThread<T> {
    pub fn new(
        name: &'static str,
        input: Arc<Receiver<T>>,
        config: SenderAccess,
        stats: Arc<Collector>,
        exception_handler: ExceptionHandler,
        private_shared_conn: Option<Arc<Mutex<Connection>>>,
        sender_encoder: SenderEncoder,
    ) -> Self {
        let running = Arc::new(AtomicBool::new(false));
        Self {
            id: get_sender_id() as usize,
            name,
            input,
            config,
            thread_handle: None,
            running,
            stats,
            exception_handler,
            private_shared_conn,
            sender_encoder,
        }
    }

    pub fn start(&mut self) {
        if self.running.swap(true, Ordering::Relaxed) {
            warn!(
                "{} uniform sender id: {} already started, do nothing.",
                self.name, self.id
            );
            return;
        }

        let mut uniform_sender = UniformSender::new(
            self.id,
            self.name,
            self.input.clone(),
            self.config.clone(),
            self.running.clone(),
            self.stats.clone(),
            self.exception_handler.clone(),
            self.private_shared_conn.clone(),
            self.sender_encoder,
        );
        self.thread_handle = Some(
            thread::Builder::new()
                .name("uniform-sender".to_owned())
                .spawn(move || uniform_sender.process())
                .unwrap(),
        );
        info!("{} uniform sender id: {} started", self.name, self.id);
    }

    pub fn notify_stop(&mut self) -> Option<JoinHandle<()>> {
        if !self.running.swap(false, Ordering::Relaxed) {
            warn!(
                "uniform sender id: {} already stopped, do nothing.",
                self.id
            );
            return None;
        }
        info!("notified stopping uniform sender id: {}", self.id);
        self.thread_handle.take()
    }

    pub fn stop(&mut self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            warn!(
                "uniform sender id: {} already stopped, do nothing.",
                self.id
            );
            return;
        }
        info!("stopping uniform sender id: {}", self.id);
        let _ = self.thread_handle.take().unwrap().join();
        info!("stopped uniform sender id: {}", self.id);
    }
}

lazy_static! {
    static ref GLOBAL_CONNECTION: Arc<Mutex<Connection>> = Arc::new(Mutex::new(Connection::new()));
    static ref TOTAL_SENT_BYTES: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    static ref SENT_START_DURATION: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    static ref LAST_LOGGING_DURATION: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionType {
    Global,
    PrivateShared,
    Private,
}

pub struct Connection {
    tcp_stream: Option<TcpStream>,

    reconnect_interval: u8,

    dest_ip: String,
    dest_port: u16,

    reconnect: bool,
    last_reconnect: Duration,
}

impl Connection {
    pub fn new() -> Self {
        Self {
            tcp_stream: None,
            reconnect_interval: 10,
            dest_ip: "127.0.0.1".to_string(),
            dest_port: 30033,
            reconnect: false,
            last_reconnect: Duration::ZERO,
        }
    }
}

pub struct UniformSender<T> {
    id: usize,
    name: &'static str,

    input: Arc<Receiver<T>>,
    counter: Arc<SenderCounter>,

    encoder: Encoder<T>,
    private_conn: Mutex<Connection>,
    private_shared_conn: Option<Arc<Mutex<Connection>>>,
    global_shared_conn: Arc<Mutex<Connection>>,
    connection_type: ConnectionType,
    multiple_sockets_to_ingester: bool,
    dest_ip: String,
    dest_port: u16,

    config: SenderAccess,

    running: Arc<AtomicBool>,
    stats: Arc<Collector>,
    stats_registered: bool,
    exception_handler: ExceptionHandler,
    buf_writer: Option<BufWriter<File>>,
    file_path: String,
    pre_file_path: String,
    written_size: u64,

    cached: bool,
}

impl<T: Sendable> UniformSender<T> {
    const TCP_WRITE_TIMEOUT: u64 = 3; // s
    const QUEUE_READ_TIMEOUT: u64 = 3; // s
    const DEFAULT_RECONNECT_INTERVAL: u8 = 10; // s

    pub fn new(
        id: usize,
        name: &'static str,
        input: Arc<Receiver<T>>,
        config: SenderAccess,
        running: Arc<AtomicBool>,
        stats: Arc<Collector>,
        exception_handler: ExceptionHandler,
        private_shared_conn: Option<Arc<Mutex<Connection>>>,
        sender_encoder: SenderEncoder,
    ) -> Self {
        let cfg = config.load();
        Self {
            id,
            name,
            input,
            counter: Arc::new(SenderCounter::default()),
            encoder: Encoder::new(
                0,
                SendMessageType::TaggedFlow,
                cfg.agent_id,
                u8::from(sender_encoder),
            ),
            config,
            private_conn: Mutex::new(Connection::new()),
            private_shared_conn,
            global_shared_conn: GLOBAL_CONNECTION.clone(),
            connection_type: ConnectionType::Global,
            multiple_sockets_to_ingester: false,
            dest_ip: "127.0.0.1".to_string(),
            dest_port: cfg.dest_port,

            running,
            stats,
            stats_registered: false,
            exception_handler,
            buf_writer: None,
            file_path: String::new(),
            pre_file_path: String::new(),
            written_size: 0,
            cached: true,
        }
    }

    fn update_connection(&mut self) {
        let cfg = self.config.load();

        if self.multiple_sockets_to_ingester != cfg.multiple_sockets_to_ingester
            || self.dest_ip != cfg.dest_ip
            || self.dest_port != cfg.dest_port
        {
            self.multiple_sockets_to_ingester = cfg.multiple_sockets_to_ingester;
            self.dest_ip = cfg.dest_ip.clone();
            self.dest_port = cfg.dest_port;

            let old_connnection_type = self.connection_type;
            // update connection type
            if self.multiple_sockets_to_ingester {
                if self.private_shared_conn.is_some() {
                    self.connection_type = ConnectionType::PrivateShared;
                } else {
                    self.connection_type = ConnectionType::Private;
                }
                self.global_shared_conn.lock().unwrap().tcp_stream.take();
            } else {
                self.connection_type = ConnectionType::Global;
                self.private_conn.lock().unwrap().tcp_stream.take();
                if let Some(conn) = self.private_shared_conn.as_ref() {
                    conn.lock().unwrap().tcp_stream.take();
                }
            }
            if old_connnection_type != self.connection_type {
                info!(
                    "{} sender update connection type from {:?} to {:?}",
                    self.name, old_connnection_type, self.connection_type
                );
            }

            let mut new_conn = match self.connection_type {
                ConnectionType::Global => self.global_shared_conn.lock().unwrap(),
                ConnectionType::PrivateShared => {
                    self.private_shared_conn.as_mut().unwrap().lock().unwrap()
                }
                ConnectionType::Private => self.private_conn.lock().unwrap(),
            };

            if new_conn.dest_ip != self.dest_ip || new_conn.dest_port != self.dest_port {
                info!(
                    "{} sender update dest address from {}:{} to {}:{}",
                    self.name, new_conn.dest_ip, new_conn.dest_port, self.dest_ip, self.dest_port
                );
                new_conn.reconnect = true;
                new_conn.dest_ip = self.dest_ip.clone();
                new_conn.dest_port = self.dest_port;
                new_conn.last_reconnect = Duration::ZERO;
            }
        }
    }

    fn flush_encoder(&mut self) {
        self.cached = true;
        if self.encoder.buffer_len() > 0 {
            self.encoder.compress_buffer();
            self.encoder.set_header_frame_size();
            self.send_buffer();
            self.encoder.reset_buffer();
        }
    }

    fn send_buffer(&mut self) {
        let mut conn = match self.connection_type {
            ConnectionType::Global => self.global_shared_conn.lock().unwrap(),
            ConnectionType::PrivateShared => {
                self.private_shared_conn.as_mut().unwrap().lock().unwrap()
            }
            ConnectionType::Private => self.private_conn.lock().unwrap(),
        };

        if conn.reconnect || conn.tcp_stream.is_none() {
            if let Some(t) = conn.tcp_stream.take() {
                if let Err(e) = t.shutdown(Shutdown::Both) {
                    debug!("{} sender tcp stream shutdown failed {}", self.name, e);
                }
            }
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap();
            // If the local timestamp adjustment requires recalculating the interval
            if conn.last_reconnect > now {
                conn.last_reconnect = now;
            }
            if conn.last_reconnect + Duration::from_secs(conn.reconnect_interval as u64) > now {
                return;
            }

            conn.last_reconnect = now;
            conn.tcp_stream = TcpStream::connect((conn.dest_ip.clone(), conn.dest_port)).ok();
            if let Some(tcp_stream) = conn.tcp_stream.as_mut() {
                if let Err(e) =
                    tcp_stream.set_write_timeout(Some(Duration::from_secs(Self::TCP_WRITE_TIMEOUT)))
                {
                    debug!(
                        "{} sender tcp stream set write timeout failed {}",
                        self.name, e
                    );
                    conn.tcp_stream.take();
                    return;
                }
                info!(
                    "{} sender tcp connection to {}:{} succeed.",
                    self.name, conn.dest_ip, conn.dest_port
                );
                conn.reconnect = false;
                conn.reconnect_interval = 0;
            } else {
                if self.counter.dropped.load(Ordering::Relaxed) == 0 {
                    self.exception_handler.set(Exception::AnalyzerSocketError);
                    if conn.dest_ip.is_empty() || conn.dest_ip == "0.0.0.0" {
                        warn!("'analyzer_ip' is not assigned, please check whether the Agent is successfully registered");
                    } else {
                        error!(
                            "{} sender tcp connection to {}:{} failed",
                            self.name, conn.dest_ip, conn.dest_port,
                        );
                    }
                }
                self.counter.dropped.fetch_add(1, Ordering::Relaxed);
                // reconnect after waiting 10 seconds + random 5 seconds to prevent frequent reconnection
                conn.reconnect_interval =
                    Self::DEFAULT_RECONNECT_INTERVAL + (thread_rng().next_u64() % 5) as u8;
                return;
            }
        }

        let tcp_stream = conn.tcp_stream.as_mut().unwrap();
        let buffer = &self.encoder.get_buffer();
        let mut write_offset = 0usize;
        while self.running.load(Ordering::Relaxed) {
            let result = tcp_stream.write(&buffer[write_offset..]);
            match result {
                Ok(size) => {
                    write_offset += size;
                    if write_offset == buffer.len() {
                        self.counter.tx.fetch_add(1, Ordering::Relaxed);
                        self.counter
                            .tx_bytes
                            .fetch_add(buffer.len() as u64, Ordering::Relaxed);
                        TOTAL_SENT_BYTES.fetch_add(buffer.len() as u64, Ordering::Relaxed);
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    debug!("{} sender tcp stream write data block {}", self.name, e);
                    continue;
                }
                Err(e) => {
                    if self.counter.dropped.load(Ordering::Relaxed) == 0 {
                        self.exception_handler.set(Exception::AnalyzerSocketError);
                        error!(
                            "{} sender tcp stream write data to {}:{} failed: {}",
                            self.name, conn.dest_ip, conn.dest_port, e
                        );
                    }
                    self.counter.dropped.fetch_add(1, Ordering::Relaxed);
                    conn.tcp_stream.take();
                    break;
                }
            };
        }
    }

    fn is_exceed_max_throughput(&mut self, max_throughput_mbps: u64) -> bool {
        if max_throughput_mbps == 0 {
            return false;
        }
        let max_throughput_bytes = max_throughput_mbps << 20 >> 3;
        if TOTAL_SENT_BYTES.load(Ordering::Relaxed) > max_throughput_bytes {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap();

            let used = now - Duration::from_nanos(SENT_START_DURATION.load(Ordering::Relaxed));
            if used > Duration::from_secs(1) {
                SENT_START_DURATION.store(now.as_nanos() as u64, Ordering::Relaxed);
                TOTAL_SENT_BYTES.store(0, Ordering::Relaxed);
            } else {
                // to prevent frequent log printing, print at least once every 5 seconds
                if now - Duration::from_nanos(LAST_LOGGING_DURATION.load(Ordering::Relaxed))
                    > Duration::from_secs(5)
                {
                    warn!(
                        "{} sender dropping message, throughput execeed setting value 'max_throughput_to_ingester' {}Mbps",
                        self.name, max_throughput_mbps
                    );
                    LAST_LOGGING_DURATION.store(now.as_nanos() as u64, Ordering::Relaxed);
                }
                self.exception_handler
                    .set(Exception::DataBpsThresholdExceeded);
                return true;
            }
        }
        return false;
    }

    fn check_or_register_counterable(&mut self, message_type: SendMessageType) {
        if self.stats_registered {
            return;
        }
        self.stats.register_countable(
            &stats::SingleTagModule("collect_sender", "type", message_type),
            Countable::Ref(Arc::downgrade(&self.counter) as Weak<dyn RefCountable>),
        );
        self.stats_registered = true;
    }

    pub fn process(&mut self) {
        let mut start_cached = Instant::now();
        let mut kv_string = String::with_capacity(2048);
        let mut batch = Vec::with_capacity(QUEUE_BATCH_SIZE);
        while self.running.load(Ordering::Relaxed) {
            let config = self.config.load();
            let socket_type = config.collector_socket_type;
            let max_throughput_mpbs = config.max_throughput_to_ingester;
            match self.input.recv_all(
                &mut batch,
                Some(Duration::from_secs(Self::QUEUE_READ_TIMEOUT)),
            ) {
                Ok(_) => {
                    // guaranteed to be sent every 10 seconds
                    if start_cached.elapsed() >= Duration::from_secs(10) {
                        start_cached = Instant::now();
                        self.cached = false;
                    }
                    if self.is_exceed_max_throughput(max_throughput_mpbs) {
                        self.counter
                            .dropped
                            .fetch_add(batch.len() as u64, Ordering::Relaxed);
                        batch.clear();
                        continue;
                    }
                    for send_item in batch.drain(..) {
                        if !self.running.load(Ordering::Relaxed) {
                            break;
                        }
                        let message_type = send_item.message_type();
                        self.counter.rx.fetch_add(1, Ordering::Relaxed);
                        debug!(
                            "{} sender send item {}: {:?}",
                            self.name, message_type, send_item
                        );

                        let result = match socket_type {
                            SocketType::File => {
                                self.handle_target_file(send_item, &mut kv_string, &config)
                            }
                            _ => self.handle_target_server(send_item),
                        };
                        if let Err(e) = result {
                            if self.counter.dropped.load(Ordering::Relaxed) == 0 {
                                warn!(
                                    "{} sender send item {} failed {}",
                                    self.name, message_type, e
                                );
                                // reopen write file and overwritten
                                let _ = self.buf_writer.take();
                            }
                            self.counter.dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Err(Error::Timeout) => match socket_type {
                    SocketType::File => self.flush_writer(),
                    _ => {
                        self.update_connection();
                        self.encoder.update_header(self.name, self.id, &self.config);
                        self.flush_encoder();
                    }
                },
                Err(Error::Terminated(..)) => {
                    match socket_type {
                        SocketType::File => self.flush_writer(),
                        _ => self.flush_encoder(),
                    }
                    break;
                }
                Err(Error::BatchTooLarge(_)) => unreachable!(),
            }
        }
    }

    pub fn flush_writer(&mut self) {
        if let Some(buf_writer) = self.buf_writer.as_mut() {
            _ = buf_writer.flush();
        }
    }

    pub fn handle_target_file(
        &mut self,
        send_item: T,
        kv_string: &mut String,
        config: &SenderConfig,
    ) -> std::io::Result<()> {
        send_item.to_kv_string(kv_string);
        if kv_string.is_empty() {
            return Ok(());
        }
        if self.file_path.is_empty() {
            create_dir_all(&self.config.load().standalone_data_file_dir)?;
            self.file_path = Path::new(&self.config.load().standalone_data_file_dir)
                .join(send_item.file_name())
                .to_str()
                .unwrap()
                .into();
            self.pre_file_path = format!("{}{}", &self.file_path, PRE_FILE_SUFFIX);
        }

        if self.buf_writer.is_none() {
            self.check_or_register_counterable(send_item.message_type());
            let f = OpenOptions::new()
                .create(true)
                .write(true)
                .open(&self.file_path)?;
            self.buf_writer = Some(BufWriter::new(f));
        }

        self.buf_writer
            .as_mut()
            .unwrap()
            .write_all(kv_string.as_bytes())?;
        self.written_size += kv_string.len() as u64;
        kv_string.truncate(0);

        if self.written_size > config.standalone_data_file_size {
            self.buf_writer.as_mut().unwrap().flush()?;
            self.buf_writer.take();
            rename(&self.file_path, &self.pre_file_path)?;
            self.written_size = 0;
        }

        Ok(())
    }

    pub fn handle_target_server(&mut self, send_item: T) -> std::io::Result<()> {
        self.encoder.cache_to_sender(send_item);
        if !self.cached || self.encoder.buffer_len() > Encoder::<T>::BUFFER_LEN {
            self.check_or_register_counterable(self.encoder.header.msg_type);
            self.update_connection();
            self.encoder.update_header(self.name, self.id, &self.config);
            self.flush_encoder();
        }
        Ok(())
    }
}
