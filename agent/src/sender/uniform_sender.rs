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
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Weak,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

use arc_swap::access::Access;
use log::{debug, error, info, warn};
use public::sender::{SendMessageType, Sendable};
use rand::{thread_rng, RngCore};

use super::{get_sender_id, QUEUE_BATCH_SIZE};

use crate::config::handler::SenderAccess;
use crate::exception::ExceptionHandler;
use crate::utils::stats::{
    self, Collector, Countable, Counter, CounterType, CounterValue, RefCountable,
};
use public::proto::trident::{Exception, SocketType};
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

#[derive(Debug)]
struct Header {
    frame_size: u32, // tcp发送时，需要按此长度收齐数据后，再decode (FrameSize总长度，包含了 BaseHeader的长度)
    msg_type: SendMessageType,

    version: u32,  // 用来校验encode和decode是否配套
    sequence: u64, // 依次递增，接收方用来判断是否有丢包(UDP发送时)
    vtap_id: u16,  // roze用来上报server活跃的VTAP信息
}

impl Header {
    fn encode(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.frame_size.to_be_bytes().as_slice());
        buffer.push(self.msg_type.into());
        // syslog header is 5 bytes
        if matches!(self.msg_type, SendMessageType::Syslog) {
            return;
        }
        buffer.extend_from_slice(self.version.to_le_bytes().as_slice());
        buffer.extend_from_slice(self.sequence.to_le_bytes().as_slice());
        buffer.extend_from_slice(self.vtap_id.to_le_bytes().as_slice());
    }
}

struct Encoder<T> {
    id: usize,
    header: Header,

    buffer: Vec<u8>,
    _marker: PhantomData<T>,
}

impl<T: Sendable> Encoder<T> {
    const BUFFER_LEN: usize = 8192;
    pub fn new(id: usize, msg_type: SendMessageType, vtap_id: u16) -> Self {
        Self {
            id,
            buffer: Vec::with_capacity(Self::BUFFER_LEN),
            header: Header {
                msg_type,
                frame_size: 0,
                version: 0,
                sequence: 0,
                vtap_id,
            },
            _marker: PhantomData,
        }
    }

    fn set_msg_type_and_version(&mut self, s: &T) {
        if self.header.version != 0 {
            return;
        }
        self.header.msg_type = s.message_type();
        self.header.version = s.version();
    }

    pub fn cache_to_sender(&mut self, s: T) {
        if self.buffer.is_empty() {
            self.set_msg_type_and_version(&s);
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
        self.header.sequence += 1;
        self.header.encode(&mut self.buffer);
    }

    pub fn set_header_frame_size(&mut self) {
        let frame_size = self.buffer.len() as u32;
        self.buffer[0..4].copy_from_slice(frame_size.to_be_bytes().as_slice());
    }

    pub fn update_header_vtap_id(&mut self, vtap_id: u16) {
        self.header.vtap_id = vtap_id;
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

    // if true, cache message for batch sending
    // can be turned off if message already cached
    cached: bool,
}

impl<T: Sendable> UniformSenderThread<T> {
    pub fn new(
        name: &'static str,
        input: Arc<Receiver<T>>,
        config: SenderAccess,
        stats: Arc<Collector>,
        exception_handler: ExceptionHandler,
        cached: bool,
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
            cached,
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
            self.cached,
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

struct Connection {
    tcp_stream: Option<TcpStream>,

    reconnect_interval: u8,

    dst_ip: String,
    dst_port: u16,

    reconnect: bool,
    last_reconnect: Duration,
}

pub struct UniformSender<T> {
    id: usize,
    name: &'static str,

    input: Arc<Receiver<T>>,
    counter: Arc<SenderCounter>,

    encoder: Encoder<T>,
    conn: Connection,

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
        cached: bool,
    ) -> Self {
        let cfg = config.load();
        Self {
            id,
            name,
            input,
            counter: Arc::new(SenderCounter::default()),
            encoder: Encoder::new(0, SendMessageType::TaggedFlow, config.load().vtap_id),
            config,
            conn: Connection {
                tcp_stream: None,
                reconnect_interval: Self::DEFAULT_RECONNECT_INTERVAL,
                dst_ip: cfg.dest_ip.clone(),
                dst_port: cfg.dest_port,
                reconnect: false,
                last_reconnect: Duration::ZERO,
            },
            running,
            stats,
            stats_registered: false,
            exception_handler,
            buf_writer: None,
            file_path: String::new(),
            pre_file_path: String::new(),
            written_size: 0,
            cached,
        }
    }

    fn update_dst_ip_and_port(&mut self) {
        let cfg = self.config.load();

        if self.conn.dst_ip != cfg.dest_ip || self.conn.dst_port != cfg.dest_port {
            info!(
                "{} sender update dst from {}:{} to {}:{}",
                self.name, self.conn.dst_ip, self.conn.dst_port, cfg.dest_ip, cfg.dest_port
            );
            self.conn.reconnect = true;
            self.conn.last_reconnect = Duration::ZERO;
            self.conn.dst_ip = cfg.dest_ip.clone();
            self.conn.dst_port = cfg.dest_port;
        }
    }

    fn flush_encoder(&mut self) {
        if self.encoder.buffer_len() > 0 {
            self.encoder.set_header_frame_size();
            Self::send_buffer(
                &self.running,
                &self.name,
                &self.counter,
                &self.exception_handler,
                &mut self.conn,
                &self.encoder.get_buffer(),
            );
            self.encoder.reset_buffer();
        }
    }

    fn send_buffer(
        running: &Arc<AtomicBool>,
        name: &str,
        counter: &SenderCounter,
        exception_handler: &ExceptionHandler,
        conn: &mut Connection,
        buffer: &[u8],
    ) {
        if conn.reconnect || conn.tcp_stream.is_none() {
            if let Some(t) = conn.tcp_stream.take() {
                if let Err(e) = t.shutdown(Shutdown::Both) {
                    debug!("{} sender tcp stream shutdown failed {}", name, e);
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
            conn.tcp_stream = TcpStream::connect((conn.dst_ip.clone(), conn.dst_port)).ok();
            if let Some(tcp_stream) = conn.tcp_stream.as_mut() {
                if let Err(e) =
                    tcp_stream.set_write_timeout(Some(Duration::from_secs(Self::TCP_WRITE_TIMEOUT)))
                {
                    debug!("{} sender tcp stream set write timeout failed {}", name, e);
                    conn.tcp_stream.take();
                    return;
                }
                info!(
                    "{} sender tcp connection to {}:{} succeed.",
                    name, conn.dst_ip, conn.dst_port
                );
                conn.reconnect = false;
                conn.reconnect_interval = 0;
            } else {
                if counter.dropped.load(Ordering::Relaxed) == 0 {
                    exception_handler.set(Exception::AnalyzerSocketError);
                    if conn.dst_ip.is_empty() || conn.dst_ip == "0.0.0.0" {
                        warn!("'analyzer_ip' is not assigned, please check whether the Agent is successfully registered");
                    } else {
                        error!(
                            "{} sender tcp connection to {}:{} failed",
                            name, conn.dst_ip, conn.dst_port,
                        );
                    }
                }
                counter.dropped.fetch_add(1, Ordering::Relaxed);
                // reconnect after waiting 10 seconds + random 5 seconds to prevent frequent reconnection
                conn.reconnect_interval =
                    Self::DEFAULT_RECONNECT_INTERVAL + (thread_rng().next_u64() % 5) as u8;
                return;
            }
        }

        let tcp_stream = conn.tcp_stream.as_mut().unwrap();

        let mut write_offset = 0usize;
        while running.load(Ordering::Relaxed) {
            let result = tcp_stream.write(&buffer[write_offset..]);
            match result {
                Ok(size) => {
                    write_offset += size;
                    if write_offset == buffer.len() {
                        counter.tx.fetch_add(1, Ordering::Relaxed);
                        counter
                            .tx_bytes
                            .fetch_add(buffer.len() as u64, Ordering::Relaxed);
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    debug!("{} sender tcp stream write data block {}", name, e);
                    continue;
                }
                Err(e) => {
                    if counter.dropped.load(Ordering::Relaxed) == 0 {
                        exception_handler.set(Exception::AnalyzerSocketError);
                        error!(
                            "{} sender tcp stream write data to {}:{} failed: {}",
                            name, conn.dst_ip, conn.dst_port, e
                        );
                    }
                    counter.dropped.fetch_add(1, Ordering::Relaxed);
                    conn.tcp_stream.take();
                    break;
                }
            };
        }
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
        let mut kv_string = String::with_capacity(2048);
        let mut batch = Vec::with_capacity(QUEUE_BATCH_SIZE);
        while self.running.load(Ordering::Relaxed) {
            let socket_type = self.config.load().collector_socket_type;
            match self.input.recv_all(
                &mut batch,
                Some(Duration::from_secs(Self::QUEUE_READ_TIMEOUT)),
            ) {
                Ok(_) => {
                    for send_item in batch.drain(..) {
                        let message_type = send_item.message_type();
                        self.counter.rx.fetch_add(1, Ordering::Relaxed);
                        debug!(
                            "{} sender send item {}: {:?}",
                            self.name, message_type, send_item
                        );
                        let result = match socket_type {
                            SocketType::File => self.handle_target_file(send_item, &mut kv_string),
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
                        self.update_dst_ip_and_port();
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

        if self.written_size > (self.config.load().standalone_data_file_size as u64) << 20 {
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
            self.update_dst_ip_and_port();
            self.encoder
                .update_header_vtap_id(self.config.load().vtap_id);
            self.flush_encoder();
        }
        Ok(())
    }
}
