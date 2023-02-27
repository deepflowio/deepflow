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

use std::fs::{create_dir_all, rename, File, OpenOptions};
use std::io::{BufWriter, ErrorKind, Write};
use std::marker::PhantomData;
use std::net::{Shutdown, TcpStream};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Weak,
};
use std::thread;
use std::time::Duration;

use arc_swap::access::Access;
use log::{debug, error, info, warn};
use public::sender::{SendMessageType, Sendable};
use thread::JoinHandle;

use super::{get_sender_id, QUEUE_BATCH_SIZE};

use crate::config::handler::SenderAccess;
use crate::exception::ExceptionHandler;
use crate::utils::stats::{
    Collector, Countable, Counter, CounterType, CounterValue, RefCountable, StatsOption,
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

    pub fn get_buffer(&mut self) -> Vec<u8> {
        self.buffer.drain(..).collect()
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

    pub fn stop(&mut self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            warn!(
                "uniform sender id: {} already stopped, do nothing.",
                self.id
            );
            return;
        }
        info!("stoping uniform sender id: {}", self.id);
        let _ = self.thread_handle.take().unwrap().join();
        info!("stopped uniform sender id: {}", self.id);
    }
}

pub struct UniformSender<T> {
    id: usize,
    name: &'static str,

    input: Arc<Receiver<T>>,
    counter: Arc<SenderCounter>,

    tcp_stream: Option<TcpStream>,
    encoder: Encoder<T>,
    last_flush: Duration,

    dst_ip: String,
    dst_port: u16,
    config: SenderAccess,
    reconnect: bool,

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
        Self {
            id,
            name,
            input,
            counter: Arc::new(SenderCounter::default()),
            encoder: Encoder::new(0, SendMessageType::TaggedFlow, config.load().vtap_id),
            last_flush: Duration::ZERO,
            dst_ip: config.load().dest_ip.clone(),
            dst_port: config.load().dest_port,
            config,
            tcp_stream: None,
            reconnect: false,
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
        if self.dst_ip != self.config.load().dest_ip {
            info!(
                "{} sender update dst ip from {} to {}",
                self.name,
                self.dst_ip,
                self.config.load().dest_ip
            );
            self.reconnect = true;
            self.dst_ip = self.config.load().dest_ip.clone();
        }

        if self.dst_port != self.config.load().dest_port {
            info!(
                "{} sender update dst port from {} to {}",
                self.name,
                self.dst_port,
                self.config.load().dest_port
            );
            self.reconnect = true;
            self.dst_port = self.config.load().dest_port;
        }
    }

    fn flush_encoder(&mut self) {
        if self.encoder.buffer_len() > 0 {
            self.encoder.set_header_frame_size();
            let buffer = self.encoder.get_buffer();
            self.send_buffer(buffer.as_slice());
        }
    }

    fn send_buffer(&mut self, buffer: &[u8]) {
        if self.reconnect || self.tcp_stream.is_none() {
            if let Some(t) = self.tcp_stream.take() {
                if let Err(e) = t.shutdown(Shutdown::Both) {
                    debug!("{} sender tcp stream shutdown failed {}", self.name, e);
                }
            }
            self.tcp_stream = TcpStream::connect((self.dst_ip.clone(), self.dst_port)).ok();
            if let Some(tcp_stream) = self.tcp_stream.as_mut() {
                if let Err(e) =
                    tcp_stream.set_write_timeout(Some(Duration::from_secs(Self::TCP_WRITE_TIMEOUT)))
                {
                    debug!(
                        "{} sender tcp stream set write timeout failed {}",
                        self.name, e
                    );
                    self.tcp_stream.take();
                    return;
                }
                self.reconnect = false;
            } else {
                if self.counter.dropped.load(Ordering::Relaxed) == 0 {
                    self.exception_handler.set(Exception::AnalyzerSocketError);
                    if self.dst_ip.is_empty() {
                        error!("'analyzer_ip' is not assigned, please check whether the Agent is successfully registered");
                    } else {
                        error!(
                            "{} sender tcp connection to {}:{} failed",
                            self.name, self.dst_ip, self.dst_port,
                        );
                    }
                }
                self.counter.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        let tcp_stream = self.tcp_stream.as_mut().unwrap();

        let mut write_offset = 0usize;
        loop {
            let result = tcp_stream.write(&buffer[write_offset..]);
            match result {
                Ok(size) => {
                    write_offset += size;
                    if write_offset == buffer.len() {
                        self.counter.tx.fetch_add(1, Ordering::Relaxed);
                        self.counter
                            .tx_bytes
                            .fetch_add(buffer.len() as u64, Ordering::Relaxed);
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
                            self.name, self.dst_ip, self.dst_port, e
                        );
                    }
                    self.counter.dropped.fetch_add(1, Ordering::Relaxed);
                    self.tcp_stream.take();
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
            "collect_sender",
            Countable::Ref(Arc::downgrade(&self.counter) as Weak<dyn RefCountable>),
            vec![StatsOption::Tag("type", message_type.to_string())],
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
                Err(Error::Terminated(_, _)) => {
                    match socket_type {
                        SocketType::File => self.flush_writer(),
                        _ => self.flush_encoder(),
                    }
                    break;
                }
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
