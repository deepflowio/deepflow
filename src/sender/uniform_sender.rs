use std::io::{ErrorKind, Write};
use std::net::{IpAddr, Shutdown, TcpStream};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::Duration;
use thread::JoinHandle;

use log::{debug, info, warn};

use super::{SendItem, SendMessageType};
use crate::utils::{
    queue::{Error, Receiver},
    stats::{Countable, Counter, CounterType, CounterValue},
};

#[derive(Debug, Default)]
pub struct SenderCounter {
    pub tx: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub dropped: AtomicU64,
}

impl Countable for UniformSender {
    fn get_counters(&self) -> Vec<Counter> {
        vec![
            (
                "tx",
                CounterType::Counted,
                CounterValue::Unsigned(self.counter.tx.swap(0, Ordering::Relaxed)),
            ),
            (
                "tx-bytes",
                CounterType::Counted,
                CounterValue::Unsigned(self.counter.tx_bytes.swap(0, Ordering::Relaxed)),
            ),
            (
                "dropped",
                CounterType::Counted,
                CounterValue::Unsigned(self.counter.dropped.swap(0, Ordering::Relaxed)),
            ),
        ]
    }

    fn closed(&self) -> bool {
        !self.running.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
struct Header {
    frame_size: u32, // tcp发送时，需要按此长度收齐数据后，再decode (FrameSize总长度，包含了 BaseHeader的长度)
    msg_type: SendMessageType,

    version: u32,  // 用来校验encode和decode是否配套
    sequence: u64, // 依次递增，接收方用来判断是否有丢包(UDP发送时)
    vtap_id: u16,  // roze用来上报trisolaris活跃的VTAP信息
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

struct Encoder {
    id: usize,
    header: Header,

    buffer: Vec<u8>,
}

impl Encoder {
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
        }
    }

    fn set_msg_type_and_version(&mut self, s: &SendItem) {
        if self.header.version != 0 {
            return;
        }
        self.header.msg_type = s.message_type();
        self.header.version = s.version();
    }

    pub fn cache_to_sender(&mut self, s: SendItem) {
        if self.buffer.is_empty() {
            self.set_msg_type_and_version(&s);
            self.add_header();
        }
        // 预留4个字节pb长度
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

    pub fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    pub fn get_buffer(&mut self) -> Vec<u8> {
        self.buffer.drain(..).collect()
    }
}

pub struct UniformSenderThread {
    id: usize,
    uniform_sender: Option<UniformSender>,
    thread_handle: Option<JoinHandle<()>>,

    running: Arc<AtomicBool>,
}

impl UniformSenderThread {
    pub fn new(
        id: usize,
        vtap_id: u16,
        input: Receiver<SendItem>,
        dst_ip: Arc<Mutex<IpAddr>>,
    ) -> Self {
        let running = Arc::new(AtomicBool::new(false));
        Self {
            id,
            uniform_sender: Some(UniformSender::new(
                id,
                vtap_id,
                input,
                dst_ip,
                running.clone(),
            )),
            thread_handle: None,
            running,
        }
    }

    pub fn start(&mut self) {
        let mut uniform_sender = self.uniform_sender.take().unwrap();
        info!("starting uniform sender: {}", self.id);
        self.running.store(true, Ordering::Relaxed);
        self.thread_handle = Some(thread::spawn(move || uniform_sender.process()));
    }

    pub fn stop(&mut self) {
        info!("stoping uniform sender: {}", self.id);
        self.running.store(false, Ordering::Relaxed);
        let _ = self.thread_handle.take().unwrap().join();
        info!("stopped uniform sender: {}", self.id);
    }
}

pub struct UniformSender {
    id: usize,

    input: Receiver<SendItem>,
    counter: SenderCounter,

    tcp_stream: Option<TcpStream>,
    encoder: Encoder,
    last_flush: Duration,

    dst_ip_new: Arc<Mutex<IpAddr>>,
    dst_ip: IpAddr,
    reconnect: bool,

    running: Arc<AtomicBool>,
}

impl UniformSender {
    const DST_PORT: u16 = 20033;
    const TCP_WRITE_TIMEOUT: u64 = 3; // s
    const QUEUE_READ_TIMEOUT: u64 = 3; // s

    pub fn new(
        id: usize,
        vtap_id: u16,
        input: Receiver<SendItem>,
        dst_ip: Arc<Mutex<IpAddr>>,
        running: Arc<AtomicBool>,
    ) -> Self {
        Self {
            id,
            input,
            counter: SenderCounter::default(),
            encoder: Encoder::new(0, SendMessageType::TaggedFlow, vtap_id),
            last_flush: Duration::ZERO,
            dst_ip_new: dst_ip.clone(),
            dst_ip: *dst_ip.lock().unwrap(),
            tcp_stream: None,
            reconnect: false,
            running,
        }
    }

    fn update_dst_ip(&mut self) {
        if self.dst_ip != *self.dst_ip_new.lock().unwrap() {
            self.reconnect = true;
            self.dst_ip = *self.dst_ip_new.lock().unwrap();
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
                    debug!("tcp stream shutdown failed {}", e);
                }
            }
            self.tcp_stream = TcpStream::connect((self.dst_ip, Self::DST_PORT)).ok();
            if let Some(tcp_stream) = self.tcp_stream.as_mut() {
                if let Err(e) =
                    tcp_stream.set_write_timeout(Some(Duration::from_secs(Self::TCP_WRITE_TIMEOUT)))
                {
                    debug!("tcp stream set write timeout failed {}", e);
                    self.tcp_stream.take();
                    return;
                }
                self.reconnect = false;
            } else {
                if self.counter.dropped.load(Ordering::Relaxed) == 0 {
                    warn!(
                        "tcp connection to {}:{} failed",
                        self.dst_ip,
                        Self::DST_PORT
                    );
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
                    debug!("tcp stream write data block {}", e);
                    continue;
                }
                Err(e) => {
                    if self.counter.dropped.load(Ordering::Relaxed) == 0 {
                        warn!("tcp stream write data failed {}", e);
                    }
                    self.counter.dropped.fetch_add(1, Ordering::Relaxed);
                    self.tcp_stream.take();
                    break;
                }
            };
        }
    }

    pub fn process(&mut self) {
        while self.running.load(Ordering::Relaxed) {
            match self
                .input
                .recv(Some(Duration::from_secs(Self::QUEUE_READ_TIMEOUT)))
            {
                Ok(send_item) => {
                    info!("send itme: {}", send_item);
                    self.encoder.cache_to_sender(send_item);
                    if self.encoder.buffer_len() > Encoder::BUFFER_LEN {
                        self.update_dst_ip();
                        self.flush_encoder();
                    }
                }
                Err(Error::Timeout) => {
                    self.update_dst_ip();
                    self.flush_encoder();
                }
                Err(Error::Terminated(_, _)) => {
                    self.flush_encoder();
                    break;
                }
            }
        }
    }
}
