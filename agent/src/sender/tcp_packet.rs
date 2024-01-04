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
    io::Write,
    net::{IpAddr, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    thread::JoinHandle,
    time::Duration,
    time::SystemTime,
};

use log::{info, warn};

use super::QUEUE_BATCH_SIZE;

use crate::utils::{
    bytes::write_u64_be,
    stats::{Counter, CounterType, CounterValue, RefCountable},
};
use public::queue::{Error, Receiver};

const SEQUENCE_OFFSET: usize = 8;
const RCV_TIMEOUT: Duration = Duration::from_secs(1);
const ERR_INTERVAL: Duration = Duration::from_secs(30);
#[derive(Default)]
pub struct TcpPacketCounter {
    id: u32,
    tx: AtomicU64,
    tx_bytes: AtomicU64,
    running: Arc<AtomicBool>,
}

// FIXME: counter not registered
impl RefCountable for TcpPacketCounter {
    fn get_counters(&self) -> Vec<Counter> {
        vec![
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
        ]
    }
}

pub struct TcpPacketSender {
    dst_ip: Arc<Mutex<IpAddr>>,
    dst_port: Arc<AtomicU16>,
    reconnect: Arc<AtomicBool>,
    running: Arc<AtomicBool>,

    receiver: Arc<Receiver<Vec<u8>>>,
    counter: Arc<TcpPacketCounter>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl TcpPacketSender {
    pub fn new(
        id: u32,
        dst_ip: IpAddr,
        dst_port: u16,
        receiver: Receiver<Vec<u8>>,
    ) -> (Self, Arc<TcpPacketCounter>) {
        let running = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(TcpPacketCounter {
            running: running.clone(),
            id,
            ..Default::default()
        });
        (
            Self {
                dst_ip: Arc::new(Mutex::new(dst_ip)),
                dst_port: Arc::new(AtomicU16::new(dst_port)),
                reconnect: Arc::new(AtomicBool::new(true)),
                running,
                receiver: Arc::new(receiver),
                counter: counter.clone(),
                thread: Mutex::new(None),
            },
            counter,
        )
    }

    pub fn start(&self) {
        if self.running.swap(true, Ordering::Relaxed) {
            return;
        }

        let running = self.running.clone();
        let reconnect = self.reconnect.clone();
        let counter = self.counter.clone();
        let dst_ip = self.dst_ip.clone();
        let dst_port = self.dst_port.clone();
        let receiver = self.receiver.clone();

        let thread = thread::Builder::new()
            .name("tcp-packet-sender".to_owned())
            .spawn(move || {
                let mut sequence = 0;
                let mut last_err_time = Duration::ZERO;
                let mut socket = None;
                let mut batch = Vec::with_capacity(QUEUE_BATCH_SIZE);
                while running.load(Ordering::Relaxed) {
                    match receiver.recv_all(&mut batch, Some(RCV_TIMEOUT)) {
                        Ok(_) => {
                            for mut pkt in batch.drain(..) {
                                if (socket.is_none() || reconnect.load(Ordering::Relaxed))
                                    && !Self::connect(
                                        &reconnect,
                                        &mut socket,
                                        *dst_ip.lock().unwrap(),
                                        dst_port.load(Ordering::Relaxed),
                                    )
                                {
                                    continue;
                                }

                                sequence += 1;
                                write_u64_be(
                                    &mut pkt[SEQUENCE_OFFSET..SEQUENCE_OFFSET + 8],
                                    sequence,
                                );
                                match socket.as_mut().unwrap().write(&pkt) {
                                    Ok(n) => {
                                        counter.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                                        counter.tx.fetch_add(1, Ordering::Relaxed);
                                    }
                                    Err(e) => {
                                        let now = SystemTime::now()
                                            .duration_since(SystemTime::UNIX_EPOCH)
                                            .unwrap();
                                        // If the local timestamp adjustment requires recalculating the interval
                                        if last_err_time > now {
                                            last_err_time = now;
                                        }
                                        if now > last_err_time + ERR_INTERVAL {
                                            warn!("send tcp packet failed: {}", e);
                                            last_err_time = now;
                                            socket.take();
                                        }
                                    }
                                }
                            }
                        }
                        Err(Error::Terminated(..)) => break,
                        Err(Error::Timeout) => continue,
                        Err(Error::BatchTooLarge(_)) => unreachable!(),
                    }
                }
            })
            .unwrap();

        self.thread.lock().unwrap().replace(thread);
        info!("tcp packet sender started");
    }

    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::Relaxed) {
            return;
        }

        if let Some(t) = self.thread.lock().unwrap().take() {
            let _ = t.join();
        }
        info!("tcp packet sender exited");
    }

    pub fn update_tsdb_ip_and_port(&self, ip: IpAddr, port: u16) {
        *self.dst_ip.lock().unwrap() = ip;
        self.dst_port.store(port, Ordering::Relaxed);
        self.reconnect.store(true, Ordering::Relaxed);
    }

    fn connect(
        reconnect: &AtomicBool,
        socket: &mut Option<TcpStream>,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> bool {
        match TcpStream::connect((dst_ip, dst_port)) {
            Ok(s) => {
                socket.replace(s);
                reconnect.swap(false, Ordering::Relaxed);
                true
            }
            Err(e) => {
                warn!("tcp packet sender connect server: {}", e);
                false
            }
        }
    }
}
