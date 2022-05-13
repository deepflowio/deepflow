use std::{
    io::Write,
    net::{IpAddr, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    thread::JoinHandle,
    time::Duration,
    time::SystemTime,
};

use log::{info, warn};

use super::{COMPRESSOR_PORT, ERR_INTERVAL, RCV_TIMEOUT, SEQUENCE_OFFSET};

use crate::utils::{
    bytes::write_u64_be,
    queue::{Error, Receiver},
    stats::{Counter, CounterType, CounterValue, RefCountable},
};

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
        let receiver = self.receiver.clone();

        let thread = thread::spawn(move || {
            let mut sequence = 0;
            let mut last_err_time = Duration::ZERO;
            let mut socket = None;
            while running.load(Ordering::Relaxed) {
                match receiver.recv(Some(RCV_TIMEOUT)) {
                    Ok(mut pkt) => {
                        if (socket.is_none() || reconnect.load(Ordering::Relaxed))
                            && !Self::connect(&reconnect, &mut socket, *dst_ip.lock().unwrap())
                        {
                            continue;
                        }

                        sequence += 1;
                        write_u64_be(&mut pkt[SEQUENCE_OFFSET..SEQUENCE_OFFSET + 8], sequence);
                        match socket.as_mut().unwrap().write(&pkt) {
                            Ok(n) => {
                                counter.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                                counter.tx.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(e) => {
                                let now = SystemTime::now()
                                    .duration_since(SystemTime::UNIX_EPOCH)
                                    .unwrap();
                                if now > last_err_time + ERR_INTERVAL {
                                    warn!("send tcp packet failed: {}", e);
                                    last_err_time = now;
                                    socket.take();
                                }
                            }
                        }
                    }
                    Err(Error::Terminated(..)) => break,
                    Err(Error::Timeout) => continue,
                }
            }
        });

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

    pub fn update_tsdb_ip(&self, ip: IpAddr) {
        *self.dst_ip.lock().unwrap() = ip;
        self.reconnect.store(true, Ordering::Relaxed);
    }

    fn connect(reconnect: &AtomicBool, socket: &mut Option<TcpStream>, dst_ip: IpAddr) -> bool {
        match TcpStream::connect((dst_ip, COMPRESSOR_PORT)) {
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
