use std::env;
use std::io::Result;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::process;
use std::sync::{
    atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering},
    Arc, Mutex,
};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Local};
use flexi_logger::{writers::LogWriter, DeferredNow, Record};
use hostname;

pub struct RemoteLogConfig {
    enabled: Arc<AtomicBool>,
    threshold: Arc<AtomicU32>,
    hostname: Arc<Mutex<String>>,
}

impl RemoteLogConfig {
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn set_threshold(&self, threshold: u32) {
        self.threshold.store(threshold, Ordering::Relaxed);
    }

    pub fn set_hostname(&self, hostname: String) {
        *self.hostname.lock().unwrap() = hostname;
    }
}

pub struct RemoteLogWriter {
    remotes: Vec<SocketAddr>,
    socket: UdpSocket,

    enabled: Arc<AtomicBool>,
    threshold: Arc<AtomicU32>,
    hostname: Arc<Mutex<String>>,

    tag: String,
    header: Vec<u8>,

    hourly_count: AtomicU32,
    last_hour: AtomicU8,
}

impl RemoteLogWriter {
    pub fn new<S: AsRef<str>>(
        addrs: &[S],
        port: u16,
        tag: String,
        header: Vec<u8>,
    ) -> (Self, RemoteLogConfig) {
        let enabled: Arc<AtomicBool> = Default::default();
        let threshold: Arc<AtomicU32> = Default::default();
        let hostname = Arc::new(Mutex::new(
            hostname::get()
                .ok()
                .and_then(|c| c.into_string().ok())
                .unwrap_or_default(),
        ));
        (
            Self {
                remotes: addrs
                    .iter()
                    .map(|addr| SocketAddr::new(addr.as_ref().parse().unwrap(), port))
                    .collect(),
                socket: UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap(),
                enabled: enabled.clone(),
                threshold: threshold.clone(),
                hostname: hostname.clone(),
                tag: if &tag == "" {
                    env::args().next().unwrap()
                } else {
                    tag
                },
                header,
                hourly_count: Default::default(),
                last_hour: Default::default(),
            },
            RemoteLogConfig {
                enabled,
                threshold,
                hostname,
            },
        )
    }

    fn over_threshold(&self, now: &SystemTime) -> bool {
        // TODO: variables accessed in single thread don't need to be atomic
        let threshold = self.threshold.load(Ordering::Relaxed);
        if threshold == 0 {
            return false;
        }
        let this_hour = ((now.duration_since(UNIX_EPOCH).unwrap().as_secs() / 3600) % 24) as u8;
        let mut hourly_count = self.hourly_count.load(Ordering::Relaxed);
        if self.last_hour.swap(this_hour, Ordering::Relaxed) != this_hour {
            if hourly_count > threshold {
                let _ = self.write_message(
                    now,
                    format!(
                        "[WARN] Log threshold exceeded, lost {} logs.",
                        hourly_count - threshold
                    ),
                );
            }
            hourly_count = 0;
            self.hourly_count.store(0, Ordering::Relaxed);
        }

        self.hourly_count.fetch_add(1, Ordering::Relaxed);
        if hourly_count > threshold {
            return true;
        }
        if hourly_count == threshold {
            let _ = self.write_message(
                now,
                format!(
                    "[WARN] Log threshold is exceeding, current config is {}.",
                    threshold
                ),
            );
            return true;
        }
        false
    }

    fn write_message(&self, now: &SystemTime, message: String) -> Result<()> {
        // TODO: avoid buffer allocation
        let mut buffer = self.header.clone();
        let time_str = DateTime::<Local>::from(*now).to_rfc3339();
        buffer.extend_from_slice(time_str.as_bytes());
        buffer.push(' ' as u8);
        buffer.extend_from_slice(self.hostname.lock().unwrap().as_bytes());
        buffer.push(' ' as u8);
        buffer.extend_from_slice(self.tag.as_bytes());
        buffer.extend_from_slice(format!("[{}]", process::id()).as_bytes());
        buffer.push(':' as u8);
        buffer.push(' ' as u8);
        buffer.extend_from_slice(&message.into_bytes());
        if buffer[buffer.len() - 1] != '\n' as u8 {
            buffer.push('\n' as u8);
        }
        let mut result = Ok(());
        for remote in self.remotes.iter() {
            match self.socket.send_to(buffer.as_slice(), remote) {
                Err(e) => result = Err(e),
                _ => (),
            }
        }
        result
    }
}

impl LogWriter for RemoteLogWriter {
    fn write(&self, now: &mut DeferredNow, record: &Record<'_>) -> Result<()> {
        if !self.enabled.load(Ordering::Relaxed) {
            return Ok(());
        }
        let now: SystemTime = (*now.now()).into();
        if self.over_threshold(&now) {
            return Ok(());
        }
        if let Some((file, line)) = record.file().zip(record.line()) {
            self.write_message(
                &now,
                format!("[{}] {}:{} {}", record.level(), file, line, record.args()),
            )
        } else {
            self.write_message(&now, format!("[{}] {}", record.level(), record.args()))
        }
    }

    fn flush(&self) -> Result<()> {
        Ok(())
    }
}
