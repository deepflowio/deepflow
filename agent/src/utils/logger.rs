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

use std::env;
use std::io::Result;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::process;
use std::sync::{
    atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering},
    Arc, Mutex, RwLock, Weak,
};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Local};
use flexi_logger::{writers::LogWriter, DeferredNow, Level, Record};

use super::stats;

#[derive(Clone)]
pub struct RemoteLogConfig {
    enabled: Arc<AtomicBool>,
    threshold: Arc<AtomicU32>,
    hostname: Arc<Mutex<String>>,
    remotes: Arc<RwLock<Vec<SocketAddr>>>,
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

    pub fn set_remotes<S: AsRef<str>>(&self, addrs: &[S], port: u16) {
        let remotes = addrs
            .iter()
            .map(|addr| SocketAddr::new(addr.as_ref().parse().unwrap(), port))
            .collect();
        *self.remotes.write().unwrap() = remotes;
    }
}

pub struct RemoteLogWriter {
    socket: UdpSocket,

    remotes: Arc<RwLock<Vec<SocketAddr>>>,
    enabled: Arc<AtomicBool>,
    threshold: Arc<AtomicU32>,
    hostname: Arc<Mutex<String>>,

    tag: String,
    header: Vec<u8>,

    hourly_count: AtomicU32,
    last_hour: AtomicU8,
}

impl RemoteLogWriter {
    pub fn new<S1: AsRef<str>, S2: AsRef<str>>(
        hostname: S1,
        addrs: &[S2],
        port: u16,
        tag: String,
        header: Vec<u8>,
    ) -> (Self, RemoteLogConfig) {
        let enabled: Arc<AtomicBool> = Default::default();
        let threshold: Arc<AtomicU32> = Default::default();
        let hostname = Arc::new(Mutex::new(hostname.as_ref().to_owned()));
        let remotes = Arc::new(RwLock::new(
            addrs
                .iter()
                .map(|addr| SocketAddr::new(addr.as_ref().parse().unwrap(), port))
                .collect(),
        ));
        (
            Self {
                remotes: remotes.clone(),
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
                remotes,
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
        let remotes = self.remotes.read().unwrap();
        for remote in remotes.iter() {
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

#[derive(Default)]
struct Counter {
    error: AtomicU64,
    warning: AtomicU64,
}

// A writer calculating log count by level without actually writing log
pub struct LogLevelWriter(Arc<Counter>);

impl LogLevelWriter {
    pub fn new() -> (Self, LogLevelCounter) {
        let c = Arc::new(Counter::default());
        (Self(c.clone()), LogLevelCounter(Arc::downgrade(&c)))
    }
}

impl LogWriter for LogLevelWriter {
    fn write(&self, _: &mut DeferredNow, record: &Record<'_>) -> Result<()> {
        match record.level() {
            Level::Error => &self.0.error,
            Level::Warn => &self.0.warning,
            _ => return Ok(()),
        }
        .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        Ok(())
    }
}

pub struct LogLevelCounter(Weak<Counter>);

impl stats::OwnedCountable for LogLevelCounter {
    fn get_counters(&self) -> Vec<stats::Counter> {
        match self.0.upgrade() {
            Some(counters) => vec![
                (
                    "error",
                    stats::CounterType::Counted,
                    stats::CounterValue::Unsigned(counters.error.swap(0, Ordering::Relaxed)),
                ),
                (
                    "warning",
                    stats::CounterType::Counted,
                    stats::CounterValue::Unsigned(counters.warning.swap(0, Ordering::Relaxed)),
                ),
            ],
            None => vec![],
        }
    }

    fn closed(&self) -> bool {
        self.0.strong_count() == 0
    }
}

pub struct LogWriterAdapter(Vec<Box<dyn LogWriter>>);

impl LogWriterAdapter {
    pub fn new(writers: Vec<Box<dyn LogWriter>>) -> Self {
        Self(writers)
    }
}

impl LogWriter for LogWriterAdapter {
    fn write(&self, now: &mut DeferredNow, record: &Record<'_>) -> Result<()> {
        self.0
            .iter()
            .fold(Ok(()), |r, w| r.or(w.write(now, record)))
    }

    fn flush(&self) -> Result<()> {
        self.0.iter().fold(Ok(()), |r, w| r.or(w.flush()))
    }
}
