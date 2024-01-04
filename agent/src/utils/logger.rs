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

use std::env;
use std::io;
use std::process;
use std::sync::{
    atomic::{AtomicI64, AtomicU32, AtomicU64, AtomicU8, Ordering},
    Arc, Weak,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::access::Access;
use flexi_logger::{writers::LogWriter, DeferredNow, Level, Record};

use public::{
    queue,
    sender::{SendMessageType, Sendable},
};

use super::stats;
use crate::{
    config::handler::{LogAccess, LogConfig, SenderAccess},
    exception::ExceptionHandler,
    sender::uniform_sender::UniformSenderThread,
};

macro_rules! write_message {
    ($self:expr, $config:expr, $now:expr, $($arg:tt)*) => {{
        use std::io::Write;
        let mut buffer = Vec::new();
        let dt = chrono::DateTime::<chrono::Local>::from(*$now).to_rfc3339();
        let hostname = if $config.host == "" {
            &$self.default_host
        } else {
            &$config.host
        };
        write!(&mut buffer, "{} {} {}[{}]: ", dt, hostname, $self.tag, process::id()).and_then(|_| {
            write!(&mut buffer, $($arg)*).and_then(|_| {
                if buffer[buffer.len() - 1] != '\n' as u8 {
                    buffer.push('\n' as u8);
                }
                $self.sender.send(LogBuffer(buffer)).map_err(|e| match e {
                    public::queue::Error::Terminated(..) => {
                        std::io::Error::new(std::io::ErrorKind::BrokenPipe, "queue terminated")
                    }
                    public::queue::Error::Timeout | public::queue::Error::BatchTooLarge(_) => unreachable!(),
                })
            })
        })
    }};
}

#[derive(Debug)]
pub struct LogBuffer(Vec<u8>);

impl Sendable for LogBuffer {
    fn encode(mut self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        let len = self.0.len();
        buf.append(&mut self.0);
        Ok(len)
    }

    fn message_type(&self) -> SendMessageType {
        SendMessageType::Syslog
    }
}

pub struct RemoteLogWriter {
    ntp_diff: Arc<AtomicI64>,

    default_host: String,
    tag: String,

    hourly_count: AtomicU32,
    last_hour: AtomicU8,

    config: LogAccess,

    sender: queue::Sender<LogBuffer>,
    uniform_sender: UniformSenderThread<LogBuffer>,
}

impl RemoteLogWriter {
    const INNER_QUEUE_SIZE: usize = 65536;

    pub fn new(
        default_host: String,
        tag: String,
        log_config: LogAccess,
        sender_config: SenderAccess,
        stats_collector: Arc<stats::Collector>,
        exception_handler: ExceptionHandler,
        ntp_diff: Arc<AtomicI64>,
    ) -> Self {
        let module = "remote_logger";
        let (sender, receiver, counter) = queue::bounded(Self::INNER_QUEUE_SIZE);
        stats_collector.register_countable(
            "queue",
            stats::Countable::Owned(Box::new(counter)),
            vec![
                stats::StatsOption::Tag("module", module.to_owned()),
                stats::StatsOption::Tag("index", "0".to_owned()),
            ],
        );
        let mut uniform_sender = UniformSenderThread::new(
            module,
            Arc::new(receiver),
            sender_config,
            stats_collector,
            exception_handler,
            true,
        );
        uniform_sender.start();
        Self {
            ntp_diff,
            default_host,
            tag: if &tag == "" {
                env::args().next().unwrap()
            } else {
                tag
            },
            hourly_count: Default::default(),
            last_hour: Default::default(),
            config: log_config,
            sender,
            uniform_sender,
        }
    }

    fn over_threshold(&self, config: &LogConfig, now: &SystemTime) -> bool {
        // TODO: variables accessed in single thread don't need to be atomic
        let threshold = config.log_threshold;
        if threshold == 0 {
            return false;
        }
        let this_hour = ((now.duration_since(UNIX_EPOCH).unwrap().as_secs() / 3600) % 24) as u8;
        let mut hourly_count = self.hourly_count.load(Ordering::Relaxed);
        if self.last_hour.swap(this_hour, Ordering::Relaxed) != this_hour {
            if hourly_count > threshold {
                let _ = write_message!(
                    &self,
                    config,
                    now,
                    "[WARN] Log threshold exceeded, lost {} logs.",
                    hourly_count - threshold
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
            let _ = write_message!(
                &self,
                config,
                now,
                "[WARN] Log threshold is exceeding, current config is {}.",
                threshold
            );
            return true;
        }
        false
    }
}

impl LogWriter for RemoteLogWriter {
    fn write(&self, now: &mut DeferredNow, record: &Record<'_>) -> io::Result<()> {
        let config = self.config.load();
        if !config.rsyslog_enabled {
            return Ok(());
        }

        let now: SystemTime = (*now.now()).into();
        let diff = self.ntp_diff.load(Ordering::Relaxed);
        let now = if diff > 0 {
            now.checked_add(Duration::from_nanos(diff as u64)).unwrap()
        } else {
            now.checked_sub(Duration::from_nanos(diff.abs() as u64))
                .unwrap()
        };

        if self.over_threshold(&config, &now) {
            return Ok(());
        }

        if let Some((file, line)) = record.file().zip(record.line()) {
            write_message!(
                &self,
                &config,
                &now,
                "[{}] {}:{} {}",
                record.level(),
                file,
                line,
                record.args(),
            )
        } else {
            write_message!(
                &self,
                &config,
                &now,
                "[{}] {}",
                record.level(),
                record.args(),
            )
        }
    }

    fn flush(&self) -> io::Result<()> {
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
    fn write(&self, _: &mut DeferredNow, record: &Record<'_>) -> io::Result<()> {
        match record.level() {
            Level::Error => &self.0.error,
            Level::Warn => &self.0.warning,
            _ => return Ok(()),
        }
        .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn flush(&self) -> io::Result<()> {
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
    fn write(&self, now: &mut DeferredNow, record: &Record<'_>) -> io::Result<()> {
        self.0
            .iter()
            .fold(Ok(()), |r, w| r.or(w.write(now, record)))
    }

    fn flush(&self) -> io::Result<()> {
        self.0.iter().fold(Ok(()), |r, w| r.or(w.flush()))
    }
}
