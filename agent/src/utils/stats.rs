/*
 * Copyright (c) 2023 Yunshan Networks
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

use std::fmt;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::{
    atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering},
    Arc, Condvar, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cadence::{Metric, MetricBuilder, MetricError, MetricResult, MetricSink, StatsdClient};
use log::{debug, info, warn};
use prost::Message;

use crate::rpc::get_timestamp;
pub use public::counter::*;
use public::{
    proto::stats,
    queue::{bounded, Receiver, Sender},
    sender::{SendMessageType, Sendable},
};

const STATS_PREFIX: &'static str = "deepflow_agent";
const TICK_CYCLE: Duration = Duration::from_secs(10);
const STATS_SENDER_QUEUE_SIZE: usize = 4096;

pub enum StatsOption {
    Tag(&'static str, String),
    Interval(Duration),
}

struct Source {
    module: &'static str,
    interval: Duration,
    countable: Countable,
    tags: Vec<(&'static str, String)>,
    // countdown to next metrics collection
    skip: i64,
}

impl PartialEq for Source {
    fn eq(&self, other: &Source) -> bool {
        self.module == other.module && self.tags == other.tags
    }
}

impl Eq for Source {}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}-{:?}", self.module, self.tags)
    }
}

#[derive(Debug)]
pub struct Batch {
    module: &'static str,
    hostname: String,
    tags: Vec<(&'static str, String)>,
    points: Vec<Counter>,
    timestamp: u32,
}

impl Batch {
    fn to_stats(&self) -> stats::Stats {
        let mut tag_names = vec![];
        let mut tag_values = vec![];
        let mut metrics_float_names = vec![];
        let mut metrics_float_values = vec![];

        let mut has_host = false;
        for t in self.tags.iter() {
            if t.0 == "host" {
                has_host = true;
            }
            tag_names.push(t.0.to_string());
            tag_values.push(t.1.clone());
        }
        if !has_host {
            tag_names.push("host".to_string());
            tag_values.push(self.hostname.clone());
        }

        for p in self.points.iter() {
            metrics_float_names.push(p.0.to_string());
            match p.2 {
                CounterValue::Signed(i) => metrics_float_values.push(i as f64),
                CounterValue::Unsigned(u) => metrics_float_values.push(u as f64),
                CounterValue::Float(f) => metrics_float_values.push(f),
            }
        }

        stats::Stats {
            name: format!("{}_{}", STATS_PREFIX, self.module).replace("-", "_"),
            timestamp: self.timestamp as u64,
            tag_names,
            tag_values,
            metrics_float_names,
            metrics_float_values,
        }
    }
}

#[derive(Debug)]
pub struct ArcBatch(Arc<Batch>);

impl Sendable for ArcBatch {
    fn encode(self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        let pb_stats: stats::Stats = self.0.to_stats();
        pb_stats.encode(buf).map(|_| pb_stats.encoded_len())
    }

    fn message_type(&self) -> SendMessageType {
        SendMessageType::DeepflowStats
    }
}

pub struct Collector {
    hostname: Arc<Mutex<String>>,

    sources: Arc<Mutex<Vec<Source>>>,
    pre_hooks: Arc<Mutex<Vec<Box<dyn FnMut() + Send>>>>,

    min_interval: Arc<AtomicU64>,

    ntp_diff: Arc<AtomicI64>,
    running: Arc<(Mutex<bool>, Condvar)>,
    thread: Mutex<Option<JoinHandle<()>>>,

    sender: Arc<Sender<ArcBatch>>,
    receiver: Arc<Receiver<ArcBatch>>,
}

impl Collector {
    pub fn new<S: AsRef<str>>(hostname: S, ntp_diff: Arc<AtomicI64>) -> Self {
        Self::with_min_interval(hostname, TICK_CYCLE, ntp_diff)
    }

    pub fn with_min_interval<S: AsRef<str>>(
        hostname: S,
        interval: Duration,
        ntp_diff: Arc<AtomicI64>,
    ) -> Self {
        let (stats_queue_sender, stats_queue_receiver, counter) = bounded(STATS_SENDER_QUEUE_SIZE);
        let min_interval = if interval <= TICK_CYCLE {
            TICK_CYCLE
        } else {
            Duration::from_secs(
                (interval.as_secs() + TICK_CYCLE.as_secs() - 1) / TICK_CYCLE.as_secs()
                    * TICK_CYCLE.as_secs(),
            )
        };
        let s = Self {
            hostname: Arc::new(Mutex::new(hostname.as_ref().to_owned())),
            sources: Arc::new(Mutex::new(vec![])),
            pre_hooks: Arc::new(Mutex::new(vec![])),
            min_interval: Arc::new(AtomicU64::new(min_interval.as_secs())),
            running: Arc::new((Mutex::new(false), Condvar::new())),
            thread: Mutex::new(None),
            sender: Arc::new(stats_queue_sender),
            receiver: Arc::new(stats_queue_receiver),
            ntp_diff,
        };
        Self::register_countable(
            &s,
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![
                StatsOption::Tag("module", "0-stats-to-sender".to_string()),
                StatsOption::Tag("index", "0".to_string()),
            ],
        );
        return s;
    }

    pub fn get_receiver(&self) -> Arc<Receiver<ArcBatch>> {
        self.receiver.clone()
    }

    pub fn register_countable(
        &self,
        module: &'static str,
        countable: Countable,
        options: Vec<StatsOption>,
    ) {
        let mut source = Source {
            module,
            interval: Duration::from_secs(self.min_interval.load(Ordering::Relaxed)),
            countable,
            tags: vec![],
            skip: 0,
        };
        for option in options {
            match option {
                StatsOption::Tag(k, v) if !source.tags.iter().any(|(key, _)| key == &k) => {
                    source.tags.push((k, v))
                }
                StatsOption::Interval(interval)
                    if interval.as_secs() >= self.min_interval.load(Ordering::Relaxed) =>
                {
                    source.interval = Duration::from_secs(
                        interval.as_secs() / TICK_CYCLE.as_secs() * TICK_CYCLE.as_secs(),
                    )
                }
                _ => warn!(
                    "ignored duplicated tag or invalid interval for module {}",
                    source.module
                ),
            }
        }
        if source.interval > TICK_CYCLE {
            source.skip = ((60
                - SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    % 60)
                / TICK_CYCLE.as_secs()) as i64;
        }
        let mut sources = self.sources.lock().unwrap();
        sources.retain(|s| {
            let closed = s.countable.closed();
            let equals = s == &source;
            if !closed && equals {
                warn!(
                    "Found duplicated counter source {}, please check if the old one is correctly closed.",
                    source
                );
            }
            !closed && !equals
        });
        sources.push(source);
    }

    pub fn deregister_countables<I>(&self, countables: I)
    where
        I: Iterator<Item = (&'static str, Vec<StatsOption>)>,
    {
        let mut tags = vec![];
        let mut sources = self.sources.lock().unwrap();
        for (module, options) in countables {
            tags.clear();
            for option in options {
                match option {
                    StatsOption::Tag(k, v) if !tags.iter().any(|(key, _)| key == &k) => {
                        tags.push((k, v))
                    }
                    _ => (),
                }
            }
            sources.retain(|s| !(s.module == module && s.tags == tags));
        }
    }

    pub fn register_pre_hook(&self, hook: Box<dyn FnMut() + Send>) {
        self.pre_hooks.lock().unwrap().push(hook);
    }

    pub fn set_hostname(&self, hostname: String) {
        let mut last = self.hostname.lock().unwrap();
        if *last != hostname {
            info!("set stats hostname to {:?}", hostname);
            *last = hostname;
        }
    }

    pub fn set_min_interval(&self, interval: Duration) {
        self.min_interval
            .store(interval.as_secs(), Ordering::Relaxed);
    }

    fn new_statsd_client<A: ToSocketAddrs + std::fmt::Debug>(
        addr: A,
    ) -> MetricResult<StatsdClient> {
        info!("stats client connect to {:?}", &addr);

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let sink = DropletSink::from(addr, socket)?;
        Ok(StatsdClient::from_sink(STATS_PREFIX, sink))
    }

    fn send_metrics<'a, T: Metric + From<String>>(
        mut b: MetricBuilder<'a, '_, T>,
        host: &'a str,
        tags: &'a Vec<(&'static str, String)>,
    ) {
        let mut has_host = false;
        for (k, v) in tags {
            if *k == "host" {
                has_host = true;
            }
            b = b.with_tag(k, v);
        }
        if !has_host {
            b = b.with_tag("host", host);
        }
        b.send();
    }

    pub fn notify_stop(&self) -> Option<JoinHandle<()>> {
        *self.running.0.lock().unwrap() = false;
        self.thread.lock().unwrap().take()
    }

    pub fn start(&self) {
        {
            let (started, _) = &*self.running;
            let mut started = started.lock().unwrap();
            if *started {
                return;
            }
            *started = true;
        }

        let running = self.running.clone();
        let sources = self.sources.clone();
        let pre_hooks = self.pre_hooks.clone();
        let hostname = self.hostname.clone();
        let min_interval = self.min_interval.clone();
        let sender = self.sender.clone();
        let ntp_diff = self.ntp_diff.clone();
        *self.thread.lock().unwrap() = Some(
            thread::Builder::new()
                .name("stats-collector".to_owned())
                .spawn(move || {
                    loop {
                        let host = hostname.lock().unwrap().clone();
                        {
                            pre_hooks.lock().unwrap().iter_mut().for_each(|hook| hook());
                        }

                        let now = get_timestamp(ntp_diff.load(Ordering::Relaxed)).as_secs() as u32;
                        {
                            let mut sources = sources.lock().unwrap();
                            let min_interval_loaded = min_interval.load(Ordering::Relaxed);
                            // TODO: use Vec::retain_mut after stablize in rust 1.61.0
                            sources.retain(|s| !s.countable.closed());
                            for source in sources.iter_mut() {
                                source.skip -= 1;
                                if source.skip > 0 {
                                    continue;
                                }
                                source.skip = (source.interval.as_secs().max(min_interval_loaded)
                                    / TICK_CYCLE.as_secs())
                                    as i64;
                                let points = source.countable.get_counters();
                                if !points.is_empty() {
                                    let batch = Arc::new(Batch {
                                        module: source.module,
                                        hostname: host.clone(),
                                        tags: source.tags.clone(),
                                        points,
                                        timestamp: now,
                                    });
                                    if let Err(_) = sender.send(ArcBatch(batch.clone())) {
                                        debug!(
                                        "stats to send queue failed because queue have terminated"
                                    );
                                    }
                                }
                            }
                        }

                        let (running, timer) = &*running;
                        let mut running = running.lock().unwrap();
                        if !*running {
                            break;
                        }
                        running = timer.wait_timeout(running, TICK_CYCLE).unwrap().0;
                        if !*running {
                            break;
                        }
                    }
                })
                .unwrap(),
        );
    }
}

struct DropletSink {
    addr: SocketAddr,
    socket: UdpSocket,
    buffer: Mutex<Vec<u8>>,
}

impl DropletSink {
    pub fn from<A>(to_addr: A, socket: UdpSocket) -> MetricResult<DropletSink>
    where
        A: ToSocketAddrs,
    {
        match to_addr.to_socket_addrs()?.next() {
            Some(addr) => Ok(DropletSink {
                addr,
                socket,
                // droplet magic
                buffer: Mutex::new(vec![0, 0, 0, 0, 2]),
            }),
            None => Err(MetricError::from((
                cadence::ErrorKind::InvalidInput,
                "No socket addresses yielded",
            ))),
        }
    }
}

impl MetricSink for DropletSink {
    fn emit(&self, metric: &str) -> io::Result<usize> {
        let mut buffer = self.buffer.lock().unwrap();
        buffer.truncate(5);
        buffer.extend_from_slice(metric.as_bytes());
        self.socket.send_to(&buffer[..], &self.addr)
    }

    // TODO: buffer metrics
}

#[derive(Default)]
pub struct AtomicTimeStats {
    pub count: AtomicU32,
    pub sum_ns: AtomicU64,
    pub max_ns: AtomicU64,
}

impl AtomicTimeStats {
    pub fn update(&self, duration: Duration) {
        self.sum_ns
            .fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        let _ = self
            .max_ns
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |x| {
                let nanos = duration.as_nanos() as u64;
                if x < nanos {
                    Some(nanos)
                } else {
                    None
                }
            });
    }
}
