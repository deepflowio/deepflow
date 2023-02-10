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

use std::fmt;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::{
    atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering},
    Arc, Condvar, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cadence::{
    Counted, Metric, MetricBuilder, MetricError, MetricResult, MetricSink, StatsdClient,
};
use log::{debug, info, warn};
use prost::Message;

pub use public::counter::*;
use public::{
    proto::stats,
    queue::{bounded, Receiver, Sender},
    sender::{SendMessageType, Sendable},
};

const STATS_PREFIX: &'static str = "deepflow_agent";
const TICK_CYCLE: Duration = Duration::from_secs(60);
pub const DFSTATS_SENDER_ID: usize = 100;

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
    timestamp: SystemTime,
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
            timestamp: self
                .timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
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

    remote: Arc<Mutex<Option<String>>>,
    remote_port: Arc<AtomicU16>,
    sources: Arc<Mutex<Vec<Source>>>,
    pre_hooks: Arc<Mutex<Vec<Box<dyn FnMut() + Send>>>>,

    min_interval: Arc<AtomicU64>,

    running: Arc<(Mutex<bool>, Condvar)>,
    thread: Mutex<Option<JoinHandle<()>>>,

    sender: Arc<Sender<ArcBatch>>,
    receiver: Arc<Receiver<ArcBatch>>,
}

impl Collector {
    pub fn new<S: AsRef<str>>(hostname: S, remote: String, port: u16) -> Self {
        Self::with_min_interval(hostname, remote, port, TICK_CYCLE)
    }

    pub fn with_min_interval<S: AsRef<str>>(
        hostname: S,
        remote: String,
        port: u16,
        interval: Duration,
    ) -> Self {
        let (stats_queue_sender, stats_queue_receiver, counter) = bounded(1000);
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
            remote: Arc::new(Mutex::new(Some(remote))),
            remote_port: Arc::new(AtomicU16::new(port)),
            sources: Arc::new(Mutex::new(vec![])),
            pre_hooks: Arc::new(Mutex::new(vec![])),
            min_interval: Arc::new(AtomicU64::new(min_interval.as_secs())),
            running: Arc::new((Mutex::new(false), Condvar::new())),
            thread: Mutex::new(None),
            sender: Arc::new(stats_queue_sender),
            receiver: Arc::new(stats_queue_receiver),
        };
        Self::register_countable(
            &s,
            "queue",
            Countable::Owned(Box::new(counter)),
            vec![StatsOption::Tag("module", "0-stats-to-sender".to_string())],
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
                    "Possible memory leak! countable {} is not correctly closed.",
                    source
                );
            }
            !closed && !equals
        });
        sources.push(source);
    }

    pub fn register_pre_hook(&self, hook: Box<dyn FnMut() + Send>) {
        self.pre_hooks.lock().unwrap().push(hook);
    }

    pub fn set_remote(&self, remote: String, port: u16) {
        info!("stats {} {}", &remote, port);
        self.remote.lock().unwrap().replace(remote);
        self.remote_port.store(port, Ordering::Relaxed);
    }

    pub fn set_hostname(&self, hostname: String) {
        *self.hostname.lock().unwrap() = hostname;
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

    pub fn start(&self) {
        {
            let (started, _) = &*self.running;
            let mut started = started.lock().unwrap();
            if *started {
                return;
            }
            *started = true;
        }

        let remote = self.remote.clone();
        let remote_port = self.remote_port.clone();
        let running = self.running.clone();
        let sources = self.sources.clone();
        let pre_hooks = self.pre_hooks.clone();
        let hostname = self.hostname.clone();
        let min_interval = self.min_interval.clone();
        let sender = self.sender.clone();
        *self.thread.lock().unwrap() = Some(
            thread::Builder::new()
                .name("stats-collector".to_owned())
                .spawn(move || {
                    let mut statsd_client: Option<StatsdClient> = None;
                    let mut old_remote = String::new();
                    loop {
                        let host = hostname.lock().unwrap().clone();
                        // for early exit
                        loop {
                            {
                                pre_hooks.lock().unwrap().iter_mut().for_each(|hook| hook());
                            }

                            let now = SystemTime::now();
                            let mut batches = vec![];
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
                                    source.skip =
                                        (source.interval.as_secs().max(min_interval_loaded)
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
                                        batches.push(batch);
                                    }
                                }
                            }
                            if batches.is_empty() {
                                break;
                            }

                            let port = remote_port.load(Ordering::Relaxed);
                            match remote.lock().unwrap().take() {
                                Some(remote) => {
                                    statsd_client = None;
                                    match Self::new_statsd_client((remote.clone(), port)) {
                                        Ok(client) => statsd_client = Some(client),
                                        Err(e) => {
                                            warn!(
                                                "create client to remote {}:{} failed: {}",
                                                &remote, port, e
                                            );
                                        }
                                    }
                                    old_remote = remote;
                                }
                                None => {
                                    if statsd_client.is_none() {
                                        match Self::new_statsd_client((old_remote.clone(), port)) {
                                            Ok(s) => {
                                                statsd_client.replace(s);
                                            }
                                            Err(e) => warn!(
                                                "create client to remote {}:{} failed: {}",
                                                &old_remote, port, e
                                            ),
                                        }
                                    }
                                }
                            }

                            if statsd_client.is_none() {
                                info!("no statsd remote available");
                                break;
                            }

                            debug!("collected: {:?}", batches);
                            let client = statsd_client.as_ref().unwrap();
                            for batch in batches.into_iter() {
                                for point in batch.points.iter() {
                                    let metric_name =
                                        format!("{}_{}", batch.module, point.0).replace("-", "_");
                                    // use counted for gauged fields for compatibility
                                    // will cause problem if counted fields in buffer not reset before next point
                                    let b = client.count_with_tags(&metric_name, point.2);
                                    Self::send_metrics(b, &host, &batch.tags);
                                }
                            }

                            break;
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
