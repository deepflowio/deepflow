use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Condvar, Mutex, Weak,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cadence::{
    ext::{MetricValue, ToCounterValue, ToGaugeValue},
    Counted, Metric, MetricBuilder, MetricError, MetricResult, MetricSink, StatsdClient,
};
use log::{debug, info, warn};

use crate::common::DROPLET_PORT;

const TICK_CYCLE: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
pub enum CounterType {
    Counted,
    Gauged,
}

#[derive(Clone, Copy, Debug)]
pub enum CounterValue {
    Signed(i64),
    Unsigned(u64),
    Float(f64),
}

impl ToCounterValue for CounterValue {
    fn try_to_value(self) -> MetricResult<MetricValue> {
        Ok(match self {
            CounterValue::Signed(v) => MetricValue::Signed(v),
            // convert unsigned and float to signed for compatibility
            CounterValue::Unsigned(v) => MetricValue::Signed(v as i64),
            CounterValue::Float(v) => MetricValue::Signed(v as i64),
        })
    }
}

impl ToGaugeValue for CounterValue {
    fn try_to_value(self) -> MetricResult<MetricValue> {
        Ok(match self {
            CounterValue::Signed(v) => MetricValue::Signed(v),
            // convert unsigned and float to signed for compatibility
            CounterValue::Unsigned(v) => MetricValue::Signed(v as i64),
            CounterValue::Float(v) => MetricValue::Signed(v as i64),
        })
    }
}

pub type Counter = (&'static str, CounterType, CounterValue);

pub trait RefCountable: Send + Sync {
    fn get_counters(&self) -> Vec<Counter>;
}

pub trait OwnedCountable: Send + Sync {
    fn get_counters(&self) -> Vec<Counter>;
    fn closed(&self) -> bool;
}

pub enum Countable {
    Owned(Box<dyn OwnedCountable>),
    Ref(Weak<dyn RefCountable>),
}

impl Countable {
    fn get_counters(&self) -> Vec<Counter> {
        match self {
            Countable::Owned(c) => c.get_counters(),
            Countable::Ref(c) => c.upgrade().map(|c| c.get_counters()).unwrap_or_default(),
        }
    }

    fn closed(&self) -> bool {
        match self {
            Countable::Owned(c) => c.closed(),
            Countable::Ref(c) => c.strong_count() == 0,
        }
    }
}

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
struct Batch {
    module: &'static str,
    tags: Vec<(&'static str, String)>,
    points: Vec<Counter>,
    timestamp: SystemTime,
}

pub struct Collector {
    hostname: Arc<Mutex<String>>,

    remotes: Arc<Mutex<Option<Vec<IpAddr>>>>,
    sources: Arc<Mutex<Vec<Source>>>,
    pre_hooks: Arc<Mutex<Vec<Box<dyn FnMut() + Send>>>>,

    min_interval: Arc<AtomicU64>,

    running: Arc<(Mutex<bool>, Condvar)>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Collector {
    const STATS_PREFIX: &'static str = "metaflow-agent";

    pub fn new(remotes: &Vec<String>) -> Self {
        Self::with_min_interval(remotes, TICK_CYCLE)
    }

    pub fn with_min_interval(remotes: &Vec<String>, interval: Duration) -> Self {
        let min_interval = if interval <= TICK_CYCLE {
            TICK_CYCLE
        } else {
            Duration::from_secs(
                (interval.as_secs() + TICK_CYCLE.as_secs() - 1) / TICK_CYCLE.as_secs()
                    * TICK_CYCLE.as_secs(),
            )
        };
        let remotes = remotes
            .iter()
            .filter_map(|x| x.parse::<IpAddr>().ok())
            .collect();
        Self {
            hostname: Arc::new(Mutex::new(
                hostname::get()
                    .ok()
                    .and_then(|s| s.into_string().ok())
                    .unwrap_or_default(),
            )),
            remotes: Arc::new(Mutex::new(Some(remotes))),
            sources: Arc::new(Mutex::new(vec![])),
            pre_hooks: Arc::new(Mutex::new(vec![])),
            min_interval: Arc::new(AtomicU64::new(min_interval.as_secs())),
            running: Arc::new((Mutex::new(false), Condvar::new())),
            thread: Mutex::new(None),
        }
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

    pub fn set_remotes(&self, remotes: Vec<IpAddr>) {
        self.remotes.lock().unwrap().replace(remotes);
    }

    pub fn set_hostname(&self, hostname: String) {
        *self.hostname.lock().unwrap() = hostname;
    }

    pub fn set_min_interval(&self, interval: Duration) {
        self.min_interval
            .store(interval.as_secs(), Ordering::Relaxed);
    }

    fn new_statsd_client<A: ToSocketAddrs>(addr: A) -> MetricResult<StatsdClient> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let sink = DropletSink::from(addr, socket)?;
        Ok(StatsdClient::from_sink(Self::STATS_PREFIX, sink))
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

        let remotes = self.remotes.clone();
        let running = self.running.clone();
        let sources = self.sources.clone();
        let pre_hooks = self.pre_hooks.clone();
        let hostname = self.hostname.clone();
        let min_interval = self.min_interval.clone();
        *self.thread.lock().unwrap() = Some(thread::spawn(move || {
            let mut statsd_clients = vec![];
            let mut old_remotes = vec![];
            loop {
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
                            source.skip = (source.interval.as_secs().max(min_interval_loaded)
                                / TICK_CYCLE.as_secs())
                                as i64;
                            let points = source.countable.get_counters();
                            if !points.is_empty() {
                                batches.push(Batch {
                                    module: source.module,
                                    tags: source.tags.clone(),
                                    points,
                                    timestamp: now,
                                });
                            }
                        }
                    }
                    if batches.is_empty() {
                        break;
                    }

                    match remotes.lock().unwrap().take() {
                        Some(remotes) => {
                            statsd_clients.clear();
                            for remote in remotes.iter() {
                                match Self::new_statsd_client((*remote, DROPLET_PORT)) {
                                    Ok(client) => statsd_clients.push(Some(client)),
                                    Err(e) => {
                                        warn!("create client to remote {} failed: {}", remote, e);
                                        statsd_clients.push(None);
                                    }
                                }
                            }
                            old_remotes = remotes;
                        }
                        None => {
                            for (i, client) in statsd_clients.iter_mut().enumerate() {
                                if client.is_some() {
                                    continue;
                                }
                                match Self::new_statsd_client((old_remotes[i], DROPLET_PORT)) {
                                    Ok(s) => {
                                        client.replace(s);
                                    }
                                    Err(e) => warn!(
                                        "create client to remote {} failed: {}",
                                        old_remotes[i], e
                                    ),
                                }
                            }
                        }
                    }

                    if statsd_clients.iter().all(|s| s.is_none()) {
                        info!("no statsd remote available");
                        break;
                    }

                    debug!("collected: {:?}", batches);
                    let host = hostname.lock().unwrap().clone();
                    for batch in batches.into_iter() {
                        for client in statsd_clients.iter() {
                            if client.is_none() {
                                continue;
                            }
                            let client = client.as_ref().unwrap();
                            for point in batch.points.iter() {
                                let metric_name =
                                    format!("{}_{}", batch.module, point.0).replace("-", "_");
                                // use counted for gauged fields for compatibility
                                // will cause problem if counted fields in buffer not reset before next point
                                let b = client.count_with_tags(&metric_name, point.2);
                                Self::send_metrics(b, &host, &batch.tags);
                            }
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
        }));
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
