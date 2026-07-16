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
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Condvar, Mutex, Weak,
    },
    thread,
    time::{Duration, Instant},
};

use ahash::AHashMap;
use arc_swap::{access::Access, ArcSwap};
use log::{debug, error, info, warn};
use lru::LruCache;
use parking_lot::RwLock;
use prost::Message;
use tokio::runtime::Runtime;

use public::{
    counter::{Countable, Counter, CounterType, CounterValue, RefCountable},
    proto::agent::{ProcessGpidEntries, ProcessGpidSyncRequest, ProcessGpidSyncResponse},
};

use crate::{
    common::meta_packet::TraceInfo,
    config::handler::PlatformAccess,
    rpc::{Session, DEFAULT_TIMEOUT},
    trident::AgentId,
    utils::stats,
};

const PROCESS_GPID_LRU_CAPACITY: usize = 4096;
const MAX_PROCESS_GPID_ENTRIES: usize = 1_000_000;
const MAX_PROCESS_GPID_MESSAGE_SIZE: usize = 32 << 20;

#[derive(Default)]
struct VersionedTable {
    version: u64,
    entries: AHashMap<u64, u32>,
}

struct SharedTable {
    version: AtomicU64,
    table: ArcSwap<VersionedTable>,
}

impl Default for SharedTable {
    fn default() -> Self {
        Self {
            version: AtomicU64::new(0),
            table: ArcSwap::from_pointee(VersionedTable::default()),
        }
    }
}

#[derive(Clone, Default)]
pub struct ProcessGpidTable {
    inner: Arc<SharedTable>,
}

impl ProcessGpidTable {
    fn version(&self) -> u64 {
        self.inner.version.load(Ordering::Acquire)
    }

    fn update(&self, version: u64, entries: AHashMap<u64, u32>) {
        self.inner
            .table
            .store(Arc::new(VersionedTable { version, entries }));
        self.inner.version.store(version, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn update_for_test(&self, version: u64, entries: AHashMap<u64, u32>) {
        self.update(version, entries);
    }

    fn clear(&self) {
        self.update(0, AHashMap::new());
    }

    pub fn new_lookup(&self, id: u32, stats_collector: &stats::Collector) -> ProcessGpidLookup {
        ProcessGpidLookup::new(self.inner.clone(), id, stats_collector)
    }
}

#[derive(Default)]
struct ProcessGpidCounter {
    client_lru_hit: AtomicU64,
    client_lru_negative_hit: AtomicU64,
    client_table_hit: AtomicU64,
    client_table_miss: AtomicU64,
    table_reload: AtomicU64,
}

impl RefCountable for ProcessGpidCounter {
    fn get_counters(&self) -> Vec<Counter> {
        macro_rules! counted {
            ($name:literal, $field:ident) => {
                (
                    $name,
                    CounterType::Counted,
                    CounterValue::Unsigned(self.$field.swap(0, Ordering::Relaxed)),
                )
            };
        }

        vec![
            counted!("client_lru_hit", client_lru_hit),
            counted!("client_lru_negative_hit", client_lru_negative_hit),
            counted!("client_table_hit", client_table_hit),
            counted!("client_table_miss", client_table_miss),
            counted!("table_reload", table_reload),
        ]
    }
}

pub struct ProcessGpidLookup {
    shared: Arc<SharedTable>,
    table: Arc<VersionedTable>,
    version: u64,
    lru: LruCache<u64, u32>,
    counter: Arc<ProcessGpidCounter>,
}

impl ProcessGpidLookup {
    fn new(shared: Arc<SharedTable>, id: u32, stats_collector: &stats::Collector) -> Self {
        let table = shared.table.load_full();
        let counter = Arc::new(ProcessGpidCounter::default());
        stats_collector.register_countable(
            &stats::SingleTagModule("process-gpid", "id", id),
            Countable::Ref(Arc::downgrade(&counter) as Weak<dyn RefCountable>),
        );
        Self {
            version: table.version,
            shared,
            table,
            lru: LruCache::new(NonZeroUsize::new(PROCESS_GPID_LRU_CAPACITY).unwrap()),
            counter,
        }
    }

    pub fn refresh(&mut self) {
        if self.shared.version.load(Ordering::Acquire) == self.version {
            return;
        }
        let table = self.shared.table.load_full();
        self.version = table.version;
        self.table = table;
        self.lru.clear();
        self.counter.table_reload.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn lookup(&mut self, trace_info: TraceInfo) -> u32 {
        let agent_id = trace_info.agent_id;
        let pid = trace_info.pid;
        if agent_id == 0 || pid == 0 {
            return 0;
        }
        let key = make_key(agent_id, pid);
        if let Some(gpid) = self.lru.get(&key).copied() {
            let counter = match gpid == 0 {
                false => &self.counter.client_lru_hit,
                true => &self.counter.client_lru_negative_hit,
            };
            counter.fetch_add(1, Ordering::Relaxed);
            return gpid;
        }

        let gpid = self.table.entries.get(&key).copied().unwrap_or_default();
        let counter = match gpid == 0 {
            false => &self.counter.client_table_hit,
            true => &self.counter.client_table_miss,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        self.lru.put(key, gpid);
        gpid
    }
}

fn make_key(agent_id: u32, pid: u32) -> u64 {
    ((agent_id as u64) << 32) | pid as u64
}

async fn rpc_with_timeout<F>(
    timeout: Duration,
    future: F,
) -> Result<F::Output, tokio::time::error::Elapsed>
where
    F: std::future::Future,
{
    tokio::time::timeout(timeout, future).await
}

pub struct ProcessGpidSynchronizer {
    runtime: Arc<Runtime>,
    config: PlatformAccess,
    agent_id: Arc<RwLock<AgentId>>,
    session: Arc<Session>,
    table: ProcessGpidTable,
    running: Arc<Mutex<bool>>,
    stop_notify: Arc<Condvar>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl ProcessGpidSynchronizer {
    pub fn new(
        runtime: Arc<Runtime>,
        config: PlatformAccess,
        agent_id: Arc<RwLock<AgentId>>,
        session: Arc<Session>,
        table: ProcessGpidTable,
    ) -> Self {
        Self {
            runtime,
            config,
            agent_id,
            session,
            table,
            running: Arc::new(Mutex::new(false)),
            stop_notify: Arc::new(Condvar::new()),
            thread_handle: None,
        }
    }

    pub fn start(&mut self) {
        let mut running = self.running.lock().unwrap();
        if *running {
            warn!("process GPID synchronizer is already running");
            return;
        }
        *running = true;

        let runtime = self.runtime.clone();
        let config = self.config.clone();
        let agent_id = self.agent_id.clone();
        let session = self.session.clone();
        let table = self.table.clone();
        let running_clone = self.running.clone();
        let stop_notify = self.stop_notify.clone();
        self.thread_handle = Some(
            thread::Builder::new()
                .name("process-gpid-synchronizer".to_string())
                .spawn(move || {
                    Self::run(
                        runtime,
                        config,
                        agent_id,
                        session,
                        table,
                        running_clone,
                        stop_notify,
                    )
                })
                .unwrap(),
        );
        info!("process GPID synchronizer started");
    }

    pub fn stop(&mut self) {
        let mut running = self.running.lock().unwrap();
        if !*running {
            return;
        }
        *running = false;
        self.stop_notify.notify_one();
        drop(running);
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
        info!("process GPID synchronizer stopped");
    }

    fn run(
        runtime: Arc<Runtime>,
        config: PlatformAccess,
        agent_id: Arc<RwLock<AgentId>>,
        session: Arc<Session>,
        table: ProcessGpidTable,
        running: Arc<Mutex<bool>>,
        stop_notify: Arc<Condvar>,
    ) {
        let mut last_interval = Duration::ZERO;
        let mut next_sync = Instant::now();
        let mut disabled = false;
        loop {
            let interval = config.load().process_gpid_sync_interval;
            if interval.is_zero() {
                if !disabled {
                    table.clear();
                    disabled = true;
                    info!("process GPID synchronization disabled and lookup table cleared");
                }
                last_interval = Duration::ZERO;
                next_sync = Instant::now();
                if !wait_for_running(&running, &stop_notify, Duration::from_secs(1)) {
                    return;
                }
                continue;
            }
            disabled = false;
            if interval != last_interval {
                last_interval = interval;
                next_sync = Instant::now();
            }
            let now = Instant::now();
            if now < next_sync {
                if !wait_for_running(
                    &running,
                    &stop_notify,
                    (next_sync - now).min(Duration::from_secs(1)),
                ) {
                    return;
                }
                continue;
            }

            let request = ProcessGpidSyncRequest {
                agent_id: Some({
                    let id = agent_id.read();
                    (&*id).into()
                }),
                process_gpid_version: Some(table.version()),
            };
            match runtime.block_on(rpc_with_timeout(
                DEFAULT_TIMEOUT,
                session.grpc_process_gpid_sync(request),
            )) {
                Err(_) => error!("process GPID sync timed out after {:?}", DEFAULT_TIMEOUT),
                Ok(Err(e)) => error!("process GPID sync failed: {e}"),
                Ok(Ok(response)) => {
                    let response = response.into_inner();
                    let version = response.process_gpid_version.unwrap_or_default();
                    if version != table.version() {
                        match decode_entries(&response) {
                            Ok(entries) => {
                                let count = entries.len();
                                table.update(version, entries);
                                debug!(
                                    "updated process GPID table to version {version} with {count} entries"
                                );
                            }
                            Err(e) => error!("failed to update process GPID table: {e}"),
                        }
                    }
                }
            }
            next_sync = Instant::now() + interval;
        }
    }
}

fn wait_for_running(running: &Mutex<bool>, stop_notify: &Condvar, timeout: Duration) -> bool {
    let guard = running.lock().unwrap();
    if !*guard {
        return false;
    }
    let (guard, _) = stop_notify.wait_timeout(guard, timeout).unwrap();
    *guard
}

fn decode_entries(response: &ProcessGpidSyncResponse) -> Result<AHashMap<u64, u32>, String> {
    let data = response.gprocess_infos.as_deref().unwrap_or_default();
    let decoded = match response.compress_algorithm.unwrap_or_default() {
        0 => {
            if data.len() > MAX_PROCESS_GPID_MESSAGE_SIZE {
                return Err(format!(
                    "process GPID message is too large: {} > {}",
                    data.len(),
                    MAX_PROCESS_GPID_MESSAGE_SIZE
                ));
            }
            data.to_vec()
        }
        1 => zstd::bulk::decompress(data, MAX_PROCESS_GPID_MESSAGE_SIZE)
            .map_err(|e| format!("failed to decompress process GPID message: {e}"))?,
        algorithm => {
            return Err(format!(
                "unknown process GPID compression algorithm {algorithm}"
            ))
        }
    };

    let entries = ProcessGpidEntries::decode(decoded.as_slice())
        .map_err(|e| format!("failed to decode process GPID entries: {e}"))?
        .entries;
    if entries.len() > MAX_PROCESS_GPID_ENTRIES {
        return Err(format!(
            "too many process GPID entries: {} > {}",
            entries.len(),
            MAX_PROCESS_GPID_ENTRIES
        ));
    }

    let mut table = AHashMap::with_capacity(entries.len());
    for entry in entries {
        let agent_id = entry.agent_id.unwrap_or_default();
        let pid = entry.pid.unwrap_or_default();
        let gpid = entry.gprocess_id.unwrap_or_default();
        if agent_id == 0 || pid == 0 || gpid == 0 {
            continue;
        }
        table.insert(make_key(agent_id, pid), gpid);
    }
    Ok(table)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicI64;

    use crate::common::meta_packet::TraceInfo;
    use public::proto::agent::ProcessGpidEntry;

    #[test]
    fn rpc_timeout_bounds_wait() {
        let runtime = Runtime::new().unwrap();
        let timeout = Duration::from_millis(10);
        let start = Instant::now();

        let result = runtime.block_on(rpc_with_timeout(timeout, std::future::pending::<()>()));

        assert!(result.is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn decode_process_gpid_entries() {
        let entries = ProcessGpidEntries {
            entries: vec![
                ProcessGpidEntry {
                    agent_id: Some(1),
                    pid: Some(2),
                    gprocess_id: Some(3),
                },
                ProcessGpidEntry {
                    agent_id: Some(1),
                    pid: Some(2),
                    gprocess_id: Some(4),
                },
                ProcessGpidEntry::default(),
            ],
        };
        let encoded = entries.encode_to_vec();
        let response = ProcessGpidSyncResponse {
            process_gpid_version: Some(1),
            compress_algorithm: Some(0),
            gprocess_infos: Some(encoded),
        };

        let table = decode_entries(&response).unwrap();
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(&make_key(1, 2)), Some(&4));
    }

    #[test]
    fn decode_zstd_process_gpid_entries() {
        let entries = ProcessGpidEntries {
            entries: vec![ProcessGpidEntry {
                agent_id: Some(10),
                pid: Some(20),
                gprocess_id: Some(30),
            }],
        };
        let encoded = zstd::bulk::compress(&entries.encode_to_vec(), 0).unwrap();
        let response = ProcessGpidSyncResponse {
            process_gpid_version: Some(1),
            compress_algorithm: Some(1),
            gprocess_infos: Some(encoded),
        };

        let table = decode_entries(&response).unwrap();
        assert_eq!(table.get(&make_key(10, 20)), Some(&30));
    }

    #[test]
    fn lookup_with_lru_and_reload() {
        let table = ProcessGpidTable::default();
        table.update(1, AHashMap::from_iter([(make_key(10, 20), 30)]));
        let stats = stats::Collector::new("", Arc::new(AtomicI64::new(0)));
        let mut lookup = table.new_lookup(1, &stats);
        let trace_info = TraceInfo {
            agent_id: 10,
            pid: 20,
        };

        assert_eq!(lookup.lookup(trace_info), 30);
        assert_eq!(lookup.counter.client_table_hit.load(Ordering::Relaxed), 1);

        assert_eq!(lookup.lookup(trace_info), 30);
        assert_eq!(lookup.counter.client_lru_hit.load(Ordering::Relaxed), 1);

        table.update(2, AHashMap::from_iter([(make_key(10, 20), 31)]));
        lookup.refresh();
        assert_eq!(lookup.counter.table_reload.load(Ordering::Relaxed), 1);

        assert_eq!(lookup.lookup(trace_info), 31);
    }

    #[test]
    fn lookup_caches_misses() {
        let table = ProcessGpidTable::default();
        let stats = stats::Collector::new("", Arc::new(AtomicI64::new(0)));
        let mut lookup = table.new_lookup(1, &stats);
        let trace_info = TraceInfo {
            agent_id: 10,
            pid: 20,
        };

        assert_eq!(lookup.lookup(trace_info), 0);
        assert_eq!(lookup.counter.client_table_miss.load(Ordering::Relaxed), 1);

        assert_eq!(lookup.lookup(trace_info), 0);
        assert_eq!(
            lookup
                .counter
                .client_lru_negative_hit
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn clear_invalidates_lookup_table_and_lru() {
        let table = ProcessGpidTable::default();
        table.update(7, AHashMap::from_iter([(make_key(10, 20), 30)]));
        let stats = stats::Collector::new("", Arc::new(AtomicI64::new(0)));
        let mut lookup = table.new_lookup(1, &stats);
        let trace_info = TraceInfo {
            agent_id: 10,
            pid: 20,
        };

        assert_eq!(lookup.lookup(trace_info), 30);

        let old_version = table.version();
        table.clear();
        assert_eq!(table.version(), 0);
        assert_ne!(table.version(), old_version);
        lookup.refresh();

        assert_eq!(lookup.lookup(trace_info), 0);
        assert_eq!(lookup.counter.table_reload.load(Ordering::Relaxed), 1);
        assert_eq!(lookup.counter.client_table_miss.load(Ordering::Relaxed), 1);
    }
}
