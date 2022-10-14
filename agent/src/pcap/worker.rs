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

use std::{
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use dashmap::DashMap;
use log::{debug, error, info, warn};

use super::{
    format_time, get_temp_filename,
    writer::{Writer, WriterCounter},
    Packet, PcapPacket, TapType,
};
use crate::rpc::get_timestamp;
use crate::utils::stats::{Counter, CounterType, CounterValue, RefCountable};
use public::queue::{self, Error};

#[derive(Default)]
pub struct WorkerCounter {
    // statsd:"file_creations
    file_creations: AtomicU64,
    // statsd:"file_closes"
    file_closes: AtomicU64,
    // statsd:"file_rejections"
    file_rejections: AtomicU64,
    // statsd:"file_creation_failures"
    file_creation_failures: AtomicU64,
    // statsd:"file_writing_failures"
    file_writing_failures: AtomicU64,
    // statsd:"written_count"
    written_count: AtomicU64,
    // statsd:"written_bytes"
    written_bytes: AtomicU64,
}

#[derive(Debug, Clone)]
struct WorkerConfig {
    max_concurrent_files: u32,
    max_file_size: u32,
    max_file_period: Duration,
    base_directory: PathBuf,
    writer_buffer_size: u32,
}

pub struct Worker {
    pub index: usize,
    config: WorkerConfig,
    counter: Arc<WorkerCounter>,
    writers: Arc<DashMap<u64, Writer>>,
    packet_receiver: Arc<queue::Receiver<PcapPacket>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    interval: Duration,
    running: Arc<AtomicBool>,
    ntp_diff: Arc<AtomicI64>,
}

impl Worker {
    pub fn new(
        index: usize,
        max_concurrent_files: u32,
        max_file_size: u32,
        max_file_period: Duration,
        base_directory: PathBuf,
        writer_buffer_size: u32,
        packet_receiver: queue::Receiver<PcapPacket>,
        interval: Duration,
        ntp_diff: Arc<AtomicI64>,
    ) -> Self {
        Self {
            index,
            interval,
            config: WorkerConfig {
                max_concurrent_files,
                max_file_size,
                max_file_period,
                base_directory,
                writer_buffer_size,
            },
            counter: Default::default(),
            writers: Arc::new(DashMap::new()),
            packet_receiver: Arc::new(packet_receiver),
            thread: Mutex::new(None),
            running: Arc::new(AtomicBool::new(false)),
            ntp_diff,
        }
    }

    pub fn counter(&self) -> &Arc<WorkerCounter> {
        &self.counter
    }

    pub fn start(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            debug!("pcap worker has already running");
            return;
        }

        let config = self.config.clone();
        let counter = self.counter.clone();
        let writers = self.writers.clone();
        let packet_receiver = self.packet_receiver.clone();
        let interval = self.interval;

        let ntp_diff = self.ntp_diff.clone();
        // 上层Sender要关闭channel，才调用worker的stop方法
        let thread = thread::spawn(move || loop {
            match packet_receiver.recv(Some(interval)) {
                Ok(PcapPacket::Packet(pkt)) => Self::write_pkt(*pkt, &writers, &config, &counter),
                Err(Error::Timeout) => {
                    let now = get_timestamp(ntp_diff.load(Ordering::Relaxed));
                    Self::clean_timeout_file(now, &writers, &config, &counter);
                }
                Err(Error::Terminated(_, _)) | Ok(PcapPacket::Terminated) => {
                    let now = get_timestamp(ntp_diff.load(Ordering::Relaxed));
                    Self::clean_timeout_file(now, &writers, &config, &counter);
                    break;
                }
            }
        });
        self.thread.lock().unwrap().replace(thread);
    }

    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            debug!("pcap worker has already stopped");
            return;
        }

        if let Some(handle) = self.thread.lock().unwrap().take() {
            let _ = handle.join();
        }
        info!(
            "stop pcap worker ({}) writing to {} files",
            self.index,
            self.writers.len()
        );

        for item in self.writers.iter() {
            let writer = self.writers.remove(item.key()).unwrap().1;
            Self::finish_writer(writer, &self.counter);
        }
    }

    fn clean_timeout_file(
        now: Duration,
        writers: &Arc<DashMap<u64, Writer>>,
        config: &WorkerConfig,
        counter: &WorkerCounter,
    ) {
        for item in writers.iter() {
            if now - item.value().first_pkt_time > config.max_file_period {
                let writer = writers.remove(item.key()).unwrap().1;
                Self::finish_writer(writer, counter);
            }
        }
    }

    fn get_writer_key(dispatcher_id: u32, acl_gid: u16, tap_type: TapType) -> u64 {
        (dispatcher_id as u64) << 32 | (acl_gid as u64) << 16 | u16::from(tap_type) as u64
    }

    fn finish_writer(writer: Writer, worker_counter: &WorkerCounter) {
        let (temp_filename, new_filename) = {
            let Writer {
                temp_filename,
                counter,
                tap_type,
                dispatcher_id,
                first_pkt_time,
                last_pkt_time,
                vtap_id,
                ..
            } = writer;

            let mut new_filename = temp_filename.to_path_buf();
            let first_pkt_time = format_time(first_pkt_time);
            let last_pkt_time = format_time(last_pkt_time);

            new_filename.pop();

            new_filename.push(format!(
                "{}_{:012x}_0_{}_{}.{}.pcap",
                tap_type, dispatcher_id, first_pkt_time, last_pkt_time, vtap_id
            ));

            debug!(
                "finish writing {}, renaming to {}",
                temp_filename.display(),
                new_filename.display()
            );

            worker_counter
                .written_count
                .fetch_add(counter.written_count, Ordering::Relaxed);
            worker_counter
                .written_bytes
                .fetch_add(counter.written_bytes, Ordering::Relaxed);

            (temp_filename, new_filename)
        };
        fs::rename(temp_filename.as_path(), new_filename.as_path()).unwrap_or_else(|err| {
            error!(
                "failed to rename from {} to {} because {:?}",
                temp_filename.display(),
                new_filename.display(),
                err
            );
        });
        worker_counter.file_closes.fetch_add(1, Ordering::Relaxed);
    }

    fn should_close_file(pkt_timestamp: Duration, writer: &Writer, config: &WorkerConfig) -> bool {
        // 距离第一个包时长超过1秒, 且大小超过maxFileSize, 则切换pcap文件
        if pkt_timestamp - writer.first_pkt_time > Duration::from_secs(1)
            && writer.counter.written_bytes as u32 >= config.max_file_size
        {
            return true;
        }
        if pkt_timestamp - writer.first_pkt_time > config.max_file_period {
            return true;
        }

        false
    }

    fn write_pkt(
        meta_pkt: Packet,
        writers: &Arc<DashMap<u64, Writer>>,
        config: &WorkerConfig,
        counter: &WorkerCounter,
    ) {
        let tap_type = meta_pkt.tap_type;
        let acl_gid = meta_pkt.acl_gid;
        let dispatcher_id = meta_pkt.dispatcher_id;
        let vtap_id = meta_pkt.vtap_id;
        let pkt_timestamp = meta_pkt.timestamp();
        let key = Self::get_writer_key(dispatcher_id, acl_gid, tap_type);

        if let Some(writer) = writers.get(&key) {
            if Self::should_close_file(pkt_timestamp, writer.value(), config) {
                let writer = writers.remove(&key).unwrap().1;
                Self::finish_writer(writer, counter);
            }
        }

        if !writers.contains_key(&key) {
            if writers.len() as u32 >= config.max_concurrent_files {
                error!(
                    "max concurrent file ({} files) exceeded",
                    config.max_concurrent_files
                );
                counter.file_rejections.fetch_add(1, Ordering::Relaxed);
                return;
            }

            match Writer::new(
                config.base_directory.as_path(),
                config.writer_buffer_size as usize,
                tap_type,
                dispatcher_id,
                acl_gid,
                vtap_id,
                pkt_timestamp,
            ) {
                Ok(writer) => {
                    counter.file_creations.fetch_add(1, Ordering::Relaxed);
                    writers.insert(key, writer);
                }
                Err(err) => {
                    error!(
                        "failed to create writer for {}: {}",
                        get_temp_filename(
                            config.base_directory.as_path(),
                            acl_gid,
                            tap_type,
                            dispatcher_id,
                            pkt_timestamp,
                            vtap_id
                        )
                        .display(),
                        err
                    );
                    counter
                        .file_creation_failures
                        .fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        }

        let mut item = writers.get_mut(&key).unwrap();
        let writer = item.value_mut();
        match writer.write(meta_pkt) {
            Ok(_) => {
                let WriterCounter {
                    written_bytes,
                    written_count,
                } = writer.get_and_reset_stats();

                counter
                    .written_count
                    .fetch_add(written_count, Ordering::Relaxed);
                counter
                    .written_bytes
                    .fetch_add(written_bytes, Ordering::Relaxed);
            }
            Err(err) => {
                warn!(
                    "failed to write packet to {}: {}",
                    writer.temp_filename.display(),
                    err
                );
                counter
                    .file_writing_failures
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl RefCountable for WorkerCounter {
    fn get_counters(&self) -> Vec<Counter> {
        vec![
            (
                "file_creations",
                CounterType::Counted,
                CounterValue::Unsigned(self.file_creations.load(Ordering::Relaxed)),
            ),
            (
                "file_closes",
                CounterType::Counted,
                CounterValue::Unsigned(self.file_closes.load(Ordering::Relaxed)),
            ),
            (
                "file_rejections",
                CounterType::Counted,
                CounterValue::Unsigned(self.file_rejections.load(Ordering::Relaxed)),
            ),
            (
                "file_creation_failures",
                CounterType::Counted,
                CounterValue::Unsigned(self.file_creation_failures.load(Ordering::Relaxed)),
            ),
            (
                "file_writing_failures",
                CounterType::Counted,
                CounterValue::Unsigned(self.file_writing_failures.load(Ordering::Relaxed)),
            ),
            (
                "written_count",
                CounterType::Counted,
                CounterValue::Unsigned(self.written_count.load(Ordering::Relaxed)),
            ),
            (
                "written_bytes",
                CounterType::Counted,
                CounterValue::Unsigned(self.written_bytes.load(Ordering::Relaxed)),
            ),
        ]
    }
}
