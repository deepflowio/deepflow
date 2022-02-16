use std::{
    fs,
    ops::Deref,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use dashmap::DashMap;
use log::{debug, error, info, warn};

use super::{
    format_time, get_temp_filename,
    writer::{Writer, WriterCounter},
    PcapPacket, TapType,
};
use crate::utils::queue::{self, Error};
use crate::utils::stats::{Countable, Counter, CounterType, CounterValue};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct WorkerCounter {
    // statsd:"file_creations
    pub(super) file_creations: u64,
    // statsd:"file_closes"
    pub(super) file_closes: u64,
    // statsd:"file_rejections"
    pub(super) file_rejections: u64,
    // statsd:"file_creation_failures"
    pub(super) file_creation_failures: u64,
    // statsd:"file_writing_failures"
    pub(super) file_writing_failures: u64,
    // statsd:"written_count"
    pub(super) written_count: u64,
    // statsd:"written_bytes"
    pub(super) written_bytes: u64,
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
    counter: Arc<Mutex<WorkerCounter>>,
    writers: Arc<DashMap<u64, Writer>>,
    packet_receiver: Arc<queue::Receiver<PcapPacket>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    interval: Duration,
    running: AtomicBool,
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
            counter: Arc::new(Mutex::new(WorkerCounter::default())),
            writers: Arc::new(DashMap::new()),
            packet_receiver: Arc::new(packet_receiver),
            thread: Mutex::new(None),
            running: AtomicBool::new(false),
        }
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

        // 上层Sender要关闭channel，才调用worker的stop方法
        let thread = thread::spawn(move || loop {
            match packet_receiver.recv(Some(interval)) {
                Ok(pkt) => {
                    Self::write_pkt(pkt, &writers, &config, &counter);
                }
                Err(Error::Timeout) => {
                    let now = rpc::get_timestamp();
                    Self::clean_timeout_file(now, &writers, &config, &counter);
                }
                Err(Error::Terminated(_, _)) => {
                    let now = rpc::get_timestamp();
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

        let mut counter_guard = self.counter.lock().unwrap();
        for item in self.writers.iter() {
            let writer = self.writers.remove(item.key()).unwrap().1;
            Self::finish_writer(writer, &mut counter_guard);
        }
    }

    fn clean_timeout_file(
        now: Duration,
        writers: &Arc<DashMap<u64, Writer>>,
        config: &WorkerConfig,
        counter: &Arc<Mutex<WorkerCounter>>,
    ) {
        let mut counter_guard = counter.lock().unwrap();
        for item in writers.iter() {
            if now - item.value().first_pkt_time > config.max_file_period {
                let writer = writers.remove(item.key()).unwrap().1;
                Self::finish_writer(writer, &mut counter_guard);
            }
        }
    }

    fn get_writer_key(dispatcher_id: u32, acl_gid: u16, tap_type: TapType) -> u64 {
        (dispatcher_id as u64) << 32 | (acl_gid as u64) << 16 | u16::from(tap_type) as u64
    }

    fn finish_writer(writer: Writer, worker_counter_guard: &mut MutexGuard<WorkerCounter>) {
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

            worker_counter_guard.written_count += counter.written_count;
            worker_counter_guard.written_bytes += counter.written_bytes;

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
        worker_counter_guard.file_closes += 1;
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
        meta_pkt: PcapPacket,
        writers: &Arc<DashMap<u64, Writer>>,
        config: &WorkerConfig,
        counter: &Arc<Mutex<WorkerCounter>>,
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
                let mut counter_guard = counter.lock().unwrap();
                Self::finish_writer(writer, &mut counter_guard);
            }
        }

        if !writers.contains_key(&key) {
            if writers.len() as u32 >= config.max_concurrent_files {
                error!(
                    "max concurrent file ({} files) exceeded",
                    config.max_concurrent_files
                );
                counter.lock().unwrap().file_rejections += 1;
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
                    counter.lock().unwrap().file_creations += 1;
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
                    counter.lock().unwrap().file_creation_failures += 1;
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

                let mut counter_guard = counter.lock().unwrap();
                counter_guard.written_count += written_count;
                counter_guard.written_bytes += written_bytes;
            }
            Err(err) => {
                warn!(
                    "failed to write packet to {}: {}",
                    writer.temp_filename.display(),
                    err
                );
                counter.lock().unwrap().file_writing_failures += 1;
            }
        }
    }
}

//TODO 测试用的，等rpc模块完成就要去掉，调用真正的rpc
mod rpc {
    use std::time::Duration;
    pub fn get_timestamp() -> Duration {
        Duration::from_millis(1634269448888)
    }
}
//END

impl Countable for Worker {
    fn get_counters(&self) -> Vec<Counter> {
        let WorkerCounter {
            file_creations,
            file_closes,
            file_rejections,
            file_creation_failures,
            file_writing_failures,
            written_count,
            written_bytes,
        } = *self.counter.lock().unwrap().deref();
        vec![
            (
                "file_creations",
                CounterType::Counted,
                CounterValue::Unsigned(file_creations),
            ),
            (
                "file_closes",
                CounterType::Counted,
                CounterValue::Unsigned(file_closes),
            ),
            (
                "file_rejections",
                CounterType::Counted,
                CounterValue::Unsigned(file_rejections),
            ),
            (
                "file_creation_failures",
                CounterType::Counted,
                CounterValue::Unsigned(file_creation_failures),
            ),
            (
                "file_writing_failures",
                CounterType::Counted,
                CounterValue::Unsigned(file_writing_failures),
            ),
            (
                "written_count",
                CounterType::Counted,
                CounterValue::Unsigned(written_count),
            ),
            (
                "written_bytes",
                CounterType::Counted,
                CounterValue::Unsigned(written_bytes),
            ),
        ]
    }

    fn closed(&self) -> bool {
        !self.running.load(Ordering::SeqCst)
    }
}
