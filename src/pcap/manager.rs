use std::{
    fs::{self, File},
    io::{Error, ErrorKind, Read, Result, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use arc_swap::access::Access;
use log::{debug, error, info, warn};

use super::{
    format_time, get_temp_filename, worker::Worker, PcapPacket, TapType, GLOBAL_HEADER_LEN,
    INCL_LEN_OFFSET, RECORD_HEADER_LEN, TS_SEC_OFFSET,
};
use crate::config::handler::PcapAccess;
use crate::utils::{
    queue,
    stats::{Collector, StatsOption},
};

pub struct WorkerManager {
    config: PcapAccess,
    running: AtomicBool,
    workers: Mutex<Vec<Worker>>,
    example_filepath: PathBuf,
    stats: Arc<Collector>,
}

impl WorkerManager {
    pub fn new(
        config: PcapAccess,
        packet_receivers: Vec<queue::Receiver<PcapPacket>>,
        stats: Arc<Collector>,
    ) -> Self {
        let config_guard = config.load();
        let worker_max_concurrent_files =
            config_guard.max_concurrent_files / packet_receivers.len() as u32;
        let workers = packet_receivers
            .into_iter()
            .enumerate()
            .map(|(index, receiver)| {
                Worker::new(
                    index,
                    worker_max_concurrent_files,
                    config_guard.max_file_size_mb << 20,
                    config_guard.max_file_period,
                    config_guard.file_directory.clone(),
                    config_guard.block_size_kb << 10,
                    receiver,
                    config_guard.max_file_period,
                )
            })
            .collect();

        let example_filepath = get_temp_filename(
            &Path::new("yunshan"),
            1,
            TapType::Tor,
            1233,
            Duration::from_secs(10),
            0,
        );

        Self {
            config,
            running: AtomicBool::new(false),
            workers: Mutex::new(workers),
            example_filepath,
            stats,
        }
    }

    pub fn start(&self) {
        let conf_guard = self.config.load();
        let base_directory = conf_guard.file_directory.as_path();
        if self.running.swap(true, Ordering::SeqCst) {
            debug!(
                "WorkerManager has already running in path: {}",
                base_directory.display()
            );
            return;
        }

        if !base_directory.exists() {
            fs::create_dir_all(base_directory).unwrap_or_else(|err| {
                error!(
                    "failed to create base directory :{} {}",
                    base_directory.display(),
                    err
                )
            });
        }
        drop(conf_guard);

        if let Err(err) = self.clean_temp_files() {
            warn!("failed to clean temp files: {}", err);
        }

        for worker in self.workers.lock().unwrap().iter() {
            self.stats.register_countable(
                "pcap",
                worker.clone_counter(),
                vec![StatsOption::Tag("index", worker.index.to_string())],
            );
            worker.start();
        }

        info!("started WorkerManager");
    }

    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            debug!(
                "WorkerManager has already stopped in path: {}",
                self.config.load().file_directory.display()
            );
            return;
        }

        for worker in self.workers.lock().unwrap().iter() {
            worker.stop();
        }

        info!("stopped WorkerManager");
    }

    fn clean_temp_files(&self) -> Result<()> {
        fn is_temp_file(path: &Path, example_filename: &str) -> bool {
            let filename = path.file_name().and_then(|f| f.to_str());
            if filename.is_none() {
                return false;
            }
            let filename = filename.unwrap();

            filename.ends_with(".pcap.temp")
                && example_filename.chars().filter(|&c| c == '_').count()
                    == filename.chars().filter(|&c| c == '_').count()
        }

        fn visit_dirs(dir: &Path, files: &mut Vec<PathBuf>, example_filename: &str) -> Result<()> {
            if dir.is_dir() {
                for entry in fs::read_dir(dir)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_dir() {
                        visit_dirs(&path, files, example_filename)?;
                    } else if is_temp_file(path.as_path(), example_filename) {
                        files.push(entry.path());
                    }
                }
            }
            Ok(())
        }

        let mut files = vec![];
        let example_filename = self
            .example_filepath
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or_default();
        visit_dirs(
            self.config.load().file_directory.as_path(),
            &mut files,
            example_filename,
        )?;

        let mut failed = false;
        // finish files gracefully
        for file in files.into_iter() {
            let last_pkt_time = match Self::find_last_record_time(file.as_path()) {
                Ok(t) => t,
                Err(e) => {
                    debug!(
                        "remove empty or corrupted file {} err: {}",
                        file.display(),
                        e
                    );
                    if let Err(err) = fs::remove_file(file.as_path()) {
                        failed = true;
                        debug!("failed to remove file {}: {}", file.display(), err);
                    }
                    continue;
                }
            };

            let new_path = match file
                .file_stem()
                .and_then(|n| n.to_str())
                .map(|n| n.replace("_.", &format!("_{}.", format_time(last_pkt_time))))
                .map(|new_name| {
                    let mut new_path = file.parent().unwrap().to_path_buf();
                    new_path.push(new_name.as_str());
                    new_path
                }) {
                Some(p) => p,
                None => {
                    continue;
                }
            };

            if let Err(err) = fs::rename(file.as_path(), new_path.as_path()) {
                debug!(
                    "failed to rename file {}->{}: {}",
                    file.display(),
                    new_path.display(),
                    err
                );
                failed = true;
            }
        }

        if failed {
            Err(Error::new(
                ErrorKind::Other,
                "remove file or rename file error",
            ))
        } else {
            Ok(())
        }
    }

    fn find_last_record_time(path: &Path) -> Result<Duration> {
        let mut file = File::open(path)?;

        if file.metadata()?.len() <= (GLOBAL_HEADER_LEN + RECORD_HEADER_LEN) as u64 {
            return Err(Error::new(
                ErrorKind::Other,
                format!("invalid content in file {}", path.display()),
            ));
        }

        let mut buffer = [0u8; RECORD_HEADER_LEN];
        file.seek(SeekFrom::Start(GLOBAL_HEADER_LEN as u64))?;
        let mut last_record_time = 0u32;

        loop {
            let n = file.read(&mut buffer)?;
            if n != RECORD_HEADER_LEN {
                break;
            }

            let second = buffer
                .get(TS_SEC_OFFSET as usize..TS_SEC_OFFSET as usize + 4)
                .and_then(|s| <&[u8; 4]>::try_from(s).ok())
                .map(|s| u32::from_le_bytes(*s));
            if second.is_none() {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("invalid content in file {}", path.display()),
                ));
            }
            let second = second.unwrap();

            let length = buffer
                .get(INCL_LEN_OFFSET as usize..INCL_LEN_OFFSET as usize + 4)
                .and_then(|s| <&[u8; 4]>::try_from(s).ok())
                .map(|s| u32::from_le_bytes(*s));
            if length.is_none() {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("invalid content in file {}", path.display()),
                ));
            }
            let length = length.unwrap();

            if second > last_record_time {
                last_record_time = second;
            }

            file.seek(SeekFrom::Current(length as i64)).unwrap();
        }

        Ok(Duration::from_secs(last_record_time as u64))
    }
}
