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

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use std::{cmp::Ordering, fs, io, path::Path, time::SystemTime};

use log::{debug, warn};
use regex::Regex;
use sysinfo::{PidExt, ProcessExt, ProcessRefreshKind, System, SystemExt};

use crate::config::ProcessMatcher;

pub struct FileAndSizeSum {
    pub file_infos: Vec<FileInfo>, // 文件信息
    pub file_sizes_sum: u64,       // 文件体积总和，单位：B
}

impl FileAndSizeSum {
    pub fn new() -> Self {
        FileAndSizeSum {
            file_infos: vec![],
            file_sizes_sum: 0,
        }
    }
}

#[derive(Debug)]
pub struct FileInfo {
    pub file_path: String,
    pub file_size: u64,
    pub file_modified_time: SystemTime,
}

impl FileInfo {
    pub fn new(file_path: String, file_size: u64, file_modified_time: SystemTime) -> Self {
        FileInfo {
            file_path,
            file_size,
            file_modified_time,
        }
    }
}

impl Eq for FileInfo {}

impl PartialEq<Self> for FileInfo {
    fn eq(&self, other: &Self) -> bool {
        self.file_modified_time == other.file_modified_time
    }
}

impl PartialOrd<Self> for FileInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.file_modified_time.cmp(&other.file_modified_time)) // 根据文件的modified时间进行排序
    }
}

impl Ord for FileInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.file_modified_time.cmp(&other.file_modified_time)
    }
}

/// 获取指定路径下的所有文件的信息及文件大小总和（单位：B）
pub fn get_file_and_size_sum(dir: &String) -> io::Result<FileAndSizeSum> {
    let mut file_and_size_sum = FileAndSizeSum::new();
    let mut file_infos = Vec::new();
    let dir = Path::new(dir);
    for item in fs::read_dir(dir)? {
        let file = match item {
            Ok(f) => f,
            Err(_) => continue,
        };
        let file_path = file.path().as_path().to_str().unwrap().to_string();
        let file = match file.metadata() {
            Ok(fm) => fm,
            Err(_) => continue,
        };
        if file.is_dir() {
            continue;
        }
        let file_size = file.len();
        file_and_size_sum.file_sizes_sum += file_size;
        let file_info = FileInfo::new(file_path, file_size, file.modified().unwrap());
        file_infos.push(file_info);
    }
    file_infos.sort();
    file_and_size_sum.file_infos = file_infos;
    Ok(file_and_size_sum)
}

type ProcessListenerCallback = fn(pids: Vec<u32>);

struct ProcessNode {
    process_matcher: Vec<ProcessMatcher>,

    pids: Vec<u32>,

    callback: Option<ProcessListenerCallback>,
}

pub struct ProcessListener {
    features: Arc<RwLock<HashMap<String, ProcessNode>>>,
    running: Arc<AtomicBool>,

    thread_handle: Option<JoinHandle<()>>,
}

impl ProcessListener {
    const INTERVAL: Duration = Duration::from_secs(10);

    fn new(process_matcher: &Vec<ProcessMatcher>) -> Self {
        let listener = Self {
            features: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(AtomicBool::new(false)),
            thread_handle: None,
        };

        listener.set(process_matcher);

        listener
    }

    fn set(&self, process_matcher: &Vec<ProcessMatcher>) {
        let mut features = self.features.write().unwrap();

        for matcher in process_matcher.iter() {
            for feature in matcher.enabled_features.iter() {
                if let Some(node) = features.get_mut(feature) {
                    node.process_matcher.push(matcher.clone());
                } else {
                    let _ = features.insert(
                        feature.to_string(),
                        ProcessNode {
                            process_matcher: vec![matcher.clone()],
                            pids: vec![],
                            callback: None,
                        },
                    );
                }
            }
        }
    }

    fn register(&self, feature: &str, callback: ProcessListenerCallback) {
        let mut features = self.features.write().unwrap();
        if let Some(node) = features.get_mut(&feature.to_string()) {
            node.callback = Some(callback);
        } else {
            let _ = features.insert(
                feature.to_string(),
                ProcessNode {
                    process_matcher: vec![],
                    pids: vec![],
                    callback: Some(callback),
                },
            );
        }
    }

    fn stop(&mut self) {
        self.running.store(false, Relaxed);

        if let Some(handler) = self.thread_handle.take() {
            let _ = handler.join();
        }
    }

    fn process(system: &mut System, features: &Arc<RwLock<HashMap<String, ProcessNode>>>) {
        system.refresh_processes_specifics(ProcessRefreshKind::new());

        let processes = system.processes();
        let mut features = features.write().unwrap();

        for (key, value) in features.iter_mut() {
            if value.process_matcher.is_empty() || value.callback.is_none() {
                continue;
            }

            let mut pids = vec![];

            for matcher in &value.process_matcher {
                let Ok(regex) = Regex::new(matcher.match_regex.as_str()) else {
                    warn!("Invalid process regex: {}", matcher.match_regex.as_str());
                    continue;
                };

                for (pid, process) in processes {
                    // TODO: match_languages match_type match_usernames only_in_container only_with_tag
                    if regex.is_match(process.name()) {
                        pids.push(pid.as_u32());
                    }
                }
            }

            pids.sort();
            pids.dedup();

            if pids != value.pids {
                debug!("Feature {} update pids {:?}.", key, pids);
                value.callback.as_ref().unwrap()(pids.clone());
                value.pids = pids;
            }
        }
    }

    fn start(&mut self) {
        if self.running.load(Relaxed) {
            return;
        }

        let features = self.features.clone();
        let running = self.running.clone();

        running.store(true, Relaxed);
        self.thread_handle = Some(
            thread::Builder::new()
                .name("process-listener".to_owned())
                .spawn(move || {
                    let mut system = System::new();

                    while running.load(Relaxed) {
                        thread::sleep(Self::INTERVAL);
                        Self::process(&mut system, &features);
                    }
                })
                .unwrap(),
        );
    }
}
