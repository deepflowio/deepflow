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
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{self, BufReader, Error, ErrorKind, Read, Result, Write},
    net::TcpStream,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    process,
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc, Mutex, RwLock,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use log::{debug, error, info, trace};
use nix::sys::utsname::uname;
use procfs::process::all_processes_with_root;

use crate::config::ProcessMatcher;
use crate::platform::{get_os_app_tag_by_exec, ProcessData, ProcessDataOp};

//返回当前进程占用内存RSS单位（字节）
pub fn get_memory_rss() -> Result<u64> {
    let pid = process::id();

    let mut status = File::open(format!("/proc/{}/status", pid))?;
    let mut buf = String::new();
    status.read_to_string(&mut buf)?;

    for line in buf.lines() {
        if !line.starts_with("VmRSS") {
            continue;
        }
        for field in line.trim().split_whitespace() {
            // /proc/pid/status VmmRSS以KB为单位
            if let Ok(n) = field.parse::<u64>() {
                return Ok(n << 10);
            }
        }
        break;
    }

    Err(Error::new(
        ErrorKind::Other,
        "run get_memory_rss function failed: can't find VmmRSS field or prase VmmRSS field failed",
    ))
}

// 仅计算当前进程及其子进程，没有计算子进程的子进程等
// /proc/<pid>/status目录中ppid为当前进程的pid
// =================
// Only the current process and its child processes are counted, the child processes of the child process are not counted, etc.
// The ppid in the /proc/<pid>/status directory is the pid of the current process
pub fn get_process_num() -> Result<u32> {
    let pid = process::id();
    // plus current process
    // 加上当前进程
    get_num_from_status_file("PPid:", pid.to_string().as_str()).map(|num| num + 1)
}

// 仅计算当前pid下的线程数, linux下应该都是1
pub fn get_thread_num() -> Result<u32> {
    let pid = process::id();
    // 读/proc/<pid>/status中的第34行获取线程数

    let mut status = File::open(format!("/proc/{}/status", pid))?;

    let mut buf = String::new();
    status.read_to_string(&mut buf)?;

    for line in buf.lines() {
        if !line.starts_with("Threads:") {
            continue;
        }
        match line
            .trim()
            .rsplit_once('\t')
            .and_then(|(_, s)| s.parse::<u32>().ok())
        {
            Some(num) => {
                return Ok(num);
            }
            None => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("line: ({}) in /proc/{}/status is not a number", line, pid),
                ));
            }
        }
    }

    Err(Error::new(
        ErrorKind::NotFound,
        format!("Threads field not found in /proc/{}/status", pid),
    ))
}

// Get the number of processes with the same name of the deepflow-agent
pub fn get_process_num_by_name(name: &str) -> Result<u32> {
    get_num_from_status_file("Name:", name)
}

pub fn get_exec_path() -> io::Result<PathBuf> {
    let sys_uname = uname();
    match sys_uname.sysname() {
        "Linux" => {
            let mut exec_path = fs::read_link("/proc/self/exe")?;
            let file_name = exec_path
                .file_name()
                .and_then(|f| f.to_str())
                .map(|s| s.trim_end_matches(" (deleted)")) // centos,ubuntu 版本 (deleted) 字段都放在字符串末尾，所以不必trim prefix
                .map(|s| format!("{}.test", s));

            if let Some(name) = file_name {
                exec_path.pop();
                exec_path.push(name);
            }
            Ok(exec_path)
        }
        "NetBSD" => fs::read_link("/proc/curproc/exe"),
        "FreeBSD" | "OpenBSD" | "DragonFly" => fs::read_link("/proc/curproc/file"),
        "Solaris" => fs::read_link(format!("/proc/{}/path/a.out", process::id())),
        x => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("ExecPath not implemented for {}", x),
            ));
        }
    }
}

pub fn deploy_program(mut reader: BufReader<TcpStream>, revision: &str) -> io::Result<()> {
    let file_path = get_exec_path()?;
    {
        let mut fp = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .mode(0o755)
            .open(file_path.as_path())?;

        let mut buf = vec![0u8; 4096];
        loop {
            let has_read = reader.read(&mut buf)?;
            if has_read == 0 {
                break;
            }
            fp.write(&buf[..has_read])?;
        }
    }

    let out = process::Command::new(file_path).arg("-v").output()?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "failed to run version check",
        ));
    }

    if let Ok(msg) = String::from_utf8(out.stdout) {
        if !msg.replacen(' ', "-", 1).starts_with(revision) {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("error version: {}, expected: {}", msg, revision),
            ));
        }
    }

    Ok(())
}

fn get_num_from_status_file(pattern: &str, value: &str) -> Result<u32> {
    let dirs = fs::read_dir("/proc")?;

    let mut num = 0;
    for entry in dirs {
        let entry = match entry {
            Ok(item) => item,
            Err(e) => {
                debug!("{:?}", e);
                continue;
            }
        };

        match entry.file_type() {
            Ok(t) => {
                if !t.is_dir() {
                    continue;
                }
            }
            Err(e) => {
                debug!("filename: {:?}, {:?}", entry.file_name(), e);
                continue;
            }
        }

        let search_pid = match entry
            .file_name()
            .to_str()
            .and_then(|pid| pid.parse::<u32>().ok())
        {
            Some(pid) => pid,
            None => {
                debug!("parse number error: {:?}", entry.file_name());
                continue;
            }
        };

        let status_file = format!("/proc/{}/status", search_pid);
        let mut status = match File::open(status_file.as_str()) {
            Ok(s) => s,
            Err(e) => {
                debug!("open status file {} error: {:?}", status_file, e);
                continue;
            }
        };
        let mut buf = String::new();
        if let Err(e) = status.read_to_string(&mut buf) {
            debug!("status_file: {}, read_to_string: {}", status_file, e);
            continue;
        }

        for line in buf.lines() {
            if !line.starts_with(pattern) {
                continue;
            }
            if line
                .trim()
                .rsplit_once('\t')
                .filter(|&(_, s)| s == value)
                .is_some()
            {
                num += 1;
            } else {
                break;
            }
        }
    }

    Ok(num)
}

type ProcessListenerCallback = fn(pids: &Vec<u32>, process_datas: &Vec<ProcessData>);

#[derive(Default, Debug)]
struct ProcessNode {
    process_matcher: Vec<ProcessMatcher>,

    pids: Vec<u32>,
    process_datas: Vec<ProcessData>,

    callback: Option<ProcessListenerCallback>,
}

#[derive(Default, Debug)]
struct Features {
    blacklist: Vec<String>,
    features: HashMap<String, ProcessNode>,
}

struct Config {
    proc_root: String,
    user: String,
    command: Vec<String>,
}

impl Config {
    fn new(proc_root: String, user: String, command: Vec<String>) -> Self {
        Self {
            proc_root,
            user,
            command,
        }
    }

    fn update(&mut self, proc_root: String, user: String, command: Vec<String>) {
        self.proc_root = proc_root;
        self.user = user;
        self.command = command;
    }
}

pub struct ProcessListener {
    features: Arc<RwLock<Features>>,
    running: Arc<AtomicBool>,
    config: Arc<RwLock<Config>>,

    thread_handle: Mutex<Option<JoinHandle<()>>>,
}

impl ProcessListener {
    const INTERVAL: usize = 10;

    pub fn new(
        process_blacklist: &Vec<String>,
        process_matcher: &Vec<ProcessMatcher>,
        proc_root: String,
        user: String,
        command: Vec<String>,
    ) -> Self {
        let listener = Self {
            features: Default::default(),
            running: Arc::new(AtomicBool::new(false)),
            thread_handle: Mutex::new(None),
            config: Arc::new(RwLock::new(Config::new(proc_root, user, command))),
        };

        listener.set(process_blacklist, process_matcher);

        listener
    }

    pub fn on_config_change(
        &self,
        process_blacklist: &Vec<String>,
        process_matcher: &Vec<ProcessMatcher>,
        proc_root: String,
        user: String,
        command: Vec<String>,
    ) {
        self.config
            .write()
            .unwrap()
            .update(proc_root, user, command);
        self.set(process_blacklist, process_matcher);
    }

    pub fn set(&self, process_blacklist: &Vec<String>, process_matcher: &Vec<ProcessMatcher>) {
        let mut features: HashMap<String, ProcessNode> = HashMap::new();
        let mut current = self.features.write().unwrap();

        for matcher in process_matcher.iter() {
            for feature in matcher.enabled_features.iter() {
                if let Some(node) = features.get_mut(feature) {
                    node.process_matcher.push(matcher.clone());
                } else {
                    let mut node = ProcessNode {
                        process_matcher: vec![matcher.clone()],
                        ..Default::default()
                    };
                    if let Some(mut last_node) = current.features.remove(feature) {
                        node.callback = last_node.callback.take();
                        node.pids = last_node.pids;
                        node.process_datas = last_node.process_datas;
                    }

                    let _ = features.insert(feature.to_string(), node);
                }
            }
        }

        for (feature, mut node) in current.features.drain() {
            if node.callback.is_some() {
                node.process_matcher.clear();
                features.insert(feature, node);
            }
        }

        *current = Features {
            blacklist: process_blacklist.clone(),
            features,
        };
    }

    pub fn register(&self, feature: &str, callback: ProcessListenerCallback) {
        info!("Process listener register feature {}", feature);
        let mut features = self.features.write().unwrap();
        if let Some(node) = features.features.get_mut(&feature.to_string()) {
            node.pids = vec![];
            node.process_datas = vec![];
            node.callback = Some(callback);
        } else {
            let _ = features.features.insert(
                feature.to_string(),
                ProcessNode {
                    process_matcher: vec![],
                    pids: vec![],
                    process_datas: vec![],
                    callback: Some(callback),
                },
            );
        }
    }

    pub fn stop(&mut self) {
        self.running.store(false, Relaxed);

        if let Some(handler) = self.thread_handle.lock().unwrap().take() {
            let _ = handler.join();
        }
    }

    fn process(
        process_data_cache: &mut HashMap<i32, ProcessData>,
        proc_root: &str,
        features: &mut Features,
        user: &str,
        command: &[String],
    ) {
        let (blacklist, features) = (&mut features.blacklist, &mut features.features);
        if features.is_empty() {
            return;
        }
        let tags_map = match get_os_app_tag_by_exec(user, command) {
            Ok(tags) => tags,
            Err(err) => {
                error!(
                    "get process tags by execute cmd `{}` with user {} fail: {}",
                    command.join(" "),
                    user,
                    err
                );
                HashMap::new()
            }
        };

        let mut alive_pids = HashSet::new();
        let Ok(processes) = all_processes_with_root(proc_root) else {
            return;
        };
        for process in processes {
            let process = match process {
                Ok(p) => p,
                Err(e) => {
                    error!("get process failed: {}", e);
                    continue;
                }
            };
            match process.status().map(|s| s.name) {
                // not found
                Ok(name) if blacklist.binary_search(&name).is_err() => (),
                Ok(name) => {
                    trace!(
                        "process {name} (pid#{}) ignored because it is in blacklist",
                        process.pid
                    );
                    continue;
                }
                Err(e) => {
                    debug!("get process status failed: {}", e);
                    continue;
                }
            }
            alive_pids.insert(process.pid);
            if let Some(old_data) = process_data_cache.get(&process.pid) {
                if let Some(start_time) = process.stat().ok().and_then(|stat| stat.starttime().ok())
                {
                    if Duration::from_secs(start_time.timestamp() as u64) == old_data.start_time {
                        continue;
                    }
                }
            }
            process_data_cache.remove(&process.pid);
            if let Ok(pdata) = ProcessData::try_from(&process) {
                process_data_cache.insert(process.pid, pdata);
            }
        }
        process_data_cache.retain(|pid, _| alive_pids.contains(pid));

        for (key, value) in features.iter_mut() {
            if (value.process_matcher.is_empty() && value.pids.is_empty())
                || value.callback.is_none()
            {
                continue;
            }

            let mut pids = vec![];
            let mut process_datas = vec![];
            let mut ignore_pids = HashSet::new();

            for matcher in &value.process_matcher {
                for pdata in process_data_cache.values() {
                    if let Some(process_data) = matcher.get_process_data(pdata, &tags_map) {
                        if matcher.ignore {
                            ignore_pids.insert(pdata.pid);
                            continue;
                        }

                        if !ignore_pids.contains(&pdata.pid) {
                            pids.push(pdata.pid as u32);
                            process_datas.push(process_data);
                        }
                    }
                }
            }

            pids.sort();
            pids.dedup();
            process_datas.sort_by_key(|x| x.pid);
            process_datas.merge_and_dedup();

            if pids != value.pids {
                debug!("Feature {} update {} pids {:?}.", key, pids.len(), pids);
                value.callback.as_ref().unwrap()(&pids, &process_datas);
                value.pids = pids;
                value.process_datas = process_datas;
            }
        }
    }

    pub fn start(&self) {
        if self.running.swap(true, Relaxed) {
            return;
        }
        info!("Startting process listener ...");
        let features = self.features.clone();
        let running = self.running.clone();
        let config = self.config.clone();

        running.store(true, Relaxed);
        *self.thread_handle.lock().unwrap() = Some(
            thread::Builder::new()
                .name("process-listener".to_owned())
                .spawn(move || {
                    let mut count = 0;
                    let mut process_data = HashMap::new();
                    while running.load(Relaxed) {
                        thread::sleep(Duration::from_secs(1));
                        count += 1;
                        if count < Self::INTERVAL {
                            continue;
                        }
                        count = 0;
                        let current_config = config.read().unwrap();
                        let mut features = features.write().unwrap();

                        Self::process(
                            &mut process_data,
                            &current_config.proc_root,
                            &mut features,
                            &current_config.user,
                            &current_config.command,
                        );

                        drop(features);
                        drop(current_config);
                    }
                })
                .unwrap(),
        );
    }

    pub fn notify_stop(&self) -> Option<JoinHandle<()>> {
        self.running.store(false, Relaxed);
        self.thread_handle.lock().unwrap().take()
    }
}
