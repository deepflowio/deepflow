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
    fs::{self, File, OpenOptions},
    io::{self, BufReader, Error, ErrorKind, Read, Result, Write},
    net::TcpStream,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    process,
};

use log::debug;
use nix::sys::utsname::uname;

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
