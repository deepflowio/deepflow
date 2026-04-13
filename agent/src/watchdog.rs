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

#![cfg(unix)]

use std::{
    io::{BufRead, BufReader, Write},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    process::{Child, Command},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use http::Uri;
use nix::{
    errno::Errno,
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use procfs::process::Process;

use crate::utils::environment::get_executable_path;

pub const WATCHDOG_FAILURE_THRESHOLD: u32 = 3;
pub const WATCHDOG_PERIOD: Duration = Duration::from_secs(10);
pub const WATCHDOG_HTTP_TIMEOUT: Duration = Duration::from_secs(3);
pub const WATCHDOG_TERMINATION_GRACE: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug)]
struct ParentIdentity {
    pid: Pid,
    start_time_ticks: u64,
}

pub fn liveness_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}/livez")
}

struct ProbeTarget {
    addr: SocketAddr,
    request: Vec<u8>,
}

impl ProbeTarget {
    fn from_url(liveness_url: &str) -> Result<Self> {
        let uri: Uri = liveness_url
            .parse()
            .with_context(|| format!("parse watchdog liveness url {liveness_url} failed"))?;
        let addr = parse_addr(&uri)?;
        let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/livez");
        let host = uri.host().unwrap_or("127.0.0.1");
        let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
            .into_bytes();
        Ok(Self { addr, request })
    }

    fn probe_once(&self) -> Result<bool> {
        let mut stream = TcpStream::connect_timeout(&self.addr, WATCHDOG_HTTP_TIMEOUT)
            .with_context(|| format!("connect {} failed", self.addr))?;
        stream.set_read_timeout(Some(WATCHDOG_HTTP_TIMEOUT))?;
        stream.set_write_timeout(Some(WATCHDOG_HTTP_TIMEOUT))?;
        stream.write_all(&self.request)?;
        stream.flush()?;

        let mut status_line = String::new();
        let mut reader = BufReader::new(stream);
        reader.read_line(&mut status_line)?;
        let code = status_line
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| anyhow!("invalid HTTP status line: {}", status_line.trim()))?;
        Ok(code == "200")
    }
}

pub fn run(parent_pid: u32, parent_start_time_ticks: u64, liveness_url: &str) -> Result<()> {
    let parent = ParentIdentity {
        pid: Pid::from_raw(parent_pid as i32),
        start_time_ticks: parent_start_time_ticks,
    };
    let probe_target = ProbeTarget::from_url(liveness_url)?;
    let mut consecutive_failures = 0;

    eprintln!(
        "[watchdog] monitoring parent pid {} start_time={} via {}",
        parent.pid, parent.start_time_ticks, liveness_url
    );
    loop {
        if !process_matches(parent)? {
            eprintln!(
                "[watchdog] parent pid {} no longer matches original identity, watchdog stopping",
                parent.pid
            );
            return Ok(());
        }

        match probe_target.probe_once() {
            Ok(true) => {
                consecutive_failures = 0;
            }
            Ok(false) => {
                consecutive_failures += 1;
                eprintln!(
                    "[watchdog] liveness returned unhealthy status for parent pid {}, consecutive_failures={}",
                        parent.pid, consecutive_failures
                );
            }
            Err(e) => {
                consecutive_failures += 1;
                eprintln!(
                    "[watchdog] liveness probe for parent pid {} failed: {}, consecutive_failures={}",
                        parent.pid, e, consecutive_failures
                );
            }
        }

        if consecutive_failures >= WATCHDOG_FAILURE_THRESHOLD {
            eprintln!(
                "[watchdog] parent pid {} exceeded liveness failure threshold {}, restarting",
                parent.pid, WATCHDOG_FAILURE_THRESHOLD
            );
            return terminate_parent(parent);
        }

        std::thread::sleep(WATCHDOG_PERIOD);
    }
}

pub fn spawn(parent_pid: u32, liveness_url: &str) -> Result<Child> {
    let parent = ParentIdentity {
        pid: Pid::from_raw(parent_pid as i32),
        start_time_ticks: read_process_start_time(Pid::from_raw(parent_pid as i32))?.ok_or_else(
            || {
                anyhow!(
                    "parent pid {} disappeared before watchdog spawn",
                    parent_pid
                )
            },
        )?,
    };
    let binary = get_executable_path().context("get executable path for watchdog failed")?;
    Command::new(binary)
        .arg("--watchdog-parent-pid")
        .arg(parent.pid.as_raw().to_string())
        .arg("--watchdog-parent-start-time")
        .arg(parent.start_time_ticks.to_string())
        .arg("--watchdog-liveness-url")
        .arg(liveness_url)
        .spawn()
        .context("spawn watchdog failed")
}

fn process_matches(parent: ParentIdentity) -> Result<bool> {
    match kill(parent.pid, None) {
        Ok(_) => Ok(true),
        Err(Errno::EPERM) => Ok(true),
        Err(Errno::ESRCH) => Ok(false),
        Err(e) => Err(anyhow!("check parent pid {} failed: {}", parent.pid, e)),
    }?;

    match read_process_start_time(parent.pid)? {
        Some(start_time_ticks) => Ok(start_time_ticks == parent.start_time_ticks),
        None => Ok(false),
    }
}

fn read_process_start_time(pid: Pid) -> Result<Option<u64>> {
    let process = match Process::new(pid.as_raw()) {
        Ok(process) => process,
        Err(procfs::ProcError::NotFound(_)) => return Ok(None),
        Err(e) => {
            return Err(anyhow!("read /proc/{}/stat failed: {}", pid, e));
        }
    };
    let stat = process
        .stat()
        .with_context(|| format!("read /proc/{}/stat failed", pid))?;
    Ok(Some(stat.starttime))
}

fn parse_addr(uri: &Uri) -> Result<SocketAddr> {
    let host = uri
        .host()
        .ok_or_else(|| anyhow!("watchdog liveness url missing host"))?;
    let port = uri.port_u16().unwrap_or(80);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("resolve watchdog host {host}:{port} failed"))
}

fn terminate_parent(parent: ParentIdentity) -> Result<()> {
    if !process_matches(parent)? {
        eprintln!(
            "[watchdog] parent pid {} no longer matches original identity, skip termination",
            parent.pid
        );
        return Ok(());
    }

    match kill(parent.pid, Signal::SIGTERM) {
        Ok(_) => eprintln!("[watchdog] sent SIGTERM to parent pid {}", parent.pid),
        Err(Errno::ESRCH) => return Ok(()),
        Err(e) => {
            return Err(anyhow!(
                "send SIGTERM to parent pid {} failed: {}",
                parent.pid,
                e
            ))
        }
    }

    let deadline = Instant::now() + WATCHDOG_TERMINATION_GRACE;
    while Instant::now() < deadline {
        if !process_matches(parent)? {
            eprintln!("[watchdog] parent pid {} exited after SIGTERM", parent.pid);
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    if !process_matches(parent)? {
        return Ok(());
    }

    match kill(parent.pid, Signal::SIGKILL) {
        Ok(_) => {
            eprintln!(
                "[watchdog] parent pid {} did not exit in {:?}, sent SIGKILL",
                parent.pid, WATCHDOG_TERMINATION_GRACE
            );
            Ok(())
        }
        Err(Errno::ESRCH) => Ok(()),
        Err(e) => Err(anyhow!(
            "send SIGKILL to parent pid {} failed: {}",
            parent.pid,
            e
        )),
    }
}
