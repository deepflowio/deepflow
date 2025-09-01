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

use std::collections::VecDeque;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::sync::Mutex;
use std::sync::OnceLock;

use libc::{__u64, c_int, c_void};
use nix::sched::setns;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execve, fork, ForkResult};
use procfs::process::all_processes;

#[derive(Default)]
pub struct IdGenerator {
    max_id: u32,
    available: VecDeque<u32>,
}

impl IdGenerator {
    pub fn acquire(&mut self) -> u32 {
        if let Some(id) = self.available.pop_front() {
            return id;
        }
        self.max_id += 1;
        self.max_id - 1
    }

    pub fn release(&mut self, id: u32) {
        self.available.push_back(id);
    }
}

pub const BPF_ANY: __u64 = 0;
extern "C" {
    pub fn bpf_update_elem(
        fd: c_int,
        key: *const c_void,
        value: *const c_void,
        flags: __u64,
    ) -> c_int;
    pub fn bpf_delete_elem(fd: c_int, key: *const c_void) -> c_int;
}

static PROTECT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn global_lock() -> &'static Mutex<()> {
    PROTECT_LOCK.get_or_init(|| Mutex::new(()))
}

/// Find the first process named "numad" in /proc and return its PID and executable path.
///
/// # Returns
/// - `Ok((pid, exe_path))` if a "numad" process is found.
/// - `Err(io::Error)` if no such process is found or if there is a failure reading /proc.
fn find_numad_proc() -> io::Result<(i32, String)> {
    for res in all_processes().map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))? {
        if let Ok(proc) = res {
            if let Ok(stat) = proc.stat() {
                if stat.comm == "numad" {
                    if let Ok(exe) = proc.exe() {
                        return Ok((proc.pid(), exe.to_string_lossy().to_string()));
                    }
                }
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "numad not found"))
}

/// Protect CPU affinity by preventing `numad` from interfering with the agent.
///
/// This function ensures that `numad` is instructed to exclude the current agent's CPU affinity,
/// without affecting the agent's own process memory or threads.
///
/// Behavior:
/// 1. Serializes access using a global mutex to avoid concurrent execution in multiple threads,
///    since fork + multi-threaded environment is unsafe.
/// 2. Finds the first running `numad` process (PID + absolute executable path).
/// 3. Checks whether the current process is already in the same PID namespace as `numad`.
///    - If in the same PID namespace, skips `setns` to avoid unnecessary namespace changes.
///    - Otherwise, opens the `pid` and `mnt` namespace file descriptors of `numad`.
/// 4. Forks a child process:
///     - Child:
///         - Enters `numad`'s PID/MNT namespaces (if different from self) using `setns`.
///         - Immediately execs `numad -x <agent_pid>`.
///         - Any failure in the child results in `_exit(code)` to prevent running destructors in the parent.
///         - Unsafe operations are minimal: `setns` and `execve`.
///     - Parent:
///         - Drops namespace file descriptors immediately after fork.
///         - Waits for child termination using `waitpid` and returns appropriate `io::Result`.
///
/// Safety considerations:
/// - Mutex prevents simultaneous calls in multiple threads, ensuring fork + multi-thread safety.
/// - Child uses `_exit` on failure to avoid destructor execution and potential deadlocks.
/// - File descriptors are only used in the child for `setns`; parent drops them immediately.
/// - If PID/MNT namespaces match, the agent itself is never replaced or modified.
/// - Errors are propagated via `io::Result` for the caller to handle.
///
/// Note:
/// - This function does not modify the agent's process memory or threads.
/// - Only a short-lived child process may perform namespace changes and exec `numad`.
pub fn protect_cpu_affinity() -> io::Result<()> {
    let _guard = global_lock().lock().unwrap();

    let (numad_pid, numad_exe) = find_numad_proc()?;
    let agent_pid = std::process::id();

    let self_pid_ns = std::fs::metadata("/proc/self/ns/mnt")?.ino();
    let target_pid_ns = std::fs::metadata(format!("/proc/{}/ns/mnt", numad_pid))?.ino();

    let need_setns = self_pid_ns != target_pid_ns;

    // Fork a helper process to run `numad -x <agent_pid>` inside the proper namespaces.
    //
    // Safety:
    // - `fork()` is unsafe because it only replicates the calling thread. We hold a global mutex
    //   so no other threads call this concurrently.
    // - In the child branch, only async-signal-safe functions are used (`setns`, `execve`, `_exit`).
    // - Rust destructors are avoided in the child by immediately calling `_exit` on any failure.
    unsafe {
        match fork() {
            Ok(ForkResult::Parent { child }) => {
                // Parent drops any state; wait for child to finish.
                match waitpid(child, None).map_err(|e| io::Error::new(io::ErrorKind::Other, e))? {
                    WaitStatus::Exited(_, 0) => Ok(()),
                    WaitStatus::Exited(_, code) => Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("helper exited with code {}", code),
                    )),
                    WaitStatus::Signaled(_, sig, _) => Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("helper killed by signal {:?}", sig),
                    )),
                    other => Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("unexpected wait status: {:?}", other),
                    )),
                }
            }
            Ok(ForkResult::Child) => {
                if need_setns {
                    // Since "numad" communicates via SysV message queues, the "ipc" namespace must also be included.
                    // If the target process is in a different IPC namespace, then even if the PID and mount namespaces match,
                    // System V message queues (msgget/msgrcv/msgsnd) cannot be shared.
                    // Joining the same IPC namespace ensures that both processes can access the same
                    // message queue identified by the common key (e.g., 0xdeadbeef).
                    for ns in ["pid", "mnt", "ipc"] {
                        let path = format!("/proc/{}/ns/{}", numad_pid, ns);
                        let file = match File::open(&path) {
                            Ok(f) => f,
                            Err(e) => {
                                eprintln!("failed to open {}: {}", path, e);
                                libc::_exit(1);
                            }
                        };

                        if let Err(e) = setns(&file, nix::sched::CloneFlags::empty()) {
                            eprintln!("setns failed for {} (fd {}): {:?}", ns, file.as_raw_fd(), e);
                            libc::_exit(1);
                        }
                    }
                }

                let prog = CString::new(numad_exe.clone()).unwrap_or_else(|_| libc::_exit(127));
                let arg0 = CString::new(numad_exe).unwrap_or_else(|_| libc::_exit(127));
                let arg1 = CString::new("-x").unwrap_or_else(|_| libc::_exit(127));
                let arg2 = CString::new(agent_pid.to_string()).unwrap_or_else(|_| libc::_exit(127));

                let argv = &[arg0.as_c_str(), arg1.as_c_str(), arg2.as_c_str()];
                let envp: &[&std::ffi::CStr] = &[];

                execve(&prog, argv, envp).unwrap_or_else(|e| {
                    eprintln!("execve failed: {:?}", e);
                    libc::_exit(127);
                });
                libc::_exit(127);
            }
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("fork failed: {}", e),
            )),
        }
    }
}
