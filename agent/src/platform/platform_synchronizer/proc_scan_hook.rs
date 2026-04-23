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

use super::ProcessData;

#[cfg(any(target_os = "linux", target_os = "android"))]
fn open_process_with_root(
    proc_root: &str,
    pid: u32,
) -> procfs::ProcResult<procfs::process::Process> {
    procfs::process::Process::new_with_root(
        std::path::PathBuf::from(proc_root).join(pid.to_string()),
    )
}

pub fn proc_scan_hook(_proc_root: &str, _process_datas: &mut Vec<ProcessData>) {
    // Enterprise: clean dead AI Agent PIDs and mark alive ones with biz_type
    #[cfg(all(
        feature = "enterprise",
        any(target_os = "linux", target_os = "android")
    ))]
    {
        use std::collections::HashSet;

        if let Some(registry) = enterprise_utils::ai_agent::global_registry() {
            // Use a full /proc scan for cleanup to avoid filtering out short-lived processes
            // that are not yet eligible for os_proc_socket_min_lifetime.
            let alive_pids: Vec<u32> = match procfs::process::all_processes_with_root(_proc_root) {
                Ok(procs) => procs
                    .into_iter()
                    .filter_map(|p| p.ok())
                    .map(|p| p.pid as u32)
                    .collect(),
                Err(_) => _process_datas.iter().map(|pd| pd.pid as u32).collect(),
            };
            registry.cleanup_dead_pids(&alive_pids);

            for pd in _process_datas.iter_mut() {
                if registry.is_ai_agent(pd.pid as u32) {
                    pd.biz_type = crate::common::flow::BIZ_TYPE_AI_AGENT;
                }
            }

            // Inject AI agent processes that weren't matched by process_matcher.
            // Without this, identified AI agents appear in l7_flow_log but NOT in the
            // MySQL process table because process_matcher only matches on socket/regex.
            let existing_pids: HashSet<u32> =
                _process_datas.iter().map(|pd| pd.pid as u32).collect();
            for pid in registry.get_all_pids() {
                if existing_pids.contains(&pid) {
                    continue;
                }
                if let Ok(proc) = open_process_with_root(_proc_root, pid) {
                    if let Ok(mut pd) = ProcessData::try_from(&proc) {
                        pd.biz_type = crate::common::flow::BIZ_TYPE_AI_AGENT;
                        _process_datas.push(pd);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn test_open_process_with_root_uses_custom_proc_root() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().expect("create tempdir");
        let fake_pid = 999_999_u32;
        let fake_proc = tmp.path().join(fake_pid.to_string());
        symlink(format!("/proc/{}", std::process::id()), &fake_proc).expect("create proc symlink");

        let proc = open_process_with_root(tmp.path().to_str().unwrap(), fake_pid)
            .expect("open process via custom proc root");
        assert_eq!(proc.pid, fake_pid as i32);

        let exe = proc.exe().expect("read exe through custom proc root");
        assert!(!exe.as_os_str().is_empty(), "exe path should not be empty");
    }
}
