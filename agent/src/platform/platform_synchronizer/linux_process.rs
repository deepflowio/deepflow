/*
 * Copyright (c) 2023 Yunshan Networks
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

use std::collections::HashSet;
use std::path::{PathBuf, MAIN_SEPARATOR};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{collections::HashMap, os::unix::process::CommandExt, process::Command};

use envmnt::{ExpandOptions, ExpansionType};
use log::{debug, error};
use nom::AsBytes;
use procfs::{process::Process, ProcError, ProcResult};
use public::bytes::write_u64_be;
use public::proto::trident::{ProcessInfo, Tag};
use public::pwd::PasswordInfo;
use regex::Regex;
use ring::digest;
use serde::Deserialize;

use super::proc_scan_hook::proc_scan_hook;
use super::{dir_inode, get_proc_netns, SHA1_DIGEST_LEN};

use crate::config::handler::OsProcScanConfig;
use crate::config::{
    OsProcRegexp, OS_PROC_REGEXP_MATCH_ACTION_ACCEPT, OS_PROC_REGEXP_MATCH_ACTION_DROP,
    OS_PROC_REGEXP_MATCH_TYPE_CMD, OS_PROC_REGEXP_MATCH_TYPE_PARENT_PROC_NAME,
    OS_PROC_REGEXP_MATCH_TYPE_PROC_NAME, OS_PROC_REGEXP_MATCH_TYPE_TAG,
};

const CONTAINER_ID_LEN: usize = 64;

#[derive(Debug, Clone)]
pub struct ProcessData {
    pub name: String, // the replaced name
    pub pid: u64,
    pub ppid: u64,
    pub process_name: String, // raw process name
    pub cmd: Vec<String>,
    pub user_id: u32,
    pub user: String,
    pub start_time: Duration, // the process start timestamp
    // Vec<key, val>
    pub os_app_tags: Vec<OsAppTagKV>,
    // netns file inode
    pub netns_id: u32,
    // pod container id in kubernetes
    pub container_id: String,
}

impl ProcessData {
    // proc data only hash the pid and tag
    pub fn digest(&self, dist_ctx: &mut digest::Context) {
        let mut pid = [0u8; 8];
        write_u64_be(&mut pid, self.pid);

        dist_ctx.update(&pid);

        for i in self.os_app_tags.iter() {
            dist_ctx.update(i.key.as_bytes());
            dist_ctx.update(i.value.as_bytes());
        }
    }

    pub(super) fn up_sec(&self, base_time: u64) -> Result<u64, ProcError> {
        let start_time_sec = self.start_time.as_secs();
        if base_time < self.start_time.as_secs() {
            Err(ProcError::Other("proc start time gt base time".into()))
        } else {
            Ok(base_time - start_time_sec)
        }
    }

    // get the inode of /proc/pid/root
    pub(super) fn get_root_inode(&mut self, proc_root: &str) -> std::io::Result<u64> {
        // /proc/{pid}/root
        let p = PathBuf::from_iter([proc_root, self.pid.to_string().as_str(), "root"]);
        dir_inode(p.to_str().unwrap())
    }

    pub(super) fn set_username(&mut self, pwd: &PasswordInfo) {
        if let Some(u) = pwd.get_username_by_uid(self.user_id) {
            self.user = u;
        }
    }
}

// need sort by pid before calc the hash
pub fn calc_process_datas_sha1(data: &Vec<ProcessData>) -> [u8; SHA1_DIGEST_LEN] {
    let mut h = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);

    for i in data {
        i.digest(&mut h)
    }

    let mut ret = [0u8; SHA1_DIGEST_LEN];
    ret.copy_from_slice(h.finish().as_ref().as_bytes());
    ret
}

impl TryFrom<&Process> for ProcessData {
    type Error = ProcError;
    // will not set the username
    fn try_from(proc: &Process) -> Result<Self, Self::Error> {
        let (cmd, uid) = (proc.cmdline()?, proc.uid()?);
        let proc_name = if cmd.len() == 0 {
            return Err(ProcError::Other(format!("pid {} cmd is nil", proc.pid)));
        } else {
            let buf = PathBuf::from(&cmd[0]);
            if let Some(f) = buf.file_name() {
                f.to_string_lossy().to_string()
            } else {
                return Err(ProcError::Other(format!("pid {} cmd parse fail", proc.pid)));
            }
        };

        Ok(ProcessData {
            name: proc_name.clone(),
            pid: proc.pid as u64,
            ppid: if let Ok(stat) = proc.stat().as_ref() {
                stat.ppid as u64
            } else {
                error!("pid {} get stat fail", proc.pid);
                0
            },
            process_name: proc_name,
            cmd,
            user_id: uid,
            user: "".to_string(),
            start_time: {
                if let Ok(stat) = proc.stat() {
                    let z = stat.starttime().unwrap_or_default();
                    Duration::from_secs(z.timestamp() as u64)
                } else {
                    Duration::ZERO
                }
            },
            os_app_tags: vec![],
            netns_id: get_proc_netns(proc)? as u32,
            container_id: get_container_id(proc).unwrap_or("".to_string()),
        })
    }
}

// convert ProcessData to ProcessInfo pb struct
impl From<&ProcessData> for ProcessInfo {
    fn from(p: &ProcessData) -> Self {
        Self {
            name: Some(p.name.clone()),
            pid: Some(p.pid),
            process_name: Some(p.process_name.clone()),
            cmdline: Some(p.cmd.join(" ")),
            user: Some(p.user.clone()),
            start_time: Some(u32::try_from(p.start_time.as_secs()).unwrap_or_default()),
            os_app_tags: {
                let mut tags = vec![];
                for t in p.os_app_tags.iter() {
                    tags.push(Tag {
                        key: Some(t.key.clone()),
                        value: Some(t.value.clone()),
                    })
                }
                tags
            },
            netns_id: Some(p.netns_id),
            container_id: Some(p.container_id.clone()),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum RegExpAction {
    Accept,
    Drop,
}

impl Default for RegExpAction {
    fn default() -> Self {
        Self::Accept
    }
}

#[derive(Clone, Debug)]
pub enum ProcRegRewrite {
    // (match reg, action, rewrite string)
    Cmd(Regex, RegExpAction, String),
    ProcessName(Regex, RegExpAction, String),
    ParentProcessName(Regex, RegExpAction),
    Tag(Regex, RegExpAction),
}

impl ProcRegRewrite {
    pub fn action(&self) -> RegExpAction {
        match self {
            ProcRegRewrite::Cmd(_, act, _) => *act,
            ProcRegRewrite::ProcessName(_, act, _) => *act,
            ProcRegRewrite::ParentProcessName(_, act) => *act,
            ProcRegRewrite::Tag(_, act) => *act,
        }
    }
}

impl PartialEq for ProcRegRewrite {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Cmd(lr, lact, ls), Self::Cmd(rr, ract, rs)) => {
                lr.as_str() == rr.as_str() && lact == ract && ls == rs
            }
            (Self::ProcessName(lr, lact, ls), Self::ProcessName(rr, ract, rs)) => {
                lr.as_str() == rr.as_str() && lact == ract && ls == rs
            }
            (Self::ParentProcessName(lr, lact), Self::ParentProcessName(rr, ract)) => {
                lr.as_str() == rr.as_str() && lact == ract
            }
            (Self::Tag(lr, lact), Self::Tag(rr, ract)) => {
                lr.as_str() == rr.as_str() && lact == ract
            }
            _ => false,
        }
    }
}

impl Eq for ProcRegRewrite {}

impl TryFrom<&OsProcRegexp> for ProcRegRewrite {
    type Error = regex::Error;

    fn try_from(value: &OsProcRegexp) -> Result<Self, Self::Error> {
        let re = Regex::new(value.match_regex.as_str())?;
        let action = match value.action.as_str() {
            "" | OS_PROC_REGEXP_MATCH_ACTION_ACCEPT => RegExpAction::Accept,
            OS_PROC_REGEXP_MATCH_ACTION_DROP => RegExpAction::Drop,
            _ => return Err(regex::Error::Syntax("action must accept or drop".into())),
        };
        let env_rewrite = |r: String| {
            envmnt::expand(
                r.as_str(),
                Some(ExpandOptions {
                    expansion_type: Some(ExpansionType::Windows),
                    default_to_empty: true,
                }),
            )
        };

        match value.match_type.as_str() {
            OS_PROC_REGEXP_MATCH_TYPE_CMD => Ok(Self::Cmd(
                re,
                action,
                env_rewrite(value.rewrite_name.clone()),
            )),
            "" | OS_PROC_REGEXP_MATCH_TYPE_PROC_NAME => Ok(Self::ProcessName(
                re,
                action,
                env_rewrite(value.rewrite_name.clone()),
            )),
            OS_PROC_REGEXP_MATCH_TYPE_PARENT_PROC_NAME => Ok(Self::ParentProcessName(re, action)),
            OS_PROC_REGEXP_MATCH_TYPE_TAG => Ok(Self::Tag(re, action)),
            _ => Err(regex::Error::Syntax(
                "regexp match type incorrect".to_string(),
            )),
        }
    }
}

impl ProcRegRewrite {
    pub(super) fn match_and_rewrite_proc(
        &self,
        proc: &mut ProcessData,
        pid_process_map: &PidProcMap,
        tags: &HashMap<u64, OsAppTag>,
        match_only: bool,
    ) -> bool {
        let mut match_replace_fn =
            |reg: &Regex, act: &RegExpAction, s: &String, replace: &String| {
                if reg.is_match(s.as_str()) {
                    if act == &RegExpAction::Accept && !replace.is_empty() && !match_only {
                        proc.name = reg.replace_all(s.as_str(), replace).to_string();
                    }
                    true
                } else {
                    false
                }
            };

        match self {
            ProcRegRewrite::Cmd(reg, act, replace) => {
                match_replace_fn(reg, act, &proc.cmd.join(" "), replace)
            }
            ProcRegRewrite::ProcessName(reg, act, replace) => {
                match_replace_fn(reg, act, &proc.process_name, replace)
            }
            ProcRegRewrite::ParentProcessName(reg, _) => {
                fn match_parent(
                    proc: &ProcessData,
                    pid_process_map: &PidProcMap,
                    reg: &Regex,
                ) -> bool {
                    if proc.ppid == 0 {
                        return false;
                    }

                    let Some(parent_proc) = pid_process_map.get(&(proc.ppid as u32)) else {
                        error!(
                            "pid {} have no parent proc with ppid: {}",
                            proc.pid, proc.ppid
                        );
                        return false;
                    };
                    if reg.is_match(&parent_proc.process_name.as_str()) {
                        return true;
                    }
                    // recursive match along the parent.
                    match_parent(parent_proc, pid_process_map, reg)
                }

                match_parent(&*proc, pid_process_map, reg)
            }
            ProcRegRewrite::Tag(reg, _) => {
                if let Some(tag) = tags.get(&proc.pid) {
                    let mut found = false;
                    for tag_kv in tag.tags.iter() {
                        let composed = format!("{}:{}", &tag_kv.key, &tag_kv.value);
                        if reg.is_match(&composed.as_str()) {
                            found = true;
                            break;
                        }
                    }
                    found
                } else {
                    false
                }
            }
        }
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct OsAppTagKV {
    pub key: String,
    pub value: String,
}

#[derive(Default, Deserialize)]
pub struct OsAppTag {
    pid: u64,
    // Vec<key, val>
    tags: Vec<OsAppTagKV>,
}

pub(super) type PidProcMap = HashMap<u32, ProcessData>;

// get the pid and process map
// now only use for match parent proc name to filter proc, the proc data in map will not fill the tag and not set username
pub(super) fn get_all_pid_process_map(proc_root: &str) -> PidProcMap {
    let mut h = HashMap::new();
    if let Ok(procs) = procfs::process::all_processes_with_root(proc_root) {
        for proc in procs {
            if let Err(err) = proc {
                error!("get process fail: {}", err);
                continue;
            }
            let proc = proc.unwrap();
            let Ok(proc_data) = ProcessData::try_from(&proc) else {
                continue;
            };

            h.insert(proc.pid as u32, proc_data);
        }
    }
    h
}

pub(super) fn get_all_process(conf: &OsProcScanConfig) -> Vec<ProcessData> {
    // Hashmap<root_inode, PasswordInfo>
    let mut pwd_info = HashMap::new();
    let (user, cmd, proc_root, proc_regexp, tagged_only, now_sec) = (
        conf.os_app_tag_exec_user.as_str(),
        conf.os_app_tag_exec.as_slice(),
        conf.os_proc_root.as_str(),
        conf.os_proc_regex.as_slice(),
        conf.os_proc_sync_tagged_only,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );

    let mut tags_map = match get_os_app_tag_by_exec(user, cmd) {
        Ok(tags) => tags,
        Err(err) => {
            error!(
                "get process tags by execute cmd `{}` with user {} fail: {}",
                cmd.join(" "),
                user,
                err
            );
            HashMap::new()
        }
    };

    let mut ret = vec![];
    let mut pid_proc_map = get_all_pid_process_map(conf.os_proc_root.as_str());

    if let Ok(procs) = procfs::process::all_processes_with_root(proc_root) {
        for proc in procs {
            if let Err(err) = proc {
                error!("get process fail: {}", err);
                continue;
            }
            let mut proc_data = {
                let Some(proc_data) = pid_proc_map.get_mut(&(proc.unwrap().pid as u32)) else {
                    continue;
                };
                proc_data.clone()
            };
            let Ok(up_sec) = proc_data.up_sec(now_sec) else {
                continue;
            };

            // filter the short live proc
            if up_sec < u64::from(conf.os_proc_socket_min_lifetime) {
                continue;
            }

            for i in proc_regexp.iter() {
                if i.match_and_rewrite_proc(&mut proc_data, &pid_proc_map, &tags_map, false) {
                    if i.action() == RegExpAction::Drop {
                        break;
                    }

                    // get pwd info from hashmap or parse pwd file from /proc/pid/root/etc/passwd and insert to hashmap
                    // and get the username from pwd info
                    match proc_data.get_root_inode(proc_root) {
                        Err(e) => error!("pid {} get root inode fail: {}", proc_data.pid, e),
                        Ok(inode) => {
                            if let Some(pwd) = pwd_info.get(&inode) {
                                proc_data.set_username(&pwd);
                            } else {
                                // not in hashmap, parse from /proc/pid/root/etc/passwd
                                let p = PathBuf::from_iter([
                                    proc_root,
                                    proc_data.pid.to_string().as_str(),
                                    "root/etc/passwd",
                                ]);
                                if let Ok(pwd) = PasswordInfo::new(p) {
                                    proc_data.set_username(&pwd);
                                    pwd_info.insert(inode, pwd);
                                }
                            }
                        }
                    }

                    // fill tags
                    if let Some(tags) = tags_map.remove(&proc_data.pid) {
                        proc_data.os_app_tags = tags.tags
                    } else if tagged_only {
                        break;
                    }

                    ret.push(proc_data);
                    break;
                }
            }
        }
        fill_child_proc_tag_by_parent(ret.as_mut());
        proc_scan_hook(&mut ret);
    }
    return ret;
}

pub(super) fn get_self_proc() -> ProcResult<ProcessData> {
    let proc = procfs::process::Process::myself()?;
    let mut path = proc.root()?;
    path.push("etc/passwd");
    let pwd = PasswordInfo::new(path).map_err(|e| ProcError::Other(e.to_string()))?;
    let mut proc_data = ProcessData::try_from(&proc)?;
    proc_data.set_username(&pwd);
    Ok(proc_data)
}

// return Hashmap<pid, OsAppTag>
pub(super) fn get_os_app_tag_by_exec(
    username: &str,
    cmd: &[String],
) -> Result<HashMap<u64, OsAppTag>, String> {
    if username.is_empty() || cmd.len() == 0 {
        return Ok(HashMap::new());
    }

    let pwd_info = PasswordInfo::new("/etc/passwd").map_err(|e| e.to_string())?;
    let Some(uid) = pwd_info.get_uid_by_username(username) else {
        return Err(format!("get userid by username {} fail", username).to_string());
    };

    let mut exec_cmd = Command::new(&cmd[0]);
    exec_cmd.uid(uid).args(&cmd[1..]);

    let output = exec_cmd.output();
    if let Err(err) = output {
        return Err(err.to_string());
    };
    let output = output.unwrap();
    let stdout = String::from_utf8_lossy(output.stdout.as_ref()).to_string();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(output.stderr.as_ref()).to_string();
        return Err(format!(
            "exit_status: {}\nstdout: {}\nstderr: {}",
            output.status, stdout, stderr
        ));
    };

    match serde_yaml::from_str::<Vec<OsAppTag>>(stdout.as_str()) {
        Ok(tags) => Ok(HashMap::from_iter(tags.into_iter().map(|t| (t.pid, t)))),
        Err(e) => Err(format!("unmarshal to yaml fail: {}\nstdout: {}", e, stdout).to_string()),
    }
}

/*
    Fill proc tag from parent tag. preserve child key and val when parent and child key conflict.
    It will recursive to tag parent before merge the child and parent tag. Therefore, the parent
    tag can spread to child only if parent process not filter by os-regexp.

*/
fn fill_child_proc_tag_by_parent(procs: &mut Vec<ProcessData>) {
    // Hashmap<pid, proc_idx> use for fill child proc tag from parent tag
    let mut pid_map = HashMap::new();
    for (i, p) in procs.iter().enumerate() {
        pid_map.insert(p.pid, i);
    }

    let mut tagged_pid = HashSet::new();
    for child_idx in 0..procs.len() {
        tag_child_along_parent(child_idx, procs, &pid_map, &mut tagged_pid);
    }
}

fn tag_child_along_parent(
    child_idx: usize,
    procs: &mut Vec<ProcessData>,
    pid_map: &HashMap<u64, usize>,
    tagged_pid: &mut HashSet<u64>,
) {
    let proc = procs.get(child_idx).unwrap();
    let pid = proc.pid;
    let ppid = proc.ppid;
    if ppid == 0 || tagged_pid.contains(&proc.pid) {
        return;
    }

    if let Some(parent_idx) = pid_map.get(&ppid) {
        if child_idx == *parent_idx {
            error!("pid: {} child pid equal to parent pid", ppid);
            return;
        }

        // recursive to tag parent
        tag_child_along_parent(*parent_idx, procs, pid_map, tagged_pid);

        let (child, parent) = if child_idx > *parent_idx {
            let (left, right) = procs.split_at_mut(child_idx);
            let child = right.get_mut(0).unwrap();
            let parent: &ProcessData = left.get(*parent_idx).unwrap();
            (child, parent)
        } else {
            let (left, right) = procs.split_at_mut(*parent_idx);
            let child = left.get_mut(child_idx).unwrap();
            let parent: &ProcessData = right.get(0).unwrap();
            (child, parent)
        };

        merge_tag(&mut child.os_app_tags, &parent.os_app_tags);
        tagged_pid.insert(pid);
    }
}

fn merge_tag(child_tag: &mut Vec<OsAppTagKV>, parent_tag: &[OsAppTagKV]) {
    'l: for pt in parent_tag {
        // ignore key is in exist in child
        for ct in child_tag.iter() {
            if ct.key == pt.key {
                continue 'l;
            }
        }
        child_tag.push(pt.clone());
    }
}

fn get_container_id(proc: &Process) -> Option<String> {
    let Ok(cgruop) = proc.cgroups() else {
        return None;
    };

    let mut path = "".to_string();

    'l: for i in cgruop {
        // cgroup version 2 have no controller
        if i.controllers.len() == 0 {
            path = i.pathname;
            break;
        } else {
            for c in i.controllers {
                match c.as_str() {
                    "pids" | "cpuset" | "devices" | "memory" | "cpu" => {
                        path = i.pathname;
                        break 'l;
                    }
                    _ => {}
                }
            }
        };
    }
    if path.is_empty() {
        return None;
    }

    let Some((_, s)) = path.rsplit_once(MAIN_SEPARATOR) else {
        debug!("cgroup path: `{:?}` get base path fail", path);
        return None;
    };

    if s.len() == CONTAINER_ID_LEN {
        // when length is 64 assume is docker cri
        Some(s.to_string())
    } else {
        // other cri likely have format like `${cri-prefix}-${container id}.scope`
        let Some((_, sp)) = s.rsplit_once("-") else {
            debug!("containerd cri path: `{:?}` get container id fail", path);
            return None;
        };
        if sp.len() != CONTAINER_ID_LEN + ".scope".len() {
            debug!("containerd cri path: `{}` parse fail, length incorrect", sp);
            return None;
        }
        Some(sp[..CONTAINER_ID_LEN].to_string())
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use rand::{seq::SliceRandom, thread_rng};

    use crate::platform::platform_synchronizer::linux_process::fill_child_proc_tag_by_parent;

    use super::{OsAppTagKV, ProcessData};

    #[test]
    fn test_tag_spread() {
        for _ in 0..20 {
            let mut procs = vec![
                ProcessData {
                    name: "root".into(),
                    pid: 999,
                    ppid: 0,
                    process_name: "root".into(),
                    cmd: vec!["root".into()],
                    user_id: 0,
                    user: "u".into(),
                    start_time: Duration::ZERO,
                    os_app_tags: vec![OsAppTagKV {
                        key: "root_key".into(),
                        value: "root_val".into(),
                    }],
                    netns_id: 1,
                    container_id: "".into(),
                },
                ProcessData {
                    name: "parent".into(),
                    pid: 99,
                    ppid: 999,
                    process_name: "parent".into(),
                    cmd: vec!["parent".into()],
                    user_id: 0,
                    user: "u".into(),
                    start_time: Duration::ZERO,
                    os_app_tags: vec![OsAppTagKV {
                        key: "parent_key".into(),
                        value: "parent_val".into(),
                    }],
                    netns_id: 1,
                    container_id: "".into(),
                },
                ProcessData {
                    name: "child".into(),
                    pid: 9999,
                    ppid: 99,
                    process_name: "child".into(),
                    cmd: vec!["child".into()],
                    user_id: 0,
                    user: "u".into(),
                    start_time: Duration::ZERO,
                    os_app_tags: vec![OsAppTagKV {
                        key: "child_key".into(),
                        value: "child_val".into(),
                    }],
                    netns_id: 1,
                    container_id: "".into(),
                },
                ProcessData {
                    name: "other".into(),
                    pid: 777,
                    ppid: 98,
                    process_name: "other".into(),
                    cmd: vec!["other".into()],
                    user_id: 0,
                    user: "u".into(),
                    start_time: Duration::ZERO,
                    os_app_tags: vec![OsAppTagKV {
                        key: "other_key".into(),
                        value: "other_val".into(),
                    }],
                    netns_id: 1,
                    container_id: "".into(),
                },
            ];

            procs.shuffle(&mut thread_rng());
            fill_child_proc_tag_by_parent(&mut procs);

            procs.sort_by_key(|x| x.pid);

            let parent = procs.get(0).unwrap();
            let other = procs.get(1).unwrap();
            let root = procs.get(2).unwrap();
            let child = procs.get(3).unwrap();

            assert_eq!(other.os_app_tags.len(), 1);
            assert_eq!(other.os_app_tags[0].key.to_string(), "other_key");
            assert_eq!(other.os_app_tags[0].value.to_string(), "other_val");

            assert_eq!(root.os_app_tags.len(), 1);
            assert_eq!(root.os_app_tags[0].key.to_string(), "root_key");
            assert_eq!(root.os_app_tags[0].value.to_string(), "root_val");

            assert_eq!(parent.os_app_tags.len(), 2);
            assert_eq!(parent.os_app_tags[0].key.to_string(), "parent_key");
            assert_eq!(parent.os_app_tags[0].value.to_string(), "parent_val");
            assert_eq!(parent.os_app_tags[1].key.to_string(), "root_key");
            assert_eq!(parent.os_app_tags[1].value.to_string(), "root_val");

            assert_eq!(child.os_app_tags.len(), 3);
            assert_eq!(child.os_app_tags[0].key.to_string(), "child_key");
            assert_eq!(child.os_app_tags[0].value.to_string(), "child_val");
            assert_eq!(child.os_app_tags[1].key.to_string(), "parent_key");
            assert_eq!(child.os_app_tags[1].value.to_string(), "parent_val");
            assert_eq!(child.os_app_tags[2].key.to_string(), "root_key");
            assert_eq!(child.os_app_tags[2].value.to_string(), "root_val");
        }
    }
}
