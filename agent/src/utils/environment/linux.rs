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
    fs,
    io::{self, Read},
    iter::Iterator,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use bollard::{container::UpdateContainerOptions, Docker};
use chrono::DateTime;
use k8s_openapi::{api::apps::v1::DaemonSet, apimachinery::pkg::api::resource::Quantity};
use kube::{
    api::{Api, Patch, PatchParams},
    Client, Config,
};
use log::{debug, error, info, warn};
use nix::sys::utsname::uname;
use nom::AsBytes;
use procfs::net::{TcpNetEntry, UdpNetEntry};

use public::utils::net::get_link_enabled_features;

use super::{get_k8s_namespace, running_in_container, running_in_k8s};
use crate::{
    common::{CONTAINER_NAME, DAEMONSET_NAME, PROCESS_NAME, PROCESS_NAME_SECONDARY},
    error::{Error, Result},
    exception::ExceptionHandler,
};

const CORE_FILE_CONFIG: &str = "/proc/sys/kernel/core_pattern";
const CORE_FILE_LIMIT: usize = 3;

pub fn free_memory_check(_required: u64, _exception_handler: &ExceptionHandler) -> Result<()> {
    return Ok(()); // fixme: The way to obtain free memory is different in earlier versions of Linux, which requires adaptation
}

pub fn kernel_check() {
    const RECOMMENDED_KERNEL_VERSION: &str = "4.19.17";
    // The `kernel_version` is in the format of 5.4.0-13
    let sys_uname = uname();
    if sys_uname
        .release()
        .trim()
        .split_once('-') // The number after "-" represents the number of times the version has been modified, and it is separated by "-"
        .unwrap_or_default()
        .0
        .ne(RECOMMENDED_KERNEL_VERSION)
    {
        warn!(
            "kernel version is not recommended({})",
            RECOMMENDED_KERNEL_VERSION
        );
    }
}

pub fn tap_interface_check(tap_interfaces: &[String]) {
    if tap_interfaces.is_empty() {
        return error!("static-config: tap-interfaces is none in analyzer-mode");
    }

    for name in tap_interfaces {
        let features = match get_link_enabled_features(name) {
            Ok(f) => f,
            Err(e) => {
                warn!("{}, please check rx-vlan-offload manually", e);
                continue;
            }
        };
        if features.contains("rx-vlan-hw-parse") {
            warn!(
                "NIC {} feature rx-vlan-offload is on, turn off if packet has vlan",
                name
            );
        }
    }
}

enum CoreFileProcessor<'a> {
    Dir(&'a str),
    Process(&'a str),
}

impl<'a> From<&'a str> for CoreFileProcessor<'a> {
    // The content is read from/doc/sys/kernel/core_mattern, example:
    // 1. "/core"
    // 2. "|/usr/libexec/abrt-hook-ccpp %s %c %p %u %g %t %e %P %I %h"
    fn from(content: &'a str) -> CoreFileProcessor<'a> {
        if content.is_empty() || content.as_bytes()[0] == '|' as u8 {
            if let Some((_, right)) = content.rsplit_once('/') {
                if let Some((left, _)) = right.split_once(' ') {
                    CoreFileProcessor::Process(left)
                } else {
                    CoreFileProcessor::Process(right)
                }
            } else {
                CoreFileProcessor::Process(content)
            }
        } else {
            CoreFileProcessor::Dir(content)
        }
    }
}

impl CoreFileProcessor<'_> {
    fn format_timestamp(timestamp: i64) -> String {
        let datetime = DateTime::from_timestamp(timestamp, 0).unwrap();

        datetime.format("%Y-%m-%d %H:%M:%S").to_string()
    }

    fn remove_core_file(mut core_files: Vec<(i64, String)>, is_dir: bool) {
        if core_files.len() > CORE_FILE_LIMIT {
            core_files.sort_by(|a, b| b.0.cmp(&a.0));
            core_files[CORE_FILE_LIMIT..].iter().for_each(|x| {
                let result = if is_dir {
                    fs::remove_dir_all(&x.1)
                } else {
                    fs::remove_file(&x.1)
                };

                if let Err(e) = result {
                    warn!("Remove core file({}) error: {e}.", x.1)
                } else {
                    info!("Remove core file: {} {}.", Self::format_timestamp(x.0), x.1)
                }
            });
        }
    }

    fn check_core_file_dir<P: AsRef<Path>>(&self, core_path: P) {
        const CORE_FILE_BUFFER: usize = 256 << 10;

        let context = match fs::read_dir(&core_path) {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    "Core file read dir {} error: {e}.",
                    core_path.as_ref().display()
                );
                return;
            }
        };

        let mut core_files = vec![];
        // Traverse the directory to get the core file in the directory
        for entry in context {
            let Ok(entry) = entry else {
                continue;
            };

            if !entry.path().is_file() {
                continue;
            }

            let Ok(mut file) = fs::File::open(entry.path()) else {
                continue;
            };

            let mut elf_data = [0u8; 128];
            let Ok(n) = file.read(&mut elf_data) else {
                continue;
            };
            let elf_data = &mut elf_data[..n];

            // Check whether the file is a core file
            let Ok(elf_header) = elf::file::FileHeader::parse(&mut elf_data.as_bytes()) else {
                continue;
            };

            if elf_header.elftype.0 != elf::gabi::ET_CORE {
                continue;
            }

            // Check whether the core file is generated by PROCESS_NAME
            let mut elf_data = [0u8; CORE_FILE_BUFFER];
            let Ok(n) = file.read(&mut elf_data) else {
                continue;
            };

            let elf_data = &mut elf_data[..n];
            let context = String::from_utf8_lossy(&elf_data);
            if context.find(PROCESS_NAME).is_none()
                && context.find(PROCESS_NAME_SECONDARY).is_none()
            {
                continue;
            }

            let Ok(meta_data) = entry.metadata() else {
                continue;
            };

            let item = {
                let last_modify_time = meta_data.mtime();
                let path = entry.file_name();

                if let Some(p) = path.to_str() {
                    (
                        last_modify_time,
                        format!("{}/{p}", core_path.as_ref().display()),
                    )
                } else {
                    continue;
                }
            };

            info!("Core file: {} {}.", Self::format_timestamp(item.0), item.1);
            core_files.push(item);
        }

        Self::remove_core_file(core_files, false);
    }

    fn check_abrt_dir<P: AsRef<Path>>(&self, core_path: P) {
        let context = match fs::read_dir(&core_path) {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    "Core file read dir {} error: {e}.",
                    core_path.as_ref().display()
                );
                return;
            }
        };

        let mut core_files = vec![];
        for entry in context {
            let Ok(entry) = entry else {
                continue;
            };

            if !entry.path().is_dir() {
                continue;
            }

            let Ok(exec) = fs::read_to_string(format!("{}/executable", entry.path().display()))
            else {
                continue;
            };

            if exec.find(PROCESS_NAME).is_none() && exec.find(PROCESS_NAME_SECONDARY).is_none() {
                continue;
            }

            let Ok(meta_data) = entry.metadata() else {
                continue;
            };

            let item = {
                let last_modify_time = meta_data.mtime();
                let path = entry.file_name();

                if let Some(p) = path.to_str() {
                    (
                        last_modify_time,
                        format!("{}/{p}", core_path.as_ref().display()),
                    )
                } else {
                    continue;
                }
            };

            info!("Core file: {} {}.", Self::format_timestamp(item.0), item.1);
            core_files.push(item);
        }

        Self::remove_core_file(core_files, true);
    }

    fn check(&self) {
        const DEFAILT_CORE_DIR: &str = "/";

        match self {
            CoreFileProcessor::Dir(core_path) => {
                // core_path example:
                // 1. "/"
                // 2. "/core"
                // 3. "/core%/"
                // 4. "/core/core-%t-%p-%h"
                let parts = core_path.split("/").collect::<Vec<&str>>();
                let core_path = if parts.len() <= 1 {
                    "/".to_string()
                } else {
                    if parts[parts.len() - 1].find("%").is_none() {
                        parts.join("/")
                    } else {
                        parts[..parts.len() - 1].join("/")
                    }
                };

                info!("Check core-files in dir: {}", core_path);
                self.check_core_file_dir(core_path);
            }
            // centos
            CoreFileProcessor::Process("abrt-hook-ccpp") => {
                const CONFIG_DIR: &str = "/etc/abrt/abrt.conf";
                const CORE_DIR: &str = "/var/spool/abrt";

                match fs::read_to_string(CONFIG_DIR) {
                    Ok(context) => {
                        for line in context.lines() {
                            if line.trim().starts_with("#") {
                                continue;
                            }

                            if line.contains("DumpLocation") {
                                if let Some((_left, right)) = line.rsplit_once("=") {
                                    info!("Check core-files in dir: {}", right.trim());
                                    self.check_abrt_dir(right.trim());
                                    info!("Check core-files in dir: {}", DEFAILT_CORE_DIR);
                                    self.check_core_file_dir(DEFAILT_CORE_DIR);
                                    return;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        info!("The core file config {} read failed: {:?}.", CONFIG_DIR, e,);
                    }
                }

                info!("Check core-files in dir: {}", CORE_DIR);
                self.check_abrt_dir(CORE_DIR);
                info!("Check core-files in dir: {}", DEFAILT_CORE_DIR);
                self.check_core_file_dir(DEFAILT_CORE_DIR);
            }
            // ubuntu
            CoreFileProcessor::Process("apport") => {
                const CONFIG_DIR: &str = "/etc/apport/apport.conf";
                const CORE_DIR: &str = "/var/lib/apport/coredump/";

                match fs::read_to_string(CONFIG_DIR) {
                    Ok(context) => {
                        for line in context.lines() {
                            if line.trim().starts_with("#") {
                                continue;
                            }

                            if line.contains("coredump_dir") || line.contains("crash_dir") {
                                if let Some((_left, right)) = line.rsplit_once("=") {
                                    info!("Check core-files in dir: {}", right.trim());
                                    self.check_core_file_dir(right.trim());
                                    info!("Check core-files in dir: {}", DEFAILT_CORE_DIR);
                                    self.check_core_file_dir(DEFAILT_CORE_DIR);
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        info!("The core file config {} read failed: {:?}.", CONFIG_DIR, e,);
                    }
                }

                info!("Check core-files in dir: {}", CORE_DIR);
                self.check_core_file_dir(CORE_DIR);
                info!("Check core-files in dir: {}", DEFAILT_CORE_DIR);
                self.check_core_file_dir(DEFAILT_CORE_DIR);
            }
            CoreFileProcessor::Process(name) => {
                info!(
                    "The core file check does not support the pipe command {}, skipping the check.",
                    name
                );
            }
        }
    }
}

fn read_core_file_config() -> Option<String> {
    let core_path = match fs::read(CORE_FILE_CONFIG) {
        Ok(c) => c,
        Err(e) => {
            warn!("Core file read {} error: {e}", CORE_FILE_CONFIG);
            return None;
        }
    };

    let core_path = match String::from_utf8(core_path) {
        Ok(c) => c,
        Err(e) => {
            warn!("Core file parse {} error: {e}", CORE_FILE_CONFIG);
            return None;
        }
    };

    Some(core_path)
}

pub fn core_file_check() {
    let Some(path) = read_core_file_config() else {
        return;
    };
    info!("Current {} content is {}", CORE_FILE_CONFIG, path);

    CoreFileProcessor::from(path.as_str()).check();
}

pub fn get_executable_path() -> Result<PathBuf, io::Error> {
    let possible_paths = vec![
        "/proc/self/exe".to_owned(),
        "/proc/curproc/exe".to_owned(),
        "/proc/curproc/file".to_owned(),
        format!("/proc/{}/path/a.out", std::process::id()),
    ];
    for path in possible_paths {
        if let Ok(path) = fs::read_link(path) {
            return Ok(path);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "executable path not found",
    ))
}

pub async fn get_current_k8s_image() -> Option<String> {
    if !running_in_k8s() {
        return None;
    }

    let daemonsets = get_k8s_daemonsets().await.ok()?;

    let Ok(daemonset) = daemonsets.get(DAEMONSET_NAME).await else {
        warn!("failed to get agent image name from daemonset: {DAEMONSET_NAME}");
        return None;
    };

    // Referer: https://kubernetes.io/zh-cn/docs/reference/kubernetes-api/workload-resources/pod-v1/#Container
    // The deepflow-agent DaemonSet.spec format is as follows:
    // {
    //   "spec":{
    //     "template":{
    //       "spec":{
    //         "containers":[{
    //           "name":"deepflow-agent",
    //           "image":"deepflow-agent:latest",
    //         }]
    //       }
    //     }
    //   }
    // }
    if let Some(spec) = daemonset.spec {
        if let Some(s) = spec.template.spec {
            for container in s.containers {
                return Some(container.image.unwrap_or_default());
            }
        }
    }
    None
}

pub fn get_container_resource_limits() -> (u32, u64) {
    if !running_in_container() {
        return (0, 0);
    }
    let cpu_cgroups_files = [
        "/sys/fs/cgroup/cpu.max", // If the container image uses cgroups v2, the format of the file is: {cfs_quota_us} {cfs_period_us}, for example: 100000 100000
        "/sys/fs/cgroup/cpu/cpu.cfs_quota_us", // If the container image uses cgroups v1, the format of the file is: {cfs_quota_us}, for example: 100000
    ];
    let mem_cgroups_files = [
        "/sys/fs/cgroup/memory.max", // unit: bytes
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    ];

    let milli_cpu_limit = cpu_cgroups_files
        .iter()
        .find_map(|f| {
            fs::read_to_string(f)
                .ok()?
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<u32>().map(|m| m / 100).ok()) // convert to milli-core
        })
        .unwrap_or_default();
    let memory_limit = mem_cgroups_files
        .iter()
        .find_map(|f| {
            fs::read_to_string(f)
                .ok()
                .and_then(|content| content.trim().parse::<u64>().ok())
        })
        .unwrap_or_default();

    (milli_cpu_limit, memory_limit)
}

pub async fn set_docker_resource_limits(
    milli_cpu_limit: u32, // unit: milli-core
    memory_limit: u64,
) -> Result<(), Error> {
    let docker = Docker::connect_with_local_defaults()
        .map_err(|e| Error::Environment(format!("connet docker failed: {:?}", e)))?;
    let update_options = UpdateContainerOptions::<String> {
        nano_cp_us: Some((milli_cpu_limit * 1_000_000) as i64),
        memory: Some(memory_limit as i64),
        memory_swap: Some((memory_limit * 2) as i64),
        ..Default::default()
    };
    docker
        .update_container(CONTAINER_NAME, update_options)
        .await
        .map(|_| ())
        .map_err(|e| {
            Error::Environment(format!(
                "set cpu_limit: {}, set memory_limit: {}bytes, update docker container failed: {:?}",
                milli_cpu_limit as f64 / 1000.0, memory_limit, e
            ))
        })
}

pub async fn get_k8s_daemonsets() -> Result<Api<DaemonSet>, Error> {
    let mut config = Config::infer()
        .await
        .map_err(|e| Error::Environment(format!("get k8s config failed: {:?}", e)))?;
    config.accept_invalid_certs = true;
    let client = Client::try_from(config)
        .map(|c| c)
        .map_err(|e| Error::Environment(format!("get k8s client failed: {:?}", e)))?;
    Ok(Api::namespaced(client, &get_k8s_namespace()))
}

pub async fn set_k8s_resource_limits(milli_cpu_limit: u32, memory_limit: u64) -> Result<(), Error> {
    let daemonsets = get_k8s_daemonsets().await?;

    let mut resource_limits = std::collections::BTreeMap::new();
    resource_limits.insert("cpu".to_string(), Quantity(format!("{}m", milli_cpu_limit)));
    resource_limits.insert(
        "memory".to_string(),
        Quantity(format!("{}Mi", (memory_limit / (1024 * 1024)))),
    );
    let patch = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": CONTAINER_NAME,
                            "resources": {
                                "limits": resource_limits,
                            },
                        }
                    ]
                }
            }
        }
    });
    let params = PatchParams::default();
    let patch = Patch::Strategic(&patch);
    daemonsets
        .patch(DAEMONSET_NAME, &params, &patch)
        .await
        .map(|_| ())
        .map_err(|e| {
            Error::Environment(format!(
                "patch k8s daemonset {} failed: {:?}, patch value: {:?}",
                DAEMONSET_NAME, e, patch
            ))
        })
}

pub async fn set_container_resource_limit(
    milli_cpu_limit: u32,
    memory_limit: u64,
) -> Result<(), Error> {
    if running_in_k8s() {
        set_k8s_resource_limits(milli_cpu_limit, memory_limit).await
    } else {
        set_docker_resource_limits(milli_cpu_limit, memory_limit).await
    }
}

pub fn is_kernel_available(kernel_version: &str) -> bool {
    let sys_uname = uname(); // kernel_version is in the format of 5.4.0-13
    sys_uname
        .release()
        .trim()
        .split_once('-')
        .unwrap_or_default()
        .0
        .ge(kernel_version)
}

pub struct SocketInfo {
    pub tcp: Vec<TcpNetEntry>,
    pub tcp6: Vec<TcpNetEntry>,
    pub udp: Vec<UdpNetEntry>,
    pub udp6: Vec<UdpNetEntry>,
}

fn tcp_filter(inodes: &[u64]) -> impl Fn(&TcpNetEntry) -> bool + '_ {
    |entry| {
        entry.state == procfs::net::TcpState::Established
            && inodes.binary_search(&entry.inode).is_ok()
    }
}

fn udp_filter(inodes: &[u64]) -> impl Fn(&UdpNetEntry) -> bool + '_ {
    |entry| inodes.binary_search(&entry.inode).is_ok()
}

impl std::fmt::Display for SocketInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, entry) in self.tcp.iter().enumerate() {
            if i == 0 {
                let _ = write!(f, "tcp:\n")?;
            }
            let _ = write!(
                f,
                "  {}:{} <-> {}:{}\n",
                entry.local_address.ip().to_canonical(),
                entry.local_address.port(),
                entry.remote_address.ip().to_canonical(),
                entry.remote_address.port()
            );
        }
        for (i, entry) in self.tcp6.iter().enumerate() {
            if i == 0 {
                let _ = write!(f, "tcp6:\n")?;
            }
            let _ = write!(
                f,
                "  {}:{} <-> {}:{}\n",
                entry.local_address.ip().to_canonical(),
                entry.local_address.port(),
                entry.remote_address.ip().to_canonical(),
                entry.remote_address.port()
            );
        }
        for (i, entry) in self.udp.iter().enumerate() {
            if i == 0 {
                let _ = write!(f, "udp:\n")?;
            }
            let _ = write!(
                f,
                "  {}:{} <-> {}:{}\n",
                entry.local_address.ip().to_canonical(),
                entry.local_address.port(),
                entry.remote_address.ip().to_canonical(),
                entry.remote_address.port()
            );
        }
        for (i, entry) in self.udp6.iter().enumerate() {
            if i == 0 {
                let _ = write!(f, "udp6:\n")?;
            }
            let _ = write!(
                f,
                "  {}:{} <-> {}:{}\n",
                entry.local_address.ip().to_canonical(),
                entry.local_address.port(),
                entry.remote_address.ip().to_canonical(),
                entry.remote_address.port()
            );
        }
        Ok(())
    }
}

impl SocketInfo {
    pub fn get() -> procfs::ProcResult<Self> {
        let mut socket_inodes = vec![];
        let proc = procfs::process::Process::myself()?;
        for fd in proc.fd()? {
            match fd?.target {
                procfs::process::FDTarget::Socket(inode) => socket_inodes.push(inode),
                _ => {}
            }
        }
        socket_inodes.sort_unstable();

        Ok(Self {
            tcp: match procfs::net::tcp() {
                Ok(entries) => entries
                    .into_iter()
                    .filter(tcp_filter(&socket_inodes))
                    .collect(),
                Err(e) => {
                    debug!("get tcp socket failed: {}", e);
                    vec![]
                }
            },
            tcp6: match procfs::net::tcp6() {
                Ok(entries) => entries
                    .into_iter()
                    .filter(tcp_filter(&socket_inodes))
                    .collect(),
                Err(e) => {
                    debug!("get tcp6 socket failed: {}", e);
                    vec![]
                }
            },
            udp: match procfs::net::udp() {
                Ok(entries) => entries
                    .into_iter()
                    .filter(udp_filter(&socket_inodes))
                    .collect(),
                Err(e) => {
                    debug!("get udp socket failed: {}", e);
                    vec![]
                }
            },
            udp6: match procfs::net::udp6() {
                Ok(entries) => entries
                    .into_iter()
                    .filter(udp_filter(&socket_inodes))
                    .collect(),
                Err(e) => {
                    debug!("get udp6 socket failed: {}", e);
                    vec![]
                }
            },
        })
    }
}
