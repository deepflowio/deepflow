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
    path::PathBuf,
};

use bollard::{container::UpdateContainerOptions, Docker};
use k8s_openapi::{api::apps::v1::DaemonSet, apimachinery::pkg::api::resource::Quantity};
use kube::{
    api::{Api, Patch, PatchParams},
    Client, Config,
};
use log::{error, info, warn};
use nom::AsBytes;

use public::utils::net::get_link_enabled_features;

use super::{get_k8s_namespace, running_in_container, running_in_k8s};
use crate::{
    common::{CONTAINER_NAME, DAEMONSET_NAME, PROCESS_NAME},
    error::{Error, Result},
    exception::ExceptionHandler,
};

const CORE_FILE_CONFIG: &str = "/proc/sys/kernel/core_pattern";
const CORE_FILE_LIMIT: usize = 3;

pub fn free_memory_check(_required: u64, _exception_handler: &ExceptionHandler) -> Result<()> {
    return Ok(()); // fixme: The way to obtain free memory is different in earlier versions of Linux, which requires adaptation
}

pub fn kernel_check() {
    use nix::sys::utsname::uname;
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

pub fn core_file_check() {
    let core_path = fs::read(CORE_FILE_CONFIG);
    if core_path.is_err() {
        warn!(
            "Core file read {} error: {}",
            CORE_FILE_CONFIG,
            core_path.unwrap_err()
        );
        return;
    }
    let core_path = String::from_utf8(core_path.unwrap());
    if core_path.is_err() {
        warn!(
            "Core file parse {} error: {}",
            CORE_FILE_CONFIG,
            core_path.unwrap_err()
        );
        return;
    }
    // core_path example:
    // 1. "|/usr/libexec/abrt-hook-ccpp %s %c %p %u %g %t e %P %I %h"
    let core_path = core_path.unwrap();
    if core_path.as_bytes()[0] == '|' as u8 {
        warn!("The core file is configured with pipeline operation, failed to check.");
        return;
    }

    // core_path example:
    // 1. "/"
    // 1. "/core"
    // 1. "/core%/"
    // 1. "/core/core-%t-%p-%h"
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

    let context = fs::read_dir(core_path.clone());
    if context.is_err() {
        warn!(
            "Core file read dir {} error: {}.",
            core_path,
            context.unwrap_err()
        );
        return;
    }

    let mut core_files = vec![];
    // Traverse the directory to get the core file in the directory
    for entry in context.unwrap() {
        if entry.is_err() || !entry.as_ref().unwrap().path().is_file() {
            continue;
        }
        let entry = entry.as_ref().unwrap();
        let file = fs::File::open(entry.path());
        if file.is_err() {
            continue;
        }
        let mut file = file.unwrap();
        let mut elf_data = [0u8; 128];
        let n = file.read(&mut elf_data);
        if n.is_err() {
            continue;
        }
        let elf_data = &mut elf_data[..n.unwrap()];

        // Check whether the file is a core file
        let elf_header = elf::file::FileHeader::parse(&mut elf_data.as_bytes());
        if elf_header.is_err() {
            continue;
        }
        let elf_header = elf_header.unwrap();
        if elf_header.elftype.0 != elf::gabi::ET_CORE {
            continue;
        }

        // Check whether the core file is generated by PROCESS_NAME
        let mut elf_data = [0u8; 80000];
        let n = file.read(&mut elf_data);
        if n.is_err() {
            continue;
        }
        let elf_data = &mut elf_data[..n.unwrap()];
        unsafe {
            if String::from_utf8_unchecked(elf_data.to_vec())
                .find(PROCESS_NAME)
                .is_none()
            {
                continue;
            }
        }

        let meta_data = entry.metadata();
        if meta_data.is_err() {
            continue;
        }
        let meta_data = meta_data.unwrap();
        let item = {
            let last_modify_time = meta_data.mtime();
            let path = entry.file_name();
            if path.to_str().is_none() {
                continue;
            }
            (
                last_modify_time,
                format!("{}/{}", core_path, path.to_str().unwrap().to_string()),
            )
        };

        info!("Core file: {} {}.", item.0, item.1);
        core_files.push(item);
    }

    if core_files.len() > CORE_FILE_LIMIT {
        core_files.sort_by(|a, b| b.0.cmp(&a.0));
        core_files[CORE_FILE_LIMIT..].iter().for_each(|x| {
            let result = fs::remove_file(&x.1);
            if result.is_err() {
                warn!("Remove core file({}) error: {}.", x.1, result.unwrap_err())
            } else {
                info!("Remove core file: {} {}.", x.0, x.1)
            }
        });
    }
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
        warn!("failed to get daemonsets");
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
                "set milli_cpu_limit: {}, set memory_limit: {}bytes, update docker container failed: {:?}",
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
