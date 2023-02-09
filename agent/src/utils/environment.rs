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
    env::{self, VarError},
    io,
    iter::Iterator,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    process, thread,
    time::Duration,
};
#[cfg(target_os = "windows")]
use std::{ffi::OsString, os::windows::ffi::OsStringExt, ptr};
#[cfg(target_os = "linux")]
use std::{fs, io::Read, os::unix::fs::MetadataExt};

use bytesize::ByteSize;
#[cfg(target_os = "linux")]
use elf::{file::FileHeader, gabi::ET_CORE};
#[cfg(target_os = "linux")]
use log::info;
use log::{error, warn};
#[cfg(target_os = "linux")]
use nom::AsBytes;
use sysinfo::{DiskExt, System, SystemExt};
#[cfg(target_os = "windows")]
use winapi::{
    shared::minwindef::{DWORD, MAX_PATH},
    um::libloaderapi::GetModuleFileNameW,
};

use crate::common::PROCESS_NAME;
use crate::error::{Error, Result};
use crate::exception::ExceptionHandler;
use public::proto::{common::TridentType, trident::Exception};

#[cfg(target_os = "windows")]
use super::process::get_memory_rss;
use super::process::get_process_num_by_name;
#[cfg(target_os = "linux")]
use public::utils::net::get_link_enabled_features;
use public::utils::net::{
    get_mac_by_ip, get_route_src_ip_and_mac, link_by_name, link_list, LinkFlags, MacAddr,
};

pub type Checker = Box<dyn Fn() -> Result<()>>;

// K8S environment node ip environment variable
pub const K8S_NODE_IP_FOR_DEEPFLOW: &str = "K8S_NODE_IP_FOR_DEEPFLOW";
#[cfg(target_os = "linux")]
const CORE_FILE_CONFIG: &str = "/proc/sys/kernel/core_pattern";
#[cfg(target_os = "linux")]
const CORE_FILE_LIMIT: usize = 3;
const DNS_HOST_IPV4: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
const DNS_HOST_IPV6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x240c, 0, 0, 0, 0, 0, 0, 0x6666));

pub fn check(f: Checker) {
    let mut logged = false;
    loop {
        match f() {
            Ok(_) => return,
            Err(e) if !logged => {
                warn!("{}", e);
                logged = true;
            }
            _ => (),
        }
        thread::sleep(Duration::from_secs(10));
    }
}

pub fn kernel_check() {
    if cfg!(target_os = "windows") {
        return;
    }

    #[cfg(target_os = "linux")]
    {
        use nix::sys::utsname::uname;
        const RECOMMENDED_KERNEL_VERSION: &str = "4.19.17";
        // kernel_version 形如 5.4.0-13格式
        let sys_uname = uname();
        if sys_uname
            .release()
            .trim()
            .split_once('-') // `-` 后面数字是修改版本号的次数，可以用 `-` 分隔
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
}

pub fn tap_interface_check(tap_interfaces: &[String]) {
    if cfg!(target_os = "windows") {
        return;
    }

    if tap_interfaces.is_empty() {
        return error!("static-config: tap-interfaces is none in analyzer-mode");
    }

    #[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
pub fn free_memory_check(_required: u64, _exception_handler: &ExceptionHandler) -> Result<()> {
    return Ok(()); // fixme: The way to obtain free memory is different in earlier versions of Linux, which requires adaptation
}

#[cfg(target_os = "windows")]
pub fn free_memory_check(required: u64, exception_handler: &ExceptionHandler) -> Result<()> {
    get_memory_rss()
        .map_err(|e| Error::Environment(e.to_string()))
        .and_then(|memory_usage| {
            if required < memory_usage {
                return Ok(());
            }

            let still_need = required - memory_usage;
            let mut system = System::new();
            system.refresh_memory();

            if still_need <= system.available_memory() {
                exception_handler.clear(Exception::MemNotEnough);
                Ok(())
            } else {
                exception_handler.set(Exception::MemNotEnough);
                Err(Error::Environment(format!(
                    "need {} more memory to run",
                    ByteSize::b(still_need).to_string_as(true)
                )))
            }
        })
}

pub fn free_memory_checker(required: u64, exception_handler: ExceptionHandler) -> Checker {
    Box::new(move || free_memory_check(required, &exception_handler))
}

pub fn free_space_check<P: AsRef<Path>>(
    path: P,
    required: u64,
    exception_handler: &ExceptionHandler,
) -> Result<()> {
    let mut system = System::new();
    system.refresh_disks_list();

    let mut disk_free_usage = 0;
    let mut path_size = 0;
    for disk in system.disks() {
        let disk_path = disk.mount_point();
        if path.as_ref().starts_with(disk_path) {
            let count = disk_path.iter().count();
            if count > path_size {
                path_size = count;
                disk_free_usage = disk.available_space();
            }
        }
    }

    if path_size == 0 {
        return Err(Error::Environment(format!(
            "can't find path={} from disk list",
            path.as_ref().display()
        )));
    }

    if required > disk_free_usage {
        exception_handler.set(Exception::DiskNotEnough);
        return Err(Error::Environment(format!(
            "insufficient free space at {}, at least {} required",
            path.as_ref().display(),
            ByteSize::b(required).to_string_as(true)
        )));
    }

    exception_handler.clear(Exception::DiskNotEnough);
    Ok(())
}

pub fn free_space_checker<P: AsRef<Path>>(
    path: P,
    required: u64,
    exception_handler: ExceptionHandler,
) -> Checker {
    let path = path.as_ref().to_owned();
    Box::new(move || free_space_check(&path, required, &exception_handler))
}

pub fn controller_ip_check(ips: &[String]) {
    if ips.iter().all(|ip| match ip.parse::<IpAddr>() {
        Ok(ip) if ip.is_ipv4() => true,
        _ => false,
    }) {
        return;
    }

    if ips.iter().all(|ip| match ip.parse::<IpAddr>() {
        Ok(ip) if ip.is_ipv6() => true,
        _ => false,
    }) {
        return;
    }

    error!(
        "controller ip({:?}) is not support both IPv4 and IPv6, trident restart...",
        ips
    );

    thread::sleep(Duration::from_secs(1));
    process::exit(-1);
}

#[cfg(target_os = "linux")]
pub fn core_file_check() {
    let core_path = fs::read(CORE_FILE_CONFIG);
    if core_path.is_err() {
        warn!(
            "read {} error: {}",
            CORE_FILE_CONFIG,
            core_path.unwrap_err()
        );
        return;
    }
    let core_path = String::from_utf8(core_path.unwrap());
    if core_path.is_err() {
        warn!(
            "parse {} error: {}",
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

    info!("check core-files in dir: {}", core_path);

    let context = fs::read_dir(core_path.clone());
    if context.is_err() {
        warn!("Read dir {} error: {}.", core_path, context.unwrap_err());
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
        let elf_header = FileHeader::parse(&mut elf_data.as_bytes());
        if elf_header.is_err() {
            continue;
        }
        let elf_header = elf_header.unwrap();
        if elf_header.elftype.0 != ET_CORE {
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

pub fn trident_process_check(process_threshold: u32) {
    let process_num = get_process_num_by_name(PROCESS_NAME);

    match process_num {
        Ok(num) => {
            if num > process_threshold {
                error!(
                    "the number of process exceeds the limit({} > {})",
                    num, process_threshold
                );
                thread::sleep(Duration::from_secs(1));
                process::exit(-1);
            }
        }
        Err(e) => {
            warn!("{}", e);
        }
    }
}

pub fn is_tt_hyper_v_compute(trident_type: TridentType) -> bool {
    trident_type == TridentType::TtHyperVCompute
}

pub fn is_tt_hyper_v_network(trident_type: TridentType) -> bool {
    trident_type == TridentType::TtHyperVNetwork
}

pub fn is_tt_hyper_v(trident_type: TridentType) -> bool {
    trident_type == TridentType::TtHyperVCompute || trident_type == TridentType::TtHyperVNetwork
}

pub fn is_tt_pod(trident_type: TridentType) -> bool {
    trident_type == TridentType::TtHostPod || trident_type == TridentType::TtVmPod
}

pub fn is_tt_process(trident_type: TridentType) -> bool {
    trident_type == TridentType::TtProcess
}

pub fn is_tt_workload(trident_type: TridentType) -> bool {
    trident_type == TridentType::TtPublicCloud || trident_type == TridentType::TtPhysicalMachine
}

pub fn get_k8s_local_node_ip() -> Option<IpAddr> {
    match env::var(K8S_NODE_IP_FOR_DEEPFLOW) {
        Ok(v) => match v.parse::<IpAddr>() {
            Ok(ip) => {
                return Some(ip);
            }
            Err(e) => warn!("parse K8S_NODE_IP_FOR_DEEPFLOW string to ip failed: {}", e),
        },
        Err(e) => {
            if let VarError::NotUnicode(_) = &e {
                warn!(
                    "parse K8S_NODE_IP_FOR_DEEPFLOW environment variable failed: {}",
                    e
                );
            }
        }
    }
    None
}

pub fn running_in_container() -> bool {
    // Environment variable "IN_CONTAINTER" is set in dockerfile
    env::var_os("IN_CONTAINER").is_some()
}

pub fn running_in_only_watch_k8s_mode() -> bool {
    running_in_container() && env::var_os("ONLY_WATCH_K8S_RESOURCE").is_some()
}

#[cfg(target_os = "linux")]
pub fn get_executable_path() -> Result<PathBuf, io::Error> {
    let possible_paths = vec![
        "/proc/self/exe".to_owned(),
        "/proc/curproc/exe".to_owned(),
        "/proc/curproc/file".to_owned(),
        format!("/proc/{}/path/a.out", process::id()),
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

#[cfg(target_os = "windows")]
pub fn get_executable_path() -> Result<PathBuf, io::Error> {
    let mut buf = Vec::with_capacity(MAX_PATH);
    unsafe {
        let ret = GetModuleFileNameW(ptr::null_mut(), buf.as_mut_ptr(), MAX_PATH as DWORD) as usize;
        if ret > 0 && ret < MAX_PATH {
            buf.set_len(ret);
            let s = OsString::from_wide(&buf);
            Ok(s.into())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "executable path not found",
            ))
        }
    }
}

pub fn get_mac_by_name(src_interface: String) -> u32 {
    if src_interface.is_empty() {
        return 0;
    }
    match link_by_name(src_interface) {
        Ok(link) => MacAddr::to_lower_32b(&link.mac_addr),
        Err(e) => {
            warn!("get_mac_by_name failed, {}", e);
            0
        }
    }
}

pub fn get_ctrl_ip_and_mac(dest: IpAddr) -> (IpAddr, MacAddr) {
    // Directlly use env.K8S_NODE_IP_FOR_DEEPFLOW as the ctrl_ip reported by deepflow-agent if available
    match get_k8s_local_node_ip() {
        Some(ip) => {
            let ctrl_mac = get_mac_by_ip(ip);
            if ctrl_mac.is_err() {
                error!("failed getting ctrl_mac from {}: {:?}", ip, ctrl_mac);
                thread::sleep(Duration::from_secs(1));
                process::exit(-1);
            }
            (ip, ctrl_mac.unwrap())
        }
        None => {
            let tuple = get_route_src_ip_and_mac(&dest);
            if tuple.is_err() {
                error!("failed getting control ip and mac from {}", dest);
                thread::sleep(Duration::from_secs(1));
                process::exit(-1);
            }
            let (ip, mac) = tuple.unwrap();
            let links = link_list();
            if links.is_err() {
                error!("failed getting local interfaces.");
                thread::sleep(Duration::from_secs(1));
                process::exit(-1);
            }
            // When the found IP is attached to a Down network card,
            // use the public IP to check again to find the outgoing
            // interface of the default route.
            for link in links.unwrap().iter() {
                if link.mac_addr == mac {
                    if !link.flags.contains(LinkFlags::UP) {
                        let dest = if dest.is_ipv4() {
                            DNS_HOST_IPV4
                        } else {
                            DNS_HOST_IPV6
                        };
                        let tuple = get_route_src_ip_and_mac(&dest);
                        if tuple.is_err() {
                            error!("failed getting control ip and mac from {}", dest);
                            thread::sleep(Duration::from_secs(1));
                            process::exit(-1);
                        }
                        return tuple.unwrap();
                    }
                    break;
                }
            }

            (ip, mac)
        }
    }
}

//TODO Windows 相关
