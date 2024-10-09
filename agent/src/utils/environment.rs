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
    cell::OnceCell,
    env::{self, VarError},
    fs,
    iter::Iterator,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    thread,
    time::Duration,
};

use bytesize::ByteSize;
use log::{error, warn};
use sysinfo::{DiskExt, System, SystemExt};

use crate::{
    common::PROCESS_NAME,
    config::K8S_CA_CRT_PATH,
    error::{Error, Result},
    exception::ExceptionHandler,
    utils::process::get_process_num_by_name,
};

use public::{
    proto::{
        agent::{AgentType, Exception, KubernetesWatchPolicy},
        trident::KubernetesWatchPolicy as OldKubernetesWatchPolicy,
    },
    utils::net::{
        addr_list, get_mac_by_ip, get_route_src_ip_and_mac, is_global, link_by_name, link_list,
        LinkFlags, MacAddr,
    },
};

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::*;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use self::windows::*;

pub type Checker = Box<dyn Fn() -> Result<()>>;

pub const IN_CONTAINER: &str = "IN_CONTAINER";
// K8S environment node ip environment variable
const K8S_NODE_IP_FOR_DEEPFLOW: &str = "K8S_NODE_IP_FOR_DEEPFLOW";
const ENV_INTERFACE_NAME: &str = "CTRL_NETWORK_INTERFACE";
const K8S_POD_IP_FOR_DEEPFLOW: &str = "K8S_POD_IP_FOR_DEEPFLOW";
const K8S_NODE_NAME_FOR_DEEPFLOW: &str = "K8S_NODE_NAME_FOR_DEEPFLOW";
pub const K8S_WATCH_POLICY: &str = "K8S_WATCH_POLICY";
const K8S_NAMESPACE_FOR_DEEPFLOW: &str = "K8S_NAMESPACE_FOR_DEEPFLOW";

// no longer used
const ONLY_WATCH_K8S_RESOURCE: &str = "ONLY_WATCH_K8S_RESOURCE";

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
        "controller ip({:?}) is not support both IPv4 and IPv6, deepflow-agent restart...",
        ips
    );

    crate::utils::notify_exit(-1);
}

pub fn trident_process_check(process_threshold: u32) {
    let process_num = get_process_num_by_name(PROCESS_NAME);

    match process_num {
        Ok(num) => {
            if num > process_threshold {
                error!(
                    "the number of process exceeds the limit({} > {}), deepflow-agent restart...",
                    num, process_threshold
                );
                crate::utils::notify_exit(-1);
            }
        }
        Err(e) => {
            warn!("{}", e);
        }
    }
}

pub fn is_tt_hyper_v_compute(agent_type: AgentType) -> bool {
    agent_type == AgentType::TtHyperVCompute
}

pub fn is_tt_hyper_v_network(agent_type: AgentType) -> bool {
    agent_type == AgentType::TtHyperVNetwork
}

pub fn is_tt_hyper_v(agent_type: AgentType) -> bool {
    agent_type == AgentType::TtHyperVCompute || agent_type == AgentType::TtHyperVNetwork
}

pub fn is_tt_pod(agent_type: AgentType) -> bool {
    agent_type == AgentType::TtHostPod
        || agent_type == AgentType::TtVmPod
        || agent_type == AgentType::TtK8sSidecar
}

pub fn is_tt_process(agent_type: AgentType) -> bool {
    agent_type == AgentType::TtProcess
}

pub fn is_tt_workload(agent_type: AgentType) -> bool {
    agent_type == AgentType::TtPublicCloud || agent_type == AgentType::TtPhysicalMachine
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
    env::var_os(IN_CONTAINER).is_some()
}

pub fn running_in_k8s() -> bool {
    // Judge whether Agent is running in k8s according to the existence of K8S_CA_CRT_PATH
    fs::metadata(K8S_CA_CRT_PATH).is_ok()
}

pub fn get_env() -> String {
    let items = vec![
        K8S_NODE_IP_FOR_DEEPFLOW,
        ENV_INTERFACE_NAME,
        K8S_POD_IP_FOR_DEEPFLOW,
        IN_CONTAINER,
        K8S_WATCH_POLICY,
        K8S_NAMESPACE_FOR_DEEPFLOW,
    ];
    items
        .into_iter()
        .map(|name| format!("{}={}", name, env::var(name).unwrap_or_default()))
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KubeWatchPolicy {
    Normal,
    WatchOnly,
    WatchDisabled,
}

thread_local! {
    // initialize once only to avoid inconsistency
    // use LazyCell instead of OnceCell after upgrading rust to 1.80 or later
    static KUBE_WATCH_POLICY: OnceCell<KubeWatchPolicy> = OnceCell::new();
}

impl KubeWatchPolicy {
    pub fn get() -> Self {
        KUBE_WATCH_POLICY.with(|p| *p.get_or_init(|| KubeWatchPolicy::from_env()))
    }

    pub fn from_env() -> Self {
        // ONLY_WATCH_K8S_RESOURCE no longer supported
        if env::var_os(ONLY_WATCH_K8S_RESOURCE).is_some() {
            error!("Environment variable ONLY_WATCH_K8S_RESOURCE is not longer supported, use K8S_WATCH_POLICY=watch-only instead!");
            thread::sleep(Duration::from_secs(60));
            crate::utils::notify_exit(-1);
            return KubeWatchPolicy::Normal;
        }

        match env::var(K8S_WATCH_POLICY) {
            Ok(policy) if policy == "watch-only" => Self::WatchOnly,
            Ok(policy) if policy == "watch-disabled" => Self::WatchDisabled,
            _ => Self::Normal,
        }
    }
}

impl From<KubeWatchPolicy> for KubernetesWatchPolicy {
    fn from(p: KubeWatchPolicy) -> Self {
        match p {
            KubeWatchPolicy::Normal => Self::KwpNormal,
            KubeWatchPolicy::WatchOnly => Self::KwpWatchOnly,
            KubeWatchPolicy::WatchDisabled => Self::KwpWatchDisabled,
        }
    }
}

impl From<KubeWatchPolicy> for OldKubernetesWatchPolicy {
    fn from(p: KubeWatchPolicy) -> Self {
        match p {
            KubeWatchPolicy::Normal => Self::KwpNormal,
            KubeWatchPolicy::WatchOnly => Self::KwpWatchOnly,
            KubeWatchPolicy::WatchDisabled => Self::KwpWatchDisabled,
        }
    }
}

pub fn running_in_only_watch_k8s_mode() -> bool {
    running_in_container() && KubeWatchPolicy::get() == KubeWatchPolicy::WatchOnly
}

pub fn get_k8s_namespace() -> String {
    env::var(K8S_NAMESPACE_FOR_DEEPFLOW).unwrap_or("deepflow".to_owned())
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

pub fn get_ctrl_ip_and_mac(dest: &IpAddr) -> Result<(IpAddr, MacAddr)> {
    // Steps to find ctrl ip and mac:
    // 1. If environment variable `ENV_INTERFACE_NAME` exists, use it as ctrl interface
    //    a) Use environment variable `K8S_POD_IP_FOR_DEEPFLOW` as ctrl ip if it exists
    //    b) If not, find addresses on the ctrl interface
    // 2. Use env.K8S_NODE_IP_FOR_DEEPFLOW as the ctrl_ip reported by deepflow-agent if available
    // 3. Find ctrl ip and mac from controller address
    if let Ok(name) = env::var(ENV_INTERFACE_NAME) {
        let Ok(link) = link_by_name(&name) else {
            return Err(Error::Environment(format!(
                "interface {} in env {} not found",
                name, ENV_INTERFACE_NAME
            )));
        };
        let ips = match env::var(K8S_POD_IP_FOR_DEEPFLOW) {
            Ok(ips) => ips
                .split(",")
                .filter_map(|s| match s.parse::<IpAddr>() {
                    Ok(ip) => Some(ip),
                    _ => {
                        warn!("ip {} in env {} invalid", s, K8S_POD_IP_FOR_DEEPFLOW);
                        None
                    }
                })
                .collect(),
            _ => match addr_list() {
                Ok(addrs) => addrs
                    .into_iter()
                    .filter_map(|addr| {
                        if addr.if_index == link.if_index {
                            Some(addr.ip_addr)
                        } else {
                            None
                        }
                    })
                    .collect(),
                _ => vec![],
            },
        };
        for ip in ips {
            if is_global(&ip) {
                return Ok((ip, link.mac_addr));
            }
        }
        return Err(Error::Environment(format!(
            "interface {} in env {} does not have valid ip address",
            name, ENV_INTERFACE_NAME
        )));
    };
    if let Some(ip) = get_k8s_local_node_ip() {
        let ctrl_mac = get_mac_by_ip(ip);
        if let Ok(mac) = ctrl_mac {
            return Ok((ip, mac));
        }
    }

    // FIXME: Getting ctrl_ip and ctrl_mac sometimes fails, increase three retry opportunities to ensure access to ctrl_ip and ctrl_mac
    'outer: for _ in 0..3 {
        let tuple = get_route_src_ip_and_mac(dest);
        if tuple.is_err() {
            warn!(
                "failed getting control ip and mac from {}, because: {:?}, wait 1 second",
                dest, tuple,
            );
            thread::sleep(Duration::from_secs(1));
            continue;
        }
        let (ip, mac) = tuple.unwrap();
        let links = link_list();
        if links.is_err() {
            warn!(
                "failed getting local interfaces, because: {:?}, wait 1 second",
                links
            );
            thread::sleep(Duration::from_secs(1));
            continue;
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
                        warn!("failed getting control ip and mac from {}, because: {:?}, wait 1 second", dest, tuple);
                        continue 'outer;
                    }
                    return Ok(tuple.unwrap());
                }
                break;
            }
        }

        return Ok((ip, mac));
    }
    Err(Error::Environment(
        "failed getting control ip and mac, deepflow-agent restart...".to_owned(),
    ))
}

//TODO Windows 相关
