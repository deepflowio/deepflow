use std::{env, net::IpAddr, path::Path, process::exit, thread, time::Duration};

use bytesize::ByteSize;
use log::{error, warn};
use sysinfo::{DiskExt, System, SystemExt};

use crate::common::TRIDENT_PROCESS_LIMIT;
use crate::error::{Error, Result};
use crate::exception::ExceptionHandler;
use crate::proto::{common::TridentType, trident::Exception};

use super::net::get_link_enabled_features;
use super::process::{get_memory_rss, get_process_num_by_name};

pub type Checker = Box<dyn Fn() -> Result<()>>;

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

pub fn tap_interface_check(tap_interfaces: &[String]) {
    if cfg!(target_os = "windows") {
        return;
    }

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

            if still_need <= system.available_memory() * 1024 {
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
    exit(-1);
}

pub fn trident_process_check() {
    let process_num = if cfg!(target_os = "windows") {
        get_process_num_by_name("metaflow-agent.exe")
    } else {
        let base_name = Path::new(&env::args().next().unwrap())
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        get_process_num_by_name(&base_name)
    };

    match process_num {
        Ok(num) => {
            if num > TRIDENT_PROCESS_LIMIT {
                error!(
                    "the number of process exceeds the limit({} > {})",
                    num, TRIDENT_PROCESS_LIMIT
                );
                thread::sleep(Duration::from_secs(1));
                exit(-1);
            }
        }
        Err(e) => {
            warn!("{}", e);
        }
    }
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

//TODO Windows 相关
