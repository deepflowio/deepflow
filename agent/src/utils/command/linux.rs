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

use std::{
    fs::{self, File},
    io::{Error, ErrorKind, Result},
    os::unix::io::AsRawFd,
    path::Path,
};

use nix::sched::{setns, CloneFlags};

use super::exec_command;

const OVS_INTERFACE_COLUMNS_OPTION: &str = "--columns=_uuid,external_ids,ifindex,mac,mac_in_use,name,ofport,options,other_config,status,type";
const NEUTRON_OPENVSWITCH_AGENT: &str = "/usr/lib/systemd/system/neutron-openvswitch-agent.service";

pub fn get_vm_states() -> Result<String> {
    exec_command("virsh", &["list", "--all"])
}

pub fn get_ovs_interfaces() -> Result<String> {
    exec_command(
        "ovs-vsctl",
        &[
            "-f",
            "csv",
            "-d",
            "bare",
            OVS_INTERFACE_COLUMNS_OPTION,
            "list",
            "interface",
        ],
    )
}

pub fn get_ovs_bridges() -> Result<String> {
    exec_command("ovs-vsctl", &["-f", "csv", "-d", "bare", "list", "bridge"])
}

pub fn get_ovs_ports() -> Result<String> {
    exec_command("ovs-vsctl", &["-f", "csv", "-d", "bare", "list", "port"])
}

pub fn get_brctl_show() -> Result<String> {
    exec_command("brctl", &["show"])
}

pub fn get_vlan_config() -> Result<String> {
    exec_command("cat", &["/proc/net/vlan/config"])
}

pub fn get_ip_address() -> Result<String> {
    exec_command("ip", &["address", "show"])
}

pub fn get_ip_link() -> Result<String> {
    exec_command("ip", &["link", "show"])
}

pub fn get_iptables_acls() -> Result<String> {
    exec_command("iptables", &["-w", "1", "-vnL", "--line-numbers", "-x"])
}

pub fn get_ovs_version() -> Result<String> {
    exec_command("ovs-vswitchd", &["--version"])
}

pub fn get_ovs_bridge_flow(name: &str) -> Result<String> {
    exec_command("ovs_ofctl", &["dump-flows", name])
}

pub fn get_ipset_list() -> Result<String> {
    exec_command("ipset", &["list"])
}

pub fn get_bridge_mapping() -> Result<String> {
    let content = fs::read_to_string(NEUTRON_OPENVSWITCH_AGENT)?;

    // 找neutron-openvswitch-agent使用的配置文件
    let mut config_paths = vec![];
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("ExecStart=") {
            let items = line.split(' ').collect::<Vec<_>>();
            for (i, &item) in items.iter().enumerate() {
                if item == "--config-file" && i + 1 < items.len() {
                    config_paths.push(items[i + 1]);
                }
            }
        }
    }
    if config_paths.is_empty() {
        config_paths = vec![
            "/etc/neutron/plugins/ml2/openvswitch_agent.ini",
            "/etc/neutron/plugins/ml2/ml2_conf.ini",
            "/etc/neutron/plugin.ini",
        ];
    }

    // 从配置文件找bridge_mappings
    // 一般来说只应该有一处配置；如果有多个，全部返回
    let mut bridge_mappings = "".to_string();
    for config_path in config_paths {
        let content = fs::read_to_string(config_path);
        if content.is_err() {
            continue;
        }
        let content = content.unwrap();

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("bridge_mappings") {
                bridge_mappings.push_str(line);
                bridge_mappings.push('\n');
            }
        }
    }
    if bridge_mappings.is_empty() {
        return Err(Error::new(
            ErrorKind::Other,
            "bridge_mappings not found".to_string(),
        ));
    }

    Ok(bridge_mappings)
}

pub fn get_all_vm_xml<P: AsRef<Path>>(xml_path: P) -> Result<String> {
    if !xml_path.as_ref().is_dir() {
        return Err(Error::new(
            ErrorKind::Other,
            format!("xml_path is not directory: {}", xml_path.as_ref().display()),
        ));
    }
    let mut files = vec![];
    for entry in fs::read_dir(xml_path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            continue;
        }

        if let Some(ext) = path.extension() {
            if ext == "xml" {
                files.push(path);
            }
        }
    }

    let mut result = "".to_string();
    for file in files {
        let content = fs::read_to_string(file)?;
        result.push_str(content.as_str());
    }

    result = format!("<domains>\n{}</domains>\n", result);
    Ok(result)
}

const ROOT_UTS_PATH: &'static str = "/proc/1/ns/uts";
const ORIGIN_UTS_PATH: &'static str = "/proc/self/ns/uts";

fn set_utsns(fp: &File) -> Result<()> {
    setns(fp.as_raw_fd(), CloneFlags::CLONE_NEWUTS).map_err(|e| Error::new(ErrorKind::Other, e))
}

pub fn get_hostname() -> Result<String> {
    let origin_fp = File::open(Path::new(ORIGIN_UTS_PATH))?;
    let root_fp = File::open(Path::new(ROOT_UTS_PATH))?;
    if let Err(e) = set_utsns(&root_fp) {
        return Err(Error::new(ErrorKind::Other, e));
    }
    let name = hostname::get()?
        .into_string()
        .map_err(|_| Error::new(ErrorKind::Other, "get hostname failed"));
    if let Err(e) = set_utsns(&origin_fp) {
        return Err(Error::new(ErrorKind::Other, e));
    }
    name
}
