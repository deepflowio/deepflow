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

#[cfg(target_os = "android")]
use std::os::android::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;

use std::{
    collections::{HashMap, HashSet},
    fmt, fs,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use log::{debug, trace};
use procfs::{
    net::TcpState,
    process::{FDTarget, Process},
    ProcError,
};

use crate::{
    config::handler::OsProcScanConfig, platform::platform_synchronizer::ProcessData,
    policy::PolicyGetter,
};

use public::{
    bytes::read_u32_be,
    netns::NsFile,
    proto::agent::{GpidSyncEntry, RoleType, ServiceProtocol},
};

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum Role {
    Client,
    Server,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(super) struct SockAddrData {
    pub(super) epc_id: u32,
    pub(super) ip: IpAddr,
    pub(super) port: u16,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(super) struct SockEntry {
    pub(super) pid: u32,
    pub(super) proto: Protocol,
    // the local addr is server or client
    pub(super) role: Role,
    pub(super) local: SockAddrData,
    pub(super) remote: SockAddrData,
    pub(super) real_client: Option<SockAddrData>,
    // netns idx is the unique number of netns, not equal to netns inode.
    pub(super) netns_idx: u16,
    pub(super) netns: NsFile,
}

impl fmt::Display for SockEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (c, s) = match self.role {
            Role::Client => (&self.local, &self.remote),
            Role::Server => (&self.remote, &self.local),
        };
        write!(
            f,
            "{:?} {}:{} -> {}:{} in {}, pid: {}",
            self.proto, c.ip, c.port, s.ip, s.port, self.netns, self.pid
        )
    }
}

impl TryFrom<SockEntry> for GpidSyncEntry {
    type Error = ProcError;

    fn try_from(s: SockEntry) -> Result<Self, Self::Error> {
        let (local_ip, remote_ip) = match (s.local.ip, s.remote.ip) {
            (IpAddr::V4(v4_local), IpAddr::V4(v4_remote)) => (
                Some(read_u32_be(&v4_local.octets())),
                Some(read_u32_be(&v4_remote.octets())),
            ),
            _ => {
                return Err(ProcError::Other(
                    "unreachable: not support ipv6".to_string(),
                ))
            }
        };

        let (epc_0, pid_0, ip_0, port_0, epc_1, pid_1, ip_1, port_1) = match s.role {
            // when role is client, local addr is client side and remote is server side
            Role::Client => (
                // TODO set epc_id
                None,
                Some(s.pid),
                local_ip,
                Some(s.local.port as u32),
                // TODO set epc_id
                None,
                None,
                remote_ip,
                Some(s.remote.port as u32),
            ),
            // when role is server, local is server side and remote is client side
            Role::Server => (
                // TODO set epc_id
                None,
                None,
                remote_ip,
                Some(s.remote.port as u32),
                // TODO set epc_id
                None,
                Some(s.pid),
                local_ip,
                Some(s.local.port as u32),
            ),
        };

        let mut r = Self {
            protocol: Some(match s.proto {
                Protocol::Tcp => ServiceProtocol::TcpService.into(),
                Protocol::Udp => ServiceProtocol::UdpService.into(),
            }),
            epc_id_1: epc_1,
            ipv4_1: ip_1,
            port_1: port_1,
            pid_1: pid_1,
            epc_id_0: epc_0,
            ipv4_0: ip_0,
            port_0: port_0,
            pid_0: pid_0,
            netns_idx: Some(s.netns_idx as u32),
            ..Default::default()
        };

        if let Some(real) = s.real_client {
            r.role_real = Some(RoleType::RoleClient.into());
            r.epc_id_real = Some(real.epc_id);
            r.ipv4_real = Some(match real.ip {
                IpAddr::V4(v4) => read_u32_be(&v4.octets()),
                _ => {
                    return Err(ProcError::Other(
                        "unreachable: not support ipv6".to_string(),
                    ))
                }
            });
            r.port_real = Some(real.port as u32);
        }

        Ok(r)
    }
}

/*
    divide all socket info to server or client side

    for tcp (on the same netns):

        if listening socket local addr is [0u8;4] or [0u8;16], assume the socket listening in all interface,
        the local addr with correspond port will assume as the server, for example

            Proto Recv-Q Send-Q Local Address          Foreign Address         State
            tcp        0      0 :::19181               0.0.0.0:*               LISTEN
            tcp        0      0 192.168.1.2:19181      1.2.3.4:45798           ESTABLISHED

            the established socket local addr with port 19181(in this case is 192.168.1.2:19181) will assume as server and local addr,
            foreign addr(in this case is 1.2.3.4:45798) will assume remote addr


        if listening socket local addr is not [0u8;4] or [0u8;16], assume the socket listenning in specific addr,
        the local addr with correspond addr and port will assue as server, for example

            Proto Recv-Q Send-Q Local Address           Foreign Address         State
            tcp        0      0 172.17.0.1:19181        0.0.0.0:*              LISTEN
            tcp        0      0 172.17.0.1:19181        172.17.0.2:12345       ESTABLISHED

            the established socket local addr with 172.17.0.1:19181  will assume as server and local addr,
            foreign addr(in this case is 172.17.0.2:12345) will assume as remote addr

        otherwise will assume local addr as client and local addr, foreign addr as remote addr .

    for udp (on the same netns):

        when when udp create use socket bind in `0.0.0.0` or `::` or specific address, the socket info like follow:

            Proto Recv-Q Send-Q Local Address           Foreign Address
            udp        0      0 10.34.0.206:999         0.0.0.0:*
            udp        0      0 0.0.0.0:9999            0.0.0.0:*

        it have no idea to determine is cliet or server. in those case will ignore

        when udp create use socket connect, the socket info like follow:

            Proto Recv-Q Send-Q Local Address           Foreign Address
            udp        0      0 10.34.0.206:68          10.34.0.1:67

        the local addr assume as client and local addr, foreign addr assume as remote addr

    note that the /proc/pid/net/{tcp,tcp6,udp,udp6} consist of all the connection in the proc netns, not the process connection.
*/
pub(super) fn get_all_socket(
    conf: &OsProcScanConfig,
    policy_getter: &mut PolicyGetter,
    epc_id: u32,
    pids: Vec<u32>,
) -> Result<Vec<SockEntry>, ProcError> {
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // find fd in processes and their net namespaces
    let mut socket_inode_to_pid = HashMap::new();
    let mut namespace_to_pids = HashMap::new();

    trace!("processes to find sockets: {pids:?}");
    for pid in pids {
        let process = match Process::new(pid as i32) {
            Ok(p) => p,
            Err(e) => {
                debug!("get process #{pid} failed: {e}");
                continue;
            }
        };
        let Ok(p_data) = ProcessData::try_from(&process) else {
            continue;
        };

        match p_data.up_sec(epoch) {
            Ok(up_sec) if up_sec >= u64::from(conf.os_proc_socket_min_lifetime) => (),
            _ => {
                debug!(
                    "process #{pid} ignored because up_sec is invalid or less than {}s",
                    conf.os_proc_socket_min_lifetime
                );
                continue;
            }
        }

        let netns = NsFile::from_pid_with_root(&conf.os_proc_root, pid).unwrap_or_default();
        let fds = match process.fd() {
            Ok(fds) => fds,
            Err(e) => {
                debug!("get process #{pid} fd failed: {e}");
                continue;
            }
        };

        let mut interested = false;
        for fd in fds {
            let Ok(fd) = fd else {
                continue;
            };
            if let FDTarget::Socket(inode) = fd.target {
                match get_fd_ctime(&conf.os_proc_root, pid, fd.fd) {
                    Ok(ctime) if ctime >= conf.os_proc_socket_min_lifetime as u64 => {
                        interested = true;
                        socket_inode_to_pid.insert(inode, pid);
                    }
                    _ => {
                        debug!(
                            "process #{pid} fd #{} ignored because ctime invalid or less than {}",
                            fd.fd, conf.os_proc_socket_min_lifetime
                        );
                        continue;
                    }
                }
            }
        }
        if interested {
            namespace_to_pids.entry(netns).or_insert(vec![]).push(pid);
        }
    }

    // find sockets by net namespaces instead of processes because /proc/pid/net/{tcp,tcp6,udp,udp6} is the same for all processes in the same net namespace
    // but we still need to use pid to access net namespaces
    trace!("net namespaces to find sockets: {namespace_to_pids:?}");
    let mut sockets = vec![];

    'outer: for (index, (ns, pids)) in namespace_to_pids.iter_mut().enumerate() {
        pids.sort_unstable();
        for pid in pids.iter() {
            trace!("visiting netns {ns} from pid {pid}");

            let process = match Process::new(*pid as i32) {
                Ok(p) => p,
                Err(e) => {
                    debug!("get process #{pid} failed: {e}");
                    continue;
                }
            };
            let mut tcp = match process.tcp() {
                Ok(tcp) => tcp,
                Err(e) => {
                    debug!("get netns {ns} tcp from process #{pid} failed: {e}");
                    continue;
                }
            };
            match process.tcp6() {
                Ok(mut tcp6) => tcp.append(&mut tcp6),
                Err(e) => {
                    debug!("get netns {ns} tcp6 from process #{pid} failed: {e}");
                    continue;
                }
            };
            let udp = match process.udp() {
                Ok(udp) => udp,
                Err(e) => {
                    debug!("get netns {ns} udp from process #{pid} failed: {e}");
                    continue;
                }
            };
            let udp6 = match process.udp6() {
                Ok(udp6) => udp6,
                Err(e) => {
                    debug!("get netns {ns} udp6 from process #{pid} failed: {e}");
                    continue;
                }
            };

            // tcp sockets that listen on 0.0.0.0
            let mut listen_any: HashSet<u16> = HashSet::new();
            // tcp sockets that listen on specific address
            let mut listen_spec: HashSet<SocketAddr> = HashSet::new();
            tcp.retain(|t| match t.state {
                TcpState::Listen => {
                    trace!("netns {ns} tcp listen on {}", t.local_address);
                    if t.local_address.ip().is_unspecified() {
                        trace!(
                            "netns {ns} tcp listen on 0.0.0.0:{}",
                            t.local_address.port()
                        );
                        listen_any.insert(t.local_address.port());
                    } else {
                        let addr = t.local_address.ip().to_canonical();
                        if addr.is_ipv4() {
                            listen_spec.insert((addr, t.local_address.port()).into());
                        }
                    }
                    false
                }
                TcpState::Established => true,
                _ => false,
            });
            trace!("netns {ns} tcp listen on any: {listen_any:?}, listen on spec: {listen_spec:?}");
            for mut tcp in tcp.into_iter() {
                assert_eq!(tcp.state, TcpState::Established);

                let pid = match socket_inode_to_pid.get(&tcp.inode) {
                    Some(pid) => *pid,
                    None => {
                        debug!("netns {ns} tcp entry {tcp:?} ignored because inode not found or too recent");
                        continue;
                    }
                };

                let local_addr = &mut tcp.local_address;
                let remote_addr = &mut tcp.remote_address;
                local_addr.set_ip(local_addr.ip().to_canonical());
                remote_addr.set_ip(remote_addr.ip().to_canonical());
                if !(local_addr.is_ipv4() && remote_addr.is_ipv4()) {
                    debug!("netns {ns} tcp entry {tcp:?} ignored because not ipv4");
                    continue;
                }

                sockets.push(SockEntry {
                    pid,
                    proto: Protocol::Tcp,
                    role: if listen_any.contains(&local_addr.port())
                        || listen_spec.contains(&local_addr)
                    {
                        Role::Server
                    } else {
                        Role::Client
                    },
                    local: SockAddrData {
                        epc_id: epc_id,
                        ip: local_addr.ip(),
                        port: local_addr.port(),
                    },
                    remote: SockAddrData {
                        epc_id: convert_i32_epc_id(policy_getter.lookup_epc_by_epc(
                            local_addr.ip(),
                            remote_addr.ip(),
                            epc_id as i32,
                        )),
                        ip: remote_addr.ip(),
                        port: remote_addr.port(),
                    },
                    real_client: None,
                    netns_idx: index as u16,
                    netns: ns.clone(),
                })
            }

            for mut udp in udp.into_iter().chain(udp6.into_iter()) {
                let pid = match socket_inode_to_pid.get(&udp.inode) {
                    Some(pid) => *pid,
                    None => {
                        debug!("netns {ns} udp entry {udp:?} ignored because inode not found or too recent");
                        continue;
                    }
                };

                if udp.remote_address.ip().is_unspecified() {
                    // foreign addr is zero, indicate the udp socker create use bind(), no idea to determine the local and remote, ignore
                    continue;
                }

                let local_addr = &mut udp.local_address;
                let remote_addr = &mut udp.remote_address;
                local_addr.set_ip(local_addr.ip().to_canonical());
                remote_addr.set_ip(remote_addr.ip().to_canonical());
                if !(local_addr.is_ipv4() && remote_addr.is_ipv4()) {
                    debug!("netns {ns} udp entry {udp:?} ignored because not ipv4");
                    continue;
                }

                sockets.push(SockEntry {
                    pid,
                    proto: Protocol::Udp,
                    role: Role::Client,
                    local: SockAddrData {
                        epc_id: epc_id,
                        ip: local_addr.ip(),
                        port: local_addr.port(),
                    },
                    remote: SockAddrData {
                        epc_id: convert_i32_epc_id(policy_getter.lookup_epc_by_epc(
                            local_addr.ip(),
                            remote_addr.ip(),
                            epc_id as i32,
                        )),
                        ip: remote_addr.ip(),
                        port: remote_addr.port(),
                    },
                    real_client: None,
                    netns_idx: index as u16,
                    netns: ns.clone(),
                })
            }

            continue 'outer;
        }

        debug!("unabled to find sockets in netns {ns}");
    }

    Ok(sockets)
}

fn convert_i32_epc_id(epc_id: i32) -> u32 {
    if epc_id >= -65535 && epc_id < 0 {
        epc_id as u16 as u32
    } else {
        epc_id as u32
    }
}

fn get_fd_ctime(proc_root: &str, pid: u32, fd: i32) -> Result<u64, std::io::Error> {
    let path: PathBuf = [proc_root, &pid.to_string(), "fd", &fd.to_string()]
        .iter()
        .collect();
    Ok(fs::symlink_metadata(path)?.st_ctime() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{config::handler::OsProcScanConfig, policy::Policy};

    #[test]
    fn get_all_sockets() {
        let conf = OsProcScanConfig {
            os_proc_root: "/proc".to_string(),
            os_proc_socket_sync_interval: 1,
            os_proc_socket_min_lifetime: 3,
            os_app_tag_exec_user: "".to_string(),
            os_app_tag_exec: vec![],
            os_proc_sync_enabled: true,
        };
        let (_, mut getter) = Policy::new(1, 0, 1 << 10, 1 << 14, false, false);
        let pids = procfs::process::all_processes()
            .unwrap()
            .into_iter()
            .map(|p| p.unwrap().pid() as u32)
            .collect::<Vec<_>>();
        let sockets = get_all_socket(&conf, &mut getter, 1, pids);
        for s in sockets.unwrap().iter() {
            println!("{s}");
        }
    }
}
