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
    collections::{HashMap, HashSet},
    ffi::OsString,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use log::error;
use procfs::{
    net::{TcpNetEntry, TcpState, UdpNetEntry},
    process::{FDTarget, Process},
    ProcError,
};

use crate::{config::handler::OsProcScanConfig, policy::PolicyGetter};
use public::{
    bytes::read_u32_be,
    proto::trident::{GpidSyncEntry, ServiceProtocol},
};

use super::{sym_uptime, ProcessData};

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
pub struct SockAddrData {
    epc_id: u32,
    ip: IpAddr,
    port: u16,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct SockEntry {
    pid: u32,
    proto: Protocol,
    // the local addr is server or client
    role: Role,
    local: SockAddrData,
    remote: SockAddrData,
    real_client: Option<SockAddrData>,
}

impl TryFrom<SockEntry> for GpidSyncEntry {
    type Error = ProcError;

    fn try_from(s: SockEntry) -> Result<Self, Self::Error> {
        let (pid0, pid1) = match s.role {
            Role::Client => (Some(s.pid), None),
            Role::Server => (None, Some(s.pid)),
        };

        let (ip0, ip1) = match (s.local.ip, s.remote.ip) {
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

        Ok(Self {
            protocol: Some(match s.proto {
                Protocol::Tcp => ServiceProtocol::TcpService as i32,
                Protocol::Udp => ServiceProtocol::UdpService as i32,
            }),
            epc_id_1: Some(s.remote.epc_id),
            ipv4_1: ip1,
            port_1: Some(s.remote.port as u32),
            pid_1: pid1,
            epc_id_0: Some(s.local.epc_id),
            ipv4_0: ip0,
            port_0: Some(s.local.port as u32),
            pid_0: pid0,
            // FIXME fill the real sock info
            ..Default::default()
        })
    }
}

// return server local addr, client remote addr
pub(super) fn get_all_socket(
    conf: &OsProcScanConfig,
    policy_getter: &mut PolicyGetter,
    epc_id: u32,
) -> Result<Vec<SockEntry>, ProcError> {
    // Hashmap<inode, (pid,fd)>
    let mut inode_pid_fd_map = HashMap::new();

    // all netns, use for skip the netns which info had been fetched
    let mut netns_set = HashSet::new();

    // HashSet<(port, proto, NetnsInode)>, the listenning port when socket listening in `0.0.0.0` or `::`
    let mut all_iface_listen_sock = HashSet::new();
    // HashSet<(SocketAddr)>, the listenning addr when socket listening specific addr
    let mut spec_addr_listen_sock = HashSet::new();

    let (proc_root, min_sock_lifetime, now_sec, mut tcp_entries, mut udp_entries, mut sock_entries) = (
        conf.os_proc_root.as_str(),
        conf.os_proc_socket_min_lifetime as u64,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        vec![],
        vec![],
        vec![],
    );

    // get all process, and record the open fd and fetch listining socket info
    // note that the /proc/pid/net/{tcp,tcp6,udp,udp6} include all the connection in the proc netns, not the process created connection.
    for p in procfs::process::all_processes_with_root(proc_root)? {
        let Ok(proc) = p else {
            continue;
        };

        let (fds, netns, mut proc_data, pid) = match (
            proc.fd(),
            get_proc_netns(&proc),
            ProcessData::try_from(&proc),
        ) {
            (Ok(fds), Ok(netns), Ok(proc_data)) => (fds, netns, proc_data, proc.pid),
            _ => {
                error!("pid {} get process info fail", proc.pid);
                continue;
            }
        };

        let Ok(up_sec) =  proc_data.up_sec(now_sec) else {
            continue;
        };

        // filter the short live proc
        if up_sec < u64::from(conf.os_proc_socket_min_lifetime) {
            continue;
        }

        for i in conf.os_proc_regex.as_slice() {
            if i.match_and_rewrite_proc(&mut proc_data, true) {
                // when match proc, will record the inode and (pid, fd) map, use for get the connection pid and fd in later.
                for fd in fds {
                    let Ok(f) = fd else {
                        continue;
                    };
                    if let FDTarget::Socket(fd_inode) = f.target {
                        inode_pid_fd_map.insert(fd_inode, (pid, f.fd));
                    }
                }

                // break if the netns had been fetched
                if !netns_set.insert(netns) {
                    break;
                }

                // also recoed the listining socket info, use for determine client or server connection.
                // note that proc.{tcp(), tcp6(), udp(), udp6()} include all connection in the proc netns
                if let Err(err) = record_tcp_listening_ip_port(
                    &proc,
                    Some(netns),
                    &mut all_iface_listen_sock,
                    &mut spec_addr_listen_sock,
                ) {
                    error!("pid {} record_tcp_listening_ip_port fail: {}", pid, err);
                    break;
                }

                // record the tcp and udp connection in current netns
                // only support ipv4 now
                match (proc.tcp(), proc.udp()) {
                    (Ok(tcp), Ok(udp)) => {
                        tcp_entries.push((tcp, netns));
                        udp_entries.push(udp);
                    }
                    _ => error!("pid {} get connection info fail", pid),
                }
                break;
            }
        }
    }

    divide_tcp_entry(
        epc_id,
        proc_root,
        policy_getter,
        min_sock_lifetime,
        &all_iface_listen_sock,
        &spec_addr_listen_sock,
        &inode_pid_fd_map,
        tcp_entries,
        &mut sock_entries,
    );
    divide_udp_entry(
        epc_id,
        proc_root,
        policy_getter,
        min_sock_lifetime,
        &inode_pid_fd_map,
        udp_entries,
        &mut sock_entries,
    );

    Ok(sock_entries)
}

fn is_zero_addr(addr: &SocketAddr) -> bool {
    match addr {
        SocketAddr::V4(v4) => v4.ip() == &Ipv4Addr::UNSPECIFIED,
        SocketAddr::V6(v6) => v6.ip() == &Ipv6Addr::UNSPECIFIED,
    }
}

fn get_proc_netns(proc: &Process) -> Result<u64, ProcError> {
    if let Some(netns) = proc.namespaces()?.get(&OsString::from("net")) {
        Ok(netns.identifier)
    } else {
        Err(ProcError::Other(format!(
            "pid {} get net ns fail",
            proc.pid
        )))
    }
}

/*
    record the listenning sock from proc netns

    note that the Process.tcp() and Process.udp() correspond the /proc/pid/net/{tcp, udp}, it include all the connection info
    in the proc netns, not only the connection which the proc create.

    param:

        all_iface_listen_sock: HashSet<(port, proto, NetnsInode)>

        spec_addr_listen_sock: HashSet<(SocketAddr)>,
*/
fn record_tcp_listening_ip_port(
    proc: &Process,
    netns: Option<u64>,
    all_iface_listen_sock: &mut HashSet<(u16, Protocol, u64)>,
    spec_addr_listen_sock: &mut HashSet<SocketAddr>,
) -> Result<(), ProcError> {
    let netns = netns.unwrap_or(get_proc_netns(&proc)?);

    let mut handle_entry = |enties: Vec<TcpNetEntry>| {
        for t in enties {
            if t.state == TcpState::Listen {
                // when listening in zero addr, indicate listen in all interface
                if is_zero_addr(&t.local_address) {
                    all_iface_listen_sock.insert((t.local_address.port(), Protocol::Tcp, netns));
                } else {
                    spec_addr_listen_sock.insert(t.local_address);
                }
            } else {
                // the listen socket info in /proc/pid/net/tcp always in the top
                break;
            }
        }
    };

    if let Ok(tcp) = proc.tcp() {
        handle_entry(tcp);
    }
    if let Ok(tcp) = proc.tcp6() {
        handle_entry(tcp);
    }

    Ok(())
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
fn divide_tcp_entry(
    local_epc_id: u32,
    proc_root: &str,
    policy_getter: &mut PolicyGetter,
    // sock min up time, use for filter short connection
    sock_min_lifetime_sec: u64,
    // HashSet<(port, proto, NetnsInode)>
    all_iface_listen_sock: &HashSet<(u16, Protocol, u64)>,
    // HashSet<(SocketAddr)>
    spec_addr_listen_sock: &HashSet<SocketAddr>,
    // Hashmap<inode, (pid,fd)>
    inode_pid_fd_map: &HashMap<u64, (i32, i32)>,
    // Vec< Vec<tcp_entrys>, netns >
    tcp_entry: Vec<(Vec<TcpNetEntry>, u64)>,
    sock_entries: &mut Vec<SockEntry>,
) {
    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    for (tcp_entries, netns) in tcp_entry {
        for t in tcp_entries {
            if t.state != TcpState::Established {
                continue;
            }

            let Some((pid,fd)) = inode_pid_fd_map.get(&t.inode) else {
                continue;
            };

            /*
                note that symbol ctime of {proc_root}/{pid}/fd/{fd} is the first time access the file,
                not the time that the connection create. unless os_proc_socket_min_lifetime config to 0,
                the new connection at lease the second times scan can be recognized.
            */
            let Ok(sock_up_sec) = sym_uptime(now_sec, &PathBuf::from_iter([proc_root.to_string(), pid.to_string(), "fd".to_string(), fd.to_string()])) else {
                continue;
            };
            if sock_up_sec < sock_min_lifetime_sec {
                continue;
            }

            sock_entries.push(SockEntry {
                pid: *pid as u32,
                proto: Protocol::Tcp,
                role: if all_iface_listen_sock.contains(&(
                    t.local_address.port(),
                    Protocol::Tcp,
                    netns,
                )) || spec_addr_listen_sock.contains(&t.local_address)
                {
                    // sport in all_iface_listen_sock or SocketAddr in spec_addr_listen_sock, assume is serve connection
                    Role::Server
                } else {
                    Role::Client
                },

                local: SockAddrData {
                    epc_id: local_epc_id,
                    ip: t.local_address.ip(),
                    port: t.local_address.port(),
                },
                remote: SockAddrData {
                    epc_id: convert_i32_epc_id(
                        policy_getter
                            .lookup_all_by_epc(
                                t.local_address.ip(),
                                t.remote_address.ip(),
                                local_epc_id as i32,
                                0,
                            )
                            .dst_info
                            .l3_epc_id,
                    ),
                    ip: t.remote_address.ip(),
                    port: t.remote_address.port(),
                },
                // FIXME get real client from toa
                real_client: None,
            });
        }
    }
}

fn divide_udp_entry(
    local_epc_id: u32,
    proc_root: &str,
    policy_getter: &mut PolicyGetter,
    // sock min up time, use for filter short connection
    sock_min_lifetime_sec: u64,
    // Hashmap<inode, (pid,fd)>
    inode_pid_fd_map: &HashMap<u64, (i32, i32)>,
    udp_entry: Vec<Vec<UdpNetEntry>>,
    sock_entries: &mut Vec<SockEntry>,
) {
    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for udp_entries in udp_entry {
        for u in udp_entries {
            let Some((pid, fd)) = inode_pid_fd_map.get(&u.inode) else {
                continue;
            };

            /*
                note that symbol ctime of {proc_root}/{pid}/fd/{fd} is the first time access the file,
                not the time that the connection create. unless os_proc_socket_min_lifetime config to 0,
                the new connection at lease the second times scan can be recognized.
            */

            let Ok(sock_up_sec) = sym_uptime(now_sec, &PathBuf::from_iter([proc_root.to_string(), pid.to_string(), "fd".to_string(), fd.to_string()])) else {
                    continue;
                };
            if sock_up_sec < sock_min_lifetime_sec {
                continue;
            }

            if is_zero_addr(&u.remote_address) {
                // foreign addr is zero, indicate the udp socker create use bind(), no idea to determine the local and remote, ignore
                continue;
            } else {
                // foreign addr is not zero, indicate the udp socker create use connect()
                sock_entries.push(SockEntry {
                    pid: *pid as u32,
                    proto: Protocol::Udp,
                    role: Role::Client,
                    local: SockAddrData {
                        epc_id: local_epc_id,
                        ip: u.local_address.ip(),
                        port: u.local_address.port(),
                    },
                    remote: SockAddrData {
                        epc_id: convert_i32_epc_id(
                            policy_getter
                                .lookup_all_by_epc(
                                    u.local_address.ip(),
                                    u.remote_address.ip(),
                                    local_epc_id as i32,
                                    0,
                                )
                                .dst_info
                                .l3_epc_id,
                        ),
                        ip: u.remote_address.ip(),
                        port: u.remote_address.port(),
                    },
                    // FIXME get real client from toa
                    real_client: None,
                });
            }
        }
    }
}

fn convert_i32_epc_id(epc_id: i32) -> u32 {
    if epc_id >= -65535 && epc_id < 0 {
        epc_id as u16 as u32
    } else {
        epc_id as u32
    }
}
