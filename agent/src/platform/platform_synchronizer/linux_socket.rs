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
    collections::{HashMap, HashSet},
    ffi::OsString,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use log::{error, warn};
use procfs::{
    net::{TcpNetEntry, TcpState, UdpNetEntry},
    process::{FDTarget, Process},
    ProcError,
};

use crate::{config::handler::OsProcScanConfig, policy::PolicyGetter};
use public::{
    bytes::read_u32_be,
    proto::trident::{GpidSyncEntry, RoleType, ServiceProtocol},
};

use super::{get_all_pid_process_map, get_os_app_tag_by_exec, sym_uptime, RegExpAction};

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

// return server local addr, client remote addr
pub(super) fn get_all_socket(
    conf: &OsProcScanConfig,
    policy_getter: &mut PolicyGetter,
    epc_id: u32,
) -> Result<Vec<SockEntry>, ProcError> {
    // Hashmap<inode, (pid,fd)>
    let mut inode_pid_fd_map = HashMap::new();

    // Hashmap<netns_id, netns_idx>, use for map the netns id to u16 and skip the netns which info had been fetched
    let mut netns_id_idx_map = HashMap::new();

    // HashSet<(port, proto, NetnsInode)>, the listenning port when socket listening in `0.0.0.0` or `::`
    let mut all_iface_listen_sock = HashSet::new();
    // HashSet<(SocketAddr)>, the listenning addr when socket listening specific addr
    let mut spec_addr_listen_sock = HashSet::new();

    let (
        user,
        cmd,
        tagged_only,
        proc_root,
        min_sock_lifetime,
        now_sec,
        mut tcp_entries,
        mut udp_entries,
        mut sock_entries,
    ) = (
        conf.os_app_tag_exec_user.as_str(),
        conf.os_app_tag_exec.as_slice(),
        conf.os_proc_sync_tagged_only,
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

    let tags_map = match get_os_app_tag_by_exec(user, cmd) {
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

    // netns idx increase every time get the new netns id
    let mut netns_idx = 0u16;

    let mut pid_proc_map = get_all_pid_process_map(conf.os_proc_root.as_str());

    // get all process, and record the open fd and fetch listining socket info
    // note that the /proc/pid/net/{tcp,tcp6,udp,udp6} include all the connection in the proc netns, not the process created connection.
    for p in procfs::process::all_processes_with_root(proc_root)? {
        let Ok(proc) = p else {
            continue;
        };

        let mut proc_data = {
            let Some(proc_data) = pid_proc_map.get_mut(&(proc.pid as u32)) else {
                continue;
            };
            proc_data.clone()
        };

        let (fds, netns, pid) = match (proc.fd(), get_proc_netns(&proc)) {
            (Ok(fds), Ok(netns)) => (fds, netns, proc.pid),
            _ => {
                continue;
            }
        };

        let Ok(up_sec) = proc_data.up_sec(now_sec) else {
            continue;
        };

        // filter the short live proc
        if up_sec < u64::from(conf.os_proc_socket_min_lifetime) {
            continue;
        }

        for i in conf.os_proc_regex.as_slice() {
            if i.match_and_rewrite_proc(&mut proc_data, &pid_proc_map, &tags_map, true) {
                if i.action() == RegExpAction::Drop {
                    break;
                }

                if tags_map.get(&(proc.pid as u64)).is_none() && tagged_only {
                    break;
                }

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
                if netns_id_idx_map.contains_key(&netns) {
                    break;
                };

                netns_id_idx_map.insert(netns, {
                    if netns_idx == u16::MAX {
                        warn!("netns_idx reach u16::Max, set to 0");
                        0
                    } else {
                        netns_idx += 1;
                        netns_idx
                    }
                });

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
                // only support ipv4 now, ipv6 dual stack will extra ipv4 addr
                match (proc.tcp(), proc.udp()) {
                    (Ok(tcp), Ok(udp)) => {
                        tcp_entries.push((tcp, netns));
                        udp_entries.push((udp, netns));
                    }
                    _ => error!("pid {} get connection info fail", pid),
                }

                // old kernel have no tcp6/udp6
                match (proc.tcp6(), proc.udp6()) {
                    (Ok(tcp6), Ok(udp6)) => {
                        tcp_entries.push((tcp6, netns));
                        udp_entries.push((udp6, netns));
                    }
                    _ => {}
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
        &netns_id_idx_map,
        tcp_entries,
        &mut sock_entries,
    );
    divide_udp_entry(
        epc_id,
        proc_root,
        policy_getter,
        min_sock_lifetime,
        &inode_pid_fd_map,
        &netns_id_idx_map,
        udp_entries,
        &mut sock_entries,
    );

    Ok(sock_entries)
}

fn is_zero_addr(addr: &SocketAddr) -> bool {
    addr.ip().is_unspecified()
}

pub(super) fn get_proc_netns(proc: &Process) -> Result<u64, ProcError> {
    // works with linux 3.0+ kernel only
    // refer to this [commit](https://github.com/torvalds/linux/commit/6b4e306aa3dc94a0545eb9279475b1ab6209a31f)
    // use 0 as default ns for old kernel
    proc.namespaces()
        .map_or(Ok(0), |m| match m.get(&OsString::from("net")) {
            Some(netns) => Ok(netns.identifier),
            _ => Ok(0),
        })
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
                    // now only support ipv4
                    let Some(local_address) = convert_addr_to_v4(t.local_address) else {
                        continue;
                    };
                    spec_addr_listen_sock.insert(local_address);
                }
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
    // Hashmap<netns_id, netnss_idx>
    netns_idx_map: &HashMap<u64, u16>,
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

            let Some((pid, fd)) = inode_pid_fd_map.get(&t.inode) else {
                continue;
            };

            /*
                note that symbol ctime of {proc_root}/{pid}/fd/{fd} is the first time access the file,
                not the time that the connection create. unless os_proc_socket_min_lifetime config to 0,
                the new connection at lease the second times scan can be recognized.
            */
            let Ok(sock_up_sec) = sym_uptime(
                now_sec,
                &PathBuf::from_iter([
                    proc_root.to_string(),
                    pid.to_string(),
                    "fd".to_string(),
                    fd.to_string(),
                ]),
            ) else {
                continue;
            };
            if sock_up_sec < sock_min_lifetime_sec {
                continue;
            }

            // now only support ipv4
            let (Some(local_address), Some(remote_address)) = (
                convert_addr_to_v4(t.local_address),
                convert_addr_to_v4(t.remote_address),
            ) else {
                continue;
            };

            sock_entries.push(SockEntry {
                pid: *pid as u32,
                proto: Protocol::Tcp,
                role: if all_iface_listen_sock.contains(&(
                    local_address.port(),
                    Protocol::Tcp,
                    netns,
                )) || spec_addr_listen_sock.contains(&local_address)
                {
                    // sport in all_iface_listen_sock or SocketAddr in spec_addr_listen_sock, assume is server connection
                    Role::Server
                } else {
                    Role::Client
                },

                local: SockAddrData {
                    epc_id: local_epc_id,
                    ip: local_address.ip(),
                    port: local_address.port(),
                },
                remote: SockAddrData {
                    epc_id: convert_i32_epc_id(policy_getter.lookup_epc_by_epc(
                        local_address.ip(),
                        remote_address.ip(),
                        local_epc_id as i32,
                    )),
                    ip: remote_address.ip(),
                    port: remote_address.port(),
                },
                netns_idx: *netns_idx_map.get(&netns).unwrap(),
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
    // Hashmap<netns_id, netnss_idx>
    netns_idx_map: &HashMap<u64, u16>,
    udp_entry: Vec<(Vec<UdpNetEntry>, u64)>,
    sock_entries: &mut Vec<SockEntry>,
) {
    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for (udp_entries, net_ns) in udp_entry {
        for u in udp_entries {
            let Some((pid, fd)) = inode_pid_fd_map.get(&u.inode) else {
                continue;
            };

            /*
                note that symbol ctime of {proc_root}/{pid}/fd/{fd} is the first time access the file,
                not the time that the connection create. unless os_proc_socket_min_lifetime config to 0,
                the new connection at lease the second times scan can be recognized.
            */

            let Ok(sock_up_sec) = sym_uptime(
                now_sec,
                &PathBuf::from_iter([
                    proc_root.to_string(),
                    pid.to_string(),
                    "fd".to_string(),
                    fd.to_string(),
                ]),
            ) else {
                continue;
            };
            if sock_up_sec < sock_min_lifetime_sec {
                continue;
            }

            if is_zero_addr(&u.remote_address) {
                // foreign addr is zero, indicate the udp socker create use bind(), no idea to determine the local and remote, ignore
                continue;
            }

            // now only support ipv4
            let (Some(local_address), Some(remote_address)) = (
                convert_addr_to_v4(u.local_address),
                convert_addr_to_v4(u.remote_address),
            ) else {
                continue;
            };

            // foreign addr is not zero, indicate the udp socker create use connect()
            sock_entries.push(SockEntry {
                pid: *pid as u32,
                proto: Protocol::Udp,
                role: Role::Client,
                local: SockAddrData {
                    epc_id: local_epc_id,
                    ip: local_address.ip(),
                    port: local_address.port(),
                },
                remote: SockAddrData {
                    epc_id: convert_i32_epc_id(policy_getter.lookup_epc_by_epc(
                        local_address.ip(),
                        remote_address.ip(),
                        local_epc_id as i32,
                    )),
                    ip: remote_address.ip(),
                    port: remote_address.port(),
                },
                netns_idx: *netns_idx_map.get(&net_ns).unwrap(),
                real_client: None,
            });
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

/*
    if sockaddr is ipv4, return self
    if sockaddr is ipv6 and have prefix ::ffff:?:? or ::?:? (such as `::ffff:127.0.0.1`), is dual stack ip addr, convert to ipv4
*/
fn convert_addr_to_v4(addr: SocketAddr) -> Option<SocketAddr> {
    const IPV6_V4_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255];
    match &addr {
        SocketAddr::V4(_) => Some(addr),
        SocketAddr::V6(v6) => {
            if &v6.ip().octets()[..12] != &IPV6_V4_PREFIX {
                // not ipv6 dual stack addr
                None
            } else {
                // extra latest 4 byte as ipv4 addr
                Some(SocketAddr::new(
                    IpAddr::V4(v6.ip().to_ipv4().unwrap()),
                    v6.port(),
                ))
            }
        }
    }
}
