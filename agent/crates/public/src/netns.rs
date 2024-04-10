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
    borrow::Cow,
    cell::OnceCell,
    cmp::Ordering,
    collections::HashMap,
    ffi::OsString,
    fmt::{self, Debug},
    fs::{self, File},
    hash::{Hash, Hasher},
    io::{Cursor, Write},
    mem,
    net::IpAddr,
    os::unix::{fs::MetadataExt, io::AsRawFd},
    path::{Path, PathBuf},
};

use ipnet::IpNet;
use log::{debug, info, trace, warn};
use neli::{
    attr::Attribute,
    consts::{genl::*, nl::*, rtnl::*, socket::*},
    err::{NlError, SerError},
    genl::Genlmsghdr,
    nl::{NlPayload, Nlmsghdr},
    rtnl::{Rtattr, Rtgenmsg},
    socket::NlSocketHandle,
    types::Buffer,
    ToBytes,
};
use nix::sched::{setns, CloneFlags};
use num_enum::IntoPrimitive;
use regex::Regex;
use thiserror::Error;

use super::utils::net::{
    self, addr_list, link_by_name, link_list, links_by_name_regex, route_list, rule_list, Addr,
    Link, MacAddr, IF_TYPE_IPVLAN,
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("neli error: {0}")]
    NeliError(String),
    #[error("net error: {0}")]
    NetError(#[from] net::Error),
    #[error("netns not found")]
    NotFound,
    #[error("syscall error: {0}")]
    Syscall(#[from] nix::Error),
}

impl<T: Debug, P: Debug> From<NlError<T, P>> for Error {
    fn from(e: NlError<T, P>) -> Self {
        Self::NeliError(format!("{}", e))
    }
}

impl From<SerError> for Error {
    fn from(e: SerError) -> Self {
        Self::NeliError(format!("{}", e))
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Default, Clone)]
pub struct InterfaceInfo {
    pub tap_ns: NsFile,
    pub tap_idx: u32,
    pub mac: MacAddr,
    pub ips: Vec<IpNet>,
    pub name: String,
    pub device_id: String,
    pub ns_inode: u64,
    pub if_type: Option<String>,
}

impl fmt::Display for InterfaceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ips_str = self
            .ips
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<String>>()
            .as_slice()
            .join(",");
        write!(
            f,
            "{}: {}: {} [{}] device {} ino {}",
            self.tap_idx, self.name, self.mac, ips_str, self.device_id, self.ns_inode
        )
    }
}

impl PartialEq for InterfaceInfo {
    fn eq(&self, other: &Self) -> bool {
        self.tap_idx.eq(&other.tap_idx) && self.mac.eq(&other.mac)
    }
}

impl Eq for InterfaceInfo {}

impl PartialOrd for InterfaceInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for InterfaceInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.tap_idx.cmp(&other.tap_idx), self.mac.cmp(&other.mac)) {
            (Ordering::Equal, mac) => mac,
            (tap, _) => tap,
        }
    }
}

#[derive(IntoPrimitive)]
#[repr(u16)]
pub enum Netnsa {
    None = 0,
    Nsid = 1,
    Pid = 2,
    Fd = 3,
    TargetNsid = 4,
    CurrentNsid = 5,
}

#[derive(Clone, Debug, Default)]
pub enum NsFile {
    #[default]
    Root,
    Named(OsString),
    Proc(u64),
}

impl NsFile {
    fn get_inode(&self) -> Result<u64> {
        match self {
            Self::Root => Ok(fs::metadata(ROOT_NS_PATH)?.ino()),
            Self::Named(name) => {
                let ns_file = Path::new(NAMED_PATH).join(name);
                Ok(fs::metadata(ns_file)?.ino())
            }
            Self::Proc(ino) => Ok(*ino),
        }
    }
}

impl fmt::Display for NsFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Root => write!(f, "default"),
            Self::Named(s) => write!(f, "{:?}", s),
            Self::Proc(p) => write!(f, "net:[{}]", p),
        }
    }
}

impl Hash for NsFile {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self.get_inode() {
            Ok(ino) => ino.hash(state),
            _ => self.to_string().hash(state),
        }
    }
}

impl PartialOrd for NsFile {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NsFile {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Root, Self::Root) => Ordering::Equal,
            (Self::Root, _) => Ordering::Less,
            (Self::Named(_), Self::Root) => Ordering::Greater,
            (Self::Named(s), Self::Named(o)) => s.cmp(o),
            (Self::Named(_), _) => Ordering::Less,
            (Self::Proc(s), Self::Proc(o)) => s.cmp(o),
            (Self::Proc(_), _) => Ordering::Greater,
        }
    }
}

impl PartialEq for NsFile {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Root, Self::Root) => true,
            (Self::Named(s), Self::Named(o)) if s == o => true,
            _ => {
                if let (Ok(s), Ok(o)) = (self.get_inode(), other.get_inode()) {
                    s == o
                } else {
                    false
                }
            }
        }
    }
}

impl Eq for NsFile {}

impl TryFrom<&Path> for NsFile {
    type Error = Error;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        if path == Path::new(ROOT_NS_PATH) {
            return Ok(NsFile::Root);
        }
        match (path.parent(), path.file_name()) {
            (Some(p), Some(name)) if p == Path::new(NAMED_PATH) => {
                Ok(NsFile::Named(name.to_owned()))
            }
            _ => Ok(NsFile::Proc(fs::metadata(path)?.ino())),
        }
    }
}

pub const NAMED_PATH: &'static str = "/var/run/netns";
pub const ROOT_NS_PATH: &'static str = "/proc/1/ns/net";
pub const PROC_PATH: &'static str = "/proc";

fn generate_masklen_map() -> Result<HashMap<IpAddr, u8>> {
    let mut prefix_map = HashMap::new();
    generate_masklen_map_in(&mut prefix_map)?;
    Ok(prefix_map)
}

/*
 * Generates mapping of ip address and its netmask prefix
 * by linux policy routing entries
 *
 * 1. Find the following routing rule (`ip rule show`) by destination $ip:
 *
 *      from all to $ip lookup $table
 *
 * 2. Find the matching route (`ip route show table $table`) in $table
 *
 *      $ip_masked/$prefix dev ...
 *
 *    in which `$ip_masked` is a address range that covers `$ip`
 *
 * 3. Populate the `HashMap` with `key=$ip` and `value=$prefix`
 */
fn generate_masklen_map_in(map: &mut HashMap<IpAddr, u8>) -> Result<()> {
    let rules = rule_list()?;
    trace!("rules: {:?}", rules);
    if rules.is_empty() {
        return Ok(());
    }
    let routes = route_list()?;
    trace!("routes: {:?}", routes);
    if routes.is_empty() {
        return Ok(());
    }

    for rule in rules {
        let Some(ip) = rule.dst_ip.as_ref() else {
            continue;
        };

        // only care about single addresses
        if ip.prefix_len() != ip.max_prefix_len() {
            continue;
        }

        for route in routes.iter() {
            let Some(route_ip) = route.dst_ip.as_ref() else {
                continue;
            };

            // found matching entry
            if rule.table == route.table && route_ip.contains(ip) {
                trace!(
                    "found prefix len {} for addr {}",
                    route_ip.prefix_len(),
                    ip.addr()
                );
                map.insert(ip.addr(), route_ip.prefix_len());
                break;
            }
        }
    }

    Ok(())
}

pub fn interfaces_linked_with<S: AsRef<[NsFile]>>(
    ns: S,
) -> Result<HashMap<NsFile, Vec<InterfaceInfo>>> {
    let ns = ns.as_ref();
    // find all net namespaces
    let mut all_ns = HashMap::new();
    for path in get_named_file_paths().into_iter() {
        if let Ok(m) = fs::metadata(&path) {
            all_ns.entry(m.ino()).or_insert(vec![]).push(path);
        }
    }
    match get_proc_cache() {
        Ok(proc_cache) => {
            for (ino, pids) in proc_cache {
                if all_ns.contains_key(&ino) {
                    continue;
                }
                all_ns.insert(
                    ino,
                    pids.iter()
                        .map(|pid| [PROC_PATH, &pid.to_string(), "ns", "net"].iter().collect())
                        .collect(),
                );
            }
        }
        Err(e) => warn!("get proc cache failed: {:?}", e),
    }
    debug!(
        "query namespaces: {:?}",
        all_ns.iter().map(|(k, v)| (k, &v[0])).collect::<Vec<_>>()
    );

    struct NamespaceInfo<'a> {
        fp: File,
        file: &'a NsFile,
        prefix_map: HashMap<IpAddr, u8>,
    }

    debug!("tap namespace: {:?}", ns);
    // nsid is not consistent between namespaces
    // the connection is established by querying nsid from pod namespace
    // for all interested namespaces (in which pod link veth pair resides)
    // and related it to `link_netsid` in link info
    //
    // `NamespaceInfo` is used to put these things together for query:
    //   fp: used for querying nsid from pod namespace
    //   file: `tap_ns` entry in `InterfaceInfo`
    //   prefix_map: getting link ip prefix
    let interested_files = ns
        .iter()
        .filter_map(|f| match open_root_or_named_ns_file(f) {
            Ok((fp, _)) => {
                if let Err(_) = set_netns(&fp) {
                    warn!("setns failed for {}", f);
                    None
                } else {
                    let prefix_map = generate_masklen_map().unwrap_or_default();
                    debug!("prefix map in {} is {:?}", f, prefix_map);
                    Some(NamespaceInfo {
                        fp,
                        file: f,
                        prefix_map,
                    })
                }
            }
            Err(e) => {
                warn!("open netns file {:?} failed: {:?}", f, e);
                None
            }
        })
        .collect::<Vec<_>>();

    let mut result = HashMap::new();
    // namespace id to nsfile in namespaces
    // cleared and updated in each namespace
    let mut nsid_map = HashMap::with_capacity(interested_files.len());
    // query net namespaces
    'outer: for (ino, paths) in all_ns.iter() {
        debug!("query namespace ino {}", ino);
        for path in paths {
            trace!("query namespace ino {} in {}", ino, path.display());
            let fp = match File::open(path) {
                Ok(fp) => fp,
                Err(e) => {
                    debug!("open {} failed: {:?}", path.display(), e);
                    continue;
                }
            };
            let current_ns = match NsFile::try_from(path.as_ref()) {
                Ok(ns) => ns,
                Err(e) => {
                    debug!("create nsfile from {} failed: {:?}", path.display(), e);
                    continue;
                }
            };
            if let Err(_) = set_netns(&fp) {
                debug!("setns failed for file {}", path.display());
                continue;
            }
            // close file ASAP
            mem::drop(fp);

            let Ok(links) = link_list() else {
                debug!("link_list() failed for file {}", path.display());
                continue;
            };
            let Ok(addrs) = addr_list() else {
                debug!("addr_list() failed for file {}", path.display());
                continue;
            };

            let Ok(mut socket) = WrappedSocket::new() else {
                debug!("WrappedSocket::new() failed for file {}", path.display());
                continue;
            };

            if links.is_empty() {
                continue 'outer;
            }

            nsid_map.clear();
            for NamespaceInfo {
                file: ns,
                fp: nsfp,
                prefix_map,
            } in interested_files.iter()
            {
                match socket.get_nsid_by_file(nsfp) {
                    Ok(id) if id >= 0 => {
                        nsid_map.insert(id, (ns, prefix_map));
                    }
                    Ok(_) => (),
                    Err(e) => {
                        debug!("get_nsid_by_file() failed for ns {:?}: {:?}", ns, e);
                    }
                }
            }
            trace!("nsid map in ino {} is {:?}", ino, nsid_map);

            for link in links {
                trace!("check {:?}", link);
                let (tap_ns, prefix_map): (&NsFile, Option<&HashMap<_, _>>) =
                    if let Some(nsid) = link.link_netnsid {
                        let Some((tap_ns, prefix_map)) = nsid_map.get(&(nsid as i32)) else {
                            debug!("no tap_ns found for link {:?}", link);
                            continue;
                        };
                        (**tap_ns, Some(*prefix_map))
                    } else {
                        match link.if_type.as_ref() {
                            Some(if_type) if if_type == IF_TYPE_IPVLAN => (&NsFile::Root, None),
                            _ => {
                                debug!("{:?} has no link-netnsid", link);
                                continue;
                            }
                        }
                    };
                let info = InterfaceInfo {
                    tap_ns: tap_ns.clone(),
                    // no peer index means same index
                    tap_idx: link.peer_index.unwrap_or(link.if_index),
                    mac: link.mac_addr,
                    ips: addrs
                        .iter()
                        .filter_map(|addr| {
                            if addr.if_index == link.if_index {
                                let prefix_len = prefix_map
                                    .and_then(|m| m.get(&addr.ip_addr))
                                    .unwrap_or(match addr.ip_addr {
                                        IpAddr::V4(_) => &32,
                                        IpAddr::V6(_) => &128,
                                    });
                                IpNet::new(addr.ip_addr, *prefix_len).ok()
                            } else {
                                None
                            }
                        })
                        .collect(),
                    name: link.name,
                    device_id: current_ns.to_string(),
                    ns_inode: *ino,
                    if_type: link.if_type,
                };
                debug!("found {:?}", info);
                result
                    .entry(info.tap_ns.clone())
                    .or_insert(vec![])
                    .push(info);
            }
            continue 'outer;
        }
        debug!("query namespace ino {} failed", ino);
    }

    reset_netns()?;
    Ok(result)
}

pub fn find_ns_files_by_regex(re: &Regex) -> Vec<NsFile> {
    let files = get_named_files()
        .into_iter()
        .filter(|entry| {
            match entry {
                NsFile::Named(name) => {
                    if let Some(s) = name.to_str() {
                        return re.is_match(s);
                    }
                }
                _ => (),
            }
            false
        })
        .collect();
    trace!("namespace files by regex /{}/ are: {:?}", re, files);
    files
}

pub fn current_netns_path() -> PathBuf {
    // SAFTY: safe FFI call to get thread id
    let tid = unsafe { libc::syscall(libc::SYS_gettid) as u32 };
    [PROC_PATH, "self", "task", &tid.to_string(), "ns", "net"]
        .iter()
        .collect()
}

thread_local! {
    // original per thread net namespace file handle
    // set at first `setns` call
    // used to restore net namespace
    static ORIGINAL_NETNS: OnceCell<File> = OnceCell::new();
    // check if current system supports network namespace
    // if not, setns calls will be NOOP
    static SUPPORTS_NETNS: OnceCell<bool> = OnceCell::new();
}

const SELF_NS_PATH: &'static str = "/proc/self/ns/net";

pub fn supported() -> bool {
    SUPPORTS_NETNS.with(|f| {
        *f.get_or_init(|| {
            if fs::metadata(SELF_NS_PATH).is_ok() {
                true
            } else {
                info!(
                    "path {} is not accessible, setns() calls will be NOOP",
                    SELF_NS_PATH
                );
                false
            }
        })
    })
}

pub fn set_netns(fp: &File) -> Result<()> {
    if !supported() {
        return Ok(());
    }
    let cur_path = current_netns_path();
    ORIGINAL_NETNS.with(|f| {
        f.get_or_init(|| File::open(&cur_path).expect("open thread net namespace file failed"));
    });

    // do nothing if current ns is target ns
    let inode = fs::metadata(&cur_path);
    let target_inode = fp.metadata().ok().map(|m| m.ino());
    match (inode.as_ref(), target_inode) {
        (Ok(a), Some(b)) if a.ino() == b => return Ok(()),
        _ => (),
    }

    if let Err(e) = setns(fp.as_raw_fd(), CloneFlags::CLONE_NEWNET) {
        debug!(
            "setns({}) failed for inode {:?}: {:?}",
            fp.as_raw_fd(),
            target_inode,
            e
        );
        return Err(e.into());
    }
    match (inode, target_inode) {
        (Ok(a), Some(b)) => debug!("set_netns {} -> {}", a.ino(), b),
        _ => (),
    }
    Ok(())
}

pub fn reset_netns() -> Result<()> {
    if !supported() {
        return Ok(());
    }
    ORIGINAL_NETNS.with(|f| {
        if let Some(fp) = f.get() {
            // do nothing if current ns is target ns
            let inode = fs::metadata(&current_netns_path());
            let target_inode = fp.metadata().ok().map(|m| m.ino());
            match (inode.as_ref(), target_inode) {
                (Ok(a), Some(b)) if a.ino() == b => return Ok(()),
                _ => (),
            }

            if let Err(e) = setns(fp.as_raw_fd(), CloneFlags::CLONE_NEWNET) {
                debug!("reset netns failed: {:?}", e);
                return Err(e.into());
            }

            match (inode, target_inode) {
                (Ok(a), Some(b)) => debug!("set_netns {} -> {}", a.ino(), b),
                _ => (),
            }
        }
        Ok(())
    })
}

pub fn open_named_and_setns(ns: &NsFile) -> Result<()> {
    if !supported() {
        return Ok(());
    }
    let path = match ns {
        NsFile::Root => Cow::Borrowed(Path::new(ROOT_NS_PATH)),
        NsFile::Named(name) => Cow::Owned(Path::new(NAMED_PATH).join(name)),
        _ => unimplemented!(),
    };
    let fp = File::open(&*path)?;
    let r = set_netns(&fp);
    if let Err(e) = r.as_ref() {
        debug!("open {} and setns failed: {:?}", path.display(), e);
    }
    r
}

fn get_named_file_paths() -> Vec<PathBuf> {
    let paths = if let Ok(entries) = fs::read_dir(NAMED_PATH) {
        entries
            .into_iter()
            .filter_map(|entry| {
                entry
                    .ok()
                    .filter(|e| match e.file_type() {
                        Ok(t) if t.is_file() || t.is_symlink() => true,
                        _ => false,
                    })
                    .map(|e| e.path())
            })
            .collect()
    } else {
        vec![]
    };
    trace!("paths under {} are: {:?}", NAMED_PATH, paths);
    paths
}

fn get_named_files() -> Vec<NsFile> {
    let files = get_named_file_paths()
        .into_iter()
        .map(|e| NsFile::Named(e.file_name().unwrap().to_owned()))
        .collect();
    trace!("named namespace files: {:?}", files);
    files
}

fn open_root_or_named_ns_file(ns: &NsFile) -> Result<(File, PathBuf)> {
    match ns {
        NsFile::Root => Ok((File::open(ROOT_NS_PATH)?, PathBuf::from(ROOT_NS_PATH))),
        NsFile::Named(name) => {
            let path = Path::new(NAMED_PATH).join(name);
            Ok((File::open(&path)?, path))
        }
        _ => unimplemented!(),
    }
}

fn get_proc_cache() -> Result<HashMap<u64, Vec<u32>>> {
    let mut cache = HashMap::new();
    for proc in fs::read_dir(PROC_PATH)? {
        let Ok(proc) = proc else {
            // ignore file not found probably caused by process terminated
            continue;
        };
        match proc.file_type() {
            Ok(t) if t.is_dir() => (),
            _ => {
                debug!("skipped {}", proc.path().display());
                continue;
            }
        }
        let pid = proc
            .file_name()
            .into_string()
            .ok()
            .and_then(|s| s.parse::<u32>().ok());
        if pid.is_none() {
            continue;
        }
        let pid = pid.unwrap();

        let mut ns_path = proc.path();
        ns_path.extend(&["ns", "net"]);
        if let Ok(fp) = fs::metadata(&ns_path) {
            cache.entry(fp.ino()).or_insert(vec![]).push(pid);
        }
    }
    Ok(cache)
}

struct WrappedSocket(NlSocketHandle);

impl WrappedSocket {
    fn new() -> Result<Self> {
        Ok(Self(NlSocketHandle::connect(NlFamily::Route, None, &[])?))
    }

    fn get_nsid_by_file(&mut self, fp: &File) -> Result<i32> {
        let mut payload = Cursor::new(Vec::new());
        Rtgenmsg {
            rtgen_family: RtAddrFamily::Unspecified,
        }
        .to_bytes(&mut payload)?;
        // padding
        payload.write(&[0, 0, 0])?;
        Rtattr::new(None, u16::from(Netnsa::Fd), fp.as_raw_fd() as u32)?.to_bytes(&mut payload)?;

        let hdr = Nlmsghdr::new(
            None,
            Rtm::Getnsid,
            NlmFFlags::new(&[NlmF::Request]),
            None,
            None,
            NlPayload::Payload(Buffer::from(payload.into_inner())),
        );
        self.0.send(hdr)?;

        for m in self
            .0
            .iter::<NlTypeWrapper, Genlmsghdr<CtrlCmd, CtrlAttr>>(false)
        {
            let m = m?;
            if let NlTypeWrapper::Rtm(Rtm::Newnsid) = m.nl_type {
                for attr in m.get_payload()?.get_attr_handle().iter() {
                    if let Ok(id) = attr.get_payload_as() {
                        return Ok(id);
                    }
                }
            }
        }
        Err(Error::NotFound)
    }
}

pub fn link_by_name_in_netns<S: AsRef<str>>(name: S, ns: &NsFile) -> Result<Link> {
    let _ = open_named_and_setns(ns)?;
    let link = link_by_name(name.as_ref())?;
    reset_netns()?;
    Ok(link)
}

pub fn links_by_name_regex_in_netns<S: AsRef<str>>(regex: S, ns: &NsFile) -> Result<Vec<Link>> {
    let _ = open_named_and_setns(ns)?;
    let links = links_by_name_regex(regex.as_ref())?;
    reset_netns()?;
    Ok(links)
}

pub fn link_list_in_netns(ns: &NsFile) -> Result<Vec<Link>> {
    let _ = open_named_and_setns(ns)?;
    let links = link_list()?;
    reset_netns()?;
    Ok(links)
}

pub fn addr_list_in_netns(ns: &NsFile) -> Result<Vec<Addr>> {
    let _ = open_named_and_setns(ns)?;
    let addrs = addr_list()?;
    reset_netns()?;
    Ok(addrs)
}
