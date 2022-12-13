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

use std::cmp::Ordering;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt::{self, Debug};
use std::fs::{self, File};
use std::hash::{Hash, Hasher};
use std::io::{self, Cursor, Write};
use std::mem;
use std::os::unix::{fs::MetadataExt, io::AsRawFd};
use std::path::{Path, PathBuf};

use log::{debug, trace, warn};
use neli::{
    attr::Attribute,
    consts::{genl::*, nl::*, rtnl::*, socket::*},
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

use super::{Error, InterfaceInfo, Result};
use crate::utils::net::{addr_list, link_list, links_by_name_regex, Link, IF_TYPE_IPVLAN};

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
            Self::Root => Ok(fs::metadata(NetNs::ROOT_NS_PATH)?.ino()),
            Self::Named(name) => {
                let ns_file = Path::new(NetNs::NAMED_PATH).join(name);
                Ok(fs::metadata(ns_file)?.ino())
            }
            Self::Proc(ino) => Ok(*ino),
        }
    }
}

impl fmt::Display for NsFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Root => write!(f, ""),
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
        if path == Path::new(NetNs::ROOT_NS_PATH) {
            return Ok(NsFile::Root);
        }
        match (path.parent(), path.file_name()) {
            (Some(p), Some(name)) if p == Path::new(NetNs::NAMED_PATH) => {
                Ok(NsFile::Named(name.to_owned()))
            }
            _ => Ok(NsFile::Proc(fs::metadata(path)?.ino())),
        }
    }
}

#[derive(Default)]
pub struct NetNs {
    proc_cache: HashMap<u64, Vec<u32>>,
}

impl NetNs {
    pub const NAMED_PATH: &'static str = "/var/run/netns";
    pub const ROOT_NS_PATH: &'static str = "/proc/1/ns/net";
    pub const CURRENT_NS_PATH: &'static str = "/proc/self/ns/net";
    pub const PROC_PATH: &'static str = "/proc";

    pub fn interfaces_linked_with(ns: &Vec<NsFile>) -> Result<HashMap<NsFile, Vec<InterfaceInfo>>> {
        // find all net namespaces
        let mut all_ns = HashMap::new();
        for path in Self::get_named_file_paths().into_iter() {
            if let Ok(m) = fs::metadata(&path) {
                all_ns.entry(m.ino()).or_insert(vec![]).push(path);
            }
        }
        match Self::get_proc_cache() {
            Ok(proc_cache) => {
                for (ino, pids) in proc_cache {
                    if all_ns.contains_key(&ino) {
                        continue;
                    }
                    all_ns.insert(
                        ino,
                        pids.iter()
                            .map(|pid| {
                                [Self::PROC_PATH, &pid.to_string(), "ns", "net"]
                                    .iter()
                                    .collect()
                            })
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

        let interested_files = ns
            .iter()
            .filter_map(|f| match Self::open_root_or_named_ns_file(f) {
                Ok((fp, _)) => Some((f, fp)),
                Err(e) => {
                    warn!("open netns file {:?} failed: {:?}", f, e);
                    None
                }
            })
            .collect::<Vec<_>>();

        // for restore
        let current_ns = NetNs::open_current_ns()?;

        let mut result = HashMap::new();
        // query net namespaces
        'outer: for (ino, paths) in all_ns.iter() {
            debug!("query namespace ino {}", ino);
            for path in paths {
                let fp = match File::open(path) {
                    Ok(fp) => fp,
                    Err(e) => {
                        debug!("open {} failed: {:?}", path.display(), e);
                        continue;
                    }
                };
                if let Err(_) = Self::setns(&fp, Some(path)) {
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

                for link in links {
                    let mut tap_ns = None;
                    if link.link_netnsid.is_none() {
                        match link.if_type.as_ref() {
                            Some(if_type) if if_type == IF_TYPE_IPVLAN => {
                                tap_ns = Some(&NsFile::Root)
                            }
                            _ => {
                                trace!("{:?} has no link-netnsid", link);
                                continue;
                            }
                        }
                    } else {
                        for (ns, nsfp) in interested_files.iter() {
                            match socket.get_nsid_by_file(nsfp) {
                                Ok(id) if id == link.link_netnsid.unwrap() as i32 => {
                                    tap_ns = Some(ns);
                                    break;
                                }
                                Err(e) => {
                                    debug!("get_nsid_by_file() failed for ns {:?}: {:?}", ns, e);
                                }
                                _ => (),
                            }
                        }
                    }
                    if tap_ns.is_none() {
                        trace!("no tap_ns found for link {:?}", link);
                        continue;
                    }
                    let info = InterfaceInfo {
                        tap_ns: (*tap_ns.unwrap()).clone(),
                        // no peer index means same index
                        tap_idx: link.peer_index.unwrap_or(link.if_index),
                        mac: link.mac_addr,
                        ips: addrs
                            .iter()
                            .filter_map(|addr| {
                                if addr.if_index == link.if_index {
                                    Some(addr.ip_addr)
                                } else {
                                    None
                                }
                            })
                            .collect(),
                        name: link.name,
                        device_id: format!("{}", NsFile::try_from(path.as_ref()).unwrap()),
                    };
                    trace!("found {:?}", info);
                    result
                        .entry(info.tap_ns.clone())
                        .or_insert(vec![])
                        .push(info);
                }
                continue 'outer;
            }
            debug!("query namespace ino {} failed", ino);
        }

        Self::setns(&current_ns, Some(Self::CURRENT_NS_PATH))?;
        Ok(result)
    }

    // interface info in this net namespace
    #[deprecated]
    pub fn get_ns_interfaces(&mut self, ns: &NsFile) -> Result<Vec<InterfaceInfo>> {
        self.open_and_setns(ns)?;

        // the socket *must* be created after setns, otherwise it will be in old namespace
        let mut socket = WrappedSocket::new()?;
        let mut ns_map = self.load_named_ns_map(&mut socket);
        // add root ns
        let root_map = self.load_ns_map(&mut socket, vec![NsFile::Root]);
        ns_map.extend(root_map);
        let mut proc_map = None;
        let mut interfaces = vec![];
        for link in link_list()? {
            if link.peer_index.is_none() {
                continue;
            }
            let peer_index = link.peer_index.unwrap();
            if link.link_netnsid.is_none() {
                continue;
            }
            let nsid = link.link_netnsid.unwrap();
            let link_netns = if let Some(ns) = ns_map.get(&nsid) {
                ns
            } else {
                if proc_map.is_none() {
                    proc_map = Some(self.load_proc_ns_map(&mut socket));
                }
                if let Some(ns) = proc_map.as_ref().unwrap().get(&nsid) {
                    ns
                } else {
                    continue;
                }
            };
            // get addr_list in ns
            if let Err(e) = self.open_and_setns(&link_netns) {
                warn!("setns {:?} failed: {:?}", link_netns, e);
                continue;
            }
            let mut ips = vec![];
            match addr_list() {
                Ok(addrs) => {
                    for addr in addrs {
                        if addr.if_index == peer_index {
                            ips.push(addr.ip_addr);
                        }
                    }
                }
                Err(e) => warn!("failed calling addr_list in {:?}: {:?}", link_netns, e),
            }
            match link_list() {
                Ok(ns_links) => {
                    for peer_link in ns_links {
                        if peer_link.if_index == peer_index {
                            interfaces.push(InterfaceInfo {
                                tap_ns: ns.clone(),
                                tap_idx: link.if_index,
                                mac: peer_link.mac_addr,
                                ips,
                                name: peer_link.name,
                                device_id: link_netns.to_string(),
                            });
                            break;
                        }
                    }
                }
                Err(e) => warn!("failed calling link_list in {:?}: {:?}", link_netns, e),
            }
        }

        Ok(interfaces)
    }

    pub fn get_current_ns() -> Result<NsFile> {
        Ok(NsFile::Proc(fs::metadata(Self::CURRENT_NS_PATH)?.ino()))
    }

    pub fn open_current_ns() -> Result<File> {
        Ok(File::open(Self::CURRENT_NS_PATH)?)
    }

    pub fn find_ns_files_by_regex(re: &Regex) -> Vec<NsFile> {
        Self::get_named_files()
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
            .collect()
    }

    pub fn setns<P: AsRef<Path>>(fp: &File, path: Option<P>) -> Result<()> {
        if let Err(e) = setns(fp.as_raw_fd(), CloneFlags::CLONE_NEWNET) {
            match path {
                Some(p) => warn!(
                    "setns({}) failed for {}: {:?}",
                    fp.as_raw_fd(),
                    p.as_ref().display(),
                    e
                ),
                None => warn!(
                    "setns({}) failed for inode {:?}: {:?}",
                    fp.as_raw_fd(),
                    fp.metadata().ok().map(|m| m.ino()),
                    e
                ),
            }
            return Err(e.into());
        }
        Ok(())
    }

    fn open_and_setns(&mut self, ns: &NsFile) -> Result<()> {
        let fp = self.open_ns_file(ns)?;
        Self::setns(&fp.0, Some(fp.1))
    }

    pub fn open_named_and_setns(ns: &NsFile) -> Result<()> {
        match ns {
            NsFile::Named(name) => {
                let path = Path::new(Self::NAMED_PATH).join(name);
                let fp = File::open(&path)?;
                Self::setns(&fp, Some(path))
            }
            _ => unimplemented!(),
        }
    }

    fn get_named_file_paths() -> Vec<PathBuf> {
        if let Ok(entries) = fs::read_dir(Self::NAMED_PATH) {
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
        }
    }

    fn get_named_files() -> Vec<NsFile> {
        Self::get_named_file_paths()
            .into_iter()
            .map(|e| NsFile::Named(e.file_name().unwrap().to_owned()))
            .collect()
    }

    fn load_named_ns_map(&mut self, socket: &mut WrappedSocket) -> HashMap<u32, NsFile> {
        let named_files = Self::get_named_files();
        self.load_ns_map(socket, named_files)
    }

    fn get_proc_files(&mut self) -> Vec<NsFile> {
        if self.proc_cache.is_empty() {
            if let Err(e) = self.update_proc_cache() {
                warn!("get proc files failed: {:?}", e);
                return vec![];
            }
        }
        self.proc_cache
            .keys()
            .map(|inode| NsFile::Proc(*inode))
            .collect()
    }

    fn load_proc_ns_map(&mut self, socket: &mut WrappedSocket) -> HashMap<u32, NsFile> {
        let proc_files = self.get_proc_files();
        self.load_ns_map(socket, proc_files)
    }

    fn load_ns_map(
        &mut self,
        socket: &mut WrappedSocket,
        files: Vec<NsFile>,
    ) -> HashMap<u32, NsFile> {
        let mut map = HashMap::new();
        for file in files {
            match self.open_ns_file(&file) {
                Ok((fp, _)) => {
                    if let Ok(id) = socket.get_nsid_by_file(&fp) {
                        // negative id (-1) is ns not related to current ns
                        if id >= 0 {
                            map.insert(id as u32, file);
                        }
                    }
                }
                Err(e) => warn!("cannot read ns from {:?}: {:?}", file, e),
            }
        }
        map
    }

    fn open_root_or_named_ns_file(ns: &NsFile) -> Result<(File, PathBuf)> {
        match ns {
            NsFile::Root => Ok((
                File::open(Self::ROOT_NS_PATH)?,
                PathBuf::from(Self::ROOT_NS_PATH),
            )),
            NsFile::Named(name) => {
                let path = Path::new(Self::NAMED_PATH).join(name);
                Ok((File::open(&path)?, path))
            }
            _ => unimplemented!(),
        }
    }

    fn open_ns_file(&mut self, ns: &NsFile) -> Result<(File, PathBuf)> {
        match ns {
            NsFile::Root | NsFile::Named(_) => Self::open_root_or_named_ns_file(ns),
            NsFile::Proc(inode) => {
                if self.proc_cache.is_empty() || !self.proc_cache.contains_key(inode) {
                    let _ = self.update_proc_cache();
                }
                if let Some(pids) = self.proc_cache.get(inode) {
                    for pid in pids {
                        let path = [Self::PROC_PATH, &pid.to_string(), "ns", "net"]
                            .iter()
                            .collect();
                        match File::open(&path) {
                            Ok(fp) => return Ok((fp, path)),
                            Err(_) => continue,
                        }
                    }
                }
                Err(Error::from(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{:?} not found", ns),
                )))
            }
        }
    }

    fn get_proc_cache() -> Result<HashMap<u64, Vec<u32>>> {
        let mut cache = HashMap::new();
        for proc in fs::read_dir(Self::PROC_PATH)? {
            let proc = proc?;
            if !proc.file_type()?.is_dir() {
                continue;
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

    fn update_proc_cache(&mut self) -> Result<()> {
        if let Ok(cache) = Self::get_proc_cache() {
            self.proc_cache = cache;
        }
        Ok(())
    }
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

pub fn links_by_name_regex_in_netns<S: AsRef<str>>(regex: S, ns: &NsFile) -> Result<Vec<Link>> {
    let current_ns = NetNs::open_current_ns()?;
    let _ = NetNs::open_named_and_setns(ns)?;
    let links = links_by_name_regex(regex.as_ref())?;
    let _ = NetNs::setns(&current_ns, Some(NetNs::CURRENT_NS_PATH))?;
    Ok(links)
}

pub fn link_list_in_netns(ns: &NsFile) -> Result<Vec<Link>> {
    let current_ns = NetNs::open_current_ns()?;
    let _ = NetNs::open_named_and_setns(ns)?;
    let links = link_list()?;
    let _ = NetNs::setns(&current_ns, Some(NetNs::CURRENT_NS_PATH))?;
    Ok(links)
}
