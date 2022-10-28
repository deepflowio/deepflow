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
use std::fmt::Debug;
use std::fs::{self, File};
use std::io::{self, Cursor, Write};
use std::os::unix::{fs::MetadataExt, io::AsRawFd};
use std::path::{Path, PathBuf};

use log::warn;
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
use crate::utils::net::{addr_list, link_list, links_by_name_regex, Link};

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

#[derive(Clone, Debug, Default, Hash)]
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
        Ok(NsFile::Proc(fs::metadata(path)?.ino()))
    }
}

#[derive(Default)]
pub struct NetNs {
    proc_cache: HashMap<u64, Vec<u32>>,
}

impl NetNs {
    const NAMED_PATH: &'static str = "/var/run/netns";
    const ROOT_NS_PATH: &'static str = "/proc/1/ns/net";
    const PROC_PATH: &'static str = "/proc";

    // interface info in this net namespace
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
                                tap_ns: link_netns.clone(),
                                tap_idx: link.if_index,
                                mac: peer_link.mac_addr,
                                ips,
                                name: peer_link.name,
                                device_id: format!(
                                    "net:[{}]",
                                    link_netns.get_inode().unwrap_or_default()
                                ),
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
        let path: PathBuf = [Self::PROC_PATH, "self", "ns", "net"].iter().collect();
        Ok(NsFile::Proc(fs::metadata(&path)?.ino()))
    }

    pub fn open_current_ns() -> Result<File> {
        let path: PathBuf = [Self::PROC_PATH, "self", "ns", "net"].iter().collect();
        Ok(File::open(&path)?)
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

    pub fn setns(fp: &File) -> Result<()> {
        if let Err(e) = setns(fp.as_raw_fd(), CloneFlags::CLONE_NEWNET) {
            let inode = fp.metadata().ok().map(|m| m.ino());
            warn!("setns() failed for fd {} inode {:?}: {:?}", fp.as_raw_fd(), inode, e);
            return Err(e.into());
        }
        Ok(())
    }

    fn open_and_setns(&mut self, ns: &NsFile) -> Result<()> {
        let fp = self.open_ns_file(ns)?;
        Self::setns(&fp)
    }

    pub fn open_named_and_setns(ns: &NsFile) -> Result<()> {
        match ns {
            NsFile::Named(name) => {
                let fp = File::open(Path::new(NetNs::NAMED_PATH).join(name))?;
                Self::setns(&fp)
            }
            _ => unimplemented!(),
        }
    }

    fn get_named_files() -> Vec<NsFile> {
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
                        .map(|e| NsFile::Named(e.file_name()))
                })
                .collect()
        } else {
            vec![]
        }
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
                Ok(fp) => {
                    if let Ok(id) = socket.get_nsid_by_file(fp) {
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

    fn open_ns_file(&mut self, ns: &NsFile) -> Result<File> {
        match ns {
            NsFile::Root => Ok(File::open(Self::ROOT_NS_PATH)?),
            NsFile::Named(name) => Ok(File::open(Path::new(NetNs::NAMED_PATH).join(name))?),
            NsFile::Proc(inode) => {
                if self.proc_cache.is_empty() || !self.proc_cache.contains_key(inode) {
                    let _ = self.update_proc_cache();
                }
                if let Some(pids) = self.proc_cache.get(inode) {
                    for pid in pids {
                        let path: PathBuf = [Self::PROC_PATH, &format!("{}", pid), "ns", "net"]
                            .iter()
                            .collect();
                        match File::open(path) {
                            Ok(fp) => return Ok(fp),
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

    fn update_proc_cache(&mut self) -> Result<()> {
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
        self.proc_cache = cache;
        Ok(())
    }
}

struct WrappedSocket(NlSocketHandle);

impl WrappedSocket {
    fn new() -> Result<Self> {
        Ok(Self(NlSocketHandle::connect(NlFamily::Route, None, &[])?))
    }

    fn get_nsid_by_file(&mut self, fp: File) -> Result<i32> {
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
    let _ = NetNs::setns(&current_ns)?;
    Ok(links)
}
