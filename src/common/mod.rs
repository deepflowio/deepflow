use std::{
    fmt,
    hash::{Hash, Hasher},
    net::Ipv4Addr,
};

mod enums;
pub use enums::*;

mod flow;
mod policy;
mod tag;
mod tagged_flow;
mod tap_types;
pub use consts::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct XflowKey {
    ip: Ipv4Addr,
    tap_idx: u32,
}

impl Hash for XflowKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let key = ((u32::from(self.ip) as u64) << 32) + self.tap_idx as u64;
        key.hash(state)
    }
}

impl fmt::Display for XflowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "source_ip:{}, interface_index:{}", self.ip, self.tap_idx)
    }
}

#[cfg(target_os = "linux")]
mod consts {
    pub const NORMAL_EXIT_WITH_RESTART: i32 = 3;
    pub const TRIDENT_PROCESS_LIMIT: u32 = 10;
    pub const TRIDENT_THREAD_LIMIT: u32 = 100;
    pub const DEFAULT_LOGFILE: &'static str = "/var/log/trident/trident.log";
    pub const DEFAULT_CONF_FILE: &'static str = "/etc/trident.yaml";
    pub const COREFILE_FORMAT: &'static str = "core";
    pub const DEFAULT_COREFILE_PATH: &'static str = "/tmp";
    pub const DEFAULT_LIBVIRT_XML_PATH: &'static str = "/etc/libvirt/qemu";
}

#[cfg(target_os = "windows")]
mod consts {
    pub const NORMAL_EXIT_WITH_RESTART: i32 = 3;
    pub const TRIDENT_PROCESS_LIMIT: u32 = 10;
    pub const TRIDENT_THREAD_LIMIT: u32 = 100;
    pub const DEFAULT_LOGFILE: &str = "C:\\DeepFlow\\trident\\log\\trident.log";
    // NOTE yaml must be full path, otherwise service wouldn't start as you wish.
    pub const DEFAULT_CONF_FILE: &str = "C:\\DeepFlow\\trident\\trident-windows.yaml";
    pub const DEFAULT_COREFILE_PATH: &str = "C:\\DeepFlow\\trident";
    pub const COREFILE_FORMAT: &str = "dump";
}
