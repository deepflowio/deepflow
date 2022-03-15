use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("parse mac address failed from: {0}")]
    ParseMacFailed(String),
    #[error("call try_from() failed from {0}")]
    TryFromFailed(String),
    #[error("kubernetes watchers error ")]
    KubeWatcher(#[from] kube::runtime::watcher::Error),
    #[error("parse bytes to String error ")]
    ParseUtf8(#[from] std::string::FromUtf8Error),
    #[error("PlatformSynchronizer failed: {0} ")]
    PlatformSynchronizer(String),
    #[error("IO error")]
    IoError(#[from] std::io::Error),
    #[error("data not found: {0}")]
    NotFound(String),
    #[error("Kubernetes ApiWatcher error: {0}")]
    KubernetesApiWatcher(String),
    #[error("system: {0}")]
    SysMonitor(String),
    #[error("environment error: {0}")]
    Environment(String),
    #[error("Nix Errno")]
    Errno(#[from] nix::errno::Errno),
    #[error("ethtool: {0}")]
    Ethtool(String),
    #[error("parse packet failed from: {0}")]
    ParsePacketFailed(String),
    #[error("dns perf parse: {0}")]
    DnsPerfParse(String),
    #[error("dns log parse: {0}")]
    DnsLogParse(String),
    #[error("redis perf parse: {0}")]
    RedisPerfParse(String),
    #[error("redis log parse: {0}")]
    RedisLogParse(String),
    #[error("invalid tpacket version: {0}")]
    InvalidTpVersion(isize),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
