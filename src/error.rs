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
    IO(#[from] std::io::Error),
    #[error("data not found: {0}")]
    NotFound(String),
    #[error("Windows related error:{0}")]
    Windows(String),
    #[error("Kubernetes ApiWatcher error: {0}")]
    KubernetesApiWatcher(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
