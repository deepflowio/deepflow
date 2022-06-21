use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("parse mac address failed: {0}")]
    ParseMacFailed(String),
    #[error("neighbor lookup failed from: {0}")]
    NeighborLookup(String),
    #[error("link not found: {0}")]
    LinkNotFound(String),
    #[error("link not found index: {0}")]
    LinkNotFoundIndex(u32),
    #[error("link regex invalid")]
    LinkRegexInvalid(#[from] regex::Error),
    #[error("netlink error")]
    NetLinkError(#[from] neli::err::NlError),
    #[error("IO error")]
    IoError(#[from] std::io::Error),
    #[error("no route to host: {0}")]
    NoRouteToHost(String),
    #[error("Windows related error:{0}")]
    Windows(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
