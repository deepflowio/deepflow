use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid tpacket version: {0}")]
    InvalidTpVersion(isize),
    #[error("IO error")]
    IoError(#[from] std::io::Error),
    #[error("link error: {0}")]
    LinkError(String),
    #[error("option invalid: {0}")]
    InvalidOption(&'static str),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
