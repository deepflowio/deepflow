use thiserror::Error;

use crate::config::ConfigError;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    BinCode(#[from] bincode::Error),
    #[error(transparent)]
    Tonic(#[from] tonic::Status),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("{0}")]
    NotFound(String),
    #[error(transparent)]
    ProstDecode(#[from] prost::DecodeError),
    #[error(transparent)]
    ProstEncode(#[from] prost::EncodeError),
    #[error(transparent)]
    ConfigError(#[from] ConfigError),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
