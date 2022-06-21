use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    BinCodeDecode(#[from] bincode::error::DecodeError),
    #[error(transparent)]
    BinCodeEncode(#[from] bincode::error::EncodeError),
    #[error(transparent)]
    Tonic(#[from] tonic::Status),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("{0}")]
    NotFound(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
