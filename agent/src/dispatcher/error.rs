use num_enum::{TryFromPrimitive, TryFromPrimitiveError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("dispatcher config incomplete: {0}")]
    ConfigIncomplete(String),
    #[error("dispatcher config invalid: {0}")]
    ConfigInvalid(String),
    #[error("packet parse failed: {0}")]
    PacketInvalid(String),
    #[error("dispatcher stats collector: {0}")]
    StatsCollector(&'static str),
}

impl<T: TryFromPrimitive> From<TryFromPrimitiveError<T>> for Error {
    fn from(e: TryFromPrimitiveError<T>) -> Self {
        Error::PacketInvalid(e.to_string())
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
