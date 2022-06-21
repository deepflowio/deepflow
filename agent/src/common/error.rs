use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    ParseCidr(String),
    #[error("{0}")]
    ParseIpGroupData(String),
    #[error("{0}")]
    ParsePlatformData(String),
}
