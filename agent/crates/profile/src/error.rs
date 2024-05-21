use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    FileReadError(#[from] std::io::Error),
    #[error(transparent)]
    ElfReadError(#[from] object::Error),
    #[error(transparent)]
    ElfParseError(#[from] gimli::Error),
    #[error(".eh_frame section not found in object file")]
    NoEhFrame,
}

pub type Result<T> = std::result::Result<T, Error>;
