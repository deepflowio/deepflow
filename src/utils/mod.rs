pub(crate) mod bytes;
pub(crate) mod command;
pub(crate) mod environment;
pub(crate) mod guard;
pub(crate) mod hasher;
pub(crate) mod leaky_bucket;
pub(crate) mod net;
pub(crate) mod process;
pub(crate) mod queue;
pub(crate) mod stats;

// for test
#[cfg(test)]
pub mod test;

const WIN_ERROR_CODE_STR: &str = "please browse website(https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes) to get more detail";
