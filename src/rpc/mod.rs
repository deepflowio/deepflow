mod ntp;
mod session;
mod synchronizer;

pub(crate) use session::{Session, DEFAULT_TIMEOUT};
pub(crate) use synchronizer::{HttpConfig, StaticConfig, Status, Synchronizer};

// todo 用synchronizer ntp 获取timestamp
use std::time::{Duration, SystemTime};
pub fn get_timestamp() -> Duration {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
}
