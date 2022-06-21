mod ntp;
mod session;
mod synchronizer;

pub(crate) use session::{Session, DEFAULT_TIMEOUT};
pub(crate) use synchronizer::{StaticConfig, Status, Synchronizer};

use std::time::{Duration, SystemTime};

pub fn get_timestamp(ntp_diff: i64) -> Duration {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64 as i64
        + ntp_diff;
    Duration::from_nanos(now as u64)
}
