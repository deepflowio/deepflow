mod decode;
mod flow_redis;
mod flow_redis_log;

pub use flow_redis::RedisPerfData;

pub const PORT: u16 = 6379;
