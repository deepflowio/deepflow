#[derive(Debug)]
pub enum Error {
    InvalidPacketTimestamp,
    RetransPacket,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
