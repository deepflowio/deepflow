#[derive(Debug)]
pub enum Error {
    InvalidPacketTimestamp,
    RetransPacket,
    // call LayerFlowPerf::parse return Error(Layer7 mismatch_response_count)
    L7ResponseNotFound(u64),
    ZeroPayloadLen,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
