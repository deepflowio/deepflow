#[derive(Debug)]
pub enum Error {
    InvalidPacketTimestamp,
    RetransPacket,
    // call LayerFlowPerf::parse return Error(Layer7 error msg and mismatch_response_count)
    InvalidL7Payload((String, u64)),
    ZeroPayloadLen,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
