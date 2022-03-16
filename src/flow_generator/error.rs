#[derive(Debug)]
pub enum Error {
    InvalidPacketTimestamp,
    RetransPacket,
    // call LayerFlowPerf::parse return Error(Layer7 mismatch_response_count)
    L7ReqNotFound(u64),
    ZeroPayloadLen,
    InvaildIpProtocol,
    InvaildL7Protocol,
    L7ParseFailed,
    DubboHeaderParseFailed,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
