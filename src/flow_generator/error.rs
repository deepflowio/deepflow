use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid packet timestamp")]
    InvalidPacketTimestamp,
    #[error("tcp retransmission packet")]
    RetransPacket,
    // call LayerFlowPerf::parse return Error(Layer7 mismatch_response_count)
    #[error("layer7 request not found")]
    L7ReqNotFound(u64),
    #[error("zero payload len")]
    ZeroPayloadLen,
    #[error("invalid ip protocol")]
    InvalidIpProtocol,
    #[error("dubbo header parse failed")]
    DubboHeaderParseFailed,
    #[error("http header parse failed")]
    HttpHeaderParseFailed,
    #[error("kafka log parse failed")]
    KafkaLogParseFailed,
    #[error("kafka perf parse failed")]
    KafkaPerfParseFailed,
    #[error("redis log parse failed")]
    RedisLogParseFailed,
    #[error("redis perf parse failed")]
    RedisPerfParseFailed,
    #[error("mysql log parse failed")]
    MysqlLogParseFailed,
    #[error("mysql perf parse failed")]
    MysqlPerfParseFailed,
    #[error("{0}")]
    DNSLogParseFailed(String),
    #[error("{0}")]
    DNSPerfParseFailed(&'static str),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
