mod flow_kafka;
mod flow_kafka_log;

pub const PORT: u16 = 9092;

const KAFKA_REQ_HEADER_LEN: usize = 14;
const KAFKA_RESP_HEADER_LEN: usize = 8;
