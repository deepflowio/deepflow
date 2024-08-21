
#[derive(Debug, Default, Clone, Serialize)]
pub struct memcached {
    msg_type: LogMessageType,
    
    rtt: u64,

    is_tls: bool,

    req_len: u32,
    resp_len: u32,

    op_code: u32,
    op_code_name: String,

    response_code: u32,
    response: String,

    captured_request_byte: u32,
    captured_response_byte: u32,
    status: L7ResponseStatus,
    is_on_blacklist: bool,
}