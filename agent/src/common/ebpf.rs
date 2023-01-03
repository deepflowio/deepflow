use serde::Serialize;

//ebpf 上报的数据类型
#[allow(dead_code)]
// tracepoint 类型
pub const SYSCALL: u8 = 0;
#[allow(dead_code)]
// hook 在 to tls 库 Read/Write 获取tls加密前数据,是原始协议报文
pub const GO_TLS_UPROBE: u8 = 1;
#[allow(dead_code)]
// hook在 go 的 http2 ReadHeader/WriteHeader 获取原始头信息
pub const GO_HTTP2_UPROBE: u8 = 2;
#[allow(dead_code)]
// hook in openssl lib
pub const OPENSSL_UPROBE: u8 = 3;
#[allow(dead_code)]
// hook in io event
pub const IO_EVENT: u8 = 4;

const EBPF_TYPE_TRACEPOINT: u8 = 0;
const EBPF_TYPE_TLS_UPROBE: u8 = 1;
const EBPF_TYPE_GO_HTTP2_UPROBE: u8 = 2;
const EBPF_TYPE_IO_EVENT: u8 = 4;
const EBPF_TYPE_NONE: u8 = 255;

// ebpf的类型,由ebpf程序传入,对应 SK_BPF_DATA 的 source 字段
#[derive(Serialize, Debug, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum EbpfType {
    // 常规 tp, 通过 hook 系统调用 read/write 获取到原始报文, l7_protocol_from_ebpf 不可信,目前通过遍历所有支持的协议判断协议类型
    TracePoint = EBPF_TYPE_TRACEPOINT,
    // hook 在 tls 库的 read/write, 获取 tls 加密前的报文, l7_protocol_from_ebpf 不可信,目前通过遍历所有支持的协议判断协议类型
    TlsUprobe = EBPF_TYPE_TLS_UPROBE,
    // hook在 go 的 http2 ReadHeader/WriteHeader
    // l7_protocol_from_ebpf 目前必定是 L7_PROTOCOL_HTTP2 或 L7_PROTOCOL_HTTP2_TLS,数据格式是自定义格式, 可以直接解析,小端编码,数据定义如下:
    /*
    fd(4 bytes)
    stream id (4 bytes)
    header key len (4 bytes)
    header value len (4 bytes)
    header key value (xxx bytes)
    header value value (xxx bytes)
    */
    GoHttp2Uprobe = EBPF_TYPE_GO_HTTP2_UPROBE,
    IOEvent = EBPF_TYPE_IO_EVENT,
    None = EBPF_TYPE_NONE, // 非 ebpf 类型.
}

impl TryFrom<u8> for EbpfType {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            GO_TLS_UPROBE | OPENSSL_UPROBE => Ok(Self::TlsUprobe),
            GO_HTTP2_UPROBE => Ok(Self::GoHttp2Uprobe),
            SYSCALL => Ok(Self::TracePoint),
            IO_EVENT => Ok(Self::IOEvent),
            _ => Err(format!("unknown ebpf type: {}", value)),
        }
    }
}

impl EbpfType {
    // 是否原始协议数据，目前除了GoHttp2Uprobe是自定一数据格式，其他都是原始协议数据。
    // 这个主要用于 ebpf 协议遍历解析的时候快速过滤一些协议，例如GoHttp2Uprobe，除了http以外其他协议都会跳过。
    // ==========================================================================================
    // is raw protocol? now only GoHttp2Uprobe is custom format.
    // it use for fast filter some protocol.
    pub fn is_raw_protocol(&self) -> bool {
        match self {
            EbpfType::GoHttp2Uprobe => false,
            _ => true,
        }
    }
}

impl Default for EbpfType {
    fn default() -> Self {
        Self::None
    }
}
