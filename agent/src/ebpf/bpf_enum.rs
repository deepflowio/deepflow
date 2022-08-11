use super::{GO_HTTP2_UPROBE, GO_TLS_UPROBE};

const EBPF_TYPE_TRACEPOINT: u8 = 0;
const EBPF_TYPE_TLS_UPROBE: u8 = 1;
const EBPF_TYPE_GO_HTTP2_UPROBE: u8 = 2;
const EBPF_TYPE_NONE: u8 = 255;

// ebpf的类型,由ebpf程序传入,对应 SK_BPF_DATA 的 source 字段
#[derive(Debug, PartialEq, Copy, Clone)]
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
    None = EBPF_TYPE_NONE, // 非 ebpf 类型.
}

impl EbpfType {
    pub fn from(v: u8) -> Self {
        match v {
            GO_TLS_UPROBE => Self::TlsUprobe,
            GO_HTTP2_UPROBE => Self::GoHttp2Uprobe,
            _ => {
                // 默认当作tracepoint
                Self::TracePoint
            }
        }
    }
}

impl Default for EbpfType {
    fn default() -> Self {
        return Self::TracePoint;
    }
}
