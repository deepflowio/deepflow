extern crate libc;
pub use libc::c_char;
pub use libc::c_int;
pub use libc::c_uchar; //u8
pub use libc::c_uint;
pub use std::ffi::{CStr, CString}; //u32

// 最大长度
pub const CAP_LEN_MAX: usize = 512;

//方向
#[allow(dead_code)]
pub const SOCK_DIR_SND: u8 = 0;
#[allow(dead_code)]
pub const SOCK_DIR_RCV: u8 = 1;

//socket协议类型
#[allow(dead_code)]
pub const SOCK_DATA_UNKNOWN: u16 = 0;
#[allow(dead_code)]
pub const SOCK_DATA_HTTP1: u16 = 20;
#[allow(dead_code)]
pub const SOCK_DATA_HTTP2: u16 = 21;
#[allow(dead_code)]
pub const SOCK_DATA_DUBBO: u16 = 40;
#[allow(dead_code)]
pub const SOCK_DATA_MYSQL: u16 = 60;
#[allow(dead_code)]
pub const SOCK_DATA_REDIS: u16 = 80;
#[allow(dead_code)]
pub const SOCK_DATA_KAFKA: u16 = 100;
#[allow(dead_code)]
pub const SOCK_DATA_DNS: u16 = 120;

//L7层协议是否需要重新核实
#[allow(dead_code)]
pub const L7_PROTO_NOT_RECONFIRM: u8 = 0;
#[allow(dead_code)]
pub const L7_PROTO_NEED_RECONFIRM: u8 = 1;

//追踪器当前状态
#[allow(dead_code)]
pub const TRACER_INIT: u8 = 0;
#[allow(dead_code)]
pub const TRACER_RUNNING: u8 = 1;
#[allow(dead_code)]
pub const TRACER_STOP: u8 = 2;

//消息类型
#[allow(dead_code)]
pub const MSG_REQUEST: u8 = 1;
#[allow(dead_code)]
pub const MSG_RESPONSE: u8 = 2;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct tuple_t {
    pub raddr: [u8; 16usize], // 远端IP地址
    pub laddr: [u8; 16usize], // 本地IP地址
    pub addr_len: u8,         // IP地址长度，4：IPV4地址，6：IPV6地址
    pub protocol: u8,         // 协议
    pub rport: u16,           // 远端端口
    pub lport: u16,           // 本地端口
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SK_BPF_DATA {
    /* session info */
    pub process_id: u32, // 进程ID，对应内核tgid
    pub thread_id: u32,  // 线程ID，对应内核pid
    // 如果process_id等于thread_id说明是一个进程，否则是一个线程
    pub process_name: [u8; 16usize], //进程名字，占用16bytes

    pub tuple: tuple_t,        // Socket五元组信息
    pub socket_id: u64, // Socket的唯一标识，从启动时的时钟开始自增1，可用此做hash key代替五元组。
    pub l7_protocal_hint: u16, // 应用数据（cap_data）的协议，取值：SOCK_DATA_*（在上面定义）
    // 存在一定误判性（例如标识为A协议但实际上是未知协议，或标识为多种协议），上层应用应继续深入判断
    pub msg_type: u8, // 信息类型，值为MSG_REQUEST(1), MSG_RESPONSE(2), 需要应用层分析进一步确认。
    pub need_reconfirm: bool, // true: 表示eBPF程序对L7协议类型的判断并不确定需要上层重新核实。
    // false: 表示eBPF程序对L7协议类型的判断是有把握的不需要上层重新核实。

    /* trace info */
    pub tcp_seq: u64, // 收发cap_data数据时TCP协议栈将会用到的TCP SEQ，可用于关联eBPF DATA与网络中的TCP Packet
    /*
     * 应用数据的追踪ID，应用于协程数据转发，L7代理、应用层负载均衡等场景。
     * 值：
     *     从启动时的时钟开始自增1
     * 实现原理：
     *     当应用程序从socket读取数据（Ingress）时，会在hash中做记录
     *       key: 线程ID/进程ID，
     *       Value: UID（追踪的唯一标识ID）
     *     而当向socket写数据（Egress），使用key（线程ID/进程ID）进行查询，从而获得一个先前记录的UID
     *     这样就会和先前的socket ingress的数据关联起来了，从而对同一协程（线程/进程）在不同socket
     *     间的数据转发进行追踪。
     *
     * 注意：
     *     上层经过协议分析得到数据的具体类型：请求/回应，
     *     请求/回应都有各自不同的syscall_trace_id_call。
     */
    pub syscall_trace_id_call: u64,
    /*
     * 应用数据的追踪ID，若应用使用多线程并发模式时，可利用此值追踪一个会话
     * 例如应用为了响应某个请求A而向其他应用发起的多个请求会标记上相同的标识，包括与这些请求关联的响应
     * 值：
     *     从启动时的时钟开始自增1
     * 实现原理：
     *     当应用程序从socket读取数据（Ingress）时，会在hash中做记录
     *       key: 线程ID/进程ID，
     *       Value: UID（追踪的唯一标识ID）+ sock内存地址
     *     在同一个线程ID/进程ID下可能经过多次数据在不同socket间转发，而当向socket写数据（Egress），
     *     使用key（线程ID/进程ID）进行查询得到“UID（追踪的唯一标识ID）+ sock内存地址”，如果这时
     *     查询到的“sock内存地址”与先前记录的“sock内存地址”相等，这样我们就关联了此线程/进程所有转发
     *     的数据。
     */
    pub syscall_trace_id_session: u64,

    /* data info */
    pub timestamp: u64, // cap_data获取的时间戳（从1970.1.1开始到数据捕获时的时间间隔，精度为微妙）
    pub direction: u8,  // 数据的收发方向，值是 SOCK_DIR_SND/SOCK_DIR_RCV

    /*
     * 说明：
     *
     * 当syscall读写数据过大时，eBPF并不会读取所有数据而是有一个最大读取数据大小的限制，
     * 这个长度限制是512字节。
     *
     */
    pub syscall_len: u64,      // 本次系统调用读、写数据的总长度
    pub cap_len: u32,          // 返回的cap_data长度
    pub cap_seq: u64, // cap_data在Socket中的相对顺序号，在所在socket下从0开始自增，用于数据乱序排序
    pub cap_data: *mut c_char, // 内核送到用户空间的数据地址
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SK_TRACE_STATS {
    /*
     * 每一次系统调用向socket读/写数据，都会被eBPF获取，并把此次的
     * 数据传递给用户态接收程序
     * 约定: 把通过eBPF获取一次socket读/写的数据称作'SockData'，
     * 一个‘SockData’包含描述头和数据两部分。
     */

    /*
     * eBPF统计
     */
    pub perf_pages_count: u32,       // perf buffer内存占用的页数量
    pub kern_lost: u64, // perf buffer数据用户态程序来不及接收数据，造成的SockData丢失数量
    pub kern_socket_map_max: u32, // socket追踪的hash表项最大值
    pub kern_socket_map_used: u32, // socket追踪的hash表项当前值
    pub kern_trace_map_max: u32, // 线程追踪会话的hash表项最大值
    pub kern_trace_map_used: u32, // 线程追踪会话的hash表项当前值
    pub socket_map_max_reclaim: u32, // socket map表项进行清理的最大阈值，
    // 当前map的表项数量超过这个值进行map清理操作。

    /*
     * 数据处理统计
     */
    pub worker_num: u16,           // 处理数据的工作线程数量
    pub queue_capacity: u32,       // 单队列容量
    pub mem_alloc_fail_count: u64, // 内存申请（用于为burst-SockDatas申请一块内存）失败次数统计
    pub user_enqueue_count: u64,   // 用户态程序收到内核传过来的入队列的SockData数量
    pub user_dequeue_count: u64,   // 用户态程序处理的SockData数量
    pub user_enqueue_lost: u64,    // 由于队列没有空闲空间使得入队列失败而造成的SockData丢失数量
    pub queue_burst_count: u64, // 通过burst方式进行入队列和出队列，这里统计burst（16个SockData）的次数。

    /*
     * tracer 当前状态
     */
    pub is_adapt_success: bool, // 适配状态：内核适配成功为true，否则为false
    pub tracer_state: u8,       // 追踪器当前状态。值：TRACER_STOP，TRACER_ACTIVE
}

extern "C" {
    // 初始化tracer用于设置eBPF环境初始化。
    // 参数：
    //   log_file  日志文件路径，如果是传递一个空指针将不会有日志写到文件。
    //   is_stdout 日志是否输出到标准输出，true 写到标准输出，false 不写到标准输出。
    // 返回值：
    //   成功返回0，否则返回非0
    pub fn bpf_tracer_init(log_file: *const i8, is_stdout: bool) -> c_int;

    // 所有tracer启动完毕后，最后显示调用bpf_tracer_finish()来通知主程序
    pub fn bpf_tracer_finish();

    // 获取socket_tracer的这种统计数据的接口
    pub fn socket_tracer_stats() -> SK_TRACE_STATS;

    // 参数说明：
    // callback: 回调接口 rust -> C
    // thread_nr: 工作线程数，是指用户态有多少线程参与数据处理。
    // perf_pages_cnt: 和内核共享内存占用的页框数量, 值为2的次幂。
    // ring_size: 环形缓存队列大小，值为2的次幂。
    // max_socket_entries: 设置用于socket追踪的hash表项最大值，取决于实际场景中并发请求数量。
    // max_thread_entries: 设置用于线程追踪会话的hash表项最大值，SK_BPF_DATA结构的syscall_trace_id_session关联这个哈希表
    // socket_map_max_reclaim: socket map表项进行清理的最大阈值，当前map的表项数量超过这个值进行map清理操作。
    // 返回值：成功返回0，否则返回非0
    pub fn running_socket_tracer(
        callback: extern "C" fn(sd: *mut SK_BPF_DATA),
        thread_nr: c_int,
        perf_pages_cnt: c_uint,
        ring_size: c_uint,
        max_socket_entries: c_uint,
        max_thread_entries: c_uint,
        socket_map_max_reclaim: c_uint,
    ) -> c_int;

    // 停止tracer运行
    // 返回值：成功返回0，否则返回非0
    pub fn tracer_stop() -> c_int;

    // 启动tracer运行
    // 返回值：成功返回0，否则返回非0
    pub fn tracer_start() -> c_int;
}
