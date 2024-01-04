/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

extern crate libc;

pub use libc::c_char;
pub use libc::c_int;
pub use libc::c_uchar; // u8
pub use libc::c_uint; // u32
pub use libc::c_ulonglong;
use log::info;
pub use std::ffi::{CStr, CString};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// 最大长度
pub const CAP_LEN_MAX: usize = 8192;

// process_kname is up to 16 bytes, if the length of process_kname exceeds 15, the ending char is '\0'
pub const PACKET_KNAME_MAX_PADDING: usize = 15;
pub const CONTAINER_ID_SIZE: usize = 65;

//方向
#[allow(dead_code)]
pub const SOCK_DIR_SND: u8 = 0;
#[allow(dead_code)]
pub const SOCK_DIR_RCV: u8 = 1;

//socket协议类型
#[allow(dead_code)]
pub const SOCK_DATA_UNKNOWN: u16 = 0;
#[allow(dead_code)]
pub const SOCK_DATA_OTHER: u16 = 1;
#[allow(dead_code)]
pub const SOCK_DATA_HTTP1: u16 = 20;
#[allow(dead_code)]
pub const SOCK_DATA_HTTP2: u16 = 21;
#[allow(dead_code)]
pub const SOCK_DATA_TLS_HTTP1: u16 = 22;
#[allow(dead_code)]
pub const SOCK_DATA_TLS_HTTP2: u16 = 23;
#[allow(dead_code)]
pub const SOCK_DATA_DUBBO: u16 = 40;
#[allow(dead_code)]
pub const SOCK_DATA_SOFARPC: u16 = 43;
#[allow(dead_code)]
pub const SOCK_DATA_FASTCGI: u16 = 44;
#[allow(dead_code)]
pub const SOCK_DATA_MYSQL: u16 = 60;
#[allow(dead_code)]
pub const SOCK_DATA_POSTGRESQL: u16 = 61;
#[allow(dead_code)]
pub const SOCK_DATA_ORACLE: u16 = 62;
#[allow(dead_code)]
pub const SOCK_DATA_REDIS: u16 = 80;
#[allow(dead_code)]
pub const SOCK_DATA_MONGO: u16 = 81;
#[allow(dead_code)]
pub const SOCK_DATA_KAFKA: u16 = 100;
#[allow(dead_code)]
pub const SOCK_DATA_MQTT: u16 = 101;
#[allow(dead_code)]
pub const SOCK_DATA_DNS: u16 = 120;
#[allow(dead_code)]
pub const SOCK_DATA_TLS: u16 = 121;

// Feature
#[allow(dead_code)]
pub const FEATURE_UPROBE_GOLANG_SYMBOL: c_int = 0;
#[allow(dead_code)]
pub const FEATURE_UPROBE_OPENSSL: c_int = 1;
#[allow(dead_code)]
pub const FEATURE_UPROBE_GOLANG: c_int = 2;

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
#[allow(dead_code)]
pub const TRACER_WAIT_START: u8 = 3;
#[allow(dead_code)]
pub const TRACER_START_ERR: u8 = 4;
#[allow(dead_code)]
pub const TRACER_WAIT_STOP: u8 = 5;
#[allow(dead_code)]
pub const TRACER_STOP_ERR: u8 = 6;

// Identifying data source
#[allow(dead_code)]
pub const DATA_SOURCE_SYSCALL: u8 = 0;
#[allow(dead_code)]
pub const DATA_SOURCE_GO_TLS_UPROBE: u8 = 1;
#[allow(dead_code)]
pub const DATA_SOURCE_GO_HTTP2_UPROBE: u8 = 2;
#[allow(dead_code)]
pub const DATA_SOURCE_OPENSSL_UPROBE: u8 = 3;
#[allow(dead_code)]
pub const DATA_SOURCE_IO_EVENT: u8 = 4;

// 消息类型
// 目前除了 source=EBPF_TYPE_GO_HTTP2_UPROBE 以外,都不能保证这个方向的正确性.
// go http2 uprobe 目前 只用了MSG_RESPONSE_END, 用于判断流结束.
#[allow(dead_code)]
pub const MSG_REQUEST: u8 = 1;
#[allow(dead_code)]
pub const MSG_RESPONSE: u8 = 2;
#[allow(dead_code)]
pub const MSG_REQUEST_END: u8 = 3;
#[allow(dead_code)]
pub const MSG_RESPONSE_END: u8 = 4;

//Register event types
#[allow(dead_code)]
pub const EVENT_TYPE_PROC_EXEC: u32 = 1 << 5;
#[allow(dead_code)]
pub const EVENT_TYPE_PROC_EXIT: u32 = 1 << 6;

//Process exec/exit events
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PROCESS_EVENT {
    pub event_type: u32,     // value: EVENT_TYPE_PROC_EXEC or EVENT_TYPE_PROC_EXIT
    pub pid: u32,            // Process ID
    pub name: [u8; 16usize], // Process name
}

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
    pub process_id: u32,   // tgid in kernel struct task_struct
    pub thread_id: u32,    // pid in kernel struct task_struct, main thread iff pid==tgid
    pub coroutine_id: u64, // CoroutineID, i.e., golang goroutine id
    pub source: u8,        // Value is DATA_SOURCE_*

    pub process_kname: [u8; PACKET_KNAME_MAX_PADDING + 1], // comm in task_struct, always 16 bytes
    pub container_id: [u8; CONTAINER_ID_SIZE],             // container id
    pub tuple: tuple_t,                                    // Socket五元组信息

    /*
     * 为每一个数据通信的套接字创建唯一的ID，可用于流标识。
     * socket_id组成：
     *
     * |--CPU-ID(8bit)--|------------ UID-MAIN(56bit) --------------|
     *
     * 1 CPU-ID: 高8位，CPU的ID号。
     * 2 UID-MAIN: 低56位，由eBPF程序启动时的时钟作为基值开始自增。
     *
     * 上面保证任何时刻启动程序在当前机器下获取的socket_id都是唯一的。
     */
    pub socket_id: u64,
    pub l7_protocol_hint: u16, // 应用数据（cap_data）的协议，取值：SOCK_DATA_*（在上面定义）
    // 存在一定误判性（例如标识为A协议但实际上是未知协议，或标识为多种协议），上层应用应继续深入判断
    // 目前只有 source=EBPF_TYPE_GO_HTTP2_UPROBE 时,msg_type的判断是准确的.
    pub msg_type: u8, // 信息类型，值为MSG_REQUEST(1), MSG_RESPONSE(2), 需要应用层分析进一步确认。
    pub need_reconfirm: bool, // true: 表示eBPF程序对L7协议类型的判断并不确定需要上层重新核实。
    // false: 表示eBPF程序对L7协议类型的判断是有把握的不需要上层重新核实。
    pub is_tls: bool,

    /* trace info */
    pub tcp_seq: u64, // 收发cap_data数据时TCP协议栈将会用到的TCP SEQ，可用于关联eBPF DATA与网络中的TCP Packet
    /*
     * 应用数据的追踪ID，应用于数据转发，L7代理、应用层负载均衡等场景。
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
    pub socket_role: u8, // this message is created by: 0:unkonwn 1:client(connect) 2:server(accept)
    pub cap_data: *mut c_char, // 内核送到用户空间的数据地址
}

impl fmt::Display for SK_BPF_DATA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (local_ip, remote_ip) = if self.tuple.addr_len == 4 {
            (
                {
                    let addr: [u8; 4] = self.tuple.laddr[..4].try_into().unwrap();
                    IpAddr::from(Ipv4Addr::from(addr))
                },
                {
                    let addr: [u8; 4] = self.tuple.raddr[..4].try_into().unwrap();
                    IpAddr::from(Ipv4Addr::from(addr))
                },
            )
        } else {
            (
                IpAddr::from(Ipv6Addr::from(self.tuple.laddr)),
                IpAddr::from(Ipv6Addr::from(self.tuple.raddr)),
            )
        };
        let (src_ip, dst_ip) = if self.direction == SOCK_DIR_SND {
            (local_ip, remote_ip)
        } else {
            (remote_ip, local_ip)
        };
        let (port_src, port_dst) = if self.direction == SOCK_DIR_SND {
            (self.tuple.lport, self.tuple.rport)
        } else {
            (self.tuple.rport, self.tuple.lport)
        };
        unsafe {
            #[cfg(target_arch = "aarch64")]
            let process_kname = CStr::from_ptr(self.process_kname.as_ptr() as *const u8)
                .to_str()
                .unwrap();

            #[cfg(target_arch = "x86_64")]
            let process_kname = CStr::from_ptr(self.process_kname.as_ptr() as *const i8)
                .to_str()
                .unwrap();

            let data_slice =
                std::slice::from_raw_parts(self.cap_data, self.cap_len.min(32) as usize);
            let data_bytes = &*(data_slice as *const [c_char] as *const [u8]);

            write!(
                f,
                "Timestamp: {} Socket: {} CapSeq: {} Process: {}:{} Thread: {} MsgType: {} Direction: {} \n \
                \t{}_{} -> {}_{} Seq: {} Trace-ID: {} L7: {} TLS: {:?} Data {:?}",
                self.timestamp,
                self.socket_id,
                self.cap_seq,
                process_kname,
                self.process_id,
                self.thread_id,
                self.msg_type,
                self.direction,
                src_ip,
                port_src,
                dst_ip,
                port_dst,
                self.tcp_seq,
                self.syscall_trace_id_call,
                self.l7_protocol_hint,
                self.is_tls,
                data_bytes
            )
        }
    }
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
    pub kern_trace_map_max: u32, // 线程/协程追踪会话的hash表项最大值
    pub kern_trace_map_used: u32, // 线程/协程追踪会话的hash表项当前值
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
    pub tracer_state: u8,       // 追踪器当前状态。值：TRACER_INIT, TRACER_STOP，TRACER_RUNNING,
    // TRACER_WAIT_START, TRACER_START_ERR, TRACER_WAIT_STOP, TRACER_STOP_ERR

    /*
     * 纳秒级系统启动时间每分钟进行一次更新，
     * 这里用于记录相邻两次更新后，系统启动时间之间的差异（单位为纳秒）。
     * boot_time_update_diff（ns）= 本次更新后的系统启动时间(ns) - 上次更新后的系统启动时间(ns)
     */
    pub boot_time_update_diff: i64,
    // How many probes now
    pub probes_count: u32,
    // Maximum length limit of eBPF data transmission
    pub data_limit_max: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct stack_profile_data {
    pub timestamp: u64, // Timestamp of the stack trace data(unit: nanoseconds).
    pub pid: u32,       // User-space process-ID.
    /*
     * Identified within the eBPF program in kernel space.
     * If the current is a process and not a thread this field(tid) is filled
     * with the ID of the process.
     */
    pub tid: u32,
    pub stime: u64,      // The start time of the process is measured in milliseconds.
    pub netns_id: u64,   // Fetch from /proc/<PID>/ns/net
    pub u_stack_id: u32, // User space stackID.
    pub k_stack_id: u32, // Kernel space stackID.
    pub cpu: u32,        // The captured stack trace data is generated on which CPU?
    /*
     * The profiler captures the number of occurrences of the same
     * data by querying with the quadruple
     * "<pid + stime + u_stack_id + k_stack_id + tid + cpu>" as the key.
     */
    pub count: u32,
    /*
     * comm in task_struct(linux kernel), always 16 bytes
     * If the capture is a process, fill in the process name here.
     * If the capture is a thread, fill in the thread name.
     */
    pub comm: [u8; PACKET_KNAME_MAX_PADDING + 1],
    pub process_name: [u8; PACKET_KNAME_MAX_PADDING + 1], // process name
    pub container_id: [u8; CONTAINER_ID_SIZE],            // container id
    pub stack_data_len: u32,                              // stack data length

    /*
     * Example of a folded stack trace string (taken from a perf profiler test):
     * main;xxx();yyy()
     * It is a list of symbols corresponding to addresses in the underlying stack trace,
     * separated by ';'.
     *
     * The merged folded stack trace string style for user space and kernel space would be:
     * <user space folded stack trace string> + ";" + <kernel space folded stack trace string>
     */
    pub stack_data: *mut c_char,
}

extern "C" {
    /*
     * Set maximum amount of data passed to the agent by eBPF programe.
     * @limit_size : The maximum length of data. If @limit_size exceeds 8192,
     *               it will automatically adjust to 8192 bytes.
     *               If limit_size is 0, use the default values 4096.
     *
     * @return the set maximum buffer size value on success, < 0 on failure.
     */
    pub fn set_data_limit_max(limit_size: c_int) -> c_int;
    pub fn set_go_tracing_timeout(timeout: c_int) -> c_int;
    pub fn set_io_event_collect_mode(mode: c_int) -> c_int;
    pub fn set_io_event_minimal_duration(duration: c_ulonglong) -> c_int;
    pub fn set_allow_port_bitmap(bitmap: *const c_uchar) -> c_int;
    pub fn set_bypass_port_bitmap(bitmap: *const c_uchar) -> c_int;
    pub fn enable_ebpf_protocol(protocol: c_int) -> c_int;
    pub fn set_feature_regex(idx: c_int, pattern: *const c_char) -> c_int;
    /*
     * Configuring application layer protocol ports
     *
     * When 'l7-protocol-enabled' includes application layer protocol types,
     * 'l7-protocol-ports' specifies the port numbers or port number ranges
     * for these protocols. eBPF will perform protocol inference on the
     * specified port numbers for a given protocol. If a protocol's port number
     * is not within the configured range, inference for that protocol will not
     * be performed.
     *
     * Parameters:
     * @proto_type: Protocol type, e.g., SOCK_DATA_HTTP1/SOCK_DATA_HTTP2 ...
     * @ports: Port range, e.g., "443, 4467-5678"
     *
     * @return: Returns 0 on success, a non-zero value on error.
     *
     * For example, with the following configuration:
     * ```
     * l7-protocol-enabled:
     *    TLS
     * l7-protocol-ports:
     *    "TLS": "443, 4467-5678"
     * ```
     * During the eBPF protocol inference phase, TLS protocol inference will be
     * performed on the port numbers and range "443, 4467-5678." If the inference
     * fails, data will be discarded.
     *
     * Note: that the default value for 'TLS' in 'l7-protocol-ports' is "443".
     */
    pub fn set_protocol_ports_bitmap(proto_type: c_int, ports: *const c_char) -> c_int;

    // 初始化tracer用于设置eBPF环境初始化。
    // 参数：
    //   log_file  日志文件路径，如果是传递一个空指针将不会有日志写到文件。
    //   is_stdout 日志是否输出到标准输出，true 写到标准输出，false 不写到标准输出。
    // 返回值：
    //   成功返回0，否则返回非0
    #[cfg(target_arch = "x86_64")]
    pub fn bpf_tracer_init(log_file: *const i8, is_stdout: bool) -> c_int;
    #[cfg(target_arch = "aarch64")]
    pub fn bpf_tracer_init(log_file: *const u8, is_stdout: bool) -> c_int;

    // 所有tracer启动完毕后，最后显示调用bpf_tracer_finish()来通知主程序
    pub fn bpf_tracer_finish();

    // 获取socket_tracer的这种统计数据的接口
    pub fn socket_tracer_stats() -> SK_TRACE_STATS;

    // Register extra event handle for socket tracer
    // @event_type : register event type, e.g.: EVENT_TYPE_PROC_EXEC or EVENT_TYPE_PROC_EXIT ...
    // @callback : Callback function for event
    // @return 0 is success, if not 0 is failed
    pub fn register_event_handle(
        event_type: c_uint,
        callback: extern "C" fn(data: *mut PROCESS_EVENT),
    ) -> c_int;

    // 参数说明：
    // callback: 回调接口 rust -> C
    // thread_nr: 工作线程数，是指用户态有多少线程参与数据处理。
    // perf_pages_cnt: 和内核共享内存占用的页框数量, 值为2的次幂。
    // ring_size: 环形缓存队列大小，值为2的次幂。
    // max_socket_entries: 设置用于socket追踪的hash表项最大值，取决于实际场景中并发请求数量。
    // max_trace_entries: 设置用于线程/协程追踪会话的hash表项最大值。
    // socket_map_max_reclaim: socket map表项进行清理的最大阈值，当前map的表项数量超过这个值进行map清理操作。
    // 返回值：成功返回0，否则返回非0
    pub fn running_socket_tracer(
        callback: extern "C" fn(sd: *mut SK_BPF_DATA),
        thread_nr: c_int,
        perf_pages_cnt: c_uint,
        ring_size: c_uint,
        max_socket_entries: c_uint,
        max_trace_entries: c_uint,
        socket_map_max_reclaim: c_uint,
    ) -> c_int;

    // 停止tracer运行
    // 返回值：成功返回0，否则返回非0
    pub fn socket_tracer_stop() -> c_int;

    // 启动tracer运行
    // 返回值：成功返回0，否则返回非0
    pub fn socket_tracer_start() -> c_int;

    // 注意：eBPF tracer初始化加载运行后进行内核适配，
    // 适配完成后马上进入stop状态，需调用socket_tracer_start()才开始工作。

    /*
     * start continuous profiler
     * @freq sample frequency, Hertz. (e.g. 99 profile stack traces at 99 Hertz)
     * @java_syms_space_limit The maximum space occupied by the Java symbol files
     *   in the '/' directory of the target POD container.The recommended range for
     *   values is [2, 100], which means it falls within the interval of 2Mi to 100Mi.
     *   If the configuration value is outside this range, the default value of
     *   10(10Mi), will be used.
     * @java_syms_update_delay To allow Java to run for an extended period and gather
     *   more symbol information, we delay symbol retrieval when encountering unknown
     *   symbols. The unit of measurement used is seconds.
     *   The recommended range for values is [5, 3600], default valuse is 60.
     * @callback Profile data processing callback interface
     * @returns 0 on success, < 0 on error
     */
    pub fn start_continuous_profiler(
        freq: c_int,
        java_syms_space_limit: c_int,
        java_syms_update_delay: c_int,
        callback: extern "C" fn(_data: *mut stack_profile_data),
    ) -> c_int;

    /*
     * stop continuous profiler
     * @returns 0 on success, < 0 on error
     */
    pub fn stop_continuous_profiler() -> c_int;

    /*
     * To set the regex matching for the profiler.
     *
     * Perform regular expression matching on process names.
     * Processes that successfully match the regular expression are
     * aggregated using the key:
     *     `{pid + stime + u_stack_id + k_stack_id + tid + cpu}`.
     *
     * For processes that do not match, they are aggregated using the
     * key:
     *     `<process name + u_stack_id + k_stack_id + cpu>`.
     *
     * Using regular expressions, we match process names to establish
     * symbol table caching for specific processes, rather than enabling
     * symbol caching for all processes. This approach aims to reduce
     * memory usage.
     *
     * For example:
     *
     *  "^(java|nginx|profiler|telegraf|mysqld|socket_tracer|.*deepflow.*)$"
     *
     * This regex pattern matches the process names: "java", "nginx", "profiler",
     * "telegraf", "mysqld", "socket_tracer", and any process containing the
     * substring "deepflow".
     *
     * By using this interface, you can customize the regular expression to
     * match specific process names that you want to establish symbol table
     * caching for, providing flexibility and control over which processes will
     * have symbol caching enabled. This allows you to finetune the memory usage
     * and profiling behavior of the profiler according to your requirements.
     *
     * The default expression is empty (''), indicating that no profile data will
     * be generated.
     *
     * @pattern : Regular expression pattern. e.g. "^(java|nginx|.*ser.*)$"
     * @returns 0 on success, < 0 on error
     */
    pub fn set_profiler_regex(pattern: *const c_char) -> c_int;

    /*
     * This interface is used to set whether CPUID should be included in the
     * aggregation of stack trace data.
     *
     * @flag:
     *   If the flag is set to 1, CPUID will be included in the aggregation
     *   of stack trace data. If the flag is set to 0, it will not be incl-
     *   uded in the aggregation. Any other value is considered invalid.
     *
     * The profiler startup will be set to 0 by default.
     *
     * @returns 0 on success, < 0 on error
     *
     * Note:
     *   If flag=0, the CPU value for stack trace data reporting is a special
     *   value (CPU_INVALID:0xfff) used to indicate that it is an invalid value.
     */
    pub fn set_profiler_cpu_aggregation(flag: c_int) -> c_int;

    /*
     * test flame graph
     */
    pub fn process_stack_trace_data_for_flame_graph(_data: *mut stack_profile_data);
    pub fn release_flame_graph_hash();

    /*
     * Configure and enable datadump - Send socket data obtained by eBPF to the controller.
     *
     * @pid
     *   Specifying a process ID or thread ID. If set to '0', it indicates
     *   all processes or threads.
     * @comm
     *   Specifying a process name or thread name. If set to an empty string(""),
     *   it indicates all processes or threads.
     * @proto
     *   Specifying the L7 protocol number. If set to '0', it indicates all
     *   L7 protocols.
     * @timeout
     *   Specifying the timeout duration. If the elapsed time exceeds this
     *   duration, datadump will stop. The unit is in seconds.
     * @callback
     *   Callback interface, used to transfer data to the remote controller.
     *
     * @return 0 on success, and a negative value on failure.
     */
    pub fn datadump_set_config(
        pid: c_int,
        comm: *const c_char,
        proto: c_int,
        timeout: c_int,
        callback: extern "C" fn(data: *mut c_char, len: c_int),
    ) -> c_int;

    /*
     * Configure and enable the debugging functionality for Continuous Profiling.
     *
     * @timeout
     *   Specifying the timeout duration. If the elapsed time exceeds this
     *   duration, cpdbg will stop. The unit is in seconds.
     * @callback
     *   Callback interface, used to transfer data to the remote controller.
     *
     * @return 0 on success, and a negative value on failure.
     */
    pub fn cpdbg_set_config(
        timeout: c_int,
        callback: extern "C" fn(data: *mut c_char, len: c_int),
    ) -> c_int;
}

#[no_mangle]
extern "C" fn rust_info_wrapper(msg: *const libc::c_char) {
    let msg_str: &str = unsafe { std::ffi::CStr::from_ptr(msg).to_str().unwrap() };
    info!("{}", msg_str);
}
