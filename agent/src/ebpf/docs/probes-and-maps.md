# Probes

- 性能开销参考

|事件类型|BPF每事件开销(纳秒)|
|-|-|
|kprobe|76|
|kretprobe|212|
|tracepoint(entry)|96|
|tracepoint(exit)|93|
|uprobe|1287|
|uretprobe|1931|

## Kprobes
- __sys_sendmsg
- __sys_sendmmsg
- __sys_recvmsg
- __sys_recvmmsg
- do_writev
- do_readv

## Tracepoint
- tracepoint/syscalls/sys_enter_write
- tracepoint/syscalls/sys_exit_write
- tracepoint/syscalls/sys_enter_read
- tracepoint/syscalls/sys_exit_read 
- tracepoint/syscalls/sys_enter_sendto
- tracepoint/syscalls/sys_exit_sendto
- tracepoint/syscalls/sys_enter_recvfrom
- tracepoint/syscalls/sys_exit_recvfrom 
- tracepoint/syscalls/sys_exit_sendmsg
- tracepoint/syscalls/sys_exit_sendmmsg
- tracepoint/syscalls/sys_exit_recvmsg
- tracepoint/syscalls/sys_exit_recvmmsg
- tracepoint/syscalls/sys_exit_writev
- tracepoint/syscalls/sys_exit_readv
- tracepoint/syscalls/sys_enter_close
- tracepoint/syscalls/sys_enter_getppid
  - 用于超时发送积压的socket data机制
- tracepoint/syscalls/sys_exit_socket
  - 用于管理socket(链接)
- tracepoint/sched/sched_process_fork
  - 用于uprobes管理
- tracepoint/sched/sched_process_exit

## Uprobes
- base
  - runtime.casgstatus (for golang)
  - runtime.newproc1 (for golang)
- http2
  - net/http.(*http2serverConn).writeHeaders
  - golang.org/x/net/http2.(*serverConn).writeHeaders
  - net/http.(*http2serverConn).processHeaders
  - golang.org/x/net/http2.(*serverConn).processHeaders
  - net/http.(*http2clientConnReadLoop).handleResponse
  - golang.org/x/net/http2.(*clientConnReadLoop).handleResponse
  - net/http.(*http2ClientConn).writeHeader
  - net/http.(*http2ClientConn).writeHeaders
  - golang.org/x/net/http2.(*ClientConn).writeHeader
  - golang.org/x/net/http2.(*ClientConn).writeHeaders
- grpc
  - google.golang.org/grpc/internal/transport.(*loopyWriter).writeHeader
  - google.golang.org/grpc/internal/transport.(*http2Client).operateHeaders
  - google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders
- tls (for golang)
  - crypto/tls.(*Conn).Write
  - crypto/tls.(*Conn).Read
- ssl (libopenssl.so)
  - SSL_write
  - SSL_read

# Maps

|名称|类型|Key|Value|作用|
|-|-|-|-|-|
|__socket_data|BPF_MAP_TYPE_PERF_EVENT_ARRAY|int|__u32|利用perf event output buffer传递数据到用户层|
|__data_buf|BPF_MAP_TYPE_PERCPU_ARRAY|__u32|struct __socket_data_buffer|数据是通过burst方式来发送给用户层的，这个map用于积压缓存数据|
|__members_offset|BPF_MAP_TYPE_PERCPU_ARRAY|__u32|struct member_fields_offset|eBPF会不断尝试推断几个关键结构体的成员偏移来完成内核适配，如果成功将会把这些偏移值写到此map中。如果BTF内核信息的文件，初始化话阶段会自动从BTF Raw文件或btf vmlinux文件中直接获取偏移填写到此map中|
|__trace_conf_map|BPF_MAP_TYPE_PERCPU_ARRAY|__u32|struct trace_conf_t|用于记录tracer的配置信息，例如：记录各种UID（traceID，CapSeq等）初始值。|
|__trace_stats_map|BPF_MAP_TYPE_PERCPU_ARRAY|__u32|struct trace_stats|用于统计`trace_map` `__socket_info_map` 的当前容量，用于老化处理（资源回收）|
|__active_write_args_map|BPF_MAP_TYPE_HASH|__u64 {tgid, pid}|struct data_args_t|write() syscall's input argument.|
|__active_read_args_map|BPF_MAP_TYPE_HASH|__u64 {tgid, pid}|struct data_args_t|read() syscall's input argument.|
|__socket_info_map|BPF_MAP_TYPE_HASH|__u64 {pid + fd}|struct socket_info_t|用于记录socket信息|
|__trace_map|BPF_MAP_TYPE_HASH|__u64 {tgid, pid}|struct trace_info_t|用于记录追踪信息|
|__progs_jmp_kp_map|BPF_MAP_TYPE_PROG_ARRAY|__u32|__u32|Tail Calls jmp table for [k/u]probe|
|__progs_jmp_tp_map|BPF_MAP_TYPE_PROG_ARRAY|__u32|__u32|Tail Calls jmp table for tracepoint|
|__allow_port_bitmap|BPF_MAP_TYPE_ARRAY|__u32|struct allow_port_bitmap|服务端口白名单|
|__protocol_filter|BPF_MAP_TYPE_ARRAY|deepflow 定义的 l7 协议号|是否启用的状态标记|标记需要进行分析的协议,关闭无关协议可以提高性能.可以通过 deepflow-server 修改|
|__http2_stack|BPF_MAP_TYPE_PERCPU_ARRAY|-|struct __http2_stack|类似 __socket_data,仅用于处理 go uprobe 获取的 http2 数据|
|tls_conn_map|BPF_MAP_TYPE_HASH|系统中单个协程的标记,由进程号和协程号组合|连接的文件描述符,buffer 指针,栈指针等函数入参信息|用于在进入函数时保存函数参数,并在函数返回时取出参数使用|
|goroutines_map|BPF_MAP_TYPE_HASH|线程号|协程号|保存线程号到协程号的映射,在需要协程号时可以直接根据线程号获取|
|http2_tcp_seq_map|BPF_MAP_TYPE_LRU_HASH|进程号,文件描述符,读操作结束时的序列号|读操作开始前的序列号|在 Go http2 的读操作 hook 点命中时,已经读完 buffer, 导致此时获取的 tcp 序列号相比于此时正在处理的报文更靠后.在比 http2 读操作更下层的 hook 点获读前后的序列号的映射并保存,可以修正成正确的序列号.由于不存在明确的用于回收这个 map 中元素的方法,所以选用 LRU|
|proc_info_map|BPF_MAP_TYPE_HASH|进程号|与该进程相关的偏移量|与 __members_offset 作用类似,__members_offset 保存的是内核中的偏移量,仅需要保存一份.proc_info_map 中保存的是与进程相关的结构体的偏移量,因此需要以进程号为 key 保存在 map 中 >这些值由用户态程序获取并设置到 map 中,由内核态程序使用|
|pid_tgid_callerid_map|BPF_MAP_TYPE_HASH|进程号,线程号|struct go_newproc_caller|在 runtime.newproc1 函数进出时传递参数,用于生成父子协程的映射关系|
|go_rw_ts_map|BPF_MAP_TYPE_LRU_HASH|struct go_key|timestamp when the data was inserted into the map|保存 (线程号,协程号) 到 最近一次读写时间戳 的映射关系,时间戳用于实现读写超时|
|go_ancerstor_map|BPF_MAP_TYPE_LRU_HASH|struct go_key|ancerstor goid|保存父子协程的映射关系|
|__proto_infer_cache_map|BPF_MAP_TYPE_ARRAY|__u32|struct proto_infer_cache_t|Fast matching cache, used to speed up protocol inference. Suitable for Linux5.2+|
|__io_event_buffer|BPF_MAP_TYPE_PERCPU_ARRAY|__u32|struct __io_event_buffer|IO 事件内容通过 struct __socket_data_buffer 格式上报, data 部分保存在这个 map 中,并复制到 __data_buf map|
