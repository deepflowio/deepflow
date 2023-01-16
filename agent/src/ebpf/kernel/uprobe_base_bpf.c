/*
 * Copyright (c) 2022 Yunshan Networks
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

#define HASH_ENTRIES_MAX 40960

struct http2_tcp_seq_key {
	int tgid;
	int fd;
	__u32 tcp_seq_end;
};

/*
 * In uprobe_go_tls_read_exit()
 * Save the TCP sequence number before the syscall(read())
 * 
 * In uprobe http2 read() (after syscall read()), lookup TCP sequence number recorded previously on the map.
 * e.g.: In uprobe_go_http2serverConn_processHeaders(), get TCP sequence before syscall read(). 
 * 
 * Note:  Use for after uprobe read() only.
 */
struct bpf_map_def SEC("maps") http2_tcp_seq_map = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct http2_tcp_seq_key),
	.value_size = sizeof(__u32),
	.max_entries = HASH_ENTRIES_MAX,
};

/*
 * The binary executable file offset of the GO process
 * key: pid
 * value: struct ebpf_proc_info
 */
struct bpf_map_def SEC("maps") proc_info_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(struct ebpf_proc_info),
	.max_entries = HASH_ENTRIES_MAX,
};

// Process ID and coroutine ID, marking the coroutine in the system
struct go_key {
	__u32 tgid;
	__u64 goid;
} __attribute__((packed));

// The mapping of coroutines to ancestors, the map is updated when a new
// coroutine is created
// key : current gorouting (struct go_key)
// value : ancerstor goid
struct bpf_map_def SEC("maps") go_ancerstor_map = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct go_key),
	.value_size = sizeof(__u64),
	.max_entries = HASH_ENTRIES_MAX,
};

// Used to determine the timeout, as a termination condition for finding
// ancestors.
// key : current gorouting (struct go_key)
// value: timestamp when the data was inserted into the map
struct bpf_map_def SEC("maps") go_rw_ts_map = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct go_key),
	.value_size = sizeof(__u64),
	.max_entries = HASH_ENTRIES_MAX,
};

// Pass data between coroutine entry and exit functions
struct go_newproc_caller {
	__u64 goid;
	void *sp; // stack pointer
} __attribute__((packed));

struct bpf_map_def SEC("maps") pid_tgid_callerid_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct go_newproc_caller),
	.max_entries = HASH_ENTRIES_MAX,
};

/*
 * Goroutines Map
 * key: {tgid, pid}
 * value: goroutine ID
 */
struct bpf_map_def SEC("maps") goroutines_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__u64),
	.max_entries = MAX_SYSTEM_THREADS,
};

// The first 16 bytes are fixed headers,
// and the total reported buffer does not exceed 1k
#define HTTP2_BUFFER_INFO_SIZE (CAP_DATA_SIZE - 16)
// Make the eBPF validator happy
#define HTTP2_BUFFER_UESLESS (CAP_DATA_SIZE)

struct __http2_buffer {
	__u32 fd;
	__u32 stream_id;
	__u32 header_len;
	__u32 value_len;
	char info[HTTP2_BUFFER_INFO_SIZE + HTTP2_BUFFER_UESLESS];
};

#define SOCKET_DATA_HEADER offsetof(typeof(struct __socket_data), data)

struct __http2_stack {
	union {
		union {
			char __raw[sizeof(struct __socket_data) + 8];
			struct {
				__u32 __unused_events_num;
				__u32 __unused_len;
				char __unused_header[SOCKET_DATA_HEADER];
				struct __http2_buffer http2_buffer;
			} __attribute__((packed));
		};
		struct {
			__u32 events_num;
			__u32 len;
			struct __socket_data send_buffer;
		} __attribute__((packed));
	};
	bool tls;
} __attribute__((packed));

MAP_PERARRAY(http2_stack, __u32, struct __http2_stack, 1)

static __inline struct __http2_stack *get_http2_stack()
{
	int k0 = 0;
	return bpf_map_lookup_elem(&NAME(http2_stack), &k0);
}

static __inline struct __http2_buffer *get_http2_buffer()
{
	struct __http2_stack *stack = get_http2_stack();
	return stack ? (&(stack->http2_buffer)) : NULL;
}

static __inline struct __socket_data *get_http2_send_buffer()
{
	struct __http2_stack *stack = get_http2_stack();
	return stack ? (&(stack->send_buffer)) : NULL;
}

static __inline void update_http2_tls(bool tls)
{
	struct __http2_stack *stack = get_http2_stack();
	if (stack)
		stack->tls = tls;
}

static __inline bool is_http2_tls()
{
	struct __http2_stack *stack = get_http2_stack();
	if (stack)
		return stack->tls;
	return false;
}

// The function address is used to set the hook point. itab is used for http2
// to obtain fd. After directly parsing the Go ELF file, the address of the
// function must be obtained, but the itab may not be obtained.
// 函数地址用于设置 hook 点. itab 用于 http2 获取 fd. 在直接解析 Go ELF 文件后,
// 一定能获取到函数的地址,但是不一定能获取 itab.
static __inline bool skip_http2_kprobe(void)
{
	__u64 id;
	pid_t pid;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	struct ebpf_proc_info *info;
	info = bpf_map_lookup_elem(&proc_info_map, &pid);
	if (!info) {
		return false;
	}
	// must have net_TCPConn_itab
	if (!info->net_TCPConn_itab) {
		return false;
	}
	// HTTP2
	if (info->crypto_tls_Conn_itab) {
		return true;
	}
	// gRPC
	if (info->credentials_syscallConn_itab) {
		return true;
	}
	return false;
}

static __inline __u64 get_current_goroutine(void)
{
	__u64 current_thread = bpf_get_current_pid_tgid();
	__u64 *goid_ptr = bpf_map_lookup_elem(&goroutines_map, &current_thread);
	if (goid_ptr) {
		return *goid_ptr;
	}

	return 0;
}

static __inline bool is_final_ancestor(__u32 tgid, __u64 goid, __u64 now,
				       __u64 timeout)
{
	struct go_key key = { .tgid = tgid, .goid = goid };

	__u64 *ts = bpf_map_lookup_elem(&go_rw_ts_map, &key);
	if (!ts) {
		return false;
	}

	return now < *ts + timeout;
}

// Try to find an ancestor coroutine that can represent this request.
// The ancestor coroutine needs to meet two conditions:
//  1. There have been socket read or write operations in the recent period of time
//  2. All of its ancestor coroutines do not satisfy condition 1
// If no such coroutine exists, mark itself as a coroutine that can represent the request and return.
static __inline __u64 get_rw_goid(__u64 timeout)
{
	__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	__u64 ts = bpf_ktime_get_ns();
	__u64 goid = get_current_goroutine();
	if (goid == 0) {
		return 0;
	}

	__u64 ancestor = goid;

	int idx = 0;
#pragma unroll
	for (idx = 0; idx < 6; ++idx) {
		if (is_final_ancestor(tgid, ancestor, ts, timeout)) {
			return ancestor;
		}
		struct go_key key = { .tgid = tgid, .goid = ancestor };
		__u64 *newancestor =
			bpf_map_lookup_elem(&go_ancerstor_map, &key);
		if (!newancestor) {
			break;
		}
		ancestor = *newancestor;
	}
	struct go_key key = { .tgid = tgid, .goid = goid };
	bpf_map_update_elem(&go_rw_ts_map, &key, &ts, BPF_ANY);
	return goid;
}

static __inline bool is_tcp_conn_interface(void *conn,
					   struct ebpf_proc_info *info)
{
	struct go_interface i;
	bpf_probe_read(&i, sizeof(i), conn);
	return info ? i.type == info->net_TCPConn_itab : false;
}

static __inline int get_fd_from_tcp_conn_interface(void *conn,
						   struct ebpf_proc_info *info)
{
	if (!is_tcp_conn_interface(conn, info)) {
		return -1;
	}

	int offset_fd_sysfd = info->offsets[OFFSET_IDX_SYSFD_POLL_FD];
	if (offset_fd_sysfd < 0)
		return -1;

	struct go_interface i = {};
	void *ptr;
	int fd;

	bpf_probe_read(&i, sizeof(i), conn);
	bpf_probe_read(&ptr, sizeof(ptr), i.ptr);
	bpf_probe_read(&fd, sizeof(fd), ptr + offset_fd_sysfd);
	return fd;
}

static __inline int get_fd_from_tls_conn_struct(void *conn,
						struct ebpf_proc_info *info)
{
	int offset_conn_conn = info->offsets[OFFSET_IDX_CONN_TLS_CONN];
	if (offset_conn_conn < 0)
		return -1;

	return get_fd_from_tcp_conn_interface(conn + offset_conn_conn, info);
}

static __inline bool is_tls_conn_interface(void *conn,
					   struct ebpf_proc_info *info)
{
	struct go_interface i;
	bpf_probe_read(&i, sizeof(i), conn);
	return info ? i.type == info->crypto_tls_Conn_itab : false;
}

static __inline int get_fd_from_tls_conn_interface(void *conn,
						   struct ebpf_proc_info *info)
{
	if (!is_tls_conn_interface(conn, info)) {
		return -1;
	}
	struct go_interface i = {};

	bpf_probe_read(&i, sizeof(i), conn);
	return get_fd_from_tls_conn_struct(i.ptr, info);
}

static __inline int
get_fd_from_tcp_or_tls_conn_interface(void *conn, struct ebpf_proc_info *info)
{
	int fd;
	fd = get_fd_from_tls_conn_interface(conn, info);
	if (fd > 0) {
		update_http2_tls(true);
		return fd;
	}
	fd = get_fd_from_tcp_conn_interface(conn, info);
	if (fd > 0) {
		return fd;
	}
	return -1;
}

// Go implements a new way of passing function arguments and results using 
// registers instead of the stack. We need the go version and the computer
// architecture to determine the parameter locations
static __inline bool is_register_based_call(struct ebpf_proc_info *info)
{
#if defined(__x86_64__)
	// https://go.dev/doc/go1.17
	return info->version >= GO_VERSION(1, 17, 0);
#elif defined(__aarch64__)
	// https://groups.google.com/g/golang-checkins/c/SO9OmZYkOXU
	return info->version >= GO_VERSION(1, 18, 0);
#else
_Pragma("error \"Must specify a BPF target arch\"");
#endif
}

SEC("uprobe/runtime.casgstatus")
int runtime_casgstatus(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;

	struct ebpf_proc_info *info = bpf_map_lookup_elem(&proc_info_map, &tgid);
	if (!info) {
		return 0;
	}
	int offset_g_goid = info->offsets[OFFSET_IDX_GOID_RUNTIME_G];
	if (offset_g_goid < 0) {
		return 0;
	}

	__s32 newval;
	void *g_ptr;

	if (is_register_based_call(info)) {
		g_ptr = (void *)PT_GO_REGS_PARM1(ctx);
		newval = (__s32)PT_GO_REGS_PARM3(ctx);
	} else {
		bpf_probe_read(&g_ptr, sizeof(g_ptr), (void *)(PT_REGS_SP(ctx) + 8));
		bpf_probe_read(&newval, sizeof(newval),
			       (void *)(PT_REGS_SP(ctx) + 20));
	}

	if (newval != 2) {
		return 0;
	}

	__s64 goid = 0;
	bpf_probe_read(&goid, sizeof(goid), g_ptr + offset_g_goid);
	bpf_map_update_elem(&goroutines_map, &pid_tgid, &goid, BPF_ANY);

	return 0;
}

// This function creates a new go coroutine, and the parent and child 
// coroutine numbers are in the parameters and return values ​​respectively.
// Pass the function parameters through pid_tgid_callerid_map
//
// go 1.15 ~ 1.17: func newproc1(fn *funcval, argp unsafe.Pointer, narg int32, callergp *g, callerpc uintptr) *g
// go1.18+ :func newproc1(fn *funcval, callergp *g, callerpc uintptr) *g
SEC("uprobe/enter_runtime.newproc1")
int enter_runtime_newproc1(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;

	struct ebpf_proc_info *info =
		bpf_map_lookup_elem(&proc_info_map, &tgid);
	if (!info) {
		return 0;
	}

	// go less than 1.15 cannot get parent-child coroutine relationship
	// ~ go1.14: func newproc1(fn *funcval, argp unsafe.Pointer, narg int32, callergp *g, callerpc uintptr)
	if (info->version < GO_VERSION(1, 15, 0)) {
		return 0;
	}

	int offset_g_goid = info->offsets[OFFSET_IDX_GOID_RUNTIME_G];
	if (offset_g_goid < 0) {
		return 0;
	}

	void *g_ptr;
	if (is_register_based_call(info)) {
		// https://github.com/golang/go/commit/8e5304f7298a0eef48e4796017c51b4d9aeb52b5
		if (info->version >= GO_VERSION(1, 18, 0)) {
			g_ptr = (void *)PT_GO_REGS_PARM2(ctx);
		} else {
			g_ptr = (void *)PT_GO_REGS_PARM4(ctx);
		}
	} else {
		if (info->version >= GO_VERSION(1, 18, 0)) {
			bpf_probe_read(&g_ptr, sizeof(g_ptr),
				       (void *)(PT_REGS_SP(ctx) + 16));
		} else {
			bpf_probe_read(&g_ptr, sizeof(g_ptr),
				       (void *)(PT_REGS_SP(ctx) + 32));
		}
	}

	__s64 goid = 0;
	bpf_probe_read(&goid, sizeof(goid), g_ptr + offset_g_goid);
	if (!goid) {
		return 0;
	}

	struct go_newproc_caller caller = {
		.goid = goid,
		.sp = (void *)PT_REGS_SP(ctx),
	};
	bpf_map_update_elem(&pid_tgid_callerid_map, &pid_tgid, &caller,
			    BPF_ANY);
	return 0;
}

// The mapping relationship between parent and child coroutines is stored in go_ancerstor_map
//
// go 1.15 ~ 1.17: func newproc1(fn *funcval, argp unsafe.Pointer, narg int32, callergp *g, callerpc uintptr) *g
// go1.18+ :func newproc1(fn *funcval, callergp *g, callerpc uintptr) *g
SEC("uprobe/exit_runtime.newproc1")
int exit_runtime_newproc1(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;

	struct ebpf_proc_info *info =
		bpf_map_lookup_elem(&proc_info_map, &tgid);
	if (!info) {
		return 0;
	}

	if(info->version < GO_VERSION(1, 15, 0)){
		return 0;
	}

	int offset_g_goid = info->offsets[OFFSET_IDX_GOID_RUNTIME_G];
	if (offset_g_goid < 0) {
		return 0;
	}

	struct go_newproc_caller *caller =
		bpf_map_lookup_elem(&pid_tgid_callerid_map, &pid_tgid);
	if (!caller) {
		return 0;
	}

	void *g_ptr;
	if (is_register_based_call(info)) {
		g_ptr = (void *)PT_GO_REGS_PARM1(ctx);
	} else {
		if (info->version >= GO_VERSION(1, 18, 0)) {
			bpf_probe_read(&g_ptr, sizeof(g_ptr), caller->sp + 32);
		} else {
			bpf_probe_read(&g_ptr, sizeof(g_ptr), caller->sp + 48);
		}
	}

	__s64 goid = 0;
	bpf_probe_read(&goid, sizeof(goid), g_ptr + offset_g_goid);
	if (!goid) {
		bpf_map_delete_elem(&pid_tgid_callerid_map, &pid_tgid);
		return 0;
	}

	struct go_key key = { .tgid = tgid, .goid = goid };
	goid = caller->goid;
	bpf_map_update_elem(&go_ancerstor_map, &key, &goid, BPF_ANY);

	bpf_map_delete_elem(&pid_tgid_callerid_map, &pid_tgid);
	return 0;
}

// /sys/kernel/debug/tracing/events/sched/sched_process_exit/format
SEC("tracepoint/sched/sched_process_exit")
int bpf_func_sched_process_exit(struct sched_comm_exit_ctx *ctx)
{
	pid_t pid, tid;
	__u64 id;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (__u32)id;

	// If is a process, clear proc_info_map element and submit event.
	if (pid == tid) {
		bpf_map_delete_elem(&proc_info_map, &pid);
		struct process_event_t data;
		data.pid = pid;
		data.meta.event_type = EVENT_TYPE_PROC_EXIT;
		bpf_get_current_comm(data.name, sizeof(data.name));
		int ret = bpf_perf_event_output(ctx, &NAME(socket_data),
						BPF_F_CURRENT_CPU, &data,
						sizeof(data));

		if (ret) {
			bpf_debug
			    ("bpf_func_sched_process_exit event output failed: %d\n",
			     ret);
		}
	}

	bpf_map_delete_elem(&goroutines_map, &id);
	return 0;
}

// /sys/kernel/debug/tracing/events/sched/sched_process_fork/format
SEC("tracepoint/sched/sched_process_fork")
int bpf_func_sched_process_fork(struct sched_comm_fork_ctx *ctx)
{
	struct process_event_t data;

	data.meta.event_type = EVENT_TYPE_PROC_EXEC;
	data.pid = ctx->child_pid;
	bpf_get_current_comm(data.name, sizeof(data.name));
	int ret = bpf_perf_event_output(ctx, &NAME(socket_data),
					BPF_F_CURRENT_CPU, &data, sizeof(data));

	if (ret) {
		bpf_debug(
			"bpf_func_sys_exit_execve event output() failed: %d\n",
			ret);
	}
	return 0;
}
