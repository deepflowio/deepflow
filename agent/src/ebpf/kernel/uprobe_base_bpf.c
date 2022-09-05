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

/*
 * The binary executable file offset of the GO process
 * key: pid
 * value: struct ebpf_proc_info
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct ebpf_proc_info);
	__uint(max_entries, HASH_ENTRIES_MAX);
} proc_info_map SEC(".maps");

/*
 * Goroutines Map
 * key: {tgid, pid}
 * value: goroutine ID
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __s64);
	__uint(max_entries, MAX_SYSTEM_THREADS);
} goroutines_map SEC(".maps");

// The first 16 bytes are fixed headers, 
// and the total reported buffer does not exceed 1k
#define HTTP2_BUFFER_INFO_SIZE (1024 - 16)
// Make the eBPF validator happy
#define HTTP2_BUFFER_UESLESS (1024)

struct __http2_buffer {
	__u32 fd;
	__u32 stream_id;
	__u32 header_len;
	__u32 value_len;
	char info[HTTP2_BUFFER_INFO_SIZE + HTTP2_BUFFER_UESLESS];
};

struct __http2_stack {
	struct __http2_buffer http2_buffer;
	struct __socket_data send_buffer;
	bool tls;
};

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

static __inline struct ebpf_proc_info *get_current_proc_info()
{
	__u64 id;
	pid_t pid;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	struct ebpf_proc_info *info = bpf_map_lookup_elem(&proc_info_map, &pid);
	return info;
}

static __inline int get_uprobe_offset(int offset_idx)
{
	struct ebpf_proc_info *info = get_current_proc_info();
	if (info) {
		return info->offsets[offset_idx];
	}

	return -1;
}

static __inline __u32 get_go_version(void)
{
	__u64 id;
	pid_t pid;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	struct ebpf_proc_info *info;
	info = bpf_map_lookup_elem(&proc_info_map, &pid);
	if (info) {
		return info->version;
	}

	return 0;
}

static __inline int get_runtime_g_goid_offset(void)
{
	return get_uprobe_offset(OFFSET_IDX_GOID_RUNTIME_G);
}

static __inline int get_crypto_tls_conn_conn_offset(void)
{
	return get_uprobe_offset(OFFSET_IDX_CONN_TLS_CONN);
}

static __inline int get_net_poll_fd_sysfd(void)
{
	return get_uprobe_offset(OFFSET_IDX_SYSFD_POLL_FD);
}

static __inline __s64 get_current_goroutine(void)
{
	__u64 current_thread = bpf_get_current_pid_tgid();
	__s64 *goid_ptr = bpf_map_lookup_elem(&goroutines_map, &current_thread);
	if (goid_ptr) {
		return *goid_ptr;
	}

	return 0;
}

static __inline bool is_tcp_conn_interface(void *conn)
{
	struct go_interface i;
	bpf_probe_read(&i, sizeof(i), conn);

	struct ebpf_proc_info *info = get_current_proc_info();
	return info ? i.type == info->net_TCPConn_itab : false;
}

static __inline int get_fd_from_tcp_conn_interface(void *conn)
{
	if (!is_tcp_conn_interface(conn)) {
		return -1;
	}

	int offset_fd_sysfd = get_net_poll_fd_sysfd();
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

static __inline int get_fd_from_tls_conn_struct(void *conn)
{
	int offset_conn_conn = get_crypto_tls_conn_conn_offset();
	if (offset_conn_conn < 0)
		return -1;

	return get_fd_from_tcp_conn_interface(conn + offset_conn_conn);
}

static __inline bool is_tls_conn_interface(void *conn)
{
	struct go_interface i;
	bpf_probe_read(&i, sizeof(i), conn);

	struct ebpf_proc_info *info = get_current_proc_info();
	return info ? i.type == info->crypto_tls_Conn_itab : false;
}

static __inline int get_fd_from_tls_conn_interface(void *conn)
{
	if (!is_tls_conn_interface(conn)) {
		return -1;
	}
	struct go_interface i = {};

	bpf_probe_read(&i, sizeof(i), conn);
	return get_fd_from_tls_conn_struct(i.ptr);
}

static __inline int get_fd_from_tcp_or_tls_conn_interface(void *conn)
{
	int fd;
	fd = get_fd_from_tls_conn_interface(conn);
	if (fd > 0) {
		update_http2_tls(true);
		return fd;
	}
	fd = get_fd_from_tcp_conn_interface(conn);
	if (fd > 0) {
		return fd;
	}
	return -1;
}

SEC("uprobe/runtime.casgstatus")
int runtime_casgstatus(struct pt_regs *ctx)
{
	int offset_g_goid = get_runtime_g_goid_offset();
	if (offset_g_goid < 0) {
		return 0;
	}

	__s32 newval;
	void *g_ptr;

	if (get_go_version() >= GO_VERSION(1, 17, 0)) {
		g_ptr = (void *)(ctx->rax);
		newval = (__s32)(ctx->rcx);
	} else {
		bpf_probe_read(&g_ptr, sizeof(g_ptr), (void *)(ctx->rsp + 8));
		bpf_probe_read(&newval, sizeof(newval),
			       (void *)(ctx->rsp + 20));
	}

	if (newval != 2) {
		return 0;
	}

	__s64 goid = 0;
	bpf_probe_read(&goid, sizeof(goid), g_ptr + offset_g_goid);
	__u64 current_thread = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&goroutines_map, &current_thread, &goid, BPF_ANY);

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

	// If is a process, clear uprobe_offsets_map element and submit event.
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
			bpf_debug(
				"bpf_func_sched_process_exit event outputfaild: %d\n",
				ret);
		}
	}

	bpf_map_delete_elem(&goroutines_map, &id);
	return 0;
}

// /sys/kernel/debug/tracing/events/sched/sched_process_exec/format
SEC("tracepoint/sched/sched_process_exec")
int bpf_func_sched_process_exec(struct sched_comm_exec_ctx *ctx)
{
	struct process_event_t data;
	__u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;
	pid_t tid = (__u32)id;

	if (pid == tid) {
		data.meta.event_type = EVENT_TYPE_PROC_EXEC;
		data.pid = pid;
		bpf_get_current_comm(data.name, sizeof(data.name));
		int ret = bpf_perf_event_output(ctx, &NAME(socket_data),
						BPF_F_CURRENT_CPU, &data,
						sizeof(data));

		if (ret) {
			bpf_debug(
				"bpf_func_sys_exit_execve event output() faild: %d\n",
				ret);
		}
	}

	return 0;
}
