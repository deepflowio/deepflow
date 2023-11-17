/*
 * This code runs using bpf in the Linux kernel.
 * Copyright 2022- The Yunshan Networks Authors.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

static __inline void *get_the_first_parameter(struct pt_regs *ctx,
					      struct ebpf_proc_info *info)
{
	void *ptr;
	if (is_register_based_call(info)) {
		ptr = (void *)PT_GO_REGS_PARM1(ctx);
	} else {
		bpf_probe_read(&ptr, sizeof(ptr), (void *)(PT_REGS_SP(ctx) + 8));
	}
	return ptr;
}

static __inline bool is_grpc_syscallConn_interface(void *ptr,
						   struct ebpf_proc_info *info)
{
	struct go_interface i;
	bpf_probe_read(&i, sizeof(i), ptr);
	return info ? i.type == info->credentials_syscallConn_itab : false;
}

static __inline int get_fd_from_http2serverConn_ctx(struct pt_regs *ctx,
						    struct ebpf_proc_info *info)
{
	update_http2_tls(false);
	void *ptr = get_the_first_parameter(ctx, info);
	ptr += info->offsets[OFFSET_IDX_CONN_HTTP2_SERVER_CONN];
	return get_fd_from_tcp_or_tls_conn_interface(ptr, info);
}

static __inline int get_fd_from_http2ClientConn(void *ptr,
						struct ebpf_proc_info *info)
{
	update_http2_tls(false);
	ptr += info->offsets[OFFSET_IDX_TCONN_HTTP2_CLIENT_CONN];
	return get_fd_from_tcp_or_tls_conn_interface(ptr, info);
}

static __inline int get_fd_from_http2ClientConn_ctx(struct pt_regs *ctx,
						    struct ebpf_proc_info *info)
{
	void *ptr = get_the_first_parameter(ctx, info);
	return get_fd_from_http2ClientConn(ptr, info);
}

static __inline int
get_fd_from_grpc_http2Client_ctx(struct pt_regs *ctx,
				 struct ebpf_proc_info *info)
{
	update_http2_tls(false);
	void *ptr = get_the_first_parameter(ctx, info);
	ptr += info->offsets[OFFSET_IDX_CONN_GRPC_HTTP2_CLIENT];
	if (is_grpc_syscallConn_interface(ptr, info)) {
		update_http2_tls(true);
		struct go_interface i;
		bpf_probe_read(&i, sizeof(i), ptr);
		bpf_probe_read(&i, sizeof(i), i.ptr);
		ptr = i.ptr;
	}
	return get_fd_from_tcp_or_tls_conn_interface(ptr, info);
}

static __inline int
get_fd_from_grpc_http2Server_ctx(struct pt_regs *ctx,
				 struct ebpf_proc_info *info)
{
	update_http2_tls(false);
	void *ptr = get_the_first_parameter(ctx, info);
	ptr += info->offsets[OFFSET_IDX_CONN_GRPC_HTTP2_SERVER];
	if (is_grpc_syscallConn_interface(ptr, info)) {
		update_http2_tls(true);
		struct go_interface i;
		bpf_probe_read(&i, sizeof(i), ptr);
		bpf_probe_read(&i, sizeof(i), i.ptr);
		ptr = i.ptr;
	}
	return get_fd_from_tcp_or_tls_conn_interface(ptr, info);
}

static __inline int get_side_from_grpc_loopyWriter(struct pt_regs *ctx,
						   struct ebpf_proc_info *info)
{
	void *ptr = get_the_first_parameter(ctx, info);

	ptr += info->offsets[OFFSET_IDX_SIDE_GRPC_TRANSPORT_LOOPY_WRITER];
	int side = 0;
	bpf_probe_read(&side, sizeof(side), ptr);
	return side;
}

static __inline int get_fd_from_grpc_loopyWriter(struct pt_regs *ctx,
						 struct ebpf_proc_info *info)
{
	update_http2_tls(false);
	void *ptr = get_the_first_parameter(ctx, info);

	ptr += info->offsets[OFFSET_IDX_FRAMER_GRPC_TRANSPORT_LOOPY_WRITER];
	bpf_probe_read(&ptr, sizeof(ptr), ptr);
	ptr += info->offsets[OFFSET_IDX_WRITER_GRPC_TRANSPORT_FRAMER];
	bpf_probe_read(&ptr, sizeof(ptr), ptr);
	ptr += info->offsets[OFFSET_IDX_CONN_GRPC_TRANSPORT_BUFWRITER];

	if (is_grpc_syscallConn_interface(ptr, info)) {
		update_http2_tls(true);
		struct go_interface i;
		bpf_probe_read(&i, sizeof(i), ptr);
		bpf_probe_read(&i, sizeof(i), i.ptr);
		ptr = i.ptr;
	}
	return get_fd_from_tcp_or_tls_conn_interface(ptr, info);
}

struct go_http2_header_field {
	struct go_string name;
	struct go_string value;
	bool sensitive;
};

static __inline void *get_http2ClientConn_from_http2clientConnReadLoop_ctx(
	struct pt_regs *ctx, struct ebpf_proc_info *info)
{
	void *ptr = get_the_first_parameter(ctx, info);
	ptr += info->offsets[OFFSET_IDX_CC_HTTP2_CLIENT_CONN_READ_LOOP];
	bpf_probe_read(&ptr, sizeof(ptr), ptr);
	return ptr;
}

static __inline int
get_fd_from_http2clientConnReadLoop_ctx(struct pt_regs *ctx,
					struct ebpf_proc_info *info)
{
	void *ptr =
		get_http2ClientConn_from_http2clientConnReadLoop_ctx(ctx, info);
	return get_fd_from_http2ClientConn(ptr, info);
}

static __inline __u32 get_previous_read_tcp_seq(int fd, __u32 seq_end)
{
	struct http2_tcp_seq_key key = {
		.tgid = bpf_get_current_pid_tgid() >> 32,
		.fd = fd,
		.tcp_seq_end = seq_end,
	};
	__u32 *seq_begin = bpf_map_lookup_elem(&http2_tcp_seq_map, &key);
	if (seq_begin) {
		return *seq_begin;
	}
	return 0;
}

struct http2_header_data {
	// The read operation must be INGRESS, otherwise EGRESS
	bool read : 1;

	// Client-side write and server-side read are marked as requests,
	// otherwise marked as responses
	enum message_type message_type;

	// Fields that need to be serialized
	int fd;
	struct go_string name;
	struct go_string value;
	__u32 stream;
	struct pt_regs *ctx;
};

// Take data from extra and send it, and a __http2_buffer used as a big stack
static __inline void report_http2_header(struct pt_regs *ctx)
{
	if (!ctx) {
		return;
	}
	struct __http2_stack *stack = get_http2_stack();

	if (!stack) {
		return;
	}

	static const int BUF_DATA_OFFSET =
		offsetof(typeof(struct __socket_data_buffer), data);
	static const int SEND_SIZE_MAX =
		offsetof(typeof(struct __socket_data), data) + CAP_DATA_SIZE +
		BUF_DATA_OFFSET;

	stack->events_num = 1;
	stack->len = SOCKET_DATA_HEADER + stack->send_buffer.data_len;

	__u32 send_size = (stack->len + BUF_DATA_OFFSET) &
		(sizeof(stack->send_buffer.data) - 1);

	if (send_size < SEND_SIZE_MAX && send_size > 0) {
		bpf_perf_event_output(ctx, &NAME(socket_data),
				      BPF_F_CURRENT_CPU, stack, 1 + send_size);
	}
	return;
}

static __inline void report_http2_dataframe(struct pt_regs *ctx)
{
	report_http2_header(ctx);
	return;
}

static __inline bool
http2_fill_common_socket_1(struct http2_header_data *data,
			   struct __socket_data *send_buffer,
			   struct member_fields_offset *offset)
{
	// Assigned at the end of the function,
	// 0 means that the function returns during execution
	send_buffer->pid = 0;

	__u64 id = bpf_get_current_pid_tgid();
	// source, coroutine_id, timestamp, comm
	send_buffer->source = DATA_SOURCE_GO_HTTP2_UPROBE;
	send_buffer->timestamp = bpf_ktime_get_ns();
	bpf_get_current_comm(send_buffer->comm, sizeof(send_buffer->comm));

	// tcp_seq, direction
	int tcp_seq;
	enum traffic_direction direction;
	if (data->read) {
		tcp_seq = get_tcp_read_seq_from_fd(data->fd);
		tcp_seq = get_previous_read_tcp_seq(data->fd, tcp_seq);
		direction = T_INGRESS;
	} else {
		tcp_seq = get_tcp_write_seq_from_fd(data->fd);
		direction = T_EGRESS;
	}

	send_buffer->tcp_seq = tcp_seq;
	send_buffer->direction = direction;

	// data_type
	enum traffic_protocol protocol;
	protocol = PROTO_HTTP2;

	send_buffer->data_type = protocol;

	// Refer to the logic of process_data in socket_trace.c to
	// obtain quintuple information
	__u32 tgid = id >> 32;

	send_buffer->tuple.l4_protocol = IPPROTO_TCP;
	void *sk = get_socket_from_fd(data->fd, offset);

	// fill in the port number
	__be16 inet_dport;
	__u16 inet_sport;
	__u16 skc_family;
	struct skc_flags_t {
		unsigned char skc_reuse : 4;
		unsigned char skc_reuseport : 1;
		unsigned char skc_ipv6only : 1;
		unsigned char skc_net_refcnt : 1;
	};
	struct skc_flags_t skc_flags;
	bpf_probe_read(&skc_flags, sizeof(skc_flags),
		       sk + offset->struct_sock_common_ipv6only_offset);
	bpf_probe_read(&skc_family, sizeof(skc_family),
		       sk + offset->struct_sock_family_offset);
	bpf_probe_read(&inet_dport, sizeof(inet_dport),
		       sk + offset->struct_sock_dport_offset);
	bpf_probe_read(&inet_sport, sizeof(inet_sport),
		       sk + offset->struct_sock_sport_offset);
	send_buffer->tuple.dport = __bpf_ntohs(inet_dport);
	send_buffer->tuple.num = inet_sport;

	if (skc_family != PF_INET && skc_family != PF_INET6)
		return false;

	if (skc_family == PF_INET6 && skc_flags.skc_ipv6only == 0) {
		ipv4_mapped_on_ipv6_confirm(sk, skc_family, offset);
	}

	if (skc_family == PF_INET) {
		bpf_probe_read(send_buffer->tuple.rcv_saddr, 4,
			       sk + offset->struct_sock_saddr_offset);
		bpf_probe_read(send_buffer->tuple.daddr, 4,
			       sk + offset->struct_sock_daddr_offset);
		send_buffer->tuple.addr_len = 4;
	}

	if (skc_family == PF_INET6) {
		bpf_probe_read(send_buffer->tuple.rcv_saddr, 16,
			       sk + offset->struct_sock_ip6saddr_offset);
		bpf_probe_read(send_buffer->tuple.daddr, 16,
			       sk + offset->struct_sock_ip6daddr_offset);
		send_buffer->tuple.addr_len = 16;
	}
	send_buffer->tgid = tgid;
	return true;
}

static __inline bool
http2_fill_common_socket_2(struct http2_header_data *data,
			   struct __socket_data *send_buffer)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	__u32 k0 = 0;

	// trace_conf, generator for socket_id
	struct trace_conf_t *trace_conf = trace_conf_map__lookup(&k0);
	if (trace_conf == NULL)
		return false;

	struct trace_stats *trace_stats = trace_stats_map__lookup(&k0);
	if (trace_stats == NULL)
		return false;

	// Update and get socket_id
	__u64 conn_key;
	struct socket_info_t *socket_info_ptr;
	conn_key = gen_conn_key_id((__u64)tgid, (__u64)data->fd);
	socket_info_ptr = socket_info_map__lookup(&conn_key);
	if (is_socket_info_valid(socket_info_ptr)) {
		send_buffer->socket_id = socket_info_ptr->uid;
	} else {
		send_buffer->socket_id = trace_conf->socket_id + 1;
		trace_conf->socket_id++;

		struct socket_info_t sk_info = {
			.uid = send_buffer->socket_id,
		};

		if (!socket_info_map__update(&conn_key, &sk_info)) {
			__sync_fetch_and_add(&trace_stats->
					     socket_map_count, 1);
		}
	}

	__u32 timeout = trace_conf->go_tracing_timeout;
	struct trace_key_t trace_key = get_trace_key(timeout, true);
	struct trace_info_t *trace_info_ptr = trace_map__lookup(&trace_key);

	struct conn_info_t conn_info = {
		.direction = send_buffer->direction,
		.message_type = send_buffer->msg_type,
	};

	if (timeout != 0) {
		trace_process(socket_info_ptr, &conn_info,
			      send_buffer->socket_id, id, trace_info_ptr,
			      trace_conf, trace_stats,
			      &send_buffer->thread_trace_id,
			      send_buffer->timestamp, &trace_key);
	}

	send_buffer->coroutine_id = trace_key.goid;
	send_buffer->pid = (__u32)id;
	return true;
}

// Fill all fields except data in buffer->send_buffer
static __inline void http2_fill_common_socket(struct http2_header_data *data,
					      struct __socket_data *send_buffer,
					      struct member_fields_offset *offset)
{
	// When the function implementation is too complex, the compiled
	// bytecode cannot pass the verification of some kernels (4.14).
	// Split the complex function and reduce the complexity of the
	// generated syntax tree to pass the verification
	if (!http2_fill_common_socket_1(data, send_buffer, offset))
		return;

	if (!http2_fill_common_socket_2(data, send_buffer))
		return;

}

// 填充 buffer->send_buffer.data
static __inline void
http2_fill_buffer_and_send(struct http2_header_data *data,
			   struct __http2_buffer *buffer,
			   struct __socket_data *send_buffer)
{
	// Check if pid is a valid value
	if (!data || !buffer || !send_buffer || !send_buffer->pid) {
		return;
	}
	send_buffer->msg_type = data->message_type;

	buffer->fd = data->fd;
	buffer->stream_id = data->stream;
	buffer->header_len = data->name.len & 0x03FF;
	buffer->value_len = data->value.len & 0x03FF;

	static const int BUF_OFFSET = offsetof(typeof(struct __http2_buffer), info);
	__u32 count = BUF_OFFSET + buffer->header_len + buffer->value_len;
	if (count > HTTP2_BUFFER_INFO_SIZE)
		return;
	send_buffer->syscall_len = count;
	send_buffer->data_len = count;
	// Useless range  checking. Make the eBPF validator happy
	if (buffer->header_len >= 0) {
		if (buffer->header_len < HTTP2_BUFFER_INFO_SIZE) {
			bpf_probe_read(buffer->info, 1 + buffer->header_len,
				       data->name.ptr);
		}
	}

	// Useless range  checking. Make the eBPF validator happy
	if (buffer->header_len >= 0) {
		if (buffer->header_len < HTTP2_BUFFER_INFO_SIZE) {
			if (buffer->value_len < HTTP2_BUFFER_INFO_SIZE) {
				bpf_probe_read(
					buffer->info + buffer->header_len,
					1 + buffer->value_len, data->value.ptr);
			}
		}
	}
	if (buffer->header_len + buffer->value_len < HTTP2_BUFFER_INFO_SIZE) {
		buffer->info[buffer->header_len + buffer->value_len] = 0;
	}

	report_http2_header(data->ctx);
}

struct http2_headers_data {
	bool read : 1;
	int fd;
	struct go_slice *fields;
	__u32 stream;
	enum message_type message_type;
	struct pt_regs *ctx;
};

// Send multiple header messages and add an end marker message at the end
static __inline int submit_http2_headers(struct http2_headers_data *headers,
					 struct member_fields_offset *offset)
{
	struct http2_header_data data = {
		.read = headers->read,
		.fd = headers->fd,
		.stream = headers->stream,
		.message_type = headers->message_type,
		.ctx = headers->ctx,
	};
	struct __http2_stack *stack = get_http2_stack();
	if (!stack) {
		return 0;
	}

	struct __http2_buffer *buffer = &(stack->http2_buffer);
	struct __socket_data *send_buffer = &(stack->send_buffer);

	http2_fill_common_socket(&data, send_buffer, offset);

	int idx;
	struct go_http2_header_field *tmp;
	struct go_http2_header_field field;

#pragma unroll
	for (idx = 0; idx < 9; ++idx) {
		if (idx >= headers->fields->len)
			break;

		tmp = headers->fields->ptr;
		bpf_probe_read(&field, sizeof(field), tmp + idx);
		data.name = field.name;
		data.value = field.value;
		http2_fill_buffer_and_send(&data, buffer, send_buffer);
	}

	data.name.len = 0;
	data.value.len = 0;

	// MSG_REQUEST -> MSG_REQUEST_END
	// MSG_RESPONSE -> MSG_RESPONSE_END
	data.message_type += 2;

	http2_fill_buffer_and_send(&data, buffer, send_buffer);
	return 0;
}

static __inline __u32
get_stream_from_http2MetaHeadersFrame(void *ptr, struct ebpf_proc_info *info)
{
	bpf_probe_read(&ptr, sizeof(ptr), ptr);
	ptr += info->offsets[OFFSET_IDX_STREAM_ID_HTTP2_FRAME_HEADER];
	__u32 stream;
	bpf_probe_read(&stream, sizeof(stream), ptr);
	return stream;
}

static __inline void *
get_fields_from_http2MetaHeadersFrame(void *ptr, struct ebpf_proc_info *info)
{
	ptr += info->offsets[OFFSET_IDX_FIELDS_HTTP2_META_HEADERS_FRAME];
	return ptr;
}

// When the type information is missing, the TCP connection information cannot
// be obtained, and kprobe reports the message when it determines that the
// uprobe cannot work properly. If it is not skipped here, the data will be
// duplicated.
static __inline bool skip_http2_uprobe(struct ebpf_proc_info *info)
{
	if (!info) {
		return true;
	}

	if (info->net_TCPConn_itab != 0) {
		return false;
	}

	if (info->crypto_tls_Conn_itab != 0) {
		return false;
	}

	if (info->credentials_syscallConn_itab != 0) {
		return false;
	}
	return true;
}

// func (cc *http2ClientConn) writeHeader(name, value string)
SEC("uprobe/go_http2ClientConn_writeHeader")
int uprobe_go_http2ClientConn_writeHeader(struct pt_regs *ctx)
{
	struct member_fields_offset *offset = retrieve_ready_kern_offset();
	if (offset == NULL)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

	struct ebpf_proc_info *info = bpf_map_lookup_elem(&proc_info_map, &pid);
	if (skip_http2_uprobe(info)) {
		return 0;
	}

	struct http2_header_data data = {
		.read = false,
		.fd = get_fd_from_http2ClientConn_ctx(ctx, info),
		.message_type = MSG_REQUEST,
		.ctx = ctx,
	};

	void *ptr = get_the_first_parameter(ctx, info);
	ptr += info->offsets[OFFSET_IDX_STREAM_HTTP2_CLIENT_CONN];
	bpf_probe_read(&(data.stream), sizeof(data.stream), ptr);

	if (info->version >= GO_VERSION(1, 16, 0)) {
		data.stream -= 2;
	}

	struct __http2_stack *stack = get_http2_stack();
	if (!stack) {
		return 0;
	}

	struct __http2_buffer *buffer = &(stack->http2_buffer);
	struct __socket_data *send_buffer = &(stack->send_buffer);

	http2_fill_common_socket(&data, send_buffer, offset);

	if (is_register_based_call(info)) {
		data.name.ptr = (void *)PT_GO_REGS_PARM2(ctx);
		data.name.len = PT_GO_REGS_PARM3(ctx);
		data.value.ptr = (void *)PT_GO_REGS_PARM4(ctx);
		data.value.len = PT_GO_REGS_PARM5(ctx);
	} else {
		bpf_probe_read(&data.name.ptr, sizeof(data.name.ptr),
			       (void *)(PT_REGS_SP(ctx) + 16));
		bpf_probe_read(&data.name.len, sizeof(data.name.len),
			       (void *)(PT_REGS_SP(ctx) + 24));
		bpf_probe_read(&data.value.ptr, sizeof(data.value.ptr),
			       (void *)(PT_REGS_SP(ctx) + 32));
		bpf_probe_read(&data.value.len, sizeof(data.value.len),
			       (void *)(PT_REGS_SP(ctx) + 40));
	}
	http2_fill_buffer_and_send(&data, buffer, send_buffer);
	return 0;
}

// func (cc *http2ClientConn) writeHeaders(streamID uint32, endStream bool, maxFrameSize int, hdrs []byte) error
SEC("uprobe/go_http2ClientConn_writeHeaders")
int uprobe_go_http2ClientConn_writeHeaders(struct pt_regs *ctx)
{
	struct member_fields_offset *offset = retrieve_ready_kern_offset();
	if (offset == NULL)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

	struct ebpf_proc_info *info = bpf_map_lookup_elem(&proc_info_map, &pid);
	if (skip_http2_uprobe(info)) {
		return 0;
	}

	struct http2_header_data data = {};

	if (is_register_based_call(info)) {
		data.stream = (__u32)PT_GO_REGS_PARM2(ctx);
	} else {
		bpf_probe_read(&(data.stream), sizeof(data.stream),
			       (void *)(PT_REGS_SP(ctx) + 16));
	}

	data.read = false;
	data.fd = get_fd_from_http2ClientConn_ctx(ctx, info);
	data.message_type = MSG_REQUEST_END;
	data.ctx = ctx;
	data.name.len = 0;
	data.value.len = 0;

	struct __http2_stack *stack = get_http2_stack();
	if (!stack) {
		return 0;
	}

	struct __http2_buffer *buffer = &(stack->http2_buffer);
	struct __socket_data *send_buffer = &(stack->send_buffer);

	http2_fill_common_socket(&data, send_buffer, offset);
	http2_fill_buffer_and_send(&data, buffer, send_buffer);

	return 0;
}

// func (sc *http2serverConn) processHeaders(f *http2MetaHeadersFrame) error
SEC("uprobe/go_http2serverConn_processHeaders")
int uprobe_go_http2serverConn_processHeaders(struct pt_regs *ctx)
{
	struct member_fields_offset *offset = retrieve_ready_kern_offset();
	if (offset == NULL)
		return 0;

	struct go_slice fields;
	void *frame;
	__u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

	struct ebpf_proc_info *info = bpf_map_lookup_elem(&proc_info_map, &pid);
	if (skip_http2_uprobe(info)) {
		return 0;
	}

	if (is_register_based_call(info)) {
		frame = (void *)PT_GO_REGS_PARM2(ctx);
	} else {
		bpf_probe_read(&frame, sizeof(frame), (void *)(PT_REGS_SP(ctx) + 16));
	}

	void *fields_ptr = get_fields_from_http2MetaHeadersFrame(frame, info);
	bpf_probe_read(&fields, sizeof(fields), fields_ptr);

	struct http2_headers_data headers = {
		.fields = &fields,
		.read = true,
		.fd = get_fd_from_http2serverConn_ctx(ctx, info),
		.stream = get_stream_from_http2MetaHeadersFrame(frame, info),
		.message_type = MSG_REQUEST,
		.ctx = ctx,
	};

	return submit_http2_headers(&headers, offset);
}

// func (sc *http2serverConn) writeHeaders(st *http2stream, headerData *http2writeResHeaders) error
SEC("uprobe/go_http2serverConn_writeHeaders")
int uprobe_go_http2serverConn_writeHeaders(struct pt_regs *ctx)
{
	struct member_fields_offset *offset = retrieve_ready_kern_offset();
	if (offset == NULL)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

	struct ebpf_proc_info *info = bpf_map_lookup_elem(&proc_info_map, &pid);
	if (skip_http2_uprobe(info)) {
		return 0;
	}

	// headerData *http2writeResHeaders
	void *ptr;

	struct http2_header_data data = {};
	data.read = false;
	data.fd = get_fd_from_http2serverConn_ctx(ctx, info);
	data.message_type = MSG_RESPONSE;
	data.ctx = ctx;

	struct __http2_stack *stack = get_http2_stack();
	if (!stack) {
		return 0;
	}

	struct __http2_buffer *buffer = &(stack->http2_buffer);
	struct __socket_data *send_buffer = &(stack->send_buffer);

	http2_fill_common_socket(&data, send_buffer, offset);

	if (is_register_based_call(info)) {
		ptr = (void *)PT_GO_REGS_PARM3(ctx);
	} else {
		bpf_probe_read(&ptr, sizeof(ptr), (void *)(PT_REGS_SP(ctx) + 24));
	}

	bpf_probe_read(&(data.stream), sizeof(data.stream), ptr + 0x0);

	char status[] = ":status";
	char status_value[3];
	unsigned int code;
	bpf_probe_read(&code, sizeof(code), ptr + 0x8);
	if (code) {
		status_value[0] = '0' + (code % 1000) / 100;
		status_value[1] = '0' + (code % 100) / 10;
		status_value[2] = '0' + (code % 10);
		data.name.ptr = (char *)&status;
		data.name.len = 7;
		data.value.ptr = (char *)&status_value;
		data.value.len = 3;
		http2_fill_buffer_and_send(&data, buffer, send_buffer);
	}

	char date[] = "date";
	data.name.ptr = (char *)&date;
	data.name.len = 4;
	bpf_probe_read(&(data.value), sizeof(data.value), ptr + 0x38);
	if (data.value.len) {
		http2_fill_buffer_and_send(&data, buffer, send_buffer);
	}

	char content_type[] = "content-type";
	data.name.ptr = (char *)&content_type;
	data.name.len = 12;
	bpf_probe_read(&(data.value), sizeof(data.value), ptr + 0x48);
	if (data.value.len) {
		http2_fill_buffer_and_send(&data, buffer, send_buffer);
	}

	char content_length[] = "content-length";
	data.name.ptr = (char *)content_length;
	data.name.len = 14;
	bpf_probe_read(&(data.value), sizeof(data.value), ptr + 0x58);
	if (data.value.len) {
		http2_fill_buffer_and_send(&data, buffer, send_buffer);
	}

	data.name.len = 0;
	data.value.len = 0;
	data.message_type += 2;
	http2_fill_buffer_and_send(&data, buffer, send_buffer);

	return 0;
}

// func (rl *http2clientConnReadLoop) handleResponse(cs *http2clientStream, f *http2MetaHeadersFrame) (*Response, error)
SEC("uprobe/go_http2clientConnReadLoop_handleResponse")
int uprobe_go_http2clientConnReadLoop_handleResponse(struct pt_regs *ctx)
{
	struct member_fields_offset *offset = retrieve_ready_kern_offset();
	if (offset == NULL)
		return 0;

	struct go_slice fields;
	void *frame;

	__u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

	struct ebpf_proc_info *info = bpf_map_lookup_elem(&proc_info_map, &pid);
	if (skip_http2_uprobe(info)) {
		return 0;
	}

	if (is_register_based_call(info)) {
		frame = (void *)PT_GO_REGS_PARM3(ctx);
	} else {
		bpf_probe_read(&frame, sizeof(frame), (void *)(PT_REGS_SP(ctx) + 24));
	}

	void *fields_ptr = get_fields_from_http2MetaHeadersFrame(frame, info);
	bpf_probe_read(&fields, sizeof(fields), fields_ptr);

	struct http2_headers_data headers = {
		.fields = &fields,
		.read = true,
		.fd = get_fd_from_http2clientConnReadLoop_ctx(ctx, info),
		.stream = get_stream_from_http2MetaHeadersFrame(frame, info),
		.message_type = MSG_RESPONSE,
		.ctx = ctx,
	};
	return submit_http2_headers(&headers, offset);
}

// func (l *loopyWriter) writeHeader(streamID uint32, endStream bool, hf []hpack.HeaderField, onWrite func()) error
SEC("uprobe/go_loopyWriter_writeHeader")
int uprobe_go_loopyWriter_writeHeader(struct pt_regs *ctx)
{
	struct member_fields_offset *offset = retrieve_ready_kern_offset();
	if (offset == NULL)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

	struct ebpf_proc_info *info = bpf_map_lookup_elem(&proc_info_map, &pid);
	if (skip_http2_uprobe(info)) {
		return 0;
	}

	struct go_slice fields = { 0 };
	if (is_register_based_call(info)) {
		fields.ptr = (void *)PT_GO_REGS_PARM4(ctx);
		fields.len = PT_GO_REGS_PARM5(ctx);
		fields.cap = PT_GO_REGS_PARM6(ctx);
	} else {
		// 8 + 8 + 4 + 4
		bpf_probe_read(&fields, sizeof(fields),
			       (void *)(PT_REGS_SP(ctx) + 24));
	}

	struct http2_headers_data headers = { 0 };
	headers.fields = &fields;
	headers.read = false;
	headers.fd = get_fd_from_grpc_loopyWriter(ctx, info);
	headers.ctx = ctx;

	if (is_register_based_call(info)) {
		headers.stream = (__u32)PT_GO_REGS_PARM2(ctx);
	} else {
		bpf_probe_read(&headers.stream, sizeof(headers.stream),
			       (void *)(PT_REGS_SP(ctx) + 16));
	}

	int is_server_side = get_side_from_grpc_loopyWriter(ctx, info);
	headers.message_type = is_server_side ? MSG_RESPONSE : MSG_REQUEST;
	return submit_http2_headers(&headers, offset);
}

// func (t *http2Server) operateHeaders(frame *http2.MetaHeadersFrame, handle func(*Stream), traceCtx func(context.Context, string) context.Context) (fatal bool)
SEC("uprobe/go_http2Server_operateHeaders")
int uprobe_go_http2Server_operateHeaders(struct pt_regs *ctx)
{
	struct member_fields_offset *offset = retrieve_ready_kern_offset();
	if (offset == NULL)
		return 0;

	struct go_slice fields;
	void *frame;

	__u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

	struct ebpf_proc_info *info = bpf_map_lookup_elem(&proc_info_map, &pid);
	if (skip_http2_uprobe(info)) {
		return 0;
	}

	if (is_register_based_call(info)) {
		frame = (void *)PT_GO_REGS_PARM2(ctx);
	} else {
		bpf_probe_read(&frame, sizeof(frame), (void *)(PT_REGS_SP(ctx) + 16));
	}

	void *fields_ptr = get_fields_from_http2MetaHeadersFrame(frame, info);
	bpf_probe_read(&fields, sizeof(fields), fields_ptr);

	struct http2_headers_data headers = {
		.fields = &fields,
		.read = true,
		.fd = get_fd_from_grpc_http2Server_ctx(ctx, info),
		.stream = get_stream_from_http2MetaHeadersFrame(frame, info),
		.message_type = MSG_REQUEST,
		.ctx = ctx,
	};

	return submit_http2_headers(&headers, offset);
}

// func (t *http2Client) operateHeaders(frame *http2.MetaHeadersFrame)
SEC("uprobe/go_http2Client_operateHeaders")
int uprobe_go_http2Client_operateHeaders(struct pt_regs *ctx)
{
	struct member_fields_offset *offset = retrieve_ready_kern_offset();
	if (offset == NULL)
		return 0;

	struct go_slice fields;
	void *frame;

	__u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

	struct ebpf_proc_info *info = bpf_map_lookup_elem(&proc_info_map, &pid);
	if (skip_http2_uprobe(info)) {
		return 0;
	}

	if (is_register_based_call(info)) {
		frame = (void *)PT_GO_REGS_PARM2(ctx);
	} else {
		bpf_probe_read(&frame, sizeof(frame), (void *)(PT_REGS_SP(ctx) + 16));
	}

	void *fields_ptr = get_fields_from_http2MetaHeadersFrame(frame, info);
	bpf_probe_read(&fields, sizeof(fields), fields_ptr);

	struct http2_headers_data headers = {
		.fields = &fields,
		.read = true,
		.fd = get_fd_from_grpc_http2Client_ctx(ctx, info),
		.stream = get_stream_from_http2MetaHeadersFrame(frame, info),
		.message_type = MSG_RESPONSE,
		.ctx = ctx,
	};

	return submit_http2_headers(&headers, offset);
}

static __inline int
get_fd_from_grpc_http2_Framer_ctx(struct pt_regs *ctx,
				  struct ebpf_proc_info *info)
{
	void *ptr = get_the_first_parameter(ctx, info);

	struct go_interface io_writer_interface;
	bpf_probe_read(&io_writer_interface, sizeof(io_writer_interface),
		       ptr + info->offsets[OFFSET_IDX_HTTP2_FRAMER_W]);

	struct go_interface conn_intf;
	bpf_probe_read(&conn_intf, sizeof(conn_intf),
		       io_writer_interface.ptr +
			       info->offsets[OFFSET_IDX_BUFWRITTER_CONN]);

	if (is_grpc_syscallConn_interface(&conn_intf, info)) {
		bpf_probe_read(&conn_intf, sizeof(conn_intf), conn_intf.ptr);
	}

	return get_fd_from_tcp_or_tls_conn_interface(&conn_intf, info);
}

static __inline int fill_http2_dataframe_base(struct __http2_stack *stack,
					      int fd, __u64 pid_tgid,
					      enum traffic_direction direction,
					      struct member_fields_offset *offset)
{
	struct __socket_data *send_buffer = &(stack->send_buffer);

	send_buffer->source = DATA_SOURCE_GO_HTTP2_DATAFRAME_UPROBE;
	send_buffer->direction = direction;
	int tgid = pid_tgid >> 32;

	send_buffer->tgid = tgid;
	send_buffer->pid = (__u32)pid_tgid;
	send_buffer->timestamp = bpf_ktime_get_ns();
	bpf_get_current_comm(send_buffer->comm, sizeof(send_buffer->comm));
	send_buffer->tcp_seq = 0;
	send_buffer->data_type = PROTO_HTTP2;

	send_buffer->tuple.l4_protocol = IPPROTO_TCP;
	void *sk = get_socket_from_fd(fd, offset);

	// fill in the port number
	__be16 inet_dport;
	__u16 inet_sport;
	__u16 skc_family;
	struct skc_flags_t {
		unsigned char skc_reuse : 4;
		unsigned char skc_reuseport : 1;
		unsigned char skc_ipv6only : 1;
		unsigned char skc_net_refcnt : 1;
	};
	struct skc_flags_t skc_flags;
	bpf_probe_read(&skc_flags, sizeof(skc_flags),
		       sk + offset->struct_sock_common_ipv6only_offset);
	bpf_probe_read(&skc_family, sizeof(skc_family),
		       sk + offset->struct_sock_family_offset);
	bpf_probe_read(&inet_dport, sizeof(inet_dport),
		       sk + offset->struct_sock_dport_offset);
	bpf_probe_read(&inet_sport, sizeof(inet_sport),
		       sk + offset->struct_sock_sport_offset);
	send_buffer->tuple.dport = __bpf_ntohs(inet_dport);
	send_buffer->tuple.num = inet_sport;

	if (skc_family != PF_INET && skc_family != PF_INET6)
		return -1;

	if (skc_family == PF_INET6 && skc_flags.skc_ipv6only == 0) {
		ipv4_mapped_on_ipv6_confirm(sk, skc_family, offset);
	}

	if (skc_family == PF_INET) {
		bpf_probe_read(send_buffer->tuple.rcv_saddr, 4,
			       sk + offset->struct_sock_saddr_offset);
		bpf_probe_read(send_buffer->tuple.daddr, 4,
			       sk + offset->struct_sock_daddr_offset);
		send_buffer->tuple.addr_len = 4;
	}

	if (skc_family == PF_INET6) {
		bpf_probe_read(send_buffer->tuple.rcv_saddr, 16,
			       sk + offset->struct_sock_ip6saddr_offset);
		bpf_probe_read(send_buffer->tuple.daddr, 16,
			       sk + offset->struct_sock_ip6daddr_offset);
		send_buffer->tuple.addr_len = 16;
	}

	__u32 k0 = 0;
	// trace_conf, generator for socket_id
	struct trace_conf_t *trace_conf = trace_conf_map__lookup(&k0);
	if (trace_conf == NULL)
		return -1;

	struct trace_stats *trace_stats = trace_stats_map__lookup(&k0);
	if (trace_stats == NULL)
		return -1;

	// Update and get socket_id
	__u64 conn_key;
	struct socket_info_t *socket_info_ptr;
	conn_key = gen_conn_key_id((__u64)tgid, (__u64)fd);
	socket_info_ptr = socket_info_map__lookup(&conn_key);
	if (is_socket_info_valid(socket_info_ptr)) {
		send_buffer->socket_id = socket_info_ptr->uid;
	} else {
		send_buffer->socket_id = trace_conf->socket_id + 1;
		trace_conf->socket_id++;

		struct socket_info_t sk_info = {
			.uid = send_buffer->socket_id,
		};

		if (!socket_info_map__update(&conn_key, &sk_info)) {
			__sync_fetch_and_add(&trace_stats->socket_map_count, 1);
		}
	}

	return 0;
}

static __inline int fill_http2_dataframe_data(struct __http2_stack *stack,
					      void *buffer, __u64 len,
					      __u32 stream_id)
{
	struct __http2_dataframe *dataframe = &(stack->http2_dataframe);
	struct __socket_data *send_buffer = &(stack->send_buffer);

	dataframe->stream_id = stream_id;
	dataframe->data_len = 0;

	if (len < HTTP2_DATAFRAME_DATA_SIZE) {
		// Make old eBPF validator happy
		if (len > 0) {
			bpf_probe_read(dataframe->data, len + 1, buffer);
			dataframe->data_len = len;
		}
	} else {
		bpf_probe_read(dataframe->data, HTTP2_DATAFRAME_DATA_SIZE,
			       buffer);
		dataframe->data_len = HTTP2_DATAFRAME_DATA_SIZE;
	}

	static const int OFFSET = offsetof(typeof(struct __http2_dataframe), data);
	send_buffer->syscall_len = dataframe->data_len + OFFSET;
	send_buffer->data_len = dataframe->data_len + OFFSET;

	return 0;
}

// grpc dataframe
// func (fr *Framer) checkFrameOrder(f Frame) error
SEC("uprobe/golang_org_x_net_http2_Framer_checkFrameOrder")
static int
uprobe_golang_org_x_net_http2_Framer_checkFrameOrder(struct pt_regs *ctx)
{
	struct member_fields_offset *offset = retrieve_ready_kern_offset();
	if (offset == NULL)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t tgid = pid_tgid >> 32;

	struct ebpf_proc_info *info = bpf_map_lookup_elem(&proc_info_map, &tgid);
	if (skip_http2_uprobe(info)) {
		return 0;
	}

	// TODO: Use the offset obtained dynamically from user mode
	int DataFrame_Type_offset = 1;
	int DataFrame_StreamID_offset = 8;
	int DataFrame_data_offset = 16;

	struct go_interface Frame = { .type = PT_GO_REGS_PARM2(ctx),
				      .ptr = (void *)PT_GO_REGS_PARM3(ctx) };

	uint8_t Type;
	bpf_probe_read_user(&Type, sizeof(Type),
			    (void *)Frame.ptr + DataFrame_Type_offset);
	if (Type != 0) {
		return 0;
	}

	__u32 stream_id;
	bpf_probe_read_user(&stream_id, sizeof(stream_id),
			    (void *)Frame.ptr + DataFrame_StreamID_offset);

	struct go_slice data;
	bpf_probe_read_user(&data, sizeof(data),
			    (void *)Frame.ptr + DataFrame_data_offset);

	int fd = get_fd_from_grpc_http2_Framer_ctx(ctx, info);

	struct __http2_stack *stack = get_http2_stack();
	if (!stack) {
		return 0;
	}

	if (fill_http2_dataframe_base(stack, fd, pid_tgid, T_INGRESS, offset)) {
		return 0;
	}

	if (fill_http2_dataframe_data(stack, data.ptr, data.len, stream_id)) {
		return 0;
	}

	report_http2_dataframe(ctx);
	return 0;
}

// func (f *Framer) WriteDataPadded(streamID uint32, endStream bool, data, pad []byte) error
SEC("uprobe/golang_org_x_net_http2_Framer_WriteDataPadded")
static int
uprobe_golang_org_x_net_http2_Framer_WriteDataPadded(struct pt_regs *ctx)
{
	struct member_fields_offset *offset = retrieve_ready_kern_offset();
	if (offset == NULL)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t tgid = pid_tgid >> 32;

	struct ebpf_proc_info *info = bpf_map_lookup_elem(&proc_info_map, &tgid);
	if (skip_http2_uprobe(info)) {
		return 0;
	}

	__u32 stream_id = (__u32)PT_GO_REGS_PARM2(ctx);
	struct go_slice data = { .ptr = (void *)PT_GO_REGS_PARM4(ctx),
				 .len = PT_GO_REGS_PARM5(ctx),
				 .cap = PT_GO_REGS_PARM6(ctx) };

	int fd = get_fd_from_grpc_http2_Framer_ctx(ctx, info);

	struct __http2_stack *stack = get_http2_stack();
	if (!stack) {
		return 0;
	}

	if (fill_http2_dataframe_base(stack, fd, pid_tgid, T_EGRESS, offset)) {
		return 0;
	}

	if (fill_http2_dataframe_data(stack, data.ptr, data.len, stream_id)) {
		return 0;
	}

	report_http2_dataframe(ctx);
	return 0;
}
