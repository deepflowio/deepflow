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

/*
 * Pass function parameters by process ID and coroutine ID
 * key: struct tls_conn_key {process ID, coroutine ID}
 * value: struct tls_conn
 */
struct {
	// FIXME: function entry without exit will cause memory leaks
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct tls_conn_key);
	__type(value, struct tls_conn);
	__uint(max_entries, MAX_SYSTEM_THREADS);
} tls_conn_map SEC(".maps");

static int get_fd_from_tls_conn(void *tls_conn)
{
	struct go_interface i = {};
	void *ptr;
	int fd;

	int offset_conn_conn = get_crypto_tls_conn_conn_offset();
	if (offset_conn_conn < 0)
		return -1;
	int offset_fd_sysfd = get_net_poll_fd_sysfd();
	if (offset_fd_sysfd < 0)
		return -1;

	bpf_probe_read_user(&i, sizeof(i), tls_conn + offset_conn_conn);
	bpf_probe_read_user(&ptr, sizeof(ptr), i.ptr);
	bpf_probe_read_user(&fd, sizeof(fd), ptr + offset_fd_sysfd);

	return fd;
}

SEC("uprobe/go_tls_write_enter")
int uprobe_go_tls_write_enter(struct pt_regs *ctx)
{
	struct tls_conn c = {};
	struct tls_conn_key key = {};

	c.sp = (void *)ctx->rsp;

	if (get_go_version() >= GO_VERSION(1, 17, 0)) {
		c.fd = get_fd_from_tls_conn((void *)ctx->rax);
		c.buffer = (char *)ctx->rbx;
	} else {
		void *conn;
		bpf_probe_read(&conn, sizeof(conn), (void *)(c.sp + 8));
		c.fd = get_fd_from_tls_conn(conn);
		bpf_probe_read(&c.buffer, sizeof(c.buffer),
			       (void *)(c.sp + 16));
	}

	if (c.fd < 0)
		return 0;
	c.tcp_seq = get_tcp_write_seq_from_fd(c.fd);

	key.tgid = bpf_get_current_pid_tgid() >> 32;
	key.goid = get_current_goroutine();

	bpf_map_update_elem(&tls_conn_map, &key, &c, BPF_ANY);

	return 0;
}

SEC("uprobe/go_tls_write_exit")
int uprobe_go_tls_write_exit(struct pt_regs *ctx)
{
	struct tls_conn *c;
	struct tls_conn_key key = {};
	ssize_t bytes_count;

	key.tgid = bpf_get_current_pid_tgid() >> 32;
	key.goid = get_current_goroutine();

	c = bpf_map_lookup_elem(&tls_conn_map, &key);
	if (!c)
		return 0;

	if (get_go_version() >= GO_VERSION(1, 17, 0)) {
		bytes_count = ctx->rax;
	} else {
		bpf_probe_read(&bytes_count, sizeof(bytes_count),
			       (void *)(c->sp + 40));
	}
	if (bytes_count == 0)
		goto out;

	struct data_args_t write_args = {};
	write_args.buf = c->buffer;
	write_args.fd = c->fd;
	write_args.enter_ts = bpf_ktime_get_ns();

	__u64 id = bpf_get_current_pid_tgid();
	struct process_data_extra extra = {
		.tls = true,
		.go = true,
		.use_tcp_seq = true,
		.tcp_seq = c->tcp_seq,
		.coroutine_id = key.goid,
	};
	process_uprobe_data_tls((struct pt_regs *)ctx, id, T_EGRESS,
				&write_args, bytes_count, &extra);
out:
	bpf_map_delete_elem(&tls_conn_map, &key);
	return 0;
}

SEC("uprobe/go_tls_read_enter")
int uprobe_go_tls_read_enter(struct pt_regs *ctx)
{
	struct tls_conn c = {};
	struct tls_conn_key key = {};

	c.sp = (void *)ctx->rsp;

	if (get_go_version() >= GO_VERSION(1, 17, 0)) {
		c.fd = get_fd_from_tls_conn((void *)ctx->rax);
		c.buffer = (char *)ctx->rbx;
	} else {
		void *conn;
		bpf_probe_read(&conn, sizeof(conn), (void *)(c.sp + 8));
		c.fd = get_fd_from_tls_conn(conn);
		bpf_probe_read(&c.buffer, sizeof(c.buffer),
			       (void *)(c.sp + 16));
	}

	if (c.fd < 0)
		return 0;
	c.tcp_seq = get_tcp_read_seq_from_fd(c.fd);

	key.tgid = bpf_get_current_pid_tgid() >> 32;
	key.goid = get_current_goroutine();

	bpf_map_update_elem(&tls_conn_map, &key, &c, BPF_ANY);

	return 0;
}

SEC("uprobe/go_tls_read_exit")
int uprobe_go_tls_read_exit(struct pt_regs *ctx)
{
	struct tls_conn *c;
	struct tls_conn_key key = {};
	ssize_t bytes_count;

	key.tgid = bpf_get_current_pid_tgid() >> 32;
	key.goid = get_current_goroutine();

	c = bpf_map_lookup_elem(&tls_conn_map, &key);
	if (!c)
		return 0;

	if (get_go_version() >= GO_VERSION(1, 17, 0)) {
		bytes_count = ctx->rax;
	} else {
		bpf_probe_read(&bytes_count, sizeof(bytes_count),
			       (void *)(c->sp + 40));
	}

	if (bytes_count == 0)
		goto out;

	struct data_args_t read_args = {};
	read_args.buf = c->buffer;
	read_args.fd = c->fd;
	read_args.enter_ts = bpf_ktime_get_ns();

	__u64 id = bpf_get_current_pid_tgid();
	struct process_data_extra extra = {
		.tls = true,
		.go = true,
		.use_tcp_seq = true,
		.tcp_seq = c->tcp_seq,
		.coroutine_id = key.goid,
	};

	process_uprobe_data_tls((struct pt_regs *)ctx, id, T_INGRESS,
				&read_args, bytes_count, &extra);
out:
	bpf_map_delete_elem(&tls_conn_map, &key);
	return 0;
}
