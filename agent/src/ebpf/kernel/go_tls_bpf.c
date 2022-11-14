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
struct bpf_map_def SEC("maps") tls_conn_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct tls_conn_key),
	.value_size = sizeof(struct tls_conn),
	.max_entries = MAX_SYSTEM_THREADS,
};

/*
 *  uprobe_go_tls_write_enter  (In tls_conn_map record A(tcp_seq) before syscall)
 *               |
 *               | - syscall write()
 *               |
 *  uprobe_go_tls_write_exit(return)  lookup A(tcp_seq) from tls_conn_map
 *     send to user finally tcp sequence is "A(tcp_seq) + bytes_count"
 */
SEC("uprobe/go_tls_write_enter")
int uprobe_go_tls_write_enter(struct pt_regs *ctx)
{
	struct tls_conn c = {};
	struct tls_conn_key key = {};

	__u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

	struct ebpf_proc_info *info = bpf_map_lookup_elem(&proc_info_map, &pid);
	if (!info) {
		return 0;
	}

	c.sp = (void *)PT_REGS_SP(ctx);

	if (is_register_based_call(info)) {
		c.fd = get_fd_from_tls_conn_struct(
			(void *)PT_GO_REGS_PARM1(ctx), info);
		c.buffer = (char *)PT_GO_REGS_PARM2(ctx);
	} else {
		void *conn;
		bpf_probe_read(&conn, sizeof(conn), (void *)(c.sp + 8));
		c.fd = get_fd_from_tls_conn_struct(conn, info);
		bpf_probe_read(&c.buffer, sizeof(c.buffer),
			       (void *)(c.sp + 16));
	}

	if (c.fd < 0)
		return 0;
	c.tcp_seq = get_tcp_write_seq_from_fd(c.fd);

	key.tgid = pid;
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

	__u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

	struct ebpf_proc_info *info = bpf_map_lookup_elem(&proc_info_map, &pid);
	if (!info) {
		return 0;
	}

	key.tgid = id >> 32;
	key.goid = get_current_goroutine();

	c = bpf_map_lookup_elem(&tls_conn_map, &key);
	if (!c)
		return 0;

	if (is_register_based_call(info)) {
		bytes_count = PT_GO_REGS_PARM1(ctx);
	} else {
		bpf_probe_read(&bytes_count, sizeof(bytes_count),
			       (void *)(c->sp + 40));
	}
	if (bytes_count == 0) {
		bpf_map_delete_elem(&tls_conn_map, &key);
		return 0;
	}

	struct data_args_t write_args = {
		.buf = c->buffer,
		.fd = c->fd,
		.enter_ts = bpf_ktime_get_ns(),
		.tcp_seq = c->tcp_seq,
	};

	struct process_data_extra extra = {
		.vecs = false,
		.source = DATA_SOURCE_GO_TLS_UPROBE,
		.coroutine_id = key.goid,
	};

	bpf_map_delete_elem(&tls_conn_map, &key);
	active_write_args_map__update(&id, &write_args);
	if (!process_data((struct pt_regs *)ctx, id, T_EGRESS, &write_args,
			  bytes_count, &extra)) {
		bpf_tail_call(ctx, &NAME(progs_jmp_kp_map), 0);
	}
	active_write_args_map__delete(&id);
	return 0;
}

/*
 *  uprobe_go_tls_read_enter  (In tls_conn_map record A(tcp_seq) before syscall)
 *               |
 *               | - syscall read()
 *               |
 *  uprobe_go_tls_read_exit(return)  lookup A(tcp_seq) from tls_conn_map
 *     send to user finally tcp sequence is "A(tcp_seq) + bytes_count"
 */
SEC("uprobe/go_tls_read_enter")
int uprobe_go_tls_read_enter(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

	struct ebpf_proc_info *info = bpf_map_lookup_elem(&proc_info_map, &pid);
	if (!info) {
		return 0;
	}

	struct tls_conn c = {};
	struct tls_conn_key key = {};

	c.sp = (void *)PT_REGS_SP(ctx);

	if (is_register_based_call(info)) {
		c.fd = get_fd_from_tls_conn_struct(
			(void *)PT_GO_REGS_PARM1(ctx), info);
		c.buffer = (char *)PT_GO_REGS_PARM2(ctx);
	} else {
		void *conn;
		bpf_probe_read(&conn, sizeof(conn), (void *)(c.sp + 8));
		c.fd = get_fd_from_tls_conn_struct(conn, info);
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
	__u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

	struct ebpf_proc_info *info = bpf_map_lookup_elem(&proc_info_map, &pid);
	if (!info) {
		return 0;
	}

	struct tls_conn *c;
	struct tls_conn_key key = {};
	ssize_t bytes_count;

	key.tgid = bpf_get_current_pid_tgid() >> 32;
	key.goid = get_current_goroutine();

	c = bpf_map_lookup_elem(&tls_conn_map, &key);
	if (!c)
		return 0;

	struct http2_tcp_seq_key tcp_seq_key = {
		.tgid = key.tgid,
		.fd = c->fd,
		.tcp_seq_end = get_tcp_read_seq_from_fd(c->fd),
	};
	// make linux 4.14 validator happy
	__u32 tcp_seq = c->tcp_seq;
	bpf_map_update_elem(&http2_tcp_seq_map, &tcp_seq_key, &tcp_seq,
			    BPF_NOEXIST);

	if (is_register_based_call(info)) {
		bytes_count = PT_GO_REGS_PARM1(ctx);
	} else {
		bpf_probe_read(&bytes_count, sizeof(bytes_count),
			       (void *)(c->sp + 40));
	}

	if (bytes_count == 0) {
		bpf_map_delete_elem(&tls_conn_map, &key);
		return 0;
	}

	struct data_args_t read_args = {
		.buf = c->buffer,
		.fd = c->fd,
		.enter_ts = bpf_ktime_get_ns(),
		.tcp_seq = c->tcp_seq,
	};

	struct process_data_extra extra = {
		.vecs = false,
		.source = DATA_SOURCE_GO_TLS_UPROBE,
		.coroutine_id = key.goid,
	};

	bpf_map_delete_elem(&tls_conn_map, &key);
	active_read_args_map__update(&id, &read_args);
	if (!process_data((struct pt_regs *)ctx, id, T_INGRESS, &read_args,
			  bytes_count, &extra)) {
		bpf_tail_call(ctx, &NAME(progs_jmp_kp_map), 0);
	}
	active_read_args_map__delete(&id);
	return 0;
}
