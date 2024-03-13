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

#ifdef TLS_DEBUG
#define DEFINE_DBG_DATA(x) struct debug_data x = {}
#define submit_debug(F, N, L)  \
do { \
  dbg_data.magic = 0xffff;\
  dbg_data.fun = (F); \
  dbg_data.num = (N); \
  dbg_data.len = (L); \
  bpf_perf_event_output(ctx, &NAME(socket_data), BPF_F_CURRENT_CPU, &dbg_data, sizeof(dbg_data)); \
} while(0)

#define submit_debug_str(F, N, P)  \
do { \
  dbg_data.magic = 0xfffe;\
  dbg_data.fun = (F); \
  dbg_data.num = (N); \
  __builtin_memset(dbg_data.buf, 0, sizeof(dbg_data.buf)); \
  bpf_probe_read_user(dbg_data.buf, sizeof(dbg_data.buf), (P)); \
  bpf_perf_event_output(ctx, &NAME(socket_data), BPF_F_CURRENT_CPU, &dbg_data, sizeof(dbg_data)); \
} while(0)
#else
#define DEFINE_DBG_DATA(x)
#define submit_debug(F, N, L)
#define submit_debug_str(F, N, P)
#endif

/*
 *  uprobe_go_tls_write_enter  (In tls_conn_map record A(tcp_seq) before syscall)
 *               |
 *               | - syscall write()
 *               |
 *  uprobe_go_tls_write_exit(return)  lookup A(tcp_seq) from tls_conn_map
 *     send to user finally tcp sequence is "A(tcp_seq) + bytes_count"
#ifdef TLS_DEBUG */
SEC("uprobe/go_tls_write_enter")
int uprobe_go_tls_write_enter(struct pt_regs *ctx)
{
	DEFINE_DBG_DATA(dbg_data);
	submit_debug(1, 0, 0);
	struct tls_conn c = {};
	struct tls_conn_key key = {};
	__u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

	struct ebpf_proc_info *info = bpf_map_lookup_elem(&proc_info_map, &pid);
	if (!info) {
		submit_debug(1, 1, 0);
		return 0;
	}

	c.sp = (void *)PT_REGS_SP(ctx);

	if (is_register_based_call(info)) {
		c.fd = get_fd_from_tcp_or_tls_conn_interface(
			(void *)PT_GO_REGS_PARM1(ctx), info);
		c.buffer = (char *)PT_GO_REGS_PARM2(ctx);
	} else {
		void *conn;
		bpf_probe_read_user(&conn, sizeof(conn), (void *)(c.sp + 8));
		c.fd = get_fd_from_tcp_or_tls_conn_interface(conn, info);
		bpf_probe_read_user(&c.buffer, sizeof(c.buffer),
				    (void *)(c.sp + 16));
	}

	if (c.fd < 0) {
		submit_debug(1, 2, 0);
		return 0;
	}
	c.tcp_seq = get_tcp_write_seq_from_fd(c.fd);

	key.tgid = pid;
	key.goid = get_current_goroutine();

	bpf_map_update_elem(&tls_conn_map, &key, &c, BPF_ANY);

	return 0;
}

SEC("uprobe/go_tls_write_exit")
int uprobe_go_tls_write_exit(struct pt_regs *ctx)
{
	DEFINE_DBG_DATA(dbg_data);
	submit_debug(2, 0, 0);
	struct tls_conn *c;
	struct tls_conn_key key = {};
	ssize_t bytes_count;

	__u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

	struct ebpf_proc_info *info = bpf_map_lookup_elem(&proc_info_map, &pid);
	if (!info) {
		submit_debug(2, 1, 0);
		return 0;
	}

	key.tgid = id >> 32;
	key.goid = get_current_goroutine();

	c = bpf_map_lookup_elem(&tls_conn_map, &key);
	if (!c) {
		submit_debug(2, 2, 0);
		return 0;
	}

	if (is_register_based_call(info)) {
		bytes_count = PT_GO_REGS_PARM1(ctx);
	} else {
		bpf_probe_read_user(&bytes_count, sizeof(bytes_count),
				    (void *)(c->sp + 40));
	}

	if (bytes_count == 0) {
		submit_debug(2, 3, 0);
		bpf_map_delete_elem(&tls_conn_map, &key);
		return 0;
	} else {
		submit_debug(2, 3, bytes_count);
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
		.is_go_process = true,
	};

	submit_debug_str(2, 4, c->buffer);
	bpf_map_delete_elem(&tls_conn_map, &key);
	active_write_args_map__update(&id, &write_args);
	
	if (!process_data((struct pt_regs *)ctx, id, T_EGRESS, &write_args,
			  bytes_count, &extra)) {
		submit_debug(2, 5, 0);
		bpf_tail_call(ctx, &NAME(progs_jmp_kp_map),
			      PROG_DATA_SUBMIT_KP_IDX);
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
	DEFINE_DBG_DATA(dbg_data);
	submit_debug(3, 0, 0);
	__u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

	struct ebpf_proc_info *info = bpf_map_lookup_elem(&proc_info_map, &pid);
	if (!info) {
		submit_debug(3, 1, 0);
		return 0;
	}

	struct tls_conn c = {};
	struct tls_conn_key key = {};

	c.sp = (void *)PT_REGS_SP(ctx);

	if (is_register_based_call(info)) {
		c.fd = get_fd_from_tcp_or_tls_conn_interface(
			(void *)PT_GO_REGS_PARM1(ctx), info);
		c.buffer = (char *)PT_GO_REGS_PARM2(ctx);
	} else {
		void *conn;
		bpf_probe_read_user(&conn, sizeof(conn), (void *)(c.sp + 8));
		c.fd = get_fd_from_tcp_or_tls_conn_interface(conn, info);
		bpf_probe_read_user(&c.buffer, sizeof(c.buffer),
				    (void *)(c.sp + 16));
	}

	if (c.fd < 0) {
		submit_debug(3, 2, 0);
		return 0;
	}
	c.tcp_seq = get_tcp_read_seq_from_fd(c.fd);

	key.tgid = bpf_get_current_pid_tgid() >> 32;
	key.goid = get_current_goroutine();

	bpf_map_update_elem(&tls_conn_map, &key, &c, BPF_ANY);

	return 0;
}

SEC("uprobe/go_tls_read_exit")
int uprobe_go_tls_read_exit(struct pt_regs *ctx)
{
	DEFINE_DBG_DATA(dbg_data);
	submit_debug(4, 0, 0);

	__u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;

	struct ebpf_proc_info *info = bpf_map_lookup_elem(&proc_info_map, &pid);
	if (!info) {
		submit_debug(4, 1, 0);
		return 0;
	}

	struct tls_conn *c;
	struct tls_conn_key key = {};
	ssize_t bytes_count;

	key.tgid = bpf_get_current_pid_tgid() >> 32;
	key.goid = get_current_goroutine();

	c = bpf_map_lookup_elem(&tls_conn_map, &key);
	if (!c) {
		submit_debug(4, 2, 0);
		return 0;
	}

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
		bpf_probe_read_user(&bytes_count, sizeof(bytes_count),
				    (void *)(c->sp + 40));
	}

	if (bytes_count == 0) {
		submit_debug(4, 3, 0);
		bpf_map_delete_elem(&tls_conn_map, &key);
		return 0;
	} else {
		submit_debug(4, 3, bytes_count);
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
		.is_go_process = true,
	};

	submit_debug_str(4, 4, c->buffer);
	bpf_map_delete_elem(&tls_conn_map, &key);
	active_read_args_map__update(&id, &read_args);
	if (!process_data((struct pt_regs *)ctx, id, T_INGRESS, &read_args,
			  bytes_count, &extra)) {
		submit_debug(4, 5, 0);
		bpf_tail_call(ctx, &NAME(progs_jmp_kp_map),
			      PROG_DATA_SUBMIT_KP_IDX);
	}
	active_read_args_map__delete(&id);
	return 0;
}
