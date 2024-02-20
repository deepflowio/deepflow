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

struct ssl_ctx_struct {
	void *buf;
	int num;

	int fd;
	// Since the length of the plaintext is not equal to the length of the
	// ciphertext, the TCP sequence number at the beginning cannot be
	// calculated based on the TCP seq at the end and the length of the
	// message.
	__u32 tcp_seq;
} __attribute__((packed));

// Save function arguments and use them when the function returns
// key: pid_tgid
// value: SSL_* arguments
BPF_HASH(ssl_ctx_map, __u64, struct ssl_ctx_struct)

static int get_fd_from_openssl_ssl(void *ssl)
{
	int fd;
	void *rbio;

	static const int rbio_ssl_offset = 0x10;
	static const int fd_rbio_offset_v3 = 0x38;
	static const int fd_rbio_offset_v1_1_1 = 0x30;
	static const int fd_rbio_offset_v1_1_0 = 0x28;

	// The openssl library generally does not have debug information, so
	// here we use constants instead.
	bpf_probe_read(&rbio, sizeof(rbio), ssl + rbio_ssl_offset);
	bpf_probe_read(&fd, sizeof(fd), rbio + fd_rbio_offset_v3);
	if (fd > 2)
		return fd;
	bpf_probe_read(&fd, sizeof(fd), rbio + fd_rbio_offset_v1_1_1);
	if (fd > 2)
		return fd;
	bpf_probe_read(&fd, sizeof(fd), rbio + fd_rbio_offset_v1_1_0);
	return fd;
}

// int SSL_write(SSL *ssl, const void *buf, int num);
SEC("uprobe/openssl_write_enter")
int uprobe_openssl_write_enter(struct pt_regs *ctx)
{
	void *ssl = (void *)PT_REGS_PARM1(ctx);
	int fd = get_fd_from_openssl_ssl(ssl);
	__u64 id = bpf_get_current_pid_tgid();
	struct ssl_ctx_struct ssl_ctx = {
		.fd = fd,
		.buf = (void *)PT_REGS_PARM2(ctx),
		.num = (int)PT_REGS_PARM3(ctx),
		.tcp_seq = get_tcp_write_seq_from_fd(fd),
	};
	ssl_ctx_map__update(&id, &ssl_ctx);
	return 0;
}

// int SSL_write(SSL *ssl, const void *buf, int num);
SEC("uretprobe/openssl_write_exit")
int uprobe_openssl_write_exit(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct ssl_ctx_struct *ssl_ctx = ssl_ctx_map__lookup(&id);
	if (!ssl_ctx)
		return 0;

	int size = (int)PT_REGS_RC(ctx);
	if (size <= 0) {
		ssl_ctx_map__delete(&id);
		return 0;
	}

	struct data_args_t write_args = {
		.buf = ssl_ctx->buf,
		.fd = ssl_ctx->fd,
		.enter_ts = bpf_ktime_get_ns(),
		.tcp_seq = ssl_ctx->tcp_seq,
	};

	struct process_data_extra extra = {
		.vecs = false,
		.source = DATA_SOURCE_OPENSSL_UPROBE,
		.is_go_process = false,
	};

	ssl_ctx_map__delete(&id);
        active_write_args_map__update(&id, &write_args);
	if (!process_data((struct pt_regs *)ctx, id, T_EGRESS, &write_args,
			  size, &extra)) {
		bpf_tail_call(ctx, &NAME(progs_jmp_kp_map),
			      PROG_DATA_SUBMIT_KP_IDX);
	}
	active_write_args_map__delete(&id);
	return 0;
}

// int SSL_read(SSL *ssl, void *buf, int num);
SEC("uprobe/openssl_read_enter")
int uprobe_openssl_read_enter(struct pt_regs *ctx)
{
	void *ssl = (void *)PT_REGS_PARM1(ctx);
	int fd = get_fd_from_openssl_ssl(ssl);
	__u64 id = bpf_get_current_pid_tgid();
	struct ssl_ctx_struct ssl_ctx = {
		.fd = fd,
		.buf = (void *)PT_REGS_PARM2(ctx),
		.num = (int)PT_REGS_PARM3(ctx),
		.tcp_seq = get_tcp_read_seq_from_fd(fd),
	};
	ssl_ctx_map__update(&id, &ssl_ctx);
	return 0;
}

// int SSL_read(SSL *ssl, void *buf, int num);
SEC("uretprobe/openssl_read_exit")
int uprobe_openssl_read_exit(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct ssl_ctx_struct *ssl_ctx = ssl_ctx_map__lookup(&id);
	if (!ssl_ctx)
		return 0;

	int size = (int)PT_REGS_RC(ctx);
	if (size <= 0) {
		ssl_ctx_map__delete(&id);
		return 0;
	}

	struct data_args_t read_args = {
		.buf = ssl_ctx->buf,
		.fd = ssl_ctx->fd,
		.enter_ts = bpf_ktime_get_ns(),
		.tcp_seq = ssl_ctx->tcp_seq,
	};

	struct process_data_extra extra = {
		.vecs = false,
		.source = DATA_SOURCE_OPENSSL_UPROBE,
		.is_go_process = false,
	};

	ssl_ctx_map__delete(&id);
        active_read_args_map__update(&id, &read_args);
	if (!process_data((struct pt_regs *)ctx, id, T_INGRESS, &read_args,
			  size, &extra)) {
		bpf_tail_call(ctx, &NAME(progs_jmp_kp_map),
			      PROG_DATA_SUBMIT_KP_IDX);
	}
	active_read_args_map__delete(&id);
	return 0;
}
