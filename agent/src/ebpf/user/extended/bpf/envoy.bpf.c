/*
 * This code runs using bpf in the Linux kernel.
 * Copyright 2025- The Yunshan Networks Authors.
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

#define BIO_TYPE_SOCKET (5 | 0x0400 | 0x0100)
#define FD_IOSOCKET_OFFSET 0x8

/*
 * How to obtain the socket fd from SSL (Envoy + BoringSSL):
 *
 * SSL (BoringSSL)
 *  +-- rbio (BIO*)   // read BIO
 *  |     +-- ptr (void*) -> (IoHandle*) -> IoSocketHandleImpl -> fd_
 *  |
 *  +-- wbio (BIO*)   // write BIO
 *        +-- ptr (void*) -> (IoHandle*) -> IoSocketHandleImpl -> fd_
 *
 * Notes:
 * 1. In BoringSSL, SSL does not store the socket fd directly; it uses BIO for I/O.
 * 2. Envoy stores its IoHandle* inside BIO->ptr.
 * 3. IoHandle is implemented by IoSocketHandleImpl, which contains the actual
 *    Linux socket file descriptor (int fd_).
 *
 * During debugging, you can access the fd as:
 *   ((IoSocketHandleImpl*)(ssl->rbio->ptr))->fd_
 */
static __inline void *SSL_get_rbio(void *ssl)
{
	void *bio;
	static const int bio_offset = 0x18;
	bpf_probe_read_user(&bio, sizeof(bio), ssl + bio_offset);
	return bio;
}

static __inline void *SSL_get_wbio(void *ssl)
{
	void *bio;
	static const int bio_offset = 0x20;
	bpf_probe_read_user(&bio, sizeof(bio), ssl + bio_offset);
	return bio;
}

static __inline int BIO_get_fd(void *bio)
{
	int fd = 0;
	void *ptr;
	static const int fd_offset = 0x8;
	static const int ptr_bio_offset = 0x28;
	bpf_probe_read_user(&ptr, sizeof(ptr), bio + ptr_bio_offset);
	bpf_probe_read_user(&fd, sizeof(fd), ptr + fd_offset);
	return fd;
}

static __inline void *BIO_find_type(void *base_bio)
{
	static const int loop_limit = 16;
	static const int next_bio = 0x28;
	int i, type;
	void *bio, *method;
	bio = base_bio;
	if (base_bio == NULL)
		return NULL;
#pragma unroll
	for (i = 0; i < loop_limit; i++) {
		bpf_probe_read_user(&method, sizeof(method), bio);
		bpf_probe_read_user(&type, sizeof(type), method);
		if (type == BIO_TYPE_SOCKET)
			return bio;

		bpf_probe_read_user(&bio, sizeof(bio), bio + next_bio);
		if (bio == NULL)
			break;
	}

	return NULL;
}

static __inline int SSL_get_rfd(void *ssl)
{
	void *rbio = BIO_find_type(SSL_get_rbio(ssl));
	if (rbio)
		return BIO_get_fd(rbio);
	return 0;
}

static __inline int SSL_get_wfd(void *ssl)
{
	void *rbio = BIO_find_type(SSL_get_wbio(ssl));
	if (rbio)
		return BIO_get_fd(rbio);
	return 0;
}

// int SSL_write(SSL *ssl, const void *buf, int num);
UPROG(boringssl_write_enter) (struct pt_regs * ctx) {
	void *ssl = (void *)PT_REGS_PARM1(ctx);
	int fd = SSL_get_wfd(ssl);
	__u64 id = bpf_get_current_pid_tgid();
	struct ssl_ctx_struct ssl_ctx = {
		.fd = fd,
		.buf = (void *)PT_REGS_PARM2(ctx),
		.num = (int)PT_REGS_PARM3(ctx),
		.tcp_seq = get_tcp_write_seq(fd, NULL, NULL),
	};
	ssl_ctx_map__update(&id, &ssl_ctx);
	return 0;
}

// int SSL_write(SSL *ssl, const void *buf, int num);
UPROG(boringssl_write_exit) (struct pt_regs * ctx) {
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
		.sk = NULL,
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
#if !defined(LINUX_VER_KFUNC) && !defined(LINUX_VER_5_2_PLUS)
		bpf_tail_call(ctx, &NAME(progs_jmp_kp_map),
			      PROG_DATA_SUBMIT_KP_IDX);
#endif
	}
	active_write_args_map__delete(&id);
	return 0;
}

// int SSL_read(SSL *ssl, void *buf, int num);
UPROG(boringssl_read_enter) (struct pt_regs * ctx) {
	void *ssl = (void *)PT_REGS_PARM1(ctx);
	int fd = SSL_get_rfd(ssl);
	__u64 id = bpf_get_current_pid_tgid();
	struct ssl_ctx_struct ssl_ctx = {
		.fd = fd,
		.buf = (void *)PT_REGS_PARM2(ctx),
		.num = (int)PT_REGS_PARM3(ctx),
		.tcp_seq = get_tcp_read_seq(fd, NULL, NULL),
	};
	ssl_ctx_map__update(&id, &ssl_ctx);
	return 0;
}

// int SSL_read(SSL *ssl, void *buf, int num);
UPROG(boringssl_read_exit) (struct pt_regs * ctx) {
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
		.sk = NULL,
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
#if !defined(LINUX_VER_KFUNC) && !defined(LINUX_VER_5_2_PLUS)
		bpf_tail_call(ctx, &NAME(progs_jmp_kp_map),
			      PROG_DATA_SUBMIT_KP_IDX);
#endif
	}
	active_read_args_map__delete(&id);
	return 0;
}
