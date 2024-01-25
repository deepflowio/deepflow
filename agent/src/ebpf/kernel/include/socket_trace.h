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

#ifndef DF_BPF_SOCKET_TRACE_H
#define DF_BPF_SOCKET_TRACE_H

#include "bpf_base.h"
#include "common.h"
#include "kernel.h"
#include "bpf_endian.h"
#include <sys/socket.h>
#include <stddef.h>
#include <netinet/in.h>

#define INFER_FINISH    0
#define INFER_CONTINUE	1
#define INFER_TERMINATE	2

typedef long unsigned int __kernel_size_t;

enum {
	TCPF_ESTABLISHED = (1 << 1),
	TCPF_SYN_SENT = (1 << 2),
	TCPF_SYN_RECV = (1 << 3),
	TCPF_FIN_WAIT1 = (1 << 4),
	TCPF_FIN_WAIT2 = (1 << 5),
	TCPF_TIME_WAIT = (1 << 6),
	TCPF_CLOSE = (1 << 7),
	TCPF_CLOSE_WAIT = (1 << 8),
	TCPF_LAST_ACK = (1 << 9),
	TCPF_LISTEN = (1 << 10),
	TCPF_CLOSING = (1 << 11)
};

struct user_msghdr {
	void *msg_name;
	int msg_namelen;
	struct iovec *msg_iov;
	__kernel_size_t msg_iovlen;
	void *msg_control;
	__kernel_size_t msg_controllen;
	unsigned int msg_flags;
};

struct mmsghdr {
	struct user_msghdr msg_hdr;
	unsigned int msg_len;
};

#define CONN_ADD		    0
#define CONN_DEL		    1

#define SOCK_DIR_SND_REQ            0
#define SOCK_DIR_SND_RES            1
#define SOCK_DIR_RCV_REQ            2
#define SOCK_DIR_RCV_RES            3
#define SOCK_ADD_EVENT	            4
#define SOCK_INFO_EVENT             5

#define HTTP_REQUEST_MIN_LEN 7

#define HTTP_CODE_MSG_LEN 16
#define AF_UNKNOWN 0xff

#define SOCK_CHECK_TYPE_ERROR           0
#define SOCK_CHECK_TYPE_UDP             1
#define SOCK_CHECK_TYPE_TCP_ES          2

#include "socket_trace_common.h"

struct member_fields_offset {
	__u8 ready;
	__u32 task__files_offset;
	__u32 sock__flags_offset;
	__u32 tcp_sock__copied_seq_offset;
	__u32 tcp_sock__write_seq_offset;

	__u32 struct_files_struct_fdt_offset;	// offsetof(struct files_struct, fdt)
	__u32 struct_files_private_data_offset;	// offsetof(struct file, private_data)
	__u32 struct_file_f_inode_offset;	// offsetof(struct file, f_inode)
	__u32 struct_inode_i_mode_offset;	// offsetof(struct inode, i_mode)
	__u32 struct_file_dentry_offset;	// offsetof(struct file, f_path) + offsetof(struct path, dentry)
	__u32 struct_dentry_name_offset;	// offsetof(struct dentry, d_name) + offsetof(struct qstr, name)
	__u32 struct_sock_family_offset;	// offsetof(struct sock_common, skc_family)
	__u32 struct_sock_saddr_offset;	// offsetof(struct sock_common, skc_rcv_saddr)
	__u32 struct_sock_daddr_offset;	// offsetof(struct sock_common, skc_daddr)
	__u32 struct_sock_ip6saddr_offset;	// offsetof(struct sock_common, skc_v6_rcv_saddr)
	__u32 struct_sock_ip6daddr_offset;	// offsetof(struct sock_common, skc_v6_daddr)
	__u32 struct_sock_dport_offset;	// offsetof(struct sock_common, skc_dport)
	__u32 struct_sock_sport_offset;	// offsetof(struct sock_common, skc_num)
	__u32 struct_sock_skc_state_offset;	// offsetof(struct sock_common, skc_state)
	__u32 struct_sock_common_ipv6only_offset;	// offsetof(struct sock_common, skc_flags)

};

/********************************************************/
// socket trace struct
/********************************************************/
#define socklen_t size_t

union sockaddr_t {
	struct sockaddr sa;
	struct sockaddr_in in4;
	struct sockaddr_in6 in6;
};

struct conn_info_s {
#ifdef PROBE_CONN
	__u64 id;
#endif
	struct __tuple_t tuple;
	__u16 skc_family;	/* PF_INET, PF_INET6... */
	__u16 sk_type;		/* socket type (SOCK_STREAM, etc) */
	__u8 skc_ipv6only:1;
	__u8 infer_reliable:1;	// Is protocol inference reliable?
	/*
	 * Whether the socket l7 protocol type needs
	 * to be confirmed again.
	 */
	__u8 need_reconfirm:1;
	/*
	 * True to keep the sequence number of the
	 * captured data unchanged, otherwise false.
	 */
	__u8 reserve:1;
	__u8 direction:1;	// current T_INGRESS or T_EGRESS
	__u8 prev_direction:1;	// The direction of the last saved data
	__u8 role:2;
	__u8 skc_state;
	/*
	 * Used to skip protocol checking when Linux 5.2+
	 * kernel protocol inference.
	 */
	__u8 skip_proto;
	/*
	   The matching logic is:

	   DNS 1 req ---->
	   DNS 1 res <-------
	   DNS 2 req ---->
	   DNS 2 res <-------

	   and now it is

	   DNS 1 req ---->
	   DNS 2 req ---->
	   DNS 1 res <-------
	   DNS 2 res <-------

	   Such a scene affects the whole tracking

	   DNS 1 req is IPV6, DNS 2 req is IPV4
	 */
	// FIXME: Remove this field when the call chain can correctly handle
	// the Go DNS case. Parse DNS save record type and ignore AAAA records
	// in call chain trace
	__u16 dns_q_type;

	__u32 fd;
	// The protocol of traffic on the connection (HTTP, MySQL, etc.).
	enum traffic_protocol protocol;
	// MSG_UNKNOWN, MSG_REQUEST, MSG_RESPONSE
	enum message_type message_type;
	__s32 correlation_id;	// Currently used for Kafka determination
	__u32 prev_count;	// Prestored data length
	__u32 syscall_infer_len;
	__u64 count:40;
	__u64 tcpseq_offset:24;
	char prev_buf[EBPF_CACHE_SIZE];
	char *syscall_infer_addr;
	void *sk;
	struct socket_info_t *socket_info_ptr;	/* lookup __socket_info_map */
};

struct process_data_extra {
	bool vecs:1;
	bool is_go_process:1;
	enum process_data_extra_source source;
	enum traffic_protocol protocol;
	__u64 coroutine_id;
	enum traffic_direction direction;
	enum message_type message_type;
} __attribute__ ((packed));

#define DATA_BUF_MAX  32

/*
 * BPF Tail Calls context
 */
struct infer_data_s {
	__u32 len;
	char data[DATA_BUF_MAX * 2];
};

struct tail_calls_context {
	/*
	 * If it is a tail call in the protocol inference section,
	 * the stored data here includes the inference data cache
	 * and its length; other tail calls currently do not use
	 * private data.
	 */
	char private_data[sizeof(struct infer_data_s)];
	int max_size_limit;		// The maximum size of the socket data that can be transferred.
	enum traffic_direction dir;	// Data flow direction.
	__u8 vecs: 1;			// Whether a memory vector is used ? (for specific syscall)
	__u8 is_close: 1;		// Is it a close() systemcall ?
	__u8 reserve: 6;
	struct conn_info_s conn_info;
	struct process_data_extra extra;
	__u32 bytes_count;
	struct member_fields_offset *offset;
};

struct ctx_info_s {
	union {
		struct infer_data_s infer_buf;
		struct tail_calls_context tail_call;
	};
};

enum syscall_src_func {
	SYSCALL_FUNC_UNKNOWN,
	SYSCALL_FUNC_WRITE,
	SYSCALL_FUNC_READ,
	SYSCALL_FUNC_SEND,
	SYSCALL_FUNC_RECV,
	SYSCALL_FUNC_SENDTO,
	SYSCALL_FUNC_RECVFROM,
	SYSCALL_FUNC_SENDMSG,
	SYSCALL_FUNC_RECVMSG,
	SYSCALL_FUNC_SENDMMSG,
	SYSCALL_FUNC_RECVMMSG,
	SYSCALL_FUNC_WRITEV,
	SYSCALL_FUNC_READV,
	SYSCALL_FUNC_SENDFILE
};

struct data_args_t {
	// Represents the function from which this argument group originates.
	enum syscall_src_func source_fn;
	__u32 fd;
	// For send()/recv()/write()/read().
	const char *buf;
	// For sendmsg()/recvmsg()/writev()/readv().
	const struct iovec *iov;
	size_t iovlen;
	union {
		// For sendmmsg()
		unsigned int *msg_len;
		// For clock_gettime()
		struct timespec *timestamp_ptr;
	};

	union {
		__u64 socket_id; // Use for socket close
		__u64 enter_ts;  // Timestamp for enter syscall function.
	};

	__u32 tcp_seq;		// Used to record the entry of syscalls
	union {
		ssize_t bytes_count;	// io event
		ssize_t data_seq;	// Use for socket close
	};
} __attribute__ ((packed));

struct syscall_comm_enter_ctx {
	__u64 __pad_0;		/*     0     8 */
	int __syscall_nr;	/*    offset:8     4 */
	__u32 __pad_1;		/*    12     4 */
	union {
		struct {
			__u64 fd;	/*  offset:16   8  */
			char *buf;	/*  offset:24   8  */
		};

		// For clock_gettime()
		struct {
			clockid_t which_clock;	/*   offset:16   8  */
			struct timespec *tp;	/*   offset:24   8  */
		};
	};
	size_t count;		/*    32     8 */
	unsigned int flags;
};

struct sched_comm_exit_ctx {
	__u64 __pad_0;		/*     0     8 */
	char comm[16];		/*     offset:8;       size:16 */
	pid_t pid;		/*     offset:24;      size:4  */
	int prio;		/*     offset:28;      size:4  */
};

struct sched_comm_fork_ctx {
	__u64 __pad_0;
	char parent_comm[16];
	__u32 parent_pid;
	char child_comm[16];
	__u32 child_pid;
};

struct sched_comm_exec_ctx {
	__u64 __pad_0;		/*     0     8 */
	int __data_loc;		/*    offset:8     4 */
	__u32 pid;		/*    offset:12    4 */
	__u32 old_pid;		/*    offset:16    4 */
};

struct syscall_comm_exit_ctx {
	__u64 __pad_0;		/*     0     8 */
	int __syscall_nr;	/*    offset:8     4 */
	__u32 __pad_1;		/*    12     4 */
	__u64 ret;		/*    offset:16    8 */
};

static __inline __u64 gen_conn_key_id(__u64 param_1, __u64 param_2)
{
	/*
	 * key:
	 *  - param_1 low 32bits as key high bits.
	 *  - param_2 low 32bits as key low bits.
	 */
	return ((param_1 << 32) | (__u32) param_2);
}

#define MAX_SYSTEM_THREADS 40960

struct go_interface {
	unsigned long long type;
	void *ptr;
};

struct go_slice {
	void *ptr;
	unsigned long long len;
	unsigned long long cap;
};

struct go_string {
	const char *ptr;
	unsigned long long len;
};

struct tls_conn {
	int fd;
	char *buffer;
	__u32 tcp_seq;
	void *sp;		// stack pointer
};

struct tls_conn_key {
	__u32 tgid;
	__u64 goid;
};

// Protocol inference fast cache structure
struct proto_infer_cache_t {
	/*
	 * The lower 16 bits of the process-ID/thread-ID
	 * are used as the index and correspond to the protocol type.
	 */
	__u8 protocols[65536];
};

#endif /* DF_BPF_SOCKET_TRACE_H */
