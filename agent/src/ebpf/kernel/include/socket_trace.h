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

#ifndef DF_BPF_SOCKET_TRACE_H
#define DF_BPF_SOCKET_TRACE_H

#include "bpf_base.h"
#include "common.h"
#include "kernel.h"
#include "bpf_endian.h"

#ifndef unlikely
#define unlikely(x)             __builtin_expect(!!(x), 0)
#endif

#ifndef likely
#define likely(x)               __builtin_expect(!!(x), 1)
#endif

#include <sys/socket.h>
#include <stddef.h>
#include <netinet/in.h>

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
	__u8  socket__has_wq_ptr;
	__u32 tcp_sock__copied_seq_offset;
	__u32 tcp_sock__write_seq_offset;
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

struct conn_info_t {
#ifdef PROBE_CONN
	__u64 id;
#endif
	struct __tuple_t tuple;
	__u16 skc_family;	/* PF_INET, PF_INET6... */
	__u16 sk_type;		/* socket type (SOCK_STREAM, etc) */
	__u8 skc_ipv6only : 1;
	__u8 infer_reliable : 1; // Is protocol inference reliable?
	__u8 padding : 6;
	bool need_reconfirm; // socket l7协议类型是否需要再次确认。
	bool keep_data_seq;  // 保持捕获数据的序列号不变为true，否则为false。
	__u32 fd;
	void *sk;

	// The protocol of traffic on the connection (HTTP, MySQL, etc.).
	enum traffic_protocol protocol;
	// MSG_UNKNOWN, MSG_REQUEST, MSG_RESPONSE
	enum message_type message_type;

	enum traffic_direction direction; //T_INGRESS or T_EGRESS
	enum endpoint_role role;
	size_t prev_count;
	char prev_buf[4];
	__s32 correlation_id; // 目前用于kafka判断
	enum traffic_direction prev_direction;
	struct socket_info_t *socket_info_ptr; /* lookup __socket_info_map */
};

enum process_data_extra_source {
	DATA_SOURCE_SYSCALL,
	DATA_SOURCE_GO_TLS_UPROBE,
	DATA_SOURCE_GO_HTTP2_UPROBE,
	DATA_SOURCE_OPENSSL_UPROBE,
	DATA_SOURCE_IO_EVENT,
};

struct process_data_extra {
	bool vecs : 1;
	enum process_data_extra_source source;
	enum traffic_protocol protocol;
	__u64 coroutine_id;
	enum traffic_direction direction;
	enum message_type message_type;
} __attribute__ ((packed));

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

/*
 * BPF Tail Calls context
 */
struct tail_calls_context {
	int max_size_limit;             // The maximum size of the socket data that can be transferred.
	enum traffic_direction dir;     // Data flow direction.
	bool vecs;                      // Whether a memory vector is used ? (for specific syscall)
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
	// Timestamp for enter syscall function.
	__u64 enter_ts;
	__u32 tcp_seq; // Used to record the entry of syscalls
	ssize_t bytes_count; // io event
} __attribute__ ((packed));

struct syscall_comm_enter_ctx {
	__u64 __pad_0;		/*     0     8 */
	int __syscall_nr;	/*    offset:8     4 */
	__u32 __pad_1;		/*    12     4 */
	union {
		struct {
			__u64 fd;		/*  offset:16   8  */
			char *buf;		/*  offset:24   8  */
		};

		// For clock_gettime()
		struct {
			clockid_t which_clock; /*   offset:16   8  */
			struct timespec * tp;  /*   offset:24   8  */
		};
	};
	size_t count;		/*    32     8 */
	unsigned int flags;
};

struct sched_comm_exit_ctx {
	__u64 __pad_0;          /*     0     8 */
	char comm[16];          /*     offset:8;       size:16 */
	pid_t pid;        	/*     offset:24;      size:4  */
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
	return ((param_1 << 32) | (__u32)param_2);
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
	void *sp; // stack pointer
};

struct tls_conn_key
{
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
