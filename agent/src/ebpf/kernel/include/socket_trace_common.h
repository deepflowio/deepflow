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

#ifndef DF_BPF_SOCKET_TRACE_COMMON_H
#define DF_BPF_SOCKET_TRACE_COMMON_H
#define CAP_DATA_SIZE 1024		// For no-brust send buffer
#define BURST_DATA_BUF_SIZE 8192	// For brust send buffer

enum endpoint_role {
	ROLE_UNKNOWN,
	ROLE_CLIENT,
	ROLE_SERVER
};

struct __tuple_t {
	__u8 daddr[16];
	__u8 rcv_saddr[16];
	__u8 addr_len;
	__u8 l4_protocol;
	__u16 dport;
	__u16 num;
};

struct __socket_data {
	/* 进程/线程信息 */
	__u32 pid;  // 表示线程号 如果'pid == tgid'表示一个进程, 否则是线程
	__u32 tgid; // 进程号
	__u64 coroutine_id; // CoroutineID, i.e., golang goroutine id
	__u8 source; // SYSCALL,GO_TLS_UPROBE,GO_HTTP2_UPROBE
	__u8 comm[TASK_COMM_LEN]; // 进程或线程名

	/* 连接（socket）信息 */
	__u64 socket_id;     /* 通信socket唯一ID， 从启动时的时钟开始自增1 */
	struct __tuple_t tuple;

	/*
	 * 携带数据， 比如：MySQL第一次读取的数据，被第二次读取的数据携带一并发给用户
	 * 注意携带数据只有4字节大小。
	 */
	char extra_data[EBPF_CACHE_SIZE];
	__u32 extra_data_count;

	/* 追踪信息 */
	__u32 tcp_seq;
	__u64 thread_trace_id;

	/* 追踪数据信息 */
	__u64 timestamp;     // 数据捕获时间戳
	__u8  direction: 1;  // bits[0]: 方向，值为T_EGRESS(0), T_INGRESS(1)
	__u8  msg_type:  7;  // bits[1-7]: 信息类型，值为MSG_UNKNOWN(0), MSG_REQUEST(1), MSG_RESPONSE(2)

	__u64 syscall_len;   // 本次系统调用读、写数据的总长度
	__u64 data_seq;      // cap_data在Socket中的相对顺序号
	__u16 data_type;     // HTTP, DNS, MySQL
	__u16 data_len;      // 数据长度
	__u8  socket_role;   // this message is created by: 0:unkonwn 1:client(connect) 2:server(accept)
	char data[BURST_DATA_BUF_SIZE];
} __attribute__((packed));

/*
 * 整个结构大小为2^15（强制为2的次幂），目的是用（2^n - 1）与数据
 * 长度作位与操作使eBPF程序进行安全的bpf_perf_event_output()操作。
 */
struct __socket_data_buffer {
	__u32 events_num;
	__u32 len; // data部分长度
	char data[32760]; // 32760 + len(4bytes) + events_num(4bytes) = 2^15 = 32768
};

struct trace_conf_t {
	__u64 socket_id;       // 会话标识
	__u64 coroutine_trace_id;  // 同一协程的数据转发关联
	__u64 thread_trace_id; // 同一进程/线程的数据转发关联，用于多事务流转场景
	__u32 data_limit_max;  // Maximum number of data transfers
	__u32 go_tracing_timeout;
	__u32 io_event_collect_mode;
	__u64 io_event_minimal_duration;
};

struct trace_stats {
	__u64 socket_map_count;     // 对socket 链接表进行统计
	__u64 trace_map_count;     // 对同一进程/线程的多次转发表进行统计
};

struct socket_info_t {
	__u64 l7_proto;
	/*
	 * The serial number of the socket read and write data, used to
	 * correct out-of-sequence.
	 *
	 * socket读写数据的序列号，用于纠正数据乱序。
	 */
	volatile __u64 seq;

	/*
	 * mysql, kafka这种类型在读取数据时，先读取4字节
	 * 然后再读取剩下的数据，这里用于对预先读取的数据存储
	 * 用于后续的协议分析。
	 */
	__u8 prev_data[EBPF_CACHE_SIZE];
	__u8 direction: 1;
	__u8 pre_direction: 1;
	__u8 msg_type: 2;	// 保存数据类型，值为MSG_UNKNOWN(0), MSG_REQUEST(1), MSG_RESPONSE(2)
	__u8 role: 4;           // 标识socket角色：ROLE_CLIENT, ROLE_SERVER, ROLE_UNKNOWN
	bool need_reconfirm;    // l7协议推断是否需要再次确认。
	__s32 correlation_id;   // 目前用于kafka协议推断。

	__u32 peer_fd;		// 用于记录socket间数据转移的对端fd。

	/*
	 * 一旦有数据读/写就会更新这个时间，这个时间是从系统开机开始
	 * 到更新时的间隔时间单位是秒。
	 */
	__u32 update_time;
	__u32 prev_data_len;
	__u64 trace_id;
	__u64 uid; // socket唯一标识ID
} __attribute__((packed));

struct trace_key_t {
	__u32 tgid;
	__u32 pid;
	__u64 goid;
} __attribute__((packed));

struct trace_info_t {
	/*
	 * Whether traceID is zero ?
	 * For the client to actively send request, set traceID to zero.
	 */
	bool is_trace_id_zero;
	__u32 update_time; // 从系统开机开始到创建/更新时的间隔时间单位是秒
	__u32 peer_fd;	   // 用于socket之间的关联
	__u64 thread_trace_id; // 线程追踪ID
	__u64 socket_id; // Records the socket associated when tracing was created (记录创建追踪时关联的socket)
} __attribute__((packed));

struct kprobe_port_bitmap {
	__u8 bitmap[65536 / 8];
} __attribute__((packed));

typedef struct kprobe_port_bitmap ports_bitmap_t;

struct __io_event_buffer {
	__u32 bytes_count;

	// 0: write
	// 1: read
	__u32 operation;

	// nanosecond
	__u64 latency;

	// strings terminated with \0
	char filename[64];
} __attribute__((packed));

// struct ebpf_proc_info -> offsets[]  arrays index.
enum offsets_index {
	OFFSET_IDX_GOID_RUNTIME_G,
	OFFSET_IDX_CONN_TLS_CONN,
	OFFSET_IDX_SYSFD_POLL_FD,
	OFFSET_IDX_CONN_HTTP2_SERVER_CONN,
	OFFSET_IDX_TCONN_HTTP2_CLIENT_CONN,
	OFFSET_IDX_CC_HTTP2_CLIENT_CONN_READ_LOOP,
	OFFSET_IDX_CONN_GRPC_HTTP2_CLIENT,
	OFFSET_IDX_CONN_GRPC_HTTP2_SERVER,
	OFFSET_IDX_FRAMER_GRPC_TRANSPORT_LOOPY_WRITER,
	OFFSET_IDX_WRITER_GRPC_TRANSPORT_FRAMER,
	OFFSET_IDX_CONN_GRPC_TRANSPORT_BUFWRITER,
	OFFSET_IDX_SIDE_GRPC_TRANSPORT_LOOPY_WRITER,
	OFFSET_IDX_FIELDS_HTTP2_META_HEADERS_FRAME,
	OFFSET_IDX_STREAM_HTTP2_CLIENT_CONN,
	OFFSET_IDX_STREAM_ID_HTTP2_FRAME_HEADER,
	OFFSET_IDX_HTTP2_FRAMER_W,
	OFFSET_IDX_BUFWRITTER_CONN,
	OFFSET_IDX_MAX,
};

// Store the ebpf_proc_info to eBPF Map.
struct ebpf_proc_info {
	__u32 version;
	__u16 offsets[OFFSET_IDX_MAX];
	
	// In golang, itab represents type, and in interface, struct is represented
	// by the address of itab. We use itab to judge the structure type, and 
	// find the fd representing the connection after multiple jumps. These
	// types are not available in Go ELF files without a symbol table.
	// Go 用 itab 表示类型, 在 interface 中通过 itab 确定具体的 struct, 并根据
	// struct 找到表示连接的 fd.
	__u64 net_TCPConn_itab;
	__u64 crypto_tls_Conn_itab; // TLS_HTTP1,TLS_HTTP2
	__u64 credentials_syscallConn_itab; // gRPC
};

enum {
	/*
	 * 0 ~ 16 for L7 socket event (struct socket_data_buffer),
	 * indicates the number of socket data in socket_data_buffer.
	 */

	/*
	 * For event registrion
	 */
	EVENT_TYPE_MIN = 1 << 5,
	EVENT_TYPE_PROC_EXEC = 1 << 5,
	EVENT_TYPE_PROC_EXIT = 1 << 6
	// Add new event type here.
};

// Description Provides basic information about an event 
struct event_meta {
	__u32 event_type;
};

// Process execution or exit event data 
struct process_event_t {
	struct event_meta meta;
	__u32 pid; // process ID
	__u8 name[TASK_COMM_LEN]; // process name
};

#define GO_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))

#endif /* BPF_SOCKET_TRACE_COMMON */
