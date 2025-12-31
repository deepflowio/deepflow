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
#define CAP_DATA_SIZE 1024	// For no-brust send buffer
#define BURST_DATA_BUF_SIZE  16384	// For brust send buffer

#include "../config.h"

#define INVALID_OFFSET 0xFFFF

// Structure used to store kernel mount information for adaptation purposes.
// Helps to infer kernel structure offsets for different kernel versions.
struct adapt_kern_data {
	__u64 id;       // Combined identifier, e.g., {tgid, pid} of the process
	int mnt_id;     // Mount ID corresponding to the file
	__u32 mntns_id; // Mount namespace ID corresponding to the file
};

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
	__u32 pid;		// 表示线程号 如果'pid == tgid'表示一个进程, 否则是线程
	__u32 tgid;		// 进程号
	__u64 coroutine_id;	// CoroutineID, i.e., golang goroutine id
	__u8 source;		// SYSCALL,GO_TLS_UPROBE,GO_HTTP2_UPROBE
	__u8 comm[TASK_COMM_LEN];	// 进程或线程名

	/* 连接（socket）信息 */
	__u64 socket_id;	/* 通信socket唯一ID， 从启动时的时钟开始自增1 */
	struct __tuple_t tuple;

	/*
	 * 携带数据， 比如：MySQL第一次读取的数据，被第二次读取的数据携带一并发给用户
	 * 注意携带数据只有4字节大小。
	 */
	char extra_data[EBPF_CACHE_SIZE];
	__u32 extra_data_count;

	/* 追踪信息 */
	union {
		__u32 tcp_seq;
		__u32 s_dev; // Device number of the superblock, which indicates the device where the file system is mounted.
	};
	__u64 thread_trace_id;

	/* 追踪数据信息 */
	__u64 timestamp;	// 数据捕获时间戳
	__u8 direction:1;	// bits[0]: 方向，值为T_EGRESS(0), T_INGRESS(1)
	__u8 msg_type:6;	// bits[1-6]: 信息类型，值为MSG_UNKNOWN(0), MSG_REQUEST(1), MSG_RESPONSE(2)
	__u8 is_tls:1;

	__u64 syscall_len;	// 本次系统调用读、写数据的总长度
	__u64 data_seq;		// cap_data在Socket中的相对顺序号
	__u32 fd;
	__u16 data_type;	// HTTP, DNS, MySQL ...
	__u16 data_len;		// 数据长度
	__u8 socket_role;	// this message is created by: 0:unkonwn 1:client(connect) 2:server(accept)
	char data[BURST_DATA_BUF_SIZE];
} __attribute__ ((packed));

/*
 * 整个结构大小为2^15（强制为2的次幂），目的是用（2^n - 1）与数据
 * 长度作位与操作使eBPF程序进行安全的bpf_perf_event_output()操作。
 */
struct __socket_data_buffer {
	__u32 events_num;
	__u32 len;		// data部分长度
	char data[32760];	// 32760 + len(4bytes) + events_num(4bytes) = 2^15 = 32768
};

/**
 * @brief Trace statistics.
 */
struct trace_stats {
	__u64 socket_map_count;	    /**< Count of socket connection entries */
	__u64 trace_map_count;	    /**< Count of multiple forwarding entries within the same process/thread */
	__u64 push_conflict_count; /**< When periodic data push is attempted and the push_buffer_refcnt is non-zero,
					it will result in a data push conflict, and the data push action will not be executed.
					This counter is used to record the number of conflicts. */
	__u64 period_event_max_delay; /**< The maximum latency for periodic data push. */
	__u64 period_event_total_time; /**< The total elapsed time for periodic event. */
	__u64 period_event_count; /**< The number of occurrences of periodic events. */
};

struct socket_info_s {
	void *sk;
	void *socket;
	__u16 l7_proto;

	/*
	 * Indicate whether this socket is allowed for reassembly,
	 * determined by the configuration of protocol reassembly.
	 */
	__u16 allow_reassembly:1;
	__u16 finish_reasm:1;	// Has the reassembly been completed?
	__u16 udp_pre_set_addr:1;	// Is the socket address pre-set during the system call phase in the UDP protocol?
	/*
	 * Indicate that the current and next data must be pushed in
	 * the form of data reorganization.
	 * Currently only protocol inference is available on sofarpc.
	 */
	__u16 force_reasm:1;
	/*
	 * Indicates whether this socket participates in tracing.
	 * If set to 1 (or true), it means the socket does not
	 * participate in tracing.
	 */
	__u16 no_trace:1;
	__u16 data_source:4; // The source of the stored data, defined in the 'enum process_data_extra_source'. 
	__u16 unused_bits:7;
	__u32 reasm_bytes;	// The amount of data bytes that have been reassembled.

	/*
	 * The serial number of the socket read and write data, used to
	 * correct out-of-sequence.
	 *
	 * Sequence number for reading and writing data in the socket, used
	 * to correct data disorder.
	 */
	volatile __u64 seq;

	/*
	 * When reading data of types like MySQL or Kafka, the first step
	 * involves reading 4 bytes followed by reading the remaining data.
	 * Here, the pre-read data is stored for subsequent protocol analysis.
	 */
	union {
		__u8 prev_data[EBPF_CACHE_SIZE];
		__u8 ipaddr[EBPF_CACHE_SIZE];	// IP address for UDP sendto()
	};
	__u8 direction:1;
	__u8 pre_direction:1;
	__u8 unused:1;
	__u8 role:3;		// Socket role identifier: ROLE_CLIENT, ROLE_SERVER, ROLE_UNKNOWN
	__u8 is_tls:1;		// Identify whether it is a TLS connection
	__u8 tls_end:1;		// Use the Identity TLS protocol to infer whether it has been completed
	bool need_reconfirm;	// L7 protocol inference requiring confirmation.
	union {
		__u8 encoding_type;	// Currently used for OpenWire encoding inference.
		__s32 correlation_id;	// Currently used for Kafka protocol inference.
		__u16 port;	// Port for UDP sendto()
	};

	__u32 peer_fd;		// Used to record the peer fd for data transfer between sockets.

	/*
	 * This time is updated whenever there is data read/write. It
	 * represents the elapsed time in seconds from the system boot
	 * to the time of update.
	 */
	__u32 update_time;
	__u32 prev_data_len;

	__u64 trace_id;
	__u64 uid;		// Unique identifier ID for the socket.
} __attribute__ ((packed));

/**
 * @brief Used to describe the runtime state of the tracer.
 */
struct tracer_ctx_s {
	__u64 socket_id;	  /**< Session identifier */
	__u64 coroutine_trace_id; /**< Data forwarding association within the same coroutine */
	__u64 thread_trace_id;	  /**< Data forwarding association within the same process/thread, used for multi-transaction scenarios */
	__u32 data_limit_max;	  /**< Maximum number of data transfers */
	__u32 go_tracing_timeout; /**< Go tracing timeout */
	__u32 io_event_collect_mode; /**< IO event collection mode */
	__u64 io_event_minimal_duration; /**< Minimum duration for IO events */
	bool virtual_file_collect_enabled;    /**< Enable virtual file collection */
	int push_buffer_refcnt;	/**< Reference count of the data push buffer */
	__u64 last_period_timestamp; /**< Record the timestamp of the last periodic check of the push buffer. */
	__u64 period_timestamp;	/**< Record the timestamp of the periodic check of the push buffer. */
	bool disable_tracing;  /**< Disable tracing feature. */
	struct socket_info_s sk_info; /**< Prevent stack overflow; this option is used as an alternative to stack allocation. */
};

struct trace_key_t {
	__u32 tgid;
	__u32 pid;
	__u64 goid;
} __attribute__ ((packed));

struct trace_info_t {
	__u8 reserve;
	__u32 update_time;	// 从系统开机开始到创建/更新时的间隔时间单位是秒
	__u32 peer_fd;		// 用于socket之间的关联
	__u64 thread_trace_id;	// 线程追踪ID
	__u64 socket_id;	// Records the socket associated when tracing was created (记录创建追踪时关联的socket)
} __attribute__ ((packed));

struct kprobe_port_bitmap {
	__u8 bitmap[65536 / 8];
} __attribute__ ((packed));

typedef struct kprobe_port_bitmap ports_bitmap_t;

struct __dentry_name {
	char name[DENTRY_NAME_SIZE];
};

struct __io_event_buffer {
	__u32 bytes_count;

	// 0: write
	// 1: read
	__u32 operation;

	// nanosecond
	__u64 latency;

	// The number of bytes of offset within the file content
	__u64 offset;

	// Mount ID of the file’s mount
	int mnt_id;
	// Mount namespace ID of the file’s mount
	__u32 mntns_id;

	// filename length
	__u32 len;

	// strings terminated with \0
	char filename[FILE_PATH_SZ];
} __attribute__ ((packed));

struct user_io_event_buffer {
	__u32 bytes_count;

	// 0: write
	// 1: read
	__u32 operation;

	// nanosecond
	__u64 latency;

	// The number of bytes of offset within the file content
	__u64 offset;

	__u32 file_type;
	// strings terminated with \0
	char filename[FILE_NAME_SZ];
	char mount_source[MOUNT_SOURCE_SZ];
	char mount_point[MOUNT_POINT_SZ];
	char file_dir[FILE_PATH_SZ];
	int mnt_id;
	__u32 mntns_id;
} __attribute__ ((packed));

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
	__u64 crypto_tls_Conn_itab;	// TLS_HTTP1,TLS_HTTP2
	__u64 credentials_syscallConn_itab;	// gRPC
};

enum {
	/*
	 * 0 ~ 256 for L7 socket event (struct socket_data_buffer),
	 * indicates the number of socket data in socket_data_buffer.
	 */

	/*
	 * For event registrion
	 */
	EVENT_TYPE_MIN = 1 << 9,
	EVENT_TYPE_PROC_EXEC = 1 << 9,
	EVENT_TYPE_PROC_EXIT = 1 << 10
	    // Add new event type here.
};

// Description Provides basic information about an event 
struct event_meta {
	__u32 event_type;
};

// Process execution or exit event data 
struct process_event_t {
	struct event_meta meta;
	__u32 pid:31;		// process ID
	__u32 maybe_thread:1;
	__u8 name[TASK_COMM_LEN];	// process name
};

struct debug_data {
	__u16 magic;
	__u8 fun;
	__u8 num;
	union {
		__u32 len;
		__u8 buf[4];
	};
};

#define GO_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))

struct member_fields_offset {
	__u8 ready;
	__u8 kprobe_invalid:1;			// This indicates that the KPROBE feature has been disabled.
	__u8 enable_unix_socket:1;		// Enable flag for Unix socket tracing
	__u8 files_infer_done:1;		// 0: file-related structure offset inference not completed
						// 1: file-related structure offset inference completed
	__u8 reserved:5;
	__u16 struct_dentry_d_parent_offset;    // offsetof(struct dentry, d_parent)
	__u32 task__files_offset;
	__u32 sock__flags_offset;
	__u32 tcp_sock__copied_seq_offset;
	__u32 tcp_sock__write_seq_offset;

	__u16 struct_files_struct_fdt_offset;	// offsetof(struct files_struct, fdt)
	__u16 struct_file_f_pos_offset;		// offsetof(struct file, f_pos)
	__u32 struct_file_private_data_offset;	// offsetof(struct file, private_data)
	__u32 struct_file_f_op_offset;		// offsetof(struct file, f_op)
	__u32 struct_file_operations_read_iter_offset; // offsetof(struct file_operations, read_iter)
	__u32 struct_file_f_inode_offset;	// offsetof(struct file, f_inode)
	__u32 struct_inode_i_mode_offset;	// offsetof(struct inode, i_mode)
	__u32 struct_inode_i_sb_offset;		// offsetof(struct inode, i_sb)
	__u32 struct_super_block_s_dev_offset;	// offsetof(struct super_block, s_dev)
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

	/*
 	 * Mount information related offsets
 	 */
	__u16 struct_file_f_path_offset;      // offsetof(struct file, f_path)
	__u16 struct_path_mnt_offset;         // offsetof(struct path, mnt)
	__u16 struct_mount_mnt_offset;	      // offsetof(struct mount, mnt)
	__u16 struct_mount_mnt_ns_offset;     // offsetof(struct mount, mnt_ns)
	__u16 struct_mnt_namespace_ns_offset; // offsetof(struct mnt_namespace, ns)
	__u16 struct_ns_common_inum_offset;   // offsetof(struct mnt_common, inum)
	__u16 struct_mount_mnt_id_offset;     // offsetof(struct mount, mnt_id)
};

typedef struct member_fields_offset bpf_offset_param_t;

// Used for obtaining packet statistics.
enum pkts_stats_type {
	STATS_RECV_PKTS,
	STATS_XMIT_PKTS,
	STATS_RECV_BYTES,
	STATS_XMIT_BYTES,
	STATS_MISS_PKTS,
	STATS_INVAL_PKTS,
	STATS_TYPE_NUM
};

#endif /* BPF_SOCKET_TRACE_COMMON */
