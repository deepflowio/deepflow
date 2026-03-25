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
 * Due to the limitation of 4096 eBPF instructions in Linux kernels below version 5.2,
 * the protocol inference code can easily exceed this limit when more protocols are added.
 * To address this issue, the protocol inference logic has been split into three separate programs.
 * The updated workflow is as follows:
 *
 * [openssl Uprobe] --
 *                   |
 *                  \|/
 * [syscall Kprobe/tracepoint] --> [protocol inference 2] --> [protocol inference 3] --> [data submission] --> [data output]
 *       |                                                                                                       /|\
 *       |                                                                                                        |
 *       ] ------------------------------------------------------
 *
 * Explanation:
 *   `[openssl Uprobe]` and `[syscall Kprobe/tracepoint]` perform initial setup for eBPF probe entry,
 *   and contain the first part of Layer 7 (L7) protocol inference logic.
 *   `protocol inference 2` : part 2 of protocol inference
 *   `protocol inference 3` : part 3 of protocol inference
 *   Newly added protocol inference code is recommended to be placed within the `infer_protocol_3()` interface.
 */
#ifndef DF_BPF_PROTO_INFER_H
#define DF_BPF_PROTO_INFER_H

#include "common.h"
#include "socket_trace.h"

#define L7_PROTO_INFER_PROG_1	0
#define L7_PROTO_INFER_PROG_2	1

static __inline bool is_nginx_process(void)
{
	char comm[TASK_COMM_LEN];
	bpf_get_current_comm(comm, sizeof(comm));

	if (comm[0] == 'n' && comm[1] == 'g' && comm[2] == 'i' &&
	    comm[3] == 'n' && comm[4] == 'x' && comm[5] == '\0')
		return true;
	return false;
}

static __inline bool is_set_ports_bitmap(ports_bitmap_t * ports, __u16 port)
{
	/*
	 * Avoid using the form `ports->bitmap[port >> 3]` to index the
	 * bitmap, as it may lead to the following error:
	 *
	 *   115: (85) call bpf_map_lookup_elem#1
	 *   116: (15) if r0 == 0x0 goto pc+5
	 *   117: (79) r1 = *(u64 *)(r10 -168)
	 *   118: (77) r1 >>= 3
	 *   119: (0f) r0 += r1
	 *   120: (71) r1 = *(u8 *)(r0 +0)
	 *   R0 unbounded memory access, make sure to bounds check any array
	 *   access into a map
	 *
	 * The error message indicates that we need to perform boundary checks
	 * for R0.
	 */
	const __u8 *end = (void *)ports + sizeof(*ports);
	const __u8 *start = (__u8 *) ports;
	const __u8 *addr = start + (port >> 3);
	if (addr >= start && addr < end) {
		/*
		 * Here, we must restrict the type of 'mask' to 'u8'; otherwise,
		 * when compiling as 'u64,' errors will occur upon loading the
		 * program:
		 *
		 *   122: (3d) if r1 >= r0 goto pc+6
		 *   123: (79) r2 = *(u64 *)(r10 -168)
		 *   124: (57) r2 &= 7
		 *   125: (71) r1 = *(u8 *)(r1 +0)
		 *   R1 unbounded memory access, make sure to bounds check any
		 *   array access into a map
		 */
		const __u8 mask = 1 << (port & 0x7);
		if (*addr & mask)
			return true;
	}

	return false;
}

static __inline bool
__protocol_port_check(enum traffic_protocol proto,
		      struct conn_info_s *conn_info, __u8 prog_num)
{
	if (!is_protocol_enabled(proto)) {
		return false;
	}

	if (conn_info->sk_type == SOCK_UNIX)
		return true;

	__u32 key = proto;
	ports_bitmap_t *ports = proto_ports_bitmap__lookup(&key);
	if (ports) {
		/*
		 * If the "is_set_ports_bitmap()" function is used in both stages,
		 * there may be the following error when loading an eBPF program in
		 * the 4.14 kernel:
		 * `failed. name: df_T_exit_sendmmsg, Argument list too long errno: 7`
		 * To avoid this situation, it is necessary to differentiate the calls.
		 *
		 * FIX: The original code used a comma operator ',' instead of '||'
		 * in the prog_num == L7_PROTO_INFER_PROG_1 branch, which caused the
		 * first is_set_bitmap() call result to be silently discarded.
		 */
		if (prog_num == L7_PROTO_INFER_PROG_1) {
			if (is_set_bitmap(ports->bitmap, conn_info->tuple.num) ||
			    is_set_bitmap(ports->bitmap, conn_info->tuple.dport))
				return true;
		} else {
			if (is_set_ports_bitmap(ports, conn_info->tuple.num) ||
			    is_set_ports_bitmap(ports, conn_info->tuple.dport))
				return true;
		}
	}

	return false;
}

static __inline bool
protocol_port_check_1(enum traffic_protocol proto,
		      struct conn_info_s *conn_info)
{
	return __protocol_port_check(proto, conn_info, L7_PROTO_INFER_PROG_1);
}

static __inline bool
protocol_port_check_2(enum traffic_protocol proto,
		      struct conn_info_s *conn_info)
{
#if defined(LINUX_VER_KFUNC) || defined(LINUX_VER_5_2_PLUS)
	return __protocol_port_check(proto, conn_info, L7_PROTO_INFER_PROG_1);
#else
	return __protocol_port_check(proto, conn_info, L7_PROTO_INFER_PROG_2);
#endif
}

static __inline bool is_infer_socket_valid(struct socket_info_s *sk_info)
{
	/*
	 * Since the kernel collects TLS handshake data, the socket type is set
	 * to 'PROTO_TLS' during this process. UPROBE-collected TLS plaintext data
	 * needs to be re-evaluated, so here we specify that a socket type of
	 * 'PROTO_TLS' is invalid and requires re-evaluation.
	 *
	 * Additionally, 'PROTO_UNKNOWN' also needs to be re-evaluated. This situation
	 * is common when pre-storing some data, which establishes socket information
	 * but sets 'l7_proto' to 'PROTO_UNKNOWN'. The data needs to be combined with
	 * the next segment to be re-evaluated as a whole.
	 */
	return (sk_info != NULL && sk_info->uid != 0
		&& sk_info->l7_proto != PROTO_TLS
		&& sk_info->l7_proto != PROTO_UNKNOWN);
}

// When calling this function, count must be a constant, and at this time, the
// compiler can optimize it into an immediate value and write it into the
// instruction.
static __inline void save_prev_data_from_kern(const char *buf,
					      struct conn_info_s *conn_info,
					      size_t count)
{
	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		bpf_probe_read_kernel(conn_info->socket_info_ptr->prev_data,
				      count, buf);

		conn_info->socket_info_ptr->prev_data_len = count;
		/*
		 * This piece of data needs to be merged with subsequent data, so
		 * the direction of the previous piece of data needs to be saved here.
		 *
		 * For example:
		 * A  --> out
		 * B1 <-- in
		 * B2 <-- in
		 *
		 * The data of 'B1' and 'B2' will be merged into a single data stream,
		 * meaning that the data from B1 will be merged into 'B2' for transmission.
		 * Therefore, the direction of the previously merged data from B2 will be
		 * the same as the direction of 'A' (out), rather than the direction of 'B1'.
		 * This is saved using 'pre_direction'.
		 */
		conn_info->socket_info_ptr->pre_direction =
		    conn_info->socket_info_ptr->direction;
		conn_info->socket_info_ptr->direction = conn_info->direction;
	} else {
		bpf_probe_read_kernel(conn_info->prev_buf, count, buf);
		conn_info->prev_count = count;
	}
}

static __inline bool is_same_command(char *a, char *b)
{
	static const int KERNEL_COMM_MAX = 16;
	for (int idx = 0; idx < KERNEL_COMM_MAX; ++idx) {
		if (a[idx] == '\0' && a[idx] == b[idx])
			return true;

		if (a[idx] != b[idx])
			return false;
	}
	// 16个字符都相同,并且没有遇到'\0',理论上不应该执行到这里
	return true;
}

static __inline bool is_current_comm(char *comm)
{
	static const int KERNEL_COMM_MAX = 16;
	char current_comm[KERNEL_COMM_MAX];

	if (bpf_get_current_comm(&current_comm, sizeof(current_comm)))
		return false;

	return is_same_command(comm, current_comm);
}

static __inline int is_http_response(const char *data)
{
	/*
	 * Here, we have removed HTTP/1.x 1xx-type responses because if a server
	 * returns two consecutive responses - such as HTTP 100 and HTTP 200 -
	 * after an HTTP request, the upper layer will not process the HTTP 100
	 * response. This results in the HTTP request and the HTTP 200 response
	 * failing to be merged.
	 */
	return (data[0] == 'H' && data[1] == 'T' && data[2] == 'T'
		&& data[3] == 'P' && data[4] == '/' && data[5] == '1'
		&& data[6] == '.' && data[8] == ' ' && data[9] != '1');
}

/*
 * FIX: The original code used ']' (array close bracket) instead of the
 * correct '||' (logical OR) combined with proper array indexing 'data[N]'.
 * This caused all HTTP method checks beyond the first character to be
 * syntactically broken and would fail to compile or produce wrong results.
 *
 * Example of original broken code:
 *   if ((data[1] != 'E') ] != 'L') ] != 'E') ...
 * Fixed to:
 *   if ((data[1] != 'E') || (data[2] != 'L') || (data[3] != 'E') ...
 */
static __inline int is_http_request(const char *data, int data_len,
				    struct conn_info_s *conn_info)
{
	switch (data[0]) {
		/* DELETE */
	case 'D':
		if ((data[1] != 'E') || (data[2] != 'L') || (data[3] != 'E') ||
		    (data[4] != 'T') || (data[5] != 'E') || (data[6] != ' ')) {
			return 0;
		}
		break;

		/* GET */
	case 'G':
		if ((data[1] != 'E') || (data[2] != 'T') || (data[3] != ' ')) {
			return 0;
		}
		break;

		/* HEAD */
	case 'H':
		if ((data[1] != 'E') || (data[2] != 'A') || (data[3] != 'D') ||
		    (data[4] != ' ')) {
			return 0;
		}

		/*
		 * In the context of NGINX, we exclude tracking of HEAD type requests
		 * in the HTTP protocol, as HEAD requests are often used for health
		 * checks. This avoids generating excessive HEAD type data in the call
		 * chain tree.
		 */
		if (is_nginx_process())
			conn_info->no_trace = true;
		break;

		/* OPTIONS */
	case 'O':
		if (data_len < 8 || (data[1] != 'P') || (data[2] != 'T') ||
		    (data[3] != 'I') || (data[4] != 'O') || (data[5] != 'N') ||
		    (data[6] != 'S') || (data[7] != ' ')) {
			return 0;
		}
		break;

		/* PATCH/POST/PUT */
	case 'P':
		switch (data[1]) {
		case 'A':
			if ((data[2] != 'T') || (data[3] != 'C') ||
			    (data[4] != 'H') || (data[5] != ' ')) {
				return 0;
			}
			break;
		case 'O':
			if ((data[2] != 'S') || (data[3] != 'T') ||
			    (data[4] != ' ')) {
				return 0;
			}
			break;
		case 'U':
			if ((data[2] != 'T') || (data[3] != ' ')) {
				return 0;
			}
			break;
		default:
			return 0;
		}
		break;

	default:
		return 0;
	}

	return 1;
}

static __inline __u8 get_block_fragment_offset(__u8 fix_sz,
					       __u8 flags_padding,
					       __u8 flags_priority)
{
	__u8 offset = 0;
	offset = fix_sz;

	if (flags_padding)
		offset += 1;
	if (flags_priority)
		offset += 5;

	return offset;
}

#define try_find__static_table_idx() \
do { \
	if (table_idx > max || table_idx == 0) \
		table_idx = buf[++offset] & 0x7f; \
} while(0)

static __inline __u8 find_idx_from_block_fragment(const __u8 * buf,
						  __u8 offset, __u8 max)
{
	/*
	 * Header Block Fragment解析出静态表索引值，最多取前面6个字节。
	 * 例如：Header Block Fragment: ddda8386e6e5e4e3e2d0 最多分析'dd da 83 86 e6 e5'
	 */
	__u8 table_idx = buf[offset] & 0x7f;
	try_find__static_table_idx();
	try_find__static_table_idx();
	try_find__static_table_idx();
	try_find__static_table_idx();
	try_find__static_table_idx();

	return table_idx;
}

static bool is_http2_magic(const char *buf_src, size_t count)
{
	static const char magic[] = "PRI * HTTP/2";
	char buffer[sizeof(magic)] = { 0 };
	bpf_probe_read_user(buffer, sizeof(buffer) - 1, buf_src);
	for (int idx = 0; idx < sizeof(magic); ++idx) {
		if (magic[idx] == buffer[idx])
			continue;
		return false;
	}
	return true;
}

// https://tools.ietf.org/html/rfc7540#section-4.1
// 帧的结构:
// +-----------------------------------------------+
// |                 Length (24)                   |
// +---------------+---------------+---------------+
// |   Type (8)    |   Flags (8)   |
// +-+-------------+---------------+-------------------------------+
// |R|                 Stream Identifier (31)                      |
// +=+=============================================================+
// |                   Frame Payload (0...)                      ...
// +---------------------------------------------------------------+
//
// HEADERS 帧格式:
// +---------------+
// |Pad Length? (8)|
// +-+-------------+-----------------------------------------------+
// |E|                 Stream Dependency? (31)                     |
// +-+-------------+-----------------------------------------------+
// |  Weight? (8)  |
// +-+-------------+-----------------------------------------------+
// |                   Header Block Fragment (*)                 ...
// +---------------------------------------------------------------+
// |                           Padding (*)                       ...
// +---------------------------------------------------------------+
//
// Pad Length: 指定 Padding 长度，存在则代表 PADDING flag 被设置
// E: 一个比特位声明流的依赖性是否是排他的，存在则代表 PRIORITY flag 被设置
// Stream Dependency: 指定一个 stream identifier，代表当前流所依赖的流的 id，存在则代表 PRIORITY flag 被设置
// Weight: 一个无符号 8bit，代表当前流的优先级权重值 (1~256)，存在则代表 PRIORITY flag 被设置
// Header Block Fragment: header 块片段
// Padding: 填充字节，没有具体语义，作用与 DATA 的 Padding 一样，存在则代表 PADDING flag 被设置
//
// request:
//      1       :authority
//      2       :method GET
//      3       :method POST
//      4       :path  /
//      5       :path  /index.html
// others as response.
static __inline enum message_type parse_http2_headers_frame(const char
							    *buf_kern,
							    size_t syscall_len,
							    const char *buf_src,
							    size_t count,
							    struct conn_info_s
							    *conn_info,
							    const bool is_first)
{
#define HTTPV2_FRAME_PROTO_SZ           0x9
#define HTTPV2_FRAME_TYPE_DATA	        0x0
#define HTTPV2_FRAME_TYPE_HEADERS       0x1
// In some cases, the compiled binary instructions exceed the limit, the
// specific reason is unknown, reduce the number of cycles of http2, which
// may cause http2 packet loss
#if defined(LINUX_VER_KFUNC) || defined(LINUX_VER_5_2_PLUS)
#define HTTPV2_LOOP_MAX 8
#else
#define HTTPV2_LOOP_MAX 5
#endif
/*
 *  HTTPV2_FRAME_READ_SZ取值考虑以下3部分：
 *  (1) fixed 9-octet header
 *
 *  HEADERS 帧:
 *  (2) Pad Length (8) + E(1) + Stream Dependency(31) + Weight(8) = 6 bytes
 *  (3) Header Block Fragment (*) 取 6bytes
 */
#define HTTPV2_FRAME_READ_SZ            21
#define HTTPV2_STATIC_TABLE_IDX_MAX     61

	/*
	 * If the server reads data in multiple passes, and the previous pass
	 * has already read the first 9 bytes of the protocol header, and it
	 * has been determined as HEADER, then the current data is directly
	 * PUSHed to the upper layer.
	 */
	if (conn_info->prev_count == HTTPV2_FRAME_PROTO_SZ) {
		return MSG_REQUEST;
	}

	// fixed 9-octet header
	if (count < HTTPV2_FRAME_PROTO_SZ)
		return MSG_UNKNOWN;

	__u32 offset = 0;
	__u8 flags_unset = 0, flags_padding = 0, flags_priority = 0;
	__u8 type = 0, reserve = 0, static_table_idx, i, block_fragment_offset;
	__u8 msg_type = MSG_UNKNOWN;
	__u8 buf[HTTPV2_FRAME_READ_SZ] = { 0 };

	// When Magic and header are in the same TCP packet, it will cause
	// packet loss. When Magic is detected, the offset is corrected to the
	// starting position of the header.
	if (is_first && is_http2_magic(buf_src, count)) {
		static const int HTTP2_MAGIC_SIZE = 24;
		offset = HTTP2_MAGIC_SIZE;
	} else {
		/*
	 	 * The frame payload length (excluding the initial 9 bytes) must not
		 * exceed the actual length of the system call.
	 	 */
		if ((__bpf_ntohl(*(__u32 *) buf_kern) >> 8) > syscall_len - HTTPV2_FRAME_PROTO_SZ)
			return MSG_UNKNOWN;

		/*
		 * The highest bit of the 5th byte (i.e., the first byte of the Stream
		 * Identifier) must be 0, indicating that the reserved bit (R) is 0;
		 * otherwise, it violates the HTTP/2 specification.
		 */
		if (buf_kern[5] >> 7 != 0)
			return MSG_UNKNOWN;
	}

	/*
	 * Use '#pragma unroll' to avoid the following error during the
	 * loading process in Linux 5.2.x:
	 * bpf load "socket-trace-bpf-linux-5.2_plus" failed, error:Invalid argument (22)
	 */
#pragma unroll
	for (i = 0; i < HTTPV2_LOOP_MAX; i++) {

		/*
		 * 这个地方考虑iovecs的情况，传递过来进行协议推断的数据
		 * 是&args->iov[0]第一个iovec，count的值也是第一个
		 * iovec的数据长度。存在协议分析出来长度是大于count的情况
		 * 因此这里不能通过"offset == count"来进行判断。
		 */
		if (offset >= count)
			break;

		bpf_probe_read_user(buf, sizeof(buf), buf_src + offset);
		offset += (__bpf_ntohl(*(__u32 *) buf) >> 8) +
		    HTTPV2_FRAME_PROTO_SZ;
		type = buf[3];

		if (type == HTTPV2_FRAME_TYPE_DATA && !is_first)
			return MSG_REQUEST;

		// 如果不是Header继续寻找下一个Frame
		if (type != HTTPV2_FRAME_TYPE_HEADERS)
			continue;

		flags_unset = buf[4] & 0xd2;
		flags_padding = buf[4] & 0x08;
		flags_priority = buf[4] & 0x20;
		reserve = buf[5] & 0x01;

		// flags_unset和reserve必须为0，否则直接放弃判断。
		if (flags_unset || reserve)
			return MSG_UNKNOWN;

		if (syscall_len == HTTPV2_FRAME_PROTO_SZ) {
			msg_type = MSG_PRESTORE;
			break;
		}

		/*
		 * If the protocol inference is complete, it can be directly
		 * pushed to the upper layer.
		 */
		if (!is_first)
			return MSG_REQUEST;

		/*
		 * 根据帧结构中的flags的不同设置(具体检查PADDING位和PRIORITY位)
		 * 来确定HEADERS帧的内容从而得到Header Block Fragment的偏移。
		 */
		block_fragment_offset =
		    get_block_fragment_offset(HTTPV2_FRAME_PROTO_SZ,
					      flags_padding, flags_priority);

		// 对Header Block Fragment的内容进行分析得到静态表的索引。
		static_table_idx =
		    find_idx_from_block_fragment(buf, block_fragment_offset,
						 HTTPV2_STATIC_TABLE_IDX_MAX);

		// 静态索引表的Index取值范围 [1, 61]
		if (static_table_idx > HTTPV2_STATIC_TABLE_IDX_MAX &&
		    static_table_idx == 0)
			continue;

		/*
		 * ref : https://datatracker.ietf.org/doc/html/rfc7541#appendix-A
		 * Static Table Entries:
		 * +-------+-----------------------------+---------------+
		 * | Index | Header Name                 | Header Value  |
		 * +-------+-----------------------------+---------------+
		 * | 1     | :authority                  |               |
		 * | 2     | :method                     | GET           |
		 * | 3     | :method                     | POST          |
		 * | 4     | :path                       | /             |
		 * | 5     | :path                       | /index.html   |
		 * | 6     | :scheme                     | http          |
		 * | 7     | :scheme                     | https         |
		 * | 8     | :status                     | 200           |
		 * | 9     | :status                     | 204           |
		 * | 10    | :status                     | 206           |
		 * | 11    | :status                     | 304           |
		 * | 12    | :status                     | 400           |
		 * | 13    | :status                     | 404           |
		 * | 14    | :status                     | 500           |
		 */
		if (static_table_idx >= 1 && static_table_idx <= 7) {
			msg_type = MSG_REQUEST;
			conn_info->role =
			    (conn_info->direction ==
			     T_INGRESS) ? ROLE_SERVER : ROLE_CLIENT;

		} else if (static_table_idx >= 8 && static_table_idx <= 14) {
			conn_info->role =
			    (conn_info->direction ==
			     T_EGRESS) ? ROLE_SERVER : ROLE_CLIENT;
			msg_type = MSG_RESPONSE;
		}

		break;
	}

	if (msg_type == MSG_PRESTORE)
		save_prev_data_from_kern(buf_kern, conn_info,
					 HTTPV2_FRAME_PROTO_SZ);

	return msg_type;
}

/*
 * Note: infer_http2_message() must be executed within infer_protocol_1() because
 * the KPROBE feature might be disabled, while UPROBE depends on the inference from
 * KPROBE. The upper layer retains the execution of infer_protocol_1(), but may skip
 * the execution of infer_protocol_2(). Therefore, it is necessary to ensure that it
 * is placed inside infer_protocol_1().
 */
static __inline enum message_type infer_http2_message(const char *buf_kern,
						      size_t syscall_len,
						      const char *buf_src,
						      size_t count,
						      struct conn_info_s
						      *conn_info)
{
	if (!protocol_port_check_1(PROTO_HTTP2, conn_info))
		return MSG_UNKNOWN;

	// When go uprobe http2 cannot be used, use kprobe/tracepoint to collect data
	if (skip_http2_kprobe()) {
		if (conn_info->direction == T_INGRESS &&
		    conn_info->tuple.l4_protocol == IPPROTO_TCP) {
			struct http2_tcp_seq_key tcp_seq_key = {
				.tgid = bpf_get_current_pid_tgid() >> 32,
				.fd = conn_info->fd,
				.tcp_seq_end =
				    get_tcp_read_seq(conn_info->fd, NULL, NULL),
			};
			// make linux 4.14 validator happy
			__u32 tcp_seq = tcp_seq_key.tcp_seq_end - count;
			bpf_map_update_elem(&http2_tcp_seq_map, &tcp_seq_key,
					    &tcp_seq, BPF_NOEXIST);
		}
		return MSG_UNKNOWN;
	}

	bool is_first = true;	// Is it the first inference?
	if (is_infer_socket_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_HTTP2)
			return MSG_UNKNOWN;
		is_first = false;
	}

	enum message_type ret =
	    parse_http2_headers_frame(buf_kern, syscall_len, buf_src, count,
				      conn_info, is_first);

	return ret;
}

static __inline enum message_type infer_http_message(const char *buf,
						     size_t count,
						     struct conn_info_s
						     *conn_info)
{
	// HTTP/1.1 200 OK\r\n (HTTP response is 17 characters)
	// GET x HTTP/1.1\r\n (HTTP response is 16 characters)
	// MAY be without "OK", ref:https://www.rfc-editor.org/rfc/rfc7231
	if (count < 14) {
		return MSG_UNKNOWN;
	}

	if (!protocol_port_check_1(PROTO_HTTP1, conn_info))
		return MSG_UNKNOWN;

	if (is_infer_socket_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_HTTP1)
			return MSG_UNKNOWN;
	}

	if (is_http_response(buf)) {
		return MSG_RESPONSE;
	}

	if (is_http_request(buf, count, conn_info)) {
		return MSG_REQUEST;
	}

	return MSG_UNKNOWN;
}

// MySQL and Kafka need the previous n bytes of data for inference
static __inline __u32 check_and_fetch_prev_data(struct conn_info_s *conn_info)
{
	if (conn_info->socket_info_ptr != NULL &&
	    conn_info->socket_info_ptr->prev_data_len > 0) {
		/*
		 * For adjacent read/write in the same direction.
		 */
		if (conn_info->direction ==
		    conn_info->socket_info_ptr->direction) {
			bpf_probe_read_kernel(conn_info->prev_buf,
					      sizeof(conn_info->prev_buf),
					      conn_info->socket_info_ptr->
					      prev_data);
			conn_info->prev_count =
			    conn_info->socket_info_ptr->prev_data_len;
			/*
			 * When data is merged, that is, when two or more data with the same
			 * direction are merged together and processed as one data, the previously
			 * saved direction needs to be restored.
			 *
			 * At the beginning of the inference stage, 'socket_info_ptr->direction'
			 * represents the direction of the previously sent data. During the final
			 * data transmission stage, it will be updated to reflect the direction of
			 * the current data.
			 */
			conn_info->socket_info_ptr->direction =
			    conn_info->socket_info_ptr->pre_direction;
		}

		/*
		 * Clean up previously stored data.
		 */
		conn_info->socket_info_ptr->prev_data_len = 0;
	}

	return conn_info->prev_count;
}

// MySQL packet:
//      0         8        16        24        32
//      +---------+---------+---------+---------+
//      |        payload_length       | seq_id  |
//      +---------+---------+---------+---------+
//      |                                       |
//      .            ...  body ...              .
//      .                                       .
//      .                                       .
//      +----------------------------------------
// ref : https://dev.mysql.com/doc/internals/en/com-process-kill.html
static __inline enum message_type infer_mysql_message(const char *buf,
						      size_t count,
						      struct conn_info_s
						      *conn_info)
{
	if (!protocol_port_check_1(PROTO_MYSQL, conn_info))
		return MSG_UNKNOWN;

	if (count == 4) {
		save_prev_data_from_kern(buf, conn_info, 4);
		return MSG_PRESTORE;
	}

	/*
	 * ref: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query.html
	 */
	static const __u8 kComQuery = 0x03;
	static const __u8 kComConnect = 0x0b;
	static const __u8 kComStmtPrepare = 0x16;
	static const __u8 kComStmtExecute = 0x17;
	static const __u8 kComStmtClose = 0x19;
	static const __u8 kComStmtQuit = 0x01;

	if (is_infer_socket_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_MYSQL)
			return MSG_UNKNOWN;
	}

	if (!conn_info->sk)
		return MSG_UNKNOWN;

	__u32 len;
	__u8 seq, com, point_1, point_2;

	len = *((__u32 *) buf) & 0x00ffffff;
	seq = buf[3];
	com = buf[4];
	point_1 = buf[6];
	point_2 = buf[8];

	if (conn_info->prev_count == 4) {
		len = *(__u32 *) conn_info->prev_buf & 0x00ffffff;
		if (len == count) {
			seq = conn_info->prev_buf[3];
			count += 4;
			com = buf[0];
			point_1 = buf[2];
			point_2 = buf[4];
		}
	}

	if (count < 5 || len == 0)
		return MSG_UNKNOWN;

	bool is_mysqld = is_current_comm("mysqld");
	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		/*
		 * Ensure the authentication response packet is captured
		 * and distinguish it based on the 5th byte (Payload start):
		 *
		 * - **Authentication Success (OK Packet):** `0x00`
		 * - **Authentication Failure (ERR Packet):** `0xFF`
		 * - **Authentication Switch Request (Auth Switch Request):** `0xFE`
		 */
		if (seq <= 1 || (seq == 2 && (com == 0x0 || com == 0xFF || com == 0xFE)))
			goto out;

		return MSG_UNKNOWN;
	}

	/*
	 * When initially determining the process, if it is a 'mysqld' process,
	 * the judgment is completed as the MySQL protocol.
	 */
	if (is_mysqld) {
		return conn_info->direction ==
		    T_INGRESS ? MSG_REQUEST : MSG_RESPONSE;
	}

	/*
	 * Strengthen length checking, such as the following MYSQL protocol data:
	 * MySQL Protocol
	 *   - Packet Length: 15  --- len
	 *   - Packet Number: 0
	 *   - Request Command Query
	 *       - Command: Query (3)
	 *       - Statement: show databases
	 */

	if (count != (len + 4))
		return MSG_UNKNOWN;

	if (seq != 0)
		return MSG_UNKNOWN;

	// 请求长度判断来提高推断准确率。
	if (len > 10000) {
		return MSG_UNKNOWN;
	}

	/*
	 * After establishing a connection, the MySQL server sends a handshake packet.
	 * The process is as follows:
	 * - **Server > Client (Handshake Packet)**
	 *   The server sends this handshake packet, which includes the MySQL version,
	 *   thread ID, authentication method, and other information.
	 * - **Client > Server (Login Request Packet)**
	 *   The client computes the encrypted password based on `auth-plugin-data` and
	 *   sends it back to the server for verification.
	 * - **Server > Client (Login Success or Failure)**
	 *   The server verifies the client's identity and returns either an **OK Packet** or an **ERR Packet**.
	 *
	 * The handshake packet sent by the server is used for identification.
	 * 0x0A indicates the current mainstream protocol version (MySQL 4.1+).
	 * e.g.: 4A(J) 00 00 00 0A 35(5) 2E(.) 37(7) 2E(.) 31(1) 38(8) 00
	 * **35 2E 37 2E 31 38 00 ASCII decoding results in 5.7.18 (MySQL 5.7.18).**
	 * If the data contains a version string in the format x.x.x, it is highly likely to be MySQL.
	 */
	if (com == 0x0A && point_1 == 0x2e && point_2 == 0x2e) {
		return MSG_REQUEST;
	}

	if (com != kComConnect && com != kComQuery &&
	    com != kComStmtPrepare && com != kComStmtExecute &&
	    com != kComStmtClose && com != kComStmtQuit) {
		return MSG_UNKNOWN;
	}

out:
	if (com == kComStmtClose || com == kComStmtQuit)
		conn_info->keep_trace = 1;

	if (is_mysqld)
		return conn_info->direction ==
		    T_INGRESS ? MSG_REQUEST : MSG_RESPONSE;
	else
		return conn_info->direction ==
		    T_INGRESS ? MSG_RESPONSE : MSG_REQUEST;

	return MSG_UNKNOWN;

	/*
	   e.g:
	   -----------------------------------------------------------
	   Query:
	   MySQL Protocol
	   Packet Length: 33 (21 00 00) ------>  先读取这四个字节
	   Packet Number: 0  (00) ------------>  /
	   ---------------------------------- 下面这些下一次读取
	   Request Command Query
	   Command: Query (3) (03)
	   Statement: select user,host from mysql.user
	   -----------------------------------------------------------
	   Response:
	   MySQL Protocol
	   Packet Length: 1
	   Packet Number: 1
	   Number of fields: 2
	   MySQL Protocol
	   Packet Length: 43
	   Packet Number: 2
	   Catalog: def
	   Database: mysql
	   Table: user
	   Original table: user
	   Name: user
	   Original name: User
	   Charset number: utf8 COLLATE utf8_general_ci (33)
	   Length: 48
	   Type: FIELD_TYPE_STRING (254)
	   Flags: 0x4083
	   Decimals: 0
	   MySQL Protocol
	   Packet Length: 43
	   Packet Number: 3
	   Catalog: def
	   Database: mysql
	   Table: user
	   Original table: user
	   Name: host
	   Original name: Host
	 */
}

static __inline bool infer_pgsql_startup_message(const char *buf, size_t count)
{
	// ref: https://developer.aliyun.com/article/751984#slide-5
	// int32 len | int32 protocol | "user" string 4 bytes
	static const __u8 min_msg_len = 12;
	// startup message wont be larger than 10240 (10KiB).
	static const __u32 max_msg_len = 10240;

	if (count < min_msg_len)
		return false;

	__u32 length = __bpf_ntohl(*(__u32 *) & buf[0]);
	if (length < min_msg_len || length > max_msg_len)
		return false;

	// PostgreSQL 3.0
	if (!(buf[4] == 0 && buf[5] == 3 && buf[6] == 0 && buf[7] == 0))
		return false;

	/*
	 * FIX: The original code used ']' (array close bracket) instead of '||'
	 * (logical OR) with proper array indexing. The check was intended to
	 * validate that buf[8..11] are alphabetic characters (loose check).
	 * Original broken code:
	 *   if (buf[8] < 'A' ] < 'A' ] < 'A' ] < 'A')
	 * Fixed to properly check each byte individually:
	 */
	if (buf[8] < 'A' || buf[9] < 'A' || buf[10] < 'A' || buf[11] < 'A')
		return false;

	return true;
}

/*
 * ref: https://developer.aliyun.com/article/751984
 * | char tag | int32 len | payload |
 * tag ref: src/flow_generator/protocol_logs/sql/postgresql.rs
 *
 * Message flow patterns in PostgreSQL protocol:
 * 'P' (Parse) is usually followed by 'B' (Bind), but sometimes directly followed by 'S' (Sync).
 * 'B' (Bind) is usually followed by 'E' (Execute), or sometimes 'S' (Sync).
 * 'E' (Execute) is usually followed by 'S' (Sync).
 * 'S' (Sync) generally does not have any message following it; it signals the end of a batch of messages.
 * The 'Q' (Query) and 'C' (Close) messages always end with a null terminator character '\0'.
 */
static __inline enum message_type infer_pgsql_query_message(const char *buf,
							    const char *s_buf,
							    size_t count)
{
	// In the protocol format, the size of the "len" field is 4 bytes,
	// and the minimum command length is 4 bytes for "COPY/MOVE",
	// The minimal length is therefore 8.
	static const __u32 min_payload_len = 8;
	// Typical query message size is below an artificial limit.
	// 30000 is copied from postgres code base:
	// https://github.com/postgres/postgres/tree/master/src/interfaces/libpq/fe-protocol3.c#L94
	static const __u32 max_payload_len = 30000;
	// Minimum length = tag(char) + len(int32)
	static const int min_msg_len = 1 + sizeof(__u32);

	// Msg length check
	if (count < min_msg_len) {
		return MSG_UNKNOWN;
	}

	char tag = buf[0];

	/*
	 * NOTE:
	 * In Linux 4.14, the eBPF verifier is very strict on complex boolean
	 * expressions. The original explicit comparison:
	 *
	 *   if (tag != 'Q' && tag != 'P' && tag != 'B' &&
	 *       tag != 'E' && tag != 'S' && tag != 'C')
	 *
	 * may fail verifier checks due to excessive branching and state explosion.
	 *
	 * To keep the program verifier-friendly, we intentionally simplify the
	 * condition to a range check:
	 *
	 *   if (tag < 'B' || tag > 'S')
	 *
	 * This relaxes the validation and allows some non-target tag values
	 * within ['B', 'S'], but is acceptable because:
	 *   1) This is only a fast pre-filter.
	 *   2) Invalid tags will be rejected by subsequent length/content checks.
	 *
	 * This trade-off is required for compatibility with Linux 4.14 eBPF verifier.
	 */
	if (tag < 'B' || tag > 'S')
		return MSG_UNKNOWN;

	// Payload length check
	__u32 length;
	bpf_probe_read_user(&length, sizeof(length), s_buf + 1);
	length = __bpf_ntohl(length);
	if (length < min_payload_len || length > max_payload_len) {
		return MSG_UNKNOWN;
	}

	// If the input includes a whole message (1 byte tag + length),
	// check the last character.
	if (length + 1 <= (__u32) count) {
		char last_char = ' ';	//Non-zero initial value
		bpf_probe_read_user(&last_char, sizeof(last_char),
				    s_buf + length);
		if (last_char == '\0' && (tag == 'Q' || tag == 'C'))
			return MSG_REQUEST;
	}

	size_t pos = length + 1;
	if (pos + 5 > count)
		return MSG_UNKNOWN;

	bpf_probe_read_user(&tag, sizeof(tag), s_buf + pos);
	if (tag == 'B' || tag == 'E' || tag == 'S')
		return MSG_REQUEST;

	return MSG_UNKNOWN;
}

static __inline enum message_type infer_postgre_message(const char *buf,
							size_t count,
							struct conn_info_s
							*conn_info)
{
#define POSTGRE_INFER_BUF_SIZE 32

	if (!protocol_port_check_2(PROTO_POSTGRESQL, conn_info))
		return MSG_UNKNOWN;

	if (conn_info->tuple.l4_protocol != IPPROTO_TCP) {
		return MSG_UNKNOWN;
	}

	char infer_buf[POSTGRE_INFER_BUF_SIZE];
	bpf_probe_read_user(infer_buf, sizeof(infer_buf), buf);

	if (is_infer_socket_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_POSTGRESQL)
			return MSG_UNKNOWN;
		char tag = infer_buf[0];
		/* *INDENT-OFF* */
		switch (tag) {
		// req, common, can not infer msg type, return MSG_REQUEST
		case 'Q': case 'P': case 'B': case 'F': case 'X': case 'f':
		case 'C': case 'E': case 'S': case 'D': case 'H': case 'd':
		case 'c':
			return MSG_REQUEST;
		default:
			return MSG_RESPONSE;
		}
		/* *INDENT-ON* */
	}

	if (infer_pgsql_startup_message(infer_buf, count))
		return MSG_REQUEST;

	return infer_pgsql_query_message(infer_buf, buf, count);
}

#define TNS_HEADER_LENGTH_OFFSET 0
#define TNS_HEADER_CHECKSUM_OFFSET 2
#define TNS_HEADER_TYPE_OFFSET 4
#define TNS_TYPE_DATA_DATA_ID_OFFSET 10
#define TNS_TYPE_DATA_CALL_ID_OFFSET 11

#define TNS_RESP_DATA_ID_RET_STATUS 0x04
#define TNS_RESP_DATA_ID_RET_PARAM 0x08
#define TNS_RESP_DATA_ID_DESC_INFO 0x10

#define TNS_REQ_DATA_ID_PIGGY_BACK_FUNC 0x11
#define TNS_REQ_DATA_ID_USER_OCI_FUNC 0x3

#define TNS_REQ_CALL_ID_USER_CURSOR_CLOSE_ALL 0x69
#define TNS_REQ_CALL_ID_USER_BUNDLED_EXEC_CALL 0x5e
#define TNS_REQ_CALL_ID_USER_SESS_SWITCH_OIGGY_BACK 0x6e

#define TNS_TYPE_CONNECT    0x01
#define TNS_TYPE_ACCEPT     0x02
#define TNS_TYPE_ACK        0x03
#define TNS_TYPE_REFUSE     0x04
#define TNS_TYPE_REDIRECT   0x05
#define TNS_TYPE_DATA       0x06
#define TNS_TYPE_NULL       0x07
#define TNS_TYPE_ABORT      0x09
#define TNS_TYPE_RESEND     0x0b
#define TNS_TYPE_MARKER     0x0c
#define TNS_TYPE_ATTENTION  0x0d
#define TNS_TYPE_CONTROL    0x0e
#define TNS_TYPE_DD         0x0f

static __inline bool is_tns_packet_type(const char ty) {
	if (ty == 0x08 || ty == 0x0a) {
		return false;
	}
	if (ty >= TNS_TYPE_CONNECT && ty <= TNS_TYPE_DD) {
		return true;
	}
	return false;
}

static __inline enum message_type infer_oracle_tns_message(const char *buf,
								size_t count,
								struct conn_info_s *conn_info)
{

	if (!protocol_port_check_2(PROTO_ORACLE, conn_info))
		return MSG_UNKNOWN;
	if (conn_info->tuple.l4_protocol != IPPROTO_TCP || count < 12) {
		return MSG_UNKNOWN;
	}

	if (is_infer_socket_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_ORACLE)
			return MSG_UNKNOWN;
	}

	if (!is_tns_packet_type(buf[TNS_HEADER_TYPE_OFFSET])) {
		return MSG_UNKNOWN;
	}

	__u16 checksum = __bpf_ntohs(*(__u16 *)(buf + TNS_HEADER_CHECKSUM_OFFSET));
	__u32 length = 0;
	// TNS header can have 2/4 bytes length field
	// ref: https://github.com/wireshark/wireshark/blob/d124e488b418acc2482fa2ae59ac69d5586d0d37/epan/dissectors/packet-tns.c#L1298
	if (checksum == 0 || checksum == 4) {
		length = (__u32)__bpf_ntohs(*(__u16 *)(buf + TNS_HEADER_LENGTH_OFFSET));
	} else {
		length = __bpf_ntohl(*(__u32 *)(buf + TNS_HEADER_LENGTH_OFFSET));
	}

	const char *infer_ptr = conn_info->syscall_infer_addr;
	char pkt_type = 0;

	// if count is larger than length, there are multiple TNS packets
	// check the next packet for higher accuracy
	if (count > length + TNS_HEADER_TYPE_OFFSET) {
		if (bpf_probe_read_user(&pkt_type, sizeof(pkt_type), infer_ptr + length + TNS_HEADER_TYPE_OFFSET) == 0 && !is_tns_packet_type(pkt_type)) {
			return MSG_UNKNOWN;
		}
	}

	pkt_type = buf[TNS_HEADER_TYPE_OFFSET];
	switch (pkt_type) {
		case TNS_TYPE_CONNECT:
			if (length < 26) {
				return MSG_UNKNOWN;
			}
			return MSG_REQUEST;
		case TNS_TYPE_ACCEPT:
			if (length < 16) {
				return MSG_UNKNOWN;
			}
			return MSG_RESPONSE;
		case TNS_TYPE_REFUSE:
			if (length < 4) {
				return MSG_UNKNOWN;
			}
			return MSG_RESPONSE;
		case TNS_TYPE_REDIRECT:
			if (length < 2) {
				return MSG_UNKNOWN;
			}
			return MSG_RESPONSE;
		case TNS_TYPE_ABORT:
			if (length < 2) {
				return MSG_UNKNOWN;
			}
			break;
		case TNS_TYPE_MARKER:
			if (length < 3) {
				return MSG_UNKNOWN;
			}
			break;
		case TNS_TYPE_ATTENTION:
			if (length < 3) {
				return MSG_UNKNOWN;
			}
			return MSG_REQUEST;
		case TNS_TYPE_CONTROL:
			if (length < 2) {
				return MSG_UNKNOWN;
			}
			return MSG_REQUEST;
		default:
			break;
	}

	// use upper layer to infer the message type
	if (pkt_type != TNS_TYPE_DATA) {
		return MSG_REQUEST;
	}

	char data_id = buf[TNS_TYPE_DATA_DATA_ID_OFFSET];
	char call_id = buf[TNS_TYPE_DATA_CALL_ID_OFFSET];

	if (data_id == TNS_RESP_DATA_ID_RET_STATUS
	    || data_id == TNS_RESP_DATA_ID_RET_PARAM
	    || data_id == TNS_RESP_DATA_ID_DESC_INFO) {
		return MSG_RESPONSE;
	} else if ((data_id == TNS_REQ_DATA_ID_PIGGY_BACK_FUNC
		    && call_id == TNS_REQ_CALL_ID_USER_CURSOR_CLOSE_ALL)
		   || (data_id == TNS_REQ_DATA_ID_PIGGY_BACK_FUNC
		       && call_id == TNS_REQ_CALL_ID_USER_SESS_SWITCH_OIGGY_BACK)
		   || (data_id == TNS_REQ_DATA_ID_USER_OCI_FUNC
		       && call_id == TNS_REQ_CALL_ID_USER_BUNDLED_EXEC_CALL)
	    ) {
		return MSG_REQUEST;
	} else {
		// use upper layer to infer the message type
		return MSG_REQUEST;
	}
}

// https://en.wikipedia.org/wiki/ISO_8583
static __inline enum message_type infer_iso8583_message(const char *buf,
						     size_t count,
						     const char *ptr,
						     __u32 infer_len,
						     struct conn_info_s
						     *conn_info)
{
#define CUPS_HEADER_SIZE 0x2e
#define CUPS_HEADER_FLAG_1 0x02
#define CUPS_HEADER_FLAG_2 0x82

	if (!protocol_port_check_2(PROTO_ISO8583, conn_info))
		return MSG_UNKNOWN;
	if (conn_info->tuple.l4_protocol != IPPROTO_TCP || count < 58 || infer_len < 53) {
		return MSG_UNKNOWN;
	}
	if (is_infer_socket_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_ISO8583)
			return MSG_UNKNOWN;
	}

	char buffer[8];
	/*
	 * FIX: The original code used ']' (array close bracket) instead of '||'
	 * (logical OR) for the CUPS header flag checks. This broke the condition
	 * and would cause incorrect protocol identification.
	 * Original broken code:
	 *   if (buf[0] == CUPS_HEADER_SIZE && (buf[1] == CUPS_HEADER_FLAG_1 ] == CUPS_HEADER_FLAG_2))
	 * Fixed to use proper '||' operator:
	 */
	if (buf[0] == CUPS_HEADER_SIZE && (buf[1] == CUPS_HEADER_FLAG_1 || buf[1] == CUPS_HEADER_FLAG_2)) {
		bpf_probe_read_user(buffer, 8, ptr + 41);
	} else if (buf[4] == CUPS_HEADER_SIZE && (buf[5] == CUPS_HEADER_FLAG_1 || buf[5] == CUPS_HEADER_FLAG_2)) {
		bpf_probe_read_user(buffer, 8, ptr + 45);
	} else {
		return MSG_UNKNOWN;
	}

	/*
	 * FIX: Same ']' vs '||' issue in the buffer content check.
	 * Original broken code:
	 *   if (buffer[0] != '0' ] != '0' ] != '0' ] != '0' ] != '0')
	 * Fixed to:
	 */
	if (buffer[0] != '0' || buffer[1] != '0' || buffer[2] != '0' ||
	    buffer[3] != '0' || buffer[4] != '0') {
		return MSG_UNKNOWN;
	}
	if (buffer[7] % 2 == 1) {
		return MSG_RESPONSE;
	}
	return MSG_REQUEST;
}

#define CSTR_LEN(s) (sizeof(s) / sizeof(char) - 1)
#define CSTR_MASK(s) ((~0ull) >> (64 - CSTR_LEN(s) * 8))
// convert const string with length <= 8 for matching
#define CSTR_AS_U64(s) (*((uint64_t*)(s)) & CSTR_MASK(s))
#define CSTR_EQ(key, s) (((key) & CSTR_MASK(s)) == CSTR_AS_U64(s))

// ref:
//  https://github.com/memcached/memcached/blob/master/doc/protocol.txt
static __inline enum message_type infer_memcached_message(const char *buf,
							  size_t count,
							  struct conn_info_s
							  *conn_info)
{
	// shortest being `END\r\n`
	if (count < 5)
		return MSG_UNKNOWN;

	if (!protocol_port_check_2(PROTO_MEMCACHED, conn_info))
		return MSG_UNKNOWN;

	if (is_infer_socket_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_MEMCACHED)
			return MSG_UNKNOWN;
	}

	char key[16];
	// __builtin_memcpy not supported
	for (int i = 0; i < 16; i++) {
		if (i < count) {
			key[i] = buf[i];
		} else {
			key[i] = 0;
		}
	}

	__u64 *ukey = (__u64 *) key;
	bool is_request =
	    CSTR_EQ(*ukey, "set ") ||
	    CSTR_EQ(*ukey, "add ") ||
	    CSTR_EQ(*ukey, "replace ") ||
	    CSTR_EQ(*ukey, "append ") ||
	    CSTR_EQ(*ukey, "prepend ") ||
	    CSTR_EQ(*ukey, "cas ") ||
	    CSTR_EQ(*ukey, "get ") ||
	    CSTR_EQ(*ukey, "gets ") ||
	    CSTR_EQ(*ukey, "gat ") ||
	    CSTR_EQ(*ukey, "gats ") ||
	    CSTR_EQ(*ukey, "delete ") ||
	    CSTR_EQ(*ukey, "incr ") ||
	    CSTR_EQ(*ukey, "decr ") ||
	    CSTR_EQ(*ukey, "touch ");
	if (is_request) {
		return MSG_REQUEST;
	}

	__u64 *ukey2 = (__u64 *)(key + 8);
	bool is_response =
	    CSTR_EQ(*ukey, "ERROR\r\n") ||
	    CSTR_EQ(*ukey, "STORED\r\n") ||
	    (CSTR_EQ(*ukey, "NOT_STOR") && CSTR_EQ(*ukey2, "ED\r\n")) ||
	    CSTR_EQ(*ukey, "EXISTS\r\n") ||
	    (CSTR_EQ(*ukey, "NOT_FOUN") && CSTR_EQ(*ukey2, "D\r\n")) ||
	    CSTR_EQ(*ukey, "END\r\n") ||
	    (CSTR_EQ(*ukey, "DELETED\r") && CSTR_EQ(*ukey2, "\n")) ||
	    (CSTR_EQ(*ukey, "TOUCHED\r") && CSTR_EQ(*ukey2, "\n")) ||
	    CSTR_EQ(*ukey, "ERROR ") ||
	    (CSTR_EQ(*ukey, "CLIENT_E") && CSTR_EQ(*ukey2, "RROR ")) ||
	    (CSTR_EQ(*ukey, "SERVER_E") && CSTR_EQ(*ukey2, "RROR ")) ||
	    CSTR_EQ(*ukey, "VALUE ");
	if (is_response) {
		return MSG_RESPONSE;
	}

	return MSG_UNKNOWN;
}

static __inline bool sofarpc_check_character(__u8 val)
{
	// 0 - 9, a - z, A - Z, '.' '_' '-' '*'
	if ((val >= 48 && val <= 57) || (val >= 65 && val <= 90)
	    || (val >= 97 && val <= 122) || val == '.' || val == '_'
	    || val == '-' || val == '*') {
		return true;
	}

	return false;
}

/*
 * Request command protocol for v1
 * 0     1     2           4           6           8          10           12          14         16
 * +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
 * |proto| type| cmdcode   |ver2 |   requestId           |codec|        timeout        |  classLen |
 * +-----------+-----------+-----------+-----------+-----------+-----------+-----------+-----------+
 * |headerLen  | contentLen            |                             ... ...                       |
 * +-----------+-----------+-----------+                                                           +
 * |               className + header  + content  bytes                                            |
 * +                                                                                               +
 * |                               ... ...                                                         |
 * +-----------------------------------------------------------------------------------------------+
 *
 * Response command protocol for v1
 * 0     1     2     3     4           6           8          10           12          14         16
 * +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
 * |proto| type| cmdcode   |ver2 |   requestId           |codec|respstatus |  classLen |headerLen  |
 * +-----------+-----------+-----------+-----------+-----------+-----------+-----------+-----------+
 * | contentLen            |                  ... ...                                              |
 * +-----------------------+                                                                       +
 * |                         className + header  + content  bytes                                  |
 * +                                                                                               +
 * |                               ... ...                                                         |
 * +-----------------------------------------------------------------------------------------------+
 *
 * ref: https://github.com/sofastack/sofa-bolt/blob/42e4e3d756b7655c0d4a058989c66d9eb09591fa/plugins/wireshark/bolt.lua
 *      https://www.cnblogs.com/throwable/p/15113352.html
 */
static __inline enum message_type infer_sofarpc_message(const char *buf,
							size_t count,
							struct conn_info_s
							*conn_info)
{
	static const __u8 bolt_resp_header_len = 20;
	static const __u8 bolt_req_header_len = 22;
	static const __u8 bolt_ver_v1 = 0x01;
	static const __u8 type_req = 0x01;
	static const __u8 type_resp = 0x0;
	static const __u16 cmd_code_heartbeat = 0x0;
	static const __u16 cmd_code_req = 0x01;
	static const __u16 cmd_code_resp = 0x02;
	static const __u8 codec_hessian2 = 1;

	if (count < bolt_resp_header_len)
		return MSG_UNKNOWN;

	if (!protocol_port_check_1(PROTO_SOFARPC, conn_info))
		return MSG_UNKNOWN;

	const __u8 *infer_buf = (const __u8 *)buf;
	__u8 proto = infer_buf[0];	// Under version V1, proto = 1; under version V2, proto = 2
	__u8 type = infer_buf[1];	// 0 => RESPONSE，1 => REQUEST，2 => REQUEST_ONEWAY

	if (is_infer_socket_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_SOFARPC)
			return MSG_UNKNOWN;
		/*
		 * The system call behavior of sofarpc protocol is to first receive
		 * 64 bytes when receiving, and then receive the following content.
		 * We make sure that this type of data is reassembled.
		 */
		if (conn_info->socket_info_ptr->allow_reassembly &&
		    (conn_info->direction == T_INGRESS)) {
			if (conn_info->prev_direction == conn_info->direction &&
			    conn_info->socket_info_ptr->force_reasm)
				return MSG_UNKNOWN;

			if (count == 64)
				conn_info->socket_info_ptr->force_reasm = true;
			else
				conn_info->socket_info_ptr->force_reasm = false;
		}

		goto out;
	}
	// code for remoting command (Heartbeat, RpcRequest, RpcResponse)
	// 1 => rpc request，2 => rpc response
	__u16 cmdcode = __bpf_ntohs(*(__u16 *) & infer_buf[2]);
	__u8 ver2 = infer_buf[4];
	// Command versions, From the source code, it is known that it is currently fixed at 1
	if (ver2 != 1)
		return MSG_UNKNOWN;

	/*
	 * Codec, literally understood as an encoder-decoder, is actually
	 * a marker for serialization and deserialization implementation.
	 * Both V1 and V2 currently have codec fixed at 1. By tracing the
	 * source code, it is found that the configuration value of
	 * SerializerManager is Hessian2 = 1, meaning Hessian2 is used by
	 * default for serialization and deserialization.
	 *
	 * 0 -- "hessian", 1 -- "hessian2", 11 -- "protobuf", 12 -- "json"
	 */
	__u8 codec = infer_buf[9];
	if (codec != codec_hessian2)
		return MSG_UNKNOWN;

	if (!((proto == bolt_ver_v1)
	      && (type == type_req || type == type_resp)
	      && (cmdcode == cmd_code_req || cmdcode == cmd_code_resp
		  || cmdcode == cmd_code_heartbeat))) {
		return MSG_UNKNOWN;
	}
	// length of request or response class name
	// length of header
	short class_len, header_len;
	int content_len;

	// bolt_ver_v1
	if (type == type_req) {
		class_len = (short)__bpf_ntohs(*(__u16 *) & infer_buf[14]);
		header_len = (short)__bpf_ntohs(*(__u16 *) & infer_buf[16]);
		content_len = (int)__bpf_ntohl(*(__u32 *) & infer_buf[18]);
		if (class_len < 0 || header_len < 0 || content_len < 0
		    || bolt_req_header_len > count) {
			return MSG_UNKNOWN;
		}
		// check className first character
		if (count >= 23 && class_len >= 1
		    && !sofarpc_check_character(infer_buf[22])) {
			return MSG_UNKNOWN;;
		}
	}

	if (cmdcode == cmd_code_resp) {
		// (resp)respStatus: response status
		__u16 resp_status = __bpf_ntohl(*(__u16 *) & infer_buf[10]);
		if (!((resp_status >= 0 && resp_status <= 9) ||
		      (resp_status >= 16 && resp_status <= 18))) {
			return MSG_UNKNOWN;
		}

		class_len = (short)__bpf_ntohs(*(__u16 *) & infer_buf[12]);
		header_len = (short)__bpf_ntohs(*(__u16 *) & infer_buf[14]);
		content_len = (int)__bpf_ntohl(*(__u32 *) & infer_buf[16]);
		if (class_len < 0 || header_len < 0 || content_len < 0) {
			return MSG_UNKNOWN;
		}
		// check className first character
		if (count >= 21 && class_len >= 1
		    && !sofarpc_check_character(infer_buf[20])) {
			return MSG_UNKNOWN;;
		}
	}

out:
	return type == type_req ? MSG_REQUEST : MSG_RESPONSE;
}

/*
0                   15 16                     31
|---------------------|-----------------------|
|    标识 ID          |     标志 flags        |
|---------------------|-----------------------|
|    问题数           |    资源记录数         |
|---------------------|-----------------------|
|    授权资源记录数   |    附加资源记录数     |
|---------------------|-----------------------|
*/
struct dns_header {
	unsigned short id;	// identification number

	unsigned char rd:1;	// recursion desired
	unsigned char tc:1;	// truncated message
	unsigned char aa:1;	// authoritive answer
	unsigned char opcode:4;	// purpose of message
	unsigned char qr:1;	// query/response flag

	unsigned char rcode:4;	// response code
	unsigned char cd:1;	// checking disabled
	unsigned char ad:1;	// authenticated data
	unsigned char z:1;	// its z! reserved
	unsigned char ra:1;	// recursion available

	unsigned short q_count;	// number of question entries
	unsigned short ans_count;	// number of answer entries
	unsigned short auth_count;	// number of authority entries
	unsigned short add_count;	// number of resource entries
};

static __inline enum message_type infer_dns_message(const char *buf,
						    size_t count,
						    const char *ptr,
						    __u32 infer_len,
						    struct conn_info_s
						    *conn_info)
{
	/*
	 * Note: When testing with 'curl' accessing a domain, the following
	 * situations are observed in DNS:
	 * (1) An 'A' type DNS request is sent.
	 * (2) An 'A' type response is received.
	 * (3) An 'AAAA' type response is received.
	 *
	 * It is noticed that the Transaction ID for (2) and (3) are different.
	 * We observe that the data obtained through eBPF is missing the data for
	 * the 'AAAA' type request, which differs from the data obtained through
	 * the 'AF_PACKET' method ('AF_PACKET' method includes data for the 'AAAA'
	 * type request).
	 */

	const int dns_header_size = 12;

	// This is the typical maximum size for DNS.
	const int dns_msg_max_size = 512;

	// Maximum number of resource records.
	// https://stackoverflow.com/questions/6794926/how-many-a-records-can-fit-in-a-single-dns-response
	const int max_num_rr = 25;

	if (count < dns_header_size || count > dns_msg_max_size) {
		return MSG_UNKNOWN;
	}

	if (!protocol_port_check_1(PROTO_DNS, conn_info))
		return MSG_UNKNOWN;

	if (is_infer_socket_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_DNS)
			return MSG_UNKNOWN;
	}

	bool update_tcp_dns_prev_count = false;
	struct dns_header *dns = (struct dns_header *)buf;

	/*
	 * Note that TCP DNS adds two length bytes at the beginning of the protocol,
	 * whereas UDP DNS does not. We need to handle this properly to ensure that
	 * these two length bytes are not sent to the upper layer.
	 *
	 * When receiving data, the client does not first receive two bytes but instead
	 * receives everything at once; whereas the server receives two bytes (length) first
	 * and then receives the remaining bytes.
	 */
	if (conn_info->tuple.l4_protocol == IPPROTO_TCP) {
		if (__bpf_ntohs(dns->id) + 2 == count) {
			dns = (void *)dns + 2;
		} else {
			/*
			 * When the client sends a request, it combines both 'A' and 'AAAA'
			 * type queries into a single request to the CoreDNS server. The first
			 * two bytes represent the length, but this length only includes the
			 * 'A' query, not the combined length of both the 'A' and 'AAAA' queries
			 * (the total size is referred to as "count" here). As a result, the
			 * length check may miss this case.
			 */
			if (conn_info->direction == T_EGRESS)
				dns = (void *)dns + 2;
			else
				update_tcp_dns_prev_count = true;
		}
	}

	__u16 num_questions = __bpf_ntohs(dns->q_count);
	__u16 num_answers = __bpf_ntohs(dns->ans_count);
	__u16 num_auth = __bpf_ntohs(dns->auth_count);
	__u16 num_addl = __bpf_ntohs(dns->add_count);

	bool qr = dns->qr;	// QR（Response）：查询请求/响应的标志信息。查询请求时，值为 0；响应时，值为 1。
	__u8 opcode = dns->opcode;	// 操作码。其中，0 表示标准查询；1 表示反向查询；2 表示服务器状态请求。
	__u8 zero = dns->z;	// Z：保留字段，在所有的请求和应答报文中，它的值必须为 0。
	if (zero != 0) {
		return MSG_UNKNOWN;
	}

	if (opcode != 0) {	//非标准查询不予处理
		return MSG_UNKNOWN;
	}

	if (num_questions == 0 || num_questions > 10) {
		return MSG_UNKNOWN;
	}

	__u32 num_rr = num_questions + num_answers + num_auth + num_addl;
	if (num_rr > max_num_rr) {
		return MSG_UNKNOWN;
	}
	// FIXME: Remove this code when the call chain can correctly handle the
	// Go DNS case.
	/*
	 * Here, we assume a maximum length of 128 bytes for the queries name.
	 * If queries name exceeds 128 bytes, the identification of AAAA or A
	 * types will be impossible.
	 *
	 * For decreasing the stack usage, we use a 32-byte buffer to store the
	 * queries name, and repeatedly read the queries name from the buffer.
	 */
	conn_info->dns_q_type = 0;
	__u8 tmp_buf[32];
	const char *queries_start = ptr + (((char *)(dns + 1)) - buf);
	for (int i = 0; i < 4; i++) {
		short tmp = bpf_probe_read_user_str(tmp_buf, sizeof(tmp_buf),
						    queries_start);
		if (tmp < 0) {
			break;
		}
		if (tmp != sizeof(tmp_buf)) {
			queries_start += tmp;
			bpf_probe_read_user(tmp_buf, 2, queries_start);
			conn_info->dns_q_type = __bpf_ntohs(*(__u16 *) tmp_buf);
			break;
		} else {
			queries_start += tmp - 1;
		}
	}
	// coreDNS will first send the length in two bytes. If it recognizes
	// that it is TCP DNS and does not have a length field, it will modify
	// the offset to correct the TCP sequence number.
	if (update_tcp_dns_prev_count) {
		conn_info->prev_count = 2;
	}
	return (qr == 0) ? MSG_REQUEST : MSG_RESPONSE;
}

static __inline bool is_include_crlf(const char *buf)
{
#define PARAMS_LIMIT 20

	int i;
	for (i = 1; i < PARAMS_LIMIT; ++i) {
		if (buf[i] == '\r')
			break;
	}

	if (i == PARAMS_LIMIT)
		return false;

	i++;
	if (buf[i] != '\n')
		return false;

	return true;
}

// ref:
//  http://redisdoc.com/topic/protocol.html
//  https://redis.io/docs/reference/protocol-spec/
static __inline enum message_type infer_redis_message(const char *buf,
						      size_t count,
						      struct conn_info_s
						      *conn_info)
{
	if (count < 4)
		return MSG_UNKNOWN;

	if (!protocol_port_check_1(PROTO_REDIS, conn_info))
		return MSG_UNKNOWN;

	if (is_infer_socket_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_REDIS)
			return MSG_UNKNOWN;
	}

	const char first_byte = buf[0];

	/*
	 * The following table summarizes the RESP data types that Redis supports:
	 *
	 * RESP data type       Minimal protocol version        Category        First byte
	 * Simple strings       RESP2                           Simple          +
	 * Simple Errors        RESP2                           Simple          -
	 * Integers             RESP2                           Simple          :
	 * Bulk strings         RESP2                           Aggregate       $
	 * Arrays               RESP2                           Aggregate       *
	 * Nulls                RESP3                           Simple          _
	 * Booleans             RESP3                           Simple          #
	 * Doubles              RESP3                           Simple          ,
	 * Big numbers          RESP3                           Simple          (
	 * Bulk errors          RESP3                           Aggregate       !
	 * Verbatim strings     RESP3                           Aggregate       =
	 * Maps                 RESP3                           Aggregate       %
	 * Sets                 RESP3                           Aggregate       ~
	 * Pushes               RESP3                           Aggregate       >
	 */
	if (first_byte != '+' && first_byte != '-' && first_byte != ':' &&
	    first_byte != '$' && first_byte != '*' && first_byte != '_' &&
	    first_byte != '#' && first_byte != ',' && first_byte != '(' &&
	    first_byte != '!' && first_byte != '=' && first_byte != '%' &&
	    first_byte != '~' && first_byte != '>')
		return MSG_UNKNOWN;

	// The redis message must contain /r/n.
	// Due to the limitation of eBPF, only the first 20 bytes are checked.
	// The position where the error type /r/n appears may exceed 20 bytes.
	// Therefore, the error type is not checked
	if (first_byte != '-' && !is_include_crlf(buf))
		return MSG_UNKNOWN;

	/*
	 * FIX: The original code used ']' (array close bracket) instead of '||'
	 * (logical OR) with proper array indexing for buf[2].
	 * Original broken code:
	 *   if (first_byte == '-' && ((buf[1] != 'E' && buf[1] != 'W') ] != 'R'))
	 * Fixed to properly check buf[2]:
	 */
	//-ERR unknown command 'foobar'
	//-WRONGTYPE Operation against a key holding the wrong kind of value
	if (first_byte == '-'
	    && ((buf[1] != 'E' && buf[1] != 'W') || buf[2] != 'R'))
		return MSG_UNKNOWN;

	return MSG_REQUEST;
}

// 伪代码参考自
// http://public.dhe.ibm.com/software/dw/webservices/ws-mqtt/mqtt-v3r1.html?spm=a2c4g.11186623.0.0.76157c1cveWwvz
//
// multiplier = 1
// value = 0
// do
//   digit = 'next digit from stream'
//   value += (digit AND 127) * multiplier
//   multiplier *= 128
// while ((digit AND 128) != 0)
static __inline bool mqtt_decoding_length(const __u8 * buffer, int *length,
					  int *lensize)
{
	int multiplier = 1;
	__u8 digit;

	// mqtt的长度从第二个字节开始,最多有四个字节
	buffer += 1;
	*length = 0;
	*lensize = 0;

	/*
	 * Limit the number of loop iterations, ensuring the byte usage remains
	 * within 32 bytes. This also resolves the issue of loading eBPF bytecode
	 * on the 4.19.90-25.24.v2101.ky10.aarch64 kernel.
	 */
	static const int loop_count = 32;
	for (int i = 0; i < loop_count; i++) {
		digit = buffer[(*lensize)++];
		*length += (digit & 127) * multiplier;
		multiplier *= 128;

		// mqtt 最多用4个字节表示长度
		if ((*lensize) > 4)
			return false;
		if((digit & 128) == 0)
			return true;
	}

	return false;
}

static __inline bool mqtt_decoding_message_type(const __u8 * buffer,
						int *message_type)
{
	*message_type = ((*buffer) >> 4) & 0x0F;

	// 根据 type 取值范围进行过滤, 0 为保留值, MQTT 5.0 启用了15
	return *message_type != 0;
}

// MQTT V3.1 Protocol Specification
// http://public.dhe.ibm.com/software/dw/webservices/ws-mqtt/mqtt-v3r1.html?spm=a2c4g.11186623.0.0.76157c1cveWwvz
static __inline enum message_type infer_mqtt_message(const char *buf,
						     size_t count,
						     struct conn_info_s
						     *conn_info)
{
	if (count < 4)
		return MSG_UNKNOWN;

	if (!protocol_port_check_2(PROTO_MQTT, conn_info))
		return MSG_UNKNOWN;

	if (is_infer_socket_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_MQTT)
			return MSG_UNKNOWN;
	}

	int mqtt_type;
	if (!mqtt_decoding_message_type((__u8 *) buf, &mqtt_type))
		return MSG_UNKNOWN;

	int length, lensize;
	if (!mqtt_decoding_length((__u8 *) buf, &length, &lensize))
		return MSG_UNKNOWN;

	if (1 + lensize + length != count)
		return MSG_UNKNOWN;

	// 仅通过上述约束条件,会存在其他协议被误判成MQTT的情况,
	// 于是根据MQTT消息类型与其长度之间的关系再次进行简单的过滤
	// CONNECT PUBLISH 至少有两个字节的 Variable header 和两个字节的 Payload
	if ((mqtt_type == 1 || mqtt_type == 3) && length < 4)
		return MSG_UNKNOWN;

	// CONNACK PUBACK PUBREC PUBREL PUBCOMP UNSUBACK 仅有两个字节的 Variable header
	if ((mqtt_type == 2 || mqtt_type == 4 || mqtt_type == 5 ||
	     mqtt_type == 6 || mqtt_type == 7 || mqtt_type == 11)
	    && length != 2)
		return MSG_UNKNOWN;

	// SUBSCRIBE SUBACK UNSUBSCRIBE 至少有两个字节的 Variable header 和一个字节的 Payload
	if ((mqtt_type == 8 || mqtt_type == 9 || mqtt_type == 10) && length < 3)
		return MSG_UNKNOWN;

	// PINGREQ PINGRESP DISCONNECT 没有 Variable header 和 Payload
	if ((mqtt_type == 12 || mqtt_type == 13 || mqtt_type == 14)
	    && length != 0)
		return MSG_UNKNOWN;

	// AUTH 类型的数据部分长度很灵活,不能通过上述过滤其他类型的方式进行过滤,
	// 默认所有 AUTH 类型都是有效的

	const volatile int __mqtt_type = mqtt_type;
	if (__mqtt_type == 1 || __mqtt_type == 3 || __mqtt_type == 8 ||
	    __mqtt_type == 10 || __mqtt_type == 12 || __mqtt_type == 14 ||
	    __mqtt_type == 15)
		return MSG_REQUEST;
	return MSG_RESPONSE;
}

// https://www.rabbitmq.com/specification.html
static __inline enum message_type infer_amqp_message(const char *buf,
						     size_t count,
						     struct conn_info_s
						     *conn_info)
{
	const char amqp_header[9] = "AMQP\x00\x00\x09\x01";
	if (count < 8)
		return MSG_UNKNOWN;
	if (!protocol_port_check_2(PROTO_AMQP, conn_info))
		return MSG_UNKNOWN;
	if (is_infer_socket_valid(conn_info->socket_info_ptr)
	    && conn_info->socket_info_ptr->l7_proto != PROTO_AMQP)
		return MSG_UNKNOWN;
	bool is_magic = true;
	for (int i = 0; i < 8; i++)
		if (buf[i] != amqp_header[i]) {
			is_magic = false;
			break;
		}
	if (is_magic)
		return MSG_REQUEST;
	if (!is_infer_socket_valid(conn_info->socket_info_ptr)
	    || conn_info->socket_info_ptr->l7_proto != PROTO_AMQP)
		return MSG_UNKNOWN;
	int frame_type = buf[0];

	static const int frame_method = 0x1;
	static const int frame_header = 0x2;
	static const int frame_body = 0x3;
	static const int frame_heartbeat = 0x8;

	if (frame_type == frame_method) {
		if (count < 12)
			return MSG_UNKNOWN;
		__s16 class_id = __bpf_ntohs(*(__s16 *) & buf[7]);
		__s16 method_id = __bpf_ntohs(*(__s16 *) & buf[9]);
		static const int class_connection = 10;
		static const int class_channel = 20;
		static const int class_exchange = 40;
		static const int class_queue = 50;
		static const int class_basic = 60;
		static const int class_tx = 90;
		static const int class_confirm = 85;
		if (class_id == class_connection) {
			static const int method_start = 10;
			static const int method_start_ok = 11;
			static const int method_secure = 20;
			static const int method_secure_ok = 21;
			static const int method_tune = 30;
			static const int method_tune_ok = 31;
			static const int method_open = 40;
			static const int method_open_ok = 41;
			static const int method_close = 50;
			static const int method_close_ok = 51;
			static const int method_blocked = 60;
			static const int method_unblocked = 61;
			static const int method_update_secret = 70;
			static const int method_update_secret_ok = 71;
			switch (method_id) {
			case method_start:
			case method_secure:
			case method_tune:
			case method_open:
			case method_close:
			case method_update_secret:
				return MSG_REQUEST;
			case method_start_ok:
			case method_secure_ok:
			case method_tune_ok:
			case method_open_ok:
			case method_close_ok:
			case method_update_secret_ok:
				return MSG_RESPONSE;
			case method_blocked:
			case method_unblocked:
				// Session
				return MSG_REQUEST;
			}
		} else if (class_id == class_channel) {
			static const int method_open = 10;
			static const int method_open_ok = 11;
			static const int method_flow = 20;
			static const int method_flow_ok = 21;
			static const int method_close = 40;
			static const int method_close_ok = 41;
			switch (method_id) {
			case method_open:
			case method_flow:
			case method_close:
				return MSG_REQUEST;
			case method_open_ok:
			case method_flow_ok:
			case method_close_ok:
				return MSG_RESPONSE;
			}
		} else if (class_id == class_exchange) {
			static const int method_declare = 10;
			static const int method_declare_ok = 11;
			static const int method_delete = 20;
			static const int method_delete_ok = 21;
			static const int method_bind = 30;
			static const int method_bind_ok = 31;
			static const int method_unbind = 40;
			static const int method_unbind_ok = 51;
			switch (method_id) {
			case method_declare:
			case method_delete:
			case method_bind:
			case method_unbind:
				return MSG_REQUEST;
			case method_declare_ok:
			case method_delete_ok:
			case method_bind_ok:
			case method_unbind_ok:
				return MSG_RESPONSE;
			}
		} else if (class_id == class_queue) {
			static const int method_declare = 10;
			static const int method_declare_ok = 11;
			static const int method_bind = 20;
			static const int method_bind_ok = 21;
			static const int method_purge = 30;
			static const int method_purge_ok = 31;
			static const int method_delete = 40;
			static const int method_delete_ok = 41;
			static const int method_unbind = 50;
			static const int method_unbind_ok = 51;
			switch (method_id) {
			case method_declare:
			case method_bind:
			case method_purge:
			case method_delete:
			case method_unbind:
				return MSG_REQUEST;
			case method_declare_ok:
			case method_bind_ok:
			case method_purge_ok:
			case method_delete_ok:
			case method_unbind_ok:
				return MSG_RESPONSE;
			}
		} else if (class_id == class_basic) {
			static const int method_qos = 10;
			static const int method_qos_ok = 11;
			static const int method_consume = 20;
			static const int method_consume_ok = 21;
			static const int method_cancel = 30;
			static const int method_cancel_ok = 31;
			static const int method_publish = 40;
			static const int method_return = 50;
			static const int method_deliver = 60;
			static const int method_get = 70;
			static const int method_get_ok = 71;
			static const int method_get_empty = 72;
			static const int method_ack = 80;
			static const int method_reject = 90;
			static const int method_recover_async = 100;
			static const int method_recover = 110;
			static const int method_recover_ok = 111;
			static const int method_nack = 120;
			switch (method_id) {
			case method_qos:
			case method_consume:
			case method_cancel:
			case method_get:
			case method_recover:
				return MSG_REQUEST;
			case method_qos_ok:
			case method_consume_ok:
			case method_cancel_ok:
			case method_get_ok:
			case method_get_empty:
			case method_recover_ok:
				return MSG_RESPONSE;
			case method_publish:
			case method_return:
			case method_deliver:
			case method_ack:
			case method_reject:
			case method_recover_async:
			case method_nack:
				// Session
				return MSG_REQUEST;
			}
		} else if (class_id == class_tx) {
			static const int method_select = 10;
			static const int method_select_ok = 11;
			static const int method_commit = 20;
			static const int method_commit_ok = 21;
			static const int method_rollback = 30;
			static const int method_rollback_ok = 31;
			switch (method_id) {
			case method_select:
			case method_commit:
			case method_rollback:
				return MSG_REQUEST;
			case method_select_ok:
			case method_commit_ok:
			case method_rollback_ok:
				return MSG_RESPONSE;
			}
		} else if (class_id == class_confirm) {
			static const int method_select = 10;
			static const int method_select_ok = 11;
			switch (method_id) {
			case method_select:
				return MSG_REQUEST;
			case method_select_ok:
				return MSG_RESPONSE;
			}
		}
	} else if (frame_type == frame_header) {
		return MSG_REQUEST;
	} else if (frame_type == frame_body) {
		return MSG_REQUEST;
	} else if (frame_type == frame_heartbeat) {
		return MSG_REQUEST;
	}
	return MSG_UNKNOWN;
}

static __inline enum message_type decode_openwire(const char *buf,
						  size_t count,
						  bool is_size_prefix_disabled,
						  bool
						  is_tight_encoding_enabled,
						  bool strict_check)
{
	static const __u32 ACTIVEMQ_MAGIC_1 = 0x41637469;	// "Acti"
	static const __u32 ACTIVEMQ_MAGIC_2 = 0x76654d51;	// "veMQ"
	// [length(4 bytes)] + command_type(1 byte) + [boolean_stream(2 byte at least)]
	// + command_id(4 bytes) + [response_required(1 byte)]
	__u32 min_length = 6;
	if (is_tight_encoding_enabled) {
		min_length++;
	}
	if (!is_size_prefix_disabled) {
		min_length += 4;
	}
	if (count < min_length)
		return MSG_UNKNOWN;
	const char *cur_buf = buf;
	__u32 command_length = 0;
	if (!is_size_prefix_disabled) {
		command_length = __bpf_ntohl(*(__u32 *) cur_buf);
		if (strict_check) {
			if (command_length < min_length - 4
			    || command_length + 4 != count)
				return MSG_UNKNOWN;
		}
		cur_buf += 4;
	}
	__u8 cmd_type = *(__u8 *) (cur_buf++);
	// WireFormatInfo
	if (cmd_type == 1) {
		// magic value
		if (count < 13) {
			return MSG_UNKNOWN;
		}
		if (__bpf_ntohl(*(__u32 *) cur_buf) != ACTIVEMQ_MAGIC_1
		    || __bpf_ntohl(*(__u32 *) (cur_buf + 4)) !=
		    ACTIVEMQ_MAGIC_2) {
			return MSG_UNKNOWN;
		}
		return MSG_REQUEST;
	}
	if (strict_check) {
		if (is_tight_encoding_enabled) {
			// parse a boolean stream
			__u16 stream_size = *(__u8 *) (cur_buf++);
			if (stream_size == 0xC0) {
				stream_size = *(__u8 *) (cur_buf++);
			} else if (stream_size == 0x80) {
				stream_size = *(__u16 *) (cur_buf);
				cur_buf += 2;
			}
			if (stream_size == 0)
				return MSG_UNKNOWN;
			// stream should not exceed the command length
			if (!is_size_prefix_disabled
			    && (cur_buf - buf) + stream_size >
			    4 + command_length)
				return MSG_UNKNOWN;
		} else {
			// parse command_id
			__bpf_ntohl(*(__u32 *) cur_buf);
			cur_buf += 4;
			// parse response_required
			__u8 response_required = *(__u8 *) (cur_buf++);
			// validate the boolean value
			if (response_required != 0x00
			    && response_required != 0x01)
				return MSG_UNKNOWN;
		}
	}
	if (!cmd_type)
		return MSG_UNKNOWN;
	// [Request / Session]
	// WireFormatInfo | BrokerInfo | ConnectionInfo | SessionInfo | ConsumerInfo
	// ProducerInfo | TransactionInfo | DestinationInfo | RemoveSubscriptionInfo
	// KeepAliveInfo | ShutdownInfo | RemoveInfo (0x01 ~ 0x0c)
	// ControlCommand | FlushCommand | ConnectionError | ConsumerControl | ConnectionControl
	// ProducerAck | MessagePull | MessageDispatch | MessageAck | ActiveMQMessage | ActiveMQBytesMessage
	// ActiveMQMapMessage | ActiveMQObjectMessage | ActiveMQStreamMessage | ActiveMQTextMessage
	// ActiveMQBlobMessage (0x0e ~ 0x1d)
	// DiscoveryEvent(0x28) | DurableSubscriptionInfo(0x37) | PartialCommand(0x3c)
	// PartialLastCommand(0x3d) | Replay(0x41) | MessageDispatchNotification(0x5a)
	if (cmd_type <= 0x0c || (0x0e <= cmd_type && cmd_type <= 0x1d)
	    || cmd_type == 0x28 || cmd_type == 0x37 || cmd_type == 0x3c
	    || cmd_type == 0x3d || cmd_type == 0x41 || cmd_type == 0x5a) {
		return MSG_REQUEST;
	}
	// [Response]
	// Response | ExceptionResponse | DataResponse | DataArrayResponse | IntegerResponse
	if (0x1e <= cmd_type && cmd_type <= 0x22) {
		return MSG_RESPONSE;
	}
	return MSG_UNKNOWN;
}

enum OpenWireEncoding {
	OPENWIRE_LOOSE_ENCODING = 0x00,
	OPENWIRE_TIGHT_ENCODING = 0x01,
};

// https://activemq.apache.org/openwire
static __inline enum message_type infer_openwire_message(const char *buf,
							 size_t count,
							 struct conn_info_s
							 *conn_info)
{
	if (count < 4)
		return MSG_UNKNOWN;

	if (!protocol_port_check_2(PROTO_OPENWIRE, conn_info))
		return MSG_UNKNOWN;

	if (is_infer_socket_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_OPENWIRE)
			return MSG_UNKNOWN;
		conn_info->encoding_type =
		    conn_info->socket_info_ptr->encoding_type;
	}
	enum message_type msg_type;
	if (conn_info->encoding_type != OPENWIRE_LOOSE_ENCODING
	    && conn_info->encoding_type != OPENWIRE_TIGHT_ENCODING) {
		// try to parse the packet in both tight and loose encoding format
		// we now only support `SizePrefixDisabled` assigned to false
		if ((msg_type =
		     decode_openwire(buf, count, false, false,
				     true)) != MSG_UNKNOWN) {
			conn_info->encoding_type = OPENWIRE_LOOSE_ENCODING;
			return msg_type;
		}
		if ((msg_type =
		     decode_openwire(buf, count, false, true,
				     true)) != MSG_UNKNOWN) {
			conn_info->encoding_type = OPENWIRE_TIGHT_ENCODING;
			return msg_type;
		}
		return MSG_UNKNOWN;
	} else {
		if ((msg_type =
		     decode_openwire(buf, count, false,
				     conn_info->encoding_type, false)
		    ) != MSG_UNKNOWN) {
			return msg_type;
		}
		return MSG_CLEAR;
	}
}

static __inline bool nats_check_info(const char *buf, size_t count)
{
	if (count < 6)
		return false;

	// info
	if (buf[0] != 'I' && buf[0] != 'i')
		return false;
	if (buf[1] != 'N' && buf[1] != 'n')
		return false;
	if (buf[2] != 'F' && buf[2] != 'f')
		return false;
	if (buf[3] != 'O' && buf[3] != 'o')
		return false;
	if (buf[4] != ' ' && buf[4] != '\t')
		return false;

	// NATS allows arbitrary whitespace after INFO
	// we only check the first 20 bytes due to eBPF limitations
	for (int p = 5; p < 20; p++)
		if (buf[p] == '{')
			return true;
		else if (buf[p] != ' ' && buf[p] != '\t')
			return false;
	return false;
}

static __inline bool nats_check_connect(const char *buf, size_t count)
{
	if (count < 8)
		return false;

	// connect
	if (buf[0] != 'C' && buf[0] != 'c')
		return false;
	if (buf[1] != 'O' && buf[1] != 'o')
		return false;
	if (buf[2] != 'N' && buf[2] != 'n')
		return false;
	if (buf[3] != 'N' && buf[3] != 'n')
		return false;
	if (buf[4] != 'E' && buf[4] != 'e')
		return false;
	if (buf[5] != 'C' && buf[5] != 'c')
		return false;
	if (buf[6] != 'T' && buf[6] != 't')
		return false;
	if (buf[7] != ' ' && buf[7] != '\t')
		return false;

	// NATS allows arbitrary whitespace after CONNECT
	// we only check the first 20 bytes due to eBPF limitations
	for (int p = 8; p < 20; p++)
		if (buf[p] == '{')
			return true;
		else if (buf[p] != ' ' && buf[p] != '\t')
			return false;
	return false;
}

// https://docs.nats.io/reference/reference-protocols/nats-protocol
static __inline enum message_type infer_nats_message(const char *buf,
						     size_t count,
						     const char *ptr,
						     __u32 infer_len,
						     struct conn_info_s
						     *conn_info)
{
	if (count < 5)
		return MSG_UNKNOWN;

	if (!protocol_port_check_2(PROTO_NATS, conn_info))
		return MSG_UNKNOWN;

	if (is_infer_socket_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_NATS)
			return MSG_UNKNOWN;
	} else {
		char buffer[2];
		bpf_probe_read_user(buffer, 2, ptr + infer_len - 2);
		/*
		 * FIX: The original code used ']' instead of '||' for the
		 * CRLF terminator check on the last two bytes.
		 * Original broken code:
		 *   if (buffer[0] != '\r' ] != '\n')
		 * Fixed to:
		 */
		if (buffer[0] != '\r' || buffer[1] != '\n')
			return MSG_UNKNOWN;
	}

	if (nats_check_info(buf, count))
		return MSG_REQUEST;

	if (nats_check_connect(buf, count))
		return MSG_RESPONSE;

	/*
	 * FIX: All the following checks used ']' (array close bracket)
	 * instead of '||' (logical OR) for case-insensitive character
	 * matching. Each instance has been corrected.
	 */
	// pub
	if (buf[0] == 'P' || buf[0] == 'p') {
		if (buf[1] == 'U' || buf[1] == 'u') {
			if (buf[2] == 'B' || buf[2] == 'b') {
				if (buf[3] == ' ' || buf[3] == '\t') {
					return MSG_REQUEST;
				}
			}
		}
	}
	// hpub
	if (buf[0] == 'H' || buf[0] == 'h') {
		if (buf[1] == 'P' || buf[1] == 'p') {
			if (buf[2] == 'U' || buf[2] == 'u') {
				if (buf[3] == 'B' || buf[3] == 'b') {
					if (buf[4] == ' ' || buf[4] == '\t') {
						return MSG_REQUEST;
					}
				}
			}
		}
	}
	// sub
	if (buf[0] == 'S' || buf[0] == 's') {
		if (buf[1] == 'U' || buf[1] == 'u') {
			if (buf[2] == 'B' || buf[2] == 'b') {
				if (buf[3] == ' ' || buf[3] == '\t') {
					return MSG_REQUEST;
				}
			}
		}
	}
	// msg
	if (buf[0] == 'M' || buf[0] == 'm') {
		if (buf[1] == 'S' || buf[1] == 's') {
			if (buf[2] == 'G' || buf[2] == 'g') {
				if (buf[3] == ' ' || buf[3] == '\t') {
					return MSG_REQUEST;
				}
			}
		}
	}
	// hmsg
	if (buf[0] == 'H' || buf[0] == 'h') {
		if (buf[1] == 'M' || buf[1] == 'm') {
			if (buf[2] == 'S' || buf[2] == 's') {
				if (buf[3] == 'G' || buf[3] == 'g') {
					if (buf[4] == ' ' || buf[4] == '\t') {
						return MSG_REQUEST;
					}
				}
			}
		}
	}
	// ping
	if (buf[0] == 'P' || buf[0] == 'p') {
		if (buf[1] == 'I' || buf[1] == 'i') {
			if (buf[2] == 'N' || buf[2] == 'n') {
				if (buf[3] == 'G' || buf[3] == 'g') {
					return MSG_REQUEST;
				}
			}
		}
	}
	// pong
	if (buf[0] == 'P' || buf[0] == 'p') {
		if (buf[1] == 'O' || buf[1] == 'o') {
			if (buf[2] == 'N' || buf[2] == 'n') {
				if (buf[3] == 'G' || buf[3] == 'g') {
					return MSG_RESPONSE;
				}
			}
		}
	}
	// +ok
	if (buf[0] == '+') {
		if (buf[1] == 'O' || buf[1] == 'o') {
			if (buf[2] == 'K' || buf[2] == 'k') {
				return MSG_REQUEST;
			}
		}
	}
	// -err
	if (buf[0] == '-') {
		if (buf[1] == 'E' || buf[1] == 'e') {
			if (buf[2] == 'R' || buf[2] == 'r') {
				if (buf[3] == 'R' || buf[3] == 'r') {
					if (buf[4] == ' ' || buf[4] == '\t') {
						return MSG_REQUEST;
					}
				}
			}
		}
	}
	if (count < 6)
		return MSG_UNKNOWN;
	// unsub
	if (buf[0] == 'U' || buf[0] == 'u') {
		if (buf[1] == 'N' || buf[1] == 'n') {
			if (buf[2] == 'S' || buf[2] == 's') {
				if (buf[3] == 'U' || buf[3] == 'u') {
					if (buf[4] == 'B' || buf[4] == 'b') {
						if (buf[5] == ' ' ||
						    buf[5] == '\t') {
							return MSG_REQUEST;
						}
					}
				}
			}
		}
	}
	return MSG_UNKNOWN;
}

static __inline bool pulsar_check_basecommand(const char *buf, size_t count)
{
	/*
	 * message BaseCommand {
	 *   required Type type = 1;
	 *   optional CommandConnect connect          = 2;
	 *   optional CommandConnected connected      = 3;
	 *   ....
	 *   optional CommandTopicMigrated topicMigrated = 68;
	 * }
	 */
#define WIRE_TYPE_VARINT 0
#define WIRE_TYPE_LEN 2
#define MIN_TAG 2		// connect
#define MAX_TAG 68		// topicMigrated

	short type_v = -1, command_tag = -1;
	const char *target = buf + count;

	if (count == 0)
		return false;

	unsigned char tmp;

	// https://protobuf.dev/programming-guides/encoding/
#pragma unroll
	for (short i = 0; i < 2; i++) {
		if (buf == target)
			return false;
		bpf_probe_read_user((char *)&tmp, sizeof(tmp), buf);
		buf += sizeof(tmp);
		short tag = tmp >> 3, wire_type = tmp & 0x07;
		if (tag == 1) {
			if (wire_type != WIRE_TYPE_VARINT)
				return false;
			if (buf == target)
				return false;
			bpf_probe_read_user((char *)&tmp, sizeof(tmp), buf);
			buf += sizeof(tmp);
			type_v = tmp;
			// for varint, the most significant bit is the continuation bit
			if (tmp & 0x80) {
				if (buf == target)
					return false;
				bpf_probe_read_user((char *)&tmp, sizeof(tmp),
						    buf);
				buf += sizeof(tmp);
				if (tmp & 0x80)
					return false;
				type_v |= tmp << 7;
			}
		} else {
			if (tmp & 0x80) {
				if (buf == target)
					return false;
				bpf_probe_read_user((char *)&tmp, sizeof(tmp),
						    buf);
				buf += sizeof(tmp);
				if (tmp & 0x80)
					return false;
				tag |= tmp << 4;
			}
			if (tag < MIN_TAG || tag > MAX_TAG)
				return false;
			if (wire_type != WIRE_TYPE_LEN)
				return false;
			command_tag = tag;
			short len = 0;
			if (buf == target)
				return false;
			bpf_probe_read_user((char *)&tmp, sizeof(tmp), buf);
			buf += sizeof(tmp);
			len |= tmp & 0x7f;
			if (tmp & 0x80) {
				if (buf == target)
					return false;
				bpf_probe_read_user((char *)&tmp, sizeof(tmp),
						    buf);
				buf += sizeof(tmp);
				if (tmp & 0x80)
					return false;
				len |= tmp << 7;
			}
			buf += len;
		}
	}

	if (type_v == -1 || command_tag == -1)
		return false;
	if (buf != target)
		return false;
	return type_v == command_tag;

#undef WIRE_TYPE_VARINT
#undef WIRE_TYPE_LEN
#undef MIN_TAG
#undef MAX_TAG
}

// https://pulsar.apache.org/docs/3.2.x/developing-binary-protocol/
static __inline enum message_type infer_pulsar_message(const char *ptr,
						       __u32 infer_len,
						       __u32 count,
						       struct conn_info_s
						       *conn_info)
{
	if (infer_len < 8)
		return MSG_UNKNOWN;

	if (!protocol_port_check_2(PROTO_PULSAR, conn_info))
		return MSG_UNKNOWN;

	if (is_infer_socket_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_PULSAR)
			return MSG_UNKNOWN;
	}

	char buffer[4];

	bpf_probe_read_user(buffer, 4, ptr);
	short total_size = __bpf_ntohl(*(__u32 *) buffer);
	bpf_probe_read_user(buffer, 4, ptr + 4);
	short command_size = __bpf_ntohl(*(__u32 *) buffer);

	if (total_size < command_size + 4)
		return MSG_UNKNOWN;

	if (is_infer_socket_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto == PROTO_PULSAR)
			return MSG_REQUEST;
		return MSG_UNKNOWN;
	}

	if (count < total_size + 4)
		return MSG_UNKNOWN;

	short limit = total_size + 4 < infer_len ? total_size + 4 : infer_len;

	short offset = 8;
	if (!pulsar_check_basecommand(ptr + 8, command_size))
		return MSG_UNKNOWN;
	offset += command_size;

	if (offset == total_size + 4)
		return MSG_REQUEST;

	if (offset + 2 > limit)
		return MSG_UNKNOWN;
	bpf_probe_read_user(buffer, 2, ptr + offset);
	offset += 2;

	if (buffer[0] == '\x0e' && buffer[1] == '\x02') {
		if (offset + 4 > limit)
			return MSG_UNKNOWN;
		bpf_probe_read_user(buffer, 4, ptr + offset);
		offset += 4;

		short


