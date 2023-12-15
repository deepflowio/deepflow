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
 * Due to the limitation of the number of eBPF instructions to 4096 in Linux
 * kernels lower than version 5.12, the protocol inference code, when augmented
 * with new protocols, easily exceeds the instruction limit. To address this
 * issue, we have split the protocol inference into two separate programs.
 * The updated workflow is as follows:
 *
 * [openssl Uprobe] ----------------
 *                                 |
 *                                \|/
 * [syscall Kprobe/tracepoint] --> [protocol infer] --> [data submit] --> [output data]
 *       |                                                                ^
 *       |                                                                |
 *       |----general file io------> [io event] ---------------------------
 *
 * Explanation:
 *   `[openssl Uprobe]` and `[syscall Kprobe/tracepoint]` encompass the preparation
 *   work for eBPF probe entry and a portion of Layer 7 (L7) protocol inference.
 *   `[protocol infer]` represents the second part of L7 protocol inference, and
 *   newly added protocol inference code can be placed within the `infer_protocol_2()`
 *   interface.
 */
#ifndef DF_BPF_PROTO_INFER_H
#define DF_BPF_PROTO_INFER_H

#include "common.h"
#include "socket_trace.h"

#define L7_PROTO_INFER_PROG_1	0
#define L7_PROTO_INFER_PROG_2	1

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
		      struct conn_info_t *conn_info, __u8 prog_num)
{
	if (!is_protocol_enabled(proto)) {
		return false;
	}

	__u32 key = proto;
	ports_bitmap_t *ports = proto_ports_bitmap__lookup(&key);
	if (ports) {
		/*
		 * If the "is_set_ports_bitmap()" function is used in both stages,
		 * there may be the following error when loading an eBPF program in
		 * the 4.14 kernel:
		 * `failed. name: bpf_func_sys_exit_sendmmsg, Argument list too long errno: 7`
		 * To avoid this situation, it is necessary to differentiate the calls.
		 */
		if (prog_num == L7_PROTO_INFER_PROG_1) {
			if (is_set_bitmap(ports->bitmap, conn_info->tuple.num)
			    || is_set_bitmap(ports->bitmap,
					     conn_info->tuple.dport))
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
		      struct conn_info_t *conn_info)
{
	return __protocol_port_check(proto, conn_info, L7_PROTO_INFER_PROG_1);
}

static __inline bool
protocol_port_check_2(enum traffic_protocol proto,
		      struct conn_info_t *conn_info)
{
	return __protocol_port_check(proto, conn_info, L7_PROTO_INFER_PROG_2);
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

static __inline bool is_socket_info_valid(struct socket_info_t *sk_info)
{
	return (sk_info != NULL && sk_info->uid != 0);
}

static __inline int is_http_response(const char *data)
{
	return (data[0] == 'H' && data[1] == 'T' && data[2] == 'T'
		&& data[3] == 'P' && data[4] == '/' && data[5] == '1'
		&& data[6] == '.' && data[8] == ' ');
}

static __inline int is_http_request(const char *data, int data_len)
{
	switch (data[0]) {
		/* DELETE */
	case 'D':
		if ((data[1] != 'E') || (data[2] != 'L') || (data[3] != 'E')
		    || (data[4] != 'T') || (data[5] != 'E')
		    || (data[6] != ' ')) {
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
		if ((data[1] != 'E') || (data[2] != 'A') || (data[3] != 'D')
		    || (data[4] != ' ')) {
			return 0;
		}
		break;

		/* OPTIONS */
	case 'O':
		if (data_len < 8 || (data[1] != 'P') || (data[2] != 'T')
		    || (data[3] != 'I') || (data[4] != 'O') || (data[5] != 'N')
		    || (data[6] != 'S') || (data[7] != ' ')) {
			return 0;
		}
		break;

		/* PATCH/POST/PUT */
	case 'P':
		switch (data[1]) {
		case 'A':
			if ((data[2] != 'T') || (data[3] != 'C')
			    || (data[4] != 'H') || (data[5] != ' ')) {
				return 0;
			}
			break;
		case 'O':
			if ((data[2] != 'S') || (data[3] != 'T')
			    || (data[4] != ' ')) {
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
	bpf_probe_read(buffer, sizeof(buffer) - 1, buf_src);
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
static __inline enum message_type parse_http2_headers_frame(const char *buf_src,
							    size_t count,
							    struct conn_info_t
							    *conn_info,
							    const bool is_first)
{
#define HTTPV2_FRAME_PROTO_SZ           0x9
#define HTTPV2_FRAME_TYPE_HEADERS       0x1
#define HTTPV2_STATIC_TABLE_AUTH_IDX    0x1
#define HTTPV2_STATIC_TABLE_GET_IDX     0x2
#define HTTPV2_STATIC_TABLE_POST_IDX    0x3
#define HTTPV2_STATIC_TABLE_PATH_1_IDX  0x4
#define HTTPV2_STATIC_TABLE_PATH_2_IDX  0x5
// In some cases, the compiled binary instructions exceed the limit, the
// specific reason is unknown, reduce the number of cycles of http2, which
// may cause http2 packet loss
#ifdef LINUX_VER_5_2_PLUS
#define HTTPV2_LOOP_MAX 8
#else
#define HTTPV2_LOOP_MAX 7
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
	}
#pragma unroll
	for (i = 0; i < HTTPV2_LOOP_MAX; i++) {

		/*
		 * 这个地方考虑iovecs的情况，传递过来进行协议推断的数据
		 * 是&args->iov[0]第一个iovec，count的值也是第一个
		 * iovec的数据长度。存在协议分析出来长度是大于count的情况
		 * 因此这里不能通过“offset == count”来进行判断。
		 */
		if (offset >= count)
			break;

		bpf_probe_read(buf, sizeof(buf), buf_src + offset);
		offset += (__bpf_ntohl(*(__u32 *) buf) >> 8) +
		    HTTPV2_FRAME_PROTO_SZ;
		type = buf[3];

		// 如果不是Header继续寻找下一个Frame
		if (type != HTTPV2_FRAME_TYPE_HEADERS)
			continue;

		/*
		 * 如果不是初次推断（即：socket已经确认了数据协议类型并明确了角色）
		 * 可以通过方向来判断请求或回应。
		 */
		if (!is_first)
			return MSG_RECONFIRM;

		flags_unset = buf[4] & 0xd2;
		flags_padding = buf[4] & 0x08;
		flags_priority = buf[4] & 0x20;
		reserve = buf[5] & 0x01;

		// flags_unset和reserve必须为0，否则直接放弃判断。
		if (flags_unset || reserve)
			return MSG_UNKNOWN;

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

		// HTTPV2 REQUEST
		if (static_table_idx == HTTPV2_STATIC_TABLE_AUTH_IDX ||
		    static_table_idx == HTTPV2_STATIC_TABLE_GET_IDX ||
		    static_table_idx == HTTPV2_STATIC_TABLE_POST_IDX ||
		    static_table_idx == HTTPV2_STATIC_TABLE_PATH_1_IDX ||
		    static_table_idx == HTTPV2_STATIC_TABLE_PATH_2_IDX) {
			msg_type = MSG_REQUEST;
			conn_info->role =
			    (conn_info->direction ==
			     T_INGRESS) ? ROLE_SERVER : ROLE_CLIENT;

		} else {

			/*
			 * If the data type of HTTPV2 is RESPONSE in the initial
			 * judgment, then the inference will be discarded directly.
			 * Because the data obtained for the first time is RESPONSE,
			 * it can be considered as invalid data (the REQUEST cannot
			 * be found for aggregation, and the judgment of RESPONSE is
			 * relatively rough and prone to misjudgment).
			 */
			if (is_first)
				return MSG_UNKNOWN;

			msg_type = MSG_RESPONSE;
		}

		break;
	}

	return msg_type;
}

static __inline enum message_type infer_http2_message(const char *buf_src,
						      size_t count,
						      struct conn_info_t
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
				    get_tcp_read_seq_from_fd(conn_info->fd),
			};
			// make linux 4.14 validator happy
			__u32 tcp_seq = tcp_seq_key.tcp_seq_end - count;
			bpf_map_update_elem(&http2_tcp_seq_map, &tcp_seq_key,
					    &tcp_seq, BPF_NOEXIST);
		}
		return MSG_UNKNOWN;
	}

	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_HTTP2)
			return MSG_UNKNOWN;

		if (parse_http2_headers_frame(buf_src, count, conn_info, false)
		    != MSG_RECONFIRM)
			return MSG_UNKNOWN;

		if (conn_info->socket_info_ptr->role == ROLE_SERVER)
			return (conn_info->direction == T_INGRESS) ?
			    MSG_REQUEST : MSG_RESPONSE;

		if (conn_info->socket_info_ptr->role == ROLE_CLIENT)
			return (conn_info->direction == T_INGRESS) ?
			    MSG_RESPONSE : MSG_REQUEST;
	}

	return parse_http2_headers_frame(buf_src, count, conn_info, true);
}

static __inline enum message_type infer_http_message(const char *buf,
						     size_t count,
						     struct conn_info_t
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

	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_HTTP1)
			return MSG_UNKNOWN;
	}

	if (is_http_response(buf)) {
		return MSG_RESPONSE;
	}

	if (is_http_request(buf, count)) {
		return MSG_REQUEST;
	}

	return MSG_UNKNOWN;
}

// When calling this function, count must be a constant, and at this time, the
// compiler can optimize it into an immediate value and write it into the
// instruction.
static __inline void save_prev_data(const char *buf,
				    struct conn_info_t *conn_info, size_t count)
{
	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		bpf_probe_read(conn_info->socket_info_ptr->prev_data, count,
			       buf);
		conn_info->socket_info_ptr->prev_data_len = count;
		/*
		 * This piece of data needs to be merged with subsequent data, so
		 * the direction of the previous piece of data needs to be saved here.
		 */
		conn_info->socket_info_ptr->pre_direction =
		    conn_info->socket_info_ptr->direction;
		conn_info->socket_info_ptr->direction = conn_info->direction;
	} else {
		bpf_probe_read(conn_info->prev_buf, count, buf);
		conn_info->prev_count = count;
	}
}

// MySQL and Kafka need the previous n bytes of data for inference
static __inline void check_and_fetch_prev_data(struct conn_info_t *conn_info)
{
	if (conn_info->socket_info_ptr != NULL &&
	    conn_info->socket_info_ptr->prev_data_len > 0) {
		/*
		 * For adjacent read/write in the same direction.
		 */
		if (conn_info->direction ==
		    conn_info->socket_info_ptr->direction) {
			bpf_probe_read(conn_info->prev_buf,
				       sizeof(conn_info->prev_buf),
				       conn_info->socket_info_ptr->prev_data);
			conn_info->prev_count =
			    conn_info->socket_info_ptr->prev_data_len;
			/*
			 * When data is merged, that is, when two or more data with the same
			 * direction are merged together and processed as one data, the previously
			 * saved direction needs to be restored.
			 */
			conn_info->socket_info_ptr->direction =
			    conn_info->socket_info_ptr->pre_direction;
		}

		/*
		 * Clean up previously stored data.
		 */
		conn_info->socket_info_ptr->prev_data_len = 0;
	}

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
						      struct conn_info_t
						      *conn_info)
{
	if (!protocol_port_check_1(PROTO_MYSQL, conn_info))
		return MSG_UNKNOWN;

	if (count == 4) {
		save_prev_data(buf, conn_info, 4);
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

	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_MYSQL)
			return MSG_UNKNOWN;
	}

	if (!conn_info->sk)
		return MSG_UNKNOWN;

	__u32 len;
	__u8 seq, com;

	len = *((__u32 *) buf) & 0x00ffffff;
	seq = buf[3];
	com = buf[4];

	if (conn_info->prev_count == 4) {
		len = *(__u32 *) conn_info->prev_buf & 0x00ffffff;
		if (len == count) {
			seq = conn_info->prev_buf[3];
			count += 4;
			com = buf[0];
		}
	}

	if (count < 5 || len == 0)
		return MSG_UNKNOWN;

	bool is_mysqld = is_current_comm("mysqld");
	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		if (seq == 0 || seq == 1)
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

	if (seq != 0)
		return MSG_UNKNOWN;

	// 请求长度判断来提高推断准确率。
	if (len > 10000) {
		return MSG_UNKNOWN;
	}

	if (com != kComConnect && com != kComQuery && com != kComStmtPrepare &&
	    com != kComStmtExecute && com != kComStmtClose) {
		return MSG_UNKNOWN;
	}

out:
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

	// "user" string, We hope it is a valid string that checks for
	// letter characters in a relaxed manner.
	// This is a loose check and still covers some non alphabetic
	// characters (e.g. `\`)
	if (buf[8] < 'A' || buf[9] < 'A' || buf[10] < 'A' || buf[11] < 'A')
		return false;

	return true;
}

/*
 * ref: https://developer.aliyun.com/article/751984
 * | char tag | int32 len | payload |
 * tag 的取值参考 src/flow_generator/protocol_logs/sql/postgresql.rs
 */
static __inline enum message_type infer_pgsql_query_message(const char *buf,
							    const char *s_buf,
							    size_t count)
{
	// Only a judgement query.
	static const char tag_q = 'Q';
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
	// Tag check
	if (buf[0] != tag_q) {
		return MSG_UNKNOWN;
	}
	// Payload length check
	__u32 length;
	bpf_probe_read(&length, sizeof(length), s_buf + 1);
	length = __bpf_ntohl(length);
	if (length < min_payload_len || length > max_payload_len) {
		return MSG_UNKNOWN;
	}
	// If the input includes a whole message (1 byte tag + length),
	// check the last character.
	if (length + 1 <= (__u32) count) {
		char last_char = ' ';	//Non-zero initial value
		bpf_probe_read(&last_char, sizeof(last_char), s_buf + length);
		if (last_char != '\0')
			return MSG_UNKNOWN;
	}

	return MSG_REQUEST;
}

static __inline enum message_type infer_postgre_message(const char *buf,
							size_t count,
							struct conn_info_t
							*conn_info)
{
#define POSTGRE_INFER_BUF_SIZE 32

	if (!protocol_port_check_2(PROTO_POSTGRESQL, conn_info))
		return MSG_UNKNOWN;

	if (conn_info->tuple.l4_protocol != IPPROTO_TCP) {
		return MSG_UNKNOWN;
	}

	char infer_buf[POSTGRE_INFER_BUF_SIZE];
	bpf_probe_read(infer_buf, sizeof(infer_buf), buf);

	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
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
		case 'Z': case 'I': case '1': case '2': case '3': case 'K':
		case 'T': case 'n': case 'N': case 't': case 'G': case 'W':
		case 'R':
			return MSG_RESPONSE;
		default:
			return MSG_UNKNOWN;
		}
		/* *INDENT-ON* */
	}

	if (infer_pgsql_startup_message(infer_buf, count))
		return MSG_REQUEST;

	return infer_pgsql_query_message(infer_buf, buf, count);
}

static __inline enum message_type infer_oracle_tns_message(const char *buf,
							   size_t count,
							   struct conn_info_t
							   *conn_info)
{
#define OEACLE_INFER_BUF_SIZE 12
#define PKT_TYPE_DATA 6
#define RESP_DATA_ID_RET_STATUS 0x04
#define RESP_DATA_ID_RET_PARAM 0x08
#define RESP_DATA_ID_DESC_INFO 0x10

#define REQ_DATA_ID_PIGGY_BACK_FUNC 0x11
#define REQ_DATA_ID_USER_OCI_FUNC 0x3

#define REQ_CALL_ID_USER_CURSOR_CLOSE_ALL 0x69
#define REQ_CALL_ID_USER_BUNDLED_EXEC_CALL 0x5e
#define REQ_CALL_ID_USER_SESS_SWITCH_OIGGY_BACK 0x6e

	if (!protocol_port_check_2(PROTO_ORACLE, conn_info))
		return MSG_UNKNOWN;
	if (conn_info->tuple.l4_protocol != IPPROTO_TCP || count < 12) {
		return MSG_UNKNOWN;
	}

	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_ORACLE)
			return MSG_UNKNOWN;
	}

	char pkt_type = buf[4];
	char data_id = buf[10];
	char call_id = buf[11];
	if (pkt_type != PKT_TYPE_DATA) {
		return MSG_UNKNOWN;
	}

	if (data_id == RESP_DATA_ID_RET_STATUS
	    || data_id == RESP_DATA_ID_RET_PARAM
	    || data_id == RESP_DATA_ID_DESC_INFO) {
		return MSG_RESPONSE;
	} else if ((data_id == REQ_DATA_ID_PIGGY_BACK_FUNC
		    && call_id == REQ_CALL_ID_USER_CURSOR_CLOSE_ALL)
		   || (data_id == REQ_DATA_ID_PIGGY_BACK_FUNC
		       && call_id == REQ_CALL_ID_USER_SESS_SWITCH_OIGGY_BACK)
		   || (data_id == REQ_DATA_ID_USER_OCI_FUNC
		       && call_id == REQ_CALL_ID_USER_BUNDLED_EXEC_CALL)
	    ) {
		return MSG_REQUEST;
	} else {
		return MSG_UNKNOWN;
	}
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
							struct conn_info_t
							*conn_info)
{
	static const __u8 bolt_resp_header_len = 20;
	static const __u8 bolt_req_header_len = 22;
	static const __u8 bolt_ver_v1 = 0x01;
	static const __u8 type_req = 0x01;
	static const __u8 type_resp = 0x0;
	static const __u16 cmd_code_req = 0x01;
	static const __u16 cmd_code_resp = 0x02;
	static const __u8 codec_hessian = 0;
	static const __u8 codec_hessian2 = 1;
	static const __u8 codec_protobuf = 11;
	static const __u8 codec_json = 12;

	if (count < bolt_resp_header_len)
		return MSG_UNKNOWN;

	if (!protocol_port_check_1(PROTO_SOFARPC, conn_info))
		return MSG_UNKNOWN;

	const __u8 *infer_buf = (const __u8 *)buf;
	__u8 ver = infer_buf[0];	//version for protocol
	__u8 type = infer_buf[1];	// request/response/request oneway

	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_SOFARPC)
			return MSG_UNKNOWN;
		goto out;
	}
	// code for remoting command (Heartbeat, RpcRequest, RpcResponse)
	__u16 cmdcode = __bpf_ntohs(*(__u16 *) & infer_buf[2]);

	// 0 -- "hessian", 1 -- "hessian2", 11 -- "protobuf", 12 -- "json"
	__u8 codec = infer_buf[9];

	if (!((ver == bolt_ver_v1)
	      && (type == type_req || type == type_resp)
	      && (cmdcode == cmd_code_req || cmdcode == cmd_code_resp)
	      && (codec == codec_hessian || codec == codec_hessian2
		  || codec == codec_protobuf || codec == codec_json))) {
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

		goto out;
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

		goto out;
	}

	return MSG_UNKNOWN;
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
						    struct conn_info_t
						    *conn_info)
{
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

	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_DNS)
			return MSG_UNKNOWN;
	}

	bool update_tcp_dns_prev_count = false;
	struct dns_header *dns = (struct dns_header *)buf;
	if (conn_info->tuple.l4_protocol == IPPROTO_TCP) {
		if (__bpf_ntohs(dns->id) + 2 == count) {
			dns = (void *)dns + 2;
		} else {
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
	__u8 *queries_start = (__u8 *) (dns + 1);
	conn_info->dns_q_type = 0;
	for (int idx = 0; idx < 32; ++idx) {
		if (queries_start[idx] == 0) {
			conn_info->dns_q_type =
			    __bpf_ntohs(*(__u16 *) (queries_start + idx + 1));
			break;
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
#pragma unroll
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

// http://redisdoc.com/topic/protocol.html
static __inline enum message_type infer_redis_message(const char *buf,
						      size_t count,
						      struct conn_info_t
						      *conn_info)
{
	if (count < 4)
		return MSG_UNKNOWN;

	if (!protocol_port_check_1(PROTO_REDIS, conn_info))
		return MSG_UNKNOWN;

	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_REDIS)
			return MSG_UNKNOWN;
	}

	const char first_byte = buf[0];

	// 第一个字节仅可能是 '+' '-' ':' '$' '*'
	if (first_byte != '+' && first_byte != '-' && first_byte != ':' &&
	    first_byte != '$' && first_byte != '*')
		return MSG_UNKNOWN;

	// The redis message must contain /r/n.
	// Due to the limitation of eBPF, only the first 20 bytes are checked.
	// The position where the error type /r/n appears may exceed 20 bytes. 
	// Therefore, the error type is not checked
	if (first_byte != '-' && !is_include_crlf(buf))
		return MSG_UNKNOWN;

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
	do {
		digit = buffer[(*lensize)++];
		*length += (digit & 127) * multiplier;
		multiplier *= 128;

		// mqtt 最多用4个字节表示长度
		if ((*lensize) > 4)
			return false;
	} while ((digit & 128) != 0);
	return true;
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
						     struct conn_info_t
						     *conn_info)
{
	if (count < 4)
		return MSG_UNKNOWN;

	if (!protocol_port_check_1(PROTO_MQTT, conn_info))
		return MSG_UNKNOWN;

	if (is_socket_info_valid(conn_info->socket_info_ptr))
		if (conn_info->socket_info_ptr->l7_proto != PROTO_MQTT)
			return MSG_UNKNOWN;

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

/*
 * https://dubbo.apache.org/zh/blog/2018/10/05/dubbo-%E5%8D%8F%E8%AE%AE%E8%AF%A6%E8%A7%A3/
 * 0                                                                                       31
 * |   1byte      |   1byte     |                  1 byte               |      1 byte      |
 * ---------------|-------------|---------------------------------------|------------------|
 * |              |             | 1bit  | 1bit | 1bit  |      5bit      |                  |
 * | Magic High   |  Magic Low  |Req/Res| 2way | Event | Serializion ID |      status      |
 * -----------------------------------------------------------------------------------------
 *
 * 32                                                                                      63
 * |-------------------------------------------------------------------------------------- |
 * 64                                Request ID (8 bytes)                                  95
 * |---------------------------------------------------------------------------------------|
 *
 * 96                                                                                      127
 * |---------------------------------Body Length (4 bytes)---------------------------------|
 *
 * | -------------------------------- Body (n bytes) --------------------------------------|
 *
 * 16字节头 header
 * - Magic High & Magic Low (16 bits) 标识协议版本号，Dubbo 协议：0xdabb
 * - Req/Res (1 bit) 标识是请求或响应。请求： 1; 响应： 0。
 * - 2 Way (1 bit) 仅在 Req/Res 为1（请求）时才有用，标记是否期望从服务器返回值。如果需要来自服务器的返回值，则设置为1。
 * - Event (1 bit) 标识是否是事件消息，例如，心跳事件。如果这是一个事件，则设置为1。
 * - Serialization ID (5 bit) 标识序列化类型：比如 fastjson 的值为6。
 * - Status (8 bits) 仅在 Req/Res 为0（响应）时有用，用于标识响应的状态。
 *     20 - OK
 *     30 - CLIENT_TIMEOUT
 *     31 - SERVER_TIMEOUT
 *     40 - BAD_REQUEST
 *     50 - BAD_RESPONSE
 *     60 - SERVICE_NOT_FOUND
 *     70 - SERVICE_ERROR
 *     80 - SERVER_ERROR
 *     90 - CLIENT_ERROR
 *     100 - SERVER_THREADPOOL_EXHAUSTED_ERROR
 * - Request ID (64 bits) 标识唯一请求。类型为long。
 * - Data Length (32 bits) 序列化后的内容长度（可变部分），按字节计数。int类型。
 * - Variable Part
 *     被特定的序列化类型（由序列化 ID 标识）序列化后，每个部分都是一个 byte [] 或者 byte
 *     如果是请求包 ( Req/Res = 1)，则每个部分依次为：
 *         Dubbo version
 *         Service name
 *         Service version
 *         Method name
 *         Method parameter types
 *         Method arguments
 *         Attachments
 *     如果是响应包（Req/Res = 0），则每个部分依次为：
 *         返回值类型(byte)，标识从服务器端返回的值类型：
 *             返回空值：RESPONSE_NULL_VALUE 2
 *             正常响应值： RESPONSE_VALUE 1
 *             异常：RESPONSE_WITH_EXCEPTION 0
 * 返回值：从服务端返回的响应bytes
 *
 * 包数据=dubbo版本号+接口名称+接口版本号+方法名+参数类型+参数值+ attachments
 */
struct dubbo_header {
	__u16 magic;
	__u8 serial_id:5;
	__u8 event:1;
	__u8 to_way:1;
	__u8 is_req:1;
	__u8 status;
	__u64 request_id;
	__u32 data_len;
} __attribute__ ((packed));

static __inline enum message_type infer_dubbo_message(const char *buf,
						      size_t count,
						      struct conn_info_t
						      *conn_info)
{
	/*
	 * The size of dubbo_header is 16 bytes. If the received quantity
	 * is less than 16 bytes, it will be returned directly.
	 */
	if (count < 16) {
		return MSG_UNKNOWN;
	}

	if (!protocol_port_check_1(PROTO_DUBBO, conn_info))
		return MSG_UNKNOWN;

	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_DUBBO)
			return MSG_UNKNOWN;
	}

	struct dubbo_header *dubbo_hdr = (struct dubbo_header *)buf;
	if (dubbo_hdr->magic != 0xbbda)
		return MSG_UNKNOWN;

	if (dubbo_hdr->serial_id < 2 || dubbo_hdr->serial_id == 5 ||
	    (dubbo_hdr->serial_id > 12 && dubbo_hdr->serial_id < 16))
		return MSG_UNKNOWN;

	if (dubbo_hdr->event == 1 && __bpf_ntohl(dubbo_hdr->data_len) != 1)
		return MSG_UNKNOWN;

	if (dubbo_hdr->is_req == 1) {
		return MSG_REQUEST;
	}

	return MSG_RESPONSE;
}

/*
 * Reference: https://kafka.apache.org/protocol.html#protocol_messages
 * 1、长度：
 * -----------------------------------------------------------------
 * RequestOrResponse --> Size( RequestMessage | ResponseMessage )
 *    Size --> int32
 * -----------------------------------------------------------------
 * 说明：解析时应先读取4字节的长度N，然后读取并解析后续的N字节请求/响应内容。
 *
 * 2、请求都具有以下格式：
 * ------------------------------------------------------------------
 * RequestMessage --> request_header request
 *   request_header --> api_key api_version correlation_id client_id
 *       api_key --> int16
 *       api_version --> int16
 *       correlation_id -->int32
 *       client_id --> string
 *   request --> MetadataRequest | ProduceRequest | FetchRequest | ...
 * -------------------------------------------------------------------
 * 说明：
 * request_header：同类型的请求有不同的ID [0, 67]
 * correlation_id：用户提供的整数，它将被服务器原封不动的传回给客户端,
 *                 用于匹配客户端和服务器之间的请求和响应。
 *
 *
 * 3、响应都具有以下格式：
 * -------------------------------------------------------------------
 * ResponseMessage --> response_header response
 *   response_header --> correlation_id
 *       correlation_id --> int32
 *   response --> MetadataResponse | ProduceResponse | ...
 * -------------------------------------------------------------------
 * 说明：correlation_id 即请求中携带的correlation_id
 *
 * 下面信息依据kafka原文件./clients/src/main/resources/common/message/目录下各种Request.json
 * ProduceRequest : apiKey 0, validVersions "0-9"
 * FetchRequest : apiKey 1, validVersions "0-13"
 * ListOffsetsRequest : apiKey 2, validVersions "0-7"
 * MetadataRequest: apiKey 3, validVersions "0-12",
 * HeartbeatRddequest: "apiKey": 12, "type": "request", "validVersions": "0-4"
 */
static __inline enum message_type infer_kafka_request(const char *buf,
						      bool is_first,
						      struct conn_info_t
						      *conn_info)
{
#define RequestAPIKeyMax 67
#define RequestAPIVerMax 13
#define ProduceRequest 0
#define FetchRequest   1
#define ListOffsetsRequest 2
#define MetadataRequest 3
#define HeartbeatRequest 12

	const __s16 request_api_key = __bpf_ntohs(*(__s16 *) buf);
	const __s16 request_api_version = __bpf_ntohs(*(__s16 *) (buf + 2));

	if (request_api_key < 0 || request_api_key > RequestAPIKeyMax)
		return MSG_UNKNOWN;

	if (request_api_version < 0 || request_api_version > RequestAPIVerMax)
		return MSG_UNKNOWN;

	switch (request_api_key) {
	case ProduceRequest:
		if (request_api_version > 9)
			return MSG_UNKNOWN;
		break;
	case FetchRequest:
		if (request_api_version > 13)
			return MSG_UNKNOWN;
		break;
	case ListOffsetsRequest:
		if (request_api_version > 7)
			return MSG_UNKNOWN;
		break;
	case MetadataRequest:
		if (request_api_version > 12)
			return MSG_UNKNOWN;
		break;
	case HeartbeatRequest:
		if (request_api_version > 4)
			return MSG_UNKNOWN;
		break;
	default:
		if (is_first)
			return MSG_UNKNOWN;
	}

	const __s32 correlation_id = __bpf_ntohl(*(__s32 *) (buf + 4));
	if (correlation_id < 0) {
		return MSG_UNKNOWN;
	}

	conn_info->correlation_id = (__u32) correlation_id;

	return MSG_REQUEST;
}

static __inline bool kafka_data_check_len(size_t count,
					  const char *buf,
					  struct conn_info_t *conn_info,
					  bool * use_prev_buf)
{
	*use_prev_buf = (conn_info->prev_count == 4)
	    && ((size_t) __bpf_ntohl(*(__s32 *) conn_info->prev_buf) == count);

	if (*use_prev_buf) {
		count += 4;
	}
	// length(4 bytes) + api_key(2 bytes) + api_version(2 bytes) + correlation_id(4 bytes)
	static const int min_req_len = 12;
	if (count < min_req_len) {
		return false;
	}
	// 总长度包含了length本身占用的4个字节
	const __s32 message_size =
	    *use_prev_buf ? count : __bpf_ntohl(*(__s32 *) buf) + 4;

	// Enforcing count to be exactly message_size + 4 to mitigate misclassification.
	// However, this will miss long messages broken into multiple reads.
	if (message_size < 0 || count != (size_t) message_size) {
		return false;
	}

	return true;
}

static __inline enum message_type infer_kafka_message(const char *buf,
						      size_t count,
						      struct conn_info_t
						      *conn_info)
{
	if (!protocol_port_check_1(PROTO_KAFKA, conn_info))
		return MSG_UNKNOWN;

	if (count == 4) {
		save_prev_data(buf, conn_info, 4);
		return MSG_PRESTORE;
	}

	bool is_first = true, use_prev_buf;
	if (!kafka_data_check_len(count, buf, conn_info, &use_prev_buf))
		return MSG_UNKNOWN;

	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_KAFKA)
			return MSG_UNKNOWN;

		conn_info->need_reconfirm =
		    conn_info->socket_info_ptr->need_reconfirm;

		if (!conn_info->need_reconfirm) {
			if ((conn_info->role == ROLE_CLIENT
			     && conn_info->direction == T_EGRESS)
			    || (conn_info->role == ROLE_SERVER
				&& conn_info->direction == T_INGRESS)) {
				return MSG_REQUEST;
			}

			return MSG_RESPONSE;
		}

		conn_info->correlation_id =
		    conn_info->socket_info_ptr->correlation_id;
		conn_info->role = conn_info->socket_info_ptr->role;
		is_first = false;
	} else
		conn_info->need_reconfirm = true;

	const char *msg_buf = use_prev_buf ? buf : buf + 4;
	enum message_type msg_type =
	    infer_kafka_request(msg_buf, is_first, conn_info);
	if (msg_type == MSG_REQUEST) {
		// 首次需要在socket_info_map新建socket
		if (is_first) {
			return MSG_RECONFIRM;
		}

		/*
		 * socket_info_map已经存在并且需要确认（需要response的数据进一步），
		 * 这里的request的数据直接丢弃。
		 */
		return MSG_UNKNOWN;
	}
	// 推断的第一个包必须是请求包，否则直接丢弃
	if (is_first)
		return MSG_UNKNOWN;

	// is response ?
	// Response Header v0 => correlation_id
	//  correlation_id => INT32
	const __s32 correlation_id = __bpf_ntohl(*(__s32 *) msg_buf);
	if (correlation_id < 0)
		return MSG_UNKNOWN;

	if (correlation_id == conn_info->correlation_id) {
		// 完成确认
		if (is_socket_info_valid(conn_info->socket_info_ptr)) {
			conn_info->socket_info_ptr->need_reconfirm = false;
			// 角色确认
			if (conn_info->direction == T_EGRESS)
				conn_info->socket_info_ptr->role = ROLE_SERVER;
			else
				conn_info->socket_info_ptr->role = ROLE_CLIENT;
		}
	} else {
		// 再次确认失败直接删除socket记录。
		return MSG_CLEAR;
	}

	// kafka长连接的形式存在，数据开始捕获从类型推断完成开始进行。
	// 此处数据（用于确认协议类型）丢弃不要，避免发给用户产生混乱。
	return MSG_UNKNOWN;
}

struct fastcgi_header {
	__u8 version;
	__u8 type;
	__u16 request_id;
	__u16 content_length;	// cannot be 0
	__u8 padding_length;
	__u8 __unused;
} __attribute__ ((packed));

#define FCGI_BEGIN_REQUEST 1
#define FCGI_PARAMS 4
#define FCGI_STDOUT 6

static bool fastcgi_header_common_check(struct fastcgi_header *header)
{
	if (header->version != 1) {
		return false;
	}
	if (header->padding_length >= 8) {
		return false;
	}

	if ((__bpf_ntohs(header->content_length) + header->padding_length) % 8) {
		return false;
	}
	return true;
}

// NOTE: Nginx receives packets as much as possible in the form of TCP streams,
// resulting in no way to find the location of the header. In this case,
// protocol identification cannot be performed. The performance of the upper
// layer is that php-fpm sends multiple responses continuously, but nginx can
// only receive the first response.
static __inline enum message_type
infer_fastcgi_message(const char *buf, size_t count,
		      struct conn_info_t *conn_info)
{
	if (count < 8) {
		return MSG_UNKNOWN;
	}

	if (!protocol_port_check_1(PROTO_FASTCGI, conn_info))
		return MSG_UNKNOWN;

	struct fastcgi_header *header = NULL;
	header = (struct fastcgi_header *)buf;

	if (fastcgi_header_common_check(header) && count == 8 &&
	    (header->type == FCGI_BEGIN_REQUEST ||
	     header->type == FCGI_PARAMS || header->type == FCGI_STDOUT) &&
	    __bpf_ntohs(header->content_length) != 0) {
		save_prev_data(buf, conn_info, 8);
		return MSG_PRESTORE;
	}

	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_FASTCGI)
			return MSG_UNKNOWN;
		if (header->type == FCGI_BEGIN_REQUEST
		    || header->type == FCGI_PARAMS)
			return MSG_REQUEST;
		else
			return MSG_RESPONSE;
	}

	if (fastcgi_header_common_check(header) && count > 8 &&
	    __bpf_ntohs(header->content_length) != 0) {
		if (header->type == FCGI_BEGIN_REQUEST) {
			return MSG_REQUEST;
		}
		if (header->type == FCGI_STDOUT) {
			return MSG_RESPONSE;
		}
	}

	if (conn_info->prev_count != 8) {
		return MSG_UNKNOWN;
	}

	header = (struct fastcgi_header *)conn_info->prev_buf;
	if (__bpf_ntohs(header->content_length) + header->padding_length !=
	    count) {
		return MSG_UNKNOWN;
	}

	if (header->type == FCGI_BEGIN_REQUEST || header->type == FCGI_PARAMS) {
		return MSG_REQUEST;
	}
	if (header->type == FCGI_STDOUT) {
		return MSG_RESPONSE;
	}
	return MSG_UNKNOWN;
}

// https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/
#define MONGO_OP_REPLY 1
#define MONGO_OP_UPDATE 2001
#define MONGO_OP_INSERT 2002
#define MONGO_RESERVED 2003
#define MONGO_OP_QUERY 2004
#define MONGO_OP_GET_MORE 2005
#define MONGO_OP_DELETE 2006
#define MONGO_OP_KILL_CURSORS 2007
#define MONGO_OP_COMPRESSED 2012
#define MONGO_OP_MSG 2013

struct mongo_header {
	__s32 message_length;
	__s32 request_id;
	__s32 response_to;
	__s32 op_code;
};

static __inline enum message_type
infer_mongo_message(const char *buf, size_t count,
		    struct conn_info_t *conn_info)
{
	if (!is_protocol_enabled(PROTO_MONGO)) {
		return MSG_UNKNOWN;
	}
	if (count < sizeof(struct mongo_header)) {
		return MSG_UNKNOWN;
	}
	struct mongo_header *header = (struct mongo_header *)buf;
	if (header->message_length < count) {
		return MSG_UNKNOWN;
	}
	if (header->request_id < 0) {
		return MSG_UNKNOWN;
	}
	if (header->op_code == MONGO_OP_REPLY) {
		return MSG_RESPONSE;
	}
	if (header->op_code < MONGO_OP_UPDATE) {
		return MSG_UNKNOWN;
	}
	if (header->op_code > MONGO_OP_KILL_CURSORS
	    && header->op_code < MONGO_OP_COMPRESSED) {
		return MSG_UNKNOWN;
	}
	if (header->op_code > MONGO_OP_MSG) {
		return MSG_UNKNOWN;
	}
	return MSG_REQUEST;
}

/*
 * ref: https://wiki.osdev.org/TLS_Handshake
 *
 * Most packets during the communication are of type Handshake (0x16) and are followed by
 * a Handshake packet header.
 * TLS Record Layer:
 * ----------------------
 *    1 bytes     Content Type: Handshake (0x16); Change Cipher Spec (0x14); Encrypted Alert (0x15)
 *    2 bytes     Version: 0x0301 for TLS 1.0; 0x0303 for TLS 1.2
 *    2 bytes     Length
 *
 * =================================================================================
 * Handshake:
 *    1 bytes content_type: 0x16
 *    2 bytes version: 0x0301 for TLS 1.0; 0x0303 for TLS 1.2
 *    2 bytes Length
 * 
 * This header may be followed by another TLS header, such as a TLS Handshake header.
 * Handshake Protocol:
 *    1 bytes   handshake_type:
 *              ----------------------------------------
 *              0x01: handshake type=Client Hello
 *		0x02: Handshake type=Server Hello
 *              0x0B: handshake type=Certificate
 *              0x0C: handshake type=server key exchange
 *              0x0E: handshake type=Server Hello Done Message
 *              0x10: handshake type=client key exchange
 *              0x04: handshake type=New Session Ticket
 *
 *    3 bytes   length
 * =================================================================================
 * Change Cipher Spec Message
 *    1 bytes content_type: 0x14
 *    2 bytes version: 0x0301 for TLS 1.0; 0x0303 for TLS 1.2
 *    2 bytes Length
 * typedef struct __attribute__((packed)) {
 *	uint8_t content_type;  // 0x14
 *       uint16_t version; // 0x0303 for TLS 1.2
 *	uint8_t length;  // 0x01
 *       uint8_t content;  // 0x01
 * } TLSChangeCipherSpec;
 * =================================================================================
 * Encrypted Alert:
 *    1 bytes  content_type: 0x15
 *    2 bytes  version: 0x0301 for TLS 1.0; 0x0303 for TLS 1.2
 *    2 bytes  Length
 *
 *
 * Like for a TCP connection, a TLS connection starts with a handshake between the client and the server:
 *
 * 1.The client sends a Client Hello message (Content_Type:0x16, handshake_type:0x01)
 *
 * 2.The server responds with a Server Hello message (Content_Type:0x16, handshake_type:0x02)
 * 3.The server sends its certificates. (Content_Type:0x16, handshake_type:0x0B)
 * 4.The server sends a Server Key Exchange message (Content_Type:0x16, handshake_type:0x0C)
 * 5.The server sends a Server Hello Done message (Content_Type:0x16, handshake_type:0x0E)
 *
 * 6.The client sends a Client Key Exchange message (Content_Type:0x16, handshake_type:0x10)
 * 7.The client sends a Change Cipher Spec message,
 *   indicate it has completed its part of the handshake. (ontent_Type:0x14, length; 0x01)
 * 8.The client sends a Encrypted Handshake Message (content_type 0x16)
 *
 * 9.The server sends a Change Cipher Spec (ontent_Type:0x14, length; 0x01)
 * 10.The server sends a Encrypted Handshake Message (content_type 0x16)
 *    The TLS handshake is concluded with the two parties sending a hash of the complete handshake exchange, 
 * 11.The client and the server can communicate by exchanging encrypted Application Data messages (content_type 0x17)
 *
 * client test data:
 *
 *       client send:
 *       --------------
 *       (1) curl-29772 handshake handshake.content_type 0x16 version 0x301 handshake_type 0x1
 *                                count 193   dir send (client hello)
 *
 *       client recv:
 *       --------------
 *       (2) curl-29772 handshake handshake.content_type 0x16 version 0x303 handshake_type 0x2
 *                                count 92    dir recv (server hello)
 *       (3) curl-29772 handshake handshake.content_type 0x16 version 0x303 handshake_type 0xb
 *                                count 2812  dir recv
 *       (4) curl-29772 handshake handshake.content_type 0x16 version 0x303 handshake_type 0xc
 *                                count 338   dir recv
 *       (5) curl-29772 handshake handshake.content_type 0x16 version 0x303 handshake_type 0xe
 *                                count 9     dir recv
 *
 *       client send:
 *       ------------
 *       (6) curl-29772 handshake handshake.content_type 0x16 version 0x303 handshake_type 0x10
 *                                count 126   dir send
 *           (7) (8) together with (6);
 *           (8) Encrypted Handshake Message (content_type 0x16) (client finish)
 *
 *       client recv:
 *       ------------
 *       (9)(droped) curl-29772 ChangeCipherSpec content_type 0x14 version 0x303 handshake_type 0x1
 *                                count 6 dir recv
 *       (10) curl-29772 handshake handshake.content_type 0x16 version 0x303 handshake_type 0x0
 *                                count 45    dir recv
 *           (10) Encrypted Handshake Message (content_type 0x16) (server finish)
 *
 * server test data:
 *
 *       server recv:
 *       ------------
 *       (1) openresty-5024 handshake(type 0x16) count 517 version 0x301 handshake_type 0x1 (clilent hello)
 *
 *       server send:
 *       ------------
 *       (2) openresty-5024 handshake(type 0x16) count 1369 version 0x303 handshake_type 0x2 (server hello)
 *           (3),(4),(5) together with (2)
 *
 *       server recv:
 *       ------------
 *       (6) openresty-5024 handshake(type 0x16) count 93 version 0x303 handshake_type 0x10
 *           (7),(8) together with (6)
 *           (7) is Change Cipher Spec message, content_Type:0x14
 *
 *       server send:
 *       ------------
 *       openresty-5024 type 0x16 version 0x303 handshake_type 0x4
 *           (9),(10) are included in this message
 *           (9) is Change Cipher Spec message, content_Type:0x14
 */

typedef struct __attribute__ ((packed)) {
	__u8 content_type;
	__u16 version;
	__u16 length;
	__u8 handshake_type;
} tls_handshake_t;

static __inline enum message_type
infer_tls_message(const char *buf, size_t count, struct conn_info_t *conn_info)
{
	tls_handshake_t handshake = { 0 };

	if (conn_info->prev_count == 5)
		count += 5;

	if (count == 5) {
		handshake.content_type = buf[0];
		handshake.version = __bpf_ntohs(*(__u16 *) & buf[1]);
		goto check;
	}
	// content type: ChangeCipherSpec(0x14) minimal length is 6
	if (count < 6)
		return MSG_UNKNOWN;

	if (conn_info->prev_count == 5) {
		handshake.content_type = conn_info->prev_buf[0];
		handshake.version =
		    __bpf_ntohs(*(__u16 *) & conn_info->prev_buf[1]);
		handshake.handshake_type = buf[0];

	} else {
		handshake.content_type = buf[0];
		handshake.version = __bpf_ntohs(*(__u16 *) & buf[1]);
		handshake.handshake_type = buf[5];
	}

check:
	/*
	 * Content Type: Handshake (0x16), We are only concerned about the
	 * handshake protocol.
	 */
	if (handshake.content_type != 0x16)
		return MSG_UNKNOWN;

	/* version: 0x0301 for TLS 1.0; 0x0303 for TLS 1.2 */
	if (!(handshake.version == 0x301 || handshake.version == 0x303))
		return MSG_UNKNOWN;

	if (count == 5) {
		save_prev_data(buf, conn_info, 5);
		return MSG_PRESTORE;
	}

	/*
	 * The following describes the read and write behavior of the
	 * system calls:
	 *
	 * client send:
	 * --------------
	 * (1) handshake_type 0x1 (client hello)
	 *
	 * client recv:
	 * --------------
	 * (2) handshake_type 0x1 (server hello)
	 * (3) handshake_type 0xb (certificates)
	 * (4) handshake_type 0xc (server key exchange message)
	 * (5) handshake_type 0xe (server hello done message)
	 *
	 * We want to merge (1) and (2) to obtain the desired data. 
	 * (3), (4), and (5) are only the server's responses and are
	 * not involved in aggregation; they are not the data we need.
	 */
	if (handshake.handshake_type == 0xb || handshake.handshake_type == 0xc
	    || handshake.handshake_type == 0xe)
		return MSG_UNKNOWN;

	/*
	 * 0x01: handshake type=Client Hello
	 * 0x10: handshake type=client key exchange
	 */
	if (handshake.handshake_type == 0x1 || handshake.handshake_type == 0x10)
		return MSG_REQUEST;
	else
		return MSG_RESPONSE;
}

static __inline bool drop_msg_by_comm(void)
{
	char comm[TASK_COMM_LEN];

	if (bpf_get_current_comm(&comm, sizeof(comm)))
		return false;

	// filter 'ssh', 'scp', 'sshd'
	if (comm[0] == 's') {
		if ((comm[1] == 's' && comm[2] == 'h' && comm[3] == '\0') ||
		    (comm[1] == 'c' && comm[2] == 'p' && comm[3] == '\0') ||
		    (comm[1] == 's' && comm[2] == 'h' && comm[3] == 'd' &&
		     comm[4] == '\0'))
			return true;
	}

	return false;
}

static __inline struct protocol_message_t
infer_protocol_1(struct ctx_info_s *ctx,
		 const struct data_args_t *args,
		 size_t count,
		 struct conn_info_t *conn_info,
		 __u8 sk_state, const struct process_data_extra *extra)
{
	struct protocol_message_t inferred_message;
	inferred_message.protocol = PROTO_UNKNOWN;
	inferred_message.type = MSG_UNKNOWN;

	if (conn_info->sk == NULL)
		return inferred_message;

	if (conn_info->sk_type == SOCK_STREAM &&
	    sk_state != SOCK_CHECK_TYPE_TCP_ES)
		return inferred_message;

	if (conn_info->tuple.dport == 0 || conn_info->tuple.num == 0) {
		return inferred_message;
	}

	/*
	 * The socket that is indeed determined to be a protocol does not
	 * enter drop_msg_by_comm().
	 */
	if (!is_socket_info_valid(conn_info->socket_info_ptr)) {
		if (drop_msg_by_comm())
			return inferred_message;
	}

	const char *buf = args->buf;
	struct infer_data_s *__infer_buf = &ctx->infer_buf;

	/*
	 * Some protocols are difficult to infer from the first 32 bytes
	 * of data and require more data to be involved in the inference
	 * process.
	 *
	 * In such cases, we can directly pass the buffer address of the
	 * system call for inference.
	 * Examples of such protocols include HTTP2 and Postgre.
	 *
	 * infer_buf:
	 *     The prepared 32-byte inference data has been placed in the buffer.
	 * syscall_infer_addr:
	 *     Just a buffer address needs to call the bpf_probe_read() interface
	 *     to read data. Special note is that if extra->vecs is true,
	 *     its value is the address of the first iov, and syscall_infer_len is
	 *     the length of the first iov.
	 */
	char *syscall_infer_addr = NULL;
	__u32 syscall_infer_len = 0;
	if (extra->vecs) {
		__infer_buf->len = infer_iovecs_copy(__infer_buf, args,
						     count, DATA_BUF_MAX,
						     &syscall_infer_addr,
						     &syscall_infer_len);
		/*
		 * The syscall_infer_len(iov_cpy.iov_len) may be larger than
		 * syscall length, make adjustments here.
		 */
		if (syscall_infer_len > count)
			syscall_infer_len = count;
	} else {
		bpf_probe_read(__infer_buf->data, sizeof(__infer_buf->data),
			       buf);
		syscall_infer_addr = (char *)buf;
		syscall_infer_len = count;
	}

	char *infer_buf = __infer_buf->data;
	conn_info->count = count;
	conn_info->syscall_infer_addr = syscall_infer_addr;
	conn_info->syscall_infer_len = syscall_infer_len;

	check_and_fetch_prev_data(conn_info);

	/*
	 * TLS protocol datas cause other L7 protocols inference misjudgment,
	 * sometimes HTTPS protocol datas is incorrectly inferred as MQTT, DUBBO protocol.
	 * TLS protocol is difficult to identify with features, the port filtering for
	 * the TLS protocol is performed here.
	 */

	/*
	 * If the current port number is configured for the TLS protocol.
	 * If the data source comes from kernel system calls, it is discarded
	 * directly because some kernel probes do not handle TLS data. 
	 */
	if (protocol_port_check_1(PROTO_TLS, conn_info) &&
	    extra->source == DATA_SOURCE_SYSCALL) {
		/*
		 * TLS first performs handshake protocol inference and discards the data
		 * directly if it is unsuccessful.
		 */
		if ((inferred_message.type =
		     infer_tls_message(infer_buf, count,
				       conn_info)) != MSG_UNKNOWN) {
			inferred_message.protocol = PROTO_TLS;
			return inferred_message;
		} else {
			return inferred_message;
		}
	}

	/*
	 * Note:
	 * Use the 'protocol_port_check_1()' interface when performing specific protocol
	 * inference checks.
	 */
#ifdef LINUX_VER_5_2_PLUS
	/*
	 * Protocol inference fast matching.
	 * One thread or process processes the application layer data, and the protocol
	 * inference program has successfully concluded that the protocol is A, then
	 * this thread or process will probably process the data of protocol A later.
	 * We can add a cache for fast matching, use the process-ID/thread-ID
	 * to query the protocol recorded in the cache, and match the protocol preferentially.
	 * If the match fails, a slow match is performed (all protocol sequence matches).
	 *
	 * Due to the limitation of the number of eBPF instruction in kernel, this feature
	 * is suitable for Linux5.2+
	 */

	__u32 pid = (__u32) bpf_get_current_pid_tgid();
	__u32 cache_key = pid >> 16;
	__u8 skip_proto = PROTO_UNKNOWN;
	if (cache_key < PROTO_INFER_CACHE_SIZE) {
		struct proto_infer_cache_t *p;
		p = proto_infer_cache_map__lookup(&cache_key);
		if (p == NULL)
			return inferred_message;
		// https://stackoverflow.com/questions/70750259/bpf-verification-error-when-trying-to-extract-sni-from-tls-packet
		__u8 this_proto = p->protocols[(__u16) pid];
		switch (this_proto) {
		case PROTO_HTTP1:
			if ((inferred_message.type =
			     infer_http_message(infer_buf, count,
						conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_HTTP1;
				conn_info->infer_reliable = 1;
				return inferred_message;
			}
			break;
		case PROTO_REDIS:
			if ((inferred_message.type =
			     infer_redis_message(infer_buf, count,
						 conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_REDIS;
				return inferred_message;
			}
			break;
		case PROTO_MQTT:
			if ((inferred_message.type =
			     infer_mqtt_message(infer_buf, count,
						conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_MQTT;
				return inferred_message;
			}
			break;
		case PROTO_DUBBO:
			if ((inferred_message.type =
			     infer_dubbo_message(infer_buf, count,
						 conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_DUBBO;
				return inferred_message;
			}
			break;
		case PROTO_DNS:
			if ((inferred_message.type =
			     infer_dns_message(infer_buf, count,
					       conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_DNS;
				return inferred_message;
			}
			break;
		case PROTO_MYSQL:
			if ((inferred_message.type =
			     infer_mysql_message(infer_buf, count,
						 conn_info)) != MSG_UNKNOWN) {
				if (inferred_message.type == MSG_PRESTORE)
					return inferred_message;
				inferred_message.protocol = PROTO_MYSQL;
				return inferred_message;
			}
			break;
		case PROTO_KAFKA:
			if ((inferred_message.type =
			     infer_kafka_message(infer_buf, count,
						 conn_info)) != MSG_UNKNOWN) {
				if (inferred_message.type == MSG_PRESTORE)
					return inferred_message;
				inferred_message.protocol = PROTO_KAFKA;
				return inferred_message;
			}
			break;
		case PROTO_SOFARPC:
			if ((inferred_message.type =
			     infer_sofarpc_message(infer_buf, count,
						   conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_SOFARPC;
				return inferred_message;
			}
			break;
		case PROTO_FASTCGI:
			if ((inferred_message.type =
			     infer_fastcgi_message(infer_buf, count,
						   conn_info)) != MSG_UNKNOWN) {
				if (inferred_message.type == MSG_PRESTORE)
					return inferred_message;
				inferred_message.protocol = PROTO_FASTCGI;
				return inferred_message;
			}
			break;
		case PROTO_HTTP2:
			if ((inferred_message.type =
			     infer_http2_message(syscall_infer_addr,
						 syscall_infer_len,
						 conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_HTTP2;
				return inferred_message;
			}
			break;
		case PROTO_POSTGRESQL:
			if ((inferred_message.type =
			     infer_postgre_message(syscall_infer_addr,
						   syscall_infer_len,
						   conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_POSTGRESQL;
				return inferred_message;
			}
			break;
		case PROTO_ORACLE:
			if ((inferred_message.type =
			     infer_oracle_tns_message(infer_buf, count,
						      conn_info)) !=
			    MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_POSTGRESQL;
				return inferred_message;
			}
			break;
		case PROTO_MONGO:
			if ((inferred_message.type =
			     infer_mongo_message(infer_buf, count,
						 conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_MONGO;
				return inferred_message;
			}
			break;
		default:
			break;
		}

		/*
		 * Going here means that no hit is going to be counted in the
		 * slow path. We want the slow path to skip this protocol inference
		 * to avoid duplicate matches.
		 */
		skip_proto = this_proto;
		conn_info->skip_proto = this_proto;
	}

	/*
	 * Enter the slow matching path.
	 */
#endif

	/*
	 * 为了提高协议推断的准确率，做了一下处理：
	 *
	 * 数据一旦首次被推断成功，就会把推断的L7协议类型设置到socket上，这样
	 * 凡是通过此socket读写的所有数据，协议类型就已经被确定了。
	 * 协议推断程序可以快速判断是否要进行数据推断处理。
	 * 例如：
	 *   在 infer_http_message() 中可以快速通过
	 *      if (conn_info->socket_info_ptr->l7_proto != PROTO_HTTP1)
	 *              return MSG_UNKNOWN;
	 *     ... ...
	 *   进行快速判断。
	 */
#ifdef LINUX_VER_5_2_PLUS
	if (skip_proto != PROTO_HTTP1 && (inferred_message.type =
#else
	if ((inferred_message.type =
#endif
	     infer_http_message(infer_buf, count, conn_info)) != MSG_UNKNOWN) {
		conn_info->infer_reliable = 1;
		inferred_message.protocol = PROTO_HTTP1;
#ifdef LINUX_VER_5_2_PLUS
	} else if (skip_proto != PROTO_REDIS && (inferred_message.type =
#else
	} else if ((inferred_message.type =
#endif
		    infer_redis_message(infer_buf, count,
					conn_info)) != MSG_UNKNOWN) {
		inferred_message.protocol = PROTO_REDIS;
#ifdef LINUX_VER_5_2_PLUS
	} else if (skip_proto != PROTO_MQTT && (inferred_message.type =
#else
	} else if ((inferred_message.type =
#endif
		    infer_mqtt_message(infer_buf, count,
				       conn_info)) != MSG_UNKNOWN) {
		inferred_message.protocol = PROTO_MQTT;
#ifdef LINUX_VER_5_2_PLUS
	} else if (skip_proto != PROTO_DUBBO && (inferred_message.type =
#else
	} else if ((inferred_message.type =
#endif
		    infer_dubbo_message(infer_buf, count,
					conn_info)) != MSG_UNKNOWN) {
		inferred_message.protocol = PROTO_DUBBO;
#ifdef LINUX_VER_5_2_PLUS
	} else if (skip_proto != PROTO_DNS && (inferred_message.type =
#else
	} else if ((inferred_message.type =
#endif
		    infer_dns_message(infer_buf, count,
				      conn_info)) != MSG_UNKNOWN) {
		inferred_message.protocol = PROTO_DNS;
#ifdef LINUX_VER_5_2_PLUS
	} else if (skip_proto != PROTO_MONGO && (inferred_message.type =
#else
	} else if ((inferred_message.type =
#endif
		    infer_mongo_message(infer_buf, count,
					conn_info)) != MSG_UNKNOWN) {
		inferred_message.protocol = PROTO_MONGO;
	}

	if (inferred_message.protocol != MSG_UNKNOWN)
		return inferred_message;

#ifdef LINUX_VER_5_2_PLUS
	if (skip_proto != PROTO_MYSQL && (inferred_message.type =
#else
	if ((inferred_message.type =
#endif
	     infer_mysql_message(infer_buf, count, conn_info)) != MSG_UNKNOWN) {
		if (inferred_message.type == MSG_PRESTORE)
			return inferred_message;
		inferred_message.protocol = PROTO_MYSQL;
#ifdef LINUX_VER_5_2_PLUS
	} else if (skip_proto != PROTO_KAFKA && (inferred_message.type =
#else
	} else if ((inferred_message.type =
#endif
		    infer_kafka_message(infer_buf, count,
					conn_info)) != MSG_UNKNOWN) {
		if (inferred_message.type == MSG_PRESTORE)
			return inferred_message;
		inferred_message.protocol = PROTO_KAFKA;
#ifdef LINUX_VER_5_2_PLUS
	} else if (skip_proto != PROTO_SOFARPC && (inferred_message.type =
#else
	} else if ((inferred_message.type =
#endif
		    infer_sofarpc_message(infer_buf, count,
					  conn_info)) != MSG_UNKNOWN) {
		inferred_message.protocol = PROTO_SOFARPC;
#ifdef LINUX_VER_5_2_PLUS
	} else if (skip_proto != PROTO_FASTCGI && (inferred_message.type =
#else
	} else if ((inferred_message.type =
#endif
		    infer_fastcgi_message(infer_buf, count,
					  conn_info)) != MSG_UNKNOWN) {
		if (inferred_message.type == MSG_PRESTORE)
			return inferred_message;
		inferred_message.protocol = PROTO_FASTCGI;
#ifdef LINUX_VER_5_2_PLUS
	} else if (skip_proto != PROTO_HTTP2 && (inferred_message.type =
#else
	} else if ((inferred_message.type =
#endif
		    infer_http2_message(syscall_infer_addr, syscall_infer_len,
					conn_info)) != MSG_UNKNOWN) {
		inferred_message.protocol = PROTO_HTTP2;
	}

	return inferred_message;
}

/* Will be called by proto_infer_2 eBPF program. */
static __inline struct protocol_message_t
infer_protocol_2(const char *infer_buf, size_t count,
		 struct conn_info_t *conn_info)
{
	/*
	 * Note:
	 * infer_buf: inferred data length is within 32 bytes (including 32 bytes).
	 * If the length that needs to be read in the inference program exceeds 32 bytes,
	 * you can use `syscall_infer_addr` and `syscall_infer_len`, but it is strongly
	 * recommended to complete the inference of the protocol within 32 bytes.
	 *
	 * Use the 'protocol_port_check_2()' interface when performing specific protocol
	 * inference checks.
	 */
	struct protocol_message_t inferred_message;
	inferred_message.protocol = PROTO_UNKNOWN;
	inferred_message.type = MSG_UNKNOWN;
	__u32 syscall_infer_len = conn_info->syscall_infer_len;
	char *syscall_infer_addr = conn_info->syscall_infer_addr;

#ifdef LINUX_VER_5_2_PLUS
	__u8 skip_proto = conn_info->skip_proto;
	if (skip_proto != PROTO_POSTGRESQL && (inferred_message.type =
#else
	if ((inferred_message.type =
#endif
	     infer_postgre_message(syscall_infer_addr, syscall_infer_len,
				   conn_info)) != MSG_UNKNOWN) {
		inferred_message.protocol = PROTO_POSTGRESQL;
#ifdef LINUX_VER_5_2_PLUS
	} else if (skip_proto != PROTO_ORACLE && (inferred_message.type =
#else
	} else if ((inferred_message.type =
#endif
		    infer_oracle_tns_message(infer_buf,
					     count,
					     conn_info)) != MSG_UNKNOWN) {
		inferred_message.protocol = PROTO_ORACLE;
	}

	return inferred_message;
}

#endif /* DF_BPF_PROTO_INFER_H */
