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

#include "include/socket_trace.h"
#include "include/task_struct_utils.h"

#define OFFSET_READY		1
#define OFFSET_NO_READY    	0

#define NS_PER_US		1000ULL
#define NS_PER_SEC		1000000000ULL

#define PROTO_INFER_CACHE_SIZE  80

/***********************************************************
 * map definitions
 ***********************************************************/
/*
 * 向用户态传递数据的专用map
 */
MAP_PERF_EVENT(socket_data, int, __u32, MAX_CPU)

/*
 * Why use two Tail Calls jmp tables ?
 *
 * struct bpf_array { ...  enum bpf_prog_type owner_prog_type}
 * 'ownership' of prog_array is claimed by the first program that
 * is going to use this map or by the first program which FD is stored
 * in the map to make sure that all callers and callees have the same
 * prog_type and JITed flag.
 *
 * Tail Calls jmp table
 * We divide the data processing and data output into two parts, and each has a -
 * different eBPF program for processing.
 * The purpose of this is to prevent the problem of the number of instructions exceeding max limit.
 *
 * 'progs_jmp_kp_map' for kprobe/uprobe (`A -> B`, both A and B are [k/u]probe program)
 * 'progs_jmp_tp_map' for tracepoint (`A -> B`, both A and B are tracepoint program)
 */
MAP_PROG_ARRAY(progs_jmp_kp_map, __u32, __u32, 1)
MAP_PROG_ARRAY(progs_jmp_tp_map, __u32, __u32, 2)

/*
 * 因为ebpf栈只有512字节无法存放http数据，这里使用map做为buffer。
 */
MAP_PERARRAY(data_buf, __u32, struct __socket_data_buffer, 1)

/*
 * For protocol infer buffer
 */
struct infer_data_s {
	__u32 len;
	char data[64];
};
MAP_PERARRAY(infer_buf, __u32, struct infer_data_s, 1)
/*
 * 结构体成员偏移
 */
MAP_PERARRAY(members_offset, __u32, struct member_fields_offset, 1)

/*
 * 记录追踪各种ID值(确保唯一性, per CPU 没有使用锁）
 * 生成方法：
 *    1、先初始化一个基值（基值 = [CPU IDX: 8bit] + [ sys_boot_time ]）
 *    2、在基值的基础上递增
 * CPU IDX:          8bit      [0 - 255]个CPU。
 * sys_boot_time:    56bit     使用1970年1月1日00:00:00开始到现在纳秒时间/100
 *
 * 按照每秒钟处理 10,000,000 Requests (这是一个很大值，实际达不到)这样的一个速率，
 * 可以存储176年(如果从2022年开始)的数据而UID不会出现重复。
 * ((2^56 - 1) - sys_boot_time)/10/1000/1000/60/60/24/365 = 176 years
 */
MAP_PERARRAY(trace_conf_map, __u32, struct trace_conf_t, 1)

/*
 * 对各类map进行统计
 */
MAP_PERARRAY(trace_stats_map, __u32, struct trace_stats, 1)

// key: protocol id, value: is protocol enabled, size: PROTO_NUM
MAP_ARRAY(protocol_filter, int, int, PROTO_NUM)

MAP_ARRAY(allow_port_bitmap, __u32, struct allow_port_bitmap, 1)

// write() syscall's input argument.
// Key is {tgid, pid}.
BPF_HASH(active_write_args_map, __u64, struct data_args_t)

// read() syscall's input argument.
// Key is {tgid, pid}.
BPF_HASH(active_read_args_map, __u64, struct data_args_t)

// socket_info_map, 这是个hash表，用于记录socket信息，
// Key is {pid + fd}. value is struct socket_info_t
BPF_HASH(socket_info_map, __u64, struct socket_info_t)

// Key is struct trace_key_t. value is trace_info_t
BPF_HASH(trace_map, struct trace_key_t, struct trace_info_t)

// Stores the identity used to fit the kernel, key: 0, vlaue:{tgid, pid}
MAP_ARRAY(adapt_kern_uid_map, __u32, __u64, 1)

#ifdef LINUX_VER_5_2_PLUS
/*
 * Fast matching cache, used to speed up protocol inference.
 * Due to the limitation of the number of eBPF instruction in kernel, this feature
 * is suitable for Linux5.2+
 * key : The high 16 bits of the process-ID/thread-ID
 * value : struct proto_infer_cache_t
 * The process-ID/thread-ID range [0, 5242880], if the process value exceeds the
 * maximum value range, fast cache matching becomes invalid.
 */
MAP_ARRAY(proto_infer_cache_map, __u32, struct proto_infer_cache_t, PROTO_INFER_CACHE_SIZE)
#endif

static __inline bool is_protocol_enabled(int protocol)
{
	int *enabled = protocol_filter__lookup(&protocol);
	return (enabled) ? (*enabled) : (0);
}

static __inline void delete_socket_info(__u64 conn_key,
					struct socket_info_t *socket_info_ptr)
{
	if (socket_info_ptr == NULL)
		return;

	__u32 k0 = 0;
	struct trace_stats *trace_stats = trace_stats_map__lookup(&k0);
	if (trace_stats == NULL)
		return;

	socket_info_map__delete(&conn_key);
	trace_stats->socket_map_count--;
}

static __u32 __inline get_tcp_write_seq_from_fd(int fd)
{
	__u32 k0 = 0;
	struct member_fields_offset *offset = members_offset__lookup(&k0);
	if (!offset)
		return 0;

	void *sock = get_socket_from_fd(fd, offset);
	__u32 tcp_seq = 0;
	bpf_probe_read(&tcp_seq, sizeof(tcp_seq),
		       sock + offset->tcp_sock__write_seq_offset);
	return tcp_seq;
}

static __u32 __inline get_tcp_read_seq_from_fd(int fd)
{
	__u32 k0 = 0;
	struct member_fields_offset *offset = members_offset__lookup(&k0);
	if (!offset)
		return 0;

	void *sock = get_socket_from_fd(fd, offset);
	if (sock == NULL)
		return 0;

	__u32 tcp_seq = 0;
	bpf_probe_read(&tcp_seq, sizeof(tcp_seq),
		       sock + offset->tcp_sock__copied_seq_offset);
	return tcp_seq;
}

/*
 * B ; buffer
 * O : buffer offset, e.g: infer_buf->len
 * I : &args->iov[i]
 * L_T : total_size
 * L_C : bytes_copy
 * F : first_iov
 * F_S : first_iov_size
 */
#define COPY_IOV(B, O, I, L_T, L_C, F, F_S) do {				\
	struct iovec iov_cpy;							\
	bpf_probe_read(&iov_cpy, sizeof(struct iovec), (I));			\
	if (iov_cpy.iov_base == NULL) continue;					\
	if (!(F)) {								\
		F = iov_cpy.iov_base;						\
		F_S = iov_cpy.iov_len;						\
	}									\
	const int bytes_remaining = (L_T) - (L_C);				\
        __u32 iov_size =							\
            iov_cpy.iov_len <							\
            bytes_remaining ? iov_cpy.iov_len : bytes_remaining;		\
        __u32 len = (O) + (L_C);						\
        struct copy_data_s *cp = (struct copy_data_s *)((B) + len);		\
	if (len > (sizeof((B)) - sizeof(*cp)))					\
		return (L_C);							\
	if (iov_size >= sizeof(cp->data)) {					\
		bpf_probe_read(cp->data, sizeof(cp->data), iov_cpy.iov_base);	\
		iov_size = sizeof(cp->data);					\
	} else {								\
		iov_size = iov_size & (sizeof(cp->data) - 1);			\
		bpf_probe_read(cp->data, iov_size + 1, iov_cpy.iov_base);	\
	}									\
	L_C = (L_C) + iov_size;							\
} while (0)

static __inline int iovecs_copy(struct __socket_data *v,
				struct __socket_data_buffer *v_buff,
				const struct data_args_t* args,
				size_t syscall_len,
				__u32 send_len)
{
#define LOOP_LIMIT 12

	struct copy_data_s {
		char data[CAP_DATA_SIZE];
	};

	int bytes_copy = 0;
	__u32 total_size = 0;

	if (syscall_len >= sizeof(v->data))
		total_size = sizeof(v->data);
	else
		total_size = send_len;
	char *first_iov = NULL;
	__u32 first_iov_size = 0;

#pragma unroll
	for (unsigned int i = 0;
	     i < LOOP_LIMIT && i < args->iovlen && bytes_copy < total_size;
	     ++i) {
		COPY_IOV(v_buff->data,
			 v_buff->len + offsetof(typeof(struct __socket_data),
						data), &args->iov[i],
			 total_size, bytes_copy, first_iov, first_iov_size);
	}

	return bytes_copy;
}

static __inline int infer_iovecs_copy(struct infer_data_s *infer_buf,
				      const struct data_args_t *args,
				      size_t syscall_len,
				      __u32 copy_len,
				      char **f_iov,
				      __u32 *f_iov_len)
{
#define INFER_COPY_SZ	 32
#define INFER_LOOP_LIMIT 3
	struct copy_data_s {
		char data[INFER_COPY_SZ];
	};

	int bytes_copy = 0;
	__u32 total_size = 0;
	infer_buf->len = 0;

	if (syscall_len >= sizeof(infer_buf->data))
		total_size = sizeof(infer_buf->data);
	else
		total_size = copy_len;
	char *first_iov = NULL;
	__u32 first_iov_size = 0;

#pragma unroll
	for (unsigned int i = 0;
	     i < INFER_LOOP_LIMIT && i < args->iovlen && bytes_copy < total_size;
	     i++) {
		COPY_IOV(infer_buf->data, infer_buf->len, &args->iov[i],
			 total_size, bytes_copy, first_iov, first_iov_size);
	}

	*f_iov = first_iov;
	*f_iov_len = first_iov_size;

	return bytes_copy;
}

#include "uprobe_base_bpf.c"
#include "include/protocol_inference.h"
#define EVENT_BURST_NUM            16
#define CONN_PERSIST_TIME_MAX_NS   100000000000ULL

static __inline struct trace_key_t get_trace_key(__u64 timeout)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 goid = 0;

	if (timeout){
		goid = get_rw_goid(timeout * NS_PER_SEC);
	}

	struct trace_key_t key = {};

	key.tgid = (__u32)(pid_tgid >> 32);

	if (goid) {
		key.goid = goid;
	} else {
		key.pid = (__u32)pid_tgid;
	}

	return key;
}

static __inline unsigned int __retry_get_sock_flags(void *sk,
						    int offset)
{
	unsigned int flags = 0;
	bpf_probe_read(&flags, sizeof(flags), (void *)sk + offset);
	return flags;
}

static __inline void infer_sock_flags(void *sk,
				      struct member_fields_offset *offset)
{
	struct sock_flags_t {
		unsigned int sk_padding : 1;
		unsigned int sk_kern_sock : 1;
		unsigned int sk_no_check_tx : 1;
		unsigned int sk_no_check_rx : 1;
		unsigned int sk_userlocks : 4;
		unsigned int sk_protocol : 8;
		unsigned int sk_type : 16;
	};

	// Member '__sk_flags_offset' the offset in struct sock
	// 0x220 for 4.19.90-23.15.v2101.ky10.x86_64
#ifdef LINUX_VER_KYLIN
	int sock_flags_offset_array[] = {0x1f0, 0x1f8, 0x200, 0x208, 0x210, 0x218, 0x220};
#else
	int sock_flags_offset_array[] = {0x1f0, 0x1f8, 0x200, 0x208, 0x210, 0x218};
#endif

	unsigned int flags = 0;
	struct sock_flags_t *sk_flags = (struct sock_flags_t *)&flags;
	int i;
#pragma unroll
	for (i = 0; i < ARRAY_SIZE(sock_flags_offset_array); i++) {
		flags  = __retry_get_sock_flags(sk, sock_flags_offset_array[i]);
		/*
		 * struct sock *sk_alloc(struct net *net, int family, gfp_t priority,
		 *		      struct proto *prot, int kern)
		 *
		 *       -》sk = sk_prot_alloc(prot, priority | __GFP_ZERO, family);
		 * 在申请sock时，使用了__GFP_ZERO，为了尽量确保准确性增加一个sk_padding为0判断。
		 */
		if ((sk_flags->sk_type == SOCK_DGRAM
		     || sk_flags->sk_type == SOCK_STREAM)
		    && sk_flags->sk_kern_sock == 0
		    && sk_flags->sk_padding == 0) {
			offset->sock__flags_offset = sock_flags_offset_array[i];
			break;
		}
	}
}

static __inline void get_sock_flags(void *sk,
				    struct member_fields_offset *offset,
				    struct conn_info_t *conn_info)
{
	struct sock_flags_t {
		unsigned int sk_padding : 1;
		unsigned int sk_kern_sock : 1;
		unsigned int sk_no_check_tx : 1;
		unsigned int sk_no_check_rx : 1;
		unsigned int sk_userlocks : 4;
		unsigned int sk_protocol : 8;
		unsigned int sk_type : 16;
	};

	unsigned int flags = 0;
	struct sock_flags_t *sk_flags = (struct sock_flags_t *)&flags;
	bpf_probe_read(&flags, sizeof(flags), (void *)sk +
		       offset->sock__flags_offset);

	conn_info->sk_type = sk_flags->sk_type;
}

/*
 * IPv4 connections can be handled with the v6 API by using the
 * v4-mapped-on-v6 address type;thus a program needs to
 * support only this API type to support both protocols.This
 * is handled transparently by the address handling functions
 * in the C library . IPv4 and IPv6 share the local port space.
 * When you get an IPv4 connection or packet to a IPv6 socket,
 * its source address will be mapped to v6 and it will be mapped
 * to v6. The address notation for IPv6 is a group of 8 4 -digit
 * hexadecimal numbers, separated with a ':'."::" stands for a
 * string of 0 bits.
 * Special addresses are
 *   ::1 for loopback and ::FFFF:<IPv4 address> for IPv4-mapped-on-IPv6.
 */
/*
 * Confirm whether you want to obtain IP through socket IPv4 address
 *
 * @s sock address
 * @f skc_family
 */
#define ipv4_mapped_on_ipv6_confirm(s, f)				\
do {									\
	char __addr[16];						\
	bpf_probe_read(__addr, 16, (s) + STRUCT_SOCK_IP6SADDR_OFFSET);	\
	__u32 __feature = *(__u32 *)&__addr[8];				\
	if (__feature == 0xffff0000)					\
		f = PF_INET;						\
} while(0)

static __inline int is_tcp_udp_data(void *sk,
				    struct member_fields_offset *offset,
				    struct conn_info_t *conn_info)
{
	struct skc_flags_t {
		unsigned char skc_reuse : 4;
		unsigned char skc_reuseport : 1;
		unsigned char skc_ipv6only : 1;
		unsigned char skc_net_refcnt : 1;
	};

	struct skc_flags_t skc_flags;
	bpf_probe_read(&skc_flags, sizeof(skc_flags),
		       sk + STRUCT_SOCK_COMMON_IPV6ONLY_OFFSET);
	conn_info->skc_ipv6only = skc_flags.skc_ipv6only;
	bpf_probe_read(&conn_info->skc_family, sizeof(conn_info->skc_family),
		       sk + STRUCT_SOCK_FAMILY_OFFSET);
	/*
	 * Without thinking about PF_UNIX.
	 */
	switch (conn_info->skc_family) {
	case PF_INET:
		break;
	case PF_INET6:
		if (conn_info->skc_ipv6only == 0) {
			ipv4_mapped_on_ipv6_confirm(sk, conn_info->skc_family);
		}
		break;
	default:
		return SOCK_CHECK_TYPE_ERROR;
	}

	get_sock_flags(sk, offset, conn_info);

	if (conn_info->sk_type == SOCK_DGRAM) {
		conn_info->tuple.l4_protocol = IPPROTO_UDP;
		return SOCK_CHECK_TYPE_UDP;
	}

	if (conn_info->sk_type != SOCK_STREAM) {
		return SOCK_CHECK_TYPE_ERROR;
	}

	unsigned char skc_state;
	bpf_probe_read(&skc_state, sizeof(skc_state), (void *)sk + STRUCT_SOCK_SKC_STATE_OFFSET);

	/* 如果连接尚未建立好，不处于ESTABLISHED或者CLOSE_WAIT状态，退出 */
	if ((1 << skc_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT)) {
		return SOCK_CHECK_TYPE_ERROR;
	}

	conn_info->tuple.l4_protocol = IPPROTO_TCP;
	return SOCK_CHECK_TYPE_TCP_ES;
}

static __inline void init_conn_info(__u32 tgid, __u32 fd,
				    struct conn_info_t *conn_info,
				    void *sk)
{
	__be16 inet_dport;
	__u16 inet_sport;
	bpf_probe_read(&inet_dport, sizeof(inet_dport), sk + STRUCT_SOCK_DPORT_OFFSET);
	bpf_probe_read(&inet_sport, sizeof(inet_sport), sk + STRUCT_SOCK_SPORT_OFFSET);
	conn_info->tuple.dport = __bpf_ntohs(inet_dport);
	conn_info->tuple.num = inet_sport;
	conn_info->correlation_id = -1; // 当前用于kafka协议推断
	conn_info->fd = fd;

	conn_info->sk = sk;
	__u64 conn_key = gen_conn_key_id((__u64)tgid, (__u64)conn_info->fd);
	conn_info->socket_info_ptr =
			socket_info_map__lookup(&conn_key);
}

static __inline bool get_socket_info(struct __socket_data *v,
				     void *sk,
				     struct conn_info_t* conn_info)
{
	if (v == NULL || sk == NULL)
		return false;

	/*
	 * Without thinking about PF_UNIX.
	 */
	switch (conn_info->skc_family) {
	case PF_INET:
		bpf_probe_read(v->tuple.rcv_saddr, 4, sk + STRUCT_SOCK_SADDR_OFFSET);
		bpf_probe_read(v->tuple.daddr, 4, sk + STRUCT_SOCK_DADDR_OFFSET);
		v->tuple.addr_len = 4;
		break;
	case PF_INET6:
		bpf_probe_read(v->tuple.rcv_saddr, 16, sk + STRUCT_SOCK_IP6SADDR_OFFSET);
		bpf_probe_read(v->tuple.daddr, 16, sk + STRUCT_SOCK_IP6DADDR_OFFSET);
		v->tuple.addr_len = 16;
		break;
	default:
		return false;
	}

	return true;
}

#ifdef PROBE_CONN_SUBMIT
static __inline void connect_submit(struct pt_regs *ctx, struct conn_info_t *v, int act)
{
	switch (act) {
	case CONN_ADD:
		v->type = SOCK_ADD_EVENT;
		break;
	case CONN_DEL:
		v->type = SOCK_INFO_EVENT;
		break;
	default:
		return;
	}

	int ret = bpf_perf_event_output(ctx, &NAME(socket_data),
					BPF_F_CURRENT_CPU, v,
					128);

	if (ret) bpf_debug("connect_submit: %d\n", ret);
}
#endif

static __inline void infer_l7_class(struct conn_info_t* conn_info,
				    enum traffic_direction direction, const struct data_args_t *args,
				    size_t count, __u8 sk_type,
				    const struct process_data_extra *extra) {
	if (conn_info == NULL) {
		return;
	}

	// 推断应用协议
	struct protocol_message_t inferred_protocol =
		infer_protocol(args, count, conn_info, sk_type, extra);
	if (inferred_protocol.protocol == PROTO_UNKNOWN &&
	    inferred_protocol.type == MSG_UNKNOWN) {
		conn_info->protocol = PROTO_UNKNOWN;
		return;
	}

	conn_info->protocol = inferred_protocol.protocol;
	conn_info->message_type = inferred_protocol.type;
}

static __inline __u32 retry_get_write_seq(void *sk,
					  int offset,
					  int snd_nxt_offset)
{
	/*
	 * 判断依据
	 *
	 * write_seq ==  snd_nxt && snd_nxt != 0 && write_seq != 0
	 */
	__u32 snd_nxt, write_seq;

	bpf_probe_read(&write_seq, sizeof(write_seq), (void *)sk + offset);
	bpf_probe_read(&snd_nxt, sizeof(snd_nxt), (void *)sk + snd_nxt_offset);

	if (snd_nxt == write_seq && snd_nxt != 0 && write_seq != 0) {
		return write_seq;
	} else
		return 0;

	return 0;
}

static __inline __u32 retry_get_copied_seq(void *sk,
					   int offset)
{
	/*
	 * 判断依据
	 * copied_seq + 1 == rcv_wup
	 * tcp_header_len 在[20, 60]区间
	 * rcv_wup == rcv_nxt
	 * rcv_wup != 0 && rcv_nxt != 0 && copied_seq != 0
	 *
	 * struct tcp_sock {
	 *     ...
	 *     u16	tcp_header_len;     -28
	 *     ...
	 *     u64	bytes_received;     -20
	 *     ...
	 *     u32	rcv_nxt;            -4
	 *     u32	copied_seq;         0
	 *     u32	rcv_wup;            +4
	 *     u32      snd_nxt;	    +8
	 *     ...
	 * }
	 */
	__u32 rcv_nxt, rcv_wup, copied_seq;
	__u16 tcp_header_len;

	bpf_probe_read(&copied_seq, sizeof(copied_seq), (void *)sk + offset);
	bpf_probe_read(&rcv_nxt, sizeof(rcv_nxt), (void *)sk + offset - 4);
	bpf_probe_read(&rcv_wup, sizeof(rcv_wup), (void *)sk + offset + 4);
	bpf_probe_read(&tcp_header_len, sizeof(tcp_header_len), (void *)sk + offset - 28);

	if (!(tcp_header_len >= 20 && tcp_header_len <= 60 && copied_seq != 0))
		return 0;

	if ((copied_seq == rcv_nxt && rcv_wup == rcv_nxt)) {
		return copied_seq;
	}

	return 0;
}

static __inline void infer_tcp_seq_offset(void *sk,
					  struct member_fields_offset *offset)
{
	// 成员 copied_seq 在 struct tcp_sock 中的偏移量
	// 0x644 for EulerOS 4.18.0-147
	// 0x65c for 4.19.90-23.15.v2101.ky10.x86_64
#ifdef LINUX_VER_KYLIN 
	int copied_seq_offsets[] = {0x514, 0x524, 0x52c, 0x534, 0x53c,
				    0x544, 0x54c, 0x554, 0x55c, 0x564,
				    0x56c, 0x574, 0x57c, 0x584, 0x58c,
				    0x594, 0x59c, 0x5dc, 0x644, 0x65c};
#else
	int copied_seq_offsets[] = {0x514, 0x51c, 0x524, 0x52c, 0x534,
				    0x53c, 0x544, 0x54c, 0x554, 0x55c,
				    0x564, 0x56c, 0x574, 0x57c, 0x584,
				    0x58c, 0x594, 0x59c, 0x5dc, 0x644};
#endif

	// 成员 write_seq 在 struct tcp_sock 中的偏移量
	// 0x7b4 for EulerOS 4.18.0-147
	// 0x7cc for 4.19.90-23.15.v2101.ky10.x86_64
	// The 0x684 feature code interferes with the inference of write_seq in the Kylin system. It must be removed.
#ifdef LINUX_VER_KYLIN
	int write_seq_offsets[] = {0x66c, 0x674, 0x68c, 0x694, 0x69c, 0x6a4,
				   0x6ac, 0x6b4, 0x6bc, 0x6c4, 0x6cc, 0x6d4,
				   0x6dc, 0x6ec, 0x6f4, 0x6fc, 0x704, 0x70c,
				   0x714, 0x71c, 0x74c, 0x7b4, 0x7cc};
#else
	int write_seq_offsets[] = {0x66c, 0x674, 0x67c, 0x684, 0x68c, 0x694,
				   0x69c, 0x6a4, 0x6ac, 0x6b4, 0x6bc, 0x6c4,
				   0x6cc, 0x6d4, 0x6dc, 0x6e4, 0x6ec, 0x6f4,
				   0x6fc, 0x704, 0x70c, 0x714, 0x71c, 0x74c,
				   0x7b4};
#endif

	int i, snd_nxt_offset = 0;

	if (!offset->tcp_sock__copied_seq_offset) {
#pragma unroll
		for (i = 0; i < ARRAY_SIZE(copied_seq_offsets); i++) {
			if (retry_get_copied_seq(sk, copied_seq_offsets[i])) {
				offset->tcp_sock__copied_seq_offset = copied_seq_offsets[i];
				break;
			}
		}
	}

	/*
	 * snd_nxt_offset 用于write_seq offset的判断。
	 *
	 *     u32      copied_seq;         0
	 *     u32      rcv_wup;            +4
	 *     u32      snd_nxt;            +8
	 */
	snd_nxt_offset = offset->tcp_sock__copied_seq_offset + 8;

	if (snd_nxt_offset == 8)
		return;

	if (!offset->tcp_sock__write_seq_offset) {
#pragma unroll
		for (i = 0; i < ARRAY_SIZE(write_seq_offsets); i++) {
			if (retry_get_write_seq(sk, write_seq_offsets[i], snd_nxt_offset)) {
				offset->tcp_sock__write_seq_offset = write_seq_offsets[i];
				break;
			}
		}
	}
}

static __inline int infer_offset_retry(int fd)
{
	__u32 k0 = 0;
	struct member_fields_offset *offset = members_offset__lookup(&k0);
	if (!offset)
		return OFFSET_NO_READY;

	if (unlikely(!offset->ready)) {
		__u64 *adapt_uid = adapt_kern_uid_map__lookup(&k0);
		if (!adapt_uid)
			return OFFSET_NO_READY;

		// Only a preset uid can be adapted to the kernel
		if (*adapt_uid != bpf_get_current_pid_tgid())
			return OFFSET_NO_READY;

		void *infer_sk =
		    infer_and_get_socket_from_fd(fd, offset, false);
		if (infer_sk) {
			if (unlikely(!offset->sock__flags_offset))
				infer_sock_flags(infer_sk, offset);

			if (unlikely(!offset->tcp_sock__copied_seq_offset ||
				     !offset->tcp_sock__write_seq_offset)) {
				infer_tcp_seq_offset(infer_sk, offset);
				if (likely
				    (offset->tcp_sock__copied_seq_offset
				     && offset->tcp_sock__write_seq_offset
				     && offset->sock__flags_offset
				     && offset->task__files_offset))
					offset->ready = 1;
			}
		}
	}

	if (!offset->ready)
		return OFFSET_NO_READY;
	return OFFSET_READY;
}

#define CHECK_OFFSET_READY(f) \
do { \
	if (infer_offset_retry((f)) == OFFSET_NO_READY) \
		return 0; \
} while(0)

#define TRACE_MAP_ACT_NONE  0
#define TRACE_MAP_ACT_NEW   1
#define TRACE_MAP_ACT_DEL   2

static __inline void trace_process(struct socket_info_t *socket_info_ptr,
				   struct conn_info_t* conn_info,
				   __u64 socket_id, __u64 pid_tgid,
				   struct trace_info_t *trace_info_ptr,
				   struct trace_conf_t *trace_conf,
				   struct trace_stats *trace_stats,
				   __u64 *thread_trace_id,
				   __u64 time_stamp,
				   struct trace_key_t *trace_key) {
	/*
	 * ==========================================
	 * Thread-Trace-ID (Single Redirect Trace)
	 * ==========================================
	 *
	 * Ingress              |                   | Egress
	 * ----------------------------------------------------------
	 *                   socket-a                |
	 * trace start ID ①  -> |                    |
	 *                      |                   socket-b
	 *                      - same thread ID --- |
	 *                                           | ①  -> trace end
	 *                                           |
	 *                                           |
	 * ... ...
	 *                   socket-n
	 * trace start ID ② -> |                     |
	 *                     |                    socket-m
	 *                      - same thread ID --- |
	 *                                           | ② -> trace end
	 */

	/*
	 * 同方向多个连续请求或回应的场景：
	 *
	 *              Ingress |
	 * ----------------------
	 *                   socket-n
	 *                ①  -> |
	 *                ②  -> |
	 *                ③  -> |
	 *               ......
	 *
	 *
	 *                      | Egress
	 * -----------------------------
	 *                   socket-m
	 *                      | -> ①
	 *                        ......
	 * 采用的策略是：沿用上次trace_info保存的traceID。
	 */

	/*
	 * Socket A actively sends a request as a client (traceID is 0), 
	 * and associates socket B with the thread ID. Socket B receives a
	 * response as the client, create new traceID as the starting point
	 * for the entire tracking process. There is a problem in tracking
	 * down like this, and a closed loop cannot be formed. This is due to
	 * receiving a response from socket B to start the trace, but not being
	 * able to get a request from socket B to finish the entire trace.
	 *
	 * (socket A) -- request ->
	 *            |
	 *       (socket B) <- response (traceID-1) [The starting point of trace]
	 *               |
	 *             (socket C) -- request -> (traceID-1)
	 *                    |
	 *                  (socket D) <- response (traceID-2)
	 *                         |
	 *                      (socket E) -- request -> (traceID-2)
	 *                            ... ...  (Can't finish the whole trace)
	 *
	 * In order to avoid invalid association of the client, the behavior of creating
	 * a new trace on socket B is cancelled.
	 *
	 * (socket A) ------- request -------->
	 *        |
	 *     thread-ID
	 *        |
	 *      (socket B) <---- response (Here, not create new trace.)
	 */

	__u64 pre_trace_id = 0;
	if (is_socket_info_valid(socket_info_ptr) &&
	    conn_info->direction == socket_info_ptr->direction &&
	    conn_info->message_type == socket_info_ptr->msg_type) {
		if (trace_info_ptr)
			pre_trace_id = trace_info_ptr->thread_trace_id;
		conn_info->keep_data_seq = true; // 同时这里确保捕获数据的序列号保持不变。
	}

	if (conn_info->direction == T_INGRESS) {
		if (trace_info_ptr) {
			/*
			 * The following scenarios do not track:
			 * ---------------------------------------
			 *                 [traceID : 0]
			 * (client-socket) request -> 
			 *       |
			 *     thread-ID
			 *       |
			 *     (client-socket) <- response
			 */
			if (trace_info_ptr->is_trace_id_zero &&
			    conn_info->message_type == MSG_RESPONSE &&
			    conn_info->infer_reliable) {
				trace_map__delete(trace_key);
				trace_stats->trace_map_count--;
				return;
			}
		}

		struct trace_info_t trace_info = { 0 };
		*thread_trace_id = trace_info.thread_trace_id =
				(pre_trace_id == 0 ? ++trace_conf->thread_trace_id : pre_trace_id);
		if (conn_info->message_type == MSG_REQUEST)
			trace_info.peer_fd = conn_info->fd;
		else if (conn_info->message_type == MSG_RESPONSE) {
			if (is_socket_info_valid(socket_info_ptr) &&
			    socket_info_ptr->peer_fd != 0)
				trace_info.peer_fd = socket_info_ptr->peer_fd;
		}
		trace_info.update_time = time_stamp / NS_PER_SEC;
		trace_info.socket_id = socket_id;
		trace_map__update(trace_key, &trace_info);
		if (!trace_info_ptr)
			trace_stats->trace_map_count++;
	} else { /* direction == T_EGRESS */
		if (trace_info_ptr) {
			/*
			 * Skip the scene below:
			 * ------------------------------------------------
			 * (client-socket) request [traceID : 0] ->
			 *        |
			 *      thread-ID
			 *	  |
			 * 	(client-socket) request [traceID : 0] ->
			 */
			if (trace_info_ptr->is_trace_id_zero) {
				return;
			}
			/*
			 * 追踪在不同socket之间进行，而对于在同一个socket的情况进行忽略。
			 */
			if (socket_id != trace_info_ptr->socket_id) {
				*thread_trace_id = trace_info_ptr->thread_trace_id;
			}

			trace_map__delete(trace_key);
			trace_stats->trace_map_count--;
		} else {
			/*
			 * Record the scene below:
			 * ------------------------------------------------
			 * (client-socket) request [traceID : 0] ->
			 */
			if (conn_info->message_type == MSG_REQUEST) {
				struct trace_info_t trace_info = { 0 };
				trace_info.is_trace_id_zero = true;
				trace_info.update_time = time_stamp / NS_PER_SEC;
				trace_map__update(trace_key, &trace_info);
				trace_stats->trace_map_count++;
			}
		}
	}
}

static __inline int
data_submit(struct pt_regs *ctx, struct conn_info_t *conn_info,
	    const struct data_args_t *args, const bool vecs, __u32 syscall_len,
	    struct member_fields_offset *offset, __u64 time_stamp,
	    const struct process_data_extra *extra)
{
	if (conn_info == NULL) {
		return -1;
	}

	// ignore non-http protocols that are go tls
	if (extra->source == DATA_SOURCE_GO_TLS_UPROBE) {
		if (conn_info->protocol != PROTO_HTTP1)
			return -1;
	}

	if (extra->source == DATA_SOURCE_OPENSSL_UPROBE) {
		if (conn_info->protocol != PROTO_HTTP1 &&
		    conn_info->protocol != PROTO_HTTP2)
			return -1;
	}

	if (conn_info->sk == NULL || conn_info->message_type == MSG_UNKNOWN) {
		return -1;
	}

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32) (pid_tgid >> 32);
	if (time_stamp == 0)
		time_stamp = bpf_ktime_get_ns();
	__u64 conn_key = gen_conn_key_id((__u64)tgid, (__u64)conn_info->fd);

	if (conn_info->message_type == MSG_CLEAR) {
		delete_socket_info(conn_key, conn_info->socket_info_ptr);
		return -1;
	}

	__u32 tcp_seq = args->tcp_seq;
	__u64 thread_trace_id = 0;
	__u32 k0 = 0;
	struct socket_info_t sk_info = { 0 };
	struct trace_conf_t *trace_conf = trace_conf_map__lookup(&k0);
	if (trace_conf == NULL)
		return -1;

	/*
	 * It is possible that these values were modified during ebpf running,
	 * so they are saved here.
	 */
	int data_max_sz = trace_conf->data_limit_max;

	struct trace_stats *trace_stats = trace_stats_map__lookup(&k0);
	if (trace_stats == NULL)
		return -1;

	__u32 timeout = trace_conf->go_tracing_timeout;
	struct trace_key_t trace_key = get_trace_key(timeout);
	struct trace_info_t *trace_info_ptr = trace_map__lookup(&trace_key);

	struct socket_info_t *socket_info_ptr = conn_info->socket_info_ptr;
	// 'socket_id' used to resolve non-tracing between the same socket
	__u64 socket_id = 0;
	if (!is_socket_info_valid(socket_info_ptr)) {
		// Not use "++trace_conf->socket_id" here,
		// because it did not pass the verification of linux 4.14.x, 4.15.x
		socket_id = trace_conf->socket_id + 1;
	} else {
		socket_id = socket_info_ptr->uid;
	}

	if (conn_info->message_type != MSG_PRESTORE &&
	    conn_info->message_type != MSG_RECONFIRM &&
	    !(trace_key.goid != 0 && timeout == 0))
		trace_process(socket_info_ptr, conn_info, socket_id, pid_tgid,
			      trace_info_ptr, trace_conf, trace_stats,
			      &thread_trace_id, time_stamp, &trace_key);

	if (!is_socket_info_valid(socket_info_ptr)) {
		if (socket_info_ptr && conn_info->direction == T_EGRESS) {
			sk_info.peer_fd = socket_info_ptr->peer_fd;
			thread_trace_id = socket_info_ptr->trace_id;
		}

		sk_info.uid = trace_conf->socket_id + 1;
		trace_conf->socket_id++; // Ensure that socket_id is incremented.
		sk_info.l7_proto = conn_info->protocol;
		sk_info.direction = conn_info->direction;
		sk_info.role = conn_info->role;
		sk_info.msg_type = conn_info->message_type;
		sk_info.update_time = time_stamp / NS_PER_SEC;
		sk_info.need_reconfirm = conn_info->need_reconfirm;
		sk_info.correlation_id = conn_info->correlation_id;

		/*
		 * MSG_PRESTORE 目前只用于MySQL, Kafka协议推断
		 */
		if (conn_info->message_type == MSG_PRESTORE) {
			*(__u32 *)sk_info.prev_data = *(__u32 *)conn_info->prev_buf;
			sk_info.prev_data_len = 4;
			sk_info.uid = 0;
		}

		socket_info_map__update(&conn_key, &sk_info);
		if (socket_info_ptr == NULL)
			trace_stats->socket_map_count++;
	}

	/*
	 * 对于预先存储数据或socket l7协议类型需要再次确认(适用于长链接)
	 * 的动作只建立socket_info_map项不会发送数据给用户态程序。
	 */
	if (conn_info->message_type == MSG_PRESTORE ||
	    conn_info->message_type == MSG_RECONFIRM)
		return -1;

	if (is_socket_info_valid(socket_info_ptr)) {
		sk_info.uid = socket_info_ptr->uid;

		/*
		 * 同方向多个连续请求或回应的场景时，
		 * 保持捕获数据的序列号保持不变。
		 */
		if (conn_info->keep_data_seq)
			sk_info.seq = socket_info_ptr->seq;
		else
			sk_info.seq = ++socket_info_ptr->seq;

		socket_info_ptr->direction = conn_info->direction;
		socket_info_ptr->msg_type = conn_info->message_type;
		socket_info_ptr->update_time = time_stamp / NS_PER_SEC;
		if (socket_info_ptr->peer_fd != 0 && conn_info->direction == T_INGRESS) {
			__u64 peer_conn_key = gen_conn_key_id((__u64)tgid,
							      (__u64)socket_info_ptr->peer_fd);
			struct socket_info_t *peer_socket_info_ptr =
							socket_info_map__lookup(&peer_conn_key);
			if (is_socket_info_valid(peer_socket_info_ptr))
				peer_socket_info_ptr->trace_id = thread_trace_id;
		}

		if (conn_info->direction == T_EGRESS && socket_info_ptr->trace_id != 0) {
			thread_trace_id = socket_info_ptr->trace_id;
			socket_info_ptr->trace_id = 0;
		}
	}

	struct __socket_data_buffer *v_buff = bpf_map_lookup_elem(&NAME(data_buf), &k0);
	if (!v_buff)
		return -1;

	struct __socket_data *v = (struct __socket_data *)&v_buff->data[0];

	if (v_buff->len > (sizeof(v_buff->data) - sizeof(*v)))
		return -1;

	v = (struct __socket_data *)(v_buff->data + v_buff->len);
	if (get_socket_info(v, conn_info->sk, conn_info) == false)
		return -1;

	v->tuple.l4_protocol = conn_info->tuple.l4_protocol;
	v->tuple.dport = conn_info->tuple.dport;
	v->tuple.num = conn_info->tuple.num;
	v->data_type = conn_info->protocol;

	if (conn_info->protocol == PROTO_HTTP1 &&
	    (extra->source == DATA_SOURCE_GO_TLS_UPROBE ||
	     extra->source == DATA_SOURCE_OPENSSL_UPROBE))
		v->data_type = PROTO_TLS_HTTP1;

	if (conn_info->protocol == PROTO_HTTP2 &&
	    (extra->source == DATA_SOURCE_OPENSSL_UPROBE))
		v->data_type = PROTO_TLS_HTTP2;

	v->socket_id = sk_info.uid;
	v->data_seq = sk_info.seq;
	v->tgid = tgid;
	v->pid = (__u32) pid_tgid;
	v->timestamp = time_stamp;
	v->direction = conn_info->direction;
	v->syscall_len = syscall_len;
	v->msg_type = conn_info->message_type;
	v->tcp_seq = 0;

	if ((extra->source == DATA_SOURCE_GO_TLS_UPROBE ||
	     extra->source == DATA_SOURCE_OPENSSL_UPROBE) ||
	    (conn_info->direction == T_INGRESS &&
	     conn_info->tuple.l4_protocol == IPPROTO_TCP)) {
		/*
		 * If the current state is TCPF_CLOSE_WAIT, the FIN frame already has been received.
		 * However, it cannot be confirmed that it has been processed by the syscall,
		 * so use the tcp_seq value that entering the syscalls.
		 *
		 * Why not use "v->tcp_seq = args->tcp_seq;" ?
		 * This is because kernel 4.14 verify reports errors("R0 invalid mem access 'inv'").
		 */
		v->tcp_seq = tcp_seq;
	} else if (conn_info->direction == T_EGRESS &&
		   conn_info->tuple.l4_protocol == IPPROTO_TCP) {
		v->tcp_seq = get_tcp_write_seq_from_fd(conn_info->fd) - syscall_len;
	}

	v->thread_trace_id = thread_trace_id;
	bpf_get_current_comm(v->comm, sizeof(v->comm));

	if (conn_info->tuple.l4_protocol == IPPROTO_TCP &&
	    conn_info->protocol == PROTO_DNS && conn_info->prev_count == 2) {
		v->tcp_seq -= 2;
		conn_info->prev_count = 0;
	}

	if (conn_info->prev_count > 0) {
		// 注意这里没有调整v->syscall_len和v->len我们会在用户层做。
		v->extra_data = *(__u32 *)conn_info->prev_buf;
		v->extra_data_count = conn_info->prev_count;
		v->tcp_seq -= conn_info->prev_count; // 客户端和服务端的tcp_seq匹配
	} else
		v->extra_data_count = 0;

	v->coroutine_id = trace_key.goid;
	v->source = extra->source;

#ifdef LINUX_VER_5_2_PLUS
	__u32 cache_key = (__u32) pid_tgid >> 16;
	if (cache_key < PROTO_INFER_CACHE_SIZE) {
		struct proto_infer_cache_t *p;
		p = proto_infer_cache_map__lookup(&cache_key);
		if (p) {
			__u16 idx = (__u16) pid_tgid;
			p->protocols[idx] = (__u8) v->data_type;
		}
	}
#endif

	struct tail_calls_context *context = (struct tail_calls_context *)v->data;
	context->max_size_limit = data_max_sz;
	context->vecs = (bool) vecs;
	context->dir = conn_info->direction;

	return 0;
}

static __inline int process_data(struct pt_regs *ctx, __u64 id,
				 const enum traffic_direction direction,
				 const struct data_args_t *args,
				 ssize_t bytes_count,
				 const struct process_data_extra *extra)
{
	if (!extra)
		return -1;

	if (!extra->vecs && args->buf == NULL)
		return -1;

	if (extra->vecs && (args->iov == NULL || args->iovlen <= 0))
		return -1;

	if (unlikely(args->fd < 0 || (int)bytes_count <= 0))
		return -1;

	// TODO : 此处可以根据配置对进程号进行过滤

	__u32 k0 = 0;
	struct member_fields_offset *offset = members_offset__lookup(&k0);
	if (!offset)
		return -1;

	if (unlikely(!offset->ready))
		return -1;
	
	void *sk = get_socket_from_fd(args->fd, offset);
	struct conn_info_t *conn_info, __conn_info = { 0 };
	conn_info = &__conn_info;
	__u8 sock_state;
	if (!(sk != NULL &&
	      ((sock_state = is_tcp_udp_data(sk, offset, conn_info))
	       != SOCK_CHECK_TYPE_ERROR))) {
		return -1;
	}

	init_conn_info(id >> 32, args->fd, &__conn_info, sk);

	conn_info->direction = direction;

	bool data_submit_dircet = false;
	struct allow_port_bitmap *bp = allow_port_bitmap__lookup(&k0);
	if (bp) {
		if (is_set_bitmap(bp->bitmap, conn_info->tuple.dport) ||
		    is_set_bitmap(bp->bitmap, conn_info->tuple.num)) {
			data_submit_dircet = true;
		}
	}
	if (data_submit_dircet) {
		conn_info->protocol = PROTO_ORTHER;
		conn_info->message_type = MSG_REQUEST;
	} else {
		infer_l7_class(conn_info, direction, args, bytes_count, sock_state, extra);
	}

	// When at least one of protocol or message_type is valid, 
	// data_submit can be performed, otherwise MySQL data may be lost
	if (conn_info->protocol != PROTO_UNKNOWN ||
	    conn_info->message_type != MSG_UNKNOWN) {
		return data_submit(ctx, conn_info, args, extra->vecs,
				   (__u32)bytes_count, offset, args->enter_ts, extra);
	}

	return -1;
}

static __inline void process_syscall_data(struct pt_regs* ctx, __u64 id,
					  const enum traffic_direction direction,
					  const struct data_args_t* args, ssize_t bytes_count) {
	struct process_data_extra extra = {
		.vecs = false,
		.source = DATA_SOURCE_SYSCALL,
	};

	if (!process_data(ctx, id, direction, args, bytes_count, &extra)) {
		bpf_tail_call(ctx, &NAME(progs_jmp_tp_map), 0);
	} else {
		bpf_tail_call(ctx, &NAME(progs_jmp_tp_map), 1);
	}
}

static __inline void process_syscall_data_vecs(struct pt_regs* ctx, __u64 id,
					       const enum traffic_direction direction,
					       const struct data_args_t* args,
					       ssize_t bytes_count) {
	struct process_data_extra extra = {
		.vecs = true,
		.source = DATA_SOURCE_SYSCALL,
	};

	if (!process_data(ctx, id, direction, args, bytes_count, &extra)) {
		bpf_tail_call(ctx, &NAME(progs_jmp_tp_map), 0);
	} else {
		bpf_tail_call(ctx, &NAME(progs_jmp_tp_map), 1);
	}
}

/***********************************************************
 * BPF syscall probe/tracepoint function entry-points
 ***********************************************************/
TPPROG(sys_enter_write) (struct syscall_comm_enter_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	int fd = (int)ctx->fd;
	char *buf = (char *)ctx->buf;

	struct data_args_t write_args = {};
	write_args.source_fn = SYSCALL_FUNC_WRITE;
	write_args.fd = fd;
	write_args.buf = buf;
	write_args.enter_ts = bpf_ktime_get_ns();
	active_write_args_map__update(&id, &write_args);

	return 0;
}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_write/format
TPPROG(sys_exit_write) (struct syscall_comm_exit_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	ssize_t bytes_count = ctx->ret;
	// Unstash arguments, and process syscall.
	struct data_args_t* write_args = active_write_args_map__lookup(&id);
	// Don't process FD 0-2 to avoid STDIN, STDOUT, STDERR.
	if (write_args != NULL && write_args->fd > 2) {
		write_args->bytes_count = bytes_count;
		process_syscall_data((struct pt_regs *)ctx, id, T_EGRESS, write_args, bytes_count);
	}

	active_write_args_map__delete(&id);
	return 0;
}

// ssize_t read(int fd, void *buf, size_t count);
TPPROG(sys_enter_read) (struct syscall_comm_enter_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	int fd = (int)ctx->fd;
	char *buf = (char *)ctx->buf;
	// Stash arguments.
	struct data_args_t read_args = {};
	read_args.source_fn = SYSCALL_FUNC_READ;
	read_args.fd = fd;
	read_args.buf = buf;
	read_args.enter_ts = bpf_ktime_get_ns();
	read_args.tcp_seq = get_tcp_read_seq_from_fd(fd);
	active_read_args_map__update(&id, &read_args);

	return 0;
}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_read/format
TPPROG(sys_exit_read) (struct syscall_comm_exit_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	ssize_t bytes_count = ctx->ret;
	// Unstash arguments, and process syscall.
	struct data_args_t* read_args = active_read_args_map__lookup(&id);
	// Don't process FD 0-2 to avoid STDIN, STDOUT, STDERR.
	if (read_args != NULL && read_args->fd > 2) {
		read_args->bytes_count = bytes_count;
		process_syscall_data((struct pt_regs *)ctx, id, T_INGRESS, read_args, bytes_count);
	}

	active_read_args_map__delete(&id);
	return 0;
}

// ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
//		const struct sockaddr *dest_addr, socklen_t addrlen);
TPPROG(sys_enter_sendto) (struct syscall_comm_enter_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	int sockfd = (int)ctx->fd;
	char *buf = (char *)ctx->buf;
	// Stash arguments.
	struct data_args_t write_args = {};
	write_args.source_fn = SYSCALL_FUNC_SENDTO;
	write_args.fd = sockfd;
	write_args.buf = buf;
	write_args.enter_ts = bpf_ktime_get_ns();
	active_write_args_map__update(&id, &write_args);

	return 0;
}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_sendto/format
TPPROG(sys_exit_sendto) (struct syscall_comm_exit_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	ssize_t bytes_count = ctx->ret;

	// 潜在的问题:如果sentto() addr是由TCP连接提供的，系统调用可能会忽略它，但我们仍然会跟踪它。在实践中，TCP连接不应该使用带addr参数的sendto()。
	// 在手册页中:
	//     如果sendto()用于连接模式(SOCK_STREAM, SOCK_SEQPACKET)套接字，参数
	//     dest_addr和addrlen会被忽略(如果不是，可能会返回EISCONN错误空和0)
	//
	// Unstash arguments, and process syscall.
	struct data_args_t* write_args = active_write_args_map__lookup(&id);
	if (write_args != NULL) {
		write_args->bytes_count = bytes_count;
		process_syscall_data((struct pt_regs*)ctx, id, T_EGRESS, write_args, bytes_count);
		active_write_args_map__delete(&id);
	}

	return 0;
}

// ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
//		  struct sockaddr *src_addr, socklen_t *addrlen);
TPPROG(sys_enter_recvfrom) (struct syscall_comm_enter_ctx *ctx) {
	// If flags contains MSG_PEEK, it is returned directly.
	// ref : https://linux.die.net/man/2/recvfrom
	if (ctx->flags & MSG_PEEK)
		return 0;
	__u64 id = bpf_get_current_pid_tgid();
	int sockfd = (int)ctx->fd;
	char *buf = (char *)ctx->buf;
	// Stash arguments.
	struct data_args_t read_args = {};
	read_args.source_fn = SYSCALL_FUNC_RECVFROM;
	read_args.fd = sockfd;
	read_args.buf = buf;
	read_args.enter_ts = bpf_ktime_get_ns();
	read_args.tcp_seq = get_tcp_read_seq_from_fd(sockfd);
	active_read_args_map__update(&id, &read_args);

	return 0;
}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_recvfrom/format
TPPROG(sys_exit_recvfrom) (struct syscall_comm_exit_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	ssize_t bytes_count = ctx->ret;

	// Unstash arguments, and process syscall.
	struct data_args_t* read_args = active_read_args_map__lookup(&id);
	if (read_args != NULL) {
		read_args->bytes_count = bytes_count;
		process_syscall_data((struct pt_regs *)ctx, id, T_INGRESS, read_args, bytes_count);
		active_read_args_map__delete(&id);
	}

	return 0;
}

// ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
KPROG(__sys_sendmsg) (struct pt_regs* ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	int sockfd = (int)PT_REGS_PARM1(ctx);
	struct user_msghdr *msghdr_ptr = (struct user_msghdr *)PT_REGS_PARM2(ctx);

	if (msghdr_ptr != NULL) {
		// Stash arguments.
		struct user_msghdr *msghdr, __msghdr;
		bpf_probe_read(&__msghdr, sizeof(__msghdr), msghdr_ptr);
		msghdr = &__msghdr;
		// Stash arguments.
		struct data_args_t write_args = {};
		write_args.source_fn = SYSCALL_FUNC_SENDMSG;
		write_args.fd = sockfd;
		write_args.iov = msghdr->msg_iov;
		write_args.iovlen = msghdr->msg_iovlen;
		write_args.enter_ts = bpf_ktime_get_ns();
		active_write_args_map__update(&id, &write_args);
	}

	return 0;
}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_sendmsg/format
TPPROG(sys_exit_sendmsg) (struct syscall_comm_exit_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	ssize_t bytes_count = ctx->ret;
	// Unstash arguments, and process syscall.
	struct data_args_t* write_args = active_write_args_map__lookup(&id);
	if (write_args != NULL) {
		write_args->bytes_count = bytes_count;
		process_syscall_data_vecs((struct pt_regs *)ctx, id, T_EGRESS, write_args, bytes_count);
		active_write_args_map__delete(&id);
	}

	return 0;
}

// int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
//              int flags);
KPROG(__sys_sendmmsg)(struct pt_regs* ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	int sockfd = (int)PT_REGS_PARM1(ctx);
	struct mmsghdr *msgvec_ptr = (struct mmsghdr *)PT_REGS_PARM2(ctx);
	unsigned int vlen = (unsigned int)PT_REGS_PARM3(ctx);

	if (msgvec_ptr != NULL && vlen >= 1) {
		struct mmsghdr *msgvec, __msgvec;
		bpf_probe_read(&__msgvec, sizeof(__msgvec), msgvec_ptr);
		msgvec = &__msgvec;
		// Stash arguments.
		struct data_args_t write_args = {};
		write_args.source_fn = SYSCALL_FUNC_SENDMMSG;
		write_args.fd = sockfd;
		write_args.iov = msgvec[0].msg_hdr.msg_iov;
		write_args.iovlen = msgvec[0].msg_hdr.msg_iovlen;
		write_args.msg_len = (void *)msgvec_ptr + offsetof(typeof(struct mmsghdr), msg_len); //&msgvec[0].msg_len;
		write_args.enter_ts = bpf_ktime_get_ns();
		active_write_args_map__update(&id, &write_args);
	}

	return 0;
}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_sendmmsg/format
TPPROG(sys_exit_sendmmsg) (struct syscall_comm_exit_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();

	int num_msgs = ctx->ret;

	// Unstash arguments, and process syscall.
	struct data_args_t* write_args = active_write_args_map__lookup(&id);
	if (write_args != NULL && num_msgs > 0) {
		ssize_t bytes_count;
		bpf_probe_read(&bytes_count, sizeof(write_args->msg_len), write_args->msg_len);
		process_syscall_data_vecs((struct pt_regs *)ctx, id, T_EGRESS, write_args, bytes_count);
	}
	active_write_args_map__delete(&id);

	return 0;
}

// BSD recvmsg interface
// long __sys_recvmsg(int fd, struct user_msghdr __user *msg, unsigned int flags,
//		   bool forbid_cmsg_compat)
// ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
KPROG(__sys_recvmsg) (struct pt_regs* ctx) {
	int flags = (int) PT_REGS_PARM3(ctx);
	if (flags & MSG_PEEK)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	struct user_msghdr __msg, *msghdr = (struct user_msghdr *)PT_REGS_PARM2(ctx);
	int sockfd = (int) PT_REGS_PARM1(ctx);

	if (msghdr != NULL) {
		bpf_probe_read(&__msg, sizeof(__msg), (void *)msghdr);
		msghdr = &__msg;
		// Stash arguments.
		struct data_args_t read_args = {};
		read_args.source_fn = SYSCALL_FUNC_RECVMSG;
		read_args.fd = sockfd;
		read_args.iov = msghdr->msg_iov;
		read_args.iovlen = msghdr->msg_iovlen;
		read_args.enter_ts = bpf_ktime_get_ns();
		read_args.tcp_seq = get_tcp_read_seq_from_fd(sockfd);
		active_read_args_map__update(&id, &read_args);
	}

	return 0;
}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_recvmsg/format
TPPROG(sys_exit_recvmsg) (struct syscall_comm_exit_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	ssize_t bytes_count = ctx->ret;
	// Unstash arguments, and process syscall.
	struct data_args_t* read_args = active_read_args_map__lookup(&id);
	if (read_args != NULL) {
		read_args->bytes_count = bytes_count;
		process_syscall_data_vecs((struct pt_regs *)ctx, id, T_INGRESS, read_args, bytes_count);
		active_read_args_map__delete(&id);
	}

	return 0;
}

// int __sys_recvmmsg(int fd, struct mmsghdr __user *mmsg, unsigned int vlen,
//		   unsigned int flags, struct timespec *timeout)
KPROG(__sys_recvmmsg) (struct pt_regs* ctx) {
	int flags = (int) PT_REGS_PARM4(ctx);
	if (flags & MSG_PEEK)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	int sockfd = (int)PT_REGS_PARM1(ctx);
	struct mmsghdr *msgvec = (struct mmsghdr *)PT_REGS_PARM2(ctx);
	unsigned int vlen = (unsigned int)PT_REGS_PARM3(ctx);
	
	if (msgvec != NULL && vlen >= 1) {
		int offset;
		// Stash arguments.
		struct data_args_t read_args = {};
		read_args.source_fn = SYSCALL_FUNC_RECVMMSG;
		read_args.fd = sockfd;
		read_args.enter_ts = bpf_ktime_get_ns();

		offset = offsetof(typeof(struct mmsghdr), msg_hdr) +
				offsetof(typeof(struct user_msghdr), msg_iov);

		bpf_probe_read(&read_args.iov, sizeof(read_args.iov), (void *)msgvec + offset);

		offset = offsetof(typeof(struct mmsghdr), msg_hdr) +
				offsetof(typeof(struct user_msghdr), msg_iovlen);

		bpf_probe_read(&read_args.iovlen, sizeof(read_args.iovlen), (void *)msgvec + offset);

		read_args.msg_len = (void *)msgvec + offsetof(typeof(struct mmsghdr), msg_len);
		read_args.tcp_seq = get_tcp_read_seq_from_fd(sockfd);
		active_read_args_map__update(&id, &read_args);
	}
	
	return 0;
}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_recvmmsg/format
TPPROG(sys_exit_recvmmsg) (struct syscall_comm_exit_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	int num_msgs = ctx->ret;
	// Unstash arguments, and process syscall.
	struct data_args_t* read_args = active_read_args_map__lookup(&id);
	if (read_args != NULL && num_msgs > 0) {
		ssize_t bytes_count;
		bpf_probe_read(&bytes_count, sizeof(read_args->msg_len), read_args->msg_len);
		process_syscall_data_vecs((struct pt_regs *)ctx, id, T_INGRESS, read_args, bytes_count);
	}
	active_read_args_map__delete(&id);

	return 0;
}

//static ssize_t do_writev(unsigned long fd, const struct iovec __user *vec,
//			 unsigned long vlen, rwf_t flags)
// ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
KPROG(do_writev) (struct pt_regs* ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	int fd = (int)PT_REGS_PARM1(ctx);
	struct iovec *iov = (struct iovec *)PT_REGS_PARM2(ctx);
	int iovlen = (int)PT_REGS_PARM3(ctx);

	// Stash arguments.
	struct data_args_t write_args = {};
	write_args.source_fn = SYSCALL_FUNC_WRITEV;
	write_args.fd = fd;
	write_args.iov = iov;
	write_args.iovlen = iovlen;
	write_args.enter_ts = bpf_ktime_get_ns();
	active_write_args_map__update(&id, &write_args);
	return 0;
}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_writev/format
TPPROG(sys_exit_writev) (struct syscall_comm_exit_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	ssize_t bytes_count = ctx->ret;

	// Unstash arguments, and process syscall.
	struct data_args_t* write_args = active_write_args_map__lookup(&id);
	if (write_args != NULL) {
		write_args->bytes_count = bytes_count;
		process_syscall_data_vecs((struct pt_regs *)ctx, id, T_EGRESS, write_args, bytes_count);
	}

	active_write_args_map__delete(&id);
	return 0;
}

// ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
KPROG(do_readv) (struct pt_regs* ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	int fd = (int)PT_REGS_PARM1(ctx);
	struct iovec *iov = (struct iovec *)PT_REGS_PARM2(ctx);
	int iovlen = (int)PT_REGS_PARM3(ctx);

	// Stash arguments.
	struct data_args_t read_args = {};
	read_args.source_fn = SYSCALL_FUNC_READV;
	read_args.fd = fd;
	read_args.iov = iov;
	read_args.iovlen = iovlen;
	read_args.enter_ts = bpf_ktime_get_ns();
	read_args.tcp_seq = get_tcp_read_seq_from_fd(fd);
	active_read_args_map__update(&id, &read_args);

	return 0;
}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_readv/format
TPPROG(sys_exit_readv) (struct syscall_comm_exit_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	ssize_t bytes_count = ctx->ret;
	struct data_args_t* read_args = active_read_args_map__lookup(&id);
	if (read_args != NULL) {
		read_args->bytes_count = bytes_count;
		process_syscall_data_vecs((struct pt_regs *)ctx, id, T_INGRESS, read_args, bytes_count);
	}

	active_read_args_map__delete(&id);
	return 0;
}

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_close/format
// 为什么不用tcp_fin? 主要原因要考虑UDP场景。
TPPROG(sys_enter_close) (struct syscall_comm_enter_ctx *ctx) {
	int fd = ctx->fd;
	//Ignore stdin, stdout and stderr
	if (fd <= 2)
		return 0;

	__u32 k0 = 0;
	struct member_fields_offset *offset = members_offset__lookup(&k0);
	if (!offset)
		return 0;

	CHECK_OFFSET_READY(fd);

	__u64 sock_addr = (__u64)get_socket_from_fd(fd, offset);
	if (sock_addr) {
		__u64 conn_key = gen_conn_key_id(bpf_get_current_pid_tgid() >> 32, (__u64)fd);
		struct socket_info_t *socket_info_ptr = socket_info_map__lookup(&conn_key);
		if (socket_info_ptr != NULL)
			delete_socket_info(conn_key, socket_info_ptr);
	}

	return 0;
}

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_getppid
// 此处tracepoint用于周期性的将驻留在缓存中还未发送的数据发给用户态接收程序处理。
TPPROG(sys_enter_getppid) (struct syscall_comm_enter_ctx *ctx) {
	int k0 = 0;
	struct __socket_data_buffer *v_buff = bpf_map_lookup_elem(&NAME(data_buf), &k0);
	if (v_buff) {
		if (v_buff->events_num > 0) {
			struct __socket_data *v = (struct __socket_data *)&v_buff->data[0];
			if ((bpf_ktime_get_ns() - v->timestamp * NS_PER_US) > NS_PER_SEC) {
				__u32 buf_size = (v_buff->len +
						  offsetof(typeof(struct __socket_data_buffer), data))
						 & (sizeof(*v_buff) - 1);
				if (buf_size >= sizeof(*v_buff))
					bpf_perf_event_output(ctx, &NAME(socket_data),
							      BPF_F_CURRENT_CPU, v_buff,
							      sizeof(*v_buff));
				else
					/* 使用'buf_size + 1'代替'buf_size'，来规避（Linux 4.14.x）长度检查 */
					bpf_perf_event_output(ctx, &NAME(socket_data),
							      BPF_F_CURRENT_CPU, v_buff,
							      buf_size + 1);

				v_buff->events_num = 0;
				v_buff->len = 0;				
			}
		}
	}

	return 0;
}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_socket/format
TPPROG(sys_exit_socket) (struct syscall_comm_exit_ctx *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	__u64 fd = (__u64)ctx->ret;
	char comm[TASK_COMM_LEN];
	bpf_get_current_comm(comm, sizeof(comm));

	// 试用于nginx负载均衡场景
	if (!(comm[0] == 'n' && comm[1] == 'g' && comm[2] == 'i' &&
	      comm[3] == 'n' && comm[4] == 'x' && comm[5] == '\0'))
		return 0;

	// nginx is not a go process, disable go tracking
	struct trace_key_t key = get_trace_key(0);
	struct trace_info_t *trace = trace_map__lookup(&key);
	if (trace && trace->peer_fd != 0 && trace->peer_fd != (__u32)fd) {
		struct socket_info_t sk_info = { 0 };
		sk_info.peer_fd = trace->peer_fd;
		sk_info.trace_id = trace->thread_trace_id;	
		__u64 conn_key = gen_conn_key_id(id >> 32, fd);
		socket_info_map__update(&conn_key, &sk_info);
		__u32 k0 = 0;
		struct trace_stats *trace_stats = trace_stats_map__lookup(&k0);
		if (trace_stats == NULL)
			return 0;
		trace_stats->socket_map_count++;
	}

	return 0;
}

// Store IO event information
MAP_PERARRAY(io_event_buffer, __u32, struct __io_event_buffer, 1)

/*
 * This eBPF program is specially used to transmit data to the agent. The purpose
 * of this is to solve the problem that the number of instructions exceeds the limit.
 */
static __inline int output_data_common(void *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	enum traffic_direction dir;
	bool vecs = false;
	int max_size = 0;
	__u32 k0 = 0;
	char *buffer = NULL;

	struct __socket_data_buffer *v_buff = bpf_map_lookup_elem(&NAME(data_buf), &k0);
	if (!v_buff)
		goto clear_args_map_2;

	struct tail_calls_context *context =
	    (struct tail_calls_context *)(v_buff->data + v_buff->len +
					  offsetof(typeof(struct __socket_data),
						   data));

	if ((v_buff->len + offsetof(typeof(struct __socket_data), data) +
	     sizeof(struct tail_calls_context)) > sizeof(v_buff->data)) {
		goto clear_args_map_2;
	}

	dir = context->dir;
	vecs = context->vecs;
	max_size = context->max_size_limit;

	struct data_args_t *args;
	if (dir == T_INGRESS)
		args = active_read_args_map__lookup(&id);
	else
		args = active_write_args_map__lookup(&id);

	if (args == NULL)
		goto clear_args_map_1;

	struct __socket_data *v =
	    (struct __socket_data *)(v_buff->data + v_buff->len);
	if (v_buff->len > (sizeof(v_buff->data) - sizeof(*v)))
		goto clear_args_map_1;

	if (v->source == DATA_SOURCE_IO_EVENT) {
		buffer = (char *)io_event_buffer__lookup(&k0);
		if (buffer == NULL) {
			goto clear_args_map_1;
		}
	} else {
		buffer = (char *)args->buf;
	}

	__u32 __len = v->syscall_len > max_size ? max_size : v->syscall_len;

	/*
	 * the bitwise AND operation will set the range of possible values for
	 * the UNKNOWN_VALUE register to [0, BUFSIZE)
	 */
	__u32 len = __len & (sizeof(v->data) - 1);

	if (vecs) {
		len = iovecs_copy(v, v_buff, args, v->syscall_len, len);
	} else {
		if (__len >= sizeof(v->data)) {
			if (unlikely(bpf_probe_read(v->data, sizeof(v->data), buffer) != 0))
				goto clear_args_map_1;
			len = sizeof(v->data);
		} else {
			/*
			 * https://elixir.bootlin.com/linux/v4.14/source/kernel/bpf/verifier.c#812
			 * __check_map_access() 触发条件检查（size <= 0）
			 * ```
			 *     if (off < 0 || size <= 0 || off + size > map->value_size)
			 * ```
			 * "invalid access to map value, value_size=10888 off=135 size=0"
			 * 使用'len + 1'代替'len'，来规避（Linux 4.14.x）这个检查。
			 */
			if (unlikely(bpf_probe_read(v->data,
						    len + 1,
						    buffer) != 0))
				goto clear_args_map_1;
		}
	}

	v->data_len = len;
	v_buff->len += offsetof(typeof(struct __socket_data), data) + v->data_len;
	v_buff->events_num++;

	if (v_buff->events_num >= EVENT_BURST_NUM ||
	    ((sizeof(v_buff->data) - v_buff->len) < sizeof(*v))) {
		__u32 buf_size = (v_buff->len + offsetof(typeof(struct __socket_data_buffer), data))
				 & (sizeof(*v_buff) - 1);
		if (buf_size >= sizeof(*v_buff))
			bpf_perf_event_output(ctx, &NAME(socket_data),
					      BPF_F_CURRENT_CPU, v_buff,
					      sizeof(*v_buff));
		else
			/* 使用'buf_size + 1'代替'buf_size'，来规避（Linux 4.14.x）长度检查 */
			bpf_perf_event_output(ctx, &NAME(socket_data),
					      BPF_F_CURRENT_CPU, v_buff,
					      buf_size + 1);

		v_buff->events_num = 0;
		v_buff->len = 0;
	}

clear_args_map_1:
	if (dir == T_INGRESS)
		active_read_args_map__delete(&id);
	else
		active_write_args_map__delete(&id);

	return 0;

clear_args_map_2:
	active_read_args_map__delete(&id);
	active_write_args_map__delete(&id);
	return 0;
}

PROGTP(output_data) (void *ctx)
{
	return output_data_common(ctx);
}

PROGKP(output_data) (void *ctx)
{
	return output_data_common(ctx);
}

static __inline bool is_regular_file(int fd)
{
	__u32 k0 = 0;
	struct member_fields_offset *offset = members_offset__lookup(&k0);
	void *file = fd_to_file(fd, offset);
	__u32 i_mode = file_to_i_mode(file);
	return S_ISREG(i_mode);
}

static __inline char *fd_to_name(int fd)
{
	__u32 k0 = 0;
	struct member_fields_offset *offset = members_offset__lookup(&k0);
	void *file = fd_to_file(fd, offset);
	return file_to_name(file);
}

static __inline void trace_io_event_common(void *ctx,
					   struct data_args_t *data_args,
					   enum traffic_direction direction,
					   __u64 pid_tgid)
{
	__u64 latency = 0;
	__u64 trace_id = 0;
	__u32 k0 = 0;
	__u32 tgid = pid_tgid >> 32;

	if (data_args->bytes_count == 0) {
		return;
	}

	struct trace_conf_t *trace_conf = trace_conf_map__lookup(&k0);
	if (trace_conf == NULL) {
		return;
	}

	if (trace_conf->io_event_collect_mode == 0) {
		return;
	}

	__u32 timeout = trace_conf->go_tracing_timeout;
	struct trace_key_t trace_key = get_trace_key(timeout);
	struct trace_info_t *trace_info_ptr = trace_map__lookup(&trace_key);
	if (trace_info_ptr) {
		trace_id = trace_info_ptr->thread_trace_id;
	}

	if (trace_id == 0 && trace_conf->io_event_collect_mode == 1) {
		return;
	}

	int data_max_sz = trace_conf->data_limit_max;

	if (!is_regular_file(data_args->fd)) {
		return;
	}

	latency = bpf_ktime_get_ns() - data_args->enter_ts;
	if (latency < trace_conf->io_event_minimal_duration) {
		return;
	}

	char *name = fd_to_name(data_args->fd);

	struct __io_event_buffer *buffer = io_event_buffer__lookup(&k0);
	if (!buffer) {
		return;
	}

	buffer->bytes_count = data_args->bytes_count;
	buffer->latency = latency;
	buffer->operation = direction;
	bpf_probe_read_str(buffer->filename, sizeof(buffer->filename), name);
	buffer->filename[sizeof(buffer->filename) - 1] = '\0';

	struct __socket_data_buffer *v_buff =
		bpf_map_lookup_elem(&NAME(data_buf), &k0);
	if (!v_buff)
		return;

	struct __socket_data *v = (struct __socket_data *)&v_buff->data[0];

	if (v_buff->len > (sizeof(v_buff->data) - sizeof(*v)))
		return;

	v = (struct __socket_data *)(v_buff->data + v_buff->len);
	__builtin_memset(v, 0, offsetof(typeof(struct __socket_data), data));
	v->tgid = tgid;
	v->pid = (__u32)pid_tgid;
	v->coroutine_id = trace_key.goid;
	v->timestamp = data_args->enter_ts;

	v->syscall_len = sizeof(*buffer);

	v->source = DATA_SOURCE_IO_EVENT;

	v->thread_trace_id = trace_id;
	bpf_get_current_comm(v->comm, sizeof(v->comm));

	struct tail_calls_context *context =
		(struct tail_calls_context *)v->data;
	context->max_size_limit = data_max_sz;
	context->vecs = false;
	context->dir = direction;

	bpf_tail_call(ctx, &NAME(progs_jmp_tp_map), 0);
	return;
}

PROGTP(io_event)(void *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();

	struct data_args_t *data_args = NULL;

	data_args = active_read_args_map__lookup(&id);
	if (data_args) {
		trace_io_event_common(ctx, data_args, T_INGRESS, id);
		active_read_args_map__delete(&id);
		return 0;
	}

	data_args = active_write_args_map__lookup(&id);
	if (data_args) {
		trace_io_event_common(ctx, data_args, T_EGRESS, id);
		active_write_args_map__delete(&id);
		return 0;
	}

	return 0;
}

//Refer to the eBPF programs here
#include "go_tls_bpf.c"
#include "go_http2_bpf.c"
#include "openssl_bpf.c"
