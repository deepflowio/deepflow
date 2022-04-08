#ifndef __BPF_SOCKET_TRACE_COMMON_H__
#define __BPF_SOCKET_TRACE_COMMON_H__

enum endpoint_role {
	ROLE_CLIENT,
	ROLE_SERVER,
	ROLE_UNKNOW
};

struct __tuple_t {
	__u8 daddr[16];
	__u8 rcv_saddr[16];
	__u8 addr_len;
	__u8 l4_protocol;
	__u16 dport;
	__u16 num;
};

// size : 512 + 107
struct __socket_data {
	/* 进程/线程信息 */
	__u32 pid;  // 表示线程号 如果'pid == tgid'表示一个进程, 否则是线程
	__u32 tgid; // 进程号
	__u8  comm[16]; // 进程名

	/* 连接（socket）信息 */
	__u64 socket_id;     /* 通信socket唯一ID， 从启动时的时钟开始自增1 */
	struct __tuple_t tuple;

	/*
	 * 携带数据， 比如：MySQL第一次读取的数据，被第二次读取的数据携带一并发给用户
	 * 注意携带数据只有4字节大小。
	 */
	__u32 extra_data;
	__u32 extra_data_count;

	/* 追踪信息 */
	__u32 tcp_seq;
	__u64 coroutine_trace_id;
	__u64 thread_trace_id;

	/* 追踪数据信息 */
	__u64 timestamp;     // 数据捕获时间戳
	__u8  direction;     // 数据的收发方向
	__u64 syscall_len;   // 本次系统调用读、写数据的总长度
	__u64 data_seq;      // cap_data在Socket中的相对顺序号
	__u16 data_type;     // HTTP, DNS, MySQL
	__u16 data_len;      // 数据长度
	char data[512];
} __attribute__((packed));

/*
 * 整个结构大小为2^14（2的次幂），目的是用（2^n - 1）与数据
 * 长度作位与操作使eBPF程序进行安全的bpf_perf_event_output()操作。
 */
struct __socket_data_buffer {
	__u32 events_num;
	__u32 len; // data部分长度
	char data[16376]; // 16376 + len(4bytes) + events_num(4bytes) = 2^14 = 16384
};

struct trace_uid_t {
	__u64 socket_id;       // 会话标识
	__u64 coroutine_trace_id;  // 同一进程/线程的数据转发关联，用于代理，负载均衡
	__u64 thread_trace_id; // 同一进程/线程的数据转发关联，用于多事务流转场景
};

struct trace_stats {
	__u64 socket_map_count;     // 对socket 链接表进行统计
	__u64 trace_map_count;     // 对同一进程/线程的多次转发表进行统计
};

struct socket_info_t {
	__u64 l7_proto: 8;
	__u64 seq: 56; // socket 读写数据的序列号，用于排序

	/*
	 * mysql, kafka这种类型在读取数据时，先读取4字节
	 * 然后再读取剩下的数据，这里用于对预先读取的数据存储
	 * 用于后续的协议分析。
	 */
	__u8 prev_data[4];
	__u8 direction: 1;
	__u8 role: 7;           // 标识socket角色：ROLE_CLIENT, ROLE_SERVER, ROLE_UNKNOW
	bool need_reconfirm;    // l7协议推断是否需要再次确认。
	__s32 correlation_id;   // 目前用于kafka协议推断。

	/*
	 * 一旦有数据读/写就会更新这个时间，这个时间是从系统开机开始
	 * 到更新时的间隔时间单位是秒。
	 */
	__u32 update_time;
	__u32 prev_data_len;

	__u64 uid;
	__u64 trace_map_key; // related trace_map hash key
} __attribute__((packed));

struct trace_info_t {
	__u64 conn_key;
	__u64 coroutine_trace_id;
	__u64 thread_trace_id;
};
#endif /* BPF_SOCKET_TRACE_COMMON */
