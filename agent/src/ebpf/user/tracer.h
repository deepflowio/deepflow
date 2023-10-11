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

#ifndef DF_USER_TRACER_H
#define DF_USER_TRACER_H
#include <stdio.h>
#include <stdbool.h>
#include <linux/limits.h>	/* ulimit */
#include <sys/resource.h>	/* RLIM_INFINITY */
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <linux/types.h>
#include <sys/types.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <string.h>
#include "ring.h"
#include "ctrl.h"
#include "atomic.h"
#include <bcc/libbpf.h>
#include "../kernel/include/common.h"
#include "xxhash.h"
#include "../kernel/include/socket_trace_common.h"
#include <bcc/libbpf.h>
#include "symbol.h"
#include <regex.h>

// TODO: 对内存拷贝进行硬件优化。

#define LOOP_DELAY_US  100000

#define memcpy_fast(a,b,c) memcpy(a,b,c)

#define IS_NULL(p) ((p) == NULL)

#define RING_SIZE 16384
#define MAX_BULK 32
#define MAX_PKT_BURST 16
#define SOCKET_ID_ANY -1

#define NANOSEC_PER_SEC 1000000000ULL	/* 10^9 */

#define BPF_PERF_READER_PAGE_CNT  64

#define NAME_LEN 64

#define TYPE_KPROBE     0
#define TYPE_UPROBE     1

#define PROBES_NUM_MAX 64
#define BPF_TRACER_NUM_MAX 8

#define PROBE_NAME_SZ   128

#define MAX_CPU_NR      256

/*
 * timeout (100ms), use for perf reader epoll().
 */
#define PERF_READER_TIMEOUT_DEF 100
#define PERF_READER_NUM_MAX	16

enum tracer_hook_type {
	HOOK_ATTACH,
	HOOK_DETACH
};

enum tracer_state {
	TRACER_INIT,
	TRACER_RUNNING,
	TRACER_STOP,
	TRACER_WAIT_START,
	TRACER_START_ERR,
	TRACER_WAIT_STOP,
	TRACER_STOP_ERR
};

enum probe_type {
	KPROBE,
	UPROBE
};

// index number of feature.
enum cfg_feature_idx {
	// Analyze go binary to get symbol address without symbol table
	FEATURE_UPROBE_GOLANG_SYMBOL,
	// openssl uprobe
	FEATURE_UPROBE_OPENSSL,
	// golang uprobe
	FEATURE_UPROBE_GOLANG,
	FEATURE_MAX,
};

struct cfg_feature_regex {
	regex_t preg;
	int ok;
};

extern struct cfg_feature_regex cfg_feature_regex_array[FEATURE_MAX];
extern int ebpf_config_protocol_filter[PROTO_NUM];
extern struct kprobe_port_bitmap allow_port_bitmap;
extern struct kprobe_port_bitmap bypass_port_bitmap;

/* *INDENT-OFF* */
#define probes_set_enter_symbol(t, fn)						\
do {                                                        			\
	char *func = (char*)calloc(PROBE_NAME_SZ, 1);             		\
	if (func != NULL) {                                       		\
		curr_idx = index++;                  		            	\
		t->ksymbols[curr_idx].isret = false;                 	    	\
		snprintf(func, PROBE_NAME_SZ, "kprobe/%s", fn);           	\
		t->ksymbols[curr_idx].func = func;                        	\
	} else {								\
		ebpf_error("no memory, probe (kprobe/%s) set failed", fn); 	\
	} 									\
} while(0)

#define probes_set_symbol(t, fn)						\
do {                            						\
	char *func = (char*)calloc(PROBE_NAME_SZ, 1);      			\
	if (func != NULL) {							\
		curr_idx = index++;						\
		t->ksymbols[curr_idx].isret = false;				\
		snprintf(func, PROBE_NAME_SZ, "kprobe/%s", fn);			\
		t->ksymbols[curr_idx].func = func;				\
	} else {								\
		ebpf_error("no memory, probe (kprobe/%s) set failed", fn);  	\
	}									\
	func = (char*)calloc(PROBE_NAME_SZ, 1);					\
	if (func != NULL) {							\
		curr_idx = index++;						\
		snprintf(func, PROBE_NAME_SZ, "kretprobe/%s", fn);		\
		t->ksymbols[curr_idx].isret = true;				\
		t->ksymbols[curr_idx].func = func;				\
	} else {								\
		ebpf_error("no memory, probe (kretprobe/%s) set failed", fn);	\
	}									\
} while(0)

#define tps_set_symbol(t, tp)							\
do {										\
	char *name = (char*)calloc(PROBE_NAME_SZ, 1);				\
	if (name != NULL) {							\
		curr_idx = index++;						\
		snprintf(name, PROBE_NAME_SZ, "%s", tp);			\
		t->tps[curr_idx].name = name;					\
	} else {								\
		ebpf_error("no memory, probe (tp %s) set failed", tp);		\
	}									\
} while(0)
/* *INDENT-ON* */

enum {
	/* set */
	SOCKOPT_SET_TRACER_ADD = 400,
	SOCKOPT_SET_TRACER_DEL,
	SOCKOPT_SET_TRACER_SET,
	SOCKOPT_SET_TRACER_FLUSH,
	/* get */
	SOCKOPT_GET_TRACER_SHOW,

	/* set */
	SOCKOPT_SET_SOCKTRACE_ADD = 500,
	SOCKOPT_SET_SOCKTRACE_DEL,
	SOCKOPT_SET_SOCKTRACE_SET,
	SOCKOPT_SET_SOCKTRACE_FLUSH,
	/* get */
	SOCKOPT_GET_SOCKTRACE_SHOW,

	/* set */
	SOCKOPT_SET_DATADUMP_ADD = 600,
	SOCKOPT_SET_DATADUMP_ON,
	SOCKOPT_SET_DATADUMP_OFF,
	/* get */
	SOCKOPT_GET_DATADUMP_SHOW
};

struct mem_block_head {
	uint8_t is_last;
	void *free_ptr;
	void (*fn)(void *);
} __attribute__((packed));

typedef void (*tracer_callback_t)(void *cp_data);

struct tracer_probes_conf {
	char *bin_file;		// only use uprobe;
	struct symbol_kprobe ksymbols[PROBES_NUM_MAX];
	int kprobes_nr;
	struct symbol_tracepoint tps[PROBES_NUM_MAX];
	int tps_nr;
	struct list_head uprobe_syms_head;	// uprobe symbol 信息存放链表。
	int uprobe_count;
};

struct probe {
	struct list_head list;
	enum probe_type type;
	char name[PROBE_NAME_SZ];
	struct ebpf_link *link;
	struct ebpf_prog *prog;
	int prog_fd;
	bool isret;
	void *private_data;	// Store uprobe information
	bool installed;
	struct bpf_tracer *tracer;
};

struct tracepoint {
	char name[PROBE_NAME_SZ];
	struct ebpf_link *link;
	struct ebpf_prog *prog;
	int prog_fd;
};

struct queue {
	struct bpf_tracer *t;
	struct ring *r;
	unsigned int ring_size;	// 队列配置大小，值为2的次幂
	void *datas_burst[MAX_PKT_BURST];	// burst的方式获取数据
	int nr;			// datas_burst中data数量

	/*
	 * 用于唤醒工作线程从队列上获取数据进行处理。
	 */
	pthread_mutex_t mutex;
	pthread_cond_t cond;

	/*
	 * 各种统计
	 */
	atomic64_t enqueue_lost;
	atomic64_t enqueue_nr;
	atomic64_t burst_count;
	atomic64_t dequeue_nr;
	atomic64_t heap_get_failed;	// 从heap上获取内存失败的次数统计
};

/*
 * map的重新配置，挂在bpf_tracer->maps_conf_head上。
 */
struct map_config {
	struct list_head list;
	char map_name[NAME_LEN];
	int max_entries;
};

struct ebpf_object;
struct perf_reader;
struct bpf_tracer;
typedef int (*tracer_op_fun_t)(struct bpf_tracer *);

/*
 * This is used to read data from the perf buffer, and each MAP
 * (type: PF_MAP_TYPE_PERF_EVENT_ARRAY) corresponds to it. A tracer
 * may contain multiple readers.
 */
struct bpf_perf_reader {
	char name[NAME_LEN];			// perf ring-buffer map
	bool is_use;				// false : free, ture : used
	struct ebpf_map *map;			// ebpf_map address
	struct perf_reader *readers[MAX_CPU_NR];// percpu readers (read from percpu ring-buffer map)
	int reader_fds[MAX_CPU_NR];		// percpu reader fds
	int readers_count;			// readers count
	unsigned int perf_pages_cnt;		// ring-buffer set memory size (memory pages count)
	perf_reader_raw_cb raw_cb;		// Used for perf ring-buffer receive callback.
	perf_reader_lost_cb lost_cb;		// Callback for perf ring-buffer data loss.
	int epoll_timeout;			// perf poll timeout (ms)
	int epoll_fd;
	struct bpf_tracer *tracer;
};

struct bpf_tracer {
	/*
	 * tracer info
	 */
	char name[NAME_LEN];		// tracer name
	char bpf_load_name[NAME_LEN];	// Tracer bpf load buffer name.
	// Used to identify which eBPF buffer is loaded by the kernel
	void *buffer_ptr;		// eBPF bytecodes buffer pointer
	int buffer_sz;			// eBPF buffer size
	struct ebpf_object *obj;	// eBPF object
	bool is_use;			// Whether it is being used.
	volatile uint32_t *lock;	// tracer lock

	/*
	 * probe, tracepoint
	 */
	struct tracer_probes_conf *tps;	// probe, tracepoint, uprobes config
	struct list_head probes_head;
	int probes_count;		// probe count.
	struct tracepoint tracepoints[PROBES_NUM_MAX];
	int tracepoints_count;
	pthread_mutex_t mutex_probes_lock; // Protect the probes operation in multiple threads

	/*
	 * perf event(type is TRACER_TYPE_PERF_EVENT) for attach fds.
	 */
	int per_cpu_fds[MAX_CPU_NR];
	int sample_freq; // sample frequency, Hertz.

	/*
	 * 数据分发处理worker，queues
	 */
	pthread_t perf_worker[MAX_CPU_NR];	// 用户态接收perf-buffer数据主线程
	pthread_t dispatch_workers[MAX_CPU_NR];	// 分发线程
	int dispatch_workers_nr;		// 分发线程数量
	struct queue queues[MAX_CPU_NR];	// 分发队列，每个分发线程都有其对应的队列。
	void *process_fn;			// 回调应用传递过来的接口, 进行数据处理
	void (*datadump)(void *data);		// eBPF data dump handle

	/*
	 * perf ring-buffer from kernel to user.
	 * A tracer may contain multiple readers, and there is a fixed
	 * upper limit (PERF_READER_NUM_MAX) on the number of
	 * readers that a tracer can have.
	 */
	struct bpf_perf_reader readers[PERF_READER_NUM_MAX];
	int perf_readers_count;

	/*
	 * statistics
	 */
	atomic64_t recv;			// User-level program event reception statistics. 
	atomic64_t lost;			// User-level programs not receiving data in time can cause data loss in the kernel.
	atomic64_t proto_status[PROTO_NUM];	// Statistical analysis based on different l7 protocols.

	/*
	 * maps re-config
	 */
	struct list_head maps_conf_head;

	/*
	 * Intended for use as a callback function
	 * for resource release and create tracer.
	 */
	tracer_op_fun_t release_cb;
	tracer_op_fun_t create_cb;

	/*
	 * tracer 控制接口和运行状态
	 */
	volatile enum tracer_state state;// 追踪器状态（Tracker status）
	bool adapt_success;		 // 是否成功适配内核, true 成功适配，false 适配失败
	uint32_t data_limit_max;	 // The maximum amount of data returned to the user-reader
};

#define EXTRA_TYPE_SERVER 0
#define EXTRA_TYPE_CLIENT 1

typedef int (*extra_waiting_fun_t)();

struct extra_waiting_op {
	struct list_head list;
	char name[NAME_LEN];
	extra_waiting_fun_t f;
	int type;
};

typedef int (*period_event_fun_t)();

struct period_event_op {
	struct list_head list;
	char name[NAME_LEN];
	bool is_valid;
	/* The cycle time of event triggering (unit is microseconds) */
	uint32_t times; 
	period_event_fun_t f;
};

/* =================================
 * 控制面数据传递
 * =================================
 */
struct rx_queue_info {
	uint64_t enqueue_lost;
	uint64_t enqueue_nr;
	uint64_t burst_count;
	uint64_t dequeue_nr;
	uint64_t heap_get_failed;
	int queue_size;
	int ring_capacity;
} __attribute__((aligned(8)));

struct bpf_tracer_param {
	char name[NAME_LEN];
	char bpf_load_name[NAME_LEN];
	int dispatch_workers_nr;
	unsigned int perf_pg_cnt;
	/* rx_queues start address 8-byte alignment */
	struct rx_queue_info rx_queues[MAX_CPU_NR] __attribute__((aligned(8)));
	uint64_t lost;
	int probes_count;
	int state;
	bool adapt_success;
	uint32_t data_limit_max;
	uint64_t proto_status[PROTO_NUM];
} __attribute__((__packed__));

struct bpf_tracer_param_array {
	int count;
	struct bpf_tracer_param tracers[0];
};

extern volatile uint32_t *tracers_lock;

/*
 * Protecting the creation, release, start and stop behaviors of tracer.
 */
static inline void tracers_ctl_lock(void)
{
	while (__atomic_test_and_set(tracers_lock, __ATOMIC_ACQUIRE))
		CLIB_PAUSE();
}

static inline void tracers_ctl_unlock(void)
{
	__atomic_clear(tracers_lock, __ATOMIC_RELEASE);
}

static inline void tracer_reader_lock(struct bpf_tracer *t)
{
	while (__atomic_test_and_set(t->lock, __ATOMIC_ACQUIRE))
		CLIB_PAUSE();
}

static inline void tracer_reader_unlock(struct bpf_tracer *t)
{
	__atomic_clear(t->lock, __ATOMIC_RELEASE);
}

#define CACHE_LINE_BYTES 64

int set_allow_port_bitmap(void *bitmap);
int set_bypass_port_bitmap(void *bitmap);
int enable_ebpf_protocol(int protocol);
int set_feature_regex(int feature, const char *pattern);
bool is_feature_enabled(int feature);
bool is_feature_matched(int feature, const char *path);
int bpf_tracer_init(const char *log_file, bool is_stdout);
int tracer_bpf_load(struct bpf_tracer *tracer);
int tracer_probes_init(struct bpf_tracer *tracer);
int tracer_hooks_attach(struct bpf_tracer *tracer);
int tracer_hooks_detach(struct bpf_tracer *tracer);
int check_kernel_version(int maj_limit, int min_limit);
int register_extra_waiting_op(const char *name,
			      extra_waiting_fun_t f, int type);
void bpf_tracer_finish(void);
struct bpf_tracer *setup_bpf_tracer(const char *name,
				    char *load_name,
				    void *bpf_bin_buffer,
				    int buffer_sz,
				    struct tracer_probes_conf *tps,
				    int workers_nr,
				    tracer_op_fun_t free_cb,
				    tracer_op_fun_t create_cb,
				    void *handle, int freq);
int maps_config(struct bpf_tracer *tracer, const char *map_name, int entries);
struct bpf_tracer *find_bpf_tracer(const char *name);
int register_period_event_op(const char *name,
			     period_event_fun_t f,
			     uint32_t period_time);
int set_period_event_invalid(const char *name);

/**
 * probe_detach - eBPF probe detach
 * @p struct probe
 *
 * @return 0 if ok, not 0 on error
 */
int probe_detach(struct probe *p);
/**
 * add_probe_to_tracer - add probe
 * @pb struct probe
 */
void add_probe_to_tracer(struct probe *pb);
/**
 * free_probe_from_tracer - free probe
 * @pb struct probe
 */
void free_probe_from_tracer(struct probe *pb);
int tracer_hooks_process(struct bpf_tracer *tracer,
			 enum tracer_hook_type type, int *probes_count);
int tracer_uprobes_update(struct bpf_tracer *tracer);
/**
 * create a perf buffer reader.
 * @t tracer
 * @map_name perf buffer map name
 * @raw_cb perf reader raw data callback
 * @lost_cb perf reader data lost callback
 * @pages_cnt How many memory pages are used for ring-buffer
 *            (system page size * pages_cnt)
 * @epoll_timeout perf epoll timeout
 *
 * @returns perf_reader address on success, NULL on error
 */
struct bpf_perf_reader*
create_perf_buffer_reader(struct bpf_tracer *t,
			  const char *map_name,
			  perf_reader_raw_cb raw_cb,
			  perf_reader_lost_cb lost_cb,
			  unsigned int pages_cnt,
			  int epoll_timeout);
void free_perf_buffer_reader(struct bpf_perf_reader *reader);
int release_bpf_tracer(const char *name);
void free_all_readers(struct bpf_tracer *t);
int enable_tracer_reader_work(const char *name,
			      struct bpf_tracer *tracer,
			      void *fn);
#endif /* DF_USER_TRACER_H */
