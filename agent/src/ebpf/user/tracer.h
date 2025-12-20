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
#include "config.h"

#define PERF_PAGE_DEF_SZ 4096

#define STRINGIFY(x) #x
#define UPROBE_FUNC_NAME(N) STRINGIFY(df_U_##N)
#define URETPROBE_FUNC_NAME(N) STRINGIFY(df_UR_##N)

#define LOOP_DELAY_US  100000

#define memcpy_fast(a,b,c) memcpy(a,b,c)

#define IS_NULL(p) ((p) == NULL)

#define RING_SIZE 16384
#define MAX_BULK 32
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

// RHEL 7 & CentOS 7 systems that run on kernel 3.10.
// eBPF support has been backported to kernel 3.10 since 3.10.0-940.el7.x86_64.
// See this blog post(https://www.redhat.com/en/blog/introduction-ebpf-red-hat-enterprise-linux-7).
#define LINUX_3_10_MIN_REV_NUM	940

/*
 * timeout (100ms), use for perf reader epoll().
 */
#define PERF_READER_TIMEOUT_DEF 100
#define PERF_READER_NUM_MAX	16

// The maximum output character value of datadump
#define DEBUG_BUFF_SIZE 163840
typedef void (*debug_callback_t) (char *data, int len);

enum perf_event_state {
	PERF_EV_INIT,
	PERF_EV_ATTACH,
	PERF_EV_DETACH
};

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

struct thread_index_entry {
	pthread_t thread;
	int index;
};

struct thread_index_array {
	struct thread_index_entry *entries;
	pthread_mutex_t lock;
};

// PID management for feature-matching processes
#define pids_match_hash_t        clib_bihash_8_8_t
#define pids_match_hash_init     clib_bihash_init_8_8
#define pids_match_hash_kv       clib_bihash_kv_8_8_t
#define print_hash_pids_match    print_bihash_8_8
#define pids_match_hash_search   clib_bihash_search_8_8
#define pids_match_hash_add_del  clib_bihash_add_del_8_8
#define pids_match_hash_free     clib_bihash_free_8_8
#define pids_match_hash_key_value_pair_cb        clib_bihash_foreach_key_value_pair_cb_8_8
#define pids_match_hash_foreach_key_value_pair   clib_bihash_foreach_key_value_pair_8_8

enum match_pids_act {
	MATCH_PID_ADD,
	MATCH_PID_DEL,
};

struct cfg_feature_regex {
	regex_t preg;
	int ok;
};

extern struct cfg_feature_regex cfg_feature_regex_array[FEATURE_MAX];
extern int ebpf_config_protocol_filter[PROTO_NUM];
extern struct kprobe_port_bitmap allow_port_bitmap;
extern struct kprobe_port_bitmap bypass_port_bitmap;
extern bool allow_seg_reasm_protos[PROTO_NUM];

/* *INDENT-OFF* */
#define probes_set_enter_symbol(t, fn)						\
do {                                                        			\
	char *func = (char*)calloc(PROBE_NAME_SZ, 1);             		\
	if (func != NULL) {                                       		\
		int curr_idx = t->kprobes_nr++;                  		\
		t->ksymbols[curr_idx].isret = false;                 	    	\
		snprintf(func, PROBE_NAME_SZ, "kprobe/%s", fn);           	\
		t->ksymbols[curr_idx].func = func;                        	\
	} else {								\
		ebpf_error("no memory, probe (kprobe/%s) set failed", fn); 	\
	} 									\
} while(0)

#define probes_set_exit_symbol(t, fn)						\
do {                                                        			\
	char *func = (char*)calloc(PROBE_NAME_SZ, 1);             		\
	if (func != NULL) {                                       		\
		int curr_idx = t->kprobes_nr++;                  		\
		t->ksymbols[curr_idx].isret = true;                 	    	\
		snprintf(func, PROBE_NAME_SZ, "kretprobe/%s", fn);           	\
		t->ksymbols[curr_idx].func = func;                        	\
	} else {								\
		ebpf_error("no memory, probe (kretprobe/%s) set failed", fn); 	\
	} 									\
} while(0)

#define probes_set_symbol(t, fn)						\
do {                            						\
	char *func = (char*)calloc(PROBE_NAME_SZ, 1);      			\
	if (func != NULL) {							\
		int curr_idx = t->kprobes_nr++;					\
		t->ksymbols[curr_idx].isret = false;				\
		snprintf(func, PROBE_NAME_SZ, "kprobe/%s", fn);			\
		t->ksymbols[curr_idx].func = func;				\
	} else {								\
		ebpf_error("no memory, probe (kprobe/%s) set failed", fn);  	\
	}									\
	func = (char*)calloc(PROBE_NAME_SZ, 1);					\
	if (func != NULL) {							\
		int curr_idx = t->kprobes_nr++;					\
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
		snprintf(name, PROBE_NAME_SZ, "%s", tp);			\
		t->tps[t->tps_nr++].name = name;				\
	} else {								\
		ebpf_error("no memory, probe (tp %s) set failed", tp);		\
	}									\
} while(0)

#define kfunc_set_symbol(t, fn, ret)						\
do {										\
	char *name = (char*)calloc(PROBE_NAME_SZ, 1);				\
	if (name != NULL) {							\
		if ((ret)) {							\
			snprintf(name, PROBE_NAME_SZ, "fexit/%s", fn);		\
		} else {							\
			snprintf(name, PROBE_NAME_SZ, "fentry/%s", fn);		\
		}								\
		t->kfuncs[t->kfuncs_nr++].name = name;				\
	} else {								\
		ebpf_error("no memory, kfunc('%s') set failed", fn);		\
	}									\
} while(0)

#define kprobe_set_symbol(t, fn, ret)						\
{										\
	if ((ret)) {								\
		probes_set_exit_symbol(t, fn);					\
	} else {								\
		probes_set_enter_symbol(t, fn);					\
	}									\
}
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
	SOCKOPT_GET_DATADUMP_SHOW,

	/* set */
	SOCKOPT_SET_CPDBG_ADD = 700,
	SOCKOPT_SET_CPDBG_ON,
	SOCKOPT_SET_CPDBG_OFF,
	/* get */
	SOCKOPT_GET_CPDBG_SHOW,

	SOCKOPT_PRINT_MATCH_PIDS = 800,
};

struct mem_block_head {
	uint8_t is_last;
	void *free_ptr;
	void (*fn) (void *);
} __attribute__ ((packed));

typedef int (*tracer_callback_t) (void *ctx, int queue_id, void *cp_data);

enum {
    TRACER_CALLBACK_FLAG_KEEP_DATA = 0x1,
};

struct tracer_probes_conf {
	char *bin_file;		// only use uprobe;
	struct symbol_kprobe ksymbols[PROBES_NUM_MAX];
	int kprobes_nr;
	struct symbol_tracepoint tps[PROBES_NUM_MAX];
	int tps_nr;
	struct symbol_kfunc kfuncs[PROBES_NUM_MAX];
	int kfuncs_nr;
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

struct kfunc {
	char name[PROBE_NAME_SZ];
	struct ebpf_link *link;
	struct ebpf_prog *prog;
	int prog_fd;
};

struct queue {
	int id; // Queue Identifier
	struct bpf_tracer *t;
	struct ring *r;
	unsigned int ring_size;	// 队列配置大小，值为2的次幂
	void *datas_burst[MAX_EVENTS_BURST];	// burst的方式获取数据
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
typedef int (*tracer_op_fun_t) (struct bpf_tracer *);

/*
 * This is used to read data from the perf buffer, and each MAP
 * (type: PF_MAP_TYPE_PERF_EVENT_ARRAY) corresponds to it. A tracer
 * may contain multiple readers.
 */
struct bpf_perf_reader {
	char name[NAME_LEN];	// perf ring-buffer map
	bool is_use;		// false : free, ture : used
	struct ebpf_map *map;	// ebpf_map address
	struct perf_reader *readers[MAX_CPU_NR];	// percpu readers (read from percpu ring-buffer map)
	int reader_fds[MAX_CPU_NR];	// percpu reader fds
	int readers_count;	// readers count
	unsigned int perf_pages_cnt;	// ring-buffer set memory size (memory pages count)
	perf_reader_raw_cb raw_cb;	// Used for perf ring-buffer receive callback.
	perf_reader_lost_cb lost_cb;	// Callback for perf ring-buffer data loss.
	int epoll_timeout;	// perf poll timeout (ms)
	int epoll_fds[MAX_CPU_NR];
	int epoll_fds_count;
	struct bpf_tracer *tracer;
};

struct bpf_tracer {
	/*
	 * tracer info
	 */
	char name[NAME_LEN];	// tracer name
	char bpf_load_name[NAME_LEN];	// Tracer bpf load buffer name.
	// Used to identify which eBPF buffer is loaded by the kernel
	void *buffer_ptr;	// eBPF bytecodes buffer pointer
	int buffer_sz;		// eBPF buffer size
	struct ebpf_object *obj;	// eBPF object
	bool is_use;		// Whether it is being used.
	volatile uint32_t *lock;	// tracer lock

	/*
	 * probe, tracepoint
	 */
	struct tracer_probes_conf *tps;	// probe, tracepoint, uprobes config
	struct list_head probes_head;
	int probes_count;	// probe count.
	struct tracepoint tracepoints[PROBES_NUM_MAX];
	int tracepoints_count;
	struct kfunc kfuncs[PROBES_NUM_MAX];
	int kfuncs_count;
	pthread_mutex_t mutex_probes_lock;	// Protect the probes operation in multiple threads

	/*
	 * perf event(type is TRACER_TYPE_PERF_EVENT) for attach fds.
	 */
	int per_cpu_fds[MAX_CPU_NR];
	int sample_freq;	// sample frequency, Hertz.
	/*
	 * Enable CPU sampling?
	 * For the following scenario:
	 * If the on-CPU profiler is disabled, this setting will be false,
	 * which means that perf sampling events will not be enabled, the attach
	 * operation will not be executed.
	 */
	bool enable_sample;
	// perf event state
	enum perf_event_state ev_state;

	/*
	 * Data distribution processing worker, queues
	 */
	pthread_t perf_workers[MAX_CPU_NR];	// Main thread for user-space receiving perf-buffer data
	pthread_t dispatch_workers[MAX_CPU_NR];	// Dispatch threads
	int dispatch_workers_nr;	// Number of dispatch threads
	struct queue queues[MAX_CPU_NR];	// Dispatch queues, each dispatch thread has its corresponding queue.
	void *process_fn;	// Callback interface passed from the application for data processing
	void (*datadump) (void *data, int64_t boot_time);	// eBPF data dump handle

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
	atomic64_t recv;	// User-level program event reception statistics. 
	atomic64_t lost;	// User-level programs not receiving data in time can cause data loss in the kernel.
	atomic64_t proto_stats[PROTO_NUM];	// Statistical analysis based on different l7 protocols.
	// Packet Statistics Obtained from DPDK
	atomic64_t rx_pkts;
	atomic64_t tx_pkts;
	atomic64_t rx_bytes;
	atomic64_t tx_bytes;
	atomic64_t dropped_pkts;

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
	volatile enum tracer_state state;	// 追踪器状态（Tracker status）
	bool adapt_success;	// 是否成功适配内核, true 成功适配，false 适配失败
	uint32_t data_limit_max;	// The maximum amount of data returned to the user-reader

	/*
	 * Callback function contexts for continuous profiler
	 * Should only be used to create profiler context
	 */
	void *profiler_callback_ctx[PROFILER_CTX_NUM];
};

#define EXTRA_TYPE_SERVER 0
#define EXTRA_TYPE_CLIENT 1

typedef int (*extra_waiting_fun_t) ();

struct extra_waiting_op {
	struct list_head list;
	char name[NAME_LEN];
	extra_waiting_fun_t f;
	int type;
};

typedef int (*period_event_fun_t) ();

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
} __attribute__ ((aligned(8)));

struct bpf_tracer_param {
	char name[NAME_LEN];
	char bpf_load_name[NAME_LEN];
	int dispatch_workers_nr;
	unsigned int perf_pg_cnt;
	/* rx_queues start address 8-byte alignment */
	struct rx_queue_info rx_queues[MAX_CPU_NR] __attribute__ ((aligned(8)));
	uint64_t lost;
	int probes_count;
	int state;
	bool adapt_success;
	uint32_t data_limit_max;
	uint64_t proto_stats[PROTO_NUM];
} __attribute__ ((__packed__));

struct bpf_tracer_param_array {
	int count;
	struct bpf_tracer_param tracers[0];
};

struct reader_forward_info {
	uint64_t queue_id;
	int cpu_id;
	struct bpf_tracer *tracer;
};

// Structure to store kick CPU thread info
typedef struct {
	pid_t tid;     // Linux thread ID (TID) of the kernel thread
	int cpu_id;    // CPU core number the thread is bound to
	bool can_bind_cpu;
} kick_thread_info_t;

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

struct clear_list_elem {
	struct list_head list;
	const char p[0];
};

static bool inline insert_list(void *elt, uint32_t len, struct list_head *h)
{
	struct clear_list_elem *cle;
	cle = calloc(1, sizeof(*cle) + len);
	if (cle == NULL) {
		ebpf_warning("calloc() failed.\n");
		return false;
	}
	memcpy((void *)cle->p, (void *)elt, len);
	list_add_tail(&cle->list, h);
	return true;
}

static int inline __reclaim_map(int map_fd, struct list_head *h)
{
	int count = 0;
	struct list_head *p, *n;
	struct clear_list_elem *cle;
	list_for_each_safe(p, n, h) {
		cle = container_of(p, struct clear_list_elem, list);
		if (!bpf_delete_elem(map_fd, (void *)cle->p))
			count++;
		list_head_del(&cle->list);
		free(cle);
	}

	return count;
}

#define CACHE_LINE_BYTES 64

int set_allow_port_bitmap(void *bitmap);
int set_bypass_port_bitmap(void *bitmap);
int enable_ebpf_protocol(int protocol);
int set_feature_regex(int feature, const char *pattern);
bool is_feature_enabled(int feature);
bool is_feature_matched(int feature, int pid, const char *path);
bool is_feature_regex_set(int feature);
bool php_profiler_enabled(void);
bool v8_profiler_enabled(void);
bool python_profiler_enabled(void);
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
				    void *handle,
				    void
				    *profiler_callback_ctx[PROFILER_CTX_NUM],
				    int freq);
int maps_config(struct bpf_tracer *tracer, const char *map_name, int entries);
struct bpf_tracer *find_bpf_tracer(const char *name);
int register_period_event_op(const char *name,
			     period_event_fun_t f, uint32_t period_time);
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
int probe_attach(struct probe *p);

/**
 * @brief Create a perf buffer reader.
 *
 * @param t tracer
 * @param map_name perf buffer map name
 * @param raw_cb perf reader raw data callback
 * @param lost_cb perf reader data lost callback
 * @param pages_cnt How many memory pages are used for ring-buffer
 * (system page size * pages_cnt)
 * @param thread_nr The number of threads required for the reader's work 
 * @param epoll_timeout perf epoll timeout
 * @return perf_reader address on success, NULL on error
 */
struct bpf_perf_reader *create_perf_buffer_reader(struct bpf_tracer *t,
						  const char *map_name,
						  perf_reader_raw_cb raw_cb,
						  perf_reader_lost_cb lost_cb,
						  unsigned int pages_cnt,
						  int thread_nr,
						  int epoll_timeout);
void free_perf_buffer_reader(struct bpf_perf_reader *reader);
int release_bpf_tracer(const char *name);
void free_all_readers(struct bpf_tracer *t);
int enable_tracer_reader_work(const char *name, int idx,
			      struct bpf_tracer *tracer, void *fn);
bool is_rt_kernel(void);
/**
 * @brief Enable eBPF segmentation reassembly for the specified protocol.
 * 
 * @param protocol Protocols for segmentation reassembly
 * @return 0 on success, non-zero on error
 */
int enable_ebpf_seg_reasm_protocol(int protocol);
int exec_set_feature_pids(int feature, const int *pids, int num);
/**
 * @brief Add regex-matched process list for feature.
 * 
 * @param feature Refers to a specific feature module, value: FEATURE_*
 * @param pids Address of the process list
 * @param num Number of elements in the process list
 * @return 0 on success, non-zero on error
 */
int set_feature_pids(int feature, const int *pids, int num);
int init_match_pids_hash(void);
bool is_pid_match(int feature, int pid);
struct probe *create_probe(struct bpf_tracer *tracer,
			   const char *func_name, bool isret,
			   enum probe_type type, void *private,
			   bool add_tracer);
void free_probe_from_conf(struct probe *pb, struct tracer_probes_conf *conf);

/**
 * @brief Creates and initializes an eBPF object from provided BPF bytecode.
 *
 * This function opens and initializes an eBPF object using the specified BPF bytecode,
 * size, and name. If the initialization fails, a warning message is logged, and `NULL` 
 * is returned.
 *
 * @param[in] bpf_code A pointer to the BPF bytecode buffer.
 * @param[in] code_size The size of the BPF bytecode buffer in bytes.
 * @param[in] name A null-terminated string specifying the name of the eBPF program.
 *
 * @return A pointer to the initialized `ebpf_object` on success, or `NULL` on failure.
 */
struct ebpf_object *create_ebpf_object(const void *bpf_code,
                                       size_t code_size, const char *name);
/**
 * @brief Loads an eBPF object into the kernel.
 *
 * This function takes an eBPF object and loads it into the kernel, preparing it
 * for use in attaching to specific hooks or operations.
 *
 * @param[in] obj A pointer to the eBPF object to be loaded.
 *
 * @return 0 on success, or a non-zero value on error.
 */
int load_ebpf_object(struct ebpf_object *obj);
#endif /* DF_USER_TRACER_H */
