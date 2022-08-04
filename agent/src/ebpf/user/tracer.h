#ifndef _USER_TRACER_H_
#define _USER_TRACER_H_
#include <stdio.h>
#include <stdbool.h>
#include <linux/limits.h>	/* ulimit */
#include <sys/resource.h>	/* RLIM_INFINITY */
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <linux/types.h>
#include <sys/types.h>
#include <sys/stat.h>
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
#include "../libbpf/src/libbpf.h"
#include "../kernel/include/common.h"
#include "../kernel/include/xxhash.h"
#include "../kernel/include/socket_trace_common.h"
#include "bcc/libbpf.h"
#include "symbol.h"

// TODO: 对内存拷贝进行硬件优化。

#define LOOP_DELAY_US  100000

#define memcpy_fast(a,b,c) memcpy(a,b,c)

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
#define BPF_TRACER_NUM_MAX 128

#define PROBE_NAME_SZ   128

#define MAX_CPU_NR      256

enum tracer_hook_type {
	HOOK_ATTACH,
	HOOK_DETACH
};

enum tracer_state {
	TRACER_INIT,
	TRACER_RUNNING,
	TRACER_STOP
};

enum probe_type {
	KPROBE,
	UPROBE
};

// use for inference struct offset.
#define OFFSET_INFER_SERVER_PORT 54583

static inline unsigned int min_log2(unsigned int x)
{
#ifdef __x86_64__
#define count_leading_zeros(x) __builtin_clzll (x)
#elif __i386__
#define count_leading_zeros(x) __builtin_clzl (x)
#endif
	unsigned int n;
	n = count_leading_zeros(x);
	return 64 - n - 1;
}

static inline unsigned int max_log2(unsigned int x)
{
	unsigned int l = min_log2(x);
	if (x > ((unsigned int)1 << l))
		l++;
	return l;
}

/* *INDENT-OFF* */
#define probes_set_enter_symbol(t, fn)                      \
do {                                                        \
  curr_idx = index++;                  		            \
  t->ksymbols[curr_idx].isret = false;                 	    \
  char *func = (char*)calloc(PROBE_NAME_SZ, 1);             \
  snprintf(func, PROBE_NAME_SZ, "kprobe/%s", fn);           \
  t->ksymbols[curr_idx].func = func;                        \
} while(0)

#define probes_set_symbol(t, fn)                            \
do {                                                        \
  curr_idx = index++;                                       \
  t->ksymbols[curr_idx].isret = false;                 	    \
  char *func = (char*)calloc(PROBE_NAME_SZ, 1);             \
  snprintf(func, PROBE_NAME_SZ, "kprobe/%s", fn);           \
  t->ksymbols[curr_idx].func = func;                        \
  curr_idx = index++;                                 	    \
  func = (char*)calloc(PROBE_NAME_SZ, 1);             	    \
  snprintf(func, PROBE_NAME_SZ, "kretprobe/%s", fn);  	    \
  t->ksymbols[curr_idx].isret = true;                       \
  t->ksymbols[curr_idx].func = func;                        \
} while(0)

#define tps_set_symbol(t, tp)                               \
do {                                                        \
  curr_idx = index++;                                       \
  char *name = (char*)calloc(PROBE_NAME_SZ, 1);             \
  snprintf(name, PROBE_NAME_SZ, "%s", tp);  		    \
  t->tps[curr_idx].name = name;                       	    \
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
};

enum {
	/* set */
	SOCKOPT_SET_SOCKTRACE_ADD = 500,
	SOCKOPT_SET_SOCKTRACE_DEL,
	SOCKOPT_SET_SOCKTRACE_SET,
	SOCKOPT_SET_SOCKTRACE_FLUSH,

	/* get */
	SOCKOPT_GET_SOCKTRACE_SHOW,
};

struct mem_block_head {
	uint8_t is_last;
	void *free_ptr;
	void (*fn)(void *);
} __attribute__ ((packed));

typedef void (*l7_handle_fn) (void *sd);

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
	struct bpf_link *link;
	struct bpf_program *prog;
	int prog_fd;
	bool isret;
	void *private_data;	// Store uprobe information
	bool installed;
	struct bpf_tracer *tracer;
};

struct tracepoint {
	char name[PROBE_NAME_SZ];
	struct bpf_link *link;
	struct bpf_program *prog;
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
	atomic64_t heap_get_faild;	// 从heap上获取内存失败的次数统计
};

/*
 * map的重新配置，挂在bpf_tracer->maps_conf_head上。
 */
struct map_config {
	struct list_head list;
	char map_name[NAME_LEN];
	int max_entries;
};

typedef int (*tracer_ctl_fun_t) (void);
struct bpf_object;

struct bpf_tracer {
	/*
	 * tracer info
	 */
	char name[NAME_LEN];	// tracer name
	char bpf_load_name[NAME_LEN];	// Tracer bpf load buffer name.
					// Used to identify which eBPF buffer is loaded by the kernel
	void *buffer_ptr;		// eBPF bytecodes buffer pointer
	int buffer_sz;			// eBPF buffer size
	struct bpf_object *pobj;	// libbpf define bpf object

	/*
	 * probe, tracepoint
	 */
	struct tracer_probes_conf *tps;	// probe, tracepoint, uprobes config
	struct list_head probes_head;
	int probes_count;	// probe count.
	struct tracepoint tracepoints[PROBES_NUM_MAX];
	int tracepoints_count;
	pthread_mutex_t mutex_probes_lock; // Protect the probes operation in multiple threads

	/*
	 * 数据分发处理worker，queues
	 */
	pthread_t perf_worker[MAX_CPU_NR];	// 用户态接收perf-buffer数据主线程
	pthread_t dispatch_workers[MAX_CPU_NR];	// 分发线程
	int dispatch_workers_nr;	// 分发线程数量
	struct queue queues[MAX_CPU_NR];	// 分发队列，每个分发线程都有其对应的队列。
	void *process_fn;	// 回调应用传递过来的接口, 进行数据处理

	/*
	 * perf ring-buffer from kernel to user.
	 */
	struct bpf_map *data_map;	// perf ring-buffer map
	struct perf_reader *readers[MAX_CPU_NR];	// percpu reader (read from percpu ring-buffer map)
	int readers_count;	// readers count       
	unsigned int perf_pages_cnt;	// ring-buffer set memory size (memory pages count)
	perf_reader_raw_cb raw_cb;	// 用于perf ring-buffer接收回调
	perf_reader_lost_cb lost_cb;	// 用于perf ring-buffer数据丢失回调

	/*
	 * statistics
	 */
	atomic64_t lost;	// 用户态程序来不及接收造成内核丢数据
	atomic64_t proto_status[PROTO_NUM];	// 分协议类型统计

	/*
	 * maps re-config
	 */
	struct list_head maps_conf_head;

	/*
	 * tracer 控制接口和运行状态
	 */
	tracer_ctl_fun_t stop_handle;
	tracer_ctl_fun_t start_handle;
	enum tracer_state state;	// 追踪器状态
	bool adapt_success;	// 是否成功适配内核, true 成功适配，false 适配失败
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
	uint64_t heap_get_faild;
	int queue_size;
	int ring_capacity;
};

struct bpf_tracer_param {
	char name[NAME_LEN];
	char bpf_load_name[NAME_LEN];
	int dispatch_workers_nr;
	unsigned int perf_pg_cnt;
	struct rx_queue_info rx_queues[MAX_CPU_NR];
	uint64_t lost;
	int probes_count;
	int state;
	bool adapt_success;
	uint64_t proto_status[PROTO_NUM];
} __attribute__ ((__packed__));

struct bpf_tracer_param_array {
	int count;
	struct bpf_tracer_param tracers[0];
};

static inline void prefetch0(const volatile void *p)
{
	asm volatile ("prefetcht0 %[p]"::[p] "m"(*(const volatile char *)p));
}

#define CACHE_LINE_BYTES 64

#define PREFETCH_READ 0
#define PREFETCH_WRITE 1

/* *INDENT-OFF* */
#define _PREFETCH(n,size,type)				\
  if ((size) > (n)*CACHE_LINE_BYTES)			\
    __builtin_prefetch (_addr + (n)*CACHE_LINE_BYTES, 	\
                  PREFETCH_##type,              	\
                  /* locality */ 3);

#define PREFETCH(addr,size,type)		\
do {						\
  void * _addr = (addr);			\
	int __sz = (size);			\
  if (__sz > 2*CACHE_LINE_BYTES)		\
		__sz = 2*CACHE_LINE_BYTES;	\
  _PREFETCH (0, __sz, type);			\
  _PREFETCH (1, __sz, type);			\
} while (0)
/* *INDENT-ON* */

static inline void
prefetch_and_process_datas(struct bpf_tracer *t, int nb_rx, void **datas_burst)
{
/* Configure how many socket_data ahead to prefetch, when reading socket_data */
#define PREFETCH_OFFSET   3
	int32_t j;
	struct socket_bpf_data *sd;
	struct mem_block_head *block_head;
	l7_handle_fn callback = (l7_handle_fn) t->process_fn;

	/* Prefetch first packets */
	for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++)
		PREFETCH(datas_burst[j], 2 * CACHE_LINE_BYTES, READ);

	/*
	 * Prefetch and forward already prefetched
	 * packets.
	 */
	for (j = 0; j < nb_rx; j++) {
		if (j + PREFETCH_OFFSET < nb_rx)
			PREFETCH(datas_burst[j + PREFETCH_OFFSET],
				 2 * CACHE_LINE_BYTES, READ);
		sd = (struct socket_bpf_data *)datas_burst[j];
		block_head = (struct mem_block_head *)sd - 1;
		if (block_head->fn != NULL) {
			block_head->fn(sd);
		} else {
			callback(sd);
		}

		if (block_head->is_last == 1)
			free(block_head->free_ptr);
	}
}

int bpf_tracer_init(const char *log_file, bool is_stdout);
int tracer_bpf_load(struct bpf_tracer *tracer);
int tracer_probes_init(struct bpf_tracer *tracer);
int tracer_hooks_attach(struct bpf_tracer *tracer);
int tracer_hooks_detach(struct bpf_tracer *tracer);
int perf_map_init(struct bpf_tracer *tracer, const char *perf_map_name);
int dispatch_worker(struct bpf_tracer *tracer, unsigned int queue_size);
int check_kernel_version(int maj_limit, int min_limit);
int register_extra_waiting_op(const char *name,
			      extra_waiting_fun_t f, int type);
void bpf_tracer_finish(void);
struct bpf_tracer *create_bpf_tracer(const char *name,
				     char *load_name,
				     void *bpf_bin_buffer,
				     int buffer_sz,
				     struct tracer_probes_conf *tps,
				     int workers_nr,
				     void *handle, unsigned int perf_pages_cnt);
int maps_config(struct bpf_tracer *tracer, const char *map_name, int entries);
struct bpf_tracer *find_bpf_tracer(const char *name);
int register_period_event_op(const char *name, period_event_fun_t f);
int set_period_event_invalid(const char *name);
// 停止tracer运行。返回值：0：成功，非0：失败
int tracer_stop(void);
// 开启tracer运行。返回值：0：成功，非0：失败
int tracer_start(void);
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
#endif
