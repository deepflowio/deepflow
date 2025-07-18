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

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <sched.h>
#include <signal.h>
#include <sys/utsname.h>
#include <sys/prctl.h>
#include <linux/version.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <bcc/bcc_proc.h>
#include <bcc/bcc_elf.h>
#include <bcc/libbpf.h>
#include <bcc/perf_reader.h>
#include "config.h"
#include "types.h"
#include "clib.h"
#include "probe.h"
#include "table.h"
#include "utils.h"
#include "log.h"
#include "symbol.h"
#include "bihash_8_8.h"
#include "tracer.h"
#include "elf.h"
#include "load.h"
#include "mem.h"
#include "socket.h"
#include "unwind_tracer.h"
#include "extended/extended.h"
#include "profile/perf_profiler.h"

/*
 * Sleep duration (in seconds) before retrying CPU binding if it fails.
 * This is used when binding fails and no event-based wakeup is implemented.
 */
#define KICK_BIND_RETRY_WAIT_SECS 1

uint32_t k_version;
// Linux kernel major version, minor version, revision version, and revision number.
int major, minor, revision, rev_num;
char linux_release[128];	// Record the contents of 'uname -r'

/*
 * Array storing kick thread information for each CPU.
 * Each entry holds the Linux thread ID (TID) and the CPU core it is associated with.
 * Used to manage or inspect per-CPU kick threads.
 */
kick_thread_info_t kick_threads[MAX_CPU_NR];
volatile uint32_t *tracers_lock;
extern volatile uint64_t sys_boot_time_ns;	// System boot time in nanoseconds
volatile uint64_t prev_sys_boot_time_ns;	// The last updated system boot time, in nanoseconds

struct cfg_feature_regex cfg_feature_regex_array[FEATURE_MAX];

// eBPF protocol filter.
int ebpf_config_protocol_filter[PROTO_NUM];

/**
 * @brief Store the protocols that can perform segmentation reassembly
 *
 * In scenarios where reading and writing of Header and Payload are completed by
 * two system calls, we can rely on the out-of-order reassembly mechanism to
 * aggregate eBPF data in user space, improving the analysis effect. This array
 * is used to store which protocols allow data aggregation, and the set content
 * will notify the eBPF program to handle it."
 */
bool allow_seg_reasm_protos[PROTO_NUM];

struct kprobe_port_bitmap allow_port_bitmap;
struct kprobe_port_bitmap bypass_port_bitmap;

uint64_t adapt_kern_uid;	// Indicates the identifier of the adaptation kernel

uint32_t attach_failed_count;	// attach failure statistics

/*
 * tracers
 */
static struct bpf_tracer tracers[BPF_TRACER_NUM_MAX];
static int tracers_count;

/*
 * 控制面用于命令行管理
 */
static pthread_t ctrl_pthread;
static pthread_t cpus_kick_pthread;

/*
 * 用于额外事务处理, 目前利用这个机制来实现socket_trace的内核结构偏移推断。
 */
static volatile int ready_flag_cpus[MAX_CPU_NR];

/* Registration of additional transactions 额外事务处理的注册 */
static struct list_head extra_waiting_head;
/* Registration for periodic event handling 周期性事件处理的注册 */
static struct list_head period_events_head;

int sys_cpus_count;
bool *cpu_online;		// 用于判断CPU是否是online

// 所有tracer成功完成启动，会被应用设置为1
static volatile uint64_t all_probes_ready;

extern __thread uword thread_index;
// Thread ID and thread index correspondence
struct thread_index_array thread_ids;
// Record the current maximum thread index value.
u64 thread_index_max;

// Number of period timer ticks.
static uint64_t period_event_ticks;

// Store the data of the last matched process ID list.
struct match_pid_s {
	int *pids;
	int count;
};
static struct match_pid_s last_match_pids[FEATURE_MAX];
pthread_mutex_t match_pids_lock;
// Used to store process IDs for matching various features
pids_match_hash_t pids_match_hash;

static int tracepoint_attach(struct tracepoint *tp);
static int perf_reader_setup(struct bpf_perf_reader *perf_readerm,
			     int thread_nr);
static void perf_reader_release(struct bpf_perf_reader *perf_reader);
static void print_match_pids_hash(void);

/*
 * 内核版本依赖检查
 */
int check_kernel_version(int maj_limit, int min_limit)
{
	struct utsname uts;
	if (uname(&uts) == -1) {
		ebpf_warning("uname() error\n");
		return ETR_INVAL;
	}

	if (!strstr(uts.machine, "x86_64") && !strstr(uts.machine, "aarch64")) {
		ebpf_warning("Current machine is \"%s\", not support.\n",
			     uts.machine);
		return ETR_INVAL;
	}

	if (fetch_kernel_version(&major, &minor, &revision, &rev_num) != ETR_OK) {
		return ETR_INVAL;
	}

	ebpf_info("%s Linux %d.%d.%d-%d\n", __func__, major, minor, revision,
		  rev_num);

	/*
	 * Redhat/CentOS 7 introduced support for eBPF tracing features starting
	 * from version 7.6 (3.10.0-940.el7.x86_64).
	 */
	if (major == 3 && minor == 10 && revision == 0 &&
	    rev_num >= LINUX_3_10_MIN_REV_NUM)
		return ETR_OK;

	if (major < maj_limit || (major == maj_limit && minor < min_limit)) {
		ebpf_warning
		    ("[eBPF Kernel Adapt] The current kernel version (%s) does not support"
		     " eBPF. It requires  kernel version of %d.%d+ or 3.10.0-%d+ (for "
		     "linux 3.10.0 kernel, the revision number must be greater than or "
		     "equal to %d).\n",
		     uts.release, maj_limit, min_limit, LINUX_3_10_MIN_REV_NUM,
		     LINUX_3_10_MIN_REV_NUM);
		return ETR_INVAL;
	}

	return ETR_OK;
}

static struct bpf_tracer *__find_bpf_tracer(const char *name)
{
	ASSERT(tracers_lock[0]);

	struct bpf_tracer *t = NULL;
	int i;
	for (i = 0; i < BPF_TRACER_NUM_MAX; i++) {
		t = &tracers[i];
		if (t->is_use && (strcmp(t->name, name) == 0))
			return t;
	}

	ebpf_debug("Tracer '%s', Not Found.\n", name);

	return NULL;
}

struct bpf_tracer *find_bpf_tracer(const char *name)
{
	if (tracers_lock == NULL)
		return NULL;

	struct bpf_tracer *t = NULL;
	tracers_ctl_lock();
	t = __find_bpf_tracer(name);
	tracers_ctl_unlock();

	return t;
}

static struct bpf_tracer *alloc_bpf_tracer(void)
{
	ASSERT(tracers_lock[0]);

	struct bpf_tracer *t = NULL;
	int i;
	for (i = 0; i < BPF_TRACER_NUM_MAX; i++) {
		t = &tracers[i];
		if (!t->is_use) {
			memset(t, 0, sizeof(*t));
			tracers_count++;
			t->is_use = true;
			return t;
		}
	}

	ebpf_warning("Tracer alloc failed.\n");

	return NULL;
}

static void free_bpf_tracer(struct bpf_tracer *t)
{
	ASSERT(tracers_lock[0]);

	memset((void *)t, 0, sizeof(*t));
	tracers_count--;
}

/*
 * Release the tracer resources.
 */
int release_bpf_tracer(const char *name)
{
	struct bpf_tracer *t;
	tracers_ctl_lock();
	if ((t = __find_bpf_tracer(name)) == NULL) {
		ebpf_warning("Tracer '%s', not existed.", name);
		tracers_ctl_unlock();
		return ETR_NOTEXIST;
	}

	/*
	 * Execute the resource release callback function of
	 * tracer to release the resources of a specific tracer.
	 */
	if (t->release_cb != NULL)
		t->release_cb(t);

	if (t->lock) {
		clib_mem_free((void *)t->lock);
		t->lock = NULL;
	}

	/* t->is_use set 0 */
	free_bpf_tracer(t);
	tracers_ctl_unlock();

	return ETR_OK;
}

/**
 * @brief Activate a tracer reader to start working.
 *
 * @param prefix_name Thread name prefix.
 * @param idx The index within the thread array.
 * @param tracer Activated tracer
 * @param fn callback for reader read ebpf ring-buffer data.
 * @return 0(ETR_OK) on success, < 0 on error
 */
int enable_tracer_reader_work(const char *prefix_name, int idx,
			      struct bpf_tracer *tracer, void *fn)
{
	int ret;
	char name[TASK_COMM_LEN];
	snprintf(name, sizeof(name), "%s-%d", prefix_name, idx);
	ret = pthread_create(&tracer->perf_workers[idx], NULL, fn,
			     (void *)(uint64_t) idx);
	if (ret) {
		ebpf_warning("tracer reader(%s), pthread_create "
			     "is error:%s\n", name, strerror(errno));
		return ETR_INVAL;
	}

	/* set thread name */
	pthread_setname_np(tracer->perf_workers[idx], name);

	/*
	 * Separating threads is to automatically release
	 * resources after pthread_exit(), without being
	 * blocked or stuck.
	 */
	ret = pthread_detach(tracer->perf_workers[idx]);
	if (ret != 0) {
		ebpf_warning("Error detaching thread, error:%s\n",
			     strerror(errno));
		return ETR_INVAL;
	} else {
		ebpf_info("thread %s, detached successful.", name);
	}

	return ETR_OK;
}

/**
 * @brief setup_bpf_tracer - create a eBPF tracer
 *
 * @param name Tracer name
 * @param load_name eBPF load buffer name
 * @param bpf_bin_buffer load eBPF buffer address
 * @param buffer_sz eBPF buffer size
 * @param tps Tracer configuration information
 * @param workers_nr How many threads process the queues
 * @param free_cb The callback interface for releasing tracer resources.
 * @param create_cb The callback interface for create tracer.
 * @param handle The upper callback function address
 * @param sample_freq sample frequency, Hertz. (e.g. 99 profile stack traces at 99 Hertz)
 * only type is TRACER_TYPE_PERF_EVENT.
 * @return struct bpf_tracer pointer on success, NULL otherwise.
 */
struct bpf_tracer *setup_bpf_tracer(const char *name,
				    char *load_name,
				    void *bpf_bin_buffer,
				    int buffer_sz,
				    struct tracer_probes_conf *tps,
				    int workers_nr,
				    tracer_op_fun_t free_cb,
				    tracer_op_fun_t create_cb,
				    void *handle, void
				    *profiler_callback_ctx[PROFILER_CTX_NUM],
				    int sample_freq)
{
	int ret;
	/*
	 * Protect the resources of the BPF tracer to avoid
	 * simultaneous operations on the tracer.
	 */
	tracers_ctl_lock();
	if (__find_bpf_tracer(name) != NULL) {
		ebpf_warning("Tracer '%s', already existed.", name);
		tracers_ctl_unlock();
		return NULL;
	}

	struct bpf_tracer *bt = alloc_bpf_tracer();
	if (bt == NULL) {
		ebpf_warning
		    ("Tracer '%s' alloc failed, current tracers count %d (limit %d)",
		     tracers_count, BPF_TRACER_NUM_MAX);
		tracers_ctl_unlock();
		return NULL;
	}
	snprintf(bt->name, sizeof(bt->name), "%s", name);
	bt->name[sizeof(bt->name) - 1] = '\0';
	atomic64_init(&bt->recv);
	atomic64_init(&bt->lost);
	atomic64_init(&bt->rx_pkts);
	atomic64_init(&bt->tx_pkts);
	atomic64_init(&bt->rx_bytes);
	atomic64_init(&bt->tx_bytes);
	atomic64_init(&bt->dropped_pkts);
	int i;
	for (i = 0; i < PROTO_NUM; i++)
		atomic64_init(&bt->proto_stats[i]);

	snprintf(bt->bpf_load_name, sizeof(bt->bpf_load_name), "%s", load_name);
	bt->bpf_load_name[sizeof(bt->bpf_load_name) - 1] = '\0';
	bt->tps = tps;
	bt->buffer_ptr = bpf_bin_buffer;
	bt->buffer_sz = buffer_sz;
	bt->state = TRACER_INIT;
	bt->release_cb = free_cb;
	bt->create_cb = create_cb;
	bt->sample_freq = sample_freq;
	bt->enable_sample = false;
	bt->ev_state = PERF_EV_INIT;

	bt->dispatch_workers_nr = workers_nr;
	bt->process_fn = handle;
	if (profiler_callback_ctx) {
		memcpy(bt->profiler_callback_ctx, profiler_callback_ctx,
		       PROFILER_CTX_NUM * sizeof(void *));
	}

	init_list_head(&bt->probes_head);
	init_list_head(&bt->maps_conf_head);

	pthread_mutex_init(&bt->mutex_probes_lock, NULL);
	bt->lock = clib_mem_alloc_aligned("tracer_lock", CLIB_CACHE_LINE_BYTES,
					  CLIB_CACHE_LINE_BYTES, NULL);
	if (bt->lock == NULL) {
		ebpf_warning("clib_mem_alloc_aligned() error\n");
		free_bpf_tracer(bt);
		tracers_ctl_unlock();
		return NULL;
	}
	bt->lock[0] = 0;

	/*
	 * Execute the create tracer callback function.
	 */
	if (bt->create_cb != NULL) {
		ret = bt->create_cb(bt);
		if (ret != ETR_OK) {
			free_bpf_tracer(bt);
			bt = NULL;
		}
	}

	tracers_ctl_unlock();

	return bt;
}

static inline struct bpf_perf_reader *alloc_reader(struct bpf_tracer *t)
{
	if (t->perf_readers_count >= PERF_READER_NUM_MAX) {
		ebpf_error("No available reader is free, current count %d"
			   " exceeds the maximum value %d.",
			   t->perf_readers_count, PERF_READER_NUM_MAX);
		return NULL;
	}

	int i;
	struct bpf_perf_reader *reader;
	for (i = 0; i < PERF_READER_NUM_MAX; i++) {
		reader = &t->readers[i];
		if (!reader->is_use) {
			reader->is_use = true;
			t->perf_readers_count++;
			return reader;
		}
	}

	return NULL;
}

static inline void free_reader(struct bpf_perf_reader *reader)
{
	reader->tracer->perf_readers_count--;
	memset(reader, 0, sizeof(*reader));
}

void free_all_readers(struct bpf_tracer *t)
{
	ASSERT(t != NULL);

	int i;
	struct bpf_perf_reader *reader;
	for (i = 0; i < PERF_READER_NUM_MAX; i++) {
		reader = &t->readers[i];
		if (reader->is_use) {
			free_perf_buffer_reader(reader);
		}
	}
}

/**
 * @brief create a perf buffer reader.
 * @param t Tracer address
 * @param The map_name Perf buffer map name
 * @param The raw_cb Perf reader raw data callback
 * @param Lost_cb perf reader data lost callback
 * @param Pages_cnt How many memory pages are used for ring-buffer
 *            (system page size * pages_cnt)
 * @param Thread_nr The number of threads required for the reader's work
 * @param Epoll_timeout perf epoll timeout
 * @return Perf_reader address on success, NULL on error
 */
struct bpf_perf_reader *create_perf_buffer_reader(struct bpf_tracer *t,
						  const char *map_name,
						  perf_reader_raw_cb raw_cb,
						  perf_reader_lost_cb lost_cb,
						  unsigned int pages_cnt,
						  int thread_nr,
						  int epoll_timeout)
{
	if (t == NULL || map_name == NULL || raw_cb == NULL || lost_cb == NULL) {
		ebpf_error("register_perf_buffer_reader() Invalid parameter."
			   "t %p map_name %s raw_cb %p lost_cb %p\n",
			   t, map_name, raw_cb, lost_cb);
		return NULL;
	}

	struct bpf_perf_reader *reader = alloc_reader(t);
	if (reader == NULL)
		return NULL;

	strncpy(reader->name, map_name, sizeof(reader->name));
	reader->name[sizeof(reader->name) - 1] = '\0';

	reader->raw_cb = raw_cb;
	reader->lost_cb = lost_cb;
	if (pages_cnt <= 0)
		pages_cnt = BPF_PERF_READER_PAGE_CNT;
	else
		pages_cnt = 1 << min_log2((unsigned int)pages_cnt);

	reader->tracer = t;
	reader->perf_pages_cnt = pages_cnt;
	reader->epoll_timeout = epoll_timeout;

	if (perf_reader_setup(reader, thread_nr))
		goto failed;

	return reader;

failed:
	free_reader(reader);
	return NULL;
}

void free_perf_buffer_reader(struct bpf_perf_reader *reader)
{
	perf_reader_release(reader);
	free_reader(reader);
}

static int map_resize_set(struct ebpf_object *obj, struct map_config *m_conf)
{
	struct ebpf_map *map = ebpf_obj__get_map_by_name(obj, m_conf->map_name);
	if (!map) {
		ebpf_info("failed to find \"%s\" map.\n", m_conf->map_name);
		return ETR_NOTEXIST;
	}

	ebpf_info("Update map (\"%s\"), set max_entries %d\n", m_conf->map_name,
		  m_conf->max_entries);

	return ebpf_map_size_adjust(map, m_conf->max_entries);
}

struct ebpf_object *create_ebpf_object(const void *bpf_code,
				       size_t code_size, const char *name)
{
	struct ebpf_object *obj;
	obj = ebpf_open_buffer(bpf_code, code_size, name);
	if (IS_NULL(obj)) {
		ebpf_warning("ebpf_open_buffer() \"%s\" failed, error:%s\n",
			     name, strerror(errno));
		return NULL;
	}

	return obj;
}

int load_ebpf_object(struct ebpf_object *obj)
{
	int ret = ebpf_obj_load(obj);
	if (ret != 0) {
		ebpf_warning("bpf load '%s' failed, error:%s (%d).\n",
			     obj->name, strerror(errno), errno);
		if (!strcmp(obj->name, "socket-trace-bpf-linux-kfunc")) {
			ebpf_info("Try other eBPF bytecode binaries ...\n");
			release_object(obj);
			return ret;
		}

		if (errno == EACCES) {
			ebpf_warning
			    ("Check the selinux status, if found SELinux"
			     " 'status: enabled' and 'Current mode:"
			     "enforcing', please try the following way "
			     "to solve:\n" "1 Create file 'deepflow-agent.te',"
			     "contents:\n\n" "module deepflow-agent 1.0;\n"
			     "require {\n" "  type container_runtime_t;\n"
			     "  class bpf { map_create map_read "
			     "map_write prog_load prog_run };\n"
			     "}\nallow container_runtime_t self:"
			     "bpf { map_create map_read map_write "
			     "prog_load prog_run };\n\n"
			     "2 checkmodule -M -m -o deepflow-agent.mod"
			     " deepflow-agent.te\n"
			     "3 semodule_package -o deepflow-agent.pp "
			     "-m deepflow-agent.mod\n"
			     "4 semodule -i deepflow-agent.pp\n"
			     "5 restart pods\n");
		}

		ebpf_warning("eBPF load failed, If you want to run normally, "
			     "you can disable the eBPF feature.\n");
		release_object(obj);
	}

	return ret;
}

int tracer_bpf_load(struct bpf_tracer *tracer)
{
	struct ebpf_object *obj;
	int ret;
	obj = create_ebpf_object(tracer->buffer_ptr,
				 tracer->buffer_sz, tracer->bpf_load_name);
	if (IS_NULL(obj)) {
		return ETR_INVAL;
	}

	struct map_config *m_conf;
	list_for_each_entry(m_conf, &tracer->maps_conf_head, list) {
		if ((ret = map_resize_set(obj, m_conf)))
			return ret;
	}

	ret = load_ebpf_object(obj);
	if (ret != 0) {
		return ret;
	}

	tracer->obj = obj;
	ebpf_info("bpf load \"%s\" succeed.\n", obj->name);
	return ETR_OK;
}

static struct tracepoint *find_tracepoint_from_name(struct bpf_tracer *tracer,
						    const char *tp_name)
{
	struct tracepoint *p;
	int i;
	for (i = 0; i < PROBES_NUM_MAX; i++) {
		p = &tracer->tracepoints[i];
		if (!strcmp(p->name, tp_name))
			return p;
	}

	return NULL;
}

static struct kfunc *find_kfunc_from_name(struct bpf_tracer *tracer,
					  const char *name)
{
	struct kfunc *p;
	int i;
	for (i = 0; i < PROBES_NUM_MAX; i++) {
		p = &tracer->kfuncs[i];
		if (!strcmp(p->name, name))
			return p;
	}

	return NULL;
}

static struct tracepoint *get_tracepoint_from_tracer(struct bpf_tracer *tracer,
						     const char *tp_name)
{
	struct tracepoint *tp = find_tracepoint_from_name(tracer, tp_name);
	if (tp && tp->prog)
		return tp;

	struct ebpf_prog *prog;
	int fd = bpf_get_program_fd(tracer->obj, tp_name, (void **)&prog);
	if (fd < 0) {
		ebpf_info
		    ("fun: %s, bpf_get_program_fd failed, tracepoint_name:%s.\n",
		     __func__, tp_name);
		return NULL;
	}

	int idx = tracer->tracepoints_count++;
	tp = &tracer->tracepoints[idx];
	tp->prog_fd = fd;
	tp->prog = prog;

	snprintf(tp->name, sizeof(tp->name), "%s", tp_name);

	return tp;
}

static struct kfunc *get_kfunc_from_tracer(struct bpf_tracer *tracer,
					   const char *name)
{
	struct kfunc *p = find_kfunc_from_name(tracer, name);
	if (p && p->prog)
		return p;

	struct ebpf_prog *prog;
	int fd = bpf_get_program_fd(tracer->obj, name, (void **)&prog);
	if (fd < 0) {
		ebpf_info
		    ("fun: %s, bpf_get_program_fd failed, tracepoint_name:%s.\n",
		     __func__, name);
		return NULL;
	}

	int idx = tracer->kfuncs_count++;
	p = &tracer->kfuncs[idx];
	p->prog_fd = fd;
	p->prog = prog;

	snprintf(p->name, sizeof(p->name), "%s", name);

	return p;
}

void add_probe_to_tracer(struct probe *pb)
{
	struct bpf_tracer *tracer = pb->tracer;
	if (pb->type == UPROBE && pb->private_data != NULL)
		((struct symbol_uprobe *)pb->private_data)->in_probe = true;

	list_add_tail(&pb->list, &tracer->probes_head);
	tracer->probes_count++;
}

void free_probe_from_tracer(struct probe *pb)
{
	struct bpf_tracer *tracer = pb->tracer;
	if (pb->type == UPROBE && pb->private_data != NULL) {
		struct symbol_uprobe *sym_u = pb->private_data;
		free_uprobe_symbol(sym_u, tracer->tps);
	}

	list_head_del(&pb->list);
	tracer->probes_count--;
	free(pb);
}

void free_probe_from_conf(struct probe *pb, struct tracer_probes_conf *conf)
{
	if (pb->type == UPROBE && pb->private_data != NULL) {
		struct symbol_uprobe *sym_u = pb->private_data;
		free_uprobe_symbol(sym_u, conf);
	}

	list_head_del(&pb->list);
	free(pb);
}

struct probe *create_probe(struct bpf_tracer *tracer,
			   const char *func_name, bool isret,
			   enum probe_type type, void *private, bool add_tracer)
{
	struct probe *pb;
	struct ebpf_prog *prog;
	char find_name[PROBE_NAME_SZ], *isra_p;
	snprintf(find_name, sizeof(find_name), "%s", func_name);
	/*
	 * If the kernel compilation optimizes hook point names to forms
	 * like 'xxx.isra.0', while our eBPF program defines interface names
	 * without the 'isra.0' suffix, the following handling is required
	 * during the query process.
	 */
	if ((isra_p = strstr(find_name, ".isra")))
		*isra_p = '\0';

	int fd = bpf_get_program_fd(tracer->obj, find_name, (void **)&prog);
	if (fd < 0) {
		ebpf_warning
		    ("fun: %s, bpf_get_program_fd failed, find_name:%s.\n",
		     __func__, find_name);
		return NULL;
	}

	pb = calloc(1, sizeof(*pb));
	if (pb == NULL) {
		ebpf_warning("probe alloc failed, no memory\n");
		return NULL;
	}

	pb->prog_fd = fd;
	pb->prog = prog;
	pb->isret = isret;
	pb->type = type;
	pb->installed = false;
	snprintf(pb->name, sizeof(pb->name), "%s", func_name);
	pb->private_data = private;
	pb->tracer = tracer;

	/*
	 * Some features' eBPF tracing interfaces require independent management
	 * and do not need to be included in the unified management of the tracer.
	 */
	if (add_tracer)
		add_probe_to_tracer(pb);

	return pb;
}

static int get_uprobe_event_name(const char *bin_path, char *ev_name, int size,
				 size_t addr, bool isret)
{
	char *path = strdup(bin_path);
	if (path == NULL) {
		ebpf_warning("strdup error.\n");
		return ETR_INVAL;
	}

	int i;
	for (i = 0; i < strlen(path); i++) {
		// TODO: regexp.MustCompile("[^a-zA-Z0-9_]")
		if (path[i] == '/' || path[i] == '-')
			path[i] = '_';
	}

	if (snprintf(ev_name, size, "%s_%s_0x%lx", isret ? "r" : "p",
		     path, addr) < 0) {
		ebpf_warning("snprintf error.\n");
		return ETR_INVAL;
	}

	free(path);
	return ETR_OK;
}

static struct ebpf_link *exec_attach_uprobe(struct ebpf_prog *prog,
					    const char *bin_path, size_t addr,
					    bool isret, int pid)
{
	struct ebpf_link *link = NULL;
	char ev_name[EV_NAME_SIZE];
	int ret;
	ret = get_uprobe_event_name(bin_path, ev_name, sizeof(ev_name), addr,
				    isret);
	if (ret != ETR_OK)
		return NULL;

	char c_id[65];
	memset(c_id, 0, sizeof(c_id));
	fetch_container_id_from_proc(pid, c_id, sizeof(c_id));
	const char *container_flag = "false";
	if (strlen(c_id) > 0)
		container_flag = "true";

	ret = program__attach_uprobe(prog, isret, pid, bin_path, addr, ev_name,
				     (void **)&link);
	if (ret != 0) {
		const char *reason = "";
		if (strstr(ev_name, "libssl")) {
			reason = "It may be due to a low Linux kernel version. "
			    "When hooking containerized OpenSSL-related "
			    "library files, the required version is Linux 4.17+.";
		} else {
			reason = "Requires kernel version Linux 4.16+";
		}

		ebpf_warning
		    ("program__attach_uprobe failed, container %s ev_name:%s, %s\n",
		     container_flag, ev_name, reason);
	}

	return link;
}

static struct ebpf_link *exec_attach_kprobe(struct ebpf_prog *prog, char *name,
					    bool isret, int pid)
{
	struct ebpf_link *link = NULL;
	char ev_name[EV_NAME_SIZE];
	char *fn_name;
	int ret;
	if (isret)
		fn_name = name + strlen("kretprobe/");
	else
		fn_name = name + strlen("kprobe/");

	snprintf(ev_name, sizeof(ev_name), "%s_deepflow_%s", isret ? "r" : "p",
		 fn_name);
	ret =
	    program__attach_kprobe(prog, isret, pid, fn_name, ev_name,
				   (void **)&link);
	if (ret != 0) {
		ebpf_warning
		    ("program__attach_kprobe failed, ev_name:%s.\n", ev_name);
		__sync_fetch_and_add(&attach_failed_count, 1);
	}

	return link;
}

int probe_attach(struct probe *p)
{
	if (p->link || p->installed) {
		return ETR_EXIST;
	}

	struct ebpf_link *link = NULL;
	if (p->type == KPROBE) {
		link = exec_attach_kprobe(p->prog, p->name, p->isret, -1);
	} else {		/* UPROBE */
		struct symbol_uprobe *usym = p->private_data;
		if (usym == NULL) {
			ebpf_warning("probe private_data is NULL.\n");
			return ETR_INVAL;
		}

		if (!usym->binary_path || !usym->probe_func || !usym->entry
		    || !usym->size) {
			ebpf_warning("probe is invalid.\n");
			return ETR_INVAL;
		}

		bool ret = usym->isret;
		if (usym->type == GO_UPROBE && usym->isret)
			ret = false;

		link = exec_attach_uprobe(p->prog, usym->binary_path,
					  usym->entry, ret, usym->pid);
	}

	p->link = link;
	if (link == NULL)
		return ETR_INVAL;

	p->installed = true;
	return ETR_OK;
}

static int exec_detach_kprobe(struct ebpf_link *link, char *name, bool isret)
{
	char ev_name[EV_NAME_SIZE];
	char *fn_name;
	if (isret)
		fn_name = name + strlen("kretprobe/");
	else
		fn_name = name + strlen("kprobe/");

	snprintf(ev_name, sizeof(ev_name), "p_%s", fn_name);
	return program__detach_probe(link, isret, ev_name, "kprobe");
}

static int exec_detach_uprobe(struct ebpf_link *link, const char *bin_path,
			      size_t addr, bool isret)
{
	char ev_name[EV_NAME_SIZE];
	int ret;
	ret = get_uprobe_event_name(bin_path, ev_name, sizeof(ev_name), addr,
				    isret);
	if (ret != ETR_OK)
		return ret;

	return program__detach_probe(link, isret, ev_name, "uprobe");
}

/**
 * probe_detach - eBPF probe detach
 * @p struct probe
 *
 * @return 0 if ok, not 0 on error
 */
int probe_detach(struct probe *p)
{
	int ret = 0;
	if (!p->installed) {
		return ETR_NOTEXIST;
	}

	if (p->type == KPROBE) {
		if ((ret = exec_detach_kprobe(p->link, p->name, p->isret)) == 0)
			p->link = NULL;
	} else {		/* UPROBE */
		struct symbol_uprobe *usym = p->private_data;
		bool isret = usym->isret;
		if (usym->type == GO_UPROBE && usym->isret)
			isret = false;

		if ((ret =
		     exec_detach_uprobe(p->link, usym->binary_path, usym->entry,
					isret)) == 0)
			p->link = NULL;
	}

	if (ret == 0)
		p->installed = false;

	return ret;
}

static int tracepoint_attach(struct tracepoint *tp)
{
	if (tp->link) {
		return ETR_EXIST;
	}

	struct ebpf_link *bl = program__attach_tracepoint(tp->prog);
	tp->link = bl;

	if (bl == NULL) {
		ebpf_warning("program__attach_tracepoint() failed, name:%s.\n",
			     tp->name);
		__sync_fetch_and_add(&attach_failed_count, 1);
		return ETR_INVAL;
	}

	return ETR_OK;
}

static int tracepoint_detach(struct tracepoint *tp)
{
	if (tp->link == NULL) {
		return ETR_NOTEXIST;
	}

	if (tp->link->detach) {
		tp->link->detach(tp->link);
	}

	free(tp->link);
	tp->link = NULL;
	return ETR_OK;
}

static int kfunc_attach(struct kfunc *p)
{
	if (p->link) {
		return ETR_EXIST;
	}

	if (p->prog->prog_fd == 0)
		p->prog->prog_fd = load_ebpf_prog(p->prog);

	struct ebpf_link *bl = program__attach_kfunc(p->prog);
	p->link = bl;

	if (bl == NULL) {
		ebpf_warning("program__attach_tracepoint() failed, name:%s.\n",
			     p->name);
		__sync_fetch_and_add(&attach_failed_count, 1);
		return ETR_INVAL;
	}

	return ETR_OK;
}

static int kfunc_detach(struct kfunc *p)
{
	if (p->link == NULL) {
		return ETR_NOTEXIST;
	}

	if (p->prog->prog_fd > 0) {
		close(p->prog->prog_fd);
		p->prog->prog_fd = 0;
	}

	if (p->link->detach) {
		p->link->detach(p->link);
	}

	free(p->link);
	p->link = NULL;
	return ETR_OK;
}

int tracer_hooks_process(struct bpf_tracer *tracer, enum tracer_hook_type type,
			 int *probes_count)
{
	int (*probe_handle) (struct probe * p) = NULL;
	int (*tracepoint_handle) (struct tracepoint * p) = NULL;
	int (*kfunc_handle) (struct kfunc * p) = NULL;

	if (type == HOOK_ATTACH) {
		probe_handle = probe_attach;
		tracepoint_handle = tracepoint_attach;
		kfunc_handle = kfunc_attach;
	} else if (type == HOOK_DETACH) {
		probe_handle = probe_detach;
		tracepoint_handle = tracepoint_detach;
		kfunc_handle = kfunc_detach;
	} else
		return ETR_INVAL;

	if (tracer->obj == NULL) {
		ebpf_info("fun: %s, not loaded bpf program yet.\n", __func__);
		return ETR_INVAL;
	}

	struct probe *p;
	int error, count = 0;
	struct list_head *c, *n;

	list_for_each_safe(c, n, &tracer->probes_head) {
		p = container_of(c, struct probe, list);
		if (!p)
			return ETR_INVAL;

		if (tracer->probes_count > OPEN_FILES_MAX) {
			ebpf_warning
			    ("Probes count too many. The maximum is %d\n",
			     OPEN_FILES_MAX);
			break;
		}

		error = probe_handle(p);
		if (type == HOOK_ATTACH && error == ETR_EXIST)
			continue;

		if (type == HOOK_DETACH && error == ETR_NOTEXIST)
			continue;

		if (p->type == KPROBE) {
			ebpf_info("%s %s %s: '%s', %s!",
				  type == HOOK_ATTACH ? "attach" : "detach",
				  p->isret ? "exit" : "enter",
				  p->type == KPROBE ? "kprobe" : "uprobe",
				  p->name, error ? "failed" : "success");
		}

		if (error) {
			free_probe_from_tracer(p);
			continue;
		}

		count++;
	}

	if (probes_count != NULL)
		*probes_count = count;

	struct tracepoint *tp;
	int i;
	struct tracer_probes_conf *tps = tracer->tps;
	if (tps == NULL)
		goto perf_event;

	for (i = 0; i < tps->tps_nr; i++) {
		tp = get_tracepoint_from_tracer(tracer, tps->tps[i].name);
		if (!tp)
			return ETR_INVAL;

		error = tracepoint_handle(tp);
		if (type == HOOK_ATTACH && error == ETR_EXIST)
			continue;

		if (type == HOOK_DETACH && error == ETR_NOTEXIST)
			continue;

		if (error) {
			ebpf_info("%s tracepoint: '%s', failed!",
				  type == HOOK_ATTACH ? "attach" : "detach",
				  tp->name);
			return ETR_INVAL;
		} else
			ebpf_info("%s tracepoint: '%s', succeed!",
				  type == HOOK_ATTACH ? "attach" : "detach",
				  tp->name);
	}

	struct kfunc *kf;
	for (i = 0; i < tps->kfuncs_nr; i++) {
		kf = get_kfunc_from_tracer(tracer, tps->kfuncs[i].name);
		if (!kf)
			return ETR_INVAL;

		error = kfunc_handle(kf);
		if (type == HOOK_ATTACH && error == ETR_EXIST)
			continue;

		if (type == HOOK_DETACH && error == ETR_NOTEXIST)
			continue;

		if (error) {
			ebpf_info("%s kfunc: '%s', failed!",
				  type == HOOK_ATTACH ? "attach" : "detach",
				  kf->name);
			return ETR_INVAL;
		} else
			ebpf_info("%s kfunc: '%s', succeed!",
				  type == HOOK_ATTACH ? "attach" : "detach",
				  kf->name);
	}

perf_event:

	if (!tracer->enable_sample)
		return ETR_OK;

	/*
	 * perf event
	 */
	if (type == HOOK_ATTACH) {
		if (tracer->ev_state == PERF_EV_ATTACH)
			return ETR_OK;
		struct ebpf_object *obj = tracer->obj;
		for (i = 0; i < obj->progs_cnt; i++) {
			if (obj->progs[i].type == BPF_PROG_TYPE_PERF_EVENT) {
				errno = 0;
				int ret =
				    program__attach_perf_event(obj->progs[i].
							       prog_fd,
							       PERF_TYPE_SOFTWARE,
							       PERF_COUNT_SW_CPU_CLOCK,
							       0,	/* sample_period */
							       tracer->
							       sample_freq,
							       -1,	/* pid, current process */
							       -1,	/* cpu, no binding */
							       -1,	/* new event group is created */
							       tracer->
							       per_cpu_fds,
							       ARRAY_SIZE
							       (tracer->
								per_cpu_fds));
				if (!ret) {
					ebpf_info
					    ("tracer \"%s\" attach perf event prog successful.\n",
					     tracer->name);
				} else {
					ebpf_warning
					    ("tracer \"%s\" attach perf event prog, failed (%s).\n",
					     tracer->name, strerror(errno));

				}

				tracer->ev_state = PERF_EV_ATTACH;
				return ret;
			}
		}
	} else {
		if (tracer->ev_state == PERF_EV_DETACH)
			return ETR_OK;
		bool has_perf_event = false;
		for (i = 0; i < ARRAY_SIZE(tracer->per_cpu_fds); i++) {
			if (tracer->per_cpu_fds[i] > 0) {
				has_perf_event = true;
				break;
			}
		}

		if (has_perf_event) {
			errno = 0;
			int ret =
			    program__detach_perf_event(tracer->per_cpu_fds,
						       ARRAY_SIZE
						       (tracer->per_cpu_fds));
			if (!ret) {
				ebpf_info
				    ("tracer \"%s\" detach perf event prog successful.\n",
				     tracer->name);
			} else {
				ebpf_warning
				    ("tracer \"%s\" detach perf event prog, failed (%s).\n",
				     tracer->name, strerror(errno));

			}

			tracer->ev_state = PERF_EV_DETACH;
			return ret;
		}
	}

	return ETR_OK;
}

int tracer_probes_init(struct bpf_tracer *tracer)
{
	struct probe *p;
	struct tracer_probes_conf *tps;
	int i;
	struct symbol_uprobe *usym;

	if (!tracer) {
		ebpf_warning("tracer_probes_init failed, tracer is NULL\n");
		return ETR_INVAL;
	}

	tps = tracer->tps;
	if (!tps) {
		ebpf_warning("tracer_probes_init failed, tps is NULL\n");
		return ETR_INVAL;
	}

	for (i = 0; i < tps->kprobes_nr; ++i) {
		p = create_probe(tracer, tps->ksymbols[i].func,
				 tps->ksymbols[i].isret, KPROBE, NULL, true);
		if (!p)
			return ETR_INVAL;
	}

	list_for_each_entry(usym, &tps->uprobe_syms_head, list) {
		p = create_probe(tracer, usym->probe_func, usym->isret, UPROBE,
				 usym, true);
		if (!p)
			return ETR_INVAL;
	}

	return 0;
}

int tracer_uprobes_update(struct bpf_tracer *tracer)
{
	struct probe *p;
	struct tracer_probes_conf *tps;
	struct symbol_uprobe *usym;

	if (!tracer) {
		ebpf_warning("tracer_probes_update failed, tracer is NULL\n");
		return ETR_INVAL;
	}

	tps = tracer->tps;
	if (!tps) {
		ebpf_warning("tracer_probes_update failed, tps is NULL\n");
		return ETR_INVAL;
	}

	list_for_each_entry(usym, &tps->uprobe_syms_head, list) {
		if (usym->in_probe)
			continue;
		p = create_probe(tracer, usym->probe_func, usym->isret, UPROBE,
				 usym, true);
		if (!p)
			return ETR_INVAL;
	}

	return 0;
}

int tracer_hooks_attach(struct bpf_tracer *tracer)
{
	int ret;
	ebpf_info("tracer(%s) attach ...\n", tracer->name);
	ret = tracer_hooks_process(tracer, HOOK_ATTACH, NULL);
	if (ret) {
		ebpf_warning("Not finish attach, tracer name %s\n",
			     tracer->name);
		return (-1);
	}

	ebpf_info("Successfully completed attach.\n");
	return (0);
}

int tracer_hooks_detach(struct bpf_tracer *tracer)
{
	int ret;
	ebpf_info("tracer(%s) detach ...\n", tracer->name);
	ret = tracer_hooks_process(tracer, HOOK_DETACH, NULL);
	if (ret) {
		ebpf_warning("Not finish detach, tracer name : %s\n",
			     tracer->name);
		return (-1);
	}

	ebpf_info("Successfully completed detach.\n");
	return (0);
}

static void perf_reader_release(struct bpf_perf_reader *perf_reader)
{
	int i;
	for (i = 0; i < perf_reader->readers_count; i++) {
		perf_reader_free(perf_reader->readers[i]);
	}

	ebpf_info("bpf_perf_reader %s release.\n", perf_reader->name);
}

static int perf_reader_setup(struct bpf_perf_reader *perf_reader, int thread_nr)
{
	ASSERT(perf_reader != NULL);

	int i;
	struct ebpf_map *map =
	    ebpf_obj__get_map_by_name(perf_reader->tracer->obj,
				      (const char *)perf_reader->name);

	int map_fd = map->fd;
	void *reader;
	int perf_fd, ret;
	int reader_idx;
	int pages_cnt = perf_reader->perf_pages_cnt;

	for (i = 0; i < thread_nr; i++) {
		perf_reader->epoll_fds[i] = epoll_create1(0);
		if (perf_reader->epoll_fds[i] == -1) {
			ebpf_error("epoll_create1(0) failed.\n");
			return ETR_EPOLL;
		}
	}

	perf_reader->epoll_fds_count = thread_nr;

	struct epoll_event event;
	uint64_t spread_id = 0;	// Used for spreading across different epoll_fds.
	for (i = 0; i < sys_cpus_count; i++) {
		if (!cpu_online[i])
			continue;

		if (spread_id >= perf_reader->epoll_fds_count)
			spread_id = 0;

		struct reader_forward_info *fwd_info =
		    malloc(sizeof(struct reader_forward_info));
		if (fwd_info == NULL) {
			ebpf_error("reader_forward_info malloc() failed.\n");
			return ETR_NOMEM;
		}

		fwd_info->queue_id = spread_id;
		fwd_info->cpu_id = i;
		fwd_info->tracer = perf_reader->tracer;

		ebpf_debug("Perf buffer reader cpu(%d) -> queue(%d)\n",
			   fwd_info->cpu_id, fwd_info->queue_id);
		reader = (struct perf_reader *)
		    bpf_open_perf_buffer(perf_reader->raw_cb,
					 perf_reader->lost_cb,
					 (void *)fwd_info, -1, i, pages_cnt);
		if (reader == NULL) {
			ebpf_error("bpf_open_perf_buffer() failed.\n");
			return ETR_NORESOURCE;
		}

		perf_fd = perf_reader_fd(reader);
		ASSERT(perf_fd >= 3);

		if ((ret = bpf_update_elem(map_fd, &i, &perf_fd, BPF_ANY))) {
			ebpf_info
			    ("fun: %s, bpf_map_update_elem reader setting failed.\n",
			     __func__);
			return ret;
		}

		reader_idx = perf_reader->readers_count++;
		perf_reader->reader_fds[reader_idx] = perf_fd;
		perf_reader->readers[reader_idx] = reader;
		event.data.ptr = reader;
		event.events = EPOLLIN;

		if (epoll_ctl
		    (perf_reader->epoll_fds[spread_id++], EPOLL_CTL_ADD,
		     perf_fd, &event) == -1) {
			ebpf_error("epoll_ctl()");
			return ETR_EPOLL;
		}
	}

	perf_reader->map = map;

	return ETR_OK;
}

static void extra_waiting_process(int type)
{
	struct extra_waiting_op *ewo;
	list_for_each_entry(ewo, &extra_waiting_head, list) {
		if (ewo->type == type)
			ewo->f();
	}
}

int register_extra_waiting_op(const char *name, extra_waiting_fun_t f, int type)
{
	struct extra_waiting_op *ewo = malloc(sizeof(struct extra_waiting_op));
	if (!ewo) {
		ebpf_warning("malloc() failed, no memory.\n");
		return -ENOMEM;
	}
	ewo->f = f;
	ewo->type = type;
	snprintf(ewo->name, sizeof(ewo->name), "%s", name);
	list_add_tail(&ewo->list, &extra_waiting_head);

	ebpf_info("%s '%s' succeed.\n", __func__, name);

	return ETR_OK;
}

// Receive command line management tool requests.
static void ctrl_main(__unused void *arg)
{
	prctl(PR_SET_NAME, "ctrl-main");
	while (all_probes_ready == 0)
		usleep(LOOP_DELAY_US);

	ebpf_info("ctrl_main begin !!!\n");

	bool one = true;
	for (;;) {
		RUN_ONCE(one, extra_waiting_process, EXTRA_TYPE_SERVER);
		sockopt_ctl(NULL);
	}

	/* never reached */
	/* pthread_exit(NULL); */
	/* return NULL; */
}

// Periodic event handling
static void period_events_process(void)
{
	period_event_ticks++;
	struct period_event_op *peo;
	list_for_each_entry(peo, &period_events_head, list) {
		if (peo->is_valid) {
			if ((period_event_ticks % peo->times) == 0) {
				peo->f();
			}
		}
	}
}

static struct period_event_op *find_period_event(const char *name)
{
	struct period_event_op *peo = NULL;
	list_for_each_entry(peo, &period_events_head, list) {
		if (strcmp(peo->name, name) == 0)
			return peo;
	}

	return NULL;
}

/*
 * Register for periodic execution events.
 * @name event name
 * @f Event execution callback interface
 * @period_time The event execution cycle time, unit is milliseconds
 * 
 * @return
 *    ETR_OK(0) on success, < 0 on error 
 */
int register_period_event_op(const char *name,
			     period_event_fun_t f, uint32_t period_time)
{
	struct period_event_op *peo = malloc(sizeof(struct period_event_op));
	if (!peo) {
		ebpf_warning("malloc() failed, no memory.\n");
		return -ENOMEM;
	}

	peo->f = f;
	peo->is_valid = true;
	peo->times = period_time;
	snprintf(peo->name, sizeof(peo->name), "%s", name);
	list_add_tail(&peo->list, &period_events_head);

	ebpf_info("%s '%s' succeed.\n", __func__, name);

	return ETR_OK;
}

int set_period_event_invalid(const char *name)
{
	struct period_event_op *peo = find_period_event(name);
	if (peo == NULL)
		return ETR_INVAL;

	peo->is_valid = false;

	ebpf_info("%s '%s' set invalid succeed.\n", __func__, name);

	return ETR_OK;
}

static inline void cpu_ebpf_data_timeout_check(int cpu_id)
{
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(cpu_id, &cpuset);
	if (-1 ==
	    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset)) {
		return;
	}

	if (all_probes_ready)
		RUN_ONCE(ready_flag_cpus[cpu_id], extra_waiting_process,
			 EXTRA_TYPE_CLIENT);
}

static int trigger_kern_adapt(void)
{
	int i;
	for (i = 0; i < sys_cpus_count; i++) {
		if (cpu_online[i])
			cpu_ebpf_data_timeout_check(i);
	}

	return ETR_OK;
}

/*
 * 对系统的启动时间（精度为纳秒）做周期性更新
 */
static int boot_time_update(void)
{
	prev_sys_boot_time_ns = sys_boot_time_ns;
	uint64_t real_time, monotonic_time;
	real_time = gettime(CLOCK_REALTIME, TIME_TYPE_NAN);
	monotonic_time = gettime(CLOCK_MONOTONIC, TIME_TYPE_NAN);
	sys_boot_time_ns = real_time - monotonic_time;

	return ETR_OK;
}

/* 
 * Thread function to periodically trigger a kernel-related action.
 *
 * The kernel uses bundled bursts to send data to the user.  
 * The following method triggers a timeout check on all CPUs  
 * to push data residing in the eBPF buffer.
 */
static void *kick_kern_push_data(void *arg)
{
	int cpu_id = (int)((uintptr_t) arg);	// Extract CPU ID from the argument
	char thread_name[NAME_LEN];

	// Set a descriptive thread name
	snprintf(thread_name, sizeof(thread_name), "kick-kern.%d", cpu_id);
	prctl(PR_SET_NAME, thread_name);
	pid_t tid = syscall(SYS_gettid);
	kick_threads[cpu_id].tid = tid;
	kick_threads[cpu_id].cpu_id = cpu_id;
	int tfd = -1, epfd = -1;
	cpu_set_t cpuset;

retry_bind:
	// Set CPU affinity for the thread
	CPU_ZERO(&cpuset);
	CPU_SET(cpu_id, &cpuset);
	if (pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset) !=
	    0) {
		ebpf_warning("Kick thread %d failed to bind to CPU %d.\n", tid, cpu_id);
		goto error;
	}

	ebpf_info("Kick thread %d successfully bound to CPU %d.\n", tid, cpu_id);
	AO_SET(&kick_threads[cpu_id].can_bind_cpu, true);
	// Create a timerfd for periodic notifications
	tfd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (tfd == -1) {
		ebpf_warning("timerfd_create failed: %s(%d)\n", strerror(errno),
			     errno);
		goto error;
	}

	struct itimerspec timer_spec = {
		.it_interval = {.tv_sec = 0,.tv_nsec = KICK_KERN_PERIOD},
		.it_value = {.tv_sec = 0,.tv_nsec = KICK_KERN_PERIOD}
	};

	if (timerfd_settime(tfd, 0, &timer_spec, NULL) == -1) {
		ebpf_warning("timerfd_settime failed: %s(%d)\n",
			     strerror(errno), errno);
		goto error;
	}
	// Create epoll instance and add timerfd
	epfd = epoll_create1(0);
	if (epfd == -1) {
		ebpf_warning("epoll_create1 failed: %s(%d)\n", strerror(errno),
			     errno);
		goto error;
	}

	struct epoll_event ev = {
		.events = EPOLLIN,
		.data.fd = tfd
	};

	if (epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &ev) == -1) {
		ebpf_warning("epoll_ctl failed: %s(%d)\n", strerror(errno),
			     errno);
		goto error;
	}

	struct epoll_event events[1];
	ssize_t ret;

	for (;;) {
		int nfds = epoll_wait(epfd, events, 1, -1);
		if (nfds > 0 && events[0].data.fd == tfd) {
			uint64_t expirations;
			while (1) {
				ret =
				    read(tfd, &expirations,
					 sizeof(expirations));
				if (ret == -1) {
					if (errno == EINTR || errno == EAGAIN
					    || errno == EWOULDBLOCK) {
						continue;
					} else {
						ebpf_warning
						    ("read from timerfd failed: %s(%d)\n",
						     strerror(errno), errno);
						goto error;
					}
				}
				break;
			}

			if (ret != sizeof(expirations)) {
				ebpf_warning("Kick kernel timer read error.\n");
				goto error;
			}

			syscall(__NR_getppid);	// Trigger a kernel-related action (sample action)
		}
	}

error:
	AO_SET(&kick_threads[cpu_id].can_bind_cpu, false);
	if (tfd > 0)
		close(tfd);
	if (epfd > 0)
		close(epfd);

	for(;;) {
		sleep(KICK_BIND_RETRY_WAIT_SECS);
		if (AO_GET(&kick_threads[cpu_id].can_bind_cpu))
			goto retry_bind;
	}

	pthread_exit(NULL);
}

static void period_process_main(__unused void *arg)
{
	prctl(PR_SET_NAME, "period-process");
	pthread_t threads[sys_cpus_count];
	int i;
	for (i = 0; i < sys_cpus_count; i++) {
		if (cpu_online[i])
			if (pthread_create
			    (&threads[i], NULL, kick_kern_push_data,
			     (void *)(uintptr_t) i) != 0) {
				ebpf_warning("pthread_create failed");
			}
	}

	// Only this unique identifier can be adapted to the kernel
	adapt_kern_uid =
	    (uint64_t) getpid() << 32 | (uint32_t) syscall(__NR_gettid);

	// Ensure all tracers have run, then trigger the kernel adaptation operation
	while (all_probes_ready == 0)
		usleep(LOOP_DELAY_US);

	// Ensure the extra_waiting_process of the server type executes first.
	sleep(1);

	ebpf_info("cpus_kick begin !!!\n");

	memset((void *)ready_flag_cpus, 1, sizeof(ready_flag_cpus));

	for (;;) {
		period_events_process();
		usleep(EVENT_TIMER_TICK_US);
	}
}

int maps_config(struct bpf_tracer *tracer, const char *map_name, int entries)
{
	struct map_config *map_conf = calloc(1, sizeof(struct map_config));
	if (map_conf == NULL)
		return -ENOMEM;

	snprintf(map_conf->map_name, sizeof(map_conf->map_name), map_name);
	map_conf->max_entries = entries;
	list_add_tail(&map_conf->list, &tracer->maps_conf_head);

	return ETR_OK;
}

/*
 * control plane
 */
static int tracer_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
	return ETR_OK;
}

static int tracer_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
			      void **out, size_t * outsize)
{
	*outsize = sizeof(struct bpf_tracer_param_array) +
	    sizeof(struct bpf_tracer_param) * tracers_count;

	*out = calloc(1, *outsize);
	if (*out == NULL) {
		ebpf_info("%s calloc, error:%s\n", __func__, strerror(errno));
		return ETR_INVAL;
	}

	struct bpf_tracer_param_array *array = *out;
	array->count = tracers_count;

	struct bpf_tracer_param *btp = (struct bpf_tracer_param *)(array + 1);
	int i, j;
	struct bpf_tracer *t;
	struct rx_queue_info *rx_q;
	for (i = 0; i < BPF_TRACER_NUM_MAX; i++) {
		t = &tracers[i];
		if (!t->is_use)
			continue;
		btp = btp + i;
		snprintf(btp->name, sizeof(btp->name), "%s", t->name);
		snprintf(btp->bpf_load_name, sizeof(btp->bpf_load_name), "%s",
			 t->bpf_load_name);
		btp->dispatch_workers_nr = t->dispatch_workers_nr;
		/*
		 * TODO(@jiping), How to report multiple reader page counts?
		 * Currently, all readers' page counts are consistent for a
		 * tracer, and readers[0]'s page count can be reported here.
		 */
		btp->perf_pg_cnt = t->readers[0].perf_pages_cnt;
		btp->lost = atomic64_read(&t->lost);
		btp->probes_count = t->probes_count;
		btp->state = t->state;
		btp->adapt_success = t->adapt_success;
		btp->data_limit_max = t->data_limit_max;

		for (j = 0; j < PROTO_NUM; j++) {
			btp->proto_stats[j] = atomic64_read(&t->proto_stats[j]);
		}

		for (j = 0; j < btp->dispatch_workers_nr; j++) {
			rx_q = (struct rx_queue_info *)&btp->rx_queues[j];
			rx_q->enqueue_lost =
			    atomic64_read(&t->queues[j].enqueue_lost);
			rx_q->enqueue_nr =
			    atomic64_read(&t->queues[j].enqueue_nr);
			rx_q->burst_count =
			    atomic64_read(&t->queues[j].burst_count);
			rx_q->dequeue_nr =
			    atomic64_read(&t->queues[j].dequeue_nr);
			rx_q->heap_get_failed =
			    atomic64_read(&t->queues[j].heap_get_failed);
			rx_q->queue_size = ring_count(t->queues[j].r);
			rx_q->ring_capacity = t->queues[j].r->capacity;
		}
	}

	print_cp_tracer_status();

	return ETR_OK;
}

static struct tracer_sockopts trace_sockopts = {
	.version = SOCKOPT_VERSION,
	.set_opt_min = SOCKOPT_SET_TRACER_ADD,
	.set_opt_max = SOCKOPT_SET_TRACER_FLUSH,
	.set = tracer_sockopt_set,
	.get_opt_min = SOCKOPT_GET_TRACER_SHOW,
	.get_opt_max = SOCKOPT_GET_TRACER_SHOW,
	.get = tracer_sockopt_get,
};

static int match_pids_sockopt_set(sockoptid_t opt, const void *conf,
				  size_t size)
{
	print_match_pids_hash();
	return ETR_OK;
}

static struct tracer_sockopts match_pids_sockopts = {
	.version = SOCKOPT_VERSION,
	.get = NULL,
	.set_opt_min = SOCKOPT_PRINT_MATCH_PIDS,
	.set_opt_max = SOCKOPT_PRINT_MATCH_PIDS,
	.set = match_pids_sockopt_set,
};

int enable_ebpf_protocol(int protocol)
{
	if (protocol < PROTO_NUM) {
		ebpf_config_protocol_filter[protocol] = true;
		return 0;
	}
	return ETR_INVAL;
}

int enable_ebpf_seg_reasm_protocol(int protocol)
{
	if (protocol < PROTO_NUM) {
		allow_seg_reasm_protos[protocol] = true;
		return 0;
	}
	return ETR_INVAL;
}

int set_allow_port_bitmap(void *bitmap)
{
	memcpy(&allow_port_bitmap, bitmap, sizeof(allow_port_bitmap));
	return 0;
}

int set_bypass_port_bitmap(void *bitmap)
{
	memcpy(&bypass_port_bitmap, bitmap, sizeof(bypass_port_bitmap));
	return 0;
}

int set_feature_regex(int feature, const char *pattern)
{
	if (feature < 0 || feature >= FEATURE_MAX) {
		return ETR_INVAL;
	}

	if (regcomp(&cfg_feature_regex_array[feature].preg, pattern,
		    REG_EXTENDED)) {
		return ETR_INVAL;
	}

	cfg_feature_regex_array[feature].ok = true;

	if (feature == FEATURE_PROFILE_ONCPU
	    || feature == FEATURE_PROFILE_OFFCPU
	    || feature == FEATURE_PROFILE_MEMORY) {
		unwind_process_reload();
	}
	return 0;
}

bool is_feature_enabled(int feature)
{
	bool enabled = false;
	pthread_mutex_lock(&match_pids_lock);
	if (last_match_pids[feature].pids != NULL
	    && last_match_pids[feature].count > 0)
		enabled = true;
	pthread_mutex_unlock(&match_pids_lock);

	return enabled;
}

bool is_feature_matched(int feature, int pid, const char *path)
{
	if (pid > 0)
		return is_pid_match(feature, pid);

	int error = 0;
	char *path_for_basename = NULL;
	char *process_name = NULL;

	if (!is_feature_enabled(feature)) {
		return false;
	}

	if (!path) {
		return false;
	}
	// basename: This is the weird XPG version of this function.  It sometimes will
	// modify its argument.
	path_for_basename = strdup(path);
	if (!path_for_basename) {
		return false;
	}

	process_name = basename(path_for_basename);
	error = regexec(&cfg_feature_regex_array[feature].preg, process_name, 0,
			NULL, 0);
	free(path_for_basename);
	return !error;
}

static void init_thread_ids(void)
{
	thread_ids.entries = NULL;
	pthread_mutex_init(&thread_ids.lock, NULL);
}

static int print_match_pids_kvp_cb(pids_match_hash_kv * kv, void *arg)
{
	ebpf_info("  PID %lu flags 0x%lx (%s %s %s %s %s %s %s)\n",
		  kv->key, kv->value,
		  (kv->value & FEATURE_FLAG_UPROBE_GOLANG_SYMBOL) ? "GOSYMBOL"
		  : "",
		  (kv->value & FEATURE_FLAG_UPROBE_GOLANG) ? "GOLANG" : "",
		  (kv->value & FEATURE_FLAG_UPROBE_OPENSSL) ? "OPENSSL" : "",
		  (kv->value & FEATURE_FLAG_PROFILE_ONCPU) ? "ONCPU" : "",
		  (kv->value & FEATURE_FLAG_PROFILE_OFFCPU) ? "OFFCPU" : "",
		  (kv->value & FEATURE_FLAG_PROFILE_MEMORY) ? "OFFCPU" : "");
	return BIHASH_WALK_CONTINUE;
}

static void print_match_pids_hash(void)
{
	pids_match_hash_t *h = &pids_match_hash;
	pids_match_hash_foreach_key_value_pair(h, print_match_pids_kvp_cb,
					       NULL);
	print_hash_pids_match(&pids_match_hash);
}

static void add_thread_ids_entry(pthread_t thread, int index)
{
	pthread_mutex_lock(&thread_ids.lock);
	struct thread_index_entry v;
	v.thread = thread;
	v.index = index;
	int ret = VEC_OK;
	vec_add1(thread_ids.entries, v, ret);
	if (ret != VEC_OK) {
		ebpf_warning("vec add failed.\n");
	}
	pthread_mutex_unlock(&thread_ids.lock);
}

static int add_pid_to_match_hash(int feature, int pid)
{
	int ret = 0;
	pids_match_hash_t *h = &pids_match_hash;
	pids_match_hash_kv kv = {};
	kv.key = (u64) pid;
	pids_match_hash_search(h, &kv, &kv);
	kv.value |= (1 << feature);
	if (pids_match_hash_add_del(h, &kv, 1)) {
		ebpf_warning("Add hash failed.(key %lu value %lu)\n",
			     kv.key, kv.value);
		ret = -1;
	}

	uprobe_match_pid_handle(feature, pid, MATCH_PID_ADD);
	profiler_match_pid_handle(feature, pid, MATCH_PID_ADD);
	extended_match_pid_handle(feature, pid, MATCH_PID_ADD);
	return ret;
}

bool is_pid_match(int feature, int pid)
{
	pids_match_hash_t *h = &pids_match_hash;
	pids_match_hash_kv kv = {};
	kv.key = (u64) pid;
	pids_match_hash_search(h, &kv, &kv);
	return kv.value & (1UL << feature);
}

static int clear_pid_from_match_hash(int feature, int pid)
{
	int ret = 0;
	pids_match_hash_t *h = &pids_match_hash;
	pids_match_hash_kv kv = {};
	kv.key = (u64) pid;
	pids_match_hash_search(h, &kv, &kv);
	kv.value &= ~(1 << feature);
	if (kv.value == 0) {
		if (pids_match_hash_add_del(h, &kv, 0)) {
			ebpf_warning("delete hash failed.(key %lu)\n", kv.key);
			ret = -1;
		}
	} else {
		if (pids_match_hash_add_del(h, &kv, 1)) {
			ebpf_warning("clear hash failed.(key %lu value %lu)\n",
				     kv.key, kv.value);
			ret = -1;
		}
	}

	uprobe_match_pid_handle(feature, pid, MATCH_PID_DEL);
	profiler_match_pid_handle(feature, pid, MATCH_PID_DEL);
	extended_match_pid_handle(feature, pid, MATCH_PID_DEL);
	return ret;
}

static void del_stale_match_pids(int feature, const int *pids, int num)
{
	int i, j;
	bool existed;
	struct match_pid_s *prev_pids = &last_match_pids[feature];
	for (i = 0; i < prev_pids->count; i++) {
		existed = false;
		for (j = 0; j < num; j++) {
			if (pids[j] == prev_pids->pids[i]) {
				existed = true;
				break;
			}
		}

		if (existed)
			continue;
		else
			clear_pid_from_match_hash(feature, prev_pids->pids[i]);
	}
}

static void add_new_match_pids(int feature, const int *pids, int num)
{
	int i, j;
	bool existed;
	struct match_pid_s *prev_pids = &last_match_pids[feature];
	for (i = 0; i < num; i++) {
		existed = false;
		for (j = 0; j < prev_pids->count; j++) {
			if (pids[i] == prev_pids->pids[j]) {
				existed = true;
				break;
			}
		}

		if (existed)
			continue;
		else
			add_pid_to_match_hash(feature, pids[i]);
	}
}

int exec_set_feature_pids(int feature, const int *pids, int num)
{
	del_stale_match_pids(feature, pids, num);
	add_new_match_pids(feature, pids, num);

	pthread_mutex_lock(&match_pids_lock);
	if (last_match_pids[feature].pids != NULL) {
		free(last_match_pids[feature].pids);
		last_match_pids[feature].pids = NULL;
		last_match_pids[feature].count = 0;
	}

	last_match_pids[feature].pids = malloc(sizeof(int) * num);
	if (last_match_pids[feature].pids == NULL) {
		ebpf_warning("last_match_pids[%d].pids malloc failed.\n",
			     feature);
		pthread_mutex_unlock(&match_pids_lock);
		return -1;
	}
	memcpy(last_match_pids[feature].pids, pids, sizeof(int) * num);
	last_match_pids[feature].count = num;
	pthread_mutex_unlock(&match_pids_lock);
	return 0;
}

int set_feature_pids(int feature, const int *match_pids, int num)
{
	if (feature < 0 || feature >= FEATURE_MAX) {
		return -1;
	}

	int i, j = 0;
	int pids[num];
	memset(pids, 0, sizeof(pids));
	for (i = 0; i < num; i++) {
		//Check if the process exists
		if (kill(match_pids[i], 0) == -1 && errno == ESRCH) {
			ebpf_warning("The process with PID %d does not exist\n",
				     match_pids[i]);
		} else {
			pids[j++] = match_pids[i];
		}
	}

	num = j;
	// Set the thread ID, which will be used in `pids_match_hash`.
	pthread_t tid = pthread_self();
	struct thread_index_entry *v;
	bool found = false;
	vec_foreach(v, thread_ids.entries) {
		if (v->thread == tid)
			found = true;
		break;
	}

	if (!found) {
		u64 idx = AO_ADD_F(&thread_index_max, 1);
		add_thread_ids_entry(tid, idx);
		thread_index = idx;
		ebpf_info("thread %ld index %ld\n", tid, thread_index);
	}

	return exec_set_feature_pids(feature, pids, num);
}

int init_match_pids_hash(void)
{
	pthread_mutex_init(&match_pids_lock, NULL);
	pids_match_hash_t *h = &pids_match_hash;
	memset(h, 0, sizeof(*h));
	u32 nbuckets = PIDS_MATCH_HASH_BUCKETS_NUM;
	u64 hash_memory_size = PIDS_MATCH_HASH_MEM_SZ;
	return pids_match_hash_init(h, (char *)"match-pids", nbuckets,
				    hash_memory_size);
}

int bpf_tracer_init(const char *log_file, bool is_stdout)
{
	init_list_head(&extra_waiting_head);
	init_list_head(&period_events_head);

	log_to_stdout = is_stdout;
	if (log_file) {
		log_stream = fopen(log_file, "a+");
		if (log_stream == NULL) {
			ebpf_info("log file: %s", log_file);
			return ETR_INVAL;
		}
	}

	int err;
	if (max_locked_memory_set_unlimited() != 0)
		return ETR_INVAL;

	const char *jit_enable_path = "/proc/sys/net/core/bpf_jit_enable";
	int jit_enable_val = sysfs_read_num(jit_enable_path);
	if (jit_enable_val == 0) {
		if (sysfs_write(jit_enable_path, "1") < 0) {
			ebpf_warning
			    ("Set 'bpf_jit_enable' is failed, Permission denied\n"
			     " (may be docker container is unprivileged).\n"
			     " There will be 10%%-30%% performance\n"
			     " degradation, ensure that the host enable jit.\n"
			     "cmdline:\n"
			     " \"echo 1 > /proc/sys/net/core/bpf_jit_enable\"\n");
		} else {
			ebpf_info("Set bpf_jit_enable success\n");
		}
	} else if (jit_enable_val == 1) {
		ebpf_info
		    ("Currently \"/proc/sys/net/core/bpf_jit_enable\" value is 1,"
		     " not need set.\n");
	} else {
		ebpf_warning
		    ("\"/proc/sys/net/core/bpf_jit_enable value is invalid\n");
	}

	/* Memory management initialization. */
	clib_mem_init();

	k_version = fetch_kernel_version_code();
	fetch_linux_release(linux_release, sizeof(linux_release) - 1);
	ebpf_info("linux version : %s (version code : %u)\n", linux_release,
		  k_version);
	max_rlim_open_files_set(OPEN_FILES_MAX);
	sys_cpus_count = get_cpus_count(&cpu_online);
	if (sys_cpus_count <= 0 || sys_cpus_count > MAX_CPU_NR) {
		ebpf_warning
		    ("The number of CPUs is required to be in the range of 1 to %d, and "
		     "the current number of CPUs is %d, which makes eBPF-tracer unable to run.\n",
		     MAX_CPU_NR, sys_cpus_count);
		return ETR_INVAL;
	}

	uint64_t real_time, monotonic_time;
	real_time = gettime(CLOCK_REALTIME, TIME_TYPE_NAN);
	monotonic_time = gettime(CLOCK_MONOTONIC, TIME_TYPE_NAN);
	sys_boot_time_ns = real_time - monotonic_time;
	prev_sys_boot_time_ns = sys_boot_time_ns;
	ebpf_info("sys_boot_time_ns : %llu\n", sys_boot_time_ns);

	init_thread_ids();

	if (!check_netns_enabled())
		ebpf_warning("If the system has not enabled the 'CONFIG_NET_NS'"
			     " option, the 'netns_id' for continuously profiling"
			     " data will be 0.\n");

	/*
	 * Set up the lock now, so we can use it to make the first add
	 * thread-safe for tracer alloc.
	 */
	tracers_lock =
	    clib_mem_alloc_aligned("t_alloc_lock", CLIB_CACHE_LINE_BYTES,
				   CLIB_CACHE_LINE_BYTES, NULL);
	if (tracers_lock == NULL) {
		ebpf_warning("clib_mem_alloc_aligned() error\n");
		return ETR_INVAL;
	}
	tracers_lock[0] = 0;

	clear_residual_probes();

	if (ctrl_init()) {
		return ETR_INVAL;
	}
	// Process matching hash initialization
	if (init_match_pids_hash() != 0)
		return ETR_INVAL;

	if ((err = sockopt_register(&trace_sockopts)) != ETR_OK)
		return err;

	if ((err = sockopt_register(&match_pids_sockopts)) != ETR_OK)
		return err;

	err = pthread_create(&ctrl_pthread, NULL, (void *)&ctrl_main, NULL);
	if (err) {
		ebpf_info("<%s> ctrl_pthread, pthread_create is error:%s\n",
			  __func__, strerror(errno));
		return ETR_INVAL;
	}

	if (register_period_event_op("trigger_kern_adapt",
				     trigger_kern_adapt,
				     TRIG_KERN_ADAPT_PERIOD))
		return ETR_INVAL;

	/*
	 * Since the system time may be modified during system operation,
	 * the system startup time (accuracy is nanoseconds) needs to be
	 * updated periodically and adjusted accordingly as the system
	 * time changes. Since the eBPF capture time is calculated by ad-
	 * ding monotonic time (monotonic time, which refers to the time
	 * lost after system startup) on the basis of system startup time
	 * (sys_boot_time_ns), the system startup time must be periodica-
	 * lly checked and adjusted to avoid system time changes. The ca-
	 * pture time of eBPF data is significantly different from the
	 * capture time of AF_PACKET data.
	 *
	 * 由于系统运行过程中会存在系统时间被改动而发生变化的情况，
	 * 因此需要对系统启动时间(精度为纳秒)进行周期性的更新，是之
	 * 随系统时间变化而相应进行调整。由于eBPF捕获时间的计算是在
	 * 系统启动时间（sys_boot_time_ns）的基础上加单调时间（monotonic
	 * time，指系统启动后流失的时间），所以系统启动时间要进行周期性
	 * 检查调整，以免系统时间改变而使eBPF数据的捕获时间较之AF_PACKET
	 * 捕获数据的时间发生较大差异。
	 */
	if (register_period_event_op("boot time update", boot_time_update,
				     SYS_TIME_UPDATE_PERIOD))
		return ETR_INVAL;

	err =
	    pthread_create(&cpus_kick_pthread, NULL,
			   (void *)&period_process_main, NULL);
	if (err) {
		ebpf_info
		    ("<%s> cpus_kick_pthread, pthread_create is error:%s\n",
		     __func__, strerror(errno));
		return ETR_INVAL;
	}

	return ETR_OK;
}

bool is_rt_kernel(void)
{
	return (strstr(linux_release, ".rt") || strstr(linux_release, "-rt"));
}

void bpf_tracer_finish(void)
{
	all_probes_ready = 1;
	ebpf_info("All tracers finish!!!\n");
}
