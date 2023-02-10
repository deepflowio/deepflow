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
#include <sys/utsname.h>
#include <sys/prctl.h>
#include <bcc/libbpf.h>
#include <bcc/perf_reader.h>
#include "config.h"
#include "probe.h"
#include "table.h"
#include "common.h"
#include "log.h"
#include "symbol.h"
#include "tracer.h"
#include "elf.h"
#include "load.h"
#include <libgen.h>

int major, minor;		// Linux kernel主版本，次版本
char linux_release[128];	// Record the contents of 'uname -r'

volatile uint64_t sys_boot_time_ns;	// 当前系统启动时间，单位：纳秒
volatile uint64_t prev_sys_boot_time_ns;	// 上一次更新的系统启动时间，单位：纳秒
uint64_t boot_time_update_count;	// 用于记录boot_time_update()调用次数。

struct cfg_feature_regex cfg_feature_regex_array[FEATURE_MAX];

// eBPF protocol filter.
int ebpf_config_protocol_filter[PROTO_NUM];

struct allow_port_bitmap allow_port_bitmap;

uint64_t adapt_kern_uid; // Indicates the identifier of the adaptation kernel

/*
 * tracers
 */
static struct bpf_tracer *tracers[BPF_TRACER_NUM_MAX];
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

static struct list_head extra_waiting_head;	// 额外事务处理的注册

#define EVENT_PERIOD_TIME	1	// 事件处理的周期时间，单位：秒
static struct list_head period_events_head;	// 周期性事件处理的注册

int sys_cpus_count;
bool *cpu_online;		// 用于判断CPU是否是online

// 所有tracer成功完成启动，会被应用设置为1
static volatile uint64_t all_probes_ready;

static int tracepoint_attach(struct tracepoint *tp);

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
		ebpf_warning("Current machine is \"%s\", not support.\n", uts.machine);
		return ETR_INVAL;
	}

	int patch;
	if (fetch_kernel_version(&major, &minor, &patch) != ETR_OK) {
		return ETR_INVAL;
	}

	ebpf_info("%s Linux %d.%d.%d\n", __func__, major, minor, patch);

	if (major < maj_limit || (major == maj_limit && minor < min_limit)) {
		ebpf_info
		    ("Current kernel version is %s, but need > %s, eBPF not support.\n",
		     uts.release, "4.14");
		return ETR_INVAL;
	}

	return ETR_OK;
}

struct bpf_tracer *find_bpf_tracer(const char *name)
{
	struct bpf_tracer *t = NULL;
	int i;
	for (i = 0; i < tracers_count; i++) {
		t = tracers[i];
		if (strcmp(t->name, name) == 0)
			return t;
	}

	ebpf_info("Tracer '%s', Not Found.", name);

	return NULL;
}

/**
 * create_bpf_tracer - create a eBPF tracer
 *
 * @name Tracer name
 * @load_name eBPF load buffer name
 * @bpf_bin_buffer load eBPF buffer address
 * @buffer_sz eBPF buffer size
 * @tps Tracer configuration information
 * @workers_nr How many threads process the queues
 * @handle The upper callback function address
 * @perf_pages_cnt How many memory pages are used for ring-buffer
 *
 * @returns
 *      Return struct bpf_tracer pointer on success, NULL otherwise.
 */
struct bpf_tracer *create_bpf_tracer(const char *name,
				     char *load_name,
				     void *bpf_bin_buffer,
				     int buffer_sz,
				     struct tracer_probes_conf *tps,
				     int workers_nr,
				     void *handle, unsigned int perf_pages_cnt)
{
	if (find_bpf_tracer(name) != NULL) {
		ebpf_warning("Tracer '%s', already existed.", name);
		return NULL;
	}

	struct bpf_tracer *bt = malloc(sizeof(struct bpf_tracer));
	if (bt == NULL) {
		ebpf_warning("Tracer '%s' failed, no memory!", name);
		return NULL;
	}

	memset(bt, 0, sizeof(*bt));
	atomic64_init(&bt->lost);

	int i;
	for (i = 0; i < PROTO_NUM; i++)
		atomic64_init(&bt->proto_status[i]);

	snprintf(bt->bpf_load_name, sizeof(bt->bpf_load_name), "%s", load_name);
	bt->tps = tps;
	bt->buffer_ptr = bpf_bin_buffer;
	bt->buffer_sz = buffer_sz;

	snprintf(bt->name, sizeof(bt->name), "%s", name);
	bt->dispatch_workers_nr = workers_nr;

	tracers[tracers_count++] = bt;
	bt->process_fn = handle;

	if (perf_pages_cnt <= 0)
		perf_pages_cnt = BPF_PERF_READER_PAGE_CNT;
	else
		perf_pages_cnt = 1 << min_log2((unsigned int)perf_pages_cnt);

	bt->perf_pages_cnt = perf_pages_cnt;

	init_list_head(&bt->probes_head);
	init_list_head(&bt->maps_conf_head);

	pthread_mutex_init(&bt->mutex_probes_lock, NULL);

	return bt;
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

int tracer_bpf_load(struct bpf_tracer *tracer)
{
	struct ebpf_object *obj;
	int ret;
	obj = ebpf_open_buffer(tracer->buffer_ptr,
			       tracer->buffer_sz, tracer->bpf_load_name);
	if (IS_NULL(obj)) {
		ebpf_warning("ebpf_open_buffer() \"%s\" failed, error:%s\n",
			     tracer->bpf_load_name, strerror(errno));
		return ETR_INVAL;
	}

	struct map_config *m_conf;
	list_for_each_entry(m_conf, &tracer->maps_conf_head, list) {
		if ((ret = map_resize_set(obj, m_conf)))
			return ret;
	}

	ret = ebpf_obj_load(obj);
	if (ret != 0) {
		ebpf_warning("bpf load \"%s\" failed, error:%s (%d).\n",
			     tracer->bpf_load_name, strerror(errno), errno);
		if (errno == EACCES) {
			ebpf_warning("Check the selinux status, if found SELinux"
				     " 'status: enabled' and 'Current mode:"
				     "enforcing', please try the following way "
				     "to solve:\n"
				     "1 Create file 'deepflow-agent.te',"
				     "contents:\n\n"
				     "module deepflow-agent 1.0;\n"
				     "require {\n"
				     "  type container_runtime_t;\n"
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

		return ret;
	}

	tracer->obj = obj;
	ebpf_info("bpf load \"%s\" succeed.\n", tracer->bpf_load_name);
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

static struct probe *create_probe(struct bpf_tracer *tracer,
				  const char *func_name, bool isret,
				  enum probe_type type, void *private)
{
	struct probe *pb;
	struct ebpf_prog *prog;
	int fd = bpf_get_program_fd(tracer->obj, func_name, (void **)&prog);
	if (fd < 0) {
		ebpf_warning
		    ("fun: %s, bpf_get_program_fd failed, func_name:%s.\n",
		     __func__, func_name);
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

	ret = program__attach_uprobe(prog, isret, pid, bin_path, addr, ev_name,
				     (void **)&link);
	if (ret != 0) {
		ebpf_warning("program__attach_uprobe failed, ev_name:%s.\n",
			     ev_name);
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

	snprintf(ev_name, sizeof(ev_name), "%s_%s", isret ? "r" : "p", fn_name);
	ret =
	    program__attach_kprobe(prog, isret, pid, fn_name, ev_name,
				   (void **)&link);
	if (ret != 0) {
		ebpf_warning
		    ("program__attach_kprobe failed, ev_name:%s.\n", ev_name);
	}

	return link;
}

static int probe_attach(struct probe *p)
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

	tp->link = NULL;
	free(tp->link);
	return ETR_OK;
}

int tracer_hooks_process(struct bpf_tracer *tracer, enum tracer_hook_type type,
			 int *probes_count)
{
	int (*probe_fun) (struct probe * p) = NULL;
	int (*tracepoint_fun) (struct tracepoint * p) = NULL;
	if (type == HOOK_ATTACH) {
		probe_fun = probe_attach;
		tracepoint_fun = tracepoint_attach;
	} else if (type == HOOK_DETACH) {
		probe_fun = probe_detach;
		tracepoint_fun = tracepoint_detach;
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

		error = probe_fun(p);
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
	for (i = 0; i < tps->tps_nr; i++) {
		tp = get_tracepoint_from_tracer(tracer, tps->tps[i].name);
		if (!tp)
			return ETR_INVAL;

		error = tracepoint_fun(tp);
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
				 tps->ksymbols[i].isret, KPROBE, NULL);
		if (!p)
			return ETR_INVAL;
	}

	list_for_each_entry(usym, &tps->uprobe_syms_head, list) {
		p = create_probe(tracer, usym->probe_func, usym->isret, UPROBE,
				 usym);
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
		ebpf_warning("tracer_probes_init failed, tracer is NULL\n");
		return ETR_INVAL;
	}

	tps = tracer->tps;
	if (!tps) {
		ebpf_warning("tracer_probes_init failed, tps is NULL\n");
		return ETR_INVAL;
	}

	list_for_each_entry(usym, &tps->uprobe_syms_head, list) {
		if (usym->in_probe)
			continue;
		p = create_probe(tracer, usym->probe_func, usym->isret, UPROBE,
				 usym);
		if (!p)
			return ETR_INVAL;
	}

	return 0;
}

int tracer_hooks_attach(struct bpf_tracer *tracer)
{
	return tracer_hooks_process(tracer, HOOK_ATTACH, NULL);
}

int tracer_hooks_detach(struct bpf_tracer *tracer)
{
	return tracer_hooks_process(tracer, HOOK_DETACH, NULL);
}

int perf_map_init(struct bpf_tracer *tracer, const char *perf_map_name)
{
	struct ebpf_map *map =
	    ebpf_obj__get_map_by_name(tracer->obj, perf_map_name);
	int map_fd = map->fd;
	void *reader;
	int perf_fd, ret;
	int i, reader_idx;
	int pages_cnt = tracer->perf_pages_cnt;
	for (i = 0; i < sys_cpus_count; i++) {
		if (!cpu_online[i])
			continue;
		reader =
		    (struct perf_reader *)bpf_open_perf_buffer(tracer->raw_cb,
							       tracer->lost_cb,
							       (void *)tracer,
							       -1, i,
							       pages_cnt);
		perf_fd = perf_reader_fd(reader);
		if ((ret = bpf_update_elem(map_fd, &i, &perf_fd, BPF_ANY))) {
			ebpf_info
			    ("fun: %s, bpf_map_update_elem reader setting failed.\n",
			     __func__);
			return ret;
		}

		reader_idx = tracer->readers_count++;
		tracer->reader_fds[reader_idx] = perf_fd;
		tracer->readers[reader_idx] = reader;
	}

	tracer->data_map = map;

	return ETR_OK;
}

#ifdef PERFORMANCE_TEST
__always_inline uint32_t random_u32(uint32_t * seed)
{
	*seed = (1664525 * *seed) + 1013904223;
	return *seed;
}

__always_inline uint64_t clib_cpu_time_now(void)
{
	uint32_t a, d;
	asm volatile ("rdtsc":"=a" (a), "=d"(d));
	return (uint64_t) a + ((uint64_t) d << (uint64_t) 32);
}
#endif

static void poller(void *t)
{
	prctl(PR_SET_NAME, "perf-reader");
	struct bpf_tracer *tracer = (struct bpf_tracer *)t;
	for (;;) {
#ifndef PERFORMANCE_TEST
		perf_reader_poll(tracer->readers_count, tracer->readers, 500);
#else
		uint64_t data_len, rand_seed;
		rand_seed = clib_cpu_time_now();
		data_len = random_u32((uint32_t *) & rand_seed) & 0xffff;

		int ring_idx = data_len % tracer->dispatch_workers_nr;
		struct queue *q = &tracer->queues[ring_idx];

		struct socket_bpf_data *prep_data =
		    malloc(sizeof(struct socket_bpf_data) + data_len);
		if (prep_data == NULL) {
			ebpf_waring("malloc() failed, no memory.\n");
			atomic64_inc(&q->heap_get_failed);
			return;
		}
		prep_data->cap_data =
		    (char *)((void **)&prep_data->cap_data + 1);
		prep_data->len = data_len;
		if (!ring_sp_enqueue_burst(q->r, (void **)&prep_data, 1, NULL)) {
			printf("%s, ring_sp_enqueue failed.\n", __func__);
			ebpf_info("%s, ring_sp_enqueue failed.\n", __func__);
			free(prep_data);
			atomic64_inc(&q->enqueue_lost);
		} else {
			pthread_mutex_lock(&q->mutex);
			pthread_cond_signal(&q->cond);
			pthread_mutex_unlock(&q->mutex);
			atomic64_inc(&q->enqueue_nr);
		}
#endif
	}
	/* never reached */
	/* pthread_exit(NULL); */
	/* return NULL; */
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

/*
 * ============================================================
 * 周期性事件处理：
 *
 * 1、周期性kick内核，实现kernel burst方式发送数据的超时检查。
 * 2、周期性检查BPF MAP
 *
 * ===========================================================
 */
static void period_events_process(void)
{
	struct period_event_op *peo;
	list_for_each_entry(peo, &period_events_head, list) {
		if (peo->is_valid)
			peo->f();
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

int register_period_event_op(const char *name, period_event_fun_t f)
{
	struct period_event_op *peo = malloc(sizeof(struct period_event_op));
	if (!peo) {
		ebpf_warning("malloc() failed, no memory.\n");
		return -ENOMEM;
	}
	peo->f = f;
	peo->is_valid = true;
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

/*
 * kernel采用捆绑burst发送数据到用户的形式，
 * 下面的方法实现所有CPU触发超时检查把驻留在eBPF buffer中数据发送上来。
 */
static inline void cpu_ebpf_data_timeout_check(int cpu_id)
{
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(cpu_id, &cpuset);
	if (-1 ==
	    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset)) {
		return;
	}

	syscall(__NR_getppid);

	if (all_probes_ready)
		RUN_ONCE(ready_flag_cpus[cpu_id], extra_waiting_process,
			 EXTRA_TYPE_CLIENT);
}

static int cpus_kick_kern(void)
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
	boot_time_update_count++;
	// 默认情况下1分钟更新一次系统启动时间
	if (!((boot_time_update_count * EVENT_PERIOD_TIME) %
	      BOOT_TIME_UPDATE_PERIOD)) {
		prev_sys_boot_time_ns = sys_boot_time_ns;
		uint64_t real_time, monotonic_time;
		real_time = gettime(CLOCK_REALTIME, TIME_TYPE_NAN);
		monotonic_time = gettime(CLOCK_MONOTONIC, TIME_TYPE_NAN);
		sys_boot_time_ns = real_time - monotonic_time;
	}

	return ETR_OK;
}

static void period_process_main(__unused void *arg)
{
	prctl(PR_SET_NAME, "period-process");

	// Only this unique identifier can be adapted to the kernel
	adapt_kern_uid = (uint64_t)getpid() << 32 | (uint32_t)syscall(__NR_gettid);

	// 确保所有tracer都运行了，之后触发kick内核操作
	while (all_probes_ready == 0)
		usleep(LOOP_DELAY_US);

	// 确保server类型的extra_waiting_process先执行
	sleep(1);

	ebpf_info("cpus_kick begin !!!\n");

	memset((void *)ready_flag_cpus, 1, sizeof(ready_flag_cpus));

	for (;;) {
		period_events_process();
		sleep(EVENT_PERIOD_TIME);
	}
}

/*
 * 工作线程从queue获取数据，进行数据处理。
 */
static void process_datas(void *queue)
{
	prctl(PR_SET_NAME, "queue-worker");
	int nr;
	struct queue *q = (struct queue *)queue;
	struct ring *r = q->r;
	void *rx_burst[MAX_PKT_BURST];
	for (;;) {
		nr = ring_sc_dequeue_burst(r, rx_burst, MAX_PKT_BURST, NULL);
		if (nr == 0) {
			/*
			 * 等着生产者唤醒
			 */
			pthread_mutex_lock(&q->mutex);
			pthread_cond_wait(&q->cond, &q->mutex);
			pthread_mutex_unlock(&q->mutex);
		} else {
			atomic64_add(&q->dequeue_nr, nr);
			prefetch_and_process_datas(q->t, nr, rx_burst);
			if (nr == MAX_PKT_BURST)
				atomic64_inc(&q->burst_count);
		}
	}

	/* never reached */
	/* pthread_exit(NULL); */
	/* return NULL; */
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

int dispatch_worker(struct bpf_tracer *tracer, unsigned int queue_size)
{
	int i, ret;

	if (queue_size <= 0)
		queue_size = RING_SIZE;
	else
		queue_size = 1 << min_log2((unsigned int)queue_size);

	for (i = 0; i < tracer->dispatch_workers_nr; i++) {
		struct ring *r = NULL;
		char name[NAME_LEN];
		snprintf(name, sizeof(name), "%s-ring-%d", tracer->name, i);
		r = ring_create(name, queue_size,
				SOCKET_ID_ANY, RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (r == NULL) {
			ebpf_info("<%s> ring_create fail. err:%s\n", __func__,
				  strerror(errno));
			return -ENOMEM;
		}

		tracer->queues[i].r = r;
		tracer->queues[i].t = tracer;
		tracer->queues[i].nr = 0;
		tracer->queues[i].ring_size = queue_size;

		atomic64_init(&tracer->queues[i].enqueue_lost);
		atomic64_init(&tracer->queues[i].enqueue_nr);
		atomic64_init(&tracer->queues[i].dequeue_nr);
		atomic64_init(&tracer->queues[i].burst_count);
		atomic64_init(&tracer->queues[i].heap_get_failed);

		pthread_mutex_init(&tracer->queues[i].mutex, NULL);
		pthread_cond_init(&tracer->queues[i].cond, NULL);
		ret =
		    pthread_create(&tracer->dispatch_workers[i], NULL,
				   (void *)&process_datas,
				   (void *)&tracer->queues[i]);
		if (ret) {
			ebpf_info
			    ("<%s> process_data, pthread_create is error:%s\n",
			     __func__, strerror(errno));
			return ETR_INVAL;
		}
	}

	ret =
	    pthread_create(&tracer->perf_worker[0], NULL, (void *)&poller,
			   (void *)tracer);
	if (ret) {
		ebpf_info("<%s> perf_worker, pthread_create is error:%s\n",
			  __func__, strerror(errno));
		return ETR_INVAL;
	}

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
	for (i = 0; i < tracers_count; i++) {
		t = tracers[i];
		btp = btp + i;
		snprintf(btp->name, sizeof(btp->name), "%s", t->name);
		snprintf(btp->bpf_load_name, sizeof(btp->bpf_load_name), "%s",
			 t->bpf_load_name);
		btp->dispatch_workers_nr = t->dispatch_workers_nr;
		btp->perf_pg_cnt = t->perf_pages_cnt;
		btp->lost = atomic64_read(&t->lost);
		btp->probes_count = t->probes_count;
		btp->state = t->state;
		btp->adapt_success = t->adapt_success;
		btp->data_limit_max = t->data_limit_max;

		for (j = 0; j < PROTO_NUM; j++) {
			btp->proto_status[j] =
			    atomic64_read(&t->proto_status[j]);
		}

		for (j = 0; j < btp->dispatch_workers_nr; j++) {
			rx_q = &btp->rx_queues[j];
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

int enable_ebpf_protocol(int protocol)
{
	if (protocol < PROTO_NUM) {
		ebpf_config_protocol_filter[protocol] = true;
		return 0;
	}
	return ETR_INVAL;
}

int set_allow_port_bitmap(void *bitmap)
{
	memcpy(&allow_port_bitmap, bitmap, sizeof(allow_port_bitmap));
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
	return 0;
}

bool is_feature_enabled(int feature){
	if (feature < 0 || feature >= FEATURE_MAX) {
		return false;
	}

	return cfg_feature_regex_array[feature].ok;
}

bool is_feature_matched(int feature, const char *path)
{
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

	fetch_linux_release(linux_release, sizeof(linux_release) - 1);
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

	clear_residual_probes();

	if (ctrl_init()) {
		return ETR_INVAL;
	}

	if ((err = sockopt_register(&trace_sockopts)) != ETR_OK)
		return err;

	err = pthread_create(&ctrl_pthread, NULL, (void *)&ctrl_main, NULL);
	if (err) {
		ebpf_info("<%s> ctrl_pthread, pthread_create is error:%s\n",
			  __func__, strerror(errno));
		return ETR_INVAL;
	}

	if (register_period_event_op("kick_kern", cpus_kick_kern))
		return ETR_INVAL;

	/*
	 * 由于系统运行过程中会存在系统时间被改动而发生变化的情况，
	 * 因此需要对系统启动时间(精度为纳秒)进行周期性的更新，是之
	 * 随系统时间变化而相应进行调整。由于eBPF捕获时间的计算是在
	 * 系统启动时间（sys_boot_time_ns）的基础上加单调时间（monotonic 
	 * time，指系统启动后流失的时间），所以系统启动时间要进行周期性
	 * 检查调整，以免系统时间改变而使eBPF数据的捕获时间较之AF_PACKET
	 * 捕获数据的时间发生较大差异。
	 */
	if (register_period_event_op("boot time update", boot_time_update))
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

void bpf_tracer_finish(void)
{
	all_probes_ready = 1;
	ebpf_info("All tracers finish!!!\n");
}

int tracer_stop(void)
{
	struct bpf_tracer *t = NULL;
	int i, ret = 0;

	for (i = 0; i < tracers_count; i++) {
		t = tracers[i];
		ret = t->stop_handle();
	}

	return ret;
}

int tracer_start(void)
{
	struct bpf_tracer *t = NULL;
	int i, ret = 0;

	for (i = 0; i < tracers_count; i++) {
		t = tracers[i];
		ret = t->start_handle();
	}

	return ret;
}
