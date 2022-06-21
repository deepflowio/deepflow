#define _GNU_SOURCE
#include "tracer.h"
#include <arpa/inet.h>
#include "libbpf/include/linux/err.h"
#include <sched.h>
#include <sys/utsname.h>
#include "probe.h"
#include "table.h"
#include "common.h"
#include "log.h"

int major, minor;		// Linux kernel主版本，次版本

#define BOOT_TIME_UPDATE_PERIOD	60		// 系统启动时间更新周期, 单位：秒
volatile uint64_t sys_boot_time_ns;		// 当前系统启动时间，单位：纳秒
volatile uint64_t prev_sys_boot_time_ns;	// 上一次更新的系统启动时间，单位：纳秒
uint64_t boot_time_update_count;		// 用于记录boot_time_update()调用次数。

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
		ebpf_info("uname() error\n");
		return -1;
	}

	if (!strstr(uts.machine, "x86_64")) {
		ebpf_info("Current machine is \"%s\", not support.\n");
		return -1;
	}

	if (sscanf(uts.release, "%d.%d", &major, &minor) != 2) {
		ebpf_info("sscanf(%s), is error.\n", uts.release);
		return -1;
	}

	ebpf_info("%s Linux %d.%d\n", __func__, major, minor);

	if (major < maj_limit || (major == maj_limit && minor < min_limit)) {
		ebpf_info
		    ("Current kernel version is %s, but need > %s, eBPF not support.\n",
		     uts.release, "4.14");
		return -1;
	}

	return 0;
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

struct bpf_tracer *create_bpf_tracer(const char *name,
				     char *bpf_file,
				     struct trace_probes_conf *tps,
				     int workers_nr,
				     void *handle, unsigned int perf_pages_cnt)
{
	if (find_bpf_tracer(name) != NULL) {
		ebpf_warning("Tracer '%s', already existed.", name);
		return NULL;
	}

	struct bpf_tracer *bt = malloc(sizeof(struct bpf_tracer));
	if (bt == NULL) {
		ebpf_warning("Tracer '%s' faild, no memory!", name);
		return NULL;
	}

	memset(bt, 0, sizeof(*bt));
	atomic64_init(&bt->lost);

	int i;
	for (i = 0; i < PROTO_NUM; i++)
		atomic64_init(&bt->proto_status[i]);

	snprintf(bt->bpf_file, sizeof(bt->bpf_file), "%s", bpf_file);
	bt->tps = tps;

	snprintf(bt->name, sizeof(bt->name), "%s", name);
	bt->dispatch_workers_nr = workers_nr;

	tracers[tracers_count++] = bt;
	bt->process_fn = handle;

	if (perf_pages_cnt <= 0)
		perf_pages_cnt = BPF_PERF_READER_PAGE_CNT;
	else
		perf_pages_cnt = 1 << min_log2((unsigned int)perf_pages_cnt);

	bt->perf_pages_cnt = perf_pages_cnt;

	INIT_LIST_HEAD(&bt->maps_conf_head);

	return bt;
}

static int map_resize_set(struct bpf_object *pobj, struct map_config *m_conf)
{
	struct bpf_map *map =
	    bpf_object__find_map_by_name(pobj, m_conf->map_name);
	if (!map) {
		ebpf_info("failed to find \"%s\" map.\n", m_conf->map_name);
		return -ESRCH;
	}

	return bpf_map__resize(map, m_conf->max_entries);
}

int tracer_bpf_load(struct bpf_tracer *tracer)
{
	struct bpf_object *pobj;
	int ret;

	pobj = bpf_object__open(tracer->bpf_file);
	if (IS_ERR_OR_NULL(pobj)) {
		ebpf_info("bpf_object__open \"%s\" failed, error:%s\n",
			  tracer->bpf_file, strerror(errno));
		return -ENOENT;
	}

	struct map_config *m_conf;
	list_for_each_entry(m_conf, &tracer->maps_conf_head, list) {
		if ((ret = map_resize_set(pobj, m_conf)))
			return ret;

		ebpf_info("map_resize_set \"%s\" map. max_entries:%d\n",
			  m_conf->map_name, m_conf->max_entries);
	}

	ret = bpf_object__load(pobj);
	if (ret != 0) {
		ebpf_info("bpf load \"%s\" failed, error:%s\n",
			  tracer->bpf_file, strerror(errno));
		return ret;
	}

	tracer->pobj = pobj;
	ebpf_info("bpf load \"%s\" succeed.\n", tracer->bpf_file);
	return 0;
}

static struct probe *find_probe_from_name(struct bpf_tracer *tracer,
					  const char *probe_name)
{
	struct probe *p;
	int i;
	for (i = 0; i < PROBES_NUM_MAX; i++) {
		p = &tracer->probes[i];
		if (!strcmp(p->name, probe_name))
			return p;
	}

	return NULL;
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

	struct bpf_program *prog;
	int fd = bpf_get_program_fd(tracer->pobj, tp_name, (void **)&prog);
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

static struct probe *get_probe_from_tracer(struct bpf_tracer *tracer,
					   const char *func_name, bool isret)
{
	struct probe *pb = find_probe_from_name(tracer, func_name);
	if (pb && pb->prog)
		return pb;

	struct bpf_program *prog;
	int fd = bpf_get_program_fd(tracer->pobj, func_name, (void **)&prog);
	if (fd < 0) {
		ebpf_info("fun: %s, bpf_get_program_fd failed, func_name:%s.\n",
			  __func__, func_name);
		return NULL;
	}

	int idx = tracer->probes_count++;
	pb = &tracer->probes[idx];
	pb->prog_fd = fd;
	pb->prog = prog;
	pb->isret = isret;

	snprintf(pb->name, sizeof(pb->name), "%s", func_name);

	return pb;
}

static int probe_attach(struct probe *p)
{
#define EV_NAME_SIZE  1024
	if (p->link) {
		ebpf_info("<%s> fn_name:%s, has been attached.\n",
			  __func__, p->name);
		return 0;
	}

	char ev_name[EV_NAME_SIZE];
	char *fn_name;
	if (p->isret)
		fn_name = p->name + strlen("kretprobe/");
	else
		fn_name = p->name + strlen("kprobe/");

	// TODO: uprobe name 需要把"/", "*" 替换成"_"
	snprintf(ev_name, sizeof(ev_name), "p_%s", fn_name);

	struct bpf_link *link;

	// TODO: 需要处理uprobe的场景
	int ret =
	    program__attach_kprobe(p->prog, p->isret, -1, fn_name, ev_name,
				   (void **)&link);
	if (ret != 0) {
		printf("error %s, %s, %s\n", p->name, fn_name, ev_name);
		ebpf_info
		    ("fun: %s, program__attach_kprobe failed, ev_name:%s.\n",
		     __func__, ev_name);
		return ret;
	}

	p->link = link;

	return 0;
}

static int probe_detach(struct probe *p)
{
#define EV_NAME_SIZE  1024
	char ev_name[EV_NAME_SIZE];
	char *fn_name;
	int ret;
	if (p->link == NULL) {
		ebpf_info
		    ("<%s> p->link == NULL, fn_name:%s, has been detached.\n",
		     __func__, p->name);
		return 0;
	}

	if (p->isret)
		fn_name = p->name + strlen("kretprobe/");
	else
		fn_name = p->name + strlen("kprobe/");

	snprintf(ev_name, sizeof(ev_name), "p_%s", fn_name);

	if ((ret = program__detach_kprobe(p->link, p->isret, ev_name)) == 0)
		p->link = NULL;

	return ret;
}

static int tracepoint_attach(struct tracepoint *tp)
{
	if (tp->link) {
		ebpf_info("<%s> name:%s, has been attached.\n", __func__,
			  tp->name);
		return 0;
	}

	struct bpf_link *bl = bpf_program__attach(tp->prog);
	tp->link = bl;

	if (IS_ERR(bl)) {
		ebpf_info("fun: %s, bpf_program__attach failed, name:%s.\n",
			  __func__, tp->name);
		return -1;
	}

	return 0;
}

static int tracepoint_detach(struct tracepoint *tp)
{
	if (tp->link == NULL) {
		ebpf_info
		    ("<%s> tp->link == NULL, name:%s, has been detached.\n",
		     __func__, tp->name);
		return 0;
	}

	bpf_link__destroy(tp->link);
	tp->link = NULL;
	return 0;
}

static int tracer_hooks_process(struct bpf_tracer *tracer,
				enum tracer_hook_type type)
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
		return -EINVAL;

	if (tracer->pobj == NULL) {
		ebpf_info("fun: %s, not loaded bpf program yet.\n", __func__);
		return -EINVAL;
	}

	struct probe *p;
	struct trace_probes_conf *tps = tracer->tps;
	int i;
	for (i = 0; i < tps->probes_nr; i++) {
		p = get_probe_from_tracer(tracer, tps->symbols[i].func,
					  tps->symbols[i].isret);
		if (!p)
			return -EINVAL;
		if (probe_fun(p)) {
			ebpf_info("%s %s probe: '%s', failed!",
				  type == HOOK_ATTACH ? "attach" : "detach",
				  p->isret ? "exit" : "enter", p->name);
			return -EINVAL;
		} else
			ebpf_info("%s %s probe: '%s', succeed!",
				  type == HOOK_ATTACH ? "attach" : "detach",
				  p->isret ? "exit" : "enter", p->name);
	}

	struct tracepoint *tp;
	for (i = 0; i < tps->tps_nr; i++) {
		tp = get_tracepoint_from_tracer(tracer, tps->tps[i].name);
		if (!tp)
			return -EINVAL;

		if (tracepoint_fun(tp)) {
			ebpf_info("%s tracepoint: '%s', failed!",
				  type == HOOK_ATTACH ? "attach" : "detach",
				  tp->name);
			return -EINVAL;
		} else
			ebpf_info("%s tracepoint: '%s', succeed!",
				  type == HOOK_ATTACH ? "attach" : "detach",
				  tp->name);
	}

	return 0;
}

int tracer_hooks_attach(struct bpf_tracer *tracer)
{
	return tracer_hooks_process(tracer, HOOK_ATTACH);
}

int tracer_hooks_detach(struct bpf_tracer *tracer)
{
	return tracer_hooks_process(tracer, HOOK_DETACH);
}

int perf_map_init(struct bpf_tracer *tracer, const char *perf_map_name)
{
	struct bpf_map *map =
	    bpf_object__find_map_by_name(tracer->pobj, perf_map_name);
	int map_fd = bpf_map__fd(map);
	struct perf_reader *reader;
	int perf_fd, ret;
	int i;
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
		perf_fd = reader->fd;
		if ((ret = bpf_map_update_elem(map_fd, &i, &perf_fd, BPF_ANY))) {
			ebpf_info
			    ("fun: %s, bpf_map_update_elem reader setting failed.\n",
			     __func__);
			return ret;
		}
		tracer->readers[tracer->readers_count++] = reader;
	}

	tracer->data_map = map;

	return 0;
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
			atomic64_inc(&q->heap_get_faild);
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

	return 0;
}

static void ctrl_main(__unused void *arg)
{
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

	return 0;
}

int set_period_event_invalid(const char *name)
{
	struct period_event_op *peo = find_period_event(name);
	if (peo == NULL)
		return -1;

	peo->is_valid = false;

	ebpf_info("%s '%s' set invalid succeed.\n", __func__, name);

	return 0;
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

	return 0;
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

	return 0;
}

static void period_process_main(__unused void *arg)
{
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

	return 0;
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
		atomic64_init(&tracer->queues[i].heap_get_faild);

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
			return -EINVAL;
		}
	}

	ret =
	    pthread_create(&tracer->perf_worker[0], NULL, (void *)&poller,
			   (void *)tracer);
	if (ret) {
		ebpf_info("<%s> perf_worker, pthread_create is error:%s\n",
			  __func__, strerror(errno));
		return -EINVAL;
	}

	return 0;
}

/*
 * control plane
 */
static int tracer_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
	return 0;
}

static int tracer_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
			      void **out, size_t * outsize)
{
	*outsize = sizeof(struct bpf_tracer_param_array) +
	    sizeof(struct bpf_tracer_param) * tracers_count;

	*out = calloc(1, *outsize);
	if (*out == NULL) {
		ebpf_info("%s calloc, error:%s\n", __func__, strerror(errno));
		return -1;
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
		snprintf(btp->bpf_file, sizeof(btp->bpf_file), "%s",
			 t->bpf_file);
		btp->dispatch_workers_nr = t->dispatch_workers_nr;
		btp->perf_pg_cnt = t->perf_pages_cnt;
		btp->lost = atomic64_read(&t->lost);

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
			rx_q->heap_get_faild =
			    atomic64_read(&t->queues[j].heap_get_faild);
			rx_q->queue_size = ring_count(t->queues[j].r);
			rx_q->ring_capacity = t->queues[j].r->capacity;
		}
	}

	return 0;
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

int bpf_tracer_init(const char *log_file, bool is_stdout)
{
	int err;
	if (max_locked_memory_set_unlimited() != 0)
		return -1;

	if (sysfs_write("/proc/sys/net/core/bpf_jit_enable", "1") < 0)
		return -1;

	INIT_LIST_HEAD(&extra_waiting_head);
	INIT_LIST_HEAD(&period_events_head);

	log_to_stdout = is_stdout;
	if (log_file) {
		log_stream = fopen(log_file, "a+");
		if (log_stream == NULL) {
			ebpf_info("log file: %s", log_file);
			return -1;
		}
	}

	sys_cpus_count = get_cpus_count(&cpu_online);
	if (sys_cpus_count <= 0)
		return -1;

	uint64_t real_time, monotonic_time;
	real_time = gettime(CLOCK_REALTIME, TIME_TYPE_NAN);
	monotonic_time = gettime(CLOCK_MONOTONIC, TIME_TYPE_NAN);
	sys_boot_time_ns = real_time - monotonic_time;
	prev_sys_boot_time_ns = sys_boot_time_ns;
	ebpf_info("sys_boot_time_ns : %llu\n", sys_boot_time_ns);

	clear_residual_probes();

	if (ctrl_init()) {
		return -1;
	}

	if ((err = sockopt_register(&trace_sockopts)) != ETR_OK)
		return err;

	err = pthread_create(&ctrl_pthread, NULL, (void *)&ctrl_main, NULL);
	if (err) {
		ebpf_info("<%s> ctrl_pthread, pthread_create is error:%s\n",
			  __func__, strerror(errno));
		return -EINVAL;
	}

	if (register_period_event_op("kick_kern", cpus_kick_kern))
		return -EINVAL;

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
		return -EINVAL;

	err =
	    pthread_create(&cpus_kick_pthread, NULL,
			   (void *)&period_process_main, NULL);
	if (err) {
		ebpf_info
		    ("<%s> cpus_kick_pthread, pthread_create is error:%s\n",
		     __func__, strerror(errno));
		return -EINVAL;
	}

	return 0;
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
