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
#include <ctype.h>
#include <arpa/inet.h>
#include <sched.h>
#include <sys/prctl.h>
#include <arpa/inet.h>
#include <bcc/perf_reader.h>
#include <linux/version.h>
#include "clib.h"
#include "symbol.h"
#include "tracer.h"
#include "probe.h"
#include "table.h"
#include "common.h"
#include "socket.h"
#include "log.h"
#include "go_tracer.h"
#include "ssl_tracer.h"
#include "load.h"
#include "btf_vmlinux.h"
#include "config.h"
#include "perf_reader.h"

#include "socket_trace_bpf_common.c"
#include "socket_trace_bpf_3_10_0.c"
#include "socket_trace_bpf_5_2_plus.c"
#include "socket_trace_bpf_kylin.c"

static struct list_head events_list;	// Use for extra register events
static pthread_t proc_events_pthread;	// Process exec/exit thread

/*
 * tracer_hooks_detach() and tracer_hooks_attach() will become terrible
 * when the number of probes is very large. Because we have to spend a
 * long time waiting for it to complete, this is not a good way, we hope
 * that calling socket_tracer_stop() or socket_tracer_start() will not
 * block the execution of subsequent tasks.
 *
 * In order to solve this problem, we use a global variable(`probes_act`)
 * to hold the latest attach/detach behavior, it be executed later by
 * another thread, so that the current thread will not be blocked.
 */
static volatile uint64_t probes_act;

extern int sys_cpus_count;
extern bool *cpu_online;
extern uint32_t attach_failed_count;

static int infer_socktrace_fd;
static uint32_t conf_max_socket_entries;
static uint32_t conf_max_trace_entries;

/*
 * The datadump related Settings
 */
static bool datadump_use_remote;
static debug_callback_t datadump_cb;
static bool datadump_enable;
static int datadump_pid;	// If the value is 0, process-ID/thread-ID filtering is not performed.
static uint32_t datadump_start_time;
static uint32_t datadump_timeout;
static char datadump_comm[16];	// If null, process or thread name filtering is not performed.
static uint8_t datadump_proto;
static char datadump_file_path[DATADUMP_FILE_PATH_SIZE];
static FILE *datadump_file;
static pthread_mutex_t datadump_mutex;

/*
 * The maximum amount of data passed to the agent by eBPF programe.
 * Set by set_data_limit_max()
 */
static uint32_t socket_data_limit_max;

static uint32_t go_tracing_timeout = GO_TRACING_TIMEOUT_DEFAULT;

// 0: disable 1: during request 2: all
static uint32_t io_event_collect_mode = 1;
static uint64_t io_event_minimal_duration = 1000000;

/*
 * The maximum threshold for socket map reclamation, with map
 * reclamation occurring if this value is exceeded.
 */
static uint32_t conf_socket_map_max_reclaim;

struct bpf_tracer *g_tracer;

/*
 * The table for L7 protocol filtering ports.
 */
ports_bitmap_t *ports_bitmap[PROTO_NUM];

extern uint32_t k_version;
extern int major, minor;
extern char linux_release[128];

extern uint64_t sys_boot_time_ns;
extern uint64_t prev_sys_boot_time_ns;

extern uint64_t adapt_kern_uid;

static bool bpf_stats_map_collect(struct bpf_tracer *tracer,
				  struct trace_stats *stats_total);
static bool is_adapt_success(struct bpf_tracer *t);
static int update_offsets_table(struct bpf_tracer *t,
				struct bpf_offset_param *offset);
static void datadump_process(void *data);
static bool bpf_stats_map_update(struct bpf_tracer *tracer,
				 int socket_num, int trace_num);
static void socket_tracer_set_probes(struct tracer_probes_conf *tps)
{
	int index = 0, curr_idx;

	probes_set_enter_symbol(tps, "__sys_sendmsg");
	probes_set_enter_symbol(tps, "__sys_sendmmsg");
	probes_set_enter_symbol(tps, "__sys_recvmsg");
	probes_set_enter_symbol(tps, "__sys_recvmmsg");

	if (k_version == KERNEL_VERSION(3, 10, 0)) {
		/*
		 * The Linux 3.10 kernel interface for Redhat7 and
		 * Centos7 is sys_writev() and sys_readv()
		 */
		probes_set_enter_symbol(tps, "sys_writev");
		probes_set_enter_symbol(tps, "sys_readv");
	} else {
		probes_set_enter_symbol(tps, "do_writev");
		probes_set_enter_symbol(tps, "do_readv");
	}

	tps->kprobes_nr = index;

	/* tracepoints */
	index = 0;

	/*
	 * 由于在Linux 4.17+ sys_write, sys_read, sys_sendto, sys_recvfrom
	 * 接口会发生变化为了避免对内核的依赖采用tracepoints方式
	 */
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_write");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_read");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_sendto");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_recvfrom");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_connect");

	// exit tracepoints
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_socket");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_read");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_write");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_sendto");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_recvfrom");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_sendmsg");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_sendmmsg");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_recvmsg");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_recvmmsg");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_writev");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_readv");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_accept");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_accept4");
	// process execute
	tps_set_symbol(tps, "tracepoint/sched/sched_process_fork");
	tps_set_symbol(tps, "tracepoint/sched/sched_process_exec");

	// 周期性触发用于缓存的数据的超时检查
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_getppid");

	// clear trace connection
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_close");
	// fetch close info
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_close");

	// Used for process offsets management
	tps_set_symbol(tps, "tracepoint/sched/sched_process_exit");

	tps->tps_nr = index;

	// 收集go可执行文件uprobe符号信息
	collect_go_uprobe_syms_from_procfs(tps);

	collect_ssl_uprobe_syms_from_procfs(tps);
}

/* ==========================================================
 * 内核结构成员偏移推断，模拟一个TCP通信tick内核，使其完成推断
 * ==========================================================
 */
static int kernel_offset_infer_server(void)
{
	int cli_fd;
	struct sockaddr_in client_addr;
	socklen_t addr_len = sizeof(client_addr);
	memset(&client_addr, 0, sizeof(struct sockaddr_in));
	int client_count = 0, cpu_online_count = 0, i;
	for (i = 0; i < sys_cpus_count; i++) {
		if (cpu_online[i])
			cpu_online_count++;
	}

next_cpu_client:
	cli_fd =
	    accept(infer_socktrace_fd, (struct sockaddr *)&client_addr,
		   &addr_len);
	if (cli_fd < 0) {
		ebpf_warning("[eBPF Kernel Adapt] Fail to accept client"
			     "request - %s\n", strerror(errno));
		return ETR_IO;
	}

	char buffer[16];
	int len;
	for (;;) {
		len = recv(cli_fd, buffer, sizeof(buffer), 0);
		if (len < 0) {
			continue;
		}

		if (len == 0) {
			client_count++;
			close(cli_fd);
			break;
		}

		buffer[len] = '\0';
		if (strcmp(buffer, "hello") == 0) {
			snprintf(buffer, sizeof(buffer), "OK");
			send(cli_fd, buffer, 2, 0);
		}
	}

	if (client_count < cpu_online_count)
		goto next_cpu_client;

	close(infer_socktrace_fd);
	ebpf_info("[eBPF Kernel Adapt] kernel_offset_infer_server close."
		  "client_count:%d\n", client_count);
	return ETR_OK;
}

static int kernel_offset_infer_client(void)
{
	int cli_fd;
	struct sockaddr_in server_addr;
	char buf[16];
	int len;

	if ((cli_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		ebpf_warning
		    ("[eBPF Kernel Adapt] Fail client create socket - %s\n",
		     strerror(errno));
		return ETR_IO;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(OFFSET_INFER_SERVER_PORT);
	server_addr.sin_addr.s_addr = inet_addr(OFFSET_INFER_SERVER_ADDR);

	if (connect
	    (cli_fd, (struct sockaddr *)&server_addr,
	     sizeof(server_addr)) < 0) {
		ebpf_warning("[eBPF Kernel Adapt] Fail to connect"
			     " - %s\n", strerror(errno));
		return ETR_IO;
	}

	for (;;) {
		snprintf(buf, sizeof(buf), "hello");
		len = send(cli_fd, buf, strlen(buf), 0);
		if (len != strlen(buf))
			continue;
	      rcv_loop:
		len = recv(cli_fd, buf, sizeof(buf), 0);
		if (len > 0) {
			/*
			 * Another send action occurs here to avoid
			 * failure to infer the value of 'write_seq'.
			 * Troubleshoot the invalid kernel adaptation
			 * mechanism in EulerOS 2.9 and EulerOS 2.10
			 * (Linux 4.18).
			 */
			buf[len] = '\0';
			send(cli_fd, buf, len, 0);
			break;
		} else if (len == 0) {
			break;
		} else
			goto rcv_loop;
	}

	close(cli_fd);
	return ETR_OK;
}

static int kernel_offset_infer_init(void)
{
	struct sockaddr_in srv_addr;
	memset(&srv_addr, 0, sizeof(srv_addr));

	infer_socktrace_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (infer_socktrace_fd < 0) {
		ebpf_warning
		    ("[eBPF Kernel Adapt] Fail to create server socket - %s\n",
		     strerror(errno));
		return ETR_IO;
	}

	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(OFFSET_INFER_SERVER_PORT);
	srv_addr.sin_addr.s_addr = inet_addr(OFFSET_INFER_SERVER_ADDR);

	if (-1 ==
	    bind(infer_socktrace_fd, (struct sockaddr *)&srv_addr,
		 sizeof(srv_addr))) {
		ebpf_warning("[eBPF Kernel Adapt] Fail to bind server socket"
			     " %s:%d - %s\n"
			     "Please check the following two situations:\n"
			     "(1) Whether the %s address has been "
			     "configured on the loopback device.\n"
			     "(2) Check if port %d has already been occupied "
			     "by other services.\n\n"
			     "%s:%d is used to trigger a temporary service"
			     " for Linux kernel adaptation. It is important to ensure"
			     " that %s is configured on the lo device and that"
			     " port %d is not occupied by other services.\n\n"
			     "If port %d is occupied by other services, you can either"
			     " change the port number of the other service or wait until"
			     " the deepflow-agent is started before starting this service."
			     "This is because the deepflow-agent only temporarily uses "
			     "port %d during its startup phase and will close the service"
			     "once it is started.\n\n",
			     OFFSET_INFER_SERVER_ADDR,
			     OFFSET_INFER_SERVER_PORT,
			     strerror(errno),
			     OFFSET_INFER_SERVER_ADDR,
			     OFFSET_INFER_SERVER_PORT,
			     OFFSET_INFER_SERVER_ADDR,
			     OFFSET_INFER_SERVER_PORT,
			     OFFSET_INFER_SERVER_ADDR,
			     OFFSET_INFER_SERVER_PORT,
			     OFFSET_INFER_SERVER_PORT,
			     OFFSET_INFER_SERVER_PORT);
		close(infer_socktrace_fd);
		return ETR_IO;
	}

	if (-1 == listen(infer_socktrace_fd, 1)) {
		ebpf_warning
		    ("[eBPF Kernel Adapt] Server socket listen failed - %s\n",
		     strerror(errno));
		close(infer_socktrace_fd);
		return ETR_IO;
	}

	return ETR_OK;
}

static int socktrace_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
	return 0;
}

static bool bpf_offset_map_collect(struct bpf_tracer *tracer,
				   struct bpf_offset_param_array *array)
{
	int nr_cpus = get_num_possible_cpus();
	struct bpf_offset_param values[nr_cpus];
	if (!bpf_table_get_value(tracer, MAP_MEMBERS_OFFSET_NAME, 0, values))
		return false;

	struct bpf_offset_param *out_val =
	    (struct bpf_offset_param *)(array + 1);

	int i;
	for (i = 0; i < array->count; i++)
		out_val[i] = values[i];

	return true;
}

static int socktrace_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
				 void **out, size_t * outsize)
{
	struct bpf_tracer *t = find_bpf_tracer(SK_TRACER_NAME);
	if (t == NULL)
		return -1;

	*outsize = sizeof(struct bpf_socktrace_params) +
	    sizeof(struct bpf_offset_param) * sys_cpus_count;

	*out = calloc(1, *outsize);
	if (*out == NULL) {
		ebpf_warning("calloc, error:%s\n", strerror(errno));
		return -1;
	}

	struct bpf_socktrace_params *params = *out;
	struct bpf_offset_param_array *array = &params->offset_array;
	array->count = sys_cpus_count;

	params->kern_socket_map_max = conf_max_socket_entries;
	params->kern_trace_map_max = conf_max_trace_entries;
	params->tracer_state = t->state;

	pthread_mutex_lock(&datadump_mutex);
	params->datadump_enable = datadump_enable;
	params->datadump_pid = datadump_pid;
	params->datadump_proto = datadump_proto;
	safe_buf_copy(params->datadump_file_path,
		      sizeof(params->datadump_file_path),
		      (void *)datadump_file_path, sizeof(datadump_file_path));
	memcpy(params->datadump_comm, datadump_comm, sizeof(datadump_comm));
	pthread_mutex_unlock(&datadump_mutex);

	struct trace_stats stats_total;

	if (bpf_stats_map_collect(t, &stats_total)) {
		params->kern_socket_map_used = stats_total.socket_map_count;
		params->kern_trace_map_used = stats_total.trace_map_count;
	}

	if (!bpf_offset_map_collect(t, array)) {
		free(*out);
		return -1;
	}

	return 0;
}

static struct tracer_sockopts socktrace_sockopts = {
	.version = SOCKOPT_VERSION,
	.set_opt_min = SOCKOPT_SET_SOCKTRACE_ADD,
	.set_opt_max = SOCKOPT_SET_SOCKTRACE_FLUSH,
	.set = socktrace_sockopt_set,
	.get_opt_min = SOCKOPT_GET_SOCKTRACE_SHOW,
	.get_opt_max = SOCKOPT_GET_SOCKTRACE_SHOW,
	.get = socktrace_sockopt_get,
};

static int datadump_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
	struct datadump_msg *msg = (struct datadump_msg *)conf;
	pthread_mutex_lock(&datadump_mutex);
	if (msg->is_params) {
		datadump_pid = msg->pid;
		datadump_proto = msg->proto;
		safe_buf_copy(datadump_comm, sizeof(datadump_comm),
			      (void *)msg->comm, sizeof(msg->comm));
		ebpf_info("Set datadump pid %d comm %s proto %d\n",
			  datadump_pid, datadump_comm, datadump_proto);
	} else {
		if (!datadump_enable && msg->enable) {
			// create a new output file
			if (datadump_file == stdout && !msg->only_stdout) {
				char *file = gen_file_name_by_datetime();
				if (file != NULL) {
					snprintf(datadump_file_path,
						 sizeof(datadump_file_path),
						 "%s/datadump-%s.log",
						 DATADUMP_FILE_PATH_PREFIX,
						 file);
					free(file);
					datadump_file =
					    fopen(datadump_file_path, "a+");
					if (datadump_file == NULL) {
						memcpy(datadump_file_path,
						       "stdout", 7);
						datadump_file = stdout;
					}
					ebpf_info("create datadump file %s\n",
						  datadump_file_path);
				}
			}
		}

		if (msg->enable) {
			datadump_start_time = get_sys_uptime();
			datadump_timeout = msg->timeout;
		}

		if (datadump_enable && !msg->enable) {
			datadump_timeout = 0;
			datadump_pid = 0;
			datadump_comm[0] = '\0';
			datadump_proto = 0;
			fprintf(datadump_file,
				"\n\nDump data is finished, use time: %us.\n\n",
				get_sys_uptime() - datadump_start_time);
			if (datadump_file != stdout) {
				fclose(datadump_file);
				ebpf_info("close datadump file %s\n",
					  datadump_file_path);
			}
			memcpy(datadump_file_path, "stdout", 7);
			datadump_file = stdout;
			datadump_start_time = 0;
		}

		datadump_enable = msg->enable;
		ebpf_info("datadump %s\n",
			  datadump_enable ? "enable" : "disable");
	}
	pthread_mutex_unlock(&datadump_mutex);
	return 0;
}

static int datadump_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
				void **out, size_t * outsize)
{
	return 0;
}

/*
 * Configure and enable datadump
 *
 * @pid
 *   Specifying a process ID or thread ID. If set to '0', it indicates
 *   all processes or threads.
 * @comm
 *   Specifying a process name or thread name. If set to an empty string(""),
 *   it indicates all processes or threads.
 * @proto
 *   Specifying the L7 protocol number. If set to '0', it indicates all
 *   L7 protocols.
 * @timeout
 *   Specifying the timeout duration. If the elapsed time exceeds this
 *   duration, datadump will stop. The unit is in seconds.
 * @callback
 *   Callback interface, used to transfer data to the remote controller.
 *
 * @return 0 on success, and a negative value on failure.
 */
int datadump_set_config(int pid, const char *comm, int proto, int timeout,
			debug_callback_t cb)
{
	if (pid < 0 || proto < 0 || proto >= PROTO_NUM || comm == NULL
	    || timeout <= 0) {
		ebpf_warning("Invalid parameter\n");
		return -1;
	}

	pthread_mutex_lock(&datadump_mutex);
	if (datadump_enable) {
		ebpf_warning("datadump is already running in the process.\n");
		goto finish;
	}

	datadump_enable = true;
	datadump_use_remote = true;
	datadump_pid = pid;
	datadump_proto = (uint8_t) proto;
	datadump_cb = cb;
	datadump_comm[0] = '\0';
	datadump_start_time = get_sys_uptime();
	datadump_timeout = timeout;
	if (strlen(comm) > 0)
		safe_buf_copy(datadump_comm, sizeof(datadump_comm),
			      (void *)comm, strlen(comm));
	ebpf_info("Set datadump pid %d comm '%s' proto %d\n",
		  datadump_pid, datadump_comm, datadump_proto);

finish:
	pthread_mutex_unlock(&datadump_mutex);
	return 0;
}

static struct tracer_sockopts datadump_sockopts = {
	.version = SOCKOPT_VERSION,
	.set_opt_min = SOCKOPT_SET_DATADUMP_ADD,
	.set_opt_max = SOCKOPT_SET_DATADUMP_OFF,
	.set = datadump_sockopt_set,
	.get_opt_min = SOCKOPT_GET_DATADUMP_SHOW,
	.get_opt_max = SOCKOPT_GET_DATADUMP_SHOW,
	.get = datadump_sockopt_get,
};

// TODO : 标记上层是否需要重新确认协议准确性
// 目前上层没有实现协议再次确认的功能,对需要重新确认的包直接丢弃,这里临时设置数据包不需要重新确认
// 上层实现重新确认功能后再使用
static inline bool need_proto_reconfirm(uint16_t l7_proto)
{
	return false;
}

static void process_event(struct process_event_t *e)
{
	if (e->meta.event_type == EVENT_TYPE_PROC_EXEC) {
		update_proc_info_cache(e->pid, PROC_EXEC);
		go_process_exec(e->pid);
		ssl_process_exec(e->pid);
	} else if (e->meta.event_type == EVENT_TYPE_PROC_EXIT) {
		/* Cache for updating process information used in
		 * symbol resolution. */
		update_proc_info_cache(e->pid, PROC_EXIT);
		go_process_exit(e->pid);
		ssl_process_exit(e->pid);
	}
}

static inline int dispatch_queue_index(uint64_t val, int count)
{
	return xxhash(val) % count;
}

// Some event types of data are handled by the user using a separate callback interface,
// which completes the dispatch logic after reading the data from the Perf-Reader.
static int register_events_handle(struct reader_forward_info *fwd_info,
				  struct event_meta *meta,
				  int size, struct bpf_tracer *tracer)
{
	// Internal logic processing for process exec/exit.
	if (meta->event_type == EVENT_TYPE_PROC_EXEC ||
	    meta->event_type == EVENT_TYPE_PROC_EXIT) {
		process_event((struct process_event_t *)meta);
	}

	struct extra_event *e;
	void (*fn) (void *) = NULL;
	list_for_each_entry(e, &events_list, list) {
		if (e->type & meta->event_type) {
			fn = e->h;
			break;
		}
	}

	if (fn == NULL) {
		return ETR_NOHANDLE;
	}

	uint64_t q_idx;
	struct queue *q;
	int nr;
	struct mem_block_head *block_head;

	q_idx = fwd_info->queue_id;
	q = &tracer->queues[q_idx];
	block_head = malloc(sizeof(struct mem_block_head) + size);
	if (block_head == NULL) {
		ebpf_warning("block_head alloc memory failed\n");
		return ETR_NOMEM;
	}

	void *data = block_head + 1;
	memcpy(data, meta, size);
	nr = ring_sp_enqueue_burst(q->r, (void **)&data, 1, NULL);
	if (nr < 1) {
		atomic64_add(&q->enqueue_lost, 1);
		free(block_head);
		ebpf_warning("Add ring(q:%d) failed\n", q_idx);
		return ETR_NOROOM;
	}

	block_head->free_ptr = block_head;
	block_head->is_last = 1;
	block_head->fn = fn;

	pthread_mutex_lock(&q->mutex);
	pthread_cond_signal(&q->cond);
	pthread_mutex_unlock(&q->mutex);

	atomic64_add(&q->enqueue_nr, nr);

	return ETR_OK;
}

// Read datas from perf ring-buffer and dispatch.
static void reader_raw_cb(void *cookie, void *raw, int raw_size)
{
#ifdef TLS_DEBUG
	struct debug_data *debug = raw;
	if (debug->magic == 0xffff || debug->magic == 0xfffe) {
		const char *fun;
		if (debug->fun == 1)
			fun = "go_tls_write_enter";
		else if (debug->fun == 2)
			fun = "go_tls_write_exit";
		else if (debug->fun == 3)
			fun = "go_tls_read_enter";
		else if (debug->fun == 4)
			fun = "go_tls_read_exit";
		else
			fun = "unknown";

		const char *err = "";
		if (debug->num == 1 || debug->num == 2)
			err = "(E)";

		if (debug->magic == 0xffff) {
			fprintf(stdout,
				">UPROBE DEBUG nobuf fun %s num %d%s len %d\n",
				fun, debug->num, err, debug->len);
		} else {
			fprintf(stdout,
				">UPROBE DEBUG buf fun %s num %d%s [%d(%c) "
				"%d(%c) %d(%c) %d(%c)]\n", fun, debug->num, err,
				debug->buf[0], debug->buf[0], debug->buf[1],
				debug->buf[1], debug->buf[2], debug->buf[2],
				debug->buf[3], debug->buf[3]);
		}
		fflush(stdout);
		return;
	}
#endif

	struct reader_forward_info *fwd_info = cookie;
	ebpf_debug(stdout, "* fwd cpu %d -> queue %ld\n",
		   fwd_info->cpu_id, fwd_info->queue_id);
	struct bpf_tracer *tracer = g_tracer;
	struct event_meta *ev_meta = raw;

	/*
	 * If 0 < ev_meta->event_type < EVENT_TYPE_MIN is 'socket data buffer'
	 * else if ev_meta->event_type >= EVENT_TYPE_MIN is register events.
	 *
	 * If raw is socket data, 'ev_meta->event_type' indicates the number of events sent by
	 * the kernel in the buffer. The value here must be greater than zero.
	 */
	if (ev_meta->event_type <= 0) {
		return;
	}

	if (ev_meta->event_type >= EVENT_TYPE_MIN) {
		register_events_handle(fwd_info, ev_meta, raw_size, tracer);
		return;
	}

	/*
	 * In the following, the socket data buffer is processed.
	 */

	uint64_t q_idx;
	struct queue *q;
	int nr;
	struct mem_block_head *block_head;	// 申请内存块的指针

	struct __socket_data_buffer *buf = (struct __socket_data_buffer *)raw;
	int data_offset = offsetof(typeof(struct __socket_data_buffer), data);
	if (raw_size < data_offset) {
		ebpf_warning("The amount(%d) of received data is less than the "
			     "minimum value(%d).\n", raw_size, data_offset);
		return;
	}

	if (raw_size < (buf->len + data_offset)) {
		ebpf_warning("There is an error in the received data length."
			     "raw_size %d events_num %u data_len %u.\n",
			     raw_size, buf->events_num, buf->len);
		return;
	}

	if (buf->events_num <= 0 || buf->events_num > MAX_PKT_BURST) {
		ebpf_warning("buf->events_num %u, invalid\n", buf->events_num);
		return;
	}

	if (buf->len < (offsetof(typeof(struct __socket_data),
				 data) * buf->events_num)) {
		ebpf_warning("buf->len(%u) invalid, socket data head size %u, "
			     "events_num %u\n", buf->len,
			     offsetof(typeof(struct __socket_data), data),
			     buf->events_num);
		return;
	}

	int i, start = 0;
	struct __socket_data *sd;
	sd = (struct __socket_data *)&buf->data[start];

	/* check uprobe data(GO HTTP2) message type */
	if (sd->source == DATA_SOURCE_GO_HTTP2_UPROBE ||
	    sd->source == DATA_SOURCE_GO_HTTP2_DATAFRAME_UPROBE) {
		if (sd->msg_type == MSG_UNKNOWN)
			return;
	}

	/* Determine which queue to distribute to based on the first socket_data. */
	q_idx = fwd_info->queue_id;
	q = &tracer->queues[q_idx];

	if (buf->events_num > MAX_PKT_BURST) {
		ebpf_info
		    ("buf->events_num > MAX_PKT_BURST(16) error. events_num:%d\n",
		     buf->events_num);
		return;
	}

	struct socket_bpf_data *burst_data[MAX_PKT_BURST];

	/*
	 * ----------- -> memory block ptr (free_ptr)
	 *         |                /\
	 *         |                *
	 * --------------------|    *
	 *      mem_block_head |    *
	 *      >is_last-------|    *   is_last 判断是否是内存块中最后一个socket data,
	 *      >*free_ptr     | ****   如果是释放整个内存。
	 *      ---------------|----> burst enqueue
	 *                     |
	 *      socket_data    |
	 *                     |
	 * --------------------|
	 *         |
	 *         |
	 * ---------
	 */
	struct socket_bpf_data *submit_data;
	int len;
	void *data_buf_ptr;

	// 所有载荷的数据总大小（去掉头）
	int alloc_len = buf->len - offsetof(typeof(struct __socket_data),
					    data) * buf->events_num;
	alloc_len += sizeof(*submit_data) * buf->events_num;	// 计算长度包含要提交的数据的头
	alloc_len += sizeof(struct mem_block_head) * buf->events_num;	// 包含内存块head
	alloc_len += sizeof(sd->extra_data) * buf->events_num;	// 可能包含额外数据
	alloc_len = CACHE_LINE_ROUNDUP(alloc_len);	// 保持cache line对齐

	void *socket_data_buff = malloc(alloc_len);
	if (socket_data_buff == NULL) {
		ebpf_warning("malloc() error.\n");
		atomic64_inc(&q->heap_get_failed);
		return;
	}

	data_buf_ptr = socket_data_buff;

	for (i = 0; i < buf->events_num; i++) {
		sd = (struct __socket_data *)&buf->data[start];
		len = sd->data_len;
		block_head = (struct mem_block_head *)data_buf_ptr;
		block_head->is_last = 0;
		block_head->free_ptr = socket_data_buff;
		block_head->fn = NULL;

		data_buf_ptr = block_head + 1;
		submit_data = data_buf_ptr;

		submit_data->socket_id = sd->socket_id;

		// 数据捕获时间戳，精度为微秒(us)
		submit_data->timestamp =
		    (sd->timestamp + sys_boot_time_ns) / 1000ULL;

		submit_data->tuple = sd->tuple;
		submit_data->direction = sd->direction;
		submit_data->l7_protocal_hint = sd->data_type;
		submit_data->need_reconfirm =
		    need_proto_reconfirm(sd->data_type);
		submit_data->process_id = sd->tgid;
		submit_data->thread_id = sd->pid;
		submit_data->coroutine_id = sd->coroutine_id;
		submit_data->source = sd->source;
		submit_data->is_tls = sd->is_tls;
		if (sd->source == DATA_SOURCE_GO_TLS_UPROBE ||
		    sd->source == DATA_SOURCE_OPENSSL_UPROBE)
			submit_data->is_tls = true;

		submit_data->cap_data =
		    (char *)((void **)&submit_data->cap_data + 1);
		submit_data->syscall_len = sd->syscall_len;
		submit_data->tcp_seq = sd->tcp_seq;
		submit_data->cap_seq = sd->data_seq;
		submit_data->syscall_trace_id_call = sd->thread_trace_id;
		safe_buf_copy(submit_data->process_kname,
			      sizeof(submit_data->process_kname), sd->comm,
			      sizeof(sd->comm));
		submit_data->process_kname[sizeof(submit_data->process_kname) -
					   1] = '\0';
		get_container_id_from_procs_cache(sd->tgid,
						  submit_data->container_id,
						  sizeof
						  (submit_data->container_id));
		submit_data->msg_type = sd->msg_type;
		submit_data->socket_role = sd->socket_role;

		// 各种协议的统计
		if (sd->data_type >= PROTO_NUM)
			sd->data_type = PROTO_UNKNOWN;

		atomic64_inc(&tracer->proto_status[sd->data_type]);
		int offset = 0;
		if (len > 0) {
			if (sd->extra_data_count > 0) {
				memcpy_fast(submit_data->cap_data,
					    sd->extra_data,
					    sd->extra_data_count);
				offset = sd->extra_data_count;
			}

			memcpy_fast(submit_data->cap_data + offset, sd->data,
				    len);
			submit_data->cap_data[len + offset] = '\0';
		}
		submit_data->syscall_len += offset;
		submit_data->cap_len = len + offset;
		burst_data[i] = submit_data;

		start +=
		    (offsetof(typeof(struct __socket_data), data) +
		     sd->data_len);

		data_buf_ptr += sizeof(*submit_data) + submit_data->cap_len;
	}

	nr = ring_sp_enqueue_burst
	    (q->r, (void **)burst_data, buf->events_num, NULL);

	if (nr < buf->events_num) {
		int lost = buf->events_num - nr;
		atomic64_add(&q->enqueue_lost, lost);
		if (lost == buf->events_num) {
			free(socket_data_buff);
			return;
		}
	}

	submit_data = burst_data[nr - 1];
	block_head = (struct mem_block_head *)submit_data - 1;
	block_head->is_last = 1;

	/*
	 * 通知工作线程进行dequeue，并进行数据处理。
	 */
	pthread_mutex_lock(&q->mutex);
	pthread_cond_signal(&q->cond);
	pthread_mutex_unlock(&q->mutex);

	atomic64_add(&q->enqueue_nr, nr);
}

static void reader_lost_cb(void *cookie, uint64_t lost)
{
	struct reader_forward_info *fwd_info = cookie;
	struct bpf_tracer *tracer = fwd_info->tracer;
	atomic64_add(&tracer->lost, lost);
}

static void reclaim_trace_map(struct bpf_tracer *tracer, uint32_t timeout)
{
	struct ebpf_map *map =
	    ebpf_obj__get_map_by_name(tracer->obj, MAP_TRACE_NAME);
	if (map == NULL) {
		ebpf_warning("[%s] map(name:%s) is NULL.\n", __func__,
			     MAP_TRACE_NAME);
		return;
	}
	int map_fd = map->fd;

	struct trace_key_t trace_key = {}, next_trace_key;
	uint32_t reclaim_count = 0;
	struct trace_info_t value;
	uint32_t uptime = get_sys_uptime();
	uint32_t curr_trace_count = 0, limit;
	limit = conf_max_trace_entries * RECLAIM_TRACE_MAP_SCALE;
	struct list_head clear_elem_head;
	init_list_head(&clear_elem_head);

	while (bpf_get_next_key(map_fd, &trace_key, &next_trace_key) == 0) {
		if (bpf_lookup_elem(map_fd, &next_trace_key, &value) == 0) {
			curr_trace_count++;
			if (uptime - value.update_time > timeout &&
			    reclaim_count < limit) {
				if (insert_list(&next_trace_key,
						sizeof(next_trace_key),
						&clear_elem_head)) {
					reclaim_count++;
				}
			}
		}

		trace_key = next_trace_key;
	}

	reclaim_count = __reclaim_map(map_fd, &clear_elem_head);
	// The trace statistics map needs to be updated to reflect the count.   
	curr_trace_count -= reclaim_count;
	if (!bpf_stats_map_update(tracer, -1, curr_trace_count)) {
		ebpf_warning("Update trace statistics failed.\n");
	}

	ebpf_info("[%s] curr_trace_count %u trace map reclaim_count :%u\n",
		  __func__, curr_trace_count, reclaim_count);
}

static void reclaim_socket_map(struct bpf_tracer *tracer, uint32_t timeout)
{
	struct ebpf_map *map =
	    ebpf_obj__get_map_by_name(tracer->obj, MAP_SOCKET_INFO_NAME);
	if (map == NULL) {
		ebpf_warning("[%s] map(name:%s) is NULL.\n", __func__,
			     MAP_SOCKET_INFO_NAME);
		return;
	}
	int map_fd = map->fd;

	uint64_t conn_key, next_conn_key;
	uint32_t sockets_reclaim_count = 0;
	struct socket_info_t value;
	conn_key = 0;
	uint32_t uptime = get_sys_uptime();
	uint32_t curr_socket_count = 0;
	struct list_head clear_elem_head;
	init_list_head(&clear_elem_head);

	while (bpf_get_next_key(map_fd, &conn_key, &next_conn_key) == 0) {
		if (bpf_lookup_elem(map_fd, &next_conn_key, &value) == 0) {
			curr_socket_count++;
			if ((uptime - value.update_time > timeout) &&
			    (sockets_reclaim_count <
			     conf_socket_map_max_reclaim)) {
				if (insert_list(&next_conn_key,
						sizeof(next_conn_key),
						&clear_elem_head)) {
					sockets_reclaim_count++;
				}
			}
		}
		conn_key = next_conn_key;
	}

	sockets_reclaim_count = __reclaim_map(map_fd, &clear_elem_head);
	curr_socket_count -= sockets_reclaim_count;
	if (!bpf_stats_map_update(tracer, curr_socket_count, -1)) {
		ebpf_warning("Update trace statistics failed.\n");
	}

	ebpf_info("[%s] curr_socket_count %u sockets_reclaim_count :%u\n",
		  __func__, curr_socket_count, sockets_reclaim_count);
}

static int check_map_exceeded(void)
{
	struct bpf_tracer *t = find_bpf_tracer(SK_TRACER_NAME);
	if (t == NULL)
		return -1;

	int64_t kern_socket_map_used = 0, kern_trace_map_used = 0;

	struct trace_stats stats_total;

	if (bpf_stats_map_collect(t, &stats_total)) {
		kern_socket_map_used = stats_total.socket_map_count;
		kern_trace_map_used = stats_total.trace_map_count;
	}

	if (kern_socket_map_used >= conf_socket_map_max_reclaim) {
		ebpf_info("Current socket map used %u exceed"
			  " conf_socket_map_max_reclaim %u,reclaim map\n",
			  kern_socket_map_used, conf_socket_map_max_reclaim);
		reclaim_socket_map(t, SOCKET_RECLAIM_TIMEOUT_DEF);
	}

	if (kern_trace_map_used >=
	    (int64_t) (conf_max_trace_entries * RECLAIM_TRACE_MAP_SCALE)) {
		ebpf_info("Current trace map used %u exceed"
			  " reclaim_map_max %u,reclaim map\n",
			  kern_trace_map_used,
			  (uint32_t) (conf_max_trace_entries *
				      RECLAIM_TRACE_MAP_SCALE));
		reclaim_trace_map(t, TRACE_RECLAIM_TIMEOUT_DEF);
	}

	return 0;
}

static inline void add_probes_act(enum probes_act_type type)
{
	probes_act = type;
}

static int check_kern_adapt_and_state_update(void)
{
	struct bpf_tracer *t = find_bpf_tracer(SK_TRACER_NAME);
	if (t == NULL)
		return -1;

	if (is_adapt_success(t) && attach_failed_count == 0) {
		ebpf_info("[eBPF Kernel Adapt] Linux %s adapt success. "
			  "Set the status to TRACER_RUNNING\n", linux_release);
		t->state = TRACER_RUNNING;
		CLIB_MEMORY_BARRIER();
		add_probes_act(ACT_DETACH);
		set_period_event_invalid("check-kern-adapt");
		t->adapt_success = true;
	}

	return 0;
}

static void process_probes_act(struct bpf_tracer *t)
{
	if (probes_act == ACT_NONE)
		return;
	enum probes_act_type type = probes_act;

	/*
	 * Probes attach/detach in multithreading, e.g.:
	 * 1. Snoop go process execute/exit events, then process events(add/remove probes).
	 * 2. Start/stop tracer need process probes.
	 * The above scenario is handled in different threads, so use thread locks for protection.
	 */
	pthread_mutex_lock(&t->mutex_probes_lock);
	// If there is an unfinished attach/detach, return directly.
	if (t->state == TRACER_WAIT_STOP || t->state == TRACER_WAIT_START) {
		ebpf_warning("Current state: %s. There are unfinished tasks.\n",
			     get_tracer_state_name(t->state));
		pthread_mutex_unlock(&t->mutex_probes_lock);
		return;
	}

	if (type == ACT_DETACH && t->state == TRACER_RUNNING) {
		t->state = TRACER_WAIT_STOP;
		ebpf_info("Set current state: TRACER_WAIT_STOP.\n");
		if (tracer_hooks_detach(t) == 0) {
			t->state = TRACER_STOP;
			ebpf_info("Set current state: TRACER_STOP.\n");
		} else {
			t->state = TRACER_STOP_ERR;
			ebpf_warning("Set current state: TRACER_STOP_ERR.\n");
		}
		CLIB_MEMORY_BARRIER();
		// clean socket map
		reclaim_socket_map(t, 0);
	} else if (type == ACT_ATTACH && t->state == TRACER_STOP) {
		t->state = TRACER_WAIT_START;
		ebpf_info("Set current state: TRACER_WAIT_START.\n");
		if (tracer_hooks_attach(t) == 0) {
			t->state = TRACER_RUNNING;
			ebpf_info("Set current state: TRACER_RUNNING.\n");
		} else {
			t->state = TRACER_START_ERR;
			ebpf_warning("Set current state: TRACER_START_ERR.\n");
		}
		CLIB_MEMORY_BARRIER();
	}
	pthread_mutex_unlock(&t->mutex_probes_lock);
}

static void check_datadump_timeout(void)
{
	uint32_t passed_sec;
	pthread_mutex_lock(&datadump_mutex);
	if (datadump_enable) {
		passed_sec = get_sys_uptime() - datadump_start_time;
		if (passed_sec > datadump_timeout) {
			datadump_start_time = 0;
			datadump_enable = false;
			datadump_use_remote = false;
			datadump_pid = 0;
			datadump_comm[0] = '\0';
			datadump_proto = 0;
			fprintf(datadump_file,
				"\n\nDump data is finished, use time: %us.\n\n",
				datadump_timeout);
			if (datadump_file != stdout) {
				ebpf_info("close datadump file %s\n",
					  datadump_file_path);
				fclose(datadump_file);
			}
			memcpy(datadump_file_path, "stdout", 7);
			datadump_file = stdout;
			datadump_timeout = 0;
			ebpf_info("datadump disable\n");
		}
	}
	pthread_mutex_unlock(&datadump_mutex);
}

// Manage process start or exit events.
static void process_events_handle_main(__unused void *arg)
{
	prctl(PR_SET_NAME, "proc-events");
	struct bpf_tracer *t = arg;
	for (;;) {
		/*
		 * Will attach/detach all probes in the following cases:
		 *
		 * 1 The socket tracer startup phase will transition from TRACER_INIT to TRACER_STOP.
		 * 2 states from TRACER_STOP to TRACER_RUNNIN.
		 * 3 state from TRACER_RUNNING to TRACER_STOP.
		 *
		 * The behavior of attach/detach will take a lot of time, we will store it into
		 * `probes_act` for asynchronous processing.
		 *
		 * Here, handle attach/detach behavior.
		 */
		process_probes_act(t);

		go_process_events_handle();
		ssl_events_handle();
		check_datadump_timeout();
		usleep(LOOP_DELAY_US);
	}
}

static int update_offset_map_default(struct bpf_tracer *t,
				     enum linux_kernel_type kern_type)
{
	struct bpf_offset_param offset;
	memset(&offset, 0, sizeof(offset));

	switch (kern_type) {
	case K_TYPE_VER_3_10:
		offset.struct_files_struct_fdt_offset = 0x8;
		offset.struct_files_private_data_offset = 0xa8;
		break;
	case K_TYPE_KYLIN:
		offset.struct_files_struct_fdt_offset = 0x20;
		offset.struct_files_private_data_offset = 0xc0;
		break;
	default:
		offset.struct_files_struct_fdt_offset = 0x20;
		offset.struct_files_private_data_offset = 0xc8;
	};

	offset.struct_file_f_inode_offset = 0x20;
	offset.struct_inode_i_mode_offset = 0x0;
	offset.struct_file_dentry_offset = 0x18;
	offset.struct_dentry_name_offset = 0x28;
	offset.struct_sock_family_offset = 0x10;
	offset.struct_sock_saddr_offset = 0x4;
	offset.struct_sock_daddr_offset = 0x0;
	offset.struct_sock_ip6saddr_offset = 0x48;
	offset.struct_sock_ip6daddr_offset = 0x38;
	offset.struct_sock_dport_offset = 0xc;
	offset.struct_sock_sport_offset = 0xe;
	offset.struct_sock_skc_state_offset = 0x12;
	offset.struct_sock_common_ipv6only_offset = 0x13;

	if (update_offsets_table(t, &offset) != ETR_OK) {
		ebpf_error("update_offset_map_default failed.\n");
		return ETR_UPDATE_MAP_FAILD;
	}
	return ETR_OK;
}

static int update_offset_map_from_btf_vmlinux(struct bpf_tracer *t)
{
	struct ebpf_object *obj = t->obj;
	if (DF_IS_ERR_OR_NULL(obj->btf_vmlinux)) {
		ebpf_info("btf_vmlinux is null.\n");
		return ETR_NOTSUPP;
	}

	int copied_seq_offs, write_seq_offs, files_offs, sk_flags_offs;
	copied_seq_offs =
	    kernel_struct_field_offset(obj, "tcp_sock", "copied_seq");
	write_seq_offs =
	    kernel_struct_field_offset(obj, "tcp_sock", "write_seq");
	files_offs = kernel_struct_field_offset(obj, "task_struct", "files");
	sk_flags_offs =
	    kernel_struct_field_offset(obj, "sock", "__sk_flags_offset");

	/*
	 * From linux 5.6+, struct sock has changed(without '__sk_flags_offset[0]').
	 * ...
	 *      u8 sk_padding : 1,
	 *         sk_kern_sock : 1,
	 *         sk_no_check_tx : 1,
	 *         sk_no_check_rx : 1,
	 *         sk_userlocks : 4;
	 *      u8  sk_pacing_shift;
	 *      u16 sk_type;
	 * ...
	 * Ajust:
	 * sk_flags_offs = [sk_pacing_shift offset] - 1;
	 */
	if (sk_flags_offs == ETR_NOTEXIST) {
		sk_flags_offs =
		    kernel_struct_field_offset(obj, "sock", "sk_pacing_shift");
		if (sk_flags_offs > 0) {
			sk_flags_offs -= 1;
		}
	}

	int struct_files_struct_fdt_offset =
	    kernel_struct_field_offset(obj, "files_struct", "fdt");
	int struct_files_private_data_offset =
	    kernel_struct_field_offset(obj, "file", "private_data");
	int struct_file_f_inode_offset =
	    kernel_struct_field_offset(obj, "file", "f_inode");
	int struct_inode_i_mode_offset =
	    kernel_struct_field_offset(obj, "inode", "i_mode");
	int struct_file_dentry_offset_1 =
	    kernel_struct_field_offset(obj, "file", "f_path");
	int struct_file_dentry_offset_2 =
	    kernel_struct_field_offset(obj, "path", "dentry");
	if (struct_file_dentry_offset_1 < 0 || struct_file_dentry_offset_2 < 0) {
		return ETR_NOTSUPP;
	}
	int struct_file_dentry_offset =
	    struct_file_dentry_offset_1 + struct_file_dentry_offset_2;
	int struct_dentry_name_offset_1 =
	    kernel_struct_field_offset(obj, "dentry", "d_name");
	int struct_dentry_name_offset_2 =
	    kernel_struct_field_offset(obj, "qstr", "name");
	if (struct_dentry_name_offset_1 < 0 || struct_dentry_name_offset_2 < 0) {
		return ETR_NOTSUPP;
	}
	int struct_dentry_name_offset =
	    struct_dentry_name_offset_1 + struct_dentry_name_offset_2;
	int struct_sock_family_offset =
	    kernel_struct_field_offset(obj, "sock_common", "skc_family");
	int struct_sock_saddr_offset =
	    kernel_struct_field_offset(obj, "sock_common", "skc_rcv_saddr");
	int struct_sock_daddr_offset =
	    kernel_struct_field_offset(obj, "sock_common", "skc_daddr");
	int struct_sock_ip6saddr_offset =
	    kernel_struct_field_offset(obj, "sock_common", "skc_v6_rcv_saddr");
	int struct_sock_ip6daddr_offset =
	    kernel_struct_field_offset(obj, "sock_common", "skc_v6_daddr");
	int struct_sock_dport_offset =
	    kernel_struct_field_offset(obj, "sock_common", "skc_dport");
	int struct_sock_sport_offset =
	    kernel_struct_field_offset(obj, "sock_common", "skc_num");
	int struct_sock_skc_state_offset =
	    kernel_struct_field_offset(obj, "sock_common", "skc_state");
	int struct_sock_common_ipv6only_offset =
	    kernel_struct_field_offset(obj, "sock_common", "skc_flags");

	if (copied_seq_offs < 0 || write_seq_offs < 0 || files_offs < 0 ||
	    sk_flags_offs < 0 || struct_files_struct_fdt_offset < 0 ||
	    struct_files_private_data_offset < 0 ||
	    struct_file_f_inode_offset < 0 || struct_inode_i_mode_offset < 0 ||
	    struct_inode_i_mode_offset < 0 || struct_file_dentry_offset < 0 ||
	    struct_dentry_name_offset < 0 || struct_sock_family_offset < 0 ||
	    struct_sock_saddr_offset < 0 || struct_sock_daddr_offset < 0 ||
	    struct_sock_ip6saddr_offset < 0 ||
	    struct_sock_ip6daddr_offset < 0 || struct_sock_dport_offset < 0 ||
	    struct_sock_sport_offset < 0 || struct_sock_skc_state_offset < 0 ||
	    struct_sock_common_ipv6only_offset < 0) {
		return ETR_NOTSUPP;
	}

	ebpf_info("Offsets from BTF vmlinux:\n");
	ebpf_info("    copied_seq_offs: 0x%x\n", copied_seq_offs);
	ebpf_info("    write_seq_offs: 0x%x\n", write_seq_offs);
	ebpf_info("    files_offs: 0x%x\n", files_offs);
	ebpf_info("    sk_flags_offs: 0x%x\n", sk_flags_offs);
	ebpf_info("    struct_files_struct_fdt_offset: 0x%x\n",
		  struct_files_struct_fdt_offset);
	ebpf_info("    struct_files_private_data_offset: 0x%x\n",
		  struct_files_private_data_offset);
	ebpf_info("    struct_file_f_inode_offset: 0x%x\n",
		  struct_file_f_inode_offset);
	ebpf_info("    struct_inode_i_mode_offset: 0x%x\n",
		  struct_inode_i_mode_offset);
	ebpf_info("    struct_file_dentry_offset: 0x%x\n",
		  struct_file_dentry_offset);
	ebpf_info("    struct_dentry_name_offset: 0x%x\n",
		  struct_dentry_name_offset);
	ebpf_info("    struct_sock_family_offset: 0x%x\n",
		  struct_sock_family_offset);
	ebpf_info("    struct_sock_saddr_offset: 0x%x\n",
		  struct_sock_saddr_offset);
	ebpf_info("    struct_sock_daddr_offset: 0x%x\n",
		  struct_sock_daddr_offset);
	ebpf_info("    struct_sock_ip6saddr_offset: 0x%x\n",
		  struct_sock_ip6saddr_offset);
	ebpf_info("    struct_sock_ip6daddr_offset: 0x%x\n",
		  struct_sock_ip6daddr_offset);
	ebpf_info("    struct_sock_dport_offset: 0x%x\n",
		  struct_sock_dport_offset);
	ebpf_info("    struct_sock_sport_offset: 0x%x\n",
		  struct_sock_sport_offset);
	ebpf_info("    struct_sock_skc_state_offset: 0x%x\n",
		  struct_sock_skc_state_offset);
	ebpf_info("    struct_sock_common_ipv6only_offset: 0x%x\n",
		  struct_sock_common_ipv6only_offset);

	struct bpf_offset_param offset;
	offset.ready = 1;
	offset.task__files_offset = files_offs;
	offset.sock__flags_offset = sk_flags_offs;
	offset.tcp_sock__copied_seq_offset = copied_seq_offs;
	offset.tcp_sock__write_seq_offset = write_seq_offs;
	offset.struct_files_struct_fdt_offset = struct_files_struct_fdt_offset;
	offset.struct_files_private_data_offset =
	    struct_files_private_data_offset;
	offset.struct_file_f_inode_offset = struct_file_f_inode_offset;
	offset.struct_inode_i_mode_offset = struct_inode_i_mode_offset;
	offset.struct_file_dentry_offset = struct_file_dentry_offset;
	offset.struct_dentry_name_offset = struct_dentry_name_offset;
	offset.struct_sock_family_offset = struct_sock_family_offset;
	offset.struct_sock_saddr_offset = struct_sock_saddr_offset;
	offset.struct_sock_daddr_offset = struct_sock_daddr_offset;
	offset.struct_sock_ip6saddr_offset = struct_sock_ip6saddr_offset;
	offset.struct_sock_ip6daddr_offset = struct_sock_ip6daddr_offset;
	offset.struct_sock_dport_offset = struct_sock_dport_offset;
	offset.struct_sock_sport_offset = struct_sock_sport_offset;
	offset.struct_sock_skc_state_offset = struct_sock_skc_state_offset;
	offset.struct_sock_common_ipv6only_offset =
	    struct_sock_common_ipv6only_offset;

	if (update_offsets_table(t, &offset) != ETR_OK) {
		ebpf_warning("Update offsets map failed.\n");
		return ETR_UPDATE_MAP_FAILD;
	}

	return ETR_OK;
}

static void update_protocol_filter_array(struct bpf_tracer *tracer)
{
	for (int idx = 0; idx < PROTO_NUM; ++idx) {
		bpf_table_set_value(tracer, MAP_PROTO_FILTER_NAME, idx,
				    &ebpf_config_protocol_filter[idx]);
	}
}

static void update_kprobe_port_bitmap(struct bpf_tracer *tracer)
{
	bpf_table_set_value(tracer, MAP_KPROBE_PORT_BITMAP_NAME, 0,
			    &allow_port_bitmap);
	bpf_table_set_value(tracer, MAP_KPROBE_PORT_BITMAP_NAME, 1,
			    &bypass_port_bitmap);
}

static void config_proto_ports_bitmap(struct bpf_tracer *tracer)
{
	int i;			// l7 protocol type 
	for (i = 0; i < ARRAY_SIZE(ports_bitmap); i++) {
		if (ports_bitmap[i]) {
			if (bpf_table_set_value
			    (tracer, MAP_PROTO_PORTS_BITMAPS_NAME, i,
			     ports_bitmap[i]))
				ebpf_info
				    ("%s, update eBPF ports_bitmap[%s] success.\n",
				     __func__, get_proto_name(i));
			else
				ebpf_info
				    ("%s, update eBPF ports_bitmap[%s] failed.\n",
				     __func__, get_proto_name(i));
			clib_mem_free(ports_bitmap[i]);
			ports_bitmap[i] = NULL;
		}
	}
}

static void insert_adapt_kern_uid_to_map(struct bpf_tracer *tracer)
{
	bpf_table_set_value(tracer, MAP_ADAPT_KERN_UID_NAME, 0,
			    &adapt_kern_uid);

	ebpf_info("Insert adapt kern uid : %d , %d\n",
		  adapt_kern_uid >> 32, (uint32_t) adapt_kern_uid);
}

static inline int __set_data_limit_max(int limit_size)
{
	if (limit_size < 0) {
		ebpf_warning("limit_size cannot be negative\n");
		return ETR_INVAL;
	} else if (limit_size == 0) {
		socket_data_limit_max = SOCKET_DATA_LIMIT_MAX_DEF;
	} else {
		if (limit_size > BURST_DATA_BUF_SIZE)
			socket_data_limit_max = BURST_DATA_BUF_SIZE;
		else
			socket_data_limit_max = limit_size;
	}

	ebpf_info("Received limit_size (%d), the final value is set to '%d'\n",
		  limit_size, socket_data_limit_max);

	return socket_data_limit_max;
}

/**
 * Set maximum amount of data passed to the agent by eBPF programe.
 * @limit_size : The maximum length of data. If @limit_size exceeds 8192,
 *               it will automatically adjust to 8192 bytes.
 *               If limit_size is 0, Use the default values 4096.
 *
 * @return the set maximum buffer size value on success, < 0 on failure.
 */
int set_data_limit_max(int limit_size)
{
	int set_val = __set_data_limit_max(limit_size);
	if (set_val <= 0)
		return set_val;

	struct bpf_tracer *tracer = find_bpf_tracer(SK_TRACER_NAME);
	if (tracer == NULL) {
		/*
		 * Called before running_socket_tracer(),
		 * no need to update config map
		 */
		return set_val;
	}

	int cpu;
	int nr_cpus = get_num_possible_cpus();
	struct trace_conf_t values[nr_cpus];
	memset(values, 0, sizeof(values));

	if (!bpf_table_get_value(tracer, MAP_TRACE_CONF_NAME, 0, values)) {
		ebpf_warning("Get map '%s' failed.\n", MAP_TRACE_CONF_NAME);
		return ETR_NOTEXIST;
	}

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		values[cpu].data_limit_max = set_val;
	}

	if (!bpf_table_set_value
	    (tracer, MAP_TRACE_CONF_NAME, 0, (void *)&values)) {
		ebpf_warning("Set '%s' failed\n", MAP_TRACE_CONF_NAME);
		return ETR_UPDATE_MAP_FAILD;
	}

	tracer->data_limit_max = set_val;

	return set_val;
}

int set_go_tracing_timeout(int timeout)
{
	go_tracing_timeout = timeout;

	struct bpf_tracer *tracer = find_bpf_tracer(SK_TRACER_NAME);
	if (tracer == NULL) {
		return 0;
	}

	int cpu;
	int nr_cpus = get_num_possible_cpus();
	struct trace_conf_t values[nr_cpus];
	memset(values, 0, sizeof(values));

	if (!bpf_table_get_value(tracer, MAP_TRACE_CONF_NAME, 0, values)) {
		ebpf_warning("Get map '%s' failed.\n", MAP_TRACE_CONF_NAME);
		return ETR_NOTEXIST;
	}

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		values[cpu].go_tracing_timeout = timeout;
	}

	if (!bpf_table_set_value
	    (tracer, MAP_TRACE_CONF_NAME, 0, (void *)&values)) {
		ebpf_warning("Set '%s' failed\n", MAP_TRACE_CONF_NAME);
		return ETR_UPDATE_MAP_FAILD;
	}

	return 0;
}

int set_io_event_collect_mode(uint32_t mode)
{
	io_event_collect_mode = mode;

	struct bpf_tracer *tracer = find_bpf_tracer(SK_TRACER_NAME);
	if (tracer == NULL) {
		return 0;
	}

	int cpu;
	int nr_cpus = get_num_possible_cpus();
	struct trace_conf_t values[nr_cpus];
	memset(values, 0, sizeof(values));

	if (!bpf_table_get_value(tracer, MAP_TRACE_CONF_NAME, 0, values)) {
		ebpf_warning("Get map '%s' failed.\n", MAP_TRACE_CONF_NAME);
		return ETR_NOTEXIST;
	}

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		values[cpu].io_event_collect_mode = io_event_collect_mode;
	}

	if (!bpf_table_set_value
	    (tracer, MAP_TRACE_CONF_NAME, 0, (void *)&values)) {
		ebpf_warning("Set '%s' failed\n", MAP_TRACE_CONF_NAME);
		return ETR_UPDATE_MAP_FAILD;
	}

	return 0;
}

int set_io_event_minimal_duration(uint64_t duration)
{
	io_event_minimal_duration = duration;

	struct bpf_tracer *tracer = find_bpf_tracer(SK_TRACER_NAME);
	if (tracer == NULL) {
		return 0;
	}

	int cpu;
	int nr_cpus = get_num_possible_cpus();
	struct trace_conf_t values[nr_cpus];
	memset(values, 0, sizeof(values));

	if (!bpf_table_get_value(tracer, MAP_TRACE_CONF_NAME, 0, values)) {
		ebpf_warning("Get map '%s' failed.\n", MAP_TRACE_CONF_NAME);
		return ETR_NOTEXIST;
	}

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		values[cpu].io_event_minimal_duration =
		    io_event_minimal_duration;
	}

	if (!bpf_table_set_value
	    (tracer, MAP_TRACE_CONF_NAME, 0, (void *)&values)) {
		ebpf_warning("Set '%s' failed\n", MAP_TRACE_CONF_NAME);
		return ETR_UPDATE_MAP_FAILD;
	}

	return 0;
}

static void __insert_output_prog_to_map(struct bpf_tracer *tracer,
					const char *map_name,
					const char *prog_name, int key)
{
	struct ebpf_prog *prog;
	prog = ebpf_obj__get_prog_by_name(tracer->obj, prog_name);
	if (prog == NULL) {
		ebpf_error("bpf_obj__get_prog_by_name() not find \"%s\"\n",
			   prog_name);
	}

	if (!bpf_table_set_value(tracer, map_name, key, &prog->prog_fd)) {
		ebpf_error("bpf_table_set_value() failed, prog fd:%d\n",
			   prog->prog_fd);
	}

	ebpf_info("Insert into map('%s'), key %d, program name %s\n",
		  map_name, key, prog_name);
}

/*
 * Using an eBPF program specifically designed to send data, the goal is to solve the
 * problem of instructions exceeding the maximum limit.
 *
 * Insert eBPF program into the tail calls map.
 */
static void insert_output_prog_to_map(struct bpf_tracer *tracer)
{
	// jmp for tracepoints
	__insert_output_prog_to_map(tracer,
				    MAP_PROGS_JMP_TP_NAME,
				    PROG_PROTO_INFER_FOR_TP,
				    PROG_PROTO_INFER_TP_IDX);
	__insert_output_prog_to_map(tracer,
				    MAP_PROGS_JMP_TP_NAME,
				    PROG_DATA_SUBMIT_NAME_FOR_TP,
				    PROG_DATA_SUBMIT_TP_IDX);
	__insert_output_prog_to_map(tracer,
				    MAP_PROGS_JMP_TP_NAME,
				    PROG_OUTPUT_DATA_NAME_FOR_TP,
				    PROG_OUTPUT_DATA_TP_IDX);
	__insert_output_prog_to_map(tracer,
				    MAP_PROGS_JMP_TP_NAME,
				    PROG_IO_EVENT_NAME_FOR_TP,
				    PROG_IO_EVENT_TP_IDX);

	// jmp for kprobe/uprobe
	__insert_output_prog_to_map(tracer,
				    MAP_PROGS_JMP_KP_NAME,
				    PROG_PROTO_INFER_FOR_KP,
				    PROG_PROTO_INFER_KP_IDX);
	__insert_output_prog_to_map(tracer,
				    MAP_PROGS_JMP_KP_NAME,
				    PROG_DATA_SUBMIT_NAME_FOR_KP,
				    PROG_DATA_SUBMIT_KP_IDX);
	__insert_output_prog_to_map(tracer,
				    MAP_PROGS_JMP_KP_NAME,
				    PROG_OUTPUT_DATA_NAME_FOR_KP,
				    PROG_OUTPUT_DATA_KP_IDX);
}

/*
 * The work thread retrieves data from the queue and processes it.
 */
static void process_data(void *queue)
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
			prefetch_and_process_data(q->t, nr, rx_burst);
			if (nr == MAX_PKT_BURST)
				atomic64_inc(&q->burst_count);
		}
	}

	/* never reached */
	/* pthread_exit(NULL); */
	/* return NULL; */
}

#ifdef PERFORMANCE_TEST
static_always_inline uint32_t random_u32(uint32_t * seed)
{
	*seed = (1664525 * *seed) + 1013904223;
	return *seed;
}

static_always_inline uint64_t clib_cpu_time_now(void)
{
	uint32_t a, d;
	asm volatile ("rdtsc":"=a" (a), "=d"(d));
	return (uint64_t) a + ((uint64_t) d << (uint64_t) 32);
}
#endif

extern __thread uword thread_index;	// for symbol pid caches hash
static void perf_buffer_read(void *arg)
{
	/*
	 * Each "read" thread has its own independent epoll fd, used
	 * to monitor the perf buffer belonging to its jurisdiction.
	 */
	uint64_t epoll_id = (uint64_t) arg;
	thread_index = THREAD_PROC_ACT_IDX_BASE + epoll_id;	// for bihash
	struct bpf_tracer *tracer = find_bpf_tracer(SK_TRACER_NAME);
	if (tracer == NULL) {
		ebpf_warning("find_bpf_tracer() error\n");
		return;
	}

	struct bpf_perf_reader *perf_reader;
	int i;
	for (;;) {
#ifndef PERFORMANCE_TEST
		for (i = 0; i < tracer->perf_readers_count; i++) {
			perf_reader = &tracer->readers[i];
			struct epoll_event events[perf_reader->readers_count];
			int nfds =
			    reader_epoll_wait(perf_reader, events, epoll_id);
			if (nfds > 0) {
				reader_event_read(events, nfds);
			}
		}
#else
		uint64_t data_len, rand_seed;
		rand_seed = clib_cpu_time_now();
		struct bpf_tracer *tracer = t;
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

static int perf_read_workers_setup(struct bpf_tracer *tracer)
{
	int i, ret;
	struct bpf_perf_reader *r = &tracer->readers[0];
	for (i = 0; i < r->epoll_fds_count; i++) {
		ret = enable_tracer_reader_work("sk-reader", i,
						tracer,
						(void *)&perf_buffer_read);
		if (ret)
			return ETR_INVAL;
	}

	return ETR_OK;
}

static int dispatch_workers_setup(struct bpf_tracer *tracer,
				  unsigned int queue_size)
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
				   (void *)&process_data,
				   (void *)&tracer->queues[i]);
		if (ret) {
			ebpf_info
			    ("<%s> process_data, pthread_create is error:%s\n",
			     __func__, strerror(errno));
			return ETR_INVAL;
		}
	}

	return ETR_OK;
}

/**
 * Start socket tracer
 *
 * Socket-Tracer is used to get all read/write datas on socket.
 * It also contains some event data related to L7 data, such as process information.
 * These datas are derived from eBPF Kprobe, Uprobe, Tracepoint and other types.
 *
 * Parameters:
 * @handle
 *     Callback interface for upper-layer Application.
 * @thread_nr
 *     Number of worker threads, which refers to the number of user mode threads involved
 *     in data processing, at the same time, it is also the number of threads reading the
 *     perf buffer.
 * @perf_pages_cnt
 *     Number of page frames with kernel shared memory footprint, the value is a power of 2.
 * @queue_size
 *     Ring cache queue size. The value is a power of 2.
 * @max_socket_entries
 *     Sets the maximum number of hash entries for socket tracing, depending on the number of concurrent
 *     requests in actual scenarios.
 * @max_trace_entries
 *     Sets the maximum number of hash entries for thread/coroutine tracing sessions.
 * @socket_map_max_reclaim
 *     Indicates the maximum threshold for clearing socket MAP entries.
 *     If the number of current map entries exceeds this threshold, the MAP will be cleared.
 *
 * @return value: 0 on success, if not 0 is failed
 */
int running_socket_tracer(tracer_callback_t handle,
			  int thread_nr,
			  uint32_t perf_pages_cnt,
			  uint32_t queue_size,
			  uint32_t max_socket_entries,
			  uint32_t max_trace_entries,
			  uint32_t socket_map_max_reclaim)
{
	int ret;
	// Used to record which eBPF buffer was loaded.
	char bpf_load_buffer_name[NAME_LEN];
	void *bpf_bin_buffer;
	int buffer_sz;

	if (sys_cpus_count <= 0) {
		ebpf_warning("sys_cpus_count(%d) <= 0, Please"
			     " prioritize the execution of bpf_tracer_init().\n",
			     sys_cpus_count);
		return -EINVAL;
	}
	// Ensure that the number of worker threads does not exceed the
	// number of CPUs
	if (thread_nr > sys_cpus_count)
		thread_nr = sys_cpus_count;

	if (check_kernel_version(4, 14) != 0) {
		return -EINVAL;
	}

	char sys_type_str[16];
	memset(sys_type_str, 0, sizeof(sys_type_str));
	if (fetch_system_type(sys_type_str, sizeof(sys_type_str) - 1) != ETR_OK) {
		ebpf_warning("Fetch system type faild.\n");
	}

	enum linux_kernel_type k_type;
	if (strcmp(sys_type_str, "ky10") == 0) {
		k_type = K_TYPE_KYLIN;
		snprintf(bpf_load_buffer_name, NAME_LEN,
			 "socket-trace-bpf-linux-kylin");
		bpf_bin_buffer = (void *)socket_trace_kylin_ebpf_data;
		buffer_sz = sizeof(socket_trace_kylin_ebpf_data);
	} else if (major > 5 || (major == 5 && minor >= 2)) {
		k_type = K_TYPE_VER_5_2_PLUS;
		snprintf(bpf_load_buffer_name, NAME_LEN,
			 "socket-trace-bpf-linux-5.2_plus");
		bpf_bin_buffer = (void *)socket_trace_5_2_plus_ebpf_data;
		buffer_sz = sizeof(socket_trace_5_2_plus_ebpf_data);
	} else if (major == 3 && minor == 10) {
		k_type = K_TYPE_VER_3_10;
		snprintf(bpf_load_buffer_name, NAME_LEN,
			 "socket-trace-bpf-linux-3.10.0");
		bpf_bin_buffer = (void *)socket_trace_3_10_0_ebpf_data;
		buffer_sz = sizeof(socket_trace_3_10_0_ebpf_data);
	} else {
		k_type = K_TYPE_COMM;
		snprintf(bpf_load_buffer_name, NAME_LEN,
			 "socket-trace-bpf-linux-common");
		bpf_bin_buffer = (void *)socket_trace_common_ebpf_data;
		buffer_sz = sizeof(socket_trace_common_ebpf_data);
	}

	/*
	 * Initialize datadump
	 */
	pthread_mutex_init(&datadump_mutex, NULL);
	datadump_enable = false;
	datadump_use_remote = false;
	memcpy(datadump_file_path, "stdout", 7);
	datadump_file = stdout;

	// Initialize events_list
	if (events_list.next == events_list.prev && events_list.next == NULL) {
		init_list_head(&events_list);
	}

	struct tracer_probes_conf *tps =
	    malloc(sizeof(struct tracer_probes_conf));
	if (tps == NULL) {
		ebpf_warning("malloc() error.\n");
		return -ENOMEM;
	}
	memset(tps, 0, sizeof(*tps));
	init_list_head(&tps->uprobe_syms_head);
	socket_tracer_set_probes(tps);

	create_and_init_proc_info_caches();

	struct bpf_tracer *tracer =
	    setup_bpf_tracer(SK_TRACER_NAME, bpf_load_buffer_name,
			     bpf_bin_buffer, buffer_sz, tps,
			     thread_nr, NULL, NULL, (void *)handle, 0);
	if (tracer == NULL)
		return -EINVAL;

	g_tracer = tracer;
	probes_act = ACT_NONE;
	tracer->adapt_success = false;

	tracer->datadump = datadump_process;

	if ((ret =
	     maps_config(tracer, MAP_SOCKET_INFO_NAME, max_socket_entries)))
		return ret;

	conf_max_socket_entries = max_socket_entries;

	conf_socket_map_max_reclaim = socket_map_max_reclaim;

	if ((ret = maps_config(tracer, MAP_TRACE_NAME, max_trace_entries)))
		return ret;

	conf_max_trace_entries = max_trace_entries;

	if (tracer_bpf_load(tracer))
		return -EINVAL;

	/*
	 * create reader for read perf buffer data. 
	 */
	struct bpf_perf_reader *reader;
	reader = create_perf_buffer_reader(tracer,
					   MAP_PERF_SOCKET_DATA_NAME,
					   reader_raw_cb,
					   reader_lost_cb,
					   perf_pages_cnt,
					   thread_nr, PERF_READER_TIMEOUT_DEF);
	if (reader == NULL)
		return -EINVAL;

	if (tracer_probes_init(tracer))
		return -EINVAL;

	// Update kernel offsets map from btf vmlinux file.
	if (update_offset_map_from_btf_vmlinux(tracer) != ETR_OK) {
		ebpf_info
		    ("[eBPF Kernel Adapt] Set offsets map from btf_vmlinux, not support.\n");
		if (update_offset_map_default(tracer, k_type) != ETR_OK) {
			ebpf_error
			    ("Fatal error, failed to update default offset\n");
		}
	} else {
		ebpf_info
		    ("[eBPF Kernel Adapt] Set offsets map from btf_vmlinux, success.\n");
	}

	// Set default maximum amount of data passed to the agent by eBPF.
	if (socket_data_limit_max == 0)
		__set_data_limit_max(0);

	uint64_t uid_base = (gettime(CLOCK_REALTIME, TIME_TYPE_NAN) / 100) &
	    0xffffffffffffffULL;
	if (uid_base == 0)
		return -EINVAL;

	uint16_t cpu;
	struct trace_conf_t t_conf[MAX_CPU_NR];
	for (cpu = 0; cpu < MAX_CPU_NR; cpu++) {
		t_conf[cpu].socket_id = (uint64_t) cpu << 56 | uid_base;
		t_conf[cpu].coroutine_trace_id = t_conf[cpu].socket_id;
		t_conf[cpu].thread_trace_id = t_conf[cpu].socket_id;
		t_conf[cpu].data_limit_max = socket_data_limit_max;
		t_conf[cpu].go_tracing_timeout = go_tracing_timeout;
		t_conf[cpu].io_event_collect_mode = io_event_collect_mode;
		t_conf[cpu].io_event_minimal_duration =
		    io_event_minimal_duration;
	}

	if (!bpf_table_set_value
	    (tracer, MAP_TRACE_CONF_NAME, 0, (void *)&t_conf))
		return -EINVAL;

	tracer->data_limit_max = socket_data_limit_max;

	// Update go offsets to eBPF "proc_info_map"
	update_proc_info_to_map(tracer);

	// Insert prog of output data into map for using BPF Tail Calls.
	insert_output_prog_to_map(tracer);

	// Insert the unique identifier of the adaptation kernel into the map
	insert_adapt_kern_uid_to_map(tracer);

	// Update protocol filter array
	update_protocol_filter_array(tracer);

	update_kprobe_port_bitmap(tracer);

	// Configure l7 protocol ports
	config_proto_ports_bitmap(tracer);

	if (tracer_hooks_attach(tracer))
		return -EINVAL;

	if ((ret = dispatch_workers_setup(tracer, queue_size)))
		return ret;

	if ((ret = perf_read_workers_setup(tracer)))
		return ret;

	// use for inference struct offset.
	if (kernel_offset_infer_init() != ETR_OK)
		return -EINVAL;

	if ((ret = register_extra_waiting_op("offset-infer-server",
					     kernel_offset_infer_server,
					     EXTRA_TYPE_SERVER)))
		return ret;

	if ((ret = register_extra_waiting_op("offset-infer-client",
					     kernel_offset_infer_client,
					     EXTRA_TYPE_CLIENT)))
		return ret;

	if ((ret =
	     register_period_event_op("check-map-exceeded",
				      check_map_exceeded,
				      CHECK_MAP_EXCEEDED_PERIOD)))
		return ret;

	if ((ret =
	     register_period_event_op("check-kern-adapt",
				      check_kern_adapt_and_state_update,
				      CHECK_KERN_ADAPT_PERIOD)))
		return ret;

	if ((ret = sockopt_register(&socktrace_sockopts)) != ETR_OK)
		return ret;

	if ((ret = sockopt_register(&datadump_sockopts)) != ETR_OK)
		return ret;
	ret =
	    pthread_create(&proc_events_pthread, NULL,
			   (void *)&process_events_handle_main, (void *)tracer);
	if (ret) {
		ebpf_warning
		    ("proc_events_pthread, pthread_create is error:%s\n",
		     strerror(errno));
		return ret;
	}

	return 0;
}

int socket_tracer_stop(void)
{
	int ret = -1;
	struct bpf_tracer *t = find_bpf_tracer(SK_TRACER_NAME);
	if (t == NULL)
		return ret;
	if (t->state == TRACER_INIT) {
		ebpf_warning
		    ("[eBPF Kernel Adapt] Adapting the linux kernel(%s) is in "
		     "progress, please try the stop operation again later.\n",
		     linux_release);
		return -1;
	}

	if (probes_act == ACT_DETACH) {
		ebpf_warning
		    ("The latest probes_act is already ACT_DETACH, without operating.\n");

		return 0;
	}

	ebpf_info("Call socket_tracer_stop()\n");
	add_probes_act(ACT_DETACH);
	return 0;
}

int socket_tracer_start(void)
{
	int ret = -1;
	struct bpf_tracer *t = find_bpf_tracer(SK_TRACER_NAME);
	if (t == NULL)
		return ret;

	if (t->state == TRACER_INIT) {
		ebpf_warning
		    ("[eBPF Kernel Adapt] Adapting the linux kernel(%s) "
		     "is in progress, please try "
		     "the start operation again later.\n", linux_release);
		return -1;
	}

	if (probes_act == ACT_ATTACH) {
		ebpf_warning
		    ("The latest probes_act already ACT_ATTACH, without operating.\n");
		return 0;
	}

	ebpf_info("Call socket_tracer_start()\n");
	add_probes_act(ACT_ATTACH);

	return 0;
}

enum tracer_state __unused get_socket_tracer_state(void)
{
	struct bpf_tracer *t = find_bpf_tracer(SK_TRACER_NAME);
	if (t == NULL)
		return TRACER_STOP_ERR;

	return t->state;
}

static bool bpf_stats_map_collect(struct bpf_tracer *tracer,
				  struct trace_stats *stats_total)
{
	struct trace_stats value = { 0 };
	if (!bpf_table_get_value(tracer, MAP_TRACE_STATS_NAME, 0, &value))
		return false;

	memset(stats_total, 0, sizeof(*stats_total));
	stats_total->socket_map_count += value.socket_map_count;
	stats_total->trace_map_count += value.trace_map_count;

	return true;
}

static bool bpf_stats_map_update(struct bpf_tracer *tracer,
				 int socket_num, int trace_num)
{
	struct trace_stats value = { 0 };
	if (!bpf_table_get_value(tracer, MAP_TRACE_STATS_NAME, 0, &value))
		return false;

	if (socket_num != -1) {
		value.socket_map_count = socket_num;
	}

	if (trace_num != -1) {
		value.trace_map_count = trace_num;
	}

	if (!bpf_table_set_value(tracer,
				 MAP_TRACE_STATS_NAME, 0, (void *)&value)) {
		return false;
	}

	return true;
}

// Update offsets tables for all cpus
static int update_offsets_table(struct bpf_tracer *t,
				struct bpf_offset_param *offset)
{
	int nr_cpus = get_num_possible_cpus();
	struct bpf_offset_param offs[nr_cpus];
	int i;
	memset(&offs, 0, sizeof(offs));
	for (i = 0; i < nr_cpus; i++) {
		offs[i] = *offset;
	}

	if (!bpf_table_set_value(t, MAP_MEMBERS_OFFSET_NAME, 0, (void *)&offs))
		return ETR_UPDATE_MAP_FAILD;

	return ETR_OK;
}

static bool is_adapt_success(struct bpf_tracer *t)
{
	bool is_success = false;
	int i;

	if (sys_cpus_count > 0) {
		struct bpf_offset_param *offset;
		struct bpf_offset_param_array *array =
		    malloc(sizeof(*array) + sizeof(*offset) * sys_cpus_count);
		if (array == NULL) {
			ebpf_warning("malloc() error.\n");
			return false;
		}

		array->count = sys_cpus_count;

		if (!bpf_offset_map_collect(t, array)) {
			free(array);
			return false;
		}

		offset = (struct bpf_offset_param *)(array + 1);
		for (i = 0; i < sys_cpus_count; i++) {
			if (!cpu_online[i])
				continue;
			if (offset[i].ready == 1) {
				// Update all cpus offset map.
				if (update_offsets_table(t, &offset[i]) ==
				    ETR_OK) {
					is_success = true;
				} else {
					is_success = false;
				}

				break;
			}
		}

		free(array);
	}

	return is_success;
}

struct socket_trace_stats socket_tracer_stats(void)
{
	struct socket_trace_stats stats;
	memset(&stats, 0, sizeof(stats));

	struct bpf_tracer *t = find_bpf_tracer(SK_TRACER_NAME);
	if (t == NULL)
		return stats;

	stats.kern_lost = atomic64_read(&t->lost);
	atomic64_init(&t->lost);
	stats.worker_num = t->dispatch_workers_nr;
	stats.perf_pages_cnt = t->readers[0].perf_pages_cnt;
	stats.queue_capacity = t->queues[0].ring_size;
	stats.kern_socket_map_max = conf_max_socket_entries;
	stats.kern_trace_map_max = conf_max_trace_entries;
	stats.socket_map_max_reclaim = conf_socket_map_max_reclaim;
	stats.probes_count = t->probes_count;
	stats.data_limit_max = socket_data_limit_max;

	struct trace_stats stats_total;

	if (bpf_stats_map_collect(t, &stats_total)) {
		stats.kern_socket_map_used = stats_total.socket_map_count;
		stats.kern_trace_map_used = stats_total.trace_map_count;
	}

	int i;
	for (i = 0; i < t->dispatch_workers_nr; i++) {
		stats.user_enqueue_lost +=
		    atomic64_read(&t->queues[i].enqueue_lost);
		stats.user_enqueue_count +=
		    atomic64_read(&t->queues[i].enqueue_nr);
		stats.user_dequeue_count +=
		    atomic64_read(&t->queues[i].dequeue_nr);
		stats.queue_burst_count +=
		    atomic64_read(&t->queues[i].burst_count);
		stats.mem_alloc_fail_count +=
		    atomic64_read(&t->queues[i].heap_get_failed);

		atomic64_init(&t->queues[i].enqueue_lost);
		atomic64_init(&t->queues[i].enqueue_nr);
		atomic64_init(&t->queues[i].dequeue_nr);
		atomic64_init(&t->queues[i].heap_get_failed);
	}

	stats.is_adapt_success = t->adapt_success;
	stats.tracer_state = t->state;

	// 相邻两次系统启动时间更新后的差值
	stats.boot_time_update_diff = sys_boot_time_ns - prev_sys_boot_time_ns;

	return stats;
}

/**
 * Register extra event handle.
 *
 * Parameter:
 * @type Event type
 * @fn Callback function
 *
 * @return 0 is success, if not 0 is failed
 */
int register_event_handle(uint32_t type, void (*fn) (void *))
{
	if (type < EVENT_TYPE_MIN || fn == NULL) {
		ebpf_warning("Parameter is invalid, type %d fn %p\n", type, fn);
		return -1;
	}

	struct list_head *events_head;
	events_head = &events_list;
	// Initialize events_list
	if (events_head->next == events_head->prev && events_head->next == NULL) {
		init_list_head(events_head);
	}

	struct extra_event *event = calloc(1, sizeof(struct extra_event));
	if (event == NULL) {
		ebpf_warning("calloc() is failed.\n");
		return -1;
	}

	event->type = type;
	event->h = fn;

	list_add_tail(&event->list, events_head);

	return 0;
}

// -------------------------------------
// 协议测试
// -------------------------------------

int print_uprobe_http2_info(const char *data, int len, char *buf, int buf_len)
{
	struct {
		__u32 fd;
		__u32 stream_id;
		__u32 header_len;
		__u32 value_len;
	} __attribute__ ((packed)) header;

	int bytes = 0;
	char key[1024] = { 0 };
	char value[1024] = { 0 };
	memcpy(&header, data, sizeof(header));
	if (datadump_enable) {
		bytes +=
		    snprintf(buf + bytes, buf_len - bytes,
			     "fd=[%d]\nstream_id=[%d]\n", header.fd,
			     header.stream_id);

	} else {
		fprintf(stdout, "fd=[%d]\nstream_id=[%d]\n", header.fd,
			header.stream_id);
	}

	const int value_start = sizeof(header) + header.header_len;

	header.header_len = header.header_len < 1024 ? header.header_len : 1023;
	header.value_len = header.value_len < 1024 ? header.value_len : 1023;

	memcpy(&key, data + sizeof(header), header.header_len);
	memcpy(&value, data + value_start, header.value_len);

	if (datadump_enable) {
		bytes +=
		    snprintf(buf + bytes, buf_len - bytes, "header=[%s:%s]\n",
			     key, value);
	} else {
		fprintf(stdout, "header=[%s:%s]\n", key, value);
		fflush(stdout);
	}

	return bytes;
}

int print_io_event_info(const char *data, int len, char *buf, int buf_len)
{
	struct {
		__u32 bytes_count;
		__u32 operation;
		__u64 latency;
		char filename[64];
	} __attribute__ ((packed)) event;

	int bytes = 0;

	memcpy(&event, data, sizeof(event));

	if (datadump_enable) {
		bytes = snprintf(buf, buf_len,
				 "bytes_count=[%u]\noperation=[%u]\nlatency=[%lu]"
				 "\nfilename=[%s]\n",
				 event.bytes_count, event.operation,
				 event.latency, event.filename);
	} else {
		fprintf(stdout,
			"bytes_count=[%u]\noperation=[%u]\nlatency=[%lu]\nfilename=[%s]\n",
			event.bytes_count, event.operation,
			event.latency, event.filename);

		fflush(stdout);
	}

	return bytes;
}

int print_uprobe_grpc_dataframe(const char *data, int len, char *buf,
				int buf_len)
{
	int i;
	struct {
		__u32 stream_id;
		__u32 data_len;
		char data[1024];
	} __attribute__ ((packed)) dataframe;

	int bytes = 0;
	memcpy(&dataframe, data, len);

	if (datadump_enable) {
		bytes +=
		    snprintf(buf + bytes, buf_len - bytes,
			     "stream_id=[%d]\ndata_len=[%d]\n",
			     dataframe.stream_id, dataframe.data_len);
	} else {
		fprintf(stdout, "stream_id=[%d]\ndata_len=[%d]\n",
			dataframe.stream_id, dataframe.data_len);
	}

	for (i = 0; i < dataframe.data_len; ++i) {
		if (!isprint(dataframe.data[i])) {
			dataframe.data[i] = '.';
		}
	}

	dataframe.data[dataframe.data_len] = '\0';

	if (datadump_enable) {
		bytes +=
		    snprintf(buf + bytes, buf_len - bytes, "data=[%s]\n",
			     dataframe.data);
	} else {
		fprintf(stdout, "data=[%s]\n", dataframe.data);
		fflush(stdout);
	}
	return bytes;
}

// ------- print mysql --------
void print_mysql_info(const char *data, uint32_t len, uint8_t dir)
{
#define SOCK_DIR_SND_REQ	0
#define SOCK_DIR_SND_RES	1
#define SOCK_DIR_RCV_REQ	2
#define SOCK_DIR_RCV_RES	3
	/*
	 * MySQL Protocol
	 *    Packet Length: 33
	 *    Packet Number: 0
	 *    Request Command Query
	 *  Command: Query (3)
	 *  Statement: select user,host from mysql.user
	 */
	int i;
	for (i = 0; i < len; i++)
		printf("%c", data[i]);
	printf("\n");

	fflush(stdout);
}

// ------- print redis --------
void print_redis_info(const char *data, uint32_t len, uint8_t dir)
{
	int i;
	for (i = 0; i < len; i++)
		printf("%c", data[i]);
	printf("\n");

	fflush(stdout);
}

// ------- print dubbo --------
void print_dubbo_info(const char *data, uint32_t len, uint8_t dir)
{
	// head + body , head 16 bytes. skip head
	int i;
	for (i = 0; i < len - 16; i++)
		printf("%c", data[i + 16]);
	printf("\n");

	fflush(stdout);
}

static char *flow_info(struct socket_bpf_data *sd)
{
#define BUF_SIZE 128

	char *buf = malloc(BUF_SIZE);
	if (buf == NULL)
		return NULL;
	memset(buf, 0, 128);
	char sbuf[64], dbuf[64];
	char *tag;
	if (sd->tuple.addr_len == 16) {
		inet_ntop(AF_INET6, sd->tuple.rcv_saddr, sbuf, sizeof(sbuf));
		inet_ntop(AF_INET6, sd->tuple.daddr, dbuf, sizeof(dbuf));
	} else {
		struct in_addr addr;
		addr.s_addr = *((in_addr_t *) sd->tuple.rcv_saddr);
		snprintf(sbuf, sizeof(sbuf), "%s", inet_ntoa(addr));
		addr.s_addr = *((in_addr_t *) sd->tuple.daddr);
		snprintf(dbuf, sizeof(dbuf), "%s", inet_ntoa(addr));
	}

	if (sd->tuple.l4_protocol == 6) {
		tag = "TCP";
	} else if (sd->tuple.l4_protocol == 17) {
		tag = "UDP";
	} else {
		tag = "Unknow";
	}

	if (sd->direction == T_EGRESS) {
		snprintf(buf, BUF_SIZE, "%s %s.%d > %s.%d",
			 tag, sbuf, sd->tuple.num, dbuf, sd->tuple.dport);
	} else {
		snprintf(buf, BUF_SIZE, "%s %s.%d > %s.%d",
			 tag, dbuf, sd->tuple.dport, sbuf, sd->tuple.num);
	}

	return buf;
}

static bool allow_datadump(struct socket_bpf_data *sd)
{
	bool output = false;
	if (datadump_pid == 0 && (strlen(datadump_comm) > 0)
	    && (datadump_proto == 0)) {
		if (strcmp((char *)sd->process_kname, (char *)datadump_comm) ==
		    0) {
			output = true;
		}

	} else if (datadump_pid == 0 && (strlen(datadump_comm) == 0)
		   && (datadump_proto == 0)) {
		output = true;

	} else if (datadump_pid > 0 && (strlen(datadump_comm) == 0)
		   && (datadump_proto == 0)) {
		if (sd->process_id == datadump_pid
		    || sd->thread_id == datadump_pid)
			output = true;

	} else if (datadump_pid > 0 && (strlen(datadump_comm) > 0)
		   && (datadump_proto == 0)) {
		if ((sd->process_id == datadump_pid
		     || sd->thread_id == datadump_pid)
		    && (strcmp((char *)sd->process_kname, (char *)datadump_comm)
			== 0))
			output = true;
	} else if (datadump_pid == 0 && (strlen(datadump_comm) > 0)
		   && (datadump_proto > 0)) {
		if (strcmp((char *)sd->process_kname, (char *)datadump_comm) ==
		    0 && sd->l7_protocal_hint == datadump_proto)
			output = true;

	} else if (datadump_pid == 0 && (strlen(datadump_comm) == 0)
		   && (datadump_proto > 0)) {
		if (sd->l7_protocal_hint == datadump_proto)
			output = true;

	} else if (datadump_pid > 0 && (strlen(datadump_comm) == 0)
		   && (datadump_proto > 0)) {
		if ((sd->process_id == datadump_pid
		     || sd->thread_id == datadump_pid)
		    && sd->l7_protocal_hint == datadump_proto)
			output = true;

	} else if (datadump_pid > 0 && (strlen(datadump_comm) > 0)
		   && (datadump_proto > 0)) {
		if ((sd->process_id == datadump_pid
		     || sd->thread_id == datadump_pid)
		    && (strcmp((char *)sd->process_kname, (char *)datadump_comm)
			== 0) && sd->l7_protocal_hint == datadump_proto)
			output = true;
	}

	return output;
}

#define DATADUMP_FORMAT						\
	"%s [datadump] <%s> DIR %s TYPE %s(%d) PID %u "		\
	"THREAD_ID %u COROUTINE_ID %" PRIu64 " ROLE %s"		\
	" CONTAINER_ID %s SOURCE %d COMM %s "			\
	"%s LEN %d SYSCALL_LEN %" PRIu64 " SOCKET_ID %" PRIu64	\
	" " "TRACE_ID %" PRIu64 " TCP_SEQ %" PRIu64		\
	" DATA_SEQ %" PRIu64 " TLS %s TimeStamp %" PRIu64 "\n"

static void print_socket_data(struct socket_bpf_data *sd)
{
	if (!allow_datadump(sd))
		return;

	char *timestamp = gen_timestamp_str(0);
	if (timestamp == NULL)
		return;

	char *proto_tag = get_proto_name(sd->l7_protocal_hint);
	char *type, *role_str;
	char *flow_str = flow_info(sd);
	if (flow_str == NULL) {
		free(timestamp);
		return;
	}

	if (sd->msg_type == MSG_REQUEST)
		type = "req";
	else if (sd->msg_type == MSG_RESPONSE)
		type = "res";
	else
		type = "unknown";

	if (sd->socket_role == ROLE_CLIENT)
		role_str = "client";
	else if (sd->socket_role == ROLE_SERVER)
		role_str = "server";
	else
		role_str = "unknown";

	char buff[DEBUG_BUFF_SIZE];
	int len = 0;
	len +=
	    snprintf(buff, sizeof(buff), DATADUMP_FORMAT, timestamp,
		     proto_tag,
		     sd->direction == T_EGRESS ? "out" : "in", type,
		     sd->msg_type, sd->process_id, sd->thread_id,
		     sd->coroutine_id, role_str,
		     strlen((char *)sd->container_id) ==
		     0 ? "null" : (char *)sd->container_id, sd->source,
		     sd->process_kname, flow_str, sd->cap_len,
		     sd->syscall_len, sd->socket_id,
		     sd->syscall_trace_id_call, sd->tcp_seq,
		     sd->cap_seq, sd->is_tls ? "true" : "false", sd->timestamp);

	if (sd->source == DATA_SOURCE_GO_HTTP2_UPROBE) {
		len +=
		    print_uprobe_http2_info(sd->cap_data, sd->cap_len,
					    buff + len, sizeof(buff) - len);
	} else if (sd->source == DATA_SOURCE_IO_EVENT) {
		len +=
		    print_io_event_info(sd->cap_data, sd->cap_len, buff + len,
					sizeof(buff) - len);
	} else if (sd->source == DATA_SOURCE_GO_HTTP2_DATAFRAME_UPROBE) {
		len +=
		    print_uprobe_grpc_dataframe(sd->cap_data, sd->cap_len,
						buff + len, sizeof(buff) - len);
	} else {
		int i;
		uint8_t v;
		bool double_args;
		const char *format;
		for (i = 0; i < sd->cap_len; i++) {
			double_args = false;
			format = "%02X ";
			v = (uint8_t) sd->cap_data[i];
			if (sd->l7_protocal_hint == PROTO_HTTP1) {
				/* printing character, LF(10), CR(13) */
				if (!(v < 32 || v > 126) || v == 10 || v == 13)
					format = "%c";
			} else {
				if (!(v < 32 || v > 126)) {
					format = "%02X(%c) ";
					double_args = true;
				}
			}

			if (double_args)
				len +=
				    snprintf(buff + len, sizeof(buff) - len,
					     format, v, v);
			else
				len +=
				    snprintf(buff + len, sizeof(buff) - len,
					     format, v);

			if (len >= sizeof(buff)) {
				break;
			}
		}
	}

	free(timestamp);
	free(flow_str);

	if (datadump_use_remote) {
		if (datadump_cb != NULL)
			datadump_cb((char *)buff, strlen(buff));
	} else {
		fprintf(datadump_file, "%s\n", buff);
		fflush(datadump_file);
	}
}

static void datadump_process(void *data)
{
	struct socket_bpf_data *sd = data;
	pthread_mutex_lock(&datadump_mutex);
	if (unlikely(datadump_enable))
		print_socket_data(sd);
	pthread_mutex_unlock(&datadump_mutex);
}

static inline int __set_protocol_ports_bitmap(int proto_type,
					      bool * allow_ports,
					      const char *ports)
{
	int i;
	ports_bitmap_t *map = NULL;
	map =
	    clib_mem_alloc_aligned("ports_bitmap", sizeof(ports_bitmap_t), 0,
				   NULL);
	if (map == NULL) {
		ebpf_warning("clib_mem_alloc_aligned() failed."
			     "Set ports_bitmap[%s] failed, ports %s\n",
			     get_proto_name(proto_type), ports);
		return -1;
	}

	memset(map, 0, sizeof(*map));
	for (i = 0; i < PORT_NUM_MAX; i++) {
		if (allow_ports[i])
			map->bitmap[i / 8] |= 1 << (i % 8);
	}

	if (ports_bitmap[proto_type])
		clib_mem_free(ports_bitmap[proto_type]);

	ports_bitmap[proto_type] = map;

	ebpf_info("Set ports_bitmap[%s] success, ports %s\n",
		  get_proto_name(proto_type), ports);

	return 0;
}

int set_protocol_ports_bitmap(int proto_type, const char *ports)
{
	ASSERT(proto_type < ARRAY_SIZE(ports_bitmap));

	bool *allow_ports = NULL;
	int err;
	err = parse_num_range_disorder(ports, strlen(ports), &allow_ports);
	if (err) {
		allow_ports = NULL;
		goto failed;
	}

	if (__set_protocol_ports_bitmap(proto_type, allow_ports, ports))
		goto failed;

	free(allow_ports);
	return 0;

failed:
	if (allow_ports)
		free(allow_ports);

	ebpf_warning
	    ("failed to get proto_type %d mask, ports %s err %d\n",
	     proto_type, ports, err);
	return -1;
}
