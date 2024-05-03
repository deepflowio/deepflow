/*
 * Copyright (c) 2024 Yunshan Networks
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

/*
 * TODO (@jiping)
 * There are some issues with aarch64 musl compilation, and the profiler
 * cannot be applied temporarily in scenarios where aarch64 is compiled
 * using musl.
 */
#ifndef AARCH64_MUSL
#include <sys/stat.h>
#include <bcc/perf_reader.h>
#include "../config.h"
#include "../utils.h"
#include "../common.h"
#include "../mem.h"
#include "../log.h"
#include "../types.h"
#include "../vec.h"
#include "../tracer.h"
#include "../socket.h"
#include "java/gen_syms_file.h"
#include "perf_profiler.h"
#include "../elf.h"
#include "../load.h"
#include "../../kernel/include/perf_profiler.h"
#include "../perf_reader.h"
#include "../bihash_8_8.h"
#include "stringifier.h"
#include "../table.h"
#include <regex.h>
#include "java/config.h"
#include "java/df_jattach.h"
#include "profile_common.h"

#include "../perf_profiler_bpf_common.c"

#define LOG_CP_TAG	"[CP] "
#define CP_TRACER_NAME	"continuous_profiler"
#define CP_PERF_PG_NUM	16

static struct profiler_context oncpu_ctx;

/* The maximum bytes limit for writing the df_perf-PID.map file by agent.so */
int g_java_syms_write_bytes_max;

/* Used for handling updates to JAVA symbol files */
static pthread_t java_syms_update_thread;

extern char linux_release[128];
extern __thread uword thread_index;

struct stack_trace_key_t *raw_stack_data;
struct bpf_tracer *profiler_tracer;

// for flame-graph test
static FILE *folded_file;
#define FOLDED_FILE_PATH "./profiler.folded"
static char *flame_graph_start_time;
static char *flame_graph_end_time;

/*
 * 'cpu_aggregation_flag' is used to set whether to retrieve CPUID
 * and include it in the aggregation of stack trace data.
 *
 * If valude is set to 1, CPUID will be retrieved and included in
 * the aggregation of stack trace data. If value is set to 0,
 * CPUID will not be retrieved and will not be included in the
 * aggregation. Any other value is considered invalid.
 */
static volatile u64 cpu_aggregation_flag;

/*
 * Cache hash: obtain folded stack trace string from stack ID.
 */
static stack_str_hash_t g_stack_str_hash;

/*
 * Used for tracking data statistics and pushing.
 */
static stack_trace_msg_hash_t g_msg_hash;

static u64 process_count;

static void print_cp_tracer_status(struct bpf_tracer *t,
				   struct profiler_context *ctx);

/* Continuous Profiler debug related settings. */
static pthread_mutex_t cpdbg_mutex;
static bool cpdbg_enable;
static debug_callback_t cpdbg_cb;
static bool cpdbg_use_remote;
static uint32_t cpdbg_start_time;
static uint32_t cpdbg_timeout;

static u64 get_process_lost_count(struct profiler_context *ctx)
{
	return atomic64_read(&ctx->process_lost_count);
}

static inline stack_trace_msg_t *alloc_stack_trace_msg(int len)
{
	void *trace_msg;
	trace_msg = clib_mem_alloc_aligned("stack_msg", len, 0, NULL);
	if (trace_msg == NULL) {
		ebpf_warning("stack trace msg alloc memory failed.\n");
	} else {
		stack_trace_msg_t *msg = trace_msg;
		return msg;
	}

	return NULL;
}

/* 
 * The invocation of this interface is always when the process name does
 * not match.
 */
static void set_msg_kvp_by_comm(stack_trace_msg_kv_t * kvp,
				struct stack_trace_key_t *v, void *msg_value)
{
	strcpy_s_inline(kvp->c_k.comm, sizeof(kvp->c_k.comm),
			v->comm, strlen(v->comm));
	kvp->c_k.cpu = v->cpu;
	kvp->c_k.pid = v->tgid;
	kvp->c_k.reserved = 0;
	kvp->msg_ptr = pointer_to_uword(msg_value);
}

static void set_msg_kvp(stack_trace_msg_kv_t * kvp,
			struct stack_trace_key_t *v, u64 stime, void *msg_value)
{
	kvp->k.tgid = v->tgid;
	kvp->k.pid = v->pid;
	kvp->k.stime = stime;
	kvp->k.cpu = v->cpu;
	kvp->k.u_stack_id = (u32) v->userstack;
	kvp->k.k_stack_id = (u32) v->kernstack;
	kvp->msg_ptr = pointer_to_uword(msg_value);
}

static void set_stack_trace_msg(struct profiler_context *ctx,
				stack_trace_msg_t * msg,
				struct stack_trace_key_t *v,
				bool matched,
				u64 stime,
				u64 ns_id,
				const char *process_name,
				const char *container_id)
{
	msg->pid = v->tgid;
	msg->tid = v->pid;
	msg->cpu = v->cpu;
	msg->u_stack_id = (u32) v->userstack;
	msg->k_stack_id = (u32) v->kernstack;
	strcpy_s_inline(msg->comm, sizeof(msg->comm), v->comm, strlen(v->comm));
	msg->stime = stime;
	msg->netns_id = ns_id;
	if (container_id != NULL) {
		strcpy_s_inline(msg->container_id, sizeof(msg->container_id),
				container_id, strlen(container_id));
	}

	if (stime > 0) {
		/*
		 * Note: There is no process with PID 0 in procfs.
		 * If the PID is 0, it will return the kernel's
		 * startup time, and the process name will be
		 * obtained from data retrieved through eBPF.
		 */
		if (msg->pid == 0) {
			memcpy(msg->process_name, v->comm, sizeof(msg->comm));
		} else {
			if (process_name != NULL) {
				strcpy_s_inline(msg->process_name,
						sizeof(msg->process_name),
						process_name,
						strlen(process_name));
			}
		}

	} else {

		/*
		 * If the process has already exited, then execution reaches
		 * this point, which means aggregating data based on the
		 * process name.
		 */
		strcpy_s_inline(msg->process_name, sizeof(msg->process_name),
				v->comm, strlen(v->comm));
		atomic64_inc(&ctx->process_lost_count);
	}

	if (!matched || stime <= 0) {
		/* The aggregation method is identified as 
		 * { process name + [u,k]stack_trace_id + cpu} */
		msg->stime = 0;
		if (!matched) {
			msg->pid = msg->tid = 0;
			snprintf((char *)msg->process_name,
				 sizeof(msg->process_name), "%s", "Total");
		}
	}

	msg->time_stamp = gettime(CLOCK_REALTIME, TIME_TYPE_NAN);
	msg->count = 1;
	msg->data_ptr = pointer_to_uword(&msg->data[0]);

	/* Only use for test flame graph. */
	if (flame_graph_start_time == NULL) {
		flame_graph_start_time = gen_file_name_by_datetime();
	}
}

static void reader_lost_cb_a(void *cookie, u64 lost)
{
	struct bpf_tracer *tracer = profiler_tracer;
	atomic64_add(&tracer->lost, lost);
	oncpu_ctx.perf_buf_lost_a_count++;
}

static void reader_lost_cb_b(void *cookie, u64 lost)
{
	struct bpf_tracer *tracer = profiler_tracer;
	atomic64_add(&tracer->lost, lost);
	oncpu_ctx.perf_buf_lost_b_count++;
}

static void reader_raw_cb(void *cookie, void *raw, int raw_size)
{
	if (unlikely(oncpu_ctx.profiler_stop == 1))
		return;

	struct reader_forward_info *fwd_info = cookie;
	if (unlikely(fwd_info->queue_id != 0)) {
		ebpf_warning("cookie(%d) error", (u64) cookie);
		return;
	}

	struct stack_trace_key_t *v;
	struct bpf_tracer *tracer = profiler_tracer;
	v = (struct stack_trace_key_t *)raw;

	int ret = VEC_OK;
	vec_add1(raw_stack_data, *v, ret);
	if (ret != VEC_OK) {
		ebpf_warning("vec add failed\n");
	}

	atomic64_add(&tracer->recv, 1);
}

static int release_profiler(struct bpf_tracer *tracer)
{
	tracer_reader_lock(tracer);

	/* detach perf event */
	tracer_hooks_detach(tracer);

	/* free all readers */
	free_all_readers(tracer);

	print_cp_tracer_status(tracer, &oncpu_ctx);

	/* release object */
	release_object(tracer->obj);

	tracer_reader_unlock(tracer);

	return ETR_OK;
}

static inline bool is_cpdbg_timeout(void)
{
	uint32_t passed_sec;
	passed_sec = get_sys_uptime() - cpdbg_start_time;
	if (passed_sec > cpdbg_timeout) {
		cpdbg_start_time = 0;
		cpdbg_enable = false;
		cpdbg_use_remote = false;
		ebpf_info("\n\ncpdbg is finished, use time: %us.\n\n",
			  cpdbg_timeout);
		cpdbg_timeout = 0;
		return true;
	}

	return false;
}

static void print_cp_data(stack_trace_msg_t * msg)
{
	char *timestamp = gen_timestamp_str(0);
	if (timestamp == NULL)
		return;

	char *cid;
	if (strlen((char *)msg->container_id) == 0)
		cid = "null";
	else
		cid = (char *)msg->container_id;

	char buff[DEBUG_BUFF_SIZE];
	snprintf(buff, sizeof(buff),
		 "%s [cpdbg] netns_id %lu container_id %s pid %u tid %u "
		 "process_name %s comm %s stime %lu u_stack_id %u k_statck_id"
		 " %u cpu %u count %u tiemstamp %lu datalen %u data %s\n",
		 timestamp, msg->netns_id, cid, msg->pid, msg->tid,
		 msg->process_name, msg->comm, msg->stime,
		 msg->u_stack_id,
		 msg->k_stack_id, msg->cpu, msg->count,
		 msg->time_stamp, msg->data_len, msg->data);

	free(timestamp);

	if (cpdbg_cb != NULL) {
		cpdbg_cb(buff, strlen(buff));
	} else {
		fprintf(stdout, "%s\n", buff);
		fflush(stdout);
	}
}

void cpdbg_process(stack_trace_msg_t * msg)
{
	pthread_mutex_lock(&cpdbg_mutex);
	if (unlikely(cpdbg_enable)) {
		if (!is_cpdbg_timeout())
			print_cp_data(msg);

	}
	pthread_mutex_unlock(&cpdbg_mutex);
}

static inline void add_stack_id_to_bitmap(struct profiler_context *ctx,
					  int stack_id, bool is_a)
{
	if (stack_id < 0)
		return;

	struct stack_ids_bitmap *ids;
	if (is_a)
		ids = &ctx->stack_ids_a;
	else
		ids = &ctx->stack_ids_b;

	if (!is_set_bitmap(ids->bitmap, stack_id)) {
		set_bitmap(ids->bitmap, stack_id);
		int ret = VEC_OK;

		if (is_a)
			vec_add1(ctx->clear_stack_ids_a, stack_id, ret);
		else
			vec_add1(ctx->clear_stack_ids_b, stack_id, ret);

		if (ret != VEC_OK) {
			ebpf_warning("vec add failed\n");
		}

		ids->count++;
	}
}

static inline void update_matched_process_in_total(struct profiler_context *ctx,
						   stack_trace_msg_hash_t *
						   msg_hash,
						   char *process_name,
						   struct stack_trace_key_t *v)
{
	stack_trace_msg_kv_t kv;
	set_msg_kvp_by_comm(&kv, v, (void *)0);

	if (stack_trace_msg_hash_search
	    (msg_hash, (stack_trace_msg_hash_kv *) & kv,
	     (stack_trace_msg_hash_kv *) & kv) == 0) {
		__sync_fetch_and_add(&msg_hash->hit_hash_count, 1);
		((stack_trace_msg_t *) kv.msg_ptr)->count++;
		return;
	}

	/* append ';' '\0' and '[p/t]' */
	char trace_str[(TASK_COMM_LEN * 2) + 10];
	bool is_thread = (v->pid != v->tgid);
	if (is_thread)
		snprintf(trace_str, sizeof(trace_str), "[p] %s;[t] %s",
			 process_name, v->comm);
	else
		snprintf(trace_str, sizeof(trace_str), "[p] %s", process_name);

	/* append 2 byte for ';''\0' */
	int len = sizeof(stack_trace_msg_t) + strlen(trace_str) + 2;
	stack_trace_msg_t *msg = alloc_stack_trace_msg(len);
	if (msg == NULL) {
		clib_mem_free(trace_str);
		return;
	}

	set_stack_trace_msg(ctx, msg, v, false, 0, 0, process_name, NULL);
	snprintf((char *)&msg->data[0], strlen(trace_str) + 2, "%s", trace_str);
	msg->data_len = strlen((char *)msg->data);
	kv.msg_ptr = pointer_to_uword(msg);

	if (stack_trace_msg_hash_add_del(msg_hash,
					 (stack_trace_msg_hash_kv
					  *) & kv, 1 /* is_add */ )) {
		ebpf_warning("stack_trace_msg_hash_add_del() failed.\n");
		clib_mem_free(msg);
	} else {
		__sync_fetch_and_add(&msg_hash->hash_elems_count, 1);
	}
}

void aggregate_stack_traces(struct profiler_context *ctx,
			    struct bpf_tracer *t,
			    const char *stack_map_name,
			    stack_str_hash_t * stack_str_hash,
			    stack_trace_msg_hash_t * msg_hash,
			    u32 * count, bool use_a_map)
{
	struct stack_trace_key_t *v;
	vec_foreach(v, raw_stack_data) {
		if (v == NULL)
			break;

		if (unlikely(ctx->profiler_stop == 1))
			break;

		/*
		 * If cpu_aggregation_flag=0, the CPU value for stack trace data
		 * reporting is a special value (CPU_INVALID:0xfff) used to indicate
		 * that it is an invalid value, the  CPUID will not be included in
		 * the aggregation.
		 */
		if (cpu_aggregation_flag == 0)
			v->cpu = CPU_INVALID;

		/*
		 * Uniform idle process names to reduce the aggregated count of stack
		 * trace data (when we aggregate using process names as part of the key).
		 * "swapper/0", "swapper/1", "swapper/2" ... > "swapper" 
		 */
		if (v->pid == v->tgid && v->pid == 0) {
			const char *idle_name = "swapper";
			strcpy_s_inline(v->comm, sizeof(v->comm),
					idle_name, strlen(idle_name));
		}

		/* -EEXIST: Hash bucket collision in the stack trace table */
		if (v->kernstack == -EEXIST)
			ctx->stack_trace_err++;

		if (v->userstack == -EEXIST)
			ctx->stack_trace_err++;

		add_stack_id_to_bitmap(ctx, v->kernstack, use_a_map);
		add_stack_id_to_bitmap(ctx, v->userstack, use_a_map);

		/* Total iteration count for this iteration. */
		(*count)++;

		/* Total iteration count for all iterations. */
		process_count++;

		/*
		 * Firstly, search the stack-trace-msg hash to see if the
		 * stack trace messages has already been stored. 
		 */
		stack_trace_msg_kv_t kv;
		char name[TASK_COMM_LEN];
		memset(name, 0, sizeof(name));
		u64 stime, netns_id;
		stime = netns_id = 0;
		void *info_p = NULL;
		char *process_name = NULL;
		bool matched, is_match_finish;
		matched = is_match_finish = false;

		/* If it is a process, match operation will be performed immediately. */
		if (v->pid == v->tgid) {
			is_match_finish = true;
			matched =
			    (regexec(&ctx->profiler_regex, v->comm, 0, NULL, 0)
			     == 0);
			if (!matched) {
				set_msg_kvp_by_comm(&kv, v, (void *)0);
				goto skip_proc_find;
			}
		}

		get_process_info_by_pid(v->tgid, &stime, &netns_id,
					(char *)name, &info_p);

		/* 
		 * If the data collected is from a running process, and the process
		 * name and the command name of the task (captured by eBPF) are not
		 * consistent, it indicates that the cached process information is
		 * no longer valid.
		 */
		if (stime > 0 && v->pid == v->tgid && strcmp(name, v->comm)) {
			stime = netns_id = 0;
			name[0] = '\0';
			process_name = NULL;
			info_p = NULL;
		}

		if (stime > 0) {
			if (v->tgid == 0)
				process_name = v->comm;
			else
				process_name = name;

			if (!is_match_finish)
				matched =
				    (regexec
				     (&ctx->profiler_regex, process_name, 0,
				      NULL, 0)
				     == 0);
			if (matched)
				set_msg_kvp(&kv, v, stime, (void *)0);
			else
				set_msg_kvp_by_comm(&kv, v, (void *)0);
		} else {
			/* Not find process in procfs. */
			set_msg_kvp_by_comm(&kv, v, (void *)0);
		}

		/*
		 * Here, we duplicate the matched process data and place it into
		 * the Total process, with the aim of showcasing the proportion
		 * of each process in the overall sampling.
		 */
		if (matched)
			update_matched_process_in_total(ctx, msg_hash,
							process_name, v);

	      skip_proc_find:
		if (stack_trace_msg_hash_search
		    (msg_hash, (stack_trace_msg_hash_kv *) & kv,
		     (stack_trace_msg_hash_kv *) & kv) == 0) {
			__sync_fetch_and_add(&msg_hash->hit_hash_count, 1);
			((stack_trace_msg_t *) kv.msg_ptr)->count++;
			continue;
		}

		/*
		 * Folded stack trace string and generate stack trace messages.
		 *
		 * Folded stack trace string (taken from a performance profiler test):
		 * main;xxx();yyy()
		 * It is a list of symbols corresponding to addresses in the underlying
		 * stack trace, separated by ';'.
		 */

		char *trace_str =
		    resolve_and_gen_stack_trace_str(t, v, stack_map_name,
						    stack_str_hash, matched,
						    process_name, info_p);
		if (trace_str) {
			/*
			 * append process/thread name to stack string
			 * append 2 byte for ';''\0'
			 * append pre_tag '[p/t]'
			 */
			char pre_tag[5];
			int str_len = strlen(trace_str) + 2;
			if (matched)
				str_len += strlen(v->comm) + sizeof(pre_tag);

			int len = sizeof(stack_trace_msg_t) + str_len;
			stack_trace_msg_t *msg = alloc_stack_trace_msg(len);
			if (msg == NULL) {
				clib_mem_free(trace_str);
				continue;
			}

			memset(msg, 0, len);
			struct symbolizer_proc_info *__p = info_p;
			set_stack_trace_msg(ctx, msg, v, matched, stime,
					    netns_id, process_name,
					    __p ? __p->container_id : NULL);

			snprintf(pre_tag, sizeof(pre_tag), "%s ",
				 v->pid == v->tgid ? "[p]" : "[t]");
			if (matched)
				snprintf((char *)&msg->data[0], str_len,
					 "%s%s;%s", pre_tag, v->comm,
					 trace_str);
			else
				snprintf((char *)&msg->data[0], str_len, "%s",
					 trace_str);

			msg->data_len = strlen((char *)msg->data);
			clib_mem_free(trace_str);
			kv.msg_ptr = pointer_to_uword(msg);

			if (stack_trace_msg_hash_add_del(msg_hash,
							 (stack_trace_msg_hash_kv
							  *) & kv,
							 1 /* is_add */ )) {
				ebpf_warning
				    ("stack_trace_msg_hash_add_del() failed.\n");
				clib_mem_free(msg);
			} else {
				__sync_fetch_and_add
				    (&msg_hash->hash_elems_count, 1);
			}
		}

		/* check and clean symbol cache */
		exec_proc_info_cache_update();
	}

	vec_free(raw_stack_data);
}

static void java_syms_update_work(void *arg)
{
	java_syms_update_main(arg);
}

static void oncpu_reader_work(void *arg)
{
	thread_index = THREAD_PROFILER_READER_IDX;
	struct bpf_tracer *t = profiler_tracer;
	oncpu_ctx.r_a = &t->readers[0];
	oncpu_ctx.r_b = &t->readers[1];

	for (;;) {
		if (unlikely(oncpu_ctx.profiler_stop == 1)) {
			if (oncpu_ctx.enable_bpf_profile)
				set_enable_profiler(t, &oncpu_ctx, 0);

			goto exit;
		}

		/* 
		 * Waiting for the regular expression to be configured
		 * and start working. Ensure the socket tracer is in
		 * the 'running' state to prevent starting the profiler
		 * before the socket tracer has completed its attach
		 * operation. The profiler's processing depends on probe
		 * interfaces provided by the socket tracer, such as process
		 * exit events. We want to ensure that everything is ready
		 * before the profiler performs address translation.
		 */
		if (unlikely(!oncpu_ctx.regex_existed ||
			     get_socket_tracer_state() != TRACER_RUNNING)) {
			if (oncpu_ctx.enable_bpf_profile)
				set_enable_profiler(t, &oncpu_ctx, 0);
			exec_proc_info_cache_update();
			sleep(1);
			continue;
		}

		if (unlikely(!oncpu_ctx.enable_bpf_profile))
			set_enable_profiler(t, &oncpu_ctx, 1);

		tracer_reader_lock(t);
		process_bpf_stacktraces(&oncpu_ctx, t);
		tracer_reader_unlock(t);
	}

exit:
	print_cp_tracer_status(t, &oncpu_ctx);

	print_hash_stack_str(&g_stack_str_hash);
	/* free stack_str_hash */
	if (likely(g_stack_str_hash.buckets != NULL)) {
		release_stack_str_hash(&g_stack_str_hash);
	}

	print_hash_stack_trace_msg(&g_msg_hash);
	/* free stack_str_hash */
	if (likely(g_msg_hash.buckets != NULL)) {
		/* Ensure that all elements are released properly/cleanly */
		push_and_release_stack_trace_msg(&oncpu_ctx, &g_msg_hash, true);
		stack_trace_msg_hash_free(&g_msg_hash);
	}

	/* resouce share release */
	release_symbol_caches();

	/* clear thread */
	t->perf_worker[0] = 0;
	ebpf_info(LOG_CP_TAG "perf profiler reader-thread exit.\n");

	pthread_exit(NULL);
}

static int create_profiler(struct bpf_tracer *tracer)
{
	int ret;

	profiler_tracer = tracer;

	/* load ebpf perf profiler */
	if (tracer_bpf_load(tracer))
		return ETR_LOAD;

	set_enable_profiler(tracer, &oncpu_ctx, 0);

	/*
	 * create reader for read eBPF-profiler data.
	 * To implement eBPF perf-profiler double buffering output,
	 * it is necessary to create two readers to correspond to
	 * the double buffering structure design.
	 */
	struct bpf_perf_reader *reader_a, *reader_b;
	reader_a = create_perf_buffer_reader(tracer,
					     MAP_PERF_PROFILER_BUF_A_NAME,
					     reader_raw_cb,
					     reader_lost_cb_a,
					     PROFILE_PG_CNT_DEF, 1,
					     PROFILER_READER_EPOLL_TIMEOUT);
	if (reader_a == NULL)
		return ETR_NORESOURCE;

	reader_b = create_perf_buffer_reader(tracer,
					     MAP_PERF_PROFILER_BUF_B_NAME,
					     reader_raw_cb,
					     reader_lost_cb_b,
					     PROFILE_PG_CNT_DEF, 1,
					     PROFILER_READER_EPOLL_TIMEOUT);
	if (reader_b == NULL) {
		free_perf_buffer_reader(reader_a);
		return ETR_NORESOURCE;
	}

	/* clear old perf files */
	exec_command("/usr/bin/rm -rf /tmp/perf-*.map", "");
	exec_command("/usr/bin/rm -rf /tmp/perf-*.log", "");

	if (tracer_probes_init(tracer))
		return (-1);

	ret = create_work_thread("java_update",
				 &java_syms_update_thread,
				 (void *)java_syms_update_work, (void *)tracer);

	if (ret) {
		goto error;
	}

	/*
	 * Start a new thread to execute the data
	 * reading of perf buffer.
	 */
	ret = enable_tracer_reader_work("oncpu_reader", 0, tracer,
					(void *)&oncpu_reader_work);

	if (ret) {
		goto error;
	}

	extended_reader_create(tracer);

	/* attach perf event */
	tracer_hooks_attach(tracer);

	return ETR_OK;

error:
	release_profiler(tracer);
	return ETR_INVAL;
}

int stop_continuous_profiler(void)
{
	oncpu_ctx.profiler_stop = 1;
	if (flame_graph_end_time == NULL) {
		flame_graph_end_time = gen_file_name_by_datetime();
	}

	release_bpf_tracer(CP_TRACER_NAME);
	profiler_tracer = NULL;

	u64 alloc_b, free_b;
	get_mem_stat(&alloc_b, &free_b);
	if (oncpu_ctx.regex_existed) {
		regfree(&oncpu_ctx.profiler_regex);
		oncpu_ctx.regex_existed = false;
	}

	ebpf_info(LOG_CP_TAG "== alloc_b %lu bytes, free_b %lu bytes, "
		  "use %lu bytes ==\n", alloc_b, free_b, alloc_b - free_b);
	return (0);
}

static void print_cp_tracer_status(struct bpf_tracer *t,
				   struct profiler_context *ctx)
{
	u64 alloc_b, free_b;
	get_mem_stat(&alloc_b, &free_b);

	u64 sample_drop_cnt = 0;
	if (!bpf_table_get_value(t, MAP_PROFILER_STATE_MAP, SAMPLE_CNT_DROP,
				 (void *)&sample_drop_cnt)) {
		ebpf_warning("Get map '%s' sample_drop_cnt failed.\n",
			     MAP_PROFILER_STATE_MAP);
	}

	u64 output_err_cnt = 0;
	if (!bpf_table_get_value(t, MAP_PROFILER_STATE_MAP, ERROR_IDX,
				 (void *)&output_err_cnt)) {
		ebpf_warning("Get map '%s' output_err_cnt failed.\n",
			     MAP_PROFILER_STATE_MAP);
	}

	u64 output_count = 0;
	if (!bpf_table_get_value(t, MAP_PROFILER_STATE_MAP, OUTPUT_CNT_IDX,
				 (void *)&output_count)) {
		ebpf_warning("Get map '%s' output_cnt failed.\n",
			     MAP_PROFILER_STATE_MAP);
	}

	u64 iter_max_cnt = 0;
	if (!bpf_table_get_value(t, MAP_PROFILER_STATE_MAP, SAMPLE_ITER_CNT_MAX,
				 (void *)&iter_max_cnt)) {
		ebpf_warning("Get map '%s' iter_max_cnt failed.\n",
			     MAP_PROFILER_STATE_MAP);
	}

	ebpf_info("\n\n----------------------------\nrecv envent:\t%lu\n"
		  "process-cnt:\t%lu\nkern_lost:\t%lu perf_buf_lost_a:\t%lu, "
		  "perf_buf_lost_b:\t%lu process_lost_count:\t%lu "
		  "stack_table_data_miss:\t%lu\n"
		  "stackmap_clear_failed_count\t%lu\n"
		  "stack_trace_err:\t%lu\ntransfer_count:\t%lu "
		  "iter_count_avg:\t%.2lf\nalloc_b:\t%lu bytes "
		  "free_b:\t%lu bytes use:\t%lu bytes\n"
		  "eBPF map status:\n"
		  " - output_cnt:\t%lu\n"
		  " - sample_drop_cnt:\t%lu\n"
		  " - output_err_cnt:\t%lu\n"
		  " - iter_max_cnt:\t%lu\n"
		  "----------------------------\n\n",
		  atomic64_read(&t->recv), process_count,
		  atomic64_read(&t->lost), ctx->perf_buf_lost_a_count,
		  ctx->perf_buf_lost_b_count, ctx->perf_buf_lost_a_count,
		  ctx->perf_buf_lost_b_count, get_process_lost_count(ctx),
		  get_stack_table_data_miss_count(),
		  ctx->stackmap_clear_failed_count, ctx->stack_trace_err,
		  ctx->transfer_count,
		  ((double)atomic64_read(&t->recv) /
		   (double)ctx->transfer_count), alloc_b, free_b,
		  alloc_b - free_b, output_count, sample_drop_cnt,
		  output_err_cnt, iter_max_cnt);
}

static int cpdbg_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
			     void **out, size_t *outsize)
{
	return 0;
}

static int cpdbg_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
	struct cpdbg_msg *msg = (struct cpdbg_msg *)conf;
	pthread_mutex_lock(&cpdbg_mutex);
	if (msg->enable) {
		cpdbg_start_time = get_sys_uptime();
		cpdbg_timeout = msg->timeout;
	}

	if (cpdbg_enable && !msg->enable) {
		cpdbg_timeout = 0;
		cpdbg_start_time = 0;
	}

	cpdbg_enable = msg->enable;
	if (cpdbg_enable) {
		ebpf_info("cpdbg enable timeout %ds\n", cpdbg_timeout);
	} else {
		ebpf_info("cpdbg disable");
	}

	pthread_mutex_unlock(&cpdbg_mutex);

	return 0;
}

static struct tracer_sockopts cpdbg_sockopts = {
	.version = SOCKOPT_VERSION,
	.set_opt_min = SOCKOPT_SET_CPDBG_ADD,
	.set_opt_max = SOCKOPT_SET_CPDBG_OFF,
	.set = cpdbg_sockopt_set,
	.get_opt_min = SOCKOPT_GET_CPDBG_SHOW,
	.get_opt_max = SOCKOPT_GET_CPDBG_SHOW,
	.get = cpdbg_sockopt_get,
};

/*
 * start continuous profiler
 * @freq sample frequency, Hertz. (e.g. 99 profile stack traces at 99 Hertz)
 * @java_syms_space_limit The maximum space occupied by the Java symbol files
 *                        in the target POD. 
 * @java_syms_update_delay To allow Java to run for an extended period and gather
 *                    more symbol information, we delay symbol retrieval when
 *                    encountering unknown symbols. The default value is
 *                    'JAVA_SYMS_UPDATE_DELAY_DEF'.
 *                    This represents the delay in seconds.
 * @callback Profile data processing callback interface
 * @returns 0 on success, < 0 on error
 */

int start_continuous_profiler(int freq, int java_syms_space_limit,
			      int java_syms_update_delay,
			      tracer_callback_t callback)
{
	char bpf_load_buffer_name[NAME_LEN];
	void *bpf_bin_buffer;
	uword buffer_sz;

	if (!run_conditions_check())
		return (-1);

	profiler_context_init(&oncpu_ctx, MAP_PROFILER_STATE_MAP,
			      MAP_STACK_A_NAME, MAP_STACK_B_NAME);

	int java_space_bytes = java_syms_space_limit * 1024 * 1024;
	if ((java_space_bytes < JAVA_POD_WRITE_FILES_SPACE_MIN) ||
	    (java_space_bytes > JAVA_POD_WRITE_FILES_SPACE_MAX))
		java_space_bytes = JAVA_POD_WRITE_FILES_SPACE_DEF;
	g_java_syms_write_bytes_max =
	    java_space_bytes - JAVA_POD_EXTRA_SPACE_MMA;
	ebpf_info("set java_syms_write_bytes_max : %d\n",
		  g_java_syms_write_bytes_max);

	if ((java_syms_update_delay < JAVA_SYMS_UPDATE_DELAY_MIN) ||
	    (java_syms_update_delay > JAVA_SYMS_UPDATE_DELAY_MAX))
		java_syms_update_delay = JAVA_SYMS_UPDATE_DELAY_DEF;
	set_java_syms_fetch_delay(java_syms_update_delay);
	ebpf_info("set java_syms_update_delay : %lu\n", java_syms_update_delay);

	/*
	 * Initialize cpdbg
	 */
	pthread_mutex_init(&cpdbg_mutex, NULL);

	// CPUID will not be included in the aggregation of stack trace data.
	set_profiler_cpu_aggregation(0);

	// Java agent so library generation and tools install.
	if (java_libs_and_tools_install() != 0)
		return (-1);

	snprintf(bpf_load_buffer_name, NAME_LEN, "continuous_profiler");
	bpf_bin_buffer = (void *)perf_profiler_common_ebpf_data;
	buffer_sz = sizeof(perf_profiler_common_ebpf_data);

	struct tracer_probes_conf *tps =
	    malloc(sizeof(struct tracer_probes_conf));
	if (tps == NULL) {
		ebpf_warning("malloc() error.\n");
		return -ENOMEM;
	}
	memset(tps, 0, sizeof(*tps));
	init_list_head(&tps->uprobe_syms_head);
	CP_PROFILE_SET_PROBES(tps);

	struct bpf_tracer *tracer =
	    setup_bpf_tracer(CP_TRACER_NAME, bpf_load_buffer_name,
			     bpf_bin_buffer, buffer_sz, tps, 0,
			     release_profiler, create_profiler,
			     (void *)callback, freq);
	if (tracer == NULL)
		return (-1);

	if (sockopt_register(&cpdbg_sockopts) != ETR_OK)
		return (-1);

	tracer->state = TRACER_RUNNING;
	return (0);
}

static u64 test_add_count, stack_count;
static u64 test_hit_count, msg_ptr_zero_count;
void process_stack_trace_data_for_flame_graph(stack_trace_msg_t * msg)
{
	stack_count++;
	if (folded_file == NULL) {
		unlink(FOLDED_FILE_PATH);
		folded_file = fopen(FOLDED_FILE_PATH, "a+");
		if (folded_file == NULL)
			return;
	}

	/* Ensure that the buffer is long enough to accommodate the stack trace string. */
	int len =
	    msg->data_len + sizeof(msg->comm) + sizeof(msg->process_name) + 64;
	char str[len];
	/* profile regex match ? */
	if (msg->stime > 0)
		snprintf(str, len, "%s (%d);%s %u\n", msg->process_name,
			 msg->pid, msg->data, msg->count);
	else
		snprintf(str, len, "%s;%s %u\n", msg->process_name,	/*msg->pid, */
			 msg->data, msg->count);

	os_puts(folded_file, str, strlen(str), false);
}

void release_flame_graph_hash(void)
{
	u64 alloc_b, free_b;
	get_mem_stat(&alloc_b, &free_b);
	ebpf_info(LOG_CP_TAG
		  "pre alloc_b:\t%lu bytes free_b:\t%lu bytes use:\t%lu"
		  " bytes\n", alloc_b, free_b, alloc_b - free_b);
	if (folded_file)
		fclose(folded_file);

	get_mem_stat(&alloc_b, &free_b);
#ifdef DF_MEM_DEBUG
	show_mem_list();
#endif
	ebpf_info(LOG_CP_TAG
		  "after alloc_b:\t%lu bytes free_b:\t%lu bytes use:\t%lu"
		  " bytes\n", alloc_b, free_b, alloc_b - free_b);

	ebpf_info(LOG_CP_TAG
		  "<<< stack_count %lu add_count %lu hit_count %lu msg_ptr_zero"
		  "_count %lu push_count %lu >>>\n", stack_count,
		  test_add_count, test_hit_count, msg_ptr_zero_count,
		  oncpu_ctx.push_count);

	ebpf_info(LOG_CP_TAG
		  "Please use the following command to generate a flame graph:"
		  "\n\n\033[33;1mcat ./profiler.folded |./.flamegraph.pl"
		  " --countname=samples --inverted > profiler-from_%s_to_%s.svg\033[0m\n",
		  flame_graph_start_time, flame_graph_end_time);
}

/*
 * To set the regex matching for the profiler. 
 *
 * @pattern : Regular expression pattern. e.g. "^(java|nginx|.*ser.*)$"
 * @returns 0 on success, < 0 on error
 */
int set_profiler_regex(const char *pattern)
{
	if (profiler_tracer == NULL) {
		ebpf_warning(LOG_CP_TAG
			     "The 'profiler_tracer' has not been created yet."
			     " Please use start_continuous_profiler() to create it first.\n");
		return (-1);
	}

	/*
	 * During the data processing, the thread responsible for matching reads the
	 * regular expression, while the thread handling the regular expression upd-
	 * ates is different. Synchronization is implemented to ensure protection and
	 * coordination between these two threads.
	 */
	tracer_reader_lock(profiler_tracer);
	do_profiler_regex_config(pattern, &oncpu_ctx);
	tracer_reader_unlock(profiler_tracer);
	ebpf_info(LOG_CP_TAG "Set 'profiler_regex' successful, pattern : '%s'",
		  pattern);
	return (0);
}

int set_profiler_cpu_aggregation(int flag)
{
	if (flag != 0 && flag != 1) {
		ebpf_info(LOG_CP_TAG
			  "Set 'cpu_aggregation_flag' parameter invalid.\n");
		return (-1);
	}

	cpu_aggregation_flag = (u64) flag;

	ebpf_info(LOG_CP_TAG
		  "Set 'cpu_aggregation_flag' successful, value %d\n", flag);
	return (0);
}

struct bpf_tracer *get_profiler_tracer(void)
{
	return profiler_tracer;
}

/*
 * Configure and enable the debugging functionality for Continuous Profiling.
 *
 * @timeout
 *   Specifying the timeout duration. If the elapsed time exceeds this
 *   duration, cpdbg will stop. The unit is in seconds.
 * @callback
 *   Callback interface, used to transfer data to the remote controller.
 *
 * @return 0 on success, and a negative value on failure.
 */
int cpdbg_set_config(int timeout, debug_callback_t cb)
{
	if (timeout < 0 || cb == NULL) {
		ebpf_warning("Invalid parameter\n");
		return -1;
	}

	pthread_mutex_lock(&cpdbg_mutex);
	if (cpdbg_enable) {
		ebpf_warning("cpdbg is already running\n");
		goto finish;
	}

	cpdbg_start_time = get_sys_uptime();
	cpdbg_timeout = timeout;
	cpdbg_enable = true;
	cpdbg_use_remote = true;
	cpdbg_cb = cb;

	ebpf_info("cpdbg enable timeout %ds\n", cpdbg_timeout);

finish:
	pthread_mutex_unlock(&cpdbg_mutex);
	return 0;
}

#else /* defined AARCH64_MUSL */
#include "../tracer.h"
#include "perf_profiler.h"

int start_continuous_profiler(int freq,
			      int java_syms_space_limit,
			      int java_syms_update_delay,
			      tracer_callback_t callback)
{
	return (-1);
}

int stop_continuous_profiler(void)
{
	return (0);
}

void process_stack_trace_data_for_flame_graph(stack_trace_msg_t * val)
{
	return;
}

void release_flame_graph_hash(void)
{
	return;
}

int set_profiler_regex(const char *pattern)
{
	return (-1);
}

int set_profiler_cpu_aggregation(int flag)
{
	return (-1);
}

struct bpf_tracer *get_profiler_tracer(void)
{
	return NULL;
}

void set_enable_profiler(struct bpf_tracer *t, u64 enable_flag)
{
}

int cpdbg_set_config(int timeout, debug_callback_t cb)
{
}

#endif /* AARCH64_MUSL */
