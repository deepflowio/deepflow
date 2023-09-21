/*
 * Copyright (c) 2023 Yunshan Networks
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
#include "../common.h"
#include "../mem.h"
#include "../log.h"
#include "../types.h"
#include "../vec.h"
#include "../tracer.h"
#include "attach.h"
#include "perf_profiler.h"
#include "../elf.h"
#include "../load.h"
#include "../../kernel/include/perf_profiler.h"
#include "../perf_reader.h"
#include "../bihash_8_8.h"
#include "stringifier.h"
#include "../table.h"
#include <regex.h>
#include "java/df_jattach.h"

#include "../perf_profiler_bpf_common.c"

/*
 * This section is for symbolization of Java addresses, and we need
 * to prepare two so librarys, one for GNU and the other for MUSL:
 *
 * df_java_agent.so
 * df_java_agent_musl.so
 *
 * These two files need to be saved in the '/tmp' directory, and the
 * agent so library will be injected into the JVM to generate
 * 'perf-<pid>.map'.
 */
#include "java_agent_so_gnu.c"
#include "java_agent_so_musl.c"
/* use for java symbols generate */
#include "deepflow_jattach_bin.c"

#define LOG_CP_TAG	"[CP] "
#define CP_TRACER_NAME	"continuous_profiler"
#define CP_PERF_PG_NUM	16

extern int major, minor;
extern char linux_release[128];
extern __thread uword thread_index;

struct stack_trace_key_t *raw_stack_data;
static u64 stack_trace_lost;
static struct bpf_tracer *profiler_tracer;
static volatile u64 profiler_stop;

// for stack_trace_msg_hash relese
static __thread stack_trace_msg_hash_kv *trace_msg_kvps;
static __thread bool msg_clear_hash;

// for flame-graph test
static FILE *folded_file;
#define FOLDED_FILE_PATH "./profiler.folded"
static char *flame_graph_start_time;
static char *flame_graph_end_time;

/* profiler start time(monotonic seconds). */
static u64 start_time;
/* Record the time of the last data push
 * (in seconds since system startup)*/
static u64 last_push_time;
static u64 push_count;

/* 
 * To perform regular expression matching on process names,
 * the 'profiler_regex' is set using the 'set_profiler_regex()'
 * interface. Processes that successfully match the regular
 * expression are aggregated using the key:
 * `{pid + stime + u_stack_id + k_stack_id + tid + cpu}`.
 *
 * For processes that do not match, they are aggregated using the
 * key:
 * `<process name + u_stack_id + k_stack_id + cpu>`.
 */
static regex_t profiler_regex;
static bool regex_existed = false;

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

/*
 * The iteration count causes BPF to switch buffers with each iteration.
 */
static u64 transfer_count;
static u64 process_count;

static void print_profiler_status(struct bpf_tracer *t, u64 iter_count,
				  stack_str_hash_t * h,
				  stack_trace_msg_hash_t * msg_h);
static void print_cp_tracer_status(struct bpf_tracer *t);

/*
 * During the parsing process, it is possible for processes in procfs
 * to be missing (processes that start and exit quickly). This variable
 * is used to count the number of lost processes during the parsing process.
 */
static atomic64_t process_lost_count;

static u64 get_process_lost_count(void)
{
	return atomic64_read(&process_lost_count);
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

static void set_msg_kvp_by_comm(stack_trace_msg_kv_t * kvp,
				const char *process_name,
				struct stack_trace_key_t *v, void *msg_value)
{
	if (process_name == NULL) {
		strcpy_s_inline(kvp->c_k.comm, sizeof(kvp->c_k.comm),
				v->comm, strlen(v->comm));
	} else {
		strcpy_s_inline(kvp->c_k.comm, sizeof(kvp->c_k.comm),
				process_name, strlen(process_name));
	}

	kvp->c_k.cpu = v->cpu;

	if (v->userstack < 0)
		kvp->c_k.u_stack_id = STACK_ID_MAX;
	else
		kvp->c_k.u_stack_id = v->userstack;

	if (v->kernstack < 0)
		kvp->c_k.k_stack_id = STACK_ID_MAX;
	else
		kvp->c_k.k_stack_id = v->kernstack;

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

static void set_stack_trace_msg(stack_trace_msg_t * msg,
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
		atomic64_inc(&process_lost_count);
	}

	if (!matched || stime <= 0) {
		/* The aggregation method is identified as 
		 * { process name + [u,k]stack_trace_id + cpu} */
		msg->stime = 0;
	}

	msg->time_stamp = gettime(CLOCK_REALTIME, TIME_TYPE_NAN);
	msg->count = 1;
	msg->data_ptr = pointer_to_uword(&msg->data[0]);

	/* Only use for test flame graph. */
	if (flame_graph_start_time == NULL) {
		flame_graph_start_time = gen_file_name_by_datetime();
	}
}

static void reader_lost_cb(void *t, u64 lost)
{
	struct bpf_tracer *tracer = (struct bpf_tracer *)t;
	atomic64_add(&tracer->lost, lost);
}

static void reader_raw_cb(void *t, void *raw, int raw_size)
{
	if (unlikely(profiler_stop == 1))
		return;

	struct stack_trace_key_t *v;
	struct bpf_tracer *tracer = (struct bpf_tracer *)t;
	v = (struct stack_trace_key_t *)raw;

	int ret = VEC_OK;
	vec_add1(raw_stack_data, *v, ret);
	if (ret != VEC_OK) {
		ebpf_warning("vec add failed\n");
	}

	atomic64_add(&tracer->recv, 1);
}

static int relase_profiler(struct bpf_tracer *tracer)
{
	tracer_reader_lock(tracer);

	/* detach perf event */
	tracer_hooks_detach(tracer);

	/* free all readers */
	free_all_readers(tracer);

	print_cp_tracer_status(tracer);

	/* release object */
	release_object(tracer->obj);

	tracer_reader_unlock(tracer);

	return ETR_OK;
}

static int init_stack_trace_msg_hash(stack_trace_msg_hash_t * h,
				     const char *name)
{
	memset(h, 0, sizeof(*h));
	u32 nbuckets = STACK_TRACE_MSG_HASH_BUCKETS_NUM;
	u64 hash_memory_size = STACK_TRACE_MSG_HASH_MEM_SZ;
	return stack_trace_msg_hash_init(h, (char *)name,
					 nbuckets, hash_memory_size);
}

static int push_and_free_msg_kvp_cb(stack_trace_msg_hash_kv * kv, void *ctx)
{
	stack_trace_msg_kv_t *msg_kv = (stack_trace_msg_kv_t *) kv;
	if (msg_kv->msg_ptr != 0) {
		stack_trace_msg_t *msg = (stack_trace_msg_t *) msg_kv->msg_ptr;
#ifdef CP_DEBUG
		ebpf_debug
		    ("tiemstamp %lu pid %u stime %lu u_stack_id %lu k_statck_id"
		     "%lu cpu %u count %u comm %s datalen %u data %s\n",
		     msg->time_stamp, msg->pid, msg->stime, msg->u_stack_id,
		     msg->k_stack_id, msg->cpu, msg->count, msg->comm,
		     msg->data_len, msg->data);
#endif
		tracer_callback_t fun = profiler_tracer->process_fn;
		/*
		 * Execute callback function to hand over the data to the
		 * higher level for processing. The higher level will se-
		 * nd the data to the server for storage as required.
		 */
		if (likely(profiler_stop == 0))
			fun(msg);

		clib_mem_free((void *)msg);
		msg_kv->msg_ptr = 0;
		(*(u64 *) ctx)++;
	}

	int ret = VEC_OK;
	vec_add1(trace_msg_kvps, *kv, ret);
	if (ret != VEC_OK) {
		ebpf_warning("vec add failed\n");
		msg_clear_hash = true;
	}

	return BIHASH_WALK_CONTINUE;
}

/*
 * Push the data and release the resources.
 * @is_force: Do you need to perform a forced release?
 */
static void push_and_release_stack_trace_msg(stack_trace_msg_hash_t * h,
					     bool is_force)
{
	ASSERT(profiler_tracer != NULL);

	u64 curr_time, elapsed;
	curr_time = gettime(CLOCK_MONOTONIC, TIME_TYPE_NAN);
	elapsed = curr_time - last_push_time;
	/*
	 * If the aggregated stack trace data obtained by the profiler
	 * satisfies one of the following conditions, it should be pushed
	 * to the upper-level processing:
	 *
	 *   If the time interval since the last push exceeds or equals
	 *   the maximum time interval (MAX_PUSH_MSG_TIME_INTERVAL).
	 *
	 * Otherwise, it should return directly.
	 */
	if (!((elapsed >= MAX_PUSH_MSG_TIME_INTERVAL) || is_force))
		return;

	/* update last push time. */
	last_push_time = curr_time;
	push_count++;

	u64 elems_count = 0;
	stack_trace_msg_hash_foreach_key_value_pair(h, push_and_free_msg_kvp_cb,
						    (void *)&elems_count);
	/*
	 * In this iteration, all elements will be cleared, and in the
	 * next iteration, this hash will be reused.
	 */
	stack_trace_msg_hash_kv *v;
	vec_foreach(v, trace_msg_kvps) {
		if (stack_trace_msg_hash_add_del(h, v, 0 /* delete */ )) {
			ebpf_warning
			    ("stack_trace_msg_hash_add_del() failed.\n");
			msg_clear_hash = true;
		}
	}

	vec_free(trace_msg_kvps);

	if (elems_count != h->hash_elems_count) {
		ebpf_warning("elems_count %lu hash_elems_count %lu "
			     "hit_hash_count %lu\n", elems_count,
			     h->hash_elems_count, h->hit_hash_count);
	}

	h->hit_hash_count = 0;
	h->hash_elems_count = 0;

	if (msg_clear_hash) {
		msg_clear_hash = false;
		stack_trace_msg_hash_free(h);
	}

	ebpf_debug("release_stack_trace_msg hashmap clear %lu "
		   "elems.\n", elems_count);
}

static void aggregate_stack_traces(struct bpf_tracer *t,
				   const char *stack_map_name,
				   stack_str_hash_t * stack_str_hash,
				   stack_trace_msg_hash_t * msg_hash,
				   u32 * count)
{
	struct stack_trace_key_t *v;
	vec_foreach(v, raw_stack_data) {
		if (v == NULL)
			break;

		if (unlikely(profiler_stop == 1))
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
			stack_trace_lost++;

		if (v->userstack == -EEXIST)
			stack_trace_lost++;

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
		u64 stime, netns_id;
		void *info_p = NULL;
		get_process_info_by_pid(v->tgid, &stime, &netns_id,
					(char *)name, &info_p);
		char *process_name = NULL;
		bool matched = false;

		if (stime > 0) {
			if (v->tgid == 0)
				process_name = v->comm;
			else
				process_name = name;

			matched =
			    (regexec(&profiler_regex, process_name, 0, NULL, 0)
			     == 0);
			if (matched)
				set_msg_kvp(&kv, v, stime, (void *)0);
			else
				set_msg_kvp_by_comm(&kv, process_name, v,
						    (void *)0);
		} else {
			/* Not find process in procfs. */
			set_msg_kvp_by_comm(&kv, NULL, v, (void *)0);
		}

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
						    stack_str_hash, matched, info_p);
		if (trace_str) {
			/*
			 * append process/thread name to stack string
			 * append 2 byte for ';' and '\0'
			 */
			int str_len = strlen(trace_str) + strlen(v->comm) + 2;
			int len = sizeof(stack_trace_msg_t) + str_len;
			stack_trace_msg_t *msg = alloc_stack_trace_msg(len);
			if (msg == NULL) {
				clib_mem_free(trace_str);
				continue;
			}

			memset(msg, 0, len);
			struct symbolizer_proc_info *__p = info_p;
			set_stack_trace_msg(msg, v, matched, stime, netns_id,
					    process_name,
					    __p ? __p->container_id : NULL);

			snprintf((char *)&msg->data[0], str_len, "%s;%s",
				 v->comm, trace_str);
			msg->data_len = str_len - 1;
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
				__sync_fetch_and_add(&msg_hash->
						     hash_elems_count, 1);
			}
		}

		/* check and clean symbol cache */
		exec_symbol_cache_update();
	}

	vec_free(raw_stack_data);
}

static void process_bpf_stacktraces(struct bpf_tracer *t,
				    struct bpf_perf_reader *r_a,
				    struct bpf_perf_reader *r_b)
{
	struct bpf_perf_reader *r;
	const char *stack_map_name;
	bool using_map_set_a = (transfer_count % 2 == 0);
	r = using_map_set_a ? r_a : r_b;
	stack_map_name = using_map_set_a ? MAP_STACK_A_NAME : MAP_STACK_B_NAME;
	const u64 sample_count_idx =
	    using_map_set_a ? SAMPLE_CNT_A_IDX : SAMPLE_CNT_B_IDX;

	struct epoll_event events[r->readers_count];
	int nfds = reader_epoll_wait(r, events);

	transfer_count++;
	/* update map MAP_PROFILER_STATE_MAP */
	if (bpf_table_set_value(t, MAP_PROFILER_STATE_MAP,
				TRANSFER_CNT_IDX, &transfer_count) == false) {
		ebpf_warning("profiler state map update error."
			     "(%s transfer_count %lu) - %s\n",
			     MAP_PROFILER_STATE_MAP,
			     transfer_count, strerror(errno));
		transfer_count--;
	}

	/* Total iteration count for this iteration. */
	u32 count = 0;

	/* eBPF map record count for this iteration. */
	u64 sample_cnt_val = 0;

	/*
	 * Why use g_stack_str_hash?
	 *
	 * When the stringizer encounters a stack-ID for the first time in
	 * the stack trace table, it clears it. If a stack-ID is reused by
	 * different stack trace keys, the stringizer returns its memoized
	 * stack trace string. Since stack IDs are unstable between profile
	 * iterations, we create and destroy the stringizer in each profile
	 * iteration.
	 */
	if (unlikely(g_stack_str_hash.buckets == NULL)) {
		if (init_stack_str_hash(&g_stack_str_hash, "profile_stack_str")) {
			ebpf_warning("init_stack_str_hash() failed.\n");
			return;
		}
	}

	/*
	 * During each transmission iteration, we have a hashmap structure in
	 * place for the following purposes:
	 *
	 * 1 Pushing the data of this iteration to the higher-level processing.
	 * 2 Performing data statistics based on the stack trace data, using the
	 *   combination of "tgid + tgid_start_time + pid + cpu + k_stack_id +
	 *   u_stack_id + " as the key.
	 *
	 * Here is the key-value pair structure of the hashmap:
	 * see perf_profiler.h (stack_trace_msg_kv_t)
	 * This is the final form of the data. If the current stack trace message
	 * is a match, we only need to increment the count field in the correspon-
	 * ding value, thus avoiding duplicate parsing.
	 */
	if (unlikely(g_msg_hash.buckets == NULL)) {
		if (init_stack_trace_msg_hash(&g_msg_hash, "stack_trace_msg")) {
			ebpf_warning("init_stack_trace_msg_hash() failed.\n");
			return;
		}
	}

	if (nfds > 0) {

	      check_again:
		if (unlikely(profiler_stop == 1))
			goto release_iter;

		/* 
		 * If there is data, the reader's callback
		 * function will be called.
		 */
		reader_event_read(events, nfds);

		/*
		 * After the reader completes data reading, the work of
		 * data aggregation will be blocked if there is no data.
		 */
		aggregate_stack_traces(t, stack_map_name, &g_stack_str_hash,
				       &g_msg_hash, &count);

		/*
		 * To ensure that all data in the perf ring-buffer is processed
		 * in this iteration, as this iteration will clean up all the
		 * data recorded in the stackmap, any residual data in the perf
		 * ring-buffer will be carried over to the next iteration for
		 * processing. This poses a risk of not being able to find the
		 * corresponding stackmap records in the next iteration, leading
		 * to incomplete processing.
		 */
		if (bpf_table_get_value(t, MAP_PROFILER_STATE_MAP,
					sample_count_idx,
					(void *)&sample_cnt_val)) {
			if (sample_cnt_val > count) {
				nfds = reader_epoll_short_wait(r, events);
				if (nfds > 0)
					goto check_again;
			}
		}
	}

release_iter:
	/* Now that we've consumed the data, reset the sample count in BPF. */
	sample_cnt_val = 0;
	bpf_table_set_value(t, MAP_PROFILER_STATE_MAP,
			    sample_count_idx, &sample_cnt_val);

	print_profiler_status(t, count, &g_stack_str_hash, &g_msg_hash);

	/* free all elems */
	clean_stack_strs(&g_stack_str_hash);

	/* Push messages and free stack_trace_msg_hash */
	push_and_release_stack_trace_msg(&g_msg_hash, false);
}

static void cp_reader_work(void *arg)
{
	thread_index = THREAD_PROFILER_READER_IDX;
	struct bpf_tracer *t = (struct bpf_tracer *)arg;
	struct bpf_perf_reader *reader_a, *reader_b;
	reader_a = &t->readers[0];
	reader_b = &t->readers[1];

	for (;;) {
		if (unlikely(profiler_stop == 1))
			goto exit;

		/* 
		 * Waiting for the regular expression to be configured
		 * and start working. 
		 */
		if (unlikely(!regex_existed)) {
			exec_symbol_cache_update();
			sleep(1);
			continue;
		}

		tracer_reader_lock(t);
		process_bpf_stacktraces(t, reader_a, reader_b);
		tracer_reader_unlock(t);
	}

exit:
	print_cp_tracer_status(t);

	print_hash_stack_str(&g_stack_str_hash);
	/* free stack_str_hash */
	if (likely(g_stack_str_hash.buckets != NULL)) {
		release_stack_str_hash(&g_stack_str_hash);
	}

	print_hash_stack_trace_msg(&g_msg_hash);
	/* free stack_str_hash */
	if (likely(g_msg_hash.buckets != NULL)) {
		/* Ensure that all elements are released properly/cleanly */
		push_and_release_stack_trace_msg(&g_msg_hash, true);
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
					     reader_lost_cb,
					     PROFILE_PG_CNT_DEF,
					     PROFILER_READER_EPOLL_TIMEOUT);
	if (reader_a == NULL)
		return ETR_NORESOURCE;

	reader_b = create_perf_buffer_reader(tracer,
					     MAP_PERF_PROFILER_BUF_B_NAME,
					     reader_raw_cb,
					     reader_lost_cb,
					     PROFILE_PG_CNT_DEF,
					     PROFILER_READER_EPOLL_TIMEOUT);
	if (reader_b == NULL) {
		free_perf_buffer_reader(reader_a);
		return ETR_NORESOURCE;
	}

	/* syms_cache_hash maps from pid to BCC symbol cache.
	 * Use of void* is inherited from the BCC library. */
	create_and_init_symbolizer_caches();

	/* attach perf event */
	tracer_hooks_attach(tracer);

	/*
	 * Start a new thread to execute the data
	 * reading of perf buffer.
	 */
	ret = enable_tracer_reader_work("cp_reader", tracer,
					(void *)&cp_reader_work);

	if (ret) {
		relase_profiler(tracer);
		return ETR_INVAL;
	}

	return ETR_OK;
}

int stop_continuous_profiler(void)
{
	profiler_stop = 1;
	if (flame_graph_end_time == NULL) {
		flame_graph_end_time = gen_file_name_by_datetime();
	}

	release_bpf_tracer(CP_TRACER_NAME);
	profiler_tracer = NULL;

	u64 alloc_b, free_b;
	get_mem_stat(&alloc_b, &free_b);
	if (regex_existed) {
		regfree(&profiler_regex);
		regex_existed = false;
	}

	ebpf_info(LOG_CP_TAG "== alloc_b %lu bytes, free_b %lu bytes, "
		  "use %lu bytes ==\n", alloc_b, free_b, alloc_b - free_b);
	return (0);
}

static void print_cp_tracer_status(struct bpf_tracer *t)
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
		  "process-cnt:\t%lu\nkern_lost:\t%lu process_lost_count:\t%lu "
		  "stack_table_data_miss:\t%lu\n"
		  "stack_trace_lost:\t%lu\ntransfer_count:\t%lu "
		  "iter_count_avg:\t%.2lf\nalloc_b:\t%lu bytes "
		  "free_b:\t%lu bytes use:\t%lu bytes\n"
		  "eBPF map status:\n"
		  " - output_cnt:\t%lu\n"
		  " - sample_drop_cnt:\t%lu\n"
		  " - output_err_cnt:\t%lu\n"
		  " - iter_max_cnt:\t%lu\n"
		  "----------------------------\n\n",
		  atomic64_read(&t->recv), process_count,
		  atomic64_read(&t->lost), get_process_lost_count(),
		  get_stack_table_data_miss_count(), stack_trace_lost,
		  transfer_count,
		  ((double)atomic64_read(&t->recv) / (double)transfer_count),
		  alloc_b, free_b, alloc_b - free_b, output_count,
		  sample_drop_cnt, output_err_cnt, iter_max_cnt);
}

static void print_profiler_status(struct bpf_tracer *t, u64 iter_count,
				  stack_str_hash_t * h,
				  stack_trace_msg_hash_t * msg_h)
{
	u64 alloc_b, free_b;
	get_mem_stat(&alloc_b, &free_b);
	ebpf_debug("\n\n----------------------------\nrecv envent:\t%lu\n"
		   "kern_lost:\t%lu\nstack_trace_lost:\t%lu\n"
		   "ransfer_count:\t%lu iter_count:\t%lu\nall"
		   "oc_b:\t%lu bytes free_b:\t%lu bytes use:\t%lu bytes\n"
		   "stack_str_hash.hit_count %lu\nstack_trace_msg_hash hit %lu\n",
		   atomic64_read(&t->recv), atomic64_read(&t->lost),
		   stack_trace_lost, transfer_count, iter_count,
		   alloc_b, free_b, alloc_b - free_b,
		   h->hit_hash_count, msg_h->hit_hash_count);
}

/*
 * View kernel addresses exposed via /proc and other interfaces
 * when /proc/sys/kernel/kptr_restrict has the value 1, it is
 * necessary to set the CAP_SYSLOG capability, otherwise all k-
 * ernel addresses are set to 0.
 *
 * This function is used to check if the kernel address is 0.
 */
static bool check_kallsyms_addr_is_zero(void)
{
	const int check_num = 100;
	const int max_line_len = 256;
	const char *check_str = "0000000000000000";

	FILE *file = fopen("/proc/kallsyms", "r");
	if (file == NULL) {
		ebpf_warning(LOG_CP_TAG "Error opening /proc/kallsyms");
		return false;
	}

	char line[max_line_len];
	int count = 0;

	while (fgets(line, sizeof(line), file) != NULL && count < check_num) {
		char address[17];	// 16 characters + null terminator
		sscanf(line, "%16s", address);

		if (strcmp(address, check_str) == 0) {
			count++;
		}
	}

	fclose(file);

	return (count == check_num);
}

/*
 * start continuous profiler
 * @freq sample frequency, Hertz. (e.g. 99 profile stack traces at 99 Hertz)
 * @callback Profile data processing callback interface
 * @returns 0 on success, < 0 on error
 */
int start_continuous_profiler(int freq, tracer_callback_t callback)
{
	char bpf_load_buffer_name[NAME_LEN];
	void *bpf_bin_buffer;
	uword buffer_sz;

	// REQUIRES: Linux 4.9+ (BPF_PROG_TYPE_PERF_EVENT support).
	if (check_kernel_version(4, 9) != 0) {
		ebpf_warning
		    (LOG_CP_TAG
		     "Currnet linux %d.%d, not support, require Linux 4.9+\n",
		     major, minor);

		return (-1);
	}

	if (check_kallsyms_addr_is_zero()) {
		ebpf_warning(LOG_CP_TAG
			     "All kernel addresses in /proc/kallsyms are 0. Please add"
			     " 'CAP_SYSLOG' permission to the container to solve the "
			     "problem.\n");
		return (-1);
	}

	atomic64_init(&process_lost_count);

	profiler_stop = 0;
	start_time = gettime(CLOCK_MONOTONIC, TIME_TYPE_SEC);

	// CPUID will not be included in the aggregation of stack trace data.
	set_profiler_cpu_aggregation(0);

	// Java agent so library generation.
	if (access(AGENT_LIB_SRC_PATH, F_OK) == 0) {
		if (unlink(AGENT_LIB_SRC_PATH) != 0) {
			ebpf_warning(LOG_CP_TAG "rm file %s failed.\n",
				     AGENT_LIB_SRC_PATH);
			return (-1);
		}
	}

	if (access(AGENT_MUSL_LIB_SRC_PATH, F_OK) == 0) {
		if (unlink(AGENT_MUSL_LIB_SRC_PATH) != 0) {
			ebpf_warning(LOG_CP_TAG "rm file %s failed.\n",
				     AGENT_MUSL_LIB_SRC_PATH);
			return (-1);
		}
	}

	if (gen_file_from_mem((const char *)java_agent_so_gnu,
			      sizeof(java_agent_so_gnu),
			      (const char *)AGENT_LIB_SRC_PATH)) {
		ebpf_warning(LOG_CP_TAG
			     "Java agent so library(%s) generate failed.\n",
			     AGENT_LIB_SRC_PATH);
		return (-1);
	}

	if (gen_file_from_mem((const char *)java_agent_so_musl,
			      sizeof(java_agent_so_musl),
			      (const char *)AGENT_MUSL_LIB_SRC_PATH)) {
		ebpf_warning(LOG_CP_TAG
			     "Java agent so library(%s) generate failed.\n",
			     AGENT_MUSL_LIB_SRC_PATH);
		return (-1);
	}

	/* For java attach tool */
	if (access(JAVA_ATTACH_TOOL_PATH, F_OK) == 0) {
		if (unlink(JAVA_ATTACH_TOOL_PATH) != 0) {
			ebpf_warning(LOG_CP_TAG "rm file %s failed.\n",
				     JAVA_ATTACH_TOOL_PATH);
			return (-1);
		}
	}

	if (gen_file_from_mem((const char *)deepflow_jattach_bin,
			      sizeof(deepflow_jattach_bin),
			      (const char *)JAVA_ATTACH_TOOL_PATH)) {
		ebpf_warning(LOG_CP_TAG
			     "Java attach tool (%s) generate failed.\n",
			     JAVA_ATTACH_TOOL_PATH);
		return (-1);
	}

	if (chmod(JAVA_ATTACH_TOOL_PATH, 0755) < 0) {
		ebpf_warning(LOG_CP_TAG
			     "file '%s' chmod failed.\n",
			     JAVA_ATTACH_TOOL_PATH);
		return (-1);
	}

	snprintf(bpf_load_buffer_name, NAME_LEN, "continuous_profiler");
	bpf_bin_buffer = (void *)perf_profiler_common_ebpf_data;
	buffer_sz = sizeof(perf_profiler_common_ebpf_data);

	struct bpf_tracer *tracer =
	    setup_bpf_tracer(CP_TRACER_NAME, bpf_load_buffer_name,
			     bpf_bin_buffer, buffer_sz, NULL, 0,
			     relase_profiler, create_profiler,
			     (void *)callback, freq);
	if (tracer == NULL)
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
		  push_count);

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
	if (*pattern == '\0') {
		regex_existed = false;
		ebpf_warning(LOG_CP_TAG
			     "Set 'profiler_regex' pattern : '', an empty"
			     " regular expression will not generate any stack data."
			     "Please configure the regular expression for profiler.\n");
		tracer_reader_unlock(profiler_tracer);
		return (0);
	}

	if (regex_existed) {
		regfree(&profiler_regex);
	}

	int ret = regcomp(&profiler_regex, pattern, REG_EXTENDED);
	if (ret != 0) {
		char error_buffer[100];
		regerror(ret, &profiler_regex, error_buffer,
			 sizeof(error_buffer));
		ebpf_warning(LOG_CP_TAG
			     "Pattern %s failed to compile the regular "
			     "expression: %s\n", pattern, error_buffer);
		regex_existed = false;
		tracer_reader_unlock(profiler_tracer);
		return (-1);
	}

	regex_existed = true;
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

#else /* defined AARCH64_MUSL */
#include "../tracer.h"
#include "perf_profiler.h"

/*
 * start continuous profiler
 * @freq sample frequency, Hertz. (e.g. 99 profile stack traces at 99 Hertz)
 * @callback Profile data processing callback interface
 * @returns 0 on success, < 0 on error
 */
int start_continuous_profiler(int freq, tracer_callback_t callback)
{
	return (-1);
}

int stop_continuous_profiler(void)
{
	return (0);
}

void process_stack_trace_data_for_flame_graph(stack_trace_msg_t *val)
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
#endif /* AARCH64_MUSL */
