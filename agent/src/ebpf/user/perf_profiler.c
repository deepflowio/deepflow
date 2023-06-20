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

/*
 * TODO (@jiping)
 * There are some issues with aarch64 musl compilation, and the profiler
 * cannot be applied temporarily in scenarios where aarch64 is compiled
 * using musl.
 */
#ifndef AARCH64_MUSL
#include <bcc/perf_reader.h>
#include "config.h"
#include "common.h"
#include "mem.h"
#include "log.h"
#include "types.h"
#include "vec.h"
#include "tracer.h"
#include "perf_profiler.h"
#include "elf.h"
#include "load.h"
#include "../kernel/include/perf_profiler.h"
#include "perf_reader.h"
#include "bihash_8_8.h"
#include "stringifier.h"
#include "table.h"

#include "perf_profiler_bpf_common.c"

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
static stack_trace_msg_hash_t test_fg_hash;
static FILE *folded_file;
#define FOLDED_FILE_PATH "./profiler.folded" 

/* "Maximum data push interval time (in seconds). */
#define MAX_PUSH_MSG_TIME_INTERVAL 10
/* "Maximum data push messages count. */
#define MAX_PUSH_MSG_COUNT 1000
/* profiler start time(monotonic seconds). */
static u64 start_time;
/* Record the time of the last data push
 * (in seconds since system startup)*/
static u64 last_push_time;
static u64 push_count;

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
				  stack_str_hash_t *h,
				  stack_trace_msg_hash_t *msg_h);
static void print_cp_status(struct bpf_tracer *t);

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

	print_cp_status(tracer);

	/* release object */
	release_object(tracer->obj);

	tracer_reader_unlock(tracer);

	return ETR_OK;
}

static void set_msg_kvp(stack_trace_msg_kv_t * kvp,
			struct stack_trace_key_t *v,
			u64 stime,
			void *msg_value)
{
	kvp->k.pid = (u64) v->pid;
	kvp->k.stime = stime;
	kvp->k.u_stack_id = (u32) v->userstack;
	kvp->k.k_stack_id = (u32) v->kernstack;
	kvp->msg_ptr = pointer_to_uword(msg_value);
}

static int init_stack_trace_msg_hash(stack_trace_msg_hash_t *h,
				     const char *name)
{
	memset(h, 0, sizeof(*h));
	u32 nbuckets = STACK_TRACE_MSG_HASH_BUCKETS_NUM;
	u64 hash_memory_size = STACK_TRACE_MSG_HASH_MEM_SZ;
	return stack_trace_msg_hash_init(h, (char *)name,
					 nbuckets, hash_memory_size);
}

static int push_and_free_msg_kvp_cb(stack_trace_msg_hash_kv *kv, void *ctx)
{
	stack_trace_msg_kv_t *msg_kv = (stack_trace_msg_kv_t *)kv;
	if (msg_kv->msg_ptr != 0) {
		stack_trace_msg_t *msg = (stack_trace_msg_t *)msg_kv->msg_ptr;
#ifdef CP_DEBUG
		ebpf_debug("tiemstamp %lu pid %u stime %lu u_stack_id %lu k_statck_id"
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
static void push_and_release_stack_trace_msg(stack_trace_msg_hash_t *h,
					     bool is_force)
{
	ASSERT(profiler_tracer != NULL);

	u64 curr_time, elapsed;
	curr_time = gettime(CLOCK_MONOTONIC, TIME_TYPE_SEC);
	elapsed = curr_time - last_push_time;
	/*
	 * If the aggregated stack trace data obtained by the profiler
	 * satisfies one of the following conditions, it should be pushed
	 * to the upper-level processing:
	 *
	 * 1 If the aggregated count exceeds or equals the maximum push
	 *   count (MAX_PUSH_MSG_COUNT).
	 *
	 * 2 If the time interval since the last push exceeds or equals
	 *   the maximum time interval (MAX_PUSH_MSG_TIME_INTERVAL).
	 *
	 * Otherwise, it should return directly.
	 */
	if (!((h->hash_elems_count >= MAX_PUSH_MSG_COUNT) ||
	      (elapsed >= MAX_PUSH_MSG_TIME_INTERVAL) || is_force))
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
			ebpf_warning("stack_trace_msg_hash_add_del() failed.\n");
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
				   stack_str_hash_t *stack_str_hash,
				   stack_trace_msg_hash_t *msg_hash,
				   u32 *count)
{
	struct stack_trace_key_t *v;
	vec_foreach(v, raw_stack_data) {
		if (v == NULL)
			break;

		if (unlikely(profiler_stop == 1))
			break;

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
		stack_trace_msg_kv_t kv; // stack_trace_msg_hash_kv
		u64 stime = get_pid_stime(v->pid);
		if (stime == 0) {
			stime = v->timestamp / NS_IN_MSEC;
		}
		set_msg_kvp(&kv, v, stime, (void *)0);
		if (stack_trace_msg_hash_search(msg_hash, (stack_trace_msg_hash_kv *)&kv,
						(stack_trace_msg_hash_kv *)&kv) == 0) {
			__sync_fetch_and_add(&msg_hash->hit_hash_count, 1);
			((stack_trace_msg_t *)kv.msg_ptr)->count++;

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

		stack_trace_msg_t *msg =
			resolve_and_gen_stack_trace_msg(t, v, stack_map_name,
							stack_str_hash);
		if (msg) {
			stack_trace_msg_kv_t msg_kvp;
			set_msg_kvp(&msg_kvp, v, msg->stime, (void *)msg);
			if (msg->stime == 0) {
				ebpf_warning("tiemstamp %lu pid %u stime %lu u_stack_id %lu k_statck_id"
					     " %lu cpu %u count %u comm %s datalen %u data %s\n",
					     msg->time_stamp, msg->pid, msg->stime, msg->u_stack_id,
					     msg->k_stack_id, msg->cpu, msg->count, msg->comm,
					     msg->data_len, msg->data);
				clib_mem_free(msg);
				continue;
			}

			if (stack_trace_msg_hash_add_del(msg_hash,
							 (stack_trace_msg_hash_kv *)&msg_kvp,
							 1 /* is_add */ )) {
				ebpf_warning("stack_trace_msg_hash_add_del() failed.\n");
				clib_mem_free(msg);
			} else {
				__sync_fetch_and_add(&msg_hash->hash_elems_count, 1);
			}
		}
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

	struct pollfd pfds[r->readers_count];
	bool has_event = reader_poll_wait(r, pfds);

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
	 *   combination of "pid + pid_start_time + k_stack_id + u_stack_id" as
	 *   the key.
	 *
	 * Here is the key-value pair structure of the hashmap:
	 * ```
	 * typedef struct {
	 *         struct {
	 *         u64 pid;
	 *         u64 stime;
	 *         u32 u_stack_id;
	 *         u32 k_stack_id;
	 *         } k;
	 *         u64 msg_ptr; Store perf profiler data
	 * } stack_trace_msg_kv_t;
	 * ```
	 *
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

	if (has_event) {

check_again:
		if (unlikely(profiler_stop == 1))
			goto release_iter;

		/* 
		 * If there is data, the reader's callback
		 * function will be called.
		 */
		reader_event_read(r, pfds);

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
					sample_count_idx, (void *)&sample_cnt_val)) {
			if (sample_cnt_val > count) {
				has_event = reader_poll_short_wait(r, pfds);
				if (has_event)
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
	release_stack_strs(&g_stack_str_hash);

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

		tracer_reader_lock(t);
		process_bpf_stacktraces(t, reader_a, reader_b);
		tracer_reader_unlock(t);
	}

exit:
        print_cp_status(t);

	print_hash_stack_str(&g_stack_str_hash);
	/* free stack_str_hash */
	if (likely(g_stack_str_hash.buckets != NULL)) {
		stack_str_hash_free(&g_stack_str_hash);
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
					     PROFILER_READER_POLL_TIMEOUT);
	if (reader_a == NULL)
		return ETR_NORESOURCE;

	reader_b = create_perf_buffer_reader(tracer,
					     MAP_PERF_PROFILER_BUF_B_NAME,
					     reader_raw_cb,
					     reader_lost_cb,
					     PROFILE_PG_CNT_DEF,
					     PROFILER_READER_POLL_TIMEOUT);
	if (reader_b == NULL) {
		free_perf_buffer_reader(reader_a);
		return ETR_NORESOURCE;
	}

	/* attach perf event */
	tracer_hooks_attach(tracer);

	/* syms_cache_hash maps from pid to BCC symbol cache.
	 * Use of void* is inherited from the BCC library. */
	create_and_init_symbolizer_caches();

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
	release_bpf_tracer(CP_TRACER_NAME);
	profiler_tracer = NULL;

	u64 alloc_b, free_b;
	get_mem_stat(&alloc_b, &free_b);
#ifdef DF_MEM_DEBUG
	show_mem_list();
#endif
	ebpf_info("== alloc_b %lu bytes, free_b %lu bytes, use %lu "
		  "bytes ==\n", alloc_b, free_b, alloc_b - free_b);
	return (0);
}

static void print_cp_status(struct bpf_tracer *t)
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
		  "process-cnt:\t%lu\nkern_lost:\t%lu\n"
		  "stack_trace_lost:\t%lu\ntransfer_count:\t%lu "
		  "iter_count_avg:\t%.2lf\nalloc_b:\t%lu bytes "
		  "free_b:\t%lu bytes use:\t%lu bytes\n"
		  "eBPF map status:\n"
		  " - output_cnt:\t%lu\n"
		  " - sample_drop_cnt:\t%lu\n"
		  " - output_err_cnt:\t%lu\n"
		  " - iter_max_cnt:\t%lu\n"
		  "----------------------------\n\n",
		  atomic64_read(&t->recv), process_count, atomic64_read(&t->lost),
		  stack_trace_lost, transfer_count,
		  ((double)atomic64_read(&t->recv) / (double)transfer_count),
		  alloc_b, free_b, alloc_b - free_b, output_count, sample_drop_cnt,
		  output_err_cnt, iter_max_cnt);
}

static void print_profiler_status(struct bpf_tracer *t, u64 iter_count,
				  stack_str_hash_t *h,
				  stack_trace_msg_hash_t *msg_h)
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
 * start continuous profiler
 * @freq sample frequency, Hertz. (e.g. 99 profile stack traces at 99 Hertz)
 * @callback Profile data processing callback interface
 * @returns 0 on success, < 0 on error
 */
int start_continuous_profiler(int freq,
			      tracer_callback_t callback)
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

	profiler_stop = 0;
	start_time = gettime(CLOCK_MONOTONIC, TIME_TYPE_SEC);

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
void process_stack_trace_data_for_flame_graph(stack_trace_msg_t *val)
{
	stack_count++;
	if (unlikely(test_fg_hash.buckets == NULL)) {
		init_stack_trace_msg_hash(&test_fg_hash,
					  "flame_graph_test");
		unlink(FOLDED_FILE_PATH);
		folded_file = fopen(FOLDED_FILE_PATH, "a+");
		if (folded_file == NULL)
			return;
	}

	stack_trace_msg_kv_t msg_kvp;
	msg_kvp.k.pid = (u64) val->pid;
        msg_kvp.k.stime = val->stime;
	msg_kvp.k.u_stack_id = val->u_stack_id;
	msg_kvp.k.k_stack_id = val->k_stack_id;

	if (stack_trace_msg_hash_search(&test_fg_hash, (stack_trace_msg_hash_kv *)&msg_kvp,
					(stack_trace_msg_hash_kv *)&msg_kvp) == 0) {
		((stack_trace_msg_t *)msg_kvp.msg_ptr)->count += val->count;
		test_hit_count += val->count;
		__sync_fetch_and_add(&test_fg_hash.hit_hash_count, 1);
		return;
	} else {
		int len = sizeof(*val) + val->data_len + 1;
		char *p = clib_mem_alloc_aligned("flame_msg", len, 0, NULL);
		if (p == NULL) return;
		msg_kvp.msg_ptr = pointer_to_uword(p);
		memcpy(p, val, sizeof(*val) + val->data_len);
		p[sizeof(*val) + val->data_len] = '\0';
		if (stack_trace_msg_hash_add_del(&test_fg_hash,
				 (stack_trace_msg_hash_kv *)&msg_kvp,
				 1 /* is_add */ )) {
			clib_mem_free(p);
			ebpf_warning("stack_trace_msg_hash_add_del() failed.\n");
		} else {
			test_add_count += val->count;
			__sync_fetch_and_add(&test_fg_hash.hash_elems_count, 1);
		}
	}
}

static int gen_stack_trace_folded_file(stack_trace_msg_hash_kv *kv, void *ctx)
{
	stack_trace_msg_kv_t *msg_kv = (stack_trace_msg_kv_t *)kv;
	if (msg_kv->msg_ptr != 0) {
		stack_trace_msg_t *msg = (stack_trace_msg_t *)msg_kv->msg_ptr;
		int len = msg->data_len + sizeof(msg->comm) + 18;
		char str[len];
		snprintf(str, len, "%s;%s %u\n", msg->comm, msg->data, msg->count);
		os_puts(folded_file, str, strlen(str), false);
#ifdef CP_DEBUG
		ebpf_debug("tiemstamp %lu pid %u stime %lu u_stack_id %lu k_statck_id"
			   "%lu cpu %u count %u comm %s datalen %u data %s\n",
			   msg->time_stamp, msg->pid, msg->stime, msg->u_stack_id,
			   msg->k_stack_id, msg->cpu, msg->count, msg->comm,
			   msg->data_len, msg->data);
#endif
		clib_mem_free((void *)msg);
		(*(u64 *) ctx)++;
	} else {
		msg_ptr_zero_count++;
	}

	return BIHASH_WALK_CONTINUE;
}

void release_flame_graph_hash(void)
{
	u64 elems_count = 0;
	u64 alloc_b, free_b;
	get_mem_stat(&alloc_b, &free_b);
	ebpf_info("pre alloc_b:\t%lu bytes free_b:\t%lu bytes use:\t%lu bytes\n",
		  alloc_b, free_b, alloc_b - free_b);

	stack_trace_msg_hash_foreach_key_value_pair(&test_fg_hash,
						    gen_stack_trace_folded_file,
						    (void *)&elems_count);

	ebpf_info("elems_count %lu hash_elems_count %lu "
		  "hit_hash_count %lu\n", elems_count,
		  test_fg_hash.hash_elems_count, test_fg_hash.hit_hash_count);

	ebpf_info("flame graph folded strings count %lu\n", elems_count);
	fclose(folded_file);

	stack_trace_msg_hash_free(&test_fg_hash);

	get_mem_stat(&alloc_b, &free_b);
	ebpf_info("after alloc_b:\t%lu bytes free_b:\t%lu bytes use:\t%lu bytes\n",
		  alloc_b, free_b, alloc_b - free_b);

	ebpf_info("<<< stack_count %lu add_count %lu hit_count %lu msg_ptr_zero"
		  "_count %lu push_count %lu >>>\n", stack_count, test_add_count, test_hit_count,
		  msg_ptr_zero_count, push_count);

	ebpf_info("Please use the following command to generate a flame graph:"
		  "\n\n\033[33;1mcat ./profiler.folded |./.flamegraph.pl --color=io"
		  " --countname=samples > profiler-test.svg\033[0m\n");
}
#else /* defined AARCH64_MUSL */
#include "tracer.h"
#include "perf_profiler.h"

/*
 * start continuous profiler
 * @freq sample frequency, Hertz. (e.g. 99 profile stack traces at 99 Hertz)
 * @callback Profile data processing callback interface
 * @returns 0 on success, < 0 on error
 */
int start_continuous_profiler(int freq,
			      tracer_callback_t callback)
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
#endif /* AARCH64_MUSL */
