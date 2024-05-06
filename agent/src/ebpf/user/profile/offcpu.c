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

#define LOG_TAG      "[OFFCPU] "

static struct profiler_context offcpu_ctx;
extern struct bpf_tracer *profiler_tracer;
extern __thread uword thread_index;

static void offcpu_reader_work(void *arg)
{
	thread_index = READER_OFFCPU_THREAD_IDX;
	struct bpf_tracer *t = profiler_tracer;
	for (;;) {
		if (unlikely(offcpu_ctx.profiler_stop == 1)) {
			if (offcpu_ctx.enable_bpf_profile)
				set_enable_profiler(t, &offcpu_ctx, 0);

			goto exit;
		}

		if (unlikely(!offcpu_ctx.regex_existed ||
			     get_socket_tracer_state() != TRACER_RUNNING)) {
			if (offcpu_ctx.enable_bpf_profile)
				set_enable_profiler(t, &offcpu_ctx, 0);
			exec_proc_info_cache_update();
			sleep(1);
			continue;
		}

		if (unlikely(!offcpu_ctx.enable_bpf_profile))
			set_enable_profiler(t, &offcpu_ctx, 1);

		process_bpf_stacktraces(&offcpu_ctx, t);
	}

exit:
	//print_cp_tracer_status(t, &offcpu_ctx);

	print_hash_stack_str(&offcpu_ctx.stack_str_hash);
	/* free stack_str_hash */
	if (likely(offcpu_ctx.stack_str_hash.buckets != NULL)) {
		release_stack_str_hash(&offcpu_ctx.stack_str_hash);
	}

	print_hash_stack_trace_msg(&offcpu_ctx.msg_hash);
	/* free stack_str_hash */
	if (likely(offcpu_ctx.msg_hash.buckets != NULL)) {
		/* Ensure that all elements are released properly/cleanly */
		push_and_release_stack_trace_msg(&offcpu_ctx,
						 &offcpu_ctx.msg_hash, true);
		stack_trace_msg_hash_free(&offcpu_ctx.msg_hash);
	}

	/* clear thread */
	t->perf_workers[READER_OFFCPU_THREAD_IDX] = 0;
	ebpf_info(LOG_TAG "perf profiler reader-thread exit.\n");

	pthread_exit(NULL);

}

static void offcpu_reader_lost_cb_a(void *cookie, u64 lost)
{
	struct bpf_tracer *tracer = profiler_tracer;
	atomic64_add(&tracer->lost, lost);
	offcpu_ctx.perf_buf_lost_a_count++;
}

static void offcpu_reader_lost_cb_b(void *cookie, u64 lost)
{
	struct bpf_tracer *tracer = profiler_tracer;
	atomic64_add(&tracer->lost, lost);
	offcpu_ctx.perf_buf_lost_b_count++;
}

static void offcpu_reader_raw_cb(void *cookie, void *raw, int raw_size)
{
	if (unlikely(offcpu_ctx.profiler_stop == 1))
		return;

	struct reader_forward_info *fwd_info = cookie;
	if (unlikely(fwd_info->queue_id != 0)) {
		ebpf_warning(LOG_TAG "cookie(%d) error", (u64) cookie);
		return;
	}

	struct stack_trace_key_t *v;
	struct bpf_tracer *tracer = profiler_tracer;
	v = (struct stack_trace_key_t *)raw;

	int ret = VEC_OK;
	vec_add1(offcpu_ctx.raw_stack_data, *v, ret);
	if (ret != VEC_OK) {
		ebpf_warning(LOG_TAG "vec add failed\n");
	}

	atomic64_add(&tracer->recv, 1);
}

int extended_reader_create(struct bpf_tracer *tracer)
{
	profiler_context_init(&offcpu_ctx,
			      MAP_OFFCPU_STATE_MAP,
			      MAP_OFFCPU_STACK_A_NAME, MAP_OFFCPU_STACK_B_NAME,
			      true, true);

	set_enable_profiler(tracer, &offcpu_ctx, 0);

	struct bpf_perf_reader *reader_a, *reader_b;
	reader_a = create_perf_buffer_reader(tracer,
					     MAP_OFFCPU_BUF_A_NAME,
					     offcpu_reader_raw_cb,
					     offcpu_reader_lost_cb_a,
					     PROFILE_PG_CNT_DEF, 1,
					     PROFILER_READER_EPOLL_TIMEOUT);
	if (reader_a == NULL)
		return ETR_NORESOURCE;

	reader_b = create_perf_buffer_reader(tracer,
					     MAP_OFFCPU_BUF_B_NAME,
					     offcpu_reader_raw_cb,
					     offcpu_reader_lost_cb_b,
					     PROFILE_PG_CNT_DEF, 1,
					     PROFILER_READER_EPOLL_TIMEOUT);
	if (reader_b == NULL) {
		free_perf_buffer_reader(reader_a);
		ebpf_warning("create offcpu reader failed.\n");
		return ETR_NORESOURCE;
	}

	offcpu_ctx.r_a = reader_a;
	offcpu_ctx.r_b = reader_b;

	/*
	 * Start a new thread to execute the data
	 * reading of perf buffer.
	 */
	int ret =
	    enable_tracer_reader_work("offcpu_reader", READER_OFFCPU_THREAD_IDX,
				      tracer, (void *)&offcpu_reader_work);

	if (ret) {
		return ret;
	}

	return 0;
}

/*
 * To set the offcpu regex matching for the profiler. 
 *
 * @pattern : Regular expression pattern. e.g. "^(java|nginx|.*ser.*)$"
 * @returns 0 on success, < 0 on error
 */
int set_offcpu_profiler_regex(const char *pattern)
{
	if (profiler_tracer == NULL) {
		ebpf_warning(LOG_TAG
			     "The 'profiler_tracer' has not been created yet."
			     " Please use start_continuous_profiler() to create it first.\n");
		return (-1);
	}

	profile_regex_lock(&offcpu_ctx);
	do_profiler_regex_config(pattern, &offcpu_ctx);
	profile_regex_unlock(&offcpu_ctx);
	ebpf_info(LOG_TAG "Set 'profiler_regex' successful, pattern : '%s'",
		  pattern);
	return (0);
}

#else /* defined AARCH64_MUSL */
int extended_reader_create(struct bpf_tracer *tracer)
{
	return 0;
}

int set_offcpu_profiler_regex(const char *pattern)
{
	return 0;
}
#endif /* AARCH64_MUSL */
