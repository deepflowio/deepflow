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

static struct bpf_tracer *profiler_tracer;

static void offcpu_reader_work(void *arg)
{
	for(;;)
		sleep(10);

#if 0
	thread_index = THREAD_PROFILER_READER_IDX;
	struct bpf_tracer *t = profiler_tracer;
	struct bpf_perf_reader *reader_a, *reader_b;
	reader_a = &t->readers[0];
	reader_b = &t->readers[1];

	for (;;) {
		if (unlikely(profiler_stop == 1)) {
			if (g_enable_perf_sample)
				set_enable_perf_sample(t, 0);

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
		if (unlikely(!regex_existed ||
			     get_socket_tracer_state() != TRACER_RUNNING)) {
			if (g_enable_perf_sample)
				set_enable_perf_sample(t, 0);
			exec_proc_info_cache_update();
			sleep(1);
			continue;
		}

		if (unlikely(!g_enable_perf_sample))
			set_enable_perf_sample(t, 1);

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
#endif
}

static int relase_profiler(struct bpf_tracer *tracer)
{
	tracer_reader_lock(tracer);

	/* detach perf event */
	tracer_hooks_detach(tracer);

	/* free all readers */
	free_all_readers(tracer);

	/* release object */
	release_object(tracer->obj);

	tracer_reader_unlock(tracer);

	return ETR_OK;
}

static int create_profiler(struct bpf_tracer *tracer)
{
	int ret;

	profiler_tracer = tracer;

	/* load ebpf perf profiler */
	if (tracer_bpf_load(tracer))
		return ETR_LOAD;


	struct bpf_perf_reader *reader_a, *reader_b;
	reader_a = create_perf_buffer_reader(tracer,
					     MAP_OFFCPU_PROFILER_BUF_A_NAME,
					     reader_raw_cb,
					     reader_lost_cb_a,
					     PROFILE_PG_CNT_DEF, 1,
					     PROFILER_READER_EPOLL_TIMEOUT);
	if (reader_a == NULL)
		return ETR_NORESOURCE;

	reader_b = create_perf_buffer_reader(tracer,
					     MAP_OFFCPU_PROFILER_BUF_B_NAME,
					     reader_raw_cb,
					     reader_lost_cb_b,
					     PROFILE_PG_CNT_DEF, 1,
					     PROFILER_READER_EPOLL_TIMEOUT);
	if (reader_b == NULL) {
		free_perf_buffer_reader(reader_a);
		return ETR_NORESOURCE;
	}

	/* attach perf event */
	tracer_hooks_attach(tracer);

	if (ret) {
		goto error;
	}

	/*
	 * Start a new thread to execute the data
	 * reading of perf buffer.
	 */
	ret = enable_tracer_reader_work("offcpu_reader", 0, tracer,
					(void *)&offcopu_reader_work);

	if (ret) {
		goto error;
	}

	return ETR_OK;

error:
	relase_profiler(tracer);
	return ETR_INVAL;
}

int start_continuous_profiler(int freq, int java_syms_space_limit,
                              int java_syms_update_delay,
                              tracer_callback_t callback)
{       
        char bpf_load_buffer_name[NAME_LEN];
        void *bpf_bin_buffer;
        uword buffer_sz;
        
        if (!run_conditions_check())
                return (-1);
        
        // Java agent so library generation and tools install.
        if (java_libs_and_tools_install() != 0)
                return (-1);
        
        snprintf(bpf_load_buffer_name, NAME_LEN, "offcpu_profiler");
        bpf_bin_buffer = (void *)offcpu_profiler_common_ebpf_data;
        buffer_sz = sizeof(offcpu_profiler_common_ebpf_data);

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

