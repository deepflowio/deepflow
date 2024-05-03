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
 * View kernel addresses exposed via /proc and other interfaces
 * when /proc/sys/kernel/kptr_restrict has the value 1, it is
 * necessary to set the CAP_SYSLOG capability, otherwise all k-
 * ernel addresses are set to 0.
 *
 * This function is used to check if the kernel address is 0.
 */

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

extern struct bpf_tracer *profiler_tracer;

extern int major, minor;

static bool java_installed;

int profiler_context_init(struct profiler_context *ctx,
			  const char *state_map_name,
			  const char *stack_map_name_a,
			  const char *stack_map_name_b)
{
	memset(ctx, 0, sizeof(struct profiler_context));
	atomic64_init(&ctx->process_lost_count);
	ctx->profiler_stop = 0;
	snprintf(ctx->state_map_name, sizeof(ctx->state_map_name), "%s",
		 state_map_name);
	snprintf(ctx->stack_map_name_a, sizeof(ctx->stack_map_name_a), "%s",
		 stack_map_name_a);
	snprintf(ctx->stack_map_name_b, sizeof(ctx->stack_map_name_b), "%s",
		 stack_map_name_b);
	ctx->regex_existed = false;

	return 0;
}

void set_enable_profiler(struct bpf_tracer *t, struct profiler_context *ctx,
			 u64 enable_flag)
{
	if (bpf_table_set_value(t, ctx->state_map_name,
				ENABLE_IDX, &enable_flag) == false) {
		ebpf_warning("profiler state map update error."
			     "(%s enable_flag %lu) - %s\n",
			     ctx->state_map_name, enable_flag, strerror(errno));
	}

	ctx->enable_bpf_profile = enable_flag;

	ebpf_info("%s() success, enable_flag:%d\n", __func__, enable_flag);
}

int do_profiler_regex_config(const char *pattern, struct profiler_context *ctx)
{
	if (*pattern == '\0') {
		ctx->regex_existed = false;
		ebpf_warning("Set 'profiler_regex' pattern : '', an empty"
			     " regular expression will not generate any stack data."
			     "Please configure the regular expression for profiler.\n");
		return (0);
	}

	if (ctx->regex_existed) {
		regfree(&ctx->profiler_regex);
	}

	int ret = regcomp(&ctx->profiler_regex, pattern, REG_EXTENDED);
	if (ret != 0) {
		char error_buffer[100];
		regerror(ret, &ctx->profiler_regex, error_buffer,
			 sizeof(error_buffer));
		ebpf_warning("Pattern %s failed to compile the regular "
			     "expression: %s\n", pattern, error_buffer);
		ctx->regex_existed = false;
		return (-1);
	}

	ctx->regex_existed = true;
	return 0;
}

static bool check_kallsyms_addr_is_zero(void)
{
	const int check_num = 100;
	const int max_line_len = 256;
	const char *check_str = "0000000000000000";

	FILE *file = fopen("/proc/kallsyms", "r");
	if (file == NULL) {
		ebpf_warning("Error opening /proc/kallsyms");
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

bool run_conditions_check(void)
{
	// REQUIRES: Linux 4.9+ (BPF_PROG_TYPE_PERF_EVENT support).
	if (check_kernel_version(4, 9) != 0) {
		ebpf_warning
		    ("Currnet linux %d.%d, not support, require Linux 4.9+\n",
		     major, minor);

		return false;
	}

	if (check_kallsyms_addr_is_zero()) {
		ebpf_warning
		    ("All kernel addresses in /proc/kallsyms are 0, Please"
		     " follow the steps below to resolve:\n"
		     "1 Make sure the content of the '/proc/sys/kernel/kpt"
		     "r_restrict' file is not 2, if it is 2 please set it "
		     "to 1.\n2 Add 'CAP_SYSLOG' permission to the containe"
		     "r.\n3 Restart the pod.");
		return false;
	}

	return true;
}

int java_libs_and_tools_install(void)
{
	if (java_installed)
		return (0);

	// Java agent so library generation.
	if (access(AGENT_LIB_SRC_PATH, F_OK) == 0) {
		if (unlink(AGENT_LIB_SRC_PATH) != 0) {
			ebpf_warning("rm file %s failed.\n",
				     AGENT_LIB_SRC_PATH);
			return (-1);
		}
	}

	if (access(AGENT_MUSL_LIB_SRC_PATH, F_OK) == 0) {
		if (unlink(AGENT_MUSL_LIB_SRC_PATH) != 0) {
			ebpf_warning("rm file %s failed.\n",
				     AGENT_MUSL_LIB_SRC_PATH);
			return (-1);
		}
	}

	if (gen_file_from_mem((const char *)java_agent_so_gnu,
			      sizeof(java_agent_so_gnu),
			      (const char *)AGENT_LIB_SRC_PATH)) {
		ebpf_warning("Java agent so library(%s) generate failed.\n",
			     AGENT_LIB_SRC_PATH);
		return (-1);
	}

	if (gen_file_from_mem((const char *)java_agent_so_musl,
			      sizeof(java_agent_so_musl),
			      (const char *)AGENT_MUSL_LIB_SRC_PATH)) {
		ebpf_warning("Java agent so library(%s) generate failed.\n",
			     AGENT_MUSL_LIB_SRC_PATH);
		return (-1);
	}

	/* For java attach tool */
	if (access(JAVA_ATTACH_TOOL_PATH, F_OK) == 0) {
		if (unlink(JAVA_ATTACH_TOOL_PATH) != 0) {
			ebpf_warning("rm file %s failed.\n",
				     JAVA_ATTACH_TOOL_PATH);
			return (-1);
		}
	}

	if (gen_file_from_mem((const char *)deepflow_jattach_bin,
			      sizeof(deepflow_jattach_bin),
			      (const char *)JAVA_ATTACH_TOOL_PATH)) {
		ebpf_warning("Java attach tool (%s) generate failed.\n",
			     JAVA_ATTACH_TOOL_PATH);
		return (-1);
	}

	if (chmod(JAVA_ATTACH_TOOL_PATH, 0755) < 0) {
		ebpf_warning("file '%s' chmod failed.\n",
			     JAVA_ATTACH_TOOL_PATH);
		return (-1);
	}

	java_installed = true;

	return (0);
}

static u32 delete_all_stackmap_elems(struct bpf_tracer *tracer,
				     const char *stack_map_name)
{
	struct ebpf_map *map =
	    ebpf_obj__get_map_by_name(tracer->obj, stack_map_name);
	if (map == NULL) {
		ebpf_warning("[%s] map(name:%s) is NULL.\n", __func__,
			     stack_map_name);
		return 0;
	}
	int map_fd = map->fd;

	u32 key = 0, next_key;
	u32 reclaim_count = 0;
	u32 find_count = 0;
	struct list_head clear_elem_head;
	init_list_head(&clear_elem_head);

	while (bpf_get_next_key(map_fd, &key, &next_key) == 0) {
		find_count++;
		insert_list(&next_key, sizeof(next_key), &clear_elem_head);
		key = next_key;
	}

	reclaim_count = __reclaim_map(map_fd, &clear_elem_head);

	ebpf_info("[%s] table %s find_count %u reclaim_count :%u\n",
		  __func__, stack_map_name, find_count, reclaim_count);

	return reclaim_count;
}

static void cleanup_stackmap(struct profiler_context *ctx, struct bpf_tracer *t,
			     const char *stack_map_name, bool is_a)
{
	struct stack_ids_bitmap *ids;
	int *clear_stack_ids;
	u64 *perf_buf_lost_p = NULL;

	if (is_a) {
		ids = &ctx->stack_ids_a;
		clear_stack_ids = ctx->clear_stack_ids_a;
		perf_buf_lost_p = &ctx->perf_buf_lost_a_count;
	} else {
		ids = &ctx->stack_ids_b;
		clear_stack_ids = ctx->clear_stack_ids_b;
		perf_buf_lost_p = &ctx->perf_buf_lost_b_count;
	}

	if (ids->count != vec_len(clear_stack_ids)) {
		ebpf_warning
		    ("stack_ids.count(%lu) != vec_len(clear_stack_ids)(%d)",
		     ids->count, vec_len(clear_stack_ids));
	}

	/*
	 * The perf profiler utilizes a perf buffer (per CPUs) for transporting stack data,
	 * which may lead to out-of-order behavior in a multi-core environment.
	 * We have employed a threshold to delay the cleanup of the stack map, reducing the
	 * occurrence of premature clearing of stack entries caused by the disorder in stack
	 * data.
	 *
	 * Examine the detailed explanation of 'STACKMAP_CLEANUP_THRESHOLD' in
	 * 'agent/src/ebpf/user/config.h'.
	 */
	if (ids->count >= STACKMAP_CLEANUP_THRESHOLD) {
		int *sid;
		vec_foreach(sid, clear_stack_ids) {
			int id = *sid;
			if (!bpf_table_delete_key(t, stack_map_name, (u64) id)) {
				/*
				 * It may be due to the disorder in the perf buffer transmission,
				 * leading to the repetitive deletion of the same stack ID.
				 */
				ctx->stackmap_clear_failed_count++;
			}

			clear_bitmap(ids->bitmap, id);
		}

		if (is_a)
			vec_free(ctx->clear_stack_ids_a);
		else
			vec_free(ctx->clear_stack_ids_b);

		ids->count = 0;

		/*
		 * If data loss occurs due to the user-space receiver program
		 * being too busy and not promptly fetching data from the perf
		 * buffer, it is necessary to clean the stack map once to prevent
		 * excessive remnants of stack data from affecting the acquisition
		 * of new stack data (i.e., eBPF using the bpf_get_stackid()
		 * interface will return -EEXIST).
		 */
		if (*perf_buf_lost_p > 0) {
			delete_all_stackmap_elems(t, stack_map_name);
			*perf_buf_lost_p = 0;
		}
	}
}

static void print_profiler_status(struct profiler_context *ctx,
				  struct bpf_tracer *t, u64 iter_count)
{
	u64 alloc_b, free_b;
	get_mem_stat(&alloc_b, &free_b);
	ebpf_debug("\n\n----------------------------\nrecv envent:\t%lu\n"
		   "kern_lost:\t%lu, perf_buf_lost_a:\t%lu, perf_buf_lost_b:\t%lu\n"
		   "stack_trace_err:\t%lu\n"
		   "stackmap_clear_failed_count\t%lu\n"
		   "ransfer_count:\t%lu iter_count:\t%lu\nall"
		   "oc_b:\t%lu bytes free_b:\t%lu bytes use:\t%lu bytes\n"
		   "stack_str_hash.hit_count %lu\nstack_trace_msg_hash hit %lu\n",
		   atomic64_read(&t->recv), atomic64_read(&t->lost),
		   ctx->perf_buf_lost_a_count, ctx->perf_buf_lost_b_count,
		   ctx->stack_trace_err, ctx->stackmap_clear_failed_count,
		   ctx->transfer_count, iter_count,
		   alloc_b, free_b, alloc_b - free_b,
		   ctx->stack_str_hash.hit_hash_count,
		   ctx->msg_hash.hit_hash_count);
}

static int push_and_free_msg_kvp_cb(stack_trace_msg_hash_kv * kv, void *arg)
{
	struct profiler_context *ctx = arg;
	stack_trace_msg_kv_t *msg_kv = (stack_trace_msg_kv_t *) kv;
	if (msg_kv->msg_ptr != 0) {
		stack_trace_msg_t *msg = (stack_trace_msg_t *) msg_kv->msg_ptr;

		/* continuous profiler debug */
		cpdbg_process(msg);

		tracer_callback_t fun = profiler_tracer->process_fn;
		/*
		 * Execute callback function to hand over the data to the
		 * higher level for processing. The higher level will se-
		 * nd the data to the server for storage as required.
		 */
		if (likely(ctx->profiler_stop == 0))
			fun(msg);

		clib_mem_free((void *)msg);
		msg_kv->msg_ptr = 0;
	}

	int ret = VEC_OK;
	vec_add1(ctx->trace_msg_kvps, *kv, ret);
	if (ret != VEC_OK) {
		ebpf_warning("vec add failed\n");
		ctx->msg_clear_hash = true;
	}

	return BIHASH_WALK_CONTINUE;
}

/*
 * Push the data and release the resources.
 * @is_force: Do you need to perform a forced release?
 */
void push_and_release_stack_trace_msg(struct profiler_context *ctx,
				      stack_trace_msg_hash_t * h, bool is_force)
{
	ASSERT(profiler_tracer != NULL);

	u64 curr_time, elapsed;
	curr_time = gettime(CLOCK_MONOTONIC, TIME_TYPE_NAN);
	elapsed = curr_time - ctx->last_push_time;

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
	ctx->last_push_time = curr_time;
	ctx->push_count++;

	stack_trace_msg_hash_foreach_key_value_pair(h, push_and_free_msg_kvp_cb,
						    (void *)ctx);
	/*
	 * In this iteration, all elements will be cleared, and in the
	 * next iteration, this hash will be reused.
	 */
	stack_trace_msg_hash_kv *v;
	vec_foreach(v, ctx->trace_msg_kvps) {
		if (stack_trace_msg_hash_add_del(h, v, 0 /* delete */ )) {
			ebpf_warning
			    ("stack_trace_msg_hash_add_del() failed.\n");
			ctx->msg_clear_hash = true;
		}
	}

	vec_free(ctx->trace_msg_kvps);

	h->hit_hash_count = 0;
	h->hash_elems_count = 0;

	if (ctx->msg_clear_hash) {
		ctx->msg_clear_hash = false;
		stack_trace_msg_hash_free(h);
	}
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

void process_bpf_stacktraces(struct profiler_context *ctx, struct bpf_tracer *t)
{
	struct bpf_perf_reader *r;
	const char *stack_map_name;
	bool using_map_set_a = (ctx->transfer_count % 2 == 0);
	r = using_map_set_a ? ctx->r_a : ctx->r_b;
	stack_map_name =
	    using_map_set_a ? ctx->stack_map_name_a : ctx->stack_map_name_b;
	const u64 sample_count_idx =
	    using_map_set_a ? SAMPLE_CNT_A_IDX : SAMPLE_CNT_B_IDX;

	struct epoll_event events[r->readers_count];
	int nfds = reader_epoll_wait(r, events, 0);

	ctx->transfer_count++;
	if (bpf_table_set_value(t, ctx->state_map_name,
				TRANSFER_CNT_IDX,
				&ctx->transfer_count) == false) {
		ebpf_warning("profiler state map update error."
			     "(%s transfer_count %lu) - %s\n",
			     ctx->state_map_name, ctx->transfer_count,
			     strerror(errno));
		ctx->transfer_count--;
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
	if (unlikely(ctx->stack_str_hash.buckets == NULL)) {
		if (init_stack_str_hash
		    (&ctx->stack_str_hash, "profile_stack_str")) {
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
	if (unlikely(ctx->msg_hash.buckets == NULL)) {
		if (init_stack_trace_msg_hash
		    (&ctx->msg_hash, "stack_trace_msg")) {
			ebpf_warning("init_stack_trace_msg_hash() failed.\n");
			return;
		}
	}

	if (nfds > 0) {

	      check_again:
		if (unlikely(ctx->profiler_stop == 1))
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
		aggregate_stack_traces(ctx, t, stack_map_name,
				       &ctx->stack_str_hash, &ctx->msg_hash,
				       &count, using_map_set_a);

		/*
		 * To ensure that all data in the perf ring-buffer is procenssed
		 * in this iteration, as this iteration will clean up all the
		 * data recorded in the stackmap, any residual data in the perf
		 * ring-buffer will be carried over to the next iteration for
		 * processing. This poses a risk of not being able to find the
		 * corresponding stackmap records in the next iteration, leading
		 * to incomplete processing.
		 */
		if (bpf_table_get_value(t, ctx->state_map_name,
					sample_count_idx,
					(void *)&sample_cnt_val)) {
			if (sample_cnt_val > count) {
				nfds = reader_epoll_short_wait(r, events, 0);
				if (nfds > 0)
					goto check_again;
			}
		}
	}

release_iter:

	cleanup_stackmap(ctx, t, stack_map_name, using_map_set_a);

	/* Now that we've consumed the data, reset the sample count in BPF. */
	sample_cnt_val = 0;
	bpf_table_set_value(t, ctx->state_map_name,
			    sample_count_idx, &sample_cnt_val);

	print_profiler_status(ctx, t, count);

	/* free all elems */
	clean_stack_strs(&ctx->stack_str_hash);

	/* Push messages and free stack_trace_msg_hash */
	push_and_release_stack_trace_msg(ctx, &ctx->msg_hash, false);
}
