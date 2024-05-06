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
extern char *flame_graph_start_time;
extern int major, minor;

static bool java_installed;

int profiler_context_init(struct profiler_context *ctx,
			  const char *state_map_name,
			  const char *stack_map_name_a,
			  const char *stack_map_name_b,
			  bool only_matched, bool use_delta_time)
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
	ctx->only_matched_data = only_matched;
	ctx->use_delta_time = use_delta_time;

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

static void add_stack_id_to_bitmap(struct profiler_context *ctx,
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
	if (ctx->use_delta_time)
		msg->count = v->duration_ns;
	else
		msg->count = 1;
	msg->data_ptr = pointer_to_uword(&msg->data[0]);

	/* Only use for test flame graph. */
	if (flame_graph_start_time == NULL) {
		flame_graph_start_time = gen_file_name_by_datetime();
	}
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

static void aggregate_stack_traces(struct profiler_context *ctx,
				   struct bpf_tracer *t,
				   const char *stack_map_name,
				   stack_str_hash_t * stack_str_hash,
				   stack_trace_msg_hash_t * msg_hash,
				   u32 * count, bool use_a_map)
{
	struct stack_trace_key_t *v;
	vec_foreach(v, ctx->raw_stack_data) {
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
		if (ctx->cpu_aggregation_flag == 0)
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
		ctx->process_count++;

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
		struct symbolizer_proc_info *__info_p = NULL;
		char *process_name = NULL;
		bool matched, is_match_finish;
		matched = is_match_finish = false;

		/* If it is a process, match operation will be performed immediately. */
		if (v->pid == v->tgid) {
			is_match_finish = true;
			profile_regex_lock(ctx);
			matched =
			    (regexec(&ctx->profiler_regex, v->comm, 0, NULL, 0)
			     == 0);
			profile_regex_unlock(ctx);
			if (!matched) {
				if (ctx->only_matched_data) {
					continue;
				}

				set_msg_kvp_by_comm(&kv, v, (void *)0);
				goto skip_proc_find;
			}
		}

		get_process_info_by_pid(v->tgid, &stime, &netns_id,
					(char *)name, &info_p);
		__info_p = info_p;

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

			if (!is_match_finish) {
				profile_regex_lock(ctx);
				matched =
				    (regexec
				     (&ctx->profiler_regex, process_name, 0,
				      NULL, 0)
				     == 0);
				profile_regex_unlock(ctx);
			}

			if (matched)
				set_msg_kvp(&kv, v, stime, (void *)0);
			else {
				if (ctx->only_matched_data) {
					if (__info_p
					    && AO_SUB_F(&__info_p->use, 1) == 0)
						free_proc_cache(__info_p);

					continue;
				}

				set_msg_kvp_by_comm(&kv, v, (void *)0);
			}
		} else {
			if (ctx->only_matched_data) {
				if (__info_p
				    && AO_SUB_F(&__info_p->use, 1) == 0)
					free_proc_cache(__info_p);
				continue;
			}

			/* Not find process in procfs. */
			set_msg_kvp_by_comm(&kv, v, (void *)0);
		}

		/*
		 * Here, we duplicate the matched process data and place it into
		 * the Total process, with the aim of showcasing the proportion
		 * of each process in the overall sampling.
		 */
		if (matched && !ctx->only_matched_data)
			update_matched_process_in_total(ctx, msg_hash,
							process_name, v);

	      skip_proc_find:
		if (stack_trace_msg_hash_search
		    (msg_hash, (stack_trace_msg_hash_kv *) & kv,
		     (stack_trace_msg_hash_kv *) & kv) == 0) {
			__sync_fetch_and_add(&msg_hash->hit_hash_count, 1);
			((stack_trace_msg_t *) kv.msg_ptr)->count +=
			    v->duration_ns;
			if (__info_p && AO_SUB_F(&__info_p->use, 1) == 0)
				free_proc_cache(__info_p);
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
				if (__info_p
				    && AO_SUB_F(&__info_p->use, 1) == 0)
					free_proc_cache(__info_p);

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

		if (__info_p && AO_SUB_F(&__info_p->use, 1) == 0)
			free_proc_cache(__info_p);

		/* check and clean symbol cache */
		exec_proc_info_cache_update();
	}

	vec_free(ctx->raw_stack_data);
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
