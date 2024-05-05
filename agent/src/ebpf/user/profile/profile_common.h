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

#ifndef DF_USER_PROFILE_COMMON_H
#define DF_USER_PROFILE_COMMON_H

struct profiler_context {
	// The name of the status map
	char state_map_name[MAP_NAME_SZ];
	// The dual-buffered reader is used to read data from the perf buffer.
	struct bpf_perf_reader *r_a;
	struct bpf_perf_reader *r_b;
	// stack map name
	char stack_map_name_a[MAP_NAME_SZ];
	char stack_map_name_b[MAP_NAME_SZ];

	// Read raw data from the eBPF perfbuf and temporarily store it.
	struct stack_trace_key_t *raw_stack_data;

	// Cache hash: obtain folded stack trace string from stack ID.
	stack_str_hash_t stack_str_hash;
	// Used for tracking data statistics and pushing.
	stack_trace_msg_hash_t msg_hash;

	/*
	 * 'cpu_aggregation_flag' is used to set whether to retrieve CPUID
	 * and include it in the aggregation of stack trace data.
	 *
	 * If valude is set to 1, CPUID will be retrieved and included in
	 * the aggregation of stack trace data. If value is set to 0,
	 * CPUID will not be retrieved and will not be included in the
	 * aggregation. Any other value is considered invalid.
	 */
	volatile u64 cpu_aggregation_flag;

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
	regex_t profiler_regex;
	bool regex_existed;
	volatile u32 regex_lock;

	/*
	 * The profiler stop flag, with 1 indicating stop and
	 * 0 indicating running status.
	 */
	volatile u64 profiler_stop;

	/*
	 * This flag is used to enable the eBPF program to start working.
	 * with 1 indicating enable and 0 indicating disable.
	 */
	volatile u64 enable_bpf_profile;

	/*
	 * The identifier to only retrieve matched data. This flag
	 * setting will exclude the total process.
	 */
	bool only_matched_data;

	// Record all stack IDs in each iteration for quick retrieval.
	struct stack_ids_bitmap stack_ids_a;
	struct stack_ids_bitmap stack_ids_b;
	// This vector table is used to remove a stack from the stack map.
	int *clear_stack_ids_a;
	int *clear_stack_ids_b;

	// for stack_trace_msg_hash relese
	stack_trace_msg_hash_kv *trace_msg_kvps;
	bool msg_clear_hash;

	/* profiler statistics */

	// Switching between dual buffers.
	u64 transfer_count;
	// Total iteration count for all iterations.
	u64 process_count;
	u64 stackmap_clear_failed_count;
	// perf buffer queue loss statistics.
	u64 perf_buf_lost_a_count;
	u64 perf_buf_lost_b_count;
	/*
	 * During the parsing process, it is possible for processes in procfs
	 * to be missing (processes that start and exit quickly). This variable
	 * is used to count the number of lost processes during the parsing process.
	 */
	atomic64_t process_lost_count;
	// Stack error quantity statistics obtained by eBPF.
	u64 stack_trace_err;
	// Quantity statistics of data pushed.
	u64 push_count;
	/*
	 * Record the time of the last data push
	 * (in seconds since system startup)
	 */
	u64 last_push_time;
};

static inline void profile_regex_lock(struct profiler_context *c)
{
	while (__atomic_test_and_set(&c->regex_lock, __ATOMIC_ACQUIRE))
		CLIB_PAUSE();
}

static inline void profile_regex_unlock(struct profiler_context *c)
{
	__atomic_clear(&c->regex_lock, __ATOMIC_RELEASE);
}

void process_bpf_stacktraces(struct profiler_context *ctx,
			     struct bpf_tracer *t);
int do_profiler_regex_config(const char *pattern, struct profiler_context *ctx);
void set_enable_profiler(struct bpf_tracer *t, struct profiler_context *ctx,
			 u64 enable_flag);
int profiler_context_init(struct profiler_context *ctx,
			  const char *state_map_name,
			  const char *stack_map_name_a,
			  const char *stack_map_name_b, bool only_matched);
bool run_conditions_check(void);
int java_libs_and_tools_install(void);
void push_and_release_stack_trace_msg(struct profiler_context *ctx,
				      stack_trace_msg_hash_t * h,
				      bool is_force);
#endif /*DF_USER_PROFILE_COMMON_H */
