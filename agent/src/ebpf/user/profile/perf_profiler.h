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

#ifndef DF_USER_PERF_PROFILER_H
#define DF_USER_PERF_PROFILER_H
#define CP_PROFILE_SET_PROBES
#include "extended/extended.h"
#include "../bihash_24_8.h"
#include "../../kernel/include/perf_profiler.h"

/*
 * stack_trace_msg_hash, used to store stack trace messages and
 * perform statistics. These data are pushed to the higher level
 * for processing.
 */

#define stack_trace_msg_hash_t		clib_bihash_24_8_t
#define stack_trace_msg_hash_init	clib_bihash_init_24_8
#define stack_trace_msg_hash_kv		clib_bihash_kv_24_8_t
#define print_hash_stack_trace_msg	print_bihash_24_8
#define stack_trace_msg_hash_search	clib_bihash_search_24_8
#define stack_trace_msg_hash_add_del	clib_bihash_add_del_24_8
#define stack_trace_msg_hash_free	clib_bihash_free_24_8
#define stack_trace_msg_hash_key_value_pair_cb		clib_bihash_foreach_key_value_pair_cb_24_8
#define stack_trace_msg_hash_foreach_key_value_pair	clib_bihash_foreach_key_value_pair_24_8

#define JAVA_ATTACH_TOOL_PATH DF_JAVA_ATTACH_CMD

/*
 * stack trace messages for push-hash kvp.
 */

#define BIT_26_MAX_VAL	0x3ffffffU
#define PID_MAX_VAL	BIT_26_MAX_VAL
#define STACK_ID_MAX	BIT_26_MAX_VAL
#define CPU_INVALID	0xFFF
typedef struct {
	union {
		struct {
			/*
			 * tgid:(max 67,108,864)
			 *   The tgid (Thread Group ID) in kernel space
			 *   is equivalent to the process ID in user space.
			 * pid:(max 67,108,864)
			 *   The process ID or thread ID in kernel space.
			 * cpu: (max 4,096)
			 *   Which CPU core does the perf event occur on?
			 */
			u64 tgid:26, pid:26, cpu:12;

			/*
			 * process start time(the number of millisecond
			 * elapsed since January 1, 1970 00:00:00).
			 */
			u64 stime;
			u32 u_stack_id;
			u32 k_stack_id;
		} k;

		/* Matching and combining for process/thread name. */
		struct {
			u8 comm[TASK_COMM_LEN];
			u64 pid:26, reserved:26, cpu:12;
		} c_k;
	};

	/* Store perf profiler data */
	uword msg_ptr;
} stack_trace_msg_kv_t;

/*
 * stack trace message value, push data
 *
 * @time_stamp
 *   Timestamp of the stack trace data(unit: nanoseconds).
 * @pid
 *   User-space process-ID.
 * @tid
 *   Identified within the eBPF program in kernel space.
 *   If the current is a process and not a thread this field(tid) is filled
 *   with the ID of the process.
 * @stime
 *   The start time of the process is measured in milliseconds.
 * @u_stack_id
 *   User space stackID.
 * @k_stack_id
 *   Kernel space stackID.
 * @cpu
 *   The captured stack trace data is generated on which CPU?
 * @count
 *   The profiler captures the number of occurrences of the same
 *   data by querying with the quadruple
 *   "<pid + stime + u_stack_id + k_stack_id + tid + cpu>" as the key.
 * @comm
 *   comm in task_struct(linux kernel), always 16 bytes
 *   If the capture is a process, fill in the process name here.
 *   If the capture is a thread, fill in the thread name.
 * @process_name
 *   process name
 * @container_id
 *   container id fetch from /proc/[pid]/cgroup
 * @data_len
 *   stack data length
 * @data_ptr
 *   Example of a folded stack trace string (taken from a perf profiler test):
 *   main;xxx();yyy()
 *   It is a list of symbols corresponding to addresses in the underlying stack trace,
 *   separated by ';'.
 *   The merged folded stack trace string style for user space and kernel space would be:
 *   <user space folded stack trace string> + ";" + <kernel space folded stack trace string>
 */
typedef struct {
	u64 time_stamp;
	u32 pid;
	u32 tid;
	u64 stime;
	u64 netns_id;
	u32 u_stack_id;
	u32 k_stack_id;
	u32 cpu;
	u64 count;
	u8 comm[TASK_COMM_LEN];
	u8 process_name[TASK_COMM_LEN];
	u8 container_id[CONTAINER_ID_SIZE];
	u32 data_len;
	u64 data_ptr;
	u8 data[0];
} stack_trace_msg_t;

struct stack_ids_bitmap {
	u64 count;
	u8 bitmap[STACK_MAP_ENTRIES / 8];
} __attribute__((packed));

int stop_continuous_profiler(void);
int start_continuous_profiler(int freq, int java_syms_space_limit,
			      int java_syms_update_delay,
			      tracer_callback_t callback);
void process_stack_trace_data_for_flame_graph(stack_trace_msg_t * val);
void release_flame_graph_hash(void);
int set_profiler_regex(const char *pattern);
int set_profiler_cpu_aggregation(int flag);
struct bpf_tracer *get_profiler_tracer(void);
void set_enable_perf_sample(struct bpf_tracer *t, u64 enable_flag);
void cpdbg_process(stack_trace_msg_t * msg);
#endif /* DF_USER_PERF_PROFILER_H */
