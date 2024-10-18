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
#define CP_PROFILE_SET_PROBES(T)
#include "../extended/extended.h"
#include "../bihash_32_8.h"
#include "../../kernel/include/perf_profiler.h"
#include "../tracer.h"

#define LOG_CP_TAG	"[CP] "

// For storing information about continuously running profiling processes.
#define DEEPFLOW_RUNNING_PID_PATH "/tmp/.deepflow-agent-running-pid"

/*
 * stack_trace_msg_hash, used to store stack trace messages and
 * perform statistics. These data are pushed to the higher level
 * for processing.
 */

#define stack_trace_msg_hash_t		clib_bihash_32_8_t
#define stack_trace_msg_hash_init	clib_bihash_init_32_8
#define stack_trace_msg_hash_kv		clib_bihash_kv_32_8_t
#define print_hash_stack_trace_msg	print_bihash_32_8
#define stack_trace_msg_hash_search	clib_bihash_search_32_8
#define stack_trace_msg_hash_add_del	clib_bihash_add_del_32_8
#define stack_trace_msg_hash_free	clib_bihash_free_32_8
#define stack_trace_msg_hash_key_value_pair_cb		clib_bihash_foreach_key_value_pair_cb_32_8
#define stack_trace_msg_hash_foreach_key_value_pair	clib_bihash_foreach_key_value_pair_32_8

#define JAVA_ATTACH_TOOL_PATH DF_JAVA_ATTACH_CMD

/*
 * stack trace messages for push-hash kvp.
 */

#define BIT_24_MAX_VAL	0xFFFFFFU
#define PID_MAX_VAL	BIT_24_MAX_VAL
#define STACK_ID_MAX	BIT_24_MAX_VAL
#define CPU_INVALID	0xFF
typedef struct {
	union {
		struct {
			/*
			 * tgid:
			 *   The tgid (Thread Group ID) in kernel space
			 *   is equivalent to the process ID in user space.
			 * pid:
			 *   The process ID or thread ID in kernel space.
			 * cpu:
			 *   Which CPU core does the perf event occur on?
			 */
			u64 tgid:24, pid:32, cpu:8;

			/*
			 * process start time(the number of millisecond
			 * elapsed since January 1, 1970 00:00:00).
			 */
			u64 stime;
			u32 u_stack_id;
			u32 k_stack_id;
			u64 e_stack_id; // extra stack id as key (object class or interpreter stack)
		} k;

		/* Matching and combining for process/thread name. */
		struct {
			u8 comm[TASK_COMM_LEN];
			u64 pid:24, reserved:32, cpu:8;
			/*
			 * Add padding fields to ensure that the hash key part reaches 32
			 * bytes (using a hash with a 32-byte key and a 1-byte value for
			 * stack tracing data), and set the 'padding' value to 0 in the
			 * key configuration.
			 */
			u64 padding;
		} c_k;

		// key for memory profile
		struct {
			/*
			 * tgid:
			 *   The tgid (Thread Group ID) in kernel space
			 *   is equivalent to the process ID in user space.
			 * pid:
			 *   The process ID or thread ID in kernel space.
			 * cpu:
			 *   Which CPU core does the perf event occur on?
			 */
			u64 tgid:24, pid:32, cpu:8;

			/*
			 * process start time(the number of millisecond
			 * elapsed since January 1, 1970 00:00:00).
			 */
			u64 stime;
			u32 u_stack_id;
			u32 uprobe_addr; // low 32B of uprobe function address which is not in uretprobe stack
			u64 mem_addr; // address of allocated/free'd memory
		} m_k;
	};

	/* Store perf profiler data */
	uword msg_ptr;
} stack_trace_msg_kv_t;

enum {
	PROFILER_TYPE_UNKNOWN,
	PROFILER_TYPE_ONCPU,
	PROFILER_TYPE_OFFCPU,
	PROFILER_TYPE_MEMORY,
	PROFILER_TYPE_NUM,
};

/*
 * stack trace message value, push data
 *
 * @profiler_type
 *   Profiler type, such as PROFILER_TYPE_ONCPU.
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
 *   The profiler captures the sum of durations of occurrences of the same
 *   data by querying with the quadruple
 *   "<pid + stime + u_stack_id + k_stack_id + tid + cpu>" as the key.
 *   Real-time intervals (in Microseconds) are used. Range: [1, 2^32-1)us
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
	u8 profiler_type;
	u64 time_stamp;
	u32 pid;
	u32 tid;
	u64 stime;
	u64 netns_id;
	u32 u_stack_id;
	u32 k_stack_id;
	u32 cpu;
	u64 mem_addr;
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

int stop_continuous_profiler(void *cb_ctx[PROFILER_CTX_NUM]);
int start_continuous_profiler(int freq, int java_syms_update_delay,
			      tracer_callback_t callback, void *cb_ctx[PROFILER_CTX_NUM]);
void process_stack_trace_data_for_flame_graph(stack_trace_msg_t * val);
void release_flame_graph_hash(void);
int set_profiler_cpu_aggregation(int flag);
struct bpf_tracer *get_profiler_tracer(void);
void set_enable_perf_sample(struct bpf_tracer *t, u64 enable_flag);
void cpdbg_process(stack_trace_msg_t * msg);
int check_profiler_running_pid(int pid);
int check_profiler_is_running(void);
int write_profiler_running_pid(void);
bool oncpu_profiler_enabled(void);
void print_cp_tracer_status(void);
void output_profiler_status(struct bpf_tracer *t, void *context);
#endif /* DF_USER_PERF_PROFILER_H */
