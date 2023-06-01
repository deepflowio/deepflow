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

#ifndef DF_USER_PERF_PROFILER_H
#define DF_USER_PERF_PROFILER_H
#include "bihash_24_8.h"

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

/*
 * stack trace messages for push-hash kvp.
 */
typedef struct {
	struct {
		/* processID */
		u64 pid;
		/*
		 * process start time(the number of millisecond
		 * elapsed since January 1, 1970 00:00:00).
 		 */
		u64 stime;
		u32 u_stack_id;
		u32 k_stack_id;
	} k;
	/* Store perf profiler data */
	u64 msg_ptr;
} stack_trace_msg_kv_t; 

/* stack trace message value, push data */
typedef struct {
	u64 time_stamp;
	u32 pid;
	u64 stime;
	u32 u_stack_id;
	u32 k_stack_id;
	u32 cpu;
	u32 count;
	u8 comm[TASK_COMM_LEN];
	u32 data_len;
	u64 data_ptr;
	u8 data[0];
} stack_trace_msg_t;

int stop_continuous_profiler(void);
int start_continuous_profiler(int freq,
			      int report_period, tracer_callback_t callback);
#endif /* DF_USER_PERF_PROFILER_H */
