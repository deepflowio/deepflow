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

#ifndef DF_BPF_PERF_PROFILER_H
#define DF_BPF_PERF_PROFILER_H

#define STACK_MAP_ENTRIES 65536

/*
 * The meaning of the "__profiler_state_map" index.
 */
typedef enum {
	TRANSFER_CNT_IDX = 0,	/* buffer-a and buffer-b transfer count.*/
	SAMPLE_CNT_A_IDX,	/* sample count A */
	SAMPLE_CNT_B_IDX,	/* sample count B */
	SAMPLE_CNT_DROP,	/* sample drop */
	SAMPLE_ITER_CNT_MAX,	/* Iteration sample number max value */
	OUTPUT_CNT_IDX,		/* Count the total number of data outputs.*/
	ERROR_IDX,		/* Count the number of failed push notifications.*/
	PROFILER_CNT
} profiler_idx;

struct stack_trace_key_t {
	union {
		__u32 pid;	// for user
		__u32 tgid;	// for kernel
	};
	__u32 cpu;
	char comm[TASK_COMM_LEN];
	int kernstack;
	int userstack;
	__u64 timestamp;
};

#endif /* DF_BPF_PERF_PROFILER_H */
