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

struct stack_trace_key_value {
	struct {
		u64 pid:24;	// processID
		/*
		 * process start time(the number of seconds elapsed since
		 * January 1, 1970 00:00:00).
		 */
		u64 start_time:40;
		__u32 kern_stack_id;
		__u32 user_stack_id;
	} key;

	u64 value_ptr; // Store the address of the stack backtracking symbolization.
};

int stop_continuous_profiler(void);
int start_continuous_profiler(int freq,
			      int report_period, tracer_callback_t callback);
#endif /* DF_USER_PERF_PROFILER_H */
