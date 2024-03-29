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

#ifndef DF_USER_OFFCPU_H
#define DF_USER_OFFCPU_H

#define TRACEPOINT_SEC_NAME "tracepoint/sched/sched_switch"

#undef CP_PROFILE_SET_PROBES
#define CP_PROFILE_SET_PROBES(T)			\
do {							\
	int index = 0, curr_idx;			\
	tps_set_symbol((T), TRACEPOINT_SEC_NAME);	\
	(T)->tps_nr = index;				\
} while(0)

#endif /*DF_USER_OFFCPU_H */
