/*
 * Copyright (c) 2026 Yunshan Networks
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

#ifndef _USER_PROC_CACHE_ADMISSION_H_
#define _USER_PROC_CACHE_ADMISSION_H_

#include <stdbool.h>

#include "types.h"

#define PROC_CACHE_LIMIT_WARN_INTERVAL_NS \
	(2ULL * 60 * 60 * 1000000000ULL)

/*
 * Update the admission state and return true only when the caller should emit
 * a capacity warning. Recovering admission deliberately keeps last_warn_ns so
 * bouncing around the capacity limit cannot restart the warning window.
 */
static inline bool proc_cache_admission_update(volatile u32 *paused,
					       volatile u64 *last_warn_ns,
					       bool limit_reached, u64 now_ns)
{
	if (!limit_reached) {
		__atomic_store_n(paused, 0, __ATOMIC_RELEASE);
		return false;
	}

	__atomic_store_n(paused, 1, __ATOMIC_RELEASE);

	u64 last_warn = __atomic_load_n(last_warn_ns, __ATOMIC_ACQUIRE);
	bool should_warn =
	    last_warn == 0 ||
	    (now_ns >= last_warn &&
	     now_ns - last_warn >= PROC_CACHE_LIMIT_WARN_INTERVAL_NS);

	if (!should_warn)
		return false;

	return __atomic_compare_exchange_n(last_warn_ns, &last_warn, now_ns,
					   false, __ATOMIC_ACQ_REL,
					   __ATOMIC_ACQUIRE);
}

#endif /* _USER_PROC_CACHE_ADMISSION_H_ */
