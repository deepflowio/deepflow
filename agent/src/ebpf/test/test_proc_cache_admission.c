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

#include <pthread.h>
#include <stdio.h>

#include "../user/proc_cache_admission.h"

#define BOUNCE_COUNT 10000U
#define THREAD_COUNT 32U
#define START_NS 1000000000ULL

struct concurrent_case {
	volatile u32 paused;
	volatile u64 last_warn_ns;
	volatile u32 warning_count;
	u64 now_ns;
};

static void *attempt_warning(void *arg)
{
	struct concurrent_case *test = arg;

	if (proc_cache_admission_update(&test->paused,
					&test->last_warn_ns, true,
					test->now_ns))
		__atomic_add_fetch(&test->warning_count, 1, __ATOMIC_RELAXED);

	return NULL;
}

static int run_concurrent_attempts(struct concurrent_case *test)
{
	pthread_t threads[THREAD_COUNT];
	u32 created = 0;

	for (; created < THREAD_COUNT; created++) {
		if (pthread_create(&threads[created], NULL, attempt_warning,
				   test) != 0) {
			printf("pthread_create failed at thread %u\n", created);
			break;
		}
	}

	for (u32 i = 0; i < created; i++)
		pthread_join(threads[i], NULL);

	return created == THREAD_COUNT ? 0 : -1;
}

static int check_limit_bouncing(void)
{
	volatile u32 paused = 0;
	volatile u64 last_warn_ns = 0;

	if (!proc_cache_admission_update(&paused, &last_warn_ns, true,
					 START_NS)) {
		printf("first limit hit did not emit a warning\n");
		return -1;
	}

	for (u32 i = 1; i <= BOUNCE_COUNT; i++) {
		if (proc_cache_admission_update(&paused, &last_warn_ns, false,
						START_NS + i)) {
			printf("recovery emitted a warning at cycle %u\n", i);
			return -1;
		}
		if (paused != 0 || last_warn_ns != START_NS) {
			printf("recovery reset limiter state at cycle %u\n", i);
			return -1;
		}

		if (proc_cache_admission_update(&paused, &last_warn_ns, true,
						START_NS + i)) {
			printf("bounce emitted a duplicate warning at cycle %u\n", i);
			return -1;
		}
		if (paused != 1 || last_warn_ns != START_NS) {
			printf("limit state changed unexpectedly at cycle %u\n", i);
			return -1;
		}
	}

	if (proc_cache_admission_update(
		&paused, &last_warn_ns, true,
		START_NS + PROC_CACHE_LIMIT_WARN_INTERVAL_NS - 1)) {
		printf("warning emitted before the two-hour interval\n");
		return -1;
	}

	if (!proc_cache_admission_update(
		&paused, &last_warn_ns, true,
		START_NS + PROC_CACHE_LIMIT_WARN_INTERVAL_NS)) {
		printf("warning not emitted at the two-hour interval\n");
		return -1;
	}

	return 0;
}

static int check_concurrent_limit_hits(void)
{
	struct concurrent_case test = {
		.now_ns = START_NS,
	};

	if (run_concurrent_attempts(&test) != 0)
		return -1;
	if (test.warning_count != 1 || test.paused != 1 ||
	    test.last_warn_ns != START_NS) {
		printf("first concurrent hit emitted %u warnings\n",
		       test.warning_count);
		return -1;
	}

	proc_cache_admission_update(&test.paused, &test.last_warn_ns, false,
				    0);
	test.warning_count = 0;
	test.now_ns = START_NS + PROC_CACHE_LIMIT_WARN_INTERVAL_NS - 1;
	if (run_concurrent_attempts(&test) != 0)
		return -1;
	if (test.warning_count != 0 || test.last_warn_ns != START_NS) {
		printf("concurrent bounce emitted %u duplicate warnings\n",
		       test.warning_count);
		return -1;
	}

	test.warning_count = 0;
	test.now_ns = START_NS + PROC_CACHE_LIMIT_WARN_INTERVAL_NS;
	if (run_concurrent_attempts(&test) != 0)
		return -1;
	if (test.warning_count != 1 || test.last_warn_ns != test.now_ns) {
		printf("concurrent interval hit emitted %u warnings\n",
		       test.warning_count);
		return -1;
	}

	return 0;
}

int main(void)
{
	if (check_limit_bouncing() != 0)
		return -1;
	if (check_concurrent_limit_hits() != 0)
		return -1;

	printf("Proc cache admission rate-limit tests passed.\n");
	return 0;
}
