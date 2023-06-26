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

#include "../user/common.h"
#include "../user/mem.h"
#include "../user/log.h"
#include "../user/types.h"
#include "../user/vec.h"

#include "../user/bihash_8_8.h"
#include "../user/bihash_16_8.h"

#if defined(__x86_64__) || defined(i386)
always_inline u64 cpu_time_now(void)
{
	u32 a, d;
	asm volatile ("rdtsc":"=a" (a), "=d"(d));
	return (u64) a + ((u64) d << (u64) 32);
}
#elif defined (__aarch64__)
always_inline u64 cpu_time_now(void)
{
	u64 vct;
	/* User access to cntvct_el0 is enabled in Linux kernel since 3.12. */
	asm volatile ("mrs %0, cntvct_el0":"=r" (vct));
	return vct;
}
#else
#error "don't know how to read CPU time stamp"
#endif

/* 32-bit random number generator */
always_inline u32 random_u32(void)
{
	srand((unsigned int)cpu_time_now());
	u32 ret = rand() % 100000 + 1;
	return ret;
}

int main(void)
{
	log_to_stdout = true;
	int i;
	clib_bihash_8_8_t *h, test_hash;
	h = &test_hash;
	memset(h, 0, sizeof(*h));
	u32 nbuckets = 8192;
	u64 hash_memory_size = 1ULL << 31;	// 2G
	clib_bihash_init_8_8(h, "test", nbuckets, hash_memory_size);
	clib_bihash_kv_8_8_t kv;

	for (i = 0; i < 100000; i++) {
		kv.key = random_u32();
		kv.value = kv.key + 99;
		clib_bihash_add_del_8_8(h, &kv, 1 /* is_add */ );
	}

	print_bihash_8_8(h);

	kv.value = 0;
	if (clib_bihash_search_8_8(h, &kv, &kv) < 0) {
		printf("search kv.key %lu kv.value %lu failed.\n", kv.key,
		       kv.value);
	} else {
		printf("search kv.key %lu kv.value %lu success.\n", kv.key,
		       kv.value);
	}

	printf("delete kv.key %lu kv.value %lu (%d).\n",
	       kv.key, kv.value, clib_bihash_add_del_8_8(h, &kv, 0));

	if (clib_bihash_search_8_8(h, &kv, &kv) < 0) {
		printf("search kv.key %lu kv.value %lu failed.\n", kv.key,
		       kv.value);
	} else {
		printf("search kv.key %lu kv.value %lu success.\n", kv.key,
		       kv.value);
	}

	clib_bihash_free_8_8(h);
	printf("[OK]\n");

        return 0;
}
