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
#include "../user/clib.h"
#include "../user/vec.h"
#define __u32 u32
#define __u64 u64
#define __u8  u8
#include "../kernel/include/common.h"
#include "../kernel/include/perf_profiler.h"

int main(void)
{
	clib_mem_init();
	struct stack_trace_key_t *st = NULL, init_st = {};
	int ret = VEC_OK;
	int num = 100;
	vec_validate_init_empty(st, num, init_st, ret);
	if (ret != VEC_OK) {
		ebpf_warning("vec_validate_init_empty() failed, "
			     "num %d, ret %d\n", num, ret);
		return (-1);
	}

	printf("st vec len %u max len %lu\n", vec_len(st), vec_max_len(st));

	vec_validate(st, 160, ret);
	if (ret != VEC_OK) {
		ebpf_warning("vec_validate_init_empty() failed, "
			     "num %d, ret %d\n", num, ret);
		return (-1);
	}

	printf("st vec len %u max len %lu\n", vec_len(st), vec_max_len(st));

	st[20] = init_st;
	printf("st 20, %u, offset %lu\n", st[20].pid,
	       (void *)&st[20] - (void *)st);

	u64 alloc_b, free_b;
	get_mem_stat(&alloc_b, &free_b);

	printf("1 alloc_b %lu free_b %lu elem_count %d\n", alloc_b, free_b,
	       (int)alloc_b / (int)sizeof(struct stack_trace_key_t));

	struct stack_trace_key_t *temp;
	int count = 0;
	vec_foreach(temp, st) {
		temp->pid = count;
		count++;
	}

	int i;
	for (i = 0; i < 300; i++) {
		ret = VEC_OK; 
		vec_add1(st, init_st, ret);
		ASSERT(ret == VEC_OK);
	}

	count = 0;
	vec_foreach(temp, st) {
		count++;
	}

	printf("count : %d\n", count);

	vec_free(st);

	get_mem_stat(&alloc_b, &free_b);
	printf("2 alloc_b %lu free_b %lu \n", alloc_b, free_b);

	printf("[OK]\n");

        return 0;
}
