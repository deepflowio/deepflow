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

#include "../user/utils.h"
#include "../user/mem.h"
#include "../user/log.h"
#include "../user/types.h"
#include "../user/vec.h"
#include "../user/tracer.h"

#include "../user/bihash_8_8.h"
extern pids_match_hash_t pids_match_hash;
static int count;
static int test_pids[] =
    { 0x30, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20 };
static bool result = true;
static int print_match_pids_kvp_cb(pids_match_hash_kv * kv, void *arg)
{
	printf("  PID %lu flags 0x%lx\n", kv->key, kv->value);
	count++;
	if (test_pids[kv->key - 1] != (int)kv->value)
		result = false;
	return BIHASH_WALK_CONTINUE;
}

void print_match_pids_hash(void)
{
	pids_match_hash_t *h = &pids_match_hash;
	pids_match_hash_foreach_key_value_pair(h, print_match_pids_kvp_cb,
					       NULL);
	print_hash_pids_match(&pids_match_hash);
}

int main(void)
{
	log_to_stdout = true;
	init_match_pids_hash();
	int pids[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
	int ret = exec_set_feature_pids(FEATURE_PROFILE_ONCPU, pids,
					sizeof(pids) / sizeof(pids[0]));
	printf("  FEATURE_PROFILE_ONCPU exec_set_feature_pids ret : %d\n", ret);
	ret =
	    exec_set_feature_pids(FEATURE_PROFILE_OFFCPU, pids,
				  sizeof(pids) / sizeof(pids[0]));
	printf("  FEATURE_PROFILE_OFFCPU exec_set_feature_pids ret : %d\n",
	       ret);
	{
		int pids[] = { 11, 12, 34, 2000 };
		ret =
		    exec_set_feature_pids(FEATURE_PROFILE_ONCPU, pids,
					  sizeof(pids) / sizeof(pids[0]));
		printf
		    ("  FEATURE_PROFILE_ONCPU exec_set_feature_pids ret : %d\n",
		     ret);
	}
	{
		int pids[] = { 1 };
		ret =
		    exec_set_feature_pids(FEATURE_PROFILE_ONCPU, pids,
					  sizeof(pids) / sizeof(pids[0]));
		printf
		    ("  FEATURE_PROFILE_ONCPU exec_set_feature_pids ret : %d\n",
		     ret);
		count = 0;
		print_match_pids_hash();
	}

	printf("count %d, result %d\n", count, result);

	bool matched = is_pid_match(FEATURE_PROFILE_OFFCPU, 2);
	printf("  FEATURE_PROFILE_OFFCPU, PID 2, matched: %d\n", matched);
	matched = is_pid_match(FEATURE_PROFILE_ONCPU, 2);
	printf("  FEATURE_PROFILE_ONCPU, PID 2, matched: %d\n", matched);
	matched = is_pid_match(FEATURE_UPROBE_GOLANG, 1);
	printf("  FEATURE_UPROBE_GOLANG, PID 1, matched: %d\n", matched);
	if (count == 10 && result && !matched) {
		printf("  TEST success.\n");
		return 0;
	}

	return -1;
}
