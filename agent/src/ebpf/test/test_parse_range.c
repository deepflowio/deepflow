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

#include "../user/common.h"
#include "../user/mem.h"
#include "../user/log.h"
#include "../user/types.h"

int main(void)
{
	log_to_stdout = true;
	bool *online = NULL;
	int err, n = 0;
	const char *online_cpus_str = "3, 5, 8-10, 10-12, 15-32";
	err =
	    parse_num_range(online_cpus_str, strlen(online_cpus_str), &online,
			    &n);
	if (err == 0)
		goto failed;
	printf("Test \"%s\" err %d done\n", online_cpus_str, err);

	free(online);
	online = NULL;
	n = 0;
	const char *online_cpus_str_0 = "3, 5, 8-10, 9-12, 15-32";
	err =
	    parse_num_range(online_cpus_str_0, strlen(online_cpus_str_0),
			    &online, &n);
	if (err == 0)
		goto failed;
	printf("Test \"%s\" err %d done\n", online_cpus_str_0, err);

	free(online);
	online = NULL;
	n = 0;
	const char *online_cpus_str_1 = "3, 5, 12, 8-10, 15-32";
	err =
	    parse_num_range(online_cpus_str_1, strlen(online_cpus_str_1),
			    &online, &n);
	if (err == 0)
		goto failed;
	printf("Test \"%s\" err %d done\n", online_cpus_str_1, err);

	free(online);
	online = NULL;
	n = 0;
	const char *online_cpus_str_2 = "3, 5, 8-10, 12, 15-32";
	err =
	    parse_num_range(online_cpus_str_2, strlen(online_cpus_str_2),
			    &online, &n);
	if (err) {
		ebpf_warning("failed to get online CPU mask: %d\n", err);
		return -1;
	}

	if (n != 33) {
		goto failed;
	}

	int i;
	for (i = 0; i < n; i++) {
		if (!online[i]) {
			if (i != 0 && i != 1 && i != 2 && i != 4 && i != 6
			    && i != 7 && i != 11 && i != 13 && i != 14) {
				goto failed;
			}
		}
	}

	printf("Test \"%s\" err %d done\n", online_cpus_str_2, err);
	free(online);
	printf("[OK]\n");
	return 0;

failed:
	free(online);
	printf("[Failed]\n");
	return -1;
}
