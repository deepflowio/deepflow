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

#include <limits.h>
#include <stdio.h>

#include <bcc/perf_reader.h>
#include "../user/config.h"
#include "../user/common_utils.h"
#include "../user/utils.h"
#include "../user/mem.h"
#include "../user/log.h"
#include "../user/types.h"
#include "../user/vec.h"
#include "../user/tracer.h"
#include "../user/socket.h"
#include "../user/profile/perf_profiler.h"
#include "../user/elf.h"
#include "../user/load.h"

int main(void)
{
	log_to_stdout = true;

	if (set_ai_agent_data_limit_max(-1) >= 0) {
		printf("negative ai_agent limit unexpectedly accepted\n");
		return -1;
	}

	if (set_ai_agent_data_limit_max(0) != 0) {
		printf("zero ai_agent limit was not preserved\n");
		return -1;
	}

	if (set_ai_agent_data_limit_max(INT_MAX) != INT_MAX) {
		printf("INT_MAX ai_agent limit was not preserved\n");
		return -1;
	}

	printf("[OK]\n");
	return 0;
}
