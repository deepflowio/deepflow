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

#include <sys/stat.h>
#include <math.h>
#include <bcc/perf_reader.h>
#include "../user/config.h"
#include "../user/common_utils.h"
#include "../user/common.h"
#include "../user/mem.h"
#include "../user/log.h"
#include "../user/types.h"
#include "../user/vec.h"
#include "../user/tracer.h"
#include "../user/socket.h"
#include "../user/profile/perf_profiler.h"
#include "../user/elf.h"
#include "../user/load.h"

#define TEST_NAME "test_pid_check"
static int check_test_is_running(void)
{
	int pid = find_pid_by_name(TEST_NAME, getpid());
	if (pid > 0) {
		return check_profiler_running_pid(pid);
	}

	return ETR_NOTEXIST;
}

int main(void)
{
	bpf_tracer_init(NULL, true);
	if (check_test_is_running() != ETR_NOTEXIST)
		exit(1);

	if (write_profiler_running_pid() != ETR_OK)
		return (-1);

	char buf[2048];
	exec_command("./test_pid_check", "", buf, sizeof(buf));
	ebpf_info("--- %s\n", buf);
	if (strstr(buf, "is already running")) {
		ebpf_info("TEST success.\n");
		return 0;
	}
	return -1;
}
