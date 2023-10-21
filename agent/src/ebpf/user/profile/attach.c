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

#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dlfcn.h>

#include "../common.h"
#include "../log.h"
#include "java/df_jattach.h"
#include "attach.h"

void gen_java_symbols_file(int pid)
{
	int target_ns_pid = get_nspid(pid);
	if (target_ns_pid < 0) {
		return;
	}

	char args[32];
	snprintf(args, sizeof(args), "%d", pid);
	exec_command(DF_JAVA_ATTACH_CMD, args);
	if (copy_file_from_target_ns(pid, target_ns_pid, "map") ||
	    copy_file_from_target_ns(pid, target_ns_pid, "log"))
		ebpf_warning("Copy pid %d files failed\n", pid);
	clear_target_ns(pid, target_ns_pid);
}

void clean_local_java_symbols_files(int pid)
{
	clear_local_perf_files(pid);
}
