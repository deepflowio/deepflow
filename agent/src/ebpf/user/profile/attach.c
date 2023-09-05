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

	char path[128];
	snprintf(path, sizeof(path), "/tmp/perf-%d.map", pid);
	/* If it already exists in the deepflow agent namespace, it will delete it. */
	clear_target_ns_tmp_file(path);

	snprintf(path, sizeof(path), "/proc/%d/root/tmp/perf-%d.log",
		 pid, target_ns_pid);
	if (access(path, F_OK) == 0) {
		copy_file_from_target_ns(pid, target_ns_pid, "log");
	}

	snprintf(path, sizeof(path), "/proc/%d/root/tmp/perf-%d.map",
		 pid, target_ns_pid);
	/* If the file already exists, it will simply perform the copy operation and
	 * then exit successfully.*/
	if (access(path, F_OK) == 0) {
		copy_file_from_target_ns(pid, target_ns_pid, "map");
		return;
	}

	char args[32];
	snprintf(args, sizeof(args), "%d", pid);

	exec_command(DF_JAVA_ATTACH_CMD, args);

	copy_file_from_target_ns(pid, target_ns_pid, "map");
	copy_file_from_target_ns(pid, target_ns_pid, "log");
	clear_target_ns(pid, target_ns_pid);
}
