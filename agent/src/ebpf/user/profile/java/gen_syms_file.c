/*
 * Copyright (c) 2023 Yunshan Networks
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
#include <bcc/perf_reader.h>
#include "../../config.h"
#include "../../common.h"
#include "../../mem.h"
#include "../../log.h"
#include "../../types.h"
#include "../../vec.h"
#include "../../tracer.h"
#include "../../socket.h"
#include "gen_syms_file.h"
#include "config.h"
#include "df_jattach.h"

extern int g_java_syms_write_bytes_max;

static pthread_mutex_t list_lock;

/* For Java symbols update task. */
static struct list_head java_syms_update_tasks_head;

void gen_java_symbols_file(int pid)
{
	int target_ns_pid = get_nspid(pid);
	if (target_ns_pid < 0) {
		return;
	}

	char args[PERF_PATH_SZ * 2];
	if (!is_same_mntns(pid)) {
		snprintf(args, sizeof(args), "%d %d,%s,%s", pid,
			 g_java_syms_write_bytes_max,
			 PERF_MAP_FILE_FMT, PERF_MAP_LOG_FILE_FMT);
	} else {
		snprintf(args, sizeof(args), "%d %d,%s,%s", pid,
			 g_java_syms_write_bytes_max,
			 DF_AGENT_LOCAL_PATH_FMT ".map",
			 DF_AGENT_LOCAL_PATH_FMT ".log");
	}

	exec_command(DF_JAVA_ATTACH_CMD, args);
	if (!is_same_mntns(pid)) {
		if (copy_file_from_target_ns(pid, target_ns_pid, "map") ||
		    copy_file_from_target_ns(pid, target_ns_pid, "log"))
			ebpf_warning("Copy pid %d files failed\n", pid);
		clear_target_ns(pid, target_ns_pid);
	}
}

void clean_local_java_symbols_files(int pid)
{
	clear_local_perf_files(pid);
}

/* Called by 'cp_reader' thread */
void add_java_syms_update_task(struct symbolizer_proc_info *p_info)
{
	struct java_syms_update_task *task;
	task =
	    clib_mem_alloc_aligned("java_update_task", sizeof(*task), 0, NULL);
	if (task == NULL) {
		ebpf_warning("java_update_task alloc memory failed.\n");
	}
	memset(task, 0, sizeof(*task));
	task->p = p_info;

	pthread_mutex_lock(&list_lock);
	p_info->use += 1;
	list_add_tail(&task->list, &java_syms_update_tasks_head);
	pthread_mutex_unlock(&list_lock);
}

void java_syms_update_main(void *arg)
{
	pthread_mutex_init(&list_lock, NULL);
	init_list_head(&java_syms_update_tasks_head);
	struct java_syms_update_task *task;

	for (;;) {
		// Multithreaded safe fetch 'java_syms_update_task'
		pthread_mutex_lock(&list_lock);
		if (!list_empty(&java_syms_update_tasks_head)) {
			task = list_first_entry(&java_syms_update_tasks_head,
						struct java_syms_update_task,
						list);
			list_head_del(&task->list);
		} else {
			task = NULL;
		}
		pthread_mutex_unlock(&list_lock);

		if (task != NULL) {

			struct symbolizer_proc_info *p = task->p;
			/* JAVA process has not exited. */
			if (AO_GET(&p->use) > 1) {
				gen_java_symbols_file(p->pid);
				AO_SET(&p->new_java_syms_file, true);
			}

			/* Ensure that all tasks are completed before releasing. */
			if (AO_SUB_F(&p->use, 1) == 0) {
				clib_mem_free((void *)p);
			}

			clib_mem_free((void *)task);
		}

		usleep(LOOP_DELAY_US);
	}
}
