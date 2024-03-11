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

/** Generate Java symbol file.
 *
 * @pid Process ID
 * @ret_val
 *   Return address, used by the caller to determine subsequent processing.
 * @error_occurred
 *   'true' indicates that an error has occurred at some point,
 *   'false' indicates that no error has occurred.
 */
void gen_java_symbols_file(int pid, int *ret_val, bool error_occurred)
{
	/*
	 * If an error has occurred at some point, no further retries will
	 * be attempted.
	 */
	if (error_occurred) {
		goto error;
	}

	*ret_val = JAVA_SYMS_OK;
	int target_ns_pid = get_nspid(pid);
	if (target_ns_pid < 0) {
		return;
	}

	char args[PERF_PATH_SZ * 2];
	snprintf(args, sizeof(args),
		"%d %d," DF_AGENT_LOCAL_PATH_FMT ".map," DF_AGENT_LOCAL_PATH_FMT ".log",
		pid, g_java_syms_write_bytes_max, pid, pid);

	i64 curr_local_sz;
	curr_local_sz = get_local_symbol_file_sz(pid, target_ns_pid);

	exec_command(DF_JAVA_ATTACH_CMD, args);

	if (target_symbol_file_access(pid, target_ns_pid, true) != 0) {
		goto error;
	}

	i64 new_file_sz = get_local_symbol_file_sz(pid, target_ns_pid);
	if (new_file_sz == 0) {
		goto error;
	}

	if (new_file_sz > curr_local_sz)
		*ret_val = JAVA_SYMS_NEED_UPDATE;
	return;
error:
	*ret_val = JAVA_SYMS_ERR;
	ebpf_warning("Generate Java symbol files failed. PID %d\n", pid);
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
	AO_INC(&p_info->use);
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
				int ret;
				gen_java_symbols_file(p->pid, &ret,
						      p->
						      gen_java_syms_file_err);
				if (ret != JAVA_SYMS_ERR) {
					if (ret == JAVA_SYMS_NEED_UPDATE)
						p->cache_need_update = true;
					else
						p->cache_need_update = false;

					p->gen_java_syms_file_err = false;
				} else {
					p->gen_java_syms_file_err = true;
					p->cache_need_update = false;
				}

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
