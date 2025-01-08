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
#include <bcc/perf_reader.h>
#include "../../config.h"
#include "../../utils.h"
#include "../../mem.h"
#include "../../log.h"
#include "../../types.h"
#include "../../vec.h"
#include "../../tracer.h"
#include "../../socket.h"
#include "../../proc.h"
#include "collect_symbol_files.h"
#include "config.h"
#include "jvm_symbol_collect.h"
#include "../perf_profiler.h"
#include "../../elf.h"
#include "../../load.h"
#include "../../perf_reader.h"
#include "../../bihash_8_8.h"
#include "../stringifier.h"
#include "../profile_common.h"

static pthread_mutex_t list_lock;

/* For Java symbols update task. */
static struct list_head java_syms_update_tasks_head;
static u64 tasks_list_init_done;

/** Collect Java symbols.
 *
 * @pid Process ID
 * @ret_val
 *   Return address, used by the caller to determine subsequent processing.
 * @error_occurred
 *   'true' indicates that an error has occurred at some point, 
 *          no symbol collection for this process.
 *   'false' indicates that no error has occurred.
 */
void collect_java_symbols(int pid, int *ret_val, bool error_occurred)
{
	/*
	 * If an error has occurred at some point, no further retries will
	 * be attempted.
	 */
	if (error_occurred) {
		*ret_val = JAVA_SYMS_COLLECT_ERR;
		return;
	}

	*ret_val = JAVA_SYMS_COLLECT_OK;
	bool is_new_collector;
	u64 start_time = gettime(CLOCK_MONOTONIC, TIME_TYPE_NAN);
	if (update_java_symbol_file(pid, &is_new_collector))
		goto error;
	u64 end_time = gettime(CLOCK_MONOTONIC, TIME_TYPE_NAN);

	if (target_symbol_file_access(pid) != 0) {
		goto error;
	}

	i64 new_file_sz = get_local_symbol_file_sz(pid);
	if (new_file_sz == 0) {
		goto error;
	}

	if (is_new_collector) {
		ebpf_info("Refreshing JAVA symbol file: "
			  DF_AGENT_LOCAL_PATH_FMT
			  ".map, PID %d, size %ld, cost %lu us", pid, pid,
			  new_file_sz, (end_time - start_time) / 1000ULL);
		*ret_val = JAVA_SYMS_NEW_COLLECTOR;
	} else {
		*ret_val = JAVA_SYMS_NEED_UPDATE;
	}

	return;

error:
	if (is_new_collector)
		*ret_val = JAVA_CREATE_COLLECTOR_ERR;
	else
		*ret_val = JAVA_SYMS_COLLECT_ERR;

	ebpf_warning("Generate Java symbol files failed. PID %d\n", pid);
}

void clean_local_java_symbols_files(int pid)
{
	clear_local_perf_files(pid);
}

/* Called by 'cp_reader' thread */
void add_java_syms_update_task(struct symbolizer_proc_info *p_info)
{
	// To ensure that 'java_syms_update_tasks_head' has been initialized.
	while (!AO_GET(&tasks_list_init_done))
		CLIB_PAUSE();
	
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
	// Ensure the profiler is initialized and currently running
	while (!profiler_is_running())
		usleep(LOOP_DELAY_US);

	pthread_mutex_init(&list_lock, NULL);
	init_list_head(&java_syms_update_tasks_head);
	AO_SET(&tasks_list_init_done, 1);

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
				collect_java_symbols(p->pid, &ret,
						     p->gen_java_syms_file_err);
				if (ret != JAVA_SYMS_COLLECT_ERR
				    && ret != JAVA_CREATE_COLLECTOR_ERR) {
					if (ret == JAVA_SYMS_NEED_UPDATE
					    || ret == JAVA_SYMS_NEW_COLLECTOR)
						p->cache_need_update = true;
					else
						p->cache_need_update = false;

					if (ret != JAVA_SYMS_NEW_COLLECTOR) {
						p->need_new_symbol_collector =
						    false;
					}

					p->gen_java_syms_file_err = false;
				} else {
					/*
					 * Mark an error occurred when creating collector,
					 * no further symbol collection for this process.
					 */
					if (ret == JAVA_CREATE_COLLECTOR_ERR)
						p->gen_java_syms_file_err =
						    true;

					p->cache_need_update = false;
				}

				AO_SET(&p->new_java_syms_file, true);
			}

			AO_DEC(&p->use);
			clib_mem_free((void *)task);
		}

		usleep(LOOP_DELAY_US);
	}
}
