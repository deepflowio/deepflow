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

#include "python_probe.h"
#include "tracer.h"
#include "socket.h"
#include "common.h"
#include "log.h"
#include <bcc/bcc_proc.h>
#include <bcc/bcc_elf.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/limits.h>
#include <linux/version.h>
#include <string.h>
#include <ctype.h>
#include "profile/perf_profiler.h"

#include "symbol.h"

struct python_process_create_event {
	struct list_head list;
	int pid;
	uint32_t expire_time;
	struct bpf_tracer *tracer;
};

static struct list_head proc_events_list;
static pthread_mutex_t proc_events_list_mutex;

static struct symbol python_syms[] = {
	{
		.type = OTHER_UPROBE,
		.path = "/usr/bin/python3",
		.symbol = "PyEval_SaveThread",
		.probe_func = "uprobe_python_save_tstate",
		.is_probe_ret = true,
	},
	{
		.type = OTHER_UPROBE,
		.path = "/usr/local/lib/python3.10/dist-packages/nvidia/cuda_runtime/lib/libcudart.so.12",
		.symbol = "cudaMalloc",
		.probe_func = "uprobe_cuda_malloc",
		.is_probe_ret = false,
	},
	{
		.type = OTHER_UPROBE,
		.path = "/usr/local/lib/python3.10/dist-packages/nvidia/cuda_runtime/lib/libcudart.so.12",
		.symbol = "cudaMalloc",
		.probe_func = "uretprobe_cuda_malloc",
		.is_probe_ret = true,
	},
	{
		.type = OTHER_UPROBE,
		.path = "/usr/local/lib/python3.10/dist-packages/nvidia/cuda_runtime/lib/libcudart.so.12",
		.symbol = "cudaFree",
		.probe_func = "uprobe_cuda_free",
		.is_probe_ret = false,
	},
};

#if defined(__powerpc64__) && defined(_CALL_ELF) && _CALL_ELF == 2
#define bcc_use_symbol_type (65535 | (1 << STT_PPC64_ELFV2_SYM_LEP))
#else
#define bcc_use_symbol_type (65535)
#endif

static struct bcc_symbol_option bcc_elf_foreach_sym_option = {
	.use_debug_file = 0,
	.check_debug_file_crc = 0,
	.lazy_symbolize = 1,
	.use_symbol_type = bcc_use_symbol_type,
};

struct elf_symbol {
	uint64_t addr;
	uint64_t size;
	const char *name;
};

static int fill_elf_symbol(const char *name, uint64_t addr,
					uint64_t size, void *payload)
{
	struct elf_symbol *p = payload;
	char *pos;
	if ((pos = strstr(name, p->name))) {
		if (pos[strlen(p->name)] == '\0') {
			p->addr = addr;
			p->size = size;
			return -1;
		}
	}
	return 0;
}

static int add_probe_sym_to_tracer_probes(int pid, const char *path,
					  struct tracer_probes_conf *conf)
{
	int ret = 0;
	int idx = 0;
	struct symbol_uprobe *probe_sym = NULL;
	struct symbol *cur = NULL;
	struct elf_symbol payload;

	for (idx = 0; idx < NELEMS(python_syms); ++idx) {
		memset(&payload, 0, sizeof(payload));
		cur = &python_syms[idx];

		if (strlen(cur->path) > 0) {
			path = cur->path;
		}

		// Use memory on the stack, no need to allocate on the heap
		payload.name = cur->symbol;
		ret = bcc_elf_foreach_sym(path, fill_elf_symbol,
					  &bcc_elf_foreach_sym_option,
					  &payload);
		if (ret)
			break;

		if (!payload.addr || !payload.size)
			continue;

		// This memory will be maintained in conf, no need to release
		probe_sym = calloc(1, sizeof(struct symbol_uprobe));
		if (!probe_sym)
			continue;

		// Data comes from symbolic information
		probe_sym->entry = payload.addr;
		probe_sym->size = payload.size;

		// Data comes from global variables
		probe_sym->type = cur->type;
		probe_sym->isret = cur->is_probe_ret;
		probe_sym->probe_func = strdup(cur->probe_func);
		probe_sym->name = strdup(cur->symbol);

		// Data comes from function input parameters
		probe_sym->binary_path = strdup(path);
		probe_sym->pid = pid;

		if (probe_sym->probe_func && probe_sym->name &&
		    probe_sym->binary_path) {
			add_uprobe_symbol(pid, probe_sym, conf);
		} else {
			free((void *)probe_sym->probe_func);
			free((void *)probe_sym->name);
			free((void *)probe_sym->binary_path);
		}
	}
	return 0;
}

static void python_parse_and_register(int pid, struct tracer_probes_conf *conf)
{
	char *path = "/usr/bin/python3";

	if (pid <= 1)
		goto out;

	if (!is_user_process(pid))
		goto out;

	ebpf_info("python uprobe, pid:%d, path:%s\n", pid, path);
	add_probe_sym_to_tracer_probes(pid, path, conf);

out:
	return;
}

static void add_event_to_proc_list(struct bpf_tracer *tracer, int pid)
{
	static const uint32_t PROC_EVENT_HANDLE_DELAY = 120;
	struct python_process_create_event *event = NULL;

	event = calloc(1, sizeof(struct python_process_create_event));
	if (!event) {
		ebpf_warning("no memory.\n");
		return;
	}

	event->tracer = tracer;
	event->pid = pid;
	event->expire_time = get_sys_uptime() + PROC_EVENT_HANDLE_DELAY;

	pthread_mutex_lock(&proc_events_list_mutex);
	list_add_tail(&event->list, &proc_events_list);
	pthread_mutex_unlock(&proc_events_list_mutex);
	return;
}

static struct python_process_create_event *get_first_event(void)
{
	struct python_process_create_event *event = NULL;
	pthread_mutex_lock(&proc_events_list_mutex);
	if (!list_empty(&proc_events_list)) {
		event = list_first_entry(&proc_events_list,
					 struct python_process_create_event, list);
	}
	pthread_mutex_unlock(&proc_events_list_mutex);
	return event;
}

static void remove_event(struct python_process_create_event *event)
{
	pthread_mutex_lock(&proc_events_list_mutex);
	list_head_del(&event->list);
	pthread_mutex_unlock(&proc_events_list_mutex);
}

static void clear_python_probes_by_pid(struct bpf_tracer *tracer, int pid)
{
	struct probe *probe;
	struct list_head *p, *n;
	struct symbol_uprobe *sym_uprobe;

	list_for_each_safe (p, n, &tracer->probes_head) {
		probe = container_of(p, struct probe, list);
		if (!(probe->type == UPROBE && probe->private_data != NULL))
			continue;
		sym_uprobe = probe->private_data;

		if (sym_uprobe->type != OTHER_UPROBE)
			continue;

		if (sym_uprobe->pid != pid)
			continue;

		if (probe_detach(probe)) {
			ebpf_warning("probe_detach failed, path:%s, name:%s\n",
				     sym_uprobe->binary_path, sym_uprobe->name);
		}
		free_probe_from_tracer(probe);
	}
}

int collect_python_uprobe_syms_from_procfs(struct tracer_probes_conf *conf)
{
	struct dirent *entry = NULL;
	DIR *fddir = NULL;
	int pid = 0;
	char *path = NULL;

	init_list_head(&proc_events_list);
	pthread_mutex_init(&proc_events_list_mutex, NULL);

	fddir = opendir("/proc/");
	if (!fddir) {
		ebpf_warning("Failed to open %s.\n");
		return ETR_PROC_FAIL;
	}

	while ((entry = readdir(fddir))) {
		if (entry->d_type != DT_DIR)
			continue;
		pid = atoi(entry->d_name);
		if (pid <= 1) {
			continue;
		}
		path = get_elf_path_by_pid(pid);
		if (!path) {
			continue;
		}
		if (strstr(path, "python3")) {
			python_parse_and_register(pid, conf);
		}
		free(path);
	}

	closedir(fddir);
	return ETR_OK;
}

void python_process_exec(int pid)
{
	struct bpf_tracer *tracer = NULL;
	char *path = get_elf_path_by_pid(pid);
	if (!path) return;
	bool matched = strstr(path, "python3") != NULL;
	free(path);
	if (!matched)
		return;

	tracer = find_bpf_tracer(SK_TRACER_NAME);
	if (tracer == NULL)
		return;

	if (tracer->state != TRACER_RUNNING)
		return;

	if (tracer->probes_count > OPEN_FILES_MAX) {
		ebpf_warning("Probes count too many. The maximum is %d\n",
			     OPEN_FILES_MAX);
		return;
	}

	add_event_to_proc_list(tracer, pid);
}

void python_process_exit(int pid)
{
	struct bpf_tracer *tracer = NULL;

	tracer = find_bpf_tracer(SK_TRACER_NAME);
	if (tracer == NULL)
		return;

	if (tracer->state != TRACER_RUNNING)
		return;

	pthread_mutex_lock(&tracer->mutex_probes_lock);
	clear_python_probes_by_pid(tracer, pid);
	pthread_mutex_unlock(&tracer->mutex_probes_lock);
}

void python_events_handle(void)
{
	struct python_process_create_event *event = NULL;
	struct bpf_tracer *tracer = get_profiler_tracer();
	int count = 0;
	do {
		event = get_first_event();
		if (!event)
			break;

		if (get_sys_uptime() < event->expire_time)
			break;

		if (tracer) {
			pthread_mutex_lock(&tracer->mutex_probes_lock);
			python_parse_and_register(event->pid, tracer->tps);
			tracer_uprobes_update(tracer);
			tracer_hooks_process(tracer, HOOK_ATTACH, &count);
			pthread_mutex_unlock(&tracer->mutex_probes_lock);
		}

		remove_event(event);
		free(event);

	} while (true);
}
