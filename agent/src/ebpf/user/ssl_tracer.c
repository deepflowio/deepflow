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

#include "ssl_tracer.h"
#include "tracer.h"
#include "proc.h"
#include "socket.h"
#include "utils.h"
#include "log.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/limits.h>
#include <linux/version.h>
#include <string.h>

static proc_event_list_t proc_events;
static bool ssl_trace_enabled;

/* *INDENT-OFF* */
static struct symbol symbols[] = {
	{
		.type = OPENSSL_UPROBE,
		.symbol = "SSL_write",
		.probe_func = UPROBE_FUNC_NAME(openssl_write_enter),
		.is_probe_ret = false,
	},
	{
		.type = OPENSSL_UPROBE,
		.symbol = "SSL_write",
		.probe_func = UPROBE_FUNC_NAME(openssl_write_exit),
		.is_probe_ret = true,
	},
	{
		.type = OPENSSL_UPROBE,
		.symbol = "SSL_read",
		.probe_func = UPROBE_FUNC_NAME(openssl_read_enter),
		.is_probe_ret = false,
	},
	{
		.type = OPENSSL_UPROBE,
		.symbol = "SSL_read",
		.probe_func = UPROBE_FUNC_NAME(openssl_read_exit),
		.is_probe_ret = true,
	},
};
/* *INDENT-ON* */

static void openssl_parse_and_register(int pid, struct tracer_probes_conf *conf)
{
	char *path = NULL;
	int count = 0;

	if (pid <= 1)
		return;

	if (!is_user_process(pid))
		return;

	path = get_so_path_by_pid_and_name(pid, "ssl");
	if (!path) {
		path = get_elf_path_by_pid(pid);
		if (!path)
			return;
	}

	count = add_probe_sym_to_tracer_probes(pid, path, conf,
					       symbols, NELEMS(symbols));
	ebpf_info("openssl uprobes: pid:%d, path:%s, probes_count:%d\n",
		  pid, path, count);
	
	free(path);
}

static void clear_ssl_probes_by_pid(struct bpf_tracer *tracer, int pid)
{
	struct probe *probe;
	struct list_head *p, *n;
	struct symbol_uprobe *sym_uprobe;

	list_for_each_safe(p, n, &tracer->probes_head) {
		probe = container_of(p, struct probe, list);
		if (!(probe->type == UPROBE && probe->private_data != NULL))
			continue;
		sym_uprobe = probe->private_data;

		if (sym_uprobe->type != OPENSSL_UPROBE)
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

int collect_ssl_uprobe_syms_from_procfs(struct tracer_probes_conf *conf)
{
	struct dirent *entry = NULL;
	DIR *fddir = NULL;
	int pid = 0;
	char *path = NULL;

	if (!is_feature_enabled(FEATURE_UPROBE_OPENSSL))
		return ETR_OK;

	if (!kernel_version_check()) {
		ebpf_warning
		    ("Uprobe openssl requires Linux version 4.17+ or Linux 3.10.0\n");
		return ETR_OK;
	}

	fddir = opendir("/proc/");
	if (!fddir) {
		ebpf_warning("Failed to open %s.\n");
		return ETR_PROC_FAIL;
	}

	while ((entry = readdir(fddir))) {
		if (entry->d_type != DT_DIR)
			continue;
		pid = atoi(entry->d_name);
		if (!process_probing_check(pid))
			continue;
		path = get_elf_path_by_pid(pid);
		if (is_feature_matched(FEATURE_UPROBE_OPENSSL, pid, path)) {
			openssl_parse_and_register(pid, conf);
		}
		free(path);
	}

	closedir(fddir);
	return ETR_OK;
}

void ssl_process_exec(int pid)
{
	struct bpf_tracer *tracer = NULL;
	char *path = NULL;
	int matched = false;
	if (!kernel_version_check())
		return;
	path = get_elf_path_by_pid(pid);
	matched = is_feature_matched(FEATURE_UPROBE_OPENSSL, pid, path);
	free(path);
	if (!matched)
		return;

	tracer = find_bpf_tracer(SK_TRACER_NAME);
	if (tracer == NULL)
		return;

	if (tracer->probes_count > OPEN_FILES_MAX) {
		ebpf_warning("Probes count too many. The maximum is %d\n",
			     OPEN_FILES_MAX);
		return;
	}

	add_event_to_proc_list(&proc_events, tracer, pid, NULL);
}

void ssl_process_exit(int pid)
{
	struct bpf_tracer *tracer = NULL;

	if (!is_feature_enabled(FEATURE_UPROBE_OPENSSL))
		return;

	if (!kernel_version_check())
		return;

	tracer = find_bpf_tracer(SK_TRACER_NAME);
	if (tracer == NULL)
		return;

	pthread_mutex_lock(&tracer->mutex_probes_lock);
	clear_ssl_probes_by_pid(tracer, pid);
	pthread_mutex_unlock(&tracer->mutex_probes_lock);
}

void ssl_events_handle(void)
{
	struct process_create_event *event = NULL;
	struct bpf_tracer *tracer = NULL;
	int count = 0;
	do {
		event = get_first_event(&proc_events);
		if (!event)
			break;

		if (get_sys_uptime() < event->expire_time)
			break;

		if (event->stime != get_process_starttime(event->pid))
			goto next;

		tracer = event->tracer;
		if (tracer) {
			pthread_mutex_lock(&tracer->mutex_probes_lock);
			openssl_parse_and_register(event->pid, tracer->tps);
			tracer_uprobes_update(tracer);
			tracer_hooks_process(tracer, HOOK_ATTACH, &count);
			pthread_mutex_unlock(&tracer->mutex_probes_lock);
		}

	next:
		remove_event(&proc_events, event);
		process_event_free(event);

	} while (true);
}

void openssl_trace_handle(int pid, enum match_pids_act act)
{
	if (act == MATCH_PID_ADD) {
		ssl_process_exec(pid);
	} else {
		ssl_process_exit(pid);
	}
}

void openssl_trace_init(void)
{
	init_list_head(&proc_events.head);
	pthread_mutex_init(&proc_events.m, NULL);
}

void set_uprobe_openssl_enabled(bool enabled)
{
	ssl_trace_enabled = enabled;
}

bool is_openssl_trace_enabled(void)
{
	return ssl_trace_enabled;
}
