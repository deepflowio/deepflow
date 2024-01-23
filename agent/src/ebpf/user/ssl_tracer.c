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

extern uint32_t k_version;

struct ssl_process_create_event {
	struct list_head list;
	int pid;
	uint32_t expire_time;
	struct bpf_tracer *tracer;
};

static struct list_head proc_events_list;
static pthread_mutex_t proc_events_list_mutex;

static struct symbol openssl_syms[] = {
	{
		.type = OPENSSL_UPROBE,
		.symbol = "SSL_write",
		.probe_func = "uprobe_openssl_write_enter",
		.is_probe_ret = false,
	},
	{
		.type = OPENSSL_UPROBE,
		.symbol = "SSL_write",
		.probe_func = "uprobe_openssl_write_exit",
		.is_probe_ret = true,
	},
	{
		.type = OPENSSL_UPROBE,
		.symbol = "SSL_read",
		.probe_func = "uprobe_openssl_read_enter",
		.is_probe_ret = false,
	},
	{
		.type = OPENSSL_UPROBE,
		.symbol = "SSL_read",
		.probe_func = "uprobe_openssl_read_exit",
		.is_probe_ret = true,
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

struct bcc_elf_foreach_sym_payload {
	uint64_t addr;
	uint64_t size;
	const char *name;
};

// Lower version kernels do not support hooking so files in containers
static inline bool openssl_kern_check(void)
{
	return ((k_version == KERNEL_VERSION(3, 10, 0))
	    || (k_version >= KERNEL_VERSION(4, 17, 0)));
}

static inline bool openssl_process_check(int pid)
{
	char c_id[65];
	memset(c_id, 0, sizeof(c_id));
	// Linux 3.10.0 kernel does not support probing files in containers.
	if ((k_version == KERNEL_VERSION(3, 10, 0)) &&
	    (fetch_container_id(pid, c_id, sizeof(c_id)) == 0))
		return false;

	return true;
}

static int bcc_elf_foreach_sym_callback(const char *name, uint64_t addr,
					uint64_t size, void *payload)
{
	struct bcc_elf_foreach_sym_payload *p = payload;
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
	struct bcc_elf_foreach_sym_payload payload;

	for (idx = 0; idx < NELEMS(openssl_syms); ++idx) {
		memset(&payload, 0, sizeof(payload));
		cur = &openssl_syms[idx];

		// Use memory on the stack, no need to allocate on the heap
		payload.name = cur->symbol;
		ret = bcc_elf_foreach_sym(path, bcc_elf_foreach_sym_callback,
					  &bcc_elf_foreach_sym_option,
					  &payload);
		if (ret)
			break;

		// It has been confirmed earlier that the incoming binary file
		// must be libssl.so and should not be hit here
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

// https://github.com/iovisor/bcc/blob/15fccdb9a4dbdc3d41e669a7ad5be73d2ac44b00/src/cc/bcc_proc.c#L419
static int which_so_in_process(const char *libname, int pid, char *libpath)
{
	int ret, found = 0;
	char endline[4096], *mapname = NULL, *newline;
	char mappings_file[128];
	const size_t search_len = strlen(libname) + strlen("/lib.");
	char search1[search_len + 1];
	char search2[search_len + 1];

	snprintf(mappings_file, sizeof(mappings_file), "/proc/%ld/maps",
		 (long)pid);
	FILE *fp = fopen(mappings_file, "r");
	if (!fp)
		return found;

	snprintf(search1, search_len + 1, "/lib%s.", libname);
	snprintf(search2, search_len + 1, "/lib%s-", libname);

	do {
		ret = fscanf(fp, "%*x-%*x %*s %*x %*s %*d");
		if (!fgets(endline, sizeof(endline), fp))
			break;

		mapname = endline;
		newline = strchr(endline, '\n');
		if (newline)
			newline[0] = '\0';

		while (isspace(mapname[0]))
			mapname++;

		if (strstr(mapname, ".so") &&
		    (strstr(mapname, search1) || strstr(mapname, search2))) {
			found = 1;
			memcpy(libpath, mapname, strlen(mapname) + 1);
			break;
		}
	} while (ret != EOF);

	fclose(fp);
	return found;
}

static char *get_openssl_so_path_by_pid(int pid)
{
	int ret = 0;
	char so_path[PATH_MAX] = { 0 };

	int offset = snprintf(so_path, sizeof(so_path), "/proc/%d/root", pid);
	if (offset < 0 || offset >= sizeof(so_path))
		return NULL;

	ret = which_so_in_process("ssl", pid, so_path + offset);
	if (!ret)
		return NULL;
	return strdup(so_path);
}

static void openssl_parse_and_register(int pid, struct tracer_probes_conf *conf)
{
	char *path = NULL;

	if (pid <= 1)
		goto out;

	if (!is_user_process(pid))
		goto out;

	path = get_openssl_so_path_by_pid(pid);
	if (!path)
		goto out;

	ebpf_info("openssl uprobe, pid:%d, path:%s\n", pid, path);
	add_probe_sym_to_tracer_probes(pid, path, conf);

out:
	free(path);
	return;
}

static void clear_ssl_probes_by_pid(struct bpf_tracer *tracer, int pid)
{
	struct probe *probe;
	struct list_head *p, *n;
	struct symbol_uprobe *sym_uprobe;

	list_for_each_safe (p, n, &tracer->probes_head) {
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

static void add_event_to_proc_list(struct bpf_tracer *tracer, int pid)
{
	static const uint32_t PROC_EVENT_HANDLE_DELAY = 120;
	struct ssl_process_create_event *event = NULL;

	event = calloc(1, sizeof(struct ssl_process_create_event));
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

static struct ssl_process_create_event *get_first_event(void)
{
	struct ssl_process_create_event *event = NULL;
	pthread_mutex_lock(&proc_events_list_mutex);
	if (!list_empty(&proc_events_list)) {
		event = list_first_entry(&proc_events_list,
					 struct ssl_process_create_event, list);
	}
	pthread_mutex_unlock(&proc_events_list_mutex);
	return event;
}

static void remove_event(struct ssl_process_create_event *event)
{
	pthread_mutex_lock(&proc_events_list_mutex);
	list_head_del(&event->list);
	pthread_mutex_unlock(&proc_events_list_mutex);
}

int collect_ssl_uprobe_syms_from_procfs(struct tracer_probes_conf *conf)
{
	struct dirent *entry = NULL;
	DIR *fddir = NULL;
	int pid = 0;
	char *path = NULL;

	if (!is_feature_enabled(FEATURE_UPROBE_OPENSSL))
		return ETR_OK;

	if (!openssl_kern_check()) {
		ebpf_warning("Uprobe openssl requires Linux version 4.17+ or Linux 3.10.0\n");
		return ETR_OK;
	}

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
		if (!openssl_process_check(pid))
			continue;
		path = get_elf_path_by_pid(pid);
		if (is_feature_matched(FEATURE_UPROBE_OPENSSL, path)) {
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
	if (!openssl_kern_check())
		return;
	path = get_elf_path_by_pid(pid);
	matched = is_feature_matched(FEATURE_UPROBE_OPENSSL, path);
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

void ssl_process_exit(int pid)
{
	struct bpf_tracer *tracer = NULL;

	if (!is_feature_enabled(FEATURE_UPROBE_OPENSSL))
		return;

	if (!openssl_kern_check())
		return;

	tracer = find_bpf_tracer(SK_TRACER_NAME);
	if (tracer == NULL)
		return;

	if (tracer->state != TRACER_RUNNING)
		return;

	pthread_mutex_lock(&tracer->mutex_probes_lock);
	clear_ssl_probes_by_pid(tracer, pid);
	pthread_mutex_unlock(&tracer->mutex_probes_lock);
}

void ssl_events_handle(void)
{
	struct ssl_process_create_event *event = NULL;
	struct bpf_tracer *tracer = NULL;
	int count = 0;
	do {
		event = get_first_event();
		if (!event)
			break;

		if (get_sys_uptime() < event->expire_time)
			break;

		tracer = event->tracer;
		if (tracer) {
			pthread_mutex_lock(&tracer->mutex_probes_lock);
			openssl_parse_and_register(event->pid, tracer->tps);
			tracer_uprobes_update(tracer);
			tracer_hooks_process(tracer, HOOK_ATTACH, &count);
			pthread_mutex_unlock(&tracer->mutex_probes_lock);
		}

		remove_event(event);
		free(event);

	} while (true);
}
