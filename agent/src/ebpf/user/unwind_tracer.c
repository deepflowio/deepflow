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

#include "unwind_tracer.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/limits.h>
#include <linux/version.h>
#include <string.h>
#include <bcc/bcc_proc.h>
#include <bcc/bcc_elf.h>
#include <bcc/bcc_syms.h>
#include <regex.h>

#include "config.h"
#include "tracer.h"
#include "socket.h"
#include "proc.h"
#include "common.h"
#include "log.h"

#include "load.h"
#include "table.h"
#include "trace_utils.h"
#include "profile/perf_profiler.h"

extern int major, minor;

#define DWARF_KERNEL_CHECK                                                                         \
    do {                                                                                           \
        if (!(major > 5 || (major == 5 && minor >= 2))) {                                          \
            return;                                                                                \
        }                                                                                          \
    } while (0)

static proc_event_list_t proc_events = { .head = { .prev = &proc_events.head,
                                                   .next = &proc_events.head, },
                                         .m = PTHREAD_MUTEX_INITIALIZER };

static pthread_mutex_t g_unwind_table_lock = PTHREAD_MUTEX_INITIALIZER;
static unwind_table_t *g_unwind_table = NULL;

static int load_running_processes(struct bpf_tracer *tracer);

static bool g_dwarf_enabled = false;

static struct {
    pthread_mutex_t m;
    bool exists;
    regex_t regex;
} g_dwarf_regex = {
    .m = PTHREAD_MUTEX_INITIALIZER,
    .exists = false,
};

void set_dwarf_enabled(bool enabled) {
    DWARF_KERNEL_CHECK;

    if (g_dwarf_enabled == enabled) {
        return;
    }
    g_dwarf_enabled = enabled;
    ebpf_info(LOG_CP_TAG "%s dwarf unwinding.\n", enabled ? "Enabled" : "Disabled");

    if (!g_unwind_table) {
        return;
    }

    if (g_dwarf_enabled) {

        struct bpf_tracer *tracer = find_bpf_tracer(CP_TRACER_NAME);
        if (tracer == NULL) {
            return;
        }
        if (tracer->state != TRACER_RUNNING) {
            return;
        }
        load_running_processes(tracer);

    } else {
        pthread_mutex_lock(&g_unwind_table_lock);
        unwind_table_unload_all(g_unwind_table);
        pthread_mutex_unlock(&g_unwind_table_lock);
    }
}

int set_dwarf_regex(const char *pattern) {
    pthread_mutex_lock(&g_dwarf_regex.m);

    if (g_dwarf_regex.exists) {
        regfree(&g_dwarf_regex.regex);
    }

    if (*pattern == '\0') {
        if (g_dwarf_regex.exists) {
            ebpf_info("DWARF regex cleared, will use heuristic check");
            g_dwarf_regex.exists = false;
        }
        pthread_mutex_unlock(&g_dwarf_regex.m);
        return 0;
    }

    g_dwarf_regex.exists = false;

    int ret = regcomp(&g_dwarf_regex.regex, pattern, REG_EXTENDED);
    if (ret != 0) {
        char error_buffer[128];
        regerror(ret, &g_dwarf_regex.regex, error_buffer,
                 sizeof(error_buffer));
        ebpf_warning("DWARF regex %s is invalid: %s", pattern, error_buffer);
        pthread_mutex_unlock(&g_dwarf_regex.m);
        return -1;
    }

    ebpf_info("DWARF regex updated to /%s/", pattern);
    g_dwarf_regex.exists = true;
    pthread_mutex_unlock(&g_dwarf_regex.m);
    return 0;
}

static bool requires_dwarf_unwind_table(int pid) {
    if (!g_dwarf_enabled) {
        return false;
    }

    pthread_mutex_lock(&g_dwarf_regex.m);
    if (g_dwarf_regex.exists) {
        char *path = get_elf_path_by_pid(pid);
        if (path == NULL) {
            pthread_mutex_unlock(&g_dwarf_regex.m);
            return false;
        }
        char *exe_name = path + strlen(path) - 1;
        while (exe_name > path && *(exe_name - 1) != '/') {
            exe_name--;
        }
        bool matched = !regexec(&g_dwarf_regex.regex, exe_name, 0, NULL, 0);
        free(path);
        pthread_mutex_unlock(&g_dwarf_regex.m);
        return matched;
    }
    pthread_mutex_unlock(&g_dwarf_regex.m);

    return !frame_pointer_heuristic_check(pid);
}

static int load_running_processes(struct bpf_tracer *tracer) {
    struct dirent *entry = NULL;
    DIR *fddir = NULL;
    int pid = 0;

    // TODO: fix version check
    if (!kernel_version_check()) {
        ebpf_warning("Dwarf unwind requires kernel version 5.x\n");
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
        if (requires_dwarf_unwind_table(pid)) {
            add_event_to_proc_list(&proc_events, tracer, pid);
        }
    }

    closedir(fddir);
    return ETR_OK;
}

void unwind_tracer_init(struct bpf_tracer *tracer) {
    DWARF_KERNEL_CHECK;

    int32_t offset = read_offset_of_stack_in_task_struct();
    if (offset < 0) {
        ebpf_warning("unwind tracer init failed: failed to get field stack offset in task struct from btf");
        return;
    }
    if (!bpf_table_set_value(tracer, MAP_UNWIND_SYSINFO_NAME, 0, &offset)) {
        ebpf_warning("unwind tracer init failed: update %s error", MAP_UNWIND_SYSINFO_NAME);
        return;
    }

    struct ebpf_map *process_map =
        ebpf_obj__get_map_by_name(tracer->obj, MAP_PROCESS_SHARD_LIST_NAME);
    struct ebpf_map *shard_map =
        ebpf_obj__get_map_by_name(tracer->obj, MAP_UNWIND_ENTRY_SHARD_NAME);
    if (!process_map) {
        ebpf_warning("create unwind table failed: map %s not found", MAP_PROCESS_SHARD_LIST_NAME);
        return;
    }
    if (!shard_map) {
        ebpf_warning("create unwind table failed: map %s not found", MAP_UNWIND_ENTRY_SHARD_NAME);
        return;
    }

    unwind_table_t *table = unwind_table_create(process_map->fd, shard_map->fd);
    load_running_processes(tracer);
    pthread_mutex_lock(&g_unwind_table_lock);
    g_unwind_table = table;
    pthread_mutex_unlock(&g_unwind_table_lock);
}

void unwind_tracer_drop() {
    DWARF_KERNEL_CHECK;

    pthread_mutex_lock(&g_unwind_table_lock);
    if (g_unwind_table) {
        unwind_table_destroy(g_unwind_table);
        g_unwind_table = NULL;
    }
    pthread_mutex_unlock(&g_unwind_table_lock);
}

void unwind_process_exec(int pid) {
    DWARF_KERNEL_CHECK;

    struct bpf_tracer *tracer = find_bpf_tracer(CP_TRACER_NAME);
    if (tracer == NULL) {
        return;
    }

    if (tracer->state != TRACER_RUNNING) {
        return;
    }

    if (!requires_dwarf_unwind_table(pid)) {
        return;
    }

    add_event_to_proc_list(&proc_events, tracer, pid);
}

// Process events in the queue
void unwind_events_handle(void) {
    DWARF_KERNEL_CHECK;

    struct process_create_event *event = NULL;
    pthread_mutex_lock(&g_unwind_table_lock);
    do {
        event = get_first_event(&proc_events);
        if (!event)
            break;

        if (get_sys_uptime() < event->expire_time) {
            break;
        }

        if (g_dwarf_enabled && g_unwind_table) {
            unwind_table_load(g_unwind_table, event->pid);
        }

        remove_event(&proc_events, event);
        free(event);

    } while (true);
    pthread_mutex_unlock(&g_unwind_table_lock);
}

// Process exit, reclaim resources
void unwind_process_exit(int pid) {
    DWARF_KERNEL_CHECK;

    struct list_head *p, *n;
    struct process_create_event *e = NULL;
    pthread_mutex_lock(&proc_events.m);
    list_for_each_safe(p, n, &proc_events.head) {
        e = container_of(p, struct process_create_event, list);
        if (e->pid == pid) {
            list_head_del(&e->list);
            free(e);
        }
    }
    pthread_mutex_unlock(&proc_events.m);

    pthread_mutex_lock(&g_unwind_table_lock);
    if (g_unwind_table) {
        unwind_table_unload(g_unwind_table, pid);
    }
    pthread_mutex_unlock(&g_unwind_table_lock);
}
