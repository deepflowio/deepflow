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
#include "utils.h"
#include "log.h"

#include "load.h"
#include "table.h"
#include "tracer.h"
#include "extended/extended.h"
#include "profile/perf_profiler.h"

#include "trace_utils.h"

extern int major, minor;

bool dwarf_available(void) { return major > 5 || (major == 5 && minor >= 2); }

static proc_event_list_t proc_events = { .head = { .prev = &proc_events.head, .next = &proc_events.head, },
                                         .m = PTHREAD_MUTEX_INITIALIZER };

static pthread_mutex_t g_unwind_table_lock = PTHREAD_MUTEX_INITIALIZER;
static unwind_table_t *g_unwind_table = NULL;

static struct {
    bool dwarf_enabled;
    struct {
        pthread_mutex_t m;
        bool exists;
        regex_t regex;
    } dwarf_regex;
    int dwarf_process_map_size;
    int dwarf_shard_map_size;
} g_unwind_config = { .dwarf_enabled = false,
                      .dwarf_regex = { .m = PTHREAD_MUTEX_INITIALIZER, .exists = false, },
                      .dwarf_process_map_size = 1024,
                      .dwarf_shard_map_size = 128, };

bool get_dwarf_enabled(void) { return g_unwind_config.dwarf_enabled; }

void set_dwarf_enabled(bool enabled) {
    if (!dwarf_available()) {
        return;
    }

    if (g_unwind_config.dwarf_enabled == enabled) {
        return;
    }
    g_unwind_config.dwarf_enabled = enabled;
    ebpf_info(LOG_CP_TAG "%s DWARF unwinding.\n", enabled ? "Enabled" : "Disabled");

    if (!g_unwind_table) {
        return;
    }

    if (g_unwind_config.dwarf_enabled) {
        unwind_process_reload();
    } else {
        pthread_mutex_lock(&g_unwind_table_lock);
        unwind_table_unload_all(g_unwind_table);
        pthread_mutex_unlock(&g_unwind_table_lock);
    }
}

int set_dwarf_regex(const char *pattern) {
    pthread_mutex_lock(&g_unwind_config.dwarf_regex.m);

    if (g_unwind_config.dwarf_regex.exists) {
        regfree(&g_unwind_config.dwarf_regex.regex);
    }

    if (*pattern == '\0') {
        if (g_unwind_config.dwarf_regex.exists) {
            ebpf_info("DWARF regex cleared, will use heuristic check");
            g_unwind_config.dwarf_regex.exists = false;
        }
        pthread_mutex_unlock(&g_unwind_config.dwarf_regex.m);
        return 0;
    }

    g_unwind_config.dwarf_regex.exists = false;

    int ret = regcomp(&g_unwind_config.dwarf_regex.regex, pattern, REG_EXTENDED);
    if (ret != 0) {
        char error_buffer[128];
        regerror(ret, &g_unwind_config.dwarf_regex.regex, error_buffer, sizeof(error_buffer));
        ebpf_warning("DWARF regex %s is invalid: %s", pattern, error_buffer);
        pthread_mutex_unlock(&g_unwind_config.dwarf_regex.m);
        return -1;
    }

    ebpf_info("DWARF regex updated to /%s/", pattern);
    g_unwind_config.dwarf_regex.exists = true;
    pthread_mutex_unlock(&g_unwind_config.dwarf_regex.m);

    unwind_process_reload();

    return 0;
}

int get_dwarf_process_map_size(void) { return g_unwind_config.dwarf_process_map_size; }

void set_dwarf_process_map_size(int size) {
    if (g_unwind_config.dwarf_process_map_size == size) {
        return;
    }
    g_unwind_config.dwarf_process_map_size = size;
    ebpf_info(LOG_CP_TAG "DWARF process map size set to %d.\n", size);
}

int get_dwarf_shard_map_size(void) { return g_unwind_config.dwarf_shard_map_size; }

void set_dwarf_shard_map_size(int size) {
    if (g_unwind_config.dwarf_shard_map_size == size) {
        return;
    }
    g_unwind_config.dwarf_shard_map_size = size;
    ebpf_info(LOG_CP_TAG "DWARF shard map size set to %d.\n", size);
}

static bool requires_dwarf_unwind_table(int pid) {
    if (!get_dwarf_enabled()) {
        return false;
    }

    if (is_pid_match(FEATURE_DWARF_UNWINDING, pid)) {
        return true;
    }

    char *path = get_elf_path_by_pid(pid);
    if (path == NULL) {
        return false;
    }

    bool need_unwind = is_pid_match(FEATURE_PROFILE_ONCPU, pid) || is_pid_match(FEATURE_PROFILE_OFFCPU, pid) ||
                       is_pid_match(FEATURE_PROFILE_MEMORY, pid);
    if (!need_unwind) {
        free(path);
        return false;
    }

    char *exe_name = basename(path);
    // Java has JIT compiled code without DWARF info, not supported at the moment
    if (strcmp(exe_name, "java") == 0) {
        free(path);
        return false;
    }

    pthread_mutex_lock(&g_unwind_config.dwarf_regex.m);
    if (g_unwind_config.dwarf_regex.exists) {
        bool matched = !regexec(&g_unwind_config.dwarf_regex.regex, exe_name, 0, NULL, 0);
        pthread_mutex_unlock(&g_unwind_config.dwarf_regex.m);
        free(path);
        return matched;
    }
    pthread_mutex_unlock(&g_unwind_config.dwarf_regex.m);
    free(path);

    return !frame_pointer_heuristic_check(pid);
}

int unwind_tracer_init(struct bpf_tracer *tracer) {
    int32_t offset = read_offset_of_stack_in_task_struct();
    if (offset < 0) {
        ebpf_warning("unwind tracer init: failed to get field stack offset in task struct from btf");
        ebpf_warning("unwinder may not handle in kernel perf events correctly");
    } else if (!bpf_table_set_value(tracer, MAP_UNWIND_SYSINFO_NAME, 0, &offset)) {
        ebpf_warning("unwind tracer init: update %s error", MAP_UNWIND_SYSINFO_NAME);
        ebpf_warning("unwinder may not handle in kernel perf events correctly");
    }

    int process_map_fd = bpf_table_get_fd(tracer, MAP_PROCESS_SHARD_LIST_NAME);
    int shard_map_fd = bpf_table_get_fd(tracer, MAP_UNWIND_ENTRY_SHARD_NAME);
    if (process_map_fd < 0) {
        ebpf_warning("create unwind table failed: map %s not found", MAP_PROCESS_SHARD_LIST_NAME);
        return -1;
    }
    if (shard_map_fd < 0) {
        ebpf_warning("create unwind table failed: map %s not found", MAP_UNWIND_ENTRY_SHARD_NAME);
        return -1;
    }

    unwind_table_t *table = unwind_table_create(process_map_fd, shard_map_fd);
    pthread_mutex_lock(&g_unwind_table_lock);
    g_unwind_table = table;
    pthread_mutex_unlock(&g_unwind_table_lock);

    return 0;
}

void unwind_tracer_drop() {
    pthread_mutex_lock(&g_unwind_table_lock);
    if (g_unwind_table) {
        unwind_table_unload_all(g_unwind_table);
        unwind_table_destroy(g_unwind_table);
        g_unwind_table = NULL;
    }
    pthread_mutex_unlock(&g_unwind_table_lock);
}

void unwind_process_exec(int pid) {
    if (!dwarf_available() || !get_dwarf_enabled()) {
        return;
    }

    // Enterprise hook for interpreter processing
    extended_process_exec(pid);

    struct bpf_tracer *tracer = find_bpf_tracer(CP_TRACER_NAME);
    if (tracer == NULL || tracer->state != TRACER_RUNNING) {
        return;
    }

    add_event_to_proc_list(&proc_events, tracer, pid, NULL);
}

// Process events in the queue
void unwind_events_handle(void) {
    if (!dwarf_available() || !get_dwarf_enabled()) {
        return;
    }

    struct process_create_event *event = NULL;
    pthread_mutex_lock(&g_unwind_table_lock);
    do {
        event = get_first_event(&proc_events);
        if (!event)
            break;

        if (get_sys_uptime() < event->expire_time) {
            break;
        }

        if (g_unwind_table && requires_dwarf_unwind_table(event->pid)) {
            unwind_table_load(g_unwind_table, event->pid);
        }

        remove_event(&proc_events, event);
        process_event_free(event);

    } while (true);
    pthread_mutex_unlock(&g_unwind_table_lock);
}

// Process exit, reclaim resources
void unwind_process_exit(int pid) {
    if (!dwarf_available() || !get_dwarf_enabled()) {
        return;
    }

    // Enterprise hook
    extended_process_exit(pid);

    struct bpf_tracer *tracer = find_bpf_tracer(CP_TRACER_NAME);
    if (tracer == NULL || tracer->state != TRACER_RUNNING) {
        return;
    }

    struct list_head *p, *n;
    struct process_create_event *e = NULL;
    pthread_mutex_lock(&proc_events.m);
    list_for_each_safe(p, n, &proc_events.head) {
        e = container_of(p, struct process_create_event, list);
        if (e->pid == pid) {
            list_head_del(&e->list);
            process_event_free(e);
        }
    }
    pthread_mutex_unlock(&proc_events.m);

    pthread_mutex_lock(&g_unwind_table_lock);
    if (g_unwind_table) {
        unwind_table_unload(g_unwind_table, pid);
    }
    pthread_mutex_unlock(&g_unwind_table_lock);
}

// Ensure exclusive access to *unwind_table before calling this function
static int load_running_processes(struct bpf_tracer *tracer, unwind_table_t *unwind_table) {
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

        extended_process_exec(pid);

        if (requires_dwarf_unwind_table(pid)) {
            unwind_table_load(unwind_table, pid);
        }
    }

    closedir(fddir);
    return ETR_OK;
}

void unwind_process_reload() {
    if (!dwarf_available() || !get_dwarf_enabled()) {
        return;
    }

    struct bpf_tracer *tracer = find_bpf_tracer(CP_TRACER_NAME);
    if (tracer == NULL || tracer->state != TRACER_RUNNING) {
        return;
    }

    pthread_mutex_lock(&g_unwind_table_lock);
    if (g_unwind_table) {
        // Unload everything for the moment
        // Maybe preserve some data on regex changes
        unwind_table_unload_all(g_unwind_table);
        load_running_processes(tracer, g_unwind_table);
    }
    pthread_mutex_unlock(&g_unwind_table_lock);
}
