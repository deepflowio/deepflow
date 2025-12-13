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

static pthread_mutex_t g_python_unwind_table_lock = PTHREAD_MUTEX_INITIALIZER;
static python_unwind_table_t *g_python_unwind_table = NULL;

static pthread_mutex_t g_lua_unwind_table_lock = PTHREAD_MUTEX_INITIALIZER;
static lua_unwind_table_t *g_lua_unwind_table = NULL;
static void lua_queue_existing_processes(struct bpf_tracer *tracer);

static struct symbol lua_symbols[] = {
    {
        .type = LUA_UPROBE,
        .symbol = "lua_resume",
        .symbol_prefix = NULL,
        .probe_func = UPROBE_FUNC_NAME(handle_entry_lua),
        .is_probe_ret = false,
    },
    {
        .type = LUA_UPROBE,
        .symbol = "lua_pcall",
        .symbol_prefix = NULL,
        .probe_func = UPROBE_FUNC_NAME(handle_entry_lua),
        .is_probe_ret = false,
    },
    {
        .type = LUA_UPROBE,
        .symbol = "lua_pcallk",
        .symbol_prefix = NULL,
        .probe_func = UPROBE_FUNC_NAME(handle_entry_lua),
        .is_probe_ret = false,
    },
    {
        .type = LUA_UPROBE,
        .symbol = "lua_yield",
        .symbol_prefix = NULL,
        .probe_func = URETPROBE_FUNC_NAME(handle_entry_lua_cancel),
        .is_probe_ret = false,
    },
    {
        .type = LUA_UPROBE,
        .symbol = "lua_yieldk",
        .symbol_prefix = NULL,
        .probe_func = URETPROBE_FUNC_NAME(handle_entry_lua_cancel),
        .is_probe_ret = false,
    },
};

static pthread_mutex_t g_php_unwind_table_lock = PTHREAD_MUTEX_INITIALIZER;
static php_unwind_table_t *g_php_unwind_table = NULL;

static pthread_mutex_t g_v8_unwind_table_lock = PTHREAD_MUTEX_INITIALIZER;
static v8_unwind_table_t *g_v8_unwind_table = NULL;

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

    // Initialize Python unwinding tables (only if enabled)
    if (python_profiler_enabled()) {
        int unwind_info_map_fd = bpf_table_get_fd(tracer, MAP_PYTHON_UNWIND_INFO_NAME);
        int offsets_map_fd = bpf_table_get_fd(tracer, MAP_PYTHON_OFFSETS_NAME);
        if (unwind_info_map_fd < 0 || offsets_map_fd < 0) {
            ebpf_warning("Failed to get Python unwind info map fd or offsets map fd\n");
            return -1;
        }
        python_unwind_table_t *python_table = python_unwind_table_create(unwind_info_map_fd, offsets_map_fd);
        pthread_mutex_lock(&g_python_unwind_table_lock);
        g_python_unwind_table = python_table;
        pthread_mutex_unlock(&g_python_unwind_table_lock);
    }

    // Initialize PHP unwinding tables (only if enabled)
    if (php_profiler_enabled()) {
        int php_unwind_info_map_fd = bpf_table_get_fd(tracer, MAP_PHP_UNWIND_INFO_NAME);
        int php_offsets_map_fd = bpf_table_get_fd(tracer, MAP_PHP_OFFSETS_NAME);
        if (php_unwind_info_map_fd < 0 || php_offsets_map_fd < 0) {
            ebpf_warning("Failed to get PHP unwind info map fd or offsets map fd\n");
            return -1;
        }
        php_unwind_table_t *php_table = php_unwind_table_create(php_unwind_info_map_fd, php_offsets_map_fd);
        pthread_mutex_lock(&g_php_unwind_table_lock);
        g_php_unwind_table = php_table;
        pthread_mutex_unlock(&g_php_unwind_table_lock);
    }

    // Initialize V8 unwinding tables (only if enabled)
    if (v8_profiler_enabled()) {
        int v8_unwind_info_map_fd = bpf_table_get_fd(tracer, MAP_V8_UNWIND_INFO_NAME);
        if (v8_unwind_info_map_fd < 0) {
            ebpf_warning("Failed to get V8 unwind info map fd\n");
            return -1;
        }
        v8_unwind_table_t *v8_table = v8_unwind_table_create(v8_unwind_info_map_fd);
        pthread_mutex_lock(&g_v8_unwind_table_lock);
        g_v8_unwind_table = v8_table;
        pthread_mutex_unlock(&g_v8_unwind_table_lock);
    }

    int lua_lang_fd = bpf_table_get_fd(tracer, MAP_LUA_LANG_FLAGS_NAME);
    int lua_unwind_info_fd = bpf_table_get_fd(tracer, MAP_LUA_UNWIND_INFO_NAME);
    int lua_offsets_fd = bpf_table_get_fd(tracer, MAP_LUA_OFFSETS_NAME);
    int luajit_offsets_fd = bpf_table_get_fd(tracer, MAP_LUAJIT_OFFSETS_NAME);

    if (lua_lang_fd < 0 || lua_unwind_info_fd < 0 || lua_offsets_fd < 0 || luajit_offsets_fd < 0) {
        ebpf_warning("Failed to get lua profiling map fds (lang:%d unwind:%d lua_ofs:%d lj_ofs:%d)\n",
                     lua_lang_fd, lua_unwind_info_fd, lua_offsets_fd, luajit_offsets_fd);
        return -1;
    }

    lua_unwind_table_t *lua_table =
        lua_unwind_table_create(lua_lang_fd, lua_unwind_info_fd, lua_offsets_fd, luajit_offsets_fd);
    if (lua_table == NULL) {
        ebpf_warning("Failed to create lua unwind table\n");
        return -1;
    }
    lua_set_map_fds(lua_lang_fd, lua_unwind_info_fd, lua_offsets_fd, luajit_offsets_fd);

    pthread_mutex_lock(&g_lua_unwind_table_lock);
    g_lua_unwind_table = lua_table;
    pthread_mutex_unlock(&g_lua_unwind_table_lock);

	if (dwarf_available() && get_dwarf_enabled() && tracer) {
		lua_queue_existing_processes(tracer);
	}

    return 0;
}

static struct symbol python_symbols[] = { { .type = PYTHON_UPROBE,
                                            .symbol = "PyEval_SaveThread",
                                            .probe_func = URETPROBE_FUNC_NAME(python_save_tstate_addr),
                                            .is_probe_ret = true, }, };

static void python_parse_and_register(int pid, struct tracer_probes_conf *conf) {
    char *path = NULL;
    int n = 0;

    if (pid <= 1)
        goto out;

    if (!is_user_process(pid))
        goto out;

    // Python symbols may reside in the main executable or libpython.so
    // Check both
    path = get_elf_path_by_pid(pid);
    if (path) {
        n = add_probe_sym_to_tracer_probes(pid, path, conf, python_symbols, NELEMS(python_symbols));
        if (n > 0) {
            ebpf_info("python uprobe, pid:%d, path:%s\n", pid, path);
            free(path);
            return;
        }
    }

    path = get_so_path_by_pid_and_name(pid, "python3");
    if (!path) {
        path = get_so_path_by_pid_and_name(pid, "python2");
        if (!path) {
            goto out;
        }
    }

    ebpf_info("python uprobe, pid:%d, path:%s\n", pid, path);
    add_probe_sym_to_tracer_probes(pid, path, conf, python_symbols, NELEMS(python_symbols));

out:
    free(path);
    return;
}

static void lua_parse_and_register(int pid, struct tracer_probes_conf *conf) {
    lua_runtime_info_t info = {0};
    char path[sizeof(info.path)] = {0};
    int n = 0;

    if (pid <= 1) {
        return;
    }

    if (!is_user_process(pid)) {
        return;
    }

    if (lua_detect(pid, &info) != 0) {
        return;
    }

    if (info.kind == 0 || info.path[0] == '\0') {
        return;
    }

    size_t len = strnlen((const char *)info.path, sizeof(info.path));
    if (len == 0) {
        return;
    }

    if (len >= sizeof(path)) {
        len = sizeof(path) - 1;
    }
    memcpy(path, info.path, len);
    path[len] = '\0';

    n = add_probe_sym_to_tracer_probes(pid, path, conf, lua_symbols, NELEMS(lua_symbols));
    if (n > 0) {
        ebpf_info("A lua %d uprobe, pid:%d, path:%s\n", n, pid, path);
    }
}

static void lua_queue_existing_processes(struct bpf_tracer *tracer)
{
	DIR *dir = NULL;
	struct dirent *entry = NULL;
	if (tracer == NULL || tracer->state != TRACER_RUNNING) {
		return;
	}

	dir = opendir("/proc");
	if (!dir) {
		ebpf_warning("Failed to open /proc when queuing existing lua processes.\n");
		return;
	}

	while ((entry = readdir(dir))) {
		if (entry->d_type != DT_DIR) {
			continue;
		}

		int pid = atoi(entry->d_name);
		if (pid <= 1) {
			continue;
		}

		if (!process_probing_check(pid)) {
			continue;
		}

		if (!is_lua_process(pid)) {
			continue;
		}

		add_event_to_proc_list(&proc_events, tracer, pid, NULL);
	}

	closedir(dir);
}

static void clear_lua_probes_by_pid(struct bpf_tracer *tracer, int pid)
{
	struct probe *probe;
	struct list_head *p, *n;
	struct symbol_uprobe *sym_uprobe;

	if (tracer == NULL) {
		return;
	}

	list_for_each_safe(p, n, &tracer->probes_head) {
		probe = container_of(p, struct probe, list);
		if (!(probe->type == UPROBE && probe->private_data != NULL)) {
			continue;
		}
		sym_uprobe = probe->private_data;

		if (sym_uprobe->type != LUA_UPROBE) {
			continue;
		}

		if (sym_uprobe->pid != pid) {
			continue;
		}

		if (probe_detach(probe) != 0) {
			ebpf_warning("path:%s, symbol name:%s probe_detach() failed.\n",
				     sym_uprobe->binary_path, sym_uprobe->name);
		}

		free_probe_from_tracer(probe);
	}
}

void unwind_tracer_drop() {
    pthread_mutex_lock(&g_unwind_table_lock);
    if (g_unwind_table) {
        unwind_table_unload_all(g_unwind_table);
        unwind_table_destroy(g_unwind_table);
        g_unwind_table = NULL;
    }
    pthread_mutex_unlock(&g_unwind_table_lock);

    pthread_mutex_lock(&g_python_unwind_table_lock);
    if (g_python_unwind_table) {
        python_unwind_table_destroy(g_python_unwind_table);
        g_python_unwind_table = NULL;
    }
    pthread_mutex_unlock(&g_python_unwind_table_lock);

    pthread_mutex_lock(&g_lua_unwind_table_lock);
    if (g_lua_unwind_table) {
        lua_unwind_table_destroy(g_lua_unwind_table);
        g_lua_unwind_table = NULL;
    }
    pthread_mutex_unlock(&g_lua_unwind_table_lock);

    pthread_mutex_lock(&g_php_unwind_table_lock);
    if (g_php_unwind_table) {
        php_unwind_table_destroy(g_php_unwind_table);
        g_php_unwind_table = NULL;
    }
    pthread_mutex_unlock(&g_php_unwind_table_lock);

    pthread_mutex_lock(&g_v8_unwind_table_lock);
    if (g_v8_unwind_table) {
        v8_unwind_table_destroy(g_v8_unwind_table);
        g_v8_unwind_table = NULL;
    }
    pthread_mutex_unlock(&g_v8_unwind_table_lock);
}

void unwind_process_exec(int pid) {
    if (!dwarf_available() || !get_dwarf_enabled()) {
        return;
    }

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
    struct bpf_tracer *tracer = NULL;
    int count = 0;
    pthread_mutex_lock(&g_unwind_table_lock);
    pthread_mutex_lock(&g_python_unwind_table_lock);
    pthread_mutex_lock(&g_lua_unwind_table_lock);
    pthread_mutex_lock(&g_php_unwind_table_lock);
    pthread_mutex_lock(&g_v8_unwind_table_lock);
    do {
        event = get_first_event(&proc_events);
        if (!event)
            break;

        if (get_sys_uptime() < event->expire_time) {
            break;
        }

        tracer = event->tracer;
        if (tracer && python_profiler_enabled() && is_python_process(event->pid)) {
            python_unwind_table_load(g_python_unwind_table, event->pid);
            pthread_mutex_lock(&tracer->mutex_probes_lock);
            python_parse_and_register(event->pid, tracer->tps);
            tracer_uprobes_update(tracer);
            tracer_hooks_process(tracer, HOOK_ATTACH, &count);
            pthread_mutex_unlock(&tracer->mutex_probes_lock);
        }

        if (tracer && php_profiler_enabled() && is_php_process(event->pid)) {
            php_unwind_table_load(g_php_unwind_table, event->pid);
            // Note: PHP profiling doesn't require uprobe registration like Python
        }

        if (tracer && v8_profiler_enabled() && is_v8_process(event->pid)) {
            v8_unwind_table_load(g_v8_unwind_table, event->pid);
            // Note: V8 profiling doesn't require uprobe registration like Python
        }

        if (tracer && is_lua_process(event->pid)) {
            if (g_lua_unwind_table) {
                lua_unwind_table_load(g_lua_unwind_table, event->pid);
            }
            pthread_mutex_lock(&tracer->mutex_probes_lock);
            lua_parse_and_register(event->pid, tracer->tps);
            tracer_uprobes_update(tracer);
            tracer_hooks_process(tracer, HOOK_ATTACH, &count);
            pthread_mutex_unlock(&tracer->mutex_probes_lock);
        }

        if (g_unwind_table && requires_dwarf_unwind_table(event->pid)) {
            unwind_table_load(g_unwind_table, event->pid);
        }

        remove_event(&proc_events, event);
        process_event_free(event);

    } while (true);
    pthread_mutex_unlock(&g_v8_unwind_table_lock);
    pthread_mutex_unlock(&g_php_unwind_table_lock);
    pthread_mutex_unlock(&g_lua_unwind_table_lock);
    pthread_mutex_unlock(&g_python_unwind_table_lock);
    pthread_mutex_unlock(&g_unwind_table_lock);
}

// Process exit, reclaim resources
void unwind_process_exit(int pid) {
    if (!dwarf_available() || !get_dwarf_enabled()) {
        return;
    }

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

    pthread_mutex_lock(&g_python_unwind_table_lock);
    if (g_python_unwind_table) {
        python_unwind_table_unload(g_python_unwind_table, pid);
    }
    pthread_mutex_unlock(&g_python_unwind_table_lock);

    pthread_mutex_lock(&g_lua_unwind_table_lock);
    if (g_lua_unwind_table) {
        lua_unwind_table_unload(g_lua_unwind_table, pid);
    }
    pthread_mutex_unlock(&g_lua_unwind_table_lock);

    pthread_mutex_lock(&tracer->mutex_probes_lock);
    clear_lua_probes_by_pid(tracer, pid);
    pthread_mutex_unlock(&tracer->mutex_probes_lock);

    pthread_mutex_lock(&g_php_unwind_table_lock);
    if (g_php_unwind_table) {
        php_unwind_table_unload(g_php_unwind_table, pid);
    }
    pthread_mutex_unlock(&g_php_unwind_table_lock);

    pthread_mutex_lock(&g_v8_unwind_table_lock);
    if (g_v8_unwind_table) {
        v8_unwind_table_unload(g_v8_unwind_table, pid);
    }
    pthread_mutex_unlock(&g_v8_unwind_table_lock);
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
