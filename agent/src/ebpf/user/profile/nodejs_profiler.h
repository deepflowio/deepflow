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

#ifndef _NODEJS_PROFILER_USER_H
#define _NODEJS_PROFILER_USER_H

#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>
#include "../table.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Node.js profiler statistics */
struct nodejs_profiler_stats {
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t cache_entries;
    uint64_t isolates_tracked;
    uint64_t stack_traces_processed;
};

/* Node.js symbol information for user space */
struct nodejs_symbol_info {
    char function_name[64];
    char script_name[128];
    char source_url[128];
    uint32_t line_number;
    uint32_t column_number;
    uint8_t frame_type;
    uint64_t js_func_addr;
};

/* V8 version information */
struct v8_version_info {
    uint8_t major;
    uint8_t minor;
    uint8_t patch;
    uint32_t build_number;
};

/* Node.js process information */
struct nodejs_process_info {
    pid_t pid;
    uint64_t isolate_addr;
    uint64_t thread_local_top;
    struct v8_version_info v8_version;
    uint8_t node_major_version;
    uint32_t heap_size_limit;
    uint32_t heap_size_used;
};

/**
 * Initialize the Node.js profiler subsystem
 * @param runtime_info_map BPF map for Node.js runtime information
 * @param offsets_map BPF map for V8 memory offsets
 * @return 0 on success, -1 on error
 */
int nodejs_profiler_init(struct bpf_table_t *runtime_info_map, 
                        struct bpf_table_t *offsets_map);

/**
 * Cleanup the Node.js profiler subsystem
 */
void nodejs_profiler_cleanup(void);

/**
 * Add a process to Node.js profiling
 * @param pid Process ID to add
 * @return 0 on success, -1 on error
 */
int nodejs_profiler_add_process(pid_t pid);

/**
 * Remove a process from Node.js profiling
 * @param pid Process ID to remove
 * @return 0 on success, -1 on error
 */
int nodejs_profiler_remove_process(pid_t pid);

/**
 * Process Node.js stack trace and convert to string representation
 * @param pid Process ID
 * @param key Stack trace key
 * @param symbols Array of Node.js symbols
 * @param symbol_count Number of symbols
 * @param stack_trace_str Output string buffer
 * @param str_size Size of output buffer
 * @return 0 on success, -1 on error
 */
int nodejs_profiler_process_stack_trace(pid_t pid, 
                                       struct stack_trace_key_t *key,
                                       const nodejs_symbol_t *symbols, 
                                       uint8_t symbol_count,
                                       char *stack_trace_str, 
                                       size_t str_size);

/**
 * Resolve Node.js symbol information from JavaScript function address
 * @param pid Process ID
 * @param js_func_addr JavaScript function address
 * @param symbol_info Output symbol information
 * @return 0 on success, -1 on error
 */
int nodejs_profiler_resolve_symbol(pid_t pid, uint64_t js_func_addr,
                                  struct nodejs_symbol_info *symbol_info);

/**
 * Get Node.js profiler statistics
 * @param stats Output statistics structure
 * @return 0 on success, -1 on error
 */
int nodejs_profiler_get_stats(struct nodejs_profiler_stats *stats);

/**
 * Check if a process is a Node.js process
 * @param pid Process ID to check
 * @return 1 if Node.js process, 0 if not, -1 on error
 */
int nodejs_profiler_is_nodejs_process(pid_t pid);

/**
 * Detect Node.js and V8 versions for a process
 * @param pid Process ID
 * @param nodejs_major Output Node.js major version
 * @param v8_major Output V8 major version
 * @param v8_minor Output V8 minor version
 * @return 0 on success, -1 on error
 */
int nodejs_profiler_detect_versions(pid_t pid, uint8_t *nodejs_major, 
                                   uint8_t *v8_major, uint8_t *v8_minor);

/**
 * Find V8 Isolate address for a Node.js process
 * @param pid Process ID
 * @param isolate_addr Output Isolate address
 * @return 0 on success, -1 on error
 */
int nodejs_profiler_find_isolate(pid_t pid, uint64_t *isolate_addr);

/**
 * Calculate ThreadLocalTop address from Isolate
 * @param pid Process ID
 * @param isolate_addr Isolate address
 * @param v8_major V8 major version
 * @param thread_local_top Output ThreadLocalTop address
 * @return 0 on success, -1 on error
 */
int nodejs_profiler_get_thread_local_top(pid_t pid, uint64_t isolate_addr, 
                                        uint8_t v8_major, uint64_t *thread_local_top);

/**
 * Update V8 memory offsets for a specific version
 * @param v8_major V8 major version
 * @param v8_minor V8 minor version
 * @param offsets_id Offsets ID to use
 * @return 0 on success, -1 on error
 */
int nodejs_profiler_update_offsets(uint8_t v8_major, uint8_t v8_minor, uint8_t offsets_id);

/**
 * Get Node.js process information
 * @param pid Process ID
 * @param process_info Output process information
 * @return 0 on success, -1 on error
 */
int nodejs_profiler_get_process_info(pid_t pid, struct nodejs_process_info *process_info);

/**
 * Enable/disable V8 heap monitoring for a process
 * @param pid Process ID
 * @param enable 1 to enable, 0 to disable
 * @return 0 on success, -1 on error
 */
int nodejs_profiler_set_heap_monitoring(pid_t pid, int enable);

/**
 * Read V8 string from process memory
 * @param pid Process ID
 * @param v8_string_addr V8 string object address
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 * @return 0 on success, -1 on error
 */
int read_v8_string(pid_t pid, uint64_t v8_string_addr, char *buffer, size_t buffer_size);

/**
 * Validate V8 object pointer
 * @param addr Address to validate
 * @return 1 if valid V8 object, 0 if not
 */
int is_valid_v8_object(uint64_t addr);

/**
 * Classify V8 frame type from marker
 * @param marker Frame marker value
 * @return V8 frame type
 */
uint8_t classify_v8_frame_type(uint64_t marker);

#ifdef __cplusplus
}
#endif

#endif /* _NODEJS_PROFILER_USER_H */