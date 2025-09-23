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

#ifndef _PHP_PROFILER_USER_H
#define _PHP_PROFILER_USER_H

#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>
#include "../table.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PHP profiler statistics */
struct php_profiler_stats {
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t cache_entries;
    uint64_t processes_tracked;
    uint64_t stack_traces_processed;
};

/* PHP symbol information for user space */
struct php_symbol_info {
    char function_name[64];
    char filename[128];
    char class_name[64];
    uint32_t lineno;
    uint8_t frame_type;
    uint64_t func_addr;
};

/**
 * Initialize the PHP profiler subsystem
 * @param runtime_info_map BPF map for PHP runtime information
 * @param offsets_map BPF map for PHP memory offsets
 * @return 0 on success, -1 on error
 */
int php_profiler_init(struct bpf_table_t *runtime_info_map, 
                     struct bpf_table_t *offsets_map);

/**
 * Cleanup the PHP profiler subsystem
 */
void php_profiler_cleanup(void);

/**
 * Add a process to PHP profiling
 * @param pid Process ID to add
 * @return 0 on success, -1 on error
 */
int php_profiler_add_process(pid_t pid);

/**
 * Remove a process from PHP profiling
 * @param pid Process ID to remove
 * @return 0 on success, -1 on error
 */
int php_profiler_remove_process(pid_t pid);

/**
 * Process PHP stack trace and convert to string representation
 * @param pid Process ID
 * @param key Stack trace key
 * @param symbols Array of PHP symbols
 * @param symbol_count Number of symbols
 * @param stack_trace_str Output string buffer
 * @param str_size Size of output buffer
 * @return 0 on success, -1 on error
 */
int php_profiler_process_stack_trace(pid_t pid, 
                                    struct stack_trace_key_t *key,
                                    const php_symbol_t *symbols, 
                                    uint8_t symbol_count,
                                    char *stack_trace_str, 
                                    size_t str_size);

/**
 * Resolve PHP symbol information from function address
 * @param pid Process ID
 * @param func_addr Function address
 * @param symbol_info Output symbol information
 * @return 0 on success, -1 on error
 */
int php_profiler_resolve_symbol(pid_t pid, uint64_t func_addr,
                               struct php_symbol_info *symbol_info);

/**
 * Get PHP profiler statistics
 * @param stats Output statistics structure
 * @return 0 on success, -1 on error
 */
int php_profiler_get_stats(struct php_profiler_stats *stats);

/**
 * Check if a process is a PHP process
 * @param pid Process ID to check
 * @return 1 if PHP process, 0 if not, -1 on error
 */
int php_profiler_is_php_process(pid_t pid);

/**
 * Detect PHP version for a process
 * @param pid Process ID
 * @param major Output major version
 * @param minor Output minor version
 * @param patch Output patch version
 * @return 0 on success, -1 on error
 */
int php_profiler_detect_version(pid_t pid, uint8_t *major, uint8_t *minor, uint8_t *patch);

/**
 * Find executor_globals address for a PHP process
 * @param pid Process ID
 * @param executor_globals Output executor_globals address
 * @return 0 on success, -1 on error
 */
int php_profiler_find_executor_globals(pid_t pid, uint64_t *executor_globals);

/**
 * Update PHP memory offsets for a specific version
 * @param version_major PHP major version
 * @param version_minor PHP minor version
 * @param offsets_id Offsets ID to use
 * @return 0 on success, -1 on error
 */
int php_profiler_update_offsets(uint8_t version_major, uint8_t version_minor, uint8_t offsets_id);

#ifdef __cplusplus
}
#endif

#endif /* _PHP_PROFILER_USER_H */