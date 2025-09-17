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

#ifndef _MULTI_LANG_PROFILER_H
#define _MULTI_LANG_PROFILER_H

#include <stdint.h>
#include <sys/types.h>
#include "../table.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Multi-language profiler configuration */
struct multi_lang_profiler_config {
    int enable_php;              /* Enable PHP profiling */
    int enable_nodejs;           /* Enable Node.js profiling */
    int enable_python;           /* Enable Python profiling (future) */
    int enable_native_fallback;  /* Enable native stack traces for unknown processes */
    
    /* Performance tuning */
    int max_stack_depth;         /* Maximum stack depth to unwind */
    int cache_size_limit;        /* Symbol cache size limit (MB) */
    int cache_ttl_seconds;       /* Cache time-to-live in seconds */
    
    /* Quality settings */
    int min_function_samples;    /* Minimum samples before caching function info */
    int enable_line_numbers;     /* Enable line number resolution */
    int enable_source_context;   /* Enable source code context */
};

/* Multi-language profiler statistics */
struct multi_lang_profiler_stats {
    /* Process tracking */
    uint64_t total_processes;
    uint64_t php_processes;
    uint64_t nodejs_processes;
    uint64_t python_processes;
    uint64_t unknown_processes;
    
    /* Stack unwinding performance */
    uint64_t total_stack_traces;
    uint64_t successful_unwinds;
    uint64_t failed_unwinds;
    uint64_t native_fallbacks;
    
    /* Cache performance */
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t php_cache_hits;
    uint64_t php_cache_misses;
    uint64_t nodejs_cache_hits;
    uint64_t nodejs_cache_misses;
    
    /* Resource usage */
    uint64_t memory_used_bytes;
    uint64_t isolates_tracked;
    uint64_t executor_globals_tracked;
    
    /* Performance metrics */
    double avg_unwind_time_us;
    double success_rate_percent;
    double cache_hit_rate_percent;
};

/* Runtime type enumeration */
enum runtime_type {
    RUNTIME_UNKNOWN = 0,
    RUNTIME_PHP = 1,
    RUNTIME_NODEJS = 2,
    RUNTIME_PYTHON = 3,
    RUNTIME_NATIVE = 4
};

/**
 * Initialize the multi-language profiler system
 * @param enhanced_progs_map BPF program array for tail calls
 * @param runtime_detection_map BPF map for runtime type detection
 * @param php_runtime_map BPF map for PHP runtime information
 * @param php_offsets_map BPF map for PHP memory offsets
 * @param nodejs_runtime_map BPF map for Node.js runtime information
 * @param v8_offsets_map BPF map for V8 memory offsets
 * @return 0 on success, -1 on error
 */
int multi_lang_profiler_init(struct bpf_table_t *enhanced_progs_map,
                            struct bpf_table_t *runtime_detection_map,
                            struct bpf_table_t *php_runtime_map,
                            struct bpf_table_t *php_offsets_map,
                            struct bpf_table_t *nodejs_runtime_map,
                            struct bpf_table_t *v8_offsets_map);

/**
 * Cleanup the multi-language profiler system
 */
void multi_lang_profiler_cleanup(void);

/**
 * Add a process to multi-language profiling
 * Automatically detects runtime type and routes to appropriate profiler
 * @param pid Process ID to add
 * @return 0 on success, -1 on error
 */
int multi_lang_profiler_add_process(pid_t pid);

/**
 * Remove a process from multi-language profiling
 * @param pid Process ID to remove
 * @return 0 on success, -1 on error
 */
int multi_lang_profiler_remove_process(pid_t pid);

/**
 * Process stack trace from any supported runtime
 * @param pid Process ID
 * @param key Stack trace key from eBPF
 * @param symbols Raw symbol data from eBPF
 * @param symbol_count Number of symbols
 * @param runtime_type Runtime type of the process
 * @param output_buffer Output string buffer
 * @param buffer_size Size of output buffer
 * @return 0 on success, -1 on error
 */
int multi_lang_profiler_process_stack_trace(pid_t pid, 
                                           struct stack_trace_key_t *key,
                                           const void *symbols,
                                           uint8_t symbol_count,
                                           uint8_t runtime_type,
                                           char *output_buffer,
                                           size_t buffer_size);

/**
 * Get comprehensive profiler statistics
 * @param stats Output statistics structure
 * @return 0 on success, -1 on error
 */
int multi_lang_profiler_get_stats(struct multi_lang_profiler_stats *stats);

/**
 * Set profiler configuration
 * @param config Configuration structure
 * @return 0 on success, -1 on error
 */
int multi_lang_profiler_set_config(const struct multi_lang_profiler_config *config);

/**
 * Get current profiler configuration
 * @param config Output configuration structure
 * @return 0 on success, -1 on error
 */
int multi_lang_profiler_get_config(struct multi_lang_profiler_config *config);

/**
 * Detect runtime type for a process
 * @param pid Process ID
 * @return Runtime type enum value
 */
enum runtime_type multi_lang_profiler_detect_runtime(pid_t pid);

/**
 * Enable/disable specific language profiling
 * @param runtime_type Runtime type to configure
 * @param enable 1 to enable, 0 to disable
 * @return 0 on success, -1 on error
 */
int multi_lang_profiler_set_runtime_enabled(enum runtime_type runtime_type, int enable);

/**
 * Check if a specific runtime profiler is enabled
 * @param runtime_type Runtime type to check
 * @return 1 if enabled, 0 if disabled, -1 on error
 */
int multi_lang_profiler_is_runtime_enabled(enum runtime_type runtime_type);

/**
 * Get stack unwinding success rate
 * @return Success rate as percentage (0.0 - 100.0)
 */
double multi_lang_profiler_get_success_rate(void);

/**
 * Get symbol cache hit rate
 * @return Cache hit rate as percentage (0.0 - 100.0)
 */
double multi_lang_profiler_get_cache_hit_rate(void);

/**
 * Clear all symbol caches
 * @return 0 on success, -1 on error
 */
int multi_lang_profiler_clear_caches(void);

/**
 * Optimize performance by adjusting cache sizes and strategies
 * @return 0 on success, -1 on error
 */
int multi_lang_profiler_optimize_performance(void);

/**
 * Export profiler statistics to JSON format
 * @param output_buffer Output buffer for JSON string
 * @param buffer_size Size of output buffer
 * @return 0 on success, -1 on error
 */
int multi_lang_profiler_export_stats_json(char *output_buffer, size_t buffer_size);

/**
 * Import profiler configuration from JSON
 * @param json_config JSON configuration string
 * @return 0 on success, -1 on error
 */
int multi_lang_profiler_import_config_json(const char *json_config);

#ifdef __cplusplus
}
#endif

#endif /* _MULTI_LANG_PROFILER_H */