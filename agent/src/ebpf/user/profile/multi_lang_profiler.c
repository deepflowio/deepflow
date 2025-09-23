/*
 * Multi-Language Profiler Integration
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

#include "../config.h"
#include "../../kernel/include/profiler_common.h"
#include "../table.h"
#include "../common_utils.h"
#include "../log.h"
#include "../mem.h"
#include "../proc.h"
#include "profile_common.h"
#include "php_profiler.h"
#include "nodejs_profiler.h"
#include "multi_lang_profiler.h"
#include <stdatomic.h>

/* Multi-language profiler manager */
struct multi_lang_profiler_manager {
    struct bpf_table_t *enhanced_progs_map;
    struct bpf_table_t *runtime_detection_map;
    
    /* Sub-profilers */
    int php_profiler_enabled;
    int nodejs_profiler_enabled;
    
    /* Statistics - using atomic operations for thread safety */
    atomic_uint_fast64_t total_processes;
    atomic_uint_fast64_t php_processes;
    atomic_uint_fast64_t nodejs_processes;
    atomic_uint_fast64_t unknown_processes;
    
    /* Performance metrics */
    atomic_uint_fast64_t total_stack_traces;
    atomic_uint_fast64_t successful_unwinds;
    atomic_uint_fast64_t failed_unwinds;
    atomic_uint_fast64_t cache_hits;
    atomic_uint_fast64_t cache_misses;
};

static struct multi_lang_profiler_manager profiler_manager = {
    .php_profiler_enabled = 1,
    .nodejs_profiler_enabled = 1,
    /* Atomic counters initialized to 0 by default */
};

/* Runtime type detection with improved resource management */
static int detect_process_runtime_type(pid_t pid)
{
    char cmdline_path[256];
    char cmdline[1024];
    FILE *cmdline_file = NULL;
    int result = RUNTIME_TYPE_UNKNOWN;
    
    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
    cmdline_file = fopen(cmdline_path, "r");
    if (!cmdline_file) {
        goto cleanup;
    }
    
    if (fgets(cmdline, sizeof(cmdline), cmdline_file)) {
        // Replace null characters with spaces for easier parsing (optimized)
        size_t cmdline_len = strnlen(cmdline, sizeof(cmdline) - 1);
        for (size_t i = 0; i < cmdline_len; i++) {
            if (cmdline[i] == '\0') {
                cmdline[i] = ' ';
            }
        }
        
        // Check for PHP processes
        if (strstr(cmdline, "php") || strstr(cmdline, "php-fpm") || 
            strstr(cmdline, "php-cgi") || strstr(cmdline, ".php")) {
            result = RUNTIME_TYPE_PHP;
            goto cleanup;
        }
        
        // Check for Node.js processes
        if (strstr(cmdline, "node") || strstr(cmdline, "nodejs") ||
            strstr(cmdline, ".js") || strstr(cmdline, "npm") ||
            strstr(cmdline, "yarn")) {
            result = RUNTIME_TYPE_NODEJS;
            goto cleanup;
        }
        
        // Check for Python processes (for future extension)
        if (strstr(cmdline, "python") || strstr(cmdline, ".py")) {
            result = RUNTIME_TYPE_PYTHON;
            goto cleanup;
        }
    }
    
cleanup:
    if (cmdline_file) {
        fclose(cmdline_file);
    }
    return result;
}

/* Performance optimization helpers with atomic operations */
static void update_performance_stats(int unwind_result, int cache_hit)
{
    atomic_fetch_add_explicit(&profiler_manager.total_stack_traces, 1, memory_order_relaxed);
    
    if (unwind_result == 0) {
        atomic_fetch_add_explicit(&profiler_manager.successful_unwinds, 1, memory_order_relaxed);
    } else {
        atomic_fetch_add_explicit(&profiler_manager.failed_unwinds, 1, memory_order_relaxed);
    }
    
    if (cache_hit) {
        atomic_fetch_add_explicit(&profiler_manager.cache_hits, 1, memory_order_relaxed);
    } else {
        atomic_fetch_add_explicit(&profiler_manager.cache_misses, 1, memory_order_relaxed);
    }
}

/* BPF map management for enhanced profiler */
static int setup_enhanced_profiler_maps(void)
{
    // Setup tail-call program array
    int prog_array_fd = profiler_manager.enhanced_progs_map->fd;
    
    // Load enhanced profiler programs (this would be done by the loader)
    // For now, we'll just verify the map is accessible
    
    if (prog_array_fd < 0) {
        ebpf_warning("Enhanced profiler program array not available\n");
        return -1;
    }
    
    ebpf_info("Enhanced profiler maps setup complete\n");
    return 0;
}

/* Process lifecycle management */
static int add_process_to_runtime_map(pid_t pid, int runtime_type)
{
    runtime_info_t runtime_info = {0};
    
    runtime_info.runtime_type = runtime_type;
    runtime_info.version_major = 0;  // Will be filled by specific profilers
    runtime_info.version_minor = 0;
    runtime_info.flags = 0;
    
    if (bpf_map_update_elem(profiler_manager.runtime_detection_map->fd, 
                           &pid, &runtime_info, BPF_ANY) != 0) {
        ebpf_warning("Failed to add process %d to runtime detection map\n", pid);
        return -1;
    }
    
    return 0;
}

/* Public interface */
int multi_lang_profiler_init(struct bpf_table_t *enhanced_progs_map,
                            struct bpf_table_t *runtime_detection_map,
                            struct bpf_table_t *php_runtime_map,
                            struct bpf_table_t *php_offsets_map,
                            struct bpf_table_t *nodejs_runtime_map,
                            struct bpf_table_t *v8_offsets_map)
{
    profiler_manager.enhanced_progs_map = enhanced_progs_map;
    profiler_manager.runtime_detection_map = runtime_detection_map;
    
    // Initialize sub-profilers
    if (profiler_manager.php_profiler_enabled) {
        if (php_profiler_init(php_runtime_map, php_offsets_map) != 0) {
            ebpf_warning("Failed to initialize PHP profiler\n");
            profiler_manager.php_profiler_enabled = 0;
        }
    }
    
    if (profiler_manager.nodejs_profiler_enabled) {
        if (nodejs_profiler_init(nodejs_runtime_map, v8_offsets_map) != 0) {
            ebpf_warning("Failed to initialize Node.js profiler\n");
            profiler_manager.nodejs_profiler_enabled = 0;
        }
    }
    
    // Setup enhanced profiler maps
    if (setup_enhanced_profiler_maps() != 0) {
        ebpf_warning("Failed to setup enhanced profiler maps\n");
        return -1;
    }
    
    ebpf_info("Multi-language profiler initialized (PHP: %s, Node.js: %s)\n",
              profiler_manager.php_profiler_enabled ? "enabled" : "disabled",
              profiler_manager.nodejs_profiler_enabled ? "enabled" : "disabled");
    
    return 0;
}

void multi_lang_profiler_cleanup(void)
{
    if (profiler_manager.php_profiler_enabled) {
        php_profiler_cleanup();
    }
    
    if (profiler_manager.nodejs_profiler_enabled) {
        nodejs_profiler_cleanup();
    }
    
    ebpf_info("Multi-language profiler cleaned up\n");
}

int multi_lang_profiler_add_process(pid_t pid)
{
    int runtime_type = detect_process_runtime_type(pid);
    int result = 0;
    
    atomic_fetch_add_explicit(&profiler_manager.total_processes, 1, memory_order_relaxed);
    
    switch (runtime_type) {
        case RUNTIME_TYPE_PHP:
            atomic_fetch_add_explicit(&profiler_manager.php_processes, 1, memory_order_relaxed);
            break;
        case RUNTIME_TYPE_NODEJS:
            atomic_fetch_add_explicit(&profiler_manager.nodejs_processes, 1, memory_order_relaxed);
            break;
        default:
            atomic_fetch_add_explicit(&profiler_manager.unknown_processes, 1, memory_order_relaxed);
            break;
    }
    
    // Add to runtime detection map
    if (add_process_to_runtime_map(pid, runtime_type) != 0) {
        return -1;
    }
    
    // Add to specific profiler
    switch (runtime_type) {
        case RUNTIME_TYPE_PHP:
            if (profiler_manager.php_profiler_enabled) {
                result = php_profiler_add_process(pid);
            }
            break;
            
        case RUNTIME_TYPE_NODEJS:
            if (profiler_manager.nodejs_profiler_enabled) {
                result = nodejs_profiler_add_process(pid);
            }
            break;
            
        default:
            // For unknown types, we still track them but don't do specific profiling
            ebpf_debug("Added unknown runtime type process %d\n", pid);
            break;
    }
    
    if (result == 0) {
        ebpf_debug("Added process %d with runtime type %d\n", pid, runtime_type);
    }
    
    return result;
}

int multi_lang_profiler_remove_process(pid_t pid)
{
    // Remove from runtime detection map
    runtime_info_t runtime_info = {0};
    if (bpf_map_lookup_elem(profiler_manager.runtime_detection_map->fd, 
                           &pid, &runtime_info) == 0) {
        
        // Remove from specific profiler
        switch (runtime_info.runtime_type) {
            case RUNTIME_TYPE_PHP:
                if (profiler_manager.php_profiler_enabled) {
                    php_profiler_remove_process(pid);
                }
                break;
                
            case RUNTIME_TYPE_NODEJS:
                if (profiler_manager.nodejs_profiler_enabled) {
                    nodejs_profiler_remove_process(pid);
                }
                break;
        }
    }
    
    // Remove from runtime detection map
    bpf_map_delete_elem(profiler_manager.runtime_detection_map->fd, &pid);
    
    // Atomically decrement total processes count if greater than 0
    uint64_t current_total = atomic_load_explicit(&profiler_manager.total_processes, memory_order_relaxed);
    if (current_total > 0) {
        atomic_fetch_sub_explicit(&profiler_manager.total_processes, 1, memory_order_relaxed);
    }
    
    ebpf_debug("Removed process %d from multi-language profiler\n", pid);
    return 0;
}

int multi_lang_profiler_process_stack_trace(pid_t pid, 
                                           struct stack_trace_key_t *key,
                                           const void *symbols,
                                           uint8_t symbol_count,
                                           uint8_t runtime_type,
                                           char *output_buffer,
                                           size_t buffer_size)
{
    int result = -1;
    int cache_hit = 0; // TODO: Implement cache hit detection
    
    switch (runtime_type) {
        case RUNTIME_TYPE_PHP:
            if (profiler_manager.php_profiler_enabled) {
                result = php_profiler_process_stack_trace(pid, key, 
                                                        (const php_symbol_t *)symbols,
                                                        symbol_count,
                                                        output_buffer, buffer_size);
            }
            break;
            
        case RUNTIME_TYPE_NODEJS:
            if (profiler_manager.nodejs_profiler_enabled) {
                result = nodejs_profiler_process_stack_trace(pid, key,
                                                           (const nodejs_symbol_t *)symbols,
                                                           symbol_count,
                                                           output_buffer, buffer_size);
            }
            break;
            
        default:
            snprintf(output_buffer, buffer_size, "<native stack trace for PID %d>\n", pid);
            result = 0;
            break;
    }
    
    update_performance_stats(result, cache_hit);
    return result;
}

int multi_lang_profiler_get_stats(struct multi_lang_profiler_stats *stats)
{
    if (!stats) {
        return -1;
    }
    
    // Read atomic counters with consistent memory ordering
    stats->total_processes = atomic_load_explicit(&profiler_manager.total_processes, memory_order_acquire);
    stats->php_processes = atomic_load_explicit(&profiler_manager.php_processes, memory_order_acquire);
    stats->nodejs_processes = atomic_load_explicit(&profiler_manager.nodejs_processes, memory_order_acquire);
    stats->unknown_processes = atomic_load_explicit(&profiler_manager.unknown_processes, memory_order_acquire);
    
    stats->total_stack_traces = atomic_load_explicit(&profiler_manager.total_stack_traces, memory_order_acquire);
    stats->successful_unwinds = atomic_load_explicit(&profiler_manager.successful_unwinds, memory_order_acquire);
    stats->failed_unwinds = atomic_load_explicit(&profiler_manager.failed_unwinds, memory_order_acquire);
    stats->cache_hits = atomic_load_explicit(&profiler_manager.cache_hits, memory_order_acquire);
    stats->cache_misses = atomic_load_explicit(&profiler_manager.cache_misses, memory_order_acquire);
    
    // Get sub-profiler stats
    if (profiler_manager.php_profiler_enabled) {
        struct php_profiler_stats php_stats;
        if (php_profiler_get_stats(&php_stats) == 0) {
            stats->php_cache_hits = php_stats.cache_hits;
            stats->php_cache_misses = php_stats.cache_misses;
        }
    }
    
    if (profiler_manager.nodejs_profiler_enabled) {
        struct nodejs_profiler_stats nodejs_stats;
        if (nodejs_profiler_get_stats(&nodejs_stats) == 0) {
            stats->nodejs_cache_hits = nodejs_stats.cache_hits;
            stats->nodejs_cache_misses = nodejs_stats.cache_misses;
            stats->isolates_tracked = nodejs_stats.isolates_tracked;
        }
    }
    
    return 0;
}

int multi_lang_profiler_set_config(const struct multi_lang_profiler_config *config)
{
    if (!config) {
        return -1;
    }
    
    profiler_manager.php_profiler_enabled = config->enable_php;
    profiler_manager.nodejs_profiler_enabled = config->enable_nodejs;
    
    ebpf_info("Multi-language profiler config updated (PHP: %s, Node.js: %s)\n",
              profiler_manager.php_profiler_enabled ? "enabled" : "disabled",
              profiler_manager.nodejs_profiler_enabled ? "enabled" : "disabled");
    
    return 0;
}

double multi_lang_profiler_get_success_rate(void)
{
    uint64_t successful = atomic_load_explicit(&profiler_manager.successful_unwinds, memory_order_acquire);
    uint64_t failed = atomic_load_explicit(&profiler_manager.failed_unwinds, memory_order_acquire);
    uint64_t total = successful + failed;
    double success_rate = 0.0;
    
    if (total > 0) {
        success_rate = (double)successful / total * 100.0;
    }
    
    return success_rate;
}

double multi_lang_profiler_get_cache_hit_rate(void)
{
    uint64_t hits = atomic_load_explicit(&profiler_manager.cache_hits, memory_order_acquire);
    uint64_t misses = atomic_load_explicit(&profiler_manager.cache_misses, memory_order_acquire);
    uint64_t total = hits + misses;
    double hit_rate = 0.0;
    
    if (total > 0) {
        hit_rate = (double)hits / total * 100.0;
    }
    
    return hit_rate;
}