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

#include "../config.h"
#include "../../kernel/include/profiler_common.h"
#include "../../kernel/include/php_profiler.h"
#include "../table.h"
#include "../common_utils.h"
#include "../log.h"
#include "../mem.h"
#include "../proc.h"
#include "profile_common.h"
#include "php_profiler.h"

/* PHP symbol resolution cache */
struct php_symbol_cache {
    uint64_t addr;           // Function address
    char function_name[64];  // Function name
    char filename[128];      // File name
    char class_name[64];     // Class name
    uint32_t lineno;         // Line number
    struct rb_node node;     // Red-black tree node
};

/* PHP runtime manager */
struct php_runtime_manager {
    struct bpf_table_t *runtime_info_map;
    struct bpf_table_t *offsets_map;
    struct rb_root symbol_cache;
    pthread_mutex_t cache_lock;
    uint64_t cache_hits;
    uint64_t cache_misses;
};

static struct php_runtime_manager php_manager = {
    .symbol_cache = RB_ROOT,
    .cache_lock = PTHREAD_MUTEX_INITIALIZER,
    .cache_hits = 0,
    .cache_misses = 0
};

/* Symbol cache management */
static struct php_symbol_cache *php_symbol_cache_lookup(uint64_t addr)
{
    struct rb_node *node = php_manager.symbol_cache.rb_node;
    
    while (node) {
        struct php_symbol_cache *cache = rb_entry(node, struct php_symbol_cache, node);
        
        if (addr < cache->addr) {
            node = node->rb_left;
        } else if (addr > cache->addr) {
            node = node->rb_right;
        } else {
            php_manager.cache_hits++;
            return cache;
        }
    }
    
    php_manager.cache_misses++;
    return NULL;
}

static int php_symbol_cache_insert(struct php_symbol_cache *new_cache)
{
    struct rb_node **link = &php_manager.symbol_cache.rb_node;
    struct rb_node *parent = NULL;
    
    while (*link) {
        struct php_symbol_cache *cache = rb_entry(*link, struct php_symbol_cache, node);
        
        parent = *link;
        if (new_cache->addr < cache->addr) {
            link = &(*link)->rb_left;
        } else if (new_cache->addr > cache->addr) {
            link = &(*link)->rb_right;
        } else {
            // Already exists
            return -1;
        }
    }
    
    rb_link_node(&new_cache->node, parent, link);
    rb_insert_color(&new_cache->node, &php_manager.symbol_cache);
    return 0;
}

static void php_symbol_cache_clear(void)
{
    struct rb_node *node = rb_first(&php_manager.symbol_cache);
    
    while (node) {
        struct php_symbol_cache *cache = rb_entry(node, struct php_symbol_cache, node);
        struct rb_node *next = rb_next(node);
        
        rb_erase(node, &php_manager.symbol_cache);
        clib_mem_free(cache);
        node = next;
    }
}

/* Helper function to detect PHP executor_globals address */
static int detect_php_executor_globals(pid_t pid, uint64_t *executor_globals_addr)
{
    // TODO: Implement proper PHP executor_globals detection
    // This should analyze the process memory to find the executor_globals structure
    // For now, return error to indicate detection is not implemented
    ebpf_warning("PHP executor_globals detection not yet implemented for process %d\n", pid);
    return -1;
}

/* Helper function to get PHP offsets for a process */
static int get_php_offsets(pid_t pid, php_offsets_t *offsets)
{
    uint32_t offsets_id = 1; // Default offsets ID
    
    // Try to get runtime info to determine correct offsets
    php_runtime_info_t runtime_info;
    if (bpf_map_lookup_elem(php_manager.runtime_info_map->fd, &pid, &runtime_info) == 0) {
        offsets_id = runtime_info.offsets_id;
    }
    
    // Get offsets from map
    if (bpf_map_lookup_elem(php_manager.offsets_map->fd, &offsets_id, offsets) != 0) {
        ebpf_warning("Failed to get PHP offsets for process %d, offsets_id %u\n", pid, offsets_id);
        return -1;
    }
    
    return 0;
}

/* PHP symbol resolution */
static int resolve_php_symbol_from_execute_data(pid_t pid, uint64_t execute_data_addr,
                                              struct php_symbol_cache *symbol)
{
    // Get PHP offsets for this process
    php_offsets_t offsets;
    if (get_php_offsets(pid, &offsets) != 0) {
        return -1;
    }
    
    // Read function pointer from execute_data
    uint64_t func_addr = 0;
    if (read_process_memory(pid, execute_data_addr + offsets.ed_func, &func_addr, sizeof(func_addr)) != 0) {
        return -1;
    }
    
    if (func_addr == 0) {
        return -1;
    }
    
    // Read function type
    uint8_t func_type = 0;
    if (read_process_memory(pid, func_addr, &func_type, sizeof(func_type)) != 0) {
        return -1;
    }
    
    symbol->addr = func_addr;
    
    if (func_type == ZEND_USER_FUNCTION) {
        // User function - read from op_array
        uint64_t op_array_addr = func_addr + offsets.func_op_array;
        
        // Read function name
        uint64_t func_name_addr = 0;
        if (read_process_memory(pid, op_array_addr + offsets.op_array_function_name, &func_name_addr, sizeof(func_name_addr)) == 0 &&
            func_name_addr != 0) {
            
            // Read zend_string for function name
            uint64_t name_str_addr = 0;
            if (read_process_memory(pid, func_name_addr + offsets.str_val, &name_str_addr, sizeof(name_str_addr)) == 0 &&
                name_str_addr != 0) {
                
                read_process_string(pid, name_str_addr, symbol->function_name, sizeof(symbol->function_name));
            }
        }
        
        // Read filename
        uint64_t filename_addr = 0;
        if (read_process_memory(pid, op_array_addr + offsets.op_array_filename, &filename_addr, sizeof(filename_addr)) == 0 &&
            filename_addr != 0) {
            
            uint64_t filename_str_addr = 0;
            if (read_process_memory(pid, filename_addr + offsets.str_val, &filename_str_addr, sizeof(filename_str_addr)) == 0 &&
                filename_str_addr != 0) {
                
                read_process_string(pid, filename_str_addr, symbol->filename, sizeof(symbol->filename));
            }
        }
        
        // Read class scope if available
        uint64_t scope_addr = 0;
        if (read_process_memory(pid, op_array_addr + offsets.op_array_scope, &scope_addr, sizeof(scope_addr)) == 0 &&
            scope_addr != 0) {
            
            uint64_t class_name_addr = 0;
            if (read_process_memory(pid, scope_addr + offsets.ce_name, &class_name_addr, sizeof(class_name_addr)) == 0 &&
                class_name_addr != 0) {
                
                uint64_t class_str_addr = 0;
                if (read_process_memory(pid, class_name_addr + offsets.str_val, &class_str_addr, sizeof(class_str_addr)) == 0 &&
                    class_str_addr != 0) {
                    
                    read_process_string(pid, class_str_addr, symbol->class_name, sizeof(symbol->class_name));
                }
            }
        }
        
    } else if (func_type == ZEND_INTERNAL_FUNCTION) {
        // Internal function
        uint64_t func_name_addr = 0;
        if (read_process_memory(pid, func_addr + offsets.func_common_function_name, &func_name_addr, sizeof(func_name_addr)) == 0 &&
            func_name_addr != 0) {
            
            uint64_t name_str_addr = 0;
            if (read_process_memory(pid, func_name_addr + offsets.str_val, &name_str_addr, sizeof(name_str_addr)) == 0 &&
                name_str_addr != 0) {
                
                read_process_string(pid, name_str_addr, symbol->function_name, sizeof(symbol->function_name));
            }
        }
        
        snprintf(symbol->filename, sizeof(symbol->filename), "<internal>");
        symbol->class_name[0] = '\0';
        symbol->lineno = 0;
    }
    
    return 0;
}

/* Public interface */
int php_profiler_init(struct bpf_table_t *runtime_info_map, struct bpf_table_t *offsets_map)
{
    php_manager.runtime_info_map = runtime_info_map;
    php_manager.offsets_map = offsets_map;
    
    ebpf_info("PHP profiler initialized\n");
    return 0;
}

void php_profiler_cleanup(void)
{
    pthread_mutex_lock(&php_manager.cache_lock);
    php_symbol_cache_clear();
    pthread_mutex_unlock(&php_manager.cache_lock);
    
    ebpf_info("PHP profiler cleaned up. Cache stats - hits: %lu, misses: %lu\n",
              php_manager.cache_hits, php_manager.cache_misses);
}

int php_profiler_process_stack_trace(pid_t pid, struct stack_trace_key_t *key,
                                   const php_symbol_t *symbols, uint8_t symbol_count,
                                   char *stack_trace_str, size_t str_size)
{
    if (!symbols || symbol_count == 0 || !stack_trace_str || str_size == 0) {
        return -1;
    }
    
    size_t pos = 0;
    
    for (uint8_t i = 0; i < symbol_count && pos < str_size - 1; i++) {
        const php_symbol_t *symbol = &symbols[i];
        
        // Format: function_name (class::method) at filename:line
        if (symbol->class_name[0] != '\0') {
            pos += snprintf(stack_trace_str + pos, str_size - pos,
                          "%s::%s() at %s:%u\n",
                          symbol->class_name, symbol->function_name,
                          symbol->filename, symbol->lineno);
        } else {
            pos += snprintf(stack_trace_str + pos, str_size - pos,
                          "%s() at %s:%u\n",
                          symbol->function_name,
                          symbol->filename, symbol->lineno);
        }
    }
    
    return 0;
}

int php_profiler_add_process(pid_t pid)
{
    php_runtime_info_t runtime_info = {0};
    
    // Detect PHP runtime information
    // TODO: Implement proper PHP runtime detection based on process analysis
    if (detect_php_executor_globals(pid, &runtime_info.executor_globals) != 0) {
        ebpf_warning("Failed to detect PHP executor_globals for process %d\n", pid);
        return -1;
    }
    runtime_info.offsets_id = 1;
    runtime_info.version_major = 8;
    runtime_info.version_minor = 0;
    runtime_info.sapi_type = PHP_SAPI_CLI;
    
    if (bpf_map_update_elem(php_manager.runtime_info_map->fd, &pid, &runtime_info, BPF_ANY) != 0) {
        ebpf_warning("Failed to add PHP process %d to runtime info map\n", pid);
        return -1;
    }
    
    ebpf_info("Added PHP process %d to profiler\n", pid);
    return 0;
}

int php_profiler_remove_process(pid_t pid)
{
    if (bpf_map_delete_elem(php_manager.runtime_info_map->fd, &pid) != 0) {
        ebpf_warning("Failed to remove PHP process %d from runtime info map\n", pid);
        return -1;
    }
    
    ebpf_info("Removed PHP process %d from profiler\n", pid);
    return 0;
}

int php_profiler_get_stats(struct php_profiler_stats *stats)
{
    if (!stats) {
        return -1;
    }
    
    pthread_mutex_lock(&php_manager.cache_lock);
    stats->cache_hits = php_manager.cache_hits;
    stats->cache_misses = php_manager.cache_misses;
    stats->cache_entries = 0; // Count cache entries
    
    struct rb_node *node = rb_first(&php_manager.symbol_cache);
    while (node) {
        stats->cache_entries++;
        node = rb_next(node);
    }
    pthread_mutex_unlock(&php_manager.cache_lock);
    
    return 0;
}