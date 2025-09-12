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
#include "../../kernel/include/nodejs_profiler.h"
#include "../table.h"
#include "../common_utils.h"
#include "../log.h"
#include "../mem.h"
#include "../proc.h"
#include "profile_common.h"
#include "nodejs_profiler.h"

/* Node.js symbol resolution cache */
struct nodejs_symbol_cache {
    uint64_t js_func_addr;      // JavaScript function address
    char function_name[64];     // Function name
    char script_name[128];      // Script name/URL
    char source_url[128];       // Source URL
    uint32_t line_number;       // Line number
    uint32_t column_number;     // Column number
    struct rb_node node;        // Red-black tree node
};

/* Node.js runtime manager */
struct nodejs_runtime_manager {
    struct bpf_table_t *runtime_info_map;
    struct bpf_table_t *offsets_map;
    struct rb_root symbol_cache;
    pthread_mutex_t cache_lock;
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t isolates_tracked;
};

static struct nodejs_runtime_manager nodejs_manager = {
    .symbol_cache = RB_ROOT,
    .cache_lock = PTHREAD_MUTEX_INITIALIZER,
    .cache_hits = 0,
    .cache_misses = 0,
    .isolates_tracked = 0
};

/* Symbol cache management */
static struct nodejs_symbol_cache *nodejs_symbol_cache_lookup(uint64_t js_func_addr)
{
    struct rb_node *node = nodejs_manager.symbol_cache.rb_node;

    while (node) {
        struct nodejs_symbol_cache *cache = rb_entry(node, struct nodejs_symbol_cache, node);

        if (js_func_addr < cache->js_func_addr) {
            node = node->rb_left;
        } else if (js_func_addr > cache->js_func_addr) {
            node = node->rb_right;
        } else {
            nodejs_manager.cache_hits++;
            return cache;
        }
    }

    nodejs_manager.cache_misses++;
    return NULL;
}

static int nodejs_symbol_cache_insert(struct nodejs_symbol_cache *new_cache)
{
    struct rb_node **link = &nodejs_manager.symbol_cache.rb_node;
    struct rb_node *parent = NULL;

    while (*link) {
        struct nodejs_symbol_cache *cache = rb_entry(*link, struct nodejs_symbol_cache, node);

        parent = *link;
        if (new_cache->js_func_addr < cache->js_func_addr) {
            link = &(*link)->rb_left;
        } else if (new_cache->js_func_addr > cache->js_func_addr) {
            link = &(*link)->rb_right;
        } else {
            // Already exists
            return -1;
        }
    }

    rb_link_node(&new_cache->node, parent, link);
    rb_insert_color(&new_cache->node, &nodejs_manager.symbol_cache);
    return 0;
}

static void nodejs_symbol_cache_clear(void)
{
    struct rb_node *node = rb_first(&nodejs_manager.symbol_cache);

    while (node) {
        struct nodejs_symbol_cache *cache = rb_entry(node, struct nodejs_symbol_cache, node);
        struct rb_node *next = rb_next(node);

        rb_erase(node, &nodejs_manager.symbol_cache);
        clib_mem_free(cache);
        node = next;
    }
}

/* Helper function to get V8 offsets for a process */
static int get_v8_offsets(pid_t pid, v8_offsets_t *offsets)
{
    uint32_t offsets_id = 1; // Default offsets ID

    // Try to get runtime info to determine correct offsets
    nodejs_runtime_info_t runtime_info;
    if (bpf_map_lookup_elem(nodejs_manager.runtime_info_map->fd, &pid, &runtime_info) == 0) {
        offsets_id = runtime_info.offsets_id;
    }

    // Get offsets from map
    if (bpf_map_lookup_elem(nodejs_manager.offsets_map->fd, &offsets_id, offsets) != 0) {
        ebpf_warning("Failed to get V8 offsets for process %d, offsets_id %u\n", pid, offsets_id);
        return -1;
    }

    return 0;
}

/* V8/Node.js symbol resolution */
static int resolve_v8_symbol_from_js_function(pid_t pid, uint64_t js_func_addr,
                                            struct nodejs_symbol_cache *symbol)
{
    // Get V8 offsets for this process
    v8_offsets_t offsets;
    if (get_v8_offsets(pid, &offsets) != 0) {
        return -1;
    }

    // Read SharedFunctionInfo from JSFunction
    uint64_t shared_info_addr = 0;
    if (read_process_memory(pid, js_func_addr + offsets.js_func_shared_info, &shared_info_addr, sizeof(shared_info_addr)) != 0) {
        return -1;
    }

    if (shared_info_addr == 0) {
        snprintf(symbol->function_name, sizeof(symbol->function_name), "<anonymous>");
        return 0;
    }

    symbol->js_func_addr = js_func_addr;

    // Read function name from SharedFunctionInfo
    uint64_t name_addr = 0;
    if (read_process_memory(pid, shared_info_addr + offsets.sfi_name_or_scope_info, &name_addr, sizeof(name_addr)) == 0 &&
        name_addr != 0) {

        // Read V8 string for function name
        if (read_v8_string(pid, name_addr, symbol->function_name, sizeof(symbol->function_name)) != 0) {
            snprintf(symbol->function_name, sizeof(symbol->function_name), "<unknown>");
        }
    } else {
        snprintf(symbol->function_name, sizeof(symbol->function_name), "<anonymous>");
    }

    // Read Script information
    uint64_t script_addr = 0;
    if (read_process_memory(pid, shared_info_addr + offsets.sfi_script, &script_addr, sizeof(script_addr)) == 0 &&
        script_addr != 0) {

        // Read script source URL
        uint64_t source_url_addr = 0;
        if (read_process_memory(pid, script_addr + offsets.script_source_url, &source_url_addr, sizeof(source_url_addr)) == 0 &&
            source_url_addr != 0) {

            if (read_v8_string(pid, source_url_addr, symbol->script_name, sizeof(symbol->script_name)) != 0) {
                snprintf(symbol->script_name, sizeof(symbol->script_name), "<eval>");
            }
        }

        // Read line and column offsets
        uint32_t line_offset = 0, column_offset = 0;
        if (read_process_memory(pid, script_addr + offsets.script_line_offset, &line_offset, sizeof(line_offset)) == 0) {
            symbol->line_number = line_offset + 1; // Convert to 1-based
        }

        if (read_process_memory(pid, script_addr + offsets.script_column_offset, &column_offset, sizeof(column_offset)) == 0) {
            symbol->column_number = column_offset;
        }
    }

    // Read function start position for more precise line calculation
    uint32_t start_pos = 0;
    if (read_process_memory(pid, shared_info_addr + offsets.sfi_start_position, &start_pos, sizeof(start_pos)) == 0) {
        if (start_pos > 0) {
            // TODO: Implement proper line calculation based on source mapping
            symbol->line_number = (start_pos / 80) + 1; // Rough estimate: 80 chars per line
        }
    }

    return 0;
}

static int read_v8_string(pid_t pid, uint64_t v8_string_addr, char *buffer, size_t buffer_size)
{
    if (v8_string_addr == 0) {
        return -1;
    }

    // Get V8 offsets for this process
    v8_offsets_t offsets;
    if (get_v8_offsets(pid, &offsets) != 0) {
        return -1;
    }

    // Read string length
    uint32_t str_len = 0;
    if (read_process_memory(pid, v8_string_addr + offsets.str_length, &str_len, sizeof(str_len)) != 0) {
        return -1;
    }

    // Limit string length
    if (str_len > buffer_size - 1) {
        str_len = buffer_size - 1;
    }

    // Read string data (V8 strings have data immediately after header)
    uint64_t str_data_addr = v8_string_addr + offsets.str_data;

    if (read_process_string(pid, str_data_addr, buffer, str_len + 1) != 0) {
        return -1;
    }

    return 0;
}

/* V8 Isolate detection helpers */
static int detect_v8_isolate_from_maps(pid_t pid, uint64_t *isolate_addr)
{
    char maps_path[256];
    FILE *maps_file;
    char line[1024];

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        return -1;
    }

    // Get V8 offsets to determine isolate base offset
    v8_offsets_t offsets;
    if (get_v8_offsets(pid, &offsets) != 0) {
        // Fallback to default offsets if not available
        memset(&offsets, 0, sizeof(offsets));
        offsets.isolate_base_offset = 0x800000; // Default for older versions
    }

    while (fgets(line, sizeof(line), maps_file)) {
        if (strstr(line, "node") || strstr(line, "libv8")) {
            // Parse memory region
            uint64_t start_addr, end_addr;
            if (sscanf(line, "%lx-%lx", &start_addr, &end_addr) == 2) {
                // Look for executable regions
                if (strstr(line, "r-xp")) {
                    // Use version-specific isolate base offset
                    *isolate_addr = start_addr + offsets.isolate_base_offset;
                    fclose(maps_file);
                    return 0;
                }
            }
        }
    }

    fclose(maps_file);
    return -1;
}

static int detect_thread_local_top(pid_t pid, uint64_t isolate_addr, uint8_t v8_major, uint64_t *tlt_addr)
{
    if (isolate_addr == 0) {
        return -1;
    }

    // Get V8 offsets for this process
    v8_offsets_t offsets;
    if (get_v8_offsets(pid, &offsets) != 0) {
        return -1;
    }

    // Try to read ThreadLocalTop from Isolate
    uint64_t calculated_tlt = isolate_addr + offsets.isolate_thread_local_top;

    // Validate the address looks reasonable
    if (calculated_tlt > isolate_addr && calculated_tlt < isolate_addr + 0x10000) {
        *tlt_addr = calculated_tlt;
        return 0;
    }

    return -1;
}

/* Public interface */
int nodejs_profiler_init(struct bpf_table_t *runtime_info_map, struct bpf_table_t *offsets_map)
{
    nodejs_manager.runtime_info_map = runtime_info_map;
    nodejs_manager.offsets_map = offsets_map;

    ebpf_info("Node.js profiler initialized\n");
    return 0;
}

void nodejs_profiler_cleanup(void)
{
    pthread_mutex_lock(&nodejs_manager.cache_lock);
    nodejs_symbol_cache_clear();
    pthread_mutex_unlock(&nodejs_manager.cache_lock);

    ebpf_info("Node.js profiler cleaned up. Cache stats - hits: %lu, misses: %lu\n",
              nodejs_manager.cache_hits, nodejs_manager.cache_misses);
}

int nodejs_profiler_process_stack_trace(pid_t pid, struct stack_trace_key_t *key,
                                       const nodejs_symbol_t *symbols, uint8_t symbol_count,
                                       char *stack_trace_str, size_t str_size)
{
    if (!symbols || symbol_count == 0 || !stack_trace_str || str_size == 0) {
        return -1;
    }

    size_t pos = 0;

    for (uint8_t i = 0; i < symbol_count && pos < str_size - 1; i++) {
        const nodejs_symbol_t *symbol = &symbols[i];

        // Format: function_name at script_name:line:column
        pos += snprintf(stack_trace_str + pos, str_size - pos,
                      "%s() at %s:%u:%u\n",
                      symbol->function_name,
                      symbol->script_name,
                      symbol->line_number,
                      symbol->column_number);
    }

    return 0;
}

int nodejs_profiler_add_process(pid_t pid)
{
    nodejs_runtime_info_t runtime_info = {0};

    // Detect V8 Isolate address
    uint64_t isolate_addr = 0;
    if (detect_v8_isolate_from_maps(pid, &isolate_addr) != 0) {
        ebpf_warning("Failed to detect V8 Isolate for process %d\n", pid);
        return -1;
    }

    runtime_info.isolate_addr = isolate_addr;
    runtime_info.offsets_id = 1;
    runtime_info.v8_version_major = 10;    // Default to V8 10.x
    runtime_info.v8_version_minor = 2;
    runtime_info.node_version_major = 18;   // Default to Node.js 18.x

    // Initialize version-specific offsets
    if (nodejs_profiler_update_offsets(runtime_info.v8_version_major,
                                       runtime_info.v8_version_minor,
                                       runtime_info.offsets_id) != 0) {
        ebpf_warning("Failed to initialize V8 offsets for process %d\n", pid);
        return -1;
    }

    // Calculate ThreadLocalTop
    uint64_t tlt_addr = 0;
    if (detect_thread_local_top(pid, isolate_addr, runtime_info.v8_version_major, &tlt_addr) == 0) {
        runtime_info.thread_local_top = tlt_addr;
    }

    if (bpf_map_update_elem(nodejs_manager.runtime_info_map->fd, &pid, &runtime_info, BPF_ANY) != 0) {
        ebpf_warning("Failed to add Node.js process %d to runtime info map\n", pid);
        return -1;
    }

    nodejs_manager.isolates_tracked++;
    ebpf_info("Added Node.js process %d to profiler (Isolate: 0x%lx)\n", pid, isolate_addr);
    return 0;
}

int nodejs_profiler_remove_process(pid_t pid)
{
    if (bpf_map_delete_elem(nodejs_manager.runtime_info_map->fd, &pid) != 0) {
        ebpf_warning("Failed to remove Node.js process %d from runtime info map\n", pid);
        return -1;
    }

    if (nodejs_manager.isolates_tracked > 0) {
        nodejs_manager.isolates_tracked--;
    }

    ebpf_info("Removed Node.js process %d from profiler\n", pid);
    return 0;
}

int nodejs_profiler_get_stats(struct nodejs_profiler_stats *stats)
{
    if (!stats) {
        return -1;
    }

    pthread_mutex_lock(&nodejs_manager.cache_lock);
    stats->cache_hits = nodejs_manager.cache_hits;
    stats->cache_misses = nodejs_manager.cache_misses;
    stats->isolates_tracked = nodejs_manager.isolates_tracked;
    stats->cache_entries = 0; // Count cache entries

    struct rb_node *node = rb_first(&nodejs_manager.symbol_cache);
    while (node) {
        stats->cache_entries++;
        node = rb_next(node);
    }
    pthread_mutex_unlock(&nodejs_manager.cache_lock);

    return 0;
}

int nodejs_profiler_update_offsets(uint8_t v8_major, uint8_t v8_minor, uint8_t offsets_id)
{
    v8_offsets_t offsets = {0};

    // Set version-specific isolate base offsets
    if (v8_major >= 12) {
        // V8 12.x+ (Node.js 21+)
        offsets.isolate_base_offset = 0x800000;
    } else if (v8_major >= 11) {
        // V8 11.x (Node.js 20)
        offsets.isolate_base_offset = 0x780000;
    } else if (v8_major >= 10) {
        // V8 10.x (Node.js 18)
        offsets.isolate_base_offset = 0x750000;
    } else if (v8_major >= 9) {
        // V8 9.x (Node.js 16)
        offsets.isolate_base_offset = 0x700000;
    } else {
        // Older versions - use conservative default
        offsets.isolate_base_offset = 0x800000;
    }

    // Set other version-specific offsets based on V8 version
    if (v8_major >= 11) {
        // V8 11.x+ offsets
        offsets.isolate_thread_local_top = 0x28;
        offsets.isolate_context = 0x30;
        offsets.isolate_current_context = 0x38;

        offsets.tlt_js_entry_sp = 0x0;
        offsets.tlt_external_callback_scope = 0x8;
        offsets.tlt_current_context = 0x10;
        offsets.tlt_pending_exception = 0x18;

        offsets.frame_fp = 0x0;
        offsets.frame_sp = 0x8;
        offsets.frame_pc = 0x10;
        offsets.frame_context = 0x18;
        offsets.frame_function = 0x20;

        offsets.js_func_shared_info = 0x18;
        offsets.js_func_code = 0x20;
        offsets.js_func_context = 0x28;

        offsets.sfi_name_or_scope_info = 0x8;
        offsets.sfi_script = 0x10;
        offsets.sfi_start_position = 0x20;
        offsets.sfi_end_position = 0x24;

        offsets.script_source = 0x8;
        offsets.script_source_url = 0x10;
        offsets.script_line_offset = 0x18;
        offsets.script_column_offset = 0x1C;

        offsets.str_length = 0x8;
        offsets.str_data = 0x10;
    } else if (v8_major >= 10) {
        // V8 10.x (Node.js 18) offsets
        offsets.isolate_thread_local_top = 0x28;
        offsets.isolate_context = 0x30;
        offsets.isolate_current_context = 0x38;

        offsets.tlt_js_entry_sp = 0x0;
        offsets.tlt_external_callback_scope = 0x8;
        offsets.tlt_current_context = 0x10;
        offsets.tlt_pending_exception = 0x18;

        offsets.frame_fp = 0x0;
        offsets.frame_sp = 0x8;
        offsets.frame_pc = 0x10;
        offsets.frame_context = 0x18;
        offsets.frame_function = 0x20;

        offsets.js_func_shared_info = 0x18;
        offsets.js_func_code = 0x20;
        offsets.js_func_context = 0x28;

        offsets.sfi_name_or_scope_info = 0x8;
        offsets.sfi_script = 0x10;
        offsets.sfi_start_position = 0x1C;
        offsets.sfi_end_position = 0x20;

        offsets.script_source = 0x8;
        offsets.script_source_url = 0x10;
        offsets.script_line_offset = 0x18;
        offsets.script_column_offset = 0x1C;

        offsets.str_length = 0x8;
        offsets.str_data = 0x10;
    } else {
        // V8 9.x (Node.js 16) and older offsets
        offsets.isolate_thread_local_top = 0x28;
        offsets.isolate_context = 0x30;
        offsets.isolate_current_context = 0x38;

        offsets.tlt_js_entry_sp = 0x0;
        offsets.tlt_external_callback_scope = 0x8;
        offsets.tlt_current_context = 0x10;
        offsets.tlt_pending_exception = 0x18;

        offsets.frame_fp = 0x0;
        offsets.frame_sp = 0x8;
        offsets.frame_pc = 0x10;
        offsets.frame_context = 0x18;
        offsets.frame_function = 0x20;

        offsets.js_func_shared_info = 0x18;
        offsets.js_func_code = 0x20;
        offsets.js_func_context = 0x28;

        offsets.sfi_name_or_scope_info = 0x8;
        offsets.sfi_script = 0x10;
        offsets.sfi_start_position = 0x1C;
        offsets.sfi_end_position = 0x20;

        offsets.script_source = 0x8;
        offsets.script_source_url = 0x10;
        offsets.script_line_offset = 0x18;
        offsets.script_column_offset = 0x1C;

        offsets.str_length = 0x8;
        offsets.str_data = 0x10;
    }

    // Update the BPF map with version-specific offsets
    if (bpf_map_update_elem(nodejs_manager.offsets_map->fd, &offsets_id, &offsets, BPF_ANY) != 0) {
        ebpf_warning("Failed to update V8 offsets for version %u.%u, offsets_id %u\n",
                     v8_major, v8_minor, offsets_id);
        return -1;
    }

    ebpf_info("Updated V8 offsets for version %u.%u (isolate_base: 0x%x)\n",
              v8_major, v8_minor, offsets.isolate_base_offset);
    return 0;
}

int nodejs_profiler_resolve_symbol(pid_t pid, uint64_t js_func_addr,
                                 struct nodejs_symbol_info *symbol_info)
{
    if (!symbol_info || js_func_addr == 0) {
        return -1;
    }

    // Check cache first
    pthread_mutex_lock(&nodejs_manager.cache_lock);
    struct nodejs_symbol_cache *cached = nodejs_symbol_cache_lookup(js_func_addr);
    if (cached) {
        strncpy(symbol_info->function_name, cached->function_name, sizeof(symbol_info->function_name) - 1);
        symbol_info->function_name[sizeof(symbol_info->function_name) - 1] = '\0';
        strncpy(symbol_info->script_name, cached->script_name, sizeof(symbol_info->script_name) - 1);
        symbol_info->script_name[sizeof(symbol_info->script_name) - 1] = '\0';
        strncpy(symbol_info->source_url, cached->source_url, sizeof(symbol_info->source_url) - 1);
        symbol_info->source_url[sizeof(symbol_info->source_url) - 1] = '\0';
        symbol_info->line_number = cached->line_number;
        symbol_info->column_number = cached->column_number;
        symbol_info->js_func_addr = cached->js_func_addr;
        pthread_mutex_unlock(&nodejs_manager.cache_lock);
        return 0;
    }
    pthread_mutex_unlock(&nodejs_manager.cache_lock);

    // Resolve from process memory
    struct nodejs_symbol_cache new_cache = {0};
    if (resolve_v8_symbol_from_js_function(pid, js_func_addr, &new_cache) != 0) {
        return -1;
    }

    // Cache the result
    pthread_mutex_lock(&nodejs_manager.cache_lock);
    struct nodejs_symbol_cache *cache_entry = clib_mem_alloc(sizeof(*cache_entry));
    if (cache_entry) {
        *cache_entry = new_cache;
        nodejs_symbol_cache_insert(cache_entry);
    }
    pthread_mutex_unlock(&nodejs_manager.cache_lock);

    // Return the resolved symbol
    strncpy(symbol_info->function_name, new_cache.function_name, sizeof(symbol_info->function_name) - 1);
    symbol_info->function_name[sizeof(symbol_info->function_name) - 1] = '\0';
    strncpy(symbol_info->script_name, new_cache.script_name, sizeof(symbol_info->script_name) - 1);
    symbol_info->script_name[sizeof(symbol_info->script_name) - 1] = '\0';
    strncpy(symbol_info->source_url, new_cache.source_url, sizeof(symbol_info->source_url) - 1);
    symbol_info->source_url[sizeof(symbol_info->source_url) - 1] = '\0';
    symbol_info->line_number = new_cache.line_number;
    symbol_info->column_number = new_cache.column_number;
    symbol_info->js_func_addr = new_cache.js_func_addr;

    return 0;
}