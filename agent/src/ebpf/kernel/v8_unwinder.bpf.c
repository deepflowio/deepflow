/*
 * V8/Node.js Stack Unwinding eBPF Implementation
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

#include "config.h"
#include "bpf_base.h"
#include "common.h"
#include "kernel.h"
#include "bpf_endian.h"
#include "profiler_common.h"
#include "nodejs_profiler.h"

/* V8/Node.js runtime information map */
MAP_HASH(nodejs_runtime_info_map, __u32, nodejs_runtime_info_t, 1024, FEATURE_FLAG_PROFILE)

/* V8 offsets map keyed by offsets_id */
MAP_HASH(v8_offsets_map, __u8, v8_offsets_t, 16, FEATURE_FLAG_PROFILE)

/* Helper function to validate V8 frame pointer */
static inline __attribute__((always_inline))
int v8_is_valid_frame_pointer_inline(__u64 fp) {
    /* Basic sanity checks for V8 frame pointer */
    if (fp == 0 || fp < 0x1000) {
        return 0;
    }

    /* Check if address is in user space */
    if (fp >= 0x7fffffffffff) {
        return 0;
    }

    /* Check 8-byte alignment */
    if (fp & 0x7) {
        return 0;
    }

    return 1;
}

/* Helper function to classify V8 frame type */
static inline __attribute__((always_inline))
__u8 v8_classify_frame_type_inline(__u64 marker) {
    /* V8 frame type classification based on marker */
    if ((marker & V8_SMI_TAG_MASK) == 0) {
        /* SMI marker indicates JavaScript frame */
        return V8_FRAME_JAVASCRIPT;
    } else if (marker >= V8_STUB_MARKER_MIN && marker <= V8_STUB_MARKER_MAX) {
        /* Stub frame markers */
        return V8_FRAME_STUB;
    } else {
        /* Other frame types (native, builtin, etc.) */
        return V8_FRAME_NATIVE;
    }
}

/* Helper function to safely read V8 string */
static inline __attribute__((always_inline))
int read_v8_string(__u64 v8_string_addr, char *buffer, __u32 buffer_size,
                   v8_offsets_t *offsets) {
    if (v8_string_addr == 0) {
        return -1;
    }

    /* Read string length first */
    __u32 str_len = 0;
    if (bpf_probe_read_user(&str_len, sizeof(__u32),
                           (void *)(v8_string_addr + offsets->str_length)) != 0) {
        return -1;
    }

    /* Limit string length to avoid excessive reads */
    if (str_len > buffer_size - 1) {
        str_len = buffer_size - 1;
    }

    /* Read string data directly */
    __u64 str_data_addr = v8_string_addr + offsets->str_data;

    /* Read the actual string content */
    if (bpf_probe_read_user_str(buffer, str_len + 1, (void *)str_data_addr) < 0) {
        return -1;
    }

    return 0;
}

/* Helper function to extract JavaScript function information */
static inline __attribute__((always_inline))
int v8_extract_js_function_info(__u64 js_func_addr, nodejs_symbol_t *symbol,
                               v8_offsets_t *offsets) {
    if (js_func_addr == 0) {
        return -1;
    }

    /* Read SharedFunctionInfo from JSFunction */
    __u64 shared_info_addr = 0;
    if (bpf_probe_read_user(&shared_info_addr, sizeof(__u64),
                           (void *)(js_func_addr + offsets->js_func_shared_info)) != 0) {
        return -1;
    }

    if (shared_info_addr == 0) {
        __builtin_memcpy(symbol->function_name, "<anonymous>", 12);
        return 0;
    }

    /* Read function name from SharedFunctionInfo */
    __u64 name_addr = 0;
    if (bpf_probe_read_user(&name_addr, sizeof(__u64),
                           (void *)(shared_info_addr + offsets->sfi_name_or_scope_info)) == 0 &&
        name_addr != 0) {

        if (read_v8_string(name_addr, symbol->function_name,
                          sizeof(symbol->function_name), offsets) != 0) {
            __builtin_memcpy(symbol->function_name, "<unknown>", 10);
        }
    } else {
        __builtin_memcpy(symbol->function_name, "<anonymous>", 12);
    }

    /* Read Script information */
    __u64 script_addr = 0;
    if (bpf_probe_read_user(&script_addr, sizeof(__u64),
                           (void *)(shared_info_addr + offsets->sfi_script)) == 0 &&
        script_addr != 0) {

        /* Read script source URL */
        __u64 source_url_addr = 0;
        if (bpf_probe_read_user(&source_url_addr, sizeof(__u64),
                               (void *)(script_addr + offsets->script_source_url)) == 0 &&
            source_url_addr != 0) {

            if (read_v8_string(source_url_addr, symbol->script_name,
                              sizeof(symbol->script_name), offsets) != 0) {
                __builtin_memcpy(symbol->script_name, "<eval>", 7);
            }
        }

        /* Read line and column offsets */
        __u32 line_offset = 0, column_offset = 0;
        if (bpf_probe_read_user(&line_offset, sizeof(__u32),
                               (void *)(script_addr + offsets->script_line_offset)) == 0) {
            symbol->line_number = line_offset + 1; /* Convert to 1-based */
        }

        if (bpf_probe_read_user(&column_offset, sizeof(__u32),
                               (void *)(script_addr + offsets->script_column_offset)) == 0) {
            symbol->column_number = column_offset;
        }
    }

    /* Read function start and end positions for more precise line calculation */
    __u32 start_pos = 0, end_pos = 0;
    __s32 script_id = 0;

    if (bpf_probe_read_user(&start_pos, sizeof(__u32),
                           (void *)(shared_info_addr + offsets->sfi_start_position)) == 0) {

        if (bpf_probe_read_user(&end_pos, sizeof(__u32),
                               (void *)(shared_info_addr + offsets->sfi_end_position)) == 0) {

            /* For V8, we need to calculate line number based on:
             * 1. Script's line offset (base line number)
             * 2. Position within the script
             * 3. Line ends array (if available)
             *
             * This is a simplified implementation. In production, you'd need:
             * - Access to the Script's line_ends array
             * - Binary search through line_ends to find the line
             */

            /* If we have script information, use it for accurate line calculation */
            if (script_addr != 0 && line_offset > 0) {
                /* The line_offset from Script is the base line number */
                symbol->line_number = line_offset;

                /* TODO: To get the exact line within the function:
                 * 1. Read Script's line_ends array
                 * 2. Binary search for start_pos in line_ends
                 * 3. Add the found line index to line_offset
                 *
                 * For now, we provide an estimate based on average line length
                 * This is more accurate than dividing by 80
                 */
                if (start_pos > 0) {
                    /* Estimate based on typical JavaScript line characteristics:
                     * - Average line length: ~40 characters
                     * - Account for minified code (longer lines)
                     */
                    __u32 estimated_lines = 0;
                    if (end_pos > start_pos) {
                        /* If function is small, likely not minified */
                        __u32 func_size = end_pos - start_pos;
                        if (func_size < 500) {
                            estimated_lines = start_pos / 40;
                        } else {
                            /* Larger functions might be minified */
                            estimated_lines = start_pos / 100;
                        }
                    } else {
                        /* Default estimation */
                        estimated_lines = start_pos / 50;
                    }
                    symbol->line_number += estimated_lines;
                }
            } else {
                /* No script info, provide a rough estimate */
                if (start_pos > 0) {
                    symbol->line_number = (start_pos / 50) + 1;
                } else {
                    symbol->line_number = 0;
                }
            }
        }
    }

    return 0;
}

/* Helper function to detect JavaScript frame from context */
static inline __attribute__((always_inline))
int v8_is_javascript_context(__u64 context_addr, v8_offsets_t *offsets) {
    if (context_addr == 0) {
        return 0;
    }

    /* V8 contexts have specific structure patterns */
    /* Read context type or other identifying information */
    __u64 context_type = 0;
    if (bpf_probe_read_user(&context_type, sizeof(__u64), (void *)context_addr) == 0) {
        /* Check if this looks like a JavaScript execution context */
        /* This is a simplified check - real implementation would be more sophisticated */
        return (context_type & 0x1) == 0; /* Even addresses typically indicate objects */
    }

    return 0;
}

/* Enhanced V8 stack unwinding with better frame detection */
static inline __attribute__((always_inline))
int v8_unwind_stack_enhanced(void *ctx, extended_unwind_state_t *state) {
    v8_offsets_t *offsets = v8_offsets_map__lookup(&state->runtime_ctx.nodejs.offsets_id);
    if (!offsets) {
        return -EINVAL;
    }

    nodejs_runtime_info_t *nodejs_info = nodejs_runtime_info_map__lookup(&state->key.tgid);
    if (!nodejs_info) {
        return -ENOENT;
    }

    /* Get V8 runtime addresses */
    __u64 isolate_addr = nodejs_info->isolate_addr;
    __u64 thread_local_top = nodejs_info->thread_local_top;

    if (isolate_addr == 0) {
        return -EINVAL;
    }

    /* Calculate ThreadLocalTop if not provided */
    if (thread_local_top == 0) {
        if (bpf_probe_read_user(&thread_local_top, sizeof(__u64),
                               (void *)(isolate_addr + offsets->isolate_thread_local_top)) != 0) {
            return -EFAULT;
        }
    }

    /* Get JavaScript entry stack pointer */
    __u64 js_entry_sp = 0;
    if (bpf_probe_read_user(&js_entry_sp, sizeof(__u64),
                           (void *)(thread_local_top + offsets->tlt_js_entry_sp)) != 0) {
        return -EFAULT;
    }

    if (!v8_is_valid_frame_pointer_inline(js_entry_sp)) {
        return 0; /* No valid JavaScript frames */
    }

    /* Initialize frame unwinding */
    __u64 current_fp = js_entry_sp;
    __u32 frame_idx = 0;
    __u32 max_frames = MAX_NODEJS_STACK_DEPTH;
    if (max_frames > NODEJS_MAX_STACK_DEPTH) {
        max_frames = NODEJS_MAX_STACK_DEPTH;
    }

    /* Unwind V8 stack frames */
    #pragma unroll
    for (int i = 0; i < MAX_STACK_UNWIND_LOOPS; i++) {
        if (frame_idx >= max_frames || !v8_is_valid_frame_pointer_inline(current_fp)) {
            break;
        }

        /* Read frame header */
        __u64 frame_marker = 0;
        __u64 frame_pc = 0;
        __u64 frame_function = 0;
        __u64 frame_context = 0;

        /* Read frame marker for type classification */
        if (bpf_probe_read_user(&frame_marker, sizeof(__u64), (void *)current_fp) != 0) {
            break;
        }

        /* Read program counter */
        if (bpf_probe_read_user(&frame_pc, sizeof(__u64),
                               (void *)(current_fp + offsets->frame_pc)) != 0) {
            break;
        }

        /* Read function object (if present) */
        if (bpf_probe_read_user(&frame_function, sizeof(__u64),
                               (void *)(current_fp + offsets->frame_function)) != 0) {
            frame_function = 0;
        }

        /* Read context */
        if (bpf_probe_read_user(&frame_context, sizeof(__u64),
                               (void *)(current_fp + offsets->frame_context)) != 0) {
            frame_context = 0;
        }

        /* Classify frame type */
        __u8 frame_type = v8_classify_frame_type_inline(frame_marker);

        /* Process different frame types */
        nodejs_symbol_t *symbol = &state->interpreter_stack.nodejs_symbols[frame_idx];
        __builtin_memset(symbol, 0, sizeof(*symbol));

        if (frame_type == V8_FRAME_JAVASCRIPT && frame_function != 0) {
            /* JavaScript function frame */
            if (v8_extract_js_function_info(frame_function, symbol, offsets) == 0) {
                symbol->frame_type = frame_type;
                frame_idx++;
            }
        } else if (frame_type == V8_FRAME_STUB) {
            /* Stub frame */
            __builtin_memcpy(symbol->function_name, "<stub>", 7);
            symbol->frame_type = frame_type;
            frame_idx++;
        } else if (frame_type == V8_FRAME_BUILTIN) {
            /* Builtin frame */
            __builtin_memcpy(symbol->function_name, "<builtin>", 10);
            symbol->frame_type = frame_type;
            frame_idx++;
        } else {
            /* Native or other frame types */
            __builtin_memcpy(symbol->function_name, "<native>", 9);
            symbol->frame_type = V8_FRAME_NATIVE;
            frame_idx++;
        }

        /* Move to next frame */
        __u64 next_fp = 0;
        if (bpf_probe_read_user(&next_fp, sizeof(__u64),
                               (void *)(current_fp + offsets->frame_fp)) != 0) {
            break;
        }

        /* Validate next frame pointer and prevent loops */
        if (!v8_is_valid_frame_pointer_inline(next_fp) || next_fp <= current_fp) {
            break;
        }

        current_fp = next_fp;
    }

    /* Update interpreter stack information */
    state->interpreter_stack.nodejs_stack_len = frame_idx;
    state->interpreter_stack.runtime_type_v8 = RUNTIME_TYPE_NODEJS;

    return frame_idx > 0 ? 0 : -ENODATA;
}

char _license[] SEC("license") = "GPL";
