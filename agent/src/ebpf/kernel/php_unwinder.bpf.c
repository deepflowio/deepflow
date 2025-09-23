/*
 * PHP Stack Unwinding eBPF Implementation
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
#include "php_profiler.h"

/* PHP runtime information map */
MAP_HASH(php_runtime_info_map, __u32, php_runtime_info_t, 1024, FEATURE_FLAG_PROFILE)

/* PHP offsets map keyed by offsets_id */
MAP_HASH(php_offsets_map, __u8, php_offsets_t, 16, FEATURE_FLAG_PROFILE)

/* Helper function to validate PHP execute_data pointer */
static inline __attribute__((always_inline))
int is_valid_execute_data(__u64 addr) {
    /* Basic sanity checks for execute_data pointer */
    if (addr == 0 || addr < 0x1000) {
        return 0;
    }

    /* Check if address is in user space */
    if (addr >= 0x7fffffffffff) {
        return 0;
    }

    return 1;
}

/* Helper function to safely read PHP zend_string */
static inline __attribute__((always_inline))
int read_php_string(__u64 zend_string_addr, char *buffer, __u32 buffer_size,
                   php_offsets_t *offsets) {
    if (zend_string_addr == 0) {
        return -1;
    }

    /* Read string length first */
    __u32 str_len = 0;
    if (bpf_probe_read_user(&str_len, sizeof(__u32),
                           (void *)(zend_string_addr + offsets->str_len)) != 0) {
        return -1;
    }

    /* Limit string length to avoid excessive reads */
    if (str_len > buffer_size - 1) {
        str_len = buffer_size - 1;
    }

    /* In PHP, zend_string structure is followed directly by the string data
     * The str_val offset points to the beginning of the actual string data
     * not a pointer to it */
    __u64 str_data_addr = zend_string_addr + offsets->str_val;

    /* Validate the string data address */
    if (str_data_addr < 0x1000 || str_data_addr >= 0x7fffffffffff) {
        return -1;
    }

    /* Read the actual string content with proper bounds */
    int ret = bpf_probe_read_user_str(buffer, str_len + 1, (void *)str_data_addr);
    if (ret < 0) {
        /* Fallback: try to read with exact length */
        if (bpf_probe_read_user(buffer, str_len, (void *)str_data_addr) != 0) {
            return -1;
        }
        buffer[str_len] = '\0';
    }

    return 0;
}

/* Helper function to extract function information from zend_function */
static inline __attribute__((always_inline))
int extract_php_function_info(__u64 func_addr, php_symbol_t *symbol,
                             php_offsets_t *offsets) {
    if (func_addr == 0) {
        return -1;
    }

    /* Read function type */
    __u8 func_type = 0;
    if (bpf_probe_read_user(&func_type, sizeof(__u8),
                           (void *)(func_addr + offsets->func_type)) != 0) {
        return -1;
    }

    if (func_type == ZEND_USER_FUNCTION) {
        /* User-defined function */
        __u64 op_array_addr = func_addr + offsets->func_op_array;

        /* Read function name */
        __u64 func_name_addr = 0;
        if (bpf_probe_read_user(&func_name_addr, sizeof(__u64),
                               (void *)(op_array_addr + offsets->op_array_function_name)) == 0 &&
            func_name_addr != 0) {

            if (read_php_string(func_name_addr, symbol->function_name,
                               sizeof(symbol->function_name), offsets) != 0) {
                /* If we can't read the name, use a placeholder */
                __builtin_memcpy(symbol->function_name, "<user_func>", 12);
            }
        }

        /* Read filename */
        __u64 filename_addr = 0;
        if (bpf_probe_read_user(&filename_addr, sizeof(__u64),
                               (void *)(op_array_addr + offsets->op_array_filename)) == 0 &&
            filename_addr != 0) {

            if (read_php_string(filename_addr, symbol->filename,
                               sizeof(symbol->filename), offsets) != 0) {
                /* If we can't read filename, leave it empty */
                __builtin_memset(symbol->filename, 0, sizeof(symbol->filename));
            }
        }

        /* Read class scope if available */
        __u64 scope_addr = 0;
        if (bpf_probe_read_user(&scope_addr, sizeof(__u64),
                               (void *)(op_array_addr + offsets->op_array_scope)) == 0 &&
            scope_addr != 0) {

            __u64 class_name_addr = 0;
            if (bpf_probe_read_user(&class_name_addr, sizeof(__u64),
                                   (void *)(scope_addr + offsets->ce_name)) == 0 &&
                class_name_addr != 0) {

                if (read_php_string(class_name_addr, symbol->class_name,
                                   sizeof(symbol->class_name), offsets) != 0) {
                    __builtin_memset(symbol->class_name, 0, sizeof(symbol->class_name));
                }
            }
        }

        symbol->frame_type = PHP_FRAME_USER;

    } else if (func_type == ZEND_INTERNAL_FUNCTION) {
        /* Internal function */
        __u64 func_name_addr = 0;
        if (bpf_probe_read_user(&func_name_addr, sizeof(__u64),
                               (void *)(func_addr + offsets->func_common_function_name)) == 0 &&
            func_name_addr != 0) {

            if (read_php_string(func_name_addr, symbol->function_name,
                               sizeof(symbol->function_name), offsets) != 0) {
                __builtin_memcpy(symbol->function_name, "<internal>", 11);
            }
        }

        symbol->frame_type = PHP_FRAME_INTERNAL;
        __builtin_memset(symbol->filename, 0, sizeof(symbol->filename));
        __builtin_memset(symbol->class_name, 0, sizeof(symbol->class_name));
        symbol->lineno = 0;

    } else {
        /* Unknown function type */
        __builtin_memcpy(symbol->function_name, "<unknown>", 10);
        symbol->frame_type = PHP_FRAME_UNKNOWN;
        __builtin_memset(symbol->filename, 0, sizeof(symbol->filename));
        __builtin_memset(symbol->class_name, 0, sizeof(symbol->class_name));
        symbol->lineno = 0;
    }

    return 0;
}

/* Helper function to get line number from execute_data */
static inline __attribute__((always_inline))
__u32 get_php_line_number(__u64 execute_data_addr, php_offsets_t *offsets) {
    __u64 opline_addr = 0;
    if (bpf_probe_read_user(&opline_addr, sizeof(__u64),
                           (void *)(execute_data_addr + offsets->ed_opline)) != 0 ||
        opline_addr == 0) {
        return 0;
    }

    __u32 lineno = 0;
    if (bpf_probe_read_user(&lineno, sizeof(__u32),
                           (void *)(opline_addr + offsets->op_lineno)) != 0) {
        return 0;
    }

    return lineno;
}

/* Main PHP stack unwinding function */
static inline __attribute__((always_inline))
int php_unwind_stack_detailed(void *ctx, extended_unwind_state_t *state) {
    /* Get PHP offsets */
    php_offsets_t *offsets = php_offsets_map__lookup(&state->runtime_ctx.php.offsets_id);
    if (!offsets) {
        return -EINVAL;
    }

    /* Get PHP runtime info */
    php_runtime_info_t *php_info = php_runtime_info_map__lookup(&state->key.tgid);
    if (!php_info) {
        return -ENOENT;
    }

    /* Read executor_globals address */
    __u64 eg_addr = php_info->executor_globals;
    if (eg_addr == 0) {
        return -EINVAL;
    }

    /* Read current_execute_data from executor_globals */
    __u64 execute_data_addr = 0;
    if (bpf_probe_read_user(&execute_data_addr, sizeof(__u64),
                           (void *)(eg_addr + offsets->eg_current_execute_data)) != 0) {
        return -EFAULT;
    }

    if (!is_valid_execute_data(execute_data_addr)) {
        return 0; /* No valid PHP frames */
    }

    /* Initialize stack frame index */
    __u32 frame_idx = 0;
    __u32 max_frames = MAX_INTERPRETER_STACK_DEPTH;
    if (max_frames > PHP_MAX_STACK_DEPTH) {
        max_frames = PHP_MAX_STACK_DEPTH;
    }

    /* Unwind PHP execution stack */
    #pragma unroll
    for (int i = 0; i < MAX_STACK_UNWIND_LOOPS; i++) {
        if (frame_idx >= max_frames || !is_valid_execute_data(execute_data_addr)) {
            break;
        }

        /* Read function pointer from execute_data */
        __u64 func_addr = 0;
        if (bpf_probe_read_user(&func_addr, sizeof(__u64),
                               (void *)(execute_data_addr + offsets->ed_func)) != 0) {
            break;
        }

        if (func_addr != 0) {
            /* Extract function information */
            php_symbol_t *symbol = &state->interpreter_stack.php_symbols[frame_idx];
            __builtin_memset(symbol, 0, sizeof(*symbol));

            if (extract_php_function_info(func_addr, symbol, offsets) == 0) {
                /* Get line number for user functions */
                if (symbol->frame_type == PHP_FRAME_USER) {
                    symbol->lineno = get_php_line_number(execute_data_addr, offsets);
                }

                frame_idx++;
            }
        }

        /* Move to previous execute_data */
        __u64 prev_execute_data = 0;
        if (bpf_probe_read_user(&prev_execute_data, sizeof(__u64),
                               (void *)(execute_data_addr + offsets->ed_prev_execute_data)) != 0) {
            break;
        }

        execute_data_addr = prev_execute_data;
    }

    /* Update interpreter stack information */
    state->interpreter_stack.php_stack_len = frame_idx;
    state->interpreter_stack.runtime_type = RUNTIME_TYPE_PHP;

    return frame_idx > 0 ? 0 : -ENODATA;
}

char _license[] SEC("license") = "GPL";
