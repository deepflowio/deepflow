/*
 * Enhanced eBPF profiler with multi-language support
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

#include <linux/bpf_perf_event.h>
#include "config.h"
#include "bpf_base.h"
#include "common.h"
#include "kernel.h"
#include "bpf_endian.h"
#include "perf_profiler.h"
#include "profiler_common.h"
#include "php_profiler.h"
#include "nodejs_profiler.h"
#include "enhanced_security.bpf.h"

/* Enhanced heap for extended unwind state */
MAP_PERARRAY(enhanced_heap, __u32, extended_unwind_state_t, 1,
             FEATURE_FLAG_PROFILE_ONCPU | FEATURE_FLAG_PROFILE_OFFCPU)

/* Tail-call program array for enhanced profiler */
MAP_PROG_ARRAY(enhanced_progs_jmp_map, __u32, __u32, PROG_MAX_IDX, FEATURE_FLAG_PROFILE_ONCPU)

/* Runtime detection map */
MAP_HASH(runtime_detection_map, __u32, runtime_info_t, 65536, FEATURE_FLAG_PROFILE)

/* PHP runtime maps */
MAP_HASH(php_runtime_info_map, __u32, php_runtime_info_t, 1024, FEATURE_FLAG_PROFILE)
MAP_HASH(php_offsets_map, __u8, php_offsets_t, 16, FEATURE_FLAG_PROFILE)

/* Node.js runtime maps */
MAP_HASH(nodejs_runtime_info_map, __u32, nodejs_runtime_info_t, 1024, FEATURE_FLAG_PROFILE)
MAP_HASH(v8_offsets_map, __u8, v8_offsets_t, 16, FEATURE_FLAG_PROFILE)

/* Per-CPU cache for frequently accessed data */
MAP_PERCPU_ARRAY(cached_php_offsets, __u32, php_offsets_t, 256, FEATURE_FLAG_PROFILE)
MAP_PERCPU_ARRAY(cached_php_runtime_info, __u32, php_runtime_info_t, 1024, FEATURE_FLAG_PROFILE)
MAP_PERCPU_ARRAY(cached_v8_offsets, __u32, v8_offsets_t, 256, FEATURE_FLAG_PROFILE)
MAP_PERCPU_ARRAY(cached_nodejs_runtime_info, __u32, nodejs_runtime_info_t, 1024, FEATURE_FLAG_PROFILE)

/* Error codes for consistent error handling */
#define PROFILER_SUCCESS                0
#define PROFILER_ERROR_INVALID_POINTER -1
#define PROFILER_ERROR_NO_MEMORY       -2
#define PROFILER_ERROR_NO_RUNTIME      -3
#define PROFILER_ERROR_READ_FAILED     -4
#define PROFILER_ERROR_INVALID_DATA    -5

/* Legacy security helper functions - replaced by enhanced_security.bpf.h */
static inline __attribute__((always_inline))
int validate_user_pointer(__u64 addr, size_t size) {
    /* Use enhanced validation with current process context */
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    int result = enhanced_validate_user_pointer(addr, size, pid, 1);
    return (result == 0) ? 1 : 0; /* Convert to legacy return format */
}

static inline __attribute__((always_inline))
int secure_read_user_string(__u64 addr, char *buffer, __u32 max_size) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    /* Use enhanced security validation */
    int result = secure_read_user_string_enhanced(addr, buffer, max_size, pid);

    /* Convert to legacy error codes */
    switch (result) {
        case 0:
            return PROFILER_SUCCESS;
        case -EINVAL:
        case -EFAULT:
        case -ERANGE:
            return PROFILER_ERROR_INVALID_POINTER;
        case -EBUSY:
        case -EPERM:
            return PROFILER_ERROR_READ_FAILED;
        default:
            return PROFILER_ERROR_READ_FAILED;
    }
}

static inline __attribute__((always_inline))
int v8_is_valid_frame_pointer_inline(__u64 fp) {
    return validate_user_pointer(fp, sizeof(__u64)) && ((fp & 0x7) == 0);
}

static inline __attribute__((always_inline))
__u8 v8_classify_frame_type_inline(__u64 marker) {
    // JavaScript frames have SMI tag (low bit clear)
    if ((marker & 0x1) == 0) {
        return V8_FRAME_JAVASCRIPT;
    } else if (marker >= 0x80000000 && marker <= 0xFFFFFFFF) {
        return V8_FRAME_STUB;
    } else {
        return V8_FRAME_NATIVE;
    }
}

static inline __attribute__((always_inline))
int v8_extract_js_function_info(__u64 function, nodejs_symbol_t *symbol, v8_offsets_t *offsets) {
    if (!validate_user_pointer(function, sizeof(__u64))) {
        return -1;
    }

    // Read SharedFunctionInfo from JSFunction
    __u64 shared_info = 0;
    if (bpf_probe_read_user(&shared_info, sizeof(__u64),
                           (void *)(function + offsets->js_func_shared_info)) != 0 ||
        !validate_user_pointer(shared_info, sizeof(__u64))) {
        return -1;
    }

    // Extract function name from SharedFunctionInfo
    __u64 name_addr = 0;
    if (bpf_probe_read_user(&name_addr, sizeof(__u64),
                           (void *)(shared_info + offsets->sfi_name_or_scope_info)) == 0 &&
        validate_user_pointer(name_addr, sizeof(__u64))) {

        if (secure_read_user_string(name_addr, symbol->function_name,
                                   sizeof(symbol->function_name)) != 0) {
            __builtin_memcpy(symbol->function_name, "<anonymous>", 12);
        }
    } else {
        __builtin_memcpy(symbol->function_name, "<unknown>", 10);
    }

    return 0;
}

/* Cache optimization helpers */
static inline __attribute__((always_inline))
php_offsets_t* get_cached_php_offsets(__u8 offsets_id) {
    // Try per-CPU cache first
    __u32 cache_key = (__u32)offsets_id;
    php_offsets_t *cached = cached_php_offsets__lookup(&cache_key);
    if (cached) {
        return cached;
    }

    // Fallback to global map
    return php_offsets_map__lookup(&offsets_id);
}

static inline __attribute__((always_inline))
php_runtime_info_t* get_cached_php_runtime_info(__u32 tgid) {
    // Try per-CPU cache first
    php_runtime_info_t *cached = cached_php_runtime_info__lookup(&tgid);
    if (cached) {
        return cached;
    }

    // Fallback to global map
    return php_runtime_info_map__lookup(&tgid);
}

static inline __attribute__((always_inline))
v8_offsets_t* get_cached_v8_offsets(__u8 offsets_id) {
    // Try per-CPU cache first
    __u32 cache_key = (__u32)offsets_id;
    v8_offsets_t *cached = cached_v8_offsets__lookup(&cache_key);
    if (cached) {
        return cached;
    }

    // Fallback to global map
    return v8_offsets_map__lookup(&offsets_id);
}

static inline __attribute__((always_inline))
nodejs_runtime_info_t* get_cached_nodejs_runtime_info(__u32 tgid) {
    // Try per-CPU cache first
    nodejs_runtime_info_t *cached = cached_nodejs_runtime_info__lookup(&tgid);
    if (cached) {
        return cached;
    }

    // Fallback to global map
    return nodejs_runtime_info_map__lookup(&tgid);
}

/* Helper functions */
static inline __attribute__((always_inline))
int detect_runtime_type(__u32 pid) {
    runtime_info_t *info = runtime_detection_map__lookup(&pid);
    if (info) {
        return info->runtime_type;
    }
    return RUNTIME_TYPE_UNKNOWN;
}

static inline __attribute__((always_inline))
int should_profile_runtime(__u8 runtime_type) {
    switch (runtime_type) {
        case RUNTIME_TYPE_PHP:
        case RUNTIME_TYPE_NODEJS:
        case RUNTIME_TYPE_V8:
        case RUNTIME_TYPE_PYTHON:
            return 1;
        default:
            return 0;
    }
}

static inline __attribute__((always_inline))
void init_unwind_state(extended_unwind_state_t *state, __u32 pid, __u32 tid) {
    __builtin_memset(state, 0, sizeof(*state));

    state->key.tgid = pid;
    state->key.pid = tid;
    state->key.cpu = bpf_get_smp_processor_id();
    state->key.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&state->key.comm, sizeof(state->key.comm));

    state->runtime_type = detect_runtime_type(pid);
}

/* Enhanced profiler entry point */
SEC("perf_event")
int enhanced_oncpu_profile(struct bpf_perf_event_data *ctx) {
    __u32 count_idx = ENABLE_IDX;
    __u64 *enable_ptr = profiler_state_map__lookup(&count_idx);

    if (enable_ptr == NULL || unlikely(*enable_ptr == 0)) {
        return 0;
    }

    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u32 tid = (__u32)id;

    /* Skip kernel threads and idle process */
    if (pid == 0 || (pid == tid && pid == 0)) {
        return 0;
    }

    /* Get enhanced unwind state */
    __u32 zero = 0;
    extended_unwind_state_t *state = enhanced_heap__lookup(&zero);
    if (state == NULL) {
        return 0;
    }

    /* Initialize state */
    init_unwind_state(state, pid, tid);

    /* Detect runtime and route to appropriate unwinder */
    __u8 runtime_type = state->runtime_type;

    if (!should_profile_runtime(runtime_type)) {
        /* Fall back to native profiling */
        runtime_type = RUNTIME_TYPE_NATIVE;
    }

    /* Route to appropriate unwinder via tail-call */
    switch (runtime_type) {
        case RUNTIME_TYPE_PHP:
            bpf_tail_call(ctx, &NAME(enhanced_progs_jmp_map), PROG_PHP_UNWIND_IDX);
            break;

        case RUNTIME_TYPE_NODEJS:
        case RUNTIME_TYPE_V8:
            bpf_tail_call(ctx, &NAME(enhanced_progs_jmp_map), PROG_NODEJS_UNWIND_IDX);
            break;

        case RUNTIME_TYPE_PYTHON:
            bpf_tail_call(ctx, &NAME(enhanced_progs_jmp_map), PROG_PYTHON_UNWIND_IDX);
            break;

        default:
            /* Native unwinding */
            bpf_tail_call(ctx, &NAME(enhanced_progs_jmp_map), PROG_NATIVE_UNWIND_IDX);
            break;
    }

    /* If tail-call fails, increment error counter */
    count_idx = ERROR_IDX;
    __u64 *error_count_ptr = profiler_state_map__lookup(&count_idx);
    if (error_count_ptr) {
        __sync_fetch_and_add(error_count_ptr, 1);
    }

    return 0;
}

/* PHP unwinder implementation */
SEC("perf_event")
int php_unwinder(struct bpf_perf_event_data *ctx) {
    __u32 zero = 0;
    extended_unwind_state_t *state = enhanced_heap__lookup(&zero);
    if (state == NULL) {
        return 0;
    }

    /* Get PHP runtime info */
    php_runtime_info_t *php_info = php_runtime_info_map__lookup(&state->key.tgid);
    if (php_info == NULL) {
        /* No PHP info found, fallback to native */
        bpf_tail_call(ctx, &NAME(enhanced_progs_jmp_map), PROG_NATIVE_UNWIND_IDX);
        return 0;
    }

    /* Set PHP context */
    state->runtime_ctx.php.offsets_id = php_info->offsets_id;

    /* Perform PHP stack unwinding */
    int ret = php_unwind_stack(ctx, state);
    if (ret < 0) {
        /* Error in PHP unwinding, increment error counter */
        __u32 count_idx = ERROR_IDX;
        __u64 *error_count_ptr = profiler_state_map__lookup(&count_idx);
        if (error_count_ptr) {
            __sync_fetch_and_add(error_count_ptr, 1);
        }
    }

    /* Continue to output handler */
    bpf_tail_call(ctx, &NAME(enhanced_progs_jmp_map), PROG_OUTPUT_HANDLER_IDX);
    return 0;
}

/* Node.js unwinder implementation */
SEC("perf_event")
int nodejs_unwinder(struct bpf_perf_event_data *ctx) {
    __u32 zero = 0;
    extended_unwind_state_t *state = enhanced_heap__lookup(&zero);
    if (state == NULL) {
        return 0;
    }

    /* Get Node.js runtime info */
    nodejs_runtime_info_t *nodejs_info = nodejs_runtime_info_map__lookup(&state->key.tgid);
    if (nodejs_info == NULL) {
        /* No Node.js info found, fallback to native */
        bpf_tail_call(ctx, &NAME(enhanced_progs_jmp_map), PROG_NATIVE_UNWIND_IDX);
        return 0;
    }

    /* Set Node.js context */
    state->runtime_ctx.nodejs.isolate = (void *)nodejs_info->isolate_addr;
    state->runtime_ctx.nodejs.offsets_id = nodejs_info->offsets_id;

    /* Perform Node.js/V8 stack unwinding */
    int ret = nodejs_unwind_stack(ctx, state);
    if (ret < 0) {
        /* Error in Node.js unwinding, increment error counter */
        __u32 count_idx = ERROR_IDX;
        __u64 *error_count_ptr = profiler_state_map__lookup(&count_idx);
        if (error_count_ptr) {
            __sync_fetch_and_add(error_count_ptr, 1);
        }
    }

    /* Continue to output handler */
    bpf_tail_call(ctx, &NAME(enhanced_progs_jmp_map), PROG_OUTPUT_HANDLER_IDX);
    return 0;
}

/* Native unwinder (fallback) */
SEC("perf_event")
int native_unwinder(struct bpf_perf_event_data *ctx) {
    __u32 zero = 0;
    extended_unwind_state_t *state = enhanced_heap__lookup(&zero);
    if (state == NULL) {
        return 0;
    }

    /* Collect native stack traces using existing mechanism */
    state->key.kernstack = bpf_get_stackid(ctx, &NAME(stack_map_a), 0);
    state->key.userstack = bpf_get_stackid(ctx, &NAME(stack_map_a), BPF_F_USER_STACK);

    /* Continue to output handler */
    bpf_tail_call(ctx, &NAME(enhanced_progs_jmp_map), PROG_OUTPUT_HANDLER_IDX);
    return 0;
}

/* Output handler */
SEC("perf_event")
int output_handler(struct bpf_perf_event_data *ctx) {
    __u32 zero = 0;
    extended_unwind_state_t *state = enhanced_heap__lookup(&zero);
    if (state == NULL) {
        return 0;
    }

    /* Convert interpreter stack to legacy format for output */
    stack_t legacy_stack = {0};
    if (state->runtime_type == RUNTIME_TYPE_PHP &&
        state->interpreter_stack.php_stack_len > 0) {
        /* For now, just output the count */
        legacy_stack.len = state->interpreter_stack.php_stack_len;
    }

    /* Get oncpu maps reference */
    extern map_group_t oncpu_maps;

    /* Send stack trace to user space using existing mechanism */
    return collect_stack_and_send_output(&ctx->regs, &state->key,
                                        &state->native_stack,
                                        &legacy_stack,
                                        &oncpu_maps, false);
}

/* PHP stack unwinding implementation */
static inline __attribute__((always_inline))
int php_unwind_stack(void *ctx, extended_unwind_state_t *state) {
    php_offsets_t *offsets = get_cached_php_offsets(state->runtime_ctx.php.offsets_id);
    if (!offsets) {
        return PROFILER_ERROR_NO_RUNTIME;
    }

    php_runtime_info_t *php_info = get_cached_php_runtime_info(state->key.tgid);
    if (!php_info) {
        return PROFILER_ERROR_NO_RUNTIME;
    }

    /* Read executor_globals address with enhanced validation */
    __u64 eg_addr = php_info->executor_globals;

    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    /* Check memory access rate limiting first */
    int rate_check = check_memory_access_rate_limit(pid);
    if (rate_check != 0) {
        return PROFILER_ERROR_READ_FAILED;
    }

    /* Enhanced pointer validation with memory region awareness */
    int validation_result = validate_pointer_with_layout(
        eg_addr, sizeof(__u64), pid, MEMORY_REGION_HEAP);
    if (validation_result != 0) {
        return PROFILER_ERROR_INVALID_POINTER;
    }

    /* Read current_execute_data from executor_globals with secure access */
    __u64 execute_data_addr = 0;
    int read_result = secure_read_user_memory(
        eg_addr + offsets->eg_current_execute_data,
        &execute_data_addr, sizeof(__u64), pid, MEMORY_REGION_HEAP);
    if (read_result != 0) {
        return PROFILER_ERROR_READ_FAILED;
    }

    /* Validate execute_data pointer with enhanced security */
    validation_result = validate_pointer_with_layout(
        execute_data_addr, sizeof(__u64), pid, MEMORY_REGION_HEAP);
    if (validation_result != 0) {
        return PROFILER_SUCCESS; /* No PHP stack frames or invalid pointer */
    }

    /* Initialize stack frame index */
    __u32 frame_idx = 0;
    __u32 max_frames = MAX_INTERPRETER_STACK_DEPTH;

    /* Safe unwind PHP stack frames with dynamic bounds checking */
    __u32 safe_limit = max_frames < 16 ? max_frames : 16; // Strict eBPF verifier limit
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (i >= safe_limit || frame_idx >= max_frames ||
            !validate_user_pointer(execute_data_addr, sizeof(__u64))) {
            break;
        }

        /* Read function pointer from execute_data with enhanced security */
        __u64 func_addr = 0;
        read_result = secure_read_user_memory(
            execute_data_addr + offsets->ed_func,
            &func_addr, sizeof(__u64), pid, MEMORY_REGION_HEAP);
        if (read_result != 0) {
            break;
        }

        if (func_addr == 0) {
            goto next_frame;
        }

        /* Read function type to determine if it's internal or user function */
        __u8 func_type = 0;
        if (bpf_probe_read_user(&func_type, sizeof(__u8),
                               (void *)(func_addr + offsets->func_type)) != 0) {
            goto next_frame;
        }

        /* For user functions (ZEND_USER_FUNCTION = 2) */
        if (func_type == 2) {
            /* Get op_array for user functions */
            __u64 op_array_addr = func_addr + offsets->func_op_array;

            /* Read function name */
            __u64 func_name_addr = 0;
            if (bpf_probe_read_user(&func_name_addr, sizeof(__u64),
                                   (void *)(op_array_addr + offsets->op_array_function_name)) == 0 &&
                func_name_addr != 0) {

                /* Read zend_string for function name - str_val is offset to data, not pointer */
                __u64 name_str_addr = func_name_addr + offsets->str_val;
                if (name_str_addr != 0) {

                    /* Store function name in interpreter stack */
                    php_symbol_t *symbol = &state->interpreter_stack.php_symbols[frame_idx];
                    if (secure_read_user_string(name_str_addr, symbol->function_name,
                                               sizeof(symbol->function_name)) != 0) {
                        // Failed to read function name, use placeholder
                        __builtin_memcpy(symbol->function_name, "<unknown>", 10);
                    }

                    /* Read filename */
                    __u64 filename_addr = 0;
                    if (bpf_probe_read_user(&filename_addr, sizeof(__u64),
                                           (void *)(op_array_addr + offsets->op_array_filename)) == 0 &&
                        filename_addr != 0) {

                        /* str_val is offset to data, not pointer */
                        __u64 filename_str_addr = filename_addr + offsets->str_val;
                        if (secure_read_user_string(filename_str_addr, symbol->filename,
                                                   sizeof(symbol->filename)) != 0) {
                            __builtin_memcpy(symbol->filename, "<unknown>", 10);
                        }
                    }

                    /* Read line number from current opline */
                    __u64 opline_addr = 0;
                    if (bpf_probe_read_user(&opline_addr, sizeof(__u64),
                                           (void *)(execute_data_addr + offsets->ed_opline)) == 0 &&
                        opline_addr != 0) {

                        if (bpf_probe_read_user(&symbol->lineno, sizeof(__u32),
                                               (void *)(opline_addr + offsets->op_lineno)) != 0) {
                            symbol->lineno = 0;
                        }
                    }

                    /* Read class name if method call */
                    __u64 scope_addr = 0;
                    if (bpf_probe_read_user(&scope_addr, sizeof(__u64),
                                           (void *)(op_array_addr + offsets->op_array_scope)) == 0 &&
                        scope_addr != 0) {

                        __u64 class_name_addr = 0;
                        if (bpf_probe_read_user(&class_name_addr, sizeof(__u64),
                                               (void *)(scope_addr + offsets->ce_name)) == 0 &&
                            class_name_addr != 0) {

                            /* str_val is offset to data, not pointer */
                            __u64 class_str_addr = class_name_addr + offsets->str_val;
                                if (secure_read_user_string(class_str_addr, symbol->class_name,
                                                           sizeof(symbol->class_name)) != 0) {
                                    __builtin_memcpy(symbol->class_name, "<unknown>", 10);
                                }
                            }
                        }
                    }

                    symbol->frame_type = PHP_FRAME_USER;
                    frame_idx++;
                }
            }
        } else if (func_type == 1) {
            /* Internal function (ZEND_INTERNAL_FUNCTION = 1) */
            __u64 func_name_addr = 0;
            if (bpf_probe_read_user(&func_name_addr, sizeof(__u64),
                                   (void *)(func_addr + offsets->func_common_function_name)) == 0 &&
                func_name_addr != 0) {

                /* str_val is offset to data, not pointer */
                __u64 name_str_addr = func_name_addr + offsets->str_val;
                if (name_str_addr != 0) {
                    php_symbol_t *symbol = &state->interpreter_stack.php_symbols[frame_idx];
                    if (secure_read_user_string(name_str_addr, symbol->function_name,
                                               sizeof(symbol->function_name)) != 0) {
                        __builtin_memcpy(symbol->function_name, "<internal>", 11);
                    }

                    /* Mark as internal function */
                    symbol->frame_type = PHP_FRAME_INTERNAL;
                    symbol->lineno = 0;
                    __builtin_memset(symbol->filename, 0, sizeof(symbol->filename));
                    __builtin_memset(symbol->class_name, 0, sizeof(symbol->class_name));

                    frame_idx++;
                }
            }
        }

    next_frame:
        /* Move to previous execute_data */
        __u64 prev_execute_data = 0;
        if (bpf_probe_read_user(&prev_execute_data, sizeof(__u64),
                               (void *)(execute_data_addr + offsets->ed_prev_execute_data)) != 0) {
            break;
        }
        execute_data_addr = prev_execute_data;
    }

    /* Update interpreter stack count */
    state->interpreter_stack.php_stack_len = frame_idx;
    state->interpreter_stack.runtime_type = RUNTIME_TYPE_PHP;

    return PROFILER_SUCCESS;
}

static inline __attribute__((always_inline))
int nodejs_unwind_stack(void *ctx, extended_unwind_state_t *state) {
    v8_offsets_t *offsets = get_cached_v8_offsets(state->runtime_ctx.nodejs.offsets_id);
    if (!offsets) {
        return PROFILER_ERROR_NO_RUNTIME;
    }

    nodejs_runtime_info_t *nodejs_info = get_cached_nodejs_runtime_info(state->key.tgid);
    if (!nodejs_info) {
        return PROFILER_ERROR_NO_RUNTIME;
    }

    /* Get Isolate and ThreadLocalTop addresses with enhanced validation */
    __u64 isolate_addr = nodejs_info->isolate_addr;
    __u64 thread_local_top = nodejs_info->thread_local_top;

    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    /* Check memory access rate limiting */
    int rate_check = check_memory_access_rate_limit(pid);
    if (rate_check != 0) {
        return PROFILER_ERROR_READ_FAILED;
    }

    /* Enhanced validation for V8 isolate address */
    int validation_result = validate_pointer_with_layout(
        isolate_addr, sizeof(__u64), pid, MEMORY_REGION_HEAP);
    if (validation_result != 0) {
        return PROFILER_ERROR_INVALID_POINTER;
    }

    /* If ThreadLocalTop is not pre-calculated, derive it from Isolate */
    if (thread_local_top == 0) {
        if (bpf_probe_read_user(&thread_local_top, sizeof(__u64),
                               (void *)(isolate_addr + offsets->isolate_thread_local_top)) != 0) {
            return PROFILER_ERROR_READ_FAILED;
        }
    }

    /* Get current JavaScript stack pointer from ThreadLocalTop */
    __u64 js_entry_sp = 0;
    if (bpf_probe_read_user(&js_entry_sp, sizeof(__u64),
                           (void *)(thread_local_top + offsets->tlt_js_entry_sp)) != 0) {
        return PROFILER_ERROR_READ_FAILED;
    }

    if (!validate_user_pointer(js_entry_sp, sizeof(__u64))) {
        return PROFILER_SUCCESS; /* No JavaScript frames or invalid pointer */
    }

    /* Start unwinding from the current frame pointer */
    __u64 current_fp = js_entry_sp;
    __u32 frame_idx = 0;
    __u32 max_frames = MAX_NODEJS_STACK_DEPTH;

    /* Safe unwind V8 JavaScript stack frames with dynamic bounds checking */
    __u32 safe_limit = max_frames < 16 ? max_frames : 16; // Strict eBPF verifier limit
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (i >= safe_limit || frame_idx >= max_frames || !v8_is_valid_frame_pointer_inline(current_fp)) {
            break;
        }

        /* Bulk read frame data for better performance */
        struct v8_frame_data {
            __u64 marker;       // Frame marker at offset 0
            __u64 pc;          // Program counter
            __u64 function;    // Function object
            __u64 context;     // Context object
        } frame_data = {0};

        /* Try to read all frame data in one operation */
        if (bpf_probe_read_user(&frame_data.marker, sizeof(__u64), (void *)current_fp) != 0) {
            break;
        }

        if (bpf_probe_read_user(&frame_data.pc, sizeof(__u64),
                               (void *)(current_fp + offsets->frame_pc)) != 0) {
            break;
        }

        if (bpf_probe_read_user(&frame_data.function, sizeof(__u64),
                               (void *)(current_fp + offsets->frame_function)) != 0) {
            frame_data.function = 0;
        }

        if (bpf_probe_read_user(&frame_data.context, sizeof(__u64),
                               (void *)(current_fp + offsets->frame_context)) != 0) {
            frame_data.context = 0;
        }

        __u64 frame_pc = frame_data.pc;
        __u64 frame_function = frame_data.function;
        __u64 frame_context = frame_data.context;
        __u64 frame_marker = frame_data.marker;

        /* Classify frame type */
        __u8 frame_type = v8_classify_frame_type_inline(frame_marker);

        /* Process JavaScript frames */
        if (frame_type == V8_FRAME_JAVASCRIPT && frame_function != 0) {
            nodejs_symbol_t *symbol = &state->interpreter_stack.nodejs_symbols[frame_idx];
            __builtin_memset(symbol, 0, sizeof(*symbol));

            /* Extract function information */
            if (v8_extract_js_function_info(frame_function, symbol, offsets) == 0) {
                symbol->frame_type = frame_type;
                frame_idx++;
            }
        } else if (frame_type == V8_FRAME_STUB || frame_type == V8_FRAME_BUILTIN) {
            /* Handle stub and builtin frames */
            nodejs_symbol_t *symbol = &state->interpreter_stack.nodejs_symbols[frame_idx];
            __builtin_memset(symbol, 0, sizeof(*symbol));

            if (frame_type == V8_FRAME_STUB) {
                __builtin_memcpy(symbol->function_name, "<stub>", 7);
            } else {
                __builtin_memcpy(symbol->function_name, "<builtin>", 10);
            }

            symbol->frame_type = frame_type;
            symbol->line_number = 0;
            symbol->column_number = 0;
            frame_idx++;
        }

        /* Move to next frame */
        __u64 next_fp = 0;
        if (bpf_probe_read_user(&next_fp, sizeof(__u64),
                               (void *)(current_fp + offsets->frame_fp)) != 0) {
            break;
        }

        /* Prevent infinite loops */
        if (next_fp <= current_fp || next_fp == 0) {
            break;
        }

        current_fp = next_fp;
    }

    /* Update interpreter stack information */
    state->interpreter_stack.nodejs_stack_len = frame_idx;
    state->interpreter_stack.runtime_type_v8 = RUNTIME_TYPE_NODEJS;

    return frame_idx > 0 ? PROFILER_SUCCESS : PROFILER_ERROR_INVALID_DATA;
}

char _license[] SEC("license") = "GPL";