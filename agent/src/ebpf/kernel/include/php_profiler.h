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

#ifndef _PHP_PROFILER_H
#define _PHP_PROFILER_H

#include "profiler_common.h"

/* PHP version constants */
#define PHP_VERSION_7_0     0x70000
#define PHP_VERSION_7_4     0x70400
#define PHP_VERSION_8_0     0x80000
#define PHP_VERSION_8_1     0x80100
#define PHP_VERSION_8_2     0x80200

/* PHP SAPI types */
#define PHP_SAPI_CLI        1
#define PHP_SAPI_FPM        2
#define PHP_SAPI_APACHE     3
#define PHP_SAPI_NGINX      4

/* PHP function types */
#define ZEND_INTERNAL_FUNCTION  1
#define ZEND_USER_FUNCTION      2

/* PHP frame types */
#define PHP_FRAME_USER          1
#define PHP_FRAME_INTERNAL      2
#define PHP_FRAME_UNKNOWN       3

/* PHP stack limits */
#define PHP_MAX_STACK_DEPTH     256
#define MAX_STACK_UNWIND_LOOPS  32

/* PHP offsets structure */
typedef struct {
    // executor_globals offsets
    __u16 eg_current_execute_data;
    __u16 eg_vm_stack;
    __u16 eg_vm_stack_top;
    __u16 eg_vm_stack_end;
    
    // zend_execute_data offsets
    __u16 ed_opline;
    __u16 ed_call;
    __u16 ed_return_value;
    __u16 ed_func;
    __u16 ed_this;
    __u16 ed_prev_execute_data;
    __u16 ed_symbol_table;
    
    // zend_function offsets
    __u16 func_common_function_name;
    __u16 func_common_scope;
    __u16 func_common_prototype;
    __u16 func_type;
    __u16 func_op_array;
    
    // zend_op_array offsets
    __u16 op_array_filename;
    __u16 op_array_function_name;
    __u16 op_array_scope;
    __u16 op_array_line_start;
    __u16 op_array_line_end;
    
    // zend_class_entry offsets
    __u16 ce_name;
    __u16 ce_parent;
    __u16 ce_type;
    
    // zend_string offsets
    __u16 str_val;
    __u16 str_len;
    
    // zend_op offsets (for line number calculation)
    __u16 op_lineno;
} php_offsets_t;

/* PHP symbol information */
typedef struct {
    char function_name[64];
    char filename[128];
    char class_name[64];
    __u32 lineno;
    __u8 frame_type;
    __u8 reserved[3];
} php_symbol_t;

/* PHP frame information */
typedef struct {
    void *execute_data;
    void *func;
    void *opline;
    __u32 lineno;
    __u8 func_type;
    __u8 reserved[3];
} php_frame_t;

/* BPF Maps for PHP profiling */
MAP_HASH(php_runtime_info_map, __u32, php_runtime_info_t, 65536, FEATURE_FLAG_PROFILE)
MAP_HASH(php_offsets_map, __u8, php_offsets_t, 16, FEATURE_FLAG_PROFILE)

/* Helper functions */
static inline __attribute__((always_inline))
int php_unwind_stack(void *ctx, extended_unwind_state_t *state);

static inline __attribute__((always_inline))
int php_get_frame_info(extended_unwind_state_t *state, 
                       void *execute_data,
                       php_frame_t *frame);

static inline __attribute__((always_inline))
int php_calculate_line_number(void *opline, void *op_array);

static inline __attribute__((always_inline))
bool php_is_valid_execute_data(void *execute_data);

static inline __attribute__((always_inline))
bool php_is_user_function(__u8 func_type);

/* Function implementations */
static inline __attribute__((always_inline))
bool php_is_valid_execute_data(void *execute_data) {
    return execute_data != NULL && 
           execute_data > (void *)0x1000 && 
           execute_data < (void *)0x7fffffffffff;
}

static inline __attribute__((always_inline))
bool php_is_user_function(__u8 func_type) {
    return func_type == ZEND_USER_FUNCTION;
}

static inline __attribute__((always_inline))
int php_calculate_line_number(void *opline, void *op_array) {
    if (!opline || !op_array) {
        return 0;
    }
    
    // For now, return a simple line number
    // In production, this would involve more complex calculation
    __u32 lineno = 0;
    php_offsets_t *offsets = php_offsets_map__lookup(&0);
    if (!offsets) {
        return 0;
    }
    
    // Try to read line number from opline
    if (bpf_probe_read_user(&lineno, sizeof(lineno),
                            opline + offsets->op_lineno) == 0) {
        return lineno;
    }
    
    return 0;
}

#endif /* _PHP_PROFILER_H */