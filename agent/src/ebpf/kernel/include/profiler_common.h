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

#ifndef _PROFILER_COMMON_H
#define _PROFILER_COMMON_H

#include "common.h"

/* Runtime types for language-specific profiling */
#define RUNTIME_TYPE_UNKNOWN    0
#define RUNTIME_TYPE_PYTHON     1
#define RUNTIME_TYPE_PHP        2
#define RUNTIME_TYPE_NODEJS     3
#define RUNTIME_TYPE_V8         4
#define RUNTIME_TYPE_NATIVE     5

/* Tail-call program indices */
#define PROG_ENTRY_IDX              0
#define PROG_PHP_UNWIND_IDX         1
#define PROG_NODEJS_UNWIND_IDX      2
#define PROG_V8_UNWIND_IDX          3
#define PROG_PYTHON_UNWIND_IDX      4
#define PROG_NATIVE_UNWIND_IDX      5
#define PROG_OUTPUT_HANDLER_IDX     6
#define PROG_MAX_IDX                7

/* Stack frame types */
#define FRAME_TYPE_UNKNOWN          0
#define FRAME_TYPE_NATIVE           1
#define FRAME_TYPE_PHP              2
#define FRAME_TYPE_NODEJS           3
#define FRAME_TYPE_V8_JS            4
#define FRAME_TYPE_V8_STUB          5
#define FRAME_TYPE_PYTHON           6

/* Maximum stack depths */
#define MAX_PHP_STACK_DEPTH         32
#define MAX_NODEJS_STACK_DEPTH      64
#define MAX_V8_STACK_DEPTH          64
#define MAX_PYTHON_STACK_DEPTH      64
#define MAX_INTERPRETER_STACK_DEPTH 64

/* Forward declarations to avoid circular dependencies */
typedef struct php_symbol_t php_symbol_t;
typedef struct nodejs_symbol_t nodejs_symbol_t;

/* Runtime-specific data structures */
typedef struct {
    __u32 runtime_type;
    __u32 version_major;
    __u32 version_minor;
    __u32 version_patch;
    __u64 key_addresses[8];  // executor_globals, isolate, etc.
    __u8 offsets_id;
    __u8 flags;
    __u8 reserved[2];
} runtime_info_t;

/* PHP-specific structures */
typedef struct {
    __u64 executor_globals;
    __u8 offsets_id;
    __u8 version_major;
    __u8 version_minor;
    __u8 sapi_type;  // CLI, FPM, Apache, etc.
} php_runtime_info_t;

/* Node.js/V8-specific structures */
typedef struct {
    __u64 isolate_addr;
    __u64 thread_local_top;
    __u8 offsets_id;
    __u8 v8_version_major;
    __u8 v8_version_minor;
    __u8 node_version_major;
} nodejs_runtime_info_t;

/* Stack unwinding state shared across tail-calls */
typedef struct {
    struct stack_trace_key_t key;
    __u8 runs;
    __u8 runtime_type;
    __u8 frame_count;
    __u8 reserved;
    
    // Native stack context
    regs_t regs;
    stack_t native_stack;
    
    // Interpreter stack context
    union {
        struct {
            __u8 php_stack_len;
            __u8 runtime_type;
            __u8 reserved[2];
            php_symbol_t php_symbols[MAX_PHP_STACK_DEPTH];
        };
        struct {
            __u8 nodejs_stack_len;
            __u8 runtime_type_v8;
            __u8 reserved_v8[2];
            nodejs_symbol_t nodejs_symbols[MAX_NODEJS_STACK_DEPTH];
        };
        struct {
            __u8 len;
            __u64 addrs[MAX_INTERPRETER_STACK_DEPTH];
        } generic;
    } interpreter_stack;
    
    // Runtime-specific context
    union {
        struct {
            void *frame_ptr;
            __u8 offsets_id;
        } php;
        
        struct {
            void *isolate;
            void *current_frame;
            __u8 offsets_id;
        } nodejs;
        
        struct {
            void *py_frame_ptr;
            __u8 py_offsets_id;
        } python;
    } runtime_ctx;
} extended_unwind_state_t;

/* Helper macros */
#define GET_PHP_CTX(state)      (&(state)->runtime_ctx.php)
#define GET_NODEJS_CTX(state)   (&(state)->runtime_ctx.nodejs)
#define GET_PYTHON_CTX(state)   (&(state)->runtime_ctx.python)

/* Function declarations */
static inline __attribute__((always_inline))
int detect_runtime_type(__u32 pid);

static inline __attribute__((always_inline))
int should_profile_runtime(__u8 runtime_type);

static inline __attribute__((always_inline))
void init_unwind_state(extended_unwind_state_t *state, __u32 pid, __u32 tid);

#endif /* _PROFILER_COMMON_H */