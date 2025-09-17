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

#ifndef _NODEJS_PROFILER_H
#define _NODEJS_PROFILER_H

#include "profiler_common.h"

/* V8 version constants */
#define V8_VERSION_9_0      0x090000  // Node.js 16
#define V8_VERSION_10_0     0x0A0000  // Node.js 18
#define V8_VERSION_11_0     0x0B0000  // Node.js 20
#define V8_VERSION_12_0     0x0C0000  // Node.js 21+

/* V8 frame types - comprehensive list */
#define V8_FRAME_JAVASCRIPT         1
#define V8_FRAME_OPTIMIZED          2
#define V8_FRAME_INTERPRETED        3
#define V8_FRAME_STUB               4
#define V8_FRAME_BUILTIN            5
#define V8_FRAME_WASM               6
#define V8_FRAME_NATIVE             7
#define V8_FRAME_INTERNAL           8
#define V8_FRAME_CONSTRUCT          9
#define V8_FRAME_ARGUMENTS_ADAPTOR  10
#define V8_FRAME_BUILTIN_EXIT       11

/* V8 frame markers - updated for modern V8 */
#define V8_SMI_TAG_MASK             0x1
#define V8_HEAP_OBJECT_TAG          0x1
#define V8_WEAK_TAG_MASK            0x3
#define V8_STUB_MARKER_MIN          0x80000000
#define V8_STUB_MARKER_MAX          0xFFFFFFFF

/* V8 frame type markers for different frame types */
#define V8_STUB_FRAME_MARKER        0xDEADBEEF
#define V8_ENTRY_FRAME_MARKER       0xFFFFFFFE
#define V8_CONSTRUCT_FRAME_MARKER   0xFFFFFFFD
#define V8_EXIT_FRAME_MARKER        0xFFFFFFFC
#define V8_BUILTIN_EXIT_MARKER      0xFFFFFFFB
#define V8_INTERPRETER_FRAME_MARKER 0xFFFFFFFA
#define V8_OPTIMIZED_FRAME_MARKER   0xFFFFFFF9
#define V8_WASM_FRAME_MARKER        0xFFFFFFF8
#define V8_ARGUMENTS_MARKER         0xFFFFFFF7

/* Node.js stack limits */
#define NODEJS_MAX_STACK_DEPTH      64
#define MAX_STACK_UNWIND_LOOPS      32

/* V8 offsets structure */
typedef struct {
    // Isolate base offset (from module base)
    __u32 isolate_base_offset;

    // Isolate offsets
    __u16 isolate_thread_local_top;
    __u16 isolate_context;
    __u16 isolate_current_context;

    // ThreadLocalTop offsets
    __u16 tlt_js_entry_sp;
    __u16 tlt_external_callback_scope;
    __u16 tlt_current_context;
    __u16 tlt_pending_exception;

    // StandardFrame offsets
    __u16 frame_fp;
    __u16 frame_sp;
    __u16 frame_pc;
    __u16 frame_constant_pool;
    __u16 frame_context;
    __u16 frame_function;

    // JSFunction offsets
    __u16 js_func_shared_info;
    __u16 js_func_code;
    __u16 js_func_context;

    // SharedFunctionInfo offsets
    __u16 sfi_name_or_scope_info;
    __u16 sfi_script;
    __u16 sfi_start_position;
    __u16 sfi_end_position;

    // Script offsets
    __u16 script_source;
    __u16 script_source_url;
    __u16 script_line_offset;
    __u16 script_column_offset;

    // String offsets
    __u16 str_length;
    __u16 str_data;
} v8_offsets_t;

/* Node.js symbol information */
typedef struct {
    char function_name[64];
    char script_name[128];
    char source_url[128];
    __u32 line_number;
    __u32 column_number;
    __u8 frame_type;
    __u8 reserved[3];
} nodejs_symbol_t;

/* V8 frame information */
typedef struct {
    void *fp;        // Frame pointer
    void *sp;        // Stack pointer
    void *pc;        // Program counter
    void *function;  // JSFunction object
    void *context;   // Context object
    __u64 marker;    // Frame type marker
    __u8 frame_type;
    __u8 reserved[7];
} v8_frame_t;

/* V8 JavaScript function info */
typedef struct {
    void *shared_info;
    void *script;
    void *name;
    __u32 start_pos;
    __u32 end_pos;
    __u32 line_offset;
    __u32 column_offset;
} v8_js_func_info_t;

/* BPF Maps for Node.js/V8 profiling */
MAP_HASH(nodejs_runtime_info_map, __u32, nodejs_runtime_info_t, 65536, FEATURE_FLAG_PROFILE)
MAP_HASH(v8_offsets_map, __u8, v8_offsets_t, 16, FEATURE_FLAG_PROFILE)

/* Helper functions */
static inline __attribute__((always_inline))
int nodejs_unwind_stack(void *ctx, extended_unwind_state_t *state);

static inline __attribute__((always_inline))
int v8_get_frame_info(extended_unwind_state_t *state,
                      void *fp,
                      v8_frame_t *frame);

static inline __attribute__((always_inline))
int v8_classify_frame_type(v8_frame_t *frame);

static inline __attribute__((always_inline))
int v8_get_js_function_info(extended_unwind_state_t *state,
                           void *js_func,
                           v8_js_func_info_t *info);

static inline __attribute__((always_inline))
bool v8_is_valid_frame_pointer(void *fp);

static inline __attribute__((always_inline))
bool v8_is_javascript_frame(__u64 marker);

/* Function implementations */
static inline __attribute__((always_inline))
bool v8_is_valid_frame_pointer(void *fp) {
    return fp != NULL &&
           fp > (void *)0x1000 &&
           fp < (void *)0x7fffffffffff &&
           (((__u64)fp) & 0x7) == 0;  // 8-byte aligned
}

static inline __attribute__((always_inline))
bool v8_is_javascript_frame(__u64 marker) {
    // JavaScript frames have SMI tag (low bit clear)
    return (marker & V8_SMI_TAG_MASK) == 0;
}

static inline __attribute__((always_inline))
int v8_classify_frame_type(v8_frame_t *frame) {
    __u64 marker = frame->marker;

    /* Check for specific frame markers first */
    switch (marker) {
        case V8_STUB_FRAME_MARKER:
            return V8_FRAME_STUB;
        case V8_ENTRY_FRAME_MARKER:
            return V8_FRAME_NATIVE;
        case V8_CONSTRUCT_FRAME_MARKER:
            return V8_FRAME_CONSTRUCT;
        case V8_EXIT_FRAME_MARKER:
            return V8_FRAME_NATIVE;
        case V8_BUILTIN_EXIT_MARKER:
            return V8_FRAME_BUILTIN_EXIT;
        case V8_INTERPRETER_FRAME_MARKER:
            return V8_FRAME_INTERPRETED;
        case V8_OPTIMIZED_FRAME_MARKER:
            return V8_FRAME_OPTIMIZED;
        case V8_WASM_FRAME_MARKER:
            return V8_FRAME_WASM;
        case V8_ARGUMENTS_MARKER:
            return V8_FRAME_ARGUMENTS_ADAPTOR;
    }

    /* Check for SMI (Small Integer) tag - indicates JavaScript frame */
    if ((marker & V8_SMI_TAG_MASK) == 0) {
        /* Further distinguish between optimized and interpreted frames
         * by checking if there's a valid function object */
        if (frame->function != NULL && (((__u64)frame->function) & V8_HEAP_OBJECT_TAG)) {
            /* Check if it's an optimized frame by looking at code object
             * This is a heuristic - in production, you'd check the Code object's kind */
            return V8_FRAME_JAVASCRIPT;
        }
        return V8_FRAME_INTERPRETED;
    }
    
    /* Check for stub frame range */
    if (marker >= V8_STUB_MARKER_MIN && marker <= V8_STUB_MARKER_MAX) {
        return V8_FRAME_STUB;
    }
    
    /* Check if it's a heap object (has heap object tag) */
    if (marker & V8_HEAP_OBJECT_TAG) {
        /* Could be a builtin or internal frame */
        return V8_FRAME_INTERNAL;
    }

    /* Default to native frame for unrecognized markers */
    return V8_FRAME_NATIVE;
}

static inline __attribute__((always_inline))
int v8_get_frame_info(extended_unwind_state_t *state, void *fp, v8_frame_t *frame) {
    if (!v8_is_valid_frame_pointer(fp)) {
        return -1;
    }

    v8_offsets_t *offsets = v8_offsets_map__lookup(&0);
    if (!offsets) {
        return -1;
    }

    __builtin_memset(frame, 0, sizeof(*frame));
    frame->fp = fp;

    // Read frame data
    if (bpf_probe_read_user(&frame->sp, sizeof(frame->sp),
                            fp + offsets->frame_sp) != 0) {
        return -1;
    }

    if (bpf_probe_read_user(&frame->pc, sizeof(frame->pc),
                            fp + offsets->frame_pc) != 0) {
        return -1;
    }

    if (bpf_probe_read_user(&frame->function, sizeof(frame->function),
                            fp + offsets->frame_function) != 0) {
        frame->function = NULL;
    }

    if (bpf_probe_read_user(&frame->context, sizeof(frame->context),
                            fp + offsets->frame_context) != 0) {
        frame->context = NULL;
    }

    // Read marker for frame type classification
    if (bpf_probe_read_user(&frame->marker, sizeof(frame->marker), fp) == 0) {
        frame->frame_type = v8_classify_frame_type(frame);
    } else {
        frame->frame_type = V8_FRAME_NATIVE;
    }

    return 0;
}

#endif /* _NODEJS_PROFILER_H */