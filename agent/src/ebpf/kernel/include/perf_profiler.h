/*
 * This code runs using bpf in the Linux kernel.
 * Copyright 2022- The Yunshan Networks Authors.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef DF_BPF_PERF_PROFILER_H
#define DF_BPF_PERF_PROFILER_H

// Type compatibility for user-space compilation
// When compiling for user-space (not kernel/BPF), define missing eBPF types
#if !defined(__KERNEL__) && !defined(__BPF__)
#ifndef __u16
#define __u16 unsigned short
#endif
#ifndef __s8
#define __s8  signed char
#endif
#ifndef __s16
#define __s16 signed short
#endif
#ifndef __s32
#define __s32 signed int
#endif
#ifndef __s64
#define __s64 signed long
#endif
#endif

#define STACK_MAP_ENTRIES 65536

/*
 * The meaning of the "__profiler_state_map" index.
 */
typedef enum {
	TRANSFER_CNT_IDX = 0,	/* buffer-a and buffer-b transfer count. */
	SAMPLE_CNT_A_IDX,	/* sample count A */
	SAMPLE_CNT_B_IDX,	/* sample count B */
	SAMPLE_CNT_DROP,	/* sample drop */
	SAMPLE_ITER_CNT_MAX,	/* Iteration sample number max value */
	OUTPUT_CNT_IDX,		/* Count the total number of data outputs. */
	ERROR_IDX,		/* Count the number of failed push notifications. */
	ENABLE_IDX,		/* Enable profiler sampling flag.
				   0: disable sampling; 1: enable sampling. */
	MINBLOCK_TIME_IDX,	/* The minimum blocking time, applied in the profiler extension.*/
	RT_KERN,                /* Indicates whether it is a real-time kernel.*/
	PROFILER_CNT
} profiler_idx;

#define JAVA_SYMBOL_MAX_LENGTH 128
#define MAP_MEMORY_JAVA_SYMBOL_MAP_NAME "__memory_java_symbol_map"

struct java_symbol_map_key {
	__u32 tgid;
	__u64 class_id;
};

#define STACK_TRACE_FLAGS_DWARF     0x1
// Stacks obtained in uretprobe does not have the frame of triggered function.
// The address is saved in "uprobe_addr" and should be appended to stack string
// if this flag is on.
#define STACK_TRACE_FLAGS_URETPROBE 0x2

struct stack_trace_key_t {
	__u32 pid;		// processID or threadID
	__u32 tgid;		// processID
	__u32 cpu;
	char comm[TASK_COMM_LEN];
	int kernstack;
	int userstack;
	int intpstack;
	__u32 flags;
	__u64 uprobe_addr;
	__u64 timestamp;

	union {
		struct {
			__u64 duration_ns;
		} off_cpu;
		struct {
			__u64 addr; // allocated or deallocating address
			__u64 size; // non-zero for allocated size, zero for deallocs
			__u64 class_id; // Use symbol address as class_id, for java only
		} memory;
	};
};

typedef struct {
	__u32 task_struct_stack_offset;
} unwind_sysinfo_t;

#define CLASS_NAME_LEN 32
#define METHOD_NAME_LEN 64
#define PATH_LEN 128

typedef struct {
	char class_name[CLASS_NAME_LEN];
	char method_name[METHOD_NAME_LEN];
	// char path[PATH_LEN];
} symbol_t;

#define MAX_SYMBOL_NUM 1024

// V8 tagged pointer constants
#define V8_HEAP_OBJECT_TAG        0x1
#define V8_HEAP_OBJECT_TAG_MASK   0x3
#define V8_SMI_TAG                0x0
#define V8_SMI_TAG_MASK           0x1
#define V8_SMI_TAG_SHIFT          1      // SMI shift for marker parsing
#define V8_SMI_VALUE_SHIFT        32     // SMI value extraction shift

#define V8_OFF_MAP_INSTANCE_TYPE  0xc

// V8 unwinding constants
#define V8_FRAMES_PER_RUN         8      // Max V8 frames per sample (instruction budget)
#define V8_FP_CONTEXT_SIZE        64     // Frame pointer context size
#define V8_MAX_FRAME_SIZE         0x2000 // 8KB max frame size

// V8 Entry Frame architecture-specific constants
// On ARM64, JS Entry Frame stores additional callee-saved registers before the FP/LR pair
// See: https://chromium.googlesource.com/v8/v8/+/main/src/execution/arm64/frame-constants-arm64.h
#if defined(__aarch64__)
  #define V8_ENTRYFRAME_CALLEE_SAVED_REGS_BEFORE_FP_LR_PAIR 18
#else
  #define V8_ENTRYFRAME_CALLEE_SAVED_REGS_BEFORE_FP_LR_PAIR 0
#endif

// V8 frame type encoding (lower 3 bits, OpenTelemetry-compatible)
// The frame type is stored in the lower 3 bits of pointer_and_type.
// V8 heap objects are aligned to 8 bytes, so bits 0-2 are always zero
// in valid pointers. We reuse these bits for frame type encoding.
#define V8_FILE_TYPE_MASK     0x7ULL

#define V8_TYPE_MARKER        0x0  // Stub/Entry frame
#define V8_TYPE_BYTECODE      0x1  // Interpreter frame (Ignition)
#define V8_TYPE_NATIVE_SFI    0x2  // Native frame with SFI only
#define V8_TYPE_NATIVE_CODE   0x3  // Native frame with Code object (TurboFan)
#define V8_TYPE_NATIVE_JSFUNC 0x4  // Baseline compiled frame (Sparkplug)

// Pointer extraction macros (OpenTelemetry-compatible)
#define V8_PTR_MASK           (~V8_FILE_TYPE_MASK)  // 0xFFFFFFFFFFFFFFF8
#define V8_GET_TYPE(p)        ((p) & V8_FILE_TYPE_MASK)
#define V8_GET_PTR(p)         ((p) & V8_PTR_MASK)
#define V8_MAKE_PTR(t, p)     (((t) & V8_FILE_TYPE_MASK) | ((p) & V8_PTR_MASK))

// Error codes for V8 unwinding
#define ERR_V8_BAD_FP         1
#define ERR_V8_READ_FAILED    2
#define ERR_V8_BAD_OFFSETS    3
#define ERR_V8_BAD_JS_FUNC    4
#define ERR_V8_UNWIND_STOP    5

// This structure contains V8 version-specific offsets and type IDs
typedef struct {
	// Heap Object Offsets
	__u16 off_HeapObject_map;              // Map field offset in HeapObject

	// JSFunction Offsets
	__u16 off_JSFunction_shared;           // SharedFunctionInfo offset
	__u16 off_JSFunction_code;             // Code object offset

	// Code Object Offsets
	__u16 off_Code_instruction_start;      // Code start offset
	__u16 off_Code_instruction_size;       // Code size offset
	__u16 off_Code_flags;                  // Code flags offset

	// Type IDs (for validation)
	__u16 type_JSFunction_first;           // JSFunction type range start
	__u16 type_JSFunction_last;            // JSFunction type range end
	__u16 type_SharedFunctionInfo;         // SFI type ID
	__u16 type_Code;                       // Code type ID

	// Frame Pointer Offsets (relative to FP)
	__s16 fp_marker;                       // Marker field offset
	__s16 fp_function;                     // Function field offset
	__s16 fp_bytecode_offset;              // Bytecode offset field

	// Version & Metadata
	__u32 v8_version;                      // V8 version encoded
	__u32 codekind_mask;                   // Mask for extracting code kind
	__u8  codekind_shift;                  // Shift for code kind
	__u8  codekind_baseline;               // Baseline code kind value
	__u16 reserved;                        // Padding for alignment

	// Debug counters (for troubleshooting)
	__u64 unwinding_attempted;             // Number of times unwinding was attempted
	__u64 unwinding_success;               // Number of successful frame unwinds
	__u64 unwinding_failed;                // Number of failed frame unwinds
} v8_proc_info_t;

// ===========================================================================
// V8 Scratch Space (Stack-Allocated Temporary Data)
// ===========================================================================
typedef struct {
	__u8 fp_ctx[64];      // Frame pointer context (marker, function, bytecode_offset)
	__u8 code_data[32];   // Code object header data
} v8_scratch_t;
// Size: 96 bytes (fits in eBPF stack limit)

// ===========================================================================
// Frame Type Markers (Shared Constants)
// ===========================================================================

// Frame type markers for interpreter stacks
#define FRAME_TYPE_NORMAL   0  // Normal native frame
#define FRAME_TYPE_PYTHON   1  // Python interpreter frame
#define FRAME_TYPE_PHP      2  // PHP interpreter frame
#define FRAME_TYPE_V8       3  // V8/Node.js frame

// Maximum stack depth for profiling
#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

#endif /* DF_BPF_PERF_PROFILER_H */
