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

#include <linux/types.h>

#include "common.h"
#include "rust_bindings.h"

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
	PROFILER_CNT
} profiler_idx;

struct stack_trace_key_t {
	__u32 pid;		// processID or threadID
	__u32 tgid;		// processID
	__u64 itid;     // interpreter thread id
	__u32 cpu;
	char comm[TASK_COMM_LEN];
	int kernstack;
	int userstack;
	__u64 dwarfstack;
	__u64 intpstack;
	__u64 timestamp;
	__u64 duration_ns;
	__u64 mem_addr;
	__u64 mem_size;
};

typedef struct {
	char class_name[32];
	char method_name[64];
	char path[128];
} symbol_t;

typedef struct {
    __u64 ip;
    __u64 sp;
    __u64 bp;
} reg_t;

typedef struct {
	struct stack_trace_key_t key;
	stack_trace_t stack;

	void *thread_state;
	void *frame_ptr;

	reg_t regs;

	__u32 runs;
} unwind_state_t;

#endif /* DF_BPF_PERF_PROFILER_H */
