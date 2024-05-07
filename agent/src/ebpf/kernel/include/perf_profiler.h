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
	__u32 cpu;
	char comm[TASK_COMM_LEN];
	int kernstack;
	int userstack;
	__u64 timestamp;
	__u64 duration_ns;
};

#endif /* DF_BPF_PERF_PROFILER_H */
