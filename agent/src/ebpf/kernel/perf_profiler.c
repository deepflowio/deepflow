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

#include <linux/bpf_perf_event.h>
#include "config.h"
#include "bpf_base.h"
#include "common.h"
#include "kernel.h"
#include "bpf_endian.h"
#include "perf_profiler.h"

#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

/*
 * To keep the stack trace profiler "always on," we utilize a double
 * buffering mechanism and allocate two identical data structures. 
 *
 * 1 stack_map Used to collect the call stack information of kernel
 *   functions. Used to collect the call stack information. Maps the
 *   entire stack trace with stack IDs.
 * 
 * 2 profiler_output perf output to user space, Through hash-table,
 *   user space can be used to collect call stack information. The
 *   higher the count, the more we observe certain stack traces, some
 *   of which may indicate potential performance issues.
 *
 * We implement continuous tracking using a double buffering scheme,
 * for which we allocate two data structures. Therefore, we have the
 * following BPF tables:
 *
 *   1 profiler_output_a
 *   2 profiler_output_b
 *   3 stack_map_a
 *   4 stack_map_b
 *
 * User space controls the switching between MAP a and MAP b. It ensures
 * that when reading data from cache a for address symbolization, BPF uses
 * cache b for writing data and vice versa.
 */

MAP_PERF_EVENT(profiler_output_a, int, __u32, MAX_CPU)
MAP_PERF_EVENT(profiler_output_b, int, __u32, MAX_CPU)

MAP_STACK_TRACE(stack_map_a, STACK_MAP_ENTRIES)
MAP_STACK_TRACE(stack_map_b, STACK_MAP_ENTRIES)

/*
 * Used for communication between user space and BPF to control the
 * switching between buffer a and buffer b.
 */
MAP_ARRAY(profiler_state_map, __u32, __u64, PROFILER_CNT)

SEC("perf_event")
int bpf_perf_event(struct bpf_perf_event_data *ctx)
{
	__u32 count_idx;

	count_idx = TRANSFER_CNT_IDX;
	__u64 *transfer_count_ptr =
		profiler_state_map__lookup(&count_idx);

	count_idx = SAMPLE_CNT_A_IDX;
	__u64 *sample_count_a_ptr =
		profiler_state_map__lookup(&count_idx);

	count_idx = SAMPLE_CNT_B_IDX;
	__u64 *sample_count_b_ptr =
		profiler_state_map__lookup(&count_idx);

	count_idx = SAMPLE_CNT_DROP;
	__u64 *drop_count_ptr =
		profiler_state_map__lookup(&count_idx);

	count_idx = SAMPLE_ITER_CNT_MAX;
	__u64 *iter_count_ptr =
		profiler_state_map__lookup(&count_idx);

	count_idx = OUTPUT_CNT_IDX;
	__u64 *output_count_ptr =
		profiler_state_map__lookup(&count_idx);

	count_idx = ERROR_IDX;
	__u64 *error_count_ptr =
		profiler_state_map__lookup(&count_idx);

	if (transfer_count_ptr == NULL || sample_count_a_ptr == NULL ||
	    sample_count_b_ptr == NULL || drop_count_ptr == NULL ||
	    iter_count_ptr == NULL || error_count_ptr == NULL ||
	    output_count_ptr == NULL) {
		count_idx = ERROR_IDX;
		__u64 err_val = 1;
		profiler_state_map__update(&count_idx, &err_val);
		return 0;
	}

	__u64 id = bpf_get_current_pid_tgid();
	struct stack_trace_key_t key = { 0 };
	key.tgid = id >> 32;
	key.pid = (__u32)id;

	/*
	 * CPU idle stacks will not be collected. 
	 */
	if (key.tgid == key.pid && key.pid == 0)
		return 0;

	key.cpu = bpf_get_smp_processor_id();
	bpf_get_current_comm(&key.comm, sizeof(key.comm));
	key.timestamp = bpf_ktime_get_ns();

	/*
	 * Note:
	 * ------------------------------------------------------
	 * int bpf_get_stackid(struct pt_reg *ctx,
	 * 		       struct bpf_map *map, u64 flags);
	 * define in include/uapi/linux/bpf.h, implementation in
	 * file "./kernel/bpf/stackmap.c"
	 *
	 * Flags **BPF_F_REUSE_STACKID** If two different stacks
	 * hash into the same *stackid*, discard the old one. Do
	 * not set this flag, we want to return the error(-EEXIST)
	 * normally for counting purposes.
	 *
	 * return
	 *    -EFAULT (couldn't fetch the stack trace)
	 *    -EEXIST (duplicate value of *stackid*) 
	 */

	__u64 sample_count = 0;
	if (!((*transfer_count_ptr) & 0x1ULL)) {
		key.kernstack = bpf_get_stackid(ctx, &NAME(stack_map_a),
						KERN_STACKID_FLAGS);
		key.userstack = bpf_get_stackid(ctx, &NAME(stack_map_a),
						USER_STACKID_FLAGS);

		if (-EEXIST == key.kernstack)
			__sync_fetch_and_add(drop_count_ptr, 1);

		if (-EEXIST == key.userstack)
			__sync_fetch_and_add(drop_count_ptr, 1);

		if (key.userstack < 0 && key.kernstack < 0)
			return 0;

		sample_count = *sample_count_a_ptr;
		__sync_fetch_and_add(sample_count_a_ptr, 1);

		if (bpf_perf_event_output(ctx,
					  &NAME(profiler_output_a),
					  BPF_F_CURRENT_CPU, &key, sizeof(key)))
			__sync_fetch_and_add(error_count_ptr, 1);
		else
			__sync_fetch_and_add(output_count_ptr, 1);

	} else {
		key.kernstack = bpf_get_stackid(ctx, &NAME(stack_map_b),
						KERN_STACKID_FLAGS);
		key.userstack = bpf_get_stackid(ctx, &NAME(stack_map_b),
						USER_STACKID_FLAGS);

		if (-EEXIST == key.kernstack)
			__sync_fetch_and_add(drop_count_ptr, 1);

		if (-EEXIST == key.userstack)
			__sync_fetch_and_add(drop_count_ptr, 1);

		if (key.userstack < 0 && key.kernstack < 0)
			return 0;

		sample_count = *sample_count_b_ptr;
		__sync_fetch_and_add(sample_count_b_ptr, 1);

		if (bpf_perf_event_output(ctx,
					  &NAME(profiler_output_b),
					  BPF_F_CURRENT_CPU, &key, sizeof(key)))
			__sync_fetch_and_add(error_count_ptr, 1);
		else
			__sync_fetch_and_add(output_count_ptr, 1);
	}

	/*
	 * Each iteration in user mode sets the sample_count to 0. If
	 * sample_count > 0, it means that the user mode program is
	 * currently in the process of iteration and has not completed
	 * the stringifier task. If sample_count is too large, it is
	 * likely to cause stack-trace loss of records. We hope to set
	 * a larger value for STACK_MAP_ENTRIES to ensure that data is
	 * not lost. The implementation method requires calculating the
	 * maximum value of the stackmap during the loading phase and
	 * resetting it.
	 *
	 * Record the maximum sample count for each iteration.
	 */
	if (sample_count > *iter_count_ptr)
		*iter_count_ptr = sample_count;

	return 0;
}
