/*
 * This code runs using bpf in the Linux kernel.
 * Copyright 2024- The Yunshan Networks Authors.
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

/*
 * Off-CPU Profiler eBPF Implementation
 *
 * This program implements complete off-CPU profiling by tracking scheduler
 * events to measure blocking time and capture stack traces when processes
 * are not running on CPU.
 */

#include <linux/bpf_perf_event.h>
#include <linux/sched.h>
#include "config.h"
#include "bpf_base.h"
#include "common.h"
#include "kernel.h"
#include "perf_profiler.h"
#include "trace_utils.h"

/* Task state definitions for kernel compatibility */
#ifndef TASK_RUNNING
#define TASK_RUNNING            0
#endif
#ifndef TASK_INTERRUPTIBLE
#define TASK_INTERRUPTIBLE      1
#endif
#ifndef TASK_UNINTERRUPTIBLE
#define TASK_UNINTERRUPTIBLE    2
#endif
#ifndef TASK_STOPPED
#define TASK_STOPPED            4
#endif

#define OFF_CPU_MIN_BLOCK_TIME_NS 50000	// 50μs minimum blocking time
#define OFF_CPU_MAX_ENTRIES 65536

/* Off-CPU event tracking structures */
struct off_cpu_event {
	__u32 pid;
	__u32 tgid;
	__u64 block_start_time;
	__u64 waker_pid;
	__u32 cpu;
	char comm[TASK_COMM_LEN];
	__u32 block_reason;
	int user_stack_id;
	int kernel_stack_id;
	__u32 flags;
};

/* Block reason classification based on kernel symbols and wait channels */
enum block_reason_type {
	BLOCK_REASON_UNKNOWN = 0,
	BLOCK_REASON_IO_WAIT,
	BLOCK_REASON_MUTEX_LOCK,
	BLOCK_REASON_SLEEP,
	BLOCK_REASON_FUTEX,
	BLOCK_REASON_NETWORK,
	BLOCK_REASON_MEMORY_ALLOC,
	BLOCK_REASON_SIGNAL_WAIT,
	BLOCK_REASON_TIMER_WAIT,
	BLOCK_REASON_POLL_SELECT,
	BLOCK_REASON_PIPE_WAIT,
	BLOCK_REASON_PAGE_FAULT,
	BLOCK_REASON_DISK_IO,
	BLOCK_REASON_MAX
};

/* Maps for tracking off-CPU events */
MAP_HASH(off_cpu_pending_map, __u32, struct off_cpu_event, OFF_CPU_MAX_ENTRIES, FEATURE_FLAG_PROFILE_OFFCPU)
MAP_PERF_EVENT(off_cpu_events, int, __u32, MAX_CPU, FEATURE_FLAG_PROFILE_OFFCPU)
MAP_STACK_TRACE(off_cpu_stack_map_a, STACK_MAP_ENTRIES, FEATURE_FLAG_PROFILE_OFFCPU)
MAP_STACK_TRACE(off_cpu_stack_map_b, STACK_MAP_ENTRIES, FEATURE_FLAG_PROFILE_OFFCPU)
MAP_ARRAY(off_cpu_state_map, __u32, __u64, PROFILER_CNT, FEATURE_FLAG_PROFILE_OFFCPU)

/* Classify blocking reason based on kernel stack trace and task state */
static inline __attribute__((always_inline))
enum block_reason_type classify_block_reason(void *ctx, __u32 pid)
{
	/* First, try to use the task's state flags if available */
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (task) {
		/* Check task state flags for specific wait reasons */
		long state = BPF_CORE_READ(task, state);

		/* Check for specific task states */
		if (state & TASK_UNINTERRUPTIBLE) {
			/* Uninterruptible sleep - usually I/O */
			return BLOCK_REASON_DISK_IO;
		}
		if (state & TASK_STOPPED) {
			/* Stopped by signal */
			return BLOCK_REASON_SIGNAL_WAIT;
		}
	}

	/* Analyze kernel stack to determine block reason */
	__u64 kernel_stack[16];
	int stack_depth = bpf_get_stack(ctx, kernel_stack, sizeof(kernel_stack), 0);

	if (stack_depth <= 0)
		return BLOCK_REASON_UNKNOWN;

	/* Look for specific patterns in the stack addresses
	 * In production, you'd want to resolve these to symbols */
	for (int i = 0; i < stack_depth / sizeof(__u64) && i < 16; i++) {
		__u64 addr = kernel_stack[i];

		/* Check for common kernel subsystem addresses
		 * These patterns are x86_64 Linux specific */

		/* Memory management functions (usually 0xffffffff81200000 range) */
		if ((addr & 0xffffffffff000000UL) == 0xffffffff81200000UL) {
			return BLOCK_REASON_MEMORY_ALLOC;
		}

		/* File system and block I/O (usually 0xffffffff81300000 range) */
		if ((addr & 0xffffffffff000000UL) == 0xffffffff81300000UL) {
			return BLOCK_REASON_DISK_IO;
		}

		/* Network stack (usually 0xffffffff81700000 range) */
		if ((addr & 0xffffffffff000000UL) == 0xffffffff81700000UL) {
			return BLOCK_REASON_NETWORK;
		}

		/* Scheduler and futex (usually 0xffffffff81100000 range) */
		if ((addr & 0xffffffffff000000UL) == 0xffffffff81100000UL) {
			/* Further distinguish between futex and scheduler */
			if ((addr & 0xffffff) >= 0x080000 && (addr & 0xffffff) <= 0x090000) {
				return BLOCK_REASON_FUTEX;
			}
			return BLOCK_REASON_SLEEP;
		}

		/* Poll/select/epoll (usually in 0xffffffff81400000 range) */
		if ((addr & 0xffffffffff000000UL) == 0xffffffff81400000UL) {
			return BLOCK_REASON_POLL_SELECT;
		}

		/* Pipe operations (usually in 0xffffffff81500000 range) */
		if ((addr & 0xffffffffff000000UL) == 0xffffffff81500000UL) {
			return BLOCK_REASON_PIPE_WAIT;
		}

		/* Timer functions (usually in 0xffffffff81600000 range) */
		if ((addr & 0xffffffffff000000UL) == 0xffffffff81600000UL) {
			return BLOCK_REASON_TIMER_WAIT;
		}

		/* Lock/mutex operations - check for specific patterns */
		if ((addr & 0xffffff) >= 0x0a0000 && (addr & 0xffffff) <= 0x0b0000) {
			return BLOCK_REASON_MUTEX_LOCK;
		}
	}

	/* If we can't determine from stack, check if it's a common wait pattern */
	if (stack_depth > sizeof(__u64)) {
		/* Check top of stack for common wait entry points */
		__u64 top_addr = kernel_stack[0];

		/* schedule() and related functions */
		if ((top_addr & 0xffffff) >= 0x100000 && (top_addr & 0xffffff) <= 0x110000) {
			return BLOCK_REASON_SLEEP;
		}

		/* io_schedule() and related */
		if ((top_addr & 0xffffff) >= 0x300000 && (top_addr & 0xffffff) <= 0x310000) {
			return BLOCK_REASON_IO_WAIT;
		}
	}

	return BLOCK_REASON_UNKNOWN;
}

/* Check if process should be profiled */
static inline __attribute__((always_inline))
bool should_profile_off_cpu(__u32 tgid)
{
	return is_pid_match(FEATURE_PROFILE_OFFCPU, tgid);
}

/* Get current stack maps based on transfer count */
static inline __attribute__((always_inline))
void *get_current_off_cpu_stack_map()
{
	__u32 transfer_idx = TRANSFER_CNT_IDX;
	__u64 *transfer_count = bpf_map_lookup_elem(&off_cpu_state_map, &transfer_idx);

	if (!transfer_count)
		return &off_cpu_stack_map_a;

	/* Use map A for even transfer counts, map B for odd */
	return (*transfer_count % 2 == 0) ? &off_cpu_stack_map_a : &off_cpu_stack_map_b;
}

/* Tracepoint for scheduler switch events */
SEC("tracepoint/sched/sched_switch")
int off_cpu_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
	__u64 ts = bpf_ktime_get_ns();
	__u32 cpu = bpf_get_smp_processor_id();

	/* Get task info from tracepoint context - correctly distinguish pid and tgid */
	__u32 prev_pid = BPF_CORE_READ(ctx, prev_pid);
	__u32 prev_state = BPF_CORE_READ(ctx, prev_state);
	__u32 next_pid = BPF_CORE_READ(ctx, next_pid);

	/* Get the actual TGID (process ID) for the previous task
	 * In Linux, pid is thread ID and tgid is process ID */
	struct task_struct *prev_task = (struct task_struct *)bpf_get_current_task();
	__u32 prev_tgid = 0;
	if (prev_task) {
		prev_tgid = BPF_CORE_READ(prev_task, tgid);
	}

	/* For next task, we need to look it up differently since it's not current yet
	 * For simplicity, we'll track by pid and resolve tgid when needed */
	__u32 next_tgid = next_pid; /* Will be resolved when it becomes current */

	/* Handle process going off-CPU (blocking) */
	if (prev_state != TASK_RUNNING && should_profile_off_cpu(prev_tgid)) {
		struct off_cpu_event event = {0};

		event.pid = prev_pid;      /* Thread ID */
		event.tgid = prev_tgid;     /* Process ID */
		event.block_start_time = ts;
		event.cpu = cpu;
		event.block_reason = classify_block_reason(ctx, prev_pid);

		/* Get comm from the previous task */
		if (prev_task) {
			bpf_probe_read_kernel_str(event.comm, TASK_COMM_LEN,
						  BPF_CORE_READ(prev_task, comm));
		}

		/* Capture stack traces */
		void *stack_map = get_current_off_cpu_stack_map();
		if (stack_map) {
			event.user_stack_id = bpf_get_stackid(ctx, stack_map, BPF_F_USER_STACK);
			event.kernel_stack_id = bpf_get_stackid(ctx, stack_map, 0);
		}

		/* Store pending event - use thread ID as key for accurate wake-up matching */
		bpf_map_update_elem(&off_cpu_pending_map, &prev_pid, &event, BPF_ANY);
	}

	/* Handle process coming back on-CPU (waking up)
	 * Note: When a thread wakes up, it becomes current, so we can get its real tgid */
	if (next_pid != 0) {
		/* Look up the pending event by thread ID */
		struct off_cpu_event *pending = bpf_map_lookup_elem(&off_cpu_pending_map, &next_pid);
		if (pending) {
			/* Verify this is a profiled process */
			if (should_profile_off_cpu(pending->tgid)) {
				__u64 block_duration = ts - pending->block_start_time;

				/* Only report events above minimum threshold */
				if (block_duration >= OFF_CPU_MIN_BLOCK_TIME_NS) {
					/* Create stack trace key for off-CPU event */
					struct stack_trace_key_t key = {0};
					key.pid = pending->pid;      /* Thread ID */
					key.tgid = pending->tgid;     /* Process ID */
					key.cpu = pending->cpu;
					key.timestamp = pending->block_start_time;
					key.kernstack = pending->kernel_stack_id;
					key.userstack = pending->user_stack_id;
					key.off_cpu.duration_ns = block_duration;

					bpf_probe_read_kernel_str(key.comm, TASK_COMM_LEN, pending->comm);

					/* Send to user space */
					bpf_perf_event_output(ctx, &off_cpu_events, BPF_F_CURRENT_CPU,
							      &key, sizeof(key));

					/* Update statistics */
					__u32 output_idx = OUTPUT_CNT_IDX;
					__u64 *output_count = bpf_map_lookup_elem(&off_cpu_state_map, &output_idx);
					if (output_count)
						__sync_fetch_and_add(output_count, 1);
				}
			}

			/* Clean up the pending event */
			bpf_map_delete_elem(&off_cpu_pending_map, &next_pid);
		}
	}

	return 0;
}

/* Optional: Tracepoint for wakeup events for more accurate tracking */
SEC("tracepoint/sched/sched_wakeup")
int off_cpu_sched_wakeup(struct trace_event_raw_sched_wakeup *ctx)
{
	__u32 waker_pid = bpf_get_current_pid_tgid() >> 32;
	__u32 target_pid = BPF_CORE_READ(ctx, pid);

	/* Update waker information for pending off-CPU events */
	struct off_cpu_event *pending = bpf_map_lookup_elem(&off_cpu_pending_map, &target_pid);
	if (pending)
		pending->waker_pid = waker_pid;

	return 0;
}

/* Perf event handler for off-CPU profiling */
SEC("perf_event")
int off_cpu_perf_event(struct bpf_perf_event_data *ctx)
{
	__u64 enable_flag_idx = ENABLE_IDX;
	__u64 *enable_flag = bpf_map_lookup_elem(&off_cpu_state_map, &enable_flag_idx);

	if (!enable_flag || *enable_flag == 0)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;

	if (!should_profile_off_cpu(tgid))
		return 0;

	/*
	 * This perf event handler can be used for periodic off-CPU sampling
	 * if needed, but the main logic is in the tracepoint handlers
	 */

	return 0;
}

char _license[] SEC("license") = "GPL";