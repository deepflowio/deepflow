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

/*
 * It works by tracking when threads are blocked and when they return
 * to the CPU, measuring their time spent in the "off-CPU" state along with
 * the blocked stack trace and task name. The output summary assists in
 * identifying the reasons for thread blocking and quantifying their time
 * spent in the "off-CPU" state. This encompasses typical blocking activities
 * in user programs such as disk I/O, network I/O, locks, etc.
 */

#include "offcpu.h"

/* *INDENT-OFF* */
// Records offcpu information
BPF_HASH(offcpu_sched_map, int, struct sched_info_s)
// Used to calculate the offcpu time
BPF_HASH(offcpu_start_map, int, __u64)
// It is used to record control information and statistics 
//MAP_ARRAY(offcpu_state_map, __u32, __u64, OFFCPU_CNT)
// For dual-buffer mechanism output
MAP_PERF_EVENT(offcpu_output_a, int, __u32, MAX_CPU)
MAP_PERF_EVENT(offcpu_output_b, int, __u32, MAX_CPU)
// Used for dual buffer stack map
MAP_STACK_TRACE(offcpu_stack_map_a, STACK_MAP_ENTRIES)
MAP_STACK_TRACE(offcpu_stack_map_b, STACK_MAP_ENTRIES)

MAP_ARRAY(offset_state_map, __u32, __u64, PROFILER_CNT);
// For process filtering

/* *INDENT-ON* */

static inline int record_sched_info(struct sched_switch_ctx *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();

	// CPU idle process does not perform any processing.
	if (id >> 32 == 0 && (__u32) id == 0)
		return -1;

	/* TODO: Threads filter */

	/* 
	 * On Linux, involuntary context switches occur for state TASK_RUNNING,
	 * whereas the blocking events we're usually interested in are in
	 * TASK_INTERRUPTIBLE (0x01) or TASK_UNINTERRUPTIBLE (0x02).
	 *
	 * TASK_INTERRUPTIBLE ('S'): interruptible sleep (waiting for an event to complete)
	 * TASK_UNINTERRUPTIBLE ('D'): uninterruptible sleep (usually IO)
	 */
	if (!(((ctx->prev_state & (TASK_REPORT_MAX - 1)) & 0x01)
	      || ((ctx->prev_state & (TASK_REPORT_MAX - 1)) & 0x02)))
		return -1;

	// Filter out the high volume of scheduling events caused by self-monitoring.
	char comm[TASK_COMM_LEN];
	bpf_get_current_comm(comm, sizeof(comm));
	if ((comm[0] == 't' && comm[1] == 'c' && comm[2] == '\0')
	    || (comm[0] == 's' && comm[1] == 's' && comm[2] == 'h')
	    || (comm[0] == 'p' && comm[1] == 'e' && comm[2] == 'r'))
		return -1;

	struct sched_info_s val = {};
	val.prev_pid = ctx->prev_pid;
	int pid = ctx->next_pid;
	offcpu_sched_map__update(&pid, &val);

	return 0;
}

static inline __u64 fetch_delta_time(int curr_pid, int offcpu_pid)
{
	int pid = curr_pid;
	int prev_pid = offcpu_pid;
	__u64 ts, *tsp;
	ts = bpf_ktime_get_ns();
	offcpu_start_map__update(&prev_pid, &ts);
	tsp = offcpu_start_map__lookup(&pid);
	if (tsp == NULL)
		return 0;

	// calculate schedule thread's delta time
	__u64 delta_ns = ts - *tsp;
	offcpu_start_map__delete(&pid);

	/*
	 * Note:
	 * Scheduler events are still high-frequency events, as their rate may exceed
	 * 1 million events per second, so caution should still be exercised.
	 *
	 * If overhead remains an issue, you can check the 'MINBLOCK_US' tunable parameter
	 * in the code. If your goal is to trace longer blocking events, then increasing
	 * this parameter can filter out shorter blocking events, further reducing overhead.
	 */
	__u64 delta_us = delta_ns / 1000;
	if ((delta_us < MINBLOCK_US) || (delta_us > MAXBLOCK_US))
		return 0;

	return delta_ns;
}

// The current task is a new task that has been scheduled.
static inline int oncpu(struct pt_regs *ctx, int pid, int tgid, __u64 delta_ns)
{
	// create map key
	struct stack_trace_key_t data = {};
	data.userstack = bpf_get_stackid(ctx, &NAME(stack_map_a),
					 USER_STACKID_FLAGS);

	/*
	 * It only handles user-space programs. If there's no
	 * user-space stack, it won't process.
	 */
	if (data.userstack < 0)
		return 0;

	data.kernstack = bpf_get_stackid(ctx, &NAME(stack_map_b),
					 KERN_STACKID_FLAGS);
	data.pid = pid;
	data.tgid = tgid;
	data.duration_ns = delta_ns;
	data.cpu = bpf_get_smp_processor_id();
	data.timestamp = bpf_ktime_get_ns();
	bpf_get_current_comm(&data.comm, sizeof(data.comm));

	bpf_perf_event_output(ctx, &NAME(offcpu_output_a),
			      BPF_F_CURRENT_CPU, &data, sizeof(data));

	return 0;
}

/*
 * Here is an indication of where the probes are located:
 *
 * schedule() -> trace_sched_switch -> switch_to() -> finish_task_switch()                  
 *                (oncpu old task)    stack switch      (oncpu new task) 
 */

// /sys/kernel/debug/tracing/events/sched/sched_switch/format 
TP_SCHED_PROG(sched_switch) (struct sched_switch_ctx * ctx) {
	return record_sched_info(ctx);
}

// static struct rq *finish_task_switch(struct task_struct *prev)
KPROG(finish_task_switch) (struct pt_regs * ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	int pid = (int)id, tgid = (int)(id >> 32);
	struct sched_info_s *v;
	v = offcpu_sched_map__lookup(&pid);
	if (v == NULL)
		return 0;

	int prev_pid = v->prev_pid;
	offcpu_sched_map__delete(&pid);

	__u64 delta_ns = fetch_delta_time(pid, prev_pid);
	if (delta_ns == 0)
		return 0;

	return oncpu(ctx, pid, tgid, delta_ns);
}
