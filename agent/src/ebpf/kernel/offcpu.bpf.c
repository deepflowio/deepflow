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

struct key_t {
	int pid;
	int tgid;
	int userstack;
	int kernstack;
	char name[TASK_COMM_LEN];
};

/* *INDENT-OFF* */
MAP_PERF_EVENT(offcpu_output_a, int, __u32, MAX_CPU)
MAP_PERF_EVENT(offcpu_output_b, int, __u32, MAX_CPU)
MAP_STACK_TRACE(offcpu_stack_map_a, STACK_MAP_ENTRIES)
MAP_STACK_TRACE(offcpu_stack_map_b, STACK_MAP_ENTRIES)
BPF_HASH(offcpu_count_map, struct key_t, __u64)
/* *INDENT-ON* */

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_read/format
/* *INDENT-OFF* */
struct sched_switch_ctx {
	short unsigned int common_type;		/*     0     2 */
	unsigned char common_flags;		/*     2     1 */
	unsigned char common_preempt_count;	/*     3     1 */
	int common_pid;				/*     4     4 */
	char prev_comm[16];			/*     8    16 */
	int prev_pid;				/*    24     4 */
	int prev_prio;				/*    28     4 */
	long int prev_state;			/*    32     8 */
	char next_comm[16];			/*    40    16 */
	int next_pid;				/*    56     4 */
	int next_prio;				/*    60     4 */

	/* size: 64, cachelines: 1, members: 11 */
};
/* *INDENT-ON* */

/*
 * prev_state=%s%s
 * (REC->prev_state & ((((0x0000 | 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0040) + 1) << 1) - 1)) ?
 *   __print_flags(REC->prev_state & ((((0x0000 | 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0040) + 1) << 1) - 1), "|", { 0x01, "S" }, { 0x02, "D" }, { 0x04, "T" }, { 0x08, "t" }, { 0x10, "X" }, { 0x20, "Z" }, { 0x40, "P" }, { 0x80, "I" }) : "R", REC->prev_state & (((0x0000 | 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0040) + 1) << 1) ? "+" : ""
 */
TP_SCHED_PROG(sched_switch) (struct sched_switch_ctx * ctx) {

	struct key_t key;
	key.kernstack = bpf_get_stackid(ctx, &NAME(stack_map_a),
					KERN_STACKID_FLAGS);
	key.userstack = bpf_get_stackid(ctx, &NAME(stack_map_a),
					USER_STACKID_FLAGS);
	int pid = ctx->prev_pid;

	bpf_debug("pid %d\n", pid);
#if 0
	int pid = 0;
	unsigned long long duration = 0;
	struct sched_switch_event *event = NULL;

	// 上一个线程 offcpu
	pid = ctx->prev_pid;
	// 如果要监控这个线程,就在用户态向 map 中插入 key, 这样就能实现在用户态动态调整待监控的线程了
	event = bpf_map_lookup_elem(&sched_switch_event_map, &pid);
	// 在 map 中查找这个线程号,只处理能够找到的线程
	if (event) {
		// 拿 stackid,需要在 offcpu 的时候拿,因为在执行这段 eBPF 代码时还没有切换上下文
		event->stackid =
		    bpf_get_stackid(ctx, &stack_trace_map,
				    BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK);
		// 如果 offcpu 是由用户态的行为传递下来的,这里取到的值会大于 0,
		// 如果用户态进程在运行过程被抢占了也会走到这里,这种情况下应该去看 oncpu,已经在前文讨论过了
		if (event->stackid > 0) {
			// 当能成功拿到 stackid 的时候设置 timestamp, timestamp 除了记录时间,
			// 还用来做标记,当值为 0 时表示 event 值无效,这个值会 oncpu 时检查
			event->offcpu_timestamp = bpf_ktime_get_boot_ns();
		}
	}
	// 下一个线程 oncpu
	pid = ctx->next_pid;
	event = bpf_map_lookup_elem(&sched_switch_event_map, &pid);
	// 检查 event 在 oncpu 前是否 offcpu 了
	if (event && event->offcpu_timestamp) {
		// 计算 offcpu 的时间并上报
		duration = bpf_ktime_get_boot_ns() - event->offcpu_timestamp;
		LOG("offcpu: pid=%d duration=%llu stackid=%d", pid, duration,
		    event->stackid);
		// 使用后标记无效,等待 offcpu 时重新赋值
		event->offcpu_timestamp = 0;
	}
#endif
	return 0;
}
