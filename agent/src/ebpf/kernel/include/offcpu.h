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

#ifndef DF_BPF_OFFCPU_H
#define DF_BPF_OFFCPU_H

/* Used in tsk->state: */
#define TASK_RUNNING                    0x0000
#define TASK_INTERRUPTIBLE              0x0001
#define TASK_UNINTERRUPTIBLE            0x0002
#define __TASK_STOPPED                  0x0004
#define __TASK_TRACED                   0x0008
/* Used in tsk->exit_state: */
#define EXIT_DEAD                       0x0010
#define EXIT_ZOMBIE                     0x0020
#define EXIT_TRACE                      (EXIT_ZOMBIE | EXIT_DEAD)
/* Used in tsk->state again: */
#define TASK_PARKED                     0x0040

#define TASK_REPORT                     (TASK_RUNNING | TASK_INTERRUPTIBLE | \
     TASK_UNINTERRUPTIBLE | __TASK_STOPPED | \
     __TASK_TRACED | EXIT_DEAD | EXIT_ZOMBIE | \
     TASK_PARKED)
#define TASK_REPORT_IDLE        (TASK_REPORT + 1)
#define TASK_REPORT_MAX         (TASK_REPORT_IDLE << 1)

#define MINBLOCK_US     1
#define MAXBLOCK_US     0xFFFFFFFF

struct sched_switch_ctx {
	short unsigned int common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	char prev_comm[TASK_COMM_LEN];
	int prev_pid;
	int prev_prio;
	long int prev_state;
	char next_comm[TASK_COMM_LEN];
	int next_pid;
	int next_prio;
};

struct sched_info_s {
	int prev_pid;
};

#endif /* DF_BPF_OFFCPU_H */
