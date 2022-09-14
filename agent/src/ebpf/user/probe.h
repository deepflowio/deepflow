/*
 * Copyright (c) 2022 Yunshan Networks
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

#ifndef _BPF_PROBE_H_
#define _BPF_PROBE_H_
#include <stdio.h>
#include <stdbool.h>
#include <limits.h>		//PATH_MAX(4096)
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <linux/types.h>
#include <sys/types.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <unistd.h>
#include "elf.h"
#include "load.h"

/// 最大错误数
#define MAX_ERRNO       4095

/// 最大MAXACTIVE，来自Linux内核定义 kernel/trace/trace_kprobe.c
#define KRETPROBE_MAXACTIVE_MAX 4096

#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)

struct ebpf_link {
	int (*detach) (struct ebpf_link * link);	// detach handle
	int (*destroy) (struct ebpf_link * link);	// destroy handle
	int fd;			// perf event FD
};

int program__attach_kprobe(void *prog,
			   bool retprobe,
			   pid_t pid,
			   const char *func_name,
			   char *ev_name, void **ret_link);

int program__attach_uprobe(void *prog, bool retprobe, pid_t pid,
			   const char *binary_path,
			   size_t func_offset, char *ev_name, void **ret_link);

int program__detach_probe(struct ebpf_link *link,
			  bool retprobe,
			  const char *ev_name, const char *event_type);

int bpf_get_program_fd(void *obj, const char *prog_name, void **p);
struct ebpf_link *program__attach_tracepoint(void *prog);
#endif
