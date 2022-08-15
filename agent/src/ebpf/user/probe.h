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

#ifndef _BPF_MODULE_H_
#define _BPF_MODULE_H_
#include <stdio.h>
#include <stdbool.h>
#include <limits.h>		//PATH_MAX(4096)
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <linux/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <unistd.h>
#include "libbpf/src/libbpf.h"
/// 最大错误数
#define MAX_ERRNO       4095

/// 最大MAXACTIVE，来自Linux内核定义 kernel/trace/trace_kprobe.c
#define KRETPROBE_MAXACTIVE_MAX 4096

#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)

struct bpf_link {
	int (*detach) (struct bpf_link * link);	///< detach handle
	int (*destroy) (struct bpf_link * link);	///< destroy handle
	char *pin_path;		///< 二进制可执行文件或者库文件的路径
	int fd;			///< perf event FD
	bool disconnected;	///< 是否断开
};

struct bpf_program {
	void *sec_def;
	char *sec_name;
	size_t sec_idx;
	size_t sec_insn_off;
	size_t sec_insn_cnt;
	size_t sub_insn_off;

	char *name;
	char *pin_name;
};

int program__attach_kprobe(void *prog,
			   bool retprobe,
			   pid_t pid,
			   const char *func_name,
			   char *ev_name, void **ret_link);

int program__attach_uprobe(void *prog, bool retprobe, pid_t pid,
			   const char *binary_path,
			   size_t func_offset, char *ev_name, void **ret_link);

int program__detach_probe(struct bpf_link *link,
			  bool retprobe,
			  const char *ev_name, const char *event_type);

int bpf_get_program_fd(void *obj, const char *prog_name, void **p);
#endif
