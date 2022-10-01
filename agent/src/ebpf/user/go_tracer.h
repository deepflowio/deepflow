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

#ifndef _BPF_GO_TRACER_H_
#define _BPF_GO_TRACER_H_
#include "symbol.h"
#include "list.h"

#include "../kernel/include/socket_trace_common.h"

struct data_members {
	const char *structure;
	const char *field_name;
	enum offsets_index idx;
	int default_offset;
};

// Pid correspond to offsets.
struct proc_info {
	struct list_head list;
	int pid;
	char *path;
	unsigned long long starttime;	// The time the process started after system boot.
	struct ebpf_proc_info info;
	bool has_updated;		// if update eBPF map ?
};



bool is_go_process(int pid);
bool fetch_go_elf_version(const char *path, struct version_info *go_ver);
int collect_go_uprobe_syms_from_procfs(struct tracer_probes_conf *conf);
void update_proc_info_to_map(struct bpf_tracer *tracer);
void go_process_exec(int pid);
void go_process_exit(int pid);
void go_process_events_handle(void);
#endif
