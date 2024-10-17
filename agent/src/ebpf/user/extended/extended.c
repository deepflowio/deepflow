/*
 * Copyright (c) 2024 Yunshan Networks
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

#include <sys/stat.h>
#include <bcc/perf_reader.h>
#include "../config.h"
#include "../utils.h"
#include "../common.h"
#include "../mem.h"
#include "../log.h"
#include "../types.h"
#include "../vec.h"
#include "../tracer.h"
#include "../socket.h"

int __attribute__ ((weak)) extended_reader_create(struct bpf_tracer *tracer)
{
	return 0;
}

int __attribute__ ((weak)) extended_maps_set(struct bpf_tracer *tracer)
{
	return 0;
}

void __attribute__ ((weak)) extended_prog_jump_tables(struct bpf_tracer *tracer) {
}

int __attribute__ ((weak)) collect_extended_uprobe_syms_from_procfs(struct tracer_probes_conf *conf)
{
	return 0;
}

void __attribute__ ((weak)) extended_process_exec(int pid) {}

void __attribute__ ((weak)) extended_events_handle(void) {}

void __attribute__ ((weak)) extended_process_exit(int pid) {}

void __attribute__ ((weak)) extended_match_pid_handle(int feat, int pid, enum match_pids_act act) {}

bool __attribute__ ((weak)) extended_require_dwarf(int pid, const char *path)
{
	return false;
}

void __attribute__ ((weak)) extended_map_preprocess(struct ebpf_map *map) {}
void __attribute__ ((weak)) extended_print_cp_tracer_status(void) {}
