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
#include "../common_utils.h"
#include "../utils.h"
#include "../mem.h"
#include "../log.h"
#include "../types.h"
#include "../vec.h"
#include "../tracer.h"
#include "../socket.h"
#include "../proc.h"

int __attribute__ ((weak)) extended_reader_create(struct bpf_tracer *tracer)
{
	return 0;
}

int __attribute__ ((weak)) extended_maps_set(struct bpf_tracer *tracer)
{
	return 0;
}

void __attribute__ ((weak)) extended_prog_jump_tables(struct bpf_tracer *tracer)
{
}

int __attribute__ ((weak)) collect_extended_uprobe_syms_from_procfs(struct
								    tracer_probes_conf
								    *conf)
{
	return 0;
}

void __attribute__ ((weak)) extended_process_exec(int pid)
{
}

void __attribute__ ((weak)) extended_events_handle(void)
{
}

void __attribute__ ((weak)) extended_process_exit(int pid)
{
}

void __attribute__ ((weak)) extended_match_pid_handle(int feat, int pid,
						      enum match_pids_act act)
{
}

bool __attribute__ ((weak)) extended_require_dwarf(int pid, const char *path)
{
	return false;
}

void __attribute__ ((weak)) extended_map_preprocess(struct ebpf_map *map)
{
}

uint32_t __attribute__ ((weak)) extended_feature_flags(struct ebpf_map *map)
{
	return 0;
}

void __attribute__ ((weak)) extended_print_cp_tracer_status(void)
{
}

int __attribute__ ((weak)) print_extra_pkt_info(bool datadump_enable,
						const char *pkt_data, int len,
						char *buf, int buf_len,
						u8 direction)
{
	return 0;
}

char * __attribute__ ((weak)) extended_resolve_frame(int pid, u64 addr, u8 frame_type, u64 extra_a, u64 extra_b)
{
	return NULL;
}

int __attribute__ ((weak)) extended_merge_stacks(char *dst, int len, const char *i_trace, const char *u_trace, int pid)
{
	return 0;
}

char * __attribute__ ((weak)) extended_format_lua_stack(void *tracer, int pid, int stack_id,
                                                        const char *stack_map_name, void *h,
                                                        bool new_cache, void *info_p)
{
	return NULL;
}
