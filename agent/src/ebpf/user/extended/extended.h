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

#ifndef DF_EXTENDED_H
#define DF_EXTENDED_H

#include <stdbool.h>
#include <stdint.h>
#include "../types.h"
#include "../tracer.h"

/**
 * @brief **extended_reader_create()** create an extended reader to
 * receive perfbuf data.
 *
 * You can rewrite the extended_reader_create() function to expand
 * the functionality of other function stack profiling. Inside it,
 * you can append new readers to read data from the eBPF perfbuf
 * and enable new threads to handle the reception.
 *
 * @param tracer BPF tracer address
 * @return 0 on success, non-zero on error
 */
int extended_reader_create(struct bpf_tracer *tracer);
int extended_maps_set(struct bpf_tracer *tracer);
void extended_prog_jump_tables(struct bpf_tracer *tracer);

/**
 * @brief **collect_extended_uprobe_syms_from_procfs()** extend the handling of uprobe
 * @param conf Tracer probes config
 * @return 0 on success, non-zero on error
 */
int collect_extended_uprobe_syms_from_procfs(struct tracer_probes_conf *conf);

/**
 * @brief **extended_process_exec()** get the process creation event and put the event into the queue
 * @param pid Process ID
 */
void extended_process_exec(int pid);

/**
 * @brief **extended_events_handle()** process events in the queue
 */
void extended_events_handle(void);

/**
 * @brief **extended_process_exit()** process exit, reclaim resources
 * @param pid Process ID
 */
void extended_process_exit(int pid);

/**
 * @brief **extended_match_pid_handle()** Perform extended processing on matching PIDs
 * @param feat Feature identifiers, such as: off-cpu/memory profiler
 * @param pid Matching process ID
 * @param act Is MATCH_PID_ADD or MATCH_PID_DEL
 */
void extended_match_pid_handle(int feat, int pid, enum match_pids_act act);

/**
 * @brief **extended_requires_dwarf()** whether extended profilers require DWARF unwinding
 * @param pid Process ID
 * @param name Process executable path
 */
bool extended_require_dwarf(int pid, const char *path);

/**
 * @brief **extended_map_preprocess()** Preprocessing before map creation
 * @param map The pointer to the map to be created
 */
void extended_map_preprocess(struct ebpf_map *map);

/**
 * @brief **extended_feature_flags()** Get enabled features in extened profile
 * @param map The pointer to the map to be created
 */
uint32_t extended_feature_flags(struct ebpf_map *map);

/**
 * @brief **extended_print_cp_tracer_status()** Extended Profile runtime
 *        status output.
 */
void extended_print_cp_tracer_status(void);

/**
 * @brief **print_extra_pkt_info()** Outputs detailed information of a packet
 *
 * @param datadump_enable Enables datadump; when enabled, information will be
 * @param pkt_data Packet data.
 * @param len Length of the packet.
 * @param buf Buffer for outputting packet debug information.
 * @param buf_len Length of the buffer for outputting packet debug informatio
 * @param direction Data direction.
 * @return Length of the output information.
 */
int print_extra_pkt_info(bool datadump_enable, const char *pkt_data, int len,
			 char *buf, int buf_len, u8 direction);

/**
 * @brief **extended_resolve_frame()** Resolve a custom/interpreter frame
 * @param pid Process ID
 * @param addr Frame address/ID
 * @param frame_type Frame type identifier
 * @param extra_a Extra data A from stack map
 * @param extra_b Extra data B from stack map
 * @return Resolved symbol string (must be freed) or NULL
 */
char *extended_resolve_frame(int pid, u64 addr, u8 frame_type, u64 extra_a, u64 extra_b);

/**
 * @brief **extended_merge_stacks()** Merge interpreter and user stacks
 * @param dst Destination buffer
 * @param len Buffer length
 * @param i_trace Interpreter stack string
 * @param u_trace User stack string
 * @param pid Process ID
 * @return Bytes written
 */
int extended_merge_stacks(char *dst, int len, const char *i_trace, const char *u_trace, int pid);

/**
 * @brief **extended_format_lua_stack()** Format Lua interpreter stack frames
 * @param tracer BPF tracer handle
 * @param pid Process ID
 * @param stack_id Interpreter stack ID from BPF map
 * @param stack_map_name Name of the stack map
 * @param h Stack string hash table
 * @param new_cache Whether to create new cache entry
 * @param info_p Process info pointer
 * @return Formatted stack string (caller must free) or NULL
 */
char *extended_format_lua_stack(void *tracer, int pid, int stack_id,
                                const char *stack_map_name, void *h,
                                bool new_cache, void *info_p);

#endif /* DF_EXTENDED_H */
