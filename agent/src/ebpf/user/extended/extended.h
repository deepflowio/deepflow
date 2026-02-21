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
 * @brief Structured interpreter symbol info for per-frame extraction.
 * Matches the Rust CSymbolInfo layout (#[repr(C)]).
 */
#ifndef INTERP_SYMBOL_INFO_DEFINED
#define INTERP_SYMBOL_INFO_DEFINED
typedef struct {
	u32 frame_type;		// FRAME_TYPE_PHP/V8/LUA/PYTHON
	char *function_name;	// allocated via clib_mem_alloc
	char *class_name;	// allocated via clib_mem_alloc (or NULL)
	u32 lineno;
	char *file_name;	// allocated via clib_mem_alloc (or NULL)
	u32 sub_type;		// language-specific sub-type
	u8 is_jit;		// 1 = JIT-compiled frame
	u64 raw_addr;		// original address
	u8 resolve_failed;	// 1 = resolution failed
} interp_symbol_info_t;
#endif

/**
 * @brief **extended_extract_interpreter_frames()** Extract structured interpreter frames
 * @param pid Process ID
 * @param frame_types Array of frame types from BPF map
 * @param addrs Array of frame addresses
 * @param extra_data_a Array of extra data A values
 * @param extra_data_b Array of extra data B values
 * @param frame_count Number of frames in arrays
 * @param tracer BPF tracer handle (for Lua)
 * @param new_cache Whether this is a new cache entry (for Lua)
 * @param info_p Process info pointer (for Lua)
 * @param out_frames Output array of interp_symbol_info_t (caller-allocated)
 * @param max_out Maximum output frames
 * @return Number of frames written to out_frames
 */
int extended_extract_interpreter_frames(int pid,
                                        const u8 *frame_types,
                                        const u64 *addrs,
                                        const u64 *extra_data_a,
                                        const u64 *extra_data_b,
                                        int frame_count,
                                        void *tracer,
                                        bool new_cache,
                                        void *info_p,
                                        interp_symbol_info_t *out_frames,
                                        int max_out);

/**
 * @brief **extended_free_interp_frames()** Free memory owned by interp_symbol_info_t array
 * @param frames Array of interp_symbol_info_t
 * @param count Number of entries
 */
void extended_free_interp_frames(interp_symbol_info_t *frames, int count);

/**
 * @brief **extended_extract_structured_frames()** High-level extraction for a stack trace
 *
 * Reads user and interpreter BPF stack maps, extracts structured interpreter
 * frame symbols via per-symbol cache + extract functions.
 *
 * @param tracer BPF tracer handle
 * @param tgid Process ID (for cache lookup and process type detection)
 * @param user_stack_id User stack ID from BPF map (-1 if none)
 * @param interp_stack_id Interpreter stack ID from BPF map (-1 if none)
 * @param custom_stack_map_name Name of the custom stack map
 * @param new_cache Whether cache entry is new
 * @param info_p Process info pointer
 * @param out_frames Caller-allocated output array
 * @param max_out Maximum output frame count
 * @return Number of frames written to out_frames
 */
int extended_extract_structured_frames(void *tracer, int tgid,
                                       int user_stack_id, int interp_stack_id,
                                       const char *custom_stack_map_name,
                                       bool new_cache, void *info_p,
                                       interp_symbol_info_t *out_frames,
                                       int max_out);

#endif /* DF_EXTENDED_H */
