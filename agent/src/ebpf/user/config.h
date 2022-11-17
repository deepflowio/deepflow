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

#ifndef DF_EBPF_CONFIG_H
#define DF_EBPF_CONFIG_H

// eBPF Map Name
#define MAP_MEMBERS_OFFSET_NAME         "__members_offset"
#define MAP_SOCKET_INFO_NAME            "__socket_info_map"
#define MAP_TRACE_NAME                  "__trace_map"
#define MAP_PERF_SOCKET_DATA_NAME       "__socket_data"
#define MAP_TRACE_CONF_NAME             "__trace_conf_map"
#define MAP_TRACE_STATS_NAME            "__trace_stats_map"

//Program jmp tables
#define MAP_PROGS_JMP_KP_NAME		"__progs_jmp_kp_map"
#define MAP_PROGS_JMP_TP_NAME		"__progs_jmp_tp_map"

// This prog is designed to handle data transfer
#define PROG_OUTPUT_DATA_NAME_FOR_KP	"bpf_prog__output_data_kp"
#define PROG_OUTPUT_DATA_NAME_FOR_TP	"bpf_prog__output_data_tp"

/*
 * When the socket map is recycled, each socket message is recycled without sending
 * and receiving actions for more than 10 seconds.
 *
 * 在socket map回收时，对每条socket信息超过10秒没有收发动作就回收掉
 */
#define SOCKET_RECLAIM_TIMEOUT_DEF	10

/*
 * When the trace map is recycled, each trace information is recycled without a matching
 * action for more than 10 seconds.
 *
 * 在trace map回收时，对每条trace信息超过10秒没有发生匹配动作就回收掉
 */
#define TRACE_RECLAIM_TIMEOUT_DEF	10

// The maximum default amount of data passed to the agent by eBPF programe.
#define SOCKET_DATA_LIMIT_MAX_DEF	4096

#define MAP_PROC_INFO_MAP_NAME		"proc_info_map"

// execute/exit events delayed processing time, unit: second
#define PROC_EVENT_DELAY_HANDLE_DEF     60

#endif /* DF_EBPF_CONFIG_H */
