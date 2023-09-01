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

#define EV_NAME_SIZE			1024

#define BOOT_TIME_UPDATE_PERIOD		60      // 系统启动时间更新周期, 单位：秒

// eBPF Map Name
#define MAP_MEMBERS_OFFSET_NAME         "__members_offset"
#define MAP_SOCKET_INFO_NAME            "__socket_info_map"
#define MAP_TRACE_NAME                  "__trace_map"
#define MAP_PERF_SOCKET_DATA_NAME       "__socket_data"
#define MAP_TRACE_CONF_NAME             "__trace_conf_map"
#define MAP_TRACE_STATS_NAME            "__trace_stats_map"
#define MAP_PROTO_FILTER_NAME		"__protocol_filter"
#define MAP_KPROBE_PORT_BITMAP_NAME	"__kprobe_port_bitmap"
#define MAP_ADAPT_KERN_UID_NAME		"__adapt_kern_uid_map"

//Program jmp tables
#define MAP_PROGS_JMP_KP_NAME		"__progs_jmp_kp_map"
#define MAP_PROGS_JMP_TP_NAME		"__progs_jmp_tp_map"

// This prog is designed to handle data transfer
#define PROG_DATA_SUBMIT_NAME_FOR_KP   "bpf_prog_kp__data_submit"
#define PROG_DATA_SUBMIT_NAME_FOR_TP   "bpf_prog_tp__data_submit"
#define PROG_OUTPUT_DATA_NAME_FOR_KP	"bpf_prog_kp__output_data"
#define PROG_OUTPUT_DATA_NAME_FOR_TP	"bpf_prog_tp__output_data"
#define PROG_IO_EVENT_NAME_FOR_TP	"bpf_prog_tp__io_event"

// perf profiler
#define MAP_PERF_PROFILER_BUF_A_NAME	"__profiler_output_a"
#define MAP_PERF_PROFILER_BUF_B_NAME    "__profiler_output_b"
#define PROFILE_PG_CNT_DEF		16	// perf ring-buffer page count

enum {
	PROG_DATA_SUBMIT_TP_IDX,
	PROG_OUTPUT_DATA_TP_IDX,
	PROG_IO_EVENT_TP_IDX,
	PROG_TP_NUM
};

enum {
	PROG_DATA_SUBMIT_KP_IDX,
	PROG_OUTPUT_DATA_KP_IDX,
	PROG_KP_NUM
};

//thread index for bihash
enum {
	THREAD_PROFILER_READER_IDX = 0,
	THREAD_PROC_ACT_IDX,
	THREAD_NUM
};

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

// seconds
#define GO_TRACING_TIMEOUT_DEFAULT      120

#define SK_TRACER_NAME			"socket-trace"

#define DATADUMP_FILE_PATH_SIZE		1024
#define DATADUMP_FILE_PATH_PREFIX	"/var/log"

// trace map回收的最大比例（指当前数量超过了整个MAP的容量的回收比例才进行回收）
// Maximum proportion of trace map reclamation (refers to the proportion of
// reclamation when the current quantity exceeds the capacity of the whole MAP)
#define RECLAIM_TRACE_MAP_SCALE		0.9

/*
 * /proc/sys/kernel/perf_event_max_stack
 * The default value of `/proc/sys/kernel/perf_event_max_stack
 * is 127, which means that perf can capture up to 127 stack frames
 * for each event.
 *
 * However, this value can be changed by system administrators to
 * increase or decrease the amount of information captured by perf,
 * depending on the needs of the user.
 *
 * Increasing the value of `/proc/sys/kernel/perf_event_max_stack`
 * may lead to increased overhead and memory usage, so it is
 * recommended to use it with caution.
 */
#ifndef PERF_MAX_STACK_DEPTH 
#define PERF_MAX_STACK_DEPTH		127
#endif

/*
 * continuous profiler 
 */
#define MAP_STACK_A_NAME	"__stack_map_a"
#define MAP_STACK_B_NAME	"__stack_map_b"
#define MAP_PROFILER_STATE_MAP	"__profiler_state_map"

#define STRINGIFIER_STACK_STR_HASH_BUCKETS_NUM	8192
#define STRINGIFIER_STACK_STR_HASH_MEM_SZ	(1ULL << 30) // 1Gbytes

#define SYMBOLIZER_CACHES_HASH_BUCKETS_NUM	8192
#define SYMBOLIZER_CACHES_HASH_MEM_SZ		(1ULL << 31) // 2Gbytes

#define STACK_TRACE_MSG_HASH_BUCKETS_NUM	8192
#define STACK_TRACE_MSG_HASH_MEM_SZ		(1ULL << 32) // 4Gbytes

#define PROFILER_READER_EPOLL_TIMEOUT		500 //msecs
#define EPOLL_SHORT_TIMEOUT			100  //mescs

/* Process information recalibration time, this time is the number of seconds
 * lost from the process startup time to the current time. */
#define PROC_INFO_VERIFY_TIME  10 // 10 seconds

#endif /* DF_EBPF_CONFIG_H */
