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
#define MAX_EVENTS_BURST           	32	// The number of events in batch processing
#define BOOT_TIME_UPDATE_PERIOD		60	// 系统启动时间更新周期, 单位：秒
#define DENTRY_NAME_SIZE		256  	// Maximum length of a directory entry name

/*
 *  Note: The following settings are related to the offset
 *  calculations in Rust, in the file 
 *  `agent/src/common/proc_event/linux.rs`.
 *  If the values of the four macros below are modified, the
 *  Rust file must be updated accordingly.
 */
#define FILE_NAME_SZ			256
#define MOUNT_SOURCE_SZ			512
#define MOUNT_POINT_SZ			256
#define FILE_PATH_SZ			512

// eBPF Map Name
#define MAP_MEMBERS_OFFSET_NAME         "__members_offset"
#define MAP_SOCKET_INFO_NAME            "__socket_info_map"
#define MAP_TRACE_NAME                  "__trace_map"
#define MAP_PERF_SOCKET_DATA_NAME       "__socket_data"
#define MAP_TRACER_CTX_NAME             "__tracer_ctx_map"
#define MAP_TRACE_STATS_NAME            "__trace_stats_map"
#define MAP_PROTO_FILTER_NAME		"__protocol_filter"
#define MAP_KPROBE_PORT_BITMAP_NAME	"__kprobe_port_bitmap"
#define MAP_ADAPT_KERN_DATA_NAME	"__adapt_kern_data_map"
#define MAP_PROTO_PORTS_BITMAPS_NAME	"__proto_ports_bitmap"
#define MAP_ALLOW_REASM_PROTOS_NAME     "__allow_reasm_protos_map"
#define MAP_PKTS_STATES_NAME		"__pkts_stats_map"

//Program jmp tables
#define MAP_PROGS_JMP_KP_NAME		"__progs_jmp_kp_map"
#define MAP_PROGS_JMP_TP_NAME		"__progs_jmp_tp_map"

#define PROG_DATA_SUBMIT_NAME_FOR_KP	"df_KP_data_submit"
#define PROG_DATA_SUBMIT_NAME_FOR_TP	"df_TP_data_submit"
#define PROG_OUTPUT_DATA_NAME_FOR_KP	"df_KP_output_data"
#define PROG_OUTPUT_DATA_NAME_FOR_TP	"df_TP_output_data"
#define PROG_IO_EVENT_NAME_FOR_TP	"df_TP_io_event"
#define PROG_IO_EVENT_NAME_FOR_KP       "df_KP_io_event"
#define PROG_PROTO_INFER_2_FOR_KP	"df_KP_proto_infer_2"
#define PROG_PROTO_INFER_2_FOR_TP	"df_TP_proto_infer_2"
#define PROG_PROTO_INFER_3_FOR_KP	"df_KP_proto_infer_3"
#define PROG_PROTO_INFER_3_FOR_TP	"df_TP_proto_infer_3"

// perf profiler
#define MAP_PERF_PROFILER_BUF_A_NAME	"__profiler_output_a"
#define MAP_PERF_PROFILER_BUF_B_NAME    "__profiler_output_b"
#define MAP_PROCESS_SHARD_LIST_NAME     "__process_shard_list_table"
#define MAP_UNWIND_ENTRY_SHARD_NAME     "__unwind_entry_shard_table"
#define MAP_UNWIND_SYSINFO_NAME         "__unwind_sysinfo"
#define MAP_PYTHON_UNWIND_INFO_NAME     "__python_unwind_info_map"
#define MAP_PYTHON_OFFSETS_NAME         "__python_offsets_map"
#define MAP_PHP_UNWIND_INFO_NAME        "__php_unwind_info_map"
#define MAP_PHP_OFFSETS_NAME            "__php_offsets_map"
#define MAP_V8_UNWIND_INFO_NAME         "__v8_unwind_info_map"
#define MAP_SYMBOL_TABLE_NAME           "__symbol_table"

#define PROFILE_PG_CNT_DEF              16	// perf ring-buffer page count

#define MAP_CP_PROGS_JMP_PE_NAME        "__cp_progs_jmp_pe_map"
#define PROG_DWARF_UNWIND_FOR_PE        "df_PE_dwarf_unwind"
#define PROG_PYTHON_UNWIND_FOR_PE       "df_PE_python_unwind"
#define PROG_LUA_UNWIND_FOR_PE          "df_PE_lua_unwind"
#define PROG_PHP_UNWIND_FOR_PE          "df_PE_php_unwind"
#define PROG_V8_UNWIND_FOR_PE           "df_PE_v8_unwind"
#define PROG_DWARF_UNWIND_BEFORE_V8_FOR_PE   "df_PE_dwarf_unwind_before_v8"
#define PROG_DWARF_UNWIND_BEFORE_PHP_FOR_PE  "df_PE_dwarf_unwind_before_php"
#define PROG_ONCPU_OUTPUT_FOR_PE        "df_PE_oncpu_output"

// lua related maps
#define MAP_LUA_LANG_FLAGS_NAME         "__lang_flags_map"
#define MAP_LUA_UNWIND_INFO_NAME        "__lua_unwind_info_map"
#define MAP_LUA_OFFSETS_NAME            "__lua_offsets_map"
#define MAP_LUAJIT_OFFSETS_NAME         "__luajit_offsets_map"
#define MAP_LUA_TSTATE_NAME             "__lua_tstate_map"

#define MAP_CP_PROGS_JMP_KP_NAME             "__cp_progs_jmp_kp_map"
#define PROG_OFFCPU_DWARF_UNWIND_FOR_KP      "df_KP_offcpu_dwarf_unwind"
#define PROG_OFFCPU_PYTHON_UNWIND_FOR_KP     "df_KP_offcpu_python_unwind"
#define PROG_OFFCPU_OUTPUT_FOR_KP            "df_KP_offcpu_output"
#define PROG_MEMORY_DWARF_UNWIND_FOR_KP      "df_KP_memory_dwarf_unwind"
#define PROG_MEMORY_OUTPUT_FOR_KP            "df_KP_memory_output"

enum {
	PROG_PROTO_INFER_TP_2_IDX,
	PROG_PROTO_INFER_TP_3_IDX,
	PROG_DATA_SUBMIT_TP_IDX,
	PROG_OUTPUT_DATA_TP_IDX,
	PROG_IO_EVENT_TP_IDX,
	PROG_TP_NUM
};

enum {
	PROG_PROTO_INFER_KP_2_IDX,
	PROG_PROTO_INFER_KP_3_IDX,
	PROG_DATA_SUBMIT_KP_IDX,
	PROG_OUTPUT_DATA_KP_IDX,
	PROG_IO_EVENT_KP_IDX,
	PROG_KP_NUM
};

enum {
	PROG_DWARF_UNWIND_PE_IDX,
	PROG_PYTHON_UNWIND_PE_IDX,
	PROG_LUA_UNWIND_PE_IDX,
	PROG_PHP_UNWIND_PE_IDX,
	PROG_V8_UNWIND_PE_IDX,
	PROG_DWARF_UNWIND_BEFORE_V8_PE_IDX,  // DWARF unwinding before V8 interpreter unwinding
	PROG_DWARF_UNWIND_BEFORE_PHP_PE_IDX, // DWARF unwinding before PHP interpreter unwinding
	PROG_ONCPU_OUTPUT_PE_IDX,
	CP_PROG_PE_NUM
};

enum {
	PROG_OFFCPU_DWARF_UNWIND_KP_IDX,
	PROG_OFFCPU_PYTHON_UNWIND_KP_IDX,
	PROG_OFFCPU_OUTPUT_KP_IDX,
	PROG_MEMORY_DWARF_UNWIND_KP_IDX,
	PROG_MEMORY_OUTPUT_KP_IDX,
	CP_PROG_KP_NUM
};

#define PROFILER_CTX_NUM 3

//thread index for bihash
enum {
	THREAD_PROFILER_READER_IDX = 0,
	THREAD_OFFCPU_READER_IDX = 1,
	THREAD_MEMORY_READER_IDX = 2,
	THREAD_PROC_EVENTS_HANDLE_IDX = 3,
	THREAD_SOCK_READER_IDX_BASE = 4,
};

// index number of feature.
enum cfg_feature_idx {
	FEATURE_UNKNOWN,
	// Analyze go binary to get symbol address without symbol table
	FEATURE_UPROBE_GOLANG_SYMBOL,
	// openssl uprobe
	FEATURE_UPROBE_OPENSSL,
	// golang uprobe
	FEATURE_UPROBE_GOLANG,
	FEATURE_PROFILE_ONCPU,
	FEATURE_PROFILE_OFFCPU,
	FEATURE_PROFILE_MEMORY,
	FEATURE_SOCKET_TRACER,
	FEATURE_DWARF_UNWINDING,
	// Language-specific profiling features
	FEATURE_PROFILE_PYTHON,
	FEATURE_PROFILE_PHP,
	FEATURE_PROFILE_V8,
	FEATURE_MAX,
};

#define FEATURE_FLAG_UPROBE_GOLANG_SYMBOL	(1 << FEATURE_UPROBE_GOLANG_SYMBOL)
#define FEATURE_FLAG_UPROBE_OPENSSL		(1 << FEATURE_UPROBE_OPENSSL)
#define FEATURE_FLAG_UPROBE_GOLANG		(1 << FEATURE_UPROBE_GOLANG)
#define FEATURE_FLAG_PROFILE_ONCPU		(1 << FEATURE_PROFILE_ONCPU)
#define FEATURE_FLAG_PROFILE_OFFCPU		(1 << FEATURE_PROFILE_OFFCPU)
#define FEATURE_FLAG_PROFILE_MEMORY		(1 << FEATURE_PROFILE_MEMORY)
#define FEATURE_FLAG_SOCKET_TRACER		(1 << FEATURE_SOCKET_TRACER)
#define FEATURE_FLAG_DWARF_UNWINDING		(1 << FEATURE_DWARF_UNWINDING)
#define FEATURE_FLAG_PROFILE_PYTHON		(1 << FEATURE_PROFILE_PYTHON)
#define FEATURE_FLAG_PROFILE_PHP		(1 << FEATURE_PROFILE_PHP)
#define FEATURE_FLAG_PROFILE_V8			(1 << FEATURE_PROFILE_V8)

#define FEATURE_FLAG_PROFILE				(FEATURE_FLAG_PROFILE_ONCPU | FEATURE_FLAG_PROFILE_OFFCPU | FEATURE_FLAG_PROFILE_MEMORY)

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
#define CP_TRACER_NAME	                "continuous_profiler"

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
#define MAP_CUSTOM_STACK_A_NAME	"__custom_stack_map_a"
#define MAP_CUSTOM_STACK_B_NAME	"__custom_stack_map_b"
#define MAP_PROFILER_STATE_NAME	"__profiler_state_map"

#define STRINGIFIER_STACK_STR_HASH_BUCKETS_NUM	8192
#define STRINGIFIER_STACK_STR_HASH_MEM_SZ	(1ULL << 30)	// 1Gbytes

#define SYMBOLIZER_CACHES_HASH_BUCKETS_NUM	8192
#define SYMBOLIZER_CACHES_HASH_MEM_SZ		(1ULL << 31)	// 2Gbytes

#define STACK_TRACE_MSG_HASH_BUCKETS_NUM	8192
#define STACK_TRACE_MSG_HASH_MEM_SZ		(1ULL << 32)	// 4Gbytes

#define PIDS_MATCH_HASH_BUCKETS_NUM		8192
#define PIDS_MATCH_HASH_MEM_SZ			(1ULL << 30)	// 1Gbytes

#define PROFILER_READER_EPOLL_TIMEOUT		500	//msecs
#define EPOLL_SHORT_TIMEOUT			100	//mescs

// The queue size for managing process execution/exit events.
#define PROC_RING_SZ 16384

/*
 * During stack trace string aggregation and statistics, thread names
 * are hashed using the DJB2 algorithm.
 */
#define USE_DJB2_HASH

/*
 * Process information recalibration time, this time is the number of seconds
 * lost from the process startup time to the current time.
 * For Java :
 *   The Java process will delay obtaining the symbol table by
 *   'PROC_INFO_VERIFY_TIME' seconds after it starts running.
 */
#define PROC_INFO_VERIFY_TIME  60	// 60 seconds

/*
 * This value is used to determine which type of Java agent's so library to
 * attach JVM (GNU or musl libc agent.so).
 */
#define JAVA_AGENT_LIBS_TEST_FUN_RET_VAL 3302

/*
 * Java symbol table update delay time.
 * When an unknown Frame is encountered during the symbolization process of
 * the Java process, it will be delayed for a fixed time (if the unknown f-
 * rame is encountered again during this period, it will be ignored) to up-
 * date the Java symbol table. This is done The purpose is to avoid freque-
 * nt updates of the java symbol table.
 */
#define JAVA_SYMS_UPDATE_DELAY_DEF 60	// 60 seconds
#define JAVA_SYMS_UPDATE_DELAY_MIN 5	// 5 seconds
#define JAVA_SYMS_UPDATE_DELAY_MAX 3600	// 3600 seconds

/* Profiler - maximum data push interval time (in nanosecond). */
#define MAX_PUSH_MSG_TIME_INTERVAL_NS 1000000000ULL	/* 1 seconds */

/*
 * The kernel uses bundled burst to send data to the user.
 * The implementation method is that all CPUs trigger timeout checks and send
 * the data resident in the eBPF buffer. This value is the periodic time, unit
 * is milliseconds.
 */
#define KICK_KERN_PERIOD 40000000  // Set default interval to 40 milliseconds
/*
 * A special value should be assigned to indicate the case where no data has
 * been pushed after exceeding 100 milliseconds.
 */
#define PUSH_DELAY_EXCEEDED_MARKER 199000 // 199 ms

/*
 * timer config
 */

/*
 * tick every 10 millisecond
 *
 * unit: microseconds
 */
#define EVENT_TIMER_TICK_US    10000

/*
 * Trigger kernel adaptation.
 */
#define TRIG_KERN_ADAPT_PERIOD 10	// 10 ticks(100 millisecond)

/*
 * System boot time update cycle time, unit is milliseconds.
 */
#define SYS_TIME_UPDATE_PERIOD 1000	// 1000 ticks(10 seconds)

/*
 * Check whether the eBPF Map exceeds the maximum value and use it to release
 * stale data (unit is milliseconds).
 */
#define CHECK_MAP_EXCEEDED_PERIOD 100	// 100 ticks(1 seconds)

/*
 * Used to check whether the kernel adaptation is successful, here is the
 * check cycle time (unit is milliseconds).
 */
#define CHECK_KERN_ADAPT_PERIOD 100	// 100 ticks(1 seconds)

/*
 * The maximum space occupied by the Java symbol files in the target POD.
 * Its valid range is [2, 100], which means it falls within the interval
 * of 2Mi to 100Mi. If the configuration value is outside this range, the
 * default value of 10(10Mi), will be used.
 */
#define JAVA_POD_WRITE_FILES_SPACE_MIN 2097152	// 2Mi
#define JAVA_POD_WRITE_FILES_SPACE_MAX 104857600	// 100Mi
#define JAVA_POD_WRITE_FILES_SPACE_DEF 10485760	// 10Mi
/*
 * The `df_java_agent_musl.so` and `df_java_agent.so` files will also be
 * placed in the target POD for loading operations. They occupy less than
 * 300Ki of space.
 */
#define JAVA_POD_EXTRA_SPACE_MMA 307200	// 300Ki

/*
 * The perf profiler utilizes a perf buffer (per CPUs) for transporting stack data,
 * which may lead to out-of-order behavior in a multi-core environment, as illustrated
 * below:
 *
 * User-received  eBPF (Kernel) Data  Description
 * Order          recv-time (ns)
 * ---------------------------------------------------------
 * 0	       1043099273143475	   First stack data with stack ID 'A'
 * 1	       1043099276726460    Successfully removed 'A' from the stack map
 * 2	       1043099169934151	   Second stack data with stack ID also 'A'
 *                                 (failed lookup in stack map for 'A')
 * 3	       1043099314811542	   Attempted duplicate removal of 'A' from the
 *                                 stack map, failed
 * ---------------------------------------------------------
 *
 * We have introduced a threshold to delay the removal of 'A' from the stack map to
 * avoid the aforementioned out-of-order scenario. After each iteration, stack map
 * cleanup is performed only if the number of entries in the stack map exceeds this
 * threshold.
 */
#define STACKMAP_CLEANUP_THRESHOLD 50

/*
 * When the deepflow-agent is started, to avoid the sudden generation of Java symbol
 * tables:
 * - Introduce an additional random value for each process's delay, on top of
 *   the configuration specified above, to prevent the abrupt generation of symbol file
 *   for a large number of processes.
 *
 * For non-Java programs, symbol loading will also be randomly delayed
 * (time range: 0 to PROFILER_DEFER_RANDOM_MAX).
 *
 * The random value has a maximum limit specified above(measured in seconds).
 */

#define PROFILER_DEFER_RANDOM_MAX 60	// 60 seconds

/*
 * Scaling factor is sized to avoid hash table collisions and timing variations.
 */
#define STACKMAP_SCALING_FACTOR 3.0
#define STACKMAP_CAPACITY_THRESHOLD 32768	// The capacity limit of the Stack trace map, power of two.

/*
 * eBPF utilizes perf event's periodic events to push all data residing in the kernel
 * cache. We have set this to push data from the kernel buffer every 40 milliseconds(KICK_KERN_PERIOD).
 *
 * The system call phase will check the time delay of the push period, and if it exceeds this
 * threshold, the data will be pushed immediately.
 */
#define PERIODIC_PUSH_DELAY_THRESHOLD_NS 50000000ULL	// 50 milliseconds

/*
 * The update interval for process information is 5 minutes in nanoseconds.
 */
#define PROCESS_CACHE_UPDATE_INTERVAL_NS 300000000000ULL

/*
 * The update interval for mount information is 20 secs in nanoseconds.
 */
#define MOUNT_CACHE_UPDATE_INTERVAL_NS 20000000000ULL

/*
 * Output to the log once every hour to prevent the log file from containing too much content.
 */
#define OUTPUT_LOG_INTERVAL_NS 3600000000000ULL
#endif /* DF_EBPF_CONFIG_H */
