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

#ifndef JVM_SYMBOL_COLLECT_H
#define JVM_SYMBOL_COLLECT_H

#include "config.h"

#define UNIX_PATH_MAX 108
#define JAVA_ADDR_STR_SIZE 13

#define DF_JAVA_ATTACH_CMD "/usr/bin/deepflow-jattach"

/* Complete fix update boundary for standard OpenJDK 8u. */
#define JAVA_ATTACH_JAVA8_FIRST_FIX_UPDATE 352
#define JAVA_ATTACH_JAVA8_COMPLETE_FIX_UPDATE 382

/*
 * Standard OpenJDK Java 8u0-8u351 lacks both JDK-8173361 and JDK-8305165,
 * while 8u352-8u381 still lacks JDK-8305165. Neither range can be considered
 * safe from the version alone. The complete-fix baseline is 8u382; HotSpot
 * versions below this baseline are not injected by the profiling agent. Keep
 * the policy here so the Agent and standalone attach tool use the same decision.
 */
#define JAVA_ATTACH_SKIPPED_UNSUPPORTED_JVM (-2)
#define JAVA_PREFLIGHT_VERSION_LEN 128

typedef enum {
	JAVA_PREFLIGHT_ALLOW = 0,
	JAVA_PREFLIGHT_SKIP = 1,
	JAVA_PREFLIGHT_ERROR = 2,
} java_preflight_result_t;

typedef struct {
	int major_version; /**< Java major version. */
	int update_version; /**< Java 8 update version. */
	bool is_hotspot; /**< Whether a HotSpot libjvm.so was detected. */
	bool is_other_jvm; /**< Whether another known JVM, such as OpenJ9, was detected. */
	bool attach_disabled; /**< Whether DisableAttachMechanism is set. */
	char java_version[JAVA_PREFLIGHT_VERSION_LEN]; /**< JAVA_VERSION value. */
	char reason[JAVA_PREFLIGHT_VERSION_LEN]; /**< Preflight result reason. */
} java_preflight_info_t;

/**
 * Core JVM attach preflight entry point.
 *
 * The check must finish before creating a socket, copying the Agent SO, or
 * calling jattach, and it cannot use the Attach API. Therefore this function
 * must not call jcmd, jinfo, or jattach, or load code into the target process.
 * Run the version command with the target Java executable and environment in a
 * short-lived helper after it enters the target PID/mount namespaces. The
 * caller remains in its original namespaces because the helper exits after the
 * version command completes.
 *
 * The result has the following meaning:
 * - Process check failure: the target exited, is a zombie, or its PID is unreadable;
 *   skip attach.
 * - JVM map check failure: neither HotSpot libjvm.so nor another known JVM core
 *   library was found; the target cannot be identified as a JVM, so skip attach.
 * - Non-HotSpot JVM: for example, OpenJ9 skips the HotSpot version gate and is
 *   allowed after the common safety checks.
 * - HotSpot: execute the target JVM's own -version in the target namespace,
 *   without relying on a release file; parse JAVA_VERSION for Java 8 update.
 *   Do not switch namespaces when both processes already share one.
 * - HotSpot Java 8 update below 352: both known fixes are missing; skip attach.
 * - HotSpot Java 8 update 352-381: JDK-8173361 is present, but JDK-8305165 is
 *   missing; skip attach under the current policy.
 * - HotSpot Java 8 update 382 or newer: both standard OpenJDK fixes are present;
 *   continue with the remaining checks.
 * - Attach is disabled, cmdline/environ cannot be read, or the PID is reused
 *   during the check: skip attach without injection.
 * - All checks pass: return allow so the caller may create the socket, copy the
 *   Agent SO, and invoke jattach.
 */
java_preflight_result_t java_attach_preflight(pid_t pid,
					      java_preflight_info_t *info);

/*
 * The address range of the 64-bit user space is from 0x0000000000000000
 * to 0x00007fffffffffff, which effectively uses only 48 bits. We use 13
 * bytes to represent the address string, with the last byte used as '\0'.
 */
typedef struct {
	char addr[JAVA_ADDR_STR_SIZE];
	bool is_verified;
} java_unload_addr_str_t;

typedef uint64_t(*agent_test_t) (void);

typedef struct options {
	char perf_map_path[PERF_PATH_SZ];
	char perf_log_path[PERF_PATH_SZ];
} options_t;

typedef struct task_s symbol_collect_task_t;

/**
 * @brief Parameters for task processing.
 */
typedef struct receiver_args {
	pid_t pid;		/**< Java process ID */
	options_t *opts;	/**< Parameters for calling jattach, such as the file path for the Unix domain socket */
	int map_socket;		/**< For receiving JVM connection requests, establishing a Java symbol data transmission channel */
	int log_socket;		/**< For receiving JVM connection requests, establishing a JVM log data transmission channel */
	int map_client;		/**< For Java symbol data transmission */
	int log_client;		/**< For JVM log data transmission */
	int epoll_fd;		/**< epoll listening socket */
	FILE *map_fp;		/**< File for saving Java symbol information */
	FILE *log_fp;		/**< File for saving JVM log information */
	volatile int attach_ret; /**< To store the return value of jattach */
	volatile bool replay_done; /**< Indicates whether Java symbol replay is complete */
	symbol_collect_task_t *task; /**< Address of the associated task */
} receiver_args_t;

/**
 * @brief Definition of Java symbol collection task.
 */
struct task_s {
	struct list_head list;	/**< Task queue */
	pid_t pid;		/**< Java process ID to be handled by the task */
	u64 pid_start_time;	/**< Process start time; combined with `<pid + pid_start_time>` to uniquely identify a process */
	bool is_local_mntns;	/**< Whether it is in the same mount namespace as deepflow-agent */
	pthread_t thread;	/**< Thread handling the task */
	void *(*func) (void *);	/**< Callback function for task processing */
	bool need_refresh;	/**< Whether the file needs to be refreshed */
	int update_status;	/**< Symbol file update status */
	pthread_mutex_t mutex;	/**< Mutex for protecting tasks */
	pthread_cond_t cond;	/**< Condition variable for notifying updates to files */
	receiver_args_t args;	/**< Parameters for task processing */
};

/**
 * @brief Definition of task thread
 */
typedef struct {
	int index; /**< thread index in pool. */
	pthread_t thread; /**< thread ID */ 
	symbol_collect_task_t *task; /**< task address */
} task_thread_t;

/**
 * @brief Definition of the thread pool for Java symbol collection tasks.
 */
typedef struct {
	task_thread_t *threads;	/**< Array for managing threads */
	int thread_index;       /**< Index of the most recent thread */
	pthread_mutex_t lock;	/**< Thread pool lock */
	pthread_cond_t cond;	/**< Condition variable for waking up threads to execute tasks */
	struct list_head task_list_head; /**< Queue of tasks waiting to be processed */
	int task_count;		/**< Total number of tasks currently being processed */
	int pending_tasks;	/**< Number of tasks waiting to be processed */
	int thread_count;	/**< Number of threads in the thread pool */
	int stop;		/**< Thread pool stop flag */
} symbol_collect_thread_pool_t;

/**
 * @brief Updates the Java symbol file.
 * 
 * Informs the Java symbol collector to collect Java symbols. If a 
 * collection task is already running, it will update the Java symbol 
 * file. If no collection task exists, a new task will be created for 
 * the collection.
 *
 * @param pid The Java process ID for symbol collection.
 * @param is_new_collector Is it a newly created symbol collector, with the result returned to the caller.
 * @return 0 if the Java symbol file has been successfully updated, 
 *         otherwise returns a failure code.
 */
int update_java_symbol_file(pid_t pid, bool *is_new_collector);

/**
 * @brief Cleans up a single file in the target namespace.
 * 
 * @param target_path The path of the file to be cleaned.
 */
void clear_target_ns_tmp_file(const char *target_path);

/**
 * @brief Cleans up files in the target namespace.
 * 
 * These files include:
 * - path/.deepflow-java-symbols-pid<pid>.socket
 * - path/.deepflow-java-jvmti-logs-pid<pid>.socket
 * - path/df_java_agent.so
 * - path/df_java_agent_musl.so
 *
 * @param pid The process ID of the target to clean.
 * @param check_in_use Whether to check if the files are being used by 
 *                     other processes. If true, the files will be 
 *                     checked, and if they are in use, they will not 
 *                     be cleaned.
 * @return 0 if the cleanup was successful, non-zero if it failed.
 */
int check_and_clear_target_ns(int pid, bool check_in_use);

/**
 * @brief Cleans up dynamic library files in the target namespace.
 * 
 * These files include:
 * - path/df_java_agent.so
 * - path/df_java_agent_musl.so
 *
 * @param pid The process ID of the target to clean.
 * @param check_in_use Whether to check if the files are being used by 
 *                     other processes. If true, the files will be 
 *                     checked, and if they are in use, they will not 
 *                     be cleaned.
 * @return 0 if the cleanup was successful, non-zero if it failed.
 */
int check_and_clear_unix_socket_files(int pid, bool check_in_use);

/**
 * @brief Cleans up local '/tmp' perf files.
 * 
 * These files include:
 * - /tmp/perf-<pid>.map
 * - /tmp/perf-<pid>.log
 *
 * @param pid The process ID of the target to clean.
 * @return 0 if the cleanup was successful, non-zero if it failed.
 */
void clear_local_perf_files(int pid);

/**
 * @brief Gets the size of the local symbol file.
 * 
 * File: /tmp/perf-<pid>.map
 *
 * @param pid The process ID associated with the file.
 * @return The file size, or a negative value if there was an error.
 */
i64 get_local_symbol_file_sz(int pid);

/**
 * @brief Checks if the symbol file is accessible.
 * 
 * File: /tmp/perf-<pid>.map
 *
 * @param pid The process ID associated with the file.
 * @return 0 if the file exists, otherwise returns a non-zero value 
 *         indicating the file does not exist.
 */
int target_symbol_file_access(int pid);

#endif /* JVM_SYMBOL_COLLECT_H */
