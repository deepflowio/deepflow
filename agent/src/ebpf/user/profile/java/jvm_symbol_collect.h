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
