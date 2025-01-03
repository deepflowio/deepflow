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

#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <dlfcn.h>
#include <dirent.h>
#include "../../config.h"
#include "../../utils.h"
#include "../../log.h"
#include "../../mem.h"
#include "../../vec.h"
#include "config.h"
#include "jvm_symbol_collect.h"

#define SYM_COLLECT_MAX_EVENTS 4

// Use thread pool to manage threads for obtaining Java symbols.
symbol_collect_thread_pool_t *g_collect_pool;

/*
 * Use a dynamic array to store the addresses of 'COMPILED_METHOD_UNLOAD'
 * sent by the Java JVM. This is a per-thread variable, with each thread
 * handling the data sent by the corresponding JVM.
 */
static __thread java_unload_addr_str_t *unload_addrs;
extern int jattach(int pid, int argc, char **argv, int print_output);
static int create_symbol_collect_task(pid_t pid, options_t * opts,
				      bool is_same_mntns);

bool test_dl_open(const char *so_lib_file_path)
{
	if (access(so_lib_file_path, F_OK)) {
		ebpf_warning(JAVA_LOG_TAG "Fun %s file '%s' not exist.\n",
			     __func__, so_lib_file_path);

		return false;
	}

	/*
	 * By calling dlerror() before each dlopen()/dlsym() invocation,
	 * you can clear any prior error state, ensuring that you accur-
	 * ately obtain error information pertaining to the current
	 * operation.
	 */
	dlerror();
	void *h = dlopen(so_lib_file_path, RTLD_LAZY);

	if (h == NULL) {
		ebpf_warning(JAVA_LOG_TAG
			     "Fuc '%s' dlopen() path %s failure: %s.", __func__,
			     so_lib_file_path, dlerror());
		return false;
	}

	dlerror();
	agent_test_t test_fn =
	    (uint64_t(*)(void))dlsym(h, "df_java_agent_so_libs_test");

	if (test_fn == NULL) {
		ebpf_warning(JAVA_LOG_TAG
			     "Func '%s' dlsym() path %s failure: %s.", __func__,
			     so_lib_file_path, dlerror());
		return false;
	}

	const uint64_t expected_test_fn_result =
	    JAVA_AGENT_LIBS_TEST_FUN_RET_VAL;
	const uint64_t observed_test_fn_result = test_fn();

	if (observed_test_fn_result != expected_test_fn_result) {
		ebpf_warning(JAVA_LOG_TAG
			     "%s test '%s' function returned: %lu, expected %lu.",
			     __func__, so_lib_file_path,
			     observed_test_fn_result, expected_test_fn_result);
		return false;
	}

	ebpf_info(JAVA_LOG_TAG "%s: Success for %s.\n", __func__,
		  so_lib_file_path);
	return true;
}

void clear_target_ns_tmp_file(const char *target_path)
{
	if (access(target_path, F_OK) == 0) {
		if (unlink(target_path) != 0)
			ebpf_warning(JAVA_LOG_TAG "rm file %s failed\n",
				     target_path);
	}
}

void clear_local_perf_files(int pid)
{
	char local_path[MAX_PATH_LENGTH];
	snprintf(local_path, sizeof(local_path),
		 DF_AGENT_LOCAL_PATH_FMT ".map", pid);
	clear_target_ns_tmp_file(local_path);

	snprintf(local_path, sizeof(local_path),
		 DF_AGENT_LOCAL_PATH_FMT ".log", pid);
	clear_target_ns_tmp_file(local_path);
}

int check_and_clear_unix_socket_files(int pid, bool check_in_use)
{
	char target_path[MAX_PATH_LENGTH];
	snprintf(target_path, sizeof(target_path),
		 DF_AGENT_MAP_SOCKET_PATH_FMT, pid, pid);

	if (check_in_use) {
		if (is_file_opened_by_other_processes(target_path) == 1) {
			ebpf_warning(JAVA_LOG_TAG
				     "File '%s' is opened by another process.\n",
				     target_path);
			return -1;
		}
	}
	clear_target_ns_tmp_file(target_path);
	snprintf(target_path, sizeof(target_path),
		 DF_AGENT_LOG_SOCKET_PATH_FMT, pid, pid);
	if (check_in_use) {
		if (is_file_opened_by_other_processes(target_path) == 1) {
			ebpf_warning(JAVA_LOG_TAG
				     "File '%s' is opened by another process.\n",
				     target_path);
			return -1;
		}
	}
	clear_target_ns_tmp_file(target_path);

	return 0;
}

static int clear_so_target_ns(int pid, bool check_in_use)
{
	char target_path[MAX_PATH_LENGTH];
	snprintf(target_path, sizeof(target_path), "/proc/%d/root%s", pid,
		 AGENT_MUSL_LIB_TARGET_PATH);
	if (check_in_use) {
		if (is_file_opened_by_other_processes(target_path) == 1) {
			ebpf_warning(JAVA_LOG_TAG
				     "File '%s' is opened by another process.\n",
				     target_path);
			return -1;
		}
	}
	clear_target_ns_tmp_file(target_path);
	snprintf(target_path, sizeof(target_path), "/proc/%d/root%s", pid,
		 AGENT_LIB_TARGET_PATH);
	if (check_in_use) {
		if (is_file_opened_by_other_processes(target_path) == 1) {
			ebpf_warning(JAVA_LOG_TAG
				     "File '%s' is opened by another process.\n",
				     target_path);
			return -1;
		}
	}
	clear_target_ns_tmp_file(target_path);

	snprintf(target_path, sizeof(target_path), TARGET_NS_STORAGE_PATH, pid);
	rmdir(target_path);

	return 0;
}

int check_and_clear_target_ns(int pid, bool check_in_use)
{
	/*
	 * Delete files:
	 *  path/.deepflow-java-symbols-pid<pid>.socket
	 *  path/.deepflow-java-jvmti-logs-ipd<pid>.socket
	 *  path/df_java_agent.so
	 *  path/df_java_agent_musl.so
	 */

	if (is_same_mntns(pid))
		return 0;

	if (check_and_clear_unix_socket_files(pid, check_in_use) == -1)
		return -1;

	return clear_so_target_ns(pid, check_in_use);
}

static int get_target_ns_info(const char *tag, struct stat *st)
{
	int fd;
	char selfpath[64];
	snprintf(selfpath, sizeof(selfpath), "/proc/self/ns/%s", tag);
	if (st != NULL) {
		if (stat(selfpath, st) != 0)
			return -1;
	}

	fd = open(selfpath, O_RDONLY);
	if (fd < 0)
		return -1;

	return fd;
}

static inline void get_nsfd_and_stat(const char *tag, struct stat *st, int *fd)
{
	*fd = get_target_ns_info(tag, st);
}

static inline void switch_to_root_ns(int root_fd)
{
	/*
	 * If the user of the target namespace is a non-root user, it will be
	 * impossible to switch the target namespace to the root namespace.
	 * There may be a better solution.
	 * (TODO @jiping)
	 */
	df_exit_ns(root_fd);
}

static inline i64 get_symbol_file_size(int pid)
{
	char path[PERF_PATH_SZ];
	snprintf(path, sizeof(path), DF_AGENT_LOCAL_PATH_FMT ".map", pid);

	if (access(path, F_OK)) {
		return -1;
	}

	struct stat st;
	if (stat(path, &st) == 0) {
		return (i64) st.st_size;
	}

	return -1;
}

int target_symbol_file_access(int pid)
{
	char path[PERF_PATH_SZ];
	snprintf(path, sizeof(path), DF_AGENT_LOCAL_PATH_FMT ".map", pid);

	return access(path, F_OK);
}

i64 get_local_symbol_file_sz(int pid)
{
	return get_symbol_file_size(pid);
}

// parse comma separated arguments
int parse_config(char *opts, options_t * parsed)
{
	char line[PERF_PATH_SZ * 2];
	strncpy(line, opts, PERF_PATH_SZ * 2);
	line[PERF_PATH_SZ * 2 - 1] = '\0';

	char *token = strtok(line, ",");
	if (token == NULL) {
		ebpf_warning(JAVA_LOG_TAG "Bad argument line %s\n", opts);
		return -1;
	}
	strncpy(parsed->perf_map_path, token, PERF_PATH_SZ);
	parsed->perf_map_path[PERF_PATH_SZ - 1] = '\0';

	token = strtok(NULL, ",");
	if (token == NULL) {
		ebpf_warning(JAVA_LOG_TAG "Bad argument line %s\n", opts);
		return -1;
	}
	strncpy(parsed->perf_log_path, token, PERF_PATH_SZ);
	parsed->perf_log_path[PERF_PATH_SZ - 1] = '\0';

	return 0;
}

int symbol_collect_same_namespace(pid_t pid, options_t * opts)
{
	// Clear '/tmp/' unix domain sockets files.
	if (check_and_clear_unix_socket_files(pid, false) == -1)
		return -1;

	return create_symbol_collect_task(pid, opts, true);
}

int create_ipc_socket(const char *path)
{
	int sock = -1;
	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		ebpf_warning(JAVA_LOG_TAG
			     "Create unix socket failed with '%s(%d)'\n",
			     strerror(errno), errno);
		return -1;
	}

	struct sockaddr_un addr = {.sun_family = AF_UNIX };
	strncpy(addr.sun_path, path, UNIX_PATH_MAX - 1);
	int len = sizeof(addr.sun_family) + strlen(addr.sun_path);
	if (bind(sock, (struct sockaddr *)&addr, len) < 0) {
		ebpf_warning(JAVA_LOG_TAG
			     "Bind unix socket failed with '%s(%d)'\n",
			     strerror(errno), errno);
		return -1;
	}
	if (listen(sock, 1) < 0) {
		ebpf_warning(JAVA_LOG_TAG
			     "Listen on unix socket failed with '%s(%d)'\n",
			     strerror(errno), errno);
		unlink(path);
		return -1;
	}

	return sock;
}

static inline int add_fd_to_epoll(int epoll_fd, int fd)
{
	if (fd <= 0) {
		ebpf_warning(JAVA_LOG_TAG
			     "fd must be a value greater than 0, fd %d\n", fd);
		return -1;
	}

	struct epoll_event event;
	event.events = EPOLLIN;
	event.data.fd = fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) == -1) {
		ebpf_warning(JAVA_LOG_TAG
			     "epoll_ctl() ADD failed with '%s(%d)'\n",
			     strerror(errno), errno);
		return -1;
	}

	return 0;
}

static inline int del_fd_from_epoll(int epoll_fd, int fd)
{
	if (fd <= 0 || epoll_fd <= 0) {
		ebpf_warning(JAVA_LOG_TAG
			     "fd must be a value greater than 0, fd %d, epoll fd %d\n",
			     fd, epoll_fd);
		return -1;
	}

	if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL) == -1) {
		ebpf_warning(JAVA_LOG_TAG
			     "epoll_ctl() DEL failed with '%s(%d)'\n",
			     strerror(errno), errno);
		return -1;
	}

	return 0;
}

static inline int receive_msg(receiver_args_t * args, int sock_fd, char *buf,
			      size_t buf_size, bool received_once)
{
	int recv_bytes = 0;
	int n = 0;		// Initialize n

	do {
		if ((n =
		     recv(sock_fd, buf + recv_bytes, buf_size - recv_bytes,
			  0)) == -1) {
			if (errno == EINTR) {
				// Retry on interrupt or temporary failure
				continue;
			} else {
				// Handle other errors
				ebpf_warning(JAVA_LOG_TAG
					     "Receive Java process(PID: %d) message"
					     " failed with '%s(%d)'\n",
					     args->pid, strerror(errno), errno);
				return -1;
			}
		} else if (n == 0) {
			ebpf_warning(JAVA_LOG_TAG
				     "The target Java process (PID: %d) has"
				     " disconnected. The Java process may have exited.\n",
				     args->pid);
			return -1;
		}

		recv_bytes += n;
	} while (recv_bytes < buf_size && !received_once);

	return recv_bytes;	// Return total bytes received
}

static bool is_unload_address(const char *sym_str)
{
	java_unload_addr_str_t *jaddr;
	vec_foreach(jaddr, unload_addrs) {
		if (jaddr->is_verified)
			continue;
		if (substring_starts_with(sym_str, jaddr->addr)) {
			jaddr->is_verified = true;
			return true;
		}
	}

	return false;
}

static int delete_method_unload_symbol(receiver_args_t * args)
{
	const char *path = args->opts->perf_map_path;
	size_t delete_count = 0;
	FILE *fp_in = fopen(path, "r");
	if (!fp_in) {
		ebpf_warning(JAVA_LOG_TAG
			     "Error opening input file %s, with '%s(%d)'\n",
			     path, strerror(errno), errno);
		return -1;
	}

	char temp_path[MAX_PATH_LENGTH];
	snprintf(temp_path, sizeof(temp_path), "%s.temp", path);
	FILE *fp_out = fopen(temp_path, "w");
	if (!fp_out) {
		ebpf_warning(JAVA_LOG_TAG
			     "Error creating temporary file %s, with '%s(%d)'\n",
			     temp_path, strerror(errno), errno);
		fclose(fp_in);
		return -1;
	}

	char buffer[STRING_BUFFER_SIZE];
	while (fgets(buffer, sizeof(buffer), fp_in)) {
		if (!is_unload_address(buffer))
			fputs(buffer, fp_out);
		else
			delete_count++;
	}

	fclose(fp_in);
	fclose(fp_out);

	if (remove(path) != 0) {
		ebpf_warning(JAVA_LOG_TAG
			     "Error deleting original file %s, with '%s(%d)'\n",
			     path, strerror(errno), errno);
		return -1;
	}
	if (rename(temp_path, path) != 0) {
		ebpf_warning(JAVA_LOG_TAG
			     "Error renaming temporary file '%s(%d)'\n",
			     strerror(errno), errno);
		return -1;
	}

	return delete_count;
}

static int update_java_perf_map_file(receiver_args_t * args, char *addr_str)
{
	if (addr_str != NULL) {
		int ret = VEC_OK;
		java_unload_addr_str_t java_addr;
		memset(&java_addr, 0, sizeof(java_addr));
		snprintf(java_addr.addr, sizeof(java_addr.addr), "%s",
			 addr_str);
		vec_add1(unload_addrs, java_addr, ret);
		if (ret != VEC_OK) {
			ebpf_warning(" Java unload_addrs add failed.\n");
		}
	}

	int unload_count = vec_len(unload_addrs);
	if ((args->task->need_refresh && unload_count > 0)
	    || unload_count >= UPDATE_SYMS_FILE_UNLOAD_HIGH_THRESH) {
		fclose(args->map_fp);
		int count;
		if ((count = delete_method_unload_symbol(args)) < 0) {
			vec_free(unload_addrs);
			return -1;
		}
		vec_free(unload_addrs);
		args->map_fp = fopen(args->opts->perf_map_path, "a");
		if (!args->map_fp) {
			ebpf_warning(JAVA_LOG_TAG
				     "fopen() %s failed with '%s(%d)'\n",
				     args->opts->perf_map_path, strerror(errno),
				     errno);
			return -1;
		}
		ebpf_debug
		    ("=== file update args->task->need_refresh %d pid %d unload_count %d\n",
		     args->task->need_refresh, args->task->pid, unload_count);
	}

	return 0;
}

static int symbol_msg_process(receiver_args_t * args, int sock_fd)
{
	FILE *fp = args->map_fp;
	struct symbol_metadata meta;
	int n = receive_msg(args, sock_fd, (char *)&meta, sizeof(meta), false);
	if (n != sizeof(meta))
		return -1;

	char rcv_buf[STRING_BUFFER_SIZE];
	if (meta.len > STRING_BUFFER_SIZE)
		return -1;

	n = receive_msg(args, sock_fd, rcv_buf, meta.len, false);
	if (n != meta.len)
		return -1;
	rcv_buf[meta.len] = '\0';

	/*
	 * If the replay is complete and the event type is
	 * JVMTI_EVENT_COMPILED_METHOD_UNLOAD, the map file
	 * needs to be updated.
	 */
	if (args->replay_done && meta.type == METHOD_UNLOAD) {
		if (update_java_perf_map_file(args, rcv_buf))
			return -1;
	} else {
		int written_count = fwrite(rcv_buf, sizeof(char), n, fp);
		if (written_count != n) {
			ebpf_warning(JAVA_LOG_TAG "%s(%d)\n", strerror(errno),
				     errno);
			return -1;
		}
		/*
		 * Ensure data is written to the file promptly,
		 * avoiding prolonged residence in the buffer.
		 */
		fflush(fp);
	}

	return 0;
}

static int symbol_log_process(receiver_args_t * args, int sock_fd)
{
	FILE *fp = args->log_fp;
	char rcv_buf[STRING_BUFFER_SIZE];
	int n = receive_msg(args, sock_fd, rcv_buf, sizeof(rcv_buf), true);
	if (n == -1)
		return -1;
	int written_count = fwrite(rcv_buf, sizeof(char), n, fp);
	if (written_count != n) {
		ebpf_warning(JAVA_LOG_TAG "%s(%d)\n", strerror(errno), errno);
		return -1;
	}
	fflush(fp);
	return 0;
}

int epoll_events_process(receiver_args_t * args, int epoll_fd,
			 struct epoll_event *ev)
{
	errno = 0;
	if (ev->data.fd == args->map_socket) {
		if ((args->map_client = accept(ev->data.fd, NULL, NULL)) < 0) {
			ebpf_warning(JAVA_LOG_TAG
				     "accept() failed with '%s(%d)'\n",
				     strerror(errno), errno);
			return -1;
		}
		if (add_fd_to_epoll(epoll_fd, args->map_client) == -1)
			return -1;
	} else if (ev->data.fd == args->log_socket) {
		if ((args->log_client = accept(ev->data.fd, NULL, NULL)) < 0) {
			ebpf_warning(JAVA_LOG_TAG
				     "accept() failed with '%s(%d)'\n",
				     strerror(errno), errno);
			return -1;
		}
		if (add_fd_to_epoll(epoll_fd, args->log_client) == -1)
			return -1;
	} else {
		if (ev->data.fd == args->map_client) {
			if (symbol_msg_process(args, ev->data.fd))
				return -1;
		} else if (ev->data.fd == args->log_client) {
			if (symbol_log_process(args, ev->data.fd))
				return -1;
		} else {
			ebpf_warning(JAVA_LOG_TAG
				     "Unexpected event, event fd %d\n",
				     ev->data.fd);
			return 0;
		}
	}

	return 0;
}

static int destroy_task(symbol_collect_task_t * task,
			symbol_collect_thread_pool_t * pool)
{
	receiver_args_t *args = (receiver_args_t *) & task->args;
	if (args->map_fp) {
		fclose(args->map_fp);
	}

	if (args->log_fp) {
		fclose(args->log_fp);
	}

	if (args->map_client > 0) {
		del_fd_from_epoll(args->epoll_fd, args->map_client);
		close(args->map_client);
	}

	if (args->log_client > 0) {
		del_fd_from_epoll(args->epoll_fd, args->log_client);
		close(args->log_client);
	}

	if (args->map_socket > 0) {
		del_fd_from_epoll(args->epoll_fd, args->map_socket);
		close(args->map_socket);
	}

	if (args->log_socket > 0) {
		del_fd_from_epoll(args->epoll_fd, args->log_socket);
		close(args->log_socket);
	}

	if (args->epoll_fd > 0) {
		close(args->epoll_fd);
	}

	if (!task->is_local_mntns)
		check_and_clear_target_ns(args->pid, false);
	else
		check_and_clear_unix_socket_files(args->pid, false);

	ebpf_debug(JAVA_LOG_TAG "All resources cleaned up for symbol table"
		   " management task (associated with JAVA PID: %d).\n",
		   args->pid);
	free(task);
	return 0;
}

static void *ipc_receiver_main(void *arguments)
{
	receiver_args_t *args = (receiver_args_t *) arguments;

	/*
	 * If the file already exists, opening it in "w" mode will clear its contents
	 * (truncate it to zero length). If the file does not exist, opening it in "w"
	 * mode will create a new file.
	 */
	FILE *map_fp = fopen(args->opts->perf_map_path, "w");
	if (!map_fp) {
		// byte stream in socket needs to be consumed to avoid client stuck
		// even if file open fails
		ebpf_warning(JAVA_LOG_TAG "fopen() %s failed with '%s(%d)'\n",
			     args->opts->perf_map_path, strerror(errno), errno);
		goto cleanup;
	}
	args->map_fp = map_fp;

	FILE *log_fp = fopen(args->opts->perf_log_path, "w");
	if (!log_fp) {
		// byte stream in socket needs to be consumed to avoid client stuck
		// even if file open fails
		ebpf_warning(JAVA_LOG_TAG "fopen() %s failed with '%s(%d)'\n",
			     args->opts->perf_log_path, strerror(errno), errno);
		goto cleanup;
	}
	args->log_fp = log_fp;

	int epoll_fd = epoll_create1(0);
	if (epoll_fd == -1) {
		ebpf_warning(JAVA_LOG_TAG
			     "epoll_create1() failed with '%s(%d)'\n",
			     strerror(errno), errno);
		goto cleanup;
	}
	args->epoll_fd = epoll_fd;

	if (add_fd_to_epoll(epoll_fd, args->map_socket) == -1) {
		goto cleanup;
	}

	if (add_fd_to_epoll(epoll_fd, args->log_socket) == -1) {
		goto cleanup;
	}

	struct epoll_event events[SYM_COLLECT_MAX_EVENTS];
	while (args->attach_ret == 0) {
		int n = epoll_wait(epoll_fd, events, SYM_COLLECT_MAX_EVENTS,
				   PROFILER_READER_EPOLL_TIMEOUT);
		if (n == -1) {
			if (errno == EINTR) {
				// If epoll_wait was interrupted by a signal, retry
				continue;
			} else {
				ebpf_warning(JAVA_LOG_TAG
					     "epoll_wait() failed with '%s(%d)'\n",
					     strerror(errno), errno);
				goto cleanup;
			}
		}

		for (int i = 0; i < n; ++i) {
			if (events[i].events & EPOLLIN) {
				struct epoll_event *ev = &events[i];
				if (epoll_events_process
				    (args, epoll_fd, ev) < 0)
					goto cleanup;
			}
		}

		if (args->task->need_refresh) {
			int ret_val = update_java_perf_map_file(args, NULL);
			pthread_mutex_lock(&args->task->mutex);
			args->task->update_status = ret_val;
			args->task->need_refresh = false;
			pthread_cond_signal(&args->task->cond);
			pthread_mutex_unlock(&args->task->mutex);
		}
	}

cleanup:
	/* Return to worker_thread() to handle unified resource cleanup. */
	return NULL;
}

static void *worker_thread(void *arg)
{
	symbol_collect_thread_pool_t *pool = arg;
	pthread_t thread = pthread_self();
	int thread_idx = pool->thread_index;

	while (1) {
		pthread_mutex_lock(&pool->lock);
		while (pool->pending_tasks <= 0 && !pool->stop) {
			pthread_cond_wait(&pool->cond, &pool->lock);
		}

		if (pool->stop && pool->task_count == 0) {
			pthread_mutex_unlock(&pool->lock);
			pthread_exit(NULL);
		}

		if (pool->threads[thread_idx].thread != thread) {
			pthread_mutex_unlock(&pool->lock);
			pthread_exit(NULL);
		}
		// Get task from queue
		symbol_collect_task_t *task;
		task = list_first_entry(&pool->task_list_head,
					symbol_collect_task_t, list);
		list_head_del(&task->list);
		pool->pending_tasks--;
		task->thread = thread;
		pool->threads[thread_idx].task = task;
		pthread_mutex_unlock(&pool->lock);

		// Execute task
		ebpf_debug(JAVA_LOG_TAG
			   "Thread %ld executing task for java processes (PID: %d)\n",
			   task->thread, task->pid);
		task->func(&task->args);

		ebpf_debug(JAVA_LOG_TAG
			   "Thread %ld finished task for java processes (PID: %d)\n",
			   task->thread, task->pid);
		pthread_mutex_lock(&pool->lock);
		pool->threads[thread_idx].task = NULL;
		pool->task_count--;
		pthread_mutex_unlock(&pool->lock);
		destroy_task(task, pool);
	}

	return NULL;
}

static bool check_target_jvmti_attach_files(pid_t pid)
{
	/*
	 * After a successful attach, the following files will be generated.
	 *  HotSpot: <target-path>/tmp/.java_pid<target-pid>
	 *  OpenJ9:  <target-path>/tmp/.com_ibm_tools_attach/<target-pid> 
	 */
	char hotspot_path[MAX_PATH_LENGTH], openj9_path[MAX_PATH_LENGTH];
	pid_t ns_pid = get_nspid(pid);

	// Check for HotSpot JVM dependency file
	snprintf(hotspot_path, sizeof(hotspot_path),
		 "/proc/%d/root/tmp/.java_pid%d", pid, ns_pid);
	bool hotspot_exist = (access(hotspot_path, F_OK) == 0);
	if (hotspot_exist) {
		ebpf_debug(JAVA_LOG_TAG
			   "Java process (PID:%d) is HotSpot JVM.\n", pid);
		return true;
	}
	// Check for OpenJ9 JVM dependency file
	snprintf(openj9_path, sizeof(openj9_path),
		 "/proc/%d/root/tmp/.com_ibm_tools_attach/%d", pid, ns_pid);
	bool openj9_exist = (access(openj9_path, F_OK) == 0);
	if (openj9_exist) {
		ebpf_debug(JAVA_LOG_TAG
			   "Java process (PID:%d) is OpenJ9 JVM.\n", pid);
		return true;
	}

	ebpf_warning(JAVA_LOG_TAG "Check HotSpot JVM, file '%s' not exist.\n"
		     "Check OpenJ9 JVM, file '%s' not exist.\n",
		     hotspot_path, openj9_path);

	return false;
}

static int thread_pool_add_task(symbol_collect_thread_pool_t * pool,
				symbol_collect_task_t * task)
{
	pthread_mutex_lock(&pool->lock);
	list_add_tail(&task->list, &pool->task_list_head);
	pool->task_count++;
	pool->pending_tasks++;

	// Wake up threads in the thread pool to execute tasks.
	pthread_cond_signal(&pool->cond);

	// If there are no threads available in the thread pool,
	// new threads need to be added to the thread pool.
	if (pool->task_count > pool->thread_count) {
		int ret;
		pthread_t thread;
		pool->thread_index = pool->thread_count;

		if ((ret =
		     pthread_create(&thread, NULL, &worker_thread, pool)) < 0) {
			ebpf_warning(JAVA_LOG_TAG
				     "Create worker thread failed with '%s(%d)'\n",
				     strerror(errno), errno);
			pthread_mutex_unlock(&pool->lock);
			return -2;
		}

		if (pthread_detach(thread) != 0) {
			ebpf_warning(JAVA_LOG_TAG
				     "Failed to detach thread with '%s(%d)'\n",
				     strerror(errno), errno);
			pthread_mutex_unlock(&pool->lock);
			return -1;
		}

		task_thread_t *new_threads = realloc(pool->threads,
						     (++pool->thread_count) *
						     sizeof(task_thread_t));
		if (new_threads == NULL) {
			ebpf_warning
			    (JAVA_LOG_TAG
			     "Failed to reallocate memory for threads with '%s(%d)'\n",
			     strerror(errno), errno);
			pthread_mutex_unlock(&pool->lock);
			return -1;
		}

		pool->threads = new_threads;
		pool->threads[pool->thread_count - 1].task = NULL;
		pool->threads[pool->thread_count - 1].thread = thread;
		pool->threads[pool->thread_count - 1].index =
		    pool->thread_count - 1;
		ebpf_debug(JAVA_LOG_TAG
			   "Created new thread. Current thread count: %d\n",
			   pool->thread_count);
	}

	pthread_mutex_unlock(&pool->lock);

	return 0;
}

static int create_symbol_collect_task(pid_t pid, options_t * opts,
				      bool is_same_mntns)
{
	int ret = -1;
	symbol_collect_task_t *task = NULL;
	int map_socket = -1, log_socket = -1;

	// make the sockets accessable from unprivileged user in container
	umask(0);

	char buffer[PERF_PATH_SZ * 2];
	snprintf(buffer, PERF_PATH_SZ, DF_AGENT_MAP_SOCKET_PATH_FMT, pid, pid);

	if ((map_socket = create_ipc_socket(buffer)) < 0) {
		goto cleanup;
	}
	snprintf(buffer, PERF_PATH_SZ, DF_AGENT_LOG_SOCKET_PATH_FMT, pid, pid);

	if ((log_socket = create_ipc_socket(buffer)) < 0) {
		goto cleanup;
	}

	task = malloc(sizeof(symbol_collect_task_t) + sizeof(*opts));
	if (task == NULL) {
		ebpf_warning(JAVA_LOG_TAG "malloc() failed, with %s(%d)\n",
			     strerror(errno), errno);
		goto cleanup;
	}
	memset(task, 0, sizeof(symbol_collect_task_t) + sizeof(*opts));
	task->pid = pid;
	task->is_local_mntns = is_same_mntns;
	task->pid_start_time = get_process_starttime_and_comm(pid, NULL, 0);
	if (task->pid_start_time == 0) {
		ebpf_warning("The Java process(PID: %d) no longer exists.\n",
			     pid);
		goto cleanup;
	}
	task->func = ipc_receiver_main;
	pthread_mutex_init(&task->mutex, NULL);
	pthread_cond_init(&task->cond, NULL);
	task->need_refresh = false;
	options_t *__opts = (options_t *) (task + 1);
	*__opts = *opts;

	task->args.pid = pid;
	task->args.opts = __opts;
	task->args.map_socket = map_socket;
	task->args.log_socket = log_socket;
	task->args.attach_ret = 0;
	task->args.replay_done = false;
	task->args.task = task;

	ret = thread_pool_add_task(g_collect_pool, task);
	if (ret < 0) {
		goto cleanup;
	}

	snprintf(buffer, sizeof(buffer), "%d", pid);
	char ret_buf[1024];
	memset(ret_buf, 0, sizeof(ret_buf));
	ret =
	    exec_command(DF_JAVA_ATTACH_CMD, buffer, ret_buf, sizeof(ret_buf));
	if (ret != 0) {
		ebpf_warning(JAVA_LOG_TAG "ret %d: %s", ret, ret_buf);
	}
	task->args.replay_done = true;
	task->args.attach_ret = ret;
	CLIB_MEMORY_STORE_BARRIER();

	/* After successfully attaching, clean up the residual .so files
	 * in the target namespace. */
	if (!is_same_mntns)
		clear_so_target_ns(pid, false);

	if (!check_target_jvmti_attach_files(pid)) {
		ebpf_warning(JAVA_LOG_TAG
			     "Miss HotSpot/OpenJ9 JVM dependency file.\n");
	}

	return ret;

cleanup:
	if (task)
		free(task);

	if (map_socket >= 0) {
		close(map_socket);
	}
	if (log_socket >= 0) {
		close(log_socket);
	}
	// attach() may change euid/egid, restore them to remove tmp files
	if (seteuid(getuid()) < 0) {
		ebpf_warning(JAVA_LOG_TAG "seteuid() failed with '%s(%d)'\n",
			     strerror(errno), errno);
	}
	if (setegid(getgid()) < 0) {
		ebpf_warning(JAVA_LOG_TAG "seteuid() failed with '%s(%d)'\n",
			     strerror(errno), errno);
	}

	if (!is_same_mntns)
		check_and_clear_target_ns(pid, false);
	else
		check_and_clear_unix_socket_files(pid, false);

	return ret;
}

int symbol_collect_different_namespace(pid_t pid, options_t * opts)
{
	/*
	 * Delete the files on the target file system if they
	 * are not on the same mount point.
	 */
	if (check_and_clear_target_ns(pid, false) == -1)
		return -1;

	return create_symbol_collect_task(pid, opts, false);
}

static int symbol_collect_thread_pool_init(void)
{
	symbol_collect_thread_pool_t *pool =
	    malloc(sizeof(symbol_collect_thread_pool_t));
	if (pool == NULL) {
		ebpf_warning(JAVA_LOG_TAG
			     "Failed to allocate memory for thread pool\n");
		return -1;
	}

	if (pthread_mutex_init(&pool->lock, NULL) != 0) {
		ebpf_warning(JAVA_LOG_TAG
			     "Failed to initialize mutex, %s(%d)\n",
			     strerror(errno), errno);
		free(pool);
		return -1;
	}

	if (pthread_cond_init(&pool->cond, NULL) != 0) {
		ebpf_warning(JAVA_LOG_TAG
			     "Failed to initialize cond, %s(%d)\n",
			     strerror(errno), errno);
		free(pool);
		return -1;
	}

	pool->task_count = 0;
	pool->thread_count = 0;	// Initial thread count is 0
	pool->threads = NULL;	// Initial thread array is empty
	pool->stop = 0;
	pool->pending_tasks = 0;
	init_list_head(&pool->task_list_head);
	g_collect_pool = pool;

	return 0;
}

static symbol_collect_task_t *get_task_by_pid(pid_t pid)
{
	if (g_collect_pool == NULL)
		return NULL;

	symbol_collect_task_t *task = NULL;
	pthread_mutex_lock(&g_collect_pool->lock);
	for (int i = 0; i < g_collect_pool->thread_count; i++) {
		if (g_collect_pool->threads[i].task == NULL)
			continue;
		if (g_collect_pool->threads[i].task->pid == pid) {
			task = g_collect_pool->threads[i].task;
			break;
		}
	}
	pthread_mutex_unlock(&g_collect_pool->lock);

	return task;
}

int start_java_symbol_collection(pid_t pid, const char *opts)
{
	// Initialize a thread pool for managing Java symbols.
	if (g_collect_pool == NULL) {
		if (symbol_collect_thread_pool_init()) {
			ebpf_warning
			    ("symbol_collect_thread_pool_init() failed.\n");
			return -1;
		}
	}

	options_t parsed_opts;
	if (parse_config((char *)opts, &parsed_opts) != 0) {
		return -1;
	}

	if (is_same_mntns(pid)) {
		return symbol_collect_same_namespace(pid, &parsed_opts);
	} else {
		return symbol_collect_different_namespace(pid, &parsed_opts);
	}
}

int update_java_symbol_file(pid_t pid, bool * is_new_collector)
{
	char opts[PERF_PATH_SZ * 2];
	snprintf(opts, sizeof(opts),
		 DF_AGENT_LOCAL_PATH_FMT ".map,"
		 DF_AGENT_LOCAL_PATH_FMT ".log", pid, pid);

	symbol_collect_task_t *task = get_task_by_pid(pid);
	if (task == NULL) {
		*is_new_collector = true;
		return start_java_symbol_collection(pid, opts);
	}

	u64 start_time = get_process_starttime_and_comm(pid, NULL, 0);
	if (start_time == 0) {
		ebpf_warning("The process with PID %d no longer exists.\n",
			     pid);
		task->args.attach_ret = -1;	// Force the thread to exit the task it is executing. 
		return -1;
	}
	// The task is stale and needs to be cleaned up.
	if (task->pid_start_time != start_time) {
		task->args.attach_ret = -1;
		ebpf_warning("The task for the process with PID %d"
			     " is invalid and needs to be recreated.\n", pid);
		return -1;
	}
	// Notify to refresh the file
	task->need_refresh = true;
	// Refresh the file again; needs to wait for completion.
	pthread_mutex_lock(&task->mutex);
	pthread_cond_wait(&task->cond, &task->mutex);
	pthread_mutex_unlock(&task->mutex);
	*is_new_collector = false;
	return task->update_status;
}

void show_collect_pool(void)
{
	if (g_collect_pool == NULL)
		return;

	task_thread_t *task_thread;
	symbol_collect_task_t *task = NULL;
	int online_task_cnt = 0;
	pthread_mutex_lock(&g_collect_pool->lock);
	fprintf(stdout,
		"-------------------------------------------------------\n");
	for (int i = 0; i < g_collect_pool->thread_count; i++) {
		if (g_collect_pool->threads[i].task == NULL)
			continue;
		task_thread = &g_collect_pool->threads[i];
		task = task_thread->task;
		fprintf(stdout, "Thread %ld Task %p JavaPID %d\n",
			task_thread->thread, task, task->pid);
		online_task_cnt++;
	}
	fprintf(stdout,
		"-------------------------------------------------------\n");
	fprintf(stdout, "pool threads %d tasks %d pending_task %d\n",
		g_collect_pool->thread_count, g_collect_pool->task_count,
		g_collect_pool->pending_tasks);
	pthread_mutex_unlock(&g_collect_pool->lock);
	fflush(stdout);
}

#ifdef JAVA_AGENT_ATTACH_TOOL
static char agent_lib_so_path[MAX_PATH_LENGTH];
static int agent_so_lib_copy(const char *src, const char *dst, int uid, int gid)
{
	if (access(src, F_OK)) {
		ebpf_warning(JAVA_LOG_TAG "Fun %s src file '%s' not exist.\n",
			     __func__, src);
		return ETR_NOTEXIST;
	}

	if (copy_file(src, dst)) {
		return ETR_INVAL;
	}

	if (chown(dst, uid, gid) != 0) {
		ebpf_warning(JAVA_LOG_TAG
			     "Failed to change ownership and group. file '%s'\n",
			     dst);
		return ETR_INVAL;
	}

	return ETR_OK;
}

static int copy_agent_libs_into_target_ns(pid_t target_pid, int target_uid,
					  int target_gid)
{

	/*
	 * Call this function only when the target process is in a subordinate
	 * namespace. Here, we copy the agent.so to a temporary path within t-
	 * he mounted namespace. We also change the file ownership so that the
	 * target process sees itself as the owner of the file (this is neces-
	 * sary because some versions of Java might reject proxy injection
	 * otherwise).
	 */
	int ret;
	char copy_target_path[MAX_PATH_LENGTH];
	int len = snprintf(copy_target_path, sizeof(copy_target_path),
			   TARGET_NS_STORAGE_PATH, target_pid);
	if (access(copy_target_path, F_OK)) {
		/*
		 * The purpose of umask(0); is to set the current process's file
		 * creation mask (umask) to 0, which means that no permission
		 * bits will be cleared when creating a file or directory. Files
		 * and directories will have the permission bits specified at the
		 * time of creation.
		 */
		umask(0);

		if (mkdir(copy_target_path, 0777) != 0) {
			ebpf_warning(JAVA_LOG_TAG
				     "Fun %s cannot mkdir() '%s'\n", __func__,
				     copy_target_path);

			return ETR_NOTEXIST;
		}
	}

	snprintf(copy_target_path + len, sizeof(copy_target_path) - len,
		 "/%s", AGENT_LIB_NAME);
	if ((ret =
	     agent_so_lib_copy(AGENT_LIB_SRC_PATH,
			       copy_target_path, target_uid,
			       target_gid)) != ETR_OK) {
		ebpf_warning(JAVA_LOG_TAG "cp '%s' to '%s' failed.\n",
			     AGENT_LIB_SRC_PATH, copy_target_path);
		return ret;
	}

	snprintf(copy_target_path + len, sizeof(copy_target_path) - len,
		 "/%s", AGENT_MUSL_LIB_NAME);

	if ((ret =
	     agent_so_lib_copy(AGENT_MUSL_LIB_SRC_PATH,
			       copy_target_path, target_uid,
			       target_gid)) != ETR_OK) {
		ebpf_warning(JAVA_LOG_TAG "cp '%s' to '%s' failed.\n",
			     AGENT_MUSL_LIB_SRC_PATH, copy_target_path);
		return ret;
	}

	return ETR_OK;
}

static void select_suitable_agent_lib(pid_t pid, bool is_same_mntns)
{
	/* Enter pid & mount namespace for target pid,
	 * and use dlopen() in that namespace.*/
	int pid_self_fd, mnt_self_fd;
	df_enter_ns(pid, "pid", &pid_self_fd);
	df_enter_ns(pid, "mnt", &mnt_self_fd);

	agent_lib_so_path[0] = '\0';
	char test_path[PERF_PATH_SZ];
	if (!is_same_mntns)
		snprintf(test_path, sizeof(test_path), "%s",
			 AGENT_LIB_TARGET_PATH);
	else
		snprintf(test_path, sizeof(test_path), "%s",
			 AGENT_LIB_SRC_PATH);

	if (test_dl_open(test_path)) {
		snprintf(agent_lib_so_path, MAX_PATH_LENGTH, "%s", test_path);
		ebpf_info(JAVA_LOG_TAG
			  "Func %s target PID %d test %s, success.\n",
			  __func__, pid, test_path);
		goto found;
	}

	if (!is_same_mntns)
		snprintf(test_path, sizeof(test_path), "%s",
			 AGENT_MUSL_LIB_TARGET_PATH);
	else
		snprintf(test_path, sizeof(test_path), "%s",
			 AGENT_MUSL_LIB_SRC_PATH);

	if (test_dl_open(test_path)) {
		snprintf(agent_lib_so_path, MAX_PATH_LENGTH, "%s", test_path);
		ebpf_info(JAVA_LOG_TAG
			  "Func %s target PID %d test %s, success.\n",
			  __func__, pid, test_path);
		goto found;
	}

	ebpf_warning(JAVA_LOG_TAG "%s test agent so libs, failure.", __func__);

found:

	if (!is_same_mntns) {
		if (strcmp(agent_lib_so_path, AGENT_LIB_TARGET_PATH) == 0) {
			clear_target_ns_tmp_file(AGENT_MUSL_LIB_TARGET_PATH);
		} else {
			clear_target_ns_tmp_file(AGENT_LIB_TARGET_PATH);
		}
	}

	df_exit_ns(pid_self_fd);
	df_exit_ns(mnt_self_fd);
}

static int prepare_for_attach_same_ns(pid_t pid)
{
	/*
	 * In containers, different libc implementations may be used to compile agent
	 * libraries, primarily two types: glibc and musl. We must provide both vers-
	 * ions of the agent library. So, which one should we choose? To determine t-
	 * his, we need to enter the target process's namespace and test each library
	 * until we find one that can be successfully loaded using dlopen.
	 */
	select_suitable_agent_lib(pid, true);

	if (strlen(agent_lib_so_path) == 0)
		return -1;
	return 0;
}

static int prepare_for_attach_different_ns(pid_t pid)
{
	int uid, gid;
	if (get_target_uid_and_gid(pid, &uid, &gid)) {
		return -1;
	}

	/* if pid == target_ns_pid, run in same namespace */
	int target_ns_pid = get_nspid(pid);
	if (target_ns_pid < 0) {
		return -1;
	}

	/*
	 * Here, the original method of determination (based on whether the net
	 * namespace is the same) is modified to use the mnt namespace for comparison,
	 * thus avoiding situations where both the net namespace and pid namespace are
	 * the same but the file system is different.
	 */

	/*
	 * If the target Java process is in a subordinate namespace, copy the
	 * 'agent.so' into the artifacts path (in /tmp) inside of that namespace
	 * (for visibility to the target process).
	 */
	ebpf_info(JAVA_LOG_TAG "[PID %d] copy agent so library ...\n", pid);
	if (copy_agent_libs_into_target_ns(pid, uid, gid)) {
		ebpf_warning(JAVA_LOG_TAG
			     "[PID %d] copy agent os library failed.\n", pid);
		check_and_clear_target_ns(pid, false);
		return -1;
	}
	ebpf_info(JAVA_LOG_TAG "[PID %d] copy agent so library success.\n",
		  pid);

	/*
	 * In containers, different libc implementations may be used to compile agent
	 * libraries, primarily two types: glibc and musl. We must provide both vers-
	 * ions of the agent library. So, which one should we choose? To determine t-
	 * his, we need to enter the target process's namespace and test each library
	 * until we find one that can be successfully loaded using dlopen.
	 */
	select_suitable_agent_lib(pid, false);

	if (strlen(agent_lib_so_path) == 0) {
		ebpf_warning(JAVA_LOG_TAG
			     "[PID %d] agent_lib_so_path is NULL.\n", pid);
		check_and_clear_target_ns(pid, false);
		return -1;
	}

	return 0;
}

static int attach(pid_t pid, char *opts)
{
	char *argv[] = { "load", agent_lib_so_path, "true", opts };
	int argc = sizeof(argv) / sizeof(argv[0]);
	int ret = jattach(pid, argc, (char **)argv, 1);
	ebpf_info(JAVA_LOG_TAG
		  "jattach pid %d argv: \"load %s true\" return %d\n", pid,
		  agent_lib_so_path, ret);

	return ret;
}

int java_attach(pid_t pid)
{
	int ret = -1;
	bool is_same_mnt = is_same_mntns(pid);
	if (is_same_mnt) {
		ret = prepare_for_attach_same_ns(pid);
	} else {
		/*
		 * Clean up the '*.so' files to prevent exceptions in
		 * the target JVM when using jattach.
		 */
		clear_so_target_ns(pid, false);
		ret = prepare_for_attach_different_ns(pid);
	}

	if (ret < 0)
		return -1;

	char buffer[PERF_PATH_SZ * 2];
	snprintf(buffer, sizeof(buffer),
		 JVM_AGENT_SYMS_SOCKET_PATH_FMT ","
		 JVM_AGENT_LOG_SOCKET_PATH_FMT, pid, pid);

	/* Invoke the jattach (https://github.com/apangin/jattach) to inject the
	 * library as a JVMTI agent.*/
	return attach(pid, buffer);

	/* Resource cleanup is performed in the thread executing 'deepflow-jattach' */
}

/*
 * Command-line execution, for example:
 * cp ./df_java_agent_v2.so /tmp/
 * ./deepflow-jattach $PID
 */
int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
		return -1;
	}

	log_to_stdout = true;
	int pid = atoi(argv[1]);
	return java_attach(pid);
}
#endif /* JAVA_AGENT_ATTACH_TOOL */
