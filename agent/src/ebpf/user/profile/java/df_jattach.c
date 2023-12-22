/*
 * Copyright (c) 2023 Yunshan Networks
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
#include <dlfcn.h>
#include <dirent.h>

#include "../../config.h"
#include "../../common.h"
#include "../../log.h"
#include "config.h"
#include "df_jattach.h"

#define jattach_log(fmt, ...)				\
	do {						\
		fprintf(stdout, fmt, ##__VA_ARGS__);	\
		fflush(stdout);				\
	} while(0)

static char agent_lib_so_path[MAX_PATH_LENGTH];
extern int jattach(int pid, int argc, char **argv);

static int agent_so_lib_copy(const char *src, const char *dst, int uid, int gid)
{
	if (access(src, F_OK)) {
		jattach_log("Fun %s src file '%s' not exist.\n", __func__, src);
		return ETR_NOTEXIST;
	}

	if (copy_file(src, dst)) {
		return ETR_INVAL;
	}

	if (chown(dst, uid, gid) != 0) {
		jattach_log
		    ("Failed to change ownership and group. file '%s'\n", dst);
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
			jattach_log(JAVA_LOG_TAG "Fun %s cannot mkdir() '%s'\n",
				    __func__, copy_target_path);

			return ETR_NOTEXIST;
		}
	}

	snprintf(copy_target_path + len, sizeof(copy_target_path) - len,
		 "/%s", AGENT_LIB_NAME);

	if ((ret =
	     agent_so_lib_copy(AGENT_LIB_SRC_PATH,
			       copy_target_path, target_uid,
			       target_gid)) != ETR_OK) {
		jattach_log("cp '%s' to '%s' failed.\n", AGENT_LIB_SRC_PATH,
			    copy_target_path);
		return ret;
	}

	snprintf(copy_target_path + len, sizeof(copy_target_path) - len,
		 "/%s", AGENT_MUSL_LIB_NAME);

	if ((ret =
	     agent_so_lib_copy(AGENT_MUSL_LIB_SRC_PATH,
			       copy_target_path, target_uid,
			       target_gid)) != ETR_OK) {
		jattach_log("cp '%s' to '%s' failed.\n",
			    AGENT_MUSL_LIB_SRC_PATH, copy_target_path);
		return ret;
	}

	return ETR_OK;
}

bool test_dl_open(const char *so_lib_file_path)
{
	if (access(so_lib_file_path, F_OK)) {
		jattach_log(JAVA_LOG_TAG "Fun %s file '%s' not exist.\n",
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
		jattach_log(JAVA_LOG_TAG
			    "Fuc '%s' dlopen() path %s failure: %s.", __func__,
			    so_lib_file_path, dlerror());
		return false;
	}

	dlerror();
	agent_test_t test_fn =
	    (uint64_t(*)(void))dlsym(h, "df_java_agent_so_libs_test");

	if (test_fn == NULL) {
		jattach_log(JAVA_LOG_TAG
			    "Func '%s' dlsym() path %s failure: %s.", __func__,
			    so_lib_file_path, dlerror());
		return false;
	}

	const uint64_t expected_test_fn_result =
	    JAVA_AGENT_LIBS_TEST_FUN_RET_VAL;
	const uint64_t observed_test_fn_result = test_fn();

	if (observed_test_fn_result != expected_test_fn_result) {
		jattach_log(JAVA_LOG_TAG
			    "%s test '%s' function returned: %lu, expected %lu.",
			    __func__, so_lib_file_path, observed_test_fn_result,
			    expected_test_fn_result);
		return false;
	}

	jattach_log(JAVA_LOG_TAG "%s: Success for %s.\n", __func__,
		    so_lib_file_path);
	return true;
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
		jattach_log(JAVA_LOG_TAG
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
		jattach_log(JAVA_LOG_TAG
			    "Func %s target PID %d test %s, success.\n",
			    __func__, pid, test_path);
		goto found;
	}

	jattach_log(JAVA_LOG_TAG "%s test agent so libs, failure.", __func__);

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

static int attach(pid_t pid, char *opts)
{
	char *argv[] = { "load", agent_lib_so_path, "true", opts };
	int argc = sizeof(argv) / sizeof(argv[0]);
	printf("argc %d opts %s\n", argc, argv[3]);
	int ret = jattach(pid, argc, (char **)argv);
	jattach_log(JAVA_LOG_TAG
		    "jattach pid %d argv: \"load %s true\" return %d\n", pid,
		    agent_lib_so_path, ret);

	return ret;
}

void clear_target_ns_tmp_file(const char *target_path)
{
	if (access(target_path, F_OK) == 0) {
		if (unlink(target_path) != 0)
			jattach_log(JAVA_LOG_TAG "rm file %s failed\n",
				    target_path);
	}
}

static inline bool __is_same_ns(int target_pid, const char *tag)
{
	struct stat self_st, target_st;
	char path[64];
	snprintf(path, sizeof(path), "/proc/self/ns/%s", tag);
	if (stat(path, &self_st) != 0)
		return false;

	snprintf(path, sizeof(path), "/proc/%d/ns/%s", target_pid, tag);
	if (stat(path, &target_st) != 0)
		return false;

	if (self_st.st_ino == target_st.st_ino) {
		return true;
	}

	return false;
}

static bool __unused is_same_netns(int pid)
{
	return __is_same_ns(pid, "net");
}

bool is_same_mntns(int pid)
{
	return __is_same_ns(pid, "mnt");
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

void clear_target_ns(int pid, int my_pid)
{
	/*
	 * Delete files:
	 *  path/df-perf-<pid>.map
	 *  path/df-perf-<pid>.log
	 *  path/df_java_agent.so
	 *  path/df_java_agent_musl.so
	 */

	if (is_same_mntns(pid))
		return;

	char target_path[MAX_PATH_LENGTH];
	snprintf(target_path, sizeof(target_path),
		 DF_AGENT_MAP_PATH_FMT, pid, my_pid);
	clear_target_ns_tmp_file(target_path);
	snprintf(target_path, sizeof(target_path),
		 DF_AGENT_LOG_PATH_FMT, pid, my_pid);
	clear_target_ns_tmp_file(target_path);

	snprintf(target_path, sizeof(target_path), "/proc/%d/root%s", pid,
		 AGENT_MUSL_LIB_TARGET_PATH);
	clear_target_ns_tmp_file(target_path);
	snprintf(target_path, sizeof(target_path), "/proc/%d/root%s", pid,
		 AGENT_LIB_TARGET_PATH);
	clear_target_ns_tmp_file(target_path);

	snprintf(target_path, sizeof(target_path), TARGET_NS_STORAGE_PATH, pid);
	rmdir(target_path);
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

static inline i64 get_symbol_file_size(int pid, int ns_pid, bool is_target)
{
	char path[PERF_PATH_SZ];
	if (is_target)
		snprintf(path, sizeof(path), DF_AGENT_PATH_FMT ".map",
			 pid, ns_pid);
	else
		snprintf(path, sizeof(path),
			 DF_AGENT_LOCAL_PATH_FMT ".map", pid);

	if (access(path, F_OK)) {
		return -1;
	}

	struct stat st;
	if (stat(path, &st) == 0) {
		return (i64) st.st_size;
	}

	return -1;
}

int target_symbol_file_access(int pid, int ns_pid, bool is_same_mnt)
{
	char path[PERF_PATH_SZ];
	if (!is_same_mnt)
		snprintf(path, sizeof(path), DF_AGENT_PATH_FMT ".map",
			 pid, ns_pid);
	else
		snprintf(path, sizeof(path),
			 DF_AGENT_LOCAL_PATH_FMT ".map", pid);

	return access(path, F_OK);
}

i64 get_target_symbol_file_sz(int pid, int ns_pid)
{
	return get_symbol_file_size(pid, ns_pid, true);
}

i64 get_local_symbol_file_sz(int pid, int ns_pid)
{
	return get_symbol_file_size(pid, ns_pid, false);
}

int copy_file_from_target_ns(int pid, int ns_pid, const char *file_type)
{
	char target_path[PERF_PATH_SZ];
	char src_path[PERF_PATH_SZ];
	snprintf(src_path, sizeof(src_path), DF_AGENT_PATH_FMT ".%s",
		 pid, ns_pid, file_type);
	snprintf(target_path, sizeof(target_path),
		 DF_AGENT_LOCAL_PATH_FMT ".%s", pid, file_type);

	if (access(src_path, F_OK)) {
		return -1;
	}

	if (access(target_path, F_OK) == 0) {
		if (unlink(target_path) != 0) {
			return -1;
		}
	}

	if (copy_file(src_path, target_path)) {
		jattach_log("Copy '%s' to '%s' failed.\n", src_path,
			    target_path);
	}

	return 0;
}

// parse comma separated arguments
int parse_config(char *opts, options_t *parsed)
{
	char line[PERF_PATH_SZ * 2];
	strncpy(line, opts, PERF_PATH_SZ * 2);
	line[PERF_PATH_SZ * 2 - 1] = '\0';

	char *token = strtok(line, ",");
	if (token == NULL) {
		jattach_log("Bad argument line %s\n", opts);
		return -1;
	}
	parsed->perf_map_size_limit = atoi(token);

	token = strtok(NULL, ",");
	if (token == NULL) {
		jattach_log("Bad argument line %s\n", opts);
		return -1;
	}
	strncpy(parsed->perf_map_path, token, PERF_PATH_SZ);
	parsed->perf_map_path[PERF_PATH_SZ - 1] = '\0';

	token = strtok(NULL, ",");
	if (token == NULL) {
		jattach_log("Bad argument line %s\n", opts);
		return -1;
	}
	strncpy(parsed->perf_log_path, token, PERF_PATH_SZ);
	parsed->perf_log_path[PERF_PATH_SZ - 1] = '\0';

	return 0;
}

int java_attach_same_namespace(pid_t pid, options_t *opts)
{
	/*
	 * If the agent is installed directly on the node or host,
	 * be careful to delete the perf-pid.map and
	 * perf-pid.log on them.
	 */
	clear_target_ns_tmp_file(opts->perf_map_path);
	clear_target_ns_tmp_file(opts->perf_log_path);

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

	char buffer[PERF_PATH_SZ * 2];
	snprintf(buffer, PERF_PATH_SZ * 2, "%d,%s,%s",
		     opts->perf_map_size_limit,
		     opts->perf_map_path,
		     opts->perf_log_path);

	/* Invoke the jattach (https://github.com/apangin/jattach) to inject the
	 * library as a JVMTI agent.*/
	return attach(pid, buffer);
}

int create_ipc_socket(const char *path)
{
	int sock = -1;
	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		jattach_log("Create unix socket failed with %d\n", errno);
		return -1;
	}

	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	strncpy(addr.sun_path, path, UNIX_PATH_MAX - 1);
	int len = sizeof(addr.sun_family) + strlen(addr.sun_path);
	if (bind(sock, (struct sockaddr *)&addr, len) < 0) {
		jattach_log("Bind unix socket failed with %d\n", errno);
		return -1;
	}
	if (listen(sock, 1) < 0) {
		jattach_log("Listen on unix socket failed with %d\n", errno);
		unlink(path);
		return -1;
	}

	return sock;
}

static void *ipc_receiver_thread(void *arguments)
{
	receiver_args_t *args = (receiver_args_t *)arguments;

	FILE *map_fp = fopen(args->opts->perf_map_path, "w");
	if (!map_fp) {
		// byte stream in socket needs to be consumed to avoid client stuck
		// even if file open fails
		jattach_log("fopen() %s failed with %d\n", args->opts->perf_map_path, errno);
	}
	FILE *log_fp = fopen(args->opts->perf_log_path, "w");
	if (!log_fp) {
		// byte stream in socket needs to be consumed to avoid client stuck
		// even if file open fails
		jattach_log("fopen() %s failed with %d\n", args->opts->perf_log_path, errno);
	}

	int map_sock = args->map_socket;
	int log_sock = args->log_socket;
	int map_client = -1;
	int log_client = -1;
	bool map_done = false, log_done = false;

	int max_fd = map_sock > log_sock ? map_sock : log_sock;
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(map_sock, &fds);
	FD_SET(log_sock, &fds);

	struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };

	char rcv_buf[BUFSIZE];

	while (!*args->done && !(map_done && log_done)) {
		struct timeval tv = timeout;
		fd_set read_fds = fds;
		if (map_client >= 0) {
			FD_SET(map_client, &read_fds);
		}
		if (log_client >= 0) {
			FD_SET(log_client, &read_fds);
		}

		int ret = select(max_fd + 1, &read_fds, 0, 0, &tv);
		if (ret == -1) {
			jattach_log("select() failed with %d\n", errno);
			continue;
		}

		if (FD_ISSET(map_sock, &read_fds)) {
			if (map_client >= 0) {
				jattach_log("map socket already accepted\n");
			} else if ((map_client = accept(map_sock, NULL, NULL)) < 0) {
				jattach_log("accept() failed with %d\n", errno);
			} else {
				max_fd = map_client > max_fd ? map_client : max_fd;
			}
		}

		if (FD_ISSET(log_sock, &read_fds)) {
			if (log_client >= 0) {
				jattach_log("log socket already accepted\n");
			} else if ((log_client = accept(log_sock, NULL, NULL)) < 0) {
				jattach_log("accept() failed with %d\n", errno);
			} else {
				max_fd = log_client > max_fd ? log_client : max_fd;
			}
		}

		if (FD_ISSET(map_client, &read_fds)) {
			int n = recv(map_client, rcv_buf, sizeof(rcv_buf), 0);
			if (n > 0) {
				if (map_fp) {
					fwrite(rcv_buf, sizeof(char), n, map_fp);
				}
			} else if (n == 0 || (n < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) {
				if (n < 0) {
					jattach_log("recv() failed with %d\n", errno);
				}
				close(map_client);
				map_client = -1;
				map_done = true;
			}
		}

		if (FD_ISSET(log_client, &read_fds)) {
			int n = recv(log_client, rcv_buf, sizeof(rcv_buf), 0);
			if (n > 0) {
				if (log_fp) {
					fwrite(rcv_buf, sizeof(char), n, log_fp);
				}
			} else if (n == 0 || (n < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) {
				if (n < 0) {
					jattach_log("recv() failed with %d\n", errno);
				}
				close(log_client);
				log_client = -1;
				log_done = true;
			}
		}
	}

	if (map_fp) {
		fclose(map_fp);
		map_fp = NULL;
	}
	if (log_fp) {
		fclose(log_fp);
		log_fp = NULL;
	}

	return NULL;
}

int java_attach_different_namespace(pid_t pid, options_t *opts)
{
	int ret = -1;
	int uid, gid;
	int map_socket = -1, log_socket = -1;

	if (get_target_uid_and_gid(pid, &uid, &gid)) {
		return -1;
	}

	/* if pid == target_ns_pid, run in same namespace */
	int target_ns_pid = get_nspid(pid);
	if (target_ns_pid < 0) {
		return -1;
	}

	int my_pid = getpid();

	/*
	 * Delete the files on the target file system if they
	 * are not on the same mount point.
	 */
	clear_target_ns(pid, my_pid);

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
	jattach_log("[PID %d] copy agent os library ...\n", pid);
	if (copy_agent_libs_into_target_ns(pid, uid, gid)) {
		jattach_log("[PID %d] copy agent os library failed.\n",
			    pid);
		goto cleanup;
	}
	jattach_log("[PID %d] copy agent os library success.\n", pid);

	/*
	 * In containers, different libc implementations may be used to compile agent
	 * libraries, primarily two types: glibc and musl. We must provide both vers-
	 * ions of the agent library. So, which one should we choose? To determine t-
	 * his, we need to enter the target process's namespace and test each library
	 * until we find one that can be successfully loaded using dlopen.
	 */
	select_suitable_agent_lib(pid, false);

	if (strlen(agent_lib_so_path) == 0)
		goto cleanup;

	/* Invoke the jattach (https://github.com/apangin/jattach) to inject the
	 * library as a JVMTI agent.*/

	// make the sockets accessable from unprivileged user in container
	umask(0);

	char buffer[PERF_PATH_SZ * 2];
	snprintf(buffer, PERF_PATH_SZ, DF_AGENT_MAP_PATH_FMT, pid, my_pid);
	if ((map_socket = create_ipc_socket(buffer)) < 0) {
		goto cleanup;
	}
	snprintf(buffer, PERF_PATH_SZ, DF_AGENT_LOG_PATH_FMT, pid, my_pid);
	if ((log_socket = create_ipc_socket(buffer)) < 0) {
		goto cleanup;
	}

	pthread_t ipc_receiver;
	bool done = false;
	receiver_args_t args = {
		.opts = opts,
		.map_socket = map_socket,
		.log_socket = log_socket,
		.done = &done,
	};
	if ((ret = pthread_create(&ipc_receiver, NULL, &ipc_receiver_thread, &args)) < 0) {
		jattach_log("Create ipc receiver thread failed with errno(%d)\n", errno);
		goto cleanup;
	}

	snprintf(buffer, PERF_PATH_SZ * 2,
	         "%d," PERF_MAP_FILE_FMT "," PERF_MAP_LOG_FILE_FMT,
		     opts->perf_map_size_limit, my_pid, my_pid);
	ret = attach(pid, buffer);

	done = true;
	pthread_join(ipc_receiver, NULL);

cleanup:
	if (map_socket >= 0) {
		close(map_socket);
	}
	if (log_socket >= 0) {
		close(log_socket);
	}
	// attach() may change euid/egid, restore them to remove tmp files
	if (seteuid(getuid()) < 0) {
		jattach_log("seteuid() failed with errno(%d)\n", errno);
	}
	if (setegid(getgid()) < 0) {
		jattach_log("seteuid() failed with errno(%d)\n", errno);
	}
	clear_target_ns(pid, my_pid);
	return ret;
}

int java_attach(pid_t pid, char *opts)
{
	options_t parsed_opts;
	if (parse_config(opts, &parsed_opts) != 0) {
		return -1;
	}

	if (is_same_mntns(pid)) {
		return java_attach_same_namespace(pid, &parsed_opts);
	} else {
		return java_attach_different_namespace(pid, &parsed_opts);
	}
}

#ifdef JAVA_AGENT_ATTACH_TOOL
int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "Usage: %s <pid> <opts>\n", argv[0]);
		return -1;
	}

	log_to_stdout = true;
	int pid = atoi(argv[1]);
	return java_attach(pid, argv[2]);
}
#endif /* JAVA_AGENT_ATTACH_TOOL */
