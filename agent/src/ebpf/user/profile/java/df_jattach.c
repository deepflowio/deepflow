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

#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
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

static void select_sitable_agent_lib(pid_t pid, bool is_same_mntns)
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

static bool __unused is_same_netns(int target_pid)
{
	return __is_same_ns(target_pid, "net");
}

bool is_same_mntns(int target_pid)
{
	return __is_same_ns(target_pid, "mnt");
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

static void __unused clear_old_target_perf_files(int pid)
{
	/* if pid == target_ns_pid, run in same namespace */
	int target_ns_pid = get_nspid(pid);
	if (target_ns_pid < 0) {
		return;
	}

	char path[MAX_PATH_LENGTH];
	snprintf(path, sizeof(path),
		 "/proc/%d/root/tmp/perf-%d.map", pid, target_ns_pid);
	clear_target_ns_tmp_file(path);

	snprintf(path, sizeof(path),
		 "/proc/%d/root/tmp/perf-%d.log", pid, target_ns_pid);
	clear_target_ns_tmp_file(path);

	snprintf(path, sizeof(path),
		 "/proc/%d/root/deepflow/perf-%d.map", pid, target_ns_pid);
	clear_target_ns_tmp_file(path);

	snprintf(path, sizeof(path),
		 "/proc/%d/root/deepflow/perf-%d.log", pid, target_ns_pid);
	clear_target_ns_tmp_file(path);
}

void clear_target_ns(int pid, int target_ns_pid)
{
	/*
	 * Delete files:
	 *  path/df_perf-<pid>.map
	 *  path/df_perf-<pid>.log
	 *  path/df_java_agent.so
	 *  path/df_java_agent_musl.so
	 */

	if (is_same_mntns(pid))
		return;

	char target_path[MAX_PATH_LENGTH];
	snprintf(target_path, sizeof(target_path),
		 DF_AGENT_MAP_PATH_FMT, pid, target_ns_pid);
	clear_target_ns_tmp_file(target_path);
	snprintf(target_path, sizeof(target_path),
		 DF_AGENT_LOG_PATH_FMT, pid, target_ns_pid);
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

void clear_target_ns_so(int pid, int target_ns_pid)
{
	/*
	 * Delete files: df_java_agent.so and df_java_agent_musl.so
	 */

	if (is_same_mntns(pid))
		return;

	char target_path[MAX_PATH_LENGTH];
	snprintf(target_path, sizeof(target_path), "/proc/%d/root%s", pid,
		 AGENT_MUSL_LIB_TARGET_PATH);
	clear_target_ns_tmp_file(target_path);
	snprintf(target_path, sizeof(target_path), "/proc/%d/root%s", pid,
		 AGENT_LIB_TARGET_PATH);
	clear_target_ns_tmp_file(target_path);
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

int java_attach(pid_t pid, char *opts)
{
#ifdef NS_FILES_COPY_TEST
	int net_fd, ipc_fd, mnt_fd;
	net_fd = ipc_fd = mnt_fd = -1;
#endif
	int ret;
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
	 * If the agent is installed directly on the node or host,
	 * be careful to delete the perf-pid.map and
	 * perf-pid.log on them.
	 */
	bool is_same_mnt = is_same_mntns(pid);
	if (is_same_mnt) {
		char path[PERF_PATH_SZ];
		snprintf(path, sizeof(path), DF_AGENT_LOCAL_PATH_FMT ".map",
			 pid);
		clear_target_ns_tmp_file(path);
		snprintf(path, sizeof(path), DF_AGENT_LOCAL_PATH_FMT ".log",
			 pid);
		clear_target_ns_tmp_file(path);
	} else {
		/*
		 * Delete the files on the target file system if they
		 * are not on the same mount point.
		 */
		clear_target_ns(pid, target_ns_pid);
	}

	/*
	 * Here, the original method of determination (based on whether the net
	 * namespace is the same) is modified to use the mnt namespace for comparison,
	 * thus avoiding situations where both the net namespace and pid namespace are
	 * the same but the file system is different.
	 */
	if (!is_same_mnt) {
		/*
		 * If the target Java process is in a subordinate namespace, copy the
		 * 'agent.so' into the artifacts path (in /tmp) inside of that namespace
		 * (for visibility to the target process).
		 */
		jattach_log("[PID %d] copy agent os library ...\n", pid);
		if (copy_agent_libs_into_target_ns(pid, uid, gid)) {
			jattach_log("[PID %d] copy agent os library failed.\n",
				    pid);
			goto failed;
		}
		jattach_log("[PID %d] copy agent os library success.\n", pid);
	}

	/*
	 * In containers, different libc implementations may be used to compile agent
	 * libraries, primarily two types: glibc and musl. We must provide both vers-
	 * ions of the agent library. So, which one should we choose? To determine t-
	 * his, we need to enter the target process's namespace and test each library
	 * until we find one that can be successfully loaded using dlopen.
	 */
	select_sitable_agent_lib(pid, is_same_mnt);

	if (strlen(agent_lib_so_path) == 0)
		goto failed;

	/* Invoke the jattach (https://github.com/apangin/jattach) to inject the
	 * library as a JVMTI agent.*/

#ifdef NS_FILES_COPY_TEST
	/* The jattach() function will switch the namespace to the target PID.
	 * After we have called jattach(), we need to return to the root namespace.*/

	get_nsfd_and_stat("net", NULL, &net_fd);
	get_nsfd_and_stat("ipc", NULL, &ipc_fd);
	get_nsfd_and_stat("mnt", NULL, &mnt_fd);
	if (net_fd < 0 || ipc_fd < 0 || mnt_fd < 0)
		goto failed;
#endif

	ret = attach(pid, opts);

#ifdef NS_FILES_COPY_TEST
	/*
	 * Copy target namespace 'perf-<target_ns_pid>.map' to host root namespace
	 * '/tmp/perf-<target_ns_pid>.map'
	 */
	if (target_ns_pid != pid) {
		switch_to_root_ns(net_fd);
		switch_to_root_ns(ipc_fd);
		switch_to_root_ns(mnt_fd);
		if (ret == 0) {
			copy_file_from_target_ns(pid, target_ns_pid, "map");
			copy_file_from_target_ns(pid, target_ns_pid, "log");
		}
		clear_target_ns(pid, target_ns_pid);
	} else {
		close(net_fd);
		close(ipc_fd);
		close(mnt_fd);
	}
#endif
	return ret;

failed:
#ifdef NS_FILES_COPY_TEST
	if (net_fd > 0)
		close(net_fd);

	if (ipc_fd > 0)
		close(ipc_fd);

	if (mnt_fd > 0)
		close(mnt_fd);

	/* Current at root namespace */
	if (target_ns_pid != pid)
		clear_target_ns(pid, target_ns_pid);
#endif
	return -1;
}

#ifdef JAVA_AGENT_ATTACH_TOOL
static void clean_old_java_perf_files(void)
{
	struct dirent *entry = NULL;
	DIR *fddir = NULL;

	fddir = opendir("/proc/");
	if (fddir == NULL) {
		jattach_log("Failed to open '/proc/'\n");
		return;
	}

	pid_t pid;
	while ((entry = readdir(fddir)) != NULL) {
		pid = atoi(entry->d_name);
		if (entry->d_type == DT_DIR && pid > 0 && is_process(pid)) {
			char comm[16];
			memset(comm, 0, sizeof(comm));
			get_process_starttime_and_comm(pid, comm, sizeof(comm));
			if (strcmp(comm, "java") == 0) {
				clear_old_target_perf_files(pid);
			}
		}
	}

	closedir(fddir);
}

int main(int argc, char **argv)
{
	if (strcmp(argv[1], "clean") == 0) {
		clean_old_java_perf_files();
		return 0;
	}

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <pid> <opts>\n", argv[0]);
		return -1;
	}

	log_to_stdout = true;
	int pid = atoi(argv[1]);
	return java_attach(pid, argv[2]);
}
#endif /* JAVA_AGENT_ATTACH_TEST */
