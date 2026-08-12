/*
 * 工具功能：在独立 helper 子进程中进入目标 Java 的 namespace，并安全获取 Java 版本。
 *
 * 使用方式：
 *     java_mnt_ns_version <java-pid>
 *
 * 执行流程：
 * 1. 读取 /proc/<pid>/exe，得到目标 Java 的绝对路径。
 * 2. 读取 /proc/<pid>/environ 中 NUL 分隔的运行环境，并补充 libjli.so 搜索路径。
 * 3. 主进程创建 helper，但主进程自身不调用 setns，不改变自己的 namespace。
 * 4. helper 进入目标 PID/mount namespace，再创建 runner。
 * 5. runner 使用 execve() 直接执行目标 Java 绝对路径的 -version。
 * 6. 主进程非阻塞读取版本输出，5 秒超时后杀掉 helper 进程组。
 * 7. helper 完成后立即退出，主进程验证自身及后续子进程仍处于原 namespace。
 *
 * 注意事项：
 * - 本工具只启动一个独立的 Java -version 子进程，不对正在运行的目标 JVM attach。
 * - PID namespace 的 setns 只影响 helper 后续创建的 runner，不改变 helper 自身的 PID。
 * - helper 退出后不需要调用 setns 恢复；主进程从未进入目标 namespace。
 * - /proc/<pid>/environ 使用 NUL 分隔环境变量，不能按普通文本行解析。
 * - 使用本工具需要读取目标进程 proc 文件并调用 setns 的权限，通常需要 root 或相应能力。
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define JAVA_VERSION_TIMEOUT_MS 5000
#define JAVA_VERSION_OUTPUT_SIZE 16384

/* 保存 namespace 文件的设备号和 inode，用于进入前后比较。 */
struct namespace_identity {
	dev_t device;
	ino_t inode;
};

/* 读取一个 namespace 文件的身份信息。 */
static int read_namespace_identity(const char *path,
					   struct namespace_identity *identity)
{
	struct stat status;

	if (path == NULL || identity == NULL)
		return -1;
	if (stat(path, &status) < 0) {
		fprintf(stderr, "stat %s 失败：%s\n", path, strerror(errno));
		return -1;
	}
	identity->device = status.st_dev;
	identity->inode = status.st_ino;
	return 0;
}

/* 比较两个 namespace 身份是否相同。 */
static bool namespace_identity_equal(
	const struct namespace_identity *left,
	const struct namespace_identity *right)
{
	return left != NULL && right != NULL && left->device == right->device &&
	       left->inode == right->inode;
}

/* 读取目标 Java 的绝对可执行文件路径。 */
static int read_java_exe_path(pid_t pid, char *path, size_t path_size)
{
	char proc_path[64];
	ssize_t length;
	char *deleted;

	if (path == NULL || path_size < 2)
		return -1;
	if (snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid) >=
	    (int)sizeof(proc_path))
		return -1;
	length = readlink(proc_path, path, path_size - 1);
	if (length < 0) {
		fprintf(stderr, "读取 %s 失败：%s\n", proc_path, strerror(errno));
		return -1;
	}
	path[length] = '\0';
	deleted = strstr(path, " (deleted)");
	if (deleted != NULL)
		*deleted = '\0';
	if (path[0] != '/') {
		fprintf(stderr, "目标 exe 路径不是绝对路径：%s\n", path);
		return -1;
	}
	return 0;
}

/* 从目标进程 NUL 分隔的 environ 中读取一个变量。 */
static int read_target_env_value(pid_t pid, const char *name, char *value,
					 size_t value_size)
{
	char proc_path[64];
	char *entry = NULL;
	size_t entry_size = 0;
	size_t name_len;
	ssize_t entry_len;
	FILE *file;
	int found = 0;

	if (name == NULL || value == NULL || value_size == 0)
		return -1;
	if (snprintf(proc_path, sizeof(proc_path), "/proc/%d/environ", pid) >=
	    (int)sizeof(proc_path))
		return -1;
	file = fopen(proc_path, "rb");
	if (file == NULL) {
		fprintf(stderr, "打开 %s 失败：%s\n", proc_path, strerror(errno));
		return -1;
	}

	name_len = strlen(name);
	while ((entry_len = getdelim(&entry, &entry_size, '\0', file)) >= 0) {
		if ((size_t)entry_len <= name_len ||
		    strncmp(entry, name, name_len) != 0 || entry[name_len] != '=')
			continue;
		entry_len--;
		if ((size_t)entry_len <= name_len + 1)
			break;
		if ((size_t)entry_len - name_len - 1 >= value_size) {
			fprintf(stderr, "环境变量 %s 超出缓冲区\n", name);
			break;
		}
		memcpy(value, entry + name_len + 1,
		       (size_t)entry_len - name_len - 1);
		value[(size_t)entry_len - name_len - 1] = '\0';
		found = 1;
		break;
	}
	if (ferror(file))
		found = -1;
	free(entry);
	fclose(file);
	return found;
}

/* 根据目标 Java 的 bin/java 路径构造 libjli.so 目录。 */
static int build_java_jli_path(const char *exe_path, char *path,
				       size_t path_size)
{
	char runtime_root[PATH_MAX];
	char *slash;
	int length;

	if (exe_path == NULL || path == NULL || path_size == 0)
		return -1;
	if (strlen(exe_path) >= sizeof(runtime_root))
		return -1;
	strcpy(runtime_root, exe_path);
	slash = strrchr(runtime_root, '/');
	if (slash == NULL || strcmp(slash + 1, "java") != 0)
		return -1;
	*slash = '\0';
	slash = strrchr(runtime_root, '/');
	if (slash == NULL || strcmp(slash + 1, "bin") != 0)
		return -1;
	*slash = '\0';
	length = snprintf(path, path_size, "%s/lib/amd64/jli", runtime_root);
	if (length < 0 || (size_t)length >= path_size)
		return -1;
	return 0;
}

/* 读取目标环境并构造 execve() 使用的显式环境白名单。 */
static int build_target_environment(pid_t pid, const char *exe_path,
					 char *envp[], int envp_size,
					 char *library_env, size_t library_env_size,
					 char *java_home_env, size_t java_home_env_size,
					 char *path_env, size_t path_env_size,
					 char *home_env, size_t home_env_size,
					 char *lang_env, size_t lang_env_size)
{
	char library_path[PATH_MAX * 2] = {};
	char java_home[PATH_MAX] = {};
	char target_path[PATH_MAX * 2] = {};
	char home[PATH_MAX] = {};
	char lang[PATH_MAX] = {};
	char jli_path[PATH_MAX];
	int value_ret;
	int count = 0;

	if (envp == NULL || envp_size < 2 || library_env == NULL ||
	    java_home_env == NULL || path_env == NULL || home_env == NULL ||
	    lang_env == NULL)
		return -1;
	value_ret = read_target_env_value(pid, "LD_LIBRARY_PATH", library_path,
						  sizeof(library_path));
	if (value_ret < 0)
		return -1;
	value_ret = read_target_env_value(pid, "JAVA_HOME", java_home,
						  sizeof(java_home));
	if (value_ret < 0)
		return -1;
	value_ret = read_target_env_value(pid, "PATH", target_path,
						  sizeof(target_path));
	if (value_ret < 0)
		return -1;
	value_ret = read_target_env_value(pid, "HOME", home, sizeof(home));
	if (value_ret < 0)
		return -1;
	value_ret = read_target_env_value(pid, "LANG", lang, sizeof(lang));
	if (value_ret < 0)
		return -1;
	if (build_java_jli_path(exe_path, jli_path, sizeof(jli_path)) < 0)
		return -1;
	if (library_path[0] == '\0') {
		if (snprintf(library_path, sizeof(library_path), "%s", jli_path) >=
		    (int)sizeof(library_path))
			return -1;
	} else {
		char original_library[sizeof(library_path)];
		strcpy(original_library, library_path);
		if (snprintf(library_path, sizeof(library_path), "%s:%s", jli_path,
			     original_library) >= (int)sizeof(library_path))
			return -1;
	}
	if (target_path[0] == '\0')
		strcpy(target_path, "/usr/bin:/bin");
	if (home[0] == '\0')
		strcpy(home, "/tmp");
	if (snprintf(library_env, library_env_size, "LD_LIBRARY_PATH=%s",
		     library_path) >= (int)library_env_size ||
	    snprintf(java_home_env, java_home_env_size, "JAVA_HOME=%s", java_home) >=
		    (int)java_home_env_size ||
	    snprintf(path_env, path_env_size, "PATH=%s", target_path) >=
		    (int)path_env_size ||
	    snprintf(home_env, home_env_size, "HOME=%s", home) >=
		    (int)home_env_size ||
	    snprintf(lang_env, lang_env_size, "LANG=%s", lang) >=
		    (int)lang_env_size)
		return -1;
	envp[count++] = library_env;
	if (java_home[0] != '\0')
		envp[count++] = java_home_env;
	envp[count++] = path_env;
	envp[count++] = home_env;
	if (lang[0] != '\0')
		envp[count++] = lang_env;
	if (count + 1 > envp_size)
		return -1;
	envp[count] = NULL;
	return 0;
}

/* 打开目标 namespace；如果已经相同，则通过 same_namespace 返回 true。 */
static int open_target_namespace(pid_t pid, const char *type,
					 bool *same_namespace)
{
	char target_path[64];
	char self_path[64];
	struct stat target_stat;
	struct stat self_stat;
	int fd;

	if (type == NULL || same_namespace == NULL)
		return -1;
	*same_namespace = false;
	if (snprintf(target_path, sizeof(target_path), "/proc/%d/ns/%s", pid,
		     type) >= (int)sizeof(target_path) ||
	    snprintf(self_path, sizeof(self_path), "/proc/self/ns/%s", type) >=
		    (int)sizeof(self_path))
		return -1;
	if (stat(target_path, &target_stat) < 0 ||
	    stat(self_path, &self_stat) < 0)
		return -1;
	if (target_stat.st_dev == self_stat.st_dev &&
	    target_stat.st_ino == self_stat.st_ino) {
		*same_namespace = true;
		return -1;
	}
	fd = open(target_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	return fd;
}

/* 返回单调时钟毫秒值，用于父进程超时控制。 */
static int64_t monotonic_milliseconds(void)
{
	struct timespec timespec_value;

	if (clock_gettime(CLOCK_MONOTONIC, &timespec_value) < 0)
		return -1;
	return (int64_t)timespec_value.tv_sec * 1000 +
	       timespec_value.tv_nsec / 1000000;
}

/* runner 直接执行目标 Java 的绝对路径，不经过 shell 或 PATH 查找。 */
static void run_java_version(const char *exe_path, char *const envp[],
				     int output_fd)
{
	char *const argv[] = { (char *)exe_path, (char *)"-version", NULL };

	if (dup2(output_fd, STDOUT_FILENO) < 0 ||
	    dup2(output_fd, STDERR_FILENO) < 0)
		_exit(125);
	if (output_fd != STDOUT_FILENO && output_fd != STDERR_FILENO)
		close(output_fd);
	execve(exe_path, argv, envp);
	_exit(127);
}

/* helper 进入目标 namespace，创建 runner，并等待 runner 结束。 */
static void run_version_helper(const char *exe_path, char *const envp[],
				       int pid_ns_fd, int mnt_ns_fd, int output_fd)
{
	pid_t runner_pid;
	int status;

	if (setpgid(0, 0) < 0)
		_exit(124);
#ifdef __NR_setns
	if (pid_ns_fd >= 0 && syscall(__NR_setns, pid_ns_fd, CLONE_NEWPID) < 0)
		_exit(124);
	if (mnt_ns_fd >= 0 && syscall(__NR_setns, mnt_ns_fd, CLONE_NEWNS) < 0)
		_exit(124);
#else
	(void)pid_ns_fd;
	(void)mnt_ns_fd;
	_exit(124);
#endif
	if (pid_ns_fd >= 0)
		close(pid_ns_fd);
	if (mnt_ns_fd >= 0)
		close(mnt_ns_fd);
	runner_pid = fork();
	if (runner_pid < 0)
		_exit(124);
	if (runner_pid == 0)
		run_java_version(exe_path, envp, output_fd);
	close(output_fd);
	while (waitpid(runner_pid, &status, 0) < 0) {
		if (errno != EINTR)
			_exit(124);
	}
	if (WIFEXITED(status))
		_exit(WEXITSTATUS(status));
	_exit(128 + WTERMSIG(status));
}

/* 非阻塞读取版本输出；超过缓冲区的尾部输出直接丢弃。 */
static void drain_version_output(int output_fd, char *output,
					 size_t output_size, size_t *used, bool *eof)
{
	char discard[1024];
	char *buffer;
	size_t remain;
	ssize_t length;

	while (!*eof) {
		buffer = *used < output_size - 1 ? output + *used : discard;
		remain = *used < output_size - 1 ? output_size - 1 - *used :
				 sizeof(discard);
		length = read(output_fd, buffer, remain);
		if (length > 0) {
			if (buffer != discard)
				*used += (size_t)length;
			continue;
		}
		if (length == 0) {
			*eof = true;
			break;
		}
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			break;
		*eof = true;
	}
	output[*used < output_size ? *used : output_size - 1] = '\0';
}

/* 终止并回收 helper 及其进程组中的 runner。 */
static void kill_version_helper(pid_t helper_pid, int *status)
{
	if (kill(-helper_pid, SIGKILL) < 0)
		kill(helper_pid, SIGKILL);
	while (waitpid(helper_pid, status, 0) < 0 && errno == EINTR)
		;
}

/* 在 5 秒上限内收集 helper 输出并等待 helper 退出。 */
static int wait_version_helper(pid_t helper_pid, int output_fd,
				       char *output, size_t output_size)
{
	struct pollfd poll_fd = { .fd = output_fd, .events = POLLIN };
	int flags;
	int status;
	int poll_timeout;
	int64_t deadline;
	int64_t now;
	pid_t wait_result;
	size_t used = 0;
	bool eof = false;
	bool exited = false;

	flags = fcntl(output_fd, F_GETFL, 0);
	if (flags < 0 || fcntl(output_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		kill_version_helper(helper_pid, &status);
		return -1;
	}
	deadline = monotonic_milliseconds();
	if (deadline < 0) {
		kill_version_helper(helper_pid, &status);
		return -1;
	}
	deadline += JAVA_VERSION_TIMEOUT_MS;
	while (!exited || !eof) {
		drain_version_output(output_fd, output, output_size, &used, &eof);
		if (!exited) {
			wait_result = waitpid(helper_pid, &status, WNOHANG);
			if (wait_result == helper_pid)
				exited = true;
			else if (wait_result < 0 && errno != EINTR) {
				kill_version_helper(helper_pid, &status);
				close(output_fd);
				return -1;
			}
		}
		if (exited && eof)
			break;
		now = monotonic_milliseconds();
		if (now < 0 || now >= deadline) {
			kill_version_helper(helper_pid, &status);
			close(output_fd);
			return -1;
		}
		poll_timeout = (int)(deadline - now);
		if (poll_timeout > 100)
			poll_timeout = 100;
		if (poll(&poll_fd, 1, poll_timeout) < 0 && errno != EINTR) {
			kill_version_helper(helper_pid, &status);
			close(output_fd);
			return -1;
		}
	}
	close(output_fd);
	if (!exited || !WIFEXITED(status))
		return -1;
	return WEXITSTATUS(status);
}

/* 验证主进程和后续子进程仍处于进入 helper 前的 namespace。 */
static int verify_parent_namespace(
	const struct namespace_identity *original_pid,
	const struct namespace_identity *original_mount)
{
	struct namespace_identity current_pid;
	struct namespace_identity current_mount;
	struct namespace_identity child_pid;
	struct namespace_identity child_mount;
	pid_t child_process;
	int status;

	if (read_namespace_identity("/proc/self/ns/pid", &current_pid) < 0 ||
	    read_namespace_identity("/proc/self/ns/mnt", &current_mount) < 0 ||
	    !namespace_identity_equal(&current_pid, original_pid) ||
	    !namespace_identity_equal(&current_mount, original_mount)) {
		fprintf(stderr, "验证失败：主进程 namespace 发生变化\n");
		return -1;
	}
	printf("验证成功：主进程仍处于原 PID/mount namespace\n");
	child_process = fork();
	if (child_process < 0)
		return -1;
	if (child_process == 0) {
		if (read_namespace_identity("/proc/self/ns/pid", &child_pid) < 0 ||
		    read_namespace_identity("/proc/self/ns/mnt", &child_mount) < 0)
			_exit(2);
		_exit(namespace_identity_equal(&child_pid, original_pid) &&
		       namespace_identity_equal(&child_mount, original_mount) ? 0 : 1);
	}
	while (waitpid(child_process, &status, 0) < 0) {
		if (errno != EINTR)
			return -1;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "验证失败：后续子进程 namespace 发生变化\n");
		return -1;
	}
	printf("验证成功：后续子进程回到原 PID/mount namespace\n");
	return 0;
}

/* 程序入口：读取目标信息，启动 helper，收集版本并验证主进程 namespace。 */
int main(int argc, char **argv)
{
	char exe_path[PATH_MAX];
	char library_env[PATH_MAX * 2 + 32];
	char java_home_env[PATH_MAX + 16];
	char path_env[PATH_MAX * 2 + 8];
	char home_env[PATH_MAX + 8];
	char lang_env[PATH_MAX + 8];
	char *envp[6] = {};
	char output[JAVA_VERSION_OUTPUT_SIZE] = {};
	char *end;
	long pid_value;
	pid_t pid;
	pid_t helper_pid;
	int pid_ns_fd = -1;
	int mnt_ns_fd = -1;
	int pipe_fds[2] = { -1, -1 };
	int command_status = -1;
	int flags;
	bool same_pid_ns = false;
	bool same_mnt_ns = false;
	struct namespace_identity original_pid;
	struct namespace_identity original_mount;

	if (argc != 2) {
		fprintf(stderr, "用法：%s <java-pid>\n", argv[0]);
		return EXIT_FAILURE;
	}
	errno = 0;
	pid_value = strtol(argv[1], &end, 10);
	if (errno != 0 || *argv[1] == '\0' || *end != '\0' || pid_value <= 0 ||
	    pid_value > INT_MAX) {
		fprintf(stderr, "无效 PID：%s\n", argv[1]);
		return EXIT_FAILURE;
	}
	pid = (pid_t)pid_value;
	if (read_namespace_identity("/proc/self/ns/pid", &original_pid) < 0 ||
	    read_namespace_identity("/proc/self/ns/mnt", &original_mount) < 0 ||
	    read_java_exe_path(pid, exe_path, sizeof(exe_path)) < 0)
		return EXIT_FAILURE;
	printf("目标 Java 绝对路径：%s\n", exe_path);
	if (build_target_environment(pid, exe_path, envp, 6, library_env,
					     sizeof(library_env), java_home_env,
					     sizeof(java_home_env), path_env, sizeof(path_env),
					     home_env, sizeof(home_env), lang_env,
					     sizeof(lang_env)) < 0)
		return EXIT_FAILURE;

	pid_ns_fd = open_target_namespace(pid, "pid", &same_pid_ns);
	if (pid_ns_fd < 0 && !same_pid_ns)
		return EXIT_FAILURE;
	mnt_ns_fd = open_target_namespace(pid, "mnt", &same_mnt_ns);
	if (mnt_ns_fd < 0 && !same_mnt_ns)
		goto cleanup;
	printf("版本 helper namespace：PID=%s MNT=%s\n",
	       same_pid_ns ? "same" : "target",
	       same_mnt_ns ? "same" : "target");
	if (pipe(pipe_fds) < 0)
		goto cleanup;
	flags = fcntl(pipe_fds[0], F_GETFL, 0);
	if (flags < 0 || fcntl(pipe_fds[0], F_SETFL, flags | O_NONBLOCK) < 0)
		goto cleanup;
	helper_pid = fork();
	if (helper_pid < 0)
		goto cleanup;
	if (helper_pid == 0) {
		close(pipe_fds[0]);
		run_version_helper(exe_path, envp, pid_ns_fd, mnt_ns_fd,
				   pipe_fds[1]);
		_exit(124);
	}
	close(pipe_fds[1]);
	pipe_fds[1] = -1;
	setpgid(helper_pid, helper_pid);
	command_status = wait_version_helper(helper_pid, pipe_fds[0], output,
					     sizeof(output));
	pipe_fds[0] = -1;
	if (command_status != 0) {
		fprintf(stderr, "Java -version 执行失败或超过 %d 秒\n",
			JAVA_VERSION_TIMEOUT_MS / 1000);
		command_status = -1;
		goto cleanup;
	}
	printf("Java -version 输出：\n%s", output);
	if (verify_parent_namespace(&original_pid, &original_mount) < 0) {
		command_status = -1;
		goto cleanup;
	}
	printf("验证成功：helper 退出后主进程未进入目标 namespace\n");

cleanup:
	if (pipe_fds[0] >= 0)
		close(pipe_fds[0]);
	if (pipe_fds[1] >= 0)
		close(pipe_fds[1]);
	if (pid_ns_fd >= 0)
		close(pid_ns_fd);
	if (mnt_ns_fd >= 0)
		close(mnt_ns_fd);
	return command_status < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
