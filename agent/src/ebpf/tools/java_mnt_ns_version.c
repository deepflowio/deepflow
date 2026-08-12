/*
 * 工具功能：验证跨 namespace 获取目标 Java 版本的完整流程。
 *
 * 使用方式：
 *     java_mnt_ns_version <java-pid>
 *
 * 执行流程：
 * 1. 通过 /proc/<pid>/exe 读取目标 Java 的绝对路径。
 * 2. 通过 /proc/<pid>/environ 读取目标 Java 的必要运行环境，重点处理
 *    LD_LIBRARY_PATH、JAVA_HOME、PATH、HOME 和 LANG；同时根据 Java 路径
 *    补充 jli 动态库目录，确保启动器可以找到 libjli.so。
 * 3. 保存当前 PID namespace，设置后续子进程使用目标 Java 的 PID namespace。
 *    setns(CLONE_NEWPID) 不会改变当前进程自身的 PID，只影响后续创建的子进程。
 * 4. 保存当前 mount namespace，进入目标 Java 的 mount namespace。
 * 5. 使用 popen() 创建子进程，执行目标 Java 的 -version，并输出版本信息。
 * 6. 等待 Java 子进程结束，恢复当前 mount namespace 和后续子进程的 PID
 *    namespace，避免测试工具影响后续创建的子进程。
 * 7. 再创建验证子进程，确认 mount namespace 已恢复，且后续子进程已经回到
 *    原 PID namespace。
 *
 * 注意事项：
 * - 本工具只执行目标 Java 的 -version，不对目标 Java 执行 attach，也不修改
 *   目标 Java 的运行状态。
 * - /proc/<pid>/environ 使用 NUL 字符分隔环境变量，读取时必须按二进制记录解析。
 * - PID namespace 的恢复针对的是后续子进程的 namespace 选择；当前工具进程
 *   自身始终处于原 PID namespace，因此程序末尾还要验证新建子进程的 namespace。
 * - 使用本工具需要能够读取目标进程的 /proc 信息并调用 setns()，通常需要 root
 *   权限或相应的 CAP_SYS_ADMIN/CAP_SYS_PTRACE 能力。
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* 保存 namespace 文件的设备号和 inode，用于进入前后做身份比对。 */
struct namespace_identity {
	dev_t device;
	ino_t inode;
};

/* 读取指定 namespace 文件的身份信息。 */
static int read_namespace_identity(const char *path,
				   struct namespace_identity *identity)
{
	struct stat status;

	/* 检查参数，避免访问无效指针。 */
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

/* 比较两个 namespace 文件是否指向同一个 namespace。 */
static bool namespace_identity_equal(
	const struct namespace_identity *left,
	const struct namespace_identity *right)
{
	return left != NULL && right != NULL && left->device == right->device &&
	       left->inode == right->inode;
}

/* 读取目标进程的 Java 可执行文件绝对路径。 */
static int read_java_exe_path(pid_t pid, char *path, size_t path_size)
{
	char proc_path[64];
	ssize_t length;
	char *deleted;

	/* 检查输出缓冲区，避免 readlink() 写入越界。 */
	if (path == NULL || path_size < 2)
		return -1;

	/* 构造目标进程的 exe proc 路径。 */
	if (snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid) >=
	    (int)sizeof(proc_path))
		return -1;

	/* readlink() 不会自动补充字符串结尾的 NUL 字符。 */
	length = readlink(proc_path, path, path_size - 1);
	if (length < 0) {
		fprintf(stderr, "读取 %s 失败：%s\n", proc_path, strerror(errno));
		return -1;
	}
	path[length] = '\0';

	/* 进程退出过程中可能出现“ (deleted)”后缀，去掉该后缀再执行。 */
	deleted = strstr(path, " (deleted)");
	if (deleted != NULL)
		*deleted = '\0';

	/* 目标 Java 路径必须是绝对路径。 */
	if (path[0] != '/') {
		fprintf(stderr, "目标 exe 路径不是绝对路径：%s\n", path);
		return -1;
	}

	return 0;
}

/* 进入目标进程的 mount namespace，并保存当前 namespace 文件描述符。 */
static int enter_mount_namespace(pid_t pid, int *self_fd, bool *entered)
{
	char target_path[64];
	char self_path[64];
	struct stat target_stat;
	struct stat self_stat;
	int target_fd;

	/* 初始化输出参数，确保所有错误路径都可以安全恢复。 */
	if (self_fd == NULL || entered == NULL)
		return -1;
	*self_fd = -1;
	*entered = false;

	/* 构造目标和当前进程的 mount namespace 路径。 */
	if (snprintf(target_path, sizeof(target_path), "/proc/%d/ns/mnt", pid) >=
	    (int)sizeof(target_path) ||
	    snprintf(self_path, sizeof(self_path), "/proc/self/ns/mnt") >=
	    (int)sizeof(self_path))
		return -1;

	/* 先比较 namespace 标识，避免已经在同一 namespace 时重复切换。 */
	if (stat(target_path, &target_stat) < 0) {
		fprintf(stderr, "stat %s 失败：%s\n", target_path, strerror(errno));
		return -1;
	}
	if (stat(self_path, &self_stat) < 0) {
		fprintf(stderr, "stat %s 失败：%s\n", self_path, strerror(errno));
		return -1;
	}
	if (target_stat.st_dev == self_stat.st_dev &&
	    target_stat.st_ino == self_stat.st_ino) {
		printf("当前进程和目标 Java 已经处于同一个 mount namespace\n");
		return 0;
	}

	/* 打开目标 namespace，供 setns() 使用。 */
	target_fd = open(target_path, O_RDONLY | O_CLOEXEC);
	if (target_fd < 0) {
		fprintf(stderr, "打开 %s 失败：%s\n", target_path, strerror(errno));
		return -1;
	}

	/* 打开当前 namespace，后续使用它恢复 Agent/测试程序的 namespace。 */
	*self_fd = open(self_path, O_RDONLY | O_CLOEXEC);
	if (*self_fd < 0) {
		fprintf(stderr, "打开 %s 失败：%s\n", self_path, strerror(errno));
		close(target_fd);
		return -1;
	}

	/* 仅切换 mount namespace，不切换 root 和当前工作目录。 */
	if (syscall(__NR_setns, target_fd, CLONE_NEWNS) < 0) {
		fprintf(stderr, "setns(%s) 失败：%s\n", target_path, strerror(errno));
		close(target_fd);
		close(*self_fd);
		*self_fd = -1;
		return -1;
	}
	close(target_fd);
	*entered = true;

	printf("已经进入目标 Java 的 mount namespace\n");
	return 0;
}

/* 设置后续子进程使用目标进程的 PID namespace，并保存原 namespace。 */
static int enter_pid_namespace(pid_t pid, int *self_fd, bool *entered)
{
	char target_path[64];
	char self_path[64];
	struct stat target_stat;
	struct stat self_stat;
	int target_fd;

	/* 初始化恢复参数，确保失败路径不会误关闭无效 fd。 */
	if (self_fd == NULL || entered == NULL)
		return -1;
	*self_fd = -1;
	*entered = false;

	/* 构造目标 PID namespace 文件路径。 */
	if (snprintf(target_path, sizeof(target_path), "/proc/%d/ns/pid", pid) >=
	    (int)sizeof(target_path) ||
	    snprintf(self_path, sizeof(self_path), "/proc/self/ns/pid") >=
	    (int)sizeof(self_path))
		return -1;

	/* 目标 PID namespace 不存在时直接报告错误。 */
	if (stat(target_path, &target_stat) < 0) {
		fprintf(stderr, "stat %s 失败：%s\n", target_path, strerror(errno));
		return -1;
	}

	/* 当前程序已经处于同一 PID namespace 时无需再次调用 setns。 */
	if (stat(self_path, &self_stat) < 0) {
		fprintf(stderr, "stat /proc/self/ns/pid 失败：%s\n",
			strerror(errno));
		return -1;
	}
	if (target_stat.st_dev == self_stat.st_dev &&
	    target_stat.st_ino == self_stat.st_ino) {
		printf("当前进程和目标 Java 已经处于同一个 PID namespace\n");
		return 0;
	}

	/* 打开目标 PID namespace 文件描述符。 */
	target_fd = open(target_path, O_RDONLY | O_CLOEXEC);
	if (target_fd < 0) {
		fprintf(stderr, "打开 %s 失败：%s\n", target_path, strerror(errno));
		return -1;
	}

	/* 保存原 PID namespace，供 popen() 完成后恢复后续子进程的 namespace。 */
	*self_fd = open(self_path, O_RDONLY | O_CLOEXEC);
	if (*self_fd < 0) {
		fprintf(stderr, "打开 %s 失败：%s\n", self_path, strerror(errno));
		close(target_fd);
		return -1;
	}

	/*
	 * 对 PID namespace 调用 setns() 后，当前进程的 PID 不会改变；
	 * 后续 fork()/popen() 创建的子进程才会进入该 PID namespace。
	 */
	if (syscall(__NR_setns, target_fd, CLONE_NEWPID) < 0) {
		fprintf(stderr, "setns(%s) 失败：%s\n", target_path, strerror(errno));
		close(target_fd);
		close(*self_fd);
		*self_fd = -1;
		return -1;
	}
	close(target_fd);
	*entered = true;

	printf("已经设置后续子进程使用目标 Java 的 PID namespace\n");
	return 0;
}

/* 验证 fork 出来的子进程确实继承了目标 PID namespace。 */
static int verify_child_pid_namespace(
	const struct namespace_identity *target_identity)
{
	struct namespace_identity child_identity;
	pid_t child_pid;
	int status;

	/* PID namespace 只对后续创建的子进程生效，因此通过 fork 验证。 */
	child_pid = fork();
	if (child_pid < 0) {
		fprintf(stderr, "fork() 验证 PID namespace 失败：%s\n",
			strerror(errno));
		return -1;
	}
	if (child_pid == 0) {
		/* 子进程读取自己的 PID namespace 身份并返回比较结果。 */
		if (read_namespace_identity("/proc/self/ns/pid", &child_identity) < 0)
			_exit(2);
		_exit(namespace_identity_equal(&child_identity, target_identity) ? 0 :
		       1);
	}

	/* 父进程等待验证子进程结束，避免留下测试僵尸进程。 */
	if (waitpid(child_pid, &status, 0) < 0) {
		fprintf(stderr, "waitpid() 验证 PID namespace 失败：%s\n",
			strerror(errno));
		return -1;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "后续子进程没有进入目标 PID namespace\n");
		return -1;
	}
	printf("验证成功：后续子进程进入了目标 PID namespace\n");
	return 0;
}

/* 恢复进入目标 mount namespace 之前的 namespace。 */
static int exit_mount_namespace(int self_fd, bool entered)
{
	int result;

	/* 如果原本就在同一个 namespace，则不需要恢复。 */
	if (!entered)
		return 0;

	/* 使用进入前保存的 namespace 文件描述符恢复。 */
	result = syscall(__NR_setns, self_fd, CLONE_NEWNS);
	if (result < 0)
		fprintf(stderr, "恢复原 mount namespace 失败：%s\n", strerror(errno));
	close(self_fd);
	return result;
}

/* 恢复后续子进程使用进入目标 PID namespace 之前的 namespace。 */
static int exit_pid_namespace(int self_fd, bool entered)
{
	int result;

	/* 如果目标 PID namespace 与当前相同，则没有需要恢复的设置。 */
	if (!entered)
		return 0;

	/* setns(CLONE_NEWPID) 恢复的是后续子进程的 namespace 选择。 */
	result = syscall(__NR_setns, self_fd, CLONE_NEWPID);
	if (result < 0)
		fprintf(stderr, "恢复后续子进程的 PID namespace 失败：%s\n",
			strerror(errno));
	close(self_fd);
	return result;
}

/* 验证恢复后新创建的子进程已经回到原 PID/mount namespace。 */
static int verify_future_child_namespaces(
	const struct namespace_identity *original_pid,
	const struct namespace_identity *original_mount)
{
	struct namespace_identity child_pid_identity;
	struct namespace_identity child_mount_identity;
	pid_t child_pid;
	int status;

	/* 再创建一个子进程，验证恢复操作对后续 fork() 生效。 */
	child_pid = fork();
	if (child_pid < 0) {
		fprintf(stderr, "fork() 验证恢复后的 PID namespace 失败：%s\n",
			strerror(errno));
		return -1;
	}
	if (child_pid == 0) {
		/* 子进程读取自己的 PID/mount namespace 并与原 namespace 比较。 */
		if (read_namespace_identity("/proc/self/ns/pid", &child_pid_identity) < 0 ||
		    read_namespace_identity("/proc/self/ns/mnt", &child_mount_identity) < 0)
			_exit(2);
		_exit(namespace_identity_equal(&child_pid_identity, original_pid) &&
		       namespace_identity_equal(&child_mount_identity, original_mount) ? 0 :
		       1);
	}

	/* 等待验证子进程，避免测试程序结束后留下僵尸。 */
	if (waitpid(child_pid, &status, 0) < 0) {
		fprintf(stderr, "waitpid() 验证恢复后的 PID namespace 失败：%s\n",
			strerror(errno));
		return -1;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr,
			"验证失败：恢复后新子进程没有回到原 PID/mount namespace\n");
		return -1;
	}
	printf("验证成功：恢复后新子进程回到了原 PID/mount namespace\n");
	return 0;
}

/* 验证测试程序已经恢复到进入 namespace 前的 mount/PID namespace。 */
static int verify_namespace_restored(
	const struct namespace_identity *original_mount,
	const struct namespace_identity *original_pid)
{
	struct namespace_identity current_mount;
	struct namespace_identity current_pid;

	/* 检查当前 mount namespace 是否恢复为进入前保存的 namespace。 */
	if (read_namespace_identity("/proc/self/ns/mnt", &current_mount) < 0)
		return -1;
	if (!namespace_identity_equal(&current_mount, original_mount)) {
		fprintf(stderr, "验证失败：当前 mount namespace 没有恢复\n");
		return -1;
	}
	printf("验证成功：已经退出目标 mount namespace\n");

	/*
	 * setns(CLONE_NEWPID) 不改变当前进程的 PID namespace，只影响后续子进程；
	 * 当前进程仍在 original_pid，但需要单独验证后续子进程的 namespace 设置。
	 */
	if (read_namespace_identity("/proc/self/ns/pid", &current_pid) < 0)
		return -1;
	if (!namespace_identity_equal(&current_pid, original_pid)) {
		fprintf(stderr, "验证失败：当前 PID namespace 发生了意外变化\n");
		return -1;
	}
	printf("验证成功：当前进程仍处于原 PID namespace\n");
	if (verify_future_child_namespaces(original_pid, original_mount) < 0)
		return -1;
	return 0;
}

/* 为 shell 命令中的 Java 路径添加单引号，避免路径字符被 shell 解释。 */
static int shell_quote(const char *value, char *quoted, size_t quoted_size)
{
	size_t used = 0;
	size_t index;

	/* 预留首尾单引号和字符串结尾的 NUL 字符。 */
	if (value == NULL || quoted == NULL || quoted_size < 3)
		return -1;
	quoted[used++] = '\'';

	/* 逐字节复制路径，并转义路径中可能出现的单引号。 */
	for (index = 0; value[index] != '\0'; index++) {
		if (value[index] == '\'') {
			if (used + 4 >= quoted_size)
				return -1;
			memcpy(quoted + used, "'\\''", 4);
			used += 4;
		} else {
			if (used + 1 >= quoted_size)
				return -1;
			quoted[used++] = value[index];
		}
	}

	/* 添加结束单引号和字符串结尾。 */
	if (used + 2 > quoted_size)
		return -1;
	quoted[used++] = '\'';
	quoted[used] = '\0';
	return 0;
}

/* 从目标进程的 NUL 分隔 environ 中读取指定环境变量。 */
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

	/* 检查参数，避免无效缓冲区导致内存访问错误。 */
	if (name == NULL || value == NULL || value_size == 0)
		return -1;

	/* 构造目标进程的环境文件路径。 */
	if (snprintf(proc_path, sizeof(proc_path), "/proc/%d/environ", pid) >=
	    (int)sizeof(proc_path))
		return -1;

	/* 以二进制方式打开，保留环境变量之间的 NUL 分隔符。 */
	file = fopen(proc_path, "rb");
	if (file == NULL) {
		fprintf(stderr, "打开 %s 失败：%s\n", proc_path, strerror(errno));
		return -1;
	}

	name_len = strlen(name);
	/* getdelim() 使用 NUL 作为分隔符，逐条读取环境变量。 */
	while ((entry_len = getdelim(&entry, &entry_size, '\0', file)) >= 0) {
		/* 环境变量必须以 NAME= 开头，避免误匹配同名前缀变量。 */
		if ((size_t)entry_len <= name_len ||
		    strncmp(entry, name, name_len) != 0 || entry[name_len] != '=')
			continue;

		/* 去除末尾的 NUL，再复制变量值。 */
		entry_len -= 1;
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

	/* 记录读取错误，但允许没有找到变量的正常情况。 */
	if (ferror(file))
		found = -1;
	free(entry);
	fclose(file);
	return found;
}

/* 根据目标 Java 的 bin/java 路径构造常见的 jli 动态库目录。 */
static int build_java_jli_path(const char *exe_path, char *path,
			       size_t path_size)
{
	char runtime_root[PATH_MAX];
	char *slash;
	int length;

	/* 检查 Java 路径和输出缓冲区。 */
	if (exe_path == NULL || path == NULL || path_size == 0)
		return -1;
	if (strlen(exe_path) >= sizeof(runtime_root))
		return -1;

	/* 复制路径，随后从 /bin/java 反推出 JRE 根目录。 */
	strcpy(runtime_root, exe_path);
	slash = strrchr(runtime_root, '/');
	if (slash == NULL || strcmp(slash + 1, "java") != 0)
		return -1;
	*slash = '\0';
	slash = strrchr(runtime_root, '/');
	if (slash == NULL || strcmp(slash + 1, "bin") != 0)
		return -1;
	*slash = '\0';

	/* 当前测试目标为 amd64，jli 目录是 Java 启动器的必要搜索路径。 */
	length = snprintf(path, path_size, "%s/lib/amd64/jli", runtime_root);
	if (length < 0 || (size_t)length >= path_size)
		return -1;
	return 0;
}

/* 复制目标 Java 的必要运行时环境，并补充 jli 动态库目录。 */
static int apply_target_environment(pid_t pid, const char *exe_path)
{
	static const char *const names[] = {
		"LD_LIBRARY_PATH",
		"JAVA_HOME",
		"PATH",
		"HOME",
		"LANG",
	};
	char value[PATH_MAX * 2];
	char jli_path[PATH_MAX];
	char library_path[PATH_MAX * 3];
	int result;
	int index;

	/* 只复制执行版本检查所需的变量，不复制 LD_PRELOAD 等危险变量。 */
	for (index = 0; index < (int)(sizeof(names) / sizeof(names[0])); index++) {
		result = read_target_env_value(pid, names[index], value,
					       sizeof(value));
		if (result < 0)
			return -1;
		if (result == 0)
			continue;
		if (setenv(names[index], value, 1) < 0) {
			fprintf(stderr, "设置环境变量 %s 失败：%s\n", names[index],
				strerror(errno));
			return -1;
		}
		printf("复制目标环境变量：%s=%s\n", names[index], value);
	}

	/* 根据目标 Java 路径补充 jli 目录，避免启动器找不到 libjli.so。 */
	if (build_java_jli_path(exe_path, jli_path, sizeof(jli_path)) < 0)
		return -1;
	if (getenv("LD_LIBRARY_PATH") == NULL ||
	    getenv("LD_LIBRARY_PATH")[0] == '\0') {
		if (setenv("LD_LIBRARY_PATH", jli_path, 1) < 0)
			return -1;
	} else {
		result = snprintf(library_path, sizeof(library_path), "%s:%s",
				  jli_path, getenv("LD_LIBRARY_PATH"));
		if (result < 0 || (size_t)result >= sizeof(library_path))
			return -1;
		if (setenv("LD_LIBRARY_PATH", library_path, 1) < 0)
			return -1;
	}
	printf("最终 LD_LIBRARY_PATH=%s\n", getenv("LD_LIBRARY_PATH"));
	return 0;
}

/* 通过 popen() 执行目标 Java 的 -version，并输出完整结果。 */
static int run_java_version(const char *exe_path)
{
	char quoted_exe[PATH_MAX * 4 + 8];
	char command[PATH_MAX * 4 + 32];
	char output[4096];
	FILE *pipe;
	int status;

	/* 对目标 Java 路径进行 shell 安全转义。 */
	if (shell_quote(exe_path, quoted_exe, sizeof(quoted_exe)) < 0)
		return -1;

	/* 保留 stderr，因为 Java -version 通常把版本输出到 stderr。 */
	if (snprintf(command, sizeof(command), "%s -version 2>&1", quoted_exe) >=
	    (int)sizeof(command))
		return -1;

	printf("执行命令：%s\n", command);
	pipe = popen(command, "r");
	if (pipe == NULL) {
		fprintf(stderr, "popen() 失败：%s\n", strerror(errno));
		return -1;
	}

	/* 读取并打印 Java -version 输出。 */
	while (fgets(output, sizeof(output), pipe) != NULL)
		fputs(output, stdout);

	/* 等待 shell 和 Java 子进程结束，获取命令退出状态。 */
	status = pclose(pipe);
	if (status < 0) {
		fprintf(stderr, "pclose() 失败：%s\n", strerror(errno));
		return -1;
	}

	printf("pclose() 返回状态：%d\n", status);
	return status;
}

/* 程序入口：读取 PID、切换 mount namespace、执行版本检查并恢复 namespace。 */
int main(int argc, char **argv)
{
	char exe_path[PATH_MAX];
	char *end;
	long pid_value;
	pid_t pid;
	int self_fd = -1;
	bool entered = false;
	int pid_self_fd = -1;
	bool pid_entered = false;
	int command_status;
	int restore_status;
	int pid_restore_status;
	int verify_status;
	struct namespace_identity original_mount;
	struct namespace_identity original_pid;
	struct namespace_identity target_pid;

	/* 检查命令行参数数量。 */
	if (argc != 2) {
		fprintf(stderr, "用法：%s <java-pid>\n", argv[0]);
		return EXIT_FAILURE;
	}

	/* 严格解析 PID，拒绝空字符串、非数字和超出 pid_t 范围的参数。 */
	errno = 0;
	pid_value = strtol(argv[1], &end, 10);
	if (errno != 0 || *argv[1] == '\0' || *end != '\0' || pid_value <= 0 ||
	    pid_value > INT_MAX) {
		fprintf(stderr, "无效 PID：%s\n", argv[1]);
		return EXIT_FAILURE;
	}
	pid = (pid_t)pid_value;

	/* 在进入任何目标 namespace 前保存当前 mount/PID namespace 身份。 */
	if (read_namespace_identity("/proc/self/ns/mnt", &original_mount) < 0 ||
	    read_namespace_identity("/proc/self/ns/pid", &original_pid) < 0)
		return EXIT_FAILURE;

	/* 保存目标 PID namespace 身份，用于验证后续子进程确实进入目标空间。 */
	{
		char target_pid_path[64];
		if (snprintf(target_pid_path, sizeof(target_pid_path),
			     "/proc/%d/ns/pid", pid) >= (int)sizeof(target_pid_path) ||
		    read_namespace_identity(target_pid_path, &target_pid) < 0)
			return EXIT_FAILURE;
	}

	/* 在切换 namespace 前读取目标 Java 的绝对路径。 */
	if (read_java_exe_path(pid, exe_path, sizeof(exe_path)) < 0)
		return EXIT_FAILURE;
	printf("目标 Java 绝对路径：%s\n", exe_path);

	/* 在执行 popen() 前复制目标 Java 的运行时环境。 */
	if (apply_target_environment(pid, exe_path) < 0)
		return EXIT_FAILURE;

	/* 设置 popen() 子进程使用目标 Java 的 PID namespace。 */
	if (enter_pid_namespace(pid, &pid_self_fd, &pid_entered) < 0)
		return EXIT_FAILURE;
	if (verify_child_pid_namespace(&target_pid) < 0) {
		exit_pid_namespace(pid_self_fd, pid_entered);
		return EXIT_FAILURE;
	}

	/* 进入目标 Java 的 mount namespace。 */
	if (enter_mount_namespace(pid, &self_fd, &entered) < 0) {
		exit_pid_namespace(pid_self_fd, pid_entered);
		return EXIT_FAILURE;
	}

	/* 在目标 mount namespace 中执行 java -version。 */
	command_status = run_java_version(exe_path);

	/* 无论 popen() 是否成功，都尝试恢复原 mount namespace。 */
	restore_status = exit_mount_namespace(self_fd, entered);
	if (restore_status < 0)
		goto restore_pid_namespace;

	/* 恢复后续子进程的 PID namespace，避免影响测试程序之后的 fork/popen。 */
	pid_restore_status = exit_pid_namespace(pid_self_fd, pid_entered);
	if (pid_restore_status < 0)
		return EXIT_FAILURE;

	/* 在程序最后核对 mount namespace 已恢复，且 PID namespace 没有泄漏。 */
	verify_status = verify_namespace_restored(&original_mount, &original_pid);
	if (verify_status < 0)
		return EXIT_FAILURE;

	/* 返回 Java -version 的状态，便于脚本判断测试结果。 */
	if (command_status < 0)
		return EXIT_FAILURE;
	return WIFEXITED(command_status) ? WEXITSTATUS(command_status) : EXIT_FAILURE;

restore_pid_namespace:
	/* mount namespace 恢复失败时仍要尝试恢复后续子进程的 PID namespace。 */
	exit_pid_namespace(pid_self_fd, pid_entered);
	return EXIT_FAILURE;
}
