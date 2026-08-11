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
#include <ctype.h>
#include <errno.h>
#include <limits.h>
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

/* Set a readable failure reason for the preflight result. */
static void java_preflight_set_reason(java_preflight_info_t *info,
					      const char *reason)
{
	if (info == NULL)
		return;
	if (reason == NULL)
		reason = "unknown";
	strncpy(info->reason, reason, sizeof(info->reason) - 1);
	info->reason[sizeof(info->reason) - 1] = '\0';
}

/* Read the target executable path and strip the exit marker. */
static bool java_preflight_readlink(pid_t pid, char *path, size_t path_len)
{
	char proc_path[64];
	ssize_t len;

	if (path == NULL || path_len < 2)
		return false;
	snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);
	len = readlink(proc_path, path, path_len - 1);
	if (len < 0)
		return false;
	path[len] = '\0';
	/* readlink may return a path with the deleted suffix while a process exits. */
	char *deleted = strstr(path, " (deleted)");
	if (deleted != NULL)
		*deleted = '\0';
	return path[0] == '/';
}

/* Check whether the target process has exited or entered the zombie state. */
static bool java_preflight_process_is_zombie(pid_t pid)
{
	char path[64], line[4096];
	FILE *fp;
	char *right_paren;

	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	fp = fopen(path, "r");
	if (fp == NULL)
		return true;
	if (fgets(line, sizeof(line), fp) == NULL) {
		fclose(fp);
		return true;
	}
	fclose(fp);

	/* comm may contain spaces and parentheses; the state follows the last ')'. */
	right_paren = strrchr(line, ')');
	if (right_paren == NULL || right_paren[1] != ' ' || right_paren[2] == '\0')
		return true;
	return right_paren[2] == 'Z' || right_paren[2] == 'X';
}

/* Extract a mapped file path from a maps line and strip an exit-time deleted marker. */
static bool java_preflight_map_path(const char *line, char *path,
					    size_t path_len)
{
	char *deleted;
	char *end;
	int parsed;

	if (line == NULL || path == NULL || path_len < 2)
		return false;
	parsed = sscanf(line, "%*s %*s %*s %*s %*s %4095[^\n]", path);
	if (parsed != 1)
		return false;
	path[path_len - 1] = '\0';
	deleted = strstr(path, " (deleted)");
	if (deleted != NULL)
		*deleted = '\0';
	end = path + strlen(path);
	while (end > path && isspace((unsigned char)end[-1]))
		*--end = '\0';
	return path[0] == '/';
}

/* Check whether a maps filename is an OpenJ9 VM core library. */
static bool java_preflight_is_openj9_library(const char *name)
{
	const char *suffix;

	if (name == NULL || strncmp(name, "libj9vm", 7) != 0)
		return false;
	suffix = name + 7;
	if (*suffix == '.')
		return strcmp(suffix, ".so") == 0;
	while (isdigit((unsigned char)*suffix))
		suffix++;
	return strcmp(suffix, ".so") == 0;
}

/* Scan the target maps and distinguish HotSpot from other known JVMs. */
static bool java_preflight_maps(pid_t pid, java_preflight_info_t *info)
{
	char maps_path[64], line[PATH_MAX + 256];
	char mapped_path[PATH_MAX];
	FILE *fp;
	bool found_libjvm = false;
	bool found_other_jvm = false;

	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
	fp = fopen(maps_path, "r");
	if (fp == NULL)
		return false;
	while (fgets(line, sizeof(line), fp) != NULL) {
		char *slash;

		if (!java_preflight_map_path(line, mapped_path,
					     sizeof(mapped_path)))
			continue;
		slash = strrchr(mapped_path, '/');
		if (slash == NULL)
			slash = mapped_path;
		else
			slash++;
		if (java_preflight_is_openj9_library(slash)) {
			/* OpenJ9 may also map a compatibility libjvm.so; prefer libj9vm. */
			found_other_jvm = true;
			continue;
		}
		if (strcmp(slash, "libjvm.so") == 0) {
			found_libjvm = true;
		}
	}
	fclose(fp);
	if (found_other_jvm) {
		info->is_other_jvm = true;
		return true;
	}
	if (found_libjvm) {
		info->is_hotspot = true;
		return true;
	}
	return false;
}

/* Copy a selected range from -version output without relying on release format. */
static void java_preflight_copy_range(const char *start, const char *end,
					      char *dst, size_t dst_len)
{
	size_t len;

	if (start == NULL || end == NULL || dst == NULL || dst_len == 0 ||
	    end < start) {
		return;
	}
	len = (size_t)(end - start);
	if (len >= dst_len)
		len = dst_len - 1;
	memcpy(dst, start, len);
	dst[len] = '\0';
}

/* Parse JAVA_VERSION from the target JVM -version output. */
static void java_preflight_parse_version_output(const char *output,
						java_preflight_info_t *info)
{
	const char *start;
	const char *end;

	if (output == NULL || info == NULL)
		return;
	/* The standard first output line looks like openjdk version "1.8.0_412". */
	start = strstr(output, "version \"");
	if (start == NULL)
		return;
	start += strlen("version \"");
	end = strchr(start, '"');
	java_preflight_copy_range(start, end, info->java_version,
				  sizeof(info->java_version));
}

/* Derive the search path for JVM libraries such as libjli.so from maps and exe. */
static void java_preflight_build_library_path(pid_t pid,
					       const char *exe_path, char *path,
					       size_t path_len)
{
	char maps_path[64], line[PATH_MAX + 256], mapped_path[PATH_MAX];
	FILE *fp;

	if (path == NULL || path_len == 0)
		return;
	path[0] = '\0';
	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
	fp = fopen(maps_path, "r");
	if (fp != NULL) {
		while (fgets(line, sizeof(line), fp) != NULL) {
			char *slash;
			if (!java_preflight_map_path(line, mapped_path,
					     sizeof(mapped_path)))
				continue;
			slash = strrchr(mapped_path, '/');
			if (slash == NULL)
				continue;
			if (strcmp(slash + 1, "libjvm.so") != 0)
				continue;
			*slash = '\0';
			slash = strrchr(mapped_path, '/');
			if (slash == NULL || strcmp(slash + 1, "server") != 0)
				continue;
			*slash = '\0';
			snprintf(path, path_len, "%s/jli:%s:%s/server", mapped_path,
				 mapped_path, mapped_path);
			break;
		}
		fclose(fp);
	}
	if (path[0] != '\0')
		return;

	/* If maps cannot be read, derive common architecture directories from the
	 * standard <jre>/bin/java layout. */
	if (exe_path != NULL && exe_path[0] == '/') {
		char runtime_root[PATH_MAX];
		char *slash = strrchr(exe_path, '/');
		if (slash != NULL) {
			size_t len = (size_t)(slash - exe_path);
			if (len >= sizeof(runtime_root))
				len = sizeof(runtime_root) - 1;
			memcpy(runtime_root, exe_path, len);
			runtime_root[len] = '\0';
			slash = strrchr(runtime_root, '/');
			if (slash != NULL && strcmp(slash + 1, "bin") == 0) {
				*slash = '\0';
				snprintf(path, path_len,
					 "%s/lib/amd64/jli:%s/lib/amd64:%s/lib/amd64/server:"
					 "%s/lib/aarch64/jli:%s/lib/aarch64:%s/lib/aarch64/server",
					 runtime_root, runtime_root, runtime_root,
					 runtime_root, runtime_root, runtime_root);
			}
		}
	}
}

/* Single-quote shell arguments so special characters in Java paths are inert. */
static bool java_preflight_shell_quote(const char *value, char *quoted,
					       size_t quoted_len)
{
	size_t used = 0;
	size_t i;

	if (value == NULL || quoted == NULL || quoted_len < 3)
		return false;
	quoted[used++] = '\'';
	for (i = 0; value[i] != '\0'; i++) {
		if (value[i] == '\'') {
			/* A shell single quote must be encoded as '\'' . */
			if (used + 4 >= quoted_len)
				return false;
			memcpy(quoted + used, "'\\''", 4);
			used += 4;
		} else {
			if (used + 1 >= quoted_len)
				return false;
			quoted[used++] = value[i];
		}
	}
	if (used + 2 > quoted_len)
		return false;
	quoted[used++] = '\'';
	quoted[used] = '\0';
	return true;
}

/* Find a command in the Agent/host rootfs for target-root execution. */
static const char *java_preflight_host_command(const char *name)
{
	static const char *const env_paths[] = { "/usr/bin/env", "/bin/env" };
	static const char *const timeout_paths[] = {
		"/usr/bin/timeout", "/bin/timeout"
	};
	static const char *const nsenter_paths[] = {
		"/usr/bin/nsenter", "/bin/nsenter"
	};
	const char *const *paths;
	size_t count;
	size_t i;

	if (strcmp(name, "env") == 0) {
		paths = env_paths;
		count = sizeof(env_paths) / sizeof(env_paths[0]);
	} else if (strcmp(name, "timeout") == 0) {
		paths = timeout_paths;
		count = sizeof(timeout_paths) / sizeof(timeout_paths[0]);
	} else {
		paths = nsenter_paths;
		count = sizeof(nsenter_paths) / sizeof(nsenter_paths[0]);
	}
	for (i = 0; i < count; i++) {
		if (access(paths[i], X_OK) == 0)
			return paths[i];
	}
	return NULL;
}

/* Execute the target JVM -version in its PID/mount namespace and capture output. */
static bool java_preflight_exec_version(pid_t pid, const char *exe_path,
					java_preflight_info_t *info)
{
	char library_path[PATH_MAX * 2] = {};
	char quoted_library[PATH_MAX * 8 + 8] = {};
	char quoted_exe[PATH_MAX * 4 + 8] = {};
	char command_args[PATH_MAX * 12 + 256] = {};
	char output[16384] = {};
	bool version_ok = false;
	bool same_mntns;
	bool use_host_nsenter = false;
	const char *env_path;
	const char *host_timeout = NULL;
	const char *host_nsenter = NULL;
	int command_ret;

	if (exe_path == NULL || exe_path[0] != '/' || info == NULL)
		return false;
	java_preflight_build_library_path(pid, exe_path, library_path,
						  sizeof(library_path));
	/* Check the mount namespace before selecting the rootfs execution path. */
	same_mntns = is_same_mntns(pid);
	/*
	 * setns changes namespaces but does not change the calling thread's root. For
	 * a different mount namespace, use host nsenter with --root so every absolute
	 * path (env, Java, and LD_LIBRARY_PATH) resolves inside the target rootfs.
	 * This also avoids changing the Agent thread's namespace while popen() runs.
	 */
	use_host_nsenter = !same_mntns;
	if (use_host_nsenter) {
		/* All helper commands execute before nsenter changes root; they must be
		 * available in the Agent/host rootfs. */
		env_path = java_preflight_host_command("env");
		host_timeout = java_preflight_host_command("timeout");
		host_nsenter = java_preflight_host_command("nsenter");
		if (env_path == NULL || host_timeout == NULL || host_nsenter == NULL)
			return false;
		ebpf_info(JAVA_LOG_TAG
			  "JAVA_VERSION_NSENTER_ROOT pid=%d root=/proc/%d/root\n",
			  pid, pid);
	} else {
		/* The same mount namespace can use the Agent's helper path directly. */
		if (access("/usr/bin/env", X_OK) == 0)
			env_path = "/usr/bin/env";
		else if (access("/bin/env", X_OK) == 0)
			env_path = "/bin/env";
		else
			return false;
	}
	if (!java_preflight_shell_quote(library_path, quoted_library,
					 sizeof(quoted_library)) ||
	    !java_preflight_shell_quote(exe_path, quoted_exe,
					 sizeof(quoted_exe)))
		return false;
	/*
	 * exec_command uses popen(). The outer env sanitizes the Agent environment,
	 * timeout imposes a five-second limit, and LD_LIBRARY_PATH points to the
	 * target JVM library directory. In the cross-namespace path nsenter changes
	 * root before Java resolves these absolute paths.
	 */
	if (use_host_nsenter) {
		/* --root is essential: --mount/--pid alone do not change the process root. */
		snprintf(command_args, sizeof(command_args),
			 "-i PATH=/usr/bin:/bin HOME=/tmp LD_LIBRARY_PATH=%s %s 5 "
			 "%s --target %d --mount --pid --root=/proc/%d/root --no-fork -- %s "
			 "-version 2>&1",
			 quoted_library, host_timeout, host_nsenter, pid, pid,
			 quoted_exe);
	} else {
		snprintf(command_args, sizeof(command_args),
			 "-i PATH=/usr/bin:/bin HOME=/tmp timeout 5 %s -i "
			 "PATH=/usr/bin:/bin HOME=/tmp LD_LIBRARY_PATH=%s %s -version 2>&1",
			 env_path, quoted_library, quoted_exe);
	}
	command_ret = exec_command(env_path, command_args, output,
					 sizeof(output));
	if (command_ret == 0) {
		java_preflight_parse_version_output(output, info);
		version_ok = info->java_version[0] != '\0';
	}
	return version_ok;
}

/* Check whether an environment variable is a standard JVM option carrier. */
static bool java_preflight_is_jvm_option_env(const char *name)
{
	return strcmp(name, "JAVA_TOOL_OPTIONS") == 0 ||
	       strcmp(name, "_JAVA_OPTIONS") == 0 ||
	       strcmp(name, "JDK_JAVA_OPTIONS") == 0;
}

/* Match a complete NUL-separated argv token in /proc/<pid>/cmdline. */
static int java_preflight_cmdline_contains_option(FILE *fp,
						 const char *needle,
						 size_t needle_len)
{
	size_t token_len = 0;
	bool token_match = true;
	int c;

	while ((c = fgetc(fp)) != EOF) {
		if (c == '\0') {
			if (token_match && token_len == needle_len)
				return 1;
			token_len = 0;
			token_match = true;
			continue;
		}
		if (token_len >= needle_len ||
		    c != (unsigned char)needle[token_len])
			token_match = false;
		token_len++;
	}
	if (ferror(fp))
		return -1;
	/* Accept a final record without a trailing NUL for completeness. */
	return token_match && token_len == needle_len;
}

/* Match a whitespace-delimited option in standard JVM option environment variables. */
static int java_preflight_environ_contains_option(FILE *fp,
						  const char *needle,
						  size_t needle_len)
{
	char env_name[64];
	size_t env_name_len = 0, token_len = 0;
	bool env_name_valid = true, option_env = false;
	bool token_match = true, in_value = false;
	int c;

	while ((c = fgetc(fp)) != EOF) {
		if (c == '\0') {
			if (in_value && option_env && token_match &&
			    token_len == needle_len)
				return 1;
			env_name_len = 0;
			env_name_valid = true;
			option_env = false;
			token_len = 0;
			token_match = true;
			in_value = false;
			continue;
		}
		if (!in_value) {
			if (c == '=') {
				env_name[env_name_len] = '\0';
				option_env = env_name_valid &&
					java_preflight_is_jvm_option_env(env_name);
				in_value = true;
				token_len = 0;
				token_match = true;
				continue;
			}
			if (env_name_len + 1 < sizeof(env_name))
				env_name[env_name_len++] = (char)c;
			else
				env_name_valid = false;
			continue;
		}
		if (!option_env)
			continue;
		if (isspace((unsigned char)c)) {
			if (token_match && token_len == needle_len)
				return 1;
			token_len = 0;
			token_match = true;
			continue;
		}
		if (token_len >= needle_len ||
		    c != (unsigned char)needle[token_len])
			token_match = false;
		token_len++;
	}
	if (ferror(fp))
		return -1;
	if (in_value && option_env && token_match && token_len == needle_len)
		return 1;
	return 0;
}

/* Find a real JVM option without matching arbitrary substrings in /proc data. */
/* Return 1 if found, 0 if absent, and -1 if reading failed. */
static int java_preflight_proc_contains(pid_t pid, const char *name,
					       const char *needle)
{
	char path[64];
	FILE *fp;
	size_t needle_len;
	int result;

	snprintf(path, sizeof(path), "/proc/%d/%s", pid, name);
	fp = fopen(path, "rb");
	if (fp == NULL)
		return -1;
	needle_len = strlen(needle);
	if (needle_len == 0) {
		fclose(fp);
		return 0;
	}
	if (strcmp(name, "cmdline") == 0)
		result = java_preflight_cmdline_contains_option(fp, needle,
								 needle_len);
	else if (strcmp(name, "environ") == 0)
		result = java_preflight_environ_contains_option(fp, needle,
								  needle_len);
	else
		result = -1;
	fclose(fp);
	return result;
}

/* Parse the Java version and extract the Java 8 update number. */
static bool java_preflight_parse_version(const char *version, int *major,
						 int *update)
{
	const char *p = version;
	char *end;
	long first, second = -1;

	if (version == NULL || major == NULL || update == NULL || *version == '\0')
		return false;
	if (!isdigit((unsigned char)*p))
		return false;
	first = strtol(p, &end, 10);
	if (end == p || first < 0 || first > INT_MAX)
		return false;
	if (*end == '.' && end[1] != '\0' && isdigit((unsigned char)end[1])) {
		second = strtol(end + 1, &end, 10);
	}
	if (first == 1 && second >= 0) {
		*major = (int)second;
	} else {
		*major = (int)first;
	}
	*update = -1;
	if (*major == 8) {
		const char *u = strchr(version, '_');
		long parsed;
		if (u == NULL)
			u = strchr(version, 'u');
		if (u != NULL && isdigit((unsigned char)u[1])) {
			parsed = strtol(u + 1, &end, 10);
			if (parsed < 0 || parsed > INT_MAX)
				return false;
			if (*end != '\0' && *end != '-' && *end != '+')
				return false;
			*update = (int)parsed;
		} else if (first == 8 && *end == '.' &&
			   isdigit((unsigned char)end[1])) {
			/* Also accept version strings in the 8.0.382 form. */
			parsed = strtol(end + 1, &end, 10);
			if (parsed < 0 || parsed > INT_MAX)
				return false;
			*update = (int)parsed;
			if (*end != '\0' && *end != '-' && *end != '+')
				return false;
		}
		if (*update < 0)
			return false;
	}
	return true;
}

/*
 * Core JVM attach preflight entry point.
 *
 * This is the shared version gate for the main Agent and deepflow-jattach.
 * The checks run in the following order:
 *
 * 1. Process state check: read /proc/<pid>/stat and exclude exited or zombie
 *    processes. Record the PID start time and exe for later PID-reuse checks.
 *
 * 2. JVM map check: read /proc/<pid>/maps and identify HotSpot libjvm.so or
 *    another known JVM core library, such as OpenJ9 libj9vm. If neither is
 *    found, the target is not a recognizable JVM and the result is skip. An
 *    already loaded Agent is not a rejection condition because a valid reattach
 *    may call Agent_OnAttach again.
 *
 * 3. Target JVM version check: obtain -version only for HotSpot. Read the
 *    target exe and maps first; when the target and Agent use different mount
 *    namespaces, run the short-lived child through host nsenter with
 *    --mount --pid --root=/proc/<pid>/root. This is required because setns()
 *    alone does not change the process root, and absolute paths could otherwise
 *    resolve from the Agent/Host rootfs. Do not switch namespaces when they are
 *    the same. Skip conservatively when the root-aware command fails or the Java
 *    version cannot be parsed. Skip HotSpot Java 8 updates below 352 because
 *    the first fix is missing; also skip 352-381 because the 8u-specific Sweeper
 *    protection is incomplete. Only 382 and newer meet the current complete-fix
 *    baseline. This is a patch completeness gate, not a claim that every update
 *    below 382 reproduced the crash. Non-HotSpot JVMs do not run these
 *    specialized checks.
 *
 * 4. Attach capability check: read the target cmdline and environ. Match the
 *    complete JVM option token in cmdline, and match whitespace-delimited
 *    tokens only in the standard JVM option environment variables. Skip when
 *    -XX:+DisableAttachMechanism is present to avoid an injection that must
 *    fail; if either file cannot be read, capability cannot be confirmed and
 *    the result is also a conservative skip.
 *
 * 5. Race recheck: read the PID start time and exe again. If the process exits,
 *    the PID is reused, or the exe changes during the check, discard the result
 *    instead of applying it to another process.
 *
 * Return JAVA_PREFLIGHT_ALLOW only after every check passes. Only then may the
 * caller create a socket, copy the Agent SO, and invoke jattach; every skip
 * result must stop the injection flow.
 */
java_preflight_result_t java_attach_preflight(pid_t pid,
					      java_preflight_info_t *info)
{
	char exe_before[PATH_MAX], exe_after[PATH_MAX];
	u64 start_before, start_after;
	int cmdline_check;
	int environ_check;

	if (info == NULL)
		return JAVA_PREFLIGHT_ERROR;
	memset(info, 0, sizeof(*info));
	info->update_version = -1;
	if (pid <= 0) {
		java_preflight_set_reason(info, "invalid_pid");
		return JAVA_PREFLIGHT_SKIP;
	}
	if (java_preflight_process_is_zombie(pid)) {
		java_preflight_set_reason(info, "zombie_or_exited");
		return JAVA_PREFLIGHT_SKIP;
	}
	start_before = get_process_starttime_and_comm(pid, NULL, 0);
	if (start_before == 0 || !java_preflight_readlink(pid, exe_before,
							 sizeof(exe_before))) {
		java_preflight_set_reason(info, "process_not_readable");
		return JAVA_PREFLIGHT_SKIP;
	}
	if (!java_preflight_maps(pid, info)) {
		java_preflight_set_reason(info, "jvm_not_mapped");
		return JAVA_PREFLIGHT_SKIP;
	}
	if (info->is_hotspot &&
	    !java_preflight_exec_version(pid, exe_before, info)) {
		/* A failed version check cannot verify the 8u382 gate; skip attach. */
		java_preflight_set_reason(info, "version_command_failed");
		return JAVA_PREFLIGHT_SKIP;
	}
	if (info->is_hotspot) {
		if (info->java_version[0] == '\0' ||
		    !java_preflight_parse_version(info->java_version,
						   &info->major_version,
						   &info->update_version)) {
			java_preflight_set_reason(info, "unrecognized_java_version");
			return JAVA_PREFLIGHT_SKIP;
		}
	}
	cmdline_check = java_preflight_proc_contains(
		pid, "cmdline", "-XX:+DisableAttachMechanism");
	environ_check = java_preflight_proc_contains(
		pid, "environ", "-XX:+DisableAttachMechanism");
	if (cmdline_check < 0 || environ_check < 0) {
		/* Unreadable JVM options prevent confirming attach capability; skip. */
		java_preflight_set_reason(info, "attach_options_unreadable");
		return JAVA_PREFLIGHT_SKIP;
	}
	if (cmdline_check > 0 || environ_check > 0) {
		info->attach_disabled = true;
		java_preflight_set_reason(info, "attach_disabled");
		return JAVA_PREFLIGHT_SKIP;
	}
	if (info->is_hotspot && info->major_version == 8 &&
	    info->update_version < JAVA_ATTACH_JAVA8_COMPLETE_FIX_UPDATE) {
		/*
		 * The attach baseline requires both standard fixes. Every Java 8 update
		 * below 8u382 is conservatively treated as missing the complete fix set,
		 * and one unified reason is used instead of classifying the update range.
		 */
		java_preflight_set_reason(
			info,
			"hotspot_java8_missing_JDK-8173361_and_JDK-8305165_crash_risk");
		return JAVA_PREFLIGHT_SKIP;
	}
	start_after = get_process_starttime_and_comm(pid, NULL, 0);
	if (start_after == 0 || start_after != start_before ||
	    !java_preflight_readlink(pid, exe_after, sizeof(exe_after)) ||
	    strcmp(exe_before, exe_after) != 0) {
		java_preflight_set_reason(info, "pid_reused_or_exe_changed");
		return JAVA_PREFLIGHT_SKIP;
	}

	java_preflight_set_reason(info, "allowed");
	return JAVA_PREFLIGHT_ALLOW;
}

/* Convert the preflight result to Agent state and emit the common log. */
static int java_preflight_status(pid_t pid,
				 java_preflight_result_t result,
				 const java_preflight_info_t *info)
{
	const char *required;

	if (result == JAVA_PREFLIGHT_ALLOW)
		return 0;
	if (info != NULL) {
		required = info->is_hotspot ? "8u382+" : "none";
		ebpf_warning(JAVA_LOG_TAG
			     "JAVA_ATTACH_SKIP pid=%d reason=%s jvm=%s required=%s\n", pid,
			     info->reason[0] ? info->reason : "unknown",
			     info->java_version[0] ? info->java_version : "unknown",
			     required);
	}
	return JAVA_ATTACH_SKIPPED_UNSUPPORTED_JVM;
}

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
	if (args->map_fp != NULL &&
	    ((args->task->need_refresh && unload_count > 0)
	     || unload_count >= UPDATE_SYMS_FILE_UNLOAD_HIGH_THRESH)) {
		fclose(args->map_fp);
		// Prevent repeated fclose() in destroy_task() when the entire thread exits.
		args->map_fp = NULL;
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
	// Prevent writing data to a null file pointer
	if (fp == NULL)
		return -1;

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
	if (fp == NULL)
		return -1;
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

static inline void refresh_symbol_file_and_notify(receiver_args_t *args,
						  int ret_val)
{
	if (!(args != NULL && args->task != NULL))
		return;

	if (args->task->need_refresh) {
		pthread_mutex_lock(&args->task->mutex);
		args->task->update_status = ret_val;
		args->task->need_refresh = false;
		pthread_cond_signal(&args->task->cond);
		pthread_mutex_unlock(&args->task->mutex);
	}
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

		refresh_symbol_file_and_notify(args, update_java_perf_map_file(args, NULL));
	}

cleanup:
	/*
	 * If an exception occurs and the thread exits, a signal must be sent to the
	 * thread retrieving Java symbols; otherwise, the Java symbol thread will be blocked.
	 */
	refresh_symbol_file_and_notify(args, -1);

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
	java_preflight_info_t preflight_info;
	java_preflight_result_t preflight_result;

	/* The second check covers the window between process discovery and task creation. */
	preflight_result = java_attach_preflight(pid, &preflight_info);
	if (preflight_result != JAVA_PREFLIGHT_ALLOW)
		return java_preflight_status(pid, preflight_result, &preflight_info);

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
	/* deepflow-jattach is a separate process; negative skip codes become 254/253
	 * through the shell, so restore the original policy result for structured logs. */
	if (ret != 0 && strstr(ret_buf, "JAVA_ATTACH_SKIP") != NULL) {
		ret = JAVA_ATTACH_SKIPPED_UNSUPPORTED_JVM;
	}
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

/*
 * First gate for the main Agent: it must run before the thread pool, socket,
 * and collector are created.
 */
int start_java_symbol_collection(pid_t pid, const char *opts)
{
	java_preflight_info_t preflight_info;
	java_preflight_result_t preflight_result;

	/* If the JVM is rejected, do not initialize the collector or create a socket. */
	preflight_result = java_attach_preflight(pid, &preflight_info);
	if (preflight_result != JAVA_PREFLIGHT_ALLOW)
		return java_preflight_status(pid, preflight_result, &preflight_info);

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
		fprintf(stdout, "Thread %p Task %p JavaPID %d\n",
			(void *)task_thread->thread, task, task->pid);
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
	if (len < 0 || len >= sizeof(copy_target_path)) {
		ebpf_warning(JAVA_LOG_TAG
			     "Fun %s target ns path is too long for pid %d\n",
			     __func__, target_pid);
		return ETR_INVAL;
	}
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

	safe_snprintf(copy_target_path + len,
		      (int64_t)sizeof(copy_target_path) - len, "/%s",
		      AGENT_LIB_NAME);
	if ((ret =
	     agent_so_lib_copy(AGENT_LIB_SRC_PATH,
			       copy_target_path, target_uid,
			       target_gid)) != ETR_OK) {
		ebpf_warning(JAVA_LOG_TAG "cp '%s' to '%s' failed.\n",
			     AGENT_LIB_SRC_PATH, copy_target_path);
		return ret;
	}

	safe_snprintf(copy_target_path + len,
		      (int64_t)sizeof(copy_target_path) - len, "/%s",
		      AGENT_MUSL_LIB_NAME);

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

/*
 * Second gate for deepflow-jattach: it must run before namespace switching,
 * SO preparation, and jattach invocation to avoid a check race between the
 * main Agent and the standalone tool.
 */
int java_attach(pid_t pid)
{
	int ret = -1;
	java_preflight_info_t preflight_info;
	java_preflight_result_t preflight_result;

	/* Defense in depth: run the check again immediately before preparing jattach. */
	preflight_result = java_attach_preflight(pid, &preflight_info);
	if (preflight_result != JAVA_PREFLIGHT_ALLOW)
		return java_preflight_status(pid, preflight_result, &preflight_info);

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
