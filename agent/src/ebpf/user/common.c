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

#include <stdio.h>
#include <stdbool.h>
#include <linux/limits.h>	/* ulimit */
#include <sys/resource.h>	/* RLIM_INFINITY */
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <linux/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/version.h>
#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <inttypes.h>
#include <sys/utsname.h>
#include "config.h"
#include "types.h"
#include "clib.h"
#include "list.h"
#include "common.h"
#include "log.h"
#include "string.h"

#define MAXLINE 1024

static u64 g_sys_btime_msecs;

bool is_core_kernel(void)
{
	return (access("/sys/kernel/btf/vmlinux", F_OK) == 0);
}

static int parse_online_cpus(const char *cpu_file, bool ** mask, int *cpu_count)
{
	int fd, i, n, len, start, end = -1;
	bool *tmp;
	char buf[1024];
	if ((fd = open(cpu_file, O_RDONLY | O_CLOEXEC)) < 0) {
		ebpf_warning("Failed to open file (%s: %d)\n", cpu_file, errno);
		return -1;
	}

	len = read(fd, buf, sizeof(buf));
	close(fd);
	if (len <= 0) {
		ebpf_warning("Failed to read file (%s: %d)\n", cpu_file, errno);
		return -1;
	}

	if (len >= sizeof(buf)) {
		ebpf_warning("File is too big %s\n", cpu_file);
		return -1;
	}

	for (i = 0; i < len; i++) {
		if (buf[i] == ',' || buf[i] == '\n') {
			continue;
		}
		n = sscanf(&buf[i], "%d%n-%d%n", &start, &len, &end, &len);
		if (n <= 0 || n > 2) {
			goto failed;
		} else if (n == 1) {
			end = start;
		}
		if (start < 0 || start > end) {
			goto failed;
		}

		tmp = realloc(*mask, end + 1);
		if (!tmp) {
			goto failed;
		}
		*mask = tmp;
		memset(tmp + *cpu_count, 0, start - *cpu_count);
		memset(tmp + start, 1, end - start + 1);
		*cpu_count = end + 1;
		i += (len - 1);
	}

	if (*cpu_count == 0) {
		goto failed;
	}

	return 0;
failed:
	ebpf_warning("CPU range error\n");
	if (*mask != NULL) {
		free(*mask);
		*mask = NULL;
	}

	*cpu_count = 0;
	return -1;
}

int get_cpus_count(bool ** mask)
{
	bool *online = NULL;
	int err, n = 0;
	const char *online_cpus_file = "/sys/devices/system/cpu/online";

	err = parse_online_cpus(online_cpus_file, &online, &n);
	if (err) {
		ebpf_warning("failed to get online CPU mask: %d\n", err);
		return -1;
	}

	*mask = online;
	return n;
}

int get_num_possible_cpus(void)
{
	bool *mask = NULL;
	int err, n = 0, i, cpus = 0;
	static const char *fcpu = "/sys/devices/system/cpu/possible";

	err = parse_online_cpus(fcpu, &mask, &n);
	if (err) {
		ebpf_warning("failed to get online CPU mask: %d\n", err);
		return -1;
	}

	for (i = 0; i < n; i++) {
		if (mask[i]) {
			cpus++;
		}
	}

	free(mask);
	return cpus;
}

// 系统启动到现在的时间（以秒为单位）
uint32_t get_sys_uptime(void)
{
	struct sysinfo s_info = { 0 };
	if (sysinfo(&s_info) != 0)
		return 0;

	return (uint32_t) s_info.uptime;
}

static void exec_clear_residual_probes(const char *events_file,
				       const char *type_name)
{
	struct probe_elem {
		struct list_head list;
		char event[MAXLINE];
	};

	FILE *fp;
	char line[MAXLINE];
	char *lf;		// 字符 '\n'
	struct list_head probe_head;
	struct probe_elem *pe;

	init_list_head(&probe_head);

	if ((fp = fopen(events_file, "r")) == NULL) {
		ebpf_info("Open config file(\"%s\") failed.\n", events_file);
		return;
	}

	while ((fgets(line, MAXLINE, fp)) != NULL) {
		if ((lf = strchr(line, '\n')))
			*lf = '\0';

		pe = (struct probe_elem *)calloc(sizeof(*pe), 1);
		if (pe == NULL) {
			ebpf_warning("calloc() failed.\n");
			break;
		}
		snprintf(pe->event, sizeof(pe->event), "%s", line);
		list_add_tail(&pe->list, &probe_head);
	}

	fclose(fp);

	char *ptr;
	struct list_head *p, *n;
	char rm_event_cmd[MAXLINE];

	int kfd = open(events_file, O_WRONLY | O_APPEND, 0);

	if (kfd < 0) {
		ebpf_info("open(%s): failed %s\n", events_file,
			  strerror(errno));
		return;
	}

	list_for_each_safe(p, n, &probe_head) {
		pe = container_of(p, struct probe_elem, list);
		// Match the [K/U]probe events of "_deepflow_"
		// 匹配"_deepflow_"的[k/u]probe事件
		if (strstr(pe->event, "_deepflow_")) {
			if ((ptr = strchr(pe->event, '/'))) {
				char *s = ++ptr;
				if ((ptr = strchr(ptr, ' ')))
					*ptr = '\0';
				snprintf(rm_event_cmd, sizeof(rm_event_cmd),
					 "-:%s", s);
				if (write
				    (kfd, rm_event_cmd,
				     strlen(rm_event_cmd)) < 0) {
					if (errno == ENOENT)
						ebpf_info
						    ("clear %s error, probe entry may not exist.(%s)\n",
						     type_name, rm_event_cmd);
					else
						ebpf_info
						    ("cannot clear %s, %s (%s)\n",
						     type_name, strerror(errno),
						     rm_event_cmd);
					close(kfd);
				} else
					ebpf_info
					    ("Clear residual %s event \"%s\" success.\n",
					     type_name, rm_event_cmd);
			}
		}

		list_head_del(&pe->list);
		free(pe);
	}

	close(kfd);
}

void clear_residual_probes(void)
{
	exec_clear_residual_probes(KPROBE_EVENTS_FILE, "kprobe");
	exec_clear_residual_probes(UPROBE_EVENTS_FILE, "uprobe");
}

/* Make sure max locked memory is set to unlimited. */
int max_locked_memory_set_unlimited(void)
{
	int ret;
	struct rlimit rlim;
	errno = 0;
	if ((ret = getrlimit(RLIMIT_MEMLOCK, &rlim)) < 0) {
		ebpf_info("Call getrlimit is error(%d). %s", errno,
			  strerror(errno));
		return -1;
	}

	if (rlim.rlim_cur != RLIM_INFINITY) {
		rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;
		if ((ret = setrlimit(RLIMIT_MEMLOCK, &rlim)) < 0) {
			ebpf_info("Call setrlimit is error. error(%d). %s",
				  errno, strerror(errno));
			return -1;
		}
	}

	return ret;
}

int max_rlim_open_files_set(int num)
{
	int ret;
	struct rlimit rlim;
	errno = 0;
	if ((ret = getrlimit(RLIMIT_NOFILE, &rlim)) < 0) {
		ebpf_info("Call getrlimit is error(%d). %s", errno,
			  strerror(errno));
		return -1;
	}

	if (rlim.rlim_cur < num) {
		rlim.rlim_cur = rlim.rlim_max = num;
		if ((ret = setrlimit(RLIMIT_NOFILE, &rlim)) < 0) {
			ebpf_info
			    ("Call setrlimit set RLIMIT_NOFILE is error. error(%d). %s",
			     errno, strerror(errno));
			return -1;
		}
	}

	memset(&rlim, 0, sizeof(rlim));
	getrlimit(RLIMIT_NOFILE, &rlim);
	ebpf_info("RLIMIT_NOFILE cur:%d, rlim_max:%d\n", rlim.rlim_cur,
		  rlim.rlim_max);

	return ret;
}

static int fs_write(const char *file_name, char *v, int mode, int len)
{
	int fd, err = 0;

	fd = open(file_name, mode);
	if (fd < 0) {
		ebpf_warning("Open debug file(\"%s\") open failed.\n",
			     file_name);
		return -1;
	}

	if ((err = write(fd, v, len)) < 0)
		ebpf_warning("Write %s to file \"%s\" failed.\n", v, file_name);

	close(fd);
	return err;
}

int sysfs_write(const char *file_name, char *v)
{
	return fs_write(file_name, v, O_WRONLY, 1);
}

static int fs_read(const char *file_name, char *v, int mode, int len)
{
	int fd, err = 0;

	fd = open(file_name, mode);
	if (fd < 0) {
		ebpf_warning("Open debug file(\"%s\") open failed.\n",
			     file_name);
		return -1;
	}

	if ((err = read(fd, v, len)) < 0)
		ebpf_warning("Read %s to file \"%s\" failed.\n", v, file_name);

	close(fd);
	return err;
}

int sysfs_read_num(const char *file_name)
{
	int ret;
	char buf[64];
	memset(buf, 0, sizeof(buf));
	ret = fs_read(file_name, (char *)buf, O_RDONLY, 1);
	if (ret > 0) {
		return atoi(buf);
	}

	return ETR_INVAL;
}

uint64_t gettime(clockid_t clk_id, int flag)
{
	struct timespec t;
	int res;
	uint64_t time = 0;
	res = clock_gettime(clk_id, &t);
	if (res < 0) {
		return 0;
	}

	if (flag == TIME_TYPE_NAN)
		time = (uint64_t) t.tv_sec * NS_IN_SEC + t.tv_nsec;
	else if (flag == TIME_TYPE_SEC)
		time = (uint64_t) t.tv_sec;

	return time;
}

/*
 * Get system boot start time (in milliseconds).
 */
u64 get_sys_btime_msecs(void)
{
	if (g_sys_btime_msecs > 0)
		goto done;

	char buff[4096];

	FILE *fp = fopen("/proc/stat", "r");
	ASSERT(fp != NULL);

	u64 sys_boot = 0;
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		if (sscanf(buff, "btime %lu", &sys_boot) == 1)
			break;
	}

	fclose(fp);
	ASSERT(sys_boot > 0);

	if (g_sys_btime_msecs == 0)
		g_sys_btime_msecs = sys_boot * 1000UL;

done:
	return g_sys_btime_msecs;
}

/*
 * Get the start time (in milliseconds) of a given PID.
 */
u64 get_process_starttime(pid_t pid)
{
	char file[PATH_MAX], buff[4096];
	int fd;
	unsigned long long etime_ticks = 0;

	snprintf(file, sizeof(file), "/proc/%d/stat", pid);
	if (access(file, F_OK))
		return 0;

	fd = open(file, O_RDONLY);
	if (fd <= 2)
		return 0;

	read(fd, buff, sizeof(buff));
	close(fd);

	if (sscanf(buff, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s"
		   " %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %llu ",
		   &etime_ticks) != 1) {
		return 0;
	}

	u64 sys_boot = get_sys_btime_msecs();
	u64 msecs_per_tick = 1000UL / sysconf(_SC_CLK_TCK);

	return ((etime_ticks * msecs_per_tick) + sys_boot);
}

u64 current_sys_time_secs(void)
{
	return (get_sys_uptime() + (get_sys_btime_msecs() / 1000));
}

/*
 * Get the start time (in milliseconds) of a given PID,
 * and fetch process comm.
 *
 * @pid processID
 * @comm_base store process name address
 * @len store process name max length
 *
 * @return process start time,
 * 	   if is 0, it indicates that an error has been encountered.
 */
u64 get_process_starttime_and_comm(pid_t pid, char *name_base, int len)
{
	char file[PATH_MAX], buff[4096];
	int fd;
	unsigned long long etime_ticks = 0;

	snprintf(file, sizeof(file), "/proc/%d/stat", pid);
	if (access(file, F_OK))
		return 0;

	fd = open(file, O_RDONLY);
	if (fd <= 2)
		return 0;

	read(fd, buff, sizeof(buff));
	close(fd);

	char *start = NULL;	// process name start address;
	if (sscanf(buff, "%*s %ms %*s %*s %*s %*s %*s %*s %*s %*s %*s"
		   " %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %llu ",
		   &start, &etime_ticks) != 2) {
		return 0;
	}

	if (name_base != NULL && len > 0) {
		int src_len = strlen(start);
		start[src_len - 1] = '\0';
		src_len -= 2;
		if (src_len > len)
			src_len = len;
		memset(name_base, 0, len);
		memcpy_s_inline((void *)name_base, len,
				(void *)start + 1, src_len);
	}

	free(start);

	u64 sys_boot = get_sys_btime_msecs();
	u64 msecs_per_tick = 1000UL / sysconf(_SC_CLK_TCK);

	return ((etime_ticks * msecs_per_tick) + sys_boot);
}

int fetch_kernel_version(int *major, int *minor, int *patch)
{
	struct utsname sys_info;

	// Get the real version of Ubuntu

	if (access("/proc/version_signature", R_OK) == 0) {
		FILE *f = fopen("/proc/version_signature", "r");
		if (f) {
			if (fscanf(f, "%*s %*s %d.%d.%d\n", major, minor, patch)
			    != 3) {
				fclose(f);
				*major = *minor = *patch = 0;
				return ETR_INVAL;
			}
			fclose(f);
			return ETR_OK;
		}
	}

	uname(&sys_info);
	if (sscanf(sys_info.release, "%u.%u.%u", major, minor, patch) != 3)
		return ETR_INVAL;

	// Get the real version of Debian
	//#1 SMP Debian 4.19.289-2 (2023-08-08)
	if (strstr(sys_info.version, "Debian")) {
		int num;
		if (
			(sscanf(sys_info.version, "%*s %*s %*s %u.%u.%u-%u %*s",
			   major, minor, patch, &num) != 4) && 
			(sscanf(sys_info.version, "%*s %*s %*s %*s %u.%u.%u-%u %*s",
			   major, minor, patch, &num) != 4)
		)
			return ETR_INVAL;
	}

	return ETR_OK;
}

int fetch_system_type(const char *sys_type, int type_len)
{
	int len, i, count = 0;
	char *p = NULL;
	struct utsname sys_info;
	uname(&sys_info);
	len = strlen(sys_info.release);
	for (i = len - 1; i >= 0; i--) {
		if (sys_info.release[i] == '.') {
			if (count == 0) {
				sys_info.release[i] = '\0';
			} else if (count == 1) {
				p = &sys_info.release[i + 1];
				break;
			}
			count++;
		}
	}

	if (p == NULL)
		return ETR_INVAL;

	len = strlen(p) + 1 > type_len ? type_len : strlen(p) + 1;
	memcpy((void *)sys_type, p, len);

	return ETR_OK;
}

void fetch_linux_release(const char *buf, int buf_len)
{
	struct utsname sys_info;
	uname(&sys_info);
	int len =
	    strlen(sys_info.release) + 1 >
	    buf_len ? buf_len : strlen(sys_info.release) + 1;
	memcpy((void *)buf, sys_info.release, len);
}

unsigned int fetch_kernel_version_code(void)
{
	int ret;
	int major, minor, patch;
	ret = fetch_kernel_version(&major, &minor, &patch);
	if (ret != ETR_OK) {
		printf("fetch_kernel_version error\n");
		return 0;
	}

	/*
	 * Calculate LINUX_VERSION_CODE based on kernel
	 * version(linux major.minor.patch), use macros
	 * `KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c)).`
	 * If the patch number is greater than 255, there will
	 * be a deviation. For example, Linux 4.14.275
	 * calculates 265983 with KERNEL_VERSION(4,14,275),
	 * and the backderived kernel version is 4.15.19,
	 * which is obviously wrong.
	 * The solution is to determine the value of patch
	 * and set it to 255 if it exceeds 255.
	 */
	if (patch > 255) {
		patch = 255;
	}

	return KERNEL_VERSION(major, minor, patch);
}

static bool __is_process(int pid, bool is_user)
{
	char file[PATH_MAX], buff[4096];
	int fd;
	int read_tgid = -1, read_pid = -1;

	snprintf(file, sizeof(file), "/proc/%d/status", pid);
	if (access(file, F_OK))
		return false;

	fd = open(file, O_RDONLY);
	if (fd < 0)
		return false;

	memset(buff, 0, 4096);
	if (read(fd, buff, sizeof(buff)) <= 0) {
		ebpf_warning("Read file '%s' failed, errno %d\n", file, errno);
		close(fd);
		return false;
	}
	close(fd);

	/*
	 * All kernel threads in Linux have their parent process
	 * as either 0 or 2, and not any other value.
	 */
	char *p;
	if (is_user) {
		int ppid = -1;
		p = strstr(buff, "PPid:");
		if (p == NULL)
			return false;
		sscanf(p, "PPid:\t%d", &ppid);
		if ((ppid == 0 && pid != 1) || ppid == 2 || ppid == -1)
			return false;
	}

	if ((p = strstr(buff, "Tgid:")) == NULL)
		return false;
	sscanf(p, "Tgid:\t%d", &read_tgid);

	if ((p = strstr(buff, "Pid:")) == NULL)
		return false;
	sscanf(p, "Pid:\t%d", &read_pid);

	if (read_tgid == -1 || read_pid == -1)
		return false;

	if (read_tgid != -1 && read_pid != -1 && read_tgid == read_pid)
		return true;

	return false;
}

bool is_user_process(int pid)
{
	return __is_process(pid, true);
}

bool is_process(int pid)
{
	return __is_process(pid, false);
}

static char *__gen_datetime_str(const char *fmt, u64 ns)
{
	const int strlen = DATADUMP_FILE_PATH_SIZE;
	time_t timep;
	char *str;
	struct tm *p;
	str = malloc(strlen);
	if (str == NULL) {
		ebpf_warning("malloc() failed.\n");
		return NULL;
	}

	long msec = 0;
	if (ns > 0) {
		timep = ns / NS_IN_SEC;
		msec = (ns % NS_IN_SEC) / NS_IN_MSEC;
	} else {
		time(&timep);
		struct timeval msectime;
		gettimeofday(&msectime, NULL);
		msec = msectime.tv_usec / 1000;
	}

	p = localtime(&timep);
	snprintf(str, strlen, fmt,
		 (1900 + p->tm_year), (1 + p->tm_mon),
		 p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec, msec);

	return str;
}

u32 legacy_fetch_log2_page_size(void)
{
#define LOG2_PAFE_SIZE_DEF 21

	u32 log2_page_size = 0;
	FILE *fp;
	char tmp[33] = {};

	if ((fp = fopen("/proc/meminfo", "r")) == NULL) {
		ebpf_warning("fopen file '/proc/meminfo' failed.\n");
		return LOG2_PAFE_SIZE_DEF;
	}

	while (fscanf(fp, "%32s", tmp) > 0) {
		if (strncmp("Hugepagesize:", tmp, 13) == 0) {
			u32 size;
			if (fscanf(fp, "%u", &size) > 0)
				log2_page_size = 10 + min_log2(size);
			break;
		}
	}

	fclose(fp);
	return log2_page_size;
}

char *gen_file_name_by_datetime(void)
{
	return __gen_datetime_str("%d_%02d_%02d_%02d_%02d_%02d_%ld", 0);
}

char *gen_timestamp_prefix(void)
{
	return __gen_datetime_str("%d-%02d-%02d %02d:%02d:%02d.%ld", 0);
}

char *gen_timestamp_str(u64 ns)
{
	return __gen_datetime_str("%d-%02d-%02d %02d:%02d:%02d.%ld", ns);
}

u64 get_netns_id_from_pid(pid_t pid)
{
	char netns_path[MAX_PATH_LENGTH];
	snprintf(netns_path, sizeof(netns_path), "/proc/%d/ns/net", pid);

	char target_path[MAX_PATH_LENGTH];
	ssize_t len =
	    readlink(netns_path, target_path, sizeof(target_path) - 1);
	if (len == -1) {
		return 0;
	}
	target_path[len] = '\0';

	// Extract netns_id from the target path
	char *netns_id_str_start = strstr(target_path, "[");
	if (netns_id_str_start == NULL) {
		ebpf_warning("Failed to extract netns_id.\n");
		return 0;
	}

	char *netns_id_str_end = strstr(netns_id_str_start, "]");
	if (netns_id_str_end == NULL) {
		ebpf_warning("Failed to extract netns_id.\n");
		return 0;
	}

	*netns_id_str_end = '\0';
	char *netns_id_str = netns_id_str_start + 1;

	return strtoull(netns_id_str, NULL, 10);
}

int get_nspid(int pid)
{
	int ns_pid_1, ns_pid_2;
	char status_path[MAX_PATH_LENGTH];
	snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
	if (access(status_path, F_OK)) {
		ebpf_info("Fun %s file '%s' not exist.\n", __func__,
			  status_path);
		return ETR_NOTEXIST;
	}

	FILE *file = fopen(status_path, "r");
	if (file == NULL) {
		ebpf_info("fopen() %s error(%d)\n", status_path, errno);
		return ETR_INVAL;
	}

	char line[MAX_PATH_LENGTH];
	while (fgets(line, sizeof(line), file) != NULL) {
		if (strncmp(line, "NSpid:", 6) == 0) {
			int result = sscanf(line + 6, "\t%d\t%d\n", &ns_pid_1,
					    &ns_pid_2);
			if (result == 1) {
				ns_pid_2 = ns_pid_1;
			}
			fclose(file);
			return ns_pid_2;
		}
	}

	fclose(file);
	ebpf_info("Not find NSpid\n", status_path);
	return ETR_NOTEXIST;
}

int get_target_uid_and_gid(int target_pid, int *uid, int *gid)
{
	char proc_path[MAX_PATH_LENGTH];
	snprintf(proc_path, sizeof(proc_path), "/proc/%d", target_pid);
	if (access(proc_path, F_OK)) {
		ebpf_info("Fun %s file '%s' not exist.\n", __func__, proc_path);
		return ETR_NOTEXIST;
	}

	*uid = *gid = -1;
	struct stat sb;
	if (stat(proc_path, &sb) == 0) {
		*uid = sb.st_uid;
		*gid = sb.st_gid;
	} else {
		ebpf_info("stat() %s error, errno %d\n", proc_path, errno);
		return ETR_INVAL;
	}

	return ETR_OK;
}

int gen_file_from_mem(const char *mem_ptr, int write_bytes, const char *path)
{
	FILE *file_ptr = fopen(path, "wb");
	if (file_ptr == NULL) {
		ebpf_warning("Cannot open file '%s' failed. errno %d %s\n",
			     path, errno, strerror(errno));
		return ETR_INVAL;
	}

	fwrite(mem_ptr, write_bytes, 1, file_ptr);
	fclose(file_ptr);

	return ETR_OK;
}

/**
 * Function to copy a file.
 * @param src_file Path of the file to be copied.
 * @param dest_file Path where the copied file will be saved.
 * @return int 1: Copy successful; 2: Copy failed.
 */
int copy_file(const char *src_file, const char *dest_file)
{
	int ret = ETR_OK;
	FILE *src_file_ptr;	// Pointer to the source file
	FILE *dest_file_ptr;	// Pointer to the destination file
	src_file_ptr = dest_file_ptr = NULL;
	const size_t buffer_size = 4096;	// Buffer size
	char *buffer = (char *)malloc(buffer_size);	// Allocate buffer
	if (buffer == NULL) {
		ebpf_warning("malloc() failed.\n");
		return ETR_NOMEM;
	}

	size_t bytes_read;	// Actual number of bytes read

	if ((src_file_ptr = fopen(src_file, "rb")) == NULL
	    || (dest_file_ptr = fopen(dest_file, "wb")) == NULL) {
		ebpf_warning("Cannot open file, src '%s' dest '%s'\n",
			     src_file, dest_file);
		ret = ETR_INVAL;
		goto failed;
	}
	// Continuously read from src_file, place in buffer, and write buffer contents to dest_file
	while ((bytes_read = fread(buffer, 1, buffer_size, src_file_ptr)) > 0) {
		fwrite(buffer, bytes_read, 1, dest_file_ptr);
	}

failed:
	free(buffer);
	if (src_file_ptr)
		fclose(src_file_ptr);

	if (dest_file_ptr)
		fclose(dest_file_ptr);

	return ret;
}

int df_enter_ns(int pid, const char *type, int *self_fd)
{
#ifdef __NR_setns
	char path[64], selfpath[64];
	snprintf(path, sizeof(path), "/proc/%d/ns/%s", pid, type);
	snprintf(selfpath, sizeof(selfpath), "/proc/self/ns/%s", type);

	*self_fd = -1;
	struct stat oldns_stat, newns_stat;
	if (stat(selfpath, &oldns_stat) == 0 && stat(path, &newns_stat) == 0) {
		// Don't try to call setns() if we're in the same namespace already
		if (oldns_stat.st_ino != newns_stat.st_ino) {
			int newns;
			newns = open(path, O_RDONLY);
			if (newns < 0) {
				return -1;
			}

			*self_fd = open(selfpath, O_RDONLY);
			if (*self_fd < 0) {
				return -1;
			}
			// Some ancient Linux distributions do not have setns() function
			int result = syscall(__NR_setns, newns, 0);
			close(newns);
			if (result < 0) {
				close(*self_fd);
				*self_fd = -1;
			}
			return result < 0 ? -1 : 1;
		}
	}
#endif // __NR_setns

	return 0;
}

void df_exit_ns(int fd)
{
	if (fd < 0)
		return;

	int result = syscall(__NR_setns, fd, 0);
	if (result < 0) {
		ebpf_warning("Fun %s setns error errno %d (%s)\n",
			     __func__, errno, strerror(errno));
	}

	close(fd);
}

int exec_command(const char *cmd, const char *args)
{
	FILE *fp;
	int rc = 0;
	char cmd_buf[64];
	snprintf(cmd_buf, sizeof(cmd_buf), "%s %s", cmd, args);
	fp = popen(cmd_buf, "r");
	if (NULL == fp) {
		ebpf_warning("%s '%s' execute error,[%s]\n",
			     __func__, cmd_buf, strerror(errno));
		return -1;
	}
#ifdef PROFILE_JAVA_DEBUG
	/* Read and print the output */
	char buffer[1024];
	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		ebpf_info("%s", buffer);
	}
#endif

	rc = pclose(fp);
	if (-1 == rc) {
		ebpf_warning("pclose error, '%s' error:%s\n",
			     cmd_buf, strerror(errno));
	} else {
		if (WIFEXITED(rc)) {
			ebpf_info("'%s' normal termination, exit status %d\n",
				  cmd_buf, WEXITSTATUS(rc));
			return WEXITSTATUS(rc);
		} else if (WIFSIGNALED(rc)) {
			ebpf_info
			    ("'%s' abnormal termination,signal number %d\n",
			     cmd_buf, WTERMSIG(rc));
		} else if (WIFSTOPPED(rc)) {
			ebpf_info("'%s' process stopped, signal number %d\n",
				  cmd_buf, WSTOPSIG(rc));
		}
	}

	return -1;
}

int fetch_container_id_from_str(char *buff, char *id, int copy_bytes)
{
	static const int cid_len = 64;
	char *p;

	if ((p = strstr(buff, ".scope")))
		*p = '\0';
	else
		p = buff + strlen(buff);

	if (strlen(buff) < cid_len)
		return -1;

	p -= cid_len;

	if (strchr(p, '.') || strchr(p, '-') || strchr(p, '/'))
		return -1;

	if (strlen(p) != cid_len)
		return -1;

	memset(id, 0, copy_bytes);
	memcpy_s_inline((void *)id, copy_bytes, (void *)p, cid_len);

	return 0;
}

int fetch_container_id(pid_t pid, char *id, int copy_bytes)
{
	char file[PATH_MAX], buff[MAXLINE];
	memset(buff, 0, sizeof(buff));
	snprintf(file, sizeof(file), "/proc/%d/cgroup", pid);
	if (access(file, F_OK))
		return -1;

	FILE *fp;
	char *lf;
	if ((fp = fopen(file, "r")) == NULL) {
		return -1;
	}

	while ((fgets(buff, sizeof(buff), fp)) != NULL) {
		if ((lf = strchr(buff, '\n')))
			*lf = '\0';
		// includes "pids" | "cpuset" | "devices" | "memory" | "cpu"
		if (strstr(buff, "pids") || strstr(buff, "cpuset")
		    || strstr(buff, "devices") || strstr(buff, "memory")
		    || strstr(buff, "cpu")) {
			break;
		}

	}

	fclose(fp);

	return fetch_container_id_from_str(buff, id, copy_bytes);
}
