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
#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>
#include "list_head.h"
#include "common.h"
#include "log.h"
#include "../libbpf/src/libbpf_internal.h"

bool is_core_kernel(void)
{
	return (access("/sys/kernel/btf/vmlinux", F_OK) == 0);
}

int get_cpus_count(bool ** mask)
{
	bool *online = NULL;
	int err, n;
	const char *online_cpus_file = "/sys/devices/system/cpu/online";

	err = parse_cpu_mask_file(online_cpus_file, &online, &n);
	if (err) {
		ebpf_info("failed to get online CPU mask: %d\n", err);
		return -1;
	}

	*mask = online;
	return n;
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
#define MAXLINE 1024
	struct probe_elem {
		struct list_head list;
		char event[MAXLINE];
	};

	FILE *fp;
	char line[MAXLINE];
	char *lf;		// 字符 '\n'
	struct list_head probe_head;
	struct probe_elem *pe;

	INIT_LIST_HEAD(&probe_head);

	if ((fp = fopen(events_file, "r")) == NULL) {
		ebpf_info("Open config file(\"%s\") faild.\n", events_file);
		return;
	}

	while ((fgets(line, MAXLINE, fp)) != NULL) {
		if ((lf = strchr(line, '\n')))
			*lf = '\0';
		pe = (struct probe_elem *)calloc(sizeof(*pe), 1);
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

//OPEN_FILES_MAX
static int fs_write(char *file_name, char *v, int mode, int len)
{
	int fd, err = 0;

	fd = open(file_name, mode);
	if (fd < 0) {
		ebpf_info("Open debug file(\"%s\") write faild.\n", file_name);
		return -1;
	}

	if ((err = write(fd, v, len)) < 0)
		ebpf_info("Write %s to file \"%s\" faild.\n", v, file_name);

	close(fd);
	return err;
}

int sysfs_write(char *file_name, char *v)
{
	return fs_write(file_name, v, O_WRONLY, 1);
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

// refs: https://man7.org/linux/man-pages/man5/proc.5.html
// /proc/[pid]/stat Status information about the process.
unsigned long long get_process_starttime(int pid)
{
	char file[PATH_MAX], buff[4096];
	int fd;
	unsigned long long starttime = 0;

	snprintf(file, sizeof(file), "/proc/%d/stat", pid);
	if (access(file, F_OK))
		return 0;

	fd = open(file, O_RDONLY);
	if (fd < 0)
		return false;

	read(fd, buff, sizeof(buff));
	close(fd);

	if (sscanf(buff, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s"
		   " %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %llu ",
		   &starttime) != 1) {
		return 0;
	}

	return starttime;
}
