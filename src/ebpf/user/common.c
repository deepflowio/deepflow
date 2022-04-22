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
#include <linux/sysinfo.h> /* for struct sysinfo */
#include <sys/sysinfo.h>
#include "common.h"
#include "log.h"

static void __pclose(FILE * fp, const char *tag)
{
	int rc;
	rc = pclose(fp);
	if (-1 == rc) {
		ebpf_info("pclose error, 'uname -r', error:%s\n",
			  strerror(errno));
	} else {
		if (WIFEXITED(rc))
			ebpf_info("%s normal termination, exit status %d\n",
				  tag, WEXITSTATUS(rc));
		else if (WIFSIGNALED(rc))
			ebpf_info("%s abnormal termination,signal number %d\n",
				  tag, WTERMSIG(rc));
		else if (WIFSTOPPED(rc))
			ebpf_info("%s process stopped, signal number %d\n",
				  tag, WSTOPSIG(rc));
	}
}

static void execute_cmd(const char *cmd)
{
	FILE *fp;
	fp = popen(cmd, "r");
	if (NULL == fp) {
		ebpf_info("%s popen error. %s", cmd, strerror(errno));
	}
	__pclose(fp, cmd);
}

int fetch_command_value(const char *cmd, char *buf, int buf_len)
{
	FILE *fp;
	char *ret;

	fp = popen(cmd, "r");
	if (NULL == fp) {
		ebpf_info("[%s]  popen error. %s", __func__, strerror(errno));
		return -1;
	}

	memset(buf, 0, buf_len);
	ret = fgets(buf, buf_len, fp);
	if (ret == NULL) {
		ebpf_info("[%s] \"fgets()\" error. %s",
			  __func__, strerror(errno));
		__pclose(fp, cmd);
		return -1;
	}

	__pclose(fp, cmd);
	return 0;
}

bool is_core_kernel(void)
{
	return (access("/sys/kernel/btf/vmlinux", F_OK) == 0);
}

int get_cpus_count(void)
{
	int cpu_count = -1;
	char cpu_count_str[64];
	if (fetch_command_value("cat /proc/cpuinfo | grep processor | wc -l",
				cpu_count_str, sizeof(cpu_count_str)) != 0)
		return -1;

	if (sscanf(cpu_count_str, "%d", &cpu_count) != 1)
		return -1;

	return cpu_count;
}

// 系统启动到现在的时间（以秒为单位）
uint32_t get_sys_uptime(void)
{
	struct sysinfo s_info = { 0 };
	if (sysinfo(&s_info) != 0)
		return 0;

	return (uint32_t)s_info.uptime;
}

uint64_t fetch_sys_boot_secs(void)
{
	uint64_t boot_time = 0;
	char boot_time_str[64];
	if (fetch_command_value
	    ("cat /proc/stat | grep btime | awk '{print $2}'", boot_time_str,
	     sizeof(boot_time_str)) != 0)
		return 0;

	if (sscanf(boot_time_str, "%" PRIu64, &boot_time) != 1)
		return 0;

	return (uint64_t) boot_time;
}

void clear_residual_probes()
{
	char buf[1024];
	snprintf(buf, sizeof(buf),
		 "cat /sys/kernel/debug/tracing/kprobe_events | grep \"_metaflow_\" | grep -v %d | awk -F'/' '{print $2}' |awk '{print \"-:\" $1}' | xargs -I {} echo {} >> /sys/kernel/debug/tracing/kprobe_events",
		 getpid());
	execute_cmd(buf);
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
