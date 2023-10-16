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
#include <string.h>
#include <bcc/linux/bpf.h>
#include <bcc/linux/bpf_common.h>
#include <bcc/libbpf.h>
#include "probe.h"
#include "log.h"
#include "symbol.h"
#include "tracer.h"
#include "load.h"

extern bool *cpu_online;
extern int sys_cpus_count;
extern int ioctl(int fd, unsigned long request, ...);

int bpf_get_program_fd(void *obj, const char *name, void **p)
{
	struct ebpf_prog *prog;

	/*
	 * tracepoint: prog->name:bpf_func_sys_exit_recvfrom
	 * kprobe: prog->name:kprobe____sys_sendmsg
	 */
	char prog_name[PROBE_NAME_SZ];
	int res;

	char *__name = (char *)name;
	if (strstr(__name, "kprobe/")) {
		__name += (sizeof("kprobe/") - 1);
		res =
		    snprintf((char *)prog_name, sizeof(prog_name), "kprobe__%s",
			     __name);
		if (res < 0 || res >= sizeof(prog_name)) {
			ebpf_warning("name (%s) snprintf() failed.\n", __name);
			return -1;
		}
	} else if (strstr(__name, "kretprobe/")) {
		__name += (sizeof("kretprobe/") - 1);
		res =
		    snprintf((char *)prog_name, sizeof(prog_name),
			     "kretprobe__%s", __name);
		if (res < 0 || res >= sizeof(prog_name)) {
			ebpf_warning("name (%s) snprintf() failed.\n", __name);
			return -1;
		}
	} else if (strstr(__name, "tracepoint/")) {
		char *p = __name;
		while (*p != '\0')
			if (*p++ == '/')
				__name = p;
		res =
		    snprintf((char *)prog_name, sizeof(prog_name),
			     "bpf_func_%s", __name);
		if (res < 0 || res >= sizeof(prog_name)) {
			ebpf_warning("name (%s) snprintf() failed.\n", __name);
			return -1;
		}
	} else
		safe_buf_copy(prog_name, sizeof(prog_name), __name, strlen(__name));

	prog = ebpf_obj__get_prog_by_name((struct ebpf_object *)obj, prog_name);
	if (prog == NULL) {
		*p = NULL;
		ebpf_warning("bpf_obj__get_prog_by_name() not find \"%s\"\n",
			     prog_name);
		return -1;
	}

	*p = prog;
	return prog->prog_fd;
}

static int ebpf_link__detach_perf_event(struct ebpf_link *link)
{
	int err;
	err = ioctl(link->fd, PERF_EVENT_IOC_DISABLE, 0);
	if (err)
		err = -errno;

	close(link->fd);
	return err;
}

/*
 * program__attach_probe - Attach [u/k]probe handle
 *
 * @prog: eBPF program address
 * @retprobe: Is retrun probe ?
 * @ev_name: When using debugfs mode, ev_name as the event name. e.g.: p___sys_sendmmsg, 
 * @config1: kprobe_func or uprobe_path. e.g.:__sys_sendmmsg
 * @event_type: "kprobe" or "uprobe"
 * @offset: kprobe_addr or probe_offset
 * @pid: Atttach to pid for uprobe.
 * @maxactive: Specifies the number of instances of the probed function that can be probed
 *             at one time. use for kretprobe.
 * @ret_link: return struct ebpf_link address
 */
static int program__attach_probe(const struct ebpf_prog *prog, bool retprobe,
				 const char *ev_name, const char *config1,
				 const char *event_type, uint64_t offset,
				 pid_t pid, int maxactive, void **ret_link)
{
	int progfd = prog->prog_fd;
	if (progfd < 0) {
		return -1;
	}

	int pfd = 0;
	bool is_kprobe = strncmp("kprobe", event_type, 6) == 0;
	enum bpf_probe_attach_type attach_type =
	    retprobe ? BPF_PROBE_RETURN : BPF_PROBE_ENTRY;
	if (is_kprobe) {
		pfd = bpf_attach_kprobe(progfd, attach_type, ev_name,
					config1, offset, maxactive);
	} else {
		// ref_ctr_offset Appear in linux 4.20, set 0
		// https://lore.kernel.org/lkml/20180606083344.31320-3-ravi.bangoria@linux.ibm.com/
		pfd = bpf_attach_uprobe(progfd, attach_type, ev_name, config1,
					offset, pid, 0);
	}

	if (pfd < 0)
		return -1;

	struct ebpf_link *link;
	link = calloc(1, sizeof(*link));
	if (!link) {
		return -1;
	}

	link->detach = ebpf_link__detach_perf_event;
	link->fd = pfd;

	*ret_link = (void *)link;
	return 0;
}

int program__detach_probe(struct ebpf_link *link,
			  bool retprobe,
			  const char *ev_name, const char *event_type)
{
	if (link->detach(link))
		ebpf_info("<%s> detach ev_name:%s, error\n", __func__, ev_name);

	int ret = 0;

#if 0
	bool is_kprobe = strncmp("kprobe", event_type, 6) == 0;
	if (is_kprobe) {
		ret = bpf_detach_kprobe(ev_name);
	} else {
		ret = bpf_detach_uprobe(ev_name);
	}

	if (ret < 0)
		ebpf_info("<%s> bpf_detach_probe ev_name:%s error.\n", __func__,
			  ev_name);
#endif

	free(link);
	return ret;
}

int program__attach_uprobe(void *prog, bool retprobe, pid_t pid,
			   const char *binary_path,
			   size_t func_offset, char *ev_name, void **ret_link)
{
	return program__attach_probe((const struct ebpf_prog *)prog,
				     retprobe, (const char *)ev_name,
				     binary_path, "uprobe", func_offset, pid,
				     0, ret_link);
}

int program__attach_kprobe(void *prog,
			   bool retprobe,
			   pid_t pid,
			   const char *func_name,
			   char *ev_name, void **ret_link)
{
	int maxactive = 0;
	//if (retprobe) {
	//	maxactive = KRETPROBE_MAXACTIVE_MAX;
	//}
	return program__attach_probe((const struct ebpf_prog *)prog,
				     retprobe, (const char *)ev_name, func_name,
				     "kprobe", 0, pid, maxactive, ret_link);
}

struct ebpf_link *program__attach_tracepoint(void *prog)
{
	// e.g.:
	// sec_name:  "tracepoint/syscalls/sys_enter_write"
	// prog name: "bpf_func_sys_enter_write"

	char *sec_name, *category, *name;
	int len, pfd;
	struct ebpf_prog *ebpf_prog;
	struct ebpf_link *link = NULL;

	if (prog == NULL) {
		ebpf_warning("prog is NULL.\n");
		return NULL;
	}
	ebpf_prog = prog;
	sec_name = strdup(ebpf_prog->sec_name);
	if (!sec_name) {
		ebpf_warning("Call strdup() failed.\n");
		return NULL;
	}

	len = strlen("tracepoint/");
	category = sec_name;

	// extract "tracepoint/<category>/<name>"
	if (!strncmp(sec_name, "tracepoint/", len)) {
		category = sec_name + len;
	}

	name = strchr(category, '/');
	if (!name) {
		ebpf_warning("section name : %s is invalid.\n", sec_name);
		free(sec_name);
		return NULL;
	}

	*name = '\0';
	name++;

	pfd = bpf_attach_tracepoint(ebpf_prog->prog_fd, category, name);
	free(sec_name);
	if (pfd < 0) {
		return NULL;
	}

	link = calloc(1, sizeof(*link));
	if (!link) {
		ebpf_warning("Call calloc() is failed.\n");
		return NULL;
	}

	link->detach = ebpf_link__detach_perf_event;
	link->fd = pfd;

	return link;
}

/**
 * attach perf event
 *
 * @ev_type
 *     The type of perf event (e.g. PERF_TYPE_HARDWARE, PERF_TYPE_SOFTWARE, etc.)
 * @ev_config
 *     The actual event to be counted (e.g. PERF_COUNT_HW_CPU_CYCLES,
 *     PERF_COUNT_SW_CPU_CLOCK).
 * @sample_period
 *     event->attr.sample_period = NSEC_PER_SEC / freq;
 *     see linux kernel perf_swevent_init_hrtimer()
 *     (kernel/events/core.c)
 * @sample_freq
 *     Mutually exclusive with sample_period.
 *     sysctl kernel.perf_event_max_sample_rate limit
 *     (e.g. centos7 40000, ubuntu 100000).
 * @pid
 *     the process ID to be monitored. If pid is -1, all processes.
 * @cpu
 *     the CPU core to be bound. If cpu is -1, then no binding is done.
 * @group_fd
 *     the file descriptor used to create the event group. If group_fd
 *     is -1, then a new event group is created.
 * @attach_fds
 *     tracer->per_cpu_fds address
 * @fds_len
 *     attach_fds[] length
 *
 * @returns 0 on success, < 0 on error
 *
 */
int program__attach_perf_event(int prog_fd, uint32_t ev_type,
			       uint32_t ev_config, uint64_t sample_period,
			       uint64_t sample_freq, pid_t pid,
			       int cpu, int group_fd,
			       int *attach_fds,
			       int fds_len)
{
	int i,j;
	int fds[fds_len];
	memset(fds, 0, sizeof(fds));
	for (i = 0; i < sys_cpus_count && i < fds_len; i++) {
		if (!cpu_online[i])
			continue;

		int fd = bpf_attach_perf_event(prog_fd, ev_type,
					       ev_config, sample_period,
					       sample_freq, pid, i, group_fd);
		if (fd < 0) {
			for (j = 0; j < MAX_CPU_NR; j++) {
				if (fds[i] > 0)
					close(fds[i]);
				return (-1);
			}
		}

		fds[i] = fd;
		ebpf_info("attach perf event sample_freq %d pid %d cpu %d done\n",
			  sample_freq, pid, i);
	}

	memcpy((void *)attach_fds, (void *)fds, sizeof(fds));

	return (0);
}

/**
 * detach perf event
 *
 * @attach_fds
 *     tracer->per_cpu_fds address
 * @len
 *     tracer->per_cpu_fds cpu count.
 *
 * @returns 0 on success, < 0 on error
 */
int program__detach_perf_event(int *attach_fds, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		if (attach_fds[i] > 0) {
			close(attach_fds[i]);
			ebpf_info("detach cpu %d close fd %d\n",
				  i, attach_fds[i]);
			attach_fds[i] = 0;
		}
	}

	return (0);
}
