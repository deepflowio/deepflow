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

#include "probe.h"
#include "string.h"
#include "libbpf/include/linux/err.h"
#include "log.h"
#include "bcc/libbpf.h"
#include "symbol.h"
#include "tracer.h"
#include "bcc/setns.h"

extern int ioctl(int fd, unsigned long request, ...);
int bpf_get_program_fd(void *obj, const char *name, void **p)
{
	struct bpf_program *prog;
	int prog_fd;

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
			return ETR_NOROOM;
		}
	} else if (strstr(__name, "kretprobe/")) {
		__name += (sizeof("kretprobe/") - 1);
		res =
		    snprintf((char *)prog_name, sizeof(prog_name),
			     "kretprobe__%s", __name);
		if (res < 0 || res >= sizeof(prog_name)) {
			ebpf_warning("name (%s) snprintf() failed.\n", __name);
			return ETR_NOROOM;
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
			return ETR_NOROOM;
		}
	} else
		memcpy(prog_name, __name, sizeof(prog_name));

	prog =
	    bpf_object__find_program_by_name((struct bpf_object *)obj,
					     prog_name);
	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		ebpf_info("program not found: %s", strerror(prog_fd));
	}
	*p = prog;
	return prog_fd;
}

static int bpf_link__detach_perf_event(struct bpf_link *link)
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
 * @ret_link: return struct bpf_link address
 */
static int program__attach_probe(const struct bpf_program *prog, bool retprobe,
				 const char *ev_name, const char *config1,
				 const char *event_type, uint64_t offset,
				 pid_t pid, int maxactive, void **ret_link)
{
	int progfd = bpf_program__fd(prog);
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
		pfd = bpf_attach_uprobe(progfd, attach_type, ev_name,
					config1, offset, pid, 0);
	}

	if (pfd < 0)
		return -1;

	struct bpf_link *link;
	link = calloc(1, sizeof(*link));
	if (!link) {
		return -1;
	}

	link->detach = bpf_link__detach_perf_event;
	link->fd = pfd;

	*ret_link = (void *)link;
	return 0;
}

int program__detach_probe(struct bpf_link *link,
			  bool retprobe,
			  const char *ev_name, const char *event_type)
{
	if (link->detach(link))
		ebpf_info("<%s> detach ev_name:%s, error\n", __func__, ev_name);

	int ret;
	bool is_kprobe = strncmp("kprobe", event_type, 6) == 0;
	if (is_kprobe) {
		ret = bpf_detach_kprobe(ev_name);
	} else {
		ret = bpf_detach_uprobe(ev_name);
	}

	if (ret < 0)
		ebpf_info("<%s> bpf_detach_probe ev_name:%s error.\n", __func__,
			  ev_name);

	free(link);
	return ret;
}

int program__attach_uprobe(void *prog, bool retprobe, pid_t pid,
			   const char *binary_path,
			   size_t func_offset, char *ev_name, void **ret_link)
{
	return program__attach_probe((const struct bpf_program *)prog,
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
	if (retprobe) {
		maxactive = KRETPROBE_MAXACTIVE_MAX;
	}
	return program__attach_probe((const struct bpf_program *)prog,
				     retprobe, (const char *)ev_name, func_name,
				     "kprobe", 0, pid, maxactive, ret_link);
}
