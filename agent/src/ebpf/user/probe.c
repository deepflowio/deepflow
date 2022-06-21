/*
 * Copyright (c) 2015 PLUMgrid, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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

extern int ioctl(int fd, unsigned long request, ...);
extern int setns(int fd, int nstype);
int bpf_get_program_fd(void *obj, const char *prog_name, void **p)
{
	struct bpf_program *prog;
	int prog_fd;
	prog =
	    bpf_object__find_program_by_title((struct bpf_object *)obj,
					      prog_name);
	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		ebpf_info("program not found: %s", strerror(prog_fd));
	}
	*p = prog;
	return prog_fd;
}

static int enter_mount_ns(int pid)
{
	struct stat self_stat, target_stat;
	int self_fd = -1, target_fd = -1;
	char buf[64];

	if (pid < 0)
		return -1;

	if ((size_t) snprintf(buf, sizeof(buf), "/proc/%d/ns/mnt", pid) >=
	    sizeof(buf))
		return -1;

	self_fd = open("/proc/self/ns/mnt", O_RDONLY);
	if (self_fd < 0) {
		perror("open(/proc/self/ns/mnt)");
		return -1;
	}

	target_fd = open(buf, O_RDONLY);
	if (target_fd < 0) {
		perror("open(/proc/<pid>/ns/mnt)");
		goto error;
	}

	if (fstat(self_fd, &self_stat)) {
		perror("fstat(self_fd)");
		goto error;
	}

	if (fstat(target_fd, &target_stat)) {
		perror("fstat(target_fd)");
		goto error;
	}

	if (self_stat.st_ino == target_stat.st_ino)
		goto error;

	if (setns(target_fd, CLONE_NEWNS)) {
		perror("setns(target)");
		goto error;
	}

	close(target_fd);
	return self_fd;

error:
	if (self_fd >= 0)
		close(self_fd);
	if (target_fd >= 0)
		close(target_fd);
	return -1;
}

static void exit_mount_ns(int fd)
{
	if (fd < 0)
		return;

	if (setns(fd, CLONE_NEWNS))
		perror("setns");
	close(fd);
}

static int create_probe_event(char *buf, const char *ev_name,
			      enum bpf_probe_attach_type attach_type,
			      const char *config1, uint64_t offset,
			      const char *event_type, pid_t pid, int maxactive)
{
	int kfd = -1, res = -1, ns_fd = -1;
	char ev_alias[256];
	bool is_kprobe = strncmp("kprobe", event_type, 6) == 0;

	snprintf(buf, PATH_MAX, "/sys/kernel/debug/tracing/%s_events",
		 event_type);
	kfd = open(buf, O_WRONLY | O_APPEND, 0);
	if (kfd < 0) {
		ebpf_info("%s: open(%s): %s\n", __func__, buf,
			strerror(errno));
		return -1;
	}
	res =
	    snprintf(ev_alias, sizeof(ev_alias), "%s_metaflow_%d_%d", ev_name,
		     getpid(), attach_type);
	if (res < 0 || res >= sizeof(ev_alias)) {
		ebpf_info("Event name (%s) is too long for buffer\n",
			ev_name);
		close(kfd);
		goto error;
	}

	if (is_kprobe) {
		if (offset > 0 && attach_type == BPF_PROBE_ENTRY)
			snprintf(buf, PATH_MAX, "p:kprobes/%s %s+%" PRIu64,
				 ev_alias, config1, offset);
		else if (maxactive > 0 && attach_type == BPF_PROBE_RETURN) {
			snprintf(buf, PATH_MAX, "r%d:kprobes/%s %s",
				 maxactive, ev_alias, config1);
		} else
			snprintf(buf, PATH_MAX, "%c:kprobes/%s %s",
				 attach_type == BPF_PROBE_ENTRY ? 'p' : 'r',
				 ev_alias, config1);
	} else {
		res =
		    snprintf(buf, PATH_MAX, "%c:%ss/%s %s:0x%lx",
			     attach_type == BPF_PROBE_ENTRY ? 'p' : 'r',
			     event_type, ev_alias, config1,
			     (unsigned long)offset);

		if (res < 0 || res >= PATH_MAX) {
			ebpf_info("Event alias (%s) too long for buffer\n",
				  ev_alias);
			close(kfd);
			return -1;
		}

		ns_fd = enter_mount_ns(pid);	///< 切换到pid所在的命名空间
	}

	if (write(kfd, buf, strlen(buf)) < 0) {
		if (errno == ENOENT)
			ebpf_info(
				  "\n**__** cannot attach %s, probe entry may not exist\n",
				  event_type);
		else
			ebpf_info(
				  "\nwirte buf : %s ##__## cannot attach %s, %s\n---\n",
				  buf, event_type, strerror(errno));

		close(kfd);
		goto error;
	}

	close(kfd);
	if (!is_kprobe)
		exit_mount_ns(ns_fd);	///< 退回到原来的namespace

	snprintf(buf, PATH_MAX, "/sys/kernel/debug/tracing/events/%ss/%s",
		 event_type, ev_alias);

	return 0;

error:
	if (!is_kprobe)
		exit_mount_ns(ns_fd);

	return -1;
}

int bpf_close_perf_event_fd(int fd)
{
	int res, error = 0;
	if (fd >= 0) {
		res = ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
		if (res != 0) {
			perror("ioctl(PERF_EVENT_IOC_DISABLE) failed");
			error = res;
		}
		res = close(fd);
		if (res != 0) {
			perror("close perf event FD failed");
			error = (res && !error) ? res : error;
		}
	}

	return error;
}

static int bpf_attach_tracing_event(int progfd, const char *event_path, int pid,
				    int *pfd)
{
	int efd, cpu = 0;
	ssize_t bytes;
	char buf[PATH_MAX];
	struct perf_event_attr attr = {};
	if (*pfd < 0) {
		snprintf(buf, sizeof(buf), "%s/id", event_path);
		efd = open(buf, O_RDONLY, 0);
		if (efd < 0) {
			ebpf_info("open(%s): %s\n", buf, strerror(errno));
			return -1;
		}

		bytes = read(efd, buf, sizeof(buf));
		if (bytes <= 0 || bytes >= sizeof(buf)) {
			ebpf_info("read(%s): %s\n", buf, strerror(errno));
			close(efd);
			return -1;
		}
		close(efd);
		buf[bytes] = '\0';
		attr.config = strtol(buf, NULL, 0);	///< event ID
		attr.type = PERF_TYPE_TRACEPOINT;
		attr.sample_period = 1;
		attr.wakeup_events = 1;
		/// PID filter is only possible for uprobe events.
		if (pid < 0)
			pid = -1;

		if (pid != -1)
			cpu = -1;

		*pfd =
		    syscall(__NR_perf_event_open, &attr, pid, cpu, -1,
			    PERF_FLAG_FD_CLOEXEC);
		if (*pfd < 0) {
			return -1;
		}
	}

	if (ioctl(*pfd, PERF_EVENT_IOC_SET_BPF, progfd) < 0) {
		perror("ioctl(PERF_EVENT_IOC_SET_BPF)");
		return -1;
	}

	if (ioctl(*pfd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
		perror("ioctl(PERF_EVENT_IOC_ENABLE)");
		return -1;
	}

	return 0;
}

static int bpf_attach_probe(int progfd, enum bpf_probe_attach_type attach_type,
			    const char *ev_name, const char *config1,
			    const char *event_type, uint64_t offset, pid_t pid,
			    int maxactive)
{

	int kfd, pfd = -1;
	char buf[PATH_MAX], fname[256];
	bool is_kprobe = strncmp("kprobe", event_type, 6) == 0;

	if (pfd < 0) {
		if (create_probe_event
		    (buf, ev_name, attach_type, config1, offset, event_type,
		     pid, maxactive) < 0) {
			goto error;
		}

		if (is_kprobe && maxactive > 0
		    && attach_type == BPF_PROBE_RETURN) {
			if (snprintf(fname, sizeof(fname), "%s/id", buf) >=
			    sizeof(fname)) {
				ebpf_info("filename (%s) is too long for buffer\n",
					  buf);
				goto error;
			}
			if (access(fname, F_OK) == -1) {
				/// Deleting kprobe event with incorrect name.
				kfd =
				    open
				    ("/sys/kernel/debug/tracing/kprobe_events",
				     O_WRONLY | O_APPEND, 0);
				if (kfd < 0) {
					ebpf_info(
						  "open(/sys/kernel/debug/tracing/kprobe_events): %s\n",
						  strerror(errno));
					return -1;
				}
				/// 向"/sys/kernel/debug/tracing/kprobe_events"中写入，"-:kprobes/p_do_exit_0"
				snprintf(fname, sizeof(fname), "-:kprobes/%s_0",
					 ev_name);
				if (write(kfd, fname, strlen(fname)) < 0) {
					if (errno == ENOENT)
						ebpf_info("cannot detach kprobe, probe entry may not exist\n");
					else
						ebpf_info("cannot detach kprobe, %s\n",
							  strerror(errno));
					close(kfd);
					goto error;
				}
				close(kfd);

				if (create_probe_event
				    (buf, ev_name, attach_type, config1, offset,
				     event_type, pid, 0) < 0)
					goto error;
			}
		}
	}

	if (bpf_attach_tracing_event(progfd, buf, pid, &pfd) == 0)
		return pfd;
	else
		ebpf_info("bpf_attach_tracing_event error!\n");

error:
	bpf_close_perf_event_fd(pfd);
	return -1;
}

static int bpf_detach_probe(enum bpf_probe_attach_type attach_type,
			    const char *ev_name,
			    const char *event_type)
{
	int kfd = -1, res;
	char buf[PATH_MAX], line_buf[PATH_MAX];
	int found_event = 0;
	FILE *fp;
	
	snprintf(buf, PATH_MAX, "/sys/kernel/debug/tracing/%s_events",
		 event_type);
	fp = fopen(buf, "r");
	if (!fp) {
		ebpf_info("open(%s): %s\n", buf, strerror(errno));
		goto error;
	}

	/*
	 * e.g:
	 *  ev_name : p___sys_sendmsg
	 *  getpid() : 11723
	 *  attach_type : 0
	 * buf  "p___sys_sendmsg_metaflow_11723_0"
	 */
	res =
	    snprintf(buf, sizeof(buf), "%s_metaflow_%d_%d", ev_name,
		     getpid(), attach_type);

	if (res < 0 || res >= sizeof(buf)) {
		ebpf_info("Event name (%s) is too long for buffer\n",
			  ev_name);
		goto error;
	}

	while (fgets(line_buf, sizeof(line_buf), fp)) {
		if (strstr(line_buf, buf) != NULL) {
			found_event = 1;
			break;
		}
	}

	fclose(fp);
	fp = NULL;

	if (!found_event)
		return 0;

	snprintf(buf, PATH_MAX, "/sys/kernel/debug/tracing/%s_events",
		 event_type);

	kfd = open(buf, O_WRONLY | O_APPEND, 0);
	if (kfd < 0) {
		ebpf_info("open(%s): error %s\n", buf, strerror(errno));
		goto error;
	}

	res =
	    snprintf(buf, sizeof(buf), "-:%s_metaflow_%d_%d", ev_name,
		     getpid(), attach_type);

	if (res < 0 || res >= sizeof(buf)) {
		ebpf_info("snprintf(%s): %d\n", ev_name, res);
		goto error;
	}

	if (write(kfd, buf, strlen(buf)) < 0) {
		ebpf_info("write(%s): %s\n", buf, strerror(errno));
		goto error;
	}

	close(kfd);
	return 0;

error:
	if (kfd >= 0)
		close(kfd);
	if (fp)
		fclose(fp);

	return -1;
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

static int program__attach_probe(const struct bpf_program *prog, bool retprobe, const char *ev_name,	/// perf event name
				 const char *config1,	/// kprobe_func or uprobe_path
				 const char *event_type,	/// "kprobe" or "uprobe"
				 uint64_t offset,	/// kprobe_addr or probe_offset
				 pid_t pid,	/// atttach to pid
				 int maxactive, void **ret_link)
{
	int progfd = bpf_program__fd(prog);
	if (progfd < 0) {
		return -1;
	}

	int pfd = bpf_attach_probe(progfd,
				   retprobe ? BPF_PROBE_RETURN :
				   BPF_PROBE_ENTRY,
				   ev_name, config1, event_type,
				   offset, pid, maxactive);
	if (pfd < 0)
		return -1;

	struct bpf_link *link;
	link = calloc(1, sizeof(*link));
	if (!link) {
		return -1;
	}

	/*
	 * 有两种方式创建：
	 * 1、create the [k,u]probe Perf Event with perf_event_open API(libbpf).
	 *    clear with bpf_link__detach_perf_event(). debugfs auto clear.
	 * 2、create the event using debugfs.
	 *    Kernel doesn't support the perf_kprobe PMU or kretprobe issue.
	 */
	link->detach = bpf_link__detach_perf_event;
	link->fd = pfd;

	*ret_link = (void *)link;
	return 0;
}

static int program__detach_probe(struct bpf_link *link,
				 bool retprobe,
				 const char *ev_name,
				 const char *event_type)
{
	if (link->detach(link))
		ebpf_info("<%s> detach ev_name:%s, error\n", __func__, ev_name);

	int ret = bpf_detach_probe(retprobe ? BPF_PROBE_RETURN : BPF_PROBE_ENTRY,
				   ev_name, event_type);
	if (ret < 0)
		ebpf_info("<%s> bpf_detach_probe ev_name:%s error.\n", __func__, ev_name);

	free(link);
	return 0;
}

int program__attach_uprobe(void *prog, bool retprobe, pid_t pid,
			   const char *binary_path,
			   size_t func_offset, char *ev_name, void **ret_link)
{
	return program__attach_probe((const struct bpf_program *)prog,
				     retprobe, (const char *)ev_name,
				     binary_path, "uprobe", func_offset, pid,
				     KRETPROBE_MAXACTIVE_MAX, ret_link);
}

int program__attach_kprobe(void *prog,
			   bool retprobe,
			   pid_t pid,
			   const char *func_name,
			   char *ev_name, void **ret_link)
{
	return program__attach_probe((const struct bpf_program *)prog,
				     retprobe, (const char *)ev_name, func_name,
				     "kprobe", 0, pid, KRETPROBE_MAXACTIVE_MAX,
				     ret_link);
}

int program__detach_kprobe(struct bpf_link *link,
			   bool retprobe,
			   char *ev_name)
{
	return program__detach_probe(link,
				     retprobe,
				     (const char *)ev_name,
				     "kprobe");
}
