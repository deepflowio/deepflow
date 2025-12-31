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

#define _GNU_SOURCE
#include <ctype.h>
#include <arpa/inet.h>
#include <sched.h>
#include <sys/prctl.h>
#include <arpa/inet.h>
#include <signal.h>
#include <bcc/perf_reader.h>
#include <linux/version.h>
#include "clib.h"
#include "config.h"
#include "symbol.h"
#include "proc.h"
#include "tracer.h"
#include "probe.h"
#include "table.h"
#include "utils.h"
#include "socket.h"
#include "log.h"
#include "go_tracer.h"
#include "ssl_tracer.h"
#include "unwind_tracer.h"
#include "load.h"
#include "btf_core.h"
#include "config.h"
#include "perf_reader.h"
#include "common_utils.h"
#include "extended/extended.h"
#include "trace_utils.h"

#include "socket_trace_bpf_common.c"
#include "socket_trace_bpf_3_10_0.c"
#include "socket_trace_bpf_5_2_plus.c"
#include "socket_trace_bpf_kylin.c"
#include "socket_trace_bpf_kfunc.c"
#include "socket_trace_bpf_rt.c"
#include "socket_trace_bpf_kprobe.c"

static enum linux_kernel_type g_k_type;
static bool use_kfunc_bin;		// Whether to use fentry/fexit binary eBPF bytecode
static struct list_head events_list;	// Use for extra register events
static pthread_t proc_events_pthread;	// Process exec/exit thread
static bool kprobe_feature_disable;	// Whether to disable the kprobe feature?
static bool unix_socket_feature_enable; // Whether to enable the kprobe feature?
static bool virtual_file_collect_enable; // Whether to enable virtual file collect?
/*
 * Control whether to disable the tracing feature.
 * 'true' disables the tracing feature, and 'false' enables it.
 * The default is 'false'.
 */
static bool g_disable_syscall_tracing;

/*
 * tracer_hooks_detach() and tracer_hooks_attach() will become terrible
 * when the number of probes is very large. Because we have to spend a
 * long time waiting for it to complete, this is not a good way, we hope
 * that calling socket_tracer_stop() or socket_tracer_start() will not
 * block the execution of subsequent tasks.
 *
 * In order to solve this problem, we use a global variable(`probes_act`)
 * to hold the latest attach/detach behavior, it be executed later by
 * another thread, so that the current thread will not be blocked.
 */
static volatile uint64_t probes_act;

extern u64 thread_index_max;
extern __thread uword thread_index;	// for symbol pid caches hash
extern int sys_cpus_count;
extern bool *cpu_online;
extern uint32_t attach_failed_count;

static int infer_socktrace_fd;
static uint32_t conf_max_socket_entries;
static uint32_t conf_max_trace_entries;

/*
 * The datadump related Settings
 */
static bool datadump_use_remote;
static debug_callback_t datadump_cb;
static bool datadump_enable;
static int datadump_pid;	// If the value is 0, process-ID/thread-ID filtering is not performed.
static uint32_t datadump_start_time;
/*
 * The sequence number of the socket data is used to label the
 * dumped data for ordering purposes.
 */
static uint64_t datadump_seq;
static uint32_t datadump_timeout;
static char datadump_comm[16];	// If null, process or thread name filtering is not performed.
static uint8_t datadump_proto;
static char datadump_file_path[DATADUMP_FILE_PATH_SIZE];
static FILE *datadump_file;
static pthread_mutex_t datadump_mutex;

/*
 * The maximum amount of data passed to the agent by eBPF programe.
 * Set by set_data_limit_max()
 */
static uint32_t socket_data_limit_max;

static uint32_t go_tracing_timeout = GO_TRACING_TIMEOUT_DEFAULT;

// 0: disable 1: during request 2: all
static uint32_t io_event_collect_mode = 1;
static uint64_t io_event_minimal_duration = 1000000;

/*
 * The maximum threshold for socket map reclamation, with map
 * reclamation occurring if this value is exceeded.
 */
static uint32_t conf_socket_map_max_reclaim;

struct bpf_tracer *g_tracer;
bpf_offset_param_t g_kern_offsets;

/*
 * The table for L7 protocol filtering ports.
 */
ports_bitmap_t *ports_bitmap[PROTO_NUM];

extern uint32_t k_version;
extern int major, minor;
extern char linux_release[128];

extern uint64_t sys_boot_time_ns;
extern uint64_t prev_sys_boot_time_ns;

extern uint64_t adapt_kern_uid;
extern int bpf_raw_tracepoint_open(const char *name, int prog_fd);

static bool bpf_stats_map_collect(struct bpf_tracer *tracer,
				  struct trace_stats *stats_total);
static bool is_adapt_success(struct bpf_tracer *t);
static int update_offsets_table(struct bpf_tracer *t,
				bpf_offset_param_t * offset);
static void datadump_process(void *data, int64_t boot_time);
static bool bpf_stats_map_update(struct bpf_tracer *tracer,
				 int socket_num, int trace_num,
				 int conflict_count,
				 int max_delay,
				 int total_time, int event_count);
static void save_kern_offsets(struct bpf_tracer *t);
static void display_kern_offsets(bpf_offset_param_t *offset);
static bool fentry_try_attach(const char *fn)
{
	int prog_fd, attach_fd;
	char kfunc_name[PROBE_NAME_SZ];
	snprintf(kfunc_name, sizeof(kfunc_name), "kfunc__%s", fn);
	struct bpf_insn insns[] = {
		BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0),	/* r0 = 0 */
		BPF_EXIT_INSN(),
	};

	int stderr_fd = suspend_stderr();
	if (stderr_fd < 0) {
		ebpf_warning("Failed to suspend stderr.\n");
		return false;
	}

	prog_fd = df_prog_load
	    (BPF_PROG_TYPE_TRACING, kfunc_name, insns, sizeof(insns));

	if (prog_fd < 0) {
		resume_stderr(stderr_fd);
		return false;
	}

	attach_fd = bpf_raw_tracepoint_open(NULL, prog_fd);
	if (attach_fd >= 0)
		close(attach_fd);

	close(prog_fd);
	resume_stderr(stderr_fd);

	return attach_fd >= 0;
}

static bool fentry_can_attach(const char *name)
{
	const char *vmlinux_path = "/sys/kernel/btf/vmlinux";
	if (access(vmlinux_path, R_OK))
		return false;

	/*
	 * There is a known bug in the fentry/fexit mechanism, detailed and fixed in
	 * the following commit:
	 * https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=e21d2b92354b3cd25dd774ebb0f0e52ff04a7861
	 *
	 * This bug poses a risk of system crash when attaching or detaching hooks on
	 * certain interfaces. To ensure the current kernel has been patched, we check
	 * for the presence of the function "__bpf_tramp_image_put_rcu", which was
	 * introduced as part of the bug fix. The existence of this function indicates
	 * that the kernel includes the necessary fix. 
	 */ 
	if (kallsyms_lookup_name("__bpf_tramp_image_put_rcu") <= 0) {
		ebpf_info("The current kernel is missing the fix for the fentry/fe"
			  "xit-related bug, will not use fentry/fexit bytecode.\n");
		return false;
	}

	return fentry_try_attach(name);
}

static inline void
kfunc_set_sym_for_entry_and_exit(struct tracer_probes_conf *tps, const char *fn)
{
	kfunc_set_symbol(tps, fn, false);
	kfunc_set_symbol(tps, fn, true);
}

static inline void config_probes_for_proc_event(struct tracer_probes_conf *tps)
{
	if (access(SYSCALL_FORK_TP_PATH, F_OK)) {
		/*
		 * Different CPU architectures have variations in system calls.
		 * It is necessary to confirm whether a specific system call exists.
		 * You can check https://arm64.syscall.sh/ for reference.
		 */
		if (kallsyms_lookup_name("sys_fork"))
			probes_set_exit_symbol(tps, "sys_fork");
		else if (kallsyms_lookup_name("__arm64_sys_fork"))
			probes_set_exit_symbol(tps, "__arm64_sys_fork");
		else if (kallsyms_lookup_name("__x64_sys_fork"))
			probes_set_exit_symbol(tps, "__x64_sys_fork");
	} else {
		tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_fork");
	}

	if (access(SYSCALL_CLONE_TP_PATH, F_OK)) {
		if (kallsyms_lookup_name("sys_clone"))
			probes_set_exit_symbol(tps, "sys_clone");
		else if (kallsyms_lookup_name("__arm64_sys_clone"))
			probes_set_exit_symbol(tps, "__arm64_sys_clone");
		else if (kallsyms_lookup_name("__x64_sys_clone"))
			probes_set_exit_symbol(tps, "__x64_sys_clone");
	} else {
		tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_clone");
	}

	if (access(FTRACE_SCHED_PROC_PATH, F_OK)) {
#if defined(__x86_64__)	
		probes_set_exit_symbol(tps, "__x64_sys_execveat");
		probes_set_exit_symbol(tps, "__x64_sys_execve");
#else
		probes_set_exit_symbol(tps, "__arm64_sys_execveat");
		probes_set_exit_symbol(tps, "__arm64_sys_execve");
#endif
		probes_set_enter_symbol(tps, "do_exit");
	} else {
		tps_set_symbol(tps, "tracepoint/sched/sched_process_exec");
		tps_set_symbol(tps, "tracepoint/sched/sched_process_exit");
	}
}

static void config_probes_for_kfunc(struct tracer_probes_conf *tps)
{
	kfunc_set_sym_for_entry_and_exit(tps, "ksys_write");
	kfunc_set_sym_for_entry_and_exit(tps, "ksys_read");
	kfunc_set_sym_for_entry_and_exit(tps, "__sys_sendto");
	kfunc_set_sym_for_entry_and_exit(tps, "__sys_sendmsg");
	kfunc_set_sym_for_entry_and_exit(tps, "__sys_sendmmsg");
	kfunc_set_sym_for_entry_and_exit(tps, "__sys_recvmsg");
	kfunc_set_sym_for_entry_and_exit(tps, "do_writev");
	kfunc_set_sym_for_entry_and_exit(tps, "do_readv");

#if defined(__x86_64__)
	kfunc_set_symbol(tps, "__x64_sys_close", false);
#else
	kfunc_set_symbol(tps, "__arm64_sys_close", false);
#endif
	kfunc_set_symbol(tps, "__sys_socket", true);
	kfunc_set_symbol(tps, "__sys_accept4", true);
	kfunc_set_symbol(tps, "__sys_connect", false);
	config_probes_for_proc_event(tps);

	/*
	 * On certain kernels, such as 5.15.0-127-generic and 5.10.134-18.al8.x86_64,
	 * `recvmmsg()/recvfrom()` probes of type `kprobe`/`kfunc` may not work properly. To address
	 * this, we use the more stable `tracepoint`-based probe instead.
	 */
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_recvfrom");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_recvfrom");	
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_recvmmsg");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_recvmmsg");

	// Periodic trigger for timeout checks on cached data
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_getppid");

        // file R/W probes
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_pread64");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_preadv");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_pwrite64");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_pwritev");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_pread64");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_preadv");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_pwrite64");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_pwritev");
	if (!access(SYSCALL_PRWV2_TP_PATH, F_OK)) {
		tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_preadv2");
		tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_preadv2");
		tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_pwritev2");
		tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_pwritev2");
	}
}

static void config_probes_for_kprobe_and_tracepoint(struct tracer_probes_conf
						    *tps)
{
	probes_set_enter_symbol(tps, "__sys_sendmsg");
	probes_set_enter_symbol(tps, "__sys_sendmmsg");
	probes_set_enter_symbol(tps, "__sys_recvmsg");

	if (k_version == KERNEL_VERSION(3, 10, 0)) {
		/*
		 * The Linux 3.10 kernel interface for Redhat7 and
		 * Centos7 is sys_writev() and sys_readv()
		 */
		probes_set_enter_symbol(tps, "sys_writev");
		probes_set_enter_symbol(tps, "sys_readv");
	} else {
		probes_set_enter_symbol(tps, "do_writev");
		probes_set_enter_symbol(tps, "do_readv");
	}

	config_probes_for_proc_event(tps);

	/* tracepoints */

	/*
	 * 由于在Linux 4.17+ sys_write, sys_read, sys_sendto, sys_recvfrom
	 * 接口会发生变化为了避免对内核的依赖采用tracepoints方式
	 */
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_write");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_read");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_sendto");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_recvfrom");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_connect");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_recvmmsg");

	// exit tracepoints
	/*
	 * `tracepoint/syscalls/sys_exit_socket` This is currently added only to
	 * implement the NGINX tracing feature. If the tracing feature is disabled,
	 * the syscall socket() interface will not be hooked.
	 */
	if (!g_disable_syscall_tracing)
		tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_socket");
	else
		ebpf_info("Due to the tracing feature being disabled, the"
			  " syscall socket() will not be attached.\n");

	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_read");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_write");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_sendto");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_recvfrom");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_sendmsg");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_sendmmsg");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_recvmsg");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_recvmmsg");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_writev");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_readv");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_accept");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_accept4");
	// clear trace connection & fetch close info
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_close");

	// Periodic trigger for timeout checks on cached data
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_getppid");
	
        // file R/W probes
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_pread64");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_preadv");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_pwrite64");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_pwritev");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_pread64");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_preadv");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_pwrite64");
	tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_pwritev");
	if (!access(SYSCALL_PRWV2_TP_PATH, F_OK)) {
		tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_preadv2");
		tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_preadv2");
		tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_pwritev2");
		tps_set_symbol(tps, "tracepoint/syscalls/sys_exit_pwritev2");
	}
}

static inline void __config_kprobe(struct tracer_probes_conf *tps,
				   const char *name_1,
				   const char *name_2,
				   const char *syscall_name)
{
	/*
	 * In Linux 4.17+, use sys_write, sys_read, sys_sendto, sys_recvfrom;
	 * otherwise, use ksys_write, ksys_read, __sys_sendto, __sys_recvfrom
	 * 
	 */
	if (kallsyms_lookup_name(name_1))
		probes_set_symbol(tps, name_1);
	else if (kallsyms_lookup_name(name_2))
		probes_set_symbol(tps, name_2);
	else
		ebpf_warning("Missing system call '%s()'\n",
			     syscall_name);
}

static void config_probes_for_kprobe(struct tracer_probes_conf *tps)
{
	__config_kprobe(tps, "ksys_write", "sys_write", "write");
	__config_kprobe(tps, "ksys_read", "sys_read", "read");
	__config_kprobe(tps, "__sys_sendto", "sys_sendto", "sendto");
	__config_kprobe(tps, "__sys_recvfrom", "sys_recvfrom", "recvfrom");
	probes_set_symbol(tps, "__sys_sendmsg");
	probes_set_symbol(tps, "__sys_sendmmsg");
	probes_set_symbol(tps, "__sys_recvmsg");
	probes_set_symbol(tps, "__sys_recvmmsg");
	probes_set_symbol(tps, "ksys_pread64");
	probes_set_symbol(tps, "do_preadv");
	probes_set_symbol(tps, "ksys_pwrite64");
	probes_set_symbol(tps, "do_pwritev");

	if (k_version == KERNEL_VERSION(3, 10, 0)) {
		/*
		 * The Linux 3.10 kernel interface for Redhat7 and
		 * Centos7 is sys_writev() and sys_readv()
		 */
		probes_set_symbol(tps, "sys_writev");
		probes_set_symbol(tps, "sys_readv");
	} else {
		probes_set_symbol(tps, "do_writev");
		probes_set_symbol(tps, "do_readv");
	}

	config_probes_for_proc_event(tps);

#if defined(__x86_64__)
	probes_set_enter_symbol(tps, "__x64_sys_getppid");
#else
	if (kallsyms_lookup_name("__arm64_sys_getppid"))
		probes_set_enter_symbol(tps, "__arm64_sys_getppid");
	else
		probes_set_enter_symbol(tps, "sys_getppid");
#endif

	probes_set_exit_symbol(tps, "__sys_accept4");
	probes_set_enter_symbol(tps, "__close_fd");
	probes_set_exit_symbol(tps, "__sys_socket");
	probes_set_enter_symbol(tps, "__sys_connect");
}

static void socket_tracer_set_probes(struct tracer_probes_conf *tps)
{
	if (g_k_type == K_TYPE_KFUNC)
		config_probes_for_kfunc(tps);
	else if (g_k_type == K_TYPE_KPROBE)
		config_probes_for_kprobe(tps);
	else
		config_probes_for_kprobe_and_tracepoint(tps);
}

/* ==========================================================
 * 内核结构成员偏移推断，模拟一个TCP通信tick内核，使其完成推断
 * ==========================================================
 */
static int kernel_offset_infer_server(void)
{
	int cli_fd;
	struct sockaddr_in client_addr;
	socklen_t addr_len = sizeof(client_addr);
	memset(&client_addr, 0, sizeof(struct sockaddr_in));
	int client_count = 0, cpu_online_count = 0, i;
	for (i = 0; i < sys_cpus_count; i++) {
		if (cpu_online[i])
			cpu_online_count++;
	}

next_cpu_client:
	cli_fd =
	    accept(infer_socktrace_fd, (struct sockaddr *)&client_addr,
		   &addr_len);
	if (cli_fd < 0) {
		ebpf_warning("[eBPF Kernel Adapt] Fail to accept client"
			     "request - %s\n", strerror(errno));
		return ETR_IO;
	}

	char buffer[16];
	int len;
	for (;;) {
		len = recv(cli_fd, buffer, sizeof(buffer), 0);
		if (len < 0) {
			continue;
		}

		if (len == 0) {
			client_count++;
			close(cli_fd);
			break;
		}

		buffer[len] = '\0';
		if (strcmp(buffer, "hello") == 0) {
			snprintf(buffer, sizeof(buffer), "OK");
			send(cli_fd, buffer, 2, 0);
		}
	}

	if (client_count < cpu_online_count)
		goto next_cpu_client;

	close(infer_socktrace_fd);
	ebpf_info("[eBPF Kernel Adapt] kernel_offset_infer_server close."
		  "client_count:%d\n", client_count);
	return ETR_OK;
}

static int kernel_offset_infer_client(void)
{
	int cli_fd;
	struct sockaddr_in server_addr;
	char buf[16];
	int len;

	if ((cli_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		ebpf_warning
		    ("[eBPF Kernel Adapt] Fail client create socket - %s\n",
		     strerror(errno));
		return ETR_IO;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(OFFSET_INFER_SERVER_PORT);
	server_addr.sin_addr.s_addr = inet_addr(OFFSET_INFER_SERVER_ADDR);

	if (connect
	    (cli_fd, (struct sockaddr *)&server_addr,
	     sizeof(server_addr)) < 0) {
		ebpf_warning("[eBPF Kernel Adapt] Fail to connect"
			     " - %s\n", strerror(errno));
		return ETR_IO;
	}

	for (;;) {
		snprintf(buf, sizeof(buf), "hello");
		len = send(cli_fd, buf, strlen(buf), 0);
		if (len != strlen(buf))
			continue;
	      rcv_loop:
		len = recv(cli_fd, buf, sizeof(buf), 0);
		if (len > 0) {
			/*
			 * Another send action occurs here to avoid
			 * failure to infer the value of 'write_seq'.
			 * Troubleshoot the invalid kernel adaptation
			 * mechanism in EulerOS 2.9 and EulerOS 2.10
			 * (Linux 4.18).
			 */
			buf[len] = '\0';
			send(cli_fd, buf, len, 0);
			break;
		} else if (len == 0) {
			break;
		} else
			goto rcv_loop;
	}

	close(cli_fd);
	return ETR_OK;
}

static int kernel_offset_infer_init(void)
{
	struct sockaddr_in srv_addr;
	memset(&srv_addr, 0, sizeof(srv_addr));

	infer_socktrace_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (infer_socktrace_fd < 0) {
		ebpf_warning
		    ("[eBPF Kernel Adapt] Fail to create server socket - %s\n",
		     strerror(errno));
		return ETR_IO;
	}

	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(OFFSET_INFER_SERVER_PORT);
	srv_addr.sin_addr.s_addr = inet_addr(OFFSET_INFER_SERVER_ADDR);

	if (-1 ==
	    bind(infer_socktrace_fd, (struct sockaddr *)&srv_addr,
		 sizeof(srv_addr))) {
		ebpf_warning("[eBPF Kernel Adapt] Fail to bind server socket"
			     " %s:%d - %s\n"
			     "Please check the following two situations:\n"
			     "(1) Whether the %s address has been "
			     "configured on the loopback device.\n"
			     "(2) Check if port %d has already been occupied "
			     "by other services.\n\n"
			     "%s:%d is used to trigger a temporary service"
			     " for Linux kernel adaptation. It is important to ensure"
			     " that %s is configured on the lo device and that"
			     " port %d is not occupied by other services.\n\n"
			     "If port %d is occupied by other services, you can either"
			     " change the port number of the other service or wait until"
			     " the deepflow-agent is started before starting this service."
			     "This is because the deepflow-agent only temporarily uses "
			     "port %d during its startup phase and will close the service"
			     "once it is started.\n\n",
			     OFFSET_INFER_SERVER_ADDR,
			     OFFSET_INFER_SERVER_PORT,
			     strerror(errno),
			     OFFSET_INFER_SERVER_ADDR,
			     OFFSET_INFER_SERVER_PORT,
			     OFFSET_INFER_SERVER_ADDR,
			     OFFSET_INFER_SERVER_PORT,
			     OFFSET_INFER_SERVER_ADDR,
			     OFFSET_INFER_SERVER_PORT,
			     OFFSET_INFER_SERVER_PORT,
			     OFFSET_INFER_SERVER_PORT);
		close(infer_socktrace_fd);
		return ETR_IO;
	}

	if (-1 == listen(infer_socktrace_fd, 1)) {
		ebpf_warning
		    ("[eBPF Kernel Adapt] Server socket listen failed - %s\n",
		     strerror(errno));
		close(infer_socktrace_fd);
		return ETR_IO;
	}

	return ETR_OK;
}

static int socktrace_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
	return 0;
}

static bool bpf_offset_map_collect(struct bpf_tracer *tracer,
				   struct bpf_offset_param_array *array)
{
	int nr_cpus = get_num_possible_cpus();
	bpf_offset_param_t values[nr_cpus];
	if (!bpf_table_get_value(tracer, MAP_MEMBERS_OFFSET_NAME, 0, values))
		return false;

	bpf_offset_param_t *out_val = (bpf_offset_param_t *) (array + 1);

	int i;
	for (i = 0; i < array->count; i++)
		out_val[i] = values[i];

	return true;
}

static int socktrace_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
				 void **out, size_t * outsize)
{
	struct bpf_tracer *t = find_bpf_tracer(SK_TRACER_NAME);
	if (t == NULL)
		return -1;

	*outsize = sizeof(struct bpf_socktrace_params) +
	    sizeof(bpf_offset_param_t) * sys_cpus_count;

	*out = calloc(1, *outsize);
	if (*out == NULL) {
		ebpf_warning("calloc, error:%s\n", strerror(errno));
		return -1;
	}

	struct bpf_socktrace_params *params = *out;
	struct bpf_offset_param_array *array = &params->offset_array;
	array->count = sys_cpus_count;

	// Fetch socket Information from eBPF map
	struct ebpf_map *map =
	    ebpf_obj__get_map_by_name(t->obj, MAP_SOCKET_INFO_NAME);
	if (map == NULL) {
		ebpf_warning("[%s] map(name:%s) is NULL.\n", __func__,
			     MAP_SOCKET_INFO_NAME);
	}
	int map_fd = map->fd;
	struct socktrace_msg *msg = (struct socktrace_msg *)conf;
	if (size != sizeof(*msg)) {
		ebpf_warning("The parameter 'socktrace_msg' is passed"
			     "incorrectly with a size mismatch. The passed"
			     " size is %d, while the actual structure length"
			     " is %d.\n", size, sizeof(*msg));
		return -1;
	}
	uint64_t conn_key = (uint64_t)msg->pid << 32 | msg->fd;
	struct socket_info_s info;
	if (bpf_lookup_elem(map_fd, &conn_key, &info) == 0) {
		params->socket_id = info.uid;
		params->seq = info.seq;
		params->l7_proto = info.l7_proto;
		params->data_source = info.data_source;
		params->direction = info.direction;
		params->pre_direction = info.pre_direction;
		params->is_tls = info.is_tls;
		params->peer_fd = info.peer_fd;
		params->prev_data_len = info.prev_data_len;
		params->allow_reassembly = info.allow_reassembly;
		params->finish_reasm = info.finish_reasm;
		params->force_reasm = info.force_reasm;
		params->no_trace = info.no_trace;
		params->reasm_bytes = info.reasm_bytes;
		params->update_time = info.update_time;
	}

	params->kern_socket_map_max = conf_max_socket_entries;
	params->kern_trace_map_max = conf_max_trace_entries;
	params->tracer_state = t->state;

	pthread_mutex_lock(&datadump_mutex);
	params->datadump_enable = datadump_enable;
	params->datadump_pid = datadump_pid;
	params->datadump_proto = datadump_proto;

	params->proc_exec_event_count = get_proc_exec_event_count();
	params->proc_exit_event_count = get_proc_exit_event_count();

	safe_buf_copy(params->datadump_file_path,
		      sizeof(params->datadump_file_path),
		      (void *)datadump_file_path, sizeof(datadump_file_path));
	memcpy(params->datadump_comm, datadump_comm, sizeof(datadump_comm));
	pthread_mutex_unlock(&datadump_mutex);

	struct trace_stats stats_total;

	if (bpf_stats_map_collect(t, &stats_total)) {
		params->kern_socket_map_used = stats_total.socket_map_count;
		params->kern_trace_map_used = stats_total.trace_map_count;
	}

	if (!bpf_offset_map_collect(t, array)) {
		free(*out);
		return -1;
	}

	return 0;
}

static struct tracer_sockopts socktrace_sockopts = {
	.version = SOCKOPT_VERSION,
	.set_opt_min = SOCKOPT_SET_SOCKTRACE_ADD,
	.set_opt_max = SOCKOPT_SET_SOCKTRACE_FLUSH,
	.set = socktrace_sockopt_set,
	.get_opt_min = SOCKOPT_GET_SOCKTRACE_SHOW,
	.get_opt_max = SOCKOPT_GET_SOCKTRACE_SHOW,
	.get = socktrace_sockopt_get,
};

static int datadump_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
	struct datadump_msg *msg = (struct datadump_msg *)conf;
	pthread_mutex_lock(&datadump_mutex);
	if (msg->is_params) {
		datadump_pid = msg->pid;
		datadump_proto = msg->proto;
		safe_buf_copy(datadump_comm, sizeof(datadump_comm),
			      (void *)msg->comm, sizeof(msg->comm));
		ebpf_info("Set datadump pid %d comm %s proto %d\n",
			  datadump_pid, datadump_comm, datadump_proto);
	} else {
		if (!datadump_enable && msg->enable) {
			// create a new output file
			if (datadump_file == stdout && !msg->only_stdout) {
				char *file = gen_file_name_by_datetime();
				if (file != NULL) {
					snprintf(datadump_file_path,
						 sizeof(datadump_file_path),
						 "%s/datadump-%s.log",
						 DATADUMP_FILE_PATH_PREFIX,
						 file);
					free(file);
					datadump_file =
					    fopen(datadump_file_path, "a+");
					if (datadump_file == NULL) {
						memcpy(datadump_file_path,
						       "stdout", 7);
						datadump_file = stdout;
					}
					ebpf_info("create datadump file %s\n",
						  datadump_file_path);
				}
			}
		}

		if (msg->enable) {
			datadump_seq = 0;
			datadump_start_time = get_sys_uptime();
			datadump_timeout = msg->timeout;
		}

		if (datadump_enable && !msg->enable) {
			datadump_seq = 0;
			datadump_timeout = 0;
			datadump_pid = 0;
			datadump_comm[0] = '\0';
			datadump_proto = 0;
			fprintf(datadump_file,
				"\n\nDump data is finished, use time: %us.\n\n",
				get_sys_uptime() - datadump_start_time);
			if (datadump_file != stdout) {
				fclose(datadump_file);
				ebpf_info("close datadump file %s\n",
					  datadump_file_path);
			}
			memcpy(datadump_file_path, "stdout", 7);
			datadump_file = stdout;
			datadump_start_time = 0;
		}

		datadump_enable = msg->enable;
		ebpf_info("datadump %s\n",
			  datadump_enable ? "enable" : "disable");
	}
	pthread_mutex_unlock(&datadump_mutex);
	return 0;
}

static int datadump_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
				void **out, size_t * outsize)
{
	return 0;
}

/*
 * Configure and enable datadump
 *
 * @pid
 *   Specifying a process ID or thread ID. If set to '0', it indicates
 *   all processes or threads.
 * @comm
 *   Specifying a process name or thread name. If set to an empty string(""),
 *   it indicates all processes or threads.
 * @proto
 *   Specifying the L7 protocol number. If set to '0', it indicates all
 *   L7 protocols.
 * @timeout
 *   Specifying the timeout duration. If the elapsed time exceeds this
 *   duration, datadump will stop. The unit is in seconds.
 * @callback
 *   Callback interface, used to transfer data to the remote controller.
 *
 * @return 0 on success, and a negative value on failure.
 */
int datadump_set_config(int pid, const char *comm, int proto, int timeout,
			debug_callback_t cb)
{
	if (pid < 0 || proto < 0 || proto >= PROTO_NUM || comm == NULL
	    || timeout <= 0) {
		ebpf_warning("Invalid parameter\n");
		return -1;
	}

	pthread_mutex_lock(&datadump_mutex);
	if (datadump_enable) {
		ebpf_warning("datadump is already running in the process.\n");
		goto finish;
	}

	datadump_enable = true;
	datadump_use_remote = true;
	datadump_seq = 0;
	datadump_pid = pid;
	datadump_proto = (uint8_t) proto;
	datadump_cb = cb;
	datadump_comm[0] = '\0';
	datadump_start_time = get_sys_uptime();
	datadump_timeout = timeout;
	if (strlen(comm) > 0)
		safe_buf_copy(datadump_comm, sizeof(datadump_comm),
			      (void *)comm, strlen(comm));
	ebpf_info("Set datadump pid %d comm '%s' proto %d\n",
		  datadump_pid, datadump_comm, datadump_proto);

finish:
	pthread_mutex_unlock(&datadump_mutex);
	return 0;
}

static struct tracer_sockopts datadump_sockopts = {
	.version = SOCKOPT_VERSION,
	.set_opt_min = SOCKOPT_SET_DATADUMP_ADD,
	.set_opt_max = SOCKOPT_SET_DATADUMP_OFF,
	.set = datadump_sockopt_set,
	.get_opt_min = SOCKOPT_GET_DATADUMP_SHOW,
	.get_opt_max = SOCKOPT_GET_DATADUMP_SHOW,
	.get = datadump_sockopt_get,
};

static inline int process_exists(pid_t pid)
{
	if (kill(pid, 0) == 0) {
		return 1; // exists, and we have permission
	}

	if (errno == EPERM) {
		ebpf_info("Pid %d exists, but no permission\n", pid);
		return 1;
	}

	return 0; // does not exist
}

static void process_event(struct process_event_t *e)
{
	if (e->meta.event_type == EVENT_TYPE_PROC_EXEC) {
		if (e->maybe_thread && !is_user_process(e->pid))
			return;

		/*
		 * To prevent 'numad' from interfering with the CPU
		 * affinity settings of deepflow-agent, the following
		 * actions are taken:
		 * If deepflow-agent starts before numad, use eBPF
		 * process monitor to detect numad startup and run
		 * "numad -x " to exclude the agent.
		 */
		if (strcmp((const char *)e->name, "numad") == 0 && process_exists(e->pid)) {
			int ret = protect_cpu_affinity_c();
			if (ret == 0)
				ebpf_info("numad(pid %d) found and execution succeeded\n", e->pid);
			else
				ebpf_info("numad(pid %d) execution failed\n", e->pid);
		}

		update_proc_info_cache(e->pid, PROC_EXEC);
		extended_process_exec(e->pid);
	} else if (e->meta.event_type == EVENT_TYPE_PROC_EXIT) {
		/* Cache for updating process information used in
		 * symbol resolution. */
		update_proc_info_cache(e->pid, PROC_EXIT);
		extended_process_exit(e->pid);
	}
}

static inline int dispatch_queue_index(uint64_t val, int count)
{
	return xxhash(val) % count;
}

// Some event types of data are handled by the user using a separate callback interface,
// which completes the dispatch logic after reading the data from the Perf-Reader.
static int register_events_handle(struct reader_forward_info *fwd_info,
				  struct event_meta *meta,
				  int size, struct bpf_tracer *tracer)
{
	// Internal logic processing for process exec/exit.
	if (meta->event_type == EVENT_TYPE_PROC_EXEC ||
	    meta->event_type == EVENT_TYPE_PROC_EXIT) {
		process_event((struct process_event_t *)meta);
	}

	struct extra_event *e;
	void (*fn) (void *) = NULL;
	list_for_each_entry(e, &events_list, list) {
		if (e->type & meta->event_type) {
			fn = e->h;
			break;
		}
	}

	if (fn == NULL) {
		return ETR_NOHANDLE;
	}

	uint64_t q_idx;
	struct queue *q;
	int nr;
	struct mem_block_head *block_head;

	q_idx = fwd_info->queue_id;
	q = &tracer->queues[q_idx];
	block_head = malloc(sizeof(struct mem_block_head) + size);
	if (block_head == NULL) {
		ebpf_warning("block_head alloc memory failed\n");
		return ETR_NOMEM;
	}

	void *data = block_head + 1;
	memcpy(data, meta, size);
	nr = ring_sp_enqueue_burst(q->r, (void **)&data, 1, NULL);
	if (nr < 1) {
		atomic64_add(&q->enqueue_lost, 1);
		free(block_head);
		ebpf_warning("Add ring(q:%d) failed\n", q_idx);
		return ETR_NOROOM;
	}

	block_head->free_ptr = block_head;
	block_head->is_last = 1;
	block_head->fn = fn;

	pthread_mutex_lock(&q->mutex);
	pthread_cond_signal(&q->cond);
	pthread_mutex_unlock(&q->mutex);

	atomic64_add(&q->enqueue_nr, nr);

	return ETR_OK;
}

/**
 * Calculate the extra memory size required when allocating,
 * due to file I/O events and the need to pass mount-related
 * information. These details are obtained in user space and
 * are not stored in the kernel structures, so additional
 * memory must be reserved to hold them.
 */
static inline int get_additional_memory_size(struct __socket_data_buffer *buf)
{
	int i, start = 0, extra_size = 0;
	struct __socket_data *sd;
	for (i = 0; i < buf->events_num; i++) {
		sd = (struct __socket_data *)&buf->data[start];
		if (sd->source == DATA_SOURCE_IO_EVENT) {
			extra_size += (sizeof(struct user_io_event_buffer) - sd->data_len);
		}
		start +=
		    (offsetof(typeof(struct __socket_data), data) +
		     sd->data_len);
	}

	return extra_size;
}	

// Read datas from perf ring-buffer and dispatch.
static void reader_raw_cb(void *cookie, void *raw, int raw_size)
{
#ifdef TLS_DEBUG
	struct debug_data *debug = raw;
	if (debug->magic == 0xffff || debug->magic == 0xfffe) {
		const char *fun;
		if (debug->fun == 1)
			fun = "go_tls_write_enter";
		else if (debug->fun == 2)
			fun = "go_tls_write_exit";
		else if (debug->fun == 3)
			fun = "go_tls_read_enter";
		else if (debug->fun == 4)
			fun = "go_tls_read_exit";
		else
			fun = "unknown";

		const char *err = "";
		if (debug->num == 1 || debug->num == 2)
			err = "(E)";

		if (debug->magic == 0xffff) {
			fprintf(stdout,
				">UPROBE DEBUG nobuf fun %s num %d%s len %d\n",
				fun, debug->num, err, debug->len);
		} else {
			fprintf(stdout,
				">UPROBE DEBUG buf fun %s num %d%s [%d(%c) "
				"%d(%c) %d(%c) %d(%c)]\n", fun, debug->num, err,
				debug->buf[0], debug->buf[0], debug->buf[1],
				debug->buf[1], debug->buf[2], debug->buf[2],
				debug->buf[3], debug->buf[3]);
		}
		fflush(stdout);
		return;
	}
#endif

	struct reader_forward_info *fwd_info = cookie;
	ebpf_debug(stdout, "* fwd cpu %d -> queue %ld\n",
		   fwd_info->cpu_id, fwd_info->queue_id);
	struct bpf_tracer *tracer = g_tracer;
	struct event_meta *ev_meta = raw;

	/*
	 * If 0 < ev_meta->event_type < EVENT_TYPE_MIN is 'socket data buffer'
	 * else if ev_meta->event_type >= EVENT_TYPE_MIN is register events.
	 *
	 * If raw is socket data, 'ev_meta->event_type' indicates the number of events sent by
	 * the kernel in the buffer. The value here must be greater than zero.
	 */
	if (ev_meta->event_type <= 0) {
		return;
	}

	if (ev_meta->event_type >= EVENT_TYPE_MIN) {
		register_events_handle(fwd_info, ev_meta, raw_size, tracer);
		return;
	}

	/*
	 * In the following, the socket data buffer is processed.
	 */

	uint64_t q_idx;
	struct queue *q;
	int nr;
	struct mem_block_head *block_head;	// 申请内存块的指针

	struct __socket_data_buffer *buf = (struct __socket_data_buffer *)raw;
	int data_offset = offsetof(typeof(struct __socket_data_buffer), data);
	if (raw_size < data_offset) {
		ebpf_warning("The amount(%d) of received data is less than the "
			     "minimum value(%d).\n", raw_size, data_offset);
		return;
	}

	if (raw_size < (buf->len + data_offset)) {
		ebpf_warning("There is an error in the received data length."
			     "raw_size %d events_num %u data_len %u.\n",
			     raw_size, buf->events_num, buf->len);
		return;
	}

	if (buf->events_num <= 0 || buf->events_num > MAX_EVENTS_BURST) {
		ebpf_warning("buf->events_num %u, invalid\n", buf->events_num);
		return;
	}

	if (buf->len < (offsetof(typeof(struct __socket_data),
				 data) * buf->events_num)) {
		ebpf_warning("buf->len(%u) invalid, socket data head size %u, "
			     "events_num %u\n", buf->len,
			     offsetof(typeof(struct __socket_data), data),
			     buf->events_num);
		return;
	}

	int i, start = 0;
	struct __socket_data *sd;
	sd = (struct __socket_data *)&buf->data[start];

	/* check uprobe data(GO HTTP2) message type */
	if (sd->source == DATA_SOURCE_GO_HTTP2_UPROBE ||
	    sd->source == DATA_SOURCE_GO_HTTP2_DATAFRAME_UPROBE) {
		if (sd->msg_type == MSG_UNKNOWN)
			return;
	}

	/* Determine which queue to distribute to based on the first socket_data. */
	q_idx = fwd_info->queue_id;
	q = &tracer->queues[q_idx];

	if (buf->events_num > MAX_EVENTS_BURST) {
		ebpf_info
		    ("buf->events_num > MAX_EVENTS_BURST(32) error. events_num:%d\n",
		     buf->events_num);
		return;
	}

	struct socket_bpf_data *burst_data[MAX_EVENTS_BURST];

	/*
	 * ----------- -> memory block ptr (free_ptr)
	 *         |                /\
	 *         |                *
	 * --------------------|    *
	 *      mem_block_head |    *
	 *      >is_last-------|    *   is_last 判断是否是内存块中最后一个socket data,
	 *      >*free_ptr     | ****   如果是释放整个内存。
	 *      ---------------|----> burst enqueue
	 *                     |
	 *      socket_data    |
	 *                     |
	 * --------------------|
	 *         |
	 *         |
	 * ---------
	 */
	struct socket_bpf_data *submit_data;
	int len;
	void *data_buf_ptr;
	char mount_point[MAX_PATH_LENGTH] = {0}, mount_source[MAX_PATH_LENGTH] = {0};
	char root[MAX_PATH_LENGTH] = {0};
	fs_type_t file_type = FS_TYPE_UNKNOWN;

	// 所有载荷的数据总大小（去掉头）
	int alloc_len = buf->len - offsetof(typeof(struct __socket_data),
					    data) * buf->events_num;
	alloc_len += sizeof(*submit_data) * buf->events_num;	// 计算长度包含要提交的数据的头
	alloc_len += sizeof(struct mem_block_head) * buf->events_num;	// 包含内存块head
	alloc_len += sizeof(sd->extra_data) * buf->events_num;	// 可能包含额外数据
	alloc_len += get_additional_memory_size(buf);
	alloc_len = CACHE_LINE_ROUNDUP(alloc_len);	// 保持cache line对齐

	void *socket_data_buff = malloc(alloc_len);
	if (socket_data_buff == NULL) {
		ebpf_warning("malloc() error.\n");
		atomic64_inc(&q->heap_get_failed);
		return;
	}

	data_buf_ptr = socket_data_buff;

	for (i = 0; i < buf->events_num; i++) {
		sd = (struct __socket_data *)&buf->data[start];
		len = sd->data_len;
		block_head = (struct mem_block_head *)data_buf_ptr;
		block_head->is_last = 0;
		block_head->free_ptr = socket_data_buff;
		block_head->fn = NULL;

		data_buf_ptr = block_head + 1;
		submit_data = data_buf_ptr;
		memset(submit_data, 0, sizeof(*submit_data));

		submit_data->timestamp = sd->timestamp;
		submit_data->direction = sd->direction;
		submit_data->fd = sd->fd;
		submit_data->source = sd->source;
		submit_data->cap_data =
		    (char *)((void **)&submit_data->cap_data + 1);
		submit_data->syscall_len = sd->syscall_len;
		submit_data->l7_protocal_hint = sd->data_type;
		submit_data->batch_last_data = false;

		u32 mntns_id = 0;
		u32 self_mntns_id = 0;
		if (sd->source != DATA_SOURCE_DPDK) {
			submit_data->socket_id = sd->socket_id;
			submit_data->tuple = sd->tuple;
			submit_data->tcp_seq = sd->tcp_seq;
			if (sd->source == DATA_SOURCE_UNIX_SOCKET) {
				submit_data->tuple.l4_protocol = IPPROTO_TCP;
				submit_data->tuple.dport = submit_data->tuple.num = 0;
				// 0:unkonwn 1:client(connect) 2:server(accept)
				if (sd->socket_role == 1) {
					submit_data->tuple.dport = 1;
				} else if (sd->socket_role == 2) {
					submit_data->tuple.num = 1;
				}
				submit_data->tuple.addr_len = 4;
				*(in_addr_t *)submit_data->tuple.rcv_saddr = htonl(0x7F000001); 
				*(in_addr_t *)submit_data->tuple.daddr = htonl(0x7F000001);
				submit_data->tcp_seq = 0;
			}

			submit_data->process_id = sd->tgid;
			submit_data->thread_id = sd->pid;
			submit_data->coroutine_id = sd->coroutine_id;
			submit_data->is_tls = sd->is_tls;
			if (sd->source == DATA_SOURCE_GO_TLS_UPROBE ||
			    sd->source == DATA_SOURCE_OPENSSL_UPROBE)
				submit_data->is_tls = true;

			submit_data->cap_seq = sd->data_seq;
			submit_data->syscall_trace_id_call =
			    sd->thread_trace_id;
			int ret = 0;
			kern_dev_t s_dev = DEV_INVALID;
			int mnt_id = 0;
			if (sd->source == DATA_SOURCE_IO_EVENT) {
				struct __io_event_buffer *event =
					(struct __io_event_buffer *)sd->data;
				s_dev = sd->s_dev;
				mnt_id = event->mnt_id;
				mntns_id = event->mntns_id;
			}
			ret = get_proc_info_from_cache(sd->tgid, submit_data->container_id,
						       sizeof(submit_data->container_id),
						       submit_data->process_kname,
						       sizeof(submit_data->process_kname),
						       mnt_id, mntns_id, &self_mntns_id,
						       s_dev, mount_point, mount_source,
						       root, sizeof(mount_point), &file_type);

			// Not found in the process cache, attempting to retrieve from procfs.
			if (ret) {
				fetch_container_id_from_proc(sd->tgid,
							     (char *)submit_data->container_id,
							     sizeof(submit_data->container_id));
			}

			if (submit_data->process_kname[0] == '\0') {
				if (fetch_process_name_from_proc(sd->tgid,
								 (char *)submit_data->process_kname,
								 sizeof(submit_data->process_kname))) {
					safe_buf_copy(submit_data->process_kname,
						      sizeof(submit_data->process_kname),
						      sd->comm, sizeof(sd->comm));
				}
			}

			submit_data->process_kname[sizeof(submit_data->process_kname) -
						   1] = '\0';
			submit_data->container_id[sizeof(submit_data->container_id) -
						   1] = '\0';
			submit_data->msg_type = sd->msg_type;
			submit_data->socket_role = sd->socket_role;
		} else {
			safe_buf_copy(submit_data->process_kname,
				      sizeof(submit_data->process_kname), sd->comm,
				      sizeof(sd->comm));
			submit_data->process_kname[sizeof(submit_data->process_kname) -
						   1] = '\0';
			if (sd->direction == T_EGRESS) {
				atomic64_inc(&tracer->tx_pkts);
				atomic64_add(&tracer->tx_bytes, sd->syscall_len);
			} else {
				atomic64_inc(&tracer->rx_pkts);
				atomic64_add(&tracer->rx_bytes, sd->syscall_len);
			}
		}

		// Statistics of Various Protocols
		if (submit_data->l7_protocal_hint >= PROTO_NUM)
			submit_data->l7_protocal_hint = PROTO_UNKNOWN;

		atomic64_inc(&tracer->proto_stats
			     [submit_data->l7_protocal_hint]);
		int offset = 0;
		if (len > 0) {
			if (sd->extra_data_count > 0) {
				memcpy_fast(submit_data->cap_data,
					    sd->extra_data,
					    sd->extra_data_count);
				offset = sd->extra_data_count;
			}
			if (sd->source == DATA_SOURCE_IO_EVENT) {
				u32 display_mntns_id = 0;
				if (self_mntns_id > 0 && mntns_id != self_mntns_id)
					display_mntns_id = mntns_id;
				len =
				    copy_file_metrics(sd->tgid, submit_data->cap_data
						      + offset, sd->data, len,
						      display_mntns_id, mount_point,
						      mount_source, root, file_type);
			} else {
				memcpy_fast(submit_data->cap_data + offset,
					    sd->data, len);
			}
			submit_data->cap_data[len + offset] = '\0';
		}
		submit_data->syscall_len += offset;
		submit_data->cap_len = len + offset;
		burst_data[i] = submit_data;

		start +=
		    (offsetof(typeof(struct __socket_data), data) +
		     sd->data_len);

		data_buf_ptr += sizeof(*submit_data) + submit_data->cap_len;
	}

	nr = ring_sp_enqueue_burst
	    (q->r, (void **)burst_data, buf->events_num, NULL);

	if (nr < buf->events_num) {
		int lost = buf->events_num - nr;
		atomic64_add(&q->enqueue_lost, lost);
		if (lost == buf->events_num) {
			free(socket_data_buff);
			return;
		}
		int i;
		for (i = nr; i < buf->events_num; i++) {
			if (burst_data[i]->source == DATA_SOURCE_DPDK)
				atomic64_inc(&tracer->dropped_pkts);
		}
	}

	submit_data = burst_data[nr - 1];
	submit_data->batch_last_data = true;
	block_head = (struct mem_block_head *)submit_data - 1;
	block_head->is_last = 1;

	/*
	 * 通知工作线程进行dequeue，并进行数据处理。
	 */
	pthread_mutex_lock(&q->mutex);
	pthread_cond_signal(&q->cond);
	pthread_mutex_unlock(&q->mutex);

	atomic64_add(&q->enqueue_nr, nr);
}

static void reader_lost_cb(void *cookie, uint64_t lost)
{
	struct reader_forward_info *fwd_info = cookie;
	struct bpf_tracer *tracer = fwd_info->tracer;
	atomic64_add(&tracer->lost, lost);
}

static void reclaim_trace_map(struct bpf_tracer *tracer, uint32_t timeout)
{
	struct ebpf_map *map =
	    ebpf_obj__get_map_by_name(tracer->obj, MAP_TRACE_NAME);
	if (map == NULL) {
		ebpf_warning("[%s] map(name:%s) is NULL.\n", __func__,
			     MAP_TRACE_NAME);
		return;
	}
	int map_fd = map->fd;

	struct trace_key_t trace_key = {}, next_trace_key;
	uint32_t reclaim_count = 0;
	struct trace_info_t value;
	uint32_t uptime = get_sys_uptime();
	uint32_t curr_trace_count = 0, limit;
	limit = conf_max_trace_entries * RECLAIM_TRACE_MAP_SCALE;
	struct list_head clear_elem_head;
	init_list_head(&clear_elem_head);

	while (bpf_get_next_key(map_fd, &trace_key, &next_trace_key) == 0) {
		if (bpf_lookup_elem(map_fd, &next_trace_key, &value) == 0) {
			curr_trace_count++;
			if (uptime - value.update_time > timeout &&
			    reclaim_count < limit) {
				if (insert_list(&next_trace_key,
						sizeof(next_trace_key),
						&clear_elem_head)) {
					reclaim_count++;
				}
			}
		}

		trace_key = next_trace_key;
	}

	reclaim_count = __reclaim_map(map_fd, &clear_elem_head);
	// The trace statistics map needs to be updated to reflect the count.   
	curr_trace_count -= reclaim_count;
	if (!bpf_stats_map_update(tracer, -1, curr_trace_count, -1, -1, -1, -1)) {
		ebpf_warning("Update trace statistics failed.\n");
	}

	ebpf_info("[%s] curr_trace_count %u trace map reclaim_count :%u\n",
		  __func__, curr_trace_count, reclaim_count);
}

static void reclaim_socket_map(struct bpf_tracer *tracer, uint32_t timeout)
{
	struct ebpf_map *map =
	    ebpf_obj__get_map_by_name(tracer->obj, MAP_SOCKET_INFO_NAME);
	if (map == NULL) {
		ebpf_warning("[%s] map(name:%s) is NULL.\n", __func__,
			     MAP_SOCKET_INFO_NAME);
		return;
	}
	int map_fd = map->fd;

	uint64_t conn_key, next_conn_key;
	uint32_t sockets_reclaim_count = 0;
	struct socket_info_s value;
	conn_key = 0;
	uint32_t uptime = get_sys_uptime();
	uint32_t curr_socket_count = 0;
	struct list_head clear_elem_head;
	init_list_head(&clear_elem_head);

	while (bpf_get_next_key(map_fd, &conn_key, &next_conn_key) == 0) {
		if (bpf_lookup_elem(map_fd, &next_conn_key, &value) == 0) {
			curr_socket_count++;
			if ((uptime - value.update_time > timeout) &&
			    (sockets_reclaim_count <
			     conf_socket_map_max_reclaim)) {
				if (insert_list(&next_conn_key,
						sizeof(next_conn_key),
						&clear_elem_head)) {
					sockets_reclaim_count++;
				}
			}
		}
		conn_key = next_conn_key;
	}

	sockets_reclaim_count = __reclaim_map(map_fd, &clear_elem_head);
	curr_socket_count -= sockets_reclaim_count;
	if (!bpf_stats_map_update
	    (tracer, curr_socket_count, -1, -1, -1, -1, -1)) {
		ebpf_warning("Update trace statistics failed.\n");
	}

	ebpf_info("[%s] curr_socket_count %u sockets_reclaim_count :%u\n",
		  __func__, curr_socket_count, sockets_reclaim_count);
}

static int check_map_exceeded(void)
{
	struct bpf_tracer *t = find_bpf_tracer(SK_TRACER_NAME);
	if (t == NULL)
		return -1;

	int64_t kern_socket_map_used = 0, kern_trace_map_used = 0;

	struct trace_stats stats_total;

	if (bpf_stats_map_collect(t, &stats_total)) {
		kern_socket_map_used = stats_total.socket_map_count;
		kern_trace_map_used = stats_total.trace_map_count;
	}

	if (kern_socket_map_used >= conf_socket_map_max_reclaim) {
		ebpf_info("Current socket map used %u exceed"
			  " conf_socket_map_max_reclaim %u,reclaim map\n",
			  kern_socket_map_used, conf_socket_map_max_reclaim);
		reclaim_socket_map(t, SOCKET_RECLAIM_TIMEOUT_DEF);
	}

	if (kern_trace_map_used >=
	    (int64_t) (conf_max_trace_entries * RECLAIM_TRACE_MAP_SCALE)) {
		ebpf_info("Current trace map used %u exceed"
			  " reclaim_map_max %u,reclaim map\n",
			  kern_trace_map_used,
			  (uint32_t) (conf_max_trace_entries *
				      RECLAIM_TRACE_MAP_SCALE));
		reclaim_trace_map(t, TRACE_RECLAIM_TIMEOUT_DEF);
	}

	return 0;
}

static inline void add_probes_act(enum probes_act_type type)
{
	probes_act = type;
}

static int check_kern_adapt_and_state_update(void)
{
	struct bpf_tracer *t = find_bpf_tracer(SK_TRACER_NAME);
	if (t == NULL)
		return -1;

	if (is_adapt_success(t) && attach_failed_count == 0) {
		ebpf_info("[eBPF Kernel Adapt] Linux %s adapt success. "
			  "Set the status to TRACER_RUNNING\n", linux_release);
		t->state = TRACER_RUNNING;
		CLIB_MEMORY_BARRIER();
		set_period_event_invalid("check-kern-adapt");
		set_period_event_invalid("trigger_kern_adapt");
		t->adapt_success = true;
		save_kern_offsets(t);
		display_kern_offsets(&g_kern_offsets);
	}

	return 0;
}

static void process_probes_act(struct bpf_tracer *t)
{
	if (probes_act == ACT_NONE)
		return;
	enum probes_act_type type = probes_act;

	/*
	 * Probes attach/detach in multithreading, e.g.:
	 * 1. Snoop go process execute/exit events, then process events(add/remove probes).
	 * 2. Start/stop tracer need process probes.
	 * The above scenario is handled in different threads, so use thread locks for protection.
	 */
	pthread_mutex_lock(&t->mutex_probes_lock);
	// If there is an unfinished attach/detach, return directly.
	if (t->state == TRACER_WAIT_STOP || t->state == TRACER_WAIT_START) {
		ebpf_warning("Current state: %s. There are unfinished tasks.\n",
			     get_tracer_state_name(t->state));
		pthread_mutex_unlock(&t->mutex_probes_lock);
		return;
	}

	if (type == ACT_DETACH && t->state == TRACER_RUNNING) {
		t->state = TRACER_WAIT_STOP;
		ebpf_info("Set current state: TRACER_WAIT_STOP.\n");
		if (tracer_hooks_detach(t) == 0) {
			t->state = TRACER_STOP;
			ebpf_info("Set current state: TRACER_STOP.\n");
		} else {
			t->state = TRACER_STOP_ERR;
			ebpf_warning("Set current state: TRACER_STOP_ERR.\n");
		}
		CLIB_MEMORY_BARRIER();
		// clean socket map
		reclaim_socket_map(t, 0);
	} else if (type == ACT_ATTACH && t->state == TRACER_STOP) {
		t->state = TRACER_WAIT_START;
		ebpf_info("Set current state: TRACER_WAIT_START.\n");
		if (tracer_hooks_attach(t) == 0) {
			t->state = TRACER_RUNNING;
			ebpf_info("Set current state: TRACER_RUNNING.\n");
		} else {
			t->state = TRACER_START_ERR;
			ebpf_warning("Set current state: TRACER_START_ERR.\n");
		}
		CLIB_MEMORY_BARRIER();
	}
	pthread_mutex_unlock(&t->mutex_probes_lock);
}

static void check_datadump_timeout(void)
{
	uint32_t passed_sec;
	pthread_mutex_lock(&datadump_mutex);
	if (datadump_enable) {
		passed_sec = get_sys_uptime() - datadump_start_time;
		if (passed_sec > datadump_timeout) {
			datadump_seq = 0;
			datadump_start_time = 0;
			datadump_enable = false;
			datadump_use_remote = false;
			datadump_pid = 0;
			datadump_comm[0] = '\0';
			datadump_proto = 0;
			fprintf(datadump_file,
				"\n\nDump data is finished, use time: %us.\n\n",
				datadump_timeout);
			if (datadump_file != stdout) {
				ebpf_info("close datadump file %s\n",
					  datadump_file_path);
				fclose(datadump_file);
			}
			memcpy(datadump_file_path, "stdout", 7);
			datadump_file = stdout;
			datadump_timeout = 0;
			ebpf_info("datadump disable\n");
		}
	}
	pthread_mutex_unlock(&datadump_mutex);
}

static inline u64 monotonic_ns()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// Manage process start or exit events.
static void process_events_handle_main(__unused void *arg)
{
	prctl(PR_SET_NAME, "proc-events");
	thread_index = THREAD_PROC_EVENTS_HANDLE_IDX;
	struct bpf_tracer *t = arg;
	u64 proc_last_ts, mnt_last_ts, now_ts;
	proc_last_ts = mnt_last_ts = monotonic_ns();
	const u64 proc_intv_ns = PROCESS_CACHE_UPDATE_INTERVAL_NS;
	const u64 mnt_intv_ns = MOUNT_CACHE_UPDATE_INTERVAL_NS;
	const u32 log_intv = OUTPUT_LOG_INTERVAL_NS / PROCESS_CACHE_UPDATE_INTERVAL_NS;
	u64 count = 0;
	bool output_log;

	for (;;) {
		output_log = false;
		/*
		 * Will attach/detach all probes in the following cases:
		 *
		 * 1 The socket tracer startup phase will transition from TRACER_INIT to TRACER_STOP.
		 * 2 states from TRACER_STOP to TRACER_RUNNIN.
		 * 3 state from TRACER_RUNNING to TRACER_STOP.
		 *
		 * The behavior of attach/detach will take a lot of time, we will store it into
		 * `probes_act` for asynchronous processing.
		 *
		 * Here, handle attach/detach behavior.
		 */
		process_probes_act(t);

		go_process_events_handle();
		ssl_events_handle();
		extended_events_handle();
		unwind_events_handle();
		check_datadump_timeout();
		/* check and clean symbol cache */
		exec_proc_info_cache_update();
		now_ts = monotonic_ns();
		if (now_ts - proc_last_ts >= proc_intv_ns) {
			proc_last_ts = now_ts;
			if (++count % log_intv == 0)
				output_log = true;
			check_and_update_proc_info(output_log);
			collect_mount_info_stats(output_log);
		}

		if (now_ts - mnt_last_ts >= mnt_intv_ns) {
			mnt_last_ts = now_ts;
			check_root_mount_info(output_log);
		}
		
		usleep(LOOP_DELAY_US);
	}
}

static int update_offset_map_default(struct bpf_tracer *t,
				     enum linux_kernel_type kern_type)
{
	bpf_offset_param_t offset;
	memset(&offset, 0, sizeof(offset));

	if (kprobe_feature_disable) {
		offset.kprobe_invalid = 1;
	}

	if (unix_socket_feature_enable) {
		offset.enable_unix_socket = 1;
	}

	switch (kern_type) {
	case K_TYPE_VER_3_10:
		offset.struct_files_struct_fdt_offset = 0x8;
		offset.struct_file_private_data_offset = 0xa8;
		offset.struct_file_f_pos_offset = 0x68;
		offset.struct_ns_common_inum_offset = 0x4;
		break;
	case K_TYPE_KYLIN:
		offset.struct_files_struct_fdt_offset = 0x20;
		offset.struct_file_private_data_offset = 0xc0;
		offset.struct_file_f_pos_offset = 0x60;
		offset.struct_ns_common_inum_offset = 0x10;
		break;
	default:
		offset.struct_files_struct_fdt_offset = 0x20;
		offset.struct_file_private_data_offset = 0xc8;
		offset.struct_file_f_pos_offset = 0x68;
		offset.struct_ns_common_inum_offset = 0x10;
	};

	/*
	 * In Tencent Linux (4.14.105-1-tlinux3-0023.1), there is a difference in
	 * `struct_file_private_data_offset`. If the offset value of the generic
	 * eBPF program is used, it will result in the kernel being unable to adapt.
	 * A separate correction is made here.
	 */
	if (strstr(linux_release, "tlinux3"))
		offset.struct_file_private_data_offset = 0xc0;

	// For 4.19.90-2211.5.0.0178.22.uel20.x86_64
	if (strstr(linux_release, "uel20"))
		offset.struct_file_private_data_offset = 0xc0;

	/*
	 * The corresponding offset is used to access `file->f_op->read_iter`, which
	 * is then used to determine whether the file belongs to a standard VFS
	 * filesystem or is a virtual file.
	 */
	offset.struct_file_f_op_offset = 0x28;
	offset.struct_file_operations_read_iter_offset = 0x20;

	offset.struct_file_f_inode_offset = 0x20;	
	offset.struct_inode_i_mode_offset = 0x0;
	offset.struct_inode_i_sb_offset = 0x28;
	offset.struct_super_block_s_dev_offset = 0x10;
	offset.struct_file_dentry_offset = 0x18;
	offset.struct_dentry_d_parent_offset = 0x18;
	offset.struct_dentry_name_offset = 0x28;
	offset.struct_sock_family_offset = 0x10;
	offset.struct_sock_saddr_offset = 0x4;
	offset.struct_sock_daddr_offset = 0x0;
	offset.struct_sock_ip6saddr_offset = 0x48;
	offset.struct_sock_ip6daddr_offset = 0x38;
	offset.struct_sock_dport_offset = 0xc;
	offset.struct_sock_sport_offset = 0xe;
	offset.struct_sock_skc_state_offset = 0x12;
	offset.struct_sock_common_ipv6only_offset = 0x13;

	/*
	 * Mount information related offsets
	 */ 
	offset.struct_file_f_path_offset      = 0x10;
	offset.struct_path_mnt_offset         = 0x0;
	offset.struct_mount_mnt_offset        = 0x20;
	offset.struct_mount_mnt_ns_offset     = 0xe0;
	offset.struct_mnt_namespace_ns_offset = 0x8; // On Linux 5.11 and later, this value is 0.
	offset.struct_mount_mnt_id_offset     = 0x11c;

	if (update_offsets_table(t, &offset) != ETR_OK) {
		ebpf_error("update_offset_map_default failed.\n");
		return ETR_UPDATE_MAP_FAILD;
	}

	return ETR_OK;
}

static int update_offset_map_from_btf_vmlinux(struct bpf_tracer *t)
{
	struct ebpf_object *obj = t->obj;
	if (DF_IS_ERR_OR_NULL(obj->btf_vmlinux)) {
		ebpf_info("btf_vmlinux is null.\n");
		return ETR_NOTSUPP;
	}

	int copied_seq_offs, write_seq_offs, files_offs, sk_flags_offs;
	copied_seq_offs =
	    kernel_struct_field_offset(obj, "tcp_sock", "copied_seq");
	write_seq_offs =
	    kernel_struct_field_offset(obj, "tcp_sock", "write_seq");
	files_offs = kernel_struct_field_offset(obj, "task_struct", "files");
	sk_flags_offs =
	    kernel_struct_field_offset(obj, "sock", "__sk_flags_offset");

	/*
	 * From linux 5.6+, struct sock has changed(without '__sk_flags_offset[0]').
	 * ...
	 *      u8 sk_padding : 1,
	 *         sk_kern_sock : 1,
	 *         sk_no_check_tx : 1,
	 *         sk_no_check_rx : 1,
	 *         sk_userlocks : 4;
	 *      u8  sk_pacing_shift;
	 *      u16 sk_type;
	 * ...
	 * Ajust:
	 * sk_flags_offs = [sk_pacing_shift offset] - 1;
	 */
	if (sk_flags_offs == ETR_NOTEXIST) {
		sk_flags_offs =
		    kernel_struct_field_offset(obj, "sock", "sk_pacing_shift");
		if (sk_flags_offs > 0) {
			sk_flags_offs -= 1;
		}
	}

	int struct_files_struct_fdt_offset =
	    kernel_struct_field_offset(obj, "files_struct", "fdt");
	int struct_file_private_data_offset =
	    kernel_struct_field_offset(obj, "file", "private_data");
	int struct_file_f_op_offset =
	    kernel_struct_field_offset(obj, "file", "f_op");
	int struct_file_operations_read_iter_offset =
	    kernel_struct_field_offset(obj, "file_operations", "read_iter");
	int struct_file_f_inode_offset =
	    kernel_struct_field_offset(obj, "file", "f_inode");
	int struct_file_f_pos_offset =
	    kernel_struct_field_offset(obj, "file", "f_pos");
	int struct_inode_i_mode_offset =
	    kernel_struct_field_offset(obj, "inode", "i_mode");
	int struct_inode_i_sb_offset =
	    kernel_struct_field_offset(obj, "inode", "i_sb");
	int struct_super_block_s_dev_offset =
	    kernel_struct_field_offset(obj, "super_block", "s_dev");
	int struct_file_dentry_offset_1 =
	    kernel_struct_field_offset(obj, "file", "f_path");
	int struct_file_dentry_offset_2 =
	    kernel_struct_field_offset(obj, "path", "dentry");
	if (struct_file_dentry_offset_1 < 0 || struct_file_dentry_offset_2 < 0) {
		return ETR_NOTSUPP;
	}
	int struct_file_dentry_offset =
	    struct_file_dentry_offset_1 + struct_file_dentry_offset_2;
	int struct_dentry_name_offset_1 =
	    kernel_struct_field_offset(obj, "dentry", "d_name");
	int struct_dentry_name_offset_2 =
	    kernel_struct_field_offset(obj, "qstr", "name");
	if (struct_dentry_name_offset_1 < 0 || struct_dentry_name_offset_2 < 0) {
		return ETR_NOTSUPP;
	}
	int struct_dentry_name_offset =
	    struct_dentry_name_offset_1 + struct_dentry_name_offset_2;
	int struct_dentry_d_parent_offset =
	    kernel_struct_field_offset(obj, "dentry", "d_parent");
	int struct_sock_family_offset =
	    kernel_struct_field_offset(obj, "sock_common", "skc_family");
	int struct_sock_saddr_offset =
	    kernel_struct_field_offset(obj, "sock_common", "skc_rcv_saddr");
	int struct_sock_daddr_offset =
	    kernel_struct_field_offset(obj, "sock_common", "skc_daddr");
	int struct_sock_ip6saddr_offset =
	    kernel_struct_field_offset(obj, "sock_common", "skc_v6_rcv_saddr");
	int struct_sock_ip6daddr_offset =
	    kernel_struct_field_offset(obj, "sock_common", "skc_v6_daddr");
	int struct_sock_dport_offset =
	    kernel_struct_field_offset(obj, "sock_common", "skc_dport");
	int struct_sock_sport_offset =
	    kernel_struct_field_offset(obj, "sock_common", "skc_num");
	int struct_sock_skc_state_offset =
	    kernel_struct_field_offset(obj, "sock_common", "skc_state");
	int struct_sock_common_ipv6only_offset =
	    struct_sock_skc_state_offset + 1;

	// Mount information related offsets
	int struct_file_f_path_offset =
	    kernel_struct_field_offset(obj, "file", "f_path");
	int struct_path_mnt_offset =
	    kernel_struct_field_offset(obj, "path", "mnt");
	int struct_mount_mnt_offset =
	    kernel_struct_field_offset(obj, "mount", "mnt");
	int struct_mount_mnt_ns_offset =
	    kernel_struct_field_offset(obj, "mount", "mnt_ns");
        int struct_mnt_namespace_ns_offset =
	    kernel_struct_field_offset(obj, "mnt_namespace", "ns");
	int struct_ns_common_inum_offset =
	    kernel_struct_field_offset(obj, "ns_common", "inum");
	int struct_mount_mnt_id_offset =
	    kernel_struct_field_offset(obj, "mount", "mnt_id");
	if (copied_seq_offs < 0 || write_seq_offs < 0 || files_offs < 0 ||
	    sk_flags_offs < 0 || struct_files_struct_fdt_offset < 0 ||
	    struct_file_private_data_offset < 0 ||
	    struct_file_f_op_offset < 0 ||
	    struct_file_operations_read_iter_offset < 0 ||
	    struct_file_f_inode_offset < 0 || struct_inode_i_mode_offset < 0 ||
	    struct_inode_i_sb_offset < 0 || 
	    struct_super_block_s_dev_offset < 0 || struct_file_dentry_offset < 0 ||
	    struct_dentry_name_offset < 0 || struct_sock_family_offset < 0 ||
	    struct_sock_saddr_offset < 0 || struct_sock_daddr_offset < 0 ||
	    struct_sock_ip6saddr_offset < 0 ||
	    struct_sock_ip6daddr_offset < 0 || struct_sock_dport_offset < 0 ||
	    struct_sock_sport_offset < 0 || struct_sock_skc_state_offset < 0 ||
	    struct_sock_common_ipv6only_offset < 0 ||
	    struct_dentry_d_parent_offset < 0 || struct_file_f_pos_offset < 0 ||
	    struct_file_f_path_offset < 0 || struct_path_mnt_offset < 0 ||
	    struct_mount_mnt_offset < 0 || struct_mount_mnt_ns_offset < 0 ||
	    struct_mnt_namespace_ns_offset < 0 || struct_ns_common_inum_offset < 0 ||
	    struct_mount_mnt_id_offset < 0) {
		return ETR_NOTSUPP;
	}

	ebpf_info("Offsets from BTF vmlinux:\n");
	ebpf_info("    copied_seq_offs: 0x%x\n", copied_seq_offs);
	ebpf_info("    write_seq_offs: 0x%x\n", write_seq_offs);
	ebpf_info("    files_offs: 0x%x\n", files_offs);
	ebpf_info("    sk_flags_offs: 0x%x\n", sk_flags_offs);
	ebpf_info("    struct_files_struct_fdt_offset: 0x%x\n",
		  struct_files_struct_fdt_offset);
	ebpf_info("    struct_file_private_data_offset: 0x%x\n",
		  struct_file_private_data_offset);
	ebpf_info("    struct_file_f_op_offset: 0x%x\n",
		  struct_file_f_op_offset);
	ebpf_info("    struct_file_operations_read_iter_offset: 0x%x\n",
		  struct_file_operations_read_iter_offset);
	ebpf_info("    struct_file_f_inode_offset: 0x%x\n",
		  struct_file_f_inode_offset);
	ebpf_info("    struct_file_f_pos_offset: 0x%x\n",
		  struct_file_f_pos_offset);
	ebpf_info("    struct_inode_i_mode_offset: 0x%x\n",
		  struct_inode_i_mode_offset);
	ebpf_info("    struct_file_dentry_offset: 0x%x\n",
		  struct_file_dentry_offset);
	ebpf_info("    struct_inode_i_sb_offset: 0x%x\n",
		  struct_inode_i_sb_offset);
	ebpf_info("    struct_super_block_s_dev_offset: 0x%x\n",
		  struct_super_block_s_dev_offset);
	ebpf_info("    struct_dentry_name_offset: 0x%x\n",
		  struct_dentry_name_offset);
	ebpf_info("    struct_dentry_d_parent_offset: 0x%x\n",
		  struct_dentry_d_parent_offset);
	ebpf_info("    struct_sock_family_offset: 0x%x\n",
		  struct_sock_family_offset);
	ebpf_info("    struct_sock_saddr_offset: 0x%x\n",
		  struct_sock_saddr_offset);
	ebpf_info("    struct_sock_daddr_offset: 0x%x\n",
		  struct_sock_daddr_offset);
	ebpf_info("    struct_sock_ip6saddr_offset: 0x%x\n",
		  struct_sock_ip6saddr_offset);
	ebpf_info("    struct_sock_ip6daddr_offset: 0x%x\n",
		  struct_sock_ip6daddr_offset);
	ebpf_info("    struct_sock_dport_offset: 0x%x\n",
		  struct_sock_dport_offset);
	ebpf_info("    struct_sock_sport_offset: 0x%x\n",
		  struct_sock_sport_offset);
	ebpf_info("    struct_sock_skc_state_offset: 0x%x\n",
		  struct_sock_skc_state_offset);
	ebpf_info("    struct_sock_common_ipv6only_offset: 0x%x\n",
		  struct_sock_common_ipv6only_offset);
	ebpf_info("    struct_file_f_path_offset: 0x%x\n",
		  struct_file_f_path_offset);
	ebpf_info("    struct_path_mnt_offset: 0x%x\n",
		  struct_path_mnt_offset);
	ebpf_info("    struct_mount_mnt_offset: 0x%x\n",
		  struct_mount_mnt_offset);
	ebpf_info("    struct_mount_mnt_ns_offset: 0x%x\n",
		  struct_mount_mnt_ns_offset);
	ebpf_info("    struct_mnt_namespace_ns_offset: 0x%x\n",
		  struct_mnt_namespace_ns_offset);
	ebpf_info("    struct_ns_common_inum_offset: 0x%x\n",
		  struct_ns_common_inum_offset);
	ebpf_info("    struct_mount_mnt_id_offset: 0x%x\n",
		  struct_mount_mnt_id_offset);

	bpf_offset_param_t offset;
	memset(&offset, 0, sizeof(offset));
	if (kprobe_feature_disable) {
		offset.kprobe_invalid = 1;
	}

	if (unix_socket_feature_enable) {
		offset.enable_unix_socket = 1;
	}

	offset.ready = 1;
	offset.files_infer_done = 1;
	offset.task__files_offset = files_offs;
	offset.sock__flags_offset = sk_flags_offs;
	offset.tcp_sock__copied_seq_offset = copied_seq_offs;
	offset.tcp_sock__write_seq_offset = write_seq_offs;
	offset.struct_files_struct_fdt_offset = struct_files_struct_fdt_offset;
	offset.struct_file_private_data_offset =
	    struct_file_private_data_offset;
	offset.struct_file_f_op_offset = struct_file_f_op_offset;
	offset.struct_file_operations_read_iter_offset =
	    struct_file_operations_read_iter_offset;
	offset.struct_file_f_inode_offset = struct_file_f_inode_offset;
	offset.struct_file_f_pos_offset = struct_file_f_pos_offset;
	offset.struct_inode_i_mode_offset = struct_inode_i_mode_offset;
	offset.struct_inode_i_sb_offset = struct_inode_i_sb_offset;	
	offset.struct_super_block_s_dev_offset = struct_super_block_s_dev_offset;
	offset.struct_file_dentry_offset = struct_file_dentry_offset;
	offset.struct_dentry_name_offset = struct_dentry_name_offset;
	offset.struct_dentry_d_parent_offset = struct_dentry_d_parent_offset;
	offset.struct_sock_family_offset = struct_sock_family_offset;
	offset.struct_sock_saddr_offset = struct_sock_saddr_offset;
	offset.struct_sock_daddr_offset = struct_sock_daddr_offset;
	offset.struct_sock_ip6saddr_offset = struct_sock_ip6saddr_offset;
	offset.struct_sock_ip6daddr_offset = struct_sock_ip6daddr_offset;
	offset.struct_sock_dport_offset = struct_sock_dport_offset;
	offset.struct_sock_sport_offset = struct_sock_sport_offset;
	offset.struct_sock_skc_state_offset = struct_sock_skc_state_offset;
	offset.struct_sock_common_ipv6only_offset =
	    struct_sock_common_ipv6only_offset;
	offset.struct_file_f_path_offset      = struct_file_f_path_offset;
	offset.struct_path_mnt_offset         = struct_path_mnt_offset;
	offset.struct_mount_mnt_offset        = struct_mount_mnt_offset;
	offset.struct_mount_mnt_ns_offset     = struct_mount_mnt_ns_offset;
	offset.struct_mnt_namespace_ns_offset = struct_mnt_namespace_ns_offset;
	offset.struct_ns_common_inum_offset   = struct_ns_common_inum_offset;
	offset.struct_mount_mnt_id_offset     = struct_mount_mnt_id_offset;

	if (update_offsets_table(t, &offset) != ETR_OK) {
		ebpf_warning("Update offsets map failed.\n");
		return ETR_UPDATE_MAP_FAILD;
	}

	return ETR_OK;
}

static void display_kern_offsets(bpf_offset_param_t * offset)
{
	if (!offset)
		return;

	ebpf_info("member_fields_offset:\n");

	ebpf_info("\tready: 0x%x\n", offset->ready);
	ebpf_info("\tkprobe_invalid: 0x%x\n", offset->kprobe_invalid);
	ebpf_info("\tenable_unix_socket: 0x%x\n", offset->enable_unix_socket);
	ebpf_info("\tfiles_infer_done: 0x%x\n", offset->files_infer_done);
	ebpf_info("\treserved: 0x%x\n", offset->reserved);

	ebpf_info("\tstruct_dentry_d_parent_offset: 0x%x\n",
		  offset->struct_dentry_d_parent_offset);
	ebpf_info("\ttask__files_offset: 0x%x\n", offset->task__files_offset);
	ebpf_info("\tsock__flags_offset: 0x%x\n", offset->sock__flags_offset);
	ebpf_info("\ttcp_sock__copied_seq_offset: 0x%x\n",
		  offset->tcp_sock__copied_seq_offset);
	ebpf_info("\ttcp_sock__write_seq_offset: 0x%x\n",
		  offset->tcp_sock__write_seq_offset);

	ebpf_info("\tstruct_files_struct_fdt_offset: 0x%x\n",
		  offset->struct_files_struct_fdt_offset);
	ebpf_info("\tstruct_file_f_pos_offset: 0x%x\n",
		  offset->struct_file_f_pos_offset);
	ebpf_info("\tstruct_file_private_data_offset: 0x%x\n",
		  offset->struct_file_private_data_offset);
	ebpf_info("\tstruct_file_f_op_offset: 0x%x\n",
		  offset->struct_file_f_op_offset);
	ebpf_info("\tstruct_file_operations_read_iter_offset: 0x%x\n",
		  offset->struct_file_operations_read_iter_offset);
	ebpf_info("\tstruct_file_f_inode_offset: 0x%x\n",
		  offset->struct_file_f_inode_offset);
	ebpf_info("\tstruct_inode_i_mode_offset: 0x%x\n",
		  offset->struct_inode_i_mode_offset);
	ebpf_info("\tstruct_inode_i_sb_offset: 0x%x\n",
		  offset->struct_inode_i_sb_offset);
	ebpf_info("\tstruct_super_block_s_dev_offset: 0x%x\n",
		  offset->struct_super_block_s_dev_offset);
	ebpf_info("\tstruct_file_dentry_offset: 0x%x\n",
		  offset->struct_file_dentry_offset);
	ebpf_info("\tstruct_dentry_name_offset: 0x%x\n",
		  offset->struct_dentry_name_offset);
	ebpf_info("\tstruct_sock_family_offset: 0x%x\n",
		  offset->struct_sock_family_offset);
	ebpf_info("\tstruct_sock_saddr_offset: 0x%x\n",
		  offset->struct_sock_saddr_offset);
	ebpf_info("\tstruct_sock_daddr_offset: 0x%x\n",
		  offset->struct_sock_daddr_offset);
	ebpf_info("\tstruct_sock_ip6saddr_offset: 0x%x\n",
		  offset->struct_sock_ip6saddr_offset);
	ebpf_info("\tstruct_sock_ip6daddr_offset: 0x%x\n",
		  offset->struct_sock_ip6daddr_offset);
	ebpf_info("\tstruct_sock_dport_offset: 0x%x\n",
		  offset->struct_sock_dport_offset);
	ebpf_info("\tstruct_sock_sport_offset: 0x%x\n",
		  offset->struct_sock_sport_offset);
	ebpf_info("\tstruct_sock_skc_state_offset: 0x%x\n",
		  offset->struct_sock_skc_state_offset);
	ebpf_info("\tstruct_sock_common_ipv6only_offset: 0x%x\n",
		  offset->struct_sock_common_ipv6only_offset);

	ebpf_info("\tstruct_file_f_path_offset: 0x%x\n",
		  offset->struct_file_f_path_offset);
	ebpf_info("\tstruct_path_mnt_offset: 0x%x\n",
		  offset->struct_path_mnt_offset);
	ebpf_info("\tstruct_mount_mnt_offset: 0x%x\n",
		  offset->struct_mount_mnt_offset);
	ebpf_info("\tstruct_mount_mnt_ns_offset: 0x%x\n",
		  offset->struct_mount_mnt_ns_offset);
	ebpf_info("\tstruct_mnt_namespace_ns_offset: 0x%x\n",
		  offset->struct_mnt_namespace_ns_offset);
	ebpf_info("\tstruct_ns_common_inum_offset: 0x%x\n",
		  offset->struct_ns_common_inum_offset);
	ebpf_info("\tstruct_mount_mnt_id_offset: 0x%x\n",
		  offset->struct_mount_mnt_id_offset);
}

static void save_kern_offsets(struct bpf_tracer *t)
{
	int i;

	if (sys_cpus_count > 0) {
		bpf_offset_param_t *offset;
		struct bpf_offset_param_array *array =
		    malloc(sizeof(*array) + sizeof(*offset) * sys_cpus_count);
		if (array == NULL) {
			ebpf_warning("malloc() error.\n");
			return;
		}

		array->count = sys_cpus_count;

		if (!bpf_offset_map_collect(t, array)) {
			free(array);
			return;
		}

		offset = (bpf_offset_param_t *) (array + 1);
		for (i = 0; i < sys_cpus_count; i++) {
			if (!cpu_online[i])
				continue;
			g_kern_offsets = offset[i];
			break;
		}

		free(array);
	}
}

static void update_protocol_filter_array(struct bpf_tracer *tracer)
{
	for (int idx = 0; idx < PROTO_NUM; ++idx) {
		bpf_table_set_value(tracer, MAP_PROTO_FILTER_NAME, idx,
				    &ebpf_config_protocol_filter[idx]);
	}
}

static void update_allow_reasm_protos_array(struct bpf_tracer *tracer)
{
	for (int idx = 0; idx < PROTO_NUM; ++idx) {
		bool ret;
		ret = bpf_table_set_value(tracer,
					  MAP_ALLOW_REASM_PROTOS_NAME,
					  idx, &allow_seg_reasm_protos[idx]);
		if (ret) {
			if (allow_seg_reasm_protos[idx]) {
				ebpf_info
				    ("Allow proto %s(%d) segment reassembly\n",
				     get_proto_name(idx), idx);
			}
		} else {
			ebpf_warning
			    ("Set proto %s(%d) to map '%s' failed, %s\n",
			     get_proto_name(idx), idx,
			     MAP_ALLOW_REASM_PROTOS_NAME, strerror(errno));
		}
	}
}

static inline void print_ports_bitmap(struct kprobe_port_bitmap *bmap,
                                      const char *list_name)
{
#define PORTS_STR_SZ 1024

	int i, idx = 0, count = 0;
	uint16_t *ports;
	char ports_str[PORTS_STR_SZ];
	memset(ports_str, 0, sizeof(ports_str));

	for (i = 0; i < PORT_NUM_MAX; i++) {
		if (is_set_bitmap(bmap->bitmap, i))
			count++;
	}

	ports = calloc(count, sizeof(uint16_t));
	if (ports == NULL) {
		ebpf_warning("Memory allocation failed.\n");
		return;
	}

	for (i = 0; i < PORT_NUM_MAX; i++) {
		if (is_set_bitmap(bmap->bitmap, i))
			ports[idx++] = i;
	}

	format_port_ranges(ports, count, ports_str, sizeof(ports_str));
	if (strlen(ports_str) == 0)
		snprintf(ports_str, sizeof(ports_str), "is empty");
	ebpf_info("%s %s\n", list_name, ports_str);
	free(ports);
}

static void update_kprobe_port_bitmap(struct bpf_tracer *tracer)
{
	bpf_table_set_value(tracer, MAP_KPROBE_PORT_BITMAP_NAME, 0,
			    &allow_port_bitmap);
	print_ports_bitmap(&allow_port_bitmap, "Whitelist");
	bpf_table_set_value(tracer, MAP_KPROBE_PORT_BITMAP_NAME, 1,
			    &bypass_port_bitmap);
	print_ports_bitmap(&bypass_port_bitmap, "Blacklist");
}

static void config_proto_ports_bitmap(struct bpf_tracer *tracer)
{
	int i;			// l7 protocol type 
	for (i = 0; i < ARRAY_SIZE(ports_bitmap); i++) {
		if (ports_bitmap[i]) {
			if (bpf_table_set_value
			    (tracer, MAP_PROTO_PORTS_BITMAPS_NAME, i,
			     ports_bitmap[i]))
				ebpf_info
				    ("%s, update eBPF ports_bitmap[%s] success.\n",
				     __func__, get_proto_name(i));
			else
				ebpf_info
				    ("%s, update eBPF ports_bitmap[%s] failed.\n",
				     __func__, get_proto_name(i));
			clib_mem_free(ports_bitmap[i]);
			ports_bitmap[i] = NULL;
		}
	}
}

void insert_adapt_kern_data_to_map(struct bpf_tracer *tracer,
				   int mnt_id, u32 mntns_id)
{
	struct adapt_kern_data val = { 0 };
	val.id = adapt_kern_uid;
	val.mnt_id = mnt_id;
	val.mntns_id = mntns_id;
	bpf_table_set_value(tracer, MAP_ADAPT_KERN_DATA_NAME, 0, &val);
}

static inline int __set_data_limit_max(int limit_size)
{
	if (limit_size < 0) {
		ebpf_warning("limit_size cannot be negative\n");
		return ETR_INVAL;
	} else if (limit_size == 0) {
		socket_data_limit_max = SOCKET_DATA_LIMIT_MAX_DEF;
	} else {
		if (limit_size > BURST_DATA_BUF_SIZE)
			socket_data_limit_max = BURST_DATA_BUF_SIZE;
		else
			socket_data_limit_max = limit_size;
	}

	ebpf_info("Received limit_size (%d), the final value is set to '%d'\n",
		  limit_size, socket_data_limit_max);

	return socket_data_limit_max;
}

/**
 * Set maximum amount of data passed to the agent by eBPF programe.
 * @limit_size : The maximum length of data. If @limit_size exceeds 16384,
 *               it will automatically adjust to 16384 bytes.
 *               If limit_size is 0, Use the default values 4096.
 *
 * @return the set maximum buffer size value on success, < 0 on failure.
 */
int set_data_limit_max(int limit_size)
{
	int set_val = __set_data_limit_max(limit_size);
	if (set_val <= 0)
		return set_val;

	struct bpf_tracer *tracer = find_bpf_tracer(SK_TRACER_NAME);
	if (tracer == NULL) {
		/*
		 * Called before running_socket_tracer(),
		 * no need to update config map
		 */
		return set_val;
	}

	int cpu;
	int nr_cpus = get_num_possible_cpus();
	struct tracer_ctx_s values[nr_cpus];
	memset(values, 0, sizeof(values));

	if (!bpf_table_get_value(tracer, MAP_TRACER_CTX_NAME, 0, values)) {
		ebpf_warning("Get map '%s' failed.\n", MAP_TRACER_CTX_NAME);
		return ETR_NOTEXIST;
	}

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		values[cpu].data_limit_max = set_val;
	}

	if (!bpf_table_set_value
	    (tracer, MAP_TRACER_CTX_NAME, 0, (void *)&values)) {
		ebpf_warning("Set '%s' failed\n", MAP_TRACER_CTX_NAME);
		return ETR_UPDATE_MAP_FAILD;
	}

	tracer->data_limit_max = set_val;

	return set_val;
}

int set_go_tracing_timeout(int timeout)
{
	go_tracing_timeout = timeout;

	struct bpf_tracer *tracer = find_bpf_tracer(SK_TRACER_NAME);
	if (tracer == NULL) {
		return 0;
	}

	int cpu;
	int nr_cpus = get_num_possible_cpus();
	struct tracer_ctx_s values[nr_cpus];
	memset(values, 0, sizeof(values));

	if (!bpf_table_get_value(tracer, MAP_TRACER_CTX_NAME, 0, values)) {
		ebpf_warning("Get map '%s' failed.\n", MAP_TRACER_CTX_NAME);
		return ETR_NOTEXIST;
	}

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		values[cpu].go_tracing_timeout = timeout;
	}

	if (!bpf_table_set_value
	    (tracer, MAP_TRACER_CTX_NAME, 0, (void *)&values)) {
		ebpf_warning("Set '%s' failed\n", MAP_TRACER_CTX_NAME);
		return ETR_UPDATE_MAP_FAILD;
	}

	return 0;
}

int set_io_event_collect_mode(uint32_t mode)
{
	io_event_collect_mode = mode;

	struct bpf_tracer *tracer = find_bpf_tracer(SK_TRACER_NAME);
	if (tracer == NULL) {
		return 0;
	}

	int cpu;
	int nr_cpus = get_num_possible_cpus();
	struct tracer_ctx_s values[nr_cpus];
	memset(values, 0, sizeof(values));

	if (!bpf_table_get_value(tracer, MAP_TRACER_CTX_NAME, 0, values)) {
		ebpf_warning("Get map '%s' failed.\n", MAP_TRACER_CTX_NAME);
		return ETR_NOTEXIST;
	}

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		values[cpu].io_event_collect_mode = io_event_collect_mode;
	}

	if (!bpf_table_set_value
	    (tracer, MAP_TRACER_CTX_NAME, 0, (void *)&values)) {
		ebpf_warning("Set '%s' failed\n", MAP_TRACER_CTX_NAME);
		return ETR_UPDATE_MAP_FAILD;
	}

	ebpf_info("Set io_event_collect_mode %d\n", io_event_collect_mode);
	return 0;
}

int set_io_event_minimal_duration(uint64_t duration)
{
	io_event_minimal_duration = duration;

	struct bpf_tracer *tracer = find_bpf_tracer(SK_TRACER_NAME);
	if (tracer == NULL) {
		return 0;
	}

	int cpu;
	int nr_cpus = get_num_possible_cpus();
	struct tracer_ctx_s values[nr_cpus];
	memset(values, 0, sizeof(values));

	if (!bpf_table_get_value(tracer, MAP_TRACER_CTX_NAME, 0, values)) {
		ebpf_warning("Get map '%s' failed.\n", MAP_TRACER_CTX_NAME);
		return ETR_NOTEXIST;
	}

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		values[cpu].io_event_minimal_duration =
		    io_event_minimal_duration;
	}

	if (!bpf_table_set_value
	    (tracer, MAP_TRACER_CTX_NAME, 0, (void *)&values)) {
		ebpf_warning("Set '%s' failed\n", MAP_TRACER_CTX_NAME);
		return ETR_UPDATE_MAP_FAILD;
	}

	ebpf_info("Set io_event_minimal_duration %llu ns\n", io_event_minimal_duration);
	return 0;
}

int set_virtual_file_collect(bool enabled)
{
	virtual_file_collect_enable = enabled;

	struct bpf_tracer *tracer = find_bpf_tracer(SK_TRACER_NAME);
	if (tracer == NULL) {
		return 0;
	}

	int cpu;
	int nr_cpus = get_num_possible_cpus();
	struct tracer_ctx_s values[nr_cpus];
	memset(values, 0, sizeof(values));

	if (!bpf_table_get_value(tracer, MAP_TRACER_CTX_NAME, 0, values)) {
		ebpf_warning("Get map '%s' failed.\n", MAP_TRACER_CTX_NAME);
		return ETR_NOTEXIST;
	}

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		values[cpu].virtual_file_collect_enabled =
					virtual_file_collect_enable;
	}

	if (!bpf_table_set_value
	    (tracer, MAP_TRACER_CTX_NAME, 0, (void *)&values)) {
		ebpf_warning("Set '%s' failed\n", MAP_TRACER_CTX_NAME);
		return ETR_UPDATE_MAP_FAILD;
	}

	ebpf_info("IO event virtual_file_collect_enable set to %s\n",
		   virtual_file_collect_enable ? "true" : "false");
	return 0;
}

/*
 * Using an eBPF program specifically designed to send data, the goal is to solve the
 * problem of instructions exceeding the maximum limit.
 *
 * Insert eBPF program into the tail calls map.
 */
static void insert_output_prog_to_map(struct bpf_tracer *tracer)
{
	// jmp for tracepoints
	insert_prog_to_map(tracer,
			   MAP_PROGS_JMP_TP_NAME,
			   PROG_PROTO_INFER_2_FOR_TP, PROG_PROTO_INFER_TP_2_IDX);
	insert_prog_to_map(tracer,
			   MAP_PROGS_JMP_TP_NAME,
			   PROG_PROTO_INFER_3_FOR_TP, PROG_PROTO_INFER_TP_3_IDX);
	insert_prog_to_map(tracer,
			   MAP_PROGS_JMP_TP_NAME,
			   PROG_DATA_SUBMIT_NAME_FOR_TP,
			   PROG_DATA_SUBMIT_TP_IDX);
	insert_prog_to_map(tracer,
			   MAP_PROGS_JMP_TP_NAME,
			   PROG_OUTPUT_DATA_NAME_FOR_TP,
			   PROG_OUTPUT_DATA_TP_IDX);
	if (g_k_type != K_TYPE_KPROBE)
		insert_prog_to_map(tracer,
				   MAP_PROGS_JMP_TP_NAME,
				   PROG_IO_EVENT_NAME_FOR_TP,
				   PROG_IO_EVENT_TP_IDX);

	// jmp for kprobe/uprobe
	insert_prog_to_map(tracer,
			   MAP_PROGS_JMP_KP_NAME,
			   PROG_PROTO_INFER_2_FOR_KP, PROG_PROTO_INFER_KP_2_IDX);
	insert_prog_to_map(tracer,
			   MAP_PROGS_JMP_KP_NAME,
			   PROG_PROTO_INFER_3_FOR_KP, PROG_PROTO_INFER_KP_3_IDX);
	insert_prog_to_map(tracer,
			   MAP_PROGS_JMP_KP_NAME,
			   PROG_DATA_SUBMIT_NAME_FOR_KP,
			   PROG_DATA_SUBMIT_KP_IDX);
	insert_prog_to_map(tracer,
			   MAP_PROGS_JMP_KP_NAME,
			   PROG_OUTPUT_DATA_NAME_FOR_KP,
			   PROG_OUTPUT_DATA_KP_IDX);
	if (g_k_type == K_TYPE_KPROBE)
		insert_prog_to_map(tracer,
				   MAP_PROGS_JMP_KP_NAME,
				   PROG_IO_EVENT_NAME_FOR_KP,
				   PROG_IO_EVENT_KP_IDX);
}

/*
 * The work thread retrieves data from the queue and processes it.
 */
static void process_data(void *queue)
{
	prctl(PR_SET_NAME, "queue-worker");
	volatile int nr;
	struct queue *q = (struct queue *)queue;
	struct ring *r = q->r;
	void *rx_burst[MAX_EVENTS_BURST];
	for (;;) {
		nr = ring_sc_dequeue_burst(r, rx_burst, MAX_EVENTS_BURST, NULL);
		if (nr == 0) {
			/*
			 * 等着生产者唤醒
			 */
			pthread_mutex_lock(&q->mutex);
			pthread_cond_wait(&q->cond, &q->mutex);
			pthread_mutex_unlock(&q->mutex);
		} else {
			atomic64_add(&q->dequeue_nr, nr);
			prefetch_and_process_data(q->t, q->id, nr, rx_burst);
			if (nr == MAX_EVENTS_BURST)
				atomic64_inc(&q->burst_count);
		}
	}

	/* never reached */
	/* pthread_exit(NULL); */
	/* return NULL; */
}

#ifdef PERFORMANCE_TEST
static_always_inline uint32_t random_u32(uint32_t * seed)
{
	*seed = (1664525 * *seed) + 1013904223;
	return *seed;
}

static_always_inline uint64_t clib_cpu_time_now(void)
{
	uint32_t a, d;
	asm volatile ("rdtsc":"=a" (a), "=d"(d));
	return (uint64_t) a + ((uint64_t) d << (uint64_t) 32);
}
#endif

static void perf_buffer_read(void *arg)
{
	/*
	 * Each "read" thread has its own independent epoll fd, used
	 * to monitor the perf buffer belonging to its jurisdiction.
	 */
	uint64_t epoll_id = (uint64_t) arg;
	thread_index = THREAD_SOCK_READER_IDX_BASE + epoll_id;	// for bihash
	if (thread_index > thread_index_max)
		thread_index_max = thread_index;
	struct bpf_tracer *tracer = find_bpf_tracer(SK_TRACER_NAME);
	if (tracer == NULL) {
		ebpf_warning("find_bpf_tracer() error\n");
		return;
	}

	struct bpf_perf_reader *perf_reader;
	int i;
	for (;;) {
#ifndef PERFORMANCE_TEST
		for (i = 0; i < tracer->perf_readers_count; i++) {
			perf_reader = &tracer->readers[i];
			struct epoll_event events[perf_reader->readers_count];
			int nfds =
			    reader_epoll_wait(perf_reader, events, epoll_id);
			if (nfds > 0) {
				reader_event_read(events, nfds);
			}
		}
#else
		uint64_t data_len, rand_seed;
		rand_seed = clib_cpu_time_now();
		struct bpf_tracer *tracer = t;
		data_len = random_u32((uint32_t *) & rand_seed) & 0xffff;

		int ring_idx = data_len % tracer->dispatch_workers_nr;
		struct queue *q = &tracer->queues[ring_idx];

		struct socket_bpf_data *prep_data =
		    malloc(sizeof(struct socket_bpf_data) + data_len);
		if (prep_data == NULL) {
			ebpf_waring("malloc() failed, no memory.\n");
			atomic64_inc(&q->heap_get_failed);
			return;
		}
		prep_data->cap_data =
		    (char *)((void **)&prep_data->cap_data + 1);
		prep_data->len = data_len;
		if (!ring_sp_enqueue_burst(q->r, (void **)&prep_data, 1, NULL)) {
			printf("%s, ring_sp_enqueue failed.\n", __func__);
			ebpf_info("%s, ring_sp_enqueue failed.\n", __func__);
			free(prep_data);
			atomic64_inc(&q->enqueue_lost);
		} else {
			pthread_mutex_lock(&q->mutex);
			pthread_cond_signal(&q->cond);
			pthread_mutex_unlock(&q->mutex);
			atomic64_inc(&q->enqueue_nr);
		}
#endif
	}
	/* never reached */
	/* pthread_exit(NULL); */
	/* return NULL; */
}

static int perf_read_workers_setup(struct bpf_tracer *tracer)
{
	int i, ret;
	struct bpf_perf_reader *r = &tracer->readers[0];
	for (i = 0; i < r->epoll_fds_count; i++) {
		ret = enable_tracer_reader_work("sk-reader", i,
						tracer,
						(void *)&perf_buffer_read);
		if (ret)
			return ETR_INVAL;
	}

	return ETR_OK;
}

static int dispatch_workers_setup(struct bpf_tracer *tracer,
				  unsigned int queue_size)
{
	int i, ret;

	if (queue_size <= 0)
		queue_size = RING_SIZE;
	else
		queue_size = 1 << min_log2((unsigned int)queue_size);

	for (i = 0; i < tracer->dispatch_workers_nr; i++) {
		struct ring *r = NULL;
		char name[NAME_LEN];
		snprintf(name, sizeof(name), "%s-ring-%d", tracer->name, i);
		r = ring_create(name, queue_size,
				SOCKET_ID_ANY, RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (r == NULL) {
			ebpf_info("<%s> ring_create fail. err:%s\n", __func__,
				  strerror(errno));
			return -ENOMEM;
		}

		tracer->queues[i].id = i;
		tracer->queues[i].r = r;
		tracer->queues[i].t = tracer;
		tracer->queues[i].nr = 0;
		tracer->queues[i].ring_size = queue_size;

		atomic64_init(&tracer->queues[i].enqueue_lost);
		atomic64_init(&tracer->queues[i].enqueue_nr);
		atomic64_init(&tracer->queues[i].dequeue_nr);
		atomic64_init(&tracer->queues[i].burst_count);
		atomic64_init(&tracer->queues[i].heap_get_failed);

		pthread_mutex_init(&tracer->queues[i].mutex, NULL);
		pthread_cond_init(&tracer->queues[i].cond, NULL);
		ret =
		    pthread_create(&tracer->dispatch_workers[i], NULL,
				   (void *)&process_data,
				   (void *)&tracer->queues[i]);
		if (ret) {
			ebpf_info
			    ("<%s> process_data, pthread_create is error:%s\n",
			     __func__, strerror(errno));
			return ETR_INVAL;
		}
	}

	return ETR_OK;
}

static bool has_ftrace_syscalls(void)
{
	if (access(FTRACE_SYSCALLS_PATH, F_OK) != 0) {
		ebpf_info("Directory %s does not exist.\n",
			  FTRACE_SYSCALLS_PATH);
		return false;
	}

	return true;
}

static int check_dependencies(void)
{
	if (check_kernel_version(4, 14) != 0) {
		return -1;
	}

	return 0;
}

static int select_bpf_binary(char load_name[NAME_LEN], void **bin_buffer,
			     int *bin_buf_size, bool skip_kfunc,
			     bool skip_k_5_2)
{
	void *bpf_bin_buffer;
	int buffer_sz;
	char sys_type_str[16];
	memset(sys_type_str, 0, sizeof(sys_type_str));
	if (fetch_system_type(sys_type_str, sizeof(sys_type_str) - 1) != ETR_OK) {
		ebpf_warning("Fetch system type faild.\n");
	}

	if (!has_ftrace_syscalls()) {
		g_k_type = K_TYPE_KPROBE;
		snprintf(load_name, NAME_LEN, "socket-trace-bpf-linux-kprobe");
		bpf_bin_buffer = (void *)socket_trace_kprobe_ebpf_data;
		buffer_sz = sizeof(socket_trace_kprobe_ebpf_data);
	} else if (is_rt_kernel()) {
		g_k_type = K_TYPE_RT;
		snprintf(load_name, NAME_LEN, "socket-trace-bpf-linux-rt");
		bpf_bin_buffer = (void *)socket_trace_rt_ebpf_data;
		buffer_sz = sizeof(socket_trace_rt_ebpf_data);
	} else if (!skip_kfunc && fentry_can_attach(TEST_KFUNC_NAME)
		   && get_kfunc_params_num(TEST_KFUNC_NAME) ==
		   TEST_KFUNC_PARAMS_NUM) {
		g_k_type = K_TYPE_KFUNC;
		snprintf(load_name, NAME_LEN, "socket-trace-bpf-linux-kfunc");
		bpf_bin_buffer = (void *)socket_trace_kfunc_ebpf_data;
		buffer_sz = sizeof(socket_trace_kfunc_ebpf_data);
	} else if (strcmp(sys_type_str, "ky10") == 0) {
		g_k_type = K_TYPE_KYLIN;
		snprintf(load_name, NAME_LEN, "socket-trace-bpf-linux-kylin");
		bpf_bin_buffer = (void *)socket_trace_kylin_ebpf_data;
		buffer_sz = sizeof(socket_trace_kylin_ebpf_data);
	} else if (!skip_k_5_2 && (major > 5 || (major == 5 && minor >= 2))) {
		g_k_type = K_TYPE_VER_5_2_PLUS;
		snprintf(load_name, NAME_LEN,
			 "socket-trace-bpf-linux-5.2_plus");
		bpf_bin_buffer = (void *)socket_trace_5_2_plus_ebpf_data;
		buffer_sz = sizeof(socket_trace_5_2_plus_ebpf_data);
	} else if (major == 3 && minor == 10) {
		g_k_type = K_TYPE_VER_3_10;
		snprintf(load_name, NAME_LEN, "socket-trace-bpf-linux-3.10.0");
		bpf_bin_buffer = (void *)socket_trace_3_10_0_ebpf_data;
		buffer_sz = sizeof(socket_trace_3_10_0_ebpf_data);
	} else {
		g_k_type = K_TYPE_COMM;
		snprintf(load_name, NAME_LEN, "socket-trace-bpf-linux-common");
		bpf_bin_buffer = (void *)socket_trace_common_ebpf_data;
		buffer_sz = sizeof(socket_trace_common_ebpf_data);
	}

	*bin_buffer = bpf_bin_buffer;
	*bin_buf_size = buffer_sz;
	return 0;
}

static void reconfig_load_resources(struct bpf_tracer *tracer, char *load_name,
				    void *bin_buffer, int buffer_sz,
				    struct tracer_probes_conf *tps)
{
	int i;
	snprintf(tracer->bpf_load_name,
		 sizeof(tracer->bpf_load_name), "%s", load_name);
	tracer->bpf_load_name[sizeof(tracer->bpf_load_name) - 1] = '\0';
	tracer->buffer_ptr = bin_buffer;
	tracer->buffer_sz = buffer_sz;
	for (i = 0; i < tps->kprobes_nr; i++)
		free(tps->ksymbols[i].func);
	tps->kprobes_nr = 0;
	for (i = 0; i < tps->tps_nr; i++)
		free(tps->tps[i].name);
	tps->tps_nr = 0;
	for (i = 0; i < tps->kfuncs_nr; i++)
		free(tps->kfuncs[i].name);
	tps->kfuncs_nr = 0;
	socket_tracer_set_probes(tps);
}

/**
 * Start socket tracer
 *
 * Socket-Tracer is used to get all read/write datas on socket.
 * It also contains some event data related to L7 data, such as process information.
 * These datas are derived from eBPF Kprobe, Uprobe, Tracepoint and other types.
 *
 * Parameters:
 * @handle
 *     Callback interface for upper-layer Application.
 * @thread_nr
 *     Number of worker threads, which refers to the number of user mode threads involved
 *     in data processing, at the same time, it is also the number of threads reading the
 *     perf buffer.
 * @perf_pages_cnt
 *     Number of page frames with kernel shared memory footprint, the value is a power of 2, with page frame size of 4 KB.
 * @queue_size
 *     Ring cache queue size. The value is a power of 2.
 * @max_socket_entries
 *     Sets the maximum number of hash entries for socket tracing, depending on the number of concurrent
 *     requests in actual scenarios.
 * @max_trace_entries
 *     Sets the maximum number of hash entries for thread/coroutine tracing sessions.
 * @socket_map_max_reclaim
 *     Indicates the maximum threshold for clearing socket MAP entries.
 *     If the number of current map entries exceeds this threshold, the MAP will be cleared.
 *
 * @return value: 0 on success, if not 0 is failed
 */
int running_socket_tracer(tracer_callback_t handle,
			  int thread_nr,
			  uint32_t perf_pages_cnt,
			  uint32_t queue_size,
			  uint32_t max_socket_entries,
			  uint32_t max_trace_entries,
			  uint32_t socket_map_max_reclaim)
{
	int ret;
	// Used to record which eBPF buffer was loaded.
	char bpf_load_buffer_name[NAME_LEN];
	void *bpf_bin_buffer;
	int buffer_sz;

	if (sys_cpus_count <= 0) {
		ebpf_warning("sys_cpus_count(%d) <= 0, Please"
			     " prioritize the execution of bpf_tracer_init().\n",
			     sys_cpus_count);
		return -EINVAL;
	}
	// Ensure that the number of worker threads does not exceed the
	// number of CPUs
	if (thread_nr > sys_cpus_count)
		thread_nr = sys_cpus_count;

	if (check_dependencies() != 0) {
		return -EINVAL;
	}

	select_bpf_binary(bpf_load_buffer_name, &bpf_bin_buffer, &buffer_sz,
			  !use_kfunc_bin, false);

	/*
	 * Initialize datadump
	 */
	pthread_mutex_init(&datadump_mutex, NULL);
	datadump_enable = false;
	datadump_use_remote = false;
	memcpy(datadump_file_path, "stdout", 7);
	datadump_file = stdout;

	// Initialize events_list
	if (events_list.next == events_list.prev && events_list.next == NULL) {
		init_list_head(&events_list);
	}

	struct tracer_probes_conf *tps =
	    malloc(sizeof(struct tracer_probes_conf));
	if (tps == NULL) {
		ebpf_warning("malloc() error.\n");
		return -ENOMEM;
	}
	memset(tps, 0, sizeof(*tps));
	init_list_head(&tps->uprobe_syms_head);
	socket_tracer_set_probes(tps);
	golang_trace_init();
	openssl_trace_init();
	create_and_init_proc_info_caches();

	struct bpf_tracer *tracer =
	    setup_bpf_tracer(SK_TRACER_NAME, bpf_load_buffer_name,
			     bpf_bin_buffer, buffer_sz, tps,
			     thread_nr, NULL, NULL, (void *)handle, NULL,
			     0);
	if (tracer == NULL)
		return -EINVAL;

	g_tracer = tracer;
	probes_act = ACT_NONE;
	tracer->adapt_success = false;

	tracer->datadump = datadump_process;

	if ((ret =
	     maps_config(tracer, MAP_SOCKET_INFO_NAME, max_socket_entries)))
		return ret;

	conf_max_socket_entries = max_socket_entries;

	conf_socket_map_max_reclaim = socket_map_max_reclaim;

	if ((ret = maps_config(tracer, MAP_TRACE_NAME, max_trace_entries)))
		return ret;

	conf_max_trace_entries = max_trace_entries;

	bool has_attempted = false;
	while (true) {
		if (tracer_bpf_load(tracer) == 0) {
			// Loading succeeded, exit the loop
			break;
		}

		if (!has_attempted) {
			if (g_k_type == K_TYPE_KFUNC) {
				has_attempted = true;
				select_bpf_binary(bpf_load_buffer_name,
						  &bpf_bin_buffer, &buffer_sz,
						  true, false);
				reconfig_load_resources(tracer,
							bpf_load_buffer_name,
							bpf_bin_buffer,
							buffer_sz, tps);
				continue;	/* Retry the load */
			}

			if (g_k_type == K_TYPE_VER_5_2_PLUS) {
				has_attempted = true;
				select_bpf_binary(bpf_load_buffer_name,
						  &bpf_bin_buffer, &buffer_sz,
						  true, true);
				reconfig_load_resources(tracer,
							bpf_load_buffer_name,
							bpf_bin_buffer,
							buffer_sz, tps);
				continue;	/* Retry the load */
			}
		}

		return -EINVAL;
	}

	/*
	 * create reader for read perf buffer data. 
	 */
	struct bpf_perf_reader *reader;
	reader = create_perf_buffer_reader(tracer,
					   MAP_PERF_SOCKET_DATA_NAME,
					   reader_raw_cb,
					   reader_lost_cb,
					   perf_pages_cnt,
					   thread_nr, PERF_READER_TIMEOUT_DEF);
	if (reader == NULL)
		return -EINVAL;

	if (tracer_probes_init(tracer))
		return -EINVAL;

	// Update kernel offsets map from btf vmlinux file.
	if (update_offset_map_from_btf_vmlinux(tracer) != ETR_OK) {
		ebpf_info
		    ("[eBPF Kernel Adapt] Set offsets map from btf_vmlinux, not support.\n");
		if (update_offset_map_default(tracer, g_k_type) != ETR_OK) {
			ebpf_error
			    ("Fatal error, failed to update default offset\n");
		}
	} else {
		ebpf_info
		    ("[eBPF Kernel Adapt] Set offsets map from btf_vmlinux, success.\n");
	}

	ebpf_info("== Unix domain socket ==\n");

	// Set default maximum amount of data passed to the agent by eBPF.
	if (socket_data_limit_max == 0)
		__set_data_limit_max(0);

	uint64_t uid_base = (gettime(CLOCK_REALTIME, TIME_TYPE_NAN) / 100) &
	    0xffffffffffffffULL;
	if (uid_base == 0)
		return -EINVAL;

	uint16_t cpu;
	struct tracer_ctx_s t_conf[MAX_CPU_NR];
	memset(&t_conf, 0, sizeof(t_conf));
	for (cpu = 0; cpu < MAX_CPU_NR; cpu++) {
		t_conf[cpu].socket_id = (uint64_t) cpu << 56 | uid_base;
		t_conf[cpu].coroutine_trace_id = t_conf[cpu].socket_id;
		t_conf[cpu].thread_trace_id = t_conf[cpu].socket_id;
		t_conf[cpu].data_limit_max = socket_data_limit_max;
		t_conf[cpu].io_event_collect_mode = io_event_collect_mode;
		t_conf[cpu].io_event_minimal_duration =
		    io_event_minimal_duration;
		t_conf[cpu].virtual_file_collect_enabled = virtual_file_collect_enable;
		t_conf[cpu].disable_tracing = g_disable_syscall_tracing;
		if (!g_disable_syscall_tracing)
			t_conf[cpu].go_tracing_timeout = go_tracing_timeout;
	}

	if (!bpf_table_set_value
	    (tracer, MAP_TRACER_CTX_NAME, 0, (void *)&t_conf))
		return -EINVAL;

	ebpf_info("Config socket_data_limit_max: %d\n", socket_data_limit_max);
	ebpf_info("Config io_event_collect_mode: %d\n", io_event_collect_mode);
	ebpf_info("Config io_event_minimal_duration: %llu ns\n", io_event_minimal_duration);
	ebpf_info("Config virtual_file_collect_enable: %d\n", virtual_file_collect_enable);
	ebpf_info("Config g_disable_syscall_tracing: %d\n", g_disable_syscall_tracing);
	ebpf_info("Config go_tracing_timeout: %d\n", go_tracing_timeout);

	tracer->data_limit_max = socket_data_limit_max;

	// Insert prog of output data into map for using BPF Tail Calls.
	insert_output_prog_to_map(tracer);

	// Insert the unique identifier of the adaptation kernel into the map
	insert_adapt_kern_data_to_map(tracer, 0, 0);

	// Update protocol filter array
	update_protocol_filter_array(tracer);

	// Update '__allow_reasm_protos_map'
	update_allow_reasm_protos_array(tracer);

	update_kprobe_port_bitmap(tracer);

	// Configure l7 protocol ports
	config_proto_ports_bitmap(tracer);

	/*
	 * Enable periodic perf events and periodically poll to push
	 * socket data residing in the kernel to a user-space program.
	 */
	tracer->enable_sample = true;

	if (tracer_hooks_attach(tracer))
		return -EINVAL;

	if ((ret = dispatch_workers_setup(tracer, queue_size)))
		return ret;

	if ((ret = perf_read_workers_setup(tracer)))
		return ret;

	// use for inference struct offset.
	if (kernel_offset_infer_init() != ETR_OK)
		return -EINVAL;

	if ((ret = register_extra_waiting_op("offset-infer-server",
					     kernel_offset_infer_server,
					     EXTRA_TYPE_SERVER)))
		return ret;

	if ((ret = register_extra_waiting_op("offset-infer-client",
					     kernel_offset_infer_client,
					     EXTRA_TYPE_CLIENT)))
		return ret;

	if ((ret = register_extra_waiting_op("mount-offset-infer",
					     mount_offset_infer,
					     EXTRA_TYPE_CLIENT)))
		return ret;

	if ((ret =
	     register_period_event_op("check-map-exceeded",
				      check_map_exceeded,
				      CHECK_MAP_EXCEEDED_PERIOD)))
		return ret;

	if ((ret =
	     register_period_event_op("check-kern-adapt",
				      check_kern_adapt_and_state_update,
				      CHECK_KERN_ADAPT_PERIOD)))
		return ret;

	if ((ret = sockopt_register(&socktrace_sockopts)) != ETR_OK)
		return ret;

	if ((ret = sockopt_register(&datadump_sockopts)) != ETR_OK)
		return ret;
	ret =
	    pthread_create(&proc_events_pthread, NULL,
			   (void *)&process_events_handle_main, (void *)tracer);
	if (ret) {
		ebpf_warning
		    ("proc_events_pthread, pthread_create is error:%s\n",
		     strerror(errno));
		return ret;
	}

	return 0;
}

int socket_tracer_stop(void)
{
	int ret = -1;
	struct bpf_tracer *t = find_bpf_tracer(SK_TRACER_NAME);
	if (t == NULL)
		return ret;
	if (t->state == TRACER_INIT) {
		ebpf_warning
		    ("[eBPF Kernel Adapt] Adapting the linux kernel(%s) is in "
		     "progress, please try the stop operation again later.\n",
		     linux_release);
		return -1;
	}

	if (probes_act == ACT_DETACH) {
		ebpf_warning
		    ("The latest probes_act is already ACT_DETACH, without operating.\n");

		return 0;
	}

	ebpf_info("Call socket_tracer_stop()\n");
	add_probes_act(ACT_DETACH);
	return 0;
}

int socket_tracer_start(void)
{
	int ret = -1;
	struct bpf_tracer *t = find_bpf_tracer(SK_TRACER_NAME);
	if (t == NULL)
		return ret;

	if (t->state == TRACER_INIT) {
		ebpf_warning
		    ("[eBPF Kernel Adapt] Adapting the linux kernel(%s) "
		     "is in progress, please try "
		     "the start operation again later.\n", linux_release);
		return -1;
	}

	if (probes_act == ACT_ATTACH) {
		ebpf_warning
		    ("The latest probes_act already ACT_ATTACH, without operating.\n");
		return 0;
	}

	ebpf_info("Call socket_tracer_start()\n");
	add_probes_act(ACT_ATTACH);

	return 0;
}

enum tracer_state __unused get_socket_tracer_state(void)
{
	struct bpf_tracer *t = find_bpf_tracer(SK_TRACER_NAME);
	if (t == NULL)
		return TRACER_STOP_ERR;

	return t->state;
}

static bool bpf_stats_map_collect(struct bpf_tracer *tracer,
				  struct trace_stats *stats_total)
{
	struct trace_stats value = { 0 };
	if (!bpf_table_get_value(tracer, MAP_TRACE_STATS_NAME, 0, &value))
		return false;

	memset(stats_total, 0, sizeof(*stats_total));
	stats_total->socket_map_count = value.socket_map_count;
	stats_total->trace_map_count = value.trace_map_count;
	stats_total->push_conflict_count = value.push_conflict_count;
	stats_total->period_event_max_delay = value.period_event_max_delay;
	stats_total->period_event_total_time = value.period_event_total_time;
	stats_total->period_event_count = value.period_event_count;
	return true;
}

static bool bpf_stats_map_update(struct bpf_tracer *tracer,
				 int socket_num, int trace_num,
				 int conflict_count,
				 int max_delay, int total_time, int event_count)
{
	struct trace_stats value = { 0 };
	if (!bpf_table_get_value(tracer, MAP_TRACE_STATS_NAME, 0, &value))
		return false;

	if (socket_num != -1)
		value.socket_map_count = socket_num;

	if (trace_num != -1)
		value.trace_map_count = trace_num;

	if (conflict_count != -1)
		value.push_conflict_count = conflict_count;

	if (total_time != -1)
		value.period_event_max_delay = max_delay;

	if (total_time != -1)
		value.period_event_total_time = total_time;

	if (event_count != -1)
		value.period_event_count = event_count;

	if (!bpf_table_set_value(tracer,
				 MAP_TRACE_STATS_NAME, 0, (void *)&value)) {
		return false;
	}

	return true;
}

// Update offsets tables for all cpus
static int update_offsets_table(struct bpf_tracer *t,
				bpf_offset_param_t * offset)
{
	int nr_cpus = get_num_possible_cpus();
	bpf_offset_param_t offs[nr_cpus];
	int i;
	memset(&offs, 0, sizeof(offs));
	for (i = 0; i < nr_cpus; i++) {
		offs[i] = *offset;
	}

	if (!bpf_table_set_value(t, MAP_MEMBERS_OFFSET_NAME, 0, (void *)&offs))
		return ETR_UPDATE_MAP_FAILD;

	return ETR_OK;
}

static bool is_adapt_success(struct bpf_tracer *t)
{
	bool is_success = false;
	int i;

	if (sys_cpus_count > 0) {
		bpf_offset_param_t *offset;
		struct bpf_offset_param_array *array =
		    malloc(sizeof(*array) + sizeof(*offset) * sys_cpus_count);
		if (array == NULL) {
			ebpf_warning("malloc() error.\n");
			return false;
		}

		array->count = sys_cpus_count;

		if (!bpf_offset_map_collect(t, array)) {
			free(array);
			return false;
		}

		offset = (bpf_offset_param_t *) (array + 1);
		for (i = 0; i < sys_cpus_count; i++) {
			if (!cpu_online[i])
				continue;
			if (offset[i].ready == 1) {
				// Update all cpus offset map.
				if (update_offsets_table(t, &offset[i]) ==
				    ETR_OK) {
					is_success = true;
				} else {
					is_success = false;
				}

				break;
			}
		}

		free(array);
	}

	return is_success;
}

static u64 prev_stats[STATS_TYPE_NUM];
static u64 update_pkts_stats(struct bpf_tracer *t, enum pkts_stats_type type)
{
	u64 curr_num, diff;
	if (!bpf_table_get_value
	    (t, MAP_PKTS_STATES_NAME, type, (void *)&curr_num))
		curr_num = prev_stats[type];

	if (prev_stats[type] == 0)
		prev_stats[type] = curr_num;

	diff = curr_num - prev_stats[type];
	prev_stats[type] = curr_num;

	return diff;
}

static void pkts_stats(struct bpf_tracer *t, struct socket_trace_stats *stats)
{
	if (bpf_table_get_fd(t, MAP_PKTS_STATES_NAME) == -1) {
		stats->rx_packets = 0;
		stats->tx_packets = 0;
		stats->rx_bytes = 0;
		stats->tx_bytes = 0;
		stats->dropped_packets = 0;
		stats->kern_missed_packets = 0;
		stats->invalid_packets = 0;
		return;
	}

	stats->rx_packets = atomic64_read(&t->rx_pkts);
	stats->tx_packets = atomic64_read(&t->tx_pkts);
	stats->rx_bytes = atomic64_read(&t->rx_bytes);
	stats->tx_bytes = atomic64_read(&t->tx_bytes);
	stats->dropped_packets = atomic64_read(&t->dropped_pkts);
	stats->kern_missed_packets = update_pkts_stats(t, STATS_MISS_PKTS);
	stats->invalid_packets = update_pkts_stats(t, STATS_INVAL_PKTS);

	atomic64_init(&t->rx_pkts);
	atomic64_init(&t->tx_pkts);
	atomic64_init(&t->rx_bytes);
	atomic64_init(&t->tx_bytes);
	atomic64_init(&t->dropped_pkts);
}

struct socket_trace_stats socket_tracer_stats(void)
{
	struct socket_trace_stats stats;
	memset(&stats, 0, sizeof(stats));

	struct bpf_tracer *t = find_bpf_tracer(SK_TRACER_NAME);
	if (t == NULL)
		return stats;

	stats.kern_lost = atomic64_read(&t->lost);
	atomic64_init(&t->lost);
	stats.worker_num = t->dispatch_workers_nr;
	stats.perf_pages_cnt = t->readers[0].perf_pages_cnt;
	stats.queue_capacity = t->queues[0].ring_size;
	stats.kern_socket_map_max = conf_max_socket_entries;
	stats.kern_trace_map_max = conf_max_trace_entries;
	stats.socket_map_max_reclaim = conf_socket_map_max_reclaim;
	stats.probes_count = t->probes_count;
	stats.data_limit_max = socket_data_limit_max;
	pkts_stats(t, &stats);

	static int skip_count = 2;
	static int curr_count = 0;
	struct trace_stats stats_total;
	memset(&stats_total, 0, sizeof(stats_total));
	if (bpf_stats_map_collect(t, &stats_total)) {
		stats.kern_socket_map_used = stats_total.socket_map_count;
		stats.kern_trace_map_used = stats_total.trace_map_count;
		stats.period_push_conflict_count =
		    stats_total.push_conflict_count;
		if (stats_total.period_event_total_time > 0
		    && stats_total.period_event_count > 0)
			stats.period_push_avg_delay =
			    (stats_total.period_event_total_time /
			     stats_total.period_event_count) / NS_IN_USEC;

		if (stats_total.period_event_max_delay > 0) {
			stats.period_push_max_delay =
			    PUSH_DELAY_EXCEEDED_MARKER;
		} else {
			stats.period_push_max_delay =
			    stats.period_push_avg_delay;
		}

		if (curr_count++ < skip_count) {
			stats.period_push_max_delay = 0;
			stats.period_push_avg_delay = 0;
		}

		if (!bpf_stats_map_update(t, -1, -1, 0, 0, 0, 0)) {
			ebpf_warning("Update trace statistics failed.\n");
		}
	}

	int i;
	for (i = 0; i < t->dispatch_workers_nr; i++) {
		stats.user_enqueue_lost +=
		    atomic64_read(&t->queues[i].enqueue_lost);
		stats.user_enqueue_count +=
		    atomic64_read(&t->queues[i].enqueue_nr);
		stats.user_dequeue_count +=
		    atomic64_read(&t->queues[i].dequeue_nr);
		stats.queue_burst_count +=
		    atomic64_read(&t->queues[i].burst_count);
		stats.mem_alloc_fail_count +=
		    atomic64_read(&t->queues[i].heap_get_failed);

		atomic64_init(&t->queues[i].enqueue_lost);
		atomic64_init(&t->queues[i].enqueue_nr);
		atomic64_init(&t->queues[i].dequeue_nr);
		atomic64_init(&t->queues[i].heap_get_failed);
	}

	stats.is_adapt_success = t->adapt_success;
	stats.tracer_state = t->state;

	// 相邻两次系统启动时间更新后的差值
	stats.boot_time_update_diff = sys_boot_time_ns - prev_sys_boot_time_ns;

	stats.proc_exec_event_count = get_proc_exec_event_count();
	stats.proc_exit_event_count = get_proc_exit_event_count();
	clear_proc_exec_event_count();
	clear_proc_exit_event_count();

	return stats;
}

/**
 * Register extra event handle.
 *
 * Parameter:
 * @type Event type
 * @fn Callback function
 *
 * @return 0 is success, if not 0 is failed
 */
int register_event_handle(uint32_t type, void (*fn) (void *))
{
	if (type < EVENT_TYPE_MIN || fn == NULL) {
		ebpf_warning("Parameter is invalid, type %d fn %p\n", type, fn);
		return -1;
	}

	struct list_head *events_head;
	events_head = &events_list;
	// Initialize events_list
	if (events_head->next == events_head->prev && events_head->next == NULL) {
		init_list_head(events_head);
	}

	struct extra_event *event = calloc(1, sizeof(struct extra_event));
	if (event == NULL) {
		ebpf_warning("calloc() is failed.\n");
		return -1;
	}

	event->type = type;
	event->h = fn;

	list_add_tail(&event->list, events_head);

	return 0;
}

// -------------------------------------
// 协议测试
// -------------------------------------

int print_uprobe_http2_info(const char *data, int len, char *buf, int buf_len)
{
	struct {
		__u32 fd;
		__u32 stream_id;
		__u32 header_len;
		__u32 value_len;
	} __attribute__ ((packed)) header;

	int bytes = 0;
	char key[1024] = { 0 };
	char value[1024] = { 0 };
	memcpy(&header, data, sizeof(header));
	if (datadump_enable) {
		bytes +=
		    snprintf(buf + bytes, buf_len - bytes,
			     "fd=[%d]\nstream_id=[%d]\n", header.fd,
			     header.stream_id);

	} else {
		fprintf(stdout, "fd=[%d]\nstream_id=[%d]\n", header.fd,
			header.stream_id);
	}

	const int value_start = sizeof(header) + header.header_len;

	header.header_len = header.header_len < 1024 ? header.header_len : 1023;
	header.value_len = header.value_len < 1024 ? header.value_len : 1023;

	memcpy(&key, data + sizeof(header), header.header_len);
	memcpy(&value, data + value_start, header.value_len);

	if (datadump_enable) {
		bytes +=
		    snprintf(buf + bytes, buf_len - bytes, "header=[%s:%s]\n",
			     key, value);
	} else {
		fprintf(stdout, "header=[%s:%s]\n", key, value);
		fflush(stdout);
	}

	return bytes;
}

int print_io_event_info(pid_t pid, u32 fd, const char *data, int len, char *buf, int buf_len)
{
	char *mount_file_tag;
	char file_path[128];
	snprintf(file_path, sizeof(file_path), "/proc/%d/mountinfo", pid);
 	if (access(file_path, F_OK) == 0)
		mount_file_tag = "exist";
	else
		mount_file_tag = "not exist";

	//char path[MAX_PATH_LENGTH];
	//get_fd_path(pid, fd, path, sizeof(path));
	int bytes = 0;
	struct user_io_event_buffer *event =
	    (struct user_io_event_buffer *)data;

	int path_len = strlen(event->filename) + 1;
	if (datadump_enable) {
		bytes = snprintf(buf, buf_len,
				 "bytes_count=[%u]\noperation=[%u]\noffset=[%llu]\n"
				 "latency=[%llu]\nmount_source=[%s]\nmount_point=[%s]\n"
				 "file_dir=[%s]\nfilename=[%s](len %d)\nfile_type=[%s]\n"
				 "mountID=[%d]\nmntnsID=[%u]\nmountinfo file %s\n",
				 event->bytes_count, event->operation,
				 event->offset, event->latency, event->mount_source,
				 event->mount_point, event->file_dir, event->filename,
				 path_len, fs_type_to_string(event->file_type),
				 event->mnt_id, event->mntns_id, mount_file_tag);
	} else {
		fprintf(stdout,
			"bytes_count=[%u]\noperation=[%u]\noffset=[%llu]\n"
			"latency=[%llu]\nmount_source=[%s]\nmount_point=[%s]\n"
			"file_dir=[%s]\nfilename=[%s](len %d)\nfile_type=[%s]\n"
			"mountID=[%d]\nmntnsID=[%u]\nmountinfo file %s\n",
			event->bytes_count, event->operation, event->offset,
			event->latency, event->mount_source, event->mount_point,
			event->file_dir, event->filename, path_len,
			fs_type_to_string(event->file_type),
			event->mnt_id, event->mntns_id, mount_file_tag);

		fflush(stdout);
	}

	return bytes;
}

int print_uprobe_grpc_dataframe(const char *data, int len, char *buf,
				int buf_len)
{
	int i;
	struct {
		__u32 stream_id;
		__u32 data_len;
		char data[1024];
	} __attribute__ ((packed)) dataframe;

	int bytes = 0;
	memcpy(&dataframe, data, len);

	if (datadump_enable) {
		bytes +=
		    snprintf(buf + bytes, buf_len - bytes,
			     "stream_id=[%d]\ndata_len=[%d]\n",
			     dataframe.stream_id, dataframe.data_len);
	} else {
		fprintf(stdout, "stream_id=[%d]\ndata_len=[%d]\n",
			dataframe.stream_id, dataframe.data_len);
	}

	for (i = 0; i < dataframe.data_len; ++i) {
		if (!isprint(dataframe.data[i])) {
			dataframe.data[i] = '.';
		}
	}

	dataframe.data[dataframe.data_len] = '\0';

	if (datadump_enable) {
		bytes +=
		    snprintf(buf + bytes, buf_len - bytes, "data=[%s]\n",
			     dataframe.data);
	} else {
		fprintf(stdout, "data=[%s]\n", dataframe.data);
		fflush(stdout);
	}
	return bytes;
}

// ------- print mysql --------
void print_mysql_info(const char *data, uint32_t len, uint8_t dir)
{
#define SOCK_DIR_SND_REQ	0
#define SOCK_DIR_SND_RES	1
#define SOCK_DIR_RCV_REQ	2
#define SOCK_DIR_RCV_RES	3
	/*
	 * MySQL Protocol
	 *    Packet Length: 33
	 *    Packet Number: 0
	 *    Request Command Query
	 *  Command: Query (3)
	 *  Statement: select user,host from mysql.user
	 */
	int i;
	for (i = 0; i < len; i++)
		printf("%c", data[i]);
	printf("\n");

	fflush(stdout);
}

// ------- print redis --------
void print_redis_info(const char *data, uint32_t len, uint8_t dir)
{
	int i;
	for (i = 0; i < len; i++)
		printf("%c", data[i]);
	printf("\n");

	fflush(stdout);
}

// ------- print dubbo --------
void print_dubbo_info(const char *data, uint32_t len, uint8_t dir)
{
	// head + body , head 16 bytes. skip head
	int i;
	for (i = 0; i < len - 16; i++)
		printf("%c", data[i + 16]);
	printf("\n");

	fflush(stdout);
}

static char *flow_info(struct socket_bpf_data *sd)
{
#define BUF_SIZE 128

	char *buf = malloc(BUF_SIZE);
	if (buf == NULL)
		return NULL;
	memset(buf, 0, 128);
	char sbuf[64], dbuf[64];
	char *tag;
	if (sd->tuple.addr_len == 16) {
		inet_ntop(AF_INET6, sd->tuple.rcv_saddr, sbuf, sizeof(sbuf));
		inet_ntop(AF_INET6, sd->tuple.daddr, dbuf, sizeof(dbuf));
	} else {
		struct in_addr addr;
		addr.s_addr = *((in_addr_t *) sd->tuple.rcv_saddr);
		snprintf(sbuf, sizeof(sbuf), "%s", inet_ntoa(addr));
		addr.s_addr = *((in_addr_t *) sd->tuple.daddr);
		snprintf(dbuf, sizeof(dbuf), "%s", inet_ntoa(addr));
	}

	if (sd->tuple.l4_protocol == 6) {
		tag = "TCP";
	} else if (sd->tuple.l4_protocol == 17) {
		tag = "UDP";
	} else {
		tag = "Unknow";
	}

	if (sd->direction == T_EGRESS) {
		snprintf(buf, BUF_SIZE, "%s %s.%d > %s.%d",
			 tag, sbuf, sd->tuple.num, dbuf, sd->tuple.dport);
	} else {
		snprintf(buf, BUF_SIZE, "%s %s.%d > %s.%d",
			 tag, dbuf, sd->tuple.dport, sbuf, sd->tuple.num);
	}

	return buf;
}

static bool allow_datadump(struct socket_bpf_data *sd)
{
	bool output = false;
	if (datadump_pid == 0 && (strlen(datadump_comm) > 0)
	    && (datadump_proto == 0)) {
		if (strcmp((char *)sd->process_kname, (char *)datadump_comm) ==
		    0) {
			output = true;
		}

	} else if (datadump_pid == 0 && (strlen(datadump_comm) == 0)
		   && (datadump_proto == 0)) {
		output = true;

	} else if (datadump_pid > 0 && (strlen(datadump_comm) == 0)
		   && (datadump_proto == 0)) {
		if (sd->process_id == datadump_pid
		    || sd->thread_id == datadump_pid)
			output = true;

	} else if (datadump_pid > 0 && (strlen(datadump_comm) > 0)
		   && (datadump_proto == 0)) {
		if ((sd->process_id == datadump_pid
		     || sd->thread_id == datadump_pid)
		    && (strcmp((char *)sd->process_kname, (char *)datadump_comm)
			== 0))
			output = true;
	} else if (datadump_pid == 0 && (strlen(datadump_comm) > 0)
		   && (datadump_proto > 0)) {
		if (strcmp((char *)sd->process_kname, (char *)datadump_comm) ==
		    0 && sd->l7_protocal_hint == datadump_proto)
			output = true;

	} else if (datadump_pid == 0 && (strlen(datadump_comm) == 0)
		   && (datadump_proto > 0)) {
		if (sd->l7_protocal_hint == datadump_proto)
			output = true;

	} else if (datadump_pid > 0 && (strlen(datadump_comm) == 0)
		   && (datadump_proto > 0)) {
		if ((sd->process_id == datadump_pid
		     || sd->thread_id == datadump_pid)
		    && sd->l7_protocal_hint == datadump_proto)
			output = true;

	} else if (datadump_pid > 0 && (strlen(datadump_comm) > 0)
		   && (datadump_proto > 0)) {
		if ((sd->process_id == datadump_pid
		     || sd->thread_id == datadump_pid)
		    && (strcmp((char *)sd->process_kname, (char *)datadump_comm)
			== 0) && sd->l7_protocal_hint == datadump_proto)
			output = true;
	}

	return output;
}

static int __unused get_fd_path(pid_t pid, u32 fd, char *buf, size_t bufsize)
{
	char link_path[64];
	snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%u", pid, fd);
	ssize_t len = readlink(link_path, buf, bufsize - 1);
	if (len < 0) {
		return -1;
	}

	buf[len] = '\0';
	return 0;
}

#define DATADUMP_FORMAT							\
	"%s [datadump] SEQ %" PRIu64 " <%s> DIR %s TYPE %s(%d) PID %u "	\
	"THREAD_ID %u COROUTINE_ID %" PRIu64 " FD %d ROLE %s"		\
	" CONTAINER_ID %s SOURCE %d COMM %s "				\
	"%s LEN %d SYSCALL_LEN %" PRIu64 " SOCKET_ID %" PRIu64		\
	" " "TRACE_ID %" PRIu64 " TCP_SEQ %" PRIu64			\
	" DATA_SEQ %" PRIu64 " TLS %s KernCapTime %s "			\
	"KernMonoTime %llu us\n"

static void print_socket_data(struct socket_bpf_data *sd, int64_t boot_time)
{
	if (!allow_datadump(sd))
		return;

	char *timestamp = gen_timestamp_str(0);
	if (timestamp == NULL)
		return;

	int64_t k_fetch_time_us;
	k_fetch_time_us = (sd->timestamp + boot_time) / NS_IN_USEC;

	char *kern_cap_time = get_timestamp_from_us(k_fetch_time_us);
	if (kern_cap_time == NULL) {
		free(timestamp);
		return;
	}

	char *proto_tag = get_proto_name(sd->l7_protocal_hint);
	char *type, *role_str;
	char *flow_str = flow_info(sd);
	if (flow_str == NULL) {
		free(timestamp);
		free(kern_cap_time);
		return;
	}

	if (sd->msg_type == MSG_REQUEST)
		type = "req";
	else if (sd->msg_type == MSG_RESPONSE)
		type = "res";
	else if (sd->msg_type == MSG_RESPONSE)
		type = "res";
	else
		type = "unknown";

	if (sd->socket_role == ROLE_CLIENT)
		role_str = "client";
	else if (sd->socket_role == ROLE_SERVER)
		role_str = "server";
	else
		role_str = "unknown";

	char buff[DEBUG_BUFF_SIZE];
	int len = 0;
	len +=
	    snprintf(buff, sizeof(buff), DATADUMP_FORMAT, timestamp,
		     datadump_seq++,
		     sd->source == DATA_SOURCE_DPDK ? "Pkt" : proto_tag,
		     sd->direction == T_EGRESS ? "out" : "in", type,
		     sd->msg_type, sd->process_id, sd->thread_id,
		     sd->coroutine_id, sd->fd, role_str,
		     strlen((char *)sd->container_id) ==
		     0 ? "null" : (char *)sd->container_id, sd->source,
		     sd->process_kname, flow_str, sd->cap_len,
		     sd->syscall_len, sd->socket_id,
		     sd->syscall_trace_id_call, sd->tcp_seq,
		     sd->cap_seq, sd->is_tls ? "true" : "false",
		     kern_cap_time, sd->timestamp / NS_IN_USEC);

	if (sd->source == DATA_SOURCE_GO_HTTP2_UPROBE) {
		len +=
		    print_uprobe_http2_info(sd->cap_data, sd->cap_len,
					    buff + len, sizeof(buff) - len);
	} else if (sd->source == DATA_SOURCE_IO_EVENT) {
		len +=
		    print_io_event_info(sd->process_id, (__u32)sd->cap_seq, sd->cap_data,
					sd->cap_len, buff + len, sizeof(buff) - len);
	} else if (sd->source == DATA_SOURCE_GO_HTTP2_DATAFRAME_UPROBE) {
		len +=
		    print_uprobe_grpc_dataframe(sd->cap_data, sd->cap_len,
						buff + len, sizeof(buff) - len);
	} else if (sd->source == DATA_SOURCE_DPDK) {
		len +=
		    print_extra_pkt_info(datadump_enable, sd->cap_data,
					 sd->cap_len, buff + len,
					 sizeof(buff) - len, sd->direction);
	} else {
		int i;
		uint8_t v;
		bool double_args;
		const char *format;
		for (i = 0; i < sd->cap_len; i++) {
			double_args = false;
			format = "%02X ";
			v = (uint8_t) sd->cap_data[i];
			if (sd->l7_protocal_hint == PROTO_HTTP1) {
				/* printing character, LF(10), CR(13) */
				if (!(v < 32 || v > 126) || v == 10 || v == 13)
					format = "%c";
			} else {
				if (!(v < 32 || v > 126)) {
					format = "%02X(%c) ";
					double_args = true;
				}
			}

			if (double_args)
				len +=
				    snprintf(buff + len, sizeof(buff) - len,
					     format, v, v);
			else
				len +=
				    snprintf(buff + len, sizeof(buff) - len,
					     format, v);

			if (len >= sizeof(buff)) {
				break;
			}
		}
	}

	free(timestamp);
	free(kern_cap_time);
	free(flow_str);

	if (datadump_use_remote) {
		if (datadump_cb != NULL)
			datadump_cb((char *)buff, strlen(buff));
	} else {
		fprintf(datadump_file, "%s\n", buff);
		fflush(datadump_file);
	}
}

static void datadump_process(void *data, int64_t boot_time)
{
	struct socket_bpf_data *sd = data;
	pthread_mutex_lock(&datadump_mutex);
	if (unlikely(datadump_enable))
		print_socket_data(sd, boot_time);
	pthread_mutex_unlock(&datadump_mutex);
}

static inline int __set_protocol_ports_bitmap(int proto_type,
					      bool * allow_ports,
					      const char *ports)
{
	int i;
	ports_bitmap_t *map = NULL;
	map =
	    clib_mem_alloc_aligned("ports_bitmap", sizeof(ports_bitmap_t), 0,
				   NULL);
	if (map == NULL) {
		ebpf_warning("clib_mem_alloc_aligned() failed."
			     "Set ports_bitmap[%s] failed, ports %s\n",
			     get_proto_name(proto_type), ports);
		return -1;
	}

	memset(map, 0, sizeof(*map));
	for (i = 0; i < PORT_NUM_MAX; i++) {
		if (allow_ports[i])
			map->bitmap[i / 8] |= 1 << (i % 8);
	}

	if (ports_bitmap[proto_type])
		clib_mem_free(ports_bitmap[proto_type]);

	ports_bitmap[proto_type] = map;

	ebpf_info("Set ports_bitmap[%s] success, ports %s\n",
		  get_proto_name(proto_type), ports);

	return 0;
}

int set_protocol_ports_bitmap(int proto_type, const char *ports)
{
	ASSERT(proto_type < ARRAY_SIZE(ports_bitmap));

	bool *allow_ports = NULL;
	int err;
	err = parse_num_range_disorder(ports, strlen(ports), &allow_ports);
	if (err) {
		allow_ports = NULL;
		goto failed;
	}

	if (__set_protocol_ports_bitmap(proto_type, allow_ports, ports))
		goto failed;

	free(allow_ports);
	return 0;

failed:
	if (allow_ports)
		free(allow_ports);

	ebpf_warning
	    ("failed to get proto_type %d mask, ports %s err %d\n",
	     proto_type, ports, err);
	return -1;
}

int disable_syscall_trace_id(void)
{
	g_disable_syscall_tracing = true;
	ebpf_info("Disable tracing feature.\n");
	return 0;
}

void uprobe_match_pid_handle(int feat, int pid, enum match_pids_act act)
{
	if (feat == FEATURE_UPROBE_GOLANG)
		golang_trace_handle(pid, act);
	else if (feat == FEATURE_UPROBE_OPENSSL)
		openssl_trace_handle(pid, act);
}

void disable_kprobe_feature(void)
{
	kprobe_feature_disable = true;
	ebpf_info("Kprobe feature has been disabled.\n");
}

void enable_kprobe_feature(void)
{
	kprobe_feature_disable = false;
	ebpf_info("Kprobe feature has been enabled.\n");
}

void disable_unix_socket_feature(void)
{
	unix_socket_feature_enable = false;
	ebpf_info("unix socket feature has been disabled.\n");
}

void enable_unix_socket_feature(void)
{
	unix_socket_feature_enable = true;
	ebpf_info("unix socket feature has been enabled.\n");
}

bool is_pure_kprobe_ebpf(void)
{
	return g_k_type == K_TYPE_KPROBE;
}

void enable_fentry(void)
{
	use_kfunc_bin = true;
	ebpf_info("Enabled the fentry/fexit feature\n");
}

void disable_fentry(void)
{
	use_kfunc_bin = false;
	ebpf_info("Disabled the fentry/fexit feature\n");
}
