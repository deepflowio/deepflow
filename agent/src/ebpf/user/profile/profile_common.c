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

/*
 * View kernel addresses exposed via /proc and other interfaces
 * when /proc/sys/kernel/kptr_restrict has the value 1, it is
 * necessary to set the CAP_SYSLOG capability, otherwise all k-
 * ernel addresses are set to 0.
 *
 * This function is used to check if the kernel address is 0.
 */

#include <sys/stat.h>
#include <bcc/perf_reader.h>
#include "../config.h"
#include "../utils.h"
#include "../common.h"
#include "../mem.h"
#include "../log.h"
#include "../types.h"
#include "../vec.h"
#include "../tracer.h"
#include "../socket.h"
#include "java/gen_syms_file.h"
#include "perf_profiler.h"
#include "../elf.h"
#include "../load.h"
#include "../../kernel/include/perf_profiler.h"
#include "../perf_reader.h"
#include "../bihash_8_8.h"
#include "stringifier.h"
#include "../table.h"
#include <regex.h>
#include "java/config.h"
#include "java/df_jattach.h"
#include "profile_common.h"

/*
 * This section is for symbolization of Java addresses, and we need
 * to prepare two so librarys, one for GNU and the other for MUSL:
 *
 * df_java_agent.so
 * df_java_agent_musl.so
 *
 * These two files need to be saved in the '/tmp' directory, and the
 * agent so library will be injected into the JVM to generate
 * 'perf-<pid>.map'.
 */
#include "java_agent_so_gnu.c"
#include "java_agent_so_musl.c"
/* use for java symbols generate */
#include "deepflow_jattach_bin.c"

extern int major, minor;

static bool java_installed;

int profiler_context_init(struct profiler_context *ctx,
			  const char *state_map_name,
			  const char *stack_map_name_a,
			  const char *stack_map_name_b)
{
	memset(ctx, 0, sizeof(struct profiler_context));
	atomic64_init(&ctx->process_lost_count);
	ctx->profiler_stop = 0;
	snprintf(ctx->state_map_name, sizeof(ctx->state_map_name), "%s",
		 state_map_name);
	snprintf(ctx->stack_map_name_a, sizeof(ctx->stack_map_name_a), "%s",
		 stack_map_name_a);
	snprintf(ctx->stack_map_name_b, sizeof(ctx->stack_map_name_b), "%s",
		 stack_map_name_b);
	return 0;
}

void set_enable_profiler(struct bpf_tracer *t, struct profiler_context *ctx,
			 u64 enable_flag)
{
	if (bpf_table_set_value(t, ctx->state_map_name,
				ENABLE_IDX, &enable_flag) == false) {
		ebpf_warning("profiler state map update error."
			     "(%s enable_flag %lu) - %s\n",
			     MAP_PROFILER_STATE_MAP,
			     enable_flag, strerror(errno));
	}

	ctx->enable_bpf_profile = enable_flag;

	ebpf_info("%s() success, enable_flag:%d\n", __func__, enable_flag);
}

static bool check_kallsyms_addr_is_zero(void)
{
	const int check_num = 100;
	const int max_line_len = 256;
	const char *check_str = "0000000000000000";

	FILE *file = fopen("/proc/kallsyms", "r");
	if (file == NULL) {
		ebpf_warning("Error opening /proc/kallsyms");
		return false;
	}

	char line[max_line_len];
	int count = 0;

	while (fgets(line, sizeof(line), file) != NULL && count < check_num) {
		char address[17];	// 16 characters + null terminator
		sscanf(line, "%16s", address);

		if (strcmp(address, check_str) == 0) {
			count++;
		}
	}

	fclose(file);

	return (count == check_num);
}

bool run_conditions_check(void)
{
	// REQUIRES: Linux 4.9+ (BPF_PROG_TYPE_PERF_EVENT support).
	if (check_kernel_version(4, 9) != 0) {
		ebpf_warning
		    ("Currnet linux %d.%d, not support, require Linux 4.9+\n",
		     major, minor);

		return false;
	}

	if (check_kallsyms_addr_is_zero()) {
		ebpf_warning
		    ("All kernel addresses in /proc/kallsyms are 0, Please"
		     " follow the steps below to resolve:\n"
		     "1 Make sure the content of the '/proc/sys/kernel/kpt"
		     "r_restrict' file is not 2, if it is 2 please set it "
		     "to 1.\n2 Add 'CAP_SYSLOG' permission to the containe"
		     "r.\n3 Restart the pod.");
		return false;
	}

	return true;
}

int java_libs_and_tools_install(void)
{
	if (java_installed)
		return (0);

	// Java agent so library generation.
	if (access(AGENT_LIB_SRC_PATH, F_OK) == 0) {
		if (unlink(AGENT_LIB_SRC_PATH) != 0) {
			ebpf_warning("rm file %s failed.\n",
				     AGENT_LIB_SRC_PATH);
			return (-1);
		}
	}

	if (access(AGENT_MUSL_LIB_SRC_PATH, F_OK) == 0) {
		if (unlink(AGENT_MUSL_LIB_SRC_PATH) != 0) {
			ebpf_warning("rm file %s failed.\n",
				     AGENT_MUSL_LIB_SRC_PATH);
			return (-1);
		}
	}

	if (gen_file_from_mem((const char *)java_agent_so_gnu,
			      sizeof(java_agent_so_gnu),
			      (const char *)AGENT_LIB_SRC_PATH)) {
		ebpf_warning("Java agent so library(%s) generate failed.\n",
			     AGENT_LIB_SRC_PATH);
		return (-1);
	}

	if (gen_file_from_mem((const char *)java_agent_so_musl,
			      sizeof(java_agent_so_musl),
			      (const char *)AGENT_MUSL_LIB_SRC_PATH)) {
		ebpf_warning("Java agent so library(%s) generate failed.\n",
			     AGENT_MUSL_LIB_SRC_PATH);
		return (-1);
	}

	/* For java attach tool */
	if (access(JAVA_ATTACH_TOOL_PATH, F_OK) == 0) {
		if (unlink(JAVA_ATTACH_TOOL_PATH) != 0) {
			ebpf_warning("rm file %s failed.\n",
				     JAVA_ATTACH_TOOL_PATH);
			return (-1);
		}
	}

	if (gen_file_from_mem((const char *)deepflow_jattach_bin,
			      sizeof(deepflow_jattach_bin),
			      (const char *)JAVA_ATTACH_TOOL_PATH)) {
		ebpf_warning("Java attach tool (%s) generate failed.\n",
			     JAVA_ATTACH_TOOL_PATH);
		return (-1);
	}

	if (chmod(JAVA_ATTACH_TOOL_PATH, 0755) < 0) {
		ebpf_warning("file '%s' chmod failed.\n",
			     JAVA_ATTACH_TOOL_PATH);
		return (-1);
	}

	java_installed = true;

	return (0);
}
