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
 * BPF Load Test Tool
 *
 * Tests whether BPF programs can be loaded on the current kernel.
 * Auto-detects kernel version and loads matching bytecodes using the
 * same selection and loading logic as production code.
 *
 * Usage:
 *   sudo ./test_bpf_load
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "../user/utils.h"
#include "../user/log.h"
#include "../user/elf.h"
#include <bcc/linux/bpf.h>
#include <bcc/linux/bpf_common.h>
#include <bcc/libbpf.h>
#include "../user/load.h"
#include "../user/tracer.h"
#include "../user/socket.h"
#include "../user/profile/perf_profiler.h"

extern char linux_release[128];

static int test_load_one(const char *name, const void *data, size_t sz)
{
	printf("\n=== Testing: %s (%zu bytes) ===\n", name, sz);

	struct ebpf_object *obj = ebpf_open_buffer(data, sz, name);
	if (obj == NULL) {
		printf("  [FAIL] ebpf_open_buffer() failed\n");
		return -1;
	}

	printf("  Maps: %d\n", obj->maps_cnt);
	for (int i = 0; i < obj->maps_cnt; i++) {
		printf("    map[%d]: %-40s type=%-2u key=%-3u val=%-5u max=%u\n",
		       i, obj->maps[i].name, obj->maps[i].def.type,
		       obj->maps[i].def.key_size, obj->maps[i].def.value_size,
		       obj->maps[i].def.max_entries);
	}

	printf("  Loading...\n");
	int ret = ebpf_obj_load(obj);
	if (ret != 0) {
		printf("  [FAIL] ebpf_obj_load() failed (errno=%d: %s)\n",
		       errno, strerror(errno));
		release_object(obj);
		return -1;
	}

	int fail_cnt = 0;
	printf("  Programs: %d\n", obj->progs_cnt);
	for (int i = 0; i < obj->progs_cnt; i++) {
		struct ebpf_prog *p = &obj->progs[i];
		if (p->prog_fd >= 0) {
			printf("    [OK]   %-45s fd=%d\n", p->name,
			       p->prog_fd);
		} else {
			printf("    [FAIL] %-45s errno=%d\n", p->name, errno);
			fail_cnt++;
		}
	}

	if (fail_cnt == 0)
		printf("  Result: ALL %d programs loaded OK\n", obj->progs_cnt);
	else
		printf("  Result: %d/%d programs FAILED\n", fail_cnt,
		       obj->progs_cnt);

	release_object(obj);
	return fail_cnt > 0 ? -1 : 0;
}

int main(int argc, char **argv)
{
	if (geteuid() != 0) {
		fprintf(stderr,
			"Warning: BPF operations require root. Run with sudo.\n");
	}

	printf("Initializing BPF infrastructure...\n");
	int ret = bpf_tracer_init(NULL, true);
	if (ret != 0) {
		fprintf(stderr, "bpf_tracer_init() failed: %d\n", ret);
		return 1;
	}

	int pass = 0, fail = 0, total = 0;
	char load_name[NAME_LEN];
	void *buf;
	int buf_sz;

	/* Socket tracer: auto-select based on kernel */
	printf("\n--- Socket Tracer (auto-detect) ---\n");
	select_socket_bpf_binary(load_name, &buf, &buf_sz, false, false);
	total++;
	if (test_load_one(load_name, buf, buf_sz) == 0)
		pass++;
	else
		fail++;

	/* Profiler: auto-select based on kernel */
	printf("\n--- Continuous Profiler (auto-detect) ---\n");
	select_profiler_bpf_binary(load_name, &buf, &buf_sz);
	total++;
	if (test_load_one(load_name, buf, buf_sz) == 0)
		pass++;
	else
		fail++;

	printf("\n========================================\n");
	printf("Kernel: %s\n", linux_release);
	printf("Summary: %d/%d passed", pass, total);
	if (fail > 0)
		printf(", %d FAILED", fail);
	printf("\n");

	return fail > 0 ? 1 : 0;
}
