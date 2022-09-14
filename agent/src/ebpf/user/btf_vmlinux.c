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

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/utsname.h>
#include "common.h"
#include "log.h"
#include "elf.h"
#include <bcc/linux/bpf.h>
#include <bcc/linux/bpf_common.h>
#include <bcc/libbpf.h>		// kernel_struct_has_field()
#include <bcc/linux/btf.h>
#include "load.h"
#include "btf_vmlinux.h"
#include "kernel/include/utils.h"	// ARRAY_SIZE

extern int32_t btf__find_by_name_kind(const struct btf *btf,
				      const char *type_name, uint32_t kind);
extern const char *btf__name_by_offset(const struct btf *btf, uint32_t offset);
extern const struct btf_type *btf__type_by_id(const struct btf *btf,
					      __u32 type_id);
extern struct btf *btf__parse_elf(const char *path, struct btf_ext **btf_ext);
extern struct btf *btf__parse_raw(const char *path);

int ebpf_obj__load_vmlinux_btf(struct ebpf_object *obj)
{
	/*
	 * If a raw btf file is provided, it can be loaded in the specified
	 * directory("/usr/lib/btf/vmlinux-%1$s.btf").
	 */
	const char *path_fmt_array[] = {
		"/sys/kernel/btf/vmlinux",
		"/usr/lib/btf/vmlinux-%1$s.btf",
		"/boot/vmlinux-%1$s",
		"/lib/modules/%1$s/vmlinux-%1$s",
		"/lib/modules/%1$s/build/vmlinux",
		"/usr/lib/modules/%1$s/kernel/vmlinux",
		"/usr/lib/debug/boot/vmlinux-%1$s",
		"/usr/lib/debug/boot/vmlinux-%1$s.debug",
		"/usr/lib/debug/lib/modules/%1$s/vmlinux"
	};

	char path[PATH_MAX + 1];
	struct utsname sysinfo;
	struct btf *btf;
	uname(&sysinfo);
	int i;
	obj->btf_vmlinux = NULL;

	for (i = 0; i < ARRAY_SIZE(path_fmt_array); i++) {
		snprintf(path, PATH_MAX, path_fmt_array[i], sysinfo.release);
		if (access(path, R_OK))
			continue;
		if (i == 0 || i == 1) {
			// /sys/kernel/btf/vmlinux
			// /usr/lib/btf/vmlinux-%1$s.btf
			btf = btf__parse_raw(path);
		} else {
			btf = btf__parse_elf(path, NULL);
		}
	
		if (!DF_IS_ERR_OR_NULL(btf)) {
			ebpf_info("BTF vmlinux file: %s\n", path);
			obj->btf_vmlinux = btf;
			return ETR_OK;			
		}
	}

	return ETR_INVAL;
}

int kernel_struct_field_offset(struct ebpf_object *obj, const char *struct_name,
			       const char *field_name)
{
	const struct btf_type *btf_type;
	const struct btf_member *btf_member;
	struct btf *btf;
	int i, btf_id;
	btf = obj->btf_vmlinux;

	if (DF_IS_ERR_OR_NULL(btf)) {
		return ETR_NOTEXIST;
	}

	btf_id = btf__find_by_name_kind(btf, struct_name, BTF_KIND_STRUCT);
	if (btf_id < 0) {
		return ETR_NOTEXIST;
	}

	btf_type = btf__type_by_id(btf, btf_id);
	btf_member = (struct btf_member *)(btf_type + 1);
	for (i = 0; i < BTF_INFO_VLEN(btf_type->info); i++, btf_member++) {
		if (!strcmp
		    (btf__name_by_offset(btf, btf_member->name_off),
		     field_name)) {
			return BTF_MEM_OFFSET(btf_type->info,
					      btf_member->offset) / 8;
		}
	}

	return ETR_NOTEXIST;
}
