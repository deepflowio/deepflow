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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include "../user/common.h"
#include "../user/log.h"
#include "../user/elf.h"
#include <bcc/linux/bpf.h>
#include <bcc/linux/bpf_common.h>
#include <bcc/libbpf.h>
#include "../user/load.h"
#include "../user/socket_trace_bpf_common.c"

static int verify_obj__progs(struct ebpf_object *obj)
{
	int i;
	int progs_cnt = obj->elf_info.prog_sec_cnt;
	struct sec_desc *desc, *prog_descs = obj->elf_info.prog_secs;

	Elf_Scn *scn_rel;	// SHT_REL type section
	Elf_Scn *scn_syms;	// SHT_SYMTAB type section
	Elf_Data *data_rel;	// SHT_REL type section data
	GElf_Shdr shdr_rel;	// SHT_REL type section header
	struct bpf_insn *insns;
	GElf_Sym sym;
	struct ebpf_prog *new_prog;

	scn_syms = elf_getscn(obj->elf_info.elf, obj->elf_info.syms_sec->shndx);
	if (scn_syms == NULL) {
		ebpf_warning("elf_getscn() is failed.\n");
		return -1;
	}

	for (i = 0; i < progs_cnt; i++) {
		desc = &prog_descs[i];
		insns = (struct bpf_insn *)desc->d_buf;	// SHT_PROGBITS & SHF_EXECINSTR data buffer
		scn_rel = elf_getscn(obj->elf_info.elf, desc->shndx_rel);
		if (gelf_getshdr(scn_rel, &shdr_rel) == NULL) {
			ebpf_warning("gelf_getshdr() is failed.\n");
			return -1;
		}

		data_rel = elf_getdata(scn_rel, 0);
		if (data_rel == NULL) {
			ebpf_warning("gelf_getshdr() is failed.\n");
			return -1;
		}

		if (find_prog_func_sym
		    (obj->elf_info.elf, scn_syms, desc->shndx,
		     &sym) != ETR_OK) {
			ebpf_warning
			    ("Not find program function symbol, program shndx:%d\n",
			     desc->shndx);
			return -1;
		}

		char *sym_name = elf_strptr(obj->elf_info.elf,
					    obj->elf_info.syms_sec->strtabidx,
					    sym.st_name);

		new_prog = NULL;
		add_new_prog(obj->progs, obj->progs_cnt, new_prog);
		if (new_prog == NULL) {
			return -1;
		}

		new_prog->sec_name = strdup(desc->name);
		if (new_prog->sec_name == NULL)
			return -1;

		new_prog->name = strdup(sym_name);
		if (new_prog->name == NULL) {
			ebpf_warning("strdup() failed.\n");
			return -1;
		}

		new_prog->insns = insns;
		new_prog->insns_cnt = desc->size / sizeof(struct bpf_insn);
		new_prog->obj = obj;

		printf
		    ("sec_name %s\tfunc %s\tinsns_cnt %zd\t"
		     "license %s\tkern_version %u\n",
		     new_prog->sec_name, new_prog->name, new_prog->insns_cnt,
		     obj->license, obj->kern_version);
		if (new_prog->insns_cnt > 4096) {
			printf("The number of instructions exceeded the 4096 limit\n");
			return -1;
		}
	}

	return 0;
}

int main(void)
{
	void *bpf_bin_buffer;
	int buffer_sz;
	bpf_bin_buffer = (void *)socket_trace_common_ebpf_data;
	buffer_sz = sizeof(socket_trace_common_ebpf_data);

	struct ebpf_object *obj;
	obj = ebpf_open_buffer(bpf_bin_buffer, buffer_sz, "common-elf");

	return verify_obj__progs(obj);
}
