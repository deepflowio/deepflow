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

#ifndef DF_TRACE_ELF_H
#define DF_TRACE_ELF_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <gelf.h>
#define EM_BPF           247
#define ELF_ST_TYPE(x) (((uint32_t) x) & 0xf)
#define SHT_LLVM_ADDRSIG 0x6FFF4C03

struct sec_desc {
	bool is_valid;
	/* via elf_getscn(e, shndx), get section */
	size_t shndx;
	size_t shndx_rel;	// For prog sections
	void *d_buf;
	size_t size;
	char *name;
	size_t strtabidx;	// for SHT_SYMTAB (shdr.sh_link)
	int nr_reloc;
};

struct elf_info {
	char *path;		// ebpf elf file path or ebpf buffer name
	int fd;			// elf file fd
	void *obj_buf;		// ebpf buffer address
	size_t obj_buf_sz;	// ebpf budder size
	Elf *elf;
	Elf64_Ehdr *ehdr;
	/*
	 * Section index for section name strings.
	 * It is used to obtain the number of segments in which the segment name is stored.
	 */
	size_t shstrndx;
	size_t prog_sec_cnt;
	struct sec_desc *prog_secs;
	struct sec_desc *map_sec;
	struct sec_desc *btf_map_sec;
	struct sec_desc *syms_sec;
	struct sec_desc *btf_sec;
	struct sec_desc *btf_ext_sec;
	struct sec_desc *license_sec;
	struct sec_desc *version_sec;
};

int openelf(const char *path, Elf ** elf, int *fd);
Elf_Scn *get_scn_by_sec_name(Elf * e, const char *sec_name);
Elf_Data *get_sec_elf_data(Elf * e, const char *section_name);
int elf_info_collect(struct elf_info *elf_info, const void *buf, size_t buf_sz);
int find_sym_by_idx(Elf * e, Elf_Scn * syms_scn, int sym_idx, GElf_Sym * sym);
int find_prog_func_sym(Elf * e, Elf_Scn * syms_scn, size_t prog_shndx,
		       GElf_Sym * sym);
int elf_read_build_id(const char *path, uint8_t *build_id, size_t build_id_cap,
		      uint32_t *build_id_size);
int elf_file_offset_to_vaddr(Elf *elf, uint64_t file_offset, uint64_t *vaddr);
int elf_symbolize_pc(Elf *elf, uint64_t vaddr, const char **symbol_name,
		     uint64_t *symbol_addr, uint64_t *symbol_size);
#endif /*DF_TRACE_ELF_H */
