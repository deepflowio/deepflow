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
#include "common.h"
#include "log.h"
#include "elf.h"

int openelf(const char *path, Elf ** elf, int *fd)
{
	if ((*fd = open(path, O_RDONLY)) < 0) {
		return -1;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		goto failed;
	}

	if (!(*elf = elf_begin(*fd, ELF_C_READ_MMAP, 0))) {
		goto failed;
	}

	return 0;
failed:
	close(*fd);
	return -1;
}

static Elf_Scn *get_scn_by_sec_name(Elf * e, const char *sec_name)
{
	Elf_Scn *scn = NULL;
	GElf_Shdr hdr;
	size_t str_index;
	char *name;

	if (elf_getshdrstrndx(e, &str_index) != 0)
		return NULL;

	while ((scn = elf_nextscn(e, scn)) != NULL) {
		if (!gelf_getshdr(scn, &hdr))
			continue;
		name = elf_strptr(e, str_index, hdr.sh_name);
		if (name == NULL)
			continue;
		if (!strcmp(name, sec_name))
			return scn;
	}

	return NULL;
}

Elf_Data *get_sec_elf_data(Elf * e, const char *section_name)
{
	Elf_Scn *scn = get_scn_by_sec_name(e, section_name);
	if (scn) {
		return elf_getdata(scn, 0);
	}

	return NULL;
}

static int verify_elf(struct elf_info *elf_info)
{
	Elf *elf = elf_info->elf;
	Elf64_Ehdr *ehdr = elf_info->ehdr;

	if (elf_kind(elf) != ELF_K_ELF || gelf_getclass(elf) != ELFCLASS64) {
		return ETR_INVAL;
	}

	if (ehdr == NULL) {
		return ETR_INVAL;
	}

	if (!elf_rawdata(elf_getscn(elf, elf_info->shstrndx), NULL)) {
		return ETR_INVAL;
	}

	if (ehdr->e_type != ET_REL
	    || (ehdr->e_machine && ehdr->e_machine != EM_BPF)) {
		return ETR_INVAL;
	}
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB)
		return ETR_INVAL;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	if (ehdr->e_ident[EI_DATA] != ELFDATA2MSB)
		return ETR_INVAL;
#else
#error "Unrecognized __BYTE_ORDER__"
#endif

	return ETR_OK;
}

static bool sym_is_extern(const GElf_Sym * sym)
{
	int st_type = GELF_ST_BIND(sym->st_info);
	/*
	 * SHN_UNDEF:
	 *      An undefined, missing, irrelevant, or otherwise meaningless section reference.
	 *      For example, a symbol defined relative to section number SHN_UNDEF is an undefined symbol.
	 * STB_GLOBAL:
	 *      Global symbols. These symbols are visible to all object files being combined.
	 * STB_WEAK:
	 *      Weak symbols.
	 * STT_NOTYPE:
	 *      The symbol type is not specified.
	 */
	return sym->st_shndx == SHN_UNDEF &&
	    (st_type == STB_GLOBAL || st_type == STB_WEAK) &&
	    GELF_ST_TYPE(sym->st_info) == STT_NOTYPE;
}

static int
    __attribute__ ((unused)) find_all_syms(Elf * e, Elf_Data * data,
					   int sym_count, size_t stridx)
{
	int i, st_type;
	GElf_Sym sym;
	char tag[16];

	if (sym_count <= 0)
		return ETR_INVAL;

	// through all the symbols
	for (i = 0; i < sym_count; ++i) {
		if (!gelf_getsym(data, (int)i, &sym))
			continue;
		/*
		 * Symbol Types, Elf standard.
		 * STT_NOTYPE  0
		 * STT_OBJECT  1
		 * STT_FUNC    2
		 * STT_SECTION 3
		 * STT_FILE    4
		 */
		st_type = ELF_ST_TYPE(sym.st_info);

		if (sym_is_extern(&sym)) {
			snprintf(tag, sizeof(tag), "%s", "EXTERN");
		} else if (st_type == STT_FUNC) {
			snprintf(tag, sizeof(tag), "%s", "FUNC");
		} else if (st_type == STT_OBJECT) {
			snprintf(tag, sizeof(tag), "%s", "MAP");
		} else {
			continue;
		}

		ebpf_debug("### symbol [%s] name\t%s\ttype\t%d\n",
			   tag, elf_strptr(e, stridx, sym.st_name), st_type);
	}

	return ETR_OK;
}

/*
 * @e: Elf
 * @scn: symbols section
 * @stridx: Point to string table(store symbols name)
 * @symsize: Entry size if section holds table
 */
static int
    __attribute__ ((unused)) extract_syms_in_scn(Elf * e, Elf_Scn * scn,
						 size_t stridx, size_t sym_size)
{
	//TODO: powerpc64 process
	Elf_Data *data = NULL;
	while ((data = elf_getdata(scn, data)) != 0) {
		int sym_count = data->d_size / sym_size;
		if (data->d_size % sym_size) {
			return ETR_INVAL;
		}
		find_all_syms(e, data, sym_count, stridx);
	}

	return ETR_OK;
}

int find_sym_by_idx(Elf * e, Elf_Scn * syms_scn, int sym_idx, GElf_Sym * sym)
{
	GElf_Shdr shdr;
	if (!gelf_getshdr(syms_scn, &shdr)) {
		return ETR_INVAL;
	}

	Elf_Data *symbols = NULL;
	int syms_cnt;
	while ((symbols = elf_getdata(syms_scn, symbols)) != 0) {
		syms_cnt = symbols->d_size / shdr.sh_entsize;
		if (symbols->d_size % shdr.sh_entsize) {
			return ETR_INVAL;
		}

		if (sym_idx > syms_cnt) {
			continue;
		}

		if (!gelf_getsym(symbols, sym_idx, sym)) {
			continue;
		} else {
			return ETR_OK;
		}
	}

	return ETR_INVAL;
}

static int find_func_sym(Elf_Data * data, int sym_count, size_t shndx,
			 GElf_Sym * sym)
{
	int i, st_type;
	if (sym_count <= 0)
		return ETR_INVAL;

	// through all the symbols
	for (i = 0; i < sym_count; ++i) {
		if (!gelf_getsym(data, (int)i, sym))
			continue;

		if (sym->st_shndx != shndx)
			continue;
		/*
		 * Symbol Types, Elf standard.
		 * STT_NOTYPE  0
		 * STT_OBJECT  1
		 * STT_FUNC    2
		 * STT_SECTION 3
		 * STT_FILE    4
		 */
		st_type = ELF_ST_TYPE(sym->st_info);
		if (st_type == STT_FUNC) {
			return ETR_OK;
		}
	}

	return ETR_INVAL;
}

int find_prog_func_sym(Elf * e, Elf_Scn * syms_scn, size_t prog_shndx,
		       GElf_Sym * sym)
{
	GElf_Shdr shdr;
	if (!gelf_getshdr(syms_scn, &shdr)) {
		return ETR_INVAL;
	}

	Elf_Data *symbols = NULL;
	int syms_cnt;
	while ((symbols = elf_getdata(syms_scn, symbols)) != 0) {
		syms_cnt = symbols->d_size / shdr.sh_entsize;
		if (symbols->d_size % shdr.sh_entsize) {
			return ETR_INVAL;
		}

		if (prog_shndx > syms_cnt) {
			continue;
		}

		if (find_func_sym(symbols, syms_cnt, prog_shndx, sym) != ETR_OK) {
			continue;
		} else {
			return ETR_OK;
		}
	}

	return ETR_INVAL;

}

static void set_sec_desc(struct sec_desc *desc, char *name, size_t idx,
			 size_t idx_rel, size_t strtabidx, void *buf,
			 size_t buf_size)
{
	desc->is_valid = true;
	desc->shndx_rel = idx_rel;
	desc->shndx = idx;
	desc->d_buf = buf;
	desc->size = buf_size;
	desc->name = name;
	desc->strtabidx = strtabidx;
}

static int add_new_sec(struct elf_info *info, char *name, size_t idx,
		       size_t idx_rel, size_t strtabidx, void *buf,
		       size_t buf_size)
{
	size_t pre_cnt = info->prog_sec_cnt;
	size_t curr_sz = (++info->prog_sec_cnt) * sizeof(*info->prog_secs);
	struct sec_desc *desc;
	desc = realloc(info->prog_secs, curr_sz);
	if (desc == NULL) {
		ebpf_warning("realloc() error\n");
		return ETR_NOMEM;
	}

	if (info->prog_secs != desc) {
		info->prog_secs = desc;
	}

	desc = info->prog_secs + pre_cnt;
	memset(desc, 0, sizeof(*info->prog_secs));
	set_sec_desc(desc, name, idx, idx_rel, strtabidx, buf, buf_size);
	return ETR_OK;
}

static int elf_info_init(struct elf_info *info)
{
	info->prog_sec_cnt = 0;
	info->prog_secs = calloc(1, sizeof(*info->prog_secs));
	info->map_sec = calloc(1, sizeof(*info->prog_secs));
	info->btf_map_sec = calloc(1, sizeof(*info->prog_secs));
	info->syms_sec = calloc(1, sizeof(*info->prog_secs));
	info->license_sec = calloc(1, sizeof(*info->prog_secs));
	info->version_sec = calloc(1, sizeof(*info->prog_secs));
	info->btf_sec = calloc(1, sizeof(*info->prog_secs));
	info->btf_ext_sec = calloc(1, sizeof(*info->prog_secs));
	if (info->prog_secs == NULL ||
	    info->map_sec == NULL ||
	    info->btf_map_sec == NULL ||
	    info->syms_sec == NULL ||
	    info->btf_sec == NULL ||
	    info->btf_ext_sec == NULL ||
	    info->license_sec == NULL || info->version_sec == NULL) {
		ebpf_warning("calloc failed.\n");
		return ETR_NOMEM;
	}

	return ETR_OK;
}

static int elf_section_collect(struct elf_info *info)
{
	Elf_Scn *section = NULL;
	char *name;
	Elf_Data *data = NULL;
	size_t idx;
	int ret;

	ret = elf_info_init(info);
	if (ret != ETR_OK) {
		return ret;
	}

	while ((section = elf_nextscn(info->elf, section)) != 0) {
		idx = elf_ndxscn(section);
		GElf_Shdr hdr;
		if (!gelf_getshdr(section, &hdr)) {
			continue;
		}

		name = elf_strptr(info->elf, info->shstrndx, hdr.sh_name);
		data = elf_getdata(section, NULL);
		if (data == NULL) {
			ebpf_warning("elf_getdata() return NULL, (%s)\n", name);
			return ETR_INVAL;
		}
		// skip symnbol section
		if (hdr.sh_type == SHT_SYMTAB || hdr.sh_type == SHT_DYNSYM) {
			extract_syms_in_scn(info->elf, section, hdr.sh_link,
					    hdr.sh_entsize);
			set_sec_desc(info->syms_sec, name, idx, 0, hdr.sh_link,
				     data->d_buf, data->d_size);
			continue;
		}
		// ignore .strtab, .llvm_addrsig
		if (hdr.sh_type == SHT_STRTAB
		    || hdr.sh_type == SHT_LLVM_ADDRSIG) {
			continue;
		}
		// .text section no subprograms, ignore it
		if (hdr.sh_type == SHT_PROGBITS && hdr.sh_size == 0 &&
		    strcmp(name, ".text") == 0) {
			continue;
		}
		// ignore DWARF section
		if (strstr(name, ".debug_")) {
			continue;
		}

		if (strcmp(name, "license") == 0) {
			set_sec_desc(info->license_sec, name, idx, 0,
				     hdr.sh_link, data->d_buf, data->d_size);
		}

		if (strcmp(name, "version") == 0) {
			set_sec_desc(info->version_sec, name, idx, 0,
				     hdr.sh_link, data->d_buf, data->d_size);
		}

		if (strcmp(name, "maps") == 0) {
			set_sec_desc(info->map_sec, name, idx, 0, hdr.sh_link,
				     data->d_buf, data->d_size);
			continue;
		}

		if (strcmp(name, ".maps") == 0) {
			set_sec_desc(info->btf_map_sec, name, idx, 0,
				     hdr.sh_link, data->d_buf, data->d_size);
			continue;
		}
		// .BTF, .BTF.ext current ignore
		if (strcmp(name, ".BTF") == 0) {
			set_sec_desc(info->btf_sec, name, idx, 0, hdr.sh_link,
				     data->d_buf, data->d_size);
			continue;
		}
		// CO-RE relocations need kernel BTF
		if (strcmp(name, ".BTF.ext") == 0) {
			set_sec_desc(info->btf_ext_sec, name, idx, 0,
				     hdr.sh_link, data->d_buf, data->d_size);
			continue;
		}

		/*
		 * When a program calls a function, the associated call instruction
		 * must transfer control to the proper destination address at execution.
		 * Relocatable files must have information that describes how to modify
		 * their section contents, thus allowing executable and shared object 
		 * files to hold the right information for a process's program image.
		 * Relocation entries are these data.
		 */
		if (hdr.sh_type == SHT_REL) {
			Elf_Scn *scn;
			GElf_Shdr shdr_prog;
			char *shname_prog;
			Elf_Data *data_prog;

			// hdr.sh_info: Additional section information,  
			// e.g.: from sec ".reluprobe/runtime.casgstatus", get sec "uprobe/runtime.casgstatus"
			scn = elf_getscn(info->elf, hdr.sh_info);
			if (scn == NULL) {
				ebpf_warning
				    ("elf_getscn() failed, hdr.sh_info:%d\n",
				     hdr.sh_info);
				return ETR_INVAL;
			}

			if (!gelf_getshdr(scn, &shdr_prog)) {
				ebpf_warning("gelf_getshdr() failed.\n");
				return ETR_INVAL;
			}

			data_prog = elf_getdata(scn, 0);
			if (!data_prog || elf_getdata(scn, data_prog) != NULL) {
				ebpf_warning("elf_getdata() failed.\n");
				return ETR_INVAL;
			}

			shname_prog =
			    elf_strptr(info->elf, info->shstrndx,
				       shdr_prog.sh_name);
			if (!shname_prog || !shdr_prog.sh_size) {
				ebpf_warning("elf_strptr() failed.\n");
				return ETR_INVAL;
			}

			if (shdr_prog.sh_type == SHT_PROGBITS
			    && data_prog->d_size > 0
			    && shdr_prog.sh_flags & SHF_EXECINSTR) {

				ebpf_debug
				    ("section idx %d\tname %s\tentsize %ld\tdata_size %ld\tlink %d\tflags %lx\ttype %d\tsh_info %d\n",
				     (int)idx, shname_prog,
				     (unsigned long)shdr_prog.sh_entsize,
				     (unsigned long)data_prog->d_size,
				     (int)shdr_prog.sh_link,
				     (unsigned long)shdr_prog.sh_flags,
				     (int)shdr_prog.sh_type,
				     (int)shdr_prog.sh_info);

				// hdr.sh_info: prog_idx
				// idx: rel prog idx
				if (add_new_sec
				    (info, shname_prog, hdr.sh_info, idx, 0,
				     data_prog->d_buf, data_prog->d_size)
				    != ETR_OK) {
					return ETR_INVAL;
				}
			}
		}

	}

	return ETR_OK;
}

int elf_info_collect(struct elf_info *elf_info, const void *buf, size_t buf_sz)
{
	int ret = ETR_OK;

	// TODO: Create elf by elf file path. 
	// (Note: You need to copy the instruction data from the binary file to buffer.)
	//int fd = open("*.elf", O_RDONLY | O_CLOEXEC);
	//elf_info->elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);

	elf_info->elf = elf_memory((char *)buf, buf_sz);
	if (!elf_info->elf) {
		ebpf_warning("elf_memory() failed.\n");
		return ETR_INVAL;
	}

	elf_info->ehdr = elf64_getehdr(elf_info->elf);
	if (elf_getshdrstrndx(elf_info->elf, &elf_info->shstrndx)) {
		ebpf_warning("elf_getshdrstrndx()  failed.\n");
		return ETR_INVAL;
	}

	if ((ret = verify_elf(elf_info)) != ETR_OK) {
		return ret;
	}

	if ((ret = elf_section_collect(elf_info)) != ETR_OK) {
		return ret;
	}

	return ret;
}
