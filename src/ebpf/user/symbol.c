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
#include <gelf.h>
#include <libelf.h>
#include <stdint.h>
#include <ctype.h>
#include "libbpf/src/libbpf.h"

#define LD_SO_CACHE "/etc/ld.so.cache"

#define CACHE1_HEADER "ld.so-1.7.0"
#define CACHE1_HEADER_LEN (sizeof(CACHE1_HEADER) - 1)

#define CACHE2_HEADER "glibc-ld.so.cache"
#define CACHE2_HEADER_LEN (sizeof(CACHE2_HEADER) - 1)
#define CACHE2_VERSION "1.1"

typedef int (*uprobe_elf_symcb) (const char *, uint64_t, void *);
// Segment virtual address, memory size, file offset, payload
// Callback returning a negative value indicates to stop the iteration
typedef int (*uprobe_elf_load_sectioncb) (uint64_t, uint64_t, uint64_t, void *);

struct ld_cache1_entry {
	int32_t flags;
	uint32_t key;
	uint32_t value;
};

struct ld_cache1 {
	char header[CACHE1_HEADER_LEN];
	uint32_t entry_count;
	struct ld_cache1_entry entries[0];
};

struct ld_cache2_entry {
	int32_t flags;
	uint32_t key;
	uint32_t value;
	uint32_t pad1_;
	uint64_t pad2_;
};

struct ld_cache2 {
	char header[CACHE2_HEADER_LEN];
	char version[3];
	uint32_t entry_count;
	uint32_t string_table_len;
	uint32_t pad_[5];
	struct ld_cache2_entry entries[0];
};

#define LD_SO_CACHE "/etc/ld.so.cache"
#define FLAG_TYPE_MASK 0x00ff
#define TYPE_ELF_LIBC6 0x0003
#define FLAG_ABI_MASK 0xff00
#define ABI_SPARC_LIB64 0x0100
#define ABI_IA64_LIB64 0x0200
#define ABI_X8664_LIB64 0x0300
#define ABI_S390_LIB64 0x0400
#define ABI_POWERPC_LIB64 0x0500
#define ABI_AARCH64_LIB64 0x0a00

static bool match_so_flags(int flags)
{
	if ((flags & FLAG_TYPE_MASK) != TYPE_ELF_LIBC6)
		return false;

	switch (flags & FLAG_ABI_MASK) {
	case ABI_SPARC_LIB64:
	case ABI_IA64_LIB64:
	case ABI_X8664_LIB64:
	case ABI_S390_LIB64:
	case ABI_POWERPC_LIB64:
	case ABI_AARCH64_LIB64:
		return (sizeof(void *) == 8);
	}

	return sizeof(void *) == 4;
}

#define NT_STAPSDT 3
#define ELF_ST_TYPE(x) (((uint32_t) x) & 0xf)

static int openelf_fd(int fd, Elf ** elf_out)
{
	if (elf_version(EV_CURRENT) == EV_NONE)
		return -1;

	*elf_out = elf_begin(fd, ELF_C_READ, 0);
	if (*elf_out == NULL)
		return -1;

	return 0;
}

static int openelf(const char *path, Elf ** elf_out, int *fd_out)
{
	*fd_out = open(path, O_RDONLY);
	if (*fd_out < 0)
		return -1;

	if (openelf_fd(*fd_out, elf_out) == -1) {
		close(*fd_out);
		return -1;
	}

	return 0;
}

static int lib_cache_count;
static struct ld_lib {
	char *libname;
	char *path;
	int flags;
} *lib_cache;

static int read_cache1(const char *ld_map)
{
	struct ld_cache1 *ldcache = (struct ld_cache1 *)ld_map;
	const char *ldstrings =
	    (const char *)(ldcache->entries + ldcache->entry_count);
	uint32_t i;

	lib_cache =
	    (struct ld_lib *)malloc(ldcache->entry_count *
				    sizeof(struct ld_lib));
	lib_cache_count = (int)ldcache->entry_count;

	for (i = 0; i < ldcache->entry_count; ++i) {
		const char *key = ldstrings + ldcache->entries[i].key;
		const char *val = ldstrings + ldcache->entries[i].value;
		const int flags = ldcache->entries[i].flags;

		lib_cache[i].libname = strdup(key);
		lib_cache[i].path = strdup(val);
		lib_cache[i].flags = flags;
	}
	return 0;
}

static int read_cache2(const char *ld_map)
{
	struct ld_cache2 *ldcache = (struct ld_cache2 *)ld_map;
	uint32_t i;

	if (memcmp(ld_map, CACHE2_HEADER, CACHE2_HEADER_LEN))
		return -1;

	lib_cache =
	    (struct ld_lib *)malloc(ldcache->entry_count *
				    sizeof(struct ld_lib));
	lib_cache_count = (int)ldcache->entry_count;

	for (i = 0; i < ldcache->entry_count; ++i) {
		const char *key = ld_map + ldcache->entries[i].key;
		const char *val = ld_map + ldcache->entries[i].value;
		const int flags = ldcache->entries[i].flags;

		lib_cache[i].libname = strdup(key);
		lib_cache[i].path = strdup(val);
		lib_cache[i].flags = flags;
	}
	return 0;
}

struct uprobe_symbol {
	const char *name;
	const char *demangle_name;
	const char *module;	//so或目标文件全路径
	uint64_t offset;
};

//从'/proc/$pid/mmap'中确定so文件全路径
static bool which_so_in_process(const char *libname, int pid, char *libpath)
{
	int ret, found = false;
	char endline[4096], *mapname = NULL, *newline;
	char mappings_file[128];
	const size_t search_len = strlen(libname) + strlen("/lib.");
	char search1[search_len + 1];
	char search2[search_len + 1];

	snprintf(mappings_file, sizeof(mappings_file), "/proc/%ld/maps",
		 (long)pid);
	FILE *fp = fopen(mappings_file, "r");
	if (!fp)
		return NULL;

	snprintf(search1, search_len + 1, "/lib%s.", libname);
	snprintf(search2, search_len + 1, "/lib%s-", libname);

	do {
		ret = fscanf(fp, "%*x-%*x %*s %*x %*s %*d");
		if (!fgets(endline, sizeof(endline), fp))
			break;

		mapname = endline;
		newline = strchr(endline, '\n');
		if (newline)
			newline[0] = '\0';

		while (isspace(mapname[0]))
			mapname++;

		if (strstr(mapname, ".so") && (strstr(mapname, search1) ||
					       strstr(mapname, search2))) {
			found = true;
			memcpy(libpath, mapname, strlen(mapname) + 1);
			break;
		}
	} while (ret != EOF);

	fclose(fp);
	return found;
}

static int load_ld_cache(const char *cache_path)
{
	struct stat st;
	size_t ld_size;
	const char *ld_map;
	int ret, fd = open(cache_path, O_RDONLY);

	if (fd < 0)
		return -1;

	if (fstat(fd, &st) < 0 || st.st_size < sizeof(struct ld_cache1)) {
		close(fd);
		return -1;
	}

	ld_size = st.st_size;
	ld_map =
	    (const char *)mmap(NULL, ld_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (ld_map == MAP_FAILED) {
		close(fd);
		return -1;
	}

	if (memcmp(ld_map, CACHE1_HEADER, CACHE1_HEADER_LEN) == 0) {
		const struct ld_cache1 *cache1 = (struct ld_cache1 *)ld_map;
		size_t cache1_len = sizeof(struct ld_cache1) +
		    (cache1->entry_count * sizeof(struct ld_cache1_entry));
		cache1_len = (cache1_len + 0x7) & ~0x7ULL;

		if (ld_size > (cache1_len + sizeof(struct ld_cache2)))
			ret = read_cache2(ld_map + cache1_len);
		else
			ret = read_cache1(ld_map);
	} else {
		ret = read_cache2(ld_map);
	}

	munmap((void *)ld_map, ld_size);
	close(fd);
	return ret;
}

//查找so库文件的全路径查找 "lib<libname>.so"
//查找到之后返回'so'文件全路径
char *uprobe_procutils_which_so(const char *libname, int pid)
{
	const size_t soname_len = strlen(libname) + strlen("lib.so");
	char soname[soname_len + 1];
	char libpath[4096];
	int i;

	// 如果带有'/',认为是全路径直接返回
	if (strchr(libname, '/'))
		return strdup(libname);

	// 如果指定pid,需要从'/proc/$pid/mmap'中确定so文件全路径
	if (pid && which_so_in_process(libname, pid, libpath))
		return strdup(libpath);

	if (lib_cache_count < 0)
		return NULL;

	if (!lib_cache_count && load_ld_cache(LD_SO_CACHE) < 0) {
		lib_cache_count = -1;
		return NULL;
	}

	snprintf(soname, soname_len + 1, "lib%s.so", libname);

	for (i = 0; i < lib_cache_count; ++i) {
		if (!strncmp(lib_cache[i].libname, soname, soname_len) &&
		    match_so_flags(lib_cache[i].flags)) {
			return strdup(lib_cache[i].path);
		}
	}

	return NULL;
}

static int _find_sym(const char *symname, uint64_t addr, void *payload)
{
	struct uprobe_symbol *sym = (struct uprobe_symbol *)payload;
	if (!strcmp(sym->name, symname)) {
		sym->offset = addr;
		return -1;
	}
	return 0;
}

static int list_in_scn(Elf * e, Elf_Scn * section, size_t stridx,
		       size_t symsize, uprobe_elf_symcb callback, void *payload)
{
	Elf_Data *data = NULL;

	while ((data = elf_getdata(section, data)) != 0) {
		size_t i, symcount = data->d_size / symsize;

		if (data->d_size % symsize)
			return -1;

		for (i = 0; i < symcount; ++i) {
			GElf_Sym sym;
			const char *name;
			//size_t name_len;

			if (!gelf_getsym(data, (int)i, &sym))
				continue;

			if ((name = elf_strptr(e, stridx, sym.st_name)) == NULL)
				continue;
			if (name[0] == 0)
				continue;
			//name_len = strlen(name);

			if (sym.st_value == 0)
				continue;

			//uint32_t st_type = ELF_ST_TYPE(sym.st_info);
			int ret;
			ret = callback(name, sym.st_value, payload);
			if (ret < 0)
				return 1;	// signal termination to caller
		}
	}

	return 0;
}

static int listsymbols(Elf * e, uprobe_elf_symcb callback, void *payload)
{
	Elf_Scn *section = NULL;

	while ((section = elf_nextscn(e, section)) != 0) {
		GElf_Shdr header;

		if (!gelf_getshdr(section, &header))
			continue;

		if (header.sh_type != SHT_SYMTAB
		    && header.sh_type != SHT_DYNSYM)
			continue;

		int rc =
		    list_in_scn(e, section, header.sh_link, header.sh_entsize,
				callback, payload);
		if (rc == 1)
			break;	// callback signaled termination

		if (rc < 0)
			return rc;
	}

	return 0;
}

static int foreach_sym_core(const char *path, uprobe_elf_symcb callback,
			    void *payload)
{
	Elf *e;
	int fd, res;

	if (openelf(path, &e, &fd) < 0)
		return -1;

	res = listsymbols(e, callback, payload);
	elf_end(e);
	close(fd);
	return res;
}

int uprobe_elf_foreach_sym(const char *path, uprobe_elf_symcb callback,
			   void *payload)
{
	return foreach_sym_core(path, callback, payload);
}

int uprobe_elf_get_type(const char *path)
{
	Elf *e;
	GElf_Ehdr hdr;
	int fd;
	void *res = NULL;

	if (openelf(path, &e, &fd) < 0)
		return -1;

	res = (void *)gelf_getehdr(e, &hdr);
	elf_end(e);
	close(fd);

	if (!res)
		return -1;
	else
		return hdr.e_type;
}

struct load_addr_t {
	uint64_t target_addr;
	uint64_t binary_addr;
};

int _find_load(uint64_t v_addr, uint64_t mem_sz, uint64_t file_offset,
	       void *payload)
{
	struct load_addr_t *addr = (struct load_addr_t *)payload;

	if (addr->target_addr >= v_addr
	    && addr->target_addr < (v_addr + mem_sz)) {
		addr->binary_addr = addr->target_addr - v_addr + file_offset;
		return -1;
	}

	return 0;
}

int uprobe_elf_foreach_load_section(const char *path,
				    uprobe_elf_load_sectioncb callback,
				    void *payload)
{
	Elf *e = NULL;
	int fd = -1, err = -1, res;
	size_t nhdrs, i;

	if (openelf(path, &e, &fd) < 0)
		goto exit;

	if (elf_getphdrnum(e, &nhdrs) != 0)
		goto exit;

	GElf_Phdr header;
	for (i = 0; i < nhdrs; i++) {
		if (!gelf_getphdr(e, (int)i, &header))
			continue;
		if (header.p_type != PT_LOAD || !(header.p_flags & PF_X))
			continue;
		res =
		    callback(header.p_vaddr, header.p_memsz, header.p_offset,
			     payload);
		if (res < 0) {
			err = 1;
			goto exit;
		}
	}
	err = 0;

exit:
	if (e)
		elf_end(e);
	if (fd >= 0)
		close(fd);
	return err;
}

//module: 目标可执行文件是全路径，so文件是库名字 lib<module>.so
int uprobe_resolve_symname(const char *module, const char *symname,
			   const uint64_t addr, int pid,
			   struct uprobe_symbol *sym)
{
	if (module == NULL)
		return -1;

	memset(sym, 0, sizeof(struct uprobe_symbol));

	// 判断是可执行目标文件还是库文件，确保so或目标文件都是全路径
	if (strchr(module, '/')) {
		sym->module = strdup(module);
	} else {
		sym->module = uprobe_procutils_which_so(module, pid);
	}

	if (sym->module == NULL)
		return -1;

	//指定了PID
	if (pid != 0 && pid != -1) {
		char *temp = (char *)sym->module;
		char format_mod[4096];
		snprintf(format_mod, 4096, "/proc/%d/root%s", pid, sym->module);
		sym->module = strdup(format_mod);
		free(temp);
	}

	sym->name = symname;
	sym->offset = addr;

	if (sym->name && sym->offset == 0x0)
		if (uprobe_elf_foreach_sym(sym->module, _find_sym, sym) < 0)
			goto invalid_module;
	if (sym->offset == 0x0)
		goto invalid_module;

	// For executable (ET_EXEC) binaries, translate the virtual address
	// to physical address in the binary file.
	// For shared object binaries (ET_DYN), the address from symbol table should
	// already be physical address in the binary file.
	if (uprobe_elf_get_type(sym->module) == ET_EXEC) {
		struct load_addr_t addr = {
			.target_addr = sym->offset,
			.binary_addr = 0x0,
		};

		if (strstr(sym->name, "go.itab.*")) {
			addr.binary_addr = addr.target_addr;
			sym->offset = addr.binary_addr;
			return 0;
		}

		if (uprobe_elf_foreach_load_section
		    (sym->module, &_find_load, &addr) < 0) {
			goto invalid_module;
		}
		if (!addr.binary_addr) {
			goto invalid_module;
		}
		sym->offset = addr.binary_addr;
	}
	return 0;

invalid_module:
	if (sym->module) {
		free((void *)sym->module);
		sym->module = NULL;
	}
	return -1;
}
