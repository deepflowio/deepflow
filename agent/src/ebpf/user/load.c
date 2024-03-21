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
#include <bcc/linux/bpf.h>
#include <bcc/linux/bpf_common.h>
#include <bcc/libbpf.h>
#include "load.h"
#include "btf_vmlinux.h"
#include "../kernel/include/bpf_base.h"

extern struct btf_ext *btf_ext__new(const uint8_t * data, uint32_t size);
extern struct btf *btf__new(const void *data, uint32_t size);
extern void btf__free(struct btf *btf);
extern void btf_ext__free(struct btf_ext *btf_ext);
extern int btf__set_pointer_size(struct btf *btf, size_t ptr_sz);

#define FN_ID(F) ((int32_t)((uint64_t)F))
#define KERN_FEAT_UNKNOWN	0
#define KERN_FEAT_SUP		1
#define KERN_FEAT_NOTSUP        2

static int probe_read_kernel_feat;

static int suspend_stderr()
{
	fflush(stderr);

	int ret = dup(STDERR_FILENO);
	if (ret == -1) {
		return -1;
	}
	int fd = open("/dev/null", O_WRONLY);
	if (fd == -1) {
		close(ret);
		return -1;
	}
	if (dup2(fd, STDERR_FILENO) == -1) {
		close(fd);
		close(ret);
		return -1;
	}
	close(fd);
	return ret;
}

static void resume_stderr(int fd)
{
	fflush(stderr);
	if (fd < 0)
		return;
	dup2(fd, STDERR_FILENO);
	close(fd);
}

/*
 * Feature checks for the Linux kernel, 
 * `bpf_probe_read{kernel,user}[_str]`, vary across
 * different versions of the Linux kernel. Using eBPF
 * instructions to determine whether the currently
 * running Linux kernel supports this feature.
 */
static bool feat_probe_read_kernel(unsigned kern_version)
{
	if (probe_read_kernel_feat == KERN_FEAT_SUP)
		return true;
	else if (probe_read_kernel_feat == KERN_FEAT_NOTSUP)
		return false;

	struct bpf_insn insns[] = {
		BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),	/* r1 = r10 (fp) */
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),	/* r1 += -8 */
		BPF_MOV64_IMM(BPF_REG_2, 8),	/* r2 = 8 */
		BPF_MOV64_IMM(BPF_REG_3, 0),	/* r3 = 0 */
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
			     FN_ID(bpf_probe_read_kernel)),
		BPF_EXIT_INSN(),
	};

	int stderr_fd = suspend_stderr();
	if (stderr_fd < 0) {
		ebpf_warning("Failed to suspend stderr\n");
	}
	int fd = bcc_prog_load
	    (BPF_PROG_TYPE_TRACEPOINT, NULL, insns, sizeof(insns), LICENSE_DEF,
	     kern_version, 0, NULL,
	     0 /*EBPF_LOG_LEVEL, log_buf, LOG_BUF_SZ */ );
	resume_stderr(stderr_fd);
	if (fd >= 0) {
		close(fd);
		probe_read_kernel_feat = KERN_FEAT_SUP;
		ebpf_info("Kernel support interfaces `bpf_probe_read{kernel,user}[_str]`\n");
		return true;
	}

	probe_read_kernel_feat = KERN_FEAT_NOTSUP;
	ebpf_info("Kernel not support interfaces `bpf_probe_read{kernel,user}[_str]`\n");

	return false;
}

static bool is_helper_call_insn(struct bpf_insn *insn, int32_t * func_id)
{
	if (BPF_CLASS(insn->code) == BPF_JMP &&
	    BPF_OP(insn->code) == BPF_CALL &&
	    BPF_SRC(insn->code) == BPF_K &&
	    insn->src_reg == 0 && insn->dst_reg == 0) {
		*func_id = insn->imm;
		return true;
	}
	return false;
}

static void sanitize_prog_instructions(struct ebpf_object *obj,
				       struct ebpf_prog *prog)
{
	struct bpf_insn *insn = prog->insns;
	int32_t func_id;

	for (int i = 0; i < prog->insns_cnt; i++, insn++) {
		if (!is_helper_call_insn(insn, &func_id))
			continue;
		if (func_id == FN_ID(bpf_probe_read_kernel)
		    || func_id == FN_ID(bpf_probe_read_user)) {
			if (!feat_probe_read_kernel(obj->kern_version))
				insn->imm = FN_ID(bpf_probe_read);
		} else if (func_id == FN_ID(bpf_probe_read_kernel_str)
			   || func_id == FN_ID(bpf_probe_read_user_str)) {
			if (!feat_probe_read_kernel(obj->kern_version))
				insn->imm = FN_ID(bpf_probe_read_str);
		}
	}
}

static void ebpf_object__release_elf(struct ebpf_object *obj)
{
	int i;

	if (obj->elf_info.elf) {
		elf_end(obj->elf_info.elf);
		obj->elf_info.elf = NULL;
	}

	if (obj->elf_info.fd != -1) {
		close(obj->elf_info.fd);
		obj->elf_info.fd = -1;
	}

	/* free ebpf byte-codes name */
	if (obj->elf_info.path != NULL) {
		zfree(obj->elf_info.path);
	}

	if (obj->elf_info.prog_secs) {
		zfree(obj->elf_info.prog_secs);
	}

	if (obj->elf_info.map_sec) {
		zfree(obj->elf_info.map_sec);
	}

	if (obj->elf_info.btf_map_sec) {
		zfree(obj->elf_info.btf_map_sec);
	}

	if (obj->elf_info.syms_sec) {
		zfree(obj->elf_info.syms_sec);
	}

	if (obj->elf_info.license_sec) {
		zfree(obj->elf_info.license_sec);
	}

	if (obj->elf_info.version_sec) {
		zfree(obj->elf_info.version_sec);
	}

	if (obj->elf_info.btf_sec) {
		zfree(obj->elf_info.btf_sec);
	}

	if (obj->elf_info.btf_ext_sec) {
		zfree(obj->elf_info.btf_ext_sec);
	}

	struct ebpf_prog *prog;
	for (i = 0; i < obj->progs_cnt; i++) {
		prog = &obj->progs[i];
		prog->insns = NULL;
	}
}

void release_object(struct ebpf_object *obj)
{
	int i;

	ebpf_info("release object (\"%s\") ...\n", obj->name);

	// release elf resource.
	ebpf_object__release_elf(obj);

	struct ebpf_map *map;
	for (i = 0; i < obj->maps_cnt; i++) {
		map = &obj->maps[i];
		if (map->fd >= 0) {
			close(map->fd);
		}
	}

	struct ebpf_prog *prog;
	for (i = 0; i < obj->progs_cnt; i++) {
		prog = &obj->progs[i];
		if (prog->name != NULL) {
			free(prog->name);
		}

		if (prog->sec_name != NULL) {
			free(prog->sec_name);
		}

		if (prog->prog_fd >= 0) {
			close(prog->prog_fd);
		}
	}
	if (obj->maps != NULL) {
		free(obj->maps);
	}

	if (obj->progs != NULL) {
		free(obj->progs);
	}

	if (!DF_IS_ERR_OR_NULL(obj->btf)) {
		btf__free(obj->btf);
	}

	if (!DF_IS_ERR_OR_NULL(obj->btf_ext)) {
		btf_ext__free(obj->btf_ext);
	}

	/* free obj */
	zfree(obj);

	ebpf_info("release object done\n");
}

static struct ebpf_object *create_new_obj(const void *buf,
					  size_t buf_sz, const char *name)
{
	struct ebpf_object *obj = malloc(sizeof(struct ebpf_object));
	if (obj == NULL) {
		ebpf_warning("Malloc memory failed for ebpf_object.\n");
		return NULL;
	}

	memset(obj, 0, sizeof(struct ebpf_object));
	obj->elf_info.path = strdup(name);
	if (obj->elf_info.path == NULL) {
		zfree(obj);
		return NULL;
	}
	safe_buf_copy(obj->name, sizeof(obj->name), (void *)name, strlen(name));
	obj->name[sizeof(obj->name) - 1] = '\0';
	obj->elf_info.fd = -1;
	obj->elf_info.obj_buf = (void *)buf;
	obj->elf_info.obj_buf_sz = buf_sz;
	obj->kern_version = fetch_kernel_version_code();
	safe_buf_copy(obj->license, sizeof(obj->license), LICENSE_DEF,
		      sizeof(LICENSE_DEF));
	obj->license[sizeof(obj->license) - 1] = '\0';
	return obj;
}

static void set_obj__license(struct ebpf_object *obj)
{
	struct sec_desc *desc = obj->elf_info.license_sec;
	if (desc->d_buf != NULL && desc->size > 0) {
		memcpy(obj->license, desc->d_buf, desc->size);
		obj->license[sizeof(obj->license) - 1] = '\0';
	}
	ebpf_info("license: %s\n", obj->license);
}

static int set_obj__version(struct ebpf_object *obj)
{
	if (obj->kern_version != 0) {
		return ETR_OK;
	}

	struct sec_desc *desc = obj->elf_info.version_sec;
	if (desc->size == 0) {
		obj->kern_version = 0;
		return ETR_OK;
	}

	ebpf_info("desc->size:%d\n", desc->size);
	if (desc->size != sizeof(int)) {
		ebpf_warning("invalid size of version section %zd\n",
			     desc->size);
		return ETR_INVAL;
	}
	memcpy(&obj->kern_version, desc->d_buf, sizeof(int));
	ebpf_info("kern_version: %x\n", obj->kern_version);
	return ETR_OK;
}

/*
 * Parse relo section and modify program instruction access to MAP by relocation info.
 *
 * @obj struct ebpf_object pointer
 * @shdr_rel SHT_REL type section header
 * @scn_syms SHT_SYMTAB type section 
 * @insns Program data buffer
 * @data_rel SHT_REL type section data
 * @desc Program section description
 */
static int relo_parse_and_apply(struct ebpf_object *obj,
				GElf_Shdr * shdr_rel,
				Elf_Scn * scn_syms,
				struct bpf_insn *insns,
				Elf_Data * data_rel, struct sec_desc *desc)
{
	int rel_i, nrels, map_i, insn_idx;
	GElf_Sym sym;
	GElf_Rel rel;

	nrels = shdr_rel->sh_size / shdr_rel->sh_entsize;
	/*
	 * RELO(PROG) --> find all relocation entries,
	 * Via relocation entries, get PROG data need relocation instruction,
	 * verify and modify the instruction.
	 * Get symbol from relocation entries(GElf_Rel), and get map def from symbol.
	 * Finally completed:
	 *      insns[insn_idx].imm = obj->maps[map_i].fd;
	 */
	for (rel_i = 0; rel_i < nrels; rel_i++) {
		gelf_getrel(data_rel, rel_i, &rel);

		/*
		 * rel.r_offset: (find need modified instruction)
		 * The value indicates a section offset. The relocation section itself
		 * describes how to modify another section in the file. Relocation offsets
		 * designate a storage unit within the second section.
		 */
		insn_idx = rel.r_offset / sizeof(struct bpf_insn);
		/*
		 * rel.r_info: (find map symbol)
		 * This member gives both the symbol table index, with respect to which
		 * the relocation must be made, and the type of relocation to apply.
		 */
		// Finds the symbol associated with the relo entry,
		// Use sym.st_value to associate a map.
		if (find_sym_by_idx
		    (obj->elf_info.elf, scn_syms,
		     GELF_R_SYM(rel.r_info), &sym) != ETR_OK) {
			ebpf_warning("Not find symbol, sym_idx:%d\n",
				     GELF_R_SYM(rel.r_info));
			return ETR_INVAL;
		}
		// is load double word (64-bit) ? (Verify the correctness of instructions)
		if (insns[insn_idx].code != (BPF_LD | BPF_IMM | BPF_DW)) {
			ebpf_warning
			    ("Relo(%s) insns[%u] code 0x%x is invalid.\n",
			     desc->name, insn_idx, insns[insn_idx].code);
			return ETR_INVAL;
		}

		/*
		 * insns[0].src_reg:  BPF_PSEUDO_MAP_FD
		 * insns[0].imm:      map fd
		 * insns[1].imm:      0
		 * insns[0].off:      0
		 * insns[1].off:      0
		 * ldimm64 rewrite:  address of map
		 * verifier type:    CONST_PTR_TO_MAP
		 */
		insns[insn_idx].src_reg = BPF_PSEUDO_MAP_FD;
		// Get map info from sym.st_value
		for (map_i = 0; map_i < obj->maps_cnt; map_i++) {
			// sym.st_value, Associate map and symbol
			if (obj->maps[map_i].elf_offset == sym.st_value) {
				insns[insn_idx].imm = obj->maps[map_i].fd;
				break;
			}
		}

		if (map_i >= obj->maps_cnt) {
			ebpf_warning
			    ("Relo(%s) insns[%u] no map data match\n",
			     desc->name, insn_idx);
			return ETR_INVAL;
		}
	}

	return ETR_OK;
}

static enum bpf_prog_type get_prog_type(struct sec_desc *desc)
{
	enum bpf_prog_type prog_type = BPF_PROG_TYPE_UNSPEC;
	if (!memcmp(desc->name, "kprobe/", 7) ||
	    !memcmp(desc->name, "kretprobe/", 10) ||
	    !memcmp(desc->name, "uprobe/", 7) ||
	    !memcmp(desc->name, "uretprobe/", 10)) {
		prog_type = BPF_PROG_TYPE_KPROBE;
	} else if (!memcmp(desc->name, "tracepoint/", 11)) {
		prog_type = BPF_PROG_TYPE_TRACEPOINT;
	} else if (!memcmp(desc->name, "perf_event", 10)) {
		prog_type = BPF_PROG_TYPE_PERF_EVENT;
	} else {
		prog_type = BPF_PROG_TYPE_UNSPEC;
	}

	return prog_type;
}

static int load_obj__progs(struct ebpf_object *obj)
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
		return ETR_INVAL;
	}

	for (i = 0; i < progs_cnt; i++) {
		desc = &prog_descs[i];
		insns = (struct bpf_insn *)desc->d_buf;	// SHT_PROGBITS & SHF_EXECINSTR data buffer
		scn_rel = elf_getscn(obj->elf_info.elf, desc->shndx_rel);
		if (gelf_getshdr(scn_rel, &shdr_rel) == NULL) {
			ebpf_warning("gelf_getshdr() is failed.\n");
			return ETR_INVAL;
		}

		data_rel = elf_getdata(scn_rel, 0);
		if (data_rel == NULL) {
			ebpf_warning("gelf_getshdr() is failed.\n");
			return ETR_INVAL;
		}
		// process relo sections, and rewrite bpf insns for maps
		if (relo_parse_and_apply
		    (obj, &shdr_rel, scn_syms, insns, data_rel,
		     desc) != ETR_OK) {
			return ETR_INVAL;
		}

		enum bpf_prog_type prog_type = get_prog_type(desc);
		if (prog_type == BPF_PROG_TYPE_UNSPEC) {
			if (!memcmp(desc->name, "prog/tp/", 8)) {
				prog_type = BPF_PROG_TYPE_TRACEPOINT;
			} else if (!memcmp(desc->name, "prog/kp/", 8)) {
				prog_type = BPF_PROG_TYPE_KPROBE;
			} else {
				ebpf_warning
				    ("Prog %s type %d invalid\n",
				     desc->name, prog_type);
				return ETR_INVAL;
			}
		}

		if (find_prog_func_sym
		    (obj->elf_info.elf, scn_syms, desc->shndx,
		     &sym) != ETR_OK) {
			ebpf_warning
			    ("Not find program function symbol, program shndx:%d\n",
			     desc->shndx);
			return ETR_INVAL;
		}

		char *sym_name = elf_strptr(obj->elf_info.elf,
					    obj->elf_info.syms_sec->strtabidx,
					    sym.st_name);

		new_prog = NULL;
		add_new_prog(obj->progs, obj->progs_cnt, new_prog);
		if (new_prog == NULL) {
			return ETR_INVAL;
		}

		new_prog->sec_name = strdup(desc->name);
		if (new_prog->sec_name == NULL)
			return ETR_NOMEM;

		new_prog->name = strdup(sym_name);
		if (new_prog->name == NULL) {
			ebpf_warning("strdup() failed.\n");
			return ETR_NOMEM;
		}

		new_prog->insns = insns;
		new_prog->insns_cnt = desc->size / sizeof(struct bpf_insn);
		new_prog->obj = obj;
		new_prog->type = prog_type;

		/*
		 * Addressing the adaptability issues of bpf_probe_read{kernel,user}[_str]
		 * helpers in the kernel.
		 */
		sanitize_prog_instructions(obj, new_prog);

		new_prog->prog_fd =
		    bcc_prog_load(new_prog->type, new_prog->name,
				  new_prog->insns, desc->size,
				  obj->license, obj->kern_version, 0, NULL, 0
				  /*EBPF_LOG_LEVEL, log_buf, LOG_BUF_SZ */
		    );

		if (new_prog->prog_fd < 0) {
			ebpf_warning
			    ("bcc_prog_load() failed. name: %s, %s errno: %d\n",
			     new_prog->name, strerror(errno), errno);
			if (new_prog->insns_cnt > BPF_MAXINSNS) {
				ebpf_warning
				    ("The number of EBPF instructions (%d) "
				     "exceeded the maximum limit (%d).\n",
				     new_prog->insns_cnt, BPF_MAXINSNS);
			}

			return ETR_INVAL;
		}

		ebpf_debug
		    ("sec_name %s\tfunc %s\tinsns_cnt %zd\tprog_type %d\tFD %d\t"
		     "license %s\tkern_version %u\n",
		     new_prog->sec_name, new_prog->name,
		     new_prog->insns_cnt, new_prog->type,
		     new_prog->prog_fd, obj->license, obj->kern_version);
	}

	return ETR_OK;
}

static int ebpf_btf_collect(struct ebpf_object *obj)
{
	struct sec_desc *desc = obj->elf_info.btf_sec;
	struct btf *btf = btf__new(desc->d_buf, desc->size);
	if (DF_IS_ERR(btf)) {
		ebpf_warning("Processing \".BTF\" section failed.\n");
		obj->btf = NULL;
		return ETR_INVAL;
	}

	ebpf_debug("[%s] \"%s\" create success.\n", __func__, desc->name);

	obj->btf = btf;
	btf__set_pointer_size(obj->btf, 8);

	return ETR_OK;
}

static int ebpf_btf_ext_collect(struct ebpf_object *obj)
{
	struct sec_desc *desc = obj->elf_info.btf_ext_sec;
	struct btf_ext *ext = btf_ext__new(desc->d_buf, desc->size);
	if (DF_IS_ERR(ext)) {
		ebpf_warning("Processing .BTF.ext section failed\n");
		obj->btf_ext = NULL;
		return ETR_INVAL;
	}

	ebpf_debug("[%s] btf_ext name \"%s\" create success.\n",
		   __func__, desc->name);
	obj->btf_ext = ext;

	return ETR_OK;
}

static int ebpf_obj__maps_collect(struct ebpf_object *obj)
{
	struct sec_desc *map_desc = obj->elf_info.map_sec;
	if (!map_desc->is_valid) {
		ebpf_warning("section \"maps\" is not exist.\n");
		return ETR_INVAL;
	}

	struct sec_desc *syms_desc = obj->elf_info.syms_sec;
	Elf_Scn *syms_scn;
	Elf_Data *syms_data;
	GElf_Sym sym;
	size_t syms_count, i, nr_maps, len;
	char *map_name;
	syms_scn = elf_getscn(obj->elf_info.elf, syms_desc->shndx);
	if (syms_scn == NULL) {
		ebpf_warning("elf_getscn() is error\n");
		return ETR_INVAL;
	}

	syms_data = elf_getdata(syms_scn, NULL);
	if (syms_data == NULL) {
		ebpf_warning("elf_getdata() is error\n");
		return ETR_INVAL;
	}

	syms_count = syms_desc->size / sizeof(GElf_Sym);
	if (syms_count <= 0) {
		ebpf_warning("syms_count is invalid, value is %zd.\n",
			     syms_count);
		return ETR_INVAL;
	}

	/*
	 * Look up the symbol table to find the map symbols,
	 * the purpose of counting the number of maps
	 */
	for (i = 0, nr_maps = 0; i < syms_count; i++) {
		if (!gelf_getsym(syms_data, (int)i, &sym))
			continue;

		// section index of symbol is section "maps" ?
		if (sym.st_shndx != map_desc->shndx)
			continue;

		nr_maps++;
	}

	int map_size = map_desc->size / nr_maps;
	int cp_sz = sizeof(struct bpf_load_map_def);
	if (map_size < sizeof(struct bpf_load_map_def)) {
		cp_sz = map_size;
	}

	struct ebpf_map *new_map;
	struct bpf_load_map_def *def;

	for (i = 0, nr_maps = 0; i < syms_count; i++) {
		/*
		 * Via sym.st_shndx == map_desc->shndx 
		 * associate a symbol table with "maps" segment
		 * "maps" segment
		 *      |---- sym-1
		 *      |---- sym-2
		 *      |---- sym-3
		 *      |---- ...
		 */
		if (!gelf_getsym(syms_data, (int)i, &sym))
			continue;

		if (sym.st_shndx != map_desc->shndx)
			continue;

		// The name of the symbol is stored in the sym->st_name subscript of the string table
		// sym.st_name: Symbol name index in str table
		if ((map_name =
		     elf_strptr(obj->elf_info.elf, syms_desc->strtabidx,
				sym.st_name)) == NULL)
			continue;

		len = strlen(map_name);
		if (len <= 0) {
			continue;
		}

		if (len >= MAP_NAME_SZ) {
			ebpf_warning
			    ("map_name(\"%s\") is too long, has to be less than %d\n",
			     map_name, MAP_NAME_SZ);
			return ETR_INVAL;
		}

		new_map = NULL;
		add_new_map(obj->maps, obj->maps_cnt, new_map);
		if (new_map == NULL) {
			return ETR_INVAL;
		}

		if (sym.st_value + map_size > map_desc->size) {
			ebpf_warning("corrupted maps section(%s)\n", map_name);
			return ETR_INVAL;
		}

		new_map->fd = -1;
		// Symbol value is offset into ELF maps section data area.
		new_map->elf_offset = sym.st_value;
		safe_buf_copy(new_map->name, sizeof(new_map->name),
			      map_name, strlen(map_name));
		new_map->name[sizeof(new_map->name) - 1] = '\0';
		def =
		    (struct bpf_load_map_def *)(map_desc->d_buf +
						new_map->elf_offset);
		memset(&new_map->def, 0, sizeof(struct bpf_load_map_def));
		memcpy(&new_map->def, def, cp_sz);
		ebpf_debug
		    ("map_name %s\tmaps_cnt:%d\toffset %zd\ttype %u\tkey_size "
		     "%u\tvalue_size %u\tmax_entries %u\n",
		     map_name, obj->maps_cnt, new_map->elf_offset,
		     new_map->def.type, new_map->def.key_size,
		     new_map->def.value_size, new_map->def.max_entries);
	}

	return ETR_OK;
}

struct ebpf_prog *ebpf_obj__get_prog_by_name(const struct ebpf_object
					     *obj, const char *name)
{
	int prog_i;
	for (prog_i = 0; prog_i < obj->progs_cnt; prog_i++) {
		if (!strcmp(obj->progs[prog_i].name, name)) {
			return &obj->progs[prog_i];
		}
	}

	return NULL;
}

struct ebpf_map *ebpf_obj__get_map_by_name(const struct ebpf_object
					   *obj, const char *name)
{
	int map_i;
	for (map_i = 0; map_i < obj->maps_cnt; map_i++) {
		if (!strcmp(obj->maps[map_i].name, name)) {
			return &obj->maps[map_i];
		}
	}

	return NULL;
}

int ebpf_map_size_adjust(struct ebpf_map *map, uint32_t max_sz)
{
	if (!map || !max_sz) {
		ebpf_warning
		    ("Parameter map(%p) or max_sz(%u) invalid\n", map, max_sz);
		return ETR_INVAL;
	}

	if (map->fd >= 0) {
		ebpf_warning
		    ("Set map size before map creation. map->fd:%d\n", map->fd);
		return ETR_INVAL;
	}

	map->def.max_entries = max_sz;
	return ETR_OK;
}

struct ebpf_object *ebpf_open_buffer(const void *buf, size_t buf_sz,
				     const char *name)
{
	if (elf_version(EV_CURRENT) == EV_NONE) {
		ebpf_warning("failed to init libelf.\n");
		return NULL;
	}

	if (buf_sz <= 0 || buf == NULL || name == NULL) {
		ebpf_warning("name %s buffer %p buf size %d.\n", name,
			     buf, buf_sz);
		return NULL;
	}

	struct ebpf_object *obj = create_new_obj(buf, buf_sz, name);
	if (obj == NULL) {
		return NULL;
	}

	if (elf_info_collect(&obj->elf_info, buf, buf_sz) != ETR_OK) {
		goto failed;
	}

	if (set_obj__version(obj) != ETR_OK) {
		goto failed;
	}

	set_obj__license(obj);
	if (ebpf_obj__maps_collect(obj) != ETR_OK) {
		goto failed;
	}

	if (ebpf_btf_collect(obj) != ETR_OK) {
		goto failed;
	}

	if (ebpf_btf_ext_collect(obj) != ETR_OK) {
		goto failed;
	}

	return obj;

failed:
	ebpf_warning("eBPF open buffer failed.\n");
	release_object(obj);
	return NULL;
}

int ebpf_obj_load(struct ebpf_object *obj)
{
	int i;
	struct ebpf_map *map;
	for (i = 0; i < obj->maps_cnt; i++) {
		map = &obj->maps[i];
		map->fd =
		    bcc_create_map(map->def.type, map->name,
				   map->def.key_size,
				   map->def.value_size,
				   map->def.max_entries, 0);
		if (map->fd < 0) {
			ebpf_warning
			    ("bcc_create_map() failed, map name:%s - %s\n",
			     map->name, strerror(errno));
			goto failed;
		}
		ebpf_debug
		    ("map->fd:%d map->def.type:%d, map->name:%s, map->def.key_size:%d,"
		     "map->def.value_size:%d, map->def.max_entries:%d\n",
		     map->fd, map->def.type, map->name,
		     map->def.key_size, map->def.value_size,
		     map->def.max_entries);
	}

	ebpf_obj__load_vmlinux_btf(obj);

	if (load_obj__progs(obj) != ETR_OK) {
		goto failed;
	}

	ebpf_object__release_elf(obj);

	return ETR_OK;

failed:
	ebpf_warning("eBPF load programs failed. (errno %d)\n", errno);
	release_object(obj);
	return ETR_INVAL;
}
