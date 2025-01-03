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
#include "utils.h"
#include "log.h"
#include "elf.h"
#include <bcc/linux/bpf.h>
#include <bcc/linux/bpf_common.h>
#include <bcc/libbpf.h>		// kernel_struct_has_field()
#include <bcc/linux/btf.h>
#include "load.h"
#include "btf_core.h"
#include "kernel/include/utils.h"	// ARRAY_SIZE
#include "hashmap.h"
#include "relo_core.h"

extern const char *btf__name_by_offset(const struct btf *btf, __u32 offset);
extern __s32 btf__find_by_name_kind(const struct btf *btf,
				    const char *type_name, __u32 kind);
extern struct btf *btf__parse_elf(const char *path, struct btf_ext **btf_ext);
extern struct btf *btf__parse_raw(const char *path);
extern const char *btf__name_by_offset(const struct btf *btf, uint32_t offset);
extern void btf__free(struct btf *btf);
extern const struct btf_type *btf__type_by_id(const struct btf *btf,
					      __u32 type_id);
extern const char *btf_kind_str(const struct btf_type *t);
extern void bpf_core_free_cands(struct bpf_core_cand_list *cands);
extern int bpf_core_add_cands(struct bpf_core_cand *local_cand,
			      size_t local_essent_len,
			      const struct btf *targ_btf,
			      const char *targ_btf_name,
			      int targ_start_id,
			      struct bpf_core_cand_list *cands);
static inline bool str_is_empty(const char *s)
{
	return !s || !s[0];
}

static bool prog_contains_insn(struct ebpf_prog *prog, size_t insn_idx)
{
	return insn_idx >= prog->sec_insn_off &&
	    insn_idx < prog->sec_insn_off + prog->sec_insn_cnt;
}

static void *u32_as_hash_key(__u32 x)
{
	return (void *)(uintptr_t) x;
}

static inline long PTR_ERR(const void *ptr)
{
	return (long)ptr;
}

static inline void *ERR_PTR(long error_)
{
	return (void *)error_;
}

const char *btf_name_by_offset(const struct btf *btf, __u32 offset)
{
	return btf__name_by_offset(btf, offset);
}

static struct bpf_core_cand_list *bpf_core_find_cands(struct ebpf_object *obj, const struct btf
						      *local_btf,
						      __u32 local_type_id)
{
	struct bpf_core_cand local_cand = {};
	struct bpf_core_cand_list *cands;
	const struct btf *main_btf;
	const struct btf_type *local_t;
	const char *local_name;
	size_t local_essent_len;
	int err;

	local_cand.btf = local_btf;
	local_cand.id = local_type_id;
	local_t = btf__type_by_id(local_btf, local_type_id);
	if (!local_t)
		return ERR_PTR(-EINVAL);

	local_name = btf__name_by_offset(local_btf, local_t->name_off);
	if (str_is_empty(local_name))
		return ERR_PTR(-EINVAL);
	local_essent_len = bpf_core_essential_name_len(local_name);

	cands = calloc(1, sizeof(*cands));
	if (!cands)
		return ERR_PTR(-ENOMEM);

	main_btf = obj->btf_vmlinux;
	err =
	    bpf_core_add_cands(&local_cand, local_essent_len, main_btf,
			       "vmlinux", 1, cands);
	if (err)
		goto err_out;

	/* if vmlinux BTF has any candidate, don't got for module BTFs */
	if (cands->len)
		return cands;

	return cands;
err_out:
	bpf_core_free_cands(cands);
	return ERR_PTR(err);
}

static int bpf_core_resolve_relo(struct ebpf_prog *prog,
				 const struct btf *btf,
				 struct hashmap *cand_cache,
				 int relo_idx, const struct bpf_core_relo *rec,
				 struct bpf_core_relo_res *targ_res)
{
	struct bpf_core_spec specs_scratch[3] = {};
	struct bpf_core_cand_list *cands = NULL;
	const void *type_key = u32_as_hash_key(rec->type_id);
	const struct btf_type *local_type;
	const char *local_name;
	int err;

	// BTF type ID of the "root" (containing) entity of a relocatable
	u32 local_id = rec->type_id;
	local_type = btf__type_by_id(btf, local_id);
	if (!local_type)
		return -1;
	local_name = btf__name_by_offset(btf, local_type->name_off);
	if (!local_name)
		return -1;
	// prog 'kfunc__do_unlinkat': relo #0: target candidate search [101] 'struct filename'
	ebpf_debug
	    ("prog '%s': relo #%d: target candidate search [%d] '%s %s'\n",
	     prog->name, relo_idx, local_id, btf_kind_str(local_type),
	     local_name);

	if (rec->kind != BPF_CORE_TYPE_ID_LOCAL &&
	    !hashmap__find(cand_cache, type_key, (void **)&cands)) {
		cands = bpf_core_find_cands(prog->obj, btf, local_id);
		if (DF_IS_ERR(cands)) {
			ebpf_warning
			    ("prog '%s': relo #%d: target candidate search failed for [%d] %s %s: %ld\n",
			     prog->name, relo_idx, local_id,
			     btf_kind_str(local_type), local_name, (long)cands);
			return (long)cands;
		}
		err = hashmap__set(cand_cache, type_key, cands, NULL, NULL);
		if (err) {
			bpf_core_free_cands(cands);
			return err;
		}
	}
	// check_core_relo(btf, rec);

	//// prog 'kfunc__do_unlinkat': relo #0: <byte_off> [101] struct filename.name (0:1 @ offset 8)
	//ebpf_debug("prog '%s': relo #%d: %s\n", prog->name, relo_idx, spec_buf);

	return bpf_core_calc_relo_insn(prog->name, rec, relo_idx, btf, cands,
				       specs_scratch, targ_res);
}

static size_t bpf_core_hash_fn(const void *key, void *ctx)
{
	return (size_t) key;
}

static bool bpf_core_equal_fn(const void *k1, const void *k2, void *ctx)
{
	return k1 == k2;
}

/*
 * Clang has a built-in attribute __attribute__((preserve_access_index))
 * (equivalent to __builtin_preserve_access_index). Uses this attribute to
 * mark all the structures it needs to access. Clang generates a 'bpf_core_relo'
 * for each such access in the object ELF file.
 */
int obj_relocate_core(struct ebpf_prog *prog)
{
	const struct btf_ext_info_sec *sec;
	const struct bpf_core_relo *rec;
	const struct btf_ext_info *seg;
	const char *sec_name;
	int i, err = 0, insn_idx, sec_idx, sec_num;
	struct sec_desc *desc = prog->sec_desc;
	struct ebpf_object *obj = prog->obj;
	struct bpf_core_relo_res targ_res;
	struct bpf_insn *insn;

	struct hashmap_entry *entry;
	struct hashmap *cand_cache = NULL;
	cand_cache = hashmap__new(bpf_core_hash_fn, bpf_core_equal_fn, NULL);
	if (DF_IS_ERR(cand_cache)) {
		err = PTR_ERR(cand_cache);
		return -1;
	}

	seg = &obj->btf_ext->core_relo_info;
	sec_num = 0;
	// Traverse the section of BTF extended information.
	for_each_btf_ext_sec(seg, sec) {
		sec_idx = seg->sec_idxs[sec_num];
		sec_num++;
		sec_name = btf__name_by_offset(obj->btf, sec->sec_name_off);
		if (str_is_empty(sec_name)) {
			return -1;
		}
		// Traverse the CO-RE relocation information.
		for_each_btf_ext_rec(seg, sec, i, rec) {
			if (rec->insn_off % BPF_INSN_SZ)
				return -1;
			insn_idx = rec->insn_off / BPF_INSN_SZ;
			// Verify whether this PORG contains BTF relocation information.
			if (strcmp(sec_name, desc->name) == 0
			    && sec_idx == desc->shndx
			    && prog_contains_insn(prog, insn_idx)) {
				// Adjust to the local program's instruction index.
				insn_idx = insn_idx - prog->sec_insn_off;
				// e.g.: sec 'fentry/do_unlinkat': found 2 CO-RE relocations,
				// sec_idx 36 shndx 36 shndx_rel 105, insn_idx 30 prog->insns_cnt 57
				ebpf_debug
				    ("sec '%s': found %d CO-RE relocations, sec_idx %d shndx %ld "
				     "shndx_rel %ld, insn_idx %d prog->insns_cnt %d\n",
				     sec_name, sec->num_info, sec_idx,
				     desc->shndx, desc->shndx_rel, insn_idx,
				     prog->insns_cnt);

				if (insn_idx >= prog->insns_cnt)
					return -1;
				insn = &prog->insns[insn_idx];
				err =
				    bpf_core_resolve_relo(prog, obj->btf,
							  cand_cache, i, rec,
							  &targ_res);
				if (err) {
					ebpf_warning
					    ("prog '%s': relo #%d: failed to relocate: %d\n",
					     prog->name, i, err);
					goto out;
				}
				err =
				    bpf_core_patch_insn(prog->name, insn,
							insn_idx, rec, i,
							&targ_res);
				if (err) {
					ebpf_warning
					    ("prog '%s': relo #%d: failed to patch insn #%u: %d\n",
					     prog->name, i, insn_idx, err);
					goto out;
				}
			}

		}
	}

out:
	if (!DF_IS_ERR_OR_NULL(cand_cache)) {
		hashmap__for_each_entry(cand_cache, entry, i) {
			bpf_core_free_cands(entry->value);
		}
		hashmap__free(cand_cache);
	}
	return err;
}

static struct btf *ebpf__load_vmlinux_btf(void)
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
			return btf;
		}
	}

	return NULL;
}

int ebpf_obj__load_vmlinux_btf(struct ebpf_object *obj)
{
	obj->btf_vmlinux = NULL;
	struct btf *btf = ebpf__load_vmlinux_btf();
	if (btf == NULL)
		return ETR_INVAL;
	obj->btf_vmlinux = btf;
	return ETR_OK;
}

static int kernel_struct_field_offset_helper(struct btf *btf, int btf_id,
					     const char *field_name)
{
	int i;
	const struct btf_type *btf_type = btf__type_by_id(btf, btf_id);
	const struct btf_member *btf_member =
	    (struct btf_member *)(btf_type + 1);

	for (i = 0; i < BTF_INFO_VLEN(btf_type->info); i++, btf_member++) {
		if (!strcmp(btf__name_by_offset(btf, btf_member->name_off),
			    field_name)) {
			return BTF_MEM_OFFSET(btf_type->info,
					      btf_member->offset) / 8;
		}
		if (!strcmp(btf__name_by_offset(btf, btf_member->name_off), "")) {
			int retval = kernel_struct_field_offset_helper(btf,
								       btf_member->
								       type,
								       field_name);
			if (retval >= 0) {
				return (BTF_MEM_OFFSET(btf_type->info,
						       btf_member->offset) /
					8) + retval;
			}
		}
	}
	return ETR_NOTEXIST;
}

int kernel_struct_field_offset(struct ebpf_object *obj, const char *struct_name,
			       const char *field_name)
{
	struct btf *btf;
	int btf_id;
	btf = obj->btf_vmlinux;

	if (DF_IS_ERR_OR_NULL(btf)) {
		return ETR_NOTEXIST;
	}

	btf_id = btf__find_by_name_kind(btf, struct_name, BTF_KIND_STRUCT);
	if (btf_id < 0) {
		ebpf_warning("BTF struct %s can not found\n", struct_name);
		return ETR_NOTEXIST;
	}

	int retval = kernel_struct_field_offset_helper(btf, btf_id, field_name);
	if (retval < 0) {
		ebpf_warning("BTF member %s of struct %s can not be found\n",
			     field_name, struct_name);
		return ETR_NOTEXIST;
	}

	return retval;
}

int get_kfunc_params_num(const char *func_name)
{
	struct btf *btf = ebpf__load_vmlinux_btf();
	if (!btf) {
		ebpf_info("Failed to load vmlinux BTF\n");
		return -1;
	}

	int type_id = btf__find_by_name_kind(btf, func_name, BTF_KIND_FUNC);
	if (type_id < 0) {
		ebpf_warning("Failed to find BTF type for %s\n", func_name);
		return -1;
	}
	const struct btf_type *t = btf__type_by_id(btf, type_id);
	if (!t) {
		ebpf_warning
		    ("Invalid BTF type or not a function prototype for %s\n",
		     func_name);
		return -1;
	}
	if ((((t->info) >> 24) & 0x1f) != BTF_KIND_FUNC)
		return -1;
	t = btf__type_by_id(btf, t->type);
	if (!t || (((t->info) >> 24) & 0x1f) != BTF_KIND_FUNC_PROTO)
		return -1;
	int num = ((t->info) & 0xffff);
	btf__free(btf);
	return num;
}
