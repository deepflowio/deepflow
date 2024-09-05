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

#ifndef DF_BTF_CORE_H_
#define DF_BTF_CORE_H_

struct elf_info;
struct btf_ext;
struct btf;
struct btf_type;

struct btf_ext_info {
	/*
	 * info points to the individual info section (e.g. func_info and
	 * line_info) from the .BTF.ext. It does not include the __u32 rec_size.
	 */
	void *info;
	__u32 rec_size;
	__u32 len;
	/* optional (maintained internally by libbpf) mapping between .BTF.ext
	 * section and corresponding ELF section. This is used to join
	 * information like CO-RE relocation records with corresponding BPF
	 * programs defined in ELF sections
	 */
	__u32 *sec_idxs;
	int sec_cnt;
};

#define for_each_btf_ext_sec(seg, sec)                                  \
  for (sec = (seg)->info;                                         \
       (void *)sec < (seg)->info + (seg)->len;                    \
       sec = (void *)sec + sizeof(struct btf_ext_info_sec) +      \
             (seg)->rec_size * sec->num_info)

#define for_each_btf_ext_rec(seg, sec, i, rec)                          \
  for (i = 0, rec = (void *)&(sec)->data;                         \
       i < (sec)->num_info;                                       \
       i++, rec = (void *)rec + (seg)->rec_size)

struct btf_ext_header {
	__u16 magic;
	__u8 version;
	__u8 flags;
	__u32 hdr_len;

	/* All offsets are in bytes relative to the end of this header */
	__u32 func_info_off;
	__u32 func_info_len;
	__u32 line_info_off;
	__u32 line_info_len;

	/* optional part of .BTF.ext header */
	__u32 core_relo_off;
	__u32 core_relo_len;
};

struct btf_ext {
	union {
		struct btf_ext_header *hdr;
		void *data;
	};
	struct btf_ext_info func_info;
	struct btf_ext_info line_info;
	struct btf_ext_info core_relo_info;
	__u32 data_size;
};

struct btf_ext_info_sec {
	__u32 sec_name_off;
	__u32 num_info;
	/* Followed by num_info * record_size number of bytes */
	__u8 data[];
};

#define BTF_MEMBER_BIT_OFFSET(val)      ((val) & 0xffffff)
#define BTF_INFO_KFLAG(info)    ((info) >> 31)
#define BTF_MEM_OFFSET(T, O)    (BTF_INFO_KFLAG((T)) ? BTF_MEMBER_BIT_OFFSET((O)) : (O))

int ebpf_obj__load_vmlinux_btf(struct ebpf_object *obj);
int kernel_struct_field_offset(struct ebpf_object *obj, const char *struct_name,
			       const char *field_name);
const char *btf_name_by_offset(const struct btf *btf, __u32 offset);
int obj_relocate_core(struct ebpf_prog *prog);
int get_kfunc_params_num(const char *func_name);
#endif /* DF_BTF_CORE_H_ */
