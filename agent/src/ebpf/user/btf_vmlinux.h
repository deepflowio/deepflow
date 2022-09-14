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

#ifndef DF_BTF_VMLINUX_H_
#define DF_BTF_VMLINUX_H_

#define BTF_MEMBER_BIT_OFFSET(val)      ((val) & 0xffffff)
#define BTF_INFO_KFLAG(info)    ((info) >> 31)
#define BTF_MEM_OFFSET(T, O)    (BTF_INFO_KFLAG((T)) ? BTF_MEMBER_BIT_OFFSET((O)) : (O))

int ebpf_obj__load_vmlinux_btf(struct ebpf_object *obj);
int kernel_struct_field_offset(struct ebpf_object *obj, const char *struct_name,
			       const char *field_name);

#endif /* DF_BTF_VMLINUX_H_ */
