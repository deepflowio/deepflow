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

#ifndef DF_BPF_TABLE_H
#define DF_BPF_TABLE_H
#include "tracer.h"

unsigned int bpf_table_key_size(struct ebpf_map *map);
unsigned int bpf_table_value_size(struct ebpf_map *map);
unsigned int bpf_table_max_entries(struct ebpf_map *map);
unsigned int bpf_table_flags(struct ebpf_map *map);
bool bpf_table_get_value(struct bpf_tracer *tracer,
			 const char *tb_name,
			 uint64_t key,
                         void *val_buf);
bool bpf_table_set_value(struct bpf_tracer * tracer,
                         const char *tb_name, uint64_t key, void *val_buf);
uint32_t bpf_table_elems_count(struct bpf_tracer * tracer,
			       const char *tb_name);
#endif /* DF_BPF_TABLE_H */
