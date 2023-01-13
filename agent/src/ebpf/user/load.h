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

#ifndef DF_BPF_LOAD_H
#define DF_BPF_LOAD_H

#ifndef BPF_MAXINSNS
#define BPF_MAXINSNS 4096
#endif

#define OBJ_NAME_SZ 128
#define MAP_NAME_SZ 128

#define EBPF_LOG_LEVEL1 1
#define EBPF_LOG_LEVEL2 2
#define EBPF_LOG_LEVEL  (EBPF_LOG_LEVEL1 | EBPF_LOG_LEVEL2)

struct elf_info;
struct btf_ext;
struct btf;

#define DF_MAX_ERRNO       4095
#define DF_IS_ERR_VALUE(x) ((x) >= (unsigned long)-DF_MAX_ERRNO)
#define DF_IS_ERR(ptr) DF_IS_ERR_VALUE((unsigned long)ptr)
#define DF_IS_ERR_OR_NULL(ptr) (DF_IS_ERR(ptr) || (ptr) == NULL)

/* eBPF programs must be GPL compatible to use GPL-ed functions */
#define LICENSE_DEF "GPL"

#define _v(var) _vec_##var

/*
 * @param V pointer to a vector
 * @param N number of elements
 * @param P pointer to new vector element
 */
#define add_new_vec(V, N, P) \
do {                                                            \
	__typeof__ ((N)) _v(l) = (N) + 1;                       \
	__typeof__ ((N)) _v(c_sz) = _v(l) * sizeof((V)[0]);     \
	__typeof__ ((V)[0]) *_v(tmp) = realloc((V), _v(c_sz));  \
	if (_v(tmp) == NULL) {                                  \
		ebpf_warning("realloc() error\n");              \
		P = NULL;                                       \
	} else {                                                \
		if (_v(tmp) != (V)) {                           \
			V = _v(tmp);                            \
		}                                               \
		P = (V) + (N);                                  \
		memset((P), 0, sizeof((V)[0]));			\
		N = _v(l);                                      \
	}                                                       \
} while(0)

#define add_new_map(V, N, P)  add_new_vec(V, N, P)
#define add_new_prog(V, N, P)  add_new_vec(V, N, P)

struct ebpf_object;

struct ebpf_prog {
	int prog_fd;
	char *sec_name;		// section name
	char *name;		// function name
	struct bpf_insn *insns;	// instructions that belong to BPF program
	size_t insns_cnt;
	struct ebpf_object *obj;
	enum bpf_prog_type type;
};

struct bpf_load_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
	unsigned int inner_map_idx;
	unsigned int numa_node;
};

struct ebpf_map {
	int fd;
	char name[MAP_NAME_SZ];
	size_t elf_offset;
	struct bpf_load_map_def def;
};

struct ebpf_object {
	char name[OBJ_NAME_SZ];
	struct elf_info elf_info;
	char license[128];
	unsigned int kern_version;
	struct ebpf_map *maps;
	int maps_cnt;
	struct ebpf_prog *progs;
	int progs_cnt;
	struct btf *btf;
	struct btf_ext *btf_ext;
	struct btf *btf_vmlinux;
};

struct ebpf_object *ebpf_open_buffer(const void *buf, size_t buf_sz,
				     const char *name);
int ebpf_map_size_adjust(struct ebpf_map *map, uint32_t max_sz);
struct ebpf_map *ebpf_obj__get_map_by_name(const struct ebpf_object *obj,
					   const char *name);
int ebpf_obj_load(struct ebpf_object *obj);
void release_object(struct ebpf_object *obj);
struct ebpf_prog *ebpf_obj__get_prog_by_name(const struct ebpf_object *obj,
					     const char *name);
#endif /* DF_BPF_LOAD_H */
