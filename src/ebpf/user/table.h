#ifndef _BPF_TABLE_H_
#define _BPF_TABLE_H_
#include "libbpf/include/linux/err.h"

unsigned int bpf_table_key_size(struct bpf_map *map);
unsigned int bpf_table_value_size(struct bpf_map *map);
unsigned int bpf_table_max_entries(struct bpf_map *map);
unsigned int bpf_table_flags(struct bpf_map *map);
bool bpf_table_get_value(struct bpf_tracer *tracer,
			 const char *tb_name,
			 uint64_t key,
                         void *val_buf);
bool bpf_table_set_value(struct bpf_tracer * tracer,
                         const char *tb_name, uint64_t key, void *val_buf);
uint32_t bpf_table_elems_count(struct bpf_tracer * tracer,
			       const char *tb_name);
#endif
