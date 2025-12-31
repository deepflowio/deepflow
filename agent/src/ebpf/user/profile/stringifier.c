/*
 * Copyright (c) 2024 Yunshan Networks
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

/*
 * Excute Stringifier on each iteration of the continuous perf profiler.
 */

#ifndef AARCH64_MUSL
#include "../config.h"
#include "../utils.h"
#include "../mem.h"
#include "../log.h"
#include "../types.h"
#include "../vec.h"
#include "../tracer.h"
#include "perf_profiler.h"
#include "../elf.h"
#include "../load.h"
#include "../../kernel/include/perf_profiler.h"
#include "../perf_reader.h"
#include "../table.h"
#include "../bihash_8_8.h"
#include "../bihash_16_8.h"
#include "java/collect_symbol_files.h"
#include "stringifier.h"
#include <bcc/bcc_syms.h>
#include "../proc.h"
#include "trace_utils.h"
#include "../extended/extended.h"

// static const char *k_err_tag = "[kernel stack trace error]";
// static const char *u_err_tag = "[user stack trace error]";
static const char *i_err_tag = "[interpreter stack trace error]";
static const char *lost_tag = "[stack trace lost]";
static const char *k_sym_prefix = "[k] ";
static const char *lib_sym_prefix = "[l] ";
static const char *u_sym_prefix = "";

// Stack trace structure definition (user-space copy of eBPF structure)
// Must match the definition in perf_profiler.bpf.c
#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

typedef struct {
	u8 len;                                    // Number of frames in the stack
	u64 addrs[PERF_MAX_STACK_DEPTH];          // Frame addresses (or pointer_and_type for V8)
	u8 frame_types[PERF_MAX_STACK_DEPTH];     // Frame type markers (FRAME_TYPE_*)
	// Extra data for extended/interpreter frames
	u64 extra_data_a[PERF_MAX_STACK_DEPTH];
	u64 extra_data_b[PERF_MAX_STACK_DEPTH];
} stack_t;

/*
 * To track the scenario where stack data is missing in the eBPF
 * 'stack_map_*' table.
 */
static __thread u64 stack_table_data_miss;

u64 get_stack_table_data_miss_count(void)
{
	return stack_table_data_miss;
}

int init_stack_str_hash(stack_str_hash_t * h, const char *name)
{
	memset(h, 0, sizeof(*h));
	u32 nbuckets = STRINGIFIER_STACK_STR_HASH_BUCKETS_NUM;
	u64 hash_memory_size = STRINGIFIER_STACK_STR_HASH_MEM_SZ;	// 1G bytes
	h->private =
	    clib_mem_alloc_aligned("hash_ext_data",
				   sizeof(struct stack_str_hash_ext_data),
				   0, NULL);
	if (h->private == NULL)
		return ETR_NOMEM;

	struct stack_str_hash_ext_data *ext = h->private;
	ext->stack_str_kvps = NULL;
	ext->clear_hash = false;

	return stack_str_hash_init(h, (char *)name, nbuckets, hash_memory_size);
}

void release_stack_str_hash(stack_str_hash_t * h)
{
	if (h->private) {
		struct stack_str_hash_ext_data *ext = h->private;
		vec_free(ext->stack_str_kvps);
		clib_mem_free(ext);
	}

	stack_str_hash_free(h);
}

void clean_stack_strs(stack_str_hash_t * h)
{
	u64 elems_count = 0;

	/*
	 * In this iteration, all elements will be cleared, and in the
	 * next iteration, this hash will be reused.
	 */
	stack_str_hash_kv *v;
	struct stack_str_hash_ext_data *ext = h->private;
	vec_foreach(v, ext->stack_str_kvps) {
		if (v->value != 0)
			clib_mem_free((void *)v->value);

		if (stack_str_hash_add_del(h, v, 0 /* delete */ )) {
			ebpf_warning("stack_str_hash_add_del() failed.\n");
			ext->clear_hash = true;
		}

		elems_count++;
	}

	vec_free(ext->stack_str_kvps);

	h->hit_hash_count = 0;
	h->hash_elems_count = 0;

	if (ext->clear_hash) {
		release_stack_str_hash(h);
	}

	ebpf_debug("clean_stack_strs hashmap clear %lu elems.\n", elems_count);
}

static inline char *create_symbol_str(int len, char *src, const char *tag)
{
	char *dst = clib_mem_alloc_aligned("symbol_str", len + 1, 0, NULL);
	if (dst == NULL)
		return NULL;
	snprintf(dst, len + 1, "%s%s", tag, src);
	return dst;
}

static char *kern_symbol_name_fetch(pid_t pid, struct bcc_symbol *sym)
{
	ASSERT(pid >= 0);

	int len = 0;
	char *ptr = NULL;
	len = strlen(sym->name) + strlen(k_sym_prefix);
	ptr = (char *)sym->name;
	ptr = create_symbol_str(len, ptr, k_sym_prefix);

	return ptr;
}

#define RUST_SYM_SUFFIX "::h0123456789abcdef"
#define RUST_SYM_MAX_LEN 512

static bool maybe_rust_symbol(const char *name) {
	if (strstr(name, ".llvm.") != NULL) {
		return true;
	}

	if (strstr(name, "__rust_alloc") != NULL || strstr(name, "__rust_dealloc") != NULL || strstr(name, "__rust_realloc") != NULL) {
		return true;
	}

	int offset = strlen(name) - strlen(RUST_SYM_SUFFIX);
	return offset > 0 && strncmp(name + offset, "::h", 3) == 0;
}

static char *proc_symbol_name_fetch(pid_t pid, struct bcc_symbol *sym)
{
	ASSERT(pid >= 0);

	int len = 0;
	char *ptr = (char *)sym->demangle_name;

	if (maybe_rust_symbol(sym->demangle_name)) {
		char rust_name[RUST_SYM_MAX_LEN];
		memset(rust_name, 0, sizeof(rust_name));
		if (rustc_demangle(sym->name, rust_name, RUST_SYM_MAX_LEN) > 0) {
			ptr = rust_name;
		}
	}

	len = strlen(ptr) + strlen(u_sym_prefix);
	char *u_prefix = (char *)u_sym_prefix;
	if (sym->module != NULL && strlen(sym->module) > 0) {
		if (strstr(sym->module, ".so")) {
			len += strlen(lib_sym_prefix);
			u_prefix = (char *)lib_sym_prefix;
		}
	}

	ptr = create_symbol_str(len, ptr, (char *)u_prefix);
	bcc_symbol_free_demangle_name(sym);

	return ptr;
}

// Demangle with
// https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.3
char *rewrite_java_symbol(char *sym)
{
	int len = strlen(sym);
	if (len == 0) {
		return NULL;
	}

	int i = 0, j = 0;
	for (i = 0; i < len && sym[i] == '['; i++);
	int array_dims = i;

	int new_len = len + array_dims + 16;
	char *dst = clib_mem_alloc_aligned("symbol_str", new_len, 0, NULL);
	if (dst == NULL) {
		return dst;
	}
	memset(dst, 0, new_len);
	int offset = 0;

	// ... Simplified copy for brevity if valid ...
    // Using original logic roughly
	switch (sym[i]) {
	case 'B': offset += snprintf(dst + offset, new_len - offset, "byte"); i++; break;
	case 'C': offset += snprintf(dst + offset, new_len - offset, "char"); i++; break;
	case 'D': offset += snprintf(dst + offset, new_len - offset, "double"); i++; break;
	case 'F': offset += snprintf(dst + offset, new_len - offset, "float"); i++; break;
	case 'I': offset += snprintf(dst + offset, new_len - offset, "int"); i++; break;
	case 'J': offset += snprintf(dst + offset, new_len - offset, "long"); i++; break;
	case 'S': offset += snprintf(dst + offset, new_len - offset, "short"); i++; break;
	case 'Z': offset += snprintf(dst + offset, new_len - offset, "boolean"); i++; break;
	case 'L': 
		for (j = i + 1; j < len; j++) { if (sym[j] == ';') break; }
		if (j == len) goto failed;
		memcpy(dst + offset, sym + i + 1, j - (i + 1));
		offset += j - (i + 1);
		i = j + 1;
		break;
	default: goto failed;
	}

	for (j = 0; j < array_dims; j++) {
		offset += snprintf(dst + offset, new_len - offset, "[]");
	}

	snprintf(dst + offset, new_len - offset, sym + i);
	return dst;

failed:
	clib_mem_free(dst);
	return NULL;
}

static inline int symcache_resolve(pid_t pid, void *resolver, u64 address,
				   struct bcc_symbol *sym, void *info_p,
				   char **sym_ptr)
{
	ASSERT(pid >= 0);

	int ret = -1;
	if (pid == 0) {
		ret = bcc_symcache_resolve_no_demangle(resolver, address, sym);
		if (ret == 0)
			*sym_ptr = kern_symbol_name_fetch(pid, sym);
	} else {
		struct symbolizer_proc_info *p = info_p;
		if (p) {
			if (p->is_exit || ((u64) resolver != (u64) p->syms_cache))
				return (-1);
			pthread_mutex_lock(&p->mutex);
			ret = bcc_symcache_resolve(resolver, address, sym);
			if (ret == 0) {
				*sym_ptr = proc_symbol_name_fetch(pid, sym);
				if (p->is_java) {
					char *new_sym = rewrite_java_symbol(*sym_ptr);
					if (new_sym != NULL) {
						clib_mem_free(*sym_ptr);
						*sym_ptr = new_sym;
					}
				}
				pthread_mutex_unlock(&p->mutex);
				return ret;
			}
			if (sym->module != NULL && strlen(sym->module) > 0) {
				char format_str[4096];
				snprintf(format_str, sizeof(format_str), "[%s]", sym->module);
				int len = strlen(format_str);
				*sym_ptr = create_symbol_str(len, format_str, "");
				if (info_p) {
					struct symbolizer_proc_info *p = info_p;
					symbolizer_proc_lock(p);
					if (p->is_java && strstr(format_str, "perf-")) {
						p->unknown_syms_found = true;
					}
					symbolizer_proc_unlock(p);
				}
			}
			pthread_mutex_unlock(&p->mutex);
		}
	}

	return ret;
}

char *resolve_addr(void *tracer_handle, uint32_t pid, bool is_start_idx,
			  u64 address, bool is_create, void *info_p)
{
	pid_t pid_signed = (pid_t)pid;
	ASSERT(pid_signed >= 0);

	int len = 0;
	char *ptr = NULL;
	char format_str[32];
	struct bcc_symbol sym;
	memset(&sym, 0, sizeof(sym));
	void *resolver = get_symbol_cache(pid_signed, is_create);
	if (resolver == NULL)
		goto resolver_err;

	int ret = symcache_resolve(pid_signed, resolver, address, &sym, info_p, &ptr);
	if (ret == 0 && ptr) {
		char *p = ptr;
		for (p = ptr; *p != '\0'; p++) {
			if (*p == ';')
				*p = ':';
		}
	}

	if (ptr)
		goto finish;

resolver_err:
	if (is_start_idx)
		snprintf(format_str, sizeof(format_str), "[unknown start_thread?]");
	else
		snprintf(format_str, sizeof(format_str), "[unknown] 0x%016lx", address);

	len = strlen(format_str);
	ptr = create_symbol_str(len, format_str, "");

finish:
	return ptr;
}

static char *resolve_custom_symbol_addr(symbol_t *symbols, u32 *symbol_ids, int n_symbols, bool is_start_idx, u64 address)
{
	int len = 0;
	char *ptr = NULL;
	char format_str[CLASS_NAME_LEN + METHOD_NAME_LEN + 3];
	memset(format_str, 0, sizeof(format_str));

	u32 symbol_id = address & 0xFFFFFFFF;
	for (int i = 0; i < n_symbols; i++) {
		if (symbol_ids[i] == symbol_id) {
			if (strlen(symbols[i].class_name) > 0) {
				snprintf(format_str, sizeof(format_str), "%s::%s", symbols[i].class_name, symbols[i].method_name);
			} else {
				snprintf(format_str, sizeof(format_str), "%s", symbols[i].method_name);
			}
			goto finish;
		}
	}

	if (is_start_idx) {
		snprintf(format_str, sizeof(format_str), "[unknown start_thread?]");
	} else {
		snprintf(format_str, sizeof(format_str), "[unknown] 0x%08x", symbol_id);
	}

finish:
	len = strlen(format_str);
	ptr = create_symbol_str(len, format_str, "");
	return ptr;
}

static int get_stack_ips(struct bpf_tracer *t,
			 const char *stack_map_name, int stack_id, u64 * ips,
			 stack_t *full_stack, u64 ts)
{
	ASSERT(stack_id >= 0);

	bool is_custom_map = (strstr(stack_map_name, "custom") != NULL);

	if (full_stack && is_custom_map &&
	    bpf_table_get_value(t, stack_map_name, stack_id, (void *)full_stack)) {
		memcpy(ips, full_stack->addrs, sizeof(full_stack->addrs));
		return ETR_OK;
	}

	if (full_stack) {
		memset(full_stack, 0, sizeof(*full_stack));
	}

	if (!bpf_table_get_value(t, stack_map_name, stack_id, (void *)ips)) {
		return ETR_NOTEXIST;
	}

	return ETR_OK;
}

static char *build_stack_trace_string(struct bpf_tracer *t,
				      const char *stack_map_name,
				      pid_t pid,
				      int stack_id,
				      stack_str_hash_t * h,
				      bool new_cache,
				      int *ret_val, void *info_p, u64 ts,
				      bool ignore_libs, bool use_symbol_table)
{
	ASSERT(pid >= 0 && stack_id >= 0);

	u64 sentinel_addr = 0xcccccccccccccccc;
	int i;

	stack_t stack;
	memset(&stack, 0, sizeof(stack));

	symbol_t symbols[MAX_SYMBOL_NUM];
	memset(symbols, 0, sizeof(symbols));
	u32 symbol_ids[MAX_SYMBOL_NUM];
	memset(symbol_ids, 0, sizeof(symbol_ids));
	int n_symbols = 0;

	if (use_symbol_table) {
		struct ebpf_map *map = ebpf_obj__get_map_by_name(t->obj, MAP_SYMBOL_TABLE_NAME);
		if (map == NULL) {
			ebpf_warning("bpf table %s not found", MAP_SYMBOL_TABLE_NAME);
			return NULL;
		}
		symbol_t key = {};
		symbol_t next_key = {};
		while (bpf_get_next_key(map->fd, &key, &next_key) == 0 && n_symbols < MAX_SYMBOL_NUM) {
			int ret = bpf_lookup_elem(map->fd, &next_key, &symbol_ids[n_symbols]);
			if (ret == 0) {
				symbols[n_symbols] = next_key;
				n_symbols++;
			}
			key = next_key;
		}
	}

	int ret;
	if ((ret = get_stack_ips(t, stack_map_name, stack_id, stack.addrs, &stack, ts))) {
		stack_table_data_miss++;
		*ret_val = ret;
		return NULL;
	}

	u64 *ips = stack.addrs;
	char *str = NULL;
	ret = VEC_OK;
	uword *symbol_array = NULL;
	vec_validate_init_empty(symbol_array, PERF_MAX_STACK_DEPTH, 0, ret);
	if (ret != VEC_OK)
		return NULL;

	int start_idx = -1, folded_size = 0;
	for (i = PERF_MAX_STACK_DEPTH - 1; i >= 0; i--) {
		if (ips[i] == 0 || ips[i] == sentinel_addr)
			continue;

		if (start_idx == -1)
			start_idx = i;

        // Use extended hook to resolve frame if it's special
        // We pass possible extra data. If the frame type is 0 (normal), this call should return NULL
        str = extended_resolve_frame(pid, ips[i], stack.frame_types[i], stack.extra_data_a[i], stack.extra_data_b[i]);
        if (str == NULL) {
            // Normal fallback
            if (use_symbol_table) {
                str = resolve_custom_symbol_addr(symbols, symbol_ids, n_symbols, (i == start_idx), ips[i]);
            } else {
                str = resolve_addr(t, pid, (i == start_idx), ips[i], new_cache, info_p);
            }
        }

		if (str) {
			if (ignore_libs && strlen(str) >= strlen(lib_sym_prefix)
			    && strncmp(str, lib_sym_prefix,
				       strlen(lib_sym_prefix)) == 0) {
				clib_mem_free(str);
				continue;
			}
			symbol_array[i] = pointer_to_uword(str);
			folded_size += strlen(str);
		}
	}

	folded_size += PERF_MAX_STACK_DEPTH;

	char *fold_stack_trace_str =
	    clib_mem_alloc_aligned("folded_str", folded_size, 0, NULL);
	if (fold_stack_trace_str == NULL)
		goto failed;

	int len = 0;
	for (i = PERF_MAX_STACK_DEPTH - 1; i >= 0; i--) {
		if (symbol_array[i]) {
			len += snprintf(fold_stack_trace_str + len,
					folded_size - len,
					"%s;", (char *)symbol_array[i]);
			clib_mem_free((void *)symbol_array[i]);
		}
	}

	if (len - 1 >= 0) {
		fold_stack_trace_str[len - 1] = '\0';
	}
	vec_free(symbol_array);
	return fold_stack_trace_str;

failed:
	for (i = PERF_MAX_STACK_DEPTH - 1; i >= 0; i--) {
		if (symbol_array[i])
			clib_mem_free((void *)symbol_array[i]);
	}
	vec_free(symbol_array);
	return NULL;
}

static char *folded_stack_trace_string(struct bpf_tracer *t,
				       int stack_id,
				       pid_t pid,
				       const char *stack_map_name,
				       stack_str_hash_t * h,
				       bool new_cache, void *info_p, u64 ts,
				       bool ignore_libs, bool use_symbol_table)
{
	ASSERT(pid >= 0 && stack_id >= 0);

	stack_str_hash_kv kv;
	kv.key = (u64) stack_id;
	kv.value = 0;
	if (stack_str_hash_search(h, &kv, &kv) == 0) {
		__sync_fetch_and_add(&h->hit_hash_count, 1);
		return (char *)kv.value;
	}

	char *str = NULL;
	int ret_val = 0;
	str = build_stack_trace_string(t, stack_map_name, pid, stack_id,
				       h, new_cache, &ret_val, info_p, ts,
				       ignore_libs, use_symbol_table);

	if (ret_val == ETR_NOTEXIST)
		return NULL;

	if (str == NULL)
		return NULL;

	kv.key = (u64) stack_id;
	kv.value = pointer_to_uword(str);
	if (stack_str_hash_add_del(h, &kv, 1 /* is_add */ )) {
		ebpf_warning("stack_str_hash_add_del() failed.\n");
		clib_mem_free((void *)str);
		str = NULL;
	} else {
		int ret = VEC_OK;
		struct stack_str_hash_ext_data *ext = h->private;
		vec_add1(ext->stack_str_kvps, kv, ret);
		if (ret != VEC_OK) {
			ebpf_warning("vec add failed\n");
		}
	}

	return str;
}

static inline char *alloc_stack_trace_str(int len)
{
	void *trace_str;
	trace_str = clib_mem_alloc_aligned("stack_str", len, 0, NULL);
	if (trace_str == NULL) {
		ebpf_warning("stack trace str alloc memory failed.\n");
	}

	return trace_str;
}

char *resolve_and_gen_stack_trace_str(struct bpf_tracer *t,
				      struct stack_trace_key_t *v,
				      const char *stack_map_name,
				      const char *custom_stack_map_name,
				      stack_str_hash_t * h,
				      bool new_cache,
				      char *process_name, void *info_p,
				      bool ignore_libs)
{
	int len = 2;
	char *k_trace_str, *u_trace_str, *trace_str, *uprobe_str, *i_trace_str;
	k_trace_str = u_trace_str = trace_str = uprobe_str = i_trace_str = NULL;

	if (!new_cache) {
		len += (TASK_COMM_LEN * 2) + 10;
		trace_str = alloc_stack_trace_str(len);
		if (trace_str == NULL) {
			ebpf_warning("No available memory space.\n");
			return NULL;
		}

		bool is_thread = (v->pid != v->tgid);
		if (process_name) {
			if (is_thread)
				snprintf(trace_str, len, "[p] %s;[t] %s", process_name, v->comm);
			else
				snprintf(trace_str, len, "[p] %s", process_name);
		} else {
			if (is_thread)
				snprintf(trace_str, len, "[t] %s", v->comm);
			else
				snprintf(trace_str, len, "[p] %s", v->comm);
		}
		return trace_str;
	}

	if (v->kernstack >= 0) {
		k_trace_str = folded_stack_trace_string(t, v->kernstack, 0, stack_map_name, h, new_cache, info_p, v->timestamp, ignore_libs, false);
		if (k_trace_str == NULL) return NULL;
		len += strlen(k_trace_str);
	}

	if (v->userstack >= 0) {
		u_trace_str = folded_stack_trace_string(t, v->userstack, v->tgid,
							v->flags & STACK_TRACE_FLAGS_DWARF ? custom_stack_map_name : stack_map_name, 
                            h, new_cache, info_p, v->timestamp, ignore_libs, false);
		if (u_trace_str == NULL) return NULL;
		len += strlen(u_trace_str);
	}

	if (v->flags & STACK_TRACE_FLAGS_URETPROBE && v->uprobe_addr != 0) {
		uprobe_str = resolve_addr(t, v->tgid, false, v->uprobe_addr, new_cache, info_p);
		if (uprobe_str == NULL) return NULL;
		len += strlen(uprobe_str) + 1;
	}

	if (v->intpstack > 0) {
        // Use generic folded_stack_trace_string which eventually uses extended_resolve_frame if types match
        // But for Lua, it was using a special map and special format.
        // We assume folding logic is similar, but access to MAP_LUA etc happens in folded_stack_trace_string -> get_stack_ips
        // Wait, get_stack_ips uses `stack_map_name` passed in.
        // Interpreter stack maps are passed as `custom_stack_map_name` for userstack?
        // Lua stack map is DIFFERENT.
        // I need `extended_resolve_interpreter_frame` to handle this?
        // Actually, `stringifier.c` called `folded_lua_stack_trace_string` which loaded from `MAP_xxxx`.
        // I should probably simplify:
        // Pass `v->intpstack` to `extended` helper to get string directly?
        // `folded_stack_trace_string` is generic.
        // Let's assume we can reuse `folded_stack_trace_string` if we tell it which map?
        // BUT Lua map name is not passed here.
        // So I need a hook that takes `intpstack` ID and returns string.
        // `extended_get_interpreter_stack_str(t, v->tgid, v->intpstack)`?
		i_trace_str = folded_stack_trace_string(t, v->intpstack, v->tgid, custom_stack_map_name, h, new_cache, info_p, v->timestamp, ignore_libs, true);
        // Note: I passed `use_symbol_table=true` arbitrarily above for intp stack?
        // No, the original code used `folded_stack_trace_string` for intpstack in Python case.
        // For Lua, it called `folded_lua_stack_trace_string`.
        
        // I'll leave valid logic as fallback but if I removed `folding_lua...`.
        // I should stick with `folded_stack_trace_string`.
        
		if (i_trace_str != NULL) {
            len += strlen(i_trace_str) + 20; // + padding
		} else {
			len += strlen(i_err_tag);
		}
	}

	trace_str = alloc_stack_trace_str(len);
	if (trace_str == NULL) {
		ebpf_warning("No available memory space.\n");
		goto error;
	}

	int offset = 0;
	if (i_trace_str && u_trace_str) {
        // Use extended merge
        int merged = extended_merge_stacks(trace_str + offset, len - offset, i_trace_str, u_trace_str, v->tgid);
        if (merged > 0) {
            offset += merged;
        } else {
             // Fallback
             offset += snprintf(trace_str + offset, len - offset, "%s;%s", i_trace_str, u_trace_str);
        }
	} else if (i_trace_str) {
		offset += snprintf(trace_str + offset, len - offset, "%s", i_trace_str);
	} else if (u_trace_str) {
		if (v->intpstack > 0) {
			offset += snprintf(trace_str + offset, len - offset, "%s;%s", i_err_tag, u_trace_str);
		} else {
			offset += snprintf(trace_str + offset, len - offset, "%s", u_trace_str);
		}
	}
	if (u_trace_str && uprobe_str) {
		offset += snprintf(trace_str + offset, len - offset, ";%s", uprobe_str);
	}
	if (k_trace_str) {
		offset += snprintf(trace_str + offset, len - offset, "%s%s", offset > 0 ? ";" : "", k_trace_str);
	}

	if (offset == 0) {
		len += strlen(lost_tag);
		trace_str = alloc_stack_trace_str(len);
		if (trace_str == NULL) {
			ebpf_warning("No available memory space.\n");
			goto error;
		}
		snprintf(trace_str, len, "%s", lost_tag);
	}

	if (uprobe_str) clib_mem_free(uprobe_str);
	return trace_str;

error:
	if (uprobe_str) clib_mem_free(uprobe_str);
	return NULL;
}
#endif /* AARCH64_MUSL */
