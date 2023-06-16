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

/*
 * Excute Stringifier on each iteration of the continuous perf profiler.
 *
 * The Stringifier serves two purposes:
 * 1. It constructs a "folded stack trace string" based on the stack frame addresses.
 * 2. It records the result of (1) when reusing a stack identifier (stack-id).
 *
 * Example of a folded stack trace string (taken from a perf profiler test):
 * main;xxx();yyy()
 * It is a list of symbols corresponding to addresses in the underlying stack trace,
 * separated by ';'.
 *
 * Kernel collects stack-traces separately for user & kernel space,
 * at the BPF level, we track stack traces with a key that includes two "stack-trace-ids",
 * one for user space and one for kernel. Therefore, it is common to see reuse of
 * individual stack trace identifiers...
 * for example, when the same kernel stack trace is observed from multiple user
 * stack traces, or when a given user space stack occasionally (but not always) enters
 * the kernel.
 *
 * When the Stringifier reads the shared BPF stack trace address map, it uses a
 * destructive read approach (it reads a stack trace from the table and then clears it).
 * Due to the reuse of stack trace identifiers and destructive reads, the Stringifier
 * caches the result of its stringification. In each iteration of a continuous perf profiler.
 */

#ifndef AARCH64_MUSL
#include "config.h"
#include "common.h"
#include "mem.h"
#include "log.h"
#include "types.h"
#include "vec.h"
#include "tracer.h"
#include "perf_profiler.h"
#include "elf.h"
#include "load.h"
#include "../kernel/include/perf_profiler.h"
#include "perf_reader.h"
#include "table.h"
#include "bihash_8_8.h"
#include "bihash_16_8.h"
#include "stringifier.h"
#include <bcc/bcc_syms.h>

/* Temporary storage for releasing the stack_str_hash resource. */
static __thread stack_str_hash_kv *stack_str_kvps;
static __thread bool clear_hash;

int init_stack_str_hash(stack_str_hash_t * h, const char *name)
{
	memset(h, 0, sizeof(*h));
	u32 nbuckets = STRINGIFIER_STACK_STR_HASH_BUCKETS_NUM;
	u64 hash_memory_size = STRINGIFIER_STACK_STR_HASH_MEM_SZ;	// 1G bytes
	return stack_str_hash_init(h, (char *)name, nbuckets, hash_memory_size);
}

static int free_kvp_cb(stack_str_hash_kv * kv, void *ctx)
{
	if (kv->value != 0) {
		clib_mem_free((void *)kv->value);
		(*(u64 *) ctx)++;
	}

	int ret = VEC_OK;
	vec_add1(stack_str_kvps, *kv, ret);
	if (ret != VEC_OK) {
		ebpf_warning("vec add failed\n");
		clear_hash = true;
	}

	return BIHASH_WALK_CONTINUE;
}

void release_stack_strs(stack_str_hash_t * h)
{
	u64 elem_count = 0;
	stack_str_hash_foreach_key_value_pair(h, free_kvp_cb,
					      (void *)&elem_count);
	/*
	 * In this iteration, all elements will be cleared, and in the
	 * next iteration, this hash will be reused.
	 */
	stack_str_hash_kv *v;
	vec_foreach(v, stack_str_kvps) {
		if (stack_str_hash_add_del(h, v, 0 /* delete */ )) {
			ebpf_warning("stack_str_hash_add_del() failed.\n");
			clear_hash = true;
		}
	}

	vec_free(stack_str_kvps);

	if (clear_hash) {
		clear_hash = false;
		stack_str_hash_free(h);
	}

	ebpf_debug("release_stack_strs hashmap clear %lu elems.\n", elem_count);
}

static inline char *create_symbol_str(int len, char *src, const char *tag)
{
	char *dst = clib_mem_alloc_aligned(len + 1, 0, NULL);
	if (dst == NULL)
		return NULL;
	snprintf(dst, len + 1, "%s%s", tag, src);
	return dst;
}

static inline int symcache_resolve(pid_t pid, void *resolver, u64 address,
				   struct bcc_symbol *sym)
{
	ASSERT(pid >= 0);

	if (pid == 0)
		return bcc_symcache_resolve_no_demangle(resolver, address, sym);
	else
		return bcc_symcache_resolve(resolver, address, sym);
}

static char *symbol_name_fetch(pid_t pid, struct bcc_symbol *sym)
{
	ASSERT(pid >= 0);

	static const char *k_sym_prefix = "[k]";
	static const char *u_sym_prefix = "[u]";
	int len = 0;
	char *ptr = NULL;
	if (pid > 0) {
		len = strlen(sym->demangle_name) + strlen(u_sym_prefix);
		ptr = (char *)sym->demangle_name;
		ptr = create_symbol_str(len, ptr, u_sym_prefix);
		bcc_symbol_free_demangle_name(sym);
	} else if (pid == 0) {
		len = strlen(sym->name) + strlen(k_sym_prefix);
		ptr = (char *)sym->name;
		ptr = create_symbol_str(len, ptr, k_sym_prefix);
	}

	return ptr;
}

static char *resolve_addr(pid_t pid, u64 address)
{
	ASSERT(pid >= 0);

	int len = 0;
	char *ptr = NULL;
	char format_str[32];
	struct bcc_symbol sym;
	void *resolver = get_symbol_cache(pid);
	if (resolver == NULL)
		goto resolver_err;

	int ret = symcache_resolve(pid, resolver, address, &sym);
	if (ret == 0) {
		ptr = symbol_name_fetch(pid, &sym);
		if (ptr)
			goto finish;
	}

	if (sym.module != NULL && strlen(sym.module) > 0) {
		/*
		 * Module is known (from /proc/<pid>/maps), but symbol is not known.
		 * build a string:
		 * [m]/lib64/xxx.so + 0x00001234
		 */
		char format_str[4096];
		snprintf(format_str, sizeof(format_str), "[m]%s + 0x%08lx",
			 sym.module, sym.offset);
		len = strlen(format_str);
		ptr = create_symbol_str(len, format_str, "");
		goto finish;
	}

	/*
	 * If we have reached this point, it means that we have truly obtained
	 * nothing. Perhaps this is a JIT-compiled or interpreted program?
	 * Perhaps the stack trace has been corrupted (no frame pointers)? We
	 * will simply return the virtual address in the form of a 64-bit
	 * hexadecimal string.
	 */
resolver_err:
	snprintf(format_str, sizeof(format_str), "%s0x%016lx",
		 pid == 0 ? "[k]" : "[u]",
		 address);

	len = strlen(format_str);
	ptr = create_symbol_str(len, format_str, "");

finish:
	return ptr;
}

static int get_stack_ips(struct bpf_tracer *t,
			 const char *stack_map_name, int stack_id, u64 * ips)
{
	ASSERT(stack_id >= 0);

	if (!bpf_table_get_value(t, stack_map_name, stack_id, (void *)ips)) {
		ebpf_warning("Get map '%s' failed.\n", stack_map_name);
		return ETR_NOTEXIST;
	}

	return ETR_OK;
}

static char *build_stack_trace_string(struct bpf_tracer *t,
				      const char *stack_map_name,
				      pid_t pid,
				      int stack_id, stack_str_hash_t * h)
{
	ASSERT(pid >= 0 && stack_id >= 0);

	/*
	 * Some stack-traces have the address 0xcccccccccccccccc
	 * where one might otherwise expect to find "main" or
	 * "start_thread". Given that this address is not a "real"
	 * address, we filter it out below.
	 */
	u64 sentinel_addr = 0xcccccccccccccccc;
	int i;

	u64 ips[PERF_MAX_STACK_DEPTH];
	memset(ips, 0, sizeof(ips));
	if (get_stack_ips(t, stack_map_name, stack_id, ips)) {
		ebpf_warning("Not get stack ips, pid %d map %s stack_id %u\n",
			     pid, stack_map_name, stack_id);
		return NULL;
	}

	char *str = NULL;
	int ret = VEC_OK;
	uword *symbol_array = NULL;
	vec_validate_init_empty(symbol_array, PERF_MAX_STACK_DEPTH, 0, ret);
	if (ret != VEC_OK)
		return NULL;

	int folded_size = 0;
	for (i = PERF_MAX_STACK_DEPTH - 1; i >= 0; i--) {
		if (ips[i] == 0 || ips[i] == sentinel_addr)
			continue;

		str = resolve_addr(pid, ips[i]);
		if (str) {
			symbol_array[i] = pointer_to_uword(str);
			folded_size += strlen(str);
		}
	}

	/* Ensure that there is sufficient memory for the ';' following it. */
	folded_size += PERF_MAX_STACK_DEPTH;

	char *fold_stack_trace_str =
	    clib_mem_alloc_aligned(folded_size, 0, NULL);
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

	/* Remove the semicolon at the end of the string. */
	fold_stack_trace_str[len - 1] = '\0';
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

static char *__folded_stack_trace_string(struct bpf_tracer *t,
					 int stack_id,
					 pid_t pid,
					 const char *stack_map_name,
					 stack_str_hash_t * h)
{
	ASSERT(pid >= 0 && stack_id >= 0);

	/*
	 * Firstly, search the stack-trace hash to see if the
	 * stack trace string has already been stored. 
	 */
	stack_str_hash_kv kv;
	kv.key = (u64) stack_id;
	kv.value = 0;
	if (stack_str_hash_search(h, &kv, &kv) == 0) {
		__sync_fetch_and_add(&h->hit_stack_str_hash_count, 1);
		return (char *)kv.value;
	}

	char *str = NULL;
	str = build_stack_trace_string(t, stack_map_name, pid, stack_id, h);

	/*
	 * The stringifier clears stack-ids out of the stack traces table
	 * when it first encounters them. If a stack-id is reused by a
	 * different stack-trace-key, the stringifier returns its memoized
	 * stack trace string.
	 */
	if (!bpf_table_delete_key(t, stack_map_name, (u64) stack_id)) {
		ebpf_warning
		    ("stack_map_name %s, delete failed, stack-ID %d\n",
		     stack_map_name, stack_id);
	}

	kv.key = (u64) stack_id;
	kv.value = pointer_to_uword(str);
	/* memoized stack trace string. Because the stack-ids
	   are not stable across profiler iterations. */
	if (stack_str_hash_add_del(h, &kv, 1 /* is_add */ )) {
		ebpf_warning("stack_str_hash_add_del() failed.\n");
		clib_mem_free((void *)str);
		str = NULL;
	}

	return str;
}

static const char *err_tag = "<stack trace error>";
static const char *k_err_tag = "<kernel stack trace error>";
static const char *u_err_tag = "<user stack trace error>";
static const char *lost_tag = "<stack trace lost>";

static inline stack_trace_msg_t *alloc_stack_trace_msg(int len)
{
	void *trace_msg;
	/* add separator and '\0' */
	len += 2;
	trace_msg = clib_mem_alloc_aligned(len, 0, NULL);
	if (trace_msg == NULL) {
		ebpf_warning("stack trace str alloc memory failed.\n");
	} else {
		stack_trace_msg_t *msg = trace_msg;
		return msg;
	}

	return NULL;
}

static void set_stack_trace_msg(stack_trace_msg_t * msg,
				struct stack_trace_key_t *v)
{
	msg->pid = v->pid;
	msg->cpu = v->cpu;
	msg->u_stack_id = (u32) v->userstack;
	msg->k_stack_id = (u32) v->kernstack;
	if (!v->is_kern) {
		msg->stime = get_pid_stime_and_name(v->pid,
						    (char *)msg->comm);
		if (msg->stime > 0)
			goto skip_kern_or_no_proc;
	}

	msg->stime = get_pid_stime(0);
	memcpy(msg->comm, v->comm, sizeof(msg->comm));

skip_kern_or_no_proc:
	msg->data_len = strlen((char *)&msg->data[0]);
	msg->time_stamp = gettime(CLOCK_REALTIME, TIME_TYPE_NAN);
	msg->count = 1;
	msg->data_ptr = pointer_to_uword(&msg->data[0]);
}

char *folded_stack_trace_string(struct bpf_tracer *t,
				struct stack_trace_key_t *v,
				const char *stack_map_name,
				stack_str_hash_t * h)
{
	char *trace_str, *k_trace_str, *u_trace_str;
	trace_str = k_trace_str = u_trace_str = NULL;

	if (v->kernstack >= 0) {
		k_trace_str = __folded_stack_trace_string(t, v->kernstack,
							  0, stack_map_name, h);
	}

	if (v->userstack >= 0) {
		u_trace_str = __folded_stack_trace_string(t, v->userstack,
							  v->pid,
							  stack_map_name, h);
	}

	/* stack_trace_str = u_stack_str_fn() + ";" + k_stack_str_fn(); */
	if (v->kernstack >= 0 && v->userstack >= 0) {
		int len = 0;
		if (k_trace_str) {
			len += strlen(k_trace_str);
		} else {
			len += strlen(k_err_tag);
		}

		if (u_trace_str) {
			len += strlen(u_trace_str);
		} else {
			len += strlen(u_err_tag);
		}

		/* add separator and '\0' */
		len += 2;
		trace_str = clib_mem_alloc_aligned(len, 0, NULL);
		if (trace_str == NULL) {
			ebpf_warning("stack trace str alloc memory failed.\n");
		} else {
			snprintf(trace_str, len, "%s;%s",
				 k_trace_str ? k_trace_str : k_err_tag,
				 u_trace_str ? u_trace_str : u_err_tag);
		}
	} else if (v->kernstack >= 0) {
		if (k_trace_str)
			trace_str =
			    create_symbol_str(strlen(k_trace_str),
					      (char *)k_trace_str, "");
	} else if (v->userstack >= 0) {
		if (u_trace_str)
			trace_str =
			    create_symbol_str(strlen(u_trace_str),
					      (char *)u_trace_str, "");
	} else {
		trace_str =
		    create_symbol_str(strlen(lost_tag), (char *)lost_tag, "");
		ebpf_warning("stack trace data lost\n");
	}

	if (trace_str == NULL)
		trace_str = create_symbol_str(strlen(err_tag), (char *)err_tag, "");

	//ebpf_debug("stack trace: %s\n", trace_str);
	//clib_mem_free(trace_str);
	return trace_str;
}

stack_trace_msg_t *
resolve_and_gen_stack_trace_msg(struct bpf_tracer *t,
				struct stack_trace_key_t *v,
				const char *stack_map_name,
				stack_str_hash_t *h)
{
	/*
	 * We need to prepare a hashtable (stack_trace_strs) to record the results
	 * of this iteration analysis. The key is the user-stack-ID or kernel-stack-ID,
	 * and the value is the "folded stack trace string". There are two reasons why
	 * we use this hashtable:
	 *
	 * 1. It is common to see reuse of individual stack trace identifiers
	 *    (avoiding repetitive symbolization work).
	 * 2. When the Stringifier reads the shared BPF stack trace address map,
	 *    it uses a destructive read approach (it reads a stack trace from
	 *    the table and then clears it). It means that when a stackID is
	 *    deleted, the list of IPs (function addresses) associated with it
	 *    no longer exists, and must be kept beforehand.
	 */

	int len = 0;
	static stack_trace_msg_t *msg;
	char *k_trace_str, *u_trace_str;
	k_trace_str = u_trace_str = NULL;

	if (v->kernstack >= 0) {
		k_trace_str = __folded_stack_trace_string(t, v->kernstack,
							  0, stack_map_name, h);
	}

	if (v->userstack >= 0) {
		u_trace_str = __folded_stack_trace_string(t, v->userstack,
							  v->pid,
							  stack_map_name, h);
	}

	/* stack_trace_str = u_stack_str_fn() + ";" + k_stack_str_fn(); */
	len += sizeof(stack_trace_msg_t);
	if (v->kernstack >= 0 && v->userstack >= 0) {
		if (k_trace_str) {
			len += strlen(k_trace_str);
		} else {
			len += strlen(k_err_tag);
		}

		if (u_trace_str) {
			len += strlen(u_trace_str);
		} else {
			len += strlen(u_err_tag);
		}

		msg = alloc_stack_trace_msg(len);
		if (msg == NULL) {
			ebpf_warning("No available memory space.\n");
			return NULL;
		}

		snprintf((char *)&msg->data[0], len, "%s;%s",
			 u_trace_str ? u_trace_str : u_err_tag,
			 k_trace_str ? k_trace_str : k_err_tag);

	} else if (v->kernstack >= 0) {
		if (k_trace_str) {
			len += strlen(k_trace_str);
		} else {
			len += strlen(k_err_tag);
		}
		msg = alloc_stack_trace_msg(len);
		if (msg == NULL) {
			ebpf_warning("No available memory space.\n");
			return NULL;
		}

		snprintf((char *)&msg->data[0], len, "%s",
			 k_trace_str ? k_trace_str : k_err_tag);
	} else if (v->userstack >= 0) {
		if (u_trace_str) {
			len += strlen(u_trace_str);
		} else {
			len += strlen(u_err_tag);
		}
		msg = alloc_stack_trace_msg(len);
		if (msg == NULL) {
			ebpf_warning("No available memory space.\n");
			return NULL;
		}

		snprintf((char *)&msg->data[0], len, "%s",
			 u_trace_str ? u_trace_str : u_err_tag);
	} else {
		/* 
		 * The kernel can indicate the invalidity of a stack ID in two
		 * different ways:
		 *
		 * -EFAULT: Stack trace is unavailable
		 * For example, if the stack trace is only available in user space
		 * and the kstack_id is invalid, this error code (-EFAULT) is used.
		 *
		 * -EEXIST: Hash bucket collision in the stack trace table
		 *
		 * If there is a hash table collision for one or both stack IDs, we
		 * may reach this branch. However, we should not reach this point when
		 * both stack IDs are set to "invalid" with the error code -EFAULT.
		 */

		len += strlen(lost_tag);
		msg = alloc_stack_trace_msg(len);
		if (msg == NULL) {
			ebpf_warning("No available memory space.\n");
			return NULL;
		}

		snprintf((char *)&msg->data[0], len, "%s", lost_tag);
		ebpf_warning("stack trace data lost\n");
	}

	set_stack_trace_msg(msg, v);

	return msg;
}
#endif /* AARCH64_MUSL */
