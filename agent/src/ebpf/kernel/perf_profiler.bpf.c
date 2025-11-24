/*
 * This code runs using bpf in the Linux kernel.
 * Copyright 2022- The Yunshan Networks Authors.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/bpf_perf_event.h>
#include "config.h"
#include "bpf_base.h"
#include "common.h"
#include "kernel.h"
#include "bpf_endian.h"
#include "perf_profiler.h"
#include "trace_utils.h"
#include "lua_unwind_helper.h"

#define KERN_STACKID_FLAGS (0)
#define USER_STACKID_FLAGS (0 | BPF_F_USER_STACK)

#ifndef __USER32_CS
// defined in arch/x86/include/asm/segment.h
#define GDT_ENTRY_DEFAULT_USER32_CS 4
#define GDT_ENTRY_DEFAULT_USER_DS 5
#define __USER32_CS (GDT_ENTRY_DEFAULT_USER32_CS * 8 + 3)
#define __USER_DS (GDT_ENTRY_DEFAULT_USER_DS * 8 + 3)
#endif

/*
 * To keep the stack trace profiler "always on," we utilize a double
 * buffering mechanism and allocate two identical data structures.
 *
 * 1 stack_map Used to collect the call stack information of kernel
 *   functions. Used to collect the call stack information. Maps the
 *   entire stack trace with stack IDs.
 *
 * 2 profiler_output perf output to user space, Through hash-table,
 *   user space can be used to collect call stack information. The
 *   higher the count, the more we observe certain stack traces, some
 *   of which may indicate potential performance issues.
 *
 * We implement continuous tracking using a double buffering scheme,
 * for which we allocate two data structures. Therefore, we have the
 * following BPF tables:
 *
 *   1 profiler_output_a
 *   2 profiler_output_b
 *   3 stack_map_a
 *   4 stack_map_b
 *
 * User space controls the switching between MAP a and MAP b. It ensures
 * that when reading data from cache a for address symbolization, BPF uses
 * cache b for writing data and vice versa.
 */

MAP_PERF_EVENT(profiler_output_a, int, __u32, MAX_CPU, FEATURE_FLAG_PROFILE_ONCPU)
MAP_PERF_EVENT(profiler_output_b, int, __u32, MAX_CPU, FEATURE_FLAG_PROFILE_ONCPU)
MAP_PROG_ARRAY(cp_progs_jmp_pe_map, __u32, __u32, CP_PROG_PE_NUM, FEATURE_FLAG_PROFILE_ONCPU)

MAP_STACK_TRACE(stack_map_a, STACK_MAP_ENTRIES, FEATURE_FLAG_PROFILE_ONCPU)
MAP_STACK_TRACE(stack_map_b, STACK_MAP_ENTRIES, FEATURE_FLAG_PROFILE_ONCPU)

typedef struct {
	struct bpf_map_def *state;
	struct bpf_map_def *stack_map_a;
	struct bpf_map_def *stack_map_b;
	struct bpf_map_def *custom_stack_map_a;
	struct bpf_map_def *custom_stack_map_b;
	struct bpf_map_def *profiler_output_a;
	struct bpf_map_def *profiler_output_b;
	struct bpf_map_def *progs_jmp;
} map_group_t;

#ifdef LINUX_VER_5_2_PLUS
typedef __u64 __raw_stack[PERF_MAX_STACK_DEPTH];

/*
 * Stack map for dwarf stacks.
 * Due to the limitation of the number of eBPF instruction in kernel, this
 * feature is suitable for Linux5.2+
 *
 * Map sizes are configured in user space program
 */
MAP_HASH(custom_stack_map_a, __u32, __raw_stack, 1, FEATURE_FLAG_DWARF_UNWINDING)
MAP_HASH(custom_stack_map_b, __u32, __raw_stack, 1, FEATURE_FLAG_DWARF_UNWINDING)

/*
 * The following maps are used for DWARF based unwinding
 *
 * process_shard_list_table stores mappings between process tgid and unwind entry shards
 * unwind_entry_shard_table stores unwind entry shards in hash table instead of array to save memory
 *
 * These two maps are populated by rust code in trace_utils::unwind::UnwindTable
 *
 * Map sizes are configured in user space program
 */
MAP_HASH(process_shard_list_table, __u32, process_shard_list_t, 1, FEATURE_FLAG_DWARF_UNWINDING)
MAP_HASH(unwind_entry_shard_table, __u32, unwind_entry_shard_t, 1, FEATURE_FLAG_DWARF_UNWINDING)

/*
 * For sysinfo gathered from BTF
 */
MAP_ARRAY(unwind_sysinfo, __u32, unwind_sysinfo_t, 1, FEATURE_FLAG_DWARF_UNWINDING)

MAP_HASH(python_tstate_addr_map, __u32, __u64, 65536, FEATURE_FLAG_PROFILE)
MAP_HASH(python_unwind_info_map, __u32, python_unwind_info_t, 65536, FEATURE_FLAG_PROFILE)
MAP_HASH(python_offsets_map, __u8, python_offsets_t, 1, FEATURE_FLAG_PROFILE)

struct bpf_map_def SEC("maps") __symbol_table = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(symbol_t),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
    .feat_flags = FEATURE_FLAG_PROFILE,
};
MAP_PERARRAY(symbol_index_storage, __u32, __u32, 1, FEATURE_FLAG_PROFILE)

typedef struct {
	__u64 ip;
	__u64 sp;
	__u64 bp;
} regs_t;

typedef struct {
	__u8 len;
	__u64 addrs[PERF_MAX_STACK_DEPTH];
} stack_t;

typedef struct {
	struct stack_trace_key_t key;

	__u8 runs;

	regs_t regs;
	stack_t stack;
	stack_t intp_stack;

	void *py_frame_ptr;
	__u8 py_offsets_id;

	void *lua_L_ptr;
	__u8  lua_is_jit;       // 0: Lua 5.x, 1: LuaJIT
	__u32 lua_offsets_id;
	void *luajit_frame;
	void *luajit_bot;
	__s32 luajit_skip_depth;
} unwind_state_t;

/*
 * memset'ing a struct larger than 1024B is not accepted by the compiler
 */
static inline __attribute__ ((always_inline))
void reset_unwind_state(unwind_state_t * state)
{
	__builtin_memset(&state->key, 0, sizeof(struct stack_trace_key_t));
	state->runs = 0;
	__builtin_memset(&state->regs, 0, sizeof(regs_t));
	__builtin_memset(&state->stack, 0, sizeof(stack_t));
	__builtin_memset(&state->intp_stack, 0, sizeof(stack_t));
	state->luajit_frame = NULL;
	state->luajit_bot = NULL;
	state->luajit_skip_depth = 0;
}

MAP_PERARRAY(heap, __u32, unwind_state_t, 1, FEATURE_FLAG_PROFILE_ONCPU | FEATURE_FLAG_PROFILE_OFFCPU | FEATURE_FLAG_PROFILE_MEMORY | FEATURE_DWARF_UNWINDING)

static inline __attribute__ ((always_inline))
int pre_python_unwind(void *ctx, unwind_state_t * state,
		 map_group_t *maps, int jmp_idx);

static inline __attribute__ ((always_inline))
int pre_lua_unwind(void *ctx, unwind_state_t * state,
		   map_group_t * maps, int jmp_idx);

#else

typedef void stack_t;		// placeholder

#endif

/* ------------------ maps for lua------------------ */
#ifdef LINUX_VER_5_2_PLUS
/* Cache lua_State* stack captured from interpreter entry per thread (key: tid, value: struct lua_state_cache_t).
 * Memory: LUA_TSTATE_ENTRIES(65536) * (key 4B + value 72B + hash header) -> roughly a few MB worst case.
 */
MAP_HASH(lua_tstate_map, __u32, struct lua_state_cache_t, LUA_TSTATE_ENTRIES, FEATURE_FLAG_PROFILE_ONCPU)
/* Records which Lua runtime a process uses (key: tgid, value: LANG_* bitmask).
 * Memory: LUA_TSTATE_ENTRIES(65536) * (key 4B + value 4B + hash header) -> roughly sub‑MB.
 */
MAP_HASH(lang_flags_map, __u32, __u32, LUA_TSTATE_ENTRIES, FEATURE_FLAG_PROFILE_ONCPU)
/* Per-process Lua unwinding metadata (key: tgid, value: lua_unwind_info_t).
 * Memory: LUA_TSTATE_ENTRIES(65536) * (key 4B + value 16B + hash header) -> roughly low MB.
 */
MAP_HASH(lua_unwind_info_map, __u32, lua_unwind_info_t, LUA_TSTATE_ENTRIES, FEATURE_FLAG_PROFILE_ONCPU)
/* Lua 5.x structure layout descriptions indexed by offsets id (key: id, value: lua_ofs).
 * Memory: up to LUA_OFFSET_PROFILES(8) * (key 4B + value ~92B + hash header) -> about a few KB kernel memory.
 * Arch: map is generic; values currently reflect arm64 layouts. x86_64 support is provided by loading x86 offsets from userspace.
 */
MAP_HASH(lua_offsets_map, __u32, lua_ofs, LUA_OFFSET_PROFILES, FEATURE_FLAG_PROFILE_ONCPU)
/* LuaJIT structure layout descriptions indexed by offsets id (key: id, value: lj_ofs).
 * Memory: up to LUA_OFFSET_PROFILES(8) * (key 4B + value ~56B + hash header) -> about a few KB kernel memory.
 * Arch: map is generic; values mirror the arch provided by userspace (currently AArch64/GC64; load GC32/x86_64 offsets from userspace when supported).
 */
MAP_HASH(luajit_offsets_map, __u32, lj_ofs, LUA_OFFSET_PROFILES, FEATURE_FLAG_PROFILE_ONCPU)

static __always_inline __u64 lua_state_slot_read(const struct lua_state_cache_t *cache,
						 __u8 idx)
{
	if (idx >= LUA_STATE_STACK_DEPTH) {
		return 0;
	}
	return cache->states[idx];
}

static __always_inline void lua_state_slot_write(struct lua_state_cache_t *cache,
                                                 __u8 idx, __u64 value)
{
	if (idx >= LUA_STATE_STACK_DEPTH) {
		return;
	}
	cache->states[idx] = value;
}

static __always_inline void lua_state_stack_push(__u64 id, __u64 state)
{
	__u32 tid = (__u32)id;
	struct lua_state_cache_t *cache_ptr = lua_tstate_map__lookup(&tid);
	if (!cache_ptr) {
		struct lua_state_cache_t init = {};
		init.depth = 1;
		init.states[0] = state;
		lua_tstate_map__update(&tid, &init);
		return;
	}

	struct lua_state_cache_t cache = {};
	__builtin_memcpy(&cache, cache_ptr, sizeof(cache));

	__u8 depth = cache.depth;
	if (depth >= LUA_STATE_STACK_DEPTH) {
#pragma unroll
		for (int i = 1; i < LUA_STATE_STACK_DEPTH; i++) {
			cache.states[i - 1] = cache.states[i];
		}
		depth = LUA_STATE_STACK_DEPTH - 1;
	}

	lua_state_slot_write(&cache, depth, state);
	cache.depth = depth + 1;
	lua_tstate_map__update(&tid, &cache);
}

static __always_inline void lua_state_stack_pop(__u64 id)
{
	__u32 tid = (__u32)id;
	struct lua_state_cache_t *cache_ptr = lua_tstate_map__lookup(&tid);
	if (!cache_ptr) {
		return;
	}

	struct lua_state_cache_t cache = {};
	__builtin_memcpy(&cache, cache_ptr, sizeof(cache));

	__u8 depth = cache.depth;
	if (depth == 0) {
		lua_tstate_map__delete(&tid);
		return;
	}

	depth--;
	cache.depth = depth;
	if (depth < LUA_STATE_STACK_DEPTH) {
		lua_state_slot_write(&cache, depth, 0);
	}

	if (depth == 0) {
		lua_tstate_map__delete(&tid);
	} else {
		lua_tstate_map__update(&tid, &cache);
	}
}
#endif

/*
 * Used for communication between user space and BPF to control the
 * switching between buffer a and buffer b.
 */
MAP_ARRAY(profiler_state_map, __u32, __u64, PROFILER_CNT, FEATURE_FLAG_PROFILE_ONCPU)
#ifdef LINUX_VER_5_2_PLUS
static inline __attribute__ ((always_inline))
void add_frame(stack_t * stack, __u64 frame)
{
	__u8 len = stack->len;
	if (len >= 0 && len < PERF_MAX_STACK_DEPTH) {
		stack->addrs[len] = frame;
		stack->len++;
	}
}

static inline __u32 rol32(__u32 word, unsigned int shift)
{
	return (word << shift) | (word >> ((-shift) & 31));
}

/* __jhash_mix -- mix 3 32-bit values reversibly. */
#define __jhash_mix(a, b, c)                                                                                           \
    {                                                                                                                  \
  a -= c;                                                                                                        \
  a ^= rol32(c, 4);                                                                                              \
  c += b;                                                                                                        \
  b -= a;                                                                                                        \
  b ^= rol32(a, 6);                                                                                              \
  a += c;                                                                                                        \
  c -= b;                                                                                                        \
  c ^= rol32(b, 8);                                                                                              \
  b += a;                                                                                                        \
  a -= c;                                                                                                        \
  a ^= rol32(c, 16);                                                                                             \
  c += b;                                                                                                        \
  b -= a;                                                                                                        \
  b ^= rol32(a, 19);                                                                                             \
  a += c;                                                                                                        \
  c -= b;                                                                                                        \
  c ^= rol32(b, 4);                                                                                              \
  b += a;                                                                                                        \
    }

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)                                                                                         \
    {                                                                                                                  \
  c ^= b;                                                                                                        \
  c -= rol32(b, 14);                                                                                             \
  a ^= c;                                                                                                        \
  a -= rol32(c, 11);                                                                                             \
  b ^= a;                                                                                                        \
  b -= rol32(a, 25);                                                                                             \
  c ^= b;                                                                                                        \
  c -= rol32(b, 16);                                                                                             \
  a ^= c;                                                                                                        \
  a -= rol32(c, 4);                                                                                              \
  b ^= a;                                                                                                        \
  b -= rol32(a, 14);                                                                                             \
  c ^= b;                                                                                                        \
  c -= rol32(b, 24);                                                                                             \
    }

#define JHASH_INITVAL 0xDEADBEEF

// PERF_MAX_STACK_DEPTH is 127, stack->addrs has max length of 254 as u32's, and
// 3 * 84 = 252
#define HASH_STACK_LOOPS 84

// hash stack with jhash2
//     https://github.com/torvalds/linux/blob/master/tools/include/linux/jhash.h
static inline __attribute__ ((always_inline))
__u32 hash_stack(stack_t * stack, __u32 initval)
{
	__u32 *k = (__u32 *) stack->addrs;
	__u32 length = stack->len * sizeof(__u64) / sizeof(__u32);

	__u32 a, b, c;
	a = b = c = JHASH_INITVAL + (length << 2) + initval;

	__u32 i = 0, offset;

#pragma unroll
	for (i = 0; i < HASH_STACK_LOOPS; i++) {
		offset = 3 * i;
		if (offset + 3 >= length) {
			break;
		}
		a += k[offset];
		b += k[offset + 1];
		c += k[offset + 2];
		__jhash_mix(a, b, c);
	}

	switch (length - offset) {
	case 3:
		c += k[offset + 2];
	case 2:
		b += k[offset + 1];
	case 1:
		a += k[offset + 0];
		__jhash_final(a, b, c);
	case 0:		/* Nothing left to add */
		break;
	}

	return c;
}

static inline __attribute__ ((always_inline))
__u32 get_stackid(struct bpf_map_def *stack_map, stack_t * stack)
{
	/*
	 * Imitates the behaviour of bpf_get_stackid
	 * ------------------------------------------------------
	 * int bpf_get_stackid(struct pt_reg *ctx,
	 *                     struct bpf_map *map, u64 flags);
	 * define in include/uapi/linux/bpf.h, implementation in
	 * file "./kernel/bpf/stackmap.c"
	 *
	 * Flags **BPF_F_REUSE_STACKID** If two different stacks
	 * hash into the same *stackid*, discard the old one. Do
	 * not set this flag, we want to return the error(-EEXIST)
	 * normally for counting purposes.
	 *
	 * return
	 *    -EFAULT (couldn't fetch the stack trace)
	 *    -EEXIST (duplicate value of *stackid*)
	 */

	if (stack->len == 0) {
		return 0;
	}

	__u32 id = hash_stack(stack, 0) & (STACK_MAP_ENTRIES - 1);
	int ret =
	    bpf_map_update_elem(stack_map, &id, stack->addrs, BPF_NOEXIST);
	if (ret == 0) {
		return id;
	}
	if (ret != -EEXIST) {
		return ret;
	}

	__u64 *addrs = bpf_map_lookup_elem(stack_map, &id);
	if (!addrs) {
		return -EEXIST;
	}

	int i;
#pragma unroll
	for (i = 0; i < PERF_MAX_STACK_DEPTH && i < stack->len; i++) {
		if (addrs[i] != stack->addrs[i]) {
			return -EEXIST;
		}
	}

	if (i == PERF_MAX_STACK_DEPTH || addrs[i] == 0) {
		return id;
	}
	return -EEXIST;
}

static inline __attribute__ ((always_inline))
bool is_usermod_regs(struct pt_regs *regs)
{
#if defined(__x86_64__)
	// On x86_64 the user mode SS should always be __USER_DS.
	return regs->ss == __USER_DS;
#elif defined(__aarch64__)
	// Check if the processor state is in the EL0t what linux uses for usermode.
	return (regs->pstate & PSR_MODE_MASK) == PSR_MODE_EL0t;
#else
	_Pragma("GCC error \"Must specify a BPF target arch\"");
#endif
}

// Values for x86_64 as of 6.0.18-200.
#define TOP_OF_KERNEL_STACK_PADDING 0
#define THREAD_SIZE_ORDER 2
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define THREAD_SIZE (PAGE_SIZE << THREAD_SIZE_ORDER)

// from
// https://github.com/open-telemetry/opentelemetry-ebpf-profiler/blob/96717079737c688891dd431210c9d29401cc1eae/support/ebpf/native_stack_trace.ebpf.c#L698
static inline __attribute__ ((always_inline))
int get_usermode_regs(struct pt_regs *regs, regs_t * dst)
{
	if (is_usermod_regs(regs)) {
		dst->ip = PT_REGS_IP(regs);
		dst->sp = PT_REGS_SP(regs);
		dst->bp = PT_REGS_FP(regs);
		return 0;
	}

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	__u32 zero = 0;
	unwind_sysinfo_t *sysinfo = unwind_sysinfo__lookup(&zero);
	if (!sysinfo) {
		return -1;
	}
	// use bpf_task_pt_regs after Linux 5.15+ instead
	void *stack;
	int ret =
	    bpf_probe_read_kernel(&stack, sizeof(void *),
				  ((void *)task) +
				  sysinfo->task_struct_stack_offset);
	if (ret || stack == NULL) {
		return -1;
	}

	struct pt_regs *user_regs_addr =
	    ((struct pt_regs *)(stack + THREAD_SIZE -
				TOP_OF_KERNEL_STACK_PADDING)) - 1;
	struct pt_regs user_regs;
	ret =
	    bpf_probe_read_kernel(&user_regs, sizeof(user_regs),
				  (void *)user_regs_addr);
	if (ret) {
		return -1;
	}

	dst->ip = PT_REGS_IP(&user_regs);
	dst->sp = PT_REGS_SP(&user_regs);
	dst->bp = PT_REGS_FP(&user_regs);
	return 0;
}

#endif

static inline __attribute__ ((always_inline))
int collect_stack_and_send_output(struct pt_regs *ctx,
				  struct stack_trace_key_t *key,
				  stack_t * stack, stack_t * intp_stack,
				  map_group_t * maps, bool user_only)
{
	__u32 count_idx;

	count_idx = TRANSFER_CNT_IDX;
	__u64 *transfer_count_ptr =
	    bpf_map_lookup_elem(maps->state, &count_idx);

	__u64 *sample_count_ptrs[2];

	count_idx = SAMPLE_CNT_A_IDX;
	sample_count_ptrs[0] = bpf_map_lookup_elem(maps->state, &count_idx);

	count_idx = SAMPLE_CNT_B_IDX;
	sample_count_ptrs[1] = bpf_map_lookup_elem(maps->state, &count_idx);

	count_idx = SAMPLE_CNT_DROP;
	__u64 *drop_count_ptr = bpf_map_lookup_elem(maps->state, &count_idx);

	count_idx = SAMPLE_ITER_CNT_MAX;
	__u64 *iter_count_ptr = bpf_map_lookup_elem(maps->state, &count_idx);

	count_idx = OUTPUT_CNT_IDX;
	__u64 *output_count_ptr = bpf_map_lookup_elem(maps->state, &count_idx);

	count_idx = ERROR_IDX;
	__u64 *error_count_ptr = bpf_map_lookup_elem(maps->state, &count_idx);

	if (transfer_count_ptr == NULL || sample_count_ptrs[0] == NULL
	    || sample_count_ptrs[1] == NULL || drop_count_ptr == NULL
	    || iter_count_ptr == NULL || error_count_ptr == NULL
	    || output_count_ptr == NULL) {
		count_idx = ERROR_IDX;
		__u64 err_val = 1;
		bpf_map_update_elem(maps->state, &count_idx, &err_val, BPF_ANY);
		return 0;
	}

	struct bpf_map_def *stack_map = NULL;

#ifdef LINUX_VER_5_2_PLUS
	if (!((*transfer_count_ptr) & 0x1ULL)) {
		stack_map = maps->custom_stack_map_a;
	} else {
		stack_map = maps->custom_stack_map_b;
	}

	if (key->flags & STACK_TRACE_FLAGS_DWARF && stack != NULL) {
		key->userstack = get_stackid(stack_map, stack);
	}

	if (intp_stack != NULL && intp_stack->len > 0) {
		key->intpstack = get_stackid(stack_map, intp_stack);
	}
#endif

	__u64 sample_count = 0;
	__u64 *sample_count_ptr = NULL;
	struct bpf_map_def *profiler_output = NULL;
	if (!((*transfer_count_ptr) & 0x1ULL)) {
		sample_count_ptr = sample_count_ptrs[0];
		stack_map = maps->stack_map_a;
		profiler_output = maps->profiler_output_a;
	} else {
		sample_count_ptr = sample_count_ptrs[1];
		stack_map = maps->stack_map_b;
		profiler_output = maps->profiler_output_b;
	}

	key->kernstack = bpf_get_stackid(ctx, stack_map, KERN_STACKID_FLAGS);
	if (!(key->flags & STACK_TRACE_FLAGS_DWARF)) {
		key->userstack =
		    bpf_get_stackid(ctx, stack_map, USER_STACKID_FLAGS);
	}

	if (-EEXIST == key->kernstack) {
		__sync_fetch_and_add(drop_count_ptr, 1);
	}

	if (-EEXIST == key->userstack) {
		__sync_fetch_and_add(drop_count_ptr, 1);
	}

	if (user_only && key->userstack < 0) {
		return 0;
	}

	if (key->userstack < 0 && key->kernstack < 0) {
		return 0;
	}

	sample_count = *sample_count_ptr;
	__sync_fetch_and_add(sample_count_ptr, 1);

	if (bpf_perf_event_output
	    (ctx, profiler_output, BPF_F_CURRENT_CPU, key,
	     sizeof(struct stack_trace_key_t))) {
		__sync_fetch_and_add(error_count_ptr, 1);
	} else {
		__sync_fetch_and_add(output_count_ptr, 1);
	}

	/*
	 * Each iteration in user mode sets the sample_count to 0. If
	 * sample_count > 0, it means that the user mode program is
	 * currently in the process of iteration and has not completed
	 * the stringifier task. If sample_count is too large, it is
	 * likely to cause stack-trace loss of records. We hope to set
	 * a larger value for STACK_MAP_ENTRIES to ensure that data is
	 * not lost. The implementation method requires calculating the
	 * maximum value of the stackmap during the loading phase and
	 * resetting it.
	 *
	 * Record the maximum sample count for each iteration.
	 */
	if (sample_count > *iter_count_ptr) {
		*iter_count_ptr = sample_count;
	}

	return 0;
}

static map_group_t oncpu_maps = {.state = &NAME(profiler_state_map),
	.stack_map_a = &NAME(stack_map_a),
	.stack_map_b = &NAME(stack_map_b),
#ifdef LINUX_VER_5_2_PLUS
	.custom_stack_map_a = &NAME(custom_stack_map_a),
	.custom_stack_map_b = &NAME(custom_stack_map_b),
#endif
	.profiler_output_a = &NAME(profiler_output_a),
	.profiler_output_b = &NAME(profiler_output_b),
	.progs_jmp = &NAME(cp_progs_jmp_pe_map),
};

PERF_EVENT_PROG(oncpu_profile) (struct bpf_perf_event_data * ctx) {
	__u32 count_idx = ENABLE_IDX;
	__u64 *enable_ptr = profiler_state_map__lookup(&count_idx);

	count_idx = ERROR_IDX;
	__u64 *error_count_ptr = profiler_state_map__lookup(&count_idx);

	if (enable_ptr == NULL || error_count_ptr == NULL) {
		count_idx = ERROR_IDX;
		__u64 err_val = 1;
		profiler_state_map__update(&count_idx, &err_val);
		return 0;
	}

	if (unlikely(*enable_ptr == 0)) {
		return 0;
	}

#ifdef LINUX_VER_5_2_PLUS
	__u32 zero = 0;
	unwind_state_t *state = heap__lookup(&zero);
	if (state == NULL) {
		return 0;
	}
	reset_unwind_state(state);
	struct stack_trace_key_t *key = &state->key;
#else
	struct stack_trace_key_t trace_key = { 0 };
	struct stack_trace_key_t *key = &trace_key;
#endif

	__u64 id = bpf_get_current_pid_tgid();
	key->tgid = id >> 32;
	key->pid = (__u32) id;

	/*
	 * CPU idle stacks will not be collected.
	 */
	if (key->tgid == key->pid && key->pid == 0) {
		return 0;
	}

	key->cpu = bpf_get_smp_processor_id();
	bpf_get_current_comm(&key->comm, sizeof(key->comm));
	key->timestamp = bpf_ktime_get_ns();

#ifdef LINUX_VER_5_2_PLUS
	python_unwind_info_t *py_unwind_info =
	    python_unwind_info_map__lookup(&state->key.tgid);
	if (py_unwind_info != NULL) {
		pre_python_unwind(ctx, state, &oncpu_maps, PROG_PYTHON_UNWIND_PE_IDX);
	}

	__u32 *flags = lang_flags_map__lookup(&key->tgid);
	if (flags && (*flags & (LANG_LUA | LANG_LUAJIT))) {
		state->lua_is_jit = (*flags & LANG_LUAJIT) ? 1 : 0;

		struct lua_state_cache_t *cache =
		    lua_tstate_map__lookup(&key->pid);  // pid==tid in key
		if (cache && cache->depth > 0) {
			__u8 top_idx = cache->depth - 1;
			__u64 top = lua_state_slot_read(cache, top_idx);
			if (top) {
				state->lua_L_ptr = (void *)top;
			}
		}

		lua_unwind_info_t *uw = lua_unwind_info_map__lookup(&key->tgid);
		if (uw) state->lua_offsets_id = uw->offsets_id;
	}

	if (state->lua_L_ptr != NULL) {
		pre_lua_unwind(ctx, state, &oncpu_maps, PROG_LUA_UNWIND_PE_IDX);
	}

	process_shard_list_t *shard_list =
	    process_shard_list_table__lookup(&key->tgid);
	if (shard_list != NULL) {
		key->flags |= STACK_TRACE_FLAGS_DWARF;

		int ret =
		    get_usermode_regs((struct pt_regs *)&ctx->regs,
				      &state->regs);
		if (ret == 0) {
			bpf_tail_call(ctx, &NAME(cp_progs_jmp_pe_map),
				      PROG_DWARF_UNWIND_PE_IDX);
		}
		__sync_fetch_and_add(error_count_ptr, 1);
		return 0;
	}
#endif

	return collect_stack_and_send_output(&ctx->regs, key, NULL, NULL,
					     &oncpu_maps, false);
}

#ifdef LINUX_VER_5_2_PLUS

#define SHARD_BSEARCH_LOOPS 9	// 2^9 = 512 > UNWIND_SHARDS_PER_PROCESS
#define ENTRY_BSEARCH_LOOPS 17	// 2^17 = 131072 > UNWIND_ENTRIES_PER_SHARD

#define LOOP_EXHAUSTED 0xFFFFFFFF
#define ENTRY_NOT_FOUND 0xFFFFFFFE

static inline __attribute__ ((always_inline))
__u32 find_shard(shard_info_t * list, int left, int right, __u64 pc)
{
	int i = left, j = right - 1, mid;
	__u32 found = ENTRY_NOT_FOUND;

#pragma unroll
	for (int loops = 0; loops < SHARD_BSEARCH_LOOPS; loops++) {
		if (i > j) {
			return found;
		}
		mid = i + (j - i) / 2;
		if (mid < 0 || mid >= UNWIND_SHARDS_PER_PROCESS) {
			return ENTRY_NOT_FOUND;
		}
		shard_info_t *info = list + mid;
		if (info->offset + info->pc_min <= pc) {
			found = mid;
			i = mid + 1;
		} else {
			j = mid - 1;
		}
	}
	return LOOP_EXHAUSTED;
}

static inline __attribute__ ((always_inline))
__u32 find_unwind_entry(unwind_entry_t * list, __u16 left, __u16 right,
			__u64 pc)
{
	int i = left, j = right - 1, mid;
	__u32 found = ENTRY_NOT_FOUND;

#pragma unroll
	for (int loops = 0; loops < ENTRY_BSEARCH_LOOPS; loops++) {
		if (i > j) {
			return found;
		}
		mid = i + (j - i) / 2;
		if (mid < 0 || mid >= UNWIND_ENTRIES_PER_SHARD) {
			return ENTRY_NOT_FOUND;
		}
		unwind_entry_t *info = list + mid;
		if (info->pc <= pc) {
			found = mid;
			i = mid + 1;
		} else {
			j = mid - 1;
		}
	}
	return LOOP_EXHAUSTED;
}

#define STACK_FRAMES_PER_RUN 16
#define UNWIND_PROG_MAX_RUN 8

static inline __attribute__ ((always_inline))
int dwarf_unwind(void *ctx, unwind_state_t * state,
		 map_group_t *maps, int jmp_idx)
{
	__u32 count_idx;

	count_idx = SAMPLE_CNT_DROP;
	__u64 *drop_count_ptr = bpf_map_lookup_elem(maps->state, &count_idx);

	count_idx = ERROR_IDX;
	__u64 *error_count_ptr = bpf_map_lookup_elem(maps->state, &count_idx);

	if (drop_count_ptr == NULL || error_count_ptr == NULL) {
		count_idx = ERROR_IDX;
		__u64 err_val = 1;
		bpf_map_update_elem(maps->state, &count_idx, &err_val, BPF_ANY);
		return -1;
	}

	process_shard_list_t *shard_list =
	    process_shard_list_table__lookup(&state->key.tgid);
	if (shard_list == NULL) {
		return 0;
	}

	regs_t *regs = &state->regs;
	shard_info_t *shard_info = NULL;
	unwind_entry_shard_t *shard = NULL;

#pragma unroll
	for (int i = 0; i < STACK_FRAMES_PER_RUN; i++) {
		if (!shard_info || !shard
		    || regs->ip < shard_info->offset + shard_info->pc_min
		    || regs->ip >= shard_info->offset + shard_info->pc_max) {
			__u32 shard_index =
			    find_shard(shard_list->entries, 0, shard_list->len,
				       regs->ip);
			if (shard_index >= UNWIND_SHARDS_PER_PROCESS) {
				if (shard_index == LOOP_EXHAUSTED) {
					__sync_fetch_and_add(error_count_ptr,
							     1);
				}
				goto finish;
			}
			shard_info = shard_list->entries + shard_index;
			shard =
			    unwind_entry_shard_table__lookup(&shard_info->id);
		}
		// bpf_debug("frame#%d", state->stack.len);
		// bpf_debug("ip=%lx bp=%lx sp=%lx", regs->ip, regs->bp, regs->sp);
		if (shard_info) {
			// add frame if ip is in executable segments
			add_frame(&state->stack, regs->ip);
		}

		if (shard_info == NULL || shard == NULL) {
			goto finish;
		}

		__u32 index =
		    find_unwind_entry(shard->entries, shard_info->entry_start,
				      shard_info->entry_end,
				      regs->ip - shard_info->offset);
		if (index >= UNWIND_ENTRIES_PER_SHARD) {
			if (index == LOOP_EXHAUSTED) {
				__sync_fetch_and_add(error_count_ptr, 1);
			}
			goto finish;
		}

		unwind_entry_t *ue = shard->entries + index;
		__u64 cfa = 0;
		switch (ue->cfa_type) {
		case CFA_TYPE_NO_ENTRY:
			// no entry means finished
			goto finish;
		case CFA_TYPE_RBP_OFFSET:
			if (ue->cfa_offset < 0) {
				cfa = regs->bp - ((-ue->cfa_offset) << 3);
			} else {
				cfa = regs->bp + (ue->cfa_offset << 3);
			}
			break;
		case CFA_TYPE_RSP_OFFSET:
			if (ue->cfa_offset < 0) {
				cfa = regs->sp - ((-ue->cfa_offset) << 3);
			} else {
				cfa = regs->sp + (ue->cfa_offset << 3);
			}
			break;
		default:
			// bpf_debug("unsupported cfa_type %d tgid=%d ip=%lx", ue->cfa_type, state->key.tgid, regs->ip);
			__sync_fetch_and_add(error_count_ptr, 1);
			goto finish;
		}
		if (bpf_probe_read_user
		    (&regs->ip, sizeof(__u64), (void *)(cfa - 8)) != 0) {
			__sync_fetch_and_add(error_count_ptr, 1);
			goto finish;
		}
		__u64 rbp_addr = cfa;
		switch (ue->rbp_type) {
		case REG_TYPE_UNDEFINED:
		case REG_TYPE_SAME_VALUE:
			break;
		case REG_TYPE_OFFSET:
			if (ue->rbp_offset < 0) {
				rbp_addr -= (-ue->rbp_offset) << 3;
			} else {
				rbp_addr += (ue->rbp_offset) << 3;
			}
			if (bpf_probe_read_user
			    (&regs->bp, sizeof(__u64), (void *)rbp_addr) != 0) {
				__sync_fetch_and_add(error_count_ptr, 1);
				goto finish;
			}
			break;
		case REG_TYPE_UNSUPPORTED:
			// bpf_debug("unsupported rpb_type %d", ue->rbp_type);
			__sync_fetch_and_add(error_count_ptr, 1);
			goto finish;
		}
		regs->sp = cfa;
	}

	if (++state->runs < UNWIND_PROG_MAX_RUN) {
		bpf_tail_call(ctx, maps->progs_jmp, jmp_idx);
	}

finish:
	return 0;
}

PROGPE(dwarf_unwind) (struct bpf_perf_event_data * ctx) {
	__u32 zero = 0;
	unwind_state_t *state = heap__lookup(&zero);
	if (state == NULL) {
		return 0;
	}

	dwarf_unwind(ctx, state, &oncpu_maps, PROG_DWARF_UNWIND_PE_IDX);

	bpf_tail_call(ctx, &NAME(cp_progs_jmp_pe_map),
		      PROG_ONCPU_OUTPUT_PE_IDX);
	return 0;
}

static inline __attribute__ ((always_inline))
__u32 read_symbol(python_offsets_t * py_offsets, void *frame_ptr,
		  void *code_ptr, symbol_t * symbol)
{
	void *ptr;
	bpf_probe_read_user(&ptr, sizeof(ptr),
			    code_ptr + py_offsets->code_object.co_varnames);
	bpf_probe_read_user(&ptr, sizeof(ptr),
			    ptr + py_offsets->tuple_object.ob_item);
	bpf_probe_read_user_str(&symbol->method_name,
				sizeof(symbol->method_name),
				ptr + py_offsets->string.data);

	char self_str[4] = "self";
	char cls_str[4] = "cls";
	bool first_self = *(__s32 *) symbol->method_name == *(__s32 *) self_str;
	bool first_cls = *(__s32 *) symbol->method_name == *(__s32 *) cls_str;

	if (first_self || first_cls) {
		bpf_probe_read_user(&ptr, sizeof(ptr),
				    frame_ptr +
				    py_offsets->frame_object.f_localsplus);
		if (first_self) {
			bpf_probe_read_user(&ptr, sizeof(ptr),
					    ptr + py_offsets->object.ob_type);
		}
		bpf_probe_read_user(&ptr, sizeof(ptr),
				    ptr + py_offsets->type_object.tp_name);
		bpf_probe_read_user_str(&symbol->class_name,
					sizeof(symbol->class_name), ptr);
	}
	// bpf_probe_read_user(&ptr, sizeof(ptr), code_ptr + py_offsets->code_object.co_filename);
	// bpf_probe_read_user_str(&symbol->path, sizeof(symbol->path), ptr + py_offsets->string.data);

	bpf_probe_read_user(&ptr, sizeof(ptr),
			    code_ptr + py_offsets->code_object.co_name);
	bpf_probe_read_user_str(&symbol->method_name,
				sizeof(symbol->method_name),
				ptr + py_offsets->string.data);

	__u32 lineno;
	bpf_probe_read_user(&lineno, sizeof(lineno),
			    code_ptr + py_offsets->code_object.co_firstlineno);

	return lineno;
}

#define MAX_CPUS 200

static inline __attribute__ ((always_inline))
__u32 get_symbol_id(symbol_t * symbol)
{
	__u32 *found_id = bpf_map_lookup_elem(&__symbol_table, symbol);
	if (found_id) {
		return *found_id;
	}

	__u32 zero = 0;
	__u32 *sym_idx = symbol_index_storage__lookup(&zero);
	if (sym_idx == NULL) {
		return 0;
	}

	__u32 id = *sym_idx * MAX_CPUS + bpf_get_smp_processor_id();
	*sym_idx += 1;

	int err = bpf_map_update_elem(&__symbol_table, symbol, &id, BPF_ANY);
	if (err) {
		return 0;
	}
	return id;
}

static inline __attribute__ ((always_inline))
int pre_python_unwind(void *ctx, unwind_state_t * state,
		 map_group_t *maps, int jmp_idx) {
	python_unwind_info_t *py_unwind_info =
	    python_unwind_info_map__lookup(&state->key.tgid);
	if (py_unwind_info == NULL) {
        return 0;
	}
	state->py_offsets_id = py_unwind_info->offsets_id;

	python_offsets_t *py_offsets =
	    python_offsets_map__lookup(&state->py_offsets_id);
	if (py_offsets == NULL) {
        return 0;
	}

	void *thread_state;
	if (bpf_probe_read_user
	    (&thread_state, sizeof(thread_state),
	     (void *)py_unwind_info->thread_state_address) != 0) {
        return 0;
	}

	if (thread_state == NULL) {
        __u64 *addr = python_tstate_addr_map__lookup(&state->key.tgid);
        if (addr && *addr != 0) {
            thread_state = (void *)*addr;
        } else {
            return 0;
		}
	}

	if (bpf_probe_read_user
	    (&state->py_frame_ptr, sizeof(state->py_frame_ptr),
	     thread_state + py_offsets->thread_state.frame) != 0) {
        return 0;
	}

	bpf_tail_call(ctx, maps->progs_jmp, jmp_idx);
	return 0;
}

static inline __attribute__ ((always_inline))
int python_unwind(void *ctx, unwind_state_t * state,
		 map_group_t *maps, int jmp_idx) {
	if (state->py_frame_ptr == NULL) {
		goto output;
	}

	python_offsets_t *py_offsets =
	    python_offsets_map__lookup(&state->py_offsets_id);
	if (py_offsets == NULL) {
		goto output;
	}

	symbol_t symbol;

#pragma unroll
	for (int i = 0; i < STACK_FRAMES_PER_RUN; i++) {
		void *code_ptr = 0;
		if (bpf_probe_read_user
		    (&code_ptr, sizeof(code_ptr),
		     state->py_frame_ptr + py_offsets->frame_object.f_code) !=
		    0) {
			goto output;
		}
		if (code_ptr == NULL) {
			goto output;
		}

		__builtin_memset(&symbol, 0, sizeof(symbol));
		__u64 lineno =
		    read_symbol(py_offsets, state->py_frame_ptr, code_ptr,
				&symbol);
		if (lineno == 0) {
			goto output;
		}
		__u64 symbol_id = get_symbol_id(&symbol);
		add_frame(&state->intp_stack, (lineno << 32) | symbol_id);

		if (bpf_probe_read_user(&state->py_frame_ptr, sizeof(void *),
					state->py_frame_ptr +
					py_offsets->frame_object.f_back) != 0) {
			goto output;
		}
		if (!state->py_frame_ptr) {
			goto output;
		}
	}

	if (++state->runs < UNWIND_PROG_MAX_RUN) {
		bpf_tail_call(ctx, maps->progs_jmp, jmp_idx);
	}

output:
	return 0;
}

PROGPE(python_unwind) (struct bpf_perf_event_data * ctx) {
	__u32 count_idx;

	count_idx = ERROR_IDX;
	__u64 *error_count_ptr = profiler_state_map__lookup(&count_idx);

	if (error_count_ptr == NULL) {
		count_idx = ERROR_IDX;
		__u64 err_val = 1;
		profiler_state_map__update(&count_idx, &err_val);
		return -1;
	}

	__u32 zero = 0;
	unwind_state_t *state = heap__lookup(&zero);
	if (state == NULL) {
		return 0;
	}

	python_unwind(ctx, state, &oncpu_maps, PROG_PYTHON_UNWIND_PE_IDX);

	process_shard_list_t *shard_list =
	    process_shard_list_table__lookup(&state->key.tgid);
	if (shard_list != NULL) {
		state->key.flags |= STACK_TRACE_FLAGS_DWARF;

		int ret =
		    get_usermode_regs((struct pt_regs *)&ctx->regs,
				      &state->regs);
		if (ret == 0) {
			bpf_tail_call(ctx, &NAME(cp_progs_jmp_pe_map),
				      PROG_DWARF_UNWIND_PE_IDX);
		}
		__sync_fetch_and_add(error_count_ptr, 1);
		return 0;
	}

	bpf_tail_call(ctx, &NAME(cp_progs_jmp_pe_map),
		      PROG_ONCPU_OUTPUT_PE_IDX);
	return 0;
}

URETPROG(python_save_tstate_addr) (struct pt_regs * ctx) {
	__u64 ret = PT_REGS_RC(ctx);
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;

	__u64 *addr = python_tstate_addr_map__lookup(&tgid);
	if (addr) {
		*addr = ret;
	} else {
		python_tstate_addr_map__update(&tgid, &ret);
	}
	return 0;
}

PROGPE(oncpu_output) (struct bpf_perf_event_data * ctx) {
	__u32 zero = 0;
	unwind_state_t *state = heap__lookup(&zero);
	if (state == NULL) {
		return 0;
	}
	return collect_stack_and_send_output(&ctx->regs, &state->key,
					     &state->stack, &state->intp_stack,
					     &oncpu_maps, false);
}

static inline __attribute__ ((always_inline))
int pre_lua_unwind(void *ctx, unwind_state_t * state,
		   map_group_t * maps, int jmp_idx)
{
	if (state->lua_L_ptr == NULL) {
		return 0;
	}

	if (state->lua_is_jit) {
		if (!luajit_offsets_map__lookup(&state->lua_offsets_id)) {
			return 0;
		}
	} else {
		if (!lua_offsets_map__lookup(&state->lua_offsets_id)) {
			return 0;
		}
	}

	bpf_tail_call(ctx, maps->progs_jmp, jmp_idx);
	return 0;
}

static __always_inline int lua_unwind(struct bpf_perf_event_data *ctx,
				      void *lua_state, lua_ofs *o, 
					  stack_t * intp_stack)
{
	if (!intp_stack) {
		return 0;
	}

	void *ci = NULL, *base_ci = NULL, *end_ci = NULL;
	if (bpf_probe_read_user
	    (&ci, sizeof(ci), (char *)lua_state + o->off_l_ci)) {
		return 0;
	}
	/* base_ci end_ci for Lua 5.1 */
	if (o->features & LUA_FEAT_CI_ARRAY) {
		if (bpf_probe_read_user
		    (&base_ci, sizeof(base_ci),
		    (char *)lua_state + o->off_l_base_ci)) {
			return 0;
		}
		if (bpf_probe_read_user
			(&end_ci, sizeof(end_ci),
		    (char *)lua_state + o->off_l_end_ci)) {
			return 0;
		}
		if (!ci || !base_ci || !end_ci) {
			return 0;
		}
	}
#pragma unroll
	for (int i = 0; i < STACK_FRAMES_PER_RUN; i++) {

		if (intp_stack->len >= STACK_FRAMES_PER_RUN) {
			break;
		}

		if (o->features & LUA_FEAT_CI_ARRAY) {
			if ((char *)ci < (char *)base_ci
			    || (char *)ci >= (char *)end_ci) {
				break;
			}
		}

		/* Load fields from this CallInfo */
		void *ci_func = NULL, *ci_prev = NULL;
		if (bpf_probe_read_user
			(&ci_func, sizeof(ci_func),
			(char *)ci + o->off_ci_func)) {
			goto next_frame;
		}
		/* ci_prev available in Lua 5.2+ */
		if (o->features & LUA_FEAT_CI_LINKED) {
			(void)bpf_probe_read_user(&ci_prev, sizeof(ci_prev),
						(char *)ci + o->off_ci_prev);
		}

		__u32 tt = -1;
		if (bpf_probe_read_user
		    (&tt, sizeof(tt), (char *)ci_func + o->off_tvalue_tt)) {
			goto next_frame;
		}

		__u32 variant = tt & 0x30;
		bool is_collectable = (tt & LUA_TCOLLECTABLE) != 0;

		void *valp = NULL;
		(void)bpf_probe_read_user(&valp, sizeof(valp),
					  (char *)ci_func +
					  (o->off_tvalue_val ? o->
					   off_tvalue_val : 0));

		void *cl = valp;

		if (o->features & LUA_FEAT_LCF) {
			if (variant == LUA_CLOSURE && is_collectable) {
				void *proto = NULL;
				if (!cl || bpf_probe_read_user(&proto,
					sizeof(proto), (char *)cl +
					o->off_lclosure_p) || !proto) {
					goto next_frame;
				}
				__u64 frame =
				    TAG_LUA | (((__u64) proto) & ~TAG_MASK);
				add_frame(intp_stack, frame);
			} else if (variant == LUA_C_CLOSURE && is_collectable) {
				void *f = NULL;
				if (cl
				    && !bpf_probe_read_user(&f, sizeof(f), (char *)cl +
							    o->off_cclosure_f) && f) {
					__u64 frame =
					    TAG_CFUNC | (((__u64) f) &
							 ~TAG_MASK);
					add_frame(intp_stack, frame);
				}
			} else if (variant == LUA_LIGHT_C_FUNC
				   && !is_collectable) {
				if (valp) {
					__u64 frame =
					    TAG_CFUNC | (((__u64) valp) & ~TAG_MASK);
					add_frame(intp_stack, frame);
				}
			} else {
				goto next_frame;
			}
		} else {
			__u8 is_c = 0;
			if (bpf_probe_read_user
			    (&is_c, sizeof(is_c),
			    (char *)cl + o->off_closure_isc)) {
				goto next_frame;
			}
			if (!is_c) {
				void *proto = NULL;
				if (bpf_probe_read_user(&proto, sizeof(proto),
					(char *)cl + o->off_lclosure_p)) {
					goto next_frame;
				}
				__u64 frame =
				    TAG_LUA | (((__u64) proto) & ~TAG_MASK);
				add_frame(intp_stack, frame);
			} else {
				void *cf = NULL;
				if (bpf_probe_read_user(&cf, sizeof(cf),
					(char *)cl + o->off_cclosure_f)) {
					goto next_frame;
				}
				__u64 frame =
				    TAG_CFUNC | (((__u64) cf) & ~TAG_MASK);
				add_frame(intp_stack, frame);
			}
		}

next_frame:
		if (o->features & LUA_FEAT_CI_LINKED) {
			if (!ci_prev) {
				break;
			}
			ci = ci_prev;
			continue;
		} else {
			ci = (void *)((char *)ci - o->sizeof_callinfo);
		}
	}

	return 0;
}

static inline int lua_get_funcdata(void *frame_ptr,
				   stack_t * intp_stack, lj_ofs *o)
{
	if (!frame_ptr) {
		return -1;
	}

	void *fn = frame_func_wr(frame_ptr, o);
	if (!fn) {
		return -1;
	}

	if (is_luafunc(fn, o)) {
		void *pt = NULL;
		if (gcfunc_get_proto(fn, &pt, o)) {
			return -1;
		}
		if (!pt) {
			return -1;
		}
		__u64 frame = TAG_LUA | (((__u64) pt) & ~TAG_MASK);
		add_frame(intp_stack, frame);
	} else if (is_cfunc(fn, o)) {
		void *cf = NULL;
		if (gcfunc_get_cfunc(fn, &cf, o)) { 
			return -1;
		}
		if (!cf) {
			return -1;
		}
		__u64 frame = TAG_CFUNC | (((__u64) cf) & ~TAG_MASK);
		add_frame(intp_stack, frame);
	} else if (is_ffunc(fn, o)) {
		__u8 ffid = 0;
		if (gcfunc_get_ffid(fn, &ffid, o)) {
			return -1;
		}
		__u64 frame = TAG_FFUNC | (__u64) ffid;
		add_frame(intp_stack, frame);
	} else {
		add_frame(intp_stack, TAG_MASK);
		return -1;
	}
	return 0;
}

static int luajit_unwind(struct bpf_perf_event_data *ctx,
			unwind_state_t *state, lj_ofs *o)
{
	stack_t *intp_stack = &state->intp_stack;
	void *lua_state = state->lua_L_ptr;

	if (!intp_stack || !lua_state) {
		return 0;
	}

	if (intp_stack->len >= STACK_FRAMES_PER_RUN) {
		return 0;
	}

	if (!state->luajit_frame || !state->luajit_bot) {
		void *stack_ptr = NULL, *base_ptr = NULL;
		if (L_get_stack(lua_state, &stack_ptr, o)) {
			return 0;
		}
		if (L_get_base(lua_state, &base_ptr, o)) {
			return 0;
		}

		state->luajit_bot = (void *)((char *)stack_ptr + o->tv_sz);
		state->luajit_frame = (void *)((char *)base_ptr - o->tv_sz);
		state->luajit_skip_depth = 1;
	}

	void *frame = state->luajit_frame;
	void *bot = state->luajit_bot;
	if (!frame || frame <= bot) {
		return 0;
	}

	/*
		* Frame walk logic mirrors LuaJIT’s lj_debug.c:
		* https://github.com/LuaJIT/LuaJIT/blob/v2.1/src/lj_debug.c
		*  - skip_depth counts how many dummy frames to skip.
		*  - we post-decrement skip_depth to detect when it hits zero (record),
		*    then immediately bump it back so it stays at zero for the rest of
		*    the run.
		*  - state->luajit_frame/skip_depth persist across tail calls, so each
		*    invocation processes a single frame but the countdown semantics
		*    remain identical to the upstream implementation.
		*/

	int skip_depth = state->luajit_skip_depth;

	int eq = frame_gc_equals_L(frame, lua_state, o);
	if (eq > 0) {
		skip_depth++;
	}

	if (skip_depth-- == 0) {
		skip_depth++;
		if (lua_get_funcdata(frame, intp_stack, o) != 0) {
			goto advance;
		}
	}

	advance:
	if (frame_islua_wr(frame, o) > 0) {
		frame = frame_prevl_wr(frame, o);
	} else {
		if (frame_isvarg_wr(frame, o) > 0) {
			skip_depth++;
		}
		frame = frame_prevd_wr(frame, o);
	}

	state->luajit_skip_depth = skip_depth;
	state->luajit_frame = frame;

	if (!frame || frame <= bot) {
		state->luajit_frame = NULL;
		state->luajit_bot = NULL;
		return 0;
	}

	return 1;
}

PROGPE(lua_unwind) (struct bpf_perf_event_data * ctx) {
	__u32 count_idx;

	count_idx = ERROR_IDX;
	__u64 *error_count_ptr = profiler_state_map__lookup(&count_idx);

	if (error_count_ptr == NULL) {
		count_idx = ERROR_IDX;
		__u64 err_val = 1;
		profiler_state_map__update(&count_idx, &err_val);
		return -1;
	}

	__u32 zero = 0;
	unwind_state_t *state = heap__lookup(&zero);
	if (state == NULL) {
		return 0;
	}

	if (state->lua_L_ptr != NULL) {
		if (state->lua_is_jit) {
			lj_ofs *o =
			    luajit_offsets_map__lookup(&state->lua_offsets_id);
			if (o) {
				int once = luajit_unwind(ctx, state, o);
				if (once > 0) {
					state->runs++;
					if (state->runs < STACK_FRAMES_PER_RUN) {
						bpf_tail_call(ctx, &NAME(cp_progs_jmp_pe_map),
							      PROG_LUA_UNWIND_PE_IDX);
					}
				}
				else {
					state->luajit_frame = NULL;
					state->luajit_bot = NULL;
					state->luajit_skip_depth = 0;
				}
			}
		} else {
			lua_ofs *o =
			    lua_offsets_map__lookup(&state->lua_offsets_id);
			if (o) {
				lua_unwind(ctx, state->lua_L_ptr, o,
							&state->intp_stack);
			}
		}
	}

	bpf_tail_call(ctx, &NAME(cp_progs_jmp_pe_map),
		      PROG_ONCPU_OUTPUT_PE_IDX);
	return 0;
}

static __always_inline int probe_entry_lua(struct pt_regs *ctx)
{
	void *param1 = (void *)PT_REGS_PARM1(ctx);
	if (!param1) {
		return 0;
	}

	__u64 id = bpf_get_current_pid_tgid();

	lua_state_stack_push(id, (__u64)param1);
	return 0;
}

static __always_inline int probe_entry_lua_cancel(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	lua_state_stack_pop(id);
	return 0;
}

/*
 * Lua interpreter entry/exit uprobes:
 *   - handle_entry_lua stores the lua_State * for the current thread so user
 *     space can unwind Lua stacks.
 *   - handle_entry_lua_cancel removes that cached state when the interpreter
 *     yields or returns.
 *
 * Toggling  (`inputs.ebpf.profile.on_cpu.disabled = true`) will keeps the agent 
 * from attaching the Lua uprobes.
 *
 */
UPROG(handle_entry_lua) (struct pt_regs * ctx) {
	return probe_entry_lua(ctx);
}

URETPROG(handle_entry_lua_cancel) (struct pt_regs * ctx) {
	return probe_entry_lua_cancel(ctx);
}

#endif
