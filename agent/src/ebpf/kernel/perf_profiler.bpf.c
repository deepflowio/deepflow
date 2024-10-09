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

MAP_PERF_EVENT(profiler_output_a, int, __u32, MAX_CPU, FEATURE_PROFILE_ONCPU)
MAP_PERF_EVENT(profiler_output_b, int, __u32, MAX_CPU, FEATURE_PROFILE_ONCPU)
MAP_PROG_ARRAY(cp_progs_jmp_pe_map, __u32, __u32, CP_PROG_PE_NUM, FEATURE_PROFILE_ONCPU)

MAP_STACK_TRACE(stack_map_a, STACK_MAP_ENTRIES, FEATURE_PROFILE_ONCPU)
MAP_STACK_TRACE(stack_map_b, STACK_MAP_ENTRIES, FEATURE_PROFILE_ONCPU)

typedef struct {
    struct bpf_map_def *state;
    struct bpf_map_def *stack_map_a;
    struct bpf_map_def *stack_map_b;
    struct bpf_map_def *custom_stack_map_a;
    struct bpf_map_def *custom_stack_map_b;
    struct bpf_map_def *profiler_output_a;
    struct bpf_map_def *profiler_output_b;
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
MAP_HASH(custom_stack_map_a, __u32, __raw_stack, 1, FEATURE_DWARF_UNWINDING)
MAP_HASH(custom_stack_map_b, __u32, __raw_stack, 1, FEATURE_DWARF_UNWINDING)

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
MAP_HASH(process_shard_list_table, __u32, process_shard_list_t, 1, FEATURE_DWARF_UNWINDING)
MAP_HASH(unwind_entry_shard_table, __u32, unwind_entry_shard_t, 1, FEATURE_DWARF_UNWINDING)

/*
 * For sysinfo gathered from BTF
 */
MAP_ARRAY(unwind_sysinfo, __u32, unwind_sysinfo_t, 1, FEATURE_DWARF_UNWINDING)

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
    process_shard_list_t *shard_list;

    regs_t regs;
    stack_t stack;

    __u8 output_callback;
} unwind_state_t;

/*
 * memset'ing a struct larger than 1024B is not accepted by the compiler
 */
static inline __attribute__((always_inline)) void reset_unwind_state(unwind_state_t *state) {
    __builtin_memset(&state->key, 0, sizeof(struct stack_trace_key_t));
    state->runs = 0;
    state->shard_list = NULL;
    __builtin_memset(&state->regs, 0, sizeof(regs_t));
    __builtin_memset(&state->stack, 0, sizeof(stack_t));
}

MAP_PERARRAY(heap, __u32, unwind_state_t, 1, FEATURE_DWARF_UNWINDING)
#else

typedef void stack_t; // placeholder

#endif

/*
 * Used for communication between user space and BPF to control the
 * switching between buffer a and buffer b.
 */
MAP_ARRAY(profiler_state_map, __u32, __u64, PROFILER_CNT, FEATURE_PROFILE_ONCPU)
#ifdef LINUX_VER_5_2_PLUS
static inline __attribute__((always_inline)) void add_frame(stack_t *stack, __u64 frame) {
    __u8 len = stack->len;
    if (len >= 0 && len < PERF_MAX_STACK_DEPTH) {
        stack->addrs[len] = frame;
        stack->len++;
    }
}

static inline __u32 rol32(__u32 word, unsigned int shift) { return (word << shift) | (word >> ((-shift) & 31)); }

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
static inline __attribute__((always_inline)) __u32 hash_stack(stack_t *stack, __u32 initval) {
    __u32 *k = (__u32 *)stack->addrs;
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
    case 0: /* Nothing left to add */
        break;
    }

    return c;
}

static inline __attribute__((always_inline)) __u32 get_stackid(struct bpf_map_def *stack_map, stack_t *stack) {
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
    int ret = bpf_map_update_elem(stack_map, &id, stack->addrs, BPF_NOEXIST);
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

static inline __attribute__((always_inline)) bool is_usermod_regs(struct pt_regs *regs) {
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
static inline __attribute__((always_inline)) int get_usermode_regs(struct pt_regs *regs, regs_t *dst) {
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
    int ret = bpf_probe_read_kernel(&stack, sizeof(void *), ((void *)task) + sysinfo->task_struct_stack_offset);
    if (ret || stack == NULL) {
        return -1;
    }

    struct pt_regs *user_regs_addr = ((struct pt_regs *)(stack + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING)) - 1;
    struct pt_regs user_regs;
    ret = bpf_probe_read_kernel(&user_regs, sizeof(user_regs), (void *)user_regs_addr);
    if (ret) {
        return -1;
    }

    dst->ip = PT_REGS_IP(&user_regs);
    dst->sp = PT_REGS_SP(&user_regs);
    dst->bp = PT_REGS_FP(&user_regs);
    return 0;
}

#endif

static inline
    __attribute__((always_inline)) int collect_stack_and_send_output(struct pt_regs *ctx, struct stack_trace_key_t *key,
                                                                     stack_t *stack, map_group_t *maps) {
    __u32 count_idx;

    count_idx = TRANSFER_CNT_IDX;
    __u64 *transfer_count_ptr = bpf_map_lookup_elem(maps->state, &count_idx);

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

    if (transfer_count_ptr == NULL || sample_count_ptrs[0] == NULL || sample_count_ptrs[1] == NULL ||
        drop_count_ptr == NULL || iter_count_ptr == NULL || error_count_ptr == NULL || output_count_ptr == NULL) {
        count_idx = ERROR_IDX;
        __u64 err_val = 1;
        bpf_map_update_elem(maps->state, &count_idx, &err_val, BPF_ANY);
        return 0;
    }

    struct bpf_map_def *stack_map = NULL;

#ifdef LINUX_VER_5_2_PLUS
    if (key->flags & STACK_TRACE_FLAGS_DWARF && stack != NULL) {
        if (!((*transfer_count_ptr) & 0x1ULL)) {
            stack_map = maps->custom_stack_map_a;
        } else {
            stack_map = maps->custom_stack_map_b;
        }
        key->userstack = get_stackid(stack_map, stack);
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
        key->userstack = bpf_get_stackid(ctx, stack_map, USER_STACKID_FLAGS);
    }

    if (-EEXIST == key->kernstack) {
        __sync_fetch_and_add(drop_count_ptr, 1);
    }

    if (-EEXIST == key->userstack) {
        __sync_fetch_and_add(drop_count_ptr, 1);
    }

    if (key->userstack < 0 && key->kernstack < 0) {
        return 0;
    }

    sample_count = *sample_count_ptr;
    __sync_fetch_and_add(sample_count_ptr, 1);

    if (bpf_perf_event_output(ctx, profiler_output, BPF_F_CURRENT_CPU, key, sizeof(struct stack_trace_key_t))) {
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

static map_group_t oncpu_maps = {
    .state = &NAME(profiler_state_map),
    .stack_map_a = &NAME(stack_map_a),
    .stack_map_b = &NAME(stack_map_b),
#ifdef LINUX_VER_5_2_PLUS
    .custom_stack_map_a = &NAME(custom_stack_map_a),
    .custom_stack_map_b = &NAME(custom_stack_map_b),
#endif
    .profiler_output_a = &NAME(profiler_output_a),
    .profiler_output_b = &NAME(profiler_output_b)
};

PERF_EVENT_PROG(oncpu_profile)(struct bpf_perf_event_data *ctx) {
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

    if (unlikely(*enable_ptr == 0))
        return 0;

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
    key->pid = (__u32)id;

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
    state->shard_list = process_shard_list_table__lookup(&key->tgid);
    if (state->shard_list != NULL) {
        key->flags |= STACK_TRACE_FLAGS_DWARF;

        int ret = get_usermode_regs((struct pt_regs *)&ctx->regs, &state->regs);
        if (ret == 0) {
            state->output_callback = PROG_ONCPU_OUTPUT_PE_IDX;
            bpf_tail_call(ctx, &NAME(cp_progs_jmp_pe_map), PROG_DWARF_UNWIND_PE_IDX);
        }
        __sync_fetch_and_add(error_count_ptr, 1);
        return 0;
    }
#endif

    return collect_stack_and_send_output(&ctx->regs, key, NULL, &oncpu_maps);
}

#ifdef LINUX_VER_5_2_PLUS

#define SHARD_BSEARCH_LOOPS 9  // 2^9 = 512 > UNWIND_SHARDS_PER_PROCESS
#define ENTRY_BSEARCH_LOOPS 17 // 2^17 = 131072 > UNWIND_ENTRIES_PER_SHARD

#define LOOP_EXHAUSTED 0xFFFFFFFF
#define ENTRY_NOT_FOUND 0xFFFFFFFE

static inline __attribute__((always_inline)) __u32 find_shard(shard_info_t *list, int left, int right, __u64 pc) {
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

static inline
    __attribute__((always_inline)) __u32 find_unwind_entry(unwind_entry_t *list, __u16 left, __u16 right, __u64 pc) {
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

static inline __attribute__((always_inline)) int dwarf_unwind(void *ctx, struct bpf_map_def *jmp_map) {
    __u32 count_idx;

    count_idx = SAMPLE_CNT_DROP;
    __u64 *drop_count_ptr = profiler_state_map__lookup(&count_idx);

    count_idx = ERROR_IDX;
    __u64 *error_count_ptr = profiler_state_map__lookup(&count_idx);

    if (drop_count_ptr == NULL || error_count_ptr == NULL) {
        count_idx = ERROR_IDX;
        __u64 err_val = 1;
        profiler_state_map__update(&count_idx, &err_val);
        return 0;
    }

    __u32 zero = 0;
    unwind_state_t *state = heap__lookup(&zero);
    if (state == NULL) {
        return 0;
    }

    process_shard_list_t *shard_list = process_shard_list_table__lookup(&state->key.tgid);
    if (shard_list == NULL) {
        return 0;
    }

    regs_t *regs = &state->regs;
    shard_info_t *shard_info = NULL;
    unwind_entry_shard_t *shard = NULL;

#pragma unroll
    for (int i = 0; i < STACK_FRAMES_PER_RUN; i++) {
        if (!shard_info || !shard || regs->ip < shard_info->offset + shard_info->pc_min ||
            regs->ip >= shard_info->offset + shard_info->pc_max) {
            __u32 shard_index = find_shard(shard_list->entries, 0, shard_list->len, regs->ip);
            if (shard_index >= UNWIND_SHARDS_PER_PROCESS) {
                if (shard_index == LOOP_EXHAUSTED) {
                    __sync_fetch_and_add(error_count_ptr, 1);
                }
                goto finish;
            }
            shard_info = shard_list->entries + shard_index;
            shard = unwind_entry_shard_table__lookup(&shard_info->id);
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

        __u32 index = find_unwind_entry(shard->entries, shard_info->entry_start, shard_info->entry_end,
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
        if (bpf_probe_read_user(&regs->ip, sizeof(__u64), (void *)(cfa - 8)) != 0) {
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
            if (bpf_probe_read_user(&regs->bp, sizeof(__u64), (void *)rbp_addr) != 0) {
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
        bpf_tail_call(ctx, jmp_map, PROG_DWARF_UNWIND_PE_IDX);
    }

finish:
    bpf_tail_call(ctx, jmp_map, state->output_callback);
    return 0;
}

PROGPE(dwarf_unwind)(struct bpf_perf_event_data *ctx) {
    return dwarf_unwind(ctx, &NAME(cp_progs_jmp_pe_map));
}

PROGPE(oncpu_output)(struct bpf_perf_event_data *ctx) {
    __u32 zero = 0;
    unwind_state_t *state = heap__lookup(&zero);
    if (state == NULL) {
        return 0;
    }
    return collect_stack_and_send_output(&ctx->regs, &state->key, &state->stack, &oncpu_maps);
}

#endif
