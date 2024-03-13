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

#ifndef DF_BPF_BASE_H
#define DF_BPF_BASE_H

#include <linux/version.h>
#include <asm/ptrace.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdbool.h>
#include <errno.h>
#include <stddef.h>
#include <bcc/compat/linux/bpf.h>
#include "utils.h"

struct task_struct;

/*
 * bpf helpers
 */
static void *(*bpf_map_lookup_elem) (void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem) (void *map, const void *key,
				    const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem) (void *map, const void *key) = (void *)3;
static long (*bpf_probe_read) (void *dst, __u32 size, const void *unsafe_ptr) =
    (void *)4;
static __u64(*bpf_ktime_get_ns) (void) = (void *)5;
static long (*bpf_trace_printk) (const char *fmt, __u32 fmt_size, ...) =
    (void *)6;
static __u32(*bpf_get_prandom_u32) (void) = (void *)7;
static __u32(*bpf_get_smp_processor_id) (void) = (void *)8;
static long (*bpf_tail_call) (void *ctx, void *prog_array_map, __u32 index) =
    (void *)12;
static __u64(*bpf_get_current_pid_tgid) (void) = (void *)14;
static __u64(*bpf_get_current_uid_gid) (void) = (void *)15;
static long (*bpf_get_current_comm) (void *buf, __u32 size_of_buf) = (void *)16;
static __u64(*bpf_get_current_task) (void) = (void *)35;
static long (*bpf_perf_event_output) (void *ctx, void *map, __u64 flags,
				      void *data, __u64 size) = (void *)25;
static long (*bpf_probe_read_str) (void *dst, __u32 size,
				   const void *unsafe_ptr) = (void *)45;
#if defined(__aarch64__) && defined(LINUX_VER_KYLIN)
static long (*bpf_probe_read_user) (void *dst, __u32 size, const void *unsafe_ptr) = (void *)112;
#else
// bpf_probe_read_user added in Linux 5.5, Instead of bpf_probe_read_user(), use bpf_probe_read() here.
static long (*bpf_probe_read_user) (void *dst, __u32 size, const void *unsafe_ptr) = (void *)4; // real value is 112
#endif

static int (*bpf_get_stackid)(void *ctx, void *map, int flags) = (void *)27;

#if __GNUC__ && !__clang__
#define SEC(name) __attribute__((section(name), used))
#else
#define SEC(name) \
	_Pragma("GCC diagnostic push")                                      \
	_Pragma("GCC diagnostic ignored \"-Wignored-attributes\"")          \
	__attribute__((section(name), used))                                \
	_Pragma("GCC diagnostic pop")                                       \

#endif

#if defined(__x86_64__)
#ifdef __KERNEL__
#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x) ((x)->sp)
#define PT_REGS_FP(x) ((x)->bp)
#define PT_REGS_RC(x) ((x)->ax)
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->ip)
#else
#ifdef __i386__
/* i386 kernel is built with -mregparm=3 */
#define PT_REGS_PARM1(x) ((x)->eax)
#define PT_REGS_PARM2(x) ((x)->edx)
#define PT_REGS_PARM3(x) ((x)->ecx)
#define PT_REGS_PARM4(x) 0
#define PT_REGS_PARM5(x) 0
#define PT_REGS_RET(x) ((x)->esp)
#define PT_REGS_FP(x) ((x)->ebp)
#define PT_REGS_RC(x) ((x)->eax)
#define PT_REGS_SP(x) ((x)->esp)
#define PT_REGS_IP(x) ((x)->eip)
#else
#define PT_REGS_PARM1(x) ((x)->rdi)
#define PT_REGS_PARM2(x) ((x)->rsi)
#define PT_REGS_PARM3(x) ((x)->rdx)
#define PT_REGS_PARM4(x) ((x)->rcx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x) ((x)->rsp)
#define PT_REGS_FP(x) ((x)->rbp)
#define PT_REGS_RC(x) ((x)->rax)
#define PT_REGS_SP(x) ((x)->rsp)
#define PT_REGS_IP(x) ((x)->rip)
#endif
#endif
#elif defined(__aarch64__)
struct pt_regs {
	union {
		struct user_pt_regs user_regs;
		struct {
			__u64 regs[31];
			__u64 sp;
			__u64 pc;
			__u64 pstate;
		};
	};
	__u64 orig_x0;
#ifdef __AARCH64EB__
	__u32 unused2;
	__s32 syscallno;
#else
	__s32 syscallno;
	__u32 unused2;
#endif

	__u64 orig_addr_limit;
	__u64 unused;		// maintain 16 byte alignment
	__u64 stackframe[2];
};

#define PT_REGS_PARM1(x) ((x)->regs[0])
#define PT_REGS_PARM2(x) ((x)->regs[1])
#define PT_REGS_PARM3(x) ((x)->regs[2])
#define PT_REGS_PARM4(x) ((x)->regs[3])
#define PT_REGS_PARM5(x) ((x)->regs[4])
#define PT_REGS_RET(x) ((x)->regs[30])
#define PT_REGS_FP(x) ((x)->regs[29])	/* Works only with CONFIG_FRAME_POINTER */
#define PT_REGS_RC(x) ((x)->regs[0])
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->pc)
#else
_Pragma("GCC error \"Must specify a BPF target arch\"");
#endif

#define MAX_CPU         256
#define SP_OFFSET(offset) (void *)(__u64)PT_REGS_SP(ctx) + offset * 8

#define bpf_debug(fmt, ...)				\
({							\
	char ____fmt[] = fmt;				\
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
			##__VA_ARGS__);			\
})

/*
 * 下面定义适合 go version >= 1.17
 * 汇编中使用RAX，EAX，下面是之间的关系
 * 注意：编译器对寄存器的选取规则
 * 大于32位最大值小于64位最大值的数据使用RAX，而数据小于32位的最大值使用EAX，
 * 这与定义的数据类型无关。
 *
 * |63 .......... 32|31 .......... 16|15 ... 8|7 ...  0|
 *                                   |---AH---|---AL---|
 *                                   |--------AX-------|
 *                  |--------------EAX-----------------|
 * |----------------------RAX--------------------------|
 */
#if defined(__x86_64__)
#define PT_GO_REGS_PARM1(x) ((x)->rax)
#define PT_GO_REGS_PARM2(x) ((x)->rbx)
#define PT_GO_REGS_PARM3(x) ((x)->rcx)
#define PT_GO_REGS_PARM4(x) ((x)->rdi)
#define PT_GO_REGS_PARM5(x) ((x)->rsi)
#define PT_GO_REGS_PARM6(x) ((x)->r8)
#define PT_GO_REGS_PARM7(x) ((x)->r9)
#define PT_GO_REGS_PARM8(x) ((x)->r10)
#define PT_GO_REGS_PARM9(x) ((x)->rdx)
#elif defined(__aarch64__)
#define PT_GO_REGS_PARM1(x) ((x)->regs[0])
#define PT_GO_REGS_PARM2(x) ((x)->regs[1])
#define PT_GO_REGS_PARM3(x) ((x)->regs[2])
#define PT_GO_REGS_PARM4(x) ((x)->regs[3])
#define PT_GO_REGS_PARM5(x) ((x)->regs[4])
#define PT_GO_REGS_PARM6(x) ((x)->regs[5])
#define PT_GO_REGS_PARM7(x) ((x)->regs[6])
#define PT_GO_REGS_PARM8(x) ((x)->regs[7])
#define PT_GO_REGS_PARM9(x) ((x)->regs[8])
#else
_Pragma("GCC error \"PT_GO_REGS_PARM\"");
#endif

#define __stringify_1(x) #x
#define __stringify(x)  __stringify_1(x)

#define NAME(N)  __##N

#define PROGTP(F) SEC("prog/tp/"__stringify(F)) int bpf_prog_tp__##F
#define PROGKP(F) SEC("prog/kp/"__stringify(F)) int bpf_prog_kp__##F
#define KRETPROG(F) SEC("kretprobe/"__stringify(F)) int kretprobe__##F
#define KPROG(F) SEC("kprobe/"__stringify(F)) int kprobe__##F
#define TPPROG(F) SEC("tracepoint/syscalls/"__stringify(F)) int bpf_func_##F

#ifndef CUR_CPU_IDENTIFIER
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
#define CUR_CPU_IDENTIFIER BPF_F_CURRENT_CPU
#else
#define CUR_CPU_IDENTIFIER bpf_get_smp_processor_id()
#endif
#endif

#ifndef static_always_inline
#define static_always_inline static inline __attribute__ ((__always_inline__))
#endif

#define _(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

#ifndef CUR_CPU_IDENTIFIER
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
#define CUR_CPU_IDENTIFIER BPF_F_CURRENT_CPU
#else
#define CUR_CPU_IDENTIFIER bpf_get_smp_processor_id()
#endif
#endif

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
};

#define __BPF_MAP_DEF(_kt, _vt, _ents) \
	.key_size = sizeof(_kt),       \
	.value_size = sizeof(_vt),     \
	.max_entries = (_ents)

#define MAP_ARRAY(name, key_type, value_type, max_entries) \
struct bpf_map_def SEC("maps") __##name = \
{   \
    .type = BPF_MAP_TYPE_ARRAY, \
    __BPF_MAP_DEF(key_type, value_type, max_entries), \
}; \
static_always_inline __attribute__((unused)) value_type * name ## __lookup(key_type *key) \
{ \
    return (value_type *) bpf_map_lookup_elem(& __##name, (const void *)key); \
} \
static_always_inline __attribute__((unused)) int name ## __update(key_type *key, value_type *value) \
{ \
    return bpf_map_update_elem(& __##name, (const void *)key, (const void *)value, BPF_ANY); \
} \
static_always_inline __attribute__((unused)) int name ## __delete(key_type *key) \
{ \
    return bpf_map_delete_elem(& __##name, (const void *)key); \
}

// BPF_MAP_TYPE_ARRAY define
#define MAP_PERARRAY(name, key_type, value_type, max_entries) \
struct bpf_map_def SEC("maps") __##name = \
{   \
    .type = BPF_MAP_TYPE_PERCPU_ARRAY, \
    __BPF_MAP_DEF(key_type, value_type, max_entries), \
}; \
static_always_inline __attribute__((unused)) value_type * name ## __lookup(key_type *key) \
{ \
    return (value_type *) bpf_map_lookup_elem(& __##name, (const void *)key); \
} \
static_always_inline __attribute__((unused)) int name ## __update(key_type *key, value_type *value) \
{ \
    return bpf_map_update_elem(& __##name, (const void *)key, (const void *)value, BPF_ANY); \
} \
static_always_inline __attribute__((unused)) int name ## __delete(key_type *key) \
{ \
    return bpf_map_delete_elem(& __##name, (const void *)key); \
}

#define MAP_PERF_EVENT(name, key_type, value_type, max_entries) \
struct bpf_map_def SEC("maps") __ ## name = \
{   \
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY, \
    __BPF_MAP_DEF(key_type, value_type, max_entries), \
};

#define MAP_PROG_ARRAY(name, key_type, value_type, max_entries) \
struct bpf_map_def SEC("maps") __ ## name = \
{   \
    .type = BPF_MAP_TYPE_PROG_ARRAY, \
    __BPF_MAP_DEF(key_type, value_type, max_entries), \
};

#define MAP_STACK_TRACE(name, max) \
struct bpf_map_def SEC("maps") __ ## name = { \
        .type = BPF_MAP_TYPE_STACK_TRACE, \
        .key_size = sizeof(__u32), \
        .value_size = PERF_MAX_STACK_DEPTH * sizeof(__u64), \
        .max_entries = (max), \
};

#define MAP_HASH(name, key_type, value_type, max_entries) \
struct bpf_map_def SEC("maps") __##name = \
{   \
    .type = BPF_MAP_TYPE_HASH, \
    __BPF_MAP_DEF(key_type, value_type, max_entries), \
}; \
static_always_inline __attribute__((unused)) value_type * name ## __lookup(key_type *key) \
{ \
    return (value_type *) bpf_map_lookup_elem(& __##name, (const void *)key); \
} \
static_always_inline __attribute__((unused)) int name ## __update(key_type *key, value_type *value) \
{ \
    return bpf_map_update_elem(& __##name, (const void *)key, (const void *)value, BPF_ANY); \
} \
static_always_inline __attribute__((unused)) int name ## __delete(key_type *key) \
{ \
    return bpf_map_delete_elem(& __##name, (const void *)key); \
}

#define BPF_HASH3(_name, _key_type, _leaf_type) \
  MAP_HASH(_name, _key_type, _leaf_type, 40960)

#define BPF_HASH4(_name, _key_type, _leaf_type, _size) \
  MAP_HASH(_name, _key_type, _leaf_type, _size)

// helper for default-variable macro function
#define BPF_HASHX(_1, _2, _3, _4, NAME, ...) NAME

#define BPF_HASH(...) \
  BPF_HASHX(__VA_ARGS__, BPF_HASH4, BPF_HASH3)(__VA_ARGS__)

#define BPF_LEN_CAP(x, cap) (x < cap ? (x & (cap - 1)) : cap)

#endif /* DF_BPF_BASE_H */
