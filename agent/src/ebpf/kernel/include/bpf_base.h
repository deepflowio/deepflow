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

/*
 * bpf helpers
 */
static void
    __attribute__ ((__unused__)) * (*bpf_map_lookup_elem) (void *map,
							   const void *key) =
    (void *)1;
static long
    __attribute__ ((__unused__)) (*bpf_map_update_elem) (void *map,
							 const void *key,
							 const void *value,
							 __u64 flags) =
    (void *)2;
static long
    __attribute__ ((__unused__)) (*bpf_map_delete_elem) (void *map,
							 const void *key) =
    (void *)3;
static long
    __attribute__ ((__unused__)) (*bpf_probe_read) (void *dst, __u32 size,
						    const void *unsafe_ptr) =
    (void *)4;
static __u64 __attribute__ ((__unused__)) (*bpf_ktime_get_ns) (void) =
    (void *)5;
static long
    __attribute__ ((__unused__)) (*bpf_trace_printk) (const char *fmt,
						      __u32 fmt_size, ...) =
    (void *)6;
static __u32 __attribute__ ((__unused__)) (*bpf_get_prandom_u32) (void) =
    (void *)7;
static __u32 __attribute__ ((__unused__)) (*bpf_get_smp_processor_id) (void) =
    (void *)8;
static long
    __attribute__ ((__unused__)) (*bpf_tail_call) (void *ctx,
						   void *prog_array_map,
						   __u32 index) = (void *)12;
static __u64 __attribute__ ((__unused__)) (*bpf_get_current_pid_tgid) (void) =
    (void *)14;
static __u64 __attribute__ ((__unused__)) (*bpf_get_current_uid_gid) (void) =
    (void *)15;
static long
    __attribute__ ((__unused__)) (*bpf_get_current_comm) (void *buf,
							  __u32 size_of_buf) =
    (void *)16;
static __u64 __attribute__ ((__unused__)) (*bpf_get_current_task) (void) =
    (void *)35;
static long
    __attribute__ ((__unused__)) (*bpf_perf_event_output) (void *ctx, void *map,
							   __u64 flags,
							   void *data,
							   __u64 size) =
    (void *)25;
static long
    __attribute__ ((__unused__)) (*bpf_probe_read_str) (void *dst, __u32 size,
							const void *unsafe_ptr)
    = (void *)45;
static long
    __attribute__ ((__unused__)) (*bpf_probe_read_user) (void *dst, __u32 size,
							 const void *unsafe_ptr)
    = (void *)112;
static long
    __attribute__ ((__unused__)) (*bpf_probe_read_kernel) (void *dst,
							   __u32 size,
							   const void
							   *unsafe_ptr) =
    (void *)113;
static long
    __attribute__ ((__unused__)) (*bpf_probe_read_user_str) (void *dst,
							     __u32 size,
							     const void
							     *unsafe_ptr) =
    (void *)114;
static long
    __attribute__ ((__unused__)) (*bpf_probe_read_kernel_str) (void *dst,
							       __u32 size,
							       const void
							       *unsafe_ptr) =
    (void *)115;
static int
    __attribute__ ((__unused__)) (*bpf_sock_ops_cb_flags_set) (void *skops,
							       int flags) =
    (void *)59;
static int
    __attribute__ ((__unused__)) (*bpf_reserve_hdr_opt) (void *skops,
							 __u32 reserve_len,
							 __u32 flags) =
    (void *)144;
static int
    __attribute__ ((__unused__)) (*bpf_store_hdr_opt) (void *skops,
						       void *from,
						       __u32 len,
						       __u32 flags) =
    (void *)143;

static int
    __attribute__ ((__unused__)) (*bpf_get_stackid) (void *ctx, void *map,
						     int flags) = (void *)27;

static int
    __attribute__ ((__unused__)) (*bpf_get_stack) (void *ctx, void *buf, __u32 size,
						     int flags) = (void *)67;

/* llvm builtin functions that eBPF C program may use to 
 * emit BPF_LD_ABS and BPF_LD_IND instructions 
 */
unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

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

#define PSR_MODE32_BIT 0x00000010
#define PSR_MODE_MASK  0x0000000f
#define PSR_MODE_EL0t  0x00000000
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
#define MAP_MAX_ENTRIES_DEF 40960

/*
 * DeepFlow eBPF program naming convention:
 *
 *   'df_<type_identifier>_<probe_name>'
 *
 * type_identifier:
 *   "T"   - tracepoint/syscalls/sys_* / tracepoint/sched/sched_*
 *   "K"   - kprobe
 *   "KR"  - kretprobe
 *   "U"   - uprobe
 *   "UR"  - uretprobe
 *   "TP"  - Tailcall eBPF prog of tracepoint type
 *   "KP"  - Tailcall eBPF prog of kprobe type
 *
 * probe_name:
 *   The name of the tracepoint or the kernel interface.
 * 
 * For example:
 * tracepoint: prog->name:df_T_enter_recvfrom
 * kprobe: prog->name:df_K_sys_sendmsg
 * kretprobe: prog->name:df_KR_sys_sendmsg
 *
 * For probes of type fentry/fexit, use the 'kfunc__' or 'kretfunc__'
 * prefixes, as these specific prefixes are utilized during loading
 * to perform corresponding BTF operations.
 */

#define TP_SYSCALL_PROG(F) SEC("tracepoint/syscalls/sys_"__stringify(F)) int df_T_##F
#define TP_SCHED_PROG(F) SEC("tracepoint/sched/sched_"__stringify(F)) int df_T_##F
#define PROGTP(F) SEC("prog/tp/"__stringify(F)) int df_TP_##F
#define PROGKP(F) SEC("prog/kp/"__stringify(F)) int df_KP_##F
#define PROGPE(F) SEC("prog/pe/"__stringify(F)) int df_PE_##F
#define KPROG(F) SEC("kprobe/"__stringify(F)) int df_K_##F
#define KRETPROG(F) SEC("kretprobe/"__stringify(F)) int df_KR_##F
#define UPROG(F) SEC("uprobe/"__stringify(F)) int df_U_##F
#define URETPROG(F) SEC("uretprobe/"__stringify(F)) int df_UR_##F
#define PERF_EVENT_PROG(F) SEC("perf_event") int df_##F
#define SOCKPROG(F) SEC("socket/"__stringify(F)) int df_S_##F

#define ___bpf_concat(a, b) a ## b
#define ___bpf_apply(fn, n) ___bpf_concat(fn, n)
#define ___bpf_nth(_, _1, _2, _3, _4, _5, _6, _7, _8, _9, _a, _b, _c, N, ...) N
#define ___bpf_narg(...) \
	___bpf_nth(_, ##__VA_ARGS__, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define ___bpf_empty(...) \
	___bpf_nth(_, ##__VA_ARGS__, N, N, N, N, N, N, N, N, N, N, 0)

#define ___bpf_ctx_cast0() ctx
#define ___bpf_ctx_cast1(x) ___bpf_ctx_cast0(), (void *)ctx[0]
#define ___bpf_ctx_cast2(x, args...) ___bpf_ctx_cast1(args), (void *)ctx[1]
#define ___bpf_ctx_cast3(x, args...) ___bpf_ctx_cast2(args), (void *)ctx[2]
#define ___bpf_ctx_cast4(x, args...) ___bpf_ctx_cast3(args), (void *)ctx[3]
#define ___bpf_ctx_cast5(x, args...) ___bpf_ctx_cast4(args), (void *)ctx[4]
#define ___bpf_ctx_cast6(x, args...) ___bpf_ctx_cast5(args), (void *)ctx[5]
#define ___bpf_ctx_cast7(x, args...) ___bpf_ctx_cast6(args), (void *)ctx[6]
#define ___bpf_ctx_cast8(x, args...) ___bpf_ctx_cast7(args), (void *)ctx[7]
#define ___bpf_ctx_cast9(x, args...) ___bpf_ctx_cast8(args), (void *)ctx[8]
#define ___bpf_ctx_cast10(x, args...) ___bpf_ctx_cast9(args), (void *)ctx[9]
#define ___bpf_ctx_cast11(x, args...) ___bpf_ctx_cast10(args), (void *)ctx[10]
#define ___bpf_ctx_cast12(x, args...) ___bpf_ctx_cast11(args), (void *)ctx[11]
#define ___bpf_ctx_cast(args...) \
	___bpf_apply(___bpf_ctx_cast, ___bpf_narg(args))(args)

#define BPF_PROG(name, args...)                                 \
int name(unsigned long long *ctx);                              \
__attribute__((__always_inline__))                           	\
static int ____##name(unsigned long long *ctx, ##args);         \
int name(unsigned long long *ctx)                               \
{                                                               \
	int __ret;                                              \
                                                                \
	_Pragma("GCC diagnostic push")                          \
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")  \
	__ret = ____##name(___bpf_ctx_cast(args));              \
	_Pragma("GCC diagnostic pop")                           \
	return __ret;                                           \
}                                                               \
static int ____##name(unsigned long long *ctx, ##args)

#define KFUNC_PROG(event, args...) \
	SEC("fentry/"__stringify(event)) \
	BPF_PROG(kfunc__ ## event, ##args)

#define KRETFUNC_PROG(event, args...) \
	SEC("fexit/"__stringify(event)) \
	BPF_PROG(kretfunc__ ## event, ##args)

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

#define _(P) ({typeof(P) val = 0; bpf_probe_read_kernel(&val, sizeof(val), &P); val;})

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
	__u32 feat_flags;
};

#define __BPF_MAP_DEF(_kt, _vt, _ents, _f) \
	.key_size = sizeof(_kt),       \
	.value_size = sizeof(_vt),     \
	.max_entries = (_ents),	\
	.feat_flags = (_f)

#define MAP_ARRAY(name, key_type, value_type, max_entries, feat) \
struct bpf_map_def SEC("maps") __##name = \
{   \
    .type = BPF_MAP_TYPE_ARRAY, \
    __BPF_MAP_DEF(key_type, value_type, max_entries, feat), \
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
#define MAP_PERARRAY(name, key_type, value_type, max_entries, feat) \
struct bpf_map_def SEC("maps") __##name = \
{   \
    .type = BPF_MAP_TYPE_PERCPU_ARRAY, \
    __BPF_MAP_DEF(key_type, value_type, max_entries, feat), \
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

#define MAP_PERF_EVENT(name, key_type, value_type, max_entries, feat) \
struct bpf_map_def SEC("maps") __ ## name = \
{   \
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY, \
    __BPF_MAP_DEF(key_type, value_type, max_entries, feat), \
};

#define MAP_PROG_ARRAY(name, key_type, value_type, max_entries, feat) \
struct bpf_map_def SEC("maps") __ ## name = \
{   \
    .type = BPF_MAP_TYPE_PROG_ARRAY, \
    __BPF_MAP_DEF(key_type, value_type, max_entries, feat), \
};

#define MAP_STACK_TRACE(name, max, f) \
struct bpf_map_def SEC("maps") __ ## name = { \
  .type = BPF_MAP_TYPE_STACK_TRACE, \
  .key_size = sizeof(__u32), \
  .value_size = PERF_MAX_STACK_DEPTH * sizeof(__u64), \
  .max_entries = (max), \
  .feat_flags = (f), \
};

#define MAP_HASH(name, key_type, value_type, max_entries, feat) \
struct bpf_map_def SEC("maps") __##name = \
{   \
    .type = BPF_MAP_TYPE_HASH, \
    __BPF_MAP_DEF(key_type, value_type, max_entries, feat), \
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
  MAP_HASH(_name, _key_type, _leaf_type, MAP_MAX_ENTRIES_DEF, 0)

#define BPF_HASH4(_name, _key_type, _leaf_type, _size) \
  MAP_HASH(_name, _key_type, _leaf_type, _size, 0)

#define BPF_HASH5(_name, _key_type, _leaf_type, _size, _feat) \
  MAP_HASH(_name, _key_type, _leaf_type, _size, _feat)

// helper for default-variable macro function
#define BPF_HASHX(_1, _2, _3, _4, _5, NAME, ...) NAME

#define BPF_HASH(...) \
  BPF_HASHX(__VA_ARGS__, BPF_HASH5, BPF_HASH4, BPF_HASH3)(__VA_ARGS__)

#define BPF_LEN_CAP(x, cap) (x < cap ? (x & (cap - 1)) : cap)

#endif /* DF_BPF_BASE_H */
