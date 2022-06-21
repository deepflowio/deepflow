#ifndef __BPF_BASE_H__
#define __BPF_BASE_H__

#include <linux/version.h>

#ifndef BPF_USE_CORE
#include <asm/ptrace.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdbool.h>
#include <errno.h>
#include <stddef.h>
#include "../../libbpf/include/uapi/linux/bpf.h"
#endif

#include "../../libbpf/src/bpf_tracing.h"
#include "../../libbpf/src/bpf_helpers.h"
#include "../../libbpf/src/bpf_core_read.h"
#include "utils.h"

#define MAX_CPU         256

#define SP_OFFSET(offset) (void *)(__u64)PT_REGS_SP(ctx) + offset * 8

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
#define PT_GO_REGS_PARM1(x) ((x)->rax)
#define PT_GO_REGS_PARM2(x) ((x)->rbx)
#define PT_GO_REGS_PARM3(x) ((x)->rcx)
#define PT_GO_REGS_PARM4(x) ((x)->rdi)
#define PT_GO_REGS_PARM5(x) ((x)->rsi)
#define PT_GO_REGS_PARM6(x) ((x)->r8)
#define PT_GO_REGS_PARM7(x) ((x)->r9)
#define PT_GO_REGS_PARM8(x) ((x)->r10)
#define PT_GO_REGS_PARM9(x) ((x)->rdx)

#define __stringify_1(x) #x
#define __stringify(x)  __stringify_1(x)

#define NAME(N)  __##N

#define KRETPROG(F) SEC("kretprobe/"__stringify(F)) int kretprobe__##F
#define KPROG(F) SEC("kprobe/"__stringify(F)) int kprobe__##F

#define _(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

#ifndef CUR_CPU_IDENTIFIER
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
#define CUR_CPU_IDENTIFIER BPF_F_CURRENT_CPU
#else
#define CUR_CPU_IDENTIFIER bpf_get_smp_processor_id()
#endif
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif


#define _(P) ({typeof(P) val = 0; bpf_probe_read(&val, sizeof(val), &P); val;})

#ifndef CUR_CPU_IDENTIFIER
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
#define CUR_CPU_IDENTIFIER BPF_F_CURRENT_CPU
#else
#define CUR_CPU_IDENTIFIER bpf_get_smp_processor_id()
#endif
#endif

#define __BPF_MAP_DEF(_kt, _vt, _ents) \
	.key_size = sizeof(_kt),		\
	.value_size = sizeof(_vt),	\
	.max_entries = (_ents)

#define MAP_ARRAY(name, key_type, value_type, max_entries) \
struct bpf_map_def SEC("maps") __##name = \
{   \
    .type = BPF_MAP_TYPE_ARRAY, \
    __BPF_MAP_DEF(key_type, value_type, max_entries), \
}; \
static __always_inline __attribute__((unused)) value_type * name ## __lookup(key_type *key) \
{ \
    return (value_type *) bpf_map_lookup_elem(& __##name, (const void *)key); \
} \
static __always_inline __attribute__((unused)) int name ## __update(key_type *key, value_type *value) \
{ \
    return bpf_map_update_elem(& __##name, (const void *)key, (const void *)value, BPF_ANY); \
} \
static __always_inline __attribute__((unused)) int name ## __delete(key_type *key) \
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
static __always_inline __attribute__((unused)) value_type * name ## __lookup(key_type *key) \
{ \
    return (value_type *) bpf_map_lookup_elem(& __##name, (const void *)key); \
} \
static __always_inline __attribute__((unused)) int name ## __update(key_type *key, value_type *value) \
{ \
    return bpf_map_update_elem(& __##name, (const void *)key, (const void *)value, BPF_ANY); \
} \
static __always_inline __attribute__((unused)) int name ## __delete(key_type *key) \
{ \
    return bpf_map_delete_elem(& __##name, (const void *)key); \
}


#define MAP_PERF_EVENT(name, key_type, value_type, max_entries) \
struct bpf_map_def SEC("maps") __ ## name = \
{   \
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY, \
    __BPF_MAP_DEF(key_type, value_type, max_entries), \
};

#define MAP_HASH(name, key_type, value_type, max_entries) \
struct bpf_map_def SEC("maps") __##name = \
{   \
    .type = BPF_MAP_TYPE_HASH, \
    __BPF_MAP_DEF(key_type, value_type, max_entries), \
}; \
static __always_inline __attribute__((unused)) value_type * name ## __lookup(key_type *key) \
{ \
    return (value_type *) bpf_map_lookup_elem(& __##name, (const void *)key); \
} \
static __always_inline __attribute__((unused)) int name ## __update(key_type *key, value_type *value) \
{ \
    return bpf_map_update_elem(& __##name, (const void *)key, (const void *)value, BPF_ANY); \
} \
static __always_inline __attribute__((unused)) int name ## __delete(key_type *key) \
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
#if 0
static __inline int bpf_memcmp(void * d, const void * s, unsigned int n) {
     return __builtin_memcmp(d, s, n);
}

static __inline void * bpf_memcpy(void * d, const void * s, unsigned int n) {
     return __builtin_memcpy(d, s, n);
}

static __inline void * bpf_memset(void * d, int c, unsigned int n) {
     return __builtin_memset(d, c, n);
}

static __inline int bpf_strcmp(char * d, const char * s) {
     return __builtin_strcmp(d, s);
}

static __inline int bpf_strncmp(char * d, const char * s, unsigned int n) {
     return __builtin_memcmp(d, s, n);
}

static __inline char * bpf_strcpy(char * d, const char * s) {
     return __builtin_strcpy(d, s);
}

static __inline char * bpf_strncpy(char * d, const char * s, unsigned int n) {
     return (char *)__builtin_memcpy(d, s, n);
}

static __inline unsigned int bpf_strlen(const char * s) {
     return __builtin_strlen(s);
}
#endif
//#define BPF_LEN_CAP(x, cap) (x < cap ? (x) : cap)

#endif /* __BPF_BASE_H__ */
