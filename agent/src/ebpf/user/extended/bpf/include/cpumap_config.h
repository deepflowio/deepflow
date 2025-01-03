#ifndef _BILD_CPUMAP_CONFIG_H
#define _BILD_CPUMAP_CONFIG_H

#ifndef NULL
#define NULL ((void*)0)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#include "../../../types.h"
typedef unsigned long size_t;
#define __always_inline __inline __attribute__ ((__always_inline__))

#define CMDLINE_SZ 256
#define PATH_SIZE  128
/* How many xdp_progs are defined in _kern.c */
#define MAX_PROG 6
#define XDP_DEFAULT_MTU 3050

#define XDP_CPUMAP_DEBUG_PATH   "/var/run/cpumap/debug"
#define PATH_MEMSIZE            64

#define XDP_CPUMAP_PAUSE_PATH   "/var/run/cpumap/pause"
#define XDP_CPUMAP_CPUS_PATH    "/var/run/cpumap/cpus"

#ifdef CPUMAP_PINNING
#define CPUMAP_PINNING_FILE             "/sys/fs/bpf/cpu_map"
#define PAUSE_PINNING_FILE             "/sys/fs/bpf/cpumap_pause"
#endif

/* Exit return codes */
#define EXIT_OK         0
#define EXIT_FAIL               1
#define EXIT_FAIL_OPTION        2
#define EXIT_FAIL_XDP           3
#define EXIT_FAIL_BPF           4
#define EXIT_FAIL_MEM           5

#endif /* _BILD_CPUMAP_CONFIG_H */

