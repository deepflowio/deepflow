/*
 * Enhanced Security and Memory Safety for eBPF Profilers
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

#pragma once

#include "bpf_base.h"
#include "common.h"

/* Memory region types for enhanced validation */
#define MEMORY_REGION_UNKNOWN       0
#define MEMORY_REGION_EXECUTABLE    1
#define MEMORY_REGION_HEAP          2
#define MEMORY_REGION_STACK         3
#define MEMORY_REGION_SHARED        4
#define MEMORY_REGION_VDSO          5

/* Security validation levels */
#define SECURITY_LEVEL_BASIC        1
#define SECURITY_LEVEL_ENHANCED     2
#define SECURITY_LEVEL_PARANOID     3

/* Address space boundaries for different architectures */
#ifdef __x86_64__
#define USER_SPACE_MIN              0x1000ULL
#define USER_SPACE_MAX              0x7fffffffffffULL
#define KERNEL_SPACE_MIN            0x8000000000000000ULL
#define STACK_REGION_MIN            0x7fff00000000ULL
#define HEAP_REGION_MIN             0x555555554000ULL
#define HEAP_REGION_MAX             0x7fff00000000ULL
#define EXECUTABLE_REGION_MIN       0x400000ULL
#define EXECUTABLE_REGION_MAX       0x800000ULL
#define SHARED_LIB_REGION_MIN       0x7f0000000000ULL
#define SHARED_LIB_REGION_MAX       0x7fff00000000ULL
#else
/* ARM64 or other architectures - define appropriate values */
#define USER_SPACE_MIN              0x1000ULL
#define USER_SPACE_MAX              0x0000ffffffffffffULL
#define KERNEL_SPACE_MIN            0xffff000000000000ULL
#define STACK_REGION_MIN            0x0000ffff00000000ULL
#define HEAP_REGION_MIN             0x0000555555554000ULL
#define HEAP_REGION_MAX             0x0000ffff00000000ULL
#define EXECUTABLE_REGION_MIN       0x0000000000400000ULL
#define EXECUTABLE_REGION_MAX       0x0000000000800000ULL
#define SHARED_LIB_REGION_MIN       0x0000ffff80000000ULL
#define SHARED_LIB_REGION_MAX       0x0000ffff00000000ULL
#endif

/* Enhanced pointer validation structure */
struct pointer_validation_context {
    __u32 pid;
    __u32 security_level;
    __u64 base_addr;
    __u64 region_size;
    __u8 region_type;
    __u8 access_type; /* read=1, write=2 */
    __u16 flags;
};

/* Memory access attempt counter (for rate limiting) */
struct memory_access_stats {
    __u64 total_attempts;
    __u64 successful_reads;
    __u64 failed_reads;
    __u64 invalid_addresses;
    __u64 boundary_violations;
    __u64 alignment_errors;
    __u64 last_violation_time;
};

/* Per-process memory access tracking */
MAP_HASH(memory_access_tracking, __u32, struct memory_access_stats, 1024, FEATURE_FLAG_PROFILE)

/* Process memory layout cache for faster validation */
struct process_memory_layout {
    __u32 pid;
    __u64 stack_start;
    __u64 stack_end;
    __u64 heap_start;
    __u64 heap_end;
    __u64 code_start;
    __u64 code_end;
    __u64 last_updated;
    __u32 validation_level;
};

MAP_HASH(process_memory_layouts, __u32, struct process_memory_layout, 512, FEATURE_FLAG_PROFILE)

/* Enhanced pointer validation with detailed security checks */
static inline __attribute__((always_inline))
int enhanced_validate_user_pointer(__u64 addr, size_t size, __u32 pid, __u8 access_type) {
    /* Basic null and size checks */
    if (addr == 0 || size == 0) {
        return -EINVAL;
    }

    /* Check for integer overflow in address + size */
    if (addr > USER_SPACE_MAX || (addr + size) < addr || (addr + size) > USER_SPACE_MAX) {
        return -ERANGE;
    }

    /* Minimum address check (guard against null pointer dereference) */
    if (addr < USER_SPACE_MIN) {
        return -EFAULT;
    }

    /* Alignment check (8-byte aligned for 64-bit systems) */
    if ((addr & 0x7) != 0) {
        return -EINVAL; // Use standard error code for invalid/misaligned address
    }

    /* Size limits - prevent excessive memory access */
    if (size > 4096) { /* Maximum 4KB read in one operation */
        return -E2BIG;
    }

    /* Get memory access stats for this process */
    struct memory_access_stats *stats = memory_access_tracking__lookup(&pid);
    if (stats) {
        stats->total_attempts++;

        /* Rate limiting: check for excessive failures */
        if (stats->failed_reads > 100 &&
            (stats->failed_reads * 100 / stats->total_attempts) > 50) {
            /* More than 50% failure rate with over 100 attempts */
            return -EBUSY;
        }
    }

    return 0; /* Validation passed */
}

/* Advanced pointer validation with memory layout awareness */
static inline __attribute__((always_inline))
int validate_pointer_with_layout(__u64 addr, size_t size, __u32 pid, __u8 region_type) {
    int basic_result = enhanced_validate_user_pointer(addr, size, pid, 1);
    if (basic_result != 0) {
        return basic_result;
    }

    /* Get cached memory layout for this process */
    struct process_memory_layout *layout = process_memory_layouts__lookup(&pid);
    if (!layout) {
        /* No layout cached, use basic validation only */
        return 0;
    }

    /* Validate against known memory regions */
    switch (region_type) {
        case MEMORY_REGION_STACK:
            if (addr >= layout->stack_start && (addr + size) <= layout->stack_end) {
                return 0;
            }
            break;

        case MEMORY_REGION_HEAP:
            if (addr >= layout->heap_start && (addr + size) <= layout->heap_end) {
                return 0;
            }
            break;

        case MEMORY_REGION_EXECUTABLE:
            if (addr >= layout->code_start && (addr + size) <= layout->code_end) {
                return 0;
            }
            break;

        default:
            /* For unknown regions, fall back to general bounds checking */
            if (addr >= USER_SPACE_MIN && (addr + size) <= USER_SPACE_MAX) {
                return 0;
            }
            break;
    }

    return -EACCES; /* Address not in expected memory region */
}

/* Secure memory read with comprehensive validation and error tracking */
static inline __attribute__((always_inline))
int secure_read_user_memory(__u64 addr, void *dst, size_t size, __u32 pid, __u8 region_type) {
    /* Enhanced pointer validation */
    int validation_result = validate_pointer_with_layout(addr, size, pid, region_type);
    if (validation_result != 0) {
        /* Update failure statistics */
        struct memory_access_stats *stats = memory_access_tracking__lookup(&pid);
        if (stats) {
            stats->failed_reads++;
            if (validation_result == -EFAULT) {
                stats->invalid_addresses++;
            } else if (validation_result == -ERANGE) {
                stats->boundary_violations++;
            } else if (validation_result == -EINVAL) {
                // Check if it was specifically an alignment error by checking the address
                if ((addr & 0x7) != 0) {
                    stats->alignment_errors++;
                } else {
                    stats->invalid_addresses++;
                }
            }
            stats->last_violation_time = bpf_ktime_get_ns();
        }
        return validation_result;
    }

    /* Attempt the actual memory read */
    int read_result = bpf_probe_read_user(dst, size, (void *)addr);

    /* Update statistics */
    struct memory_access_stats *stats = memory_access_tracking__lookup(&pid);
    if (stats) {
        if (read_result == 0) {
            stats->successful_reads++;
        } else {
            stats->failed_reads++;
        }
    }

    return read_result;
}

/* Secure string read with enhanced bounds checking */
static inline __attribute__((always_inline))
int secure_read_user_string_enhanced(__u64 addr, char *buffer, __u32 max_size, __u32 pid) {
    if (!buffer || max_size == 0) {
        return -EINVAL;
    }

    /* Validate the string address */
    int validation_result = enhanced_validate_user_pointer(addr, max_size, pid, 1);
    if (validation_result != 0) {
        buffer[0] = '\0';
        return validation_result;
    }

    /* Ensure max_size leaves room for null terminator and is reasonable */
    __u32 safe_max = max_size - 1;
    if (safe_max > 256) safe_max = 256; /* Limit string reads to 256 chars */

    /* Attempt to read the string */
    int ret = bpf_probe_read_user_str(buffer, safe_max + 1, (void *)addr);
    if (ret < 0) {
        buffer[0] = '\0';

        /* Update failure statistics */
        struct memory_access_stats *stats = memory_access_tracking__lookup(&pid);
        if (stats) {
            stats->failed_reads++;
        }
        return ret;
    }

    /* Ensure null termination */
    buffer[safe_max] = '\0';

    /* Update success statistics */
    struct memory_access_stats *stats = memory_access_tracking__lookup(&pid);
    if (stats) {
        stats->successful_reads++;
    }

    return 0;
}

/* Batch validation for multiple pointers (more efficient for stack unwinding) */
static inline __attribute__((always_inline))
int validate_pointer_batch(__u64 *addresses, __u32 count, __u32 pid) {
    if (!addresses || count == 0 || count > 32) {
        return -EINVAL;
    }

    /* Validate each address in the batch */
    for (__u32 i = 0; i < count && i < 32; i++) {
        int result = enhanced_validate_user_pointer(addresses[i], sizeof(__u64), pid, 1);
        if (result != 0) {
            return result;
        }
    }

    return 0;
}

/* Memory access rate limiting and abuse detection */
static inline __attribute__((always_inline))
int check_memory_access_rate_limit(__u32 pid) {
    struct memory_access_stats *stats = memory_access_tracking__lookup(&pid);
    if (!stats) {
        /* Initialize stats for new process */
        struct memory_access_stats new_stats = {0};
        new_stats.total_attempts = 1;
        memory_access_tracking__update(&pid, &new_stats, BPF_ANY);
        return 0;
    }

    __u64 current_time = bpf_ktime_get_ns();

    /* Check for excessive access rate (more than 1000 accesses per second) */
    if (stats->total_attempts > 1000) {
        __u64 time_since_last = current_time - stats->last_violation_time;
        if (time_since_last < 1000000000ULL) { /* Less than 1 second */
            return -EBUSY; /* Rate limit exceeded */
        }
    }

    /* Check for suspicious patterns */
    if (stats->failed_reads > 0 && stats->total_attempts > 50) {
        __u64 failure_rate = (stats->failed_reads * 100) / stats->total_attempts;
        if (failure_rate > 75) {
            /* More than 75% failure rate indicates potential attack */
            return -EPERM;
        }
    }

    return 0;
}

/* Update process memory layout cache (called from user space) */
static inline __attribute__((always_inline))
int update_process_memory_layout(__u32 pid, __u64 stack_start, __u64 stack_end,
                                __u64 heap_start, __u64 heap_end,
                                __u64 code_start, __u64 code_end) {
    struct process_memory_layout layout = {
        .pid = pid,
        .stack_start = stack_start,
        .stack_end = stack_end,
        .heap_start = heap_start,
        .heap_end = heap_end,
        .code_start = code_start,
        .code_end = code_end,
        .last_updated = bpf_ktime_get_ns(),
        .validation_level = SECURITY_LEVEL_ENHANCED,
    };

    return process_memory_layouts__update(&pid, &layout, BPF_ANY);
}

/* Clean up memory tracking for exited processes */
static inline __attribute__((always_inline))
void cleanup_process_memory_tracking(__u32 pid) {
    memory_access_tracking__delete(&pid);
    process_memory_layouts__delete(&pid);
}

/* Get memory access statistics for monitoring */
static inline __attribute__((always_inline))
struct memory_access_stats* get_memory_access_stats(__u32 pid) {
    return memory_access_tracking__lookup(&pid);
}

/* Security level configuration */
static __u32 global_security_level = SECURITY_LEVEL_ENHANCED;

static inline __attribute__((always_inline))
void set_security_level(__u32 level) {
    if (level >= SECURITY_LEVEL_BASIC && level <= SECURITY_LEVEL_PARANOID) {
        global_security_level = level;
    }
}

static inline __attribute__((always_inline))
__u32 get_security_level(void) {
    return global_security_level;
}