/*
 * Off-CPU Profiler Integration Header
 * Copyright (c) 2024 Yunshan Networks
 */

#ifndef DF_OFF_CPU_INTEGRATION_H
#define DF_OFF_CPU_INTEGRATION_H

#include <stdbool.h>
#include "../tracer.h"
#include "profile_common.h"

/**
 * Initialize off-CPU profiler integration with the main profiler system
 * @return 0 on success, negative on error
 */
int off_cpu_profiler_integration_init(void);

/**
 * Start off-CPU profiler integration
 * @param tracer BPF tracer instance
 * @return 0 on success, negative on error
 */
int off_cpu_profiler_integration_start(struct bpf_tracer *tracer);

/**
 * Stop off-CPU profiler integration
 * @param tracer BPF tracer instance
 * @return 0 on success, negative on error
 */
int off_cpu_profiler_integration_stop(struct bpf_tracer *tracer);

/**
 * Process off-CPU stack traces (integration with main profiler pipeline)
 * @param tracer BPF tracer instance
 */
void off_cpu_profiler_integration_process(struct bpf_tracer *tracer);

/**
 * Get off-CPU profiler context
 * @return Profiler context pointer or NULL
 */
struct profiler_context* off_cpu_profiler_integration_get_context(void);

/**
 * Cleanup off-CPU profiler integration
 */
void off_cpu_profiler_integration_cleanup(void);

/**
 * Check if off-CPU profiler is running
 * @return true if running, false otherwise
 */
bool off_cpu_profiler_integration_is_running(void);

#endif /* DF_OFF_CPU_INTEGRATION_H */